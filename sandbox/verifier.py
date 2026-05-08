"""
Dockerサンドボックス検証モジュール
LLMが生成したPoCをDockerで実際に実行し、脆弱性の成立を確認する

Exploitabilityの判定:
  confirmed   : Docker実行で明確な成功指標を確認
  practical   : 実行は失敗したが論理的に成立する根拠あり
  theoretical : 成立しなかった / 未検証
"""

import asyncio
import re
import json
from typing import List, Optional, Tuple

from config import MAX_DOCKER_RETRY, MAX_PARALLEL_DOCKER
from schema import VulnSample, Exploitability, AttackType
from sandbox.attacker import DockerExecutor


# ===========================
# 成功判定ルール
# ===========================

# 脆弱性種別ごとの成功指標
SUCCESS_INDICATORS: dict[str, list[str]] = {
    "injection": [
        "error in your sql syntax",
        "you have an error in your sql",
        "sqlite3.operationalerror",
        "pg::syntaxerror",
        "ora-",
        "unclosed quotation",
        "1=1",
        "or 1=1",
    ],
    "rce": [
        "uid=0",
        "uid=",
        "root:",
        "root:x:0:0",
        "/bin/bash",
        "total 0",        # ls出力
        "command not found",  # コマンド到達の証拠
    ],
    "path_traversal": [
        "root:x:0:0",
        "nobody:x:",
        "daemon:x:",
        "etc/passwd",
        "[boot loader]",   # win
    ],
    "ssrf": [
        "ami-id",
        "169.254.169.254",
        "aws_secret_access_key",
        "iam/security-credentials",
        "computemetadata",
        "instance/id",
    ],
    "xss": [
        "<script>",
        "alert(",
        "onerror=",
        "xss_executed",
        "script executed",
    ],
    "overflow": [
        "segmentation fault",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "address sanitizer",
        "==error:",
        "crash detected",
        "signal 11",
        "core dumped",
    ],
    "deserialization": [
        "uid=",
        "root:",
        "pickleexploit",
        "java.lang.runtime",
        "remote code execution",
    ],
    "auth_bypass": [
        "logged in",
        "welcome admin",
        "access granted",
        "200 ok",
        "authorization: bearer",
    ],
}

# 全種別共通の失敗指標（これが出たら confirmed にしない）
FAILURE_INDICATORS = [
    "permission denied",
    "access denied",
    "traceback",         # Python例外（ただし種別によっては正常）
    "docker unavailable",
    "timeout",
]


def _check_success(result: str, attack_type: AttackType) -> bool:
    """ツール実行結果が攻撃成立を示すか判定"""
    result_lower = result.lower()

    # 失敗指標が含まれていたら即 False（overflow系は除く）
    if attack_type not in (AttackType.OVERFLOW,):
        if any(ind in result_lower for ind in FAILURE_INDICATORS[:2]):
            return False

    # 種別ごとの成功指標を確認
    type_key = attack_type.value if attack_type.value in SUCCESS_INDICATORS else "rce"
    indicators = SUCCESS_INDICATORS.get(type_key, [])

    return any(ind in result_lower for ind in indicators)


def _extract_payloads(sample: VulnSample) -> List[str]:
    """
    attack_scenarioのsteps・poc_scriptからペイロード候補を複数抽出
    バリエーションを持たせて retry に使う
    """
    payloads = []

    # stepsから引用符内の文字列を抽出
    for step in sample.attack_scenario.steps:
        found = re.findall(r"['\"]([^'\"]{3,100})['\"]", step)
        payloads.extend(found)

    # poc_scriptからも抽出
    if sample.attack_scenario.poc_script:
        found = re.findall(r"['\"]([^'\"]{3,100})['\"]",
                           sample.attack_scenario.poc_script)
        payloads.extend(found)

    # 攻撃タイプ別のデフォルトペイロードを末尾に追加（fallback）
    defaults = {
        AttackType.INJECTION:    ["' OR 1=1--", "1' OR '1'='1", "'; DROP TABLE users--"],
        AttackType.RCE:          ["; id", "| id", "$(id)", "`id`", "; whoami"],
        AttackType.PATH_TRAVERSAL: ["../../etc/passwd", "../../../etc/passwd",
                                    "....//....//etc/passwd"],
        AttackType.SSRF:         ["http://169.254.169.254/latest/meta-data/",
                                  "http://127.0.0.1/"],
        AttackType.XSS:          ["<script>alert(1)</script>",
                                  "\"><script>alert(1)</script>",
                                  "javascript:alert(1)"],
        AttackType.OVERFLOW:     ["A" * 256, "A" * 1024, "%n%n%n%n"],
    }
    payloads += defaults.get(sample.attack_model.type, [])

    # 重複排除・空文字除去
    seen = set()
    unique = []
    for p in payloads:
        if p and p not in seen:
            seen.add(p)
            unique.append(p)

    return unique[:MAX_DOCKER_RETRY + 2]


async def _run_single_verify(
    docker: DockerExecutor,
    sample: VulnSample,
    payload: str,
) -> Tuple[bool, str]:
    """
    1回の検証を実行して (成功したか, 実行結果) を返す
    """
    attack_type = sample.attack_model.type
    lang        = sample.language.value

    try:
        if attack_type == AttackType.INJECTION:
            result = await docker.run_sql_test(sample.code, lang, payload)
        elif attack_type == AttackType.RCE:
            result = await docker.run_cmd_test(sample.code, lang, payload)
        elif attack_type == AttackType.PATH_TRAVERSAL:
            result = await docker.run_path_test(sample.code, lang, payload)
        elif attack_type == AttackType.SSRF:
            result = await docker.run_ssrf_test(sample.code, lang, payload)
        elif attack_type in (AttackType.OVERFLOW,):
            result = await docker.run_asan(sample.code, lang, payload)
        else:
            # XSS / auth_bypass / deserialization / その他 → 汎用SQLテストで試す
            result = await docker.run_sql_test(sample.code, lang, payload)

        success = _check_success(result, attack_type)
        return success, result

    except Exception as e:
        return False, f"Execution error: {e}"


class SandboxVerifier:
    """
    Dockerサンドボックスを使ってVulnSampleの脆弱性成立を検証する

    フロー:
      1. LLMにPoCコードを生成させる
      2. Dockerで実行
      3. エラー時はLLMにエラーを渡して修正させ再実行（MAX_DOCKER_RETRY回）
      4. LLMが「成立不可能」と判断したら INFEASIBLE: <理由> を返させ、theoretical に降格
      5. 成功 → CONFIRMED
    """

    def __init__(self, docker: Optional[DockerExecutor] = None, llm_client=None):
        self.docker = docker or DockerExecutor()
        self._llm = llm_client  # None時は後からVulnAnalyzerのclientを使う

    def _get_llm_client(self):
        """LLMクライアントを遅延取得"""
        if self._llm:
            return self._llm
        from openai import AsyncOpenAI
        from config import LLM_BASE_URL, LLM_API_KEY, LLM_MODEL
        import os
        return AsyncOpenAI(
            base_url=os.getenv("LLM_BASE_URL", LLM_BASE_URL),
            api_key=LLM_API_KEY,
        )

    async def _generate_poc(
        self,
        sample: VulnSample,
        last_error: str = "",
        attempt: int = 0,
    ) -> str:
        """
        LLMにPoCコードを生成（または修正）させる。
        「INFEASIBLE: <reason>」を返した場合は成立不可と判定する。
        """
        client = self._get_llm_client()
        from config import LLM_MODEL
        import os

        error_section = ""
        if last_error:
            error_section = f"""
## Previous attempt failed (attempt {attempt})
Error output:
```
{last_error[:600]}
```
Fix the PoC to address this error. If you determine exploitation is truly impossible, respond with exactly:
INFEASIBLE: <reason>
"""

        prompt = f"""You are writing a PoC exploit for a confirmed vulnerability.

## Vulnerability
CWE: {sample.label.cwe}
Attack type: {sample.attack_model.type.value}
Exploitability: {sample.attack_model.exploitability.value}

## Vulnerable code
```{sample.language.value}
{sample.code[:800]}
```

## Attack scenario
{chr(10).join(sample.attack_scenario.steps[:5])}

## Data flow
Source: {sample.analysis.input}
Sink: {sample.analysis.sink}
{error_section}

Write a standalone Python or shell PoC script that demonstrates this vulnerability.
The script must:
1. Set up the vulnerable code/environment if needed
2. Send the exploit payload
3. Print clear evidence of success (e.g., SQL error, command output, file content)

If after analysis you are certain this is NOT exploitable, respond with exactly:
INFEASIBLE: <one-line reason>

Otherwise, output ONLY the PoC script code, no explanation.
"""
        try:
            resp = await client.chat.completions.create(
                model=os.getenv("LLM_MODEL", LLM_MODEL),
                messages=[{"role": "user", "content": prompt}],
                max_tokens=800,
                temperature=0.2,
                extra_body={"chat_template_kwargs": {"thinking": False}},
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            return f"# PoC generation error: {e}"

    async def verify(self, sample: VulnSample) -> VulnSample:
        """
        単一サンプルを検証してexploitabilityを更新する
        """
        if not self.docker._docker_available:
            print(f"    [!] Docker不使用: {_func_name(sample)} → スキップ")
            return sample

        func = _func_name(sample)
        print(f"    [*] LLM PoC生成+検証: {func} ({sample.attack_model.type.value})")

        last_error = ""
        for attempt in range(MAX_DOCKER_RETRY):
            # LLMにPoC生成（または修正）させる
            poc_code = await self._generate_poc(sample, last_error, attempt)

            # 成立不可能判定
            if poc_code.startswith("INFEASIBLE:"):
                reason = poc_code[len("INFEASIBLE:"):].strip()
                print(f"       [✗] LLMが成立不可能と判断: {reason}")
                sample.attack_model.exploitability = Exploitability.THEORETICAL
                sample.attack_scenario.poc_script = f"# INFEASIBLE: {reason}"
                return sample

            print(f"       試行 {attempt+1}/{MAX_DOCKER_RETRY}: PoCコード生成済み")

            # Dockerで実行
            try:
                result = await self.docker.run_script(poc_code, sample.language.value)
            except AttributeError:
                # run_scriptがない場合は既存メソッドにフォールバック
                payloads = _extract_payloads(sample)
                payload = payloads[attempt] if attempt < len(payloads) else (payloads[0] if payloads else "test")
                success, result = await _run_single_verify(self.docker, sample, payload)
                if success:
                    sample.attack_model.exploitability = Exploitability.CONFIRMED
                    sample.attack_scenario.poc_script = f"# Verified payload\n{payload}\n\n# Output\n{result[:800]}"
                    print(f"       [✓] confirmed")
                    return sample
                last_error = result
                continue

            # 成功判定
            success = _check_success(result, sample.attack_model.type)
            if success:
                sample.attack_model.exploitability = Exploitability.CONFIRMED
                sample.attack_scenario.poc_script = (
                    f"# LLM-generated PoC (verified)\n{poc_code}\n\n"
                    f"# Output\n{result[:800]}"
                )
                print(f"       [✓] confirmed: {result[:100].strip()!r}")
                return sample

            last_error = result
            print(f"       [-] 失敗: {result[:80].strip()!r}")

        # 全試行失敗
        print(f"    [-] Docker検証失敗: {func} → exploitability据え置き"
              f" ({sample.attack_model.exploitability.value})")
        return sample

    async def verify_batch(
        self,
        samples: List[VulnSample],
        concurrency: int = MAX_PARALLEL_DOCKER,
    ) -> List[VulnSample]:
        """
        複数サンプルを並列検証する

        Args:
            samples: 検証対象のVulnSampleリスト
            concurrency: 同時実行数（デフォルト: MAX_PARALLEL_DOCKER）

        Returns:
            exploitabilityが更新されたVulnSampleリスト
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def bounded_verify(s: VulnSample) -> VulnSample:
            async with semaphore:
                return await self.verify(s)

        results = await asyncio.gather(*[bounded_verify(s) for s in samples])
        return list(results)

    async def verify_with_feedback(
        self,
        sample: VulnSample,
        llm_client=None,
        max_retries: int = 3,
    ) -> VulnSample:
        """
        LLMフィードバックループ付き検証（高精度モード）

        失敗時にLLMへ実行結果を渡してペイロードを改善させ再試行する。
        llm_clientが未指定の場合は通常のverify()にフォールバック。
        """
        if llm_client is None:
            return await self.verify(sample)

        func = _func_name(sample)
        print(f"    [*] フィードバックループ検証: {func}")

        last_result = ""
        for attempt in range(max_retries):
            print(f"       試行 {attempt+1}/{max_retries}")

            payloads = _extract_payloads(sample)
            payload  = payloads[0] if payloads else ""

            success, last_result = await _run_single_verify(
                self.docker, sample, payload
            )

            if success:
                sample.attack_model.exploitability = Exploitability.CONFIRMED
                sample.attack_scenario.poc_script  = (
                    f"# Verified payload (attempt {attempt+1})\n{payload}\n\n"
                    f"# Output\n{last_result[:800]}"
                )
                print(f"       [✓] confirmed on attempt {attempt+1}")
                return sample

            # LLMにフィードバックして改善されたペイロードを生成
            if attempt < max_retries - 1:
                improved = await _ask_llm_improve_payload(
                    llm_client=llm_client,
                    sample=sample,
                    last_payload=payload,
                    last_result=last_result,
                )
                if improved:
                    # 改善されたペイロードをstepsに反映して次回のextractに使わせる
                    sample.attack_scenario.steps = (
                        [f"Payload: '{improved}'"] + sample.attack_scenario.steps
                    )

        print(f"    [-] フィードバックループ失敗: {func}")
        return sample


# ===========================
# ヘルパー関数
# ===========================

def _func_name(sample: VulnSample) -> str:
    return sample.context.function if sample.context else "unknown"


async def _ask_llm_improve_payload(
    llm_client,
    sample: VulnSample,
    last_payload: str,
    last_result: str,
) -> Optional[str]:
    """
    LLMに実行結果を見せてペイロードを改善させる
    """
    prompt = f"""The following exploit attempt failed. Suggest a better payload.

Vulnerability: {sample.label.cwe}
Attack type: {sample.attack_model.type.value}
Code excerpt:
```{sample.language.value}
{sample.code[:600]}
```

Last payload tried: {last_payload!r}
Execution result:
{last_result[:400]}

Respond with ONLY the improved payload string, no explanation.
"""
    try:
        resp = await llm_client.chat.completions.create(
            model=None,  # callerが設定済みのモデルを使う
            messages=[{"role": "user", "content": prompt}],
            max_tokens=100,
            temperature=0.2,
        )
        improved = resp.choices[0].message.content.strip().strip("'\"")
        return improved if improved else None
    except Exception as e:
        print(f"       [!] LLMフィードバックエラー: {e}")
        return None
