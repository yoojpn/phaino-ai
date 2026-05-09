"""
LLM解析モジュール（最新版）
Qwen3.6-27B による構造推論・adversarial prompting
OpenAI tool callingで構造化出力を強制
"""

import os
import json
import asyncio
import re
from collections import defaultdict
from typing import List, Optional, Dict
from openai import AsyncOpenAI

from config import LLM_BASE_URL, LLM_MODEL, LLM_API_KEY, BATCH_SIZE
from schema import (
    VulnSample, Label, Analysis, AttackModel, Reasoning,
    AttackScenario, Fix, Context, Language, Severity,
    Exploitability, AttackType, PatchType,
)
from parser.ast_parser import FunctionChunk


# ===========================
# 全知コンテキストクラス
# ===========================

class OmniscientContext:
    """
    全チャンクから呼び出しグラフ・クロスファイルコンテキストを構築する。
    LLMに解析対象コードの「全体像」を与えるために使う。
    """

    def __init__(self, chunks: List[FunctionChunk]):
        self.chunks = chunks
        # 関数名 → チャンク のマップ
        self.func_map: Dict[str, FunctionChunk] = {}
        # 呼び出しグラフ: 関数名 → 呼び出す関数名リスト
        self.call_graph: Dict[str, List[str]] = defaultdict(list)
        # 被呼び出しグラフ: 関数名 → 呼び出し元関数名リスト
        self.reverse_graph: Dict[str, List[str]] = defaultdict(list)
        # ファイル → 関数リスト
        self.file_funcs: Dict[str, List[str]] = defaultdict(list)

    def build(self):
        """
        チャンクリストから呼び出しグラフを構築。
        chunk.calls（ASTParser が AST から抽出した呼び出し先リスト）を優先使用。
        chunk.calls が空の場合のみ正規表現フォールバック。
        """
        for chunk in self.chunks:
            self.func_map[chunk.function_name] = chunk
            self.file_funcs[chunk.file_path].append(chunk.function_name)

        all_func_names = set(self.func_map.keys())

        for chunk in self.chunks:
            if chunk.calls:
                # AST由来の呼び出し先を使用
                for callee in chunk.calls:
                    if callee in all_func_names and callee != chunk.function_name:
                        if callee not in self.call_graph[chunk.function_name]:
                            self.call_graph[chunk.function_name].append(callee)
                        if chunk.function_name not in self.reverse_graph[callee]:
                            self.reverse_graph[callee].append(chunk.function_name)
            else:
                # フォールバック: 正規表現で呼び出し先を検索
                for name in all_func_names:
                    if name == chunk.function_name:
                        continue
                    if re.search(r'\b' + re.escape(name) + r'\s*\(', chunk.code):
                        self.call_graph[chunk.function_name].append(name)
                        self.reverse_graph[name].append(chunk.function_name)

    def get_cross_file_context(self, chunk: FunctionChunk, max_chars: int = 0) -> str:
        """
        指定チャンクの呼び出し元・呼び出し先・同一クラス・同一ファイルの関数・taint情報を返す。
        max_chars=0 は無制限（Qwen3.6-27Bの262Kコンテキストを活用）。
        """
        lines = []
        func_name = chunk.function_name

        # クラス情報
        if chunk.class_name:
            class_header = f"class {chunk.class_name}"
            if chunk.class_parents:
                class_header += f" extends {', '.join(chunk.class_parents)}"
            lines.append(f"=== Class: {class_header} ===")
        if chunk.annotations:
            lines.append(f"[Annotations] {' '.join(chunk.annotations)}")

        # AST由来のtaint情報 + 多段taint伝播結果
        has_taint = (chunk.taint_sources or chunk.taint_sinks
                     or getattr(chunk, 'propagated_sources', [])
                     or getattr(chunk, 'taint_paths', []))
        if has_taint:
            lines.append(f"=== Taint analysis for {func_name} ===")
            if chunk.taint_sources:
                lines.append(f"[AST] taint sources (user-controlled): {chunk.taint_sources[:8]}")
            if chunk.taint_sinks:
                lines.append(f"[AST] taint sinks (dangerous): {chunk.taint_sinks[:8]}")
            if chunk.params:
                lines.append(f"[AST] params: {chunk.params}")
            propagated = getattr(chunk, 'propagated_sources', [])
            taint_paths = getattr(chunk, 'taint_paths', [])
            if propagated:
                lines.append(f"[TAINT] propagated tainted vars (multi-hop): {propagated[:12]}")
            if taint_paths:
                lines.append("[TAINT] data flow paths:")
                for p in taint_paths[:15]:
                    lines.append(f"  → {p}")

        # 同一クラスの他メソッドを全コードつきで追加
        if chunk.class_name:
            same_class = [
                c for c in self.chunks
                if c.class_name == chunk.class_name
                and c.file_path == chunk.file_path
                and c.function_name != func_name
            ]
            if same_class:
                lines.append(f"=== Other methods in class {chunk.class_name} ===")
                for sc in same_class[:10]:
                    lines.append(f"# {sc.function_name} (lines {sc.start_line}-{sc.end_line})")
                    if sc.annotations:
                        lines.append(f"  {' '.join(sc.annotations)}")
                    if sc.taint_sources or sc.taint_sinks:
                        lines.append(f"  taint: src={sc.taint_sources[:3]} sink={sc.taint_sinks[:3]}")
                    lines.append(sc.code)

        # 呼び出し元（この関数を使っている関数）
        callers = self.reverse_graph.get(func_name, [])
        if callers:
            lines.append(f"=== Callers of {func_name} ===")
            for caller in callers[:5]:
                caller_chunk = self.func_map.get(caller)
                if caller_chunk:
                    lines.append(f"# {caller} ({caller_chunk.file_path})")
                    if caller_chunk.annotations:
                        lines.append(f"  {' '.join(caller_chunk.annotations)}")
                    if caller_chunk.taint_sources:
                        lines.append(f"  caller taint sources: {caller_chunk.taint_sources[:4]}")
                    caller_propagated = getattr(caller_chunk, 'propagated_sources', [])
                    if caller_propagated:
                        lines.append(f"  caller propagated taint: {caller_propagated[:4]}")
                    lines.append(caller_chunk.code)

        # 呼び出し先（この関数が呼ぶ関数）
        callees = self.call_graph.get(func_name, [])
        if callees:
            lines.append(f"=== Callees from {func_name} ===")
            for callee in callees[:5]:
                callee_chunk = self.func_map.get(callee)
                if callee_chunk:
                    lines.append(f"# {callee} ({callee_chunk.file_path})")
                    if callee_chunk.annotations:
                        lines.append(f"  {' '.join(callee_chunk.annotations)}")
                    if callee_chunk.taint_sinks:
                        lines.append(f"  callee taint sinks: {callee_chunk.taint_sinks[:4]}")
                    callee_propagated = getattr(callee_chunk, 'propagated_sources', [])
                    if callee_propagated:
                        lines.append(f"  callee propagated taint: {callee_propagated[:4]}")
                    lines.append(callee_chunk.code)

        # 同一ファイルの他関数一覧（コードなし、名前だけ）
        file_funcs = [f for f in self.file_funcs.get(chunk.file_path, [])
                      if f != func_name]
        if file_funcs:
            lines.append(f"=== Other functions in {chunk.file_path} ===")
            lines.append(", ".join(file_funcs[:30]))

        result = "\n".join(lines)
        if max_chars and len(result) > max_chars:
            result = result[:max_chars] + "\n...(truncated)"
        return result

    def build_class_groups(self) -> List[List[FunctionChunk]]:
        """
        同一クラスの全メソッドをグループ化して返す。
        Qwen3.6-27Bに「クラス全体」を一度に見せるため。
        優先度1-3のクラスのみ対象。
        """
        from collections import defaultdict
        class_map: Dict[str, List[FunctionChunk]] = defaultdict(list)
        for chunk in self.chunks:
            if chunk.priority <= 3 and chunk.class_name:
                key = f"{chunk.file_path}::{chunk.class_name}"
                class_map[key].append(chunk)
        # 2メソッド以上あるクラスのみ返す
        return [group for group in class_map.values() if len(group) >= 2]

    def build_taint_chain_groups(self) -> List[List[FunctionChunk]]:
        """
        taintチェーンに沿って関連関数をグループ化。
        source→sinkのフルパスをLLMに一括で渡す。
        """
        groups = []
        seen_funcs = set()

        for chunk in self.chunks:
            if chunk.function_name in seen_funcs:
                continue
            # propagated_sourcesとtaint_sinksが両方ある（実際のsource→sink経路）
            propagated = getattr(chunk, 'propagated_sources', [])
            if not (propagated and chunk.taint_sinks):
                continue

            # このsinkまでのチェーンを収集
            chain = [chunk]
            seen_funcs.add(chunk.function_name)

            # callerを遡る（最大3段）
            current = chunk.function_name
            for _ in range(3):
                callers = self.reverse_graph.get(current, [])
                for caller in callers[:2]:
                    if caller not in seen_funcs:
                        caller_chunk = self.func_map.get(caller)
                        if caller_chunk:
                            chain.insert(0, caller_chunk)
                            seen_funcs.add(caller)
                if callers:
                    current = callers[0]
                else:
                    break

            # calleeを追う（最大3段）
            current = chunk.function_name
            for _ in range(3):
                callees = self.call_graph.get(current, [])
                for callee in callees[:2]:
                    if callee not in seen_funcs:
                        callee_chunk = self.func_map.get(callee)
                        if callee_chunk and callee_chunk.taint_sinks:
                            chain.append(callee_chunk)
                            seen_funcs.add(callee)
                if callees:
                    current = callees[0]
                else:
                    break

            if len(chain) >= 1:
                groups.append(chain)

        return groups


# ===========================
# report_vulnerability ツール定義
# LLMに構造化出力を強制するためのtool
# ===========================

REPORT_TOOL = {
    "type": "function",
    "function": {
        "name": "report_vulnerability",
        "description": (
            "Report the result of your security analysis. "
            "Call this with is_vulnerable=false if no real exploitable vulnerability exists. "
            "Call this with is_vulnerable=true ONLY if an actual attack succeeds."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "is_vulnerable": {
                    "type": "boolean",
                    "description": "True only if an exploitable vulnerability exists",
                },
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Severity level (required if is_vulnerable=true)",
                },
                "cwe": {
                    "type": "string",
                    "description": "CWE identifier, e.g. CWE-89 for SQL injection",
                },
                "analysis": {
                    "type": "object",
                    "description": "Data flow analysis",
                    "properties": {
                        "input":  {"type": "string", "description": "Exact source location (user-controlled input)"},
                        "sink":   {"type": "string", "description": "Exact dangerous sink"},
                        "flow":   {"type": "array",  "items": {"type": "string"}, "description": "Step-by-step data flow"},
                    },
                    "required": ["input", "sink", "flow"],
                },
                "attack_model": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": [
                                "injection", "overflow", "auth_bypass", "logic_bug",
                                "deserialization", "rce", "xss", "path_traversal",
                                "ssrf", "xxe", "idor", "compound", "second_order",
                            ],
                        },
                        "exploitability": {
                            "type": "string",
                            "enum": ["theoretical", "practical", "confirmed"],
                            "description": "theoretical=pattern match only, practical=likely works, confirmed=tested",
                        },
                        "assumption": {
                            "type": "string",
                            "description": "Required conditions for the exploit to succeed",
                        },
                    },
                    "required": ["type", "exploitability", "assumption"],
                },
                "reasoning": {
                    "type": "object",
                    "properties": {
                        "why_vulnerable":     {"type": "string", "description": "Structural explanation of the vulnerability"},
                        "why_exploitable":    {"type": "string", "description": "Why the attack actually succeeds"},
                        "false_positive_risk": {"type": "string", "description": "Conditions where this is NOT exploitable"},
                    },
                    "required": ["why_vulnerable", "why_exploitable", "false_positive_risk"],
                },
                "attack_scenario": {
                    "type": "object",
                    "properties": {
                        "steps":      {"type": "array", "items": {"type": "string"}, "description": "Ordered attack steps"},
                        "result":     {"type": "string", "description": "Expected impact (RCE / data leak / privilege escalation)"},
                        "poc_script": {"type": "string", "description": "curl/python PoC script or null"},
                    },
                    "required": ["steps", "result"],
                },
                "fix": {
                    "type": "object",
                    "properties": {
                        "patch_type":   {
                            "type": "string",
                            "enum": ["input_validation", "sanitization", "rewrite", "disable_function", "access_control"],
                        },
                        "patched_code": {"type": "string", "description": "Fixed code snippet"},
                        "explanation":  {"type": "string", "description": "Why the fix works"},
                    },
                    "required": ["patch_type", "patched_code", "explanation"],
                },
                "confidence": {
                    "type": "integer",
                    "description": "Confidence score 0-100. 0=definitely false positive, 100=certain exploit. Score below 40 means uncertain.",
                },
                "adversarial_check": {
                    "type": "string",
                    "description": "Self-challenge: argue why this might NOT be exploitable, then conclude. Required.",
                },
                "reason": {
                    "type": "string",
                    "description": "If is_vulnerable=false, explain why there is no real vulnerability",
                },
            },
            "required": ["is_vulnerable", "confidence", "adversarial_check"],
        },
    },
}


# ===========================
# システムプロンプト
# ===========================
SYSTEM_PROMPT = """\
You are an elite security researcher and penetration tester with omniscient knowledge of the entire codebase.
Your goal is to find REAL, EXPLOITABLE vulnerabilities for bug bounty reports.

## Core Rules
1. NEVER rely on CVE classifications or known patterns alone
2. ALWAYS reason from code structure and data flow
3. Only report vulnerabilities where an attack ACTUALLY succeeds
4. Think as an attacker first, then verify as a defender
5. You MUST call the report_vulnerability tool with your findings
6. You MUST fill adversarial_check: argue why this is NOT a vulnerability, then conclude
7. You MUST assign confidence (0-100): below 40 = false positive territory
8. Cross-file context is provided — use it to trace data flows across function boundaries
9. Look for: business logic bugs, TOCTOU, second-order injections, compound auth bypass
"""


# ===========================
# Prompt テンプレート
# ===========================

def build_structural_prompt(chunk: FunctionChunk, cross_file: str = "") -> str:
    class_info = ""
    if chunk.class_name:
        class_header = f"class {chunk.class_name}"
        if chunk.class_parents:
            class_header += f" extends {', '.join(chunk.class_parents)}"
        class_info = f"\n## Class: {class_header}"
    if chunk.annotations:
        class_info += f"\n## Annotations: {' '.join(chunk.annotations)}"

    return f"""Analyze this {chunk.language} code for security vulnerabilities.

## File: {chunk.file_path} (lines {chunk.start_line}-{chunk.end_line}){class_info}
## Function: {chunk.function_name}

```{chunk.language}
{chunk.code}
```
{f"## Cross-file Context{chr(10)}{cross_file}" if cross_file else ""}

## Analysis Instructions

**CRITICAL: Do NOT reference CVE databases or known vulnerability patterns.**
**Reason purely from the code structure.**

**Step 1: Map all data sources**
What inputs does this function accept?
- HTTP parameters, headers, cookies, body
- Function arguments (are they user-controlled from callers above?)
- File reads, environment variables, database values

**Step 2: Trace every data path**
Follow each input through ALL transformations:
- String operations (concat, format, interpolation)
- Type conversions, conditional branches, function calls
- Cross-file flows shown in context above

**Step 3: Identify dangerous sinks**
Where does user-controlled data end up?
- SQL/NoSQL queries, OS commands, file paths
- Deserialization, HTML output, HTTP requests, auth decisions

**Step 4: Check sanitization gaps**
For each source->sink path:
- Is there validation? Can it be bypassed?
- Is there encoding? Is it correct for this context?

**Step 5: Think as an attacker**
What specific payload would you send? What would happen? What would you gain?

**Step 6: Adversarial self-check (REQUIRED)**
Argue why this is NOT exploitable:
- Is there a framework/middleware handling it?
- Is the input actually user-controlled?
- Is the sink actually reachable?
Then conclude: "Despite this, the vulnerability holds because..." OR "Conclusion: false positive."

**Step 7: Assign confidence score (0-100)**
- 90-100: Trivially exploitable, clear data flow, no mitigations
- 70-89: Likely exploitable, minor uncertainty
- 40-69: Uncertain (→ uncertain report)
- 0-39: Likely false positive (→ skip)

Call report_vulnerability with your complete findings.
"""


def build_attacker_prompt(chunk: FunctionChunk) -> str:
    return f"""You are an experienced attacker targeting this {chunk.language} code.

## Function: {chunk.function_name} in {chunk.file_path}

```{chunk.language}
{chunk.code}
```

## Task
Find something exploitable in this code. Forget CVE classifications.
Look at the RAW STRUCTURE.

Think about:
1. What can an attacker CONTROL?
2. Where does attacker-controlled data GO?
3. Is there any path from controlled input to dangerous output?
4. What happens at BOUNDARY CONDITIONS?
5. What if you send NULL, empty string, very long input, special characters?
6. Are there TIMING issues or STATE issues?

Design a specific attack if you find something.
Call report_vulnerability with your findings (is_vulnerable=false if nothing exploitable found).
"""


def build_php_prompt(chunk: FunctionChunk) -> str:
    return f"""Analyze this PHP code for security vulnerabilities.

## Function: {chunk.function_name} in {chunk.file_path}

```php
{chunk.code}
```

## PHP-specific Analysis

**Taint sources:** $_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, $_FILES,
php://input, getallheaders()

**Dangerous sinks:** mysql_query(), mysqli_query(), PDO->query() without prepare,
exec(), system(), shell_exec(), passthru(), popen(),
include(), require(), eval(), preg_replace(/e),
file_get_contents(), file_put_contents(), unlink(),
echo/print without escaping, unserialize(), extract(), parse_str()

**PHP-specific vulns:**
- Type juggling: "0e1234" == "0e5678"
- Variable variable injection: $$var
- Object injection via unserialize()
- LFI/RFI via include/require

Trace every $_GET/$_POST to dangerous sinks.
Call report_vulnerability with your findings.
"""


def build_compound_prompt(function_group: List[FunctionChunk], group_type: str = "compound") -> str:
    code_sections = []
    for chunk in function_group:
        class_info = ""
        if chunk.class_name:
            class_info = f" [class: {chunk.class_name}"
            if chunk.class_parents:
                class_info += f" extends {', '.join(chunk.class_parents)}"
            class_info += "]"
        annot_info = f"\n// Annotations: {' '.join(chunk.annotations)}" if chunk.annotations else ""
        taint_info = ""
        propagated = getattr(chunk, 'propagated_sources', [])
        if chunk.taint_sources or propagated:
            taint_info = f"\n// Taint sources: {(chunk.taint_sources + propagated)[:5]}"
        if chunk.taint_sinks:
            taint_info += f"\n// Taint sinks: {chunk.taint_sinks[:5]}"
        code_sections.append(f"""
### {chunk.function_name} ({chunk.file_path}{class_info}){annot_info}{taint_info}
```{chunk.language}
{chunk.code}
```""")

    if group_type == "taint_chain":
        group_desc = "TAINT CHAIN — these functions form a source→sink data flow path"
        analysis_focus = """
## Taint Chain Analysis

The static analysis engine has identified this as a potential source→sink chain.
Verify the complete data flow:

1. **Source**: Where does user-controlled data enter the chain?
2. **Propagation**: How does tainted data flow through each function?
3. **Sink**: Does tainted data reach a dangerous operation without sanitization?
4. **Bypass**: Can any sanitization in the middle be bypassed?
"""
    else:
        group_desc = "these functions work together in the same class/module"
        analysis_focus = """
## Compound Vulnerability Analysis

Find vulnerabilities that ONLY exist because of how these functions INTERACT:

1. **Chain Attacks** (A -> B -> C -> Goal): Does A's output become B's input?
2. **Auth Bypass Chains**: Unprotected path to reach protected resource?
3. **Second-Order**: Does A store data that B later executes?
4. **Race Conditions**: State corruption across function calls?
"""

    return f"""Analyze these MULTIPLE functions — {group_desc}.

{''.join(code_sections)}
{analysis_focus}
Do NOT classify each function individually.
Find compound vulnerabilities with attack_model.type = "compound", "second_order", or "injection".
Call report_vulnerability with your findings.
"""


# ===========================
# LLMクライアント
# ===========================
class VulnAnalyzer:

    def __init__(self):
        self.client = AsyncOpenAI(
            base_url=os.getenv("LLM_BASE_URL", LLM_BASE_URL),
            api_key=LLM_API_KEY,
        )
        self.model = LLM_MODEL

    async def analyze_chunk(
        self,
        chunk: FunctionChunk,
        prompt_type: str = "structural",
        cross_file: str = "",
    ) -> Optional[VulnSample]:
        """単一関数の解析"""
        if prompt_type == "structural":
            user_prompt = build_structural_prompt(chunk, cross_file)
        elif prompt_type == "attacker":
            user_prompt = build_attacker_prompt(chunk)
        elif prompt_type == "php":
            user_prompt = build_php_prompt(chunk)
        else:
            user_prompt = build_structural_prompt(chunk, cross_file)

        return await self._call_llm(user_prompt, chunk)

    async def analyze_compound(
        self,
        function_groups: List[List[FunctionChunk]],
    ) -> List[VulnSample]:
        """複合脆弱性解析"""
        results = []
        for group in function_groups:
            prompt = build_compound_prompt(group)
            result = await self._call_llm(prompt, group[0], is_compound=True, compound_group=group)
            if result and result.label.is_vulnerable:
                results.append(result)
        return results

    async def analyze_batch(
        self,
        chunks: List[FunctionChunk],
        progress_callback=None,
        omniscient: Optional["OmniscientContext"] = None,
    ) -> List[VulnSample]:
        """バッチ並列解析"""
        results = []
        uncertain = []
        total = len(chunks)

        for i in range(0, total, BATCH_SIZE):
            batch = chunks[i:i + BATCH_SIZE]

            tasks = []
            for chunk in batch:
                cross_file = omniscient.get_cross_file_context(chunk, max_chars=4000) if omniscient else ""
                if chunk.language == "php":
                    prompt_type = "php"
                elif chunk.priority >= 5:
                    prompt_type = "attacker"
                else:
                    prompt_type = "structural"
                tasks.append(self.analyze_chunk(chunk, prompt_type, cross_file=cross_file))

            batch_results = await asyncio.gather(*tasks)
            for r in batch_results:
                if r is None:
                    continue
                conf = r.context.confidence if r.context else 50
                if r.label.is_vulnerable:
                    if conf >= 40:
                        results.append(r)
                    else:
                        # confidence低いが脆弱性あり → uncertainリストへ
                        uncertain.append(r)

            done = min(i + BATCH_SIZE, total)
            if progress_callback:
                await progress_callback(done, total, len(results))
            else:
                print(f"[*] LLM解析: {done}/{total} | 確定候補: {len(results)}件 | 曖昧: {len(uncertain)}件")

        # uncertainをattributeとして保持（workerがreporterに渡す）
        self._uncertain = uncertain
        print(f"[+] LLM解析完了: {len(results)}件の確定候補 / {len(uncertain)}件の曖昧候補")
        return results

    async def _call_llm(
        self,
        user_prompt: str,
        chunk: FunctionChunk,
        is_compound: bool = False,
        compound_group: List[FunctionChunk] = None,
    ) -> Optional[VulnSample]:
        """
        tool calling（report_vulnerability）で構造化出力を強制してVulnSampleに変換
        """
        try:
            resp = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ],
                tools=[REPORT_TOOL],
                tool_choice={"type": "function", "function": {"name": "report_vulnerability"}},
                max_tokens=1500,
                temperature=0.1,
                extra_body={
                    "chat_template_kwargs": {"thinking": False},
                },
            )

            # tool_callsから引数を取り出す
            msg = resp.choices[0].message
            if not msg.tool_calls:
                # フォールバック: contentをJSONとして解析を試みる
                return self._parse_json_fallback(
                    msg.content or "", chunk, is_compound, compound_group
                )

            tc = msg.tool_calls[0]
            if tc.function.name != "report_vulnerability":
                return None

            data = json.loads(tc.function.arguments)
            return self._build_vuln_sample(data, chunk, is_compound, compound_group)

        except Exception as e:
            err_str = str(e)
            # トークン超過エラーの場合、プロンプトを削ってリトライ
            if "context length" in err_str or "input_tokens" in err_str or "400" in err_str:
                try:
                    truncated = user_prompt[:8000] + "\n...(truncated for context limit)"
                    resp = await self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user",   "content": truncated},
                        ],
                        tools=[REPORT_TOOL],
                        tool_choice={"type": "function", "function": {"name": "report_vulnerability"}},
                        max_tokens=1500,
                        temperature=0.1,
                        extra_body={"chat_template_kwargs": {"thinking": False}},
                    )
                    msg = resp.choices[0].message
                    if msg.tool_calls:
                        tc = msg.tool_calls[0]
                        if tc.function.name == "report_vulnerability":
                            data = json.loads(tc.function.arguments)
                            return self._build_vuln_sample(data, chunk, is_compound, compound_group)
                except Exception as e2:
                    print(f"  [-] LLMリトライ失敗 ({chunk.function_name}): {e2}")
            else:
                print(f"  [-] LLMエラー ({chunk.function_name}): {e}")
            return None

    def _build_vuln_sample(
        self,
        data: Dict,
        chunk: FunctionChunk,
        is_compound: bool = False,
        compound_group: List[FunctionChunk] = None,
    ) -> Optional[VulnSample]:
        """tool calling引数からVulnSampleを構築"""
        try:
            if not data.get("is_vulnerable", False):
                return None

            analysis  = data.get("analysis", {})
            attack    = data.get("attack_model", {})
            reasoning = data.get("reasoning", {})
            scenario  = data.get("attack_scenario", {})
            fix_data  = data.get("fix", {})

            return VulnSample(
                code=chunk.code,
                language=Language(chunk.language) if chunk.language in [l.value for l in Language] else Language.PYTHON,
                label=Label(
                    is_vulnerable=True,
                    severity=Severity(data["severity"]) if data.get("severity") else None,
                    cwe=data.get("cwe"),
                ),
                analysis=Analysis(
                    input=analysis.get("input", ""),
                    sink=analysis.get("sink", ""),
                    flow=analysis.get("flow", []),
                ),
                attack_model=AttackModel(
                    type=AttackType(attack.get("type", "injection")),
                    exploitability=Exploitability(attack.get("exploitability", "theoretical")),
                    assumption=attack.get("assumption", ""),
                ),
                reasoning=Reasoning(
                    why_vulnerable=reasoning.get("why_vulnerable", ""),
                    why_exploitable=reasoning.get("why_exploitable", ""),
                    false_positive_risk=reasoning.get("false_positive_risk", ""),
                ),
                attack_scenario=AttackScenario(
                    steps=scenario.get("steps", []),
                    result=scenario.get("result", ""),
                    poc_script=scenario.get("poc_script"),
                ),
                fix=Fix(
                    patch_type=PatchType(fix_data.get("patch_type", "input_validation")),
                    patched_code=fix_data.get("patched_code", ""),
                    explanation=fix_data.get("explanation", ""),
                ),
                context=Context(
                    file=chunk.file_path,
                    function=chunk.function_name,
                    codeql_confirmed=chunk.codeql_confirmed,
                    codeql_flow=chunk.codeql_flow,
                    is_compound=is_compound,
                    compound_functions=[c.function_name for c in (compound_group or [])],
                    confidence=int(data.get("confidence", 50)),
                ),
            )
        except Exception as e:
            print(f"  [-] VulnSample構築エラー: {e}")
            return None

    def _parse_json_fallback(
        self,
        raw: str,
        chunk: FunctionChunk,
        is_compound: bool = False,
        compound_group: List[FunctionChunk] = None,
    ) -> Optional[VulnSample]:
        """tool callingが使えない場合のJSONフォールバック（後方互換）"""
        try:
            raw = raw.strip()
            if "```" in raw:
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            data = json.loads(raw)
            return self._build_vuln_sample(data, chunk, is_compound, compound_group)
        except Exception as e:
            print(f"  [-] JSONフォールバックエラー: {e}")
            return None
