"""
ReActループ - Project Naptime方式
LLMがOpenAI tool callingを使って自律的にツールを選択・実行し脆弱性を検証する
最大32ステップの多段階攻撃チェーンを構築
"""

import json
import asyncio
from typing import List, Dict, Optional, Any
from openai import AsyncOpenAI

from config import LLM_BASE_URL, LLM_MODEL, LLM_API_KEY, MAX_REACT_STEPS
from schema import VulnSample, Exploitability


# ===========================
# Tool定義（OpenAI tool calling形式）
# ===========================

TOOLS: List[Dict] = [
    {
        "type": "function",
        "function": {
            "name": "run_http_request",
            "description": (
                "Send an HTTP request with a crafted payload to the target application "
                "running in the Docker sandbox. Use to test injection, SSRF, auth bypass, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL, e.g. http://target:8080/api/endpoint"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
                    "payload": {"type": "string", "description": "Payload string (body or injected parameter)"},
                    "headers": {"type": "object", "description": "Additional HTTP headers", "additionalProperties": {"type": "string"}},
                },
                "required": ["url", "method"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sql_payload",
            "description": "Test a SQL injection payload against the vulnerable code in Docker with a real DB.",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "SQL injection payload, e.g. \"' OR 1=1-- \""},
                    "parameter": {"type": "string", "description": "The input parameter name to inject into"},
                },
                "required": ["payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command_injection",
            "description": "Test an OS command injection payload. Returns command output to confirm RCE.",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "Command injection payload, e.g. \"; id\" or \"| cat /etc/passwd\""},
                    "parameter": {"type": "string", "description": "The input parameter to inject into"},
                },
                "required": ["payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_path_traversal",
            "description": "Test a path traversal payload to read arbitrary files from the server filesystem.",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "Path traversal payload, e.g. \"../../etc/passwd\""},
                    "parameter": {"type": "string", "description": "The filename/path parameter to inject into"},
                },
                "required": ["payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ssrf_check",
            "description": "Test SSRF by making the target app request an internal endpoint. Returns response to confirm success.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Internal URL to target, e.g. http://169.254.169.254/latest/meta-data/"},
                    "parameter": {"type": "string", "description": "The URL input parameter to inject"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_xss_check",
            "description": "Test an XSS payload. Returns whether the payload was reflected/stored without sanitization.",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "XSS payload, e.g. \"<script>alert(1)</script>\""},
                    "parameter": {"type": "string", "description": "The input parameter to inject"},
                    "url": {"type": "string", "description": "Target endpoint URL"},
                },
                "required": ["payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_deserialization",
            "description": "Test a deserialization exploit payload (Python pickle, Java serialized object, PHP unserialize).",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "Base64-encoded serialized payload or raw payload string"},
                    "language": {"type": "string", "enum": ["python", "java", "php", "ruby"]},
                },
                "required": ["payload", "language"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_fuzzer",
            "description": "Run AFL++ fuzzer on the target function in Docker. Returns crash info if found within timeout.",
            "parameters": {
                "type": "object",
                "properties": {
                    "function_name": {"type": "string", "description": "Name of the function to fuzz"},
                    "seed_input": {"type": "string", "description": "Initial seed input for the fuzzer"},
                    "timeout": {"type": "integer", "description": "Fuzzer timeout in seconds", "default": 30},
                },
                "required": ["function_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_gdb",
            "description": "Analyze memory with GDB+pwndbg in Docker. Use to inspect crash state, validate ROP chains.",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "Input payload to send to the binary"},
                    "gdb_commands": {"type": "string", "description": "GDB commands after crash, e.g. \"bt\\ninfo registers\""},
                },
                "required": ["payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_asan",
            "description": "Run code with AddressSanitizer in Docker. Detects heap-buffer-overflow, use-after-free, stack-overflow.",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "Input payload to trigger the memory error"},
                },
                "required": ["payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "modify_payload",
            "description": "Refine the current payload based on the previous tool output. Use when the initial payload failed but gives hints.",
            "parameters": {
                "type": "object",
                "properties": {
                    "new_payload": {"type": "string", "description": "The improved payload to try next"},
                    "reason": {"type": "string", "description": "Why you are modifying the payload"},
                },
                "required": ["new_payload", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_exploit",
            "description": (
                "Call this when you have CONFIRMED the vulnerability is exploitable, "
                "OR when all approaches have failed. This ends the ReAct loop."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "confirmed": {"type": "boolean", "description": "True if exploit confirmed, False if all attempts failed"},
                    "working_exploit": {"type": "string", "description": "The final working exploit payload or script (null if failed)"},
                    "evidence": {"type": "string", "description": "Evidence that confirms the exploit worked (output snippet, crash info, etc.)"},
                    "impact": {"type": "string", "description": "What an attacker gains by exploiting this"},
                },
                "required": ["confirmed"],
            },
        },
    },
]


REACT_SYSTEM_PROMPT = """\
You are an autonomous security researcher with access to a Docker sandbox.
Your goal is to CONFIRM exploitability of a reported vulnerability by actually running exploits.

## Rules
1. Start with the most direct exploit based on the initial analysis
2. If a tool call fails, analyze the output and refine your payload
3. After each tool call, decide: retry with modified payload, try different tool, or report result
4. Call report_exploit when you are CERTAIN the vuln is confirmed OR all approaches have failed
5. Maximum steps: 32. Be efficient.

## Success Indicators by Attack Type
- SQLi    : Error messages, unexpected row counts, DB data in response
- RCE/CMDi: uid=0, command output, /etc/passwd contents
- LFI/PT  : root:x:0:0 in response
- SSRF    : Internal metadata or private IP responses
- XSS     : Unescaped payload in response body
- Memory  : heap-buffer-overflow, segfault, ASAN report
- Deserial: Command execution output
"""


class ReActLoop:

    def __init__(self, docker_executor=None, cpu_url: str = ""):
        self.client = AsyncOpenAI(
            base_url=LLM_BASE_URL,
            api_key=LLM_API_KEY,
        )
        self.model  = LLM_MODEL
        self.docker = docker_executor
        self.cpu_url = cpu_url  # CPUポッドのURL（exec/fuzz用）

    async def run_on_chunk(self, chunk, omniscient=None) -> Optional[VulnSample]:
        """
        FunctionChunkを直接受け取り、LLMが仮説→実行→検証するReActループを回す。
        VulnSampleを生成して返す（脆弱性なしの場合はNone）。
        """
        import httpx
        from schema import (
            VulnSample, VulnLabel, AttackModel, AttackScenario,
            VulnAnalysis, VulnReasoning, VulnContext, Exploitability,
            AttackType, Severity, Language,
        )
        from analyzer.llm import build_attacker_prompt

        fn = chunk.function_name
        lang = chunk.language
        print(f"[*] ReAct on chunk: {fn} ({lang})")

        # CPUポッドの /exec を叩くツールを動的に定義
        cpu_tools = [
            {
                "type": "function",
                "function": {
                    "name": "exec_code",
                    "description": "Execute Python/Shell/C++ code in the CPU sandbox and get the output. Use to test exploits, run scripts, check behavior.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "code": {"type": "string", "description": "Code to execute"},
                            "language": {"type": "string", "enum": ["python", "shell", "cpp", "c"], "description": "Language of the code"},
                            "stdin": {"type": "string", "description": "Optional stdin input"},
                        },
                        "required": ["code", "language"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "fuzz_function",
                    "description": "Run libFuzzer on a C/C++ function with a custom harness to find memory corruption bugs.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "harness_code": {"type": "string", "description": "libFuzzer LLVMFuzzerTestOneInput harness code"},
                            "source_code": {"type": "string", "description": "The target function source code to compile with the harness"},
                            "timeout": {"type": "integer", "description": "Fuzzing timeout in seconds", "default": 20},
                        },
                        "required": ["harness_code"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "report_finding",
                    "description": "Report whether a vulnerability was confirmed or not.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "vulnerable": {"type": "boolean"},
                            "cwe": {"type": "string", "description": "e.g. CWE-787"},
                            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                            "evidence": {"type": "string", "description": "Concrete evidence from tool output"},
                            "exploit_code": {"type": "string", "description": "Working exploit or PoC"},
                            "description": {"type": "string"},
                        },
                        "required": ["vulnerable"],
                    },
                },
            },
        ]

        cross_file = omniscient.get_cross_file_context(chunk, max_chars=3000) if omniscient else ""
        taint_info = ""
        if getattr(chunk, 'taint_sources', []) or getattr(chunk, 'taint_sinks', []):
            taint_info = f"\nTaint sources: {chunk.taint_sources}\nTaint sinks: {chunk.taint_sinks}"
        codeql_info = ""
        if getattr(chunk, 'codeql_confirmed', False):
            codeql_info = f"\nCodeQL finding: {chunk.codeql_flow}"

        system_prompt = """\
You are an expert vulnerability researcher. Analyze the given function and use the tools to:
1. Hypothesize a vulnerability based on the code
2. Write and execute exploit/test code to confirm it
3. For C/C++ memory bugs, use fuzz_function with a libFuzzer harness
4. Report your finding with report_finding

Be concrete and efficient. Maximum 16 steps."""

        user_msg = f"""## Function: {fn} in {chunk.file_path}

```{lang}
{chunk.code[:2000]}
```
{taint_info}{codeql_info}
{f"## Cross-file context{chr(10)}{cross_file}" if cross_file else ""}

Analyze this function for security vulnerabilities. Start with the most likely attack vector."""

        messages: List[Dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ]

        found_sample = None

        for step in range(16):
            try:
                resp = await self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=cpu_tools,
                    tool_choice="required",
                    max_tokens=1024,
                    temperature=0.1,
                    extra_body={"chat_template_kwargs": {"thinking": False}},
                )
            except Exception as e:
                print(f"  [-] ReAct LLMエラー: {e}")
                break

            assistant_msg = resp.choices[0].message
            messages.append(assistant_msg.model_dump(exclude_none=True))

            if not assistant_msg.tool_calls:
                break

            done = False
            for tc in assistant_msg.tool_calls:
                tool_name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}

                print(f"  → {tool_name}")

                if tool_name == "report_finding":
                    if args.get("vulnerable"):
                        from schema import Language as Lang
                        try:
                            lang_enum = Lang(lang)
                        except Exception:
                            lang_enum = Lang.PYTHON
                        found_sample = VulnSample(
                            code=chunk.code,
                            language=lang_enum,
                            label=VulnLabel(
                                is_vulnerable=True,
                                cwe=args.get("cwe", "CWE-Unknown"),
                                severity=Severity(args.get("severity", "medium")),
                            ),
                            attack_model=AttackModel(
                                type=AttackType.OVERFLOW if lang in ("c", "cpp") else AttackType.RCE,
                                exploitability=Exploitability.CONFIRMED if args.get("evidence") else Exploitability.PRACTICAL,
                            ),
                            attack_scenario=AttackScenario(
                                steps=[args.get("description", "")],
                                poc_script=args.get("exploit_code", ""),
                            ),
                            analysis=VulnAnalysis(
                                input="user input",
                                sink=chunk.function_name,
                                flow=[chunk.function_name],
                            ),
                            reasoning=VulnReasoning(
                                why_vulnerable=args.get("description", ""),
                                why_exploitable=args.get("evidence", ""),
                                false_positive_risk="",
                            ),
                            context=VulnContext(
                                function=chunk.function_name,
                                file=chunk.file_path,
                                confidence=80,
                            ),
                        )
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps({"status": "reported"}),
                    })
                    done = True
                    break

                elif tool_name == "exec_code" and self.cpu_url:
                    try:
                        async with httpx.AsyncClient(timeout=30) as client:
                            r = await client.post(f"{self.cpu_url}/exec", json={
                                "code": args.get("code", ""),
                                "language": args.get("language", "python"),
                                "stdin": args.get("stdin", ""),
                            })
                            result_data = r.json()
                            tool_result = f"stdout:\n{result_data.get('stdout', '')}\nstderr:\n{result_data.get('stderr', '')}\nreturncode: {result_data.get('returncode', -1)}"
                    except Exception as e:
                        tool_result = f"exec error: {e}"

                elif tool_name == "fuzz_function" and self.cpu_url:
                    try:
                        async with httpx.AsyncClient(timeout=60) as client:
                            r = await client.post(f"{self.cpu_url}/fuzz", json={
                                "harness_code": args.get("harness_code", ""),
                                "source_code": args.get("source_code", chunk.code),
                                "language": lang if lang in ("c", "cpp") else "cpp",
                                "timeout": args.get("timeout", 20),
                            })
                            result_data = r.json()
                            if result_data.get("crash_found"):
                                tool_result = f"CRASH FOUND:\n{result_data.get('crash_output', '')}"
                            else:
                                tool_result = f"No crash found.\n{result_data.get('output', '')}"
                    except Exception as e:
                        tool_result = f"fuzz error: {e}"

                else:
                    tool_result = f"tool {tool_name} unavailable (no cpu_url or unknown tool)"

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": str(tool_result)[:2000],
                })

                # クラッシュ自動検知
                if any(k in str(tool_result).lower() for k in [
                    "heap-buffer-overflow", "stack-buffer-overflow", "use-after-free",
                    "crash found", "segfault", "==error:"
                ]):
                    print(f"  [✓] ReAct自動クラッシュ検知: {fn}")
                    done = True
                    break

            if done:
                break

        return found_sample

    async def run(
        self,
        sample: VulnSample,
        max_steps: int = MAX_REACT_STEPS,
    ) -> VulnSample:
        """
        OpenAI tool callingを使ってReActループを実行。
        LLMが自律的にツールを選択し、脆弱性の成立をDockerで検証する。
        """
        fn = sample.context.function if sample.context else "unknown"
        print(f"[*] ReActループ開始: {fn} ({sample.label.cwe})")

        # 会話履歴（OpenAI messages形式）
        messages: List[Dict] = [
            {"role": "system", "content": REACT_SYSTEM_PROMPT},
            {"role": "user",   "content": self._build_initial_context(sample)},
        ]

        step_log: List[str] = []

        for step in range(max_steps):
            print(f"  Step {step + 1}/{max_steps}")

            # ===========================
            # LLMにツールコールを決定させる
            # ===========================
            try:
                resp = await self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=TOOLS,
                    tool_choice="required",   # 必ずいずれかのツールを呼ばせる
                    max_tokens=1024,
                    temperature=0.1,
                    extra_body={
                        "chat_template_kwargs": {"thinking": False},
                    },
                )
            except Exception as e:
                print(f"  [-] LLMエラー: {e}")
                break

            assistant_msg = resp.choices[0].message
            # アシスタントメッセージを履歴に追加
            messages.append(assistant_msg.model_dump(exclude_none=True))

            if not assistant_msg.tool_calls:
                print("  [-] tool_callsなし、ループ終了")
                break

            # ===========================
            # ツールコールを実行
            # ===========================
            all_done = False
            for tc in assistant_msg.tool_calls:
                tool_name = tc.function.name
                try:
                    tool_args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}

                print(f"  → {tool_name}({list(tool_args.keys())})")

                # --- report_exploit でループ終了 ---
                if tool_name == "report_exploit":
                    confirmed       = tool_args.get("confirmed", False)
                    working_exploit = tool_args.get("working_exploit")
                    evidence        = tool_args.get("evidence", "")
                    impact          = tool_args.get("impact", "")

                    if confirmed:
                        sample.attack_model.exploitability = Exploitability.CONFIRMED
                        if working_exploit:
                            sample.attack_scenario.poc_script = working_exploit
                        print(f"  [✓] Exploit確認: {evidence[:120]}")
                    else:
                        print(f"  [-] Exploit失敗: {evidence[:120]}")

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps({"status": "reported", "confirmed": confirmed, "impact": impact}),
                    })
                    all_done = True
                    break

                # --- 通常ツール実行 ---
                tool_result = await self._dispatch_tool(tool_name, tool_args, sample)
                step_log.append(
                    f"Step {step+1}: {tool_name}({json.dumps(tool_args)[:100]}) → {tool_result[:200]}"
                )

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": str(tool_result),
                })

                # 自動成功検知（保険）
                if self._is_goal_achieved(tool_result, sample):
                    sample.attack_model.exploitability = Exploitability.CONFIRMED
                    print(f"  [✓] 自動検知成功: Step {step+1}")
                    all_done = True
                    break

            if all_done:
                break

        # ステップ履歴をattack_scenarioに反映
        if step_log:
            sample.attack_scenario.steps = step_log

        return sample

    # ===========================
    # ツールディスパッチャー
    # ===========================

    async def _dispatch_tool(self, tool_name: str, args: Dict[str, Any], sample: VulnSample) -> str:
        code     = sample.code
        language = sample.language.value

        try:
            if tool_name == "run_http_request":
                return await self.docker.run_http_request(
                    url=args.get("url", "http://target:8080/"),
                    method=args.get("method", "GET"),
                    payload=args.get("payload", ""),
                    headers=args.get("headers", {}),
                )
            elif tool_name == "run_sql_payload":
                return await self.docker.run_sql_test(
                    code=code, language=language,
                    payload=args.get("payload", "' OR 1=1--"),
                )
            elif tool_name == "run_command_injection":
                return await self.docker.run_cmd_test(
                    code=code, language=language,
                    payload=args.get("payload", "; id"),
                )
            elif tool_name == "run_path_traversal":
                return await self.docker.run_path_test(
                    code=code, language=language,
                    payload=args.get("payload", "../../etc/passwd"),
                )
            elif tool_name == "run_ssrf_check":
                return await self.docker.run_ssrf_test(
                    code=code, language=language,
                    url=args.get("url", "http://169.254.169.254/"),
                )
            elif tool_name == "run_xss_check":
                return await self.docker.run_http_request(
                    url=args.get("url", "http://target:8080/"),
                    method="GET",
                    payload=args.get("payload", "<script>alert(1)</script>"),
                    headers={},
                )
            elif tool_name == "run_deserialization":
                return await self.docker.run_code_in_docker(
                    code=code,
                    language=args.get("language", language),
                )
            elif tool_name == "run_fuzzer":
                return await self.docker.run_afl(
                    code=code, language=language,
                    function=args.get("function_name", "target"),
                    timeout=args.get("timeout", 30),
                )
            elif tool_name == "run_gdb":
                return await self._run_with_llm_fix(
                    "run_gdb", code, language,
                    lambda c: self.docker.run_gdb(code=c, payload=args.get("payload", "")),
                    sample,
                )
            elif tool_name == "run_asan":
                return await self._run_with_llm_fix(
                    "run_asan", code, language,
                    lambda c: self.docker.run_asan(code=c, language=language, payload=args.get("payload", "")),
                    sample,
                )
            elif tool_name == "modify_payload":
                return f"Payload updated to: {args.get('new_payload', '')} (reason: {args.get('reason', '')})"
            else:
                return f"Unknown tool: {tool_name}"

        except Exception as e:
            return f"Tool execution error ({tool_name}): {e}"

    # ===========================
    # LLMコード修正＋再試行
    # ===========================

    async def _run_with_llm_fix(
        self,
        tool_name: str,
        code: str,
        language: str,
        executor,
        sample: VulnSample,
        max_retries: int = 2,
    ) -> str:
        """ツール実行が失敗したらLLMにコードを修正させて再試行する"""
        current_code = code
        last_result = ""

        for attempt in range(max_retries + 1):
            result = await executor(current_code)
            last_result = result

            # 成功判定: エラーなし かつ 空でない
            error_keywords = ["error", "Error", "fatal", "No such file", "Traceback", "cc1:"]
            is_error = any(kw in result for kw in error_keywords) or result.strip() == ""

            if not is_error:
                return result

            if attempt >= max_retries:
                break

            print(f"  [!] {tool_name} 失敗 (attempt {attempt+1}), LLMに修正依頼...")

            # LLMにコード修正を依頼
            try:
                fix_resp = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": (
                            "You are a security exploit code fixer. "
                            "Fix the given code so it compiles and runs correctly in a Linux Docker environment. "
                            "Return ONLY the fixed code, no explanation, no markdown fences."
                        )},
                        {"role": "user", "content": (
                            f"Tool: {tool_name}\n"
                            f"Language: {language}\n"
                            f"Error output:\n{result[:500]}\n\n"
                            f"Original code:\n{current_code}\n\n"
                            f"Fix the code to eliminate the error and make it runnable."
                        )},
                    ],
                    max_tokens=1024,
                    temperature=0.2,
                    extra_body={"chat_template_kwargs": {"thinking": False}},
                )
                fixed_code = fix_resp.choices[0].message.content.strip()
                # マークダウンフェンス除去
                if fixed_code.startswith("```"):
                    lines = fixed_code.split("\n")
                    fixed_code = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
                current_code = fixed_code
                print(f"  [→] コード修正完了 ({len(fixed_code)} chars)")
            except Exception as e:
                print(f"  [!] LLM修正失敗: {e}")
                break

        return last_result

    # ===========================
    # ヘルパー
    # ===========================

    def _build_initial_context(self, sample: VulnSample) -> str:
        ctx = sample.context
        return f"""\
## Target Vulnerability

CWE       : {sample.label.cwe}
Severity  : {sample.label.severity.value if sample.label.severity else 'unknown'}
Function  : {ctx.function if ctx else 'unknown'}
File      : {ctx.file if ctx else 'unknown'}

## Static Analysis Findings

Why vulnerable  : {sample.reasoning.why_vulnerable[:400]}
Why exploitable : {sample.reasoning.why_exploitable[:400]}
False positive? : {sample.reasoning.false_positive_risk[:200]}

## Data Flow

Source : {sample.analysis.input}
Sink   : {sample.analysis.sink}
Flow   : {' -> '.join(sample.analysis.flow)}

## Suggested Attack Scenario

{chr(10).join(f'  {i+1}. {s}' for i, s in enumerate(sample.attack_scenario.steps))}

## Vulnerable Code

```{sample.language.value}
{sample.code[:1500]}
```

Start by running the most direct exploit. Use the tools to confirm or deny exploitability.
"""

    def _is_goal_achieved(self, result: str, sample: VulnSample) -> bool:
        """ツール出力から成功を自動検知（report_exploitを呼ばなかった場合の保険）"""
        r = result.lower()
        patterns = [
            "root:", "uid=0", "uid=",
            "error in your sql syntax",
            "root:x:0:0",
            "aws_secret_access_key",
            "169.254.169.254",
            "segmentation fault",
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "use-after-free",
            "crash detected",
            "<script>alert",
        ]
        return any(p in r for p in patterns)
