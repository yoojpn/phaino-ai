"""
LLM解析モジュール（最新版）
Qwen3.6-27B による構造推論・adversarial prompting
OpenAI tool callingで構造化出力を強制
"""

import os
import json
import asyncio
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
                "reason": {
                    "type": "string",
                    "description": "If is_vulnerable=false, explain why there is no real vulnerability",
                },
            },
            "required": ["is_vulnerable"],
        },
    },
}


# ===========================
# システムプロンプト
# ===========================
SYSTEM_PROMPT = """\
You are an elite security researcher and penetration tester.
Your goal is to find REAL, EXPLOITABLE vulnerabilities for bug bounty reports.

## Core Rules
1. NEVER rely on CVE classifications or known patterns alone
2. ALWAYS reason from code structure and data flow
3. Only report vulnerabilities where an attack ACTUALLY succeeds
4. Think as an attacker first, then verify as a defender
5. You MUST call the report_vulnerability tool with your findings
"""


# ===========================
# Prompt テンプレート
# ===========================

def build_structural_prompt(chunk: FunctionChunk, cross_file: str = "") -> str:
    codeql_section = ""
    if chunk.codeql_confirmed:
        codeql_section = f"""
## CodeQL Detection
CodeQL has confirmed a taint flow in this function:
{chr(10).join(chunk.codeql_flow[:5])}

Analyze WHY this flow is exploitable and design a specific payload.
"""

    return f"""Analyze this {chunk.language} code for security vulnerabilities.

## File: {chunk.file_path} (lines {chunk.start_line}-{chunk.end_line})
## Function: {chunk.function_name}

```{chunk.language}
{chunk.code}
```
{f"## Cross-file Context{chr(10)}{cross_file}" if cross_file else ""}
{codeql_section}

## Analysis Instructions

**CRITICAL: Do NOT reference CVE databases or known vulnerability patterns.**
**Reason purely from the code structure.**

**Step 1: Map all data sources**
What inputs does this function accept?
- HTTP parameters, headers, cookies, body
- Function arguments (are they user-controlled?)
- File reads, environment variables, database values

**Step 2: Trace every data path**
Follow each input through ALL transformations:
- String operations (concat, format, interpolation)
- Type conversions, conditional branches, function calls

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

**Step 6: Eliminate false positives**
Under what conditions does this NOT work?

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


def build_compound_prompt(function_group: List[FunctionChunk]) -> str:
    code_sections = []
    for chunk in function_group:
        code_sections.append(f"""
### {chunk.function_name} ({chunk.file_path})
```{chunk.language}
{chunk.code}
```""")

    return f"""Analyze these MULTIPLE functions that work together.

{''.join(code_sections)}

## Compound Vulnerability Analysis

Find vulnerabilities that ONLY exist because of how these functions INTERACT:

1. **Chain Attacks** (A -> B -> C -> Goal): Does A's output become B's input?
2. **Auth Bypass Chains**: Unprotected path to reach protected resource?
3. **Second-Order**: Does A store data that B later executes?
4. **Race Conditions**: State corruption across function calls?

Do NOT classify each function individually.
Find compound vulnerabilities with attack_model.type = "compound" or "second_order".
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
    ) -> List[VulnSample]:
        """バッチ並列解析"""
        results = []
        total = len(chunks)

        for i in range(0, total, BATCH_SIZE):
            batch = chunks[i:i + BATCH_SIZE]

            tasks = []
            for chunk in batch:
                if chunk.language == "php":
                    prompt_type = "php"
                elif chunk.priority <= 2 and chunk.codeql_confirmed:
                    prompt_type = "structural"
                elif chunk.priority >= 5:
                    prompt_type = "attacker"
                else:
                    prompt_type = "structural"
                tasks.append(self.analyze_chunk(chunk, prompt_type))

            batch_results = await asyncio.gather(*tasks)
            for r in batch_results:
                if r and r.label.is_vulnerable:
                    results.append(r)

            done = min(i + BATCH_SIZE, total)
            if progress_callback:
                await progress_callback(done, total, len(results))
            else:
                print(f"[*] LLM解析: {done}/{total} | 脆弱性候補: {len(results)}件")

        print(f"[+] LLM解析完了: {len(results)}件の脆弱性候補")
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
