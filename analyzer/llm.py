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
                    "description": "Confidence score 0-100. 0=definitely false positive, 100=certain exploit. Score below 25 means uncertain.",
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
You are an elite security researcher specializing in bug bounty hunting and finding novel, unknown vulnerabilities.
Your goal is to find REAL vulnerabilities including novel bugs that have never been seen before.

## Core Rules
1. NEVER rely on CVE classifications or known patterns alone — look for NEW vulnerability classes
2. ALWAYS reason from code structure and data flow
3. Report vulnerabilities where an attack is PLAUSIBLE, not just certain — bug bounty rewards go to finders, not perfectionists
4. Think as an attacker first, then verify as a defender
5. You MUST call the report_vulnerability tool with your findings
6. You MUST fill adversarial_check: argue why this is NOT a vulnerability, then conclude
7. You MUST assign confidence (0-100): below 25 = false positive territory
8. Cross-file context is provided — use it to trace data flows across function boundaries
9. Look for: memory corruption, UAF, type confusion, integer overflow/underflow, OOB read/write,
   business logic bugs, TOCTOU, second-order injections, compound auth bypass,
   JIT compiler bugs, garbage collector bugs, parser differentials
10. For C/C++: pay special attention to pointer arithmetic, buffer bounds, integer conversions,
    use-after-free, double-free, uninitialized memory
11. For JS engines (JavaScriptCore, V8): look for type confusion, JIT optimization bugs,
    speculative execution issues, prototype pollution paths
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
- 40-69: Plausible attack path, some uncertainty (→ uncertain report, still valuable)
- 25-39: Weak signal but worth flagging (→ uncertain report)
- 0-24: Likely false positive (→ skip)

Call report_vulnerability with your complete findings.
"""


def build_attacker_prompt(chunk: FunctionChunk, cross_file: str = "") -> str:
    cross_file_section = f"\n## Cross-file Context\n{cross_file}\n" if cross_file else ""
    taint_section = ""
    if getattr(chunk, 'taint_sources', []) or getattr(chunk, 'taint_sinks', []):
        taint_section = f"\n## Taint Info\nSources: {chunk.taint_sources}\nSinks: {chunk.taint_sinks}\n"
    codeql_section = ""
    if getattr(chunk, 'codeql_confirmed', False):
        codeql_section = f"\n## CodeQL Finding\n{chunk.codeql_flow}\n"

    if chunk.language in ("cpp", "c"):
        cpp_section = """
## C/C++ Specific Attack Vectors
1. **Buffer overflow**: array indexing without bounds check, memcpy with attacker-controlled length
2. **Integer overflow/underflow**: size_t arithmetic, signed/unsigned conversion, multiplication before malloc
3. **Use-after-free**: object freed then accessed, dangling pointers, iterator invalidation
4. **Type confusion**: casting between incompatible types, union misuse, vtable corruption
5. **Format string**: printf/sprintf with user-controlled format argument
6. **Double-free**: same pointer freed twice, especially in error paths
7. **Uninitialized memory**: stack variables used before assignment, partial struct init
8. **OOB read/write**: pointer arithmetic beyond allocation bounds
9. **Race conditions (TOCTOU)**: check-then-use on shared state without lock

For JS engine code (JavaScriptCore/V8/SpiderMonkey):
- Type confusion via speculative JIT optimization
- GC unsafety: JSValue roots not protected during allocation
- Incorrect cell type assumptions after optimization
- Prototype chain manipulation leading to wrong property access
"""
    else:
        cpp_section = ""

    return f"""You are an experienced bug bounty hunter targeting this {chunk.language} code.

## Function: {chunk.function_name} in {chunk.file_path}

```{chunk.language}
{chunk.code}
```
{taint_section}{codeql_section}{cross_file_section}{cpp_section}
## Task
Find exploitable bugs. Novel, unknown vulnerabilities are just as valuable as known classes.
Look at the RAW STRUCTURE and data flow.

1. What can an attacker CONTROL (directly or indirectly)?
2. Where does attacker-controlled data GO? Trace every path.
3. What happens at BOUNDARY CONDITIONS (0, -1, MAX_INT, empty, null)?
4. Are there STATE or ORDERING issues?
5. Are there implicit assumptions that can be violated?

Design a specific attack if you find something.
Call report_vulnerability with your findings (is_vulnerable=false if nothing exploitable found).
"""


def build_semantic_prompt(chunk: FunctionChunk, callers: List[str] = None, callees: List[str] = None, cross_file: str = "") -> str:
    """
    意味論的矛盾プロンプト - 上級バグハンター向け
    パターンマッチではなく「コードが何を約束しているか vs 実際に何をしているか」のギャップを探す
    """
    caller_section = ""
    if callers:
        caller_section = "\n## Caller functions (these TRUST this function's behavior)\n" + "\n".join(f"- {c}" for c in callers[:8])
    callee_section = ""
    if callees:
        callee_section = "\n## Callee functions (called by this function)\n" + "\n".join(f"- {c}" for c in callees[:8])
    cross_section = f"\n## Cross-file Context\n{cross_file}\n" if cross_file else ""

    taint_section = ""
    if getattr(chunk, 'taint_sources', []) or getattr(chunk, 'taint_sinks', []):
        taint_section = f"\n## Taint Info\nSources: {chunk.taint_sources}\nSinks: {chunk.taint_sinks}\n"

    if chunk.language in ("cpp", "c"):
        lang_phase = """
### Phase 7: C/C++ Memory Safety (semantic level)
Beyond simple buffer overflows — look for SEMANTIC memory bugs:
- **Ownership confusion**: Who is responsible for freeing this memory? Can double-free happen?
- **Lifetime violation**: Is there a path where a reference outlives the object?
- **Size semantic mismatch**: Does `size` mean bytes here but elements elsewhere in callers?
- **Signed/unsigned contract violation**: Does the caller pass a signed value the callee treats as unsigned?
- **NULL dereference after "guaranteed" non-null**: Code that assumes a prior check guarantees non-null, but there's a path that skips the check
- **Iterator/pointer invalidation**: Container modified while iterating
- **Exception safety**: In C++ with exceptions, does partial construction leave memory in inconsistent state?
"""
    else:
        lang_phase = ""

    return f"""You are an expert vulnerability researcher. Find bugs that tools and humans MISS — semantic contradictions, logic bugs, implicit assumption violations.

## `{chunk.function_name}` in `{chunk.file_path}`
```{chunk.language}
{chunk.code}
```
{taint_section}{caller_section}{callee_section}{cross_section}{lang_phase}
## Analysis
1. What does this function CONTRACT to do (name/comments/caller assumptions) vs what it ACTUALLY does?
2. What INVARIANTS must hold after return — can any be broken by attacker input?
3. Trace every ERROR PATH — what state is left on mid-way failure?
4. What IMPLICIT ASSUMPTIONS exist (no overflow, pointer valid, lock held) — which can be violated?
5. If vulnerable: exact trigger, sequence, outcome, why a reviewer would miss it.

Confidence 30+ = report it. Call report_vulnerability.
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

Find vulnerabilities that ONLY exist because of how these functions INTERACT.
Single-function analysis will miss these. Think in SEQUENCES and STATES.

### Attack Sequence Analysis (A → B → C)
1. Can you call these functions in an unexpected ORDER?
2. Does Function A set up state that Function B misuses?
3. Does Function A's output become Function B's unsanitized input?
4. Can you interleave calls to corrupt shared state?

### State Machine Exploitation
- What STATES can each object/resource be in?
- Are there ILLEGAL state transitions an attacker can force?
- Is there a state where invariants break (e.g., initialized=true but buffer=null)?
- Can you force a PARTIAL state (e.g., half-initialized, half-freed)?

### Second-Order Attacks
- Does Function A STORE data that Function B later EXECUTES or TRUSTS?
- Is there a time gap between store and use where state can be corrupted?

### Resource/Error Interaction
- What happens if Function A fails halfway and Function B runs on partial state?
- Can resource exhaustion (OOM, disk full) trigger an exploitable path?

### Caller Trust Violations
- Does Caller C assume Functions A+B together guarantee some property?
- Can an attacker violate that guarantee without Caller C noticing?

Design a specific multi-step attack sequence if found.
"""

    return f"""Analyze these MULTIPLE functions — {group_desc}.

{''.join(code_sections)}
{analysis_focus}
Do NOT classify each function individually.
Find compound vulnerabilities with attack_model.type = "compound", "second_order", or "injection".
Call report_vulnerability with your findings.
"""


# ===========================
# Spec-guided prompt (NDSS 2025)
# ===========================

def build_spec_prompt(chunk: FunctionChunk, cross_file: str = "") -> str:
    """
    Specification-guided vulnerability detection (NDSS 2025方式)
    precondition/postconditionを推論してから実装との乖離を探す
    """
    taint_section = ""
    if getattr(chunk, 'taint_sources', []) or getattr(chunk, 'taint_sinks', []):
        taint_section = f"\n// Taint: src={chunk.taint_sources[:3]} sink={chunk.taint_sinks[:3]}"
    codeql_section = f"\n// CodeQL: {chunk.codeql_flow}" if getattr(chunk, 'codeql_confirmed', False) else ""
    cross_section = f"\n## Context\n{cross_file}" if cross_file else ""

    return f"""You are a formal-methods-aware security researcher.

## `{chunk.function_name}` ({chunk.file_path}){taint_section}{codeql_section}
```{chunk.language}
{chunk.code}
```{cross_section}

## Step 1 — Infer Specification
- Preconditions: what must be TRUE when this function is called?
- Postconditions: what must be TRUE when this function returns?
- Invariants: what must hold throughout execution?
- Implicit contracts: what do callers assume this function guarantees?

## Step 2 — Find Spec Violations
For each precondition: is there a path where it's NOT enforced?
For each postcondition: is there a path where it's NOT satisfied?
Can an attacker trigger a partial failure that leaves broken state?

## Step 3 — Exploit Design
Exact input that violates the spec → what does the attacker gain (UAF/OOB/auth bypass/etc)?

Confidence 35+ = report. Call report_vulnerability.
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
        callers: List[str] = None,
        callees: List[str] = None,
    ) -> Optional[VulnSample]:
        """単一関数の解析"""
        if prompt_type == "structural":
            user_prompt = build_structural_prompt(chunk, cross_file)
        elif prompt_type == "attacker":
            user_prompt = build_attacker_prompt(chunk, cross_file)
        elif prompt_type == "semantic":
            user_prompt = build_semantic_prompt(chunk, callers=callers, callees=callees, cross_file=cross_file)
        elif prompt_type == "spec":
            user_prompt = build_spec_prompt(chunk, cross_file)
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
        """バッチ並列解析 - セマフォでvLLMのmax_num_seqsに合わせた同時実行数制限"""
        results = []
        uncertain = []
        total = len(chunks)
        # vLLMのmax_num_seqs=32に合わせて同時リクエスト数を制限
        # 多すぎるとKVキャッシュが溢れてスループットが下がる
        sem = asyncio.Semaphore(64)

        async def _analyze_with_sem(chunk, prompt_type, cross_file, callers, callees):
            async with sem:
                return await self.analyze_chunk(chunk, prompt_type, cross_file=cross_file, callers=callers, callees=callees)

        tasks = []
        # 関数名パターン（spec-guidedが効く関数種別）
        SPEC_PATTERNS = re.compile(
            r'(valid|sanitiz|check|verify|auth|ensure|assert|guard|enforce|init|setup|create|alloc|parse|decode|deserializ)',
            re.IGNORECASE
        )
        # 攻撃者視点が効く危険シンク関連パターン
        ATTACKER_PATTERNS = re.compile(
            r'(exec|eval|query|render|send|write|copy|memcpy|sprintf|format|request|response|upload|download|open|read|recv)',
            re.IGNORECASE
        )
        for chunk in chunks:
            cross_file = omniscient.get_cross_file_context(chunk, max_chars=6000) if omniscient else ""
            callers = list(omniscient.reverse_graph.get(chunk.function_name, []))[:8] if omniscient else []
            callees = list(omniscient.call_graph.get(chunk.function_name, []))[:8] if omniscient else []

            has_taint = getattr(chunk, 'propagated_sources', []) and chunk.taint_sinks
            fn = chunk.function_name

            if chunk.language == "php":
                prompt_type = "php"
            elif getattr(chunk, 'codeql_confirmed', False):
                # CodeQL確認済み → attacker（実証パス確認）
                prompt_type = "attacker"
            elif has_taint and chunk.priority >= 6:
                # taintパス確認済み + 高priority → semantic（意味論的矛盾を深掘り）
                prompt_type = "semantic"
            elif has_taint:
                # taintパスあり → attacker（データフロー追跡）
                prompt_type = "attacker"
            elif SPEC_PATTERNS.search(fn):
                # validate/auth/parse系 → spec（仕様違反を探す）
                prompt_type = "spec"
            elif ATTACKER_PATTERNS.search(fn) or chunk.language in ("c", "cpp"):
                # 危険シンク系 or C/C++ → attacker
                prompt_type = "attacker"
            elif chunk.priority >= 6:
                # 高priority → semantic
                prompt_type = "semantic"
            elif chunk.priority >= 3:
                prompt_type = "attacker"
            else:
                prompt_type = "structural"
            tasks.append(_analyze_with_sem(chunk, prompt_type, cross_file, callers, callees))

        # 全タスクを一気に投げてセマフォで流量制御
        done_count = 0
        for coro in asyncio.as_completed(tasks):
            r = await coro
            done_count += 1
            if r is None:
                pass
            else:
                conf = r.context.confidence if r.context else 50
                if r.label.is_vulnerable:
                    if conf >= 40:
                        results.append(r)
                    else:
                        uncertain.append(r)

            if progress_callback and done_count % 10 == 0:
                await progress_callback(done_count, total, len(results))
            elif done_count % 50 == 0:
                print(f"[*] LLM解析: {done_count}/{total} | 確定候補: {len(results)}件 | 曖昧: {len(uncertain)}件")

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
        thinkingなし・max_tokens=700でコストを最小化しつつ精度を維持
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
                max_tokens=700,
                temperature=0.1,
                extra_body={"chat_template_kwargs": {"thinking": False}},
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
                        max_tokens=700,
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


# ===========================
# Mythosスタイル: 検証エージェント（セカンドパス）
# ===========================

VERIFICATION_SYSTEM_PROMPT = """\
You are a senior security triager. You receive a vulnerability report and must decide:
1. Is this a REAL, exploitable vulnerability?
2. Is it interesting and high-severity enough to report?

Be skeptical. False positives waste time. Only approve bugs that:
- Have a clear, realistic attack path
- Affect real users in real scenarios
- Are not mitigated by framework/middleware

Respond with JSON only: {"approved": true/false, "reason": "...", "adjusted_severity": "critical|high|medium|low|none"}
"""

async def verify_finding(
    client,
    model: str,
    sample: VulnSample,
) -> tuple[bool, str]:
    """
    Mythosスタイルの検証エージェント。
    発見した脆弱性に対して「本当に重要か？」を確認してFPを除去する。
    """
    report_text = f"""## Bug Report

Function: {sample.context.function if sample.context else "unknown"}
File: {sample.context.file if sample.context else "unknown"}
CWE: {sample.label.cwe if sample.label else "unknown"}
Severity: {sample.label.severity.value if sample.label and sample.label.severity else "unknown"}

Why vulnerable: {sample.reasoning.why_vulnerable[:500] if sample.reasoning else ""}
Why exploitable: {sample.reasoning.why_exploitable[:300] if sample.reasoning else ""}
False positive risk: {sample.reasoning.false_positive_risk[:200] if sample.reasoning else ""}

Attack steps:
{chr(10).join(f"  {i+1}. {s}" for i, s in enumerate((sample.attack_scenario.steps or [])[:5]))}

Code (excerpt):
```
{sample.code[:600]}
```
"""
    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": VERIFICATION_SYSTEM_PROMPT},
                {"role": "user", "content": f"Please triage this bug report:\n\n{report_text}"},
            ],
            max_tokens=300,
            temperature=0.1,
            extra_body={"chat_template_kwargs": {"thinking": False}},
        )
        import re as _re
        raw = resp.choices[0].message.content or ""
        raw = _re.sub(r"<think>.*?</think>", "", raw, flags=_re.DOTALL).strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()
        data = json.loads(raw)
        approved = data.get("approved", True)
        reason = data.get("reason", "")
        adj_sev = data.get("adjusted_severity", "")
        # severityを調整
        if adj_sev and adj_sev != "none" and sample.label:
            try:
                sample.label.severity = Severity(adj_sev)
            except Exception:
                pass
        return approved, reason
    except Exception as e:
        # 検証エラーは保守的にapprove
        return True, f"verification error: {e}"



# ===========================
# 軽量FPプレフィルタ（2段階検証の第1段）
# ===========================

QUICK_FP_PROMPT = """\
You are a fast false-positive filter. Given a bug report, answer in JSON only:
{"is_fp": true/false, "reason": "one sentence"}

Mark as FP (is_fp=true) ONLY if:
- The dangerous sink is clearly unreachable from user input
- The "vulnerability" is in dead code or test-only code
- There is an obvious framework/middleware that fully mitigates it

If uncertain, mark is_fp=false (keep it for deeper review).
"""

async def quick_fp_check(
    client,
    model: str,
    sample: VulnSample,
) -> bool:
    """
    max_tokens=150の軽量FPチェック。
    明らかなFPを重いverify_findingの前に除去する。
    戻り値: True=FPではない(keep) / False=FP(drop)
    """
    snippet = f"Function: {sample.context.function if sample.context else '?'}\n"
    snippet += f"Why vulnerable: {sample.reasoning.why_vulnerable[:300] if sample.reasoning else ''}\n"
    snippet += f"False positive risk: {sample.reasoning.false_positive_risk[:200] if sample.reasoning else ''}\n"
    snippet += f"Code:\n```\n{sample.code[:400]}\n```"
    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": QUICK_FP_PROMPT},
                {"role": "user", "content": snippet},
            ],
            max_tokens=150,
            temperature=0.0,
            extra_body={"chat_template_kwargs": {"thinking": False}},
        )
        raw = resp.choices[0].message.content or ""
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        m = re.search(r"\{.*?\}", raw, re.DOTALL)
        if m:
            data = json.loads(m.group(0))
            if data.get("is_fp", False):
                print(f"  [quick-FP] drop: {sample.context.function if sample.context else '?'} — {data.get('reason','')[:80]}")
                return False
    except Exception:
        pass
    return True


async def verify_findings_batch(
    client,
    model: str,
    samples: List[VulnSample],
) -> List[VulnSample]:
    """
    2段階FP除去:
    Stage1: quick_fp_check (max_tokens=150) で明らかなFPを高速除去
    Stage2: verify_finding (max_tokens=300) で残りを深くトリアージ
    Mythosの「最後にエージェントを走らせて重要度が低いものを除外」に相当。
    """
    if not samples:
        return samples

    print(f"[*] Stage1 軽量FPフィルタ: {len(samples)}件...")
    stage1_tasks = [quick_fp_check(client, model, s) for s in samples]
    stage1_results = await asyncio.gather(*stage1_tasks, return_exceptions=True)
    after_stage1 = [s for s, keep in zip(samples, stage1_results)
                    if not isinstance(keep, Exception) and keep]
    dropped_stage1 = len(samples) - len(after_stage1)
    print(f"[*] Stage1完了: {dropped_stage1}件除去 → {len(after_stage1)}件残存")

    print(f"[*] Stage2 詳細検証: {len(after_stage1)}件をセカンドパスで確認...")
    tasks = [verify_finding(client, model, s) for s in after_stage1]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    approved = []
    rejected = 0
    for sample, result in zip(after_stage1, results):
        if isinstance(result, Exception):
            approved.append(sample)
            continue
        ok, reason = result
        if ok:
            approved.append(sample)
        else:
            rejected += 1
            print(f"  [-] Stage2リジェクト: {sample.context.function if sample.context else '?'} — {reason[:80]}")

    print(f"[+] 検証完了: {len(approved)}件承認 / {dropped_stage1+rejected}件リジェクト")
    return approved


# ===========================
# Mythosスタイル: ファイルランキングエージェント
# ===========================

FILE_RANKING_SYSTEM_PROMPT = """\
You are a security researcher prioritizing files for vulnerability analysis.
Rate each file on a scale of 1-5 based on how likely it is to contain security vulnerabilities:

5 = Very likely: handles user input, authentication, file I/O, network, crypto, memory management
4 = Likely: data processing, serialization, database access, config parsing
3 = Possible: business logic, API endpoints, middleware
2 = Unlikely: utility functions, helpers, constants
1 = Very unlikely: tests, documentation, pure data definitions, generated code

Respond with JSON only: {"rankings": {"filename": score, ...}}
"""

async def rank_files_by_risk(
    client,
    model: str,
    file_list: List[str],
) -> dict:
    """
    Mythosと同じ戦略: 解析前にファイルを1-5でスコアリングして高リスクから優先解析。
    最大50ファイルを一括ランキングする（それ以上は複数バッチに分割）。
    """
    if not file_list:
        return {}

    rankings = {}
    batch_size = 50
    for i in range(0, len(file_list), batch_size):
        batch = file_list[i:i + batch_size]
        files_str = "\n".join(f"- {f}" for f in batch)
        try:
            resp = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": FILE_RANKING_SYSTEM_PROMPT},
                    {"role": "user", "content": f"Rate these files for security vulnerability likelihood:\n{files_str}"},
                ],
                max_tokens=500,
                temperature=0.0,
                extra_body={"chat_template_kwargs": {"thinking": False}},
            )
            raw = resp.choices[0].message.content or ""
            # thinking タグを除去
            import re as _re
            raw = _re.sub(r"<think>.*?</think>", "", raw, flags=_re.DOTALL).strip()
            # ```json ... ``` ブロックを抽出
            m = _re.search(r"```(?:json)?\s*([\s\S]+?)```", raw)
            if m:
                raw = m.group(1).strip()
            # JSONオブジェクト部分だけ抽出
            m2 = _re.search(r"\{[\s\S]+\}", raw)
            if m2:
                raw = m2.group(0)
            if not raw:
                continue
            data = json.loads(raw)
            rankings.update(data.get("rankings", {}))
        except Exception as e:
            print(f"  [-] ファイルランキングエラー: {e}")

    return rankings
