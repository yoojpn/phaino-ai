"""
パーサーレイヤー - tree-sitter AST解析 + 優先度付け（最新版）

優先度設計（1が最高・10が最低）:
  1: CodeQL証明済み + source+sink
  2: source+sink両方あり（高スコア）
  3〜5: 一般関数
  6〜8: テストコード
  9: サードパーティ・無名関数
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

from config import LANGUAGE_PRIORITY, MAX_FUNCTION_TOKENS

# ===========================
# 優先度判定パターン
# ===========================

# 危険なsink
HIGH_PRIORITY_SINK_PATTERNS = [
    r"execute\s*\(", r"cursor\.", r"\.query\s*\(", r"mysql_query",
    r"pg_query", r"sqlite3", r"\.raw\s*\(",
    r"os\.system", r"subprocess\.", r"exec\s*\(", r"eval\s*\(",
    r"Runtime\.exec", r"ProcessBuilder", r"popen\s*\(",
    r"pickle\.loads", r"unserialize\s*\(", r"ObjectInputStream",
    r"yaml\.load\s*\(", r"marshal\.loads",
    r"open\s*\(", r"readFile", r"writeFile",
    r"include\s*\(", r"require\s*\(", r"file_get_contents",
    r"requests\.get", r"requests\.post", r"urllib\.request",
    r"http\.get\s*\(", r"fetch\s*\(",
    r"innerHTML", r"document\.write", r"echo\s+\$",
    r"render_template_string", r"Template\s*\(",
    r"password", r"token", r"secret", r"api_key", r"apikey",
]

# ユーザー入力のsource
HIGH_PRIORITY_SOURCE_PATTERNS = [
    r"request\.", r"req\.", r"\$_GET", r"\$_POST", r"\$_REQUEST",
    r"getParameter", r"getHeader", r"getCookie",
    r"argv\[", r"sys\.argv", r"input\s*\(",
    r"body\[", r"params\[", r"query\[",
    r"formData", r"req\.body", r"req\.query", r"req\.params",
    r"flask\.request", r"request\.form", r"request\.args",
]

# 重要な関数名
HIGH_PRIORITY_FUNC_NAMES = {
    "login", "auth", "authenticate", "authorize", "verify",
    "checkauth", "checkpermission", "checktoken", "verifytoken",
    "checksession", "validatetoken", "verifyjwt", "decodetoken",
    "query", "execute", "select", "insert", "update", "delete",
    "find", "search", "fetch", "get", "load",
    "upload", "download", "read", "write", "open", "save",
    "readfile", "writefile", "include", "require",
    "request", "fetch", "send", "post", "put",
    "redirect", "forward", "proxy",
    "exec", "eval", "run", "invoke", "call",
    "deserialize", "unserialize", "unpickle",
    "render", "template", "compile",
    "handle", "process", "parse", "validate", "sanitize",
}

# サードパーティ判定
LOW_PRIORITY_FILE_PATTERNS = [
    r"/js/[^/]+\.js$", r"/static/[^/]+\.js$", r"/assets/[^/]+\.js$",
    r"/vendor/", r"/plugins/", r"/bower_components/",
    r"/node_modules/", r"/third.?party/", r"/lib/[^/]+\.js$",
    r"\.min\.[jt]s$", r"-\d+\.\d+[\d\.]*\.[jt]s$",
    r"clipboard", r"tinysort", r"wysihtml", r"codemirror",
    r"bootstrap", r"jquery", r"angular", r"react",
    r"moment\.js", r"lodash", r"underscore",
]

# テストコード判定
TEST_FILE_PATTERNS = [
    r"test_", r"_test\.", r"Test\.", r"IT\.java$", r"ITCase\.java$",
    r"Spec\.java$", r"\.test\.[jt]s", r"\.spec\.[jt]s",
    r"/test/", r"/tests/", r"/spec/", r"/__tests__/",
    r"Mock", r"Stub", r"Fake", r"Dummy",
]

# 無名関数判定
LOW_PRIORITY_FUNC_PATTERNS = [
    r"^anonymous_\d+$", r"^_\d+$", r"^func_\d+$",
    r"^lambda", r"^test_", r"^setUp$", r"^tearDown$",
    r"^mock", r"^stub", r"^fake",
]


@dataclass
class FunctionChunk:
    file_path:       str
    language:        str
    function_name:   str
    code:            str
    start_line:      int
    end_line:        int
    priority:        int = 5
    priority_reason: str = ""
    context_refs:    List[str] = field(default_factory=list)
    # CodeQL結果（後から付与）
    codeql_confirmed: bool = False
    codeql_flow:      List[str] = field(default_factory=list)


class ASTParser:

    def __init__(self):
        self._parsers = {}
        self._init_tree_sitter()

    def _init_tree_sitter(self):
        try:
            from tree_sitter_languages import get_parser
            self._parsers = {
                "python":     get_parser("python"),
                "javascript": get_parser("javascript"),
                "typescript": get_parser("typescript"),
                "java":       get_parser("java"),
                "c":          get_parser("c"),
                "cpp":        get_parser("cpp"),
                "go":         get_parser("go"),
                "rust":       get_parser("rust"),
            }
            print("[+] tree-sitter初期化成功")
        except ImportError:
            print("[!] tree-sitter未インストール、正規表現フォールバック使用")

    # テストコードと判定するパスパターン
    TEST_PATH_PATTERNS = [
        r"(^|/)tests?/", r"(^|/)test_", r"_test\.(c|cpp|py|go|rs|java)$",
        r"(^|/)spec/", r"(^|/)__tests__/", r"\.test\.(js|ts)$",
        r"(^|/)testharness", r"(^|/)mock", r"(^|/)fixture",
        r"(^|/)bench(mark)?/",
    ]

    def _is_test_file(self, file_path: str) -> bool:
        p = file_path.replace("\\", "/").lower()
        return any(re.search(pat, p) for pat in self.TEST_PATH_PATTERNS)

    def parse(self, file_path: str, language: str, content: str) -> List[FunctionChunk]:
        if self._is_test_file(file_path):
            return []
        if language in self._parsers:
            chunks = self._parse_with_tree_sitter(file_path, language, content)
        else:
            chunks = self._parse_with_regex(file_path, language, content)

        for chunk in chunks:
            chunk.priority, chunk.priority_reason = self._calc_priority(chunk)

        chunks.sort(key=lambda x: x.priority)
        return chunks

    def _parse_with_tree_sitter(self, file_path, language, content) -> List[FunctionChunk]:
        parser = self._parsers[language]
        tree   = parser.parse(bytes(content, "utf-8"))
        chunks = []
        lines  = content.split("\n")

        func_node_types = {
            "python":     ["function_definition", "async_function_definition"],
            "javascript": ["function_declaration", "arrow_function",
                           "method_definition", "function_expression"],
            "typescript": ["function_declaration", "arrow_function",
                           "method_definition", "function_expression"],
            "java":       ["method_declaration", "constructor_declaration"],
            "c":          ["function_definition"],
            "cpp":        ["function_definition"],
            "go":         ["function_declaration", "method_declaration"],
            "rust":       ["function_item"],
        }.get(language, ["function_definition"])

        def traverse(node):
            if node.type in func_node_types:
                name  = self._extract_func_name(node)
                start = node.start_point[0]
                end   = node.end_point[0]
                code  = "\n".join(lines[start:end+1])
                if len(code) <= MAX_FUNCTION_TOKENS * 4:
                    chunks.append(FunctionChunk(
                        file_path=file_path,
                        language=language,
                        function_name=name or f"anonymous_{start}",
                        code=code,
                        start_line=start + 1,
                        end_line=end + 1,
                    ))
            for child in node.children:
                traverse(child)

        traverse(tree.root_node)
        return chunks

    def _extract_func_name(self, node) -> Optional[str]:
        # 直下の identifier/name を探す
        for child in node.children:
            if child.type in ("identifier", "name", "property_identifier"):
                return child.text.decode("utf-8")
        # C/C++: function_definition > function_declarator > identifier
        for child in node.children:
            if child.type in ("function_declarator", "declarator", "pointer_declarator"):
                result = self._extract_func_name(child)
                if result:
                    return result
        return None

    def _parse_with_regex(self, file_path, language, content) -> List[FunctionChunk]:
        patterns = {
            "python":     r"^(async\s+)?def\s+(\w+)\s*\(",
            "javascript": r"(function\s+(\w+)\s*\(|const\s+(\w+)\s*=.*=>)",
            "java":       r"(public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(",
            "php":        r"function\s+(\w+)\s*\(",
            "go":         r"func\s+(\w+)\s*\(",
            "rust":       r"fn\s+(\w+)\s*\(",
            "ruby":       r"def\s+(\w+)",
        }
        pattern = patterns.get(language, r"function\s+(\w+)\s*\(")
        lines   = content.split("\n")
        chunks  = []

        func_starts = [i for i, l in enumerate(lines) if re.search(pattern, l)]
        for idx, start in enumerate(func_starts):
            end  = func_starts[idx+1] - 1 if idx+1 < len(func_starts) else len(lines)-1
            code = "\n".join(lines[start:end+1])
            m    = re.search(pattern, lines[start])
            groups = [g for g in (m.groups() if m else []) if g]
            name = groups[-1] if groups else f"func_{start}"
            chunks.append(FunctionChunk(
                file_path=file_path,
                language=language,
                function_name=name,
                code=code,
                start_line=start+1,
                end_line=end+1,
            ))

        if not chunks:
            chunks.append(FunctionChunk(
                file_path=file_path,
                language=language,
                function_name="__module__",
                code=content,
                start_line=1,
                end_line=len(lines),
            ))
        return chunks

    def _calc_priority(self, chunk: FunctionChunk):
        """
        優先度計算（1最高・10最低）

        Step1: サードパーティ → 即9
        Step2: テストコード   → 即7〜8
        Step3: 無名関数       → 即9
        Step4: スコアリング
        """
        file_path = chunk.file_path
        func_name = chunk.function_name
        code      = chunk.code

        # Step1: サードパーティ
        for p in LOW_PRIORITY_FILE_PATTERNS:
            if re.search(p, file_path, re.IGNORECASE):
                return 9, f"サードパーティ: {p}"

        # Step2: テストコード
        for p in TEST_FILE_PATTERNS:
            if re.search(p, file_path, re.IGNORECASE):
                return 7, f"テストファイル: {p}"
        if re.search(r"^test_", func_name, re.IGNORECASE):
            return 8, "テスト関数"

        # Step3: 無名関数
        for p in LOW_PRIORITY_FUNC_PATTERNS:
            if re.match(p, func_name, re.IGNORECASE):
                return 9, f"無名/自動生成: {func_name}"

        # Step4: スコアリング
        score   = 0
        reasons = []

        sink_hits = sum(
            1 for p in HIGH_PRIORITY_SINK_PATTERNS
            if re.search(p, code, re.IGNORECASE)
        )
        if sink_hits >= 3:
            score += 40
            reasons.append(f"sinkヒット{sink_hits}件")
        elif sink_hits >= 1:
            score += 25
            reasons.append(f"sinkヒット{sink_hits}件")

        source_hits = sum(
            1 for p in HIGH_PRIORITY_SOURCE_PATTERNS
            if re.search(p, code, re.IGNORECASE)
        )
        if source_hits >= 2:
            score += 20
            reasons.append(f"sourceヒット{source_hits}件")
        elif source_hits >= 1:
            score += 10
            reasons.append(f"sourceヒット{source_hits}件")

        if sink_hits >= 1 and source_hits >= 1:
            score += 15
            reasons.append("source+sink両方")

        func_lower = func_name.lower()
        if any(k in func_lower for k in HIGH_PRIORITY_FUNC_NAMES):
            score += 15
            reasons.append(f"重要関数名: {func_name}")

        lang_bonus = {1: 5, 2: 2, 3: 0}.get(
            LANGUAGE_PRIORITY.get(chunk.language, 3), 0
        )
        score += lang_bonus

        if score >= 60:   priority = 1
        elif score >= 40: priority = 2
        elif score >= 25: priority = 3
        elif score >= 15: priority = 4
        elif score >= 5:  priority = 5
        else:             priority = 6

        reason = ", ".join(reasons) if reasons else "一般関数"
        return priority, reason


class ChunkPipeline:

    def __init__(self):
        self.parser = ASTParser()

    def process(self, files, codeql_results=None) -> List[FunctionChunk]:
        all_chunks = []
        for f in files:
            chunks = self.parser.parse(f.path, f.language, f.content)
            all_chunks.extend(chunks)

        # 重複除去
        seen   = set()
        unique = []
        for c in all_chunks:
            key = (c.function_name, c.code[:100].strip())
            if key not in seen:
                seen.add(key)
                unique.append(c)

        # CodeQL結果を優先度0に反映
        if codeql_results:
            codeql_lines = {
                (r.file.split("/")[-1], r.start_line): r.rule_id
                for r in codeql_results
            }
            for c in unique:
                fname = c.file_path.split("/")[-1]
                for (f, line), rule in codeql_lines.items():
                    if f == fname and c.start_line <= line <= c.end_line:
                        c.priority = 0
                        c.priority_reason = f"CodeQL証明済み: {rule} (line {line})"
                        break
        unique.sort(key=lambda x: x.priority)

        dist    = {}
        removed = len(all_chunks) - len(unique)
        for c in unique:
            dist[c.priority] = dist.get(c.priority, 0) + 1

        print(f"[+] {len(unique)}関数を抽出（重複{removed}件除去）")
        print(f"    優先度分布: {dict(sorted(dist.items()))}")
        return unique
