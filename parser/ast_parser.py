"""
パーサーレイヤー - tree-sitter AST解析 + 優先度付け（最新版）

優先度設計（1が最高・10が最低）:
  1: source+sink両方あり（最高スコア）
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
    # Web/DB
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
    # C/C++ memory
    r"memcpy\s*\(", r"memmove\s*\(", r"memset\s*\(", r"strcpy\s*\(",
    r"strcat\s*\(", r"sprintf\s*\(", r"snprintf\s*\(",
    r"gets\s*\(", r"scanf\s*\(", r"sscanf\s*\(",
    r"malloc\s*\(", r"realloc\s*\(", r"free\s*\(",
    r"new\s+\w", r"delete\s+", r"delete\[\]",
    r"\bwrite\s*\(", r"\bread\s*\(", r"fwrite\s*\(", r"fread\s*\(",
    r"system\s*\(", r"popen\s*\(", r"execv\s*\(", r"execve\s*\(",
    r"printf\s*\(", r"fprintf\s*\(", r"vprintf\s*\(",  # format string
    r"->setJSValue\b", r"->put\b", r"->get\b",  # JSC specific
    r"JSValue", r"jsString", r"jsNumber",
]

# ユーザー入力のsource
HIGH_PRIORITY_SOURCE_PATTERNS = [
    # Web
    r"request\.", r"req\.", r"\$_GET", r"\$_POST", r"\$_REQUEST",
    r"getParameter", r"getHeader", r"getCookie",
    r"argv\[", r"sys\.argv", r"input\s*\(",
    r"body\[", r"params\[", r"query\[",
    r"formData", r"req\.body", r"req\.query", r"req\.params",
    r"flask\.request", r"request\.form", r"request\.args",
    # C/C++ input
    r"\bfgets\s*\(", r"\bgetline\s*\(", r"\bread\s*\(", r"\bfread\s*\(",
    r"\brecv\s*\(", r"\brecvfrom\s*\(", r"\brecvmsg\s*\(",
    r"getenv\s*\(", r"\bfgetc\s*\(", r"\bgetchar\s*\(",
    r"\batoi\s*\(", r"\batol\s*\(", r"\bstrtol\s*\(", r"\bstrtoul\s*\(",
    # ファイル・ストリーム入力（パーサー系コードに多い）
    r"\bLoadFile\s*\(", r"\bReadFile\s*\(", r"\bOpenFile\s*\(",
    r"\bifstream\b", r"\bfopen\s*\(", r"\bstd::cin\b",
    r"ParseFromFile\s*\(", r"ParseFromString\s*\(", r"ParseFromArray\s*\(",
    r"->ParseFromFile", r"->ParsePartial",
    # バッファ・バイト列入力
    r"\bVerify\s*\(", r"\bGetRoot\s*\(", r"\bGetMutableRoot\s*\(",
    r"flatbuffers::GetRoot", r"flatbuffers::Verify",
    r"\buint8_t\s*\*\s*\w+\s*,\s*(?:size_t|int)\s+\w+",  # (buf, len) パターン
    r"\bconst\s+(?:char|uint8_t)\s*\*\s+buf",
    # JSC/WebKit specific
    r"->argument\s*\(", r"->uncheckedArgument\s*\(",
    r"callFrame->", r"exec->", r"globalObject->",
    r"toWTFString", r"toString\s*\(", r"toNumber\s*\(",
    r"JSC::JSValue", r"JSC::ExecState",
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
    codeql_flow:      str  = ""
    # AST由来の呼び出しグラフ情報（ASTParser が付与）
    calls:           List[str] = field(default_factory=list)  # この関数が呼ぶ関数名リスト
    # DFG: source変数名リスト・sink変数名リスト（ASTParser が付与）
    taint_sources:   List[str] = field(default_factory=list)  # ユーザー入力を受け取る変数
    taint_sinks:     List[str] = field(default_factory=list)  # 危険な sink に渡る変数
    params:          List[str] = field(default_factory=list)  # 引数名リスト
    # クラス構造情報（ASTParser が付与）
    class_name:      Optional[str] = None                     # 所属クラス名
    class_parents:   List[str] = field(default_factory=list)  # 継承元クラスリスト
    annotations:     List[str] = field(default_factory=list)  # メソッドアノテーション (@RequestMapping 等)


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
        content_bytes = bytes(content, "utf-8")

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

        def node_text(n) -> str:
            return content_bytes[n.start_byte:n.end_byte].decode("utf-8", errors="replace")

        def extract_params(func_node) -> List[str]:
            """関数の引数名を抽出"""
            params = []
            for child in func_node.children:
                if child.type in ("parameters", "formal_parameters", "parameter_list",
                                  "argument_list", "params"):
                    for param in child.children:
                        if param.type == "identifier":
                            params.append(node_text(param))
                        elif param.type in ("typed_parameter", "default_parameter",
                                            "typed_default_parameter"):
                            for sub in param.children:
                                if sub.type == "identifier":
                                    params.append(node_text(sub))
                                    break
                        elif param.type in ("formal_parameter", "spread_parameter"):
                            # Java: modifiers? type_identifier identifier
                            # 最後の identifier が変数名
                            ids = [sub for sub in param.children
                                   if sub.type == "identifier"]
                            if ids:
                                params.append(node_text(ids[-1]))
            return params

        def extract_calls(func_node) -> List[str]:
            """AST を走査して呼び出し先関数名を収集"""
            called = []
            def walk(n):
                if n.type == "call":
                    # Python: call > (attribute | identifier) が関数名
                    func_part = n.children[0] if n.children else None
                    if func_part:
                        if func_part.type == "identifier":
                            called.append(node_text(func_part))
                        elif func_part.type == "attribute":
                            # obj.method → method だけ取る
                            for sub in func_part.children:
                                if sub.type in ("identifier", "property_identifier"):
                                    called.append(node_text(sub))
                elif n.type == "call_expression":
                    # JS/TS
                    func_part = n.children[0] if n.children else None
                    if func_part:
                        if func_part.type == "identifier":
                            called.append(node_text(func_part))
                        elif func_part.type == "member_expression":
                            for sub in func_part.children:
                                if sub.type == "property_identifier":
                                    called.append(node_text(sub))
                elif n.type == "method_invocation":
                    # Java: method_invocation > identifier が関数名
                    for sub in n.children:
                        if sub.type == "identifier":
                            called.append(node_text(sub))
                            break
                for child in n.children:
                    walk(child)
            walk(func_node)
            return list(dict.fromkeys(called))  # 順序保持dedup

        # taint source/sink パターン（変数名レベルで追跡）
        SOURCE_CALL_PATTERNS = re.compile(
            # Python/Flask
            r"request\.|req\.|flask\.request|request\.form|request\.args|"
            r"request\.json|request\.get_json|request\.data|"
            r"sys\.argv|os\.environ|input\s*\(|"
            # PHP
            r"\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_FILES|\$_SERVER|"
            # Java Servlet / Spring
            r"getParameter\s*\(|getParameterValues\s*\(|getHeader\s*\(|"
            r"getCookies\s*\(|getQueryString\s*\(|getInputStream\s*\(|"
            r"getReader\s*\(|getPart\s*\(|getAttribute\s*\(|"
            r"@RequestParam|@RequestBody|@PathVariable|@RequestHeader|"
            r"@ModelAttribute|HttpServletRequest|ServletRequest|"
            r"request\.getParameter|request\.getHeader|request\.getCookie|"
            # JS/Node
            r"req\.body|req\.query|req\.params|req\.headers|"
            r"formData|process\.env|document\.location|window\.location|"
            r"document\.URL|document\.referrer|"
            # C/C++ — 外部入力を受け取るAPI
            r"\bread\s*\(|\bfread\s*\(|\bfgets\s*\(|\bgets\s*\(|\bgetline\s*\(|"
            r"\brecv\s*\(|\brecvfrom\s*\(|\brecvmsg\s*\(|"
            r"\bgetenv\s*\(|\bargv\b|\bstdin\b|"
            r"\batoi\s*\(|\batol\s*\(|\batoll\s*\(|\bstrtol\s*\(|\bstrtoul\s*\(|"
            r"\bsscanf\s*\(|\bfscanf\s*\(|\bscanf\s*\(|"
            r"\bmmap\s*\(|ReadFile\s*\(|ReadProcessMemory\s*\(",
            re.IGNORECASE
        )
        SINK_CALL_PATTERNS = re.compile(
            # SQL
            r"execute\s*\(|executeQuery\s*\(|executeUpdate\s*\(|"
            r"prepareStatement\s*\(|createStatement\s*\(|"
            r"cursor\.|\.query\s*\(|mysql_query|pg_query|"
            r"nativeQuery|createNativeQuery\s*\(|createQuery\s*\(|"
            # OS Command
            r"os\.system\s*\(|subprocess\.|exec\s*\(|"
            r"Runtime\.getRuntime|ProcessBuilder|"
            r"Runtime\s*\.\s*exec|process\.exec|child_process|"
            # Code eval
            r"eval\s*\(|ScriptEngine|groovy\.lang\.Script|"
            r"GroovyShell|ClassLoader|loadClass\s*\(|"
            # Deserialization
            r"pickle\.loads|yaml\.load\s*\(|marshal\.loads|"
            r"ObjectInputStream|readObject\s*\(|XMLDecoder|"
            r"XStream\.fromXML|JSON\.parse\s*\(|"
            # File
            r"open\s*\(|readFile|writeFile|Files\.write|Files\.read|"
            r"new\s+File\s*\(|FileInputStream|FileOutputStream|"
            r"include\s*\(|require\s*\(|"
            # XSS
            r"innerHTML|document\.write|render_template_string|Template\s*\(|"
            r"response\.getWriter|PrintWriter|out\.print|out\.write|"
            r"getWriter\s*\(\.\s*write|Model\.addAttribute|"
            r"ModelAndView|ResponseBody|"
            # SSRF / redirect
            r"requests\.get|requests\.post|urllib\.request|fetch\s*\(|"
            r"HttpURLConnection|URL\s*\(\.\s*openConnection|"
            r"response\.sendRedirect|redirect\s*\(|"
            # C/C++ 危険シンク
            r"\bmemcpy\s*\(|\bmemmove\s*\(|\bstrcpy\s*\(|\bstrcat\s*\(|"
            r"\bsprintf\s*\(|\bvsprintf\s*\(|\bsnprintf\s*\(|"
            r"\bstrcmp\s*\(|\bstrncpy\s*\(|\bstrncat\s*\(|"
            r"\bmalloc\s*\(|\brealloc\s*\(|\balloca\s*\(|"
            r"\bfree\s*\(|\bdelete\s+|\bdelete\[\]|"
            r"\bwrite\s*\(|\bfwrite\s*\(|\bsend\s*\(|\bsendto\s*\(|"
            r"\bsystem\s*\(|\bpopen\s*\(|\bexecl\s*\(|\bexecv\s*\(|"
            r"\bprintf\s*\(|\bfprintf\s*\(|"
            r"reinterpret_cast|static_cast|const_cast|"
            r"\[\s*\w+\s*\]",  # 配列インデックスアクセス
            re.IGNORECASE
        )

        def extract_taint(func_node, params: List[str], code: str):
            """
            簡易汚染伝播：
            - sources: source API を直接受けている変数 or パラメータ
            - sinks: sink に渡っている変数
            """
            sources = set()
            sinks   = set()

            # 代入文から source を受け取る変数を検出
            for m in re.finditer(
                r"(\w+)\s*=\s*(?:.*?)" + SOURCE_CALL_PATTERNS.pattern,
                code, re.IGNORECASE
            ):
                if m.group(1):
                    sources.add(m.group(1))

            # パラメータ自体も source 候補（呼び出し元から汚染データが来る可能性）
            for p in params:
                if p:
                    sources.add(p)

            # sink に渡っている引数変数を検出
            # パターン: sinkメソッド名(... var ...) の形を探す
            for m in re.finditer(
                r"(?:" + SINK_CALL_PATTERNS.pattern + r")\s*\(([^)]{0,200})\)",
                code, re.IGNORECASE
            ):
                args_str = m.group(m.lastindex) if m.lastindex else ""
                for var in re.findall(r"\b(\w+)\b", args_str):
                    if var and len(var) > 1 and not var[0].isupper():
                        sinks.add(var)

            # source変数がsinkに使われているかも追加チェック（文字列連結など）
            for src in list(sources):
                if src and re.search(
                    r"(?:" + SINK_CALL_PATTERNS.pattern + r")[^;]*\b" + re.escape(src) + r"\b",
                    code, re.IGNORECASE
                ):
                    sinks.add(src)

            return list(sources), list(sinks)

        CLASS_NODE_TYPES = {
            "python":     ["class_definition"],
            "javascript": ["class_declaration", "class_expression"],
            "typescript": ["class_declaration", "class_expression"],
            "java":       ["class_declaration", "interface_declaration",
                           "enum_declaration", "annotation_type_declaration"],
            "c":          [],
            "cpp":        ["class_specifier", "struct_specifier"],
            "go":         [],
            "rust":       ["impl_item"],
        }.get(language, [])

        def extract_class_info(class_node):
            """クラス名・継承元を抽出"""
            class_name = None
            parents = []
            for child in class_node.children:
                if child.type in ("identifier", "type_identifier"):
                    if class_name is None:
                        class_name = node_text(child)
                elif child.type in ("superclass", "extends_clause", "base_class",
                                    "class_parents", "superclasses"):
                    for sub in child.children:
                        if sub.type in ("identifier", "type_identifier",
                                        "scoped_type_identifier"):
                            parents.append(node_text(sub))
                elif child.type == "super_interfaces":
                    for sub in child.children:
                        if sub.type in ("type_list", "interface_type_list"):
                            for t in sub.children:
                                if t.type in ("type_identifier", "identifier"):
                                    parents.append(node_text(t))
            return class_name, parents

        def extract_annotations(func_node):
            """メソッド直前3行のアノテーション (@Xxx / @decorator) を抽出"""
            start = func_node.start_point[0]
            result = []
            for i in range(max(0, start - 4), start):
                line = lines[i].strip()
                if line.startswith("@"):
                    result.append(line)
            return result

        class_stack: List[tuple] = []  # (class_name, parents)

        def traverse(node):
            if node.type in CLASS_NODE_TYPES:
                cname, cparents = extract_class_info(node)
                class_stack.append((cname, cparents))
                for child in node.children:
                    traverse(child)
                class_stack.pop()
                return

            if node.type in func_node_types:
                name   = self._extract_func_name(node)
                start  = node.start_point[0]
                end    = node.end_point[0]
                code   = "\n".join(lines[start:end+1])
                if len(code) <= MAX_FUNCTION_TOKENS * 4:
                    params       = extract_params(node)
                    calls        = extract_calls(node)
                    t_src, t_snk = extract_taint(node, params, code)
                    cur_class, cur_parents = class_stack[-1] if class_stack else (None, [])
                    annots = extract_annotations(node)
                    chunks.append(FunctionChunk(
                        file_path=file_path,
                        language=language,
                        function_name=name or f"anonymous_{start}",
                        code=code,
                        start_line=start + 1,
                        end_line=end + 1,
                        calls=calls,
                        params=params,
                        taint_sources=t_src,
                        taint_sinks=t_snk,
                        class_name=cur_class,
                        class_parents=cur_parents,
                        annotations=annots,
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
        Step4: スコアリング（AST由来のtaintを優先、正規表現は補助）
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

        # AST由来のtaint情報を優先使用
        has_ast_source = bool(chunk.taint_sources)
        has_ast_sink   = bool(chunk.taint_sinks)

        if has_ast_source and has_ast_sink:
            score += 55
            reasons.append(f"AST taint: src={chunk.taint_sources[:2]} → sink={chunk.taint_sinks[:2]}")
        elif has_ast_source:
            score += 20
            reasons.append(f"AST source={chunk.taint_sources[:2]}")
        elif has_ast_sink:
            score += 20
            reasons.append(f"AST sink={chunk.taint_sinks[:2]}")
        else:
            # AST情報なし → 正規表現フォールバック
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

    def process(self, files) -> List[FunctionChunk]:
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

        unique.sort(key=lambda x: x.priority)

        dist    = {}
        removed = len(all_chunks) - len(unique)
        for c in unique:
            dist[c.priority] = dist.get(c.priority, 0) + 1

        print(f"[+] {len(unique)}関数を抽出（重複{removed}件除去）")
        print(f"    優先度分布: {dict(sorted(dist.items()))}")
        return unique
