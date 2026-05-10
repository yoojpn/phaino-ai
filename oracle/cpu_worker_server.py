"""
CPUポッド上で動くワーカーサーバー
担当: git clone / AST解析 / 多段taint伝播 / OmniscientContext構築

起動:
  uvicorn oracle.cpu_worker_server:app --host 0.0.0.0 --port 8001

Oracle側からジョブを受け取り、chunks + taint_graphをJSONで返す。
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# vulnscanルートをパスに追加
VULNSCAN_ROOT = Path(os.getenv("VULNSCAN_ROOT", "/workspace/vulnscan"))
sys.path.insert(0, str(VULNSCAN_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cpu_worker")

app = FastAPI(title="vulnscan CPU Worker")


# ===========================
# リクエスト/レスポンス型
# ===========================

class AnalyzeRequest(BaseModel):
    target: str
    target_type: str          # "github" | "zip" | "url" | "multi"
    options: Dict[str, Any] = {}


class ChunkData(BaseModel):
    file_path: str
    language: str
    function_name: str
    code: str
    start_line: int
    end_line: int
    priority: int
    priority_reason: str
    calls: List[str]
    params: List[str]
    taint_sources: List[str]
    taint_sinks: List[str]
    # 多段taint伝播の結果
    propagated_sources: List[str] = []   # 伝播後のtaint変数セット
    taint_paths: List[str] = []          # source→sinkのパス説明
    # CodeQL解析結果
    codeql_confirmed: bool = False
    codeql_flow: str = ""
    class_parents: List[str] = []
    annotations: List[str] = []


class AnalyzeResponse(BaseModel):
    chunks: List[ChunkData]
    call_graph: Dict[str, List[str]]     # 関数名 → 呼び出す関数名リスト
    reverse_graph: Dict[str, List[str]]  # 関数名 → 呼び出し元関数名リスト
    taint_summary: Dict[str, Any]        # サマリー統計
    file_count: int
    tmpdir: Optional[str] = None         # clone済みtmpdirパス（CodeQL用）
    error: Optional[str] = None


# ===========================
# CPUポッド ツール実行エンドポイント
# ReActループからの動的コード実行用
# ===========================

class ExecRequest(BaseModel):
    code: str                        # 実行するコード（Python/Shell/C++）
    language: str                    # "python" | "shell" | "cpp" | "c"
    stdin: str = ""                  # 標準入力
    timeout: int = 15

class ExecResponse(BaseModel):
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False

class BuildAsanRequest(BaseModel):
    repo_url: str                    # git clone済みの場合はパス、なければURL
    target_file: str                 # ビルド対象ファイル（相対パス）
    extra_flags: str = ""            # 追加コンパイルフラグ

class BuildAsanResponse(BaseModel):
    binary_path: str = ""
    compile_output: str = ""
    success: bool = False

class FuzzRequest(BaseModel):
    binary_path: str                 # ASANビルド済みバイナリのパス
    harness_code: str = ""           # libFuzzerハーネスコード（空の場合はstdin fuzzing）
    target_function: str = ""        # 対象関数名
    source_code: str = ""            # ハーネスと結合するソースコード
    language: str = "cpp"
    timeout: int = 30

class FuzzResponse(BaseModel):
    crash_found: bool = False
    crash_output: str = ""
    crash_input: str = ""
    output: str = ""


# ビルド済みASANバイナリのキャッシュ（CPUポッドのメモリ内）
_asan_cache: Dict[str, str] = {}  # repo_url+file → binary_path
_repo_tmpdir: Optional[str] = None  # cloneしたリポジトリのtmpdir


@app.post("/exec", response_model=ExecResponse)
async def exec_code(req: ExecRequest):
    """
    ReActループからのコード実行リクエストを処理。
    Python/Shell/C++を安全に実行して結果を返す。
    """
    try:
        if req.language == "python":
            proc = await asyncio.create_subprocess_exec(
                "python3", "-c", req.code,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        elif req.language == "shell":
            proc = await asyncio.create_subprocess_shell(
                req.code,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        elif req.language in ("cpp", "c"):
            # C/C++はコンパイルして実行
            ext = ".cpp" if req.language == "cpp" else ".c"
            compiler = "g++" if req.language == "cpp" else "gcc"
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False, mode="w") as f:
                f.write(req.code)
                src = f.name
            out = src.replace(ext, "")
            compile_proc = await asyncio.create_subprocess_exec(
                compiler, "-o", out, src, "-fsanitize=address", "-O1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            cout, cerr = await asyncio.wait_for(compile_proc.communicate(), timeout=30)
            if compile_proc.returncode != 0:
                return ExecResponse(stdout="", stderr=cerr.decode(), returncode=1)
            proc = await asyncio.create_subprocess_exec(
                out,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            return ExecResponse(stdout="", stderr=f"unsupported language: {req.language}", returncode=1)

        stdin_data = req.stdin.encode() if req.stdin else b""
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(stdin_data), timeout=req.timeout
            )
            return ExecResponse(
                stdout=stdout.decode(errors="replace")[:4000],
                stderr=stderr.decode(errors="replace")[:2000],
                returncode=proc.returncode,
            )
        except asyncio.TimeoutError:
            proc.kill()
            return ExecResponse(stdout="", stderr="timeout", returncode=-1, timed_out=True)

    except Exception as e:
        return ExecResponse(stdout="", stderr=str(e), returncode=-1)


@app.post("/build_asan", response_model=BuildAsanResponse)
async def build_asan(req: BuildAsanRequest):
    """
    対象リポジトリをASAN付きでビルドしてバイナリパスを返す。
    CPUポッドのtmpdirを再利用する。
    """
    cache_key = f"{req.repo_url}::{req.target_file}"
    if cache_key in _asan_cache:
        return BuildAsanResponse(
            binary_path=_asan_cache[cache_key],
            compile_output="(cached)",
            success=True,
        )

    # repo_url がパスの場合はそのまま使う
    if req.repo_url.startswith("/"):
        src_root = Path(req.repo_url)
    else:
        # 既存のclone済みtmpdirを探す
        src_root = Path("/tmp") / "asan_build"
        src_root.mkdir(exist_ok=True)
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth=1", req.repo_url, str(src_root / "repo"),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=120)
        src_root = src_root / "repo"

    target = src_root / req.target_file
    if not target.exists():
        return BuildAsanResponse(compile_output=f"file not found: {target}", success=False)

    ext = target.suffix
    compiler = "g++" if ext in (".cpp", ".cc", ".cxx") else "gcc"
    out_path = f"/tmp/asan_{target.stem}"

    proc = await asyncio.create_subprocess_exec(
        compiler, "-fsanitize=address,undefined", "-O1", "-g",
        str(target), "-o", out_path,
        *(req.extra_flags.split() if req.extra_flags else []),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        return BuildAsanResponse(compile_output="build timeout", success=False)

    if proc.returncode == 0:
        _asan_cache[cache_key] = out_path
        return BuildAsanResponse(
            binary_path=out_path,
            compile_output=stderr.decode()[:1000],
            success=True,
        )
    return BuildAsanResponse(
        compile_output=stderr.decode()[:2000],
        success=False,
    )


@app.post("/fuzz", response_model=FuzzResponse)
async def fuzz_target(req: FuzzRequest):
    """
    libFuzzerでクラッシュを探す。
    harness_codeが提供された場合はlibFuzzerハーネスとしてコンパイル・実行。
    """
    if req.language not in ("c", "cpp"):
        return FuzzResponse(output="libFuzzer: C/C++のみ対応")

    ext = ".cpp" if req.language == "cpp" else ".c"
    compiler = "clang++" if req.language == "cpp" else "clang"

    work_dir = Path(tempfile.mkdtemp(prefix="fuzz_"))
    try:
        if req.harness_code:
            # ハーネス + ソースコードを結合してlibFuzzerバイナリを作成
            combined = f"{req.source_code}\n\n{req.harness_code}"
            src = work_dir / f"fuzz_target{ext}"
            src.write_text(combined)

            out = work_dir / "fuzz_bin"
            proc = await asyncio.create_subprocess_exec(
                compiler, "-fsanitize=fuzzer,address", "-O1",
                str(src), "-o", str(out),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            cout, cerr = await asyncio.wait_for(proc.communicate(), timeout=60)
            if proc.returncode != 0:
                return FuzzResponse(output=f"compile error:\n{cerr.decode()[:1000]}")

            corpus = work_dir / "corpus"
            corpus.mkdir()
            (corpus / "seed").write_bytes(b"AAAA")

            proc = await asyncio.create_subprocess_exec(
                str(out),
                f"-max_total_time={req.timeout}",
                "-max_len=4096",
                "-print_final_stats=1",
                str(corpus),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=req.timeout + 10
                )
            except asyncio.TimeoutError:
                proc.kill()
                stdout, stderr = b"", b"timeout"

            output = (stdout + stderr).decode(errors="replace")
            crash_found = any(k in output.lower() for k in [
                "heap-buffer-overflow", "stack-buffer-overflow", "use-after-free",
                "segfault", "==error:", "crash_", "signal 11", "addresssanitizer",
            ])
            return FuzzResponse(
                crash_found=crash_found,
                crash_output=output[-2000:] if crash_found else "",
                output=output[-1000:],
            )

        elif req.binary_path and Path(req.binary_path).exists():
            # 既存バイナリを直接fuzz
            corpus = work_dir / "corpus"
            corpus.mkdir()
            (corpus / "seed").write_bytes(b"AAAA")
            proc = await asyncio.create_subprocess_exec(
                req.binary_path,
                f"-max_total_time={req.timeout}",
                str(corpus),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=req.timeout + 10
                )
            except asyncio.TimeoutError:
                proc.kill()
                stdout, stderr = b"", b"timeout"
            output = (stdout + stderr).decode(errors="replace")
            crash_found = "crash_" in output or "==error:" in output.lower()
            return FuzzResponse(crash_found=crash_found, output=output[-1000:])

        return FuzzResponse(output="binary_path or harness_code required")

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


# ===========================
# 多段Taint伝播エンジン
# ===========================

class TaintEngine:
    """
    クロスファイル多段taint伝播エンジン。

    伝播ルール:
      1. 直接代入:   b = a          → b が汚染
      2. 引数伝播:   func(tainted)  → calleeの対応するparamが汚染
      3. 返り値伝播: x = tainted_func() → calleeがtainted変数をreturnしていればxが汚染
    """

    def __init__(self, chunks, call_graph: Dict[str, List[str]],
                 reverse_graph: Dict[str, List[str]]):
        self.func_map = {c.function_name: c for c in chunks}
        self.call_graph = call_graph
        self.reverse_graph = reverse_graph
        # 関数名 → 汚染変数セット（ワークリスト法で更新）
        self.taint_state: Dict[str, Set[str]] = {
            c.function_name: set(c.taint_sources) for c in chunks
        }
        # 関数名 → taintパス（説明文リスト）
        self.taint_paths: Dict[str, List[str]] = {
            c.function_name: [] for c in chunks
        }
        # 関数がtainted変数をreturnするか
        self.returns_taint: Dict[str, bool] = {}

    def _extract_assignments(self, code: str, tainted: Set[str]) -> Set[str]:
        """
        コード内の代入文を解析してtaint伝播。
        a = tainted_var → a も汚染。
        連鎖代入にも対応（ワークリストで収束まで繰り返す）。
        """
        import re
        newly_tainted = set()
        changed = True
        current_tainted = set(tainted)

        while changed:
            changed = False
            # 単純代入: var = expr
            for m in re.finditer(
                r'^\s*(\w+)\s*=\s*(.+)$', code, re.MULTILINE
            ):
                lhs = m.group(1)
                rhs = m.group(2)
                if lhs in current_tainted:
                    continue
                # rhsに汚染変数が含まれているか
                for t in current_tainted:
                    if re.search(r'\b' + re.escape(t) + r'\b', rhs):
                        current_tainted.add(lhs)
                        newly_tainted.add(lhs)
                        changed = True
                        break

            # 複合代入: var += expr, var[key] = expr
            for m in re.finditer(
                r'^\s*(\w+)(?:\[.*?\])?\s*[+\-*/|&^]?=\s*(.+)$', code, re.MULTILINE
            ):
                lhs = m.group(1)
                rhs = m.group(2)
                if lhs in current_tainted:
                    continue
                for t in current_tainted:
                    if re.search(r'\b' + re.escape(t) + r'\b', rhs):
                        current_tainted.add(lhs)
                        newly_tainted.add(lhs)
                        changed = True
                        break

            # f-string / format: result = f"...{tainted}..."
            for m in re.finditer(
                r'^\s*(\w+)\s*=\s*[fF][\'"](.*?)[\'"]', code, re.MULTILINE | re.DOTALL
            ):
                lhs = m.group(1)
                fstr = m.group(2)
                if lhs in current_tainted:
                    continue
                for t in current_tainted:
                    if t in fstr:
                        current_tainted.add(lhs)
                        newly_tainted.add(lhs)
                        changed = True
                        break

        return current_tainted

    def _check_returns_taint(self, chunk, tainted: Set[str]) -> bool:
        """calleeがtaintedな変数をreturnしているか"""
        import re
        for m in re.finditer(r'\breturn\b\s+(.+)', chunk.code):
            ret_expr = m.group(1)
            for t in tainted:
                if re.search(r'\b' + re.escape(t) + r'\b', ret_expr):
                    return True
        return False

    def _propagate_to_callee(self, caller_name: str, callee_name: str,
                              caller_tainted: Set[str]) -> bool:
        """
        caller → callee への引数伝播。
        実引数が汚染されていれば callee の対応する仮引数を汚染。
        返り値: callee の taint_state が更新されたら True
        """
        import re
        caller_chunk = self.func_map.get(caller_name)
        callee_chunk = self.func_map.get(callee_name)
        if not caller_chunk or not callee_chunk:
            return False

        changed = False
        # caller のコード内で callee(arg1, arg2, ...) を探す
        pattern = re.compile(
            r'\b' + re.escape(callee_name) + r'\s*\(([^)]*)\)'
        )
        for m in pattern.finditer(caller_chunk.code):
            raw_args = m.group(1)
            # カンマ分割（簡易: ネストした括弧は無視）
            actual_args = [a.strip() for a in raw_args.split(',') if a.strip()]
            formal_params = callee_chunk.params

            for i, actual in enumerate(actual_args):
                # 実引数が汚染されているか（変数名として）
                is_tainted = False
                for t in caller_tainted:
                    if re.search(r'\b' + re.escape(t) + r'\b', actual):
                        is_tainted = True
                        break
                if is_tainted and i < len(formal_params):
                    param = formal_params[i]
                    if param not in self.taint_state[callee_name]:
                        self.taint_state[callee_name].add(param)
                        self.taint_paths[callee_name].append(
                            f"arg_propagation: {caller_name}({actual}) → {callee_name}.{param}"
                        )
                        changed = True

        return changed

    def run(self, max_iterations: int = 10) -> None:
        """
        ワークリストアルゴリズムで全関数のtaint状態が収束するまで繰り返す。
        """
        # 初期ワークリスト: taint_sourcesがある関数
        worklist = {
            name for name, tainted in self.taint_state.items() if tainted
        }

        for iteration in range(max_iterations):
            if not worklist:
                break

            next_worklist: Set[str] = set()

            for func_name in worklist:
                chunk = self.func_map.get(func_name)
                if not chunk:
                    continue

                current_tainted = set(self.taint_state[func_name])

                # Step1: 関数内の多段代入伝播
                propagated = self._extract_assignments(chunk.code, current_tainted)
                new_vars = propagated - current_tainted
                if new_vars:
                    self.taint_state[func_name] = propagated
                    for v in new_vars:
                        self.taint_paths[func_name].append(
                            f"alias: {func_name}.{v} ← tainted assignment"
                        )
                    current_tainted = propagated

                # Step2: 返り値チェック
                self.returns_taint[func_name] = self._check_returns_taint(
                    chunk, current_tainted
                )

                # Step3: calleeへ引数伝播
                for callee_name in self.call_graph.get(func_name, []):
                    if self._propagate_to_callee(func_name, callee_name, current_tainted):
                        next_worklist.add(callee_name)

                # Step4: 返り値伝播 → callerへ
                if self.returns_taint.get(func_name):
                    for caller_name in self.reverse_graph.get(func_name, []):
                        caller_chunk = self.func_map.get(caller_name)
                        if not caller_chunk:
                            continue
                        # caller内で `var = func_name(...)` の var を汚染
                        import re
                        for m in re.finditer(
                            r'(\w+)\s*=\s*' + re.escape(func_name) + r'\s*\(',
                            caller_chunk.code
                        ):
                            ret_var = m.group(1)
                            if ret_var not in self.taint_state[caller_name]:
                                self.taint_state[caller_name].add(ret_var)
                                self.taint_paths[caller_name].append(
                                    f"return_propagation: {ret_var} ← {func_name}() returns tainted"
                                )
                                next_worklist.add(caller_name)

            worklist = next_worklist
            logger.info(f"  [TaintEngine] iteration {iteration+1}: worklist={len(worklist)}")

        logger.info(
            f"  [TaintEngine] 収束完了: "
            f"{sum(1 for t in self.taint_state.values() if t)}関数が汚染状態"
        )

    def get_taint_paths_for(self, func_name: str) -> List[str]:
        return self.taint_paths.get(func_name, [])

    def get_propagated_sources(self, func_name: str) -> List[str]:
        return list(self.taint_state.get(func_name, set()))


# ===========================
# メイン解析エンドポイント
# ===========================


# ===========================
# CodeQL統合
# ===========================

CODEQL_DIR = Path(os.getenv("CODEQL_DIR", "/workspace/codeql"))
CODEQL_BIN = CODEQL_DIR / "codeql"

# CodeQLが対応する言語マッピング
CODEQL_LANG_MAP = {
    "python":     "python",
    "javascript": "javascript",
    "java":       "java",
    "cpp":        "cpp",
    "c":          "cpp",
    "go":         "go",
    "ruby":       "ruby",
}

# 言語別クエリスイート
CODEQL_QUERY_SUITES = {
    "python":     "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    "java":       "codeql/java-queries:codeql-suites/java-security-extended.qls",
    "cpp":        "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
    "go":         "codeql/go-queries:codeql-suites/go-security-extended.qls",
    "ruby":       "codeql/ruby-queries:codeql-suites/ruby-security-extended.qls",
}

# メモリを多く使う言語（ファイル数が少ない場合はスキップ）
CODEQL_HEAVY_LANGS = {"javascript", "java"}


def detect_languages(files) -> List[str]:
    """ファイルリストから使用言語を検出。重い言語はファイル数が少ない場合スキップ"""
    lang_counts: Dict[str, int] = {}
    for f in files:
        lang = getattr(f, "language", None) or ""
        cq_lang = CODEQL_LANG_MAP.get(lang.lower())
        if cq_lang:
            lang_counts[cq_lang] = lang_counts.get(cq_lang, 0) + 1

    result = []
    for lang, count in lang_counts.items():
        # 重い言語は10ファイル以上ある場合のみ実行
        if lang in CODEQL_HEAVY_LANGS and count < 10:
            logger.info(f"  CodeQL {lang}: ファイル数{count}件のためスキップ")
            continue
        result.append(lang)
    return result


def parse_sarif(sarif_path: Path) -> List[Dict]:
    """SARIFファイルをパースしてsource→sinkパスリストを返す"""
    results = []
    try:
        with open(sarif_path, encoding="utf-8") as f:
            sarif = json.load(f)
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                message = result.get("message", {}).get("text", "")
                # パス情報（codeFlows）からsource/sinkを抽出
                code_flows = result.get("codeFlows", [])
                for flow in code_flows:
                    for thread_flow in flow.get("threadFlows", []):
                        locs = thread_flow.get("locations", [])
                        if len(locs) < 2:
                            continue
                        source_loc = locs[0].get("location", {})
                        sink_loc = locs[-1].get("location", {})

                        source_file = (source_loc.get("physicalLocation", {})
                                       .get("artifactLocation", {}).get("uri", ""))
                        source_line = (source_loc.get("physicalLocation", {})
                                       .get("region", {}).get("startLine", 0))
                        sink_file = (sink_loc.get("physicalLocation", {})
                                     .get("artifactLocation", {}).get("uri", ""))
                        sink_line = (sink_loc.get("physicalLocation", {})
                                     .get("region", {}).get("startLine", 0))

                        results.append({
                            "rule_id": rule_id,
                            "message": message,
                            "source_file": source_file,
                            "source_line": source_line,
                            "sink_file": sink_file,
                            "sink_line": sink_line,
                            "flow_length": len(locs),
                        })

                # codeFlowsがない場合はlocationのみ
                if not code_flows:
                    for loc_obj in result.get("locations", []):
                        phys = loc_obj.get("physicalLocation", {})
                        file_uri = phys.get("artifactLocation", {}).get("uri", "")
                        line = phys.get("region", {}).get("startLine", 0)
                        results.append({
                            "rule_id": rule_id,
                            "message": message,
                            "source_file": file_uri,
                            "source_line": line,
                            "sink_file": file_uri,
                            "sink_line": line,
                            "flow_length": 1,
                        })
    except Exception as e:
        logger.warning(f"  SARIF parse error: {e}")
    return results


def merge_codeql_results(chunks, codeql_results: List[Dict]):
    """
    CodeQLのsource→sink結果をchunksのtaint情報にマージ。
    該当する行番号のchunkにCodeQL検出フラグを付与する。
    """
    for result in codeql_results:
        sink_file = result["sink_file"]
        sink_line = result["sink_line"]
        rule_id = result["rule_id"]
        message = result["message"]

        for chunk in chunks:
            # ファイルパスの末尾マッチ（絶対パス vs 相対パス対策）
            if not (chunk.file_path.endswith(sink_file) or
                    sink_file.endswith(chunk.file_path.lstrip("/"))):
                continue
            if not (chunk.start_line <= sink_line <= chunk.end_line):
                continue

            # taint_sinksにCodeQL検出のsinkを追加
            codeql_sink = f"[CodeQL:{rule_id}] line {sink_line}"
            if codeql_sink not in chunk.taint_sinks:
                chunk.taint_sinks.append(codeql_sink)

            # sourceがある場合taint_sourcesにも追加
            source_label = f"[CodeQL] {message[:80]}"
            if source_label not in chunk.taint_sources:
                chunk.taint_sources.append(source_label)

            # codeql_confirmedフラグ
            chunk.codeql_confirmed = True
            chunk.codeql_flow = message[:200]

            # 優先度を最高に引き上げ
            chunk.priority = max(chunk.priority, 8)
            break


async def run_codeql(tmpdir: str, files, chunks) -> List[Dict]:
    """
    CodeQL CLIを使ってtaint解析を実行。
    結果のSARIFをパースして返す。インストールされていない場合は空リストを返す。
    """
    if not CODEQL_BIN.exists():
        return []

    langs = detect_languages(files)
    if not langs:
        return []

    all_results = []
    src_root = Path(tmpdir)
    codeql_work = src_root / "_codeql_work"
    codeql_work.mkdir(exist_ok=True)

    for lang in langs:
        suite = CODEQL_QUERY_SUITES.get(lang)
        if not suite:
            continue

        db_path = codeql_work / f"db_{lang}"
        sarif_path = codeql_work / f"results_{lang}.sarif"

        try:
            # コンパイル言語のみ --build-mode=none（interpreted言語に渡すとエラー）
            COMPILED_LANGS = {"cpp", "java", "go", "csharp"}
            build_mode_args = ["--build-mode=none"] if lang in COMPILED_LANGS else []

            logger.info(f"  CodeQL DB作成中: {lang}")
            proc = await asyncio.create_subprocess_exec(
                str(CODEQL_BIN), "database", "create",
                str(db_path),
                f"--language={lang}",
                *build_mode_args,
                f"--source-root={src_root}",
                "--overwrite",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            if proc.returncode != 0:
                logger.warning(f"  CodeQL DB作成失敗 ({lang}): {stderr.decode()[-500:]}")
                continue

            logger.info(f"  CodeQL analyze中: {lang}")
            proc = await asyncio.create_subprocess_exec(
                str(CODEQL_BIN), "database", "analyze",
                str(db_path),
                suite,
                "--format=sarif-latest",
                f"--output={sarif_path}",
                "--threads=2",
                "--ram=4096",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
            if proc.returncode != 0:
                logger.warning(f"  CodeQL analyze失敗 ({lang}): {stderr.decode()[-500:]}")
                continue

            results = parse_sarif(sarif_path)
            logger.info(f"  CodeQL {lang}: {len(results)}件検出")
            all_results.extend(results)

        except asyncio.TimeoutError:
            logger.warning(f"  CodeQL タイムアウト ({lang})")
        except Exception as e:
            logger.warning(f"  CodeQL エラー ({lang}): {e}")

    return all_results


class CodeQLRequest(BaseModel):
    target: str          # git clone済みのtmpdirパス or repo URL
    languages: List[str] = []  # 空の場合は自動検出

class CodeQLResponse(BaseModel):
    results: List[Dict[str, Any]] = []
    error: Optional[str] = None


# CodeQL バックグラウンドジョブ管理
_codeql_jobs: Dict[str, Dict] = {}  # job_id -> {status, results, error}


@app.post("/codeql/start")
async def start_codeql(req: CodeQLRequest):
    """CodeQL解析をバックグラウンドで開始してjob_idを返す"""
    import uuid
    job_id = str(uuid.uuid4())[:8]
    _codeql_jobs[job_id] = {"status": "running", "results": [], "error": None}

    async def _run():
        tmpdir_to_cleanup = None
        try:
            if not CODEQL_BIN.exists():
                _codeql_jobs[job_id] = {"status": "done", "results": [], "error": "CodeQL not installed"}
                return

            if req.target.startswith("/"):
                # /analyze から渡されたclone済みtmpdirパス
                src_root = Path(req.target)
                tmpdir_to_cleanup = req.target  # CodeQL完了後に削除
            else:
                clone_dir = tempfile.mkdtemp(prefix="codeql_clone_")
                tmpdir_to_cleanup = clone_dir
                proc = await asyncio.create_subprocess_exec(
                    "git", "clone", "--depth=1", req.target, clone_dir,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=120)
                src_root = Path(clone_dir)

            ext_map = {".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c": "cpp",
                       ".java": "java", ".py": "python", ".js": "javascript",
                       ".ts": "javascript", ".go": "go", ".rb": "ruby"}
            lang_counts: Dict[str, int] = {}
            for p in src_root.rglob("*"):
                if p.suffix in ext_map:
                    lang = ext_map[p.suffix]
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1

            if req.languages:
                langs = req.languages
            else:
                langs = []
                for lang, count in lang_counts.items():
                    if lang in CODEQL_HEAVY_LANGS and count < 10:
                        logger.info(f"  CodeQL {lang}: ファイル数{count}件のためスキップ (codeql/start)")
                        continue
                    langs.append(lang)

            class _DummyFile:
                def __init__(self, lang): self.language = lang
            dummy_files = [_DummyFile(l) for l in langs]

            results = await run_codeql(str(src_root), dummy_files, [])
            _codeql_jobs[job_id] = {"status": "done", "results": results, "error": None}
        except Exception as e:
            _codeql_jobs[job_id] = {"status": "done", "results": [], "error": str(e)}
        finally:
            if tmpdir_to_cleanup:
                shutil.rmtree(tmpdir_to_cleanup, ignore_errors=True)

    asyncio.create_task(_run())
    return {"job_id": job_id}


@app.get("/codeql/result/{job_id}")
async def get_codeql_result(job_id: str):
    """CodeQL解析結果をポーリングで取得"""
    job = _codeql_jobs.get(job_id)
    if not job:
        return {"status": "not_found", "results": []}
    return job


@app.post("/codeql", response_model=CodeQLResponse)
async def run_codeql_endpoint(req: CodeQLRequest):
    """
    CodeQL解析を非同期で実行してSARIF結果を返す。
    /analyze とは分離してCloudflareタイムアウトを回避。
    """
    try:
        if not CODEQL_BIN.exists():
            return CodeQLResponse(error="CodeQL not installed")

        # target がパスならそのまま使う、URLならclone
        if req.target.startswith("/"):
            src_root = Path(req.target)
        else:
            tmpdir = tempfile.mkdtemp(prefix="codeql_clone_")
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth=1", req.target, tmpdir,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            src_root = Path(tmpdir)

        # 言語を自動検出
        if req.languages:
            langs = req.languages
        else:
            # ファイル拡張子で検出
            ext_map = {".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c": "cpp",
                       ".java": "java", ".py": "python", ".js": "javascript",
                       ".ts": "javascript", ".go": "go", ".rb": "ruby"}
            found = set()
            for p in src_root.rglob("*"):
                if p.suffix in ext_map:
                    found.add(ext_map[p.suffix])
            langs = list(found)

        # ダミーのfiles/chunksで run_codeql を呼ぶ
        class _DummyFile:
            def __init__(self, lang): self.language = lang
        dummy_files = [_DummyFile(l) for l in langs]

        results = await run_codeql(str(src_root), dummy_files, [])
        return CodeQLResponse(results=results)

    except Exception as e:
        return CodeQLResponse(error=str(e))


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    tmpdir = None
    try:
        from input.loader import InputLoader
        from parser.ast_parser import ChunkPipeline

        logger.info(f"[CPUWorker] analyze開始: {req.target_type} / {req.target[:80]}")

        # Step1: コード取得
        loader = InputLoader()
        if req.target_type == "multi":
            target_list = json.loads(req.target)
        else:
            target_list = [{"type": req.target_type, "value": req.target,
                            "display": req.target}]

        tmpdir = tempfile.mkdtemp(prefix="cpuworker_")
        files = []
        for t in target_list:
            t_files = loader.load(t["value"])
            files.extend(t_files)
            for f in t_files:
                fp = Path(tmpdir) / f.path
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(f.content, encoding="utf-8", errors="ignore")

        if not files:
            raise HTTPException(status_code=400, detail="コードファイルが見つかりません")

        logger.info(f"  ファイル数: {len(files)}")

        # Step2: AST解析
        pipeline = ChunkPipeline()
        chunks = pipeline.process(files)
        logger.info(f"  AST: {len(chunks)}関数")

        # max_functions フィルタ
        max_functions = req.options.get("max_functions", 0)
        if max_functions and max_functions > 0:
            chunks = chunks[:max_functions]

        # Step3: 呼び出しグラフ構築
        func_map = {c.function_name: c for c in chunks}
        all_func_names = set(func_map.keys())
        call_graph: Dict[str, List[str]] = {}
        reverse_graph: Dict[str, List[str]] = {}

        for chunk in chunks:
            call_graph.setdefault(chunk.function_name, [])
            reverse_graph.setdefault(chunk.function_name, [])

        for chunk in chunks:
            if chunk.calls:
                for callee in chunk.calls:
                    if callee in all_func_names and callee != chunk.function_name:
                        if callee not in call_graph[chunk.function_name]:
                            call_graph[chunk.function_name].append(callee)
                        reverse_graph.setdefault(callee, [])
                        if chunk.function_name not in reverse_graph[callee]:
                            reverse_graph[callee].append(chunk.function_name)
            else:
                import re
                for name in all_func_names:
                    if name == chunk.function_name:
                        continue
                    if re.search(r'\b' + re.escape(name) + r'\s*\(', chunk.code):
                        if name not in call_graph[chunk.function_name]:
                            call_graph[chunk.function_name].append(name)
                        reverse_graph.setdefault(name, [])
                        if chunk.function_name not in reverse_graph[name]:
                            reverse_graph[name].append(chunk.function_name)

        logger.info(f"  呼び出しグラフ: {len([v for v in call_graph.values() if v])}関数")

        # Step3.5: CodeQL解析はスキップ（/codeql エンドポイントで非同期実行）
        # Cloudflareの100秒タイムアウトを避けるため分離

        # Step4: 多段taint伝播
        logger.info("  多段taint伝播開始...")
        engine = TaintEngine(chunks, call_graph, reverse_graph)
        engine.run(max_iterations=10)

        # Step5: chunksにtaint伝播結果を反映してシリアライズ
        chunk_data_list = []
        taint_path_count = 0

        for c in chunks:
            propagated = engine.get_propagated_sources(c.function_name)
            paths = engine.get_taint_paths_for(c.function_name)
            taint_path_count += len(paths)

            chunk_data_list.append(ChunkData(
                file_path=c.file_path,
                language=c.language,
                function_name=c.function_name,
                code=c.code,
                start_line=c.start_line,
                end_line=c.end_line,
                priority=c.priority,
                priority_reason=c.priority_reason,
                calls=c.calls,
                params=c.params,
                taint_sources=c.taint_sources,
                taint_sinks=c.taint_sinks,
                propagated_sources=propagated,
                taint_paths=paths[:20],  # 多すぎる場合は先頭20件
                class_name=getattr(c, "class_name", None),
                class_parents=getattr(c, "class_parents", []),
                annotations=getattr(c, "annotations", []),
                codeql_confirmed=getattr(c, "codeql_confirmed", False),
                codeql_flow=getattr(c, "codeql_flow", ""),
            ))

        taint_summary = {
            "total_functions": len(chunks),
            "tainted_functions": sum(
                1 for c in chunk_data_list if c.propagated_sources
            ),
            "source_sink_pairs": sum(
                1 for c in chunk_data_list
                if c.propagated_sources and c.taint_sinks
            ),
            "total_taint_paths": taint_path_count,
        }
        logger.info(
            f"  taint完了: {taint_summary['tainted_functions']}関数汚染, "
            f"source→sink {taint_summary['source_sink_pairs']}件"
        )

        # tmpdirはCodeQL用に残す（/codeql/startに渡してCodeQL完了後に削除）
        return AnalyzeResponse(
            chunks=chunk_data_list,
            call_graph=call_graph,
            reverse_graph=reverse_graph,
            taint_summary=taint_summary,
            file_count=len(files),
            tmpdir=tmpdir,
        )

    except HTTPException:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
        raise
    except Exception as e:
        logger.exception(f"analyze失敗: {e}")
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
        return AnalyzeResponse(
            chunks=[],
            call_graph={},
            reverse_graph={},
            taint_summary={},
            file_count=0,
            error=str(e),
        )


@app.get("/health")
async def health():
    import subprocess
    try:
        commit = subprocess.check_output(
            ["git", "-C", "/workspace/vulnscan", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        commit = "unknown"
    try:
        from tree_sitter_languages import get_parser
        ts_ok = True
    except Exception:
        ts_ok = False
    return {"status": "ok", "commit": commit, "tree_sitter_languages": ts_ok}
