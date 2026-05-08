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
    # クラス構造情報
    class_name: Optional[str] = None
    class_parents: List[str] = []
    annotations: List[str] = []


class AnalyzeResponse(BaseModel):
    chunks: List[ChunkData]
    call_graph: Dict[str, List[str]]     # 関数名 → 呼び出す関数名リスト
    reverse_graph: Dict[str, List[str]]  # 関数名 → 呼び出し元関数名リスト
    taint_summary: Dict[str, Any]        # サマリー統計
    file_count: int
    error: Optional[str] = None


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

        return AnalyzeResponse(
            chunks=chunk_data_list,
            call_graph=call_graph,
            reverse_graph=reverse_graph,
            taint_summary=taint_summary,
            file_count=len(files),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"analyze失敗: {e}")
        return AnalyzeResponse(
            chunks=[],
            call_graph={},
            reverse_graph={},
            taint_summary={},
            file_count=0,
            error=str(e),
        )
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


@app.get("/health")
async def health():
    return {"status": "ok"}
