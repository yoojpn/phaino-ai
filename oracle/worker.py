"""
バックグラウンドスキャンワーカー

役割分担：
  Oracle Free Tier  → 入力取得 / AST解析 / Dockerサンドボックス / レポート生成
  RunPod RTX 4090   → LLM解析のみ（vLLM + Qwen3.6-27B）

キューからジョブを取り出して順次実行する。
LLM解析が必要なときだけRunPodを起動し、完了後に停止する。
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("oracle.worker")

# vulnscanのルートをパスに追加
VULNSCAN_ROOT = Path(os.getenv("VULNSCAN_ROOT", "/workspace/vulnscan"))
sys.path.insert(0, str(VULNSCAN_ROOT))


class ScanWorker:
    """
    ジョブキューを監視してスキャンを実行するワーカー。

    処理フロー:
      CPUポッド → git clone / AST解析 / 多段taint伝播
      A40ポッド → LLM解析
      Oracle    → サンドボックス検証 / レポート生成
    """

    def __init__(self, db, manager, cpu_manager, report_dir: Path):
        self.db = db
        self.manager = manager          # GPU (A40) manager
        self.cpu_manager = cpu_manager  # CPU pod manager
        self.report_dir = report_dir
        self._current_job_id: Optional[str] = None

    async def run_forever(self):
        """無限ループでジョブキューを監視"""
        logger.info("ScanWorker started")
        while True:
            try:
                job = self.db.pop_next_queued()
                if job:
                    await self._run_job(job)
                else:
                    await asyncio.sleep(5)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.exception(f"Worker error: {e}")
                await asyncio.sleep(10)

    # ===========================
    # メインジョブ処理
    # ===========================
    async def _run_job(self, job: Dict[str, Any]):
        job_id = job["id"]
        self._current_job_id = job_id
        target = job["target"]
        target_type = job["target_type"]
        options = job.get("options") or {}

        self._log(job_id, f"[{datetime.utcnow().isoformat()}] ジョブ開始: {job['target_display']}\n")

        try:
            import httpx as _httpx

            from analyzer.llm import VulnAnalyzer, OmniscientContext
            from analyzer.react_loop import ReActLoop
            from analyzer.compound import build_compound_groups
            from sandbox.attacker import DockerExecutor
            from sandbox.verifier import SandboxVerifier
            from reporter.report import ReportGenerator
            from parser.ast_parser import FunctionChunk
            from schema import VulnSample, Exploitability, Severity
            from config import MAX_PARALLEL_DOCKER

            # ===========================
            # Step 1-3: CPUポッドで実行
            # (git clone / AST / 多段taint伝播)
            # ===========================
            self._log(job_id, "\n[Step 1-3] CPUポッド起動中...\n")
            cpu_url = await self.cpu_manager.start_pod()
            self._log(job_id, f"  CPUポッド ready: {cpu_url}\n")

            self._log(job_id, "  git clone / AST解析 / 多段taint伝播 実行中...\n")
            async with _httpx.AsyncClient(timeout=1800) as client:
                resp = await client.post(
                    f"{cpu_url}/analyze",
                    json={
                        "target": target,
                        "target_type": target_type,
                        "options": options,
                    },
                )
                resp.raise_for_status()
                result = resp.json()

            # CPUポッドは解析完了後すぐ停止（課金節約）
            await self.cpu_manager.stop_pod()
            self._log(job_id, "  CPUポッド停止\n")

            if result.get("error"):
                raise ValueError(f"CPUワーカーエラー: {result['error']}")

            # CPUポッドの結果からFunctionChunkを復元
            raw_chunks = result["chunks"]
            call_graph  = result["call_graph"]
            reverse_graph = result["reverse_graph"]
            taint_summary = result["taint_summary"]
            file_count = result["file_count"]

            self._log(
                job_id,
                f"  ファイル数: {file_count} | "
                f"関数数: {len(raw_chunks)} | "
                f"汚染関数: {taint_summary.get('tainted_functions', 0)} | "
                f"source→sink: {taint_summary.get('source_sink_pairs', 0)}件\n"
            )

            # dictからFunctionChunkに復元
            chunks = []
            for r in raw_chunks:
                c = FunctionChunk(
                    file_path=r["file_path"],
                    language=r["language"],
                    function_name=r["function_name"],
                    code=r["code"],
                    start_line=r["start_line"],
                    end_line=r["end_line"],
                    priority=r["priority"],
                    priority_reason=r["priority_reason"],
                    calls=r["calls"],
                    params=r["params"],
                    taint_sources=r["taint_sources"],
                    taint_sinks=r["taint_sinks"],
                )
                # 多段taint伝播結果を付与
                c.propagated_sources = r.get("propagated_sources", [])
                c.taint_paths = r.get("taint_paths", [])
                chunks.append(c)

            # OmniscientContextをOracle側で再構築（call_graphはCPUポッドから受け取ったものを使用）
            omniscient = OmniscientContext(chunks)
            omniscient.call_graph = {k: v for k, v in call_graph.items()}
            omniscient.reverse_graph = {k: v for k, v in reverse_graph.items()}
            omniscient.func_map = {c.function_name: c for c in chunks}
            from collections import defaultdict
            omniscient.file_funcs = defaultdict(list)
            for c in chunks:
                omniscient.file_funcs[c.file_path].append(c.function_name)

            self._log(job_id, f"  呼び出しグラフ: {len([v for v in call_graph.values() if v])}関数\n")

            # ===========================
            # 優先度フィルタ
            # ===========================
            max_functions = options.get("max_functions", 0)
            if max_functions and max_functions > 0:
                import re as _re
                SINK_PATTERNS = [
                    "memcpy", "memmove", "memset", "strcpy", "strcat", "sprintf",
                    "malloc", "realloc", "free", "alloca", "new ", "delete ",
                    "read", "write", "recv", "send", "fread", "fwrite",
                    "parse", "decode", "deserializ", "uncompress", "inflate",
                ]

                def _score(chunk):
                    score = 0
                    code = chunk.code.lower()
                    for kw in SINK_PATTERNS:
                        if kw in code:
                            score += 3
                    if _re.search(r'\b(char\s*\*|void\s*\*|uint8_t\s*\*|size_t|len|length|size|count)', code):
                        score += 2
                    score += min(code.count("\n") // 10, 5)
                    score += min(len(_re.findall(r'\b(if|for|while|switch|case)\b', code)), 5)
                    # 多段taint伝播でsource→sink確認済みは最優先
                    if getattr(chunk, 'propagated_sources', []) and chunk.taint_sinks:
                        score += 20
                    return score

                chunks.sort(key=_score, reverse=True)
                original_count = len(chunks)
                chunks = chunks[:max_functions]
                self._log(job_id, f"  優先度フィルタ: {original_count}関数 → {len(chunks)}関数\n")

            compound_groups = _build_compound_groups(chunks)
            self._log(job_id, f"\n[Step 4] 複合グループ: {len(compound_groups)}件\n")

            # ===========================
            # Step 4: LLM解析（A40起動）
            # ===========================
            self._log(job_id, "\n[Step 5] LLM解析 - A40起動中...\n")
            vllm_url = await self.manager.start_pod()
            self._log(job_id, f"  vLLM URL: {vllm_url}\n")

            os.environ["LLM_BASE_URL"] = vllm_url

            llm_analyzer = VulnAnalyzer()
            total_single   = len(chunks)
            total_compound = len(compound_groups)
            total_funcs    = total_single + total_compound
            self._log(job_id, f"  LLM: 0/{total_funcs} 関数完了 | 脆弱性候補: 0件\n")

            counter_lock   = asyncio.Lock()
            single_done    = [0]
            single_vulns   = [0]
            compound_done  = [0]
            compound_vulns = [0]

            async def _log_progress():
                done  = single_done[0] + compound_done[0]
                vulns = single_vulns[0] + compound_vulns[0]
                self._log(job_id,
                    f"  LLM: {done}/{total_funcs} 関数完了 | 脆弱性候補: {vulns}件\n")

            async def batch_progress(done, total, vulns):
                async with counter_lock:
                    single_done[0]  = done
                    single_vulns[0] = vulns
                await _log_progress()

            async def run_compound():
                results = []
                for group in compound_groups:
                    from analyzer.llm import build_compound_prompt
                    prompt = build_compound_prompt(group)
                    r = await llm_analyzer._call_llm(
                        prompt, group[0], is_compound=True, compound_group=group
                    )
                    async with counter_lock:
                        compound_done[0] += 1
                        if r and r.label.is_vulnerable:
                            compound_vulns[0] += 1
                            results.append(r)
                    await _log_progress()
                return results

            single_results, compound_results = await asyncio.gather(
                llm_analyzer.analyze_batch(
                    chunks, progress_callback=batch_progress, omniscient=omniscient
                ),
                run_compound(),
            )

            all_vulns: List[VulnSample] = single_results + compound_results
            self._log(
                job_id,
                f"  脆弱性候補: {len(all_vulns)}件 "
                f"(単一:{len(single_results)} 複合:{len(compound_results)})\n",
            )

            # ===========================
            # Step 5: Dockerサンドボックス検証
            # ===========================
            no_docker = options.get("no_docker", False)
            if not no_docker and all_vulns:
                self._log(job_id, "\n[Step 7] Dockerサンドボックス検証...\n")
                docker = DockerExecutor()
                verifier = SandboxVerifier(docker)
                all_vulns = await verifier.verify_batch(
                    all_vulns, concurrency=MAX_PARALLEL_DOCKER
                )
                confirmed = sum(
                    1 for s in all_vulns
                    if s.attack_model.exploitability == Exploitability.CONFIRMED
                )
                self._log(job_id, f"  confirmed: {confirmed}件\n")

            # ===========================
            # Step 6: ReActループ
            # ===========================
            no_react = options.get("no_react", False)
            if not no_react:
                react_targets = [
                    s for s in all_vulns
                    if (
                        s.attack_model.exploitability == Exploitability.PRACTICAL
                        and s.label.severity in (Severity.HIGH, Severity.CRITICAL)
                    )
                ][:5]
                if react_targets:
                    self._log(job_id, f"\n[Step 8] ReActループ ({len(react_targets)}件)...\n")
                    docker = DockerExecutor()
                    react_loop = ReActLoop(docker)
                    react_tasks = [react_loop.run(s) for s in react_targets]
                    react_results = await asyncio.gather(*react_tasks)
                    react_ids = {id(s) for s in react_targets}
                    all_vulns = (
                        [s for s in all_vulns if id(s) not in react_ids]
                        + list(react_results)
                    )
                    await self.manager.stop_pod()

            # ===========================
            # Step 7: フィルタ
            # ===========================
            min_exp = options.get("min_exploitability", "practical")
            exp_order = {
                Exploitability.THEORETICAL: 0,
                Exploitability.PRACTICAL:   1,
                Exploitability.CONFIRMED:   2,
            }
            min_level = exp_order[Exploitability(min_exp)]

            import re as _re
            TEST_PATTERNS = [
                r"(^|/)tests?/", r"(^|/)test_", r"_test\.(c|cpp|py|go|rs|java)$",
                r"(^|/)spec/", r"(^|/)__tests__/", r"\.test\.(js|ts)$",
                r"(^|/)testharness", r"(^|/)mock", r"(^|/)fixture",
                r"(^|/)bench(mark)?/",
            ]
            def _is_test_path(p):
                p = (p or "").replace("\\", "/").lower()
                return any(_re.search(pat, p) for pat in TEST_PATTERNS)

            filtered = [
                s for s in all_vulns
                if exp_order.get(s.attack_model.exploitability, 0) >= min_level
                and not _is_test_path(s.context.file if s.context else "")
            ]
            self._log(job_id, f"\n[Step 9] フィルタ後: {len(filtered)}件\n")

            # ===========================
            # Step 8: レポート生成
            # ===========================
            self._log(job_id, "\n[Step 10] レポート生成...\n")
            job_report_dir = self.report_dir / job_id
            job_report_dir.mkdir(parents=True, exist_ok=True)

            reporter = ReportGenerator(output_dir=str(job_report_dir))
            uncertain_samples = getattr(llm_analyzer, "_uncertain", [])
            report_path = reporter.generate(
                samples=filtered,
                target=job["target_display"],
                format="markdown",
                uncertain_samples=uncertain_samples,
            )
            self._log(job_id, f"  レポート: {report_path}\n")

            # ===========================
            # 完了
            # ===========================
            summary = {
                "files": file_count,
                "functions": len(chunks),
                "tainted_functions": taint_summary.get("tainted_functions", 0),
                "source_sink_pairs": taint_summary.get("source_sink_pairs", 0),
                "total_vulns": len(all_vulns),
                "reported": len(filtered),
                "confirmed": sum(
                    1 for s in filtered
                    if s.attack_model.exploitability == Exploitability.CONFIRMED
                ),
                "practical": sum(
                    1 for s in filtered
                    if s.attack_model.exploitability == Exploitability.PRACTICAL
                ),
            }
            self.db.update_job(
                job_id,
                status="done",
                log_append=f"\n[{datetime.utcnow().isoformat()}] 完了\n",
                report_path=str(report_path),
                result_summary=summary,
            )
            logger.info(f"Job {job_id} done: {summary}")

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.exception(f"Job {job_id} failed: {e}")
            # 両ポッドが起きたままにならないよう停止
            for mgr in (self.cpu_manager, self.manager):
                try:
                    await mgr.stop_pod()
                except Exception:
                    pass
            self.db.update_job(
                job_id,
                status="error",
                log_append=f"\n[ERROR] {e}\n",
            )
        finally:
            self._current_job_id = None

    def _log(self, job_id: str, msg: str):
        """ログをDBに追記しつつ標準出力にも出す"""
        logger.info(msg.strip())
        self.db.update_job(job_id, log_append=msg)


# ===========================
# 複合グループ構築（main.pyと同じロジック）
# ===========================
def _build_compound_groups(chunks, group_size: int = 3, max_groups: int = 20):
    groups = []
    file_chunks: Dict[str, list] = {}
    for chunk in chunks:
        if chunk.priority <= 3:
            file_chunks.setdefault(chunk.file_path, []).append(chunk)
    for _, lst in file_chunks.items():
        if len(lst) >= 2:
            groups.append(lst[:group_size])
        if len(groups) >= max_groups:
            break
    return groups
