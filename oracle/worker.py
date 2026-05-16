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
        poll_count = 0
        while True:
            try:
                job = self.db.pop_next_queued()
                if job:
                    await self._run_job(job)
                else:
                    # 60秒ごとにqueued_waitingジョブのA40在庫を確認
                    poll_count += 1
                    if poll_count >= 12:
                        poll_count = 0
                        await self._promote_waiting_jobs()
                    await asyncio.sleep(5)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.exception(f"Worker error: {e}")
                await asyncio.sleep(10)

    async def _promote_waiting_jobs(self):
        """A40在庫が空いたらqueued_waitingをqueuedに昇格"""
        waiting = self.db.list_jobs(status="queued_waiting", limit=50)
        if not waiting:
            return
        try:
            gpu_candidates = await self.manager._get_available_gpus()
            a40_available = any("A40" in g for g in gpu_candidates)
        except Exception:
            a40_available = False
        if a40_available:
            logger.info(f"A40在庫確認: queued_waiting {len(waiting)}件をqueuedに昇格")
            for job in waiting:
                self.db.update_job(job["id"], status="queued")
        else:
            logger.debug("A40在庫なし: queued_waitingは待機継続")

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

            from analyzer.llm import VulnAnalyzer, OmniscientContext, verify_findings_batch, rank_files_by_risk
            from analyzer.react_loop import ReActLoop
            from reporter.report import ReportGenerator
            from parser.ast_parser import FunctionChunk
            from schema import VulnSample, Exploitability, Severity
            from openai import AsyncOpenAI
            from config import LLM_BASE_URL, LLM_API_KEY, LLM_MODEL

            # ===========================
            # Step 1-3 & 5: CPUポッドとA40を並行起動
            # ===========================
            self._log(job_id, "\n[Step 1-3] CPUポッド・A40 並行起動中...\n")

            async def _start_cpu():
                url = await self.cpu_manager.start_pod()
                self._log(job_id, f"  CPUポッド ready: {url}\n")
                return url

            async def _start_a40():
                url = await self.manager.start_pod()
                self._log(job_id, f"  A40 ready: {url}\n")
                return url

            try:
                cpu_url, vllm_url = await asyncio.gather(_start_cpu(), _start_a40())
            except Exception as e:
                if "A40" in str(e) or "GPU" in str(e) or "instances" in str(e):
                    self._log(job_id, f"  A40在庫なし: キューに戻します\n")
                    self.db.update_job(job_id, status="queued_waiting")
                    return
                raise

            os.environ["LLM_BASE_URL"] = vllm_url

            self._log(job_id, "  git clone / AST解析 / 多段taint伝播 実行中...\n")

            async def _call_analyze():
                async with _httpx.AsyncClient(timeout=1800) as client:
                    resp = await client.post(
                        f"{cpu_url}/analyze",
                        json={"target": target, "target_type": target_type, "options": options},
                    )
                    resp.raise_for_status()
                    return resp.json()

            async def _start_and_poll_codeql(analyze_result):
                """CodeQLをバックグラウンド起動してポーリングで結果取得"""
                try:
                    # /analyze が返したtmpdir（clone済みパス）を使う
                    codeql_target = analyze_result.get("tmpdir") or target
                    logger.info(f"  [DEBUG] /codeql/start target: {codeql_target}")
                    # GitHub tree URLからリポジトリルートURLを抽出
                    # 例: https://github.com/owner/repo/tree/branch/path → https://github.com/owner/repo
                    import re as _re
                    raw_target = target if target_type == "github" else ""
                    if raw_target:
                        m = _re.match(r'(https://github\.com/[^/]+/[^/]+)(/|$)', raw_target)
                        repo_root_url = m.group(1) if m else raw_target
                    else:
                        repo_root_url = ""
                    async with _httpx.AsyncClient(timeout=30) as client:
                        r = await client.post(
                            f"{cpu_url}/codeql/start",
                            json={"target": codeql_target, "repo_url": repo_root_url},
                        )
                        codeql_job_id = r.json().get("job_id")
                    logger.info(f"  [DEBUG] codeql job_id: {codeql_job_id}")
                    if not codeql_job_id:
                        return []
                    # 最大10分ポーリング
                    for _ in range(60):
                        await asyncio.sleep(10)
                        async with _httpx.AsyncClient(timeout=10) as client:
                            r = await client.get(f"{cpu_url}/codeql/result/{codeql_job_id}")
                            data = r.json()
                            if data.get("status") == "done":
                                logger.info(f"  [DEBUG] codeql done: {len(data.get('results', []))}件, error={data.get('error')}")
                                return data.get("results", [])
                except Exception as e:
                    logger.warning(f"CodeQL polling failed: {e}")
                return []

            # まず /analyze を実行してから CodeQL を起動（tmpdirを受け取るため）
            result = await _call_analyze()
            tmpdir_from_analyze = result.get("tmpdir")
            logger.info(f"  [DEBUG] /analyze tmpdir: {tmpdir_from_analyze}")
            codeql_results = await _start_and_poll_codeql(result)

            # CPUポッドはLLM解析中も維持（ReActループのツール実行に使う）
            # 停止はLLM解析完了後
            self._log(job_id, "  CPUポッド: AST解析完了（LLM解析中も維持）\n")

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
                    class_name=r.get("class_name"),
                    class_parents=r.get("class_parents", []),
                    annotations=r.get("annotations", []),
                )
                # 多段taint伝播結果を付与
                c.propagated_sources = r.get("propagated_sources", [])
                c.taint_paths = r.get("taint_paths", [])
                c.codeql_confirmed = r.get("codeql_confirmed", False)
                c.codeql_flow = r.get("codeql_flow", "")
                chunks.append(c)

            # CodeQL結果をchunksにマージ
            if codeql_results:
                from oracle.cpu_worker_server import merge_codeql_results
                merge_codeql_results(chunks, codeql_results)
                self._log(job_id, f"  CodeQL: {len(codeql_results)}件をマージ\n")
            else:
                self._log(job_id, "  CodeQL: 結果なし\n")

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
            # 優先度フィルタ・ソート
            # ===========================
            max_functions = options.get("max_functions", 0)
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
                # CodeQL確認済みは最優先
                if getattr(chunk, 'codeql_confirmed', False):
                    score += 30
                # 多段taint伝播でsource→sink確認済みは高優先
                if getattr(chunk, 'propagated_sources', []) and chunk.taint_sinks:
                    score += 20
                return score

            chunks.sort(key=_score, reverse=True)
            # スコアをpriorityに反映（attacker promptの閾値priority>=5に対応）
            for chunk in chunks:
                s = _score(chunk)
                if s >= 20:
                    chunk.priority = max(chunk.priority, 8)
                elif s >= 10:
                    chunk.priority = max(chunk.priority, 5)
            original_count = len(chunks)
            if max_functions and max_functions > 0:
                chunks = chunks[:max_functions]
            self._log(job_id, f"  優先度フィルタ: {original_count}関数 → {len(chunks)}関数\n")

            compound_groups = _build_compound_groups(chunks)
            class_groups = omniscient.build_class_groups()
            taint_chain_groups = omniscient.build_taint_chain_groups()
            total_group_count = len(compound_groups) + len(class_groups) + len(taint_chain_groups)
            self._log(job_id, (
                f"\n[Step 4] グループ構築: "
                f"複合={len(compound_groups)}件 / "
                f"クラス={len(class_groups)}件 / "
                f"taintチェーン={len(taint_chain_groups)}件\n"
            ))

            # ===========================
            # Step 4: LLM解析（A40は既に起動済み）
            # ===========================
            self._log(job_id, "\n[Step 5] LLM解析開始...\n")

            llm_analyzer = VulnAnalyzer()

            # Mythosスタイル: ファイルランキングエージェントで優先度を補正
            # 解析前にLLMがファイルを1-5でスコアリングして高リスクから優先解析
            try:
                file_list = list(set(c.file_path for c in chunks))
                file_rankings = await rank_files_by_risk(llm_analyzer.client, LLM_MODEL, file_list)
                if file_rankings:
                    for c in chunks:
                        # ファイルリスクスコア(1-5)でchunkのpriorityを補正
                        # スコア5=最高リスク → priorityを下げる（低いほど優先）
                        fname = c.file_path.split("/")[-1]
                        score = file_rankings.get(fname) or file_rankings.get(c.file_path) or 3
                        file_risk_adj = max(0, 3 - score)  # score5→-2, score1→+2
                        c.priority = max(1, min(9, c.priority + file_risk_adj))
                    chunks.sort(key=lambda x: x.priority)
                    self._log(job_id, f"  ファイルランキング完了: {len(file_rankings)}ファイルをスコアリング\n")
            except Exception as e:
                logger.warning(f"ファイルランキングエラー: {e}")

            # IRIS方式 (ICLR 2025): LLMがアプリ固有のソース/シンク仕様を動的生成
            # 標準CodeQLクエリで見逃すカスタムソース・シンクを補完する
            try:
                from oracle.cpu_worker_server import iris_generate_codeql_specs
                iris_results = await iris_generate_codeql_specs(
                    chunks=chunks,
                    llm_base_url=os.environ.get("LLM_BASE_URL", ""),
                    llm_api_key=os.environ.get("LLM_API_KEY", ""),
                    llm_model=LLM_MODEL,
                )
                if iris_results:
                    self._log(job_id, f"  IRIS: {len(iris_results)}件のカスタムシンク検出\n")
            except Exception as e:
                logger.warning(f"IRISエラー: {e}")

            # 高優先度（CodeQL確認済み）はReActループで先に処理
            react_chunks = [
                c for c in chunks
                if getattr(c, 'codeql_confirmed', False) or (
                    getattr(c, 'propagated_sources', []) and c.taint_sinks
                )
            ][:20]  # 最大20件（コスト制御）
            react_chunk_ids = {id(c) for c in react_chunks}
            remaining_chunks = [c for c in chunks if id(c) not in react_chunk_ids]

            react_vulns: List[VulnSample] = []
            if react_chunks:
                self._log(job_id, f"  ReActループ: {len(react_chunks)}件の高優先度関数を先行解析...\n")
                react_loop = ReActLoop(cpu_url=cpu_url)
                react_tasks = [react_loop.run_on_chunk(c, omniscient) for c in react_chunks]
                react_results = await asyncio.gather(*react_tasks, return_exceptions=True)
                for r in react_results:
                    if isinstance(r, VulnSample) and r.label.is_vulnerable:
                        react_vulns.append(r)
                self._log(job_id, f"  ReActループ完了: {len(react_vulns)}件検出\n")

            total_single   = len(remaining_chunks)
            total_compound = total_group_count
            total_funcs    = total_single + total_compound + len(react_chunks)
            self._log(job_id, f"  LLM: {len(react_chunks)}/{total_funcs} 関数完了 | 脆弱性候補: {len(react_vulns)}件\n")

            counter_lock   = asyncio.Lock()
            single_done    = [len(react_chunks)]
            single_vulns   = [len(react_vulns)]
            compound_done  = [0]
            compound_vulns = [0]

            async def _log_progress():
                done  = single_done[0] + compound_done[0]
                vulns = single_vulns[0] + compound_vulns[0]
                self._log(job_id,
                    f"  LLM: {done}/{total_funcs} 関数完了 | 脆弱性候補: {vulns}件\n")

            async def batch_progress(done, total, vulns):
                async with counter_lock:
                    single_done[0]  = len(react_chunks) + done
                    single_vulns[0] = len(react_vulns) + vulns
                await _log_progress()

            async def run_compound():
                results = []
                all_groups = [
                    (compound_groups, "compound"),
                    (class_groups, "compound"),
                    (taint_chain_groups, "taint_chain"),
                ]
                # 全グループを並列実行（直列ではなく並列化）
                async def _run_group(group, gtype):
                    from analyzer.llm import build_compound_prompt
                    prompt = build_compound_prompt(group, group_type=gtype)
                    r = await llm_analyzer._call_llm(
                        prompt, group[0], is_compound=True, compound_group=group
                    )
                    async with counter_lock:
                        compound_done[0] += 1
                        if r and r.label.is_vulnerable:
                            compound_vulns[0] += 1
                    await _log_progress()
                    return r

                tasks = []
                for groups, gtype in all_groups:
                    for group in groups:
                        tasks.append(_run_group(group, gtype))
                group_results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in group_results:
                    if isinstance(r, VulnSample) and r.label.is_vulnerable:
                        results.append(r)
                return results

            single_results, compound_results = await asyncio.gather(
                llm_analyzer.analyze_batch(
                    remaining_chunks, progress_callback=batch_progress, omniscient=omniscient
                ),
                run_compound(),
            )

            # CPUポッドをLLM解析完了後に停止
            await self.cpu_manager.stop_pod()
            self._log(job_id, "  CPUポッド停止\n")

            all_vulns: List[VulnSample] = react_vulns + single_results + compound_results
            self._log(
                job_id,
                f"  脆弱性候補: {len(all_vulns)}件 "
                f"(ReAct:{len(react_vulns)} 単一:{len(single_results)} 複合:{len(compound_results)})\n",
            )

            # ===========================
            # Step 5: CPUポッドでASan/libFuzzer検証
            # (Docker不要 — CPUポッドの /exec /fuzz を使う)
            # Mythosと同じ戦略: ASanをクラッシュオラクルとして使い
            # ハルシネーションと本物のバグを分離する
            # ===========================
            llm_client = AsyncOpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)

            if all_vulns:
                self._log(job_id, "\n[Step 5] CPUポッドでASan/PoC検証...\n")
                cpp_vulns = [s for s in all_vulns if s.language.value in ("c", "cpp")]
                other_vulns = [s for s in all_vulns if s.language.value not in ("c", "cpp")]

                confirmed_cpp = []
                if cpp_vulns and cpu_url:
                    for s in cpp_vulns:
                        try:
                            poc_code = getattr(s.attack_scenario, 'poc_script', None) or s.code
                            async with _httpx.AsyncClient(timeout=90) as client:
                                r = await client.post(f"{cpu_url}/exec_poc", json={
                                    "vuln_description": s.label.title if s.label else "",
                                    "vulnerable_code": poc_code,
                                    "language": s.language.value,
                                    "repo_path": "",
                                    "timeout": 30,
                                })
                            d = r.json()
                            if d.get("crashed"):
                                s.attack_model.exploitability = Exploitability.CONFIRMED
                                s.attack_scenario.poc_script = (
                                    f"# ASan crash confirmed: {d.get('crash_type', 'unknown')}\n"
                                    f"{d.get('asan_output', '')[:800]}"
                                )
                                self._log(job_id, f"  [✓] クラッシュ確認 ({d.get('crash_type')}): {s.context.function if s.context else '?'}\n")
                            elif d.get("error"):
                                self._log(job_id, f"  [-] PoC実行エラー: {d['error'][:100]}\n")
                        except Exception as e:
                            logger.warning(f"PoC exec error: {e}")
                        confirmed_cpp.append(s)
                    all_vulns = confirmed_cpp + other_vulns

                confirmed = sum(1 for s in all_vulns if s.attack_model.exploitability == Exploitability.CONFIRMED)
                self._log(job_id, f"  ASan/PoC完了: {confirmed}件confirmed\n")

            # ===========================
            # Step 6: ReActループ (CPUポッドの /exec /fuzz を使用)
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
                    self._log(job_id, f"\n[Step 6] ReActループ ({len(react_targets)}件)...\n")
                    # CPUポッドのURLをReActLoopに渡す（Docker不要）
                    react_loop = ReActLoop(cpu_url=cpu_url)
                    react_tasks = [react_loop.run(s) for s in react_targets]
                    react_results = await asyncio.gather(*react_tasks)
                    react_ids = {id(s) for s in react_targets}
                    all_vulns = (
                        [s for s in all_vulns if id(s) not in react_ids]
                        + list(react_results)
                    )

            # ===========================
            # Step 6.5: 検証エージェント（Mythosスタイルのセカンドパス）
            # 「本当に重要か？」を確認してFPを除去
            # ===========================
            if all_vulns:
                self._log(job_id, "\n[Step 6.5] 検証エージェント（セカンドパス）...\n")
                from analyzer.llm import verify_findings_batch
                all_vulns = await verify_findings_batch(llm_client, LLM_MODEL, all_vulns)
                self._log(job_id, f"  検証後: {len(all_vulns)}件\n")

            # GPUポッドは必ずここで停止
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
            # フェイルセーフ: 何があっても両ポッドを停止
            for mgr in (self.cpu_manager, self.manager):
                try:
                    await mgr.stop_pod()
                except Exception:
                    pass
            self._current_job_id = None

    def _log(self, job_id: str, msg: str):
        """ログをDBに追記しつつ標準出力にも出す"""
        logger.info(msg.strip())
        self.db.update_job(job_id, log_append=msg)


# ===========================
# 複合グループ構築（main.pyと同じロジック）
# ===========================
def _build_compound_groups(chunks, group_size: int = 3, max_groups: int = 30):
    """
    複合解析グループを構築。
    1. 同一ファイルの高priority関数グループ（従来通り）
    2. 呼び出しチェーン深度2: A→B→C のグループ（新規）
    """
    groups = []
    seen = set()

    # 関数名→chunkのマップ
    func_map = {c.function_name: c for c in chunks}

    # 1. 呼び出しチェーン深度2グループ（A→B→C）
    for chunk in chunks:
        if chunk.priority > 5:
            continue  # 低priorityはスキップ
        callees = getattr(chunk, 'calls', [])
        chain = [chunk]
        for callee_name in callees[:3]:
            callee = func_map.get(callee_name)
            if callee and id(callee) != id(chunk):
                chain.append(callee)
                # 深度2
                for callee2_name in getattr(callee, 'calls', [])[:2]:
                    callee2 = func_map.get(callee2_name)
                    if callee2 and id(callee2) not in {id(c) for c in chain}:
                        chain.append(callee2)
                        break
            if len(chain) >= group_size:
                break
        if len(chain) >= 2:
            key = frozenset(id(c) for c in chain)
            if key not in seen:
                seen.add(key)
                groups.append(chain[:group_size])
        if len(groups) >= max_groups // 2:
            break

    # 2. 同一ファイルの高priority関数グループ（従来）
    file_chunks: Dict[str, list] = {}
    for chunk in chunks:
        if chunk.priority <= 4:
            file_chunks.setdefault(chunk.file_path, []).append(chunk)
    for _, lst in file_chunks.items():
        if len(lst) >= 2:
            key = frozenset(id(c) for c in lst[:group_size])
            if key not in seen:
                seen.add(key)
                groups.append(lst[:group_size])
        if len(groups) >= max_groups:
            break

    return groups
