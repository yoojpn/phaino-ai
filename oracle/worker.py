"""
バックグラウンドスキャンワーカー

役割分担：
  Oracle Free Tier  → 入力取得 / AST解析 / CodeQL / Dockerサンドボックス / レポート生成
  RunPod RTX 4090   → LLM解析のみ（vLLM + Qwen3.6-27B）

キューからジョブを取り出して順次実行する。
LLM解析が必要なときだけRunPodを起動し、完了後に停止する。
"""

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
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
    1ジョブずつ順番に処理する（Oracle ARM 4コアの限界を考慮）。
    """

    def __init__(self, db, manager, report_dir: Path):
        self.db = db
        self.manager = manager
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
            # ---- vulnscanモジュールをここでimport（パスが通ってから） ----
            from config import CODEQL_LANGUAGES, MAX_PARALLEL_DOCKER
            from input.loader import InputLoader
            from parser.ast_parser import ChunkPipeline
            from codeql.analyzer import CodeQLAnalyzer
            from analyzer.llm import VulnAnalyzer
            from analyzer.react_loop import ReActLoop
            from sandbox.attacker import DockerExecutor
            from sandbox.verifier import SandboxVerifier
            from reporter.report import ReportGenerator
            from schema import VulnSample, Exploitability, Severity

            # ===========================
            # Step 1: 入力取得（Oracle側）
            # ===========================
            self._log(job_id, "\n[Step 1] コード取得...\n")
            loader = InputLoader()

            # multi ターゲット対応
            if target_type == "multi":
                import json as _json
                target_list = _json.loads(target)
            else:
                target_list = [{"type": target_type, "value": target, "display": target}]

            files = []
            tmpdir = tempfile.mkdtemp(prefix="vulnscan_")
            for t in target_list:
                self._log(job_id, f"  取得中: {t['display']}\n")
                t_files = loader.load(t["value"])
                files.extend(t_files)
                for f in t_files:
                    fp = Path(tmpdir) / f.path
                    fp.parent.mkdir(parents=True, exist_ok=True)
                    fp.write_text(f.content, encoding="utf-8", errors="ignore")

            if not files:
                raise ValueError("コードファイルが見つかりません")
            languages = {f.language for f in files}
            self._log(job_id, f"  合計ファイル数: {len(files)} | 言語: {languages}\n")

            # ===========================
            # Step 2: AST解析 + CodeQL（Oracle側・並列）
            # ===========================
            self._log(job_id, "\n[Step 2+3] AST解析 + CodeQL（並列）...\n")
            ast_pipeline = ChunkPipeline()
            codeql_analyzer = CodeQLAnalyzer()

            no_codeql = options.get("no_codeql", False)

            async def run_ast():
                return ast_pipeline.process(files)

            async def run_codeql():
                if no_codeql:
                    return []
                codeql_langs = [l for l in languages if l in CODEQL_LANGUAGES]
                if not codeql_langs:
                    return []
                return await codeql_analyzer.analyze_multi_language(tmpdir, codeql_langs)

            chunks, codeql_results = await asyncio.gather(run_ast(), run_codeql())
            self._log(job_id, f"  AST: {len(chunks)}関数 | CodeQL: {len(codeql_results)}件\n")

            if codeql_results:
                chunks = codeql_analyzer.apply_to_chunks(chunks, codeql_results)
                confirmed_count = sum(1 for c in chunks if c.codeql_confirmed)
                self._log(job_id, f"  CodeQL証明済み: {confirmed_count}件\n")

            # ===========================
            # Step 3: 複合グループ化（Oracle側）
            # ===========================
            compound_groups = _build_compound_groups(chunks)
            self._log(job_id, f"\n[Step 4.5] 複合グループ: {len(compound_groups)}件\n")

            # ===========================
            # Step 4: LLM解析（RunPod起動）
            # ===========================
            self._log(job_id, "\n[Step 5] LLM解析 - RunPod起動中...\n")
            vllm_url = await self.manager.start_pod()
            self._log(job_id, f"  vLLM URL: {vllm_url}\n")

            # LLM_BASE_URLをRunPodのURLに動的上書き
            os.environ["LLM_BASE_URL"] = vllm_url

            llm_analyzer = VulnAnalyzer()
            total_single   = len(chunks)
            total_compound = len(compound_groups)
            total_funcs    = total_single + total_compound
            self._log(job_id, f"  LLM: 0/{total_funcs} 関数完了 | 脆弱性候補: 0件\n")

            compound_done  = [0]
            compound_vulns = [0]

            async def batch_progress(done, total, vulns):
                self._log(job_id,
                    f"  LLM: {done + compound_done[0]}/{total_funcs} 関数完了 | 脆弱性候補: {vulns + compound_vulns[0]}件\n")

            async def run_compound():
                results = []
                for group in compound_groups:
                    from analyzer.llm import build_compound_prompt
                    prompt = build_compound_prompt(group)
                    r = await llm_analyzer._call_llm(prompt, group[0], is_compound=True, compound_group=group)
                    compound_done[0] += 1
                    if r and r.label.is_vulnerable:
                        compound_vulns[0] += 1
                        results.append(r)
                    self._log(job_id,
                        f"  LLM: {compound_done[0]}/{total_funcs} 関数完了 | 脆弱性候補: {compound_vulns[0]}件\n")
                return results

            single_results, compound_results = await asyncio.gather(
                llm_analyzer.analyze_batch(chunks, progress_callback=batch_progress),
                run_compound(),
            )

            all_vulns: List[VulnSample] = single_results + compound_results
            self._log(
                job_id,
                f"  脆弱性候補: {len(all_vulns)}件 (単一:{len(single_results)} 複合:{len(compound_results)})\n",
            )

            # Step 5完了後はPodをそのまま維持（Step 8で再利用）

            # ===========================
            # Step 6: Dockerサンドボックス検証（Oracle側）
            # ===========================
            no_docker = options.get("no_docker", False)
            if not no_docker and all_vulns:
                self._log(job_id, "\n[Step 7] Dockerサンドボックス検証...\n")
                docker = DockerExecutor()
                verifier = SandboxVerifier(docker)
                all_vulns = await verifier.verify_batch(all_vulns, concurrency=MAX_PARALLEL_DOCKER)
                confirmed = sum(
                    1 for s in all_vulns
                    if s.attack_model.exploitability == Exploitability.CONFIRMED
                )
                self._log(job_id, f"  confirmed: {confirmed}件\n")

            # ===========================
            # Step 7: ReActループ（Oracle側）
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
                    all_vulns = [s for s in all_vulns if id(s) not in react_ids] + list(react_results)

                    # 再停止
                    await self.manager.stop_pod()

            # ===========================
            # Step 8: フィルタ
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
                and not _is_test_path(s.context.file)
            ]
            self._log(job_id, f"\n[Step 9] フィルタ後: {len(filtered)}件\n")

            # ===========================
            # Step 9: レポート生成（Oracle側）
            # ===========================
            self._log(job_id, "\n[Step 10] レポート生成...\n")
            job_report_dir = self.report_dir / job_id
            job_report_dir.mkdir(parents=True, exist_ok=True)

            reporter = ReportGenerator(output_dir=str(job_report_dir))
            report_path = reporter.generate(
                samples=filtered,
                target=job["target_display"],
                format="markdown",
            )
            self._log(job_id, f"  レポート: {report_path}\n")

            # クリーンアップ
            shutil.rmtree(tmpdir, ignore_errors=True)

            # ===========================
            # 完了
            # ===========================
            summary = {
                "files": len(files),
                "functions": len(chunks),
                "total_vulns": len(all_vulns),
                "reported": len(filtered),
                "confirmed": sum(1 for s in filtered if s.attack_model.exploitability == Exploitability.CONFIRMED),
                "practical": sum(1 for s in filtered if s.attack_model.exploitability == Exploitability.PRACTICAL),
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
            # RunPodが起きたままになってないか確認して停止
            try:
                await self.manager.stop_pod()
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
