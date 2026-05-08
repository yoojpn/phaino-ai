"""
vulnscan - 脆弱性検出特化AIパイプライン（最新版）
並列実行で高速化

使い方:
  python main.py https://github.com/owner/repo
  python main.py target.zip
  python main.py https://example.com
"""

import asyncio
import sys
import argparse
import tempfile
import os
from datetime import datetime
from pathlib import Path
from typing import List, Set

from config import (
    MIN_EXPLOITABILITY, REPORT_FORMAT, OUTPUT_DIR,
    MAX_PARALLEL_DOCKER,
)
from input.loader import InputLoader
from parser.ast_parser import ChunkPipeline, FunctionChunk
from analyzer.llm import VulnAnalyzer, OmniscientContext
from analyzer.react_loop import ReActLoop
from sandbox.attacker import DockerExecutor
from sandbox.verifier import SandboxVerifier
from reporter.report import ReportGenerator
from schema import VulnSample, Exploitability, Severity


def parse_args():
    parser = argparse.ArgumentParser(description="vulnscan - 脆弱性検出パイプライン")
    parser.add_argument("target", help="スキャン対象（GitHub URL / ZIP / URL）")
    parser.add_argument("--format", choices=["hackerone","bugcrowd","markdown"],
                        default=REPORT_FORMAT)
    parser.add_argument("--min-exploitability",
                        choices=["theoretical","practical","confirmed"],
                        default=MIN_EXPLOITABILITY)
    parser.add_argument("--no-docker",  action="store_true", help="Docker無効")
    parser.add_argument("--no-react",   action="store_true", help="ReActループ無効")
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    return parser.parse_args()


async def run_pipeline(args):
    start = datetime.now()
    print(f"""
╔══════════════════════════════════════════╗
║  vulnscan - 脆弱性検出パイプライン       ║
╚══════════════════════════════════════════╝
Target  : {args.target}
Docker  : {'無効' if args.no_docker else '有効'}
ReAct   : {'無効' if args.no_react else '有効'}
""")

    # ===========================
    # Step 1: 入力取得
    # ===========================
    print("=" * 45)
    print("[Step 1] コード取得")
    print("=" * 45)
    loader = InputLoader()
    files  = loader.load(args.target)
    if not files:
        print("[-] コードファイルが見つかりません")
        return

    # 言語の収集
    languages: Set[str] = {f.language for f in files}
    print(f"  言語: {languages}")

    # ===========================
    # Step 2: AST解析
    # ===========================
    print("\n" + "=" * 45)
    print("[Step 2] AST解析")
    print("=" * 45)

    tmpdir = tempfile.mkdtemp(prefix="vulnscan_repo_")
    for f in files:
        file_path = Path(tmpdir) / f.path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(f.content, encoding="utf-8", errors="ignore")

    ast_pipeline = ChunkPipeline()
    chunks = ast_pipeline.process(files)

    print(f"\n[+] AST: {len(chunks)}関数")

    # ===========================
    # Step 3: 全知コンテキスト構築
    # ===========================
    print("\n" + "=" * 45)
    print("[Step 3] 全知コンテキスト構築（クロスファイル呼び出しグラフ）")
    print("=" * 45)
    omniscient = OmniscientContext(chunks)
    omniscient.build()
    print(f"[+] 呼び出しグラフ: {len(omniscient.call_graph)}関数")

    # ===========================
    # Step 4: 複合脆弱性グループ化
    # ===========================
    print("\n" + "=" * 45)
    print("[Step 4] クロスファイル解析・複合グループ化")
    print("=" * 45)
    compound_groups = _build_compound_groups(chunks)
    print(f"[+] 複合解析グループ: {len(compound_groups)}件")

    # ===========================
    # Step 5+5.5: LLM解析 並列実行
    # ===========================
    print("\n" + "=" * 45)
    print("[Step 5+5.5] LLM解析（単一 + 複合 並列）")
    print("=" * 45)
    llm_analyzer = VulnAnalyzer()

    single_task   = llm_analyzer.analyze_batch(chunks, omniscient=omniscient)
    compound_task = llm_analyzer.analyze_compound(compound_groups)

    single_results, compound_results = await asyncio.gather(
        single_task,
        compound_task,
    )

    all_vulns = single_results + compound_results
    print(f"\n[+] 脆弱性候補合計: {len(all_vulns)}件")
    print(f"    単一: {len(single_results)}件")
    print(f"    複合: {len(compound_results)}件")

    # ===========================
    # Step 7: Dockerサンドボックス検証（並列）
    # ===========================
    if not args.no_docker and all_vulns:
        print("\n" + "=" * 45)
        print("[Step 7] Dockerサンドボックス検証（並列）")
        print("=" * 45)

        docker   = DockerExecutor()
        verifier = SandboxVerifier(docker)
        all_vulns = await verifier.verify_batch(
            all_vulns, concurrency=MAX_PARALLEL_DOCKER
        )

        confirmed = sum(1 for s in all_vulns
                        if s.attack_model.exploitability == Exploitability.CONFIRMED)
        print(f"[+] Docker検証完了: confirmed={confirmed}件")

    # ===========================
    # Step 8: ReActループ（高severity候補のみ）
    # ===========================
    if not args.no_react:
        react_targets = [
            s for s in all_vulns
            if (s.attack_model.exploitability == Exploitability.PRACTICAL
                and s.label.severity in (Severity.HIGH, Severity.CRITICAL))
        ][:5]  # 最大5件

        if react_targets:
            print("\n" + "=" * 45)
            print(f"[Step 8] ReActループ ({len(react_targets)}件)")
            print("=" * 45)
            docker     = DockerExecutor()
            react_loop = ReActLoop(docker)
            react_tasks = [react_loop.run(s) for s in react_targets]
            react_results = await asyncio.gather(*react_tasks)

            # 元のリストを更新
            react_ids = {id(s) for s in react_targets}
            all_vulns = [
                s for s in all_vulns if id(s) not in react_ids
            ] + list(react_results)

    # ===========================
    # Step 9: フィルタ
    # ===========================
    exp_order = {
        Exploitability.THEORETICAL: 0,
        Exploitability.PRACTICAL:   1,
        Exploitability.CONFIRMED:   2,
    }
    min_level = exp_order[Exploitability(args.min_exploitability)]
    filtered  = [
        s for s in all_vulns
        if exp_order.get(s.attack_model.exploitability, 0) >= min_level
    ]

    # ===========================
    # Step 10: レポート生成
    # ===========================
    print("\n" + "=" * 45)
    print("[Step 10] レポート生成")
    print("=" * 45)
    reporter    = ReportGenerator(output_dir=args.output_dir)
    report_path = reporter.generate(
        samples=filtered,
        target=args.target,
        format=args.format,
    )

    # クリーンアップ
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    elapsed = (datetime.now() - start).total_seconds()
    print(f"""
╔══════════════════════════════════════════╗
║  スキャン完了                            ║
╚══════════════════════════════════════════╝
所要時間  : {elapsed:.1f}秒（{elapsed/60:.1f}分）
解析関数  : {len(chunks)}件
脆弱性候補: {len(all_vulns)}件
報告対象  : {len(filtered)}件
  - confirmed: {sum(1 for s in filtered if s.attack_model.exploitability == Exploitability.CONFIRMED)}件
  - practical: {sum(1 for s in filtered if s.attack_model.exploitability == Exploitability.PRACTICAL)}件
レポート  : {report_path}
""")


def _build_compound_groups(
    chunks: List[FunctionChunk],
    group_size: int = 3,
    max_groups: int = 20,
) -> List[List[FunctionChunk]]:
    """
    複合脆弱性解析のためのグループを構築

    同一ファイル内の優先度の高い関数をグループ化
    """
    groups = []
    # ファイルごとにグループ化
    file_chunks: dict = {}
    for chunk in chunks:
        if chunk.priority <= 3:  # 優先度1〜3のみ対象
            file_chunks.setdefault(chunk.file_path, []).append(chunk)

    for file_path, file_chunk_list in file_chunks.items():
        if len(file_chunk_list) >= 2:
            # 同一ファイルの優先度高い関数をグループとして追加
            groups.append(file_chunk_list[:group_size])
        if len(groups) >= max_groups:
            break

    return groups





def main():
    args = parse_args()
    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    main()
