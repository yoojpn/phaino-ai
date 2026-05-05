"""
CodeQL統合モジュール
taint analysisでsource→sinkフローを証明する

役割：除外フィルタではなく優先度付けに使う
      全関数はLLMに渡す（CodeQL未検出でも）
"""

import os
import re
import json
import asyncio
import tempfile
import subprocess
from pathlib import Path
from typing import List, Dict, Optional

from config import (
    CODEQL_PATH, CODEQL_DB_DIR, CODEQL_TIMEOUT,
    CODEQL_LANGUAGES,
)
from parser.ast_parser import FunctionChunk




class CodeQLResult:
    def __init__(
        self,
        file: str,
        start_line: int,
        end_line: int,
        message: str,
        rule_id: str,
        flow: List[str],
    ):
        self.file       = file
        self.start_line = start_line
        self.end_line   = end_line
        self.message    = message
        self.rule_id    = rule_id
        self.flow       = flow  # source→sinkのフロー


class CodeQLAnalyzer:

    def __init__(self):
        self._check_codeql()
        os.makedirs(CODEQL_DB_DIR, exist_ok=True)

    def _check_codeql(self):
        try:
            result = subprocess.run(
                [CODEQL_PATH, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                print(f"[+] CodeQL: {result.stdout.strip().split(chr(10))[0]}")
            else:
                print("[!] CodeQL: 使用不可")
        except Exception:
            print("[!] CodeQL: インストールされていません")

    async def analyze(
        self,
        repo_path: str,
        language: str,
        db_name: str = "vulnscan_db",
    ) -> List[CodeQLResult]:
        """
        リポジトリをCodeQLで解析する

        Args:
            repo_path: 解析対象のリポジトリパス
            language: 対象言語
            db_name: CodeQLデータベース名

        Returns:
            CodeQLResultのリスト
        """
        codeql_lang = CODEQL_LANGUAGES.get(language)
        if not codeql_lang:
            print(f"[!] CodeQL: {language}は非対応")
            return []

        db_path = Path(CODEQL_DB_DIR) / db_name

        # DBビルド
        print(f"[*] CodeQL DBビルド: {language}")
        built = await self._build_database(repo_path, codeql_lang, str(db_path))
        if not built:
            return []

        # クエリ実行
        print(f"[*] CodeQL クエリ実行: {language}")
        results = await self._run_queries(str(db_path), codeql_lang)
        print(f"[+] CodeQL: {len(results)}件のフローを検出")
        return results

    async def analyze_multi_language(
        self,
        repo_path: str,
        languages: List[str],
    ) -> List[CodeQLResult]:
        """複数言語を並列解析"""
        tasks = []
        for i, lang in enumerate(languages):
            if lang in CODEQL_LANGUAGES:
                tasks.append(
                    self.analyze(repo_path, lang, f"vulnscan_db_{lang}_{i}")
                )

        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        all_results  = []
        for r in results_list:
            if isinstance(r, list):
                all_results.extend(r)
        return all_results

    async def _build_database(
        self, repo_path: str, language: str, db_path: str
    ) -> bool:
        """CodeQLデータベースをビルド"""
        # 既存DBを削除
        if Path(db_path).exists():
            import shutil
            shutil.rmtree(db_path, ignore_errors=True)

        cmd = [
            CODEQL_PATH, "database", "create",
            db_path,
            f"--language={language}",
            f"--source-root={repo_path}",
            "--overwrite",
        ]

        try:
            loop   = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=CODEQL_TIMEOUT,
                )
            )
            if result.returncode == 0:
                print(f"  [+] DBビルド成功: {language}")
                return True
            else:
                print(f"  [-] DBビルド失敗: {result.stderr[:200]}")
                return False
        except subprocess.TimeoutExpired:
            print(f"  [-] DBビルドタイムアウト: {language}")
            return False
        except Exception as e:
            print(f"  [-] DBビルドエラー: {e}")
            return False

    async def _run_queries(
        self, db_path: str, language: str
    ) -> List[CodeQLResult]:
        """セキュリティクエリを実行してSARIFを取得"""
        # クエリパック（言語別）
        # CWE個別指定（CodeQL 2.19.0互換）
        cwe_packs = {
            "python": [
                "codeql/python-queries@0.6.3:Security/CWE-089",
                "codeql/python-queries@0.6.3:Security/CWE-078",
                "codeql/python-queries@0.6.3:Security/CWE-022",
                "codeql/python-queries@0.6.3:Security/CWE-079",
                "codeql/python-queries@0.6.3:Security/CWE-918",
            ],
            "javascript": [
                "codeql/javascript-queries@0.9.3:Security/CWE-089",
                "codeql/javascript-queries@0.9.3:Security/CWE-079",
                "codeql/javascript-queries@0.9.3:Security/CWE-022",
                "codeql/javascript-queries@0.9.3:Security/CWE-078",
            ],
            "java": [
                "codeql/java-queries@0.7.5:Security/CWE-089",
                "codeql/java-queries@0.7.5:Security/CWE-079",
                "codeql/java-queries@0.7.5:Security/CWE-022",
                "codeql/java-queries@0.7.5:Security/CWE-078",
            ],
            "go": [
                "codeql/go-queries@0.7.3:Security/CWE-089",
                "codeql/go-queries@0.7.3:Security/CWE-079",
                "codeql/go-queries@0.7.3:Security/CWE-022",
            ],
            "ruby": [
                "codeql/ruby-queries@0.7.4:Security/CWE-089",
                "codeql/ruby-queries@0.7.4:Security/CWE-079",
                "codeql/ruby-queries@0.7.4:Security/CWE-022",
            ],
        }
        query_pack = cwe_packs.get(language)
        if not query_pack:
            return []

        # SARIF出力先
        sarif_path = tempfile.mktemp(suffix=".sarif")

        cmd = [
            CODEQL_PATH, "database", "analyze",
            db_path,
            *query_pack,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "--threads=4",
        ]

        try:
            loop   = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=CODEQL_TIMEOUT * 2,
                )
            )
            if result.returncode != 0:
                print(f"  [-] クエリ実行失敗: {result.stderr[:200]}")
                return []

            return self._parse_sarif(sarif_path)

        except Exception as e:
            print(f"  [-] クエリ実行エラー: {e}")
            return []
        finally:
            if Path(sarif_path).exists():
                os.unlink(sarif_path)

    def _parse_sarif(self, sarif_path: str) -> List[CodeQLResult]:
        """SARIFファイルをパースしてCodeQLResultに変換"""
        try:
            with open(sarif_path, "r", encoding="utf-8") as f:
                sarif = json.load(f)
        except Exception as e:
            print(f"  [-] SARIFパースエラー: {e}")
            return []

        results = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                rule_id  = result.get("ruleId", "")
                message  = result.get("message", {}).get("text", "")

                # 場所情報
                locations = result.get("locations", [])
                if not locations:
                    continue

                loc       = locations[0]
                phys_loc  = loc.get("physicalLocation", {})
                artifact  = phys_loc.get("artifactLocation", {})
                region    = phys_loc.get("region", {})

                file_uri   = artifact.get("uri", "")
                start_line = region.get("startLine", 0)
                end_line   = region.get("endLine", start_line)

                # フロー情報（CodeFlows）
                flow = []
                for code_flow in result.get("codeFlows", []):
                    for thread_flow in code_flow.get("threadFlows", []):
                        for loc_item in thread_flow.get("locations", []):
                            step_loc = loc_item.get("location", {})
                            step_msg = step_loc.get("message", {}).get("text", "")
                            step_phys = step_loc.get("physicalLocation", {})
                            step_line = step_phys.get("region", {}).get("startLine", 0)
                            if step_msg:
                                flow.append(f"Line {step_line}: {step_msg}")

                results.append(CodeQLResult(
                    file=file_uri,
                    start_line=start_line,
                    end_line=end_line,
                    message=message,
                    rule_id=rule_id,
                    flow=flow,
                ))

        return results

    def apply_to_chunks(
        self,
        chunks: List[FunctionChunk],
        codeql_results: List[CodeQLResult],
    ) -> List[FunctionChunk]:
        """
        CodeQLの結果をFunctionChunkに反映する

        CodeQL検出済みの関数を優先度1に格上げ
        フロー情報をchunkに付与
        """
        for result in codeql_results:
            result_file = result.file.replace("file://", "")

            for chunk in chunks:
                # ファイルと行番号でマッチ
                if (chunk.file_path in result_file or
                        result_file.endswith(chunk.file_path)):

                    if (chunk.start_line <= result.start_line <= chunk.end_line or
                            chunk.start_line <= result.end_line <= chunk.end_line):

                        # CodeQL確認済みとしてマーク
                        chunk.codeql_confirmed = True
                        chunk.codeql_flow      = result.flow

                        # 優先度を1に格上げ
                        if chunk.priority > 1:
                            chunk.priority        = 1
                            chunk.priority_reason = (
                                f"CodeQL証明済み: {result.rule_id}, "
                                + chunk.priority_reason
                            )

        return chunks
