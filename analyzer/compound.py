"""
複合脆弱性解析補助モジュール
関数間の依存関係を解析してグループを構築する
"""

import re
from typing import List, Dict, Set, Tuple
from parser.ast_parser import FunctionChunk


class CompoundAnalyzer:
    """
    関数呼び出しグラフを構築して
    複合脆弱性の候補グループを特定する
    """

    def build_call_graph(
        self, chunks: List[FunctionChunk]
    ) -> Dict[str, List[str]]:
        """
        関数呼び出しグラフを構築

        Returns:
            {関数名: [呼び出している関数名のリスト]}
        """
        func_names = {c.function_name for c in chunks}
        call_graph: Dict[str, List[str]] = {}

        for chunk in chunks:
            called = []
            for name in func_names:
                if name == chunk.function_name:
                    continue
                # コード内に関数名が呼び出し形式で登場するか
                pattern = rf"\b{re.escape(name)}\s*\("
                if re.search(pattern, chunk.code):
                    called.append(name)
            call_graph[chunk.function_name] = called

        return call_graph

    def find_compound_groups(
        self,
        chunks: List[FunctionChunk],
        max_groups: int = 20,
    ) -> List[List[FunctionChunk]]:
        """
        複合脆弱性候補グループを特定

        戦略:
        1. 関数呼び出しグラフでリンクされた関数群
        2. 同一ファイルの認証+処理の組み合わせ
        3. source関数 + sink関数のペア
        """
        groups = []
        chunk_map = {c.function_name: c for c in chunks}

        # 戦略1: 呼び出しグラフベース
        call_graph = self.build_call_graph(chunks)
        for func_name, called_funcs in call_graph.items():
            if not called_funcs:
                continue
            caller = chunk_map.get(func_name)
            if not caller or caller.priority > 4:
                continue
            group = [caller] + [
                chunk_map[f] for f in called_funcs
                if f in chunk_map and chunk_map[f].priority <= 5
            ]
            if len(group) >= 2:
                groups.append(group[:4])

        # 戦略2: 認証 + 処理 の組み合わせ
        auth_funcs = [
            c for c in chunks
            if any(k in c.function_name.lower()
                   for k in ["auth", "login", "verify", "check", "validate"])
            and c.priority <= 4
        ]
        data_funcs = [
            c for c in chunks
            if any(k in c.function_name.lower()
                   for k in ["get", "fetch", "query", "select", "read", "load"])
            and c.priority <= 4
        ]
        for auth in auth_funcs[:5]:
            for data in data_funcs[:5]:
                if auth.file_path == data.file_path:
                    groups.append([auth, data])

        # 戦略3: source + sink のペア（異なるファイル間）
        source_funcs = [c for c in chunks if c.priority <= 2]
        for i, src in enumerate(source_funcs[:10]):
            for dst in source_funcs[i+1:i+4]:
                if src.file_path != dst.file_path:
                    groups.append([src, dst])

        # 重複除去・上限
        seen   = set()
        unique = []
        for group in groups:
            key = frozenset(c.function_name for c in group)
            if key not in seen:
                seen.add(key)
                unique.append(group)
            if len(unique) >= max_groups:
                break

        return unique
