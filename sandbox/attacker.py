"""
Dockerサンドボックス - 攻撃者環境
pwntools / AFL++ / gdb / AddressSanitizer を統合
"""

import os
import asyncio
import tempfile
import subprocess
from pathlib import Path
from typing import Optional


ATTACKER_DOCKERFILE = """
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 基本ツール
RUN apt-get update && apt-get install -y \\
    python3 python3-pip nodejs npm \\
    openjdk-17-jdk-headless php-cli \\
    golang-go \\
    gcc g++ gdb \\
    clang llvm \\
    libasan6 libasan8 \\
    curl wget netcat-openbsd \\
    git build-essential \\
    && rm -rf /var/lib/apt/lists/*

# Python セキュリティツール
RUN pip3 install pwntools requests

# AFL++
RUN apt-get update && apt-get install -y afl++ && rm -rf /var/lib/apt/lists/*

# pwndbg（gdb拡張）
RUN git clone https://github.com/pwndbg/pwndbg /opt/pwndbg && \\
    cd /opt/pwndbg && ./setup.sh

WORKDIR /sandbox

# 非rootユーザー（セキュリティ）
RUN useradd -m -u 1000 attacker
"""

TARGET_DOCKERFILE = """
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \\
    python3 python3-pip nodejs npm \\
    openjdk-17-jdk-headless php-cli \\
    golang-go ruby \\
    gcc g++ \\
    libasan6 \\
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install flask django fastapi uvicorn

WORKDIR /target
EXPOSE 8080
"""

DOCKER_COMPOSE = """
version: '3.8'

services:
  target:
    build:
      context: .
      dockerfile: Dockerfile.target
    ports:
      - "8080:8080"
    networks:
      - sandbox_net
    mem_limit: 512m
    cpus: 0.5

  attacker:
    build:
      context: .
      dockerfile: Dockerfile.attacker
    depends_on:
      - target
    networks:
      - sandbox_net
    volumes:
      - ./results:/results
    mem_limit: 1g
    cpus: 1.0

networks:
  sandbox_net:
    driver: bridge
    internal: true  # 外部ネットワーク遮断
"""


class DockerExecutor:
    """Docker環境でツールを実行するクライアント"""

    def __init__(self, sandbox_dir: str = "/tmp/vulnscan_sandbox"):
        self.sandbox_dir = sandbox_dir
        os.makedirs(sandbox_dir, exist_ok=True)
        self._docker_available = self._check_docker()

    def _check_docker(self) -> bool:
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    # ===========================
    # WebApp系ツール
    # ===========================
    async def run_http_request(
        self,
        url: str,
        method: str = "GET",
        payload: str = "",
        headers: dict = None,
    ) -> str:
        """HTTPリクエストを送信してレスポンスを返す"""
        headers = headers or {}
        header_args = " ".join(f'-H "{k}: {v}"' for k, v in headers.items())

        if method == "GET":
            cmd = f'curl -s -m 10 {header_args} "{url}?{payload}"'
        else:
            cmd = f'curl -s -m 10 -X {method} {header_args} -d "{payload}" "{url}"'

        return await self._run_in_docker(cmd, "attacker")

    async def run_sql_test(
        self,
        code: str,
        language: str,
        payload: str = "' OR 1=1--",
    ) -> str:
        """SQLインジェクションをテスト"""
        test_code = self._wrap_code_for_test(code, language, payload)
        return await self._run_code_in_docker(test_code, language)

    async def run_cmd_test(
        self,
        code: str,
        language: str,
        payload: str = "; id",
    ) -> str:
        """コマンドインジェクションをテスト"""
        test_code = self._wrap_code_for_test(code, language, payload)
        return await self._run_code_in_docker(test_code, language)

    async def run_path_test(
        self,
        code: str,
        language: str,
        payload: str = "../../etc/passwd",
    ) -> str:
        """パストラバーサルをテスト"""
        test_code = self._wrap_code_for_test(code, language, payload)
        return await self._run_code_in_docker(test_code, language)

    async def run_ssrf_test(
        self,
        code: str,
        language: str,
        url: str = "http://169.254.169.254/",
    ) -> str:
        """SSRFをテスト"""
        test_code = self._wrap_code_for_test(code, language, url)
        return await self._run_code_in_docker(test_code, language)

    # ===========================
    # メモリ・バイナリ系ツール
    # ===========================
    async def run_afl(
        self,
        code: str,
        language: str,
        function: str,
        timeout: int = 30,
    ) -> str:
        """AFL++でfuzzingを実行"""
        if language not in ("c", "cpp"):
            return "AFL++: C/C++のみ対応"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".c", delete=False, dir=self.sandbox_dir
        ) as f:
            f.write(code)
            src_path = f.name

        cmd = f"""
cd /sandbox && \\
    AFL_SKIP_CPUFREQ=1 afl-fuzz -i /sandbox/inputs -o /sandbox/outputs \\
    -t {timeout*1000} -- ./target @@
"""
        return await self._run_in_docker(cmd, "attacker")

    async def run_gdb(
        self,
        code: str,
        payload: str = "",
    ) -> str:
        """GDB + pwndbgでメモリ解析"""
        gdb_script = f"""
set pagination off
run {payload}
info registers
backtrace
x/20x $sp
quit
"""
        return await self._run_in_docker(
            f"echo '{gdb_script}' | gdb -batch -x /dev/stdin ./target",
            "attacker",
        )

    async def run_asan(
        self,
        code: str,
        language: str,
        payload: str = "",
    ) -> str:
        """AddressSanitizerでメモリエラーを検出"""
        if language not in ("c", "cpp"):
            return "ASan: C/C++のみ対応"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".c", delete=False, dir=self.sandbox_dir
        ) as f:
            f.write(code)
            src_path = f.name

        compile_cmd = f"gcc -fsanitize=address -o /sandbox/asan_target {src_path}"
        run_cmd     = f"/sandbox/asan_target {payload}"

        result = await self._run_in_docker(compile_cmd, "attacker")
        result += await self._run_in_docker(run_cmd, "attacker")
        return result

    async def run_libfuzzer(
        self,
        code: str,
        harness: str,
        language: str,
        timeout: int = 30,
    ) -> str:
        """
        libFuzzerでメモリ安全性バグを検出。
        code: 脆弱な関数のコード
        harness: LLMが生成したlibFuzzerハーネスコード
        """
        if language not in ("c", "cpp"):
            return "libFuzzer: C/C++のみ対応"

        ext = ".cpp" if language == "cpp" else ".c"
        compiler = "clang++" if language == "cpp" else "clang"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, delete=False, dir=self.sandbox_dir
        ) as f:
            # ハーネスと対象コードを結合
            combined = f"{code}\n\n{harness}"
            f.write(combined)
            src_path = f.name

        compile_cmd = (
            f"{compiler} -fsanitize=fuzzer,address -O1 "
            f"-o /sandbox/fuzz_target {src_path}"
        )
        run_cmd = (
            f"timeout {timeout} /sandbox/fuzz_target "
            f"-max_total_time={timeout} -max_len=4096 2>&1 | tail -30"
        )

        result = await self._run_in_docker(compile_cmd, "attacker")
        if "error:" in result.lower():
            return f"libFuzzer compile error:\n{result[:500]}"
        result += await self._run_in_docker(run_cmd, "attacker")
        return result

    # ===========================
    # ユーティリティ
    # ===========================
    async def _run_in_docker(self, cmd: str, container: str = "attacker") -> str:
        """Dockerコンテナでコマンドを実行"""
        if not self._docker_available:
            return f"[Docker unavailable] Would run: {cmd[:100]}"

        try:
            loop   = asyncio.get_event_loop()
            docker_args = [
                "docker", "run", "--rm",
                "--network", "none",
                "--memory", "256m",
                "--cpus", "0.5",
                "--read-only",
                "--tmpfs", "/tmp",
                "--tmpfs", "/sandbox",
                "-v", f"{self.sandbox_dir}:{self.sandbox_dir}:ro",
                "vulnscan-attacker:latest",
                "bash", "-c", cmd,
            ]
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    docker_args,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            )
            return (result.stdout + result.stderr)[:2000]
        except subprocess.TimeoutExpired:
            return "Timeout"
        except Exception as e:
            return f"Error: {e}"

    async def _run_code_in_docker(self, code: str, language: str) -> str:
        """コードをDockerで実行"""
        ext_map = {
            "python": ".py", "javascript": ".js",
            "java": ".java", "php": ".php",
            "go": ".go", "ruby": ".rb",
        }
        cmd_map = {
            "python": "python3", "javascript": "node",
            "php": "php", "ruby": "ruby",
        }

        ext = ext_map.get(language, ".py")
        cmd = cmd_map.get(language, "python3")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, delete=False,
            dir=self.sandbox_dir, prefix="vulnscan_test_"
        ) as f:
            f.write(code)
            tmp_path = f.name

        try:
            return await self._run_in_docker(
                f"{cmd} {tmp_path}",
                "attacker",
            )
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def _wrap_code_for_test(
        self,
        code: str,
        language: str,
        payload: str,
    ) -> str:
        """テスト用にコードをラップする"""
        if language == "python":
            return f"""
{code}

# Test execution
import sys
try:
    # Find the main function and call it with payload
    result = None
    for name, obj in list(globals().items()):
        if callable(obj) and not name.startswith('_'):
            try:
                result = obj({repr(payload)})
                print(f"RESULT: {{result}}")
                break
            except TypeError:
                try:
                    result = obj()
                    print(f"RESULT: {{result}}")
                    break
                except Exception as e:
                    print(f"ERROR: {{e}}")
except Exception as e:
    print(f"EXEC_ERROR: {{e}}")
"""
        elif language == "javascript":
            return f"""
{code}

// Test execution
try {{
    const payload = {json.dumps(payload) if payload else '""'};
    const funcs = Object.keys(global).filter(k => typeof global[k] === 'function');
    for (const name of funcs) {{
        try {{
            const result = global[name](payload);
            console.log('RESULT:', result);
            break;
        }} catch(e) {{
            console.log('ERROR:', e.message);
        }}
    }}
}} catch(e) {{
    console.log('EXEC_ERROR:', e.message);
}}
"""
        else:
            return code


import json  # top-level importが必要
