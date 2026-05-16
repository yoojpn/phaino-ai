"""
RunPod管理デーモン
- Pod名でPod IDを自動検索（ID固定不要）
- resume失敗時に新規Pod作成でフォールバック
- pod自動起動 / 停止
- vLLMヘルスチェック
"""

import asyncio
import logging
import os
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("oracle.runpod_manager")

VALID_GPU_IDS = {
    'A40',
    'NVIDIA A40',
    'A100 PCIe',
    'NVIDIA A100 80GB PCIe',
    'A100 SXM',
    'NVIDIA A100-SXM4-80GB',
    'L40',
    'NVIDIA L40',
    'RTX 6000 Ada',
    'NVIDIA RTX 6000 Ada Generation',
    'L40S',
    'NVIDIA L40S',
}

RUNPOD_API_KEY      = os.getenv("RUNPOD_API_KEY", "")
RUNPOD_POD_NAME     = os.getenv("RUNPOD_POD_NAME", "vulnscan")
VLLM_PORT           = int(os.getenv("VLLM_PORT", "8000"))
VLLM_HEALTH_TIMEOUT = int(os.getenv("VLLM_HEALTH_TIMEOUT", "1200"))
RUNPOD_API_BASE     = "https://api.runpod.io/graphql"

POD_IMAGE      = os.getenv("RUNPOD_IMAGE", "vllm/vllm-openai:latest")
POD_GPU_TYPE   = os.getenv("RUNPOD_GPU_TYPE", "NVIDIA GeForce RTX 4090")
POD_DISK_SIZE  = int(os.getenv("RUNPOD_DISK_SIZE", "40"))
POD_START_CMD  = os.getenv("RUNPOD_START_CMD", "bash /workspace/vulnscan/scripts/runpod_start.sh")

# CPUポッド設定（AST解析・taint伝播用）
CPU_POD_NAME        = os.getenv("CPU_POD_NAME", "vulnscan-cpu")
CPU_POD_PORT        = int(os.getenv("CPU_POD_PORT", "8001"))
CPU_POD_IMAGE       = os.getenv("CPU_POD_IMAGE", "python:3.11-slim")
CPU_POD_DISK_SIZE   = int(os.getenv("CPU_POD_DISK_SIZE", "20"))
CPU_POD_HEALTH_TIMEOUT = int(os.getenv("CPU_POD_HEALTH_TIMEOUT", "1800"))
# 8vCPUs 16GB RAM $0.28/hr に対応するRunPodのCPUタイプ
CPU_POD_TYPE        = os.getenv("CPU_POD_TYPE", "cpu3c")  # 有効値: cpu3c/cpu3g/cpu3m/cpu5c/cpu5g/cpu5m
_CPU_POD_INLINE_SCRIPT = (
    "set -e && "
    "apt-get update -qq && apt-get install -y -qq git curl zstd && "
    "pip uninstall -y tree-sitter tree-sitter-languages 2>/dev/null || true && "
    "pip install -q fastapi uvicorn PyGithub httpx pydantic beautifulsoup4 requests "
    "\"tree-sitter==0.21.3\" \"tree-sitter-languages==1.10.2\" && "
    "python3 -c \"from tree_sitter_languages import get_parser; get_parser('java'); print('[CPU] tree_sitter_languages OK')\" && "
    "mkdir -p /workspace && cd /workspace && "
    "rm -rf vulnscan && "
    "git clone https://yoojpn:${GITHUB_TOKEN}@github.com/yoojpn/phaino-ai.git vulnscan && "
    "test -f /workspace/vulnscan/oracle/cpu_worker_server.py || (echo 'ERROR: clone failed' && exit 1) && "
    "echo '[CPU] clone OK: '$(git -C /workspace/vulnscan rev-parse --short HEAD) && "
    # CodeQLバンドルのダウンロード（未インストール時のみ）
    "if [ ! -f /workspace/codeql/codeql ]; then "
    "  echo '[CPU] CodeQLダウンロード中...' && "
    "  cd /workspace && "
    "  for i in 1 2 3; do "
    "    curl -fL --max-time 600 --retry 3 --retry-delay 5 "
    "      https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.24.2/codeql-bundle-linux64.tar.zst "
    "      -o codeql-bundle.tar.zst && break || "
    "    echo \"[CPU] ダウンロード試行${i}失敗、リトライ...\" && sleep 10; "
    "  done && "
    "  tar --use-compress-program=unzstd -xf codeql-bundle.tar.zst && "
    "  rm codeql-bundle.tar.zst && "
    "  /workspace/codeql/codeql --version && "
    "  echo '[CPU] CodeQL準備完了'; "
    "else "
    "  echo '[CPU] CodeQL既存 skip'; "
    "fi && "
    "cd /workspace/vulnscan && "
    "exec uvicorn oracle.cpu_worker_server:app --host 0.0.0.0 --port ${CPU_POD_PORT:-8001} --workers 1"
)
# dockerStartCmd は配列形式で渡す必要がある
_env_cmd = os.getenv("CPU_POD_START_CMD")
CPU_POD_START_CMD: list = _env_cmd.split() if _env_cmd else ["bash", "-c", _CPU_POD_INLINE_SCRIPT]


class CpuPodManager:
    """
    AST解析・多段taint伝播用CPUポッドの管理。
    8vCPUs / 16GB RAM / $0.28/hr のCPUポッドを使う。
    """

    def __init__(self):
        self.api_key = RUNPOD_API_KEY
        self._pod_id: Optional[str] = None
        self._pod_ip: Optional[str] = None
        self._lock = asyncio.Lock()

    def _worker_url(self) -> Optional[str]:
        if self._pod_ip:
            if "proxy.runpod.net" in str(self._pod_ip):
                return f"https://{self._pod_ip}"
            return f"http://{self._pod_ip}:{CPU_POD_PORT}"
        return None

    async def start_pod(self) -> str:
        """CPUポッドを起動してworker URLを返す"""
        async with self._lock:
            url = self._worker_url()
            if url and await self._check_health(url):
                return url

            # 既存podを探す
            pod_id = await self._resolve_pod_id()
            if pod_id:
                try:
                    await self._resume_pod(pod_id)
                    await self._wait_for_ip(pod_id)
                    return await self._wait_for_health()
                except Exception as e:
                    logger.warning(f"[CPU] resume失敗: {e} → 新規作成")
                    try:
                        await self._delete_pod(self._pod_id)
                    except Exception:
                        pass
                    self._pod_id = None

            # 新規作成
            logger.info("[CPU] CPUポッド新規作成中...")
            new_id = await self._create_pod()
            self._pod_id = new_id
            await self._wait_for_ip(new_id)
            return await self._wait_for_health()

    async def stop_pod(self):
        pod_id = self._pod_id or await self._resolve_pod_id()
        if pod_id:
            logger.info(f"[CPU] CPUポッド停止: {pod_id}")
            await self._delete_pod(pod_id)
        self._pod_id = None
        self._pod_ip = None

    async def _resolve_pod_id(self) -> Optional[str]:
        env_id = os.getenv("CPU_POD_ID", "")
        if env_id:
            self._pod_id = env_id
            return env_id
        query = """
        query Pods {
            myself { pods { id name desiredStatus } }
        }
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RUNPOD_API_BASE,
                json={"query": query},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15,
            )
            resp.raise_for_status()
            pods = resp.json().get("data", {}).get("myself", {}).get("pods", [])
        for pod in pods:
            if CPU_POD_NAME.lower() in (pod.get("name") or "").lower():
                self._pod_id = pod["id"]
                return pod["id"]
        return None

    async def _wait_for_ip(self, pod_id: str):
        self._pod_ip = f"{pod_id}-{CPU_POD_PORT}.proxy.runpod.net"
        logger.info(f"[CPU] プロキシURL: https://{self._pod_ip}")

    async def _wait_for_health(self) -> str:
        url = self._worker_url()
        deadline = asyncio.get_event_loop().time() + CPU_POD_HEALTH_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            if await self._check_health(url):
                # バージョン確認
                try:
                    async with httpx.AsyncClient() as client:
                        r = await client.get(f"{url}/health", timeout=5, follow_redirects=True)
                        info = r.json()
                        pod_commit = info.get('commit', '?')
                        logger.info(
                            f"[CPU] CPUワーカー ready | commit={pod_commit} "
                            f"tree_sitter_languages={info.get('tree_sitter_languages','?')}"
                        )
                except Exception:
                    logger.info("[CPU] CPUワーカー ready (health取得失敗)")
                    return url

                # commitミスマッチ確認（Oracleのcommitと比較）
                try:
                    import subprocess
                    expected = subprocess.check_output(
                        ["git", "-C", "/opt/vulnscan", "rev-parse", "--short", "HEAD"],
                        stderr=subprocess.DEVNULL
                    ).decode().strip()
                except Exception:
                    expected = None

                if expected and pod_commit != expected:
                    logger.warning(
                        f"[CPU] commitミスマッチ: pod={pod_commit} oracle={expected} → ポッド再作成"
                    )
                    try:
                        await self._delete_pod(self._pod_id)
                    except Exception:
                        pass
                    self._pod_id = None
                    logger.info("[CPU] CPUポッド新規作成中（commit更新）...")
                    new_id = await self._create_pod()
                    self._pod_id = new_id
                    await self._wait_for_ip(new_id)
                    url = self._worker_url()
                    deadline = asyncio.get_event_loop().time() + CPU_POD_HEALTH_TIMEOUT
                    continue

                # /analyzeエンドポイントの疎通確認（404回避）
                analyze_ok = False
                for _ in range(6):
                    try:
                        async with httpx.AsyncClient() as client:
                            r = await client.post(
                                f"{url}/analyze",
                                json={"target": "__warmup__", "target_type": "github", "options": {}},
                                timeout=5,
                            )
                            # 400/422はエンドポイントが存在する証拠
                            if r.status_code in (200, 400, 422):
                                analyze_ok = True
                                break
                    except Exception:
                        pass
                    await asyncio.sleep(3)

                if not analyze_ok:
                    logger.warning("[CPU] /analyze未応答、さらに待機...")
                    await asyncio.sleep(10)
                    continue

                return url
            await asyncio.sleep(5)
        raise RuntimeError("CPUワーカー起動タイムアウト")

    async def _check_health(self, base_url: str) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{base_url}/health", timeout=5, follow_redirects=True
                )
                return resp.status_code == 200
        except Exception:
            return False

    async def _resume_pod(self, pod_id: str):
        mutation = """
        mutation ResumePod($input: PodResumeInput!) {
            podResume(input: $input) { id desiredStatus }
        }
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RUNPOD_API_BASE,
                json={"query": mutation,
                      "variables": {"input": {"podId": pod_id}}},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("errors"):
                raise RuntimeError(f"podResume error: {data['errors']}")

    async def _create_pod(self) -> str:
        """CPUポッドを新規作成（RunPod CPU Pod API）"""
        payload = {
            "name": CPU_POD_NAME,
            "imageName": CPU_POD_IMAGE,
            "cloudType": "COMMUNITY",
            "computeType": "CPU",
            "cpuFlavorIds": [CPU_POD_TYPE],
            "vcpuCount": 4,
            "containerDiskInGb": CPU_POD_DISK_SIZE,
            "ports": [f"{CPU_POD_PORT}/http"],
            "dockerStartCmd": CPU_POD_START_CMD,
            "env": {
                "VULNSCAN_ROOT": "/workspace/vulnscan",
                "CPU_POD_PORT": str(CPU_POD_PORT),
                "GITHUB_TOKEN": os.getenv("GITHUB_TOKEN", ""),
            },
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://rest.runpod.io/v1/pods",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=30,
            )
            data = resp.json()
            if resp.status_code in (200, 201) and isinstance(data, dict) and data.get("id"):
                logger.info(f"[CPU] ポッド作成成功: {data['id']}")
                return data["id"]
            raise RuntimeError(f"CPUポッド作成失敗: {data}")

    async def _delete_pod(self, pod_id: str):
        mutation = """
        mutation TerminatePod($input: PodTerminateInput!) {
            podTerminate(input: $input)
        }
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RUNPOD_API_BASE,
                json={"query": mutation,
                      "variables": {"input": {"podId": pod_id}}},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15,
            )
            resp.raise_for_status()


class RunPodManager:

    def __init__(self):
        self.api_key  = RUNPOD_API_KEY
        self._pod_id: Optional[str] = None
        self._pod_ip: Optional[str] = None
        self._pod_port: Optional[int] = None
        self._lock = asyncio.Lock()

    # ===========================
    # Pod ID自動解決
    # ===========================
    async def _resolve_pod_id(self) -> Optional[str]:
        """Pod名からPod IDを自動検索して返す。見つからなければNone"""
        env_id = os.getenv("RUNPOD_POD_ID", "")
        if env_id:
            self._pod_id = env_id
            return env_id

        query = """
        query Pods {
            myself {
                pods { id name desiredStatus }
            }
        }
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RUNPOD_API_BASE,
                json={"query": query},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15,
            )
            resp.raise_for_status()
            pods = resp.json().get("data", {}).get("myself", {}).get("pods", [])

        for pod in pods:
            pod_name = (pod.get("name") or "").lower()
            # CPUポッドを除外してGPUポッドのみ検出
            if CPU_POD_NAME.lower() in pod_name:
                continue
            if RUNPOD_POD_NAME.lower() in pod_name:
                self._pod_id = pod["id"]
                logger.info(f"Pod自動検出: {pod['name']} ({pod['id']})")
                return pod["id"]

        # フォールバック: CPUポッド以外の最初のポッド
        for pod in pods:
            pod_name = (pod.get("name") or "").lower()
            if CPU_POD_NAME.lower() not in pod_name:
                self._pod_id = pod["id"]
                logger.info(f"Pod自動選択（名前不一致）: {pod.get('name')} ({pod['id']})")
                return self._pod_id

        return None

    # ===========================
    # 状態取得
    # ===========================
    async def get_status(self) -> Dict[str, Any]:
        if not self.api_key:
            return {"configured": False, "message": "RUNPOD_API_KEY が未設定"}
        try:
            pod_id = await self._resolve_pod_id()
            if not pod_id:
                return {"configured": True, "pod_status": "no_pod", "vllm_healthy": False}
            info = await self._get_pod_info(pod_id)
            vllm_url = self._vllm_url()
            vllm_healthy = False
            if vllm_url:
                vllm_healthy = await self._check_vllm_health(vllm_url)
            return {
                "configured": True,
                "pod_id": pod_id,
                "pod_status": info.get("desiredStatus", "unknown"),
                "pod_ip": self._pod_ip,
                "vllm_url": vllm_url,
                "vllm_healthy": vllm_healthy,
            }
        except Exception as e:
            return {"configured": True, "error": str(e)}

    # ===========================
    # 起動（resume → 失敗時は新規作成）
    # ===========================
    async def start_pod(self) -> str:
        async with self._lock:
            url = self._vllm_url()
            if url and await self._check_vllm_health(url):
                return url

            pod_id = await self._resolve_pod_id()

            if pod_id:
                # まずresumeを試みる
                try:
                    logger.info(f"Resuming pod {pod_id}...")
                    await self._resume_pod(pod_id)
                    pod_id = await self._wait_for_ip(pod_id)
                    if pod_id:
                        return await self._wait_for_vllm()
                except Exception as e:
                    logger.warning(f"Resume失敗: {e} → 新規Pod作成にフォールバック")
                    # 古いPodを削除してから新規作成
                    try:
                        await self._delete_pod(self._pod_id)
                        logger.info(f"古いPod {self._pod_id} を削除しました")
                    except Exception as del_e:
                        logger.warning(f"古いPod削除失敗（無視）: {del_e}")
                    self._pod_id = None

            # 新規Pod作成
            logger.info("新規Pod作成中...")
            new_pod_id = await self._create_pod()
            self._pod_id = new_pod_id
            logger.info(f"新規Pod作成完了: {new_pod_id}")

            await self._wait_for_ip(new_pod_id)
            return await self._wait_for_vllm()

    # ===========================
    # 停止
    # ===========================
    async def stop_pod(self):
        pod_id = self._pod_id or await self._resolve_pod_id()
        if pod_id:
            logger.info(f"Terminating pod {pod_id}...")
            await self._delete_pod(pod_id)
        self._pod_ip = None
        self._pod_port = None

    # ===========================
    # 内部ヘルパー
    # ===========================
    async def _wait_for_ip(self, pod_id: str) -> Optional[str]:
        """RunPodプロキシURLを設定（IPは不要）"""
        self._pod_ip = f"{pod_id}-{VLLM_PORT}.proxy.runpod.net"
        self._pod_port = 443
        logger.info(f"RunPodプロキシURL設定: https://{self._pod_ip}/v1")
        return pod_id

    async def _wait_for_vllm(self) -> str:
        """vLLMがhealthyになるまで待つ"""
        vllm_url = self._vllm_url()
        deadline = asyncio.get_event_loop().time() + VLLM_HEALTH_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            if await self._check_vllm_health(vllm_url):
                logger.info("vLLM healthy")
                return vllm_url
            await asyncio.sleep(5)
        raise RuntimeError("vLLM起動タイムアウト")

    # ===========================
    # RunPod GraphQL API
    # ===========================
    async def _get_pod_info(self, pod_id: str) -> Dict:
        """REST APIでPod情報を取得"""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://rest.runpod.io/v1/pods/{pod_id}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            # publicIpがあればpod_ipを更新
            public_ip = data.get("publicIp", "")
            if public_ip:
                self._pod_ip = public_ip
                self._pod_port = VLLM_PORT
            return data

    async def _resume_pod(self, pod_id: str):
        mutation = """
        mutation ResumePod($input: PodResumeInput!) {
            podResume(input: $input) { id desiredStatus }
        }
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RUNPOD_API_BASE,
                json={"query": mutation, "variables": {"input": {"podId": pod_id, "gpuCount": 1}}},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            # resumeが失敗した場合（GPUなし等）はエラーを投げる
            if data.get("errors"):
                raise RuntimeError(f"podResume error: {data['errors']}")

    async def _get_available_gpus(self) -> list:
        """リアルタイム在庫確認して使えるGPUをコスパ順に返す"""
        query = """
        query {
            gpuTypes {
                id
                displayName
                memoryInGb
                lowestPrice(input: {gpuCount: 1, minMemoryInGb: 20}) {
                    stockStatus
                    uninterruptablePrice
                }
            }
        }
        """
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    RUNPOD_API_BASE,
                    json={"query": query},
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=15,
                )
                resp.raise_for_status()
                gpu_types = resp.json().get("data", {}).get("gpuTypes", [])

            available = []
            for g in gpu_types:
                lp = g.get("lowestPrice") or {}
                stock = lp.get("stockStatus", "")
                price = lp.get("uninterruptablePrice") or 9999
                vram = g.get("memoryInGb", 0)
                if stock in ("High", "Medium", "Low") and vram >= 45 and (lp.get("uninterruptablePrice") or 9999) < 1.60:
                    available.append({
                        "id": g["id"],
                        "name": g["displayName"],
                        "vram": vram,
                        "price": price,
                        "stock": stock,
                    })

            # High優先、同じstockなら安い順
            logger.info(f"GPU在庫確認: {[(g['name'], g['price'], g['stock']) for g in available[:5]]}")
            # 4090に性能・金額が近いGPUを優先するスコアリング
            GPU_PRIORITY = {
                "A40":                       1,
                "NVIDIA A40":                1,
                "A100 PCIe":                 2,
                "NVIDIA A100 80GB PCIe":     2,
                "A100 SXM":                  3,
                "NVIDIA A100-SXM4-80GB":     3,
            }
            filtered = available
            filtered.sort(key=lambda x: (GPU_PRIORITY.get(x["name"], 99), 0 if x["stock"] == "High" else 1, x["price"]))
            logger.info(f"GPU優先順: {[(g['name'], g['price'], g['stock']) for g in filtered[:5]]}")
            return [g["id"] for g in filtered]
        except Exception as e:
            logger.warning(f"GPU在庫確認失敗、デフォルト使用: {e}")
            return ["NVIDIA A100 80GB PCIe", "NVIDIA A100-SXM4-80GB"]

    async def _create_pod(self) -> str:
        """REST APIでA40のみ指定してPodを作成。A40以外は使わない。"""
        gpu_count = 1
        # A40のみ。在庫APIに出てこなくても試行する。
        a40_ids = ["NVIDIA A40"]
        gpu_attempts = [a40_ids]

        last_error = None
        for gpu_ids in gpu_attempts:
            logger.info(f"Pod作成GPU試行: {gpu_ids}")
            result = await self._try_create_pod(gpu_ids, gpu_count)
            if result:
                return result
            last_error = f"GPU {gpu_ids} で作成失敗"
        raise RuntimeError(f"利用可能なGPUが見つかりません: {last_error}")

    async def _try_create_pod(self, selected_gpus: list, gpu_count: int) -> str | None:
        """指定GPUリストでPod作成を試みる。成功したらPod IDを返す。"""
        base_payload = {
            "name": RUNPOD_POD_NAME,
            "imageName": POD_IMAGE,
            "gpuTypeIds": selected_gpus,
            "gpuCount": gpu_count,
            "containerDiskInGb": int(os.getenv("RUNPOD_DISK_SIZE", "100")),
            "ports": [f"{VLLM_PORT}/http"],
            "dockerStartCmd": [
                "--model", "Qwen/Qwen3.6-27B-FP8",
                "--dtype", "auto",
                "--max-model-len", "16384",
                "--gpu-memory-utilization", "0.85",
                "--served-model-name", "Qwen/Qwen3.6-27B",
                "--trust-remote-code",
                "--tool-call-parser", "pythonic",
                "--enable-auto-tool-choice",
                "--enable-prefix-caching",
                "--max-num-seqs", "32",
                "--port", "8000"
            ],
            "env": {
                # vllm/vllm-openai イメージはこれらの環境変数を読む
                "MODEL": os.getenv("MODEL_ID", "Qwen/Qwen3.6-27B-FP8"),
                "VLLM_MODEL": os.getenv("MODEL_ID", "Qwen/Qwen3.6-27B-FP8"),
                "HF_MODEL_ID": os.getenv("MODEL_ID", "Qwen/Qwen3.6-27B-FP8"),
                "VLLM_DTYPE": "bfloat16",
                "VLLM_MAX_MODEL_LEN": "16384",
                "VLLM_TOOL_CALL_PARSER": "hermes",
                "VLLM_ENABLE_AUTO_TOOL_CHOICE": "1",
                "VLLM_EXTRA_ARGS": "--tool-call-parser hermes --enable-auto-tool-choice",
                "VLLM_GPU_MEMORY_UTILIZATION": "0.90",
                "VLLM_SERVED_MODEL_NAME": "Qwen/Qwen3.6-27B",
                "VLLM_TRUST_REMOTE_CODE": "true",
                "VLLM_ENABLE_PREFIX_CACHING": "true",
                "VLLM_DTYPE": "float16",
                "HF_HUB_ENABLE_HF_TRANSFER": "1",
                "HF_HOME": "/runpod-volume/hf_cache",
                "VLLM_WORKER_MULTIPROC_METHOD": "spawn",
                "VLLM_USE_V1": "0",
                "NCCL_SHM_DISABLE": "1",
                "NCCL_P2P_DISABLE": "1",
            },
        }

        payload = {**base_payload, "interruptible": False}
        try:
            logger.info(f"Pod作成試行: GPUs: {selected_gpus}")
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://rest.runpod.io/v1/pods",
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    timeout=30,
                )
                data = resp.json()
                if resp.status_code in (200, 201) and isinstance(data, dict) and data.get("id"):
                    pod_id = data["id"]
                    dc = data.get("machine", {}).get("dataCenterId", "?")
                    gpu = data.get("machine", {}).get("gpuTypeId", "?")
                    logger.info(f"Pod作成成功: ({pod_id}) on {dc} / {gpu}")
                    return pod_id
                else:
                    err_msg = data.get("error") if isinstance(data, dict) else str(data)
                    logger.warning(f"Pod作成失敗: {err_msg}")
                    return None
        except Exception as e:
            logger.warning(f"Pod作成例外: {e}")
            return None

    async def _delete_pod(self, pod_id: str):
        mutation = """
        mutation TerminatePod($input: PodTerminateInput!) {
            podTerminate(input: $input)
        }
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RUNPOD_API_BASE,
                json={"query": mutation, "variables": {"input": {"podId": pod_id}}},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15,
            )
            resp.raise_for_status()

    async def _stop_pod_api(self, pod_id: str):
        mutation = """
        mutation StopPod($input: PodStopInput!) {
            podStop(input: $input) { id desiredStatus }
        }
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                RUNPOD_API_BASE,
                json={"query": mutation, "variables": {"input": {"podId": pod_id}}},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15,
            )
            resp.raise_for_status()

    async def _check_vllm_health(self, base_url: str) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                # base_urlから/v1を除いたベースURLで/healthを叩く
                base = base_url.replace("/v1", "")
                resp = await client.get(f"{base}/health", timeout=5, follow_redirects=True)
                return resp.status_code == 200
        except Exception:
            return False

    def _vllm_url(self) -> Optional[str]:
        if self._pod_ip:
            if "proxy.runpod.net" in str(self._pod_ip):
                return f"https://{self._pod_ip}/v1"
            return f"http://{self._pod_ip}:{self._pod_port}/v1"
        return None
