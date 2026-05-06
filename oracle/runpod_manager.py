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
    'NVIDIA GeForce RTX 4090', 'NVIDIA A40', 'NVIDIA RTX A5000', 'NVIDIA GeForce RTX 5090',
    'NVIDIA H100 80GB HBM3', 'NVIDIA GeForce RTX 3090', 'NVIDIA RTX A4500', 'NVIDIA L40S',
    'NVIDIA H200', 'NVIDIA L4', 'NVIDIA RTX 6000 Ada Generation', 'NVIDIA A100-SXM4-80GB',
    'NVIDIA RTX 4000 Ada Generation', 'NVIDIA RTX A6000', 'NVIDIA A100 80GB PCIe',
    'NVIDIA RTX 2000 Ada Generation', 'NVIDIA RTX A4000', 'NVIDIA RTX PRO 6000 Blackwell Server Edition',
    'NVIDIA H100 PCIe', 'NVIDIA H100 NVL', 'NVIDIA L40', 'NVIDIA B200',
    'NVIDIA GeForce RTX 3080 Ti', 'NVIDIA RTX PRO 6000 Blackwell Workstation Edition',
    'NVIDIA GeForce RTX 3080', 'NVIDIA GeForce RTX 3070', 'AMD Instinct MI300X OAM',
    'NVIDIA GeForce RTX 4080 SUPER', 'Tesla V100-PCIE-16GB', 'Tesla V100-SXM2-32GB',
    'NVIDIA RTX 5000 Ada Generation', 'NVIDIA GeForce RTX 4070 Ti', 'NVIDIA RTX 4000 SFF Ada Generation',
    'NVIDIA GeForce RTX 3090 Ti', 'NVIDIA RTX A2000', 'NVIDIA GeForce RTX 4080', 'NVIDIA A30',
    'NVIDIA GeForce RTX 5080', 'Tesla V100-FHHL-16GB', 'NVIDIA H200 NVL', 'Tesla V100-SXM2-16GB',
    'NVIDIA RTX PRO 6000 Blackwell Max-Q Workstation Edition', 'NVIDIA A5000 Ada',
    'Tesla V100-PCIE-32GB', 'NVIDIA  RTX A4500', 'NVIDIA  A30', 'NVIDIA GeForce RTX 3080TI',
    'Tesla T4', 'NVIDIA RTX A30',
}

RUNPOD_API_KEY      = os.getenv("RUNPOD_API_KEY", "")
RUNPOD_POD_NAME     = os.getenv("RUNPOD_POD_NAME", "vulnscan")
VLLM_PORT           = int(os.getenv("VLLM_PORT", "8000"))
VLLM_HEALTH_TIMEOUT = int(os.getenv("VLLM_HEALTH_TIMEOUT", "600"))
RUNPOD_API_BASE     = "https://api.runpod.io/graphql"

POD_IMAGE      = os.getenv("RUNPOD_IMAGE", "vllm/vllm-openai:latest")
POD_GPU_TYPE   = os.getenv("RUNPOD_GPU_TYPE", "NVIDIA GeForce RTX 4090")
POD_DISK_SIZE  = int(os.getenv("RUNPOD_DISK_SIZE", "40"))
POD_START_CMD  = os.getenv("RUNPOD_START_CMD", "bash /workspace/vulnscan/scripts/runpod_start.sh")


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
            if RUNPOD_POD_NAME.lower() in (pod.get("name") or "").lower():
                self._pod_id = pod["id"]
                logger.info(f"Pod自動検出: {pod['name']} ({pod['id']})")
                return pod["id"]

        if pods:
            self._pod_id = pods[0]["id"]
            logger.info(f"Pod自動選択（名前不一致）: {pods[0].get('name')} ({pods[0]['id']})")
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
                await asyncio.sleep(30)
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
                if stock in ("High", "Medium") and vram >= 24:
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
                "NVIDIA A100 80GB PCIe":     1,
                "NVIDIA A100-SXM4-80GB":     2,
                "NVIDIA A100 80GB":          3,
                "NVIDIA RTX 6000 Ada Generation": 4,
                "NVIDIA L40":                5,
            }
            filtered = available
            filtered.sort(key=lambda x: (0 if x["stock"] == "High" else 1, x["price"]))
            logger.info(f"GPU優先順: {[(g['name'], g['price'], g['stock']) for g in filtered[:5]]}")
            return [g["id"] for g in filtered]
        except Exception as e:
            logger.warning(f"GPU在庫確認失敗、デフォルト使用: {e}")
            return [
                "NVIDIA GeForce RTX 4090",
                "NVIDIA L40S",
                "NVIDIA RTX 6000 Ada Generation",
                "NVIDIA L40",
                "NVIDIA RTX A5000",
                "NVIDIA GeForce RTX 3090",
                "NVIDIA GeForce RTX 5090",
                "NVIDIA A40",
            ]

    async def _create_pod(self) -> str:
        """REST APIで複数GPUタイプを一括指定してPodを作成。On-demand→Spotの順で試す。"""
        gpu_candidates = await self._get_available_gpus()

        base_payload = {
            "name": RUNPOD_POD_NAME,
            "imageName": POD_IMAGE,
            "gpuTypeIds": [g for g in gpu_candidates if g in VALID_GPU_IDS][:8],
            "gpuCount": 1,
            "containerDiskInGb": int(os.getenv("RUNPOD_DISK_SIZE", "100")),
            "ports": [f"{VLLM_PORT}/http"],
            "dockerStartCmd": [
                "--model", "Qwen/Qwen3.6-27B-FP8",
                "--quantization", "fp8",
                "--max-model-len", "16384",
                "--gpu-memory-utilization", "0.90",
                "--served-model-name", "Qwen/Qwen3.6-27B",
                "--trust-remote-code",
                "--tool-call-parser", "qwen3_coder",
                "--enable-auto-tool-choice",
                "--port", "8000"
            ],
            "env": {
                # vllm/vllm-openai イメージはこれらの環境変数を読む
                "MODEL": os.getenv("MODEL_ID", "Qwen/Qwen3.6-27B-FP8"),
                "VLLM_MODEL": os.getenv("MODEL_ID", "Qwen/Qwen3.6-27B-FP8"),
                "HF_MODEL_ID": os.getenv("MODEL_ID", "Qwen/Qwen3.6-27B-FP8"),
                "VLLM_QUANTIZATION": "fp8",
                "VLLM_MAX_MODEL_LEN": "16384",
                "VLLM_TOOL_CALL_PARSER": "qwen3_coder",
                "VLLM_ENABLE_AUTO_TOOL_CHOICE": "1",
                "VLLM_EXTRA_ARGS": "--tool-call-parser qwen3_coder --enable-auto-tool-choice",
                "VLLM_GPU_MEMORY_UTILIZATION": "0.90",
                "VLLM_SERVED_MODEL_NAME": "Qwen/Qwen3.6-27B",
                "VLLM_TRUST_REMOTE_CODE": "true",
                "VLLM_ENABLE_PREFIX_CACHING": "true",
                "VLLM_DTYPE": "float16",
                "HF_HUB_ENABLE_HF_TRANSFER": "1",
                "HF_HOME": "/runpod-volume/hf_cache",
            },
        }

        attempts = [
            ("Spot",      {**base_payload, "interruptible": True}),
            ("On-demand", {**base_payload, "interruptible": False}),
        ]

        last_error = None
        for label, payload in attempts:
            try:
                logger.info(f"Pod作成試行: {label} / GPUs: {gpu_candidates[:4]}...")
                logger.info(f"Pod作成ペイロード imageName={payload.get('imageName')} gpuTypeIds={payload.get('gpuTypeIds')}")
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
                        logger.info(f"Pod作成成功: {label} ({pod_id}) on {dc} / {gpu}")
                        return pod_id
                    else:
                        err_msg = data.get("error") if isinstance(data, dict) else str(data)
                        logger.warning(f"{label} 失敗: {err_msg}")
                        last_error = err_msg
            except Exception as e:
                logger.warning(f"{label} 例外: {e}")
                last_error = str(e)

        raise RuntimeError(f"利用可能なGPUが見つかりません: {last_error}")

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
