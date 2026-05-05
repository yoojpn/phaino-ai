#!/bin/bash
set -e

VOLUME_BASE="${VOLUME_BASE:-/workspace}"
VLLM_PORT="${VLLM_PORT:-8000}"
VLLM_HOST="${VLLM_HOST:-0.0.0.0}"
MAX_MODEL_LEN="${MAX_MODEL_LEN:-32768}"
GPU_MEMORY_UTIL="${GPU_MEMORY_UTIL:-0.90}"
MODEL_ID="${MODEL_ID:-Qwen/Qwen3.6-27B-FP8}"
MODEL_DIR="${MODEL_DIR:-/workspace/models/Qwen3.6-27B-FP8}"

echo "============================================================"
echo " vulnscan RunPod - vLLM 起動"
echo "============================================================"
echo "  Model   : $MODEL_DIR ($MODEL_ID)"
echo "  Port    : $VLLM_PORT"
echo ""

if ! python3 -c "import vllm" 2>/dev/null; then
    echo "[1/3] vLLMインストール..."
    pip install -q vllm openai "huggingface_hub[cli]"
    echo "  [+] 完了"
else
    echo "[1/3] vLLM済み (skip)"
    pip install -q "huggingface_hub[cli]" 2>/dev/null || true
fi

echo ""
echo "[2/3] モデル確認..."
if [ ! -f "$MODEL_DIR/config.json" ]; then
    echo "  ダウンロード中: $MODEL_ID"
    mkdir -p "$MODEL_DIR"
    huggingface-cli download "$MODEL_ID" \
        --local-dir "$MODEL_DIR" \
        --local-dir-use-symlinks False \
        ${HF_TOKEN:+--token "$HF_TOKEN"}
    echo "  [+] 完了"
else
    echo "  確認済み (skip)"
fi

echo ""
echo "[3/3] vLLM起動..."
VRAM_GB=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | awk '{printf "%.0f", $1/1024}' | head -1)
echo "  VRAM: ${VRAM_GB}GB / モード: FP8"

if pgrep -f "vllm.entrypoints" > /dev/null 2>&1; then
    pkill -f "vllm.entrypoints" || true
    sleep 3
fi

VLLM_LOG="/tmp/vllm.log"

python3 -m vllm.entrypoints.openai.api_server \
    --model "$MODEL_DIR" \
    --host "$VLLM_HOST" \
    --port "$VLLM_PORT" \
    --dtype float16 \
    --quantization fp8 \
    --max-model-len "$MAX_MODEL_LEN" \
    --gpu-memory-utilization "$GPU_MEMORY_UTIL" \
    --enable-prefix-caching \
    --served-model-name "Qwen/Qwen3.6-27B" \
    --trust-remote-code \
    >> "$VLLM_LOG" 2>&1 &

VLLM_PID=$!
echo "  PID: $VLLM_PID | ログ: $VLLM_LOG"

echo ""
echo "  ヘルスチェック中（最大15分）..."
for i in $(seq 1 180); do
    if kill -0 "$VLLM_PID" 2>/dev/null; then
        if curl -sf "http://localhost:$VLLM_PORT/health" > /dev/null 2>&1; then
            echo ""
            echo "============================================================"
            echo " vLLM 起動完了！"
            echo "============================================================"
            exit 0
        fi
    else
        echo ""
        echo "[ERROR] vLLMプロセス終了"
        tail -20 "$VLLM_LOG"
        exit 1
    fi
    sleep 5
    printf "."
done

echo ""
echo "[ERROR] 起動タイムアウト（15分）"
tail -30 "$VLLM_LOG"
exit 1
