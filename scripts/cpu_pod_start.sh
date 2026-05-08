#!/bin/bash
# CPUポッド起動スクリプト
# 8vCPUs / 16GB RAM / $0.28/hr

set -e

echo "[CPU Worker] 起動開始..."

# 依存インストール
pip install -q \
    fastapi \
    uvicorn \
    tree-sitter==0.21.3 \
    tree-sitter-languages==1.10.2 \
    PyGithub>=2.3.0 \
    beautifulsoup4>=4.12.0 \
    requests>=2.31.0 \
    httpx \
    pydantic

echo "[CPU Worker] pip install完了"

# vulnscanをクローン（最新版）
mkdir -p /workspace
cd /workspace
if [ ! -d "vulnscan/.git" ]; then
    echo "[CPU Worker] git clone..."
    rm -rf vulnscan
    git clone https://yoojpn:${GITHUB_TOKEN}@github.com/yoojpn/phaino-ai.git vulnscan || {
        echo "[CPU Worker] git clone失敗、リトライ..."
        sleep 5
        git clone https://yoojpn:${GITHUB_TOKEN}@github.com/yoojpn/phaino-ai.git vulnscan
    }
else
    echo "[CPU Worker] git pull..."
    cd vulnscan
    git fetch origin || true
    git reset --hard origin/main || true
    cd ..
fi

export VULNSCAN_ROOT=/workspace/vulnscan
export CPU_POD_PORT=${CPU_POD_PORT:-8001}

cd /workspace/vulnscan

echo "[CPU Worker] ワーカーサーバー起動 port=${CPU_POD_PORT}"
exec uvicorn oracle.cpu_worker_server:app \
    --host 0.0.0.0 \
    --port ${CPU_POD_PORT} \
    --workers 4
