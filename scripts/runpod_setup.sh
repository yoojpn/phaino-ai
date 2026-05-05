#!/bin/bash
# RunPod RTX 4090 セットアップスクリプト（最新版）
# Qwen3.6-27B + vLLM + CodeQL + Docker を起動する

set -e

echo "======================================"
echo " vulnscan - RunPod セットアップ"
echo "======================================"

# ===========================
# 1. 依存関係インストール
# ===========================
echo "[1/5] 依存関係インストール..."
pip install -q \
    vllm \
    openai \
    requests \
    beautifulsoup4 \
    tree-sitter \
    tree-sitter-python \
    tree-sitter-javascript \
    tree-sitter-java \
    tree-sitter-c \
    tree-sitter-cpp \
    tree-sitter-go \
    tree-sitter-rust \
    huggingface_hub \
    PyGithub \
    tqdm

# ===========================
# 2. CodeQL インストール
# ===========================
echo "[2/5] CodeQL インストール..."
if ! command -v codeql &> /dev/null; then
    cd /workspace
    curl -L --http1.1 \
        https://github.com/github/codeql-cli-binaries/releases/download/v2.19.0/codeql-linux64.zip \
        -o codeql.zip
    unzip -q codeql.zip
    echo 'export PATH=$PATH:/workspace/codeql' >> ~/.bashrc
    export PATH=$PATH:/workspace/codeql

    # クエリパックDL
    codeql pack download codeql/python-queries
    codeql pack download codeql/javascript-queries
    codeql pack download codeql/java-queries
    codeql pack download codeql/go-queries
    codeql pack download codeql/ruby-queries
    echo "[+] CodeQL インストール完了"
else
    echo "[skip] CodeQL すでにインストール済み"
fi

# ===========================
# 3. Qwen3.6-27Bダウンロード
# ===========================
echo "[3/5] Qwen3.6-27B ダウンロード..."
if [ ! -d "/workspace/models/Qwen3.6-27B" ]; then
    python3 -c "
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id='Qwen/Qwen3.6-27B',
    local_dir='/workspace/models/Qwen3.6-27B',
    ignore_patterns=['*.msgpack', '*.h5'],
)
print('[+] ダウンロード完了')
"
else
    echo "[skip] モデルすでに存在"
fi

# ===========================
# 4. vLLM サーバー起動
# ===========================
echo "[4/5] vLLM サーバー起動..."
python3 -m vllm.entrypoints.openai.api_server \
    --model /workspace/models/Qwen3.6-27B \
    --host 0.0.0.0 \
    --port 8000 \
    --dtype float16 \
    --max-model-len 65536 \
    --gpu-memory-utilization 0.90 \
    --enable-prefix-caching \
    --served-model-name "Qwen/Qwen3.6-27B" \
    &

VLLM_PID=$!
echo "[+] vLLM PID: $VLLM_PID"

# 起動待ち
echo "[*] サーバー起動待ち..."
for i in $(seq 1 60); do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo "[+] vLLM 起動完了"
        break
    fi
    sleep 3
done

# ===========================
# 5. vulnscan セットアップ
# ===========================
echo "[5/5] vulnscan セットアップ..."
cd /workspace
if [ ! -d "vulnscan2" ]; then
    echo "[!] vulnscan2ディレクトリが見つかりません"
    echo "    ZIPをアップロードするか git clone してください"
fi

echo ""
echo "======================================"
echo " セットアップ完了！"
echo "======================================"
echo ""
echo "使い方:"
echo "  cd /workspace/vulnscan2"
echo "  python main.py https://github.com/owner/repo"
echo "  python main.py target.zip"
echo "  python main.py https://example.com"
echo ""
echo "オプション:"
echo "  --no-codeql  CodeQL無効"
echo "  --no-docker  Docker無効"
echo "  --no-react   ReActループ無効"
echo "  --format hackerone|bugcrowd|markdown"
echo ""
echo "vLLM API: http://localhost:8000"
echo "======================================"
