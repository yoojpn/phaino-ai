#!/bin/bash
# ============================================================
# setup_network_volume.sh
# RunPod Network Volumeにモデル・ツールを準備するスクリプト
#
# 手順:
#   1. RunPodでNetwork Volumeを作成（30GB, $2.1/月）
#   2. Network VolumeをマウントしたCPU Podを一時起動
#   3. このスクリプトをCPU Pod上で実行（$0.01〜0.02/時間）
#   4. 完了後CPU Podを削除
#
# 使い方（CPU Pod上で実行）:
#   bash /workspace/setup_network_volume.sh
# ============================================================

set -e

VOLUME_BASE="${VOLUME_BASE:-/workspace}"
MODEL_DIR="${MODEL_DIR:-$VOLUME_BASE/models}"
CODEQL_DIR="${CODEQL_DIR:-$VOLUME_BASE/codeql}"
VULNSCAN_DIR="${VULNSCAN_DIR:-$VOLUME_BASE/vulnscan}"
CODEQL_VERSION="v2.20.3"
MODEL_ID="${MODEL_ID:-Qwen/Qwen3-30B-A3B}"  # MoE 30B(アクティブ3B) - 4090に最適

echo "============================================================"
echo " vulnscan - Network Volume セットアップ"
echo "============================================================"
echo "  Volume base : $VOLUME_BASE"
echo "  Model       : $MODEL_ID"
echo "  CodeQL      : $CODEQL_VERSION"
echo ""

# ===========================
# 1. Pythonパッケージ（volume内に入れる）
# ===========================
echo "[1/4] Pythonパッケージインストール..."
pip install -q \
    huggingface_hub \
    hf_transfer

echo "  [+] huggingface_hub インストール完了"

# ===========================
# 2. Qwen3モデルダウンロード
# ===========================
echo ""
echo "[2/4] モデルダウンロード中..."
echo "  モデル: $MODEL_ID"
echo "  保存先: $MODEL_DIR"

mkdir -p "$MODEL_DIR"

MODEL_LOCAL_DIR="$MODEL_DIR/$(echo $MODEL_ID | tr '/' '_')"

if [ -d "$MODEL_LOCAL_DIR" ] && [ "$(ls -A $MODEL_LOCAL_DIR 2>/dev/null)" ]; then
    echo "  [skip] モデルはすでに存在します: $MODEL_LOCAL_DIR"
else
    echo "  ダウンロード開始（数分〜十数分かかります）..."
    HF_HUB_ENABLE_HF_TRANSFER=1 python3 -c "
from huggingface_hub import snapshot_download
import os

local_dir = '$MODEL_LOCAL_DIR'
print(f'  -> {local_dir}')
snapshot_download(
    repo_id='$MODEL_ID',
    local_dir=local_dir,
    ignore_patterns=['*.msgpack', '*.h5', 'flax_model*', 'tf_model*'],
)
print('[+] モデルダウンロード完了')
"
fi

echo "  [+] モデル準備完了: $MODEL_LOCAL_DIR"
du -sh "$MODEL_LOCAL_DIR" 2>/dev/null || true

# ===========================
# 3. CodeQL CLI インストール
# ===========================
echo ""
echo "[3/4] CodeQL インストール..."

mkdir -p "$CODEQL_DIR"

if command -v "$CODEQL_DIR/codeql/codeql" &>/dev/null || \
   [ -f "$CODEQL_DIR/codeql/codeql" ]; then
    echo "  [skip] CodeQL はすでにインストール済みです"
else
    echo "  CodeQL $CODEQL_VERSION をダウンロード中..."
    cd "$CODEQL_DIR"
    curl -sSL \
        "https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip" \
        -o codeql.zip
    unzip -q codeql.zip
    rm codeql.zip
    echo "  [+] CodeQL バイナリ展開完了"

    # クエリパック（6言語並列DL）
    echo "  クエリパックをダウンロード中..."
    export PATH="$CODEQL_DIR/codeql:$PATH"

    declare -A PACKS=(
        [python]="codeql/python-queries"
        [javascript]="codeql/javascript-queries"
        [java]="codeql/java-queries"
        [go]="codeql/go-queries"
        [ruby]="codeql/ruby-queries"
        [cpp]="codeql/cpp-queries"
    )

    PIDS=()
    for lang in "${!PACKS[@]}"; do
        pack="${PACKS[$lang]}"
        echo "    DL: $pack"
        "$CODEQL_DIR/codeql/codeql" pack download "$pack" > "/tmp/codeql_${lang}.log" 2>&1 &
        PIDS+=($!)
    done

    for pid in "${PIDS[@]}"; do
        wait "$pid" || true
    done

    echo "  [+] CodeQLクエリパック完了"
fi

# パス設定を保存
cat > "$VOLUME_BASE/env.sh" << ENVEOF
# vulnscan 環境変数（RunPod起動時に source する）
export PATH="\$PATH:$CODEQL_DIR/codeql"
export CODEQL_PATH="$CODEQL_DIR/codeql/codeql"
export MODEL_DIR="$MODEL_LOCAL_DIR"
export VULNSCAN_ROOT="$VULNSCAN_DIR"
ENVEOF

echo "  [+] 環境変数ファイル: $VOLUME_BASE/env.sh"

# ===========================
# 4. vulnscanコード配置確認
# ===========================
echo ""
echo "[4/4] vulnscanコード確認..."

if [ -d "$VULNSCAN_DIR" ] && [ -f "$VULNSCAN_DIR/main.py" ]; then
    echo "  [+] vulnscanコードはすでに存在します"
else
    echo "  [!] vulnscanコードが見つかりません"
    echo "      WSLからデプロイするか、以下のコマンドでコピーしてください:"
    echo "      scp -P <PORT> -r /path/to/vulnscan root@<POD-IP>:$VULNSCAN_DIR"
fi

# ===========================
# 完了
# ===========================
echo ""
echo "============================================================"
echo " セットアップ完了！"
echo "============================================================"
echo ""
echo "  モデル    : $MODEL_LOCAL_DIR"
echo "  CodeQL    : $CODEQL_DIR/codeql"
echo "  env.sh    : $VOLUME_BASE/env.sh"
echo ""
echo "次のステップ:"
echo "  1. このCPU Podを削除（削除してもVolumeのデータは残ります）"
echo "  2. RunPodでGPU Pod（RTX 4090）を作成し、同じVolumeをマウント"
echo "  3. GPU Pod起動後は scripts/runpod_start.sh だけで即使用可能"
echo ""
du -sh "$VOLUME_BASE"/* 2>/dev/null | sort -h || true
echo ""
