#!/bin/bash
# ============================================================
# deploy_oracle.sh
# WSL → Oracle Free Tier へのデプロイスクリプト
#
# 使い方（WSLから実行）:
#   bash scripts/deploy_oracle.sh <ORACLE_IP>
#
# 例:
#   bash scripts/deploy_oracle.sh 140.238.xxx.xxx
# ============================================================

set -e

ORACLE_IP="${1:?使い方: $0 <ORACLE_IP>}"
ORACLE_USER="${ORACLE_USER:-ubuntu}"
ORACLE_PORT="${ORACLE_PORT:-22}"
REMOTE_DIR="${REMOTE_DIR:-/opt/vulnscan}"
SSH_KEY="${SSH_KEY:-~/.ssh/oracle_key}"

SSH_OPTS="-i $SSH_KEY -p $ORACLE_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=10"
SSH="ssh $SSH_OPTS $ORACLE_USER@$ORACLE_IP"
SCP="scp $SSH_OPTS"

echo "============================================================"
echo " vulnscan → Oracle Free Tier デプロイ"
echo "============================================================"
echo "  宛先: $ORACLE_USER@$ORACLE_IP:$REMOTE_DIR"
echo ""

# ===========================
# 1. 接続確認
# ===========================
echo "[1/5] SSH接続確認..."
$SSH "echo '  [+] SSH接続OK'" || {
    echo "  [ERROR] SSH接続に失敗しました"
    echo "  確認事項:"
    echo "    - Oracle インスタンスが起動しているか"
    echo "    - セキュリティリストで22番ポートが開いているか"
    echo "    - SSH鍵のパス: $SSH_KEY"
    exit 1
}

# ===========================
# 2. コードを転送
# ===========================
echo ""
echo "[2/5] コード転送..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VULNSCAN_DIR="$(dirname "$SCRIPT_DIR")"

# ZIPに固めて転送（rsyncでもOKだが依存なしで動くように）
TMPZIP="/tmp/vulnscan_deploy_$$.zip"
cd "$VULNSCAN_DIR/.."
zip -qr "$TMPZIP" vulnscan/ \
    --exclude "vulnscan/__pycache__/*" \
    --exclude "vulnscan/*/\__pycache__/*" \
    --exclude "vulnscan/.git/*" \
    --exclude "vulnscan/reports/*" \
    --exclude "vulnscan/*.zip"

echo "  ZIPサイズ: $(du -sh $TMPZIP | cut -f1)"
$SCP -r "$TMPZIP" "$ORACLE_USER@$ORACLE_IP:/tmp/vulnscan_deploy.zip"
rm -f "$TMPZIP"
echo "  [+] コード転送完了"

# ===========================
# 3. リモートでセットアップ
# ===========================
echo ""
echo "[3/5] リモートセットアップ..."
$SSH << REMOTE
set -e

# 展開
sudo mkdir -p $REMOTE_DIR
sudo chown $ORACLE_USER:$ORACLE_USER $REMOTE_DIR
cd $REMOTE_DIR/..
unzip -qo /tmp/vulnscan_deploy.zip
rm /tmp/vulnscan_deploy.zip
echo "  [+] コード展開完了"

# Python依存パッケージ
echo "  依存パッケージインストール..."
cd $REMOTE_DIR
pip3 install -q --user \
    fastapi \
    uvicorn[standard] \
    jinja2 \
    python-multipart \
    httpx \
    aiofiles \
    tree-sitter \
    tree-sitter-python \
    tree-sitter-javascript \
    tree-sitter-java \
    tree-sitter-go \
    tree-sitter-rust \
    PyGithub \
    beautifulsoup4 \
    requests \
    aiohttp
echo "  [+] パッケージインストール完了"

# DBディレクトリ
sudo mkdir -p /var/lib/vulnscan
sudo chown $ORACLE_USER:$ORACLE_USER /var/lib/vulnscan

# レポート・アップロードディレクトリ
mkdir -p /tmp/vulnscan_reports /tmp/vulnscan_uploads

echo "  [+] セットアップ完了"
REMOTE

# ===========================
# 4. .env ファイルを設定
# ===========================
echo ""
echo "[4/5] 環境変数ファイル確認..."

ENV_FILE="$VULNSCAN_DIR/.env.oracle"
if [ ! -f "$ENV_FILE" ]; then
    echo "  .env.oracle が見つかりません。テンプレートを作成します..."
    cat > "$ENV_FILE" << 'EOF'
# Oracle Free Tier 環境変数
# ここを編集してから再デプロイしてください

RUNPOD_API_KEY=your_runpod_api_key_here
RUNPOD_POD_ID=your_pod_id_here
VLLM_PORT=8000

DB_PATH=/var/lib/vulnscan/jobs.db
UPLOAD_DIR=/tmp/vulnscan_uploads
REPORT_DIR=/tmp/vulnscan_reports
VULNSCAN_ROOT=/opt/vulnscan
MAX_UPLOAD_MB=200
EOF
    echo "  [!] $ENV_FILE を編集してから再実行してください"
    echo "  必須項目: RUNPOD_API_KEY, RUNPOD_POD_ID"
else
    $SCP "$ENV_FILE" "$ORACLE_USER@$ORACLE_IP:$REMOTE_DIR/.env"
    echo "  [+] .env 転送完了"
fi

# ===========================
# 5. systemdサービス登録・起動
# ===========================
echo ""
echo "[5/5] systemdサービス設定..."
$SSH << REMOTE
set -e

# systemdサービスファイル
sudo tee /etc/systemd/system/vulnscan.service > /dev/null << 'SERVICE'
[Unit]
Description=phaino_ai vulnscan Web Server
After=network.target

[Service]
Type=simple
User=$ORACLE_USER
WorkingDirectory=$REMOTE_DIR
EnvironmentFile=$REMOTE_DIR/.env
ExecStart=/usr/bin/python3 -m uvicorn oracle.app:app --host 0.0.0.0 --port 8080 --workers 1
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable vulnscan
sudo systemctl restart vulnscan
sleep 3
sudo systemctl status vulnscan --no-pager | head -20
REMOTE

echo ""
echo "============================================================"
echo " デプロイ完了！"
echo "============================================================"
echo ""
echo "  Web UI: http://$ORACLE_IP:8080"
echo ""
echo "ポート開放（Oracle側のセキュリティリスト）："
echo "  Ingress: TCP 8080 from 0.0.0.0/0"
echo ""
echo "ログ確認:"
echo "  ssh -i $SSH_KEY $ORACLE_USER@$ORACLE_IP 'journalctl -u vulnscan -f'"
