#!/usr/bin/env bash
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行: sudo bash $0"
  exit 1
fi

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST=${HOST:-0.0.0.0}
PORT=${PORT:-8080}
SERVICE_NAME="strongswan-admin"

# 确保虚拟环境和依赖就绪
if [ ! -d "$APP_DIR/.venv" ]; then
  echo "创建虚拟环境..."
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=StrongSwan Admin Web Console
After=network.target strongswan.service

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/uvicorn main:app --host ${HOST} --port ${PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}

echo "✅ 已安装并启动 ${SERVICE_NAME} 服务"
echo "   目录: ${APP_DIR}"
echo "   地址: http://${HOST}:${PORT}"
echo ""
echo "常用命令:"
echo "   systemctl status  ${SERVICE_NAME}"
echo "   systemctl stop    ${SERVICE_NAME}"
echo "   systemctl restart ${SERVICE_NAME}"
echo "   journalctl -u ${SERVICE_NAME} -f"
