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

# Python 版本检测（需要 >= 3.9）
MIN_MAJOR=3
MIN_MINOR=9
PYTHON=""
for cmd in python3.12 python3.11 python3.10 python3.9 python3; do
  if command -v "$cmd" &>/dev/null; then
    ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
    major=${ver%%.*}
    minor=${ver##*.}
    if [ "$major" -ge "$MIN_MAJOR" ] 2>/dev/null && [ "$minor" -ge "$MIN_MINOR" ] 2>/dev/null; then
      PYTHON="$cmd"
      break
    fi
  fi
done
if [ -z "$PYTHON" ]; then
  echo "错误：需要 Python >= ${MIN_MAJOR}.${MIN_MINOR}，当前系统未找到合适版本。"
  echo ""
  echo "安装方法："
  if command -v apt-get &>/dev/null; then
    echo "  sudo apt-get update && sudo apt-get install -y python3.11"
  elif command -v dnf &>/dev/null; then
    echo "  sudo dnf install -y python3.11"
  elif command -v yum &>/dev/null; then
    echo "  sudo yum install -y python3.11"
  else
    echo "  请手动安装 Python >= ${MIN_MAJOR}.${MIN_MINOR}"
  fi
  exit 1
fi

# 确保虚拟环境和依赖就绪
if [ ! -d "$APP_DIR/.venv" ]; then
  echo "创建虚拟环境 ($PYTHON)..."
  $PYTHON -m venv "$APP_DIR/.venv"
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
