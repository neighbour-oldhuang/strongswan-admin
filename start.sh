#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  echo "错误：请使用 root 用户运行，例如: sudo bash $0 $*"
  exit 1
fi

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

HOST=${HOST:-0.0.0.0}
PORT=${PORT:-8080}
RELOAD=${RELOAD:-1}
PID_FILE="strongswan-admin.pid"
LOG_FILE="strongswan-admin.log"

case "$1" in
  stop)
    if [ -f "$PID_FILE" ]; then
      kill $(cat "$PID_FILE") && rm "$PID_FILE"
      echo "Stopped."
    else
      echo "Not running."
    fi
    exit 0
    ;;
esac

if [ ! -d .venv ]; then
  echo "Creating virtual environment with $PYTHON..."
  $PYTHON -m venv .venv
fi

# 依赖变更时自动同步
REQ_HASH=$(md5sum requirements.txt 2>/dev/null | cut -d' ' -f1)
LAST_HASH=""
[ -f .venv/.req_hash ] && LAST_HASH=$(cat .venv/.req_hash)
if [ "$REQ_HASH" != "$LAST_HASH" ]; then
  echo "Installing / updating dependencies..."
  .venv/bin/pip install -r requirements.txt
  echo "$REQ_HASH" > .venv/.req_hash
fi

RELOAD_ARGS=""
[ "$RELOAD" = "1" ] && RELOAD_ARGS="--reload --reload-dir ."

if [ "$1" = "-d" ]; then
  echo "Starting in background on http://$HOST:$PORT (log: $LOG_FILE)"
  nohup .venv/bin/uvicorn main:app --host "$HOST" --port "$PORT" $RELOAD_ARGS > "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  echo "PID: $!"
else
  echo "Starting on http://$HOST:$PORT"
  exec .venv/bin/uvicorn main:app --host "$HOST" --port "$PORT" $RELOAD_ARGS
fi
