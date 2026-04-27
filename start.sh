#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  echo "错误：请使用 root 用户运行，例如: sudo bash $0 $*"
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
  echo "Creating virtual environment..."
  python3 -m venv .venv
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
