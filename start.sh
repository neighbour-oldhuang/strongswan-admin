#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

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
  .venv/bin/pip install -q -r requirements.txt
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
