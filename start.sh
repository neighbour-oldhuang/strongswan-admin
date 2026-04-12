#!/usr/bin/env bash
# 需要 root 权限（写 /etc/swanctl/）
set -e
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi

HOST=${HOST:-0.0.0.0}
PORT=${PORT:-8080}
RELOAD=${RELOAD:-1}

RELOAD_ARGS=""
if [ "$RELOAD" = "1" ]; then
  RELOAD_ARGS="--reload --reload-dir ."
fi

echo "Starting StrongSwan Admin on http://$HOST:$PORT (auto-reload: $RELOAD)"
exec .venv/bin/uvicorn main:app --host "$HOST" --port "$PORT" $RELOAD_ARGS
