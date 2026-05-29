#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="${BASE_DIR}/.venv"
if [ -x "${VENV}/bin/uvicorn" ]; then
  UVCMD="${VENV}/bin/uvicorn"
else
  UVCMD="$(which uvicorn || true)"
fi
if [ $# -lt 1 ]; then
  echo "Usage: $0 start|stop|status"
  exit 2
fi
CMD="$1"
case "$CMD" in
  start)
    echo "Starting runner (uvicorn runner:app)..."
    if [ -z "$UVCMD" ]; then
      echo "uvicorn not found; install requirements in ${VENV} or ensure uvicorn is on PATH"
      exit 1
    fi
    "$UVCMD" runner:app --host 127.0.0.1 --port 5001 &
    echo $! > "${BASE_DIR}/runner.pid"
    echo "runner started pid $(cat ${BASE_DIR}/runner.pid)"
    ;;
  stop)
    if [ -f "${BASE_DIR}/runner.pid" ]; then
      kill "$(cat ${BASE_DIR}/runner.pid)" || true
      rm -f "${BASE_DIR}/runner.pid"
      echo "runner stopped"
    else
      echo "no pid file"
    fi
    ;;
  status)
    if [ -f "${BASE_DIR}/runner.pid" ] && kill -0 "$(cat ${BASE_DIR}/runner.pid)" 2>/dev/null; then
      echo "running pid $(cat ${BASE_DIR}/runner.pid)"
    else
      echo "not running"
    fi
    ;;
  *)
    echo "unknown command"
    exit 2
    ;;
esac
