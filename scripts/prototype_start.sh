#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${SHIGURE_PROTOTYPE_HOST:-0.0.0.0}"
PORT="${SHIGURE_PROTOTYPE_PORT:-8765}"
DB="${SHIGURE_PROTOTYPE_DB:-$ROOT/.scratch/prototype-p0/prototype.sqlite3}"
LOG="${SHIGURE_PROTOTYPE_LOG:-$ROOT/.scratch/prototype-p0/server.log}"
PID_FILE="${SHIGURE_PROTOTYPE_PID:-$ROOT/.scratch/prototype-p0/server.pid}"
ADMIN_TOKEN="${SHIGURE_PROTOTYPE_ADMIN_TOKEN:-dev-admin-token}"
ENROLLMENT_TOKEN="${SHIGURE_PROTOTYPE_ENROLLMENT_TOKEN:-dev-token}"

cd "$ROOT"
mkdir -p "$(dirname "$DB")" "$(dirname "$LOG")"

if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
  echo "Prototype server already responds on http://127.0.0.1:${PORT}"
  echo "UI: http://127.0.0.1:${PORT}/ui"
  exit 0
fi

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install -e . >/tmp/shigure-prototype-pip.log

OPEN_EDR_MDR_PROFILE=dev \
OPEN_EDR_MDR_ADMIN_TOKEN="$ADMIN_TOKEN" \
OPEN_EDR_MDR_DEV_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" \
.venv/bin/python -m open_edr_mdr_agent.cli serve \
  --host "$HOST" \
  --port "$PORT" \
  --db "$DB" \
  --profile dev >"$LOG" 2>&1 &

SERVER_PID=$!
echo "$SERVER_PID" >"$PID_FILE"

for _ in $(seq 1 80); do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    echo "Prototype server started"
    echo "PID: $SERVER_PID"
    echo "DB: $DB"
    echo "Log: $LOG"
    echo "UI: http://127.0.0.1:${PORT}/ui"
    exit 0
  fi
  sleep 0.25
done

echo "Prototype server did not become healthy; log follows:" >&2
tail -n 80 "$LOG" >&2 || true
exit 1
