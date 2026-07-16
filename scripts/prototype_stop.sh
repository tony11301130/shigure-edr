#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="${SHIGURE_PROTOTYPE_PID:-$ROOT/.scratch/prototype-p0/server.pid}"

if [[ -f "$PID_FILE" ]]; then
  PID="$(cat "$PID_FILE")"
  if [[ "$PID" =~ ^[0-9]+$ ]] && kill -0 "$PID" >/dev/null 2>&1; then
    kill "$PID" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      if ! kill -0 "$PID" >/dev/null 2>&1; then
        break
      fi
      sleep 0.25
    done
    if kill -0 "$PID" >/dev/null 2>&1; then
      echo "Server pid $PID did not stop after SIGTERM" >&2
      exit 1
    fi
    echo "Stopped prototype server pid $PID"
  else
    echo "No live process for pid file $PID_FILE"
  fi
  rm -f "$PID_FILE"
else
  echo "No prototype pid file at $PID_FILE"
fi

cat <<'EOF'

If you are done with the Windows lab endpoint, stop it manually on Windows:

  Stop-Service ShigureAgent

Or keep the service running in quiet mode:

  scripts/prototype_config_quiet.sh
EOF
