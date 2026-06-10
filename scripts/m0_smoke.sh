#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${OPEN_EDR_MDR_SMOKE_PORT:-8766}"
DB="${OPEN_EDR_MDR_SMOKE_DB:-/tmp/open-edr-mdr-smoke.sqlite3}"
STATE="${OPEN_EDR_MDR_SMOKE_STATE:-/tmp/open-edr-agent-smoke-state.json}"
SPOOL="${OPEN_EDR_MDR_SMOKE_SPOOL:-/tmp/open-edr-agent-smoke-spool.jsonl}"
AGENT_BIN="${OPEN_EDR_MDR_SMOKE_AGENT:-/tmp/open-edr-agent-smoke}"
LOG="${OPEN_EDR_MDR_SMOKE_LOG:-/tmp/open-edr-mdr-smoke-uvicorn.log}"

rm -f "$DB" "$STATE" "$SPOOL" "$LOG"

cd "$ROOT"
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
. .venv/bin/activate
pip install -e . >/tmp/open-edr-mdr-smoke-pip.log

(cd agent && go build -o "$AGENT_BIN" ./cmd/open-edr-agent)

OPEN_EDR_MDR_DB="$DB" uvicorn open_edr_mdr_agent.api.app:app --host 127.0.0.1 --port "$PORT" >"$LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" >/dev/null 2>&1 || true' EXIT

python - <<PY
import time, urllib.request
url='http://127.0.0.1:${PORT}/health'
for _ in range(50):
    try:
        print(urllib.request.urlopen(url, timeout=1).read().decode())
        break
    except Exception:
        time.sleep(0.1)
else:
    raise SystemExit('server did not become healthy')
PY

"$AGENT_BIN" --server "http://127.0.0.1:${PORT}" --state "$STATE" --spool "$SPOOL" --enroll-token dev-token --once --demo-suspicious-event --max-snapshot-events 5

python - <<PY
import json, urllib.request
state=json.load(open('$STATE'))
body=json.dumps({'tenant_id':'default','agent_id':state['agent_id'],'task_type':'file_exists','args':{'path':'$STATE'}}).encode()
req=urllib.request.Request('http://127.0.0.1:${PORT}/api/v1/admin/tasks', data=body, headers={'Content-Type':'application/json','Authorization':'Bearer dev-admin-token'}, method='POST')
print(urllib.request.urlopen(req).read().decode())
PY

"$AGENT_BIN" --server "http://127.0.0.1:${PORT}" --state "$STATE" --spool "$SPOOL" --once --max-snapshot-events 5

python - <<PY
import json, sqlite3
conn=sqlite3.connect('$DB'); conn.row_factory=sqlite3.Row
alerts=conn.execute('select title from alerts order by timestamp desc').fetchall()
tasks=conn.execute('select status, result_json from tasks order by created_at desc').fetchall()
events=conn.execute('select count(*) c from events').fetchone()['c']
assert events > 0, 'no events ingested'
assert any(r['title']=='Suspicious encoded PowerShell command' for r in alerts), [dict(r) for r in alerts]
assert tasks and tasks[0]['status']=='succeeded', [dict(r) for r in tasks]
print(json.dumps({'events': events, 'alerts': [r['title'] for r in alerts], 'latest_task_status': tasks[0]['status']}, ensure_ascii=False))
PY
