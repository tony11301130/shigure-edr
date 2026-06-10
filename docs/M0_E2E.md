# M0 Local E2E Smoke Test

This validates the intranet vertical slice:

```text
agent enrolls -> heartbeat -> uploads telemetry -> backend detection generates alert -> backend creates task -> agent claims/executes task -> uploads result
```

## Start backend

```bash
cd /opt/open-edr-mdr-agent
. .venv/bin/activate
OPEN_EDR_MDR_DB=/tmp/open-edr-mdr-e2e.sqlite3 \
  uvicorn open_edr_mdr_agent.api.app:app --host 127.0.0.1 --port 8765
```

## Build and run agent once

```bash
cd /opt/open-edr-mdr-agent/agent
go build -o /tmp/open-edr-agent ./cmd/open-edr-agent

/tmp/open-edr-agent \
  --server http://127.0.0.1:8765 \
  --state /tmp/open-edr-agent-state.json \
  --enroll-token dev-token \
  --once \
  --demo-suspicious-event
```

Expected:

- agent enrolls using `dev-token`
- state file contains `tenant_id`, `agent_id`, `agent_token`
- backend receives suspicious PowerShell demo event
- backend creates `Suspicious encoded PowerShell command` alert

## Create and execute a task

```bash
python3 - <<'PY'
import json, urllib.request
state=json.load(open('/tmp/open-edr-agent-state.json'))
body=json.dumps({'tenant_id':'default','agent_id':state['agent_id'],'task_type':'process_list','args':{}}).encode()
req=urllib.request.Request('http://127.0.0.1:8765/api/v1/admin/tasks', data=body, headers={'Content-Type':'application/json'}, method='POST')
print(urllib.request.urlopen(req).read().decode())
PY

/tmp/open-edr-agent --server http://127.0.0.1:8765 --state /tmp/open-edr-agent-state.json --once
```

Expected task status in SQLite:

```text
status = succeeded
result_json contains process list
```

## Query alerts/events

```bash
curl 'http://127.0.0.1:8765/api/v1/admin/alerts?tenant_id=default'
curl 'http://127.0.0.1:8765/api/v1/admin/events?tenant_id=default'
```
