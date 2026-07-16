#!/usr/bin/env bash
set -euo pipefail

URL="${SHIGURE_PROTOTYPE_URL:-http://127.0.0.1:8765}"
ADMIN_TOKEN="${SHIGURE_PROTOTYPE_ADMIN_TOKEN:-dev-admin-token}"
TENANT="${SHIGURE_PROTOTYPE_TENANT:-default}"
MAX_SNAPSHOT_EVENTS="${SHIGURE_PROTOTYPE_MAX_SNAPSHOT_EVENTS:-25}"

PYTHON_BIN="${SHIGURE_PROTOTYPE_PYTHON:-python3}"
if [[ -x .venv/bin/python ]]; then
  PYTHON_BIN=".venv/bin/python"
fi

"$PYTHON_BIN" - "$URL" "$ADMIN_TOKEN" "$TENANT" "$MAX_SNAPSHOT_EVENTS" <<'PY'
import json
import sys
import urllib.request

url, token, tenant, max_snapshot_events = sys.argv[1:5]
headers = {"X-Admin-Token": token}

def request(path, *, method="GET", body=None):
    data = None
    h = dict(headers)
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{url}{path}", data=data, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode())

config = request(f"/api/v1/admin/config?tenant_id={tenant}")
config["version"] = int(config.get("version", 1)) + 1
config["max_snapshot_events"] = int(max_snapshot_events)
config["collect_snapshot"] = True
config["collect_process_snapshot"] = True
config["collect_network_snapshot"] = False
config["collect_windows_event_logs"] = False
features = dict(config.get("features") or {})
features["collector_gates_explicit"] = True
features["windows_etw"] = False
features["windows_eventlog_subscriptions"] = False
config["features"] = features

updated = request(f"/api/v1/admin/config?tenant_id={tenant}", method="PUT", body=config)
print(json.dumps(updated, indent=2, sort_keys=True))
PY

echo "Prototype demo config applied. The agent will pick it up on the next heartbeat."
