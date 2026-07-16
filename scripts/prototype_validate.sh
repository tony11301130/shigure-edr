#!/usr/bin/env bash
set -euo pipefail

URL="${SHIGURE_PROTOTYPE_URL:-http://127.0.0.1:8765}"
ADMIN_TOKEN="${SHIGURE_PROTOTYPE_ADMIN_TOKEN:-dev-admin-token}"
TENANT="${SHIGURE_PROTOTYPE_TENANT:-default}"

PYTHON_BIN="${SHIGURE_PROTOTYPE_PYTHON:-python3}"
if [[ -x .venv/bin/python ]]; then
  PYTHON_BIN=".venv/bin/python"
fi

"$PYTHON_BIN" - "$URL" "$ADMIN_TOKEN" "$TENANT" <<'PY'
import json
import sys
import time
import urllib.request

url, token, tenant = sys.argv[1:4]
headers = {"X-Admin-Token": token}

def request(path, *, headers_override=None):
    h = dict(headers)
    if headers_override:
        h.update(headers_override)
    req = urllib.request.Request(f"{url}{path}", headers=h)
    with urllib.request.urlopen(req, timeout=10) as res:
        body = res.read()
        ctype = res.headers.get("content-type", "")
        if "application/json" in ctype:
            return json.loads(body.decode())
        return body.decode(errors="replace")

def count_events():
    return request(f"/api/v1/admin/summary?tenant_id={tenant}")["counts"]["events"]

health = request("/health", headers_override={})
ui = request("/ui", headers_override={})
summary = request(f"/api/v1/admin/summary?tenant_id={tenant}")
agents_payload = request(f"/api/v1/admin/agents?tenant_id={tenant}")
storage = request(f"/api/v1/admin/storage-profile?tenant_id={tenant}")
config = request(f"/api/v1/admin/config?tenant_id={tenant}")

agents = agents_payload.get("agents", agents_payload) if isinstance(agents_payload, dict) else agents_payload
online_agents = [a for a in agents if a.get("status") == "online"]
warnings = []

if health.get("status") != "ok":
    raise SystemExit(f"health check failed: {health}")
if "<html" not in ui.lower() and "<!doctype html" not in ui.lower():
    raise SystemExit("UI did not return HTML")
if not online_agents:
    raise SystemExit("No online endpoint is available for Prototype P0")

for agent in online_agents:
    h = agent.get("health") or {}
    etw = h.get("windows_etw_process") or {}
    eventlog = h.get("windows_event_log_subscription") or {}
    if etw.get("running"):
        warnings.append(f"{agent.get('host')}: windows_etw_process is still running")
    if eventlog.get("running"):
        warnings.append(f"{agent.get('host')}: windows_event_log_subscription is still running")

before = count_events()
time.sleep(5)
after = count_events()
growth = after - before
if growth > 25:
    warnings.append(f"event count grew by {growth} in 5s; use scripts/prototype_config_quiet.sh when idle")

report = {
    "prototype": "P0",
    "server": url,
    "health": health,
    "ui_bytes": len(ui),
    "summary": summary,
    "online_agents": [
        {
            "agent_id": a.get("agent_id"),
            "host": a.get("host"),
            "ip_address": a.get("ip_address"),
            "last_seen": a.get("last_seen"),
            "spool": (a.get("health") or {}).get("spool"),
            "windows_etw_process": (a.get("health") or {}).get("windows_etw_process"),
            "windows_event_log_subscription": (a.get("health") or {}).get("windows_event_log_subscription"),
        }
        for a in online_agents
    ],
    "storage_profile": storage,
    "agent_config": config,
    "event_growth_5s": growth,
    "warnings": warnings,
}
print(json.dumps(report, indent=2, sort_keys=True))
if warnings:
    print("\nWARNINGS:")
    for warning in warnings:
        print(f"- {warning}")
PY
