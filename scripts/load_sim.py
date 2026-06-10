#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

ADMIN = "dev-admin-token"


def post(url: str, body: dict, token: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as res:
        return json.loads(res.read().decode() or "{}")


@dataclass
class AgentAuth:
    tenant_id: str
    agent_id: str
    agent_token: str
    host: str


def enroll(base: str, token: str, i: int) -> AgentAuth:
    host = f"LOAD-{i:05d}"
    out = post(f"{base}/api/v1/enroll", {"enrollment_token": token, "host": host, "ip_address": f"10.10.{i//255}.{i%255}", "os": "Windows", "agent_version": "load-sim"})
    return AgentAuth(out["tenant_id"], out["agent_id"], out["agent_token"], host)


def heartbeat_and_event(base: str, auth: AgentAuth, events_per_agent: int) -> tuple[int, int]:
    token = auth.agent_token
    post(f"{base}/api/v1/agents/{auth.agent_id}/heartbeat", {"host": auth.host, "os": "Windows", "agent_version": "load-sim", "health": {"simulated": True}}, token)
    events = []
    for j in range(events_per_agent):
        events.append({"source": "internal", "event_type": "process_start", "tenant_id": auth.tenant_id, "host": auth.host, "process_name": "powershell.exe" if j == 0 else "notepad.exe", "process_id": str(1000 + j), "parent_process_id": "500", "command_line": "powershell -enc SQBFAFgA" if j == 0 else "notepad.exe", "severity": "info", "raw": {"simulator": True, "seq": j}})
    out = post(f"{base}/api/v1/agents/{auth.agent_id}/events", {"events": events}, token)
    return out.get("accepted", 0), out.get("alerts_generated", 0)


def main() -> None:
    ap = argparse.ArgumentParser(description="M0/M1 load simulator for agent enrollment, heartbeat, and telemetry ingestion")
    ap.add_argument("--base", default="http://127.0.0.1:8765")
    ap.add_argument("--tenant", default="loadtest")
    ap.add_argument("--agents", type=int, default=100)
    ap.add_argument("--events-per-agent", type=int, default=3)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--token", default=None, help="existing enrollment token; creates one if omitted")
    args = ap.parse_args()

    if args.token:
        token = args.token
    else:
        token_res = post(f"{args.base}/api/v1/admin/enrollment-tokens?tenant_id={args.tenant}", {}, ADMIN)
        token = token_res["token"]

    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        agents = list(ex.map(lambda i: enroll(args.base, token, i), range(args.agents)))
    t1 = time.time()
    accepted = alerts = 0
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for a, al in ex.map(lambda auth: heartbeat_and_event(args.base, auth, args.events_per_agent), agents):
            accepted += a
            alerts += al
    t2 = time.time()
    print(json.dumps({
        "tenant": args.tenant,
        "agents": len(agents),
        "events_accepted": accepted,
        "alerts_generated": alerts,
        "enroll_seconds": round(t1 - t0, 3),
        "heartbeat_ingest_seconds": round(t2 - t1, 3),
        "total_seconds": round(t2 - t0, 3),
    }, indent=2))


if __name__ == "__main__":
    main()
