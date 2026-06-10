from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query

from open_edr_mdr_agent.api.models import (
    AgentRecord,
    EnrollmentRequest,
    EnrollmentResponse,
    EventIngestRequest,
    EventIngestResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    TaskClaimRequest,
    TaskClaimResponse,
    TaskCreateRequest,
    TaskRecord,
    TaskResultRequest,
)
from open_edr_mdr_agent.api.store import SQLiteStore
from open_edr_mdr_agent.core.detection import detect_many
from open_edr_mdr_agent.core.schemas import Alert, NormalizedEvent, Severity, Source

DEFAULT_DB = os.environ.get("OPEN_EDR_MDR_DB", "/tmp/open-edr-mdr-agent.sqlite3")
DEFAULT_DEV_TOKEN = os.environ.get("OPEN_EDR_MDR_DEV_ENROLLMENT_TOKEN", "dev-token")


def create_app(db_path: str | Path = DEFAULT_DB, *, create_dev_token: bool = True) -> FastAPI:
    app = FastAPI(title="Open EDR MDR Agent API", version="0.1.0")
    store = SQLiteStore(db_path)
    if create_dev_token:
        store.create_enrollment_token("default", token=DEFAULT_DEV_TOKEN, max_uses=None)
    app.state.store = store

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/api/v1/enroll", response_model=EnrollmentResponse)
    def enroll(req: EnrollmentRequest):
        try:
            result = store.enroll_agent(
                enrollment_token=req.enrollment_token,
                public_key=req.public_key,
                host=req.host,
                ip_address=req.ip_address,
                os=req.os,
                agent_version=req.agent_version,
                metadata=req.metadata,
            )
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return EnrollmentResponse(**result, config={"upload_mode": "hybrid", "task_poll_seconds": 15, "tenant_id": result["tenant_id"]})

    @app.post("/api/v1/agents/{agent_id}/heartbeat", response_model=HeartbeatResponse)
    def heartbeat(agent=Depends(_agent_auth), req: HeartbeatRequest = None):
        req = req or HeartbeatRequest(host=agent["host"])
        store.update_heartbeat(agent["agent_id"], req.host, req.ip_address, req.os, req.agent_version, req.health)
        pending = store.pending_tasks_count(agent["tenant_id"], agent["agent_id"]) > 0
        return HeartbeatResponse(status="ok", tasks_pending=pending)

    @app.post("/api/v1/agents/{agent_id}/events", response_model=EventIngestResponse)
    def ingest_events(agent=Depends(_agent_auth), req: EventIngestRequest = None):
        req = req or EventIngestRequest(events=[])
        normalized = []
        for event in req.events:
            # Tenant is authoritative from authenticated agent, not client payload.
            event.tenant_id = agent["tenant_id"]
            if not event.host:
                event.host = agent["host"]
            normalized.append(event)
        accepted = store.insert_events(agent["agent_id"], normalized)
        alerts = detect_many(normalized)
        # Ensure generated alerts are tenant-scoped through raw metadata.
        for alert in alerts:
            alert.raw = {**(alert.raw or {}), "tenant_id": agent["tenant_id"], "agent_id": agent["agent_id"]}
        inserted_alerts = store.insert_alerts(alerts)
        return EventIngestResponse(accepted=accepted, alerts_generated=inserted_alerts)

    @app.post("/api/v1/agents/{agent_id}/tasks/claim", response_model=TaskClaimResponse)
    def claim_tasks(agent=Depends(_agent_auth), req: TaskClaimRequest = None):
        req = req or TaskClaimRequest()
        tasks = store.claim_tasks(agent["tenant_id"], agent["agent_id"], max_tasks=req.max_tasks)
        return TaskClaimResponse(tasks=tasks)

    @app.post("/api/v1/agents/{agent_id}/tasks/{task_id}/result")
    def task_result(task_id: str, agent=Depends(_agent_auth), req: TaskResultRequest = None):
        req = req or TaskResultRequest(status="failed", error="empty result")
        store.complete_task(agent["tenant_id"], agent["agent_id"], task_id, req.status, req.result, req.error)
        return {"status": "ok"}

    @app.post("/api/v1/admin/tasks", response_model=TaskRecord)
    def create_task(req: TaskCreateRequest):
        task_id = store.create_task(req.tenant_id, req.agent_id, req.task_type, req.args, req.timeout_seconds)
        claimed = store.claim_tasks(req.tenant_id, req.agent_id, max_tasks=0)
        # Fetch via direct SQLite row to avoid adding public store method for now.
        with store.connect() as conn:
            row = conn.execute("select * from tasks where task_id=?", (task_id,)).fetchone()
            return store._task_record(dict(row))

    @app.get("/api/v1/admin/agents")
    def list_agents(tenant_id: str = Query("default")):
        return {"agents": store.list_agents(tenant_id)}

    @app.get("/api/v1/admin/events", response_model=list[NormalizedEvent])
    def list_events(
        tenant_id: str = Query("default"),
        host: Optional[str] = None,
        event_type: Optional[str] = None,
        process_name: Optional[str] = None,
        remote_ip: Optional[str] = None,
        domain: Optional[str] = None,
        indicator: Optional[str] = None,
        limit: int = 100,
    ):
        return store.list_events(tenant_id, host=host, event_type=event_type, process_name=process_name, remote_ip=remote_ip, domain=domain, indicator=indicator, limit=limit)

    @app.get("/api/v1/admin/tasks", response_model=list[TaskRecord])
    def list_tasks(tenant_id: str = Query("default"), agent_id: Optional[str] = None, limit: int = 100):
        return store.list_tasks(tenant_id, agent_id=agent_id, limit=limit)

    @app.get("/api/v1/admin/alerts", response_model=list[Alert])
    def list_alerts(tenant_id: str = Query("default"), limit: int = 100):
        return store.list_alerts(tenant_id, limit=limit)

    @app.post("/api/v1/admin/enrollment-tokens")
    def create_enrollment_token(tenant_id: str = "default", max_uses: Optional[int] = None):
        return {"tenant_id": tenant_id, "token": store.create_enrollment_token(tenant_id, max_uses=max_uses)}

    @app.post("/api/v1/admin/detections/agent-health")
    def run_agent_health_detection(tenant_id: Optional[str] = None, stale_after_seconds: int = 300):
        stale_before = (datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)).isoformat()
        alerts = []
        for agent_row in store.stale_agents(stale_before, tenant_id=tenant_id):
            alert = Alert(
                alert_id=f"builtin.agent.offline:{agent_row['agent_id']}:{agent_row.get('last_seen')}",
                title="Agent offline or telemetry gap",
                severity=Severity.MEDIUM,
                timestamp=datetime.now(timezone.utc),
                host=agent_row.get("host"),
                description=f"Agent {agent_row['agent_id']} last seen at {agent_row.get('last_seen')}",
                mitre=[],
                source=Source.INTERNAL,
                raw={"rule_id": "builtin.agent.offline", "tenant_id": agent_row["tenant_id"], "agent_id": agent_row["agent_id"], "last_seen": agent_row.get("last_seen")},
            )
            alerts.append(alert)
        inserted = store.insert_alerts(alerts)
        return {"stale_agents": len(alerts), "alerts_generated": inserted}

    app.dependency_overrides[_agent_auth] = _make_agent_auth(app)
    return app


def _agent_auth(agent_id: str, authorization: Annotated[Optional[str], Header()] = None):
    # `agent_id` is supplied by the route path. FastAPI injects it by name.
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1]
    # app.state is not directly available in dependencies without request, so this
    # dependency is wrapped below at runtime by FastAPI path function closure.
    raise RuntimeError("_agent_auth must be overridden by create_app")


# Override dependency with one that can access app.state.store. Kept separate so
def _make_agent_auth(app: FastAPI):
    def dep(agent_id: str, authorization: Annotated[Optional[str], Header()] = None):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization.split(" ", 1)[1]
        agent = app.state.store.authenticate_agent(agent_id, token)
        if not agent:
            raise HTTPException(status_code=401, detail="invalid agent credential")
        return agent
    return dep


def bind_auth_dependency(app: FastAPI) -> FastAPI:
    app.dependency_overrides[_agent_auth] = _make_agent_auth(app)
    return app


app = create_app()
