from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

from open_edr_mdr_agent.api.cases import CaseCreateRequest, CaseEvidenceRecord, CaseEvidenceRequest, CaseRecord, CaseUpdateRequest
from open_edr_mdr_agent.api.hunts import HuntCreateRequest, HuntRecord, HuntRunRecord, HuntUpdateRequest
from open_edr_mdr_agent.api.models import (
    AgentConfig,
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
from open_edr_mdr_agent.api.task_catalog import READONLY_TASK_CATALOG, TaskArgumentError, validate_task_args
from open_edr_mdr_agent.core.detection import detect_many
from open_edr_mdr_agent.core.rules import load_rules
from open_edr_mdr_agent.core.schemas import Alert, NormalizedEvent, Severity, Source

DEFAULT_DB = os.environ.get("OPEN_EDR_MDR_DB", "/tmp/open-edr-mdr-agent.sqlite3")
DEFAULT_DEV_TOKEN = os.environ.get("OPEN_EDR_MDR_DEV_ENROLLMENT_TOKEN", "dev-token")
DEFAULT_ADMIN_TOKEN = os.environ.get("OPEN_EDR_MDR_ADMIN_TOKEN", "dev-admin-token")


def create_app(db_path: str | Path = DEFAULT_DB, *, create_dev_token: bool = True) -> FastAPI:
    app = FastAPI(title="Open EDR MDR Agent API", version="0.1.0")
    store = SQLiteStore(db_path)
    app.state.custom_rules = load_rules(os.environ.get("OPEN_EDR_MDR_RULES"))
    if create_dev_token:
        store.create_enrollment_token("default", token=DEFAULT_DEV_TOKEN, max_uses=None)
    app.state.store = store

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse(url="/ui")

    @app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
    def ui():
        return UI_HTML

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
        config = store.get_agent_config(result["tenant_id"])
        return EnrollmentResponse(**result, config={**config.model_dump(), "tenant_id": result["tenant_id"]})

    @app.post("/api/v1/agents/{agent_id}/heartbeat", response_model=HeartbeatResponse)
    def heartbeat(agent=Depends(_agent_auth), req: HeartbeatRequest = None):
        req = req or HeartbeatRequest(host=agent["host"])
        store.update_heartbeat(agent["agent_id"], req.host, req.ip_address, req.os, req.agent_version, req.health)
        pending = store.pending_tasks_count(agent["tenant_id"], agent["agent_id"]) > 0
        config = store.get_agent_config(agent["tenant_id"])
        return HeartbeatResponse(status="ok", tasks_pending=pending, config_version=config.version, config=config)

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
        alerts = detect_many(normalized, custom_rules=app.state.custom_rules)
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

    @app.get("/api/v1/admin/readonly-scripts")
    def list_readonly_scripts(_admin=Depends(_admin_auth)):
        return {"scripts": READONLY_TASK_CATALOG}

    @app.post("/api/v1/admin/tasks", response_model=TaskRecord)
    def create_task(req: TaskCreateRequest, _admin=Depends(_admin_auth)):
        try:
            validate_task_args(req.task_type, req.args)
            task_id = store.create_task(req.tenant_id, req.agent_id, req.task_type, req.args, req.timeout_seconds)
        except TaskArgumentError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # Fetch via direct SQLite row to avoid adding public store method for now.
        with store.connect() as conn:
            row = conn.execute("select * from tasks where task_id=?", (task_id,)).fetchone()
            return store._task_record(dict(row))

    @app.post("/api/v1/admin/rules/reload")
    def reload_rules(_admin=Depends(_admin_auth)):
        app.state.custom_rules = load_rules(os.environ.get("OPEN_EDR_MDR_RULES"))
        return {"rules_loaded": len(app.state.custom_rules)}

    @app.get("/api/v1/admin/agents")
    def list_agents(tenant_id: str = Query("default"), status: Optional[str] = None, _admin=Depends(_admin_auth)):
        return {"agents": store.list_agents(tenant_id, status=status)}

    @app.get("/api/v1/admin/agents/{agent_id}", response_model=AgentRecord)
    def get_agent(agent_id: str, tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        agent = store.get_agent(tenant_id, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="agent_not_found")
        return agent

    @app.get("/api/v1/admin/summary")
    def tenant_summary(tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        return store.tenant_summary(tenant_id)

    @app.get("/api/v1/admin/events/count")
    def count_events(
        _admin=Depends(_admin_auth),
        tenant_id: str = Query("default"),
        host: Optional[str] = None,
        event_type: Optional[str] = None,
        process_name: Optional[str] = None,
        user: Optional[str] = None,
        hash_sha256: Optional[str] = None,
        remote_ip: Optional[str] = None,
        domain: Optional[str] = None,
        indicator: Optional[str] = None,
    ):
        return {"tenant_id": tenant_id, "count": store.count_events(tenant_id, host=host, event_type=event_type, process_name=process_name, user=user, hash_sha256=hash_sha256, remote_ip=remote_ip, domain=domain, indicator=indicator)}

    @app.get("/api/v1/admin/events/related", response_model=list[NormalizedEvent])
    def related_events(entity_type: str, value: str, tenant_id: str = Query("default"), limit: int = 100, _admin=Depends(_admin_auth)):
        return store.related_events(tenant_id, entity_type=entity_type, value=value, limit=limit)

    @app.get("/api/v1/admin/events/{event_id}", response_model=NormalizedEvent)
    def get_event(event_id: str, tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        event = store.get_event(tenant_id, event_id)
        if not event:
            raise HTTPException(status_code=404, detail="event_not_found")
        return event

    @app.get("/api/v1/admin/events", response_model=list[NormalizedEvent])
    def list_events(
        _admin=Depends(_admin_auth),
        tenant_id: str = Query("default"),
        host: Optional[str] = None,
        event_type: Optional[str] = None,
        process_name: Optional[str] = None,
        user: Optional[str] = None,
        hash_sha256: Optional[str] = None,
        remote_ip: Optional[str] = None,
        domain: Optional[str] = None,
        indicator: Optional[str] = None,
        limit: int = 100,
    ):
        return store.list_events(tenant_id, host=host, event_type=event_type, process_name=process_name, user=user, hash_sha256=hash_sha256, remote_ip=remote_ip, domain=domain, indicator=indicator, limit=limit)

    @app.get("/api/v1/admin/tasks", response_model=list[TaskRecord])
    def list_tasks(tenant_id: str = Query("default"), agent_id: Optional[str] = None, status: Optional[str] = None, limit: int = 100, _admin=Depends(_admin_auth)):
        return store.list_tasks(tenant_id, agent_id=agent_id, status=status, limit=limit)

    @app.post("/api/v1/admin/tasks/expire-stale")
    def expire_stale_tasks(tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        return {"tenant_id": tenant_id, "expired": store.expire_stale_tasks(tenant_id)}

    @app.get("/api/v1/admin/tasks/{task_id}", response_model=TaskRecord)
    def get_task(task_id: str, tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        task = store.get_task(tenant_id, task_id)
        if not task:
            raise HTTPException(status_code=404, detail="task_not_found")
        return task

    @app.get("/api/v1/admin/alerts/{alert_id}", response_model=Alert)
    def get_alert(alert_id: str, tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        alert = store.get_alert(tenant_id, alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="alert_not_found")
        return alert

    @app.get("/api/v1/admin/alerts", response_model=list[Alert])
    def list_alerts(tenant_id: str = Query("default"), limit: int = 100, severity: Optional[str] = None, host: Optional[str] = None, title: Optional[str] = None, _admin=Depends(_admin_auth)):
        return store.list_alerts(tenant_id, limit=limit, severity=severity, host=host, title=title)

    @app.get("/api/v1/admin/raw-evidence")
    def get_raw_evidence(raw_ref: str, tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        evidence = store.get_raw_evidence(tenant_id, raw_ref)
        if not evidence:
            raise HTTPException(status_code=404, detail="raw_evidence_not_found")
        return evidence

    @app.get("/api/v1/admin/raw-evidence/list")
    def list_raw_evidence(tenant_id: str = Query("default"), kind: Optional[str] = None, limit: int = 100, _admin=Depends(_admin_auth)):
        return {"tenant_id": tenant_id, "evidence": store.list_raw_evidence(tenant_id, kind=kind, limit=limit)}

    @app.get("/api/v1/admin/raw-evidence/by-hash/{sha256}")
    def get_raw_evidence_by_hash(sha256: str, tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        evidence = store.get_raw_evidence_by_hash(tenant_id, sha256)
        if not evidence:
            raise HTTPException(status_code=404, detail="raw_evidence_not_found")
        return evidence

    @app.get("/api/v1/admin/investigate/endpoint-context")
    def endpoint_context(host: str, tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        agents = [a for a in store.list_agents(tenant_id) if a.get("host") == host]
        recent_events = store.list_events(tenant_id, host=host, limit=50)
        recent_alerts = [a for a in store.list_alerts(tenant_id, limit=100) if a.host == host][:20]
        tasks = [t for t in store.list_tasks(tenant_id, limit=100) if t.agent_id in {a.get("agent_id") for a in agents}][:20]
        return {"tenant_id": tenant_id, "host": host, "agents": agents, "recent_events": recent_events, "recent_alerts": recent_alerts, "recent_tasks": tasks}

    @app.get("/api/v1/admin/investigate/hunt")
    def hunt_indicator(indicator: str, tenant_id: str = Query("default"), limit: int = 100, _admin=Depends(_admin_auth)):
        events = store.list_events(tenant_id, indicator=indicator, limit=limit)
        alerts = [a for a in store.list_alerts(tenant_id, limit=limit) if indicator.lower() in a.model_dump_json().lower()]
        hosts = sorted({e.host for e in events if e.host} | {a.host for a in alerts if a.host})
        return {"tenant_id": tenant_id, "indicator": indicator, "hosts": hosts, "events": events, "alerts": alerts[:limit]}

    @app.post("/api/v1/admin/hunts", response_model=HuntRecord)
    def create_saved_hunt(req: HuntCreateRequest, _admin=Depends(_admin_auth)):
        if not req.indicator and not req.query:
            raise HTTPException(status_code=400, detail="indicator_or_query_required")
        return store.create_hunt(req.tenant_id, req.name, req.description, req.indicator, req.query, enabled=req.enabled)

    @app.get("/api/v1/admin/hunts", response_model=list[HuntRecord])
    def list_saved_hunts(tenant_id: str = Query("default"), enabled: Optional[bool] = None, limit: int = 100, _admin=Depends(_admin_auth)):
        return store.list_hunts(tenant_id, enabled=enabled, limit=limit)

    @app.patch("/api/v1/admin/hunts/{hunt_id}", response_model=HuntRecord)
    def update_saved_hunt(hunt_id: str, req: HuntUpdateRequest, tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        try:
            hunt = store.update_hunt(tenant_id, hunt_id, name=req.name, description=req.description, indicator=req.indicator, query=req.query, enabled=req.enabled)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not hunt:
            raise HTTPException(status_code=404, detail="hunt_not_found")
        return hunt

    @app.post("/api/v1/admin/hunts/{hunt_id}/run", response_model=HuntRunRecord)
    def run_saved_hunt(hunt_id: str, tenant_id: str = Query("default"), limit: int = 100, _admin=Depends(_admin_auth)):
        hunt = store.get_hunt(tenant_id, hunt_id)
        if not hunt:
            raise HTTPException(status_code=404, detail="hunt_not_found")
        if not hunt.enabled:
            raise HTTPException(status_code=400, detail="hunt_disabled")
        query = hunt.query or {}
        indicator = hunt.indicator or query.get("indicator")
        events = store.list_events(
            tenant_id,
            host=query.get("host"),
            event_type=query.get("event_type"),
            process_name=query.get("process_name"),
            user=query.get("user"),
            hash_sha256=query.get("hash_sha256"),
            remote_ip=query.get("remote_ip"),
            domain=query.get("domain"),
            indicator=indicator,
            limit=limit,
        )
        alerts = []
        if indicator:
            alerts = [a for a in store.list_alerts(tenant_id, limit=limit) if str(indicator).lower() in a.model_dump_json().lower()]
        hosts = sorted({e.host for e in events if e.host} | {a.host for a in alerts if a.host})
        result = {"hunt_id": hunt_id, "name": hunt.name, "indicator": indicator, "query": query, "hosts": hosts, "event_count": len(events), "alert_count": len(alerts), "events": [e.model_dump(mode="json") for e in events[:limit]], "alerts": [a.model_dump(mode="json") for a in alerts[:limit]]}
        return store.record_hunt_run(tenant_id, hunt_id, "succeeded", result)

    @app.get("/api/v1/admin/hunts/{hunt_id}/runs", response_model=list[HuntRunRecord])
    def list_saved_hunt_runs(hunt_id: str, tenant_id: str = Query("default"), limit: int = 100, _admin=Depends(_admin_auth)):
        if not store.get_hunt(tenant_id, hunt_id):
            raise HTTPException(status_code=404, detail="hunt_not_found")
        return store.list_hunt_runs(tenant_id, hunt_id=hunt_id, limit=limit)

    @app.get("/api/v1/admin/investigate/process-chain")
    def process_chain(host: str, process_id: str, tenant_id: str = Query("default"), limit: int = 500, _admin=Depends(_admin_auth)):
        events = store.list_events(tenant_id, host=host, limit=limit)
        by_pid = {e.process_id: e for e in events if e.process_id}
        chain = []
        children = [e for e in events if e.parent_process_id == process_id]
        seen = set()
        current = process_id
        while current and current not in seen and current in by_pid:
            seen.add(current)
            event = by_pid[current]
            chain.append(event)
            current = event.parent_process_id
        return {"tenant_id": tenant_id, "host": host, "process_id": process_id, "chain": chain, "children": children[:100]}

    @app.get("/api/v1/admin/investigate/behavior-context")
    def behavior_context(host: str, tenant_id: str = Query("default"), process_id: Optional[str] = None, indicator: Optional[str] = None, limit: int = 200, _admin=Depends(_admin_auth)):
        events = store.list_events(tenant_id, host=host, indicator=indicator, limit=limit)
        if process_id:
            events = [e for e in events if e.process_id == process_id or e.parent_process_id == process_id]
        by_type: dict[str, int] = {}
        for event in events:
            by_type[event.event_type.value] = by_type.get(event.event_type.value, 0) + 1
        return {"tenant_id": tenant_id, "host": host, "process_id": process_id, "indicator": indicator, "counts_by_type": by_type, "events": events}

    @app.get("/api/v1/admin/investigate/network-context")
    def network_context(host: str, tenant_id: str = Query("default"), process_id: Optional[str] = None, remote_ip: Optional[str] = None, limit: int = 200, _admin=Depends(_admin_auth)):
        events = store.list_events(tenant_id, host=host, event_type="network_connection", remote_ip=remote_ip, limit=limit)
        if process_id:
            events = [e for e in events if e.process_id == process_id]
        remotes = sorted({f"{e.remote_ip}:{e.remote_port}" for e in events if e.remote_ip})
        return {"tenant_id": tenant_id, "host": host, "process_id": process_id, "remote_ip": remote_ip, "remotes": remotes, "events": events}

    @app.post("/api/v1/admin/cases", response_model=CaseRecord)
    def create_case(req: CaseCreateRequest, _admin=Depends(_admin_auth)):
        try:
            return store.create_case(req.tenant_id, req.title, req.severity, alert_id=req.alert_id, description=req.description)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/admin/cases", response_model=list[CaseRecord])
    def list_cases(tenant_id: str = "default", status: Optional[str] = None, severity: Optional[str] = None, assignee: Optional[str] = None, limit: int = 100, _admin=Depends(_admin_auth)):
        return store.list_cases(tenant_id, status=status, severity=severity, assignee=assignee, limit=limit)

    @app.get("/api/v1/admin/cases/{case_id}")
    def get_case(case_id: str, tenant_id: str = "default", _admin=Depends(_admin_auth)):
        case = store.get_case(tenant_id, case_id)
        if not case:
            raise HTTPException(status_code=404, detail="case_not_found")
        return {"case": case, "evidence": store.list_case_evidence(tenant_id, case_id)}

    @app.patch("/api/v1/admin/cases/{case_id}", response_model=CaseRecord)
    def update_case(case_id: str, req: CaseUpdateRequest, tenant_id: str = "default", _admin=Depends(_admin_auth)):
        case = store.update_case(tenant_id, case_id, status=req.status, assignee=req.assignee, summary=req.summary)
        if not case:
            raise HTTPException(status_code=404, detail="case_not_found")
        return case

    @app.post("/api/v1/admin/cases/{case_id}/evidence", response_model=CaseEvidenceRecord)
    def add_case_evidence(case_id: str, req: CaseEvidenceRequest, tenant_id: str = "default", _admin=Depends(_admin_auth)):
        try:
            return store.add_case_evidence(tenant_id, case_id, req.evidence_type, req.ref_id, req.summary, req.data)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/v1/admin/config", response_model=AgentConfig)
    def get_config(tenant_id: str = "default", _admin=Depends(_admin_auth)):
        return store.get_agent_config(tenant_id)

    @app.put("/api/v1/admin/config", response_model=AgentConfig)
    def put_config(config: AgentConfig, tenant_id: str = "default", _admin=Depends(_admin_auth)):
        return store.set_agent_config(tenant_id, config)

    @app.post("/api/v1/admin/enrollment-tokens")
    def create_enrollment_token(tenant_id: str = "default", max_uses: Optional[int] = None, _admin=Depends(_admin_auth)):
        return {"tenant_id": tenant_id, "token": store.create_enrollment_token(tenant_id, max_uses=max_uses)}

    @app.get("/api/v1/admin/downloads/agent/windows")
    def download_windows_agent(_admin=Depends(_admin_auth)):
        path = Path(os.environ.get("OPEN_EDR_MDR_WINDOWS_AGENT_EXE", "/tmp/open-edr-agent.exe"))
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=404, detail="windows_agent_binary_not_found")
        return FileResponse(path, media_type="application/vnd.microsoft.portable-executable", filename="open-edr-agent.exe")

    @app.get("/api/v1/admin/downloads/agent-config")
    def download_agent_config(tenant_id: str = "default", server_url: str = "http://127.0.0.1:8765", max_uses: int = 1, _admin=Depends(_admin_auth)):
        token = store.create_enrollment_token(tenant_id, max_uses=max_uses)
        config = {
            "tenant_id": tenant_id,
            "server_url": server_url,
            "enrollment_token": token,
            "agent_filename": "open-edr-agent.exe",
            "install_command": f".\\open-edr-agent.exe --install-service --server {server_url} --enroll-token {token}",
            "start_command": "sc.exe start OpenEDRMDRAgent",
            "notes": [
                "Run from an elevated PowerShell prompt on the Windows endpoint.",
                "Endpoint traffic is outbound-only; server queues jobs and agent polls /tasks/claim.",
                "Protect this file because it contains an enrollment token.",
            ],
        }
        return JSONResponse(config, headers={"Content-Disposition": "attachment; filename=open-edr-agent-config.json"})

    @app.get("/api/v1/admin/enrollment-tokens")
    def list_enrollment_tokens(tenant_id: str = "default", _admin=Depends(_admin_auth)):
        return {"tenant_id": tenant_id, "tokens": store.list_enrollment_tokens(tenant_id)}

    @app.post("/api/v1/admin/enrollment-tokens/revoke")
    def revoke_enrollment_token(token: str, tenant_id: str = "default", _admin=Depends(_admin_auth)):
        if not store.revoke_enrollment_token(tenant_id, token):
            raise HTTPException(status_code=404, detail="enrollment_token_not_found")
        return {"tenant_id": tenant_id, "revoked": True}

    @app.post("/api/v1/admin/detections/agent-health")
    def run_agent_health_detection(tenant_id: Optional[str] = None, stale_after_seconds: int = 300, _admin=Depends(_admin_auth)):
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
        marked_offline = store.mark_agents_offline([agent["agent_id"] for agent in store.stale_agents(stale_before, tenant_id=tenant_id)])
        inserted = store.insert_alerts(alerts)
        return {"stale_agents": len(alerts), "agents_marked_offline": marked_offline, "alerts_generated": inserted}

    app.dependency_overrides[_agent_auth] = _make_agent_auth(app)
    return app


def _admin_auth(authorization: Annotated[Optional[str], Header()] = None, x_admin_token: Annotated[Optional[str], Header()] = None):
    expected = os.environ.get("OPEN_EDR_MDR_ADMIN_TOKEN", DEFAULT_ADMIN_TOKEN)
    supplied = x_admin_token
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization.split(" ", 1)[1]
    if supplied != expected:
        raise HTTPException(status_code=401, detail="invalid admin token")
    return {"role": "admin"}


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

UI_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Open EDR MDR // Intranet Console</title>
  <style>
    :root{--bg:#080b0f;--line:#263544;--text:#d8e2ec;--muted:#7f92a5;--green:#6dff9d;--amber:#ffcc66;--red:#ff6b6b;--cyan:#6bdcff;--shadow:0 18px 60px rgba(0,0,0,.42)}
    *{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at 20% 0%,#142032 0,#080b0f 32%,#05070a 100%);color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;min-height:100vh}
    body:before{content:"";position:fixed;inset:0;background:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:28px 28px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.7),transparent);pointer-events:none}
    header{display:flex;align-items:center;justify-content:space-between;padding:22px 28px;border-bottom:1px solid var(--line);background:rgba(8,11,15,.86);backdrop-filter:blur(16px);position:sticky;top:0;z-index:2}
    h1{font-size:18px;margin:0;letter-spacing:.12em;text-transform:uppercase}.mark{color:var(--green);text-shadow:0 0 18px rgba(109,255,157,.35)}
    .controls,.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap} input,select,button{font:inherit;border:1px solid var(--line);background:#0b1118;color:var(--text);padding:10px 12px;border-radius:4px} input{min-width:190px} button{cursor:pointer;color:var(--green);border-color:#315143;background:#0d1915} button:hover{filter:brightness(1.15)} button.warn{color:var(--amber);border-color:#59451d;background:#191408}
    main{padding:28px;display:grid;gap:18px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:18px}.card{background:linear-gradient(180deg,rgba(19,29,40,.96),rgba(12,17,24,.96));border:1px solid var(--line);box-shadow:var(--shadow);border-radius:10px;overflow:hidden}.card h2{margin:0;padding:14px 16px;border-bottom:1px solid var(--line);font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--cyan)}.card .body{padding:14px 16px}.span3{grid-column:span 3}.span6{grid-column:span 6}.span12{grid-column:span 12}
    .metric{font-size:34px;color:var(--green);line-height:1}.label{color:var(--muted);font-size:12px;margin-top:6px}.pill{border:1px solid var(--line);background:#0b1118;padding:4px 8px;border-radius:999px;color:var(--muted);font-size:12px}.online{color:var(--green)}.offline{color:var(--red)}.sev-high,.sev-critical{color:var(--red)}.sev-medium{color:var(--amber)}.sev-low,.sev-info{color:var(--cyan)}
    table{width:100%;border-collapse:collapse;font-size:12px} th,td{padding:9px 8px;border-bottom:1px solid rgba(38,53,68,.72);vertical-align:top;text-align:left} th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px} tr:hover td{background:rgba(109,220,255,.04)} .muted{color:var(--muted)}.error{color:var(--red)}.ok{color:var(--green)} code{color:var(--green);white-space:pre-wrap}
    @media(max-width:900px){.grid{grid-template-columns:1fr}.span3,.span6,.span12{grid-column:span 1} header{display:block}.controls{margin-top:14px} input,select{min-width:0;width:100%}}
  </style>
</head>
<body>
<header>
  <h1><span class="mark">OPEN EDR MDR</span> // INTRANET V1</h1>
  <div class="controls"><input id="tenant" value="default" title="tenant"/><input id="token" type="password" value="dev-admin-token" title="admin token"/><button onclick="loadAll()">REFRESH</button></div>
</header>
<main>
  <section class="grid" id="metrics"></section>
  <section class="grid">
    <div class="card span6"><h2>Deployment Package</h2><div class="body"><p class="muted">下載 Windows agent 與含 enrollment token/server URL 的安裝設定檔。</p><div class="row"><input id="serverUrl" value="http://127.0.0.1:8765" placeholder="server url"><input id="maxUses" value="1" title="token max uses"><button onclick="downloadAgent()">DOWNLOAD AGENT EXE</button><button onclick="downloadConfig()">DOWNLOAD CONFIG</button></div><div id="deployStatus" style="margin-top:10px"></div></div></div>
    <div class="card span6"><h2>Reverse-Proxy Job Dispatch</h2><div class="body"><p class="muted">Server queue job；endpoint outbound polling /tasks/claim 後執行。</p><div class="row"><select id="taskAgent"></select><select id="taskType"><option>inventory</option><option>process_list</option><option>network_connections</option><option>service_list</option><option>scheduled_tasks</option><option>windows_event_logs</option><option>file_exists</option><option>file_hash</option></select><input id="taskArgs" placeholder='args JSON, e.g. {"profile":"powershell"}' style="flex:1"><button onclick="createTask()">QUEUE JOB</button></div><div id="taskStatus" style="margin-top:10px"></div></div></div>
  </section>
  <section class="grid">
    <div class="card span6"><h2>Indicator Hunt</h2><div class="body"><div class="row"><input id="indicator" placeholder="IP / domain / hash / command fragment" style="flex:1"><button onclick="hunt()">HUNT</button></div><div id="hunt" style="margin-top:14px"></div></div></div>
    <div class="card span6"><h2>Operational Distribution</h2><div class="body" id="dist"></div></div>
  </section>
  <section class="grid">
    <div class="card span12"><h2>Reporting Endpoints</h2><div class="body" id="agents"></div></div>
    <div class="card span6"><h2>Alerts</h2><div class="body" id="alerts"></div></div>
    <div class="card span6"><h2>Tasks</h2><div class="body" id="tasks"></div></div>
    <div class="card span6"><h2>Cases</h2><div class="body" id="cases"></div></div>
    <div class="card span6"><h2>Saved Hunts / Raw Evidence</h2><div class="body"><div id="hunts"></div><hr style="border-color:#263544"><div id="evidence"></div></div></div>
  </section>
</main>
<script>
const $=id=>document.getElementById(id); let AGENTS=[];
function tenant(){return encodeURIComponent($('tenant').value||'default')} function rawTenant(){return $('tenant').value||'default'} function headers(json=false){const h={'Authorization':'Bearer '+$('token').value}; if(json) h['Content-Type']='application/json'; return h}
async function api(path,opts={}){opts.headers={...(opts.headers||{}),...headers(opts.json)}; if(opts.json&&opts.body&&typeof opts.body!=='string') opts.body=JSON.stringify(opts.body); const r=await fetch(path,opts); if(!r.ok) throw new Error(path+' '+r.status+' '+await r.text()); return await r.json()}
function esc(v){return String(v??'').replace(/[&<>]/g,s=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[s]))} function pills(obj){return Object.entries(obj||{}).map(([k,v])=>`<span class="pill">${esc(k)}: <b>${esc(v)}</b></span>`).join(' ')}
function table(rows,cols){if(!rows||!rows.length)return '<span class="muted">no records</span>';return '<table><thead><tr>'+cols.map(c=>'<th>'+c[0]+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+cols.map(c=>'<td>'+c[1](r)+'</td>').join('')+'</tr>').join('')+'</tbody></table>'}
async function loadAll(){try{const t=tenant();const [s,a,al,c,ta,h,ev]=await Promise.all([api(`/api/v1/admin/summary?tenant_id=${t}`),api(`/api/v1/admin/agents?tenant_id=${t}`),api(`/api/v1/admin/alerts?tenant_id=${t}&limit=25`),api(`/api/v1/admin/cases?tenant_id=${t}&limit=25`),api(`/api/v1/admin/tasks?tenant_id=${t}&limit=25`),api(`/api/v1/admin/hunts?tenant_id=${t}&limit=25`),api(`/api/v1/admin/raw-evidence/list?tenant_id=${t}&limit=25`)]);AGENTS=a.agents||[];renderSummary(s);renderAgents(AGENTS);renderAgentOptions(AGENTS);renderAlerts(al);renderCases(c);renderTasks(ta);renderHunts(h);renderEvidence(ev.evidence)}catch(e){$('metrics').innerHTML='<div class="card span12"><div class="body error">'+esc(e.message)+'</div></div>'}}
function renderSummary(s){const c=s.counts||{};$('metrics').innerHTML=['agents','events','alerts','cases','tasks','raw_evidence'].map(k=>`<div class="card span3"><div class="body"><div class="metric">${c[k]??0}</div><div class="label">${k}</div></div></div>`).join('');$('dist').innerHTML=`<p>Agents ${pills(s.agent_status)}</p><p>Tasks ${pills(s.task_status)}</p><p>Cases ${pills(s.case_status)}</p><p>Alerts ${pills(s.alert_severity)}</p>`}
function renderAgentOptions(rows){$('taskAgent').innerHTML=(rows||[]).map(a=>`<option value="${esc(a.agent_id)}">${esc(a.host)} (${esc(a.status)})</option>`).join('')}
function renderAgents(rows){$('agents').innerHTML=table(rows,[['Status',r=>`<span class="${esc(r.status)}">${esc(r.status)}</span>`],['Hostname',r=>esc(r.host)],['OS',r=>esc(r.os)],['IP',r=>esc(r.ip_address)],['Agent',r=>esc(r.agent_version)],['Last Report',r=>esc(r.last_seen)],['ID',r=>`<code>${esc(r.agent_id)}</code>`],['Action',r=>`<button onclick="quickInventory('${esc(r.agent_id)}')">inventory</button>`]])}
function renderAlerts(rows){$('alerts').innerHTML=table(rows,[['Severity',r=>`<span class="sev-${esc(r.severity)}">${esc(r.severity)}</span>`],['Title',r=>esc(r.title)],['Host',r=>esc(r.host)],['Time',r=>esc(r.timestamp)]])}
function renderCases(rows){$('cases').innerHTML=table(rows,[['Status',r=>esc(r.status)],['Severity',r=>esc(r.severity)],['Title',r=>esc(r.title)],['Assignee',r=>esc(r.assignee)],['Updated',r=>esc(r.updated_at)]])}
function renderTasks(rows){$('tasks').innerHTML=table(rows,[['Status',r=>esc(r.status)],['Type',r=>esc(r.task_type)],['Agent',r=>esc((r.agent_id||'').slice(0,8))],['Raw',r=>r.raw_ref?'yes':''],['Created',r=>esc(r.created_at)]])}
function renderHunts(rows){$('hunts').innerHTML='<b>Hunts</b>'+table(rows,[['Enabled',r=>r.enabled?'yes':'no'],['Name',r=>esc(r.name)],['Indicator',r=>esc(r.indicator)],['Updated',r=>esc(r.updated_at)]])}
function renderEvidence(rows){$('evidence').innerHTML='<b>Evidence</b>'+table(rows,[['Kind',r=>esc(r.kind)],['SHA256',r=>esc((r.sha256||'').slice(0,16))],['Ref',r=>esc(r.raw_ref)],['Created',r=>esc(r.created_at)]])}
async function createTask(){try{const args=$('taskArgs').value?JSON.parse($('taskArgs').value):{};const body={tenant_id:rawTenant(),agent_id:$('taskAgent').value,task_type:$('taskType').value,args};const r=await api('/api/v1/admin/tasks',{method:'POST',json:true,body});$('taskStatus').innerHTML=`<span class="ok">queued ${esc(r.task_id)}</span>`;loadAll()}catch(e){$('taskStatus').innerHTML='<span class="error">'+esc(e.message)+'</span>'}}
async function quickInventory(agentId){$('taskAgent').value=agentId;$('taskType').value='inventory';$('taskArgs').value='{}';await createTask()}
async function hunt(){try{const q=encodeURIComponent($('indicator').value);if(!q)return;$('hunt').innerHTML='<span class="muted">hunting...</span>';const r=await api(`/api/v1/admin/investigate/hunt?tenant_id=${tenant()}&indicator=${q}&limit=50`);$('hunt').innerHTML=`<p>Hosts ${pills(Object.fromEntries((r.hosts||[]).map(h=>[h,'hit'])))}</p>`+table(r.events||[],[['Type',e=>esc(e.event_type)],['Host',e=>esc(e.host)],['Process',e=>esc(e.process_name)],['Command',e=>esc(e.command_line||e.remote_ip||e.domain||'')]])}catch(e){$('hunt').innerHTML='<span class="error">'+esc(e.message)+'</span>'}}
async function downloadBlob(path,filename,statusId){try{const r=await fetch(path,{headers:headers()}); if(!r.ok) throw new Error(await r.text()); const b=await r.blob(); const u=URL.createObjectURL(b); const a=document.createElement('a'); a.href=u; a.download=filename; a.click(); URL.revokeObjectURL(u); $(statusId).innerHTML='<span class="ok">download started</span>'}catch(e){$(statusId).innerHTML='<span class="error">'+esc(e.message)+'</span>'}}
function downloadAgent(){downloadBlob('/api/v1/admin/downloads/agent/windows','open-edr-agent.exe','deployStatus')}
function downloadConfig(){const q=`tenant_id=${tenant()}&server_url=${encodeURIComponent($('serverUrl').value)}&max_uses=${encodeURIComponent($('maxUses').value||'1')}`;downloadBlob('/api/v1/admin/downloads/agent-config?'+q,'open-edr-agent-config.json','deployStatus')}
loadAll();
</script>
</body>
</html>
"""
