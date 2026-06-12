from __future__ import annotations

import io
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response

from open_edr_mdr_agent.api.cases import CaseCreateRequest, CaseEvidenceRecord, CaseEvidenceRequest, CaseRecord, CaseUpdateRequest
from open_edr_mdr_agent.api.evidence import EvidenceError
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
    EvidenceUploadRequest,
    EvidenceUploadResponse,
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
    app = FastAPI(title="Shiori API", version="0.1.0")
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

    @app.post("/api/v1/agents/{agent_id}/evidence", response_model=EvidenceUploadResponse)
    def upload_agent_evidence(agent=Depends(_agent_auth), req: EvidenceUploadRequest = None):
        if req is None:
            raise HTTPException(status_code=400, detail="empty_evidence_upload")
        try:
            return store.store_agent_evidence(agent["tenant_id"], agent["agent_id"], req)
        except EvidenceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/admin/task-catalog")
    def list_task_catalog(_admin=Depends(_admin_auth)):
        return {"tasks": READONLY_TASK_CATALOG}

    @app.get("/api/v1/admin/readonly-scripts")
    def list_readonly_scripts(_admin=Depends(_admin_auth)):
        # Backward-compatible alias for older UI/tests. The catalog now includes
        # both read-only collection tasks and explicitly dispatched response tools.
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

    @app.post("/api/v1/admin/tasks/{task_id}/cancel")
    def cancel_task(task_id: str, tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        if not store.cancel_task(tenant_id, task_id):
            raise HTTPException(status_code=400, detail="task_not_cancellable")
        return {"tenant_id": tenant_id, "task_id": task_id, "status": "cancelled"}

    @app.post("/api/v1/admin/tasks/{task_id}/retry")
    def retry_task(task_id: str, tenant_id: str = Query("default"), _admin=Depends(_admin_auth)):
        if not store.retry_task(tenant_id, task_id):
            raise HTTPException(status_code=400, detail="task_not_retryable")
        return {"tenant_id": tenant_id, "task_id": task_id, "status": "queued"}

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
        path = Path(os.environ.get("SHIORI_WINDOWS_AGENT_EXE") or os.environ.get("OPEN_EDR_MDR_WINDOWS_AGENT_EXE", "/tmp/shiori-agent.exe"))
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=404, detail="windows_agent_binary_not_found")
        return FileResponse(path, media_type="application/vnd.microsoft.portable-executable", filename="shiori-agent.exe")

    def _deployment_config(tenant_id: str, server_url: str, enrollment_token: str) -> dict:
        return {
            "tenant_id": tenant_id,
            "server_url": server_url,
            "enrollment_token": enrollment_token,
            "agent_filename": "shiori-agent.exe",
            "install_dir": "C:\\Program Files\\Shiori",
            "data_dir": "C:\\ProgramData\\Shiori",
            "identity_file": "C:\\ProgramData\\Shiori\\shiori-agent-state.json",
            "spool_file": "C:\\ProgramData\\Shiori\\spool.jsonl",
            "install_command": f".\\shiori-agent.exe --install-service --server {server_url} --enroll-token {enrollment_token}",
            "package_install_command": ".\\install.ps1",
            "start_command": "sc.exe start ShioriAgent",
            "enrollment_model": {
                "stage_1": "This shared enrollment token is only for first registration with the server.",
                "stage_2": "After successful enrollment, the server issues a per-endpoint credential stored as C:\\ProgramData\\Shiori\\shiori-agent-state.json.",
                "stage_3": "All heartbeat, event ingest, task claim, and result upload calls use the per-endpoint credential, not the shared enrollment token.",
            },
            "notes": [
                "Run install.ps1 from an elevated PowerShell prompt on the Windows endpoint.",
                "Endpoint traffic is outbound-only; server queues jobs and agent polls /tasks/claim.",
                "The installer copies the service binary to C:\\Program Files\\Shiori and stores endpoint state/spool files under C:\\ProgramData\\Shiori.",
                "Protect this package because it contains an enrollment token. The token should be short-lived or limited-use in production.",
            ],
        }

    @app.get("/api/v1/admin/downloads/agent-config")
    def download_agent_config(tenant_id: str = "default", server_url: str = "http://127.0.0.1:8765", max_uses: Optional[int] = None, _admin=Depends(_admin_auth)):
        token = store.create_enrollment_token(tenant_id, max_uses=max_uses)
        config = _deployment_config(tenant_id, server_url, token)
        return JSONResponse(config, headers={"Content-Disposition": "attachment; filename=shiori-agent-config.json"})

    @app.get("/api/v1/admin/downloads/agent/package")
    def download_agent_package(tenant_id: str = "default", server_url: str = "http://127.0.0.1:8765", max_uses: Optional[int] = None, _admin=Depends(_admin_auth)):
        agent_path = Path(os.environ.get("SHIORI_WINDOWS_AGENT_EXE") or os.environ.get("OPEN_EDR_MDR_WINDOWS_AGENT_EXE", "/tmp/shiori-agent.exe"))
        if not agent_path.exists() or not agent_path.is_file():
            raise HTTPException(status_code=404, detail="windows_agent_binary_not_found")
        token = store.create_enrollment_token(tenant_id, max_uses=max_uses)
        config = _deployment_config(tenant_id, server_url, token)
        install_ps1 = r"""$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Agent = Join-Path $Here "shiori-agent.exe"
$ConfigPath = Join-Path $Here "shiori-agent-config.json"
if (!(Test-Path $Agent)) { throw "shiori-agent.exe not found" }
if (!(Test-Path $ConfigPath)) { throw "shiori-agent-config.json not found" }
$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
if (!$Config.server_url) { throw "server_url missing from config" }
if (!$Config.enrollment_token) { throw "enrollment_token missing from config" }
$InstallDir = $Config.install_dir
$DataDir = $Config.data_dir
if (!$InstallDir) { $InstallDir = "C:\Program Files\Shiori" }
if (!$DataDir) { $DataDir = "C:\ProgramData\Shiori" }
Write-Host "Installing Shiori Agent for $($Config.server_url)"
& $Agent --install-service --server $Config.server_url --enroll-token $Config.enrollment_token --install-dir $InstallDir --state (Join-Path $DataDir "shiori-agent-state.json") --spool (Join-Path $DataDir "spool.jsonl")
sc.exe start ShioriAgent
Write-Host "Installed. Service binary: $(Join-Path $InstallDir 'shiori-agent.exe')"
Write-Host "Endpoint state: $(Join-Path $DataDir 'shiori-agent-state.json')"
"""
        readme = r"""Shiori Agent deployment package

Files:
- shiori-agent.exe: Windows endpoint service binary
- shiori-agent-config.json: shared first-enrollment config
- install.ps1: elevated PowerShell installer

Enrollment model:
1. The config contains a shared enrollment token, similar to Fleet/osquery enroll secret.
2. On first successful registration, the server creates the endpoint record and returns a per-endpoint credential.
3. The endpoint stores that credential as C:\ProgramData\Shiori\shiori-agent-state.json and uses it for future authentication.
4. The shared enrollment token should not be used as the long-term endpoint identity.

Run from elevated PowerShell:
  Set-ExecutionPolicy -Scope Process Bypass
  .\\install.ps1
"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(agent_path, "shiori-agent.exe")
            zf.writestr("shiori-agent-config.json", json.dumps(config, ensure_ascii=False, indent=2))
            zf.writestr("install.ps1", install_ps1)
            zf.writestr("README.txt", readme)
        buf.seek(0)
        return Response(
            buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=shiori-agent-package.zip"},
        )

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
  <title>Shiori // Investigation Console</title>
  <style>
    :root{color-scheme:dark;--bg:#080b10;--rail:#0d1219;--panel:#111821;--panel2:#151e2a;--panel3:#0b1017;--ink:#e8eef7;--muted:#8fa1b5;--faint:#627487;--line:#243142;--line2:#33475b;--cyan:#5eead4;--blue:#7cc7ff;--green:#88f7a2;--amber:#ffd166;--red:#ff6370;--violet:#a78bfa;--shadow:0 24px 80px rgba(0,0,0,.38);--mono:"SFMono-Regular",Consolas,"Liberation Mono",monospace;--sans:"Aptos","Segoe UI",system-ui,-apple-system,sans-serif}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 20% -20%,rgba(94,234,212,.16),transparent 34rem),linear-gradient(180deg,#080b10,#06080c);color:var(--ink);font-family:var(--sans);overflow:hidden}button,input,select,textarea{font:inherit}button{border:0;border-radius:11px;background:linear-gradient(135deg,var(--cyan),var(--blue));color:#061015;font-weight:800;padding:9px 11px;cursor:pointer;min-height:38px}button:hover{filter:brightness(1.08)}button.secondary{background:#121b26;color:var(--ink);border:1px solid var(--line)}button.ghost{background:transparent;color:var(--cyan);border:1px solid rgba(94,234,212,.35);box-shadow:none}button.danger{background:rgba(255,99,112,.12);color:#ffc0c6;border:1px solid rgba(255,99,112,.35)}input,select,textarea{width:100%;border:1px solid var(--line);background:#080d13;color:var(--ink);border-radius:11px;padding:9px 10px;outline:none}textarea{min-height:72px;resize:vertical;font-family:var(--mono);font-size:12px}input:focus,select:focus,textarea:focus{border-color:rgba(94,234,212,.75);box-shadow:0 0 0 3px rgba(94,234,212,.08)}label{display:block;color:var(--faint);font-size:10px;letter-spacing:.12em;text-transform:uppercase;margin:0 0 6px}.app{height:100vh;display:grid;grid-template-rows:58px 1fr}.topbar{display:grid;grid-template-columns:280px 1fr auto;align-items:center;gap:16px;padding:0 18px;border-bottom:1px solid var(--line);background:rgba(8,11,16,.88);backdrop-filter:blur(18px)}.brand{display:flex;gap:12px;align-items:center}.sigil{width:34px;height:34px;border-radius:12px;background:conic-gradient(from 220deg,var(--cyan),var(--blue),#203247,var(--cyan));box-shadow:0 0 28px rgba(94,234,212,.23)}.brand h1{margin:0;font-size:14px;letter-spacing:.18em}.brand small{display:block;color:var(--muted);font-family:var(--mono);font-size:10px}.status-strip{display:flex;gap:8px;min-width:0}.stat{display:flex;gap:7px;align-items:baseline;border:1px solid var(--line);background:#0b1118;border-radius:999px;padding:7px 10px;white-space:nowrap}.stat b{font-family:var(--mono)}.stat span{color:var(--muted);font-size:12px}.top-actions{display:flex;gap:8px;align-items:center}.tenantbox{width:150px}.shell{min-height:0;display:grid;grid-template-columns:330px minmax(480px,1fr) 370px;gap:1px;background:var(--line)}.pane{min-height:0;background:rgba(9,13,19,.96);overflow:hidden}.pane-head{height:52px;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:0 14px;border-bottom:1px solid var(--line);background:#0b1017}.pane-title{min-width:0}.pane-title b{display:block;font-size:12px;letter-spacing:.13em;text-transform:uppercase}.pane-title span{display:block;color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.pane-body{height:calc(100% - 52px);overflow:auto;padding:12px}.tabs,.scope-tabs{display:flex;gap:6px}.tab,.scope{padding:7px 9px;border-radius:999px;border:1px solid var(--line);background:#0b1118;color:var(--muted);font-size:12px;cursor:pointer}.tab.active,.scope.active{color:#061015;background:linear-gradient(135deg,var(--cyan),var(--blue));border-color:transparent;font-weight:800}.alert-row,.endpoint-row{border:1px solid var(--line);border-radius:14px;background:linear-gradient(180deg,#101823,#0b1118);padding:10px 11px;margin-bottom:8px;cursor:pointer}.alert-row:hover,.endpoint-row:hover,.alert-row.active,.endpoint-row.active{border-color:rgba(94,234,212,.58);background:#121c28}.alert-main{display:grid;grid-template-columns:8px minmax(0,1fr) auto;gap:10px;align-items:center}.sevbar{height:34px;border-radius:99px;background:var(--muted)}.sev-high,.sev-critical{color:var(--red)}.sev-medium{color:var(--amber)}.sev-low{color:var(--cyan)}.sev-info{color:var(--blue)}.sevbar.high,.sevbar.critical{background:var(--red)}.sevbar.medium{background:var(--amber)}.sevbar.low{background:var(--cyan)}.sevbar.info{background:var(--blue)}.titleline{min-width:0}.titleline b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:13px}.meta{display:flex;gap:8px;align-items:center;color:var(--muted);font-size:12px;min-width:0}.meta span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.meta2{display:none;margin:8px 0 0 18px;color:var(--muted);font-size:12px;line-height:1.35}.alert-row:hover .meta2,.alert-row.active .meta2{display:block}.time{color:var(--faint);font-family:var(--mono);font-size:11px;white-space:nowrap}.empty{border:1px dashed var(--line);border-radius:14px;color:var(--muted);padding:18px;text-align:center}.workspace{display:grid;grid-template-rows:auto 1fr}.hero{padding:16px 18px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#101722,#0b1017)}.hero-row{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.hero h2{margin:0 0 7px;font-size:24px;line-height:1.1;letter-spacing:-.03em;max-width:820px}.hero p{margin:0;color:var(--muted);max-width:840px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.badges{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}.pill{display:inline-flex;gap:6px;align-items:center;border:1px solid var(--line);border-radius:999px;background:#0a1017;color:var(--muted);padding:4px 8px;font-size:12px;max-width:100%}.pill strong{color:var(--ink);overflow:hidden;text-overflow:ellipsis}.timeline-wrap{min-height:0;display:grid;grid-template-rows:43px 1fr}.timeline-toolbar{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:7px 14px;border-bottom:1px solid var(--line);background:#090e14}.timeline{overflow:auto;padding:16px 18px 30px}.event{display:grid;grid-template-columns:84px 1fr;gap:14px;margin-bottom:12px}.event-time{font-family:var(--mono);color:var(--faint);font-size:11px;padding-top:12px}.event-card{border:1px solid var(--line);border-radius:16px;background:linear-gradient(180deg,#111923,#0c121a);padding:12px 13px}.event-card b{display:block;margin-bottom:4px}.event-card p{margin:0;color:var(--muted);font-size:13px;line-height:1.45}.event-kind{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--cyan);margin-bottom:6px}.right .pane-body{display:grid;grid-template-rows:auto auto 1fr;gap:12px}.section{border:1px solid var(--line);border-radius:16px;background:#0b1118;padding:12px;min-width:0}.section h3{margin:0 0 10px;font-size:11px;letter-spacing:.13em;text-transform:uppercase;color:#d9e4ee}.kv{display:grid;grid-template-columns:86px minmax(0,1fr);gap:7px 10px;font-size:12px}.kv div:nth-child(odd){color:var(--faint);text-transform:uppercase;letter-spacing:.08em;font-size:10px}.kv div:nth-child(even){min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.actions{display:grid;gap:8px}.action-row{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;border:1px solid var(--line);border-radius:12px;padding:9px;background:#0a1017}.action-row b{font-size:13px}.action-row span{display:block;color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.more{margin-top:10px;border-top:1px solid var(--line);padding-top:10px}.drawer{position:fixed;inset:0;display:none;background:rgba(0,0,0,.5);z-index:10}.drawer.open{display:block}.drawer-panel{position:absolute;right:0;top:0;height:100%;width:min(440px,100vw);background:#0b1118;border-left:1px solid var(--line);box-shadow:var(--shadow);padding:18px;display:grid;grid-template-rows:auto 1fr}.drawer-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}.drawer-head h2{margin:0}.form-stack{display:grid;gap:12px;align-content:start}.toast{min-height:20px;color:var(--muted);font-size:12px}.code{font-family:var(--mono);color:#c6f7ff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.subgrid{display:grid;grid-template-columns:1fr 1fr;gap:8px}.sr-only{position:absolute;left:-9999px}@media(max-width:1180px){body{overflow:auto}.app{height:auto}.shell{grid-template-columns:1fr}.pane{min-height:420px}.right{min-height:620px}.topbar{grid-template-columns:1fr}.status-strip{flex-wrap:wrap}.tenantbox{width:100%}}
  </style>
</head>
<body>
<div class="app">
  <header class="topbar">
    <div class="brand"><div class="sigil" aria-hidden="true"></div><div><h1>SHIORI</h1><small>alert-driven investigation</small></div></div>
    <div class="status-strip" id="statusStrip"><span class="stat"><b>—</b><span>loading</span></span></div>
    <div class="top-actions"><input class="tenantbox" id="tenant" value="default" aria-label="Tenant"><input class="tenantbox" id="token" type="password" value="dev-admin-token" aria-label="Admin token"><button class="secondary" onclick="openDeploy()">Deploy agent</button><button onclick="loadAll()">Refresh</button></div>
  </header>
  <main class="shell">
    <aside class="pane queue">
      <div class="pane-head"><div class="pane-title"><b>Investigation queue</b><span>Alerts first, endpoints nearby</span></div><div class="tabs"><button class="tab active" id="tabAlerts" onclick="switchQueue('alerts')">Alerts</button><button class="tab" id="tabEndpoints" onclick="switchQueue('endpoints')">Endpoints</button></div></div>
      <div class="pane-body" id="queueBody"></div>
    </aside>
    <section class="pane workspace">
      <div class="hero">
        <div class="hero-row"><div><div class="pill"><strong id="selectedKind">No alert selected</strong></div><h2 id="workspaceTitle">Choose an alert to begin investigation.</h2><p id="workspaceSummary">The timeline stays narrow by default, then expands by scope when you need more context.</p></div><div class="time" id="liveText">idle</div></div>
        <div class="badges" id="workspaceBadges"></div>
      </div>
      <div class="timeline-wrap">
        <div class="timeline-toolbar"><div class="scope-tabs"><button class="scope active" id="scopeRelated" onclick="setScope('related')">Related</button><button class="scope" id="scopeWindow" onclick="setScope('window')">±15m</button><button class="scope" id="scopeHost" onclick="setScope('host')">Host day</button><button class="scope" id="scopeTenant" onclick="setScope('tenant')">All tenant</button></div><span class="muted" id="timelineCount">0 events</span></div>
        <div class="timeline" id="timeline"></div>
      </div>
    </section>
    <aside class="pane right">
      <div class="pane-head"><div class="pane-title"><b>Context panel</b><span>Entity detail + next steps</span></div></div>
      <div class="pane-body">
        <section class="section"><h3>Selected entity</h3><div id="entityDetail" class="kv"></div></section>
        <section class="section"><h3>Recommended next steps</h3><div id="recommendedActions" class="actions"></div></section>
        <section class="section"><h3>More actions</h3><div class="form-stack"><select id="taskAgent"></select><select id="taskType"></select><textarea id="taskArgs" placeholder='{"profile":"powershell","max_events":25}'></textarea><div class="subgrid"><button onclick="queueCustomTask()">Queue task</button><button class="secondary" onclick="presetSafeTask()">Safe preset</button></div><div id="taskStatus" class="toast"></div></div></section>
      </div>
    </aside>
  </main>
</div>
<div class="drawer" id="deployDrawer" role="dialog" aria-modal="true" aria-labelledby="deployTitle"><div class="drawer-panel"><div class="drawer-head"><h2 id="deployTitle">Deploy Shiori Agent</h2><button class="secondary" onclick="closeDeploy()">Close</button></div><div class="form-stack"><p class="muted">Deployment is setup work, so it lives outside the investigation surface.</p><label for="serverUrl">Server URL</label><input id="serverUrl" value="http://192.168.1.93:8765"><label for="maxUses">Enrollment token max uses</label><input id="maxUses" placeholder="optional"><div class="subgrid"><button onclick="downloadPackage()">Download ZIP</button><button class="secondary" onclick="downloadConfig()">Config JSON</button></div><button class="ghost" onclick="downloadAgent()">Download agent binary</button><div id="deployStatus" class="toast"></div></div></div></div>
<script>
const $=id=>document.getElementById(id);let STATE={queue:'alerts',scope:'related',summary:null,agents:[],alerts:[],tasks:[],cases:[],hunts:[],evidence:[],events:[],selectedAlert:null,selectedEndpoint:null};
const TASKS=['inventory','agent_identity','process_list','process_detail','process_tree','network_connections','listening_ports','service_list','scheduled_tasks','windows_event_logs','file_exists','file_hash','list_directory','read_file_chunk','copy_file','collect_file','registry_query','autoruns_collect','quarantine_file','delete_file','kill_process','service_control'];
function tenant(){return encodeURIComponent($('tenant').value||'default')}function rawTenant(){return $('tenant').value||'default'}function headers(json=false){const h={'Authorization':'Bearer '+$('token').value};if(json)h['Content-Type']='application/json';return h}async function api(path,opts={}){opts.headers={...(opts.headers||{}),...headers(opts.json)};if(opts.json&&opts.body&&typeof opts.body!=='string')opts.body=JSON.stringify(opts.body);const r=await fetch(path,opts);if(!r.ok)throw new Error(path+' '+r.status+' '+await r.text());return await r.json()}function esc(v){return String(v??'').replace(/[&<>"']/g,s=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s]))}function short(v,n=18){v=String(v||'');return v.length>n?v.slice(0,n)+'…':v}function clsSeverity(s){return String(s||'info').toLowerCase()}function fmtTime(v){if(!v)return '—';try{return new Date(v).toLocaleString()}catch{return v}}function empty(msg){return `<div class="empty">${esc(msg)}</div>`}function pill(k,v){return `<span class="pill"><span>${esc(k)}</span><strong>${esc(v||'—')}</strong></span>`}function setText(id,v){$(id).textContent=v}
async function loadAll(){try{setText('liveText','refreshing…');const t=tenant();const [summary,agents,alerts,cases,tasks,hunts,evidence,events]=await Promise.all([api(`/api/v1/admin/summary?tenant_id=${t}`),api(`/api/v1/admin/agents?tenant_id=${t}`),api(`/api/v1/admin/alerts?tenant_id=${t}&limit=50`),api(`/api/v1/admin/cases?tenant_id=${t}&limit=25`),api(`/api/v1/admin/tasks?tenant_id=${t}&limit=50`),api(`/api/v1/admin/hunts?tenant_id=${t}&limit=25`),api(`/api/v1/admin/raw-evidence/list?tenant_id=${t}&limit=50`),api(`/api/v1/admin/events?tenant_id=${t}&limit=150`)]);STATE.summary=summary;STATE.agents=agents.agents||[];STATE.alerts=alerts.alerts||alerts||[];STATE.cases=cases.cases||cases||[];STATE.tasks=tasks.tasks||tasks||[];STATE.hunts=hunts.hunts||hunts||[];STATE.evidence=evidence.evidence||evidence||[];STATE.events=events.events||events||[];if(!STATE.selectedAlert&&STATE.alerts[0])selectAlert(STATE.alerts[0].alert_id,false);renderAll();setText('liveText','updated '+new Date().toLocaleTimeString())}catch(e){setText('liveText','load failed');$('queueBody').innerHTML=empty(e.message)}}
function renderAll(){renderStatus();renderTaskSelectors();renderQueue();renderWorkspace();renderContext()}function renderStatus(){const c=(STATE.summary&&STATE.summary.counts)||{};$('statusStrip').innerHTML=[['alerts','Alerts'],['agents','Endpoints'],['tasks','Tasks'],['cases','Cases']].map(([k,l])=>`<span class="stat"><b>${esc(c[k]??0)}</b><span>${l}</span></span>`).join('')}
function switchQueue(q){STATE.queue=q;$('tabAlerts').classList.toggle('active',q==='alerts');$('tabEndpoints').classList.toggle('active',q==='endpoints');renderQueue()}function renderQueue(){if(STATE.queue==='endpoints')return renderEndpointQueue();const rows=STATE.alerts;if(!rows.length){$('queueBody').innerHTML=empty('No alerts yet. Shiori will populate this queue when detection rules match endpoint telemetry.');return}$('queueBody').innerHTML=rows.map(a=>{const active=STATE.selectedAlert&&STATE.selectedAlert.alert_id===a.alert_id;const sev=clsSeverity(a.severity);return `<div class="alert-row ${active?'active':''}" onclick="selectAlert('${esc(a.alert_id)}')"><div class="alert-main"><div class="sevbar ${sev}"></div><div class="titleline"><b>${esc(a.title)}</b><div class="meta"><span class="sev-${sev}">${esc(a.severity)}</span><span>${esc(a.host||'unknown host')}</span></div></div><div class="time">${esc(fmtTime(a.timestamp||a.created_at))}</div></div><div class="meta2">${esc(a.process_name||'no process')} · ${esc((a.mitre||[]).join(', ')||'no MITRE')} · ${esc(short(a.description||a.alert_id,96))}</div></div>`}).join('')}
function renderEndpointQueue(){const rows=STATE.agents;if(!rows.length){$('queueBody').innerHTML=empty('No reporting endpoints. Use Deploy agent to enroll one.');return}$('queueBody').innerHTML=rows.map(a=>{const active=STATE.selectedEndpoint&&STATE.selectedEndpoint.agent_id===a.agent_id;return `<div class="endpoint-row ${active?'active':''}" onclick="selectEndpoint('${esc(a.agent_id)}')"><div class="titleline"><b>${esc(a.host||'unknown host')}</b><div class="meta"><span class="status-${esc(a.status)}">● ${esc(a.status)}</span><span>${esc(a.ip_address||'no ip')}</span></div><div class="meta2" style="display:block;margin-left:0">${esc(a.os||'unknown os')} · ${esc(short(a.agent_id,22))}</div></div></div>`}).join('')}
function findAlert(id){return STATE.alerts.find(a=>a.alert_id===id)}function findAgentByHost(host){return STATE.agents.find(a=>a.host===host||a.hostname===host)}function findAgent(id){return STATE.agents.find(a=>a.agent_id===id)}function selectAlert(id,rerender=true){STATE.selectedAlert=findAlert(id)||null;STATE.selectedEndpoint=STATE.selectedAlert?findAgentByHost(STATE.selectedAlert.host)||null:STATE.selectedEndpoint;if(rerender)renderAll()}function selectEndpoint(id){STATE.selectedEndpoint=findAgent(id)||null;STATE.selectedAlert=null;renderAll()}function setScope(scope){STATE.scope=scope;['Related','Window','Host','Tenant'].forEach(s=>$('scope'+s).classList.toggle('active',scope.toLowerCase()===(s==='Window'?'window':s.toLowerCase())));renderWorkspace()}
function relatedEvents(){const a=STATE.selectedAlert,ep=STATE.selectedEndpoint;if(!a&&!ep)return[];let rows=STATE.events||[];if(STATE.scope==='tenant')return rows;if(STATE.scope==='host')return rows.filter(e=>e.host===(a&&a.host)||(ep&&e.host===ep.host));if(STATE.scope==='window'&&a&&a.timestamp){const t=Date.parse(a.timestamp);return rows.filter(e=>e.host===a.host&&Math.abs(Date.parse(e.timestamp||e.created_at||0)-t)<=15*60*1000)}if(a){return rows.filter(e=>e.host===a.host&&(e.process_name===a.process_name||JSON.stringify(e).includes(a.alert_id)||JSON.stringify(a).includes(e.id)||e.event_type==='endpoint_state')).slice(0,40)}return rows.filter(e=>e.host===ep.host).slice(0,40)}
function renderWorkspace(){const a=STATE.selectedAlert,ep=STATE.selectedEndpoint;if(a){setText('selectedKind','Selected alert');setText('workspaceTitle',a.title);setText('workspaceSummary',`${a.host||'unknown host'} · ${a.process_name||'no process'} · ${a.description||a.alert_id}`);$('workspaceBadges').innerHTML=[pill('severity',a.severity),pill('host',a.host),pill('process',a.process_name),pill('MITRE',(a.mitre||[]).join(', '))].join('')}else if(ep){setText('selectedKind','Selected endpoint');setText('workspaceTitle',ep.host||'Endpoint');setText('workspaceSummary',`${ep.status||'unknown'} · ${ep.ip_address||'no ip'} · ${ep.os||'unknown os'}`);$('workspaceBadges').innerHTML=[pill('status',ep.status),pill('ip',ep.ip_address),pill('agent',short(ep.agent_id,22))].join('')}else{setText('selectedKind','No selection');setText('workspaceTitle','Choose an alert to begin investigation.');setText('workspaceSummary','Alert-driven timeline keeps context focused.');$('workspaceBadges').innerHTML=''}renderTimeline()}
function renderTimeline(){const a=STATE.selectedAlert,ep=STATE.selectedEndpoint;let items=[];if(a)items.push({time:a.timestamp||a.created_at,kind:'alert',title:a.title,text:a.description||a.alert_id});for(const e of relatedEvents())items.push({time:e.timestamp||e.created_at,kind:e.event_type||'event',title:e.process_name||e.event_type||'Event',text:e.command_line||e.remote_ip||e.domain||e.raw_ref||JSON.stringify(e.raw||{}).slice(0,160)});const agentId=(ep&&ep.agent_id)||(a&&findAgentByHost(a.host)||{}).agent_id;for(const t of (STATE.tasks||[]).filter(t=>!agentId||t.agent_id===agentId).slice(0,12))items.push({time:t.completed_at||t.created_at,kind:'task',title:t.task_type+' · '+t.status,text:t.error||t.raw_ref||'task result'});items.sort((x,y)=>Date.parse(y.time||0)-Date.parse(x.time||0));$('timelineCount').textContent=items.length+' timeline items';$('timeline').innerHTML=items.length?items.map(i=>`<div class="event"><div class="event-time">${esc(fmtTime(i.time))}</div><div class="event-card"><div class="event-kind">${esc(i.kind)}</div><b>${esc(i.title)}</b><p>${esc(short(i.text,220))}</p></div></div>`).join(''):empty('No related timeline data for this scope yet.')}
function renderContext(){const a=STATE.selectedAlert,ep=STATE.selectedEndpoint;let detail=[];if(a){detail=[['Severity',a.severity],['Host',a.host],['Process',a.process_name],['MITRE',(a.mitre||[]).join(', ')],['Time',fmtTime(a.timestamp||a.created_at)],['Alert ID',a.alert_id]]}else if(ep){detail=[['Host',ep.host],['Status',ep.status],['IP',ep.ip_address],['OS',ep.os],['Version',ep.agent_version],['Agent ID',ep.agent_id]]}else detail=[['Selection','none'],['Hint','Pick an alert']];$('entityDetail').innerHTML=detail.map(([k,v])=>`<div>${esc(k)}</div><div title="${esc(v)}">${esc(v||'—')}</div>`).join('');renderRecommendedActions()}
function currentAgent(){return STATE.selectedEndpoint||(STATE.selectedAlert&&findAgentByHost(STATE.selectedAlert.host))||STATE.agents[0]}function renderRecommendedActions(){const a=STATE.selectedAlert;let rec=[['Collect event logs','windows_event_logs',{profile:a&&String(a.title||'').toLowerCase().includes('powershell')?'powershell':'service',max_events:25}],['Inspect processes','process_list',{}],['Network snapshot','network_connections',{}],['Persistence sweep','autoruns_collect',{}]];if(!a)rec=[['Inventory','inventory',{}],['Agent identity','agent_identity',{}],['Listening ports','listening_ports',{}]];$('recommendedActions').innerHTML=rec.map(([label,type,args])=>`<div class="action-row"><div><b>${esc(label)}</b><span>${esc(type)} ${esc(JSON.stringify(args))}</span></div><button class="secondary" onclick='queueTask("${type}",${JSON.stringify(args)})'>Run</button></div>`).join('')}
function renderTaskSelectors(){const ep=currentAgent();$('taskAgent').innerHTML=STATE.agents.map(a=>`<option value="${esc(a.agent_id)}" ${ep&&ep.agent_id===a.agent_id?'selected':''}>${esc(a.host||a.agent_id)}</option>`).join('')||'<option value="">no agent</option>';$('taskType').innerHTML=TASKS.map(t=>`<option>${t}</option>`).join('')}async function queueTask(type,args){const ep=currentAgent();if(!ep)throwStatus('No endpoint selected');$('taskStatus').innerHTML='<span class="muted">queueing…</span>';try{const body={tenant_id:rawTenant(),agent_id:ep.agent_id,task_type:type,args:args||{}};const r=await api('/api/v1/admin/tasks',{method:'POST',json:true,body});$('taskStatus').innerHTML=`<span class="ok">queued ${esc(short(r.task_id,16))}</span>`;await loadAll()}catch(e){$('taskStatus').innerHTML=`<span class="error">${esc(e.message)}</span>`}}function throwStatus(msg){$('taskStatus').innerHTML=`<span class="error">${esc(msg)}</span>`;throw new Error(msg)}async function queueCustomTask(){let args={};try{args=$('taskArgs').value?JSON.parse($('taskArgs').value):{}}catch(e){return throwStatus('Invalid JSON args')}await queueTask($('taskType').value,args)}function presetSafeTask(){$('taskType').value='windows_event_logs';$('taskArgs').value=JSON.stringify({profile:'powershell',max_events:25},null,2)}
function openDeploy(){$('deployDrawer').classList.add('open')}function closeDeploy(){$('deployDrawer').classList.remove('open')}async function downloadBlob(path,filename,statusId){try{const r=await fetch(path,{headers:headers()});if(!r.ok)throw new Error(await r.text());const b=await r.blob();const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=filename;a.click();URL.revokeObjectURL(u);$(statusId).innerHTML='<span class="ok">download started</span>'}catch(e){$(statusId).innerHTML='<span class="error">'+esc(e.message)+'</span>'}}function deploymentQuery(){const max=$('maxUses').value;return `tenant_id=${tenant()}&server_url=${encodeURIComponent($('serverUrl').value)}`+(max?`&max_uses=${encodeURIComponent(max)}`:'')}function downloadPackage(){downloadBlob('/api/v1/admin/downloads/agent/package?'+deploymentQuery(),'shiori-agent-package.zip','deployStatus')}function downloadAgent(){downloadBlob('/api/v1/admin/downloads/agent/windows','shiori-agent.exe','deployStatus')}function downloadConfig(){downloadBlob('/api/v1/admin/downloads/agent-config?'+deploymentQuery(),'shiori-agent-config.json','deployStatus')}
loadAll();
</script>
</body>
</html>
"""
