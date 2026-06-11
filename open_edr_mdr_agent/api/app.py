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
  <title>Shiori // SOC Console</title>
  <style>
    :root{
      color-scheme:dark;
      --bg:#07090d;--panel:#0d1219;--panel2:#111923;--panel3:#151f2b;--ink:#e8eef7;--muted:#8fa0b3;--faint:#5d6f82;
      --line:#223040;--line2:#314254;--blue:#65b7ff;--cyan:#4ee4d1;--green:#7dffa7;--amber:#ffd166;--orange:#ff9f43;--red:#ff5f6d;
      --shadow:0 24px 70px rgba(0,0,0,.46);--radius:18px;--mono:"SFMono-Regular",Consolas,"Liberation Mono",monospace;
      --sans:"Aptos","Segoe UI",system-ui,-apple-system,sans-serif;
    }
    *{box-sizing:border-box} html{scroll-behavior:smooth} body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);font-family:var(--sans);overflow-x:hidden}
    body:before{content:"";position:fixed;inset:0;pointer-events:none;background:
      radial-gradient(circle at 16% -10%,rgba(78,228,209,.22),transparent 28rem),radial-gradient(circle at 85% 4%,rgba(101,183,255,.16),transparent 24rem),
      linear-gradient(135deg,rgba(255,255,255,.035) 0 1px,transparent 1px 13px);mask-image:linear-gradient(to bottom,#000 0%,rgba(0,0,0,.9) 50%,transparent 100%)}
    .app{position:relative;display:grid;grid-template-columns:280px minmax(0,1fr);min-height:100vh}.rail{position:sticky;top:0;height:100vh;padding:22px;border-right:1px solid var(--line);background:linear-gradient(180deg,rgba(9,14,20,.94),rgba(7,9,13,.88));backdrop-filter:blur(18px)}
    .brand{display:flex;gap:12px;align-items:center;margin-bottom:28px}.sigil{width:42px;height:42px;border-radius:14px;background:conic-gradient(from 210deg,var(--cyan),var(--blue),#203247,var(--cyan));box-shadow:0 0 36px rgba(78,228,209,.25);position:relative}.sigil:after{content:"";position:absolute;inset:9px;border:1px solid rgba(255,255,255,.55);border-radius:10px;background:rgba(7,9,13,.45)}
    .brand h1{font-size:15px;letter-spacing:.16em;line-height:1.2;margin:0;text-transform:uppercase}.brand small{color:var(--muted);font-family:var(--mono);font-size:11px}.nav{display:grid;gap:8px;margin:18px 0 26px}.nav a{color:var(--muted);text-decoration:none;padding:11px 12px;border:1px solid transparent;border-radius:12px;font-size:13px}.nav a:hover{color:var(--ink);border-color:var(--line);background:rgba(255,255,255,.035)}
    .authbox{padding:14px;border:1px solid var(--line);border-radius:16px;background:rgba(17,25,35,.7)}label{display:block;color:var(--faint);text-transform:uppercase;letter-spacing:.12em;font-size:10px;margin:0 0 7px}input,select,button{font:inherit}input,select{width:100%;border:1px solid var(--line);background:#090e14;color:var(--ink);border-radius:12px;padding:11px 12px;outline:none}input:focus,select:focus{border-color:rgba(78,228,209,.72);box-shadow:0 0 0 3px rgba(78,228,209,.08)}.authbox input+label{margin-top:12px}
    button{border:0;border-radius:12px;background:linear-gradient(135deg,var(--cyan),var(--blue));color:#041015;font-weight:800;letter-spacing:.04em;padding:11px 13px;cursor:pointer;box-shadow:0 12px 30px rgba(78,228,209,.16)}button:hover{filter:brightness(1.08)}button.secondary{background:#111923;color:var(--ink);border:1px solid var(--line);box-shadow:none}button.ghost{background:transparent;color:var(--cyan);border:1px solid rgba(78,228,209,.42);box-shadow:none}.rail button{width:100%;margin-top:14px}
    .content{padding:26px 30px 40px}.hero{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:end;margin-bottom:22px}.eyebrow{font-family:var(--mono);color:var(--cyan);letter-spacing:.16em;text-transform:uppercase;font-size:12px}.hero h2{font-size:42px;line-height:1.02;margin:8px 0 8px;letter-spacing:-.04em}.hero p{color:var(--muted);margin:0;max-width:760px}.live{display:flex;gap:8px;align-items:center;border:1px solid var(--line);border-radius:999px;padding:9px 13px;background:rgba(17,25,35,.76);color:var(--muted);font-family:var(--mono);font-size:12px}.dot{width:9px;height:9px;border-radius:99px;background:var(--green);box-shadow:0 0 18px var(--green)}
    .grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px;margin-bottom:16px}.card{grid-column:span 12;background:linear-gradient(180deg,rgba(17,25,35,.92),rgba(10,15,22,.92));border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}.span3{grid-column:span 3}.span4{grid-column:span 4}.span5{grid-column:span 5}.span6{grid-column:span 6}.span7{grid-column:span 7}.span8{grid-column:span 8}.card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 17px;border-bottom:1px solid var(--line)}.card h3{margin:0;font-size:12px;letter-spacing:.13em;text-transform:uppercase;color:#cdd8e5}.body{padding:16px 17px}.metric{font-family:var(--mono);font-size:38px;line-height:1;color:var(--ink);letter-spacing:-.05em}.metric-label{margin-top:8px;color:var(--muted);font-size:12px}.metric-card{position:relative;min-height:122px}.metric-card:after{content:"";position:absolute;right:-26px;bottom:-28px;width:95px;height:95px;border-radius:999px;border:1px solid rgba(78,228,209,.28)}
    .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row>*{flex:1}.row button{flex:0 0 auto}.stack{display:grid;gap:12px}.muted{color:var(--muted)}.faint{color:var(--faint)}.ok{color:var(--green)}.error{color:var(--red)}code{font-family:var(--mono);color:#c2f7ff;word-break:break-all}.pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:#0a1017;color:var(--muted);border-radius:999px;padding:5px 9px;font-size:12px;margin:2px}.pill strong{color:var(--ink)}.status-online{color:var(--green)}.status-offline{color:var(--red)}.sev-critical,.sev-high{color:var(--red)}.sev-medium{color:var(--amber)}.sev-low{color:var(--cyan)}.sev-info{color:var(--blue)}
    table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px}th{color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.11em;text-align:left;font-weight:800;padding:0 10px 9px}td{padding:12px 10px;border-top:1px solid rgba(34,48,64,.78);vertical-align:top}tbody tr:hover td{background:rgba(78,228,209,.035)}.hostcell{display:flex;gap:10px;align-items:center}.osicon{width:30px;height:30px;border-radius:10px;display:grid;place-items:center;background:#0b121a;border:1px solid var(--line);color:var(--cyan);font-family:var(--mono);font-size:11px}.empty{border:1px dashed var(--line);border-radius:14px;padding:22px;color:var(--muted);text-align:center}.split{display:grid;grid-template-columns:1fr 1fr;gap:12px}.bar{height:9px;border-radius:99px;background:#081018;overflow:hidden;border:1px solid var(--line);margin-top:7px}.bar span{display:block;height:100%;background:linear-gradient(90deg,var(--cyan),var(--blue))}.timeline{display:grid;gap:10px}.event{padding:11px 12px;border:1px solid var(--line);border-radius:14px;background:rgba(10,16,23,.72)}.event b{display:block;margin-bottom:4px}
    @media(max-width:1100px){.app{grid-template-columns:1fr}.rail{position:relative;height:auto}.nav{grid-template-columns:repeat(3,1fr)}.hero{grid-template-columns:1fr}.span3,.span4,.span5,.span6,.span7,.span8{grid-column:span 12}}@media(max-width:680px){.content{padding:18px}.hero h2{font-size:31px}.nav{grid-template-columns:1fr}.row{display:grid}.row button{width:100%}.split{grid-template-columns:1fr}}
  </style>
</head>
<body>
<div class="app">
  <aside class="rail">
    <div class="brand"><div class="sigil"></div><div><h1>SHIORI</h1><small>endpoint response console</small></div></div>
    <nav class="nav"><a href="#overview">Overview</a><a href="#endpoints">Endpoints</a><a href="#response">Response</a><a href="#detections">Detections</a><a href="#hunt">Hunt</a><a href="#evidence">Evidence</a></nav>
    <div class="authbox">
      <label for="tenant">Tenant</label><input id="tenant" value="default" />
      <label for="token">Admin token</label><input id="token" type="password" value="dev-admin-token" />
      <button onclick="loadAll()">Refresh console</button>
    </div>
  </aside>
  <main class="content">
    <section class="hero" id="overview">
      <div><div class="eyebrow">SOC command surface</div><h2>Endpoint visibility, queued response, and evidence in one place.</h2><p>Inspired by Wazuh-style security overview, Velociraptor collection workflows, and Fleet/osquery host operations — tuned for this prototype's outbound-only agent model.</p></div>
      <div class="live"><span class="dot"></span><span id="liveText">loading telemetry</span></div>
    </section>
    <section class="grid" id="metrics"></section>
    <section class="grid">
      <div class="card span8" id="endpoints"><div class="card-head"><h3>Reporting Endpoints</h3><span class="pill" id="agentPill">0 hosts</span></div><div class="body" id="agents"></div></div>
      <div class="card span4"><div class="card-head"><h3>Operational distribution</h3></div><div class="body stack" id="dist"></div></div>
    </section>
    <section class="grid" id="response">
      <div class="card span6"><div class="card-head"><h3>Deployment package</h3><span class="pill">Windows agent</span></div><div class="body stack"><p class="muted">下載 agent 與含 tenant/server/enrollment token 的設定檔。</p><div class="row"><input id="serverUrl" value="http://192.168.1.93:8765" placeholder="server url"><input id="maxUses" value="" title="token max uses" placeholder="max uses optional"></div><div class="row"><button onclick="downloadPackage()">DOWNLOAD DEPLOYMENT ZIP</button><button class="secondary" onclick="downloadConfig()">DOWNLOAD CONFIG</button></div><div id="deployStatus"></div></div></div>
      <div class="card span6"><div class="card-head"><h3>Reverse-Proxy Job Dispatch</h3><span class="pill">outbound polling</span></div><div class="body stack"><p class="muted">Server queue job；endpoint 之後 polling <code>/tasks/claim</code> 取走執行。</p><div class="row"><select id="taskAgent"></select><select id="taskType"><option>inventory</option><option>process_list</option><option>network_connections</option><option>service_list</option><option>scheduled_tasks</option><option>windows_event_logs</option><option>file_exists</option><option>file_hash</option></select></div><input id="taskArgs" placeholder='args JSON, e.g. {"path":"C:\\Windows\\System32\\cmd.exe"}'><div class="row"><button onclick="createTask()">Queue read-only job</button><button class="secondary" onclick="presetInventory()">Inventory preset</button></div><div id="taskStatus"></div></div></div>
    </section>
    <section class="grid" id="detections">
      <div class="card span7"><div class="card-head"><h3>Alerts</h3><span class="pill">latest 25</span></div><div class="body" id="alerts"></div></div>
      <div class="card span5"><div class="card-head"><h3>Cases</h3><span class="pill">triage queue</span></div><div class="body" id="cases"></div></div>
      <div class="card span12"><div class="card-head"><h3>Tasks</h3><span class="pill">agent queue</span></div><div class="body" id="tasks"></div></div>
    </section>
    <section class="grid" id="hunt">
      <div class="card span7"><div class="card-head"><h3>Indicator hunt</h3><span class="pill">events + hosts</span></div><div class="body stack"><div class="row"><input id="indicator" placeholder="IP / domain / hash / command fragment"><button onclick="hunt()">Hunt</button></div><div id="huntResults"></div></div></div>
      <div class="card span5" id="evidence"><div class="card-head"><h3>Saved hunts / raw evidence</h3></div><div class="body stack"><div id="hunts"></div><div id="evidenceList"></div></div></div>
    </section>
  </main>
</div>
<script>
const $=id=>document.getElementById(id); let AGENTS=[];
function tenant(){return encodeURIComponent($('tenant').value||'default')} function rawTenant(){return $('tenant').value||'default'} function headers(json=false){const h={'Authorization':'Bearer '+$('token').value}; if(json) h['Content-Type']='application/json'; return h}
async function api(path,opts={}){opts.headers={...(opts.headers||{}),...headers(opts.json)}; if(opts.json&&opts.body&&typeof opts.body!=='string') opts.body=JSON.stringify(opts.body); const r=await fetch(path,opts); if(!r.ok) throw new Error(path+' '+r.status+' '+await r.text()); return await r.json()}
function esc(v){return String(v??'').replace(/[&<>"']/g,s=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s]))}
function pill(k,v){return `<span class="pill">${esc(k)} <strong>${esc(v)}</strong></span>`} function pills(obj){const e=Object.entries(obj||{}); return e.length?e.map(([k,v])=>pill(k,v)).join(' '):'<span class="muted">no data</span>'}
function empty(msg){return `<div class="empty">${esc(msg)}</div>`} function short(v,n=10){v=String(v||''); return v.length>n?v.slice(0,n)+'…':v}
function table(rows,cols,msg='no records'){if(!rows||!rows.length)return empty(msg);return '<table><thead><tr>'+cols.map(c=>'<th>'+c[0]+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+cols.map(c=>'<td>'+c[1](r)+'</td>').join('')+'</tr>').join('')+'</tbody></table>'}
function pct(v,total){return total?Math.max(4,Math.round((Number(v)||0)*100/total)):0} function distBlock(title,obj){const total=Object.values(obj||{}).reduce((a,b)=>a+Number(b||0),0); const rows=Object.entries(obj||{}); if(!rows.length)return `<div><b>${esc(title)}</b><div class="muted">no data</div></div>`; return `<div><b>${esc(title)}</b>`+rows.map(([k,v])=>`<div style="margin-top:10px"><div class="row" style="justify-content:space-between"><span class="muted">${esc(k)}</span><code>${esc(v)}</code></div><div class="bar"><span style="width:${pct(v,total)}%"></span></div></div>`).join('')+'</div>'}
async function loadAll(){try{$('liveText').textContent='refreshing';const t=tenant();const [s,a,al,c,ta,h,ev]=await Promise.all([api(`/api/v1/admin/summary?tenant_id=${t}`),api(`/api/v1/admin/agents?tenant_id=${t}`),api(`/api/v1/admin/alerts?tenant_id=${t}&limit=25`),api(`/api/v1/admin/cases?tenant_id=${t}&limit=25`),api(`/api/v1/admin/tasks?tenant_id=${t}&limit=25`),api(`/api/v1/admin/hunts?tenant_id=${t}&limit=25`),api(`/api/v1/admin/raw-evidence/list?tenant_id=${t}&limit=25`)]);AGENTS=a.agents||[];renderSummary(s);renderAgents(AGENTS);renderAgentOptions(AGENTS);renderAlerts(al.alerts||al);renderCases(c.cases||c);renderTasks(ta.tasks||ta);renderHunts(h.hunts||h);renderEvidence(ev.evidence||ev);$('liveText').textContent='updated '+new Date().toLocaleTimeString()}catch(e){$('liveText').textContent='load failed';$('metrics').innerHTML='<div class="card"><div class="body error">'+esc(e.message)+'</div></div>'}}
function renderSummary(s){const c=s.counts||{};const items=[['agents','Endpoints'],['alerts','Alerts'],['cases','Cases'],['tasks','Tasks']];$('metrics').innerHTML=items.map(([k,l])=>`<div class="card span3 metric-card"><div class="body"><div class="metric">${esc(c[k]??0)}</div><div class="metric-label">${esc(l)}</div></div></div>`).join('');$('dist').innerHTML=distBlock('Agent health',s.agent_status)+distBlock('Alert severity',s.alert_severity)+distBlock('Task queue',s.task_status)+distBlock('Case status',s.case_status)}
function renderAgentOptions(rows){$('agentPill').textContent=(rows||[]).length+' hosts';$('taskAgent').innerHTML=(rows||[]).map(a=>`<option value="${esc(a.agent_id)}">${esc(a.host||a.hostname||a.agent_id)} (${esc(a.status)})</option>`).join('')||'<option value="">no agent</option>'}
function renderAgents(rows){$('agents').innerHTML=table(rows,[['Host',r=>`<div class="hostcell"><div class="osicon">${esc((r.os||'?').slice(0,3).toUpperCase())}</div><div><b>${esc(r.host||r.hostname||'unknown')}</b><br><span class="muted">${esc(r.ip_address||r.ip||'no ip')}</span></div></div>`],['Health',r=>`<span class="status-${esc(r.status)}">● ${esc(r.status)}</span>`],['Agent',r=>esc(r.agent_version||'unknown')],['Last seen',r=>esc(r.last_seen||'never')],['ID',r=>`<code>${esc(short(r.agent_id,18))}</code>`],['Action',r=>`<button class="ghost" onclick="quickInventory('${esc(r.agent_id)}')">inventory</button>`]],'no enrolled endpoints yet')}
function renderAlerts(rows){$('alerts').innerHTML=table(rows,[['Severity',r=>`<b class="sev-${esc(r.severity)}">${esc(r.severity)}</b>`],['Detection',r=>`<b>${esc(r.title)}</b><br><span class="muted">${esc(r.source||'')}</span>`],['Host',r=>esc(r.host||'')],['Time',r=>esc(r.timestamp||r.created_at||'')]],'no alerts')}
function renderCases(rows){$('cases').innerHTML=table(rows,[['Status',r=>esc(r.status)],['Case',r=>`<b>${esc(r.title)}</b><br><span class="muted">${esc(r.assignee||'unassigned')}</span>`],['Severity',r=>`<span class="sev-${esc(r.severity)}">${esc(r.severity)}</span>`],['Updated',r=>esc(r.updated_at||'')]],'no open cases')}
function renderTasks(rows){$('tasks').innerHTML=table(rows,[['Status',r=>`<b>${esc(r.status)}</b>`],['Task',r=>esc(r.task_type)],['Endpoint',r=>`<code>${esc(short(r.agent_id,18))}</code>`],['Raw evidence',r=>r.raw_ref?`<code>${esc(r.raw_ref)}</code>`:'<span class="muted">none</span>'],['Created',r=>esc(r.created_at||'')]],'no queued tasks')}
function renderHunts(rows){$('hunts').innerHTML='<b>Saved hunts</b>'+table(rows,[['Enabled',r=>r.enabled?'yes':'no'],['Name',r=>esc(r.name)],['Indicator',r=>`<code>${esc(r.indicator)}</code>`]],'no saved hunts')}
function renderEvidence(rows){$('evidenceList').innerHTML='<b>Raw evidence</b>'+table(rows,[['Kind',r=>esc(r.kind)],['SHA256',r=>`<code>${esc(short(r.sha256,16))}</code>`],['Created',r=>esc(r.created_at||'')]],'no evidence collected')}
async function createTask(){try{if(!$('taskAgent').value)throw new Error('no endpoint selected');const args=$('taskArgs').value?JSON.parse($('taskArgs').value):{};const body={tenant_id:rawTenant(),agent_id:$('taskAgent').value,task_type:$('taskType').value,args};const r=await api('/api/v1/admin/tasks',{method:'POST',json:true,body});$('taskStatus').innerHTML=`<span class="ok">queued ${esc(r.task_id)}</span>`;loadAll()}catch(e){$('taskStatus').innerHTML='<span class="error">'+esc(e.message)+'</span>'}}
function presetInventory(){ $('taskType').value='inventory'; $('taskArgs').value='{}'; }
async function quickInventory(agentId){$('taskAgent').value=agentId;presetInventory();await createTask()}
async function hunt(){try{const q=encodeURIComponent($('indicator').value);if(!q)return;$('huntResults').innerHTML='<span class="muted">hunting...</span>';const r=await api(`/api/v1/admin/investigate/hunt?tenant_id=${tenant()}&indicator=${q}&limit=50`);$('huntResults').innerHTML=`<div class="split"><div class="event"><b>Matched hosts</b>${pills(Object.fromEntries((r.hosts||[]).map(h=>[h,'hit'])))}</div><div class="event"><b>Event count</b><span class="metric" style="font-size:28px">${esc((r.events||[]).length)}</span></div></div>`+table(r.events||[],[['Type',e=>esc(e.event_type)],['Host',e=>esc(e.host)],['Process',e=>esc(e.process_name)],['Signal',e=>esc(e.command_line||e.remote_ip||e.domain||'')]],'no matching events')}catch(e){$('huntResults').innerHTML='<span class="error">'+esc(e.message)+'</span>'}}
async function downloadBlob(path,filename,statusId){try{const r=await fetch(path,{headers:headers()}); if(!r.ok) throw new Error(await r.text()); const b=await r.blob(); const u=URL.createObjectURL(b); const a=document.createElement('a'); a.href=u; a.download=filename; a.click(); URL.revokeObjectURL(u); $(statusId).innerHTML='<span class="ok">download started</span>'}catch(e){$(statusId).innerHTML='<span class="error">'+esc(e.message)+'</span>'}}
function deploymentQuery(){const max=$('maxUses').value;return `tenant_id=${tenant()}&server_url=${encodeURIComponent($('serverUrl').value)}`+(max?`&max_uses=${encodeURIComponent(max)}`:'')} function downloadPackage(){downloadBlob('/api/v1/admin/downloads/agent/package?'+deploymentQuery(),'shiori-agent-package.zip','deployStatus')} function downloadAgent(){downloadBlob('/api/v1/admin/downloads/agent/windows','shiori-agent.exe','deployStatus')} function downloadConfig(){downloadBlob('/api/v1/admin/downloads/agent-config?'+deploymentQuery(),'shiori-agent-config.json','deployStatus')}
loadAll();
</script>
</body>
</html>
"""

