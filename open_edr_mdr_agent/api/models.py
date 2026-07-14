from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from open_edr_mdr_agent.core.schemas import NormalizedEvent, ScriptResult


class EnrollmentRequest(BaseModel):
    enrollment_token: str
    public_key: Optional[str] = None
    host: str
    ip_address: Optional[str] = None
    os: Optional[str] = None
    agent_version: str = "dev"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EnrollmentResponse(BaseModel):
    tenant_id: str
    agent_id: str
    agent_token: str
    credential_version: int = 1
    config: Dict[str, Any] = Field(default_factory=dict)


class HeartbeatRequest(BaseModel):
    host: str
    ip_address: Optional[str] = None
    os: Optional[str] = None
    agent_version: str = "dev"
    uptime_seconds: Optional[int] = None
    health: Dict[str, Any] = Field(default_factory=dict)


class AgentCredentialUpdate(BaseModel):
    agent_token: str
    credential_version: int


class AgentConfig(BaseModel):
    version: int = Field(default=1, ge=1)
    task_poll_seconds: int = Field(default=15, ge=1, le=3600)
    heartbeat_seconds: int = Field(default=30, ge=1, le=3600)
    upload_interval_seconds: int = Field(default=15, ge=1, le=3600)
    max_snapshot_events: int = Field(default=25, ge=0, le=1000)
    collect_snapshot: bool = True
    collect_process_snapshot: bool = True
    collect_network_snapshot: bool = True
    collect_windows_event_logs: bool = True
    demo_suspicious_event: bool = False
    features: Dict[str, Any] = Field(default_factory=lambda: {"collector_gates_explicit": True})


class HeartbeatResponse(BaseModel):
    status: str = "ok"
    tasks_pending: bool = False
    config_version: int = 1
    config: AgentConfig = Field(default_factory=AgentConfig)
    credential_update: Optional[AgentCredentialUpdate] = None


class EventIngestRequest(BaseModel):
    events: List[NormalizedEvent]


class EventIngestResponse(BaseModel):
    accepted: int
    alerts_generated: int


class TaskCreateRequest(BaseModel):
    tenant_id: str = "default"
    agent_id: str
    task_type: str
    args: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 300


class TaskClaimRequest(BaseModel):
    max_tasks: int = 1


class TaskRecord(BaseModel):
    task_id: str
    tenant_id: str
    agent_id: str
    task_type: str
    args: Dict[str, Any] = Field(default_factory=dict)
    status: str
    created_at: datetime
    claimed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    raw_ref: Optional[str] = None
    raw_hash: Optional[str] = None


class TaskClaimResponse(BaseModel):
    tasks: List[TaskRecord]


class TaskResultRequest(BaseModel):
    status: str
    result: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class EvidenceUploadRequest(BaseModel):
    kind: str = "file"
    path: Optional[str] = None
    sha256: str
    size: int = Field(ge=0)
    content_base64: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvidenceUploadResponse(BaseModel):
    raw_ref: str
    sha256: str
    size: int


class AgentRecord(BaseModel):
    tenant_id: str
    agent_id: str
    host: str
    ip_address: Optional[str] = None
    os: Optional[str] = None
    agent_version: str = "dev"
    status: str = "online"
    credential_version: int = 1
    credential_status: str = "active"
    credential_revoked_at: Optional[datetime] = None
    credential_rotated_at: Optional[datetime] = None
    enrolled_at: datetime
    last_seen: Optional[datetime] = None
