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
    config: Dict[str, Any] = Field(default_factory=dict)


class HeartbeatRequest(BaseModel):
    host: str
    ip_address: Optional[str] = None
    os: Optional[str] = None
    agent_version: str = "dev"
    uptime_seconds: Optional[int] = None
    health: Dict[str, Any] = Field(default_factory=dict)


class AgentConfig(BaseModel):
    version: int = 1
    task_poll_seconds: int = 15
    heartbeat_seconds: int = 30
    upload_interval_seconds: int = 15
    max_snapshot_events: int = 25
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


class TaskClaimResponse(BaseModel):
    tasks: List[TaskRecord]


class TaskResultRequest(BaseModel):
    status: str
    result: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class AgentRecord(BaseModel):
    tenant_id: str
    agent_id: str
    host: str
    ip_address: Optional[str] = None
    os: Optional[str] = None
    agent_version: str = "dev"
    status: str = "online"
    enrolled_at: datetime
    last_seen: Optional[datetime] = None
