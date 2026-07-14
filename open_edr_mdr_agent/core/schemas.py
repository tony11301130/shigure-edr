from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class Source(str, Enum):
    SYSMON = "sysmon"
    WAZUH = "wazuh"
    OSQUERY = "osquery"
    VELOCIRAPTOR = "velociraptor"
    FALCO = "falco"
    TETRAGON = "tetragon"
    INTERNAL = "internal"


class EventType(str, Enum):
    ALERT = "alert"
    PROCESS_START = "process_start"
    PROCESS_END = "process_end"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    FILE_EVENT = "file_event"
    REGISTRY_EVENT = "registry_event"
    AUTH_EVENT = "auth_event"
    ENDPOINT_STATE = "endpoint_state"
    SCRIPT_RESULT = "script_result"
    GENERIC = "generic"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NormalizedEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    source: Source
    event_type: EventType = EventType.GENERIC
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ingested_at: Optional[datetime] = None
    tenant_id: str = "default"
    source_event_id: Optional[str] = None
    host: Optional[str] = None
    ip_address: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[str] = None
    process_entity_id: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[str] = None
    parent_process_entity_id: Optional[str] = None
    boot_id: Optional[str] = None
    process_create_time: Optional[str] = None
    process_exit_time: Optional[str] = None
    image_path: Optional[str] = None
    image_hash: Optional[str] = None
    process_identity_confidence: Optional[str] = None
    missing_parent_reason: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    hash_sha256: Optional[str] = None
    hash_md5: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    domain: Optional[str] = None
    registry_key: Optional[str] = None
    alert_title: Optional[str] = None
    severity: Severity = Severity.INFO
    mitre: List[str] = Field(default_factory=list)
    raw_ref: Optional[str] = None
    raw_hash: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class EndpointContext(BaseModel):
    host: str
    ip_address: Optional[str] = None
    os: Optional[str] = None
    agent_connected: Optional[bool] = None
    agent_version: Optional[str] = None
    last_seen: Optional[datetime] = None
    isolated: Optional[bool] = None
    sources: List[Source] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    alert_id: str
    title: str
    severity: Severity = Severity.INFO
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: Optional[datetime] = None
    host: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    description: Optional[str] = None
    mitre: List[str] = Field(default_factory=list)
    source: Source
    raw_ref: Optional[str] = None
    raw_hash: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class ScriptResult(BaseModel):
    job_id: str = Field(default_factory=lambda: str(uuid4()))
    helper_name: str
    host: str
    status: str
    result: Dict[str, Any] = Field(default_factory=dict)
    source: Source = Source.INTERNAL
