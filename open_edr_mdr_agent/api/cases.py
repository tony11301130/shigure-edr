from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class CaseCreateRequest(BaseModel):
    tenant_id: str = "default"
    title: str
    severity: str = "medium"
    alert_id: Optional[str] = None
    description: Optional[str] = None


class CaseEvidenceRequest(BaseModel):
    evidence_type: str
    ref_id: str
    summary: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)


class CaseUpdateRequest(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    summary: Optional[str] = None


class CaseRecord(BaseModel):
    case_id: str
    tenant_id: str
    title: str
    severity: str
    status: str
    alert_id: Optional[str] = None
    assignee: Optional[str] = None
    description: Optional[str] = None
    summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CaseEvidenceRecord(BaseModel):
    evidence_id: str
    case_id: str
    tenant_id: str
    evidence_type: str
    ref_id: str
    summary: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
