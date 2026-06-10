from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class HuntCreateRequest(BaseModel):
    tenant_id: str = "default"
    name: str
    description: Optional[str] = None
    indicator: Optional[str] = None
    query: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class HuntUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    indicator: Optional[str] = None
    query: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class HuntRecord(BaseModel):
    hunt_id: str
    tenant_id: str
    name: str
    description: Optional[str] = None
    indicator: Optional[str] = None
    query: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime
    updated_at: datetime


class HuntRunRecord(BaseModel):
    run_id: str
    hunt_id: str
    tenant_id: str
    status: str
    result: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
