from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping


class EvidenceError(ValueError):
    """Raised when endpoint evidence cannot be safely stored."""


@dataclass(frozen=True)
class RawEvidenceRecord:
    raw_ref: str
    tenant_id: str
    kind: str
    sha256: str
    payload_json: str

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.payload_json)


def canonical_payload(payload: Mapping[str, Any] | None) -> str:
    return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), default=str)


def build_raw_evidence(tenant_id: str, kind: str, object_id: str, payload: Mapping[str, Any] | None, *, sha256: str | None = None) -> RawEvidenceRecord:
    payload_json = canonical_payload(payload)
    payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    safe_object_id = str(object_id).replace("/", "_").replace(":", "_")
    raw_ref = f"sqlite://raw_evidence/{tenant_id}/{kind}/{safe_object_id}/{payload_hash[:16]}"
    return RawEvidenceRecord(raw_ref=raw_ref, tenant_id=tenant_id, kind=kind, sha256=(sha256 or payload_hash).lower(), payload_json=payload_json)


def build_agent_evidence(tenant_id: str, agent_id: str, req: Any) -> RawEvidenceRecord:
    metadata = dict(req.metadata or {})
    if req.kind == "file":
        if not str(metadata.get("reason") or "").strip():
            raise EvidenceError("evidence_reason_required")
        if not str(metadata.get("case_id") or "").strip():
            raise EvidenceError("evidence_case_id_required")
    declared_sha = str(req.sha256).lower()
    try:
        content = base64.b64decode(req.content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EvidenceError("evidence_content_base64_invalid") from exc
    actual_sha = hashlib.sha256(content).hexdigest()
    if actual_sha != declared_sha:
        raise EvidenceError("evidence_sha256_mismatch")
    if len(content) != req.size:
        raise EvidenceError("evidence_size_mismatch")
    payload = {
        "agent_id": agent_id,
        "kind": req.kind,
        "path": req.path,
        "sha256": declared_sha,
        "size": req.size,
        "content_base64": req.content_base64,
        "metadata": metadata,
    }
    object_id = f"{agent_id}:{req.kind}:{req.path or declared_sha}:{declared_sha[:16]}"
    return build_raw_evidence(tenant_id, f"agent_{req.kind}", object_id, payload, sha256=declared_sha)
