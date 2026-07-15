from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol

from open_edr_mdr_agent.api.evidence import canonical_payload


@dataclass(frozen=True)
class StoredRawObject:
    raw_ref: str
    storage_provider: str
    bucket: str
    object_key: str
    size: int
    mime_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


class RawObjectStore(Protocol):
    storage_provider: str
    bucket: str

    def put_json(
        self,
        *,
        tenant_id: str,
        kind: str,
        object_id: str,
        payload: Mapping[str, Any] | None,
        sha256: str,
        size: int | None = None,
        mime_type: str = "application/json",
        metadata: Mapping[str, Any] | None = None,
    ) -> StoredRawObject:
        ...

    def get_json(self, raw_ref: str) -> dict[str, Any]:
        ...


class LocalObjectStore:
    def __init__(
        self,
        root: str | Path,
        *,
        bucket: str = "raw-evidence",
        storage_provider: str = "local",
        ref_scheme: str = "object",
        endpoint_url: str | None = None,
    ) -> None:
        self.root = Path(root)
        self.bucket = bucket
        self.storage_provider = storage_provider
        self.ref_scheme = ref_scheme
        self.endpoint_url = endpoint_url
        self.root.mkdir(parents=True, exist_ok=True)

    def put_json(
        self,
        *,
        tenant_id: str,
        kind: str,
        object_id: str,
        payload: Mapping[str, Any] | None,
        sha256: str,
        size: int | None = None,
        mime_type: str = "application/json",
        metadata: Mapping[str, Any] | None = None,
    ) -> StoredRawObject:
        payload_json = canonical_payload(payload)
        payload_bytes = payload_json.encode("utf-8")
        object_key = _object_key(tenant_id, kind, object_id, sha256)
        path = self.root / self.bucket / object_key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload_bytes)
        raw_ref = f"{self.ref_scheme}://{self.bucket}/{object_key}"
        return StoredRawObject(
            raw_ref=raw_ref,
            storage_provider=self.storage_provider,
            bucket=self.bucket,
            object_key=object_key,
            size=int(size if size is not None else len(payload_bytes)),
            mime_type=mime_type,
            metadata=dict(metadata or {}),
        )

    def get_json(self, raw_ref: str) -> dict[str, Any]:
        object_key = _object_key_from_ref(raw_ref, self.bucket)
        payload = (self.root / self.bucket / object_key).read_text()
        return json.loads(payload)


def object_store_from_env(base_dir: str | Path) -> RawObjectStore:
    provider = os.environ.get("OPEN_EDR_MDR_RAW_OBJECT_STORE_PROVIDER", "local").strip().lower() or "local"
    bucket = os.environ.get("OPEN_EDR_MDR_RAW_OBJECT_STORE_BUCKET", "raw-evidence").strip() or "raw-evidence"
    root = os.environ.get("OPEN_EDR_MDR_RAW_OBJECT_STORE_ROOT") or str(Path(base_dir) / "raw-objects")
    endpoint = os.environ.get("OPEN_EDR_MDR_RAW_OBJECT_STORE_ENDPOINT")
    if provider in {"s3", "s3_compatible", "s3-compatible"}:
        return LocalObjectStore(root, bucket=bucket, storage_provider="s3_compatible", ref_scheme="s3", endpoint_url=endpoint)
    return LocalObjectStore(root, bucket=bucket, storage_provider="local", ref_scheme="object", endpoint_url=endpoint)


def _object_key(tenant_id: str, kind: str, object_id: str, sha256: str) -> str:
    return "/".join([_safe_segment(tenant_id), _safe_segment(kind), _safe_segment(object_id), f"{sha256.lower()}.json"])


def _object_key_from_ref(raw_ref: str, bucket: str) -> str:
    marker = f"://{bucket}/"
    if marker not in raw_ref:
        raise KeyError("raw_ref_bucket_mismatch")
    return raw_ref.split(marker, 1)[1]


def _safe_segment(value: str) -> str:
    safe = []
    for char in str(value):
        if char.isalnum() or char in {"-", "_", "."}:
            safe.append(char)
        else:
            safe.append("_")
    return "".join(safe).strip("._") or "object"
