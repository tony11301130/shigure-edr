from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from open_edr_mdr_agent.core.schemas import NormalizedEvent


class ClickHouseTelemetryStore:
    storage_profile = "clickhouse"

    def __init__(self, dsn: str, *, client: Any | None = None, init_schema: bool = True):
        self.dsn = dsn
        self.client = client or ClickHouseHTTPClient(dsn)
        if init_schema:
            self.init_schema()

    @staticmethod
    def schema_statements() -> list[str]:
        return [
            """
            CREATE TABLE IF NOT EXISTS shigure_events (
                tenant_id String,
                endpoint_id String,
                host String,
                event_id String,
                event_time DateTime64(3, 'UTC'),
                ingested_at DateTime64(3, 'UTC'),
                event_type LowCardinality(String),
                source LowCardinality(String),
                process_entity_id String,
                parent_process_entity_id String,
                pid String,
                parent_pid String,
                process_name String,
                image_path String,
                command_line String,
                user String,
                hash_sha256 String,
                remote_ip String,
                remote_port UInt16,
                domain String,
                severity LowCardinality(String),
                confidence String,
                gap_reason String,
                raw_ref String,
                raw_hash String,
                raw_json String,
                event_json String
            )
            ENGINE = MergeTree
            PARTITION BY toYYYYMMDD(event_time)
            ORDER BY (tenant_id, endpoint_id, event_time, event_type, process_entity_id, event_id)
            TTL event_time + INTERVAL 30 DAY
            """,
            """
            CREATE TABLE IF NOT EXISTS shigure_process_edges (
                tenant_id String,
                endpoint_id String,
                host String,
                parent_process_entity_id String,
                process_entity_id String,
                first_seen DateTime64(3, 'UTC'),
                last_seen DateTime64(3, 'UTC'),
                confidence String,
                gap_reason String
            )
            ENGINE = MergeTree
            PARTITION BY toYYYYMMDD(first_seen)
            ORDER BY (tenant_id, endpoint_id, parent_process_entity_id, process_entity_id, first_seen)
            TTL first_seen + INTERVAL 30 DAY
            """,
            """
            CREATE TABLE IF NOT EXISTS shigure_event_rollups_hourly (
                tenant_id String,
                endpoint_id String,
                host String,
                bucket_start DateTime64(3, 'UTC'),
                event_type LowCardinality(String),
                event_count UInt64,
                gap_count UInt64,
                collector_health_json String
            )
            ENGINE = SummingMergeTree
            PARTITION BY toYYYYMMDD(bucket_start)
            ORDER BY (tenant_id, endpoint_id, bucket_start, event_type)
            TTL bucket_start + INTERVAL 180 DAY
            """,
        ]

    def init_schema(self) -> None:
        for statement in self.schema_statements():
            self.client.execute(statement)

    def insert_events(self, agent_id: str, events: Iterable[NormalizedEvent]) -> int:
        now = datetime.now(timezone.utc)
        rows = []
        edges = []
        rollups: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        for event in events:
            event.ingested_at = event.ingested_at or now
            rows.append(_event_row(agent_id, event))
            if event.process_entity_id:
                edges.append(_edge_row(agent_id, event))
            bucket = event.timestamp.replace(minute=0, second=0, microsecond=0)
            key = (event.tenant_id, agent_id, event.host or "", bucket.isoformat(), event.event_type.value)
            current = rollups.setdefault(
                key,
                {
                    "tenant_id": event.tenant_id,
                    "endpoint_id": agent_id,
                    "host": event.host or "",
                    "bucket_start": _ch_datetime(bucket),
                    "event_type": event.event_type.value,
                    "event_count": 0,
                    "gap_count": 0,
                    "collector_health_json": json.dumps({}),
                },
            )
            current["event_count"] += 1
            if event.missing_parent_reason:
                current["gap_count"] += 1
        if rows:
            self.client.insert_json_each_row("shigure_events", rows)
        if edges:
            self.client.insert_json_each_row("shigure_process_edges", edges)
        if rollups:
            self.client.insert_json_each_row("shigure_event_rollups_hourly", list(rollups.values()))
        return len(rows)

    def get_event(self, tenant_id: str, event_id: str) -> Optional[NormalizedEvent]:
        rows = self.client.query_json_each_row(
            f"SELECT event_json FROM shigure_events WHERE tenant_id = {_quote(tenant_id)} AND event_id = {_quote(event_id)} LIMIT 1"
        )
        return _event_from_row(rows[0]) if rows else None

    def count_events(
        self,
        tenant_id: str,
        host: Optional[str] = None,
        event_type: Optional[str] = None,
        process_name: Optional[str] = None,
        user: Optional[str] = None,
        hash_sha256: Optional[str] = None,
        process_entity_id: Optional[str] = None,
        remote_ip: Optional[str] = None,
        domain: Optional[str] = None,
        indicator: Optional[str] = None,
    ) -> int:
        where = _event_where(
            tenant_id,
            host=host,
            event_type=event_type,
            process_name=process_name,
            user=user,
            hash_sha256=hash_sha256,
            process_entity_id=process_entity_id,
            remote_ip=remote_ip,
            domain=domain,
            indicator=indicator,
        )
        rows = self.client.query_json_each_row(f"SELECT count() AS count FROM shigure_events WHERE {where}")
        return int(rows[0].get("count", 0)) if rows else 0

    def related_events(self, tenant_id: str, entity_type: str, value: str, limit: int = 100) -> list[NormalizedEvent]:
        field_map = {
            "host": "host",
            "process_id": "pid",
            "parent_process_id": "parent_pid",
            "process_entity_id": "process_entity_id",
            "parent_process_entity_id": "parent_process_entity_id",
            "process_name": "process_name",
            "user": "user",
            "hash_sha256": "hash_sha256",
            "remote_ip": "remote_ip",
            "domain": "domain",
            "command_line": "command_line",
        }
        if entity_type == "file_path":
            predicate = f"positionCaseInsensitive(event_json, {_quote(value)}) > 0"
        elif entity_type in {"process_name", "command_line", "user"}:
            predicate = f"positionCaseInsensitive({field_map[entity_type]}, {_quote(value)}) > 0"
        elif entity_type in field_map:
            predicate = f"{field_map[entity_type]} = {_quote(value)}"
        else:
            return []
        rows = self.client.query_json_each_row(
            f"SELECT event_json FROM shigure_events WHERE tenant_id = {_quote(tenant_id)} AND {predicate} ORDER BY event_time DESC LIMIT {int(limit)}"
        )
        return [_event_from_row(row) for row in rows]

    def list_events(
        self,
        tenant_id: str,
        host: Optional[str] = None,
        event_type: Optional[str] = None,
        process_name: Optional[str] = None,
        user: Optional[str] = None,
        hash_sha256: Optional[str] = None,
        process_entity_id: Optional[str] = None,
        remote_ip: Optional[str] = None,
        domain: Optional[str] = None,
        indicator: Optional[str] = None,
        limit: int = 100,
    ) -> list[NormalizedEvent]:
        where = _event_where(
            tenant_id,
            host=host,
            event_type=event_type,
            process_name=process_name,
            user=user,
            hash_sha256=hash_sha256,
            process_entity_id=process_entity_id,
            remote_ip=remote_ip,
            domain=domain,
            indicator=indicator,
        )
        rows = self.client.query_json_each_row(f"SELECT event_json FROM shigure_events WHERE {where} ORDER BY event_time DESC LIMIT {int(limit)}")
        return [_event_from_row(row) for row in rows]

    def telemetry_storage_config(self) -> dict[str, Any]:
        return {
            "storage_provider": "clickhouse",
            "dsn": _safe_dsn(self.dsn),
            "tables": ["shigure_events", "shigure_process_edges", "shigure_event_rollups_hourly"],
            "retention": self.telemetry_retention_policy(),
        }

    def telemetry_retention_policy(self) -> dict[str, Any]:
        return {
            "hot_normalized_telemetry_days": 30,
            "warm_rollup_days": 180,
            "partition": "toYYYYMMDD(event_time)",
            "rollups": ["event_rollups_hourly", "collector_health_hourly", "telemetry_gaps_hourly"],
        }


class ClickHouseHTTPClient:
    def __init__(self, dsn: str):
        self.endpoint = _http_endpoint(dsn)

    def execute(self, sql: str) -> None:
        self._post(sql)

    def insert_json_each_row(self, table: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        body = f"INSERT INTO {table} FORMAT JSONEachRow\n" + "\n".join(json.dumps(row, default=str) for row in rows)
        self._post(body)

    def query_json_each_row(self, sql: str) -> list[dict[str, Any]]:
        raw = self._post(f"{sql} FORMAT JSONEachRow")
        return [json.loads(line) for line in raw.splitlines() if line.strip()]

    def _post(self, body: str) -> str:
        req = Request(self.endpoint, data=body.encode("utf-8"), method="POST")
        with urlopen(req, timeout=10) as res:
            return res.read().decode("utf-8")


def _event_row(agent_id: str, event: NormalizedEvent) -> dict[str, Any]:
    raw_json = json.dumps(event.raw or {}, default=str, sort_keys=True)
    return {
        "tenant_id": event.tenant_id,
        "endpoint_id": agent_id,
        "host": event.host or "",
        "event_id": event.id,
        "event_time": _ch_datetime(event.timestamp),
        "ingested_at": _ch_datetime(event.ingested_at or datetime.now(timezone.utc)),
        "event_type": event.event_type.value,
        "source": event.source.value,
        "process_entity_id": event.process_entity_id or "",
        "parent_process_entity_id": event.parent_process_entity_id or "",
        "pid": event.process_id or "",
        "parent_pid": event.parent_process_id or "",
        "process_name": event.process_name or "",
        "image_path": event.image_path or "",
        "command_line": event.command_line or "",
        "user": event.user or "",
        "hash_sha256": event.hash_sha256 or "",
        "remote_ip": event.remote_ip or "",
        "remote_port": event.remote_port or 0,
        "domain": event.domain or "",
        "severity": event.severity.value,
        "confidence": event.process_identity_confidence or "",
        "gap_reason": event.missing_parent_reason or "",
        "raw_ref": event.raw_ref or "",
        "raw_hash": event.raw_hash or "",
        "raw_json": raw_json,
        "event_json": event.model_dump_json(),
    }


def _edge_row(agent_id: str, event: NormalizedEvent) -> dict[str, Any]:
    return {
        "tenant_id": event.tenant_id,
        "endpoint_id": agent_id,
        "host": event.host or "",
        "parent_process_entity_id": event.parent_process_entity_id or "",
        "process_entity_id": event.process_entity_id or "",
        "first_seen": _ch_datetime(event.timestamp),
        "last_seen": _ch_datetime(event.timestamp),
        "confidence": event.process_identity_confidence or "",
        "gap_reason": event.missing_parent_reason or "",
    }


def _event_where(
    tenant_id: str,
    *,
    host: Optional[str] = None,
    event_type: Optional[str] = None,
    process_name: Optional[str] = None,
    user: Optional[str] = None,
    hash_sha256: Optional[str] = None,
    process_entity_id: Optional[str] = None,
    remote_ip: Optional[str] = None,
    domain: Optional[str] = None,
    indicator: Optional[str] = None,
) -> str:
    clauses = [f"tenant_id = {_quote(tenant_id)}"]
    exact_fields = {
        "host": host,
        "event_type": event_type,
        "hash_sha256": hash_sha256,
        "process_entity_id": process_entity_id,
        "remote_ip": remote_ip,
        "domain": domain,
    }
    for field, value in exact_fields.items():
        if value:
            clauses.append(f"{field} = {_quote(value)}")
    if process_name:
        clauses.append(f"positionCaseInsensitive(process_name, {_quote(process_name)}) > 0")
    if user:
        clauses.append(f"positionCaseInsensitive(user, {_quote(user)}) > 0")
    if indicator:
        clauses.append(f"positionCaseInsensitive(event_json, {_quote(indicator)}) > 0")
    return " AND ".join(clauses)


def _event_from_row(row: dict[str, Any]) -> NormalizedEvent:
    value = row.get("event_json")
    if isinstance(value, str):
        return NormalizedEvent.model_validate_json(value)
    return NormalizedEvent.model_validate(value)


def _quote(value: Any) -> str:
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def _ch_datetime(value: datetime) -> str:
    if value.tzinfo:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat(sep=" ", timespec="milliseconds")


def _http_endpoint(dsn: str) -> str:
    parsed = urlparse(dsn)
    if parsed.scheme in {"http", "https"}:
        return dsn
    if parsed.scheme in {"clickhouse", "clickhouses"}:
        scheme = "https" if parsed.scheme == "clickhouses" else "http"
        query = parse_qs(parsed.query)
        query.setdefault("database", [parsed.path.lstrip("/") or "default"])
        return urlunparse((scheme, parsed.netloc, "/", "", urlencode(query, doseq=True), ""))
    return dsn


def _safe_dsn(dsn: str) -> str:
    parsed = urlparse(dsn)
    if parsed.password:
        netloc = parsed.netloc.replace(f":{parsed.password}@", ":***@")
        return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    return dsn
