from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4

from open_edr_mdr_agent.api.cases import CaseEvidenceRecord, CaseRecord
from open_edr_mdr_agent.api.hunts import HuntRecord, HuntRunRecord
from open_edr_mdr_agent.api.models import AgentConfig, AgentRecord, TaskRecord
from open_edr_mdr_agent.core.schemas import Alert, NormalizedEvent


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SQLiteStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                create table if not exists enrollment_tokens (
                    token text primary key,
                    tenant_id text not null,
                    expires_at text,
                    max_uses integer,
                    uses integer not null default 0,
                    revoked integer not null default 0,
                    created_at text not null
                );
                create table if not exists agents (
                    agent_id text primary key,
                    tenant_id text not null,
                    agent_token text not null,
                    public_key text,
                    host text not null,
                    ip_address text,
                    os text,
                    agent_version text,
                    status text not null,
                    enrolled_at text not null,
                    last_seen text,
                    metadata_json text not null default '{}'
                );
                create index if not exists idx_agents_tenant on agents(tenant_id);
                create table if not exists raw_evidence (
                    raw_ref text primary key,
                    tenant_id text not null,
                    kind text not null,
                    sha256 text not null,
                    payload_json text not null,
                    created_at text not null
                );
                create index if not exists idx_raw_evidence_tenant on raw_evidence(tenant_id, created_at);
                create table if not exists events (
                    id text primary key,
                    tenant_id text not null,
                    agent_id text,
                    host text,
                    event_type text not null,
                    source text not null,
                    timestamp text not null,
                    process_name text,
                    process_id text,
                    command_line text,
                    user text,
                    hash_sha256 text,
                    remote_ip text,
                    domain text,
                    raw_ref text,
                    raw_hash text,
                    event_json text not null
                );
                create index if not exists idx_events_tenant_time on events(tenant_id, timestamp);
                create index if not exists idx_events_host on events(tenant_id, host);
                create table if not exists alerts (
                    alert_id text primary key,
                    tenant_id text not null,
                    title text not null,
                    severity text not null,
                    timestamp text not null,
                    host text,
                    user text,
                    process_name text,
                    raw_ref text,
                    raw_hash text,
                    alert_json text not null
                );
                create index if not exists idx_alerts_tenant_time on alerts(tenant_id, timestamp);
                create table if not exists cases (
                    case_id text primary key,
                    tenant_id text not null,
                    title text not null,
                    severity text not null,
                    status text not null,
                    alert_id text,
                    assignee text,
                    description text,
                    summary text,
                    created_at text not null,
                    updated_at text not null
                );
                create index if not exists idx_cases_tenant_status on cases(tenant_id, status, updated_at);
                create table if not exists case_evidence (
                    evidence_id text primary key,
                    case_id text not null,
                    tenant_id text not null,
                    evidence_type text not null,
                    ref_id text not null,
                    summary text,
                    data_json text not null,
                    created_at text not null
                );
                create index if not exists idx_case_evidence_case on case_evidence(tenant_id, case_id, created_at);
                create table if not exists hunts (
                    hunt_id text primary key,
                    tenant_id text not null,
                    name text not null,
                    description text,
                    indicator text,
                    query_json text not null,
                    enabled integer not null,
                    created_at text not null,
                    updated_at text not null
                );
                create index if not exists idx_hunts_tenant on hunts(tenant_id, enabled, updated_at);
                create table if not exists hunt_runs (
                    run_id text primary key,
                    hunt_id text not null,
                    tenant_id text not null,
                    status text not null,
                    result_json text not null,
                    created_at text not null
                );
                create index if not exists idx_hunt_runs_tenant on hunt_runs(tenant_id, hunt_id, created_at);
                create table if not exists tenant_configs (
                    tenant_id text primary key,
                    version integer not null,
                    config_json text not null,
                    updated_at text not null
                );
                create table if not exists tasks (
                    task_id text primary key,
                    tenant_id text not null,
                    agent_id text not null,
                    task_type text not null,
                    args_json text not null,
                    status text not null,
                    created_at text not null,
                    claimed_at text,
                    completed_at text,
                    timeout_seconds integer not null,
                    result_json text,
                    error text,
                    raw_ref text,
                    raw_hash text
                );
                create index if not exists idx_tasks_agent_status on tasks(tenant_id, agent_id, status);
                """
            )
            self._ensure_column(conn, "events", "user", "text")
            self._ensure_column(conn, "events", "hash_sha256", "text")
            self._ensure_column(conn, "events", "raw_ref", "text")
            self._ensure_column(conn, "events", "raw_hash", "text")
            self._ensure_column(conn, "alerts", "raw_ref", "text")
            self._ensure_column(conn, "alerts", "raw_hash", "text")
            self._ensure_column(conn, "tasks", "raw_ref", "text")
            self._ensure_column(conn, "tasks", "raw_hash", "text")

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, ddl_type: str) -> None:
        cols = {row["name"] for row in conn.execute(f"pragma table_info({table})").fetchall()}
        if column not in cols:
            conn.execute(f"alter table {table} add column {column} {ddl_type}")

    def get_agent_config(self, tenant_id: str = "default") -> AgentConfig:
        with self.connect() as conn:
            row = conn.execute("select config_json from tenant_configs where tenant_id=?", (tenant_id,)).fetchone()
        if not row:
            return AgentConfig()
        return AgentConfig.model_validate_json(row["config_json"])

    def set_agent_config(self, tenant_id: str, config: AgentConfig) -> AgentConfig:
        current = self.get_agent_config(tenant_id)
        config.features = {"collector_gates_explicit": True, **(config.features or {})}
        if config.version <= current.version:
            config.version = current.version + 1
        with self.connect() as conn:
            conn.execute(
                "insert or replace into tenant_configs(tenant_id, version, config_json, updated_at) values (?, ?, ?, ?)",
                (tenant_id, config.version, config.model_dump_json(), utc_now()),
            )
        return config

    def create_enrollment_token(self, tenant_id: str = "default", token: Optional[str] = None, max_uses: Optional[int] = None, expires_at: Optional[str] = None) -> str:
        token = token or secrets.token_urlsafe(32)
        with self.connect() as conn:
            conn.execute(
                "insert or replace into enrollment_tokens(token, tenant_id, expires_at, max_uses, uses, revoked, created_at) values (?, ?, ?, ?, 0, 0, ?)",
                (token, tenant_id, expires_at, max_uses, utc_now()),
            )
        return token

    def list_enrollment_tokens(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("select tenant_id, token, expires_at, max_uses, uses, revoked, created_at from enrollment_tokens where tenant_id=? order by created_at desc", (tenant_id,)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            token = item.pop("token")
            item["token_prefix"] = f"{token[:6]}..."
            item["revoked"] = bool(item["revoked"])
            result.append(item)
        return result

    def enroll_agent(self, *, enrollment_token: str, host: str, public_key: Optional[str], ip_address: Optional[str], os: Optional[str], agent_version: str, metadata: Dict[str, Any]) -> Dict[str, str]:
        now = utc_now()
        with self.connect() as conn:
            token = conn.execute("select * from enrollment_tokens where token = ?", (enrollment_token,)).fetchone()
            if not token or token["revoked"]:
                raise ValueError("invalid_or_revoked_enrollment_token")
            if token["expires_at"] and token["expires_at"] < now:
                raise ValueError("expired_enrollment_token")
            if token["max_uses"] is not None and token["uses"] >= token["max_uses"]:
                raise ValueError("enrollment_token_use_limit_reached")
            agent_id = str(uuid4())
            agent_token = secrets.token_urlsafe(32)
            conn.execute("update enrollment_tokens set uses = uses + 1 where token = ?", (enrollment_token,))
            conn.execute(
                "insert into agents(agent_id, tenant_id, agent_token, public_key, host, ip_address, os, agent_version, status, enrolled_at, last_seen, metadata_json) values (?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?)",
                (agent_id, token["tenant_id"], agent_token, public_key, host, ip_address, os, agent_version, now, now, json.dumps(metadata)),
            )
        return {"tenant_id": token["tenant_id"], "agent_id": agent_id, "agent_token": agent_token}

    def authenticate_agent(self, agent_id: str, agent_token: str) -> Optional[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("select * from agents where agent_id = ? and agent_token = ?", (agent_id, agent_token)).fetchone()

    def update_heartbeat(self, agent_id: str, host: str, ip_address: Optional[str], os: Optional[str], agent_version: str, health: Dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                "update agents set host=?, ip_address=?, os=?, agent_version=?, status='online', last_seen=?, metadata_json=? where agent_id=?",
                (host, ip_address, os, agent_version, utc_now(), json.dumps({"health": health}), agent_id),
            )

    def insert_events(self, agent_id: str, events: Iterable[NormalizedEvent]) -> int:
        rows = []
        raw_rows = []
        now_dt = datetime.now(timezone.utc)
        for event in events:
            event.ingested_at = event.ingested_at or now_dt
            raw_ref, raw_hash, payload = self._raw_evidence_values(event.tenant_id, "event", event.id, event.raw)
            event.raw_ref = event.raw_ref or raw_ref
            event.raw_hash = event.raw_hash or raw_hash
            raw_rows.append((event.raw_ref, event.tenant_id, "event", event.raw_hash, payload, utc_now()))
            rows.append((event.id, event.tenant_id, agent_id, event.host, event.event_type.value, event.source.value, event.timestamp.isoformat(), event.process_name, event.process_id, event.command_line, event.user, event.hash_sha256, event.remote_ip, event.domain, event.raw_ref, event.raw_hash, event.model_dump_json()))
        with self.connect() as conn:
            conn.executemany(
                "insert or ignore into raw_evidence(raw_ref, tenant_id, kind, sha256, payload_json, created_at) values (?, ?, ?, ?, ?, ?)",
                raw_rows,
            )
            conn.executemany(
                "insert or ignore into events(id, tenant_id, agent_id, host, event_type, source, timestamp, process_name, process_id, command_line, user, hash_sha256, remote_ip, domain, raw_ref, raw_hash, event_json) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def insert_alerts(self, alerts: Iterable[Alert]) -> int:
        rows = []
        raw_rows = []
        now_dt = datetime.now(timezone.utc)
        for alert in alerts:
            tenant_id = str((alert.raw or {}).get("tenant_id") or "default")
            alert.created_at = alert.created_at or now_dt
            raw_ref, raw_hash, payload = self._raw_evidence_values(tenant_id, "alert", alert.alert_id, alert.raw)
            alert.raw_ref = alert.raw_ref or raw_ref
            alert.raw_hash = alert.raw_hash or raw_hash
            raw_rows.append((alert.raw_ref, tenant_id, "alert", alert.raw_hash, payload, utc_now()))
            rows.append((alert.alert_id, tenant_id, alert.title, alert.severity.value, alert.timestamp.isoformat(), alert.host, alert.user, alert.process_name, alert.raw_ref, alert.raw_hash, alert.model_dump_json()))
        with self.connect() as conn:
            conn.executemany(
                "insert or ignore into raw_evidence(raw_ref, tenant_id, kind, sha256, payload_json, created_at) values (?, ?, ?, ?, ?, ?)",
                raw_rows,
            )
            conn.executemany(
                "insert or ignore into alerts(alert_id, tenant_id, title, severity, timestamp, host, user, process_name, raw_ref, raw_hash, alert_json) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def create_task(self, tenant_id: str, agent_id: str, task_type: str, args: Dict[str, Any], timeout_seconds: int) -> str:
        task_id = str(uuid4())
        with self.connect() as conn:
            agent = conn.execute("select tenant_id from agents where agent_id=?", (agent_id,)).fetchone()
            if not agent:
                raise ValueError("target_agent_not_found")
            if agent["tenant_id"] != tenant_id:
                raise ValueError("target_agent_tenant_mismatch")
            conn.execute(
                "insert into tasks(task_id, tenant_id, agent_id, task_type, args_json, status, created_at, timeout_seconds) values (?, ?, ?, ?, ?, 'queued', ?, ?)",
                (task_id, tenant_id, agent_id, task_type, json.dumps(args), utc_now(), timeout_seconds),
            )
        return task_id

    def claim_tasks(self, tenant_id: str, agent_id: str, max_tasks: int = 1) -> List[TaskRecord]:
        now = utc_now()
        with self.connect() as conn:
            rows = conn.execute(
                "select * from tasks where tenant_id=? and agent_id=? and status='queued' order by created_at limit ?",
                (tenant_id, agent_id, max_tasks),
            ).fetchall()
            for row in rows:
                conn.execute("update tasks set status='claimed', claimed_at=? where task_id=?", (now, row["task_id"]))
        return [self._task_record({**dict(r), "status": "claimed", "claimed_at": now}) for r in rows]

    def complete_task(self, tenant_id: str, agent_id: str, task_id: str, status: str, result: Dict[str, Any], error: Optional[str]) -> None:
        raw_payload = {"task_id": task_id, "agent_id": agent_id, "status": status, "result": result, "error": error}
        raw_ref, raw_hash, payload_json = self._raw_evidence_values(tenant_id, "task_result", task_id, raw_payload)
        with self.connect() as conn:
            conn.execute(
                "insert or ignore into raw_evidence(raw_ref, tenant_id, kind, sha256, payload_json, created_at) values (?, ?, ?, ?, ?, ?)",
                (raw_ref, tenant_id, "task_result", raw_hash, payload_json, utc_now()),
            )
            conn.execute(
                "update tasks set status=?, completed_at=?, result_json=?, error=?, raw_ref=?, raw_hash=? where tenant_id=? and agent_id=? and task_id=?",
                (status, utc_now(), json.dumps(result), error, raw_ref, raw_hash, tenant_id, agent_id, task_id),
            )

    def expire_stale_tasks(self, tenant_id: str) -> int:
        now = datetime.now(timezone.utc)
        expired: list[str] = []
        with self.connect() as conn:
            rows = conn.execute("select task_id, claimed_at, timeout_seconds from tasks where tenant_id=? and status='claimed'", (tenant_id,)).fetchall()
            for row in rows:
                if not row["claimed_at"]:
                    continue
                claimed_at = datetime.fromisoformat(row["claimed_at"].replace("Z", "+00:00"))
                if (now - claimed_at).total_seconds() >= int(row["timeout_seconds"]):
                    expired.append(row["task_id"])
            if expired:
                conn.executemany(
                    "update tasks set status='timed_out', completed_at=?, error='task_claim_timeout' where tenant_id=? and task_id=?",
                    [(utc_now(), tenant_id, task_id) for task_id in expired],
                )
        return len(expired)

    def list_agents(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("select * from agents where tenant_id=? order by host", (tenant_id,)).fetchall()]

    def get_agent(self, tenant_id: str, agent_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute("select * from agents where tenant_id=? and agent_id=?", (tenant_id, agent_id)).fetchone()
        return dict(row) if row else None

    def tenant_summary(self, tenant_id: str) -> Dict[str, Any]:
        with self.connect() as conn:
            agent_status = {r["status"]: r["count"] for r in conn.execute("select status, count(*) count from agents where tenant_id=? group by status", (tenant_id,)).fetchall()}
            task_status = {r["status"]: r["count"] for r in conn.execute("select status, count(*) count from tasks where tenant_id=? group by status", (tenant_id,)).fetchall()}
            case_status = {r["status"]: r["count"] for r in conn.execute("select status, count(*) count from cases where tenant_id=? group by status", (tenant_id,)).fetchall()}
            severity_counts = {r["severity"]: r["count"] for r in conn.execute("select severity, count(*) count from alerts where tenant_id=? group by severity", (tenant_id,)).fetchall()}
            counts = {
                "agents": conn.execute("select count(*) count from agents where tenant_id=?", (tenant_id,)).fetchone()["count"],
                "events": conn.execute("select count(*) count from events where tenant_id=?", (tenant_id,)).fetchone()["count"],
                "alerts": conn.execute("select count(*) count from alerts where tenant_id=?", (tenant_id,)).fetchone()["count"],
                "cases": conn.execute("select count(*) count from cases where tenant_id=?", (tenant_id,)).fetchone()["count"],
                "tasks": conn.execute("select count(*) count from tasks where tenant_id=?", (tenant_id,)).fetchone()["count"],
                "raw_evidence": conn.execute("select count(*) count from raw_evidence where tenant_id=?", (tenant_id,)).fetchone()["count"],
            }
        return {"tenant_id": tenant_id, "counts": counts, "agent_status": agent_status, "task_status": task_status, "case_status": case_status, "alert_severity": severity_counts}

    def get_event(self, tenant_id: str, event_id: str) -> Optional[NormalizedEvent]:
        with self.connect() as conn:
            row = conn.execute("select event_json from events where tenant_id=? and id=?", (tenant_id, event_id)).fetchone()
        return NormalizedEvent.model_validate_json(row["event_json"]) if row else None

    def get_alert(self, tenant_id: str, alert_id: str) -> Optional[Alert]:
        with self.connect() as conn:
            row = conn.execute("select alert_json from alerts where tenant_id=? and alert_id=?", (tenant_id, alert_id)).fetchone()
        return Alert.model_validate_json(row["alert_json"]) if row else None

    def count_events(
        self,
        tenant_id: str,
        host: Optional[str] = None,
        event_type: Optional[str] = None,
        process_name: Optional[str] = None,
        user: Optional[str] = None,
        hash_sha256: Optional[str] = None,
        remote_ip: Optional[str] = None,
        domain: Optional[str] = None,
        indicator: Optional[str] = None,
    ) -> int:
        q, args = self._event_query("count(*) count", tenant_id, host=host, event_type=event_type, process_name=process_name, user=user, hash_sha256=hash_sha256, remote_ip=remote_ip, domain=domain, indicator=indicator)
        with self.connect() as conn:
            return int(conn.execute(q, args).fetchone()["count"])

    def related_events(self, tenant_id: str, entity_type: str, value: str, limit: int = 100) -> List[NormalizedEvent]:
        field_map = {
            "host": "host",
            "process_id": "process_id",
            "parent_process_id": "process_id",
            "process_name": "process_name",
            "user": "user",
            "hash_sha256": "hash_sha256",
            "remote_ip": "remote_ip",
            "domain": "domain",
            "command_line": "command_line",
        }
        field = field_map.get(entity_type)
        if not field:
            return []
        if field in {"process_name", "command_line", "user"}:
            q = f"select event_json from events where tenant_id=? and {field} like ? order by timestamp desc limit ?"
            args: list[Any] = [tenant_id, f"%{value}%", limit]
        else:
            q = f"select event_json from events where tenant_id=? and {field}=? order by timestamp desc limit ?"
            args = [tenant_id, value, limit]
        with self.connect() as conn:
            return [NormalizedEvent.model_validate_json(r["event_json"]) for r in conn.execute(q, args).fetchall()]

    def list_events(
        self,
        tenant_id: str,
        host: Optional[str] = None,
        event_type: Optional[str] = None,
        process_name: Optional[str] = None,
        user: Optional[str] = None,
        hash_sha256: Optional[str] = None,
        remote_ip: Optional[str] = None,
        domain: Optional[str] = None,
        indicator: Optional[str] = None,
        limit: int = 100,
    ) -> List[NormalizedEvent]:
        q, args = self._event_query("event_json", tenant_id, host=host, event_type=event_type, process_name=process_name, user=user, hash_sha256=hash_sha256, remote_ip=remote_ip, domain=domain, indicator=indicator)
        q += " order by timestamp desc limit ?"
        args.append(limit)
        with self.connect() as conn:
            return [NormalizedEvent.model_validate_json(r["event_json"]) for r in conn.execute(q, args).fetchall()]

    def create_case(self, tenant_id: str, title: str, severity: str, alert_id: Optional[str] = None, description: Optional[str] = None) -> CaseRecord:
        case_id = str(uuid4())
        now = utc_now()
        with self.connect() as conn:
            alert = None
            if alert_id:
                alert = conn.execute("select alert_id, raw_ref, raw_hash, alert_json from alerts where tenant_id=? and alert_id=?", (tenant_id, alert_id)).fetchone()
                if not alert:
                    raise ValueError("alert_not_found_in_tenant")
            conn.execute(
                "insert into cases(case_id, tenant_id, title, severity, status, alert_id, description, created_at, updated_at) values (?, ?, ?, ?, 'open', ?, ?, ?, ?)",
                (case_id, tenant_id, title, severity, alert_id, description, now, now),
            )
            if alert:
                conn.execute(
                    "insert into case_evidence(evidence_id, case_id, tenant_id, evidence_type, ref_id, summary, data_json, created_at) values (?, ?, ?, ?, ?, ?, ?, ?)",
                    (str(uuid4()), case_id, tenant_id, "alert", alert["alert_id"], "Source alert", json.dumps({"raw_ref": alert["raw_ref"], "raw_hash": alert["raw_hash"]}), now),
                )
                if alert["raw_ref"]:
                    conn.execute(
                        "insert into case_evidence(evidence_id, case_id, tenant_id, evidence_type, ref_id, summary, data_json, created_at) values (?, ?, ?, ?, ?, ?, ?, ?)",
                        (str(uuid4()), case_id, tenant_id, "raw_evidence", alert["raw_ref"], "Source alert raw evidence", json.dumps({"kind": "alert", "sha256": alert["raw_hash"]}), now),
                    )
            row = conn.execute("select * from cases where case_id=?", (case_id,)).fetchone()
        return self._case_record(dict(row))

    def create_hunt(self, tenant_id: str, name: str, description: Optional[str], indicator: Optional[str], query: Dict[str, Any], enabled: bool = True) -> HuntRecord:
        hunt_id = str(uuid4())
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "insert into hunts(hunt_id, tenant_id, name, description, indicator, query_json, enabled, created_at, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (hunt_id, tenant_id, name, description, indicator, json.dumps(query or {}), 1 if enabled else 0, now, now),
            )
            row = conn.execute("select * from hunts where hunt_id=?", (hunt_id,)).fetchone()
        return self._hunt_record(dict(row))

    def list_hunts(self, tenant_id: str, enabled: Optional[bool] = None, limit: int = 100) -> List[HuntRecord]:
        q = "select * from hunts where tenant_id=?"
        args: list[Any] = [tenant_id]
        if enabled is not None:
            q += " and enabled=?"
            args.append(1 if enabled else 0)
        q += " order by updated_at desc limit ?"
        args.append(limit)
        with self.connect() as conn:
            return [self._hunt_record(dict(r)) for r in conn.execute(q, args).fetchall()]

    def get_hunt(self, tenant_id: str, hunt_id: str) -> Optional[HuntRecord]:
        with self.connect() as conn:
            row = conn.execute("select * from hunts where tenant_id=? and hunt_id=?", (tenant_id, hunt_id)).fetchone()
        return self._hunt_record(dict(row)) if row else None

    def update_hunt(
        self,
        tenant_id: str,
        hunt_id: str,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        indicator: Optional[str] = None,
        query: Optional[Dict[str, Any]] = None,
        enabled: Optional[bool] = None,
    ) -> Optional[HuntRecord]:
        current = self.get_hunt(tenant_id, hunt_id)
        if not current:
            return None
        next_indicator = current.indicator if indicator is None else indicator
        next_query = current.query if query is None else query
        if not next_indicator and not next_query:
            raise ValueError("indicator_or_query_required")
        with self.connect() as conn:
            conn.execute(
                """
                update hunts
                set name=coalesce(?, name),
                    description=coalesce(?, description),
                    indicator=?,
                    query_json=?,
                    enabled=coalesce(?, enabled),
                    updated_at=?
                where tenant_id=? and hunt_id=?
                """,
                (name, description, next_indicator, json.dumps(next_query or {}), None if enabled is None else (1 if enabled else 0), utc_now(), tenant_id, hunt_id),
            )
            row = conn.execute("select * from hunts where tenant_id=? and hunt_id=?", (tenant_id, hunt_id)).fetchone()
        return self._hunt_record(dict(row))

    def record_hunt_run(self, tenant_id: str, hunt_id: str, status: str, result: Dict[str, Any]) -> HuntRunRecord:
        run_id = str(uuid4())
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "insert into hunt_runs(run_id, hunt_id, tenant_id, status, result_json, created_at) values (?, ?, ?, ?, ?, ?)",
                (run_id, hunt_id, tenant_id, status, json.dumps(result, default=str), now),
            )
            row = conn.execute("select * from hunt_runs where run_id=?", (run_id,)).fetchone()
        return self._hunt_run_record(dict(row))

    def list_hunt_runs(self, tenant_id: str, hunt_id: Optional[str] = None, limit: int = 100) -> List[HuntRunRecord]:
        q = "select * from hunt_runs where tenant_id=?"
        args: list[Any] = [tenant_id]
        if hunt_id:
            q += " and hunt_id=?"
            args.append(hunt_id)
        q += " order by created_at desc limit ?"
        args.append(limit)
        with self.connect() as conn:
            return [self._hunt_run_record(dict(r)) for r in conn.execute(q, args).fetchall()]

    def list_cases(self, tenant_id: str, status: Optional[str] = None, severity: Optional[str] = None, assignee: Optional[str] = None, limit: int = 100) -> List[CaseRecord]:
        q = "select * from cases where tenant_id=?"
        args: list[Any] = [tenant_id]
        if status:
            q += " and status=?"
            args.append(status)
        if severity:
            q += " and severity=?"
            args.append(severity)
        if assignee:
            q += " and assignee=?"
            args.append(assignee)
        q += " order by updated_at desc limit ?"
        args.append(limit)
        with self.connect() as conn:
            return [self._case_record(dict(r)) for r in conn.execute(q, args).fetchall()]

    def get_case(self, tenant_id: str, case_id: str) -> Optional[CaseRecord]:
        with self.connect() as conn:
            row = conn.execute("select * from cases where tenant_id=? and case_id=?", (tenant_id, case_id)).fetchone()
        return self._case_record(dict(row)) if row else None

    def update_case(self, tenant_id: str, case_id: str, status: Optional[str] = None, assignee: Optional[str] = None, summary: Optional[str] = None) -> Optional[CaseRecord]:
        current = self.get_case(tenant_id, case_id)
        if not current:
            return None
        with self.connect() as conn:
            conn.execute(
                "update cases set status=coalesce(?, status), assignee=coalesce(?, assignee), summary=coalesce(?, summary), updated_at=? where tenant_id=? and case_id=?",
                (status, assignee, summary, utc_now(), tenant_id, case_id),
            )
            row = conn.execute("select * from cases where tenant_id=? and case_id=?", (tenant_id, case_id)).fetchone()
        return self._case_record(dict(row))

    def add_case_evidence(self, tenant_id: str, case_id: str, evidence_type: str, ref_id: str, summary: Optional[str], data: Dict[str, Any]) -> CaseEvidenceRecord:
        if not self.get_case(tenant_id, case_id):
            raise ValueError("case_not_found_in_tenant")
        evidence_id = str(uuid4())
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "insert into case_evidence(evidence_id, case_id, tenant_id, evidence_type, ref_id, summary, data_json, created_at) values (?, ?, ?, ?, ?, ?, ?, ?)",
                (evidence_id, case_id, tenant_id, evidence_type, ref_id, summary, json.dumps(data), now),
            )
            row = conn.execute("select * from case_evidence where evidence_id=?", (evidence_id,)).fetchone()
        return self._case_evidence_record(dict(row))

    def list_case_evidence(self, tenant_id: str, case_id: str) -> List[CaseEvidenceRecord]:
        with self.connect() as conn:
            return [self._case_evidence_record(dict(r)) for r in conn.execute("select * from case_evidence where tenant_id=? and case_id=? order by created_at", (tenant_id, case_id)).fetchall()]

    def get_raw_evidence(self, tenant_id: str, raw_ref: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute("select * from raw_evidence where tenant_id=? and raw_ref=?", (tenant_id, raw_ref)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["payload"] = json.loads(data.pop("payload_json"))
        return data

    def list_raw_evidence(self, tenant_id: str, kind: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        q = "select raw_ref, tenant_id, kind, sha256, created_at from raw_evidence where tenant_id=?"
        args: list[Any] = [tenant_id]
        if kind:
            q += " and kind=?"
            args.append(kind)
        q += " order by created_at desc limit ?"
        args.append(limit)
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(q, args).fetchall()]

    def list_tasks(self, tenant_id: str, agent_id: Optional[str] = None, status: Optional[str] = None, limit: int = 100) -> List[TaskRecord]:
        q = "select * from tasks where tenant_id=?"
        args: list[Any] = [tenant_id]
        if agent_id:
            q += " and agent_id=?"
            args.append(agent_id)
        if status:
            q += " and status=?"
            args.append(status)
        q += " order by created_at desc limit ?"
        args.append(limit)
        with self.connect() as conn:
            return [self._task_record(dict(r)) for r in conn.execute(q, args).fetchall()]

    def get_task(self, tenant_id: str, task_id: str) -> Optional[TaskRecord]:
        with self.connect() as conn:
            row = conn.execute("select * from tasks where tenant_id=? and task_id=?", (tenant_id, task_id)).fetchone()
        return self._task_record(dict(row)) if row else None

    def list_alerts(self, tenant_id: str, limit: int = 100, severity: Optional[str] = None, host: Optional[str] = None) -> List[Alert]:
        q = "select alert_json from alerts where tenant_id=?"
        args: list[Any] = [tenant_id]
        if severity:
            q += " and severity=?"
            args.append(severity)
        if host:
            q += " and host=?"
            args.append(host)
        q += " order by timestamp desc limit ?"
        args.append(limit)
        with self.connect() as conn:
            return [Alert.model_validate_json(r["alert_json"]) for r in conn.execute(q, args).fetchall()]

    def stale_agents(self, stale_before_iso: str, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        q = "select * from agents where last_seen < ?"
        args: list[Any] = [stale_before_iso]
        if tenant_id:
            q += " and tenant_id=?"
            args.append(tenant_id)
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(q, args).fetchall()]

    def pending_tasks_count(self, tenant_id: str, agent_id: str) -> int:
        with self.connect() as conn:
            row = conn.execute("select count(*) c from tasks where tenant_id=? and agent_id=? and status='queued'", (tenant_id, agent_id)).fetchone()
            return int(row["c"])

    def _event_query(self, select: str, tenant_id: str, host: Optional[str] = None, event_type: Optional[str] = None, process_name: Optional[str] = None, user: Optional[str] = None, hash_sha256: Optional[str] = None, remote_ip: Optional[str] = None, domain: Optional[str] = None, indicator: Optional[str] = None) -> tuple[str, list[Any]]:
        q = f"select {select} from events where tenant_id=?"
        args: list[Any] = [tenant_id]
        if host:
            q += " and host=?"
            args.append(host)
        if event_type:
            q += " and event_type=?"
            args.append(event_type)
        if process_name:
            q += " and process_name like ?"
            args.append(f"%{process_name}%")
        if user:
            q += " and user like ?"
            args.append(f"%{user}%")
        if hash_sha256:
            q += " and hash_sha256=?"
            args.append(hash_sha256)
        if remote_ip:
            q += " and remote_ip=?"
            args.append(remote_ip)
        if domain:
            q += " and domain=?"
            args.append(domain)
        if indicator:
            q += " and event_json like ?"
            args.append(f"%{indicator}%")
        return q, args

    def _hunt_record(self, row: Dict[str, Any]) -> HuntRecord:
        return HuntRecord(
            hunt_id=row["hunt_id"], tenant_id=row["tenant_id"], name=row["name"], description=row.get("description"),
            indicator=row.get("indicator"), query=json.loads(row["query_json"] or "{}"), enabled=bool(row["enabled"]),
            created_at=datetime.fromisoformat(row["created_at"]), updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def _hunt_run_record(self, row: Dict[str, Any]) -> HuntRunRecord:
        return HuntRunRecord(
            run_id=row["run_id"], hunt_id=row["hunt_id"], tenant_id=row["tenant_id"], status=row["status"],
            result=json.loads(row["result_json"] or "{}"), created_at=datetime.fromisoformat(row["created_at"]),
        )

    def _case_record(self, row: Dict[str, Any]) -> CaseRecord:
        return CaseRecord(
            case_id=row["case_id"], tenant_id=row["tenant_id"], title=row["title"], severity=row["severity"], status=row["status"],
            alert_id=row.get("alert_id"), assignee=row.get("assignee"), description=row.get("description"), summary=row.get("summary"),
            created_at=datetime.fromisoformat(row["created_at"]), updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def _case_evidence_record(self, row: Dict[str, Any]) -> CaseEvidenceRecord:
        return CaseEvidenceRecord(
            evidence_id=row["evidence_id"], case_id=row["case_id"], tenant_id=row["tenant_id"], evidence_type=row["evidence_type"], ref_id=row["ref_id"],
            summary=row.get("summary"), data=json.loads(row["data_json"] or "{}"), created_at=datetime.fromisoformat(row["created_at"]),
        )

    def _raw_evidence_values(self, tenant_id: str, kind: str, object_id: str, payload: Dict[str, Any]) -> tuple[str, str, str]:
        payload_json = json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), default=str)
        raw_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        safe_object_id = str(object_id).replace("/", "_").replace(":", "_")
        raw_ref = f"sqlite://raw_evidence/{tenant_id}/{kind}/{safe_object_id}/{raw_hash[:16]}"
        return raw_ref, raw_hash, payload_json

    def _task_record(self, row: Dict[str, Any]) -> TaskRecord:
        return TaskRecord(
            task_id=row["task_id"], tenant_id=row["tenant_id"], agent_id=row["agent_id"], task_type=row["task_type"],
            args=json.loads(row["args_json"] or "{}"), status=row["status"], created_at=datetime.fromisoformat(row["created_at"]),
            claimed_at=datetime.fromisoformat(row["claimed_at"]) if row.get("claimed_at") else None,
            completed_at=datetime.fromisoformat(row["completed_at"]) if row.get("completed_at") else None,
            result=json.loads(row["result_json"]) if row.get("result_json") else None, error=row.get("error"), raw_ref=row.get("raw_ref"), raw_hash=row.get("raw_hash"),
        )
