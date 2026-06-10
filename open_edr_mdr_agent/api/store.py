from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4

from open_edr_mdr_agent.api.models import AgentRecord, TaskRecord
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
                    remote_ip text,
                    domain text,
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
                    alert_json text not null
                );
                create index if not exists idx_alerts_tenant_time on alerts(tenant_id, timestamp);
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
                    error text
                );
                create index if not exists idx_tasks_agent_status on tasks(tenant_id, agent_id, status);
                """
            )

    def create_enrollment_token(self, tenant_id: str = "default", token: Optional[str] = None, max_uses: Optional[int] = None, expires_at: Optional[str] = None) -> str:
        token = token or secrets.token_urlsafe(32)
        with self.connect() as conn:
            conn.execute(
                "insert or replace into enrollment_tokens(token, tenant_id, expires_at, max_uses, uses, revoked, created_at) values (?, ?, ?, ?, 0, 0, ?)",
                (token, tenant_id, expires_at, max_uses, utc_now()),
            )
        return token

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
        for event in events:
            rows.append((event.id, event.tenant_id, agent_id, event.host, event.event_type.value, event.source.value, event.timestamp.isoformat(), event.process_name, event.process_id, event.command_line, event.remote_ip, event.domain, event.model_dump_json()))
        with self.connect() as conn:
            conn.executemany(
                "insert or ignore into events(id, tenant_id, agent_id, host, event_type, source, timestamp, process_name, process_id, command_line, remote_ip, domain, event_json) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def insert_alerts(self, alerts: Iterable[Alert]) -> int:
        rows = []
        for alert in alerts:
            tenant_id = str((alert.raw or {}).get("tenant_id") or "default")
            rows.append((alert.alert_id, tenant_id, alert.title, alert.severity.value, alert.timestamp.isoformat(), alert.host, alert.user, alert.process_name, alert.model_dump_json()))
        with self.connect() as conn:
            conn.executemany(
                "insert or ignore into alerts(alert_id, tenant_id, title, severity, timestamp, host, user, process_name, alert_json) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        with self.connect() as conn:
            conn.execute(
                "update tasks set status=?, completed_at=?, result_json=?, error=? where tenant_id=? and agent_id=? and task_id=?",
                (status, utc_now(), json.dumps(result), error, tenant_id, agent_id, task_id),
            )

    def list_agents(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("select * from agents where tenant_id=? order by host", (tenant_id,)).fetchall()]

    def list_events(
        self,
        tenant_id: str,
        host: Optional[str] = None,
        event_type: Optional[str] = None,
        process_name: Optional[str] = None,
        remote_ip: Optional[str] = None,
        domain: Optional[str] = None,
        indicator: Optional[str] = None,
        limit: int = 100,
    ) -> List[NormalizedEvent]:
        q = "select event_json from events where tenant_id=?"
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
        if remote_ip:
            q += " and remote_ip=?"
            args.append(remote_ip)
        if domain:
            q += " and domain=?"
            args.append(domain)
        if indicator:
            q += " and event_json like ?"
            args.append(f"%{indicator}%")
        q += " order by timestamp desc limit ?"
        args.append(limit)
        with self.connect() as conn:
            return [NormalizedEvent.model_validate_json(r["event_json"]) for r in conn.execute(q, args).fetchall()]

    def list_tasks(self, tenant_id: str, agent_id: Optional[str] = None, limit: int = 100) -> List[TaskRecord]:
        q = "select * from tasks where tenant_id=?"
        args: list[Any] = [tenant_id]
        if agent_id:
            q += " and agent_id=?"
            args.append(agent_id)
        q += " order by created_at desc limit ?"
        args.append(limit)
        with self.connect() as conn:
            return [self._task_record(dict(r)) for r in conn.execute(q, args).fetchall()]

    def list_alerts(self, tenant_id: str, limit: int = 100) -> List[Alert]:
        with self.connect() as conn:
            return [Alert.model_validate_json(r["alert_json"]) for r in conn.execute("select alert_json from alerts where tenant_id=? order by timestamp desc limit ?", (tenant_id, limit)).fetchall()]

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

    def _task_record(self, row: Dict[str, Any]) -> TaskRecord:
        return TaskRecord(
            task_id=row["task_id"], tenant_id=row["tenant_id"], agent_id=row["agent_id"], task_type=row["task_type"],
            args=json.loads(row["args_json"] or "{}"), status=row["status"], created_at=datetime.fromisoformat(row["created_at"]),
            claimed_at=datetime.fromisoformat(row["claimed_at"]) if row.get("claimed_at") else None,
            completed_at=datetime.fromisoformat(row["completed_at"]) if row.get("completed_at") else None,
            result=json.loads(row["result_json"]) if row.get("result_json") else None, error=row.get("error"),
        )
