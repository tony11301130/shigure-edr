import base64
import hashlib
import os

import pytest
from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app
from open_edr_mdr_agent.api.postgres_store import SCHEMA_VERSION

ADMIN = {"Authorization": "Bearer operator-admin-token"}


pytestmark = pytest.mark.skipif(
    not os.environ.get("OPEN_EDR_MDR_TEST_POSTGRES_DSN"),
    reason="OPEN_EDR_MDR_TEST_POSTGRES_DSN is required for PostgreSQL control-plane tests",
)


def _reset_postgres_schema(dsn: str) -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("drop schema if exists public cascade")
        conn.execute("create schema public")


def test_postgresql_control_plane_runs_mdr_workflow_metadata(tmp_path, monkeypatch):
    dsn = os.environ["OPEN_EDR_MDR_TEST_POSTGRES_DSN"]
    _reset_postgres_schema(dsn)
    monkeypatch.setenv("OPEN_EDR_MDR_CONTROL_PLANE_STORE", "postgresql")
    monkeypatch.setenv("OPEN_EDR_MDR_POSTGRES_DSN", dsn)
    monkeypatch.setenv("OPEN_EDR_MDR_RAW_OBJECT_STORE_ROOT", str(tmp_path / "raw-objects"))
    client = TestClient(
        create_app(
            tmp_path / "ignored.sqlite3",
            create_dev_token=False,
            profile="production",
            admin_token="operator-admin-token",
            enrollment_token="tenant-bootstrap-token",
            server_trust="system",
        )
    )

    storage = client.get("/api/v1/admin/storage-profile", headers=ADMIN)
    assert storage.status_code == 200, storage.text
    assert storage.json()["control_plane_store"] == "postgresql"
    assert storage.json()["raw_object_store"]["storage_provider"] == "local"

    alpha_token = client.post("/api/v1/admin/enrollment-tokens", headers=ADMIN, params={"tenant_id": "alpha", "max_uses": 1}).json()["token"]
    beta_token = client.post("/api/v1/admin/enrollment-tokens", headers=ADMIN, params={"tenant_id": "beta", "max_uses": 1}).json()["token"]
    alpha = client.post("/api/v1/enroll", json={"enrollment_token": alpha_token, "host": "PG-ALPHA", "os": "Windows", "agent_version": "dev"}).json()
    beta = client.post("/api/v1/enroll", json={"enrollment_token": beta_token, "host": "PG-BETA", "os": "Windows", "agent_version": "dev"}).json()
    assert alpha["tenant_id"] == "alpha"
    assert beta["tenant_id"] == "beta"

    cross_tenant_task = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={"tenant_id": "beta", "agent_id": alpha["agent_id"], "task_type": "inventory", "args": {}},
    )
    assert cross_tenant_task.status_code == 400
    assert cross_tenant_task.json()["detail"] == "target_agent_tenant_mismatch"

    task = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={"tenant_id": "alpha", "agent_id": alpha["agent_id"], "task_type": "inventory", "args": {}, "requested_by": "analyst@example.test"},
    )
    assert task.status_code == 200, task.text
    agent_headers = {"Authorization": f"Bearer {alpha['agent_token']}"}
    claim = client.post(f"/api/v1/agents/{alpha['agent_id']}/tasks/claim", headers=agent_headers, json={"max_tasks": 1})
    assert claim.status_code == 200, claim.text
    completed = client.post(
        f"/api/v1/agents/{alpha['agent_id']}/tasks/{task.json()['task_id']}/result",
        headers=agent_headers,
        json={"status": "succeeded", "result": {"size": 19, "case_id": "case-pg", "requester": "analyst@example.test"}},
    )
    assert completed.status_code == 200, completed.text

    event = {
        "source": "internal",
        "event_type": "process_start",
        "tenant_id": "client-spoofed",
        "host": "PG-ALPHA",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA",
        "severity": "info",
        "raw": {"source": "postgres-workflow-test"},
    }
    ingest = client.post(f"/api/v1/agents/{alpha['agent_id']}/events", headers=agent_headers, json={"events": [event]})
    assert ingest.status_code == 200, ingest.text
    assert ingest.json()["alerts_generated"] == 1
    alert = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "alpha"}).json()[0]
    case = client.post(
        "/api/v1/admin/cases",
        headers=ADMIN,
        json={"tenant_id": "alpha", "title": "PostgreSQL backed case", "severity": "high", "alert_id": alert["alert_id"]},
    )
    assert case.status_code == 200, case.text

    data = b"postgres object metadata"
    sha = hashlib.sha256(data).hexdigest()
    evidence = client.post(
        f"/api/v1/agents/{alpha['agent_id']}/evidence",
        headers=agent_headers,
        json={
            "kind": "file",
            "path": "C:/Temp/pg.txt",
            "sha256": sha,
            "size": len(data),
            "content_base64": base64.b64encode(data).decode(),
            "metadata": {"reason": "triage", "case_id": case.json()["case_id"], "requester": "analyst@example.test"},
        },
    )
    assert evidence.status_code == 200, evidence.text

    raw_list = client.get("/api/v1/admin/raw-evidence/list", headers=ADMIN, params={"tenant_id": "alpha"})
    assert raw_list.status_code == 200, raw_list.text
    raw_items = raw_list.json()["evidence"]
    assert raw_items
    assert all("payload" not in item for item in raw_items)
    assert {item["storage_provider"] for item in raw_items} == {"local"}
    assert any(item["raw_ref"] == evidence.json()["raw_ref"] and item["sha256"] == sha for item in raw_items)

    beta_agents = client.get("/api/v1/admin/agents", headers=ADMIN, params={"tenant_id": "beta"}).json()["agents"]
    assert [agent["agent_id"] for agent in beta_agents] == [beta["agent_id"]]

    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as conn:
        migration = conn.execute("select version from schema_migrations where version = %s", (SCHEMA_VERSION,)).fetchone()
        metadata = conn.execute(
            "select payload_json, storage_provider, object_key, size from raw_evidence where raw_ref = %s",
            (evidence.json()["raw_ref"],),
        ).fetchone()
        tenants = conn.execute("select tenant_id from agents order by tenant_id").fetchall()
        tenant_rows = conn.execute("select tenant_id from tenants order by tenant_id").fetchall()
    assert migration == {"version": SCHEMA_VERSION}
    assert metadata["payload_json"] == ""
    assert metadata["storage_provider"] == "local"
    assert metadata["object_key"].startswith("alpha/agent_file/")
    assert metadata["size"] == len(data)
    assert [row["tenant_id"] for row in tenants] == ["alpha", "beta"]
    assert [row["tenant_id"] for row in tenant_rows] == ["alpha", "beta"]
