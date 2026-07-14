import base64
import hashlib

from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def _enroll(client: TestClient, host: str = "CRED01", token: str = "dev-token") -> dict:
    res = client.post(
        "/api/v1/enroll",
        json={"enrollment_token": token, "host": host, "os": "Windows", "agent_version": "dev"},
    )
    assert res.status_code == 200, res.text
    return res.json()


def _agent_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_revoked_agent_credential_cannot_use_agent_operations(tmp_path):
    client = TestClient(create_app(tmp_path / "agent-credential-revoke.sqlite3", create_dev_token=True))
    auth = _enroll(client)
    agent_id = auth["agent_id"]
    agent_token = auth["agent_token"]

    revoked = client.post(
        f"/api/v1/admin/agents/{agent_id}/credential/revoke",
        headers=ADMIN,
        params={"tenant_id": "default", "reason": "compromised"},
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"

    headers = _agent_headers(agent_token)
    heartbeat = client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers=headers,
        json={"host": "CRED01", "os": "Windows", "agent_version": "dev"},
    )
    assert heartbeat.status_code == 401

    events = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events": []})
    assert events.status_code == 401

    tasks = client.post(f"/api/v1/agents/{agent_id}/tasks/claim", headers=headers, json={"max_tasks": 1})
    assert tasks.status_code == 401

    payload = b"credential revoked"
    evidence = client.post(
        f"/api/v1/agents/{agent_id}/evidence",
        headers=headers,
        json={
            "kind": "file",
            "path": "C:/Temp/revoked.txt",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "content_base64": base64.b64encode(payload).decode(),
            "metadata": {},
        },
    )
    assert evidence.status_code == 401

    fetched = client.get(f"/api/v1/admin/agents/{agent_id}", headers=ADMIN, params={"tenant_id": "default"})
    assert fetched.status_code == 200, fetched.text
    body = fetched.json()
    assert body["status"] == "revoked"
    assert body["credential_status"] == "revoked"
    assert body["credential_version"] == 1
    assert "agent_token" not in body

    events = client.get(
        f"/api/v1/admin/agents/{agent_id}/credential/events",
        headers=ADMIN,
        params={"tenant_id": "default"},
    )
    assert events.status_code == 200, events.text
    assert [event["event_type"] for event in events.json()["events"]] == ["enrolled", "revoked"]
    assert events.json()["events"][-1]["metadata"]["reason"] == "compromised"


def test_enrollment_token_cannot_authenticate_agent_operations(tmp_path):
    client = TestClient(create_app(tmp_path / "enrollment-token-bootstrap-only.sqlite3", create_dev_token=True))
    auth = _enroll(client, host="BOOTSTRAP01")
    agent_id = auth["agent_id"]
    assert auth["credential_version"] == 1

    enrollment_headers = _agent_headers("dev-token")
    heartbeat = client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers=enrollment_headers,
        json={"host": "BOOTSTRAP01", "os": "Windows", "agent_version": "dev"},
    )
    assert heartbeat.status_code == 401

    events = client.post(f"/api/v1/agents/{agent_id}/events", headers=enrollment_headers, json={"events": []})
    assert events.status_code == 401

    tasks = client.post(f"/api/v1/agents/{agent_id}/tasks/claim", headers=enrollment_headers, json={"max_tasks": 1})
    assert tasks.status_code == 401

    valid = client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers=_agent_headers(auth["agent_token"]),
        json={"host": "BOOTSTRAP01", "os": "Windows", "agent_version": "dev"},
    )
    assert valid.status_code == 200, valid.text

    events = client.get(
        f"/api/v1/admin/agents/{agent_id}/credential/events",
        headers=ADMIN,
        params={"tenant_id": "default"},
    )
    assert events.status_code == 200, events.text
    assert "authenticated" in [event["event_type"] for event in events.json()["events"]]


def test_rotating_agent_credential_is_delivered_on_next_heartbeat_and_audited(tmp_path):
    client = TestClient(create_app(tmp_path / "agent-credential-rotate.sqlite3", create_dev_token=True))
    auth = _enroll(client, host="ROTATE01")
    agent_id = auth["agent_id"]
    old_token = auth["agent_token"]

    rotated = client.post(
        f"/api/v1/admin/agents/{agent_id}/credential/rotate",
        headers=ADMIN,
        params={"tenant_id": "default", "reason": "scheduled"},
    )
    assert rotated.status_code == 200, rotated.text
    body = rotated.json()
    assert body["agent_id"] == agent_id
    assert body["credential_version"] == 2
    assert "agent_token" not in body
    assert "pending_agent_token" not in body

    pending = client.get(f"/api/v1/admin/agents/{agent_id}", headers=ADMIN, params={"tenant_id": "default"})
    assert pending.status_code == 200, pending.text
    assert pending.json()["credential_version"] == 2
    assert pending.json()["credential_status"] == "pending_rotation"
    assert "agent_token" not in pending.json()
    assert "pending_agent_token" not in pending.json()

    delivered = client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers=_agent_headers(old_token),
        json={"host": "ROTATE01", "os": "Windows", "agent_version": "dev"},
    )
    assert delivered.status_code == 200, delivered.text
    update = delivered.json()["credential_update"]
    assert update["credential_version"] == 2
    assert update["agent_token"]
    assert update["agent_token"] != old_token

    old = client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers=_agent_headers(old_token),
        json={"host": "ROTATE01", "os": "Windows", "agent_version": "dev"},
    )
    assert old.status_code == 401

    new = client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers=_agent_headers(update["agent_token"]),
        json={"host": "ROTATE01", "os": "Windows", "agent_version": "dev"},
    )
    assert new.status_code == 200, new.text

    fetched = client.get(f"/api/v1/admin/agents/{agent_id}", headers=ADMIN, params={"tenant_id": "default"})
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["credential_version"] == 2
    assert fetched.json()["credential_status"] == "active"
    assert "agent_token" not in fetched.json()
    assert "pending_agent_token" not in fetched.json()

    events = client.get(
        f"/api/v1/admin/agents/{agent_id}/credential/events",
        headers=ADMIN,
        params={"tenant_id": "default"},
    )
    assert events.status_code == 200, events.text
    event_types = [event["event_type"] for event in events.json()["events"]]
    assert event_types[:2] == ["enrolled", "rotation_scheduled"]
    assert "authenticated" in event_types
    assert "rotated" in event_types
    scheduled = next(event for event in events.json()["events"] if event["event_type"] == "rotation_scheduled")
    rotated_event = next(event for event in events.json()["events"] if event["event_type"] == "rotated")
    assert scheduled["credential_version"] == 2
    assert scheduled["metadata"]["reason"] == "scheduled"
    assert rotated_event["credential_version"] == 2


def test_agent_auth_uses_authenticated_tenant_not_client_payload(tmp_path):
    client = TestClient(create_app(tmp_path / "agent-tenant-isolation.sqlite3", create_dev_token=True))
    tenant_b_token = client.post(
        "/api/v1/admin/enrollment-tokens",
        headers=ADMIN,
        params={"tenant_id": "tenant-b", "max_uses": 1},
    )
    assert tenant_b_token.status_code == 200, tenant_b_token.text

    tenant_a = _enroll(client, host="TENANT-A")
    tenant_b = _enroll(client, host="TENANT-B", token=tenant_b_token.json()["token"])

    spoofed = client.post(
        f"/api/v1/agents/{tenant_a['agent_id']}/events",
        headers=_agent_headers(tenant_a["agent_token"]),
        json={
            "events": [
                {
                    "source": "internal",
                    "event_type": "endpoint_state",
                    "tenant_id": "tenant-b",
                    "host": "spoofed-host",
                    "severity": "info",
                    "raw": {"attempted_tenant": "tenant-b"},
                }
            ]
        },
    )
    assert spoofed.status_code == 200, spoofed.text

    tenant_a_events = client.get("/api/v1/admin/events", headers=ADMIN, params={"tenant_id": "default"})
    assert tenant_a_events.status_code == 200, tenant_a_events.text
    assert len(tenant_a_events.json()) == 1
    assert tenant_a_events.json()[0]["tenant_id"] == "default"

    tenant_b_events = client.get("/api/v1/admin/events", headers=ADMIN, params={"tenant_id": "tenant-b"})
    assert tenant_b_events.status_code == 200, tenant_b_events.text
    assert tenant_b_events.json() == []

    cross_tenant_task = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={"tenant_id": "tenant-b", "agent_id": tenant_a["agent_id"], "task_type": "inventory", "args": {}},
    )
    assert cross_tenant_task.status_code == 400
    assert cross_tenant_task.json()["detail"] == "target_agent_tenant_mismatch"

    valid_task = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={"tenant_id": "tenant-b", "agent_id": tenant_b["agent_id"], "task_type": "inventory", "args": {}},
    )
    assert valid_task.status_code == 200, valid_task.text
