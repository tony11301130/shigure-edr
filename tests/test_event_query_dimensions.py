from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_event_query_supports_user_and_sha256_dimensions(tmp_path):
    client = TestClient(create_app(tmp_path / "event-dimensions.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "DIM01", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    agent_id = auth["agent_id"]
    headers = {"Authorization": f"Bearer {auth['agent_token']}"}
    sha256 = "a" * 64

    events = [
        {"source": "internal", "event_type": "file_event", "tenant_id": "default", "host": "DIM01", "user": "CORP\\alice", "file_path": "C:/Temp/a.exe", "hash_sha256": sha256, "severity": "info", "raw": {"seq": 1}},
        {"source": "internal", "event_type": "file_event", "tenant_id": "default", "host": "DIM01", "user": "CORP\\bob", "file_path": "C:/Temp/b.exe", "hash_sha256": "b" * 64, "severity": "info", "raw": {"seq": 2}},
    ]
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events": events})
    assert ingest.status_code == 200

    by_user = client.get("/api/v1/admin/events", headers=ADMIN, params={"tenant_id": "default", "user": "alice"})
    assert by_user.status_code == 200
    assert len(by_user.json()) == 1
    assert by_user.json()[0]["user"] == "CORP\\alice"

    by_hash = client.get("/api/v1/admin/events/count", headers=ADMIN, params={"tenant_id": "default", "hash_sha256": sha256})
    assert by_hash.status_code == 200
    assert by_hash.json()["count"] == 1

    related = client.get("/api/v1/admin/events/related", headers=ADMIN, params={"tenant_id": "default", "entity_type": "hash_sha256", "value": sha256})
    assert related.status_code == 200
    assert len(related.json()) == 1
