from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_raw_evidence_list_supports_kind_filter(tmp_path):
    client = TestClient(create_app(tmp_path / "raw-list.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "RAW01", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    agent_id = auth["agent_id"]
    headers = {"Authorization": f"Bearer {auth['agent_token']}"}

    event = {
        "source": "internal",
        "event_type": "process_start",
        "tenant_id": "default",
        "host": "RAW01",
        "process_name": "cmd.exe",
        "command_line": "cmd /c whoami",
        "severity": "info",
        "raw_ref": "sqlite://raw_evidence/default/event/legacy/ref",
        "raw_hash": "0" * 64,
        "raw": {"source": "raw-list-test"},
    }
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events": [event]})
    assert ingest.status_code == 200

    listed = client.get("/api/v1/admin/raw-evidence/list", headers=ADMIN, params={"tenant_id": "default", "kind": "event"})
    assert listed.status_code == 200, listed.text
    refs = listed.json()["evidence"]
    assert len(refs) == 1
    assert refs[0]["kind"] == "event"
    assert refs[0]["raw_ref"].startswith("object://raw-evidence/default/event/")
    assert refs[0]["storage_provider"] == "local"
    assert refs[0]["object_key"].startswith("default/event/")
    assert refs[0]["size"] > 0
    assert "payload" not in refs[0]
    events = client.get("/api/v1/admin/events", headers=ADMIN, params={"tenant_id": "default", "host": "RAW01"})
    assert events.json()[0]["raw_ref"] == refs[0]["raw_ref"]
    assert events.json()[0]["raw_hash"] == refs[0]["sha256"]

    fetched = client.get("/api/v1/admin/raw-evidence", headers=ADMIN, params={"tenant_id": "default", "raw_ref": refs[0]["raw_ref"]})
    assert fetched.status_code == 200
    assert fetched.json()["payload"] == {"source": "raw-list-test"}

    by_hash = client.get(f"/api/v1/admin/raw-evidence/by-hash/{refs[0]['sha256']}", headers=ADMIN, params={"tenant_id": "default"})
    assert by_hash.status_code == 200
    assert by_hash.json()["raw_ref"] == refs[0]["raw_ref"]
