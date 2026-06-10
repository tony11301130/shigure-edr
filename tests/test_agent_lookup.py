from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_admin_get_agent_by_id_is_tenant_scoped(tmp_path):
    client = TestClient(create_app(tmp_path / "agent-lookup.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "LOOKUP01", "ip_address": "10.10.1.5", "os": "Windows", "agent_version": "dev"})
    assert enroll.status_code == 200
    agent_id = enroll.json()["agent_id"]

    found = client.get(f"/api/v1/admin/agents/{agent_id}", headers=ADMIN, params={"tenant_id": "default"})
    assert found.status_code == 200, found.text
    assert found.json()["agent_id"] == agent_id
    assert found.json()["host"] == "LOOKUP01"
    assert found.json()["ip_address"] == "10.10.1.5"

    hidden = client.get(f"/api/v1/admin/agents/{agent_id}", headers=ADMIN, params={"tenant_id": "other"})
    assert hidden.status_code == 404
    assert hidden.json()["detail"] == "agent_not_found"
