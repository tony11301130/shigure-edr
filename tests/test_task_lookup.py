from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_admin_get_task_by_id_is_tenant_scoped(tmp_path):
    client = TestClient(create_app(tmp_path / "task-lookup.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "TASKLOOKUP01", "os": "Windows", "agent_version": "dev"})
    agent_id = enroll.json()["agent_id"]

    created = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "inventory", "args": {}})
    assert created.status_code == 200, created.text
    task_id = created.json()["task_id"]

    found = client.get(f"/api/v1/admin/tasks/{task_id}", headers=ADMIN, params={"tenant_id": "default"})
    assert found.status_code == 200, found.text
    assert found.json()["task_id"] == task_id
    assert found.json()["status"] == "queued"

    hidden = client.get(f"/api/v1/admin/tasks/{task_id}", headers=ADMIN, params={"tenant_id": "other"})
    assert hidden.status_code == 404
    assert hidden.json()["detail"] == "task_not_found"
