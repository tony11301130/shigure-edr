from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def _task(client: TestClient) -> str:
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "LIFE01", "os": "Windows", "agent_version": "dev"})
    agent_id = enroll.json()["agent_id"]
    res = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "inventory", "args": {}})
    assert res.status_code == 200
    return res.json()["task_id"]


def test_cancel_queued_task(tmp_path):
    client = TestClient(create_app(tmp_path / "task-cancel.sqlite3", create_dev_token=True))
    task_id = _task(client)
    res = client.post(f"/api/v1/admin/tasks/{task_id}/cancel", headers=ADMIN, params={"tenant_id": "default"})
    assert res.status_code == 200
    task = client.get(f"/api/v1/admin/tasks/{task_id}", headers=ADMIN, params={"tenant_id": "default"}).json()
    assert task["status"] == "cancelled"


def test_retry_cancelled_task(tmp_path):
    client = TestClient(create_app(tmp_path / "task-retry.sqlite3", create_dev_token=True))
    task_id = _task(client)
    assert client.post(f"/api/v1/admin/tasks/{task_id}/cancel", headers=ADMIN, params={"tenant_id": "default"}).status_code == 200
    res = client.post(f"/api/v1/admin/tasks/{task_id}/retry", headers=ADMIN, params={"tenant_id": "default"})
    assert res.status_code == 200
    task = client.get(f"/api/v1/admin/tasks/{task_id}", headers=ADMIN, params={"tenant_id": "default"}).json()
    assert task["status"] == "queued"
    assert task["error"] is None
