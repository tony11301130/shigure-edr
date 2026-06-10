from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_task_list_filters_by_status(tmp_path):
    client = TestClient(create_app(tmp_path / "task-filters.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "TASKFILTER01", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    agent_id = auth["agent_id"]
    agent_headers = {"Authorization": f"Bearer {auth['agent_token']}"}

    for task_type in ["inventory", "process_list"]:
        created = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": task_type, "args": {}})
        assert created.status_code == 200, created.text

    claim = client.post(f"/api/v1/agents/{agent_id}/tasks/claim", headers=agent_headers, json={"max_tasks": 1})
    assert claim.status_code == 200

    queued = client.get("/api/v1/admin/tasks", headers=ADMIN, params={"tenant_id": "default", "status": "queued"})
    assert queued.status_code == 200
    assert len(queued.json()) == 1
    assert queued.json()[0]["status"] == "queued"

    claimed = client.get("/api/v1/admin/tasks", headers=ADMIN, params={"tenant_id": "default", "status": "claimed"})
    assert claimed.status_code == 200
    assert len(claimed.json()) == 1
    assert claimed.json()[0]["status"] == "claimed"
