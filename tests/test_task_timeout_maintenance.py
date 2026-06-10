from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_expire_stale_claimed_tasks_marks_timed_out(tmp_path):
    app = create_app(tmp_path / "task-timeout.sqlite3", create_dev_token=True)
    client = TestClient(app)
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "TIMEOUT01", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    agent_id = auth["agent_id"]
    agent_headers = {"Authorization": f"Bearer {auth['agent_token']}"}

    task = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "inventory", "args": {}, "timeout_seconds": 1})
    assert task.status_code == 200, task.text
    task_id = task.json()["task_id"]

    claim = client.post(f"/api/v1/agents/{agent_id}/tasks/claim", headers=agent_headers, json={"max_tasks": 1})
    assert claim.status_code == 200
    assert claim.json()["tasks"][0]["status"] == "claimed"

    with app.state.store.connect() as conn:
        conn.execute("update tasks set claimed_at='2000-01-01T00:00:00+00:00' where task_id=?", (task_id,))

    expired = client.post("/api/v1/admin/tasks/expire-stale", headers=ADMIN, params={"tenant_id": "default"})
    assert expired.status_code == 200
    assert expired.json()["expired"] == 1

    tasks = client.get("/api/v1/admin/tasks", headers=ADMIN, params={"tenant_id": "default"}).json()
    assert tasks[0]["status"] == "timed_out"
    assert tasks[0]["error"] == "task_claim_timeout"
