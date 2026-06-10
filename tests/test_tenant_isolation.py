from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def enroll(client: TestClient, host: str, token: str = "dev-token"):
    res = client.post("/api/v1/enroll", json={"enrollment_token": token, "host": host, "os": "Windows", "agent_version": "dev"})
    assert res.status_code == 200, res.text
    return res.json()


def test_task_creation_rejects_cross_tenant_target(tmp_path):
    app = create_app(tmp_path / "tenant.sqlite3", create_dev_token=True)
    client = TestClient(app)
    app.state.store.create_enrollment_token("tenant-b", token="tenant-b-token")

    a = enroll(client, "TENANT-A")
    b = enroll(client, "TENANT-B", token="tenant-b-token")
    assert a["tenant_id"] == "default"
    assert b["tenant_id"] == "tenant-b"

    bad = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "tenant-b", "agent_id": a["agent_id"], "task_type": "inventory", "args": {}})
    assert bad.status_code == 400
    assert bad.json()["detail"] == "target_agent_tenant_mismatch"

    good = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "tenant-b", "agent_id": b["agent_id"], "task_type": "inventory", "args": {}})
    assert good.status_code == 200
