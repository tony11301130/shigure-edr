from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_readonly_script_catalog_and_server_side_allowlist(tmp_path):
    client = TestClient(create_app(tmp_path / "catalog.sqlite3", create_dev_token=True))
    scripts = client.get("/api/v1/admin/readonly-scripts", headers=ADMIN)
    assert scripts.status_code == 200
    task_types = {s["task_type"] for s in scripts.json()["scripts"]}
    assert {"inventory", "process_list", "windows_event_logs", "file_hash"}.issubset(task_types)

    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "CAT01", "os": "Windows", "agent_version": "dev"})
    agent_id = enroll.json()["agent_id"]

    blocked = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "delete_file", "args": {"path": "C:/x"}})
    assert blocked.status_code == 400
    assert blocked.json()["detail"] == "task_not_readonly_allowlisted"

    allowed = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "inventory", "args": {}})
    assert allowed.status_code == 200
