from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_task_catalog_and_server_side_allowlist(tmp_path):
    client = TestClient(create_app(tmp_path / "catalog.sqlite3", create_dev_token=True))
    scripts = client.get("/api/v1/admin/readonly-scripts", headers=ADMIN)
    assert scripts.status_code == 200
    catalog = scripts.json()["scripts"]
    task_types = {s["task_type"] for s in catalog}
    assert {"inventory", "process_list", "windows_event_logs", "file_hash"}.issubset(task_types)
    assert {"agent_identity", "list_directory", "read_file_chunk", "copy_file", "quarantine_file", "delete_file", "kill_process", "service_control"}.issubset(task_types)
    delete_spec = next(s for s in catalog if s["task_type"] == "delete_file")
    assert delete_spec["risk"] == "high"
    assert delete_spec["destructive"] is True
    assert delete_spec["requires_explicit_dispatch"] is True

    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "CAT01", "os": "Windows", "agent_version": "dev"})
    agent_id = enroll.json()["agent_id"]

    blocked = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "arbitrary_shell", "args": {"cmd": "whoami"}})
    assert blocked.status_code == 400
    assert blocked.json()["detail"] == "task_not_allowlisted"

    missing_hash = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "delete_file", "args": {"path": "C:/x"}})
    assert missing_hash.status_code == 400
    assert missing_hash.json()["detail"] == "task_arg_confirm_sha256_required"

    allowed = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "inventory", "args": {}})
    assert allowed.status_code == 200


def test_task_catalog_rejects_unknown_args(tmp_path):
    client = TestClient(create_app(tmp_path / "catalog-args.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "CAT02", "os": "Windows", "agent_version": "dev"})
    agent_id = enroll.json()["agent_id"]

    res = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "service_control", "args": {"service_name": "Spooler", "action": "restart"}})
    assert res.status_code == 400
    assert res.json()["detail"] == "task_arg_action_invalid"

    res = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "file_hash", "args": {"path": "C:/x", "extra": True}})
    assert res.status_code == 400
    assert res.json()["detail"] == "task_arg_extra_unknown"


def test_task_catalog_endpoint_alias(tmp_path):
    client = TestClient(create_app(tmp_path / "catalog-alias.sqlite3", create_dev_token=True))
    res = client.get("/api/v1/admin/task-catalog", headers=ADMIN)
    assert res.status_code == 200
    task_types = {t["task_type"] for t in res.json()["tasks"]}
    assert "agent_identity" in task_types
    assert "delete_file" in task_types
