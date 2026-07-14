from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_task_catalog_and_server_side_allowlist(tmp_path):
    client = TestClient(create_app(tmp_path / "catalog.sqlite3", create_dev_token=True))
    scripts = client.get("/api/v1/admin/readonly-scripts", headers=ADMIN)
    assert scripts.status_code == 200
    catalog = scripts.json()["scripts"]
    task_types = {s["task_type"] for s in catalog}
    assert {"inventory", "process_list", "windows_event_logs", "file_hash", "agent_identity", "list_directory", "read_file_chunk", "collect_file"}.issubset(task_types)
    assert {"copy_file", "quarantine_file", "delete_file", "kill_process", "service_control"}.isdisjoint(task_types)

    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "CAT01", "os": "Windows", "agent_version": "dev"})
    agent_id = enroll.json()["agent_id"]

    blocked = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "arbitrary_shell", "args": {"cmd": "whoami"}})
    assert blocked.status_code == 200
    blocked_task = blocked.json()
    assert blocked_task["status"] == "blocked_by_policy"
    assert blocked_task["error"] == "task_not_allowlisted"
    assert blocked_task["result"]["policy_version"] == "read_only_v1"
    assert blocked_task["result"]["task_type"] == "arbitrary_shell"

    destructive = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "delete_file", "args": {"path": "C:/x", "confirm_sha256": "0" * 64}})
    assert destructive.status_code == 200
    blocked_task = destructive.json()
    assert blocked_task["status"] == "blocked_by_policy"
    assert blocked_task["error"] == "destructive_task_blocked"
    assert blocked_task["result"]["risk"] == "high"
    assert blocked_task["result"]["destructive"] is True
    assert blocked_task["result"]["policy_version"] == "read_only_v1"

    visible = client.get(f"/api/v1/admin/tasks/{blocked_task['task_id']}", headers=ADMIN, params={"tenant_id": "default"})
    assert visible.status_code == 200
    assert visible.json()["status"] == "blocked_by_policy"

    allowed = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "inventory", "args": {}})
    assert allowed.status_code == 200


def test_task_catalog_rejects_unknown_args(tmp_path):
    client = TestClient(create_app(tmp_path / "catalog-args.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "CAT02", "os": "Windows", "agent_version": "dev"})
    agent_id = enroll.json()["agent_id"]

    res = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "service_control", "args": {"service_name": "Spooler", "action": "restart"}})
    assert res.status_code == 200
    assert res.json()["status"] == "blocked_by_policy"
    assert res.json()["error"] == "destructive_task_blocked"

    res = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "file_hash", "args": {"path": "C:/x", "extra": True}})
    assert res.status_code == 400
    assert res.json()["detail"] == "task_arg_extra_unknown"


def test_task_catalog_endpoint_alias(tmp_path):
    client = TestClient(create_app(tmp_path / "catalog-alias.sqlite3", create_dev_token=True))
    res = client.get("/api/v1/admin/task-catalog", headers=ADMIN)
    assert res.status_code == 200
    task_types = {t["task_type"] for t in res.json()["tasks"]}
    assert "agent_identity" in task_types
    assert "delete_file" not in task_types
    assert "copy_file" not in task_types


def test_medium_risk_evidence_tasks_require_limits_and_reason_context(tmp_path):
    client = TestClient(create_app(tmp_path / "catalog-evidence.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "CAT03", "os": "Windows", "agent_version": "dev"})
    agent_id = enroll.json()["agent_id"]

    missing_reason = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={"tenant_id": "default", "agent_id": agent_id, "task_type": "collect_file", "args": {"path": "C:/Temp/a.txt", "max_bytes": 1024}},
    )
    assert missing_reason.status_code == 400
    assert missing_reason.json()["detail"] == "task_arg_reason_required"

    missing_limit = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={"tenant_id": "default", "agent_id": agent_id, "task_type": "read_file_chunk", "args": {"path": "C:/Temp/a.txt", "reason": "triage", "case_id": "case-1"}},
    )
    assert missing_limit.status_code == 400
    assert missing_limit.json()["detail"] == "task_arg_max_bytes_required"

    allowed = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={
            "tenant_id": "default",
            "agent_id": agent_id,
            "task_type": "collect_file",
            "args": {"path": "C:/Temp/a.txt", "max_bytes": 1024, "reason": "triage", "case_id": "case-1"},
        },
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["result"]["policy_version"] == "read_only_v1"
    assert allowed.json()["result"]["reason"] == "triage"


def test_readonly_task_policy_audit_survives_completion(tmp_path):
    client = TestClient(create_app(tmp_path / "catalog-audit.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "CAT04", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    agent_id = auth["agent_id"]
    agent_headers = {"Authorization": f"Bearer {auth['agent_token']}"}

    created = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={"tenant_id": "default", "agent_id": agent_id, "task_type": "file_hash", "args": {"path": "C:/Temp/a.txt"}, "requested_by": "analyst@example.test"},
    )
    assert created.status_code == 200, created.text
    task_id = created.json()["task_id"]
    assert created.json()["result"]["requested_by"] == "analyst@example.test"

    claim = client.post(f"/api/v1/agents/{agent_id}/tasks/claim", headers=agent_headers, json={"max_tasks": 1})
    assert claim.status_code == 200
    completed = client.post(
        f"/api/v1/agents/{agent_id}/tasks/{task_id}/result",
        headers=agent_headers,
        json={"status": "succeeded", "result": {"sha256": "0" * 64, "requested_by": "endpoint-spoof", "policy_version": "endpoint-spoof"}},
    )
    assert completed.status_code == 200

    task = client.get(f"/api/v1/admin/tasks/{task_id}", headers=ADMIN, params={"tenant_id": "default"}).json()
    assert task["status"] == "succeeded"
    assert task["result"]["requested_by"] == "analyst@example.test"
    assert task["result"]["policy_version"] == "read_only_v1"
    assert task["result"]["risk"] == "low"
    assert task["raw_ref"]
    assert task["raw_hash"]


def test_blocked_policy_task_cannot_be_retried_into_dispatch_queue(tmp_path):
    client = TestClient(create_app(tmp_path / "catalog-blocked-retry.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "CAT05", "os": "Windows", "agent_version": "dev"})
    agent_id = enroll.json()["agent_id"]

    blocked = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={"tenant_id": "default", "agent_id": agent_id, "task_type": "delete_file", "args": {"path": "C:/x", "confirm_sha256": "0" * 64}},
    )
    assert blocked.status_code == 200
    task_id = blocked.json()["task_id"]

    retry = client.post(f"/api/v1/admin/tasks/{task_id}/retry", headers=ADMIN, params={"tenant_id": "default"})
    assert retry.status_code == 400
    assert retry.json()["detail"] == "task_not_retryable"

    task = client.get(f"/api/v1/admin/tasks/{task_id}", headers=ADMIN, params={"tenant_id": "default"}).json()
    assert task["status"] == "blocked_by_policy"
    assert task["result"]["policy_version"] == "read_only_v1"
