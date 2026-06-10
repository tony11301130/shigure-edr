from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def _agent_id(client: TestClient) -> str:
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "ARG01", "os": "Windows", "agent_version": "dev"})
    assert enroll.status_code == 200
    return enroll.json()["agent_id"]


def test_task_argument_validation_rejects_missing_required_path(tmp_path):
    client = TestClient(create_app(tmp_path / "task-args.sqlite3", create_dev_token=True))
    agent_id = _agent_id(client)

    res = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "file_hash", "args": {}})

    assert res.status_code == 400
    assert res.json()["detail"] == "task_arg_path_required"


def test_task_argument_validation_rejects_unknown_windows_event_profile(tmp_path):
    client = TestClient(create_app(tmp_path / "task-args-profile.sqlite3", create_dev_token=True))
    agent_id = _agent_id(client)

    res = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "windows_event_logs", "args": {"profile": "sysmon", "max_events": 25}})

    assert res.status_code == 400
    assert res.json()["detail"] == "task_arg_profile_invalid"


def test_task_argument_validation_accepts_safe_windows_event_profile(tmp_path):
    client = TestClient(create_app(tmp_path / "task-args-ok.sqlite3", create_dev_token=True))
    agent_id = _agent_id(client)

    res = client.post("/api/v1/admin/tasks", headers=ADMIN, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "windows_event_logs", "args": {"profile": "powershell", "max_events": 50}})

    assert res.status_code == 200, res.text
    assert res.json()["task_type"] == "windows_event_logs"
