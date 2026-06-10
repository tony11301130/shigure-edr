from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_agent_config_rejects_invalid_timing_values(tmp_path):
    client = TestClient(create_app(tmp_path / "config-validation.sqlite3", create_dev_token=True))

    res = client.put("/api/v1/admin/config", headers=ADMIN, params={"tenant_id": "default"}, json={"version": 1, "task_poll_seconds": 0, "heartbeat_seconds": 30, "upload_interval_seconds": 15, "max_snapshot_events": 25})

    assert res.status_code == 422


def test_agent_config_accepts_zero_snapshot_limit_for_pause(tmp_path):
    client = TestClient(create_app(tmp_path / "config-validation-ok.sqlite3", create_dev_token=True))

    res = client.put("/api/v1/admin/config", headers=ADMIN, params={"tenant_id": "default"}, json={"version": 1, "task_poll_seconds": 15, "heartbeat_seconds": 30, "upload_interval_seconds": 15, "max_snapshot_events": 0})

    assert res.status_code == 200, res.text
    assert res.json()["max_snapshot_events"] == 0
