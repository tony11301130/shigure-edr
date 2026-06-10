from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_saved_hunt_update_disable_and_enabled_filter(tmp_path):
    client = TestClient(create_app(tmp_path / "hunt-update.sqlite3", create_dev_token=True))
    created = client.post("/api/v1/admin/hunts", headers=ADMIN, json={"tenant_id": "default", "name": "Original", "indicator": "powershell"})
    assert created.status_code == 200, created.text
    hunt_id = created.json()["hunt_id"]

    updated = client.patch(f"/api/v1/admin/hunts/{hunt_id}", headers=ADMIN, params={"tenant_id": "default"}, json={"name": "Disabled sweep", "enabled": False})
    assert updated.status_code == 200, updated.text
    assert updated.json()["name"] == "Disabled sweep"
    assert updated.json()["enabled"] is False

    enabled = client.get("/api/v1/admin/hunts", headers=ADMIN, params={"tenant_id": "default", "enabled": True})
    assert enabled.status_code == 200
    assert enabled.json() == []

    run = client.post(f"/api/v1/admin/hunts/{hunt_id}/run", headers=ADMIN, params={"tenant_id": "default"})
    assert run.status_code == 400
    assert run.json()["detail"] == "hunt_disabled"


def test_saved_hunt_update_keeps_indicator_or_query_guard(tmp_path):
    client = TestClient(create_app(tmp_path / "hunt-update-guard.sqlite3", create_dev_token=True))
    created = client.post("/api/v1/admin/hunts", headers=ADMIN, json={"tenant_id": "default", "name": "Original", "indicator": "powershell"})
    hunt_id = created.json()["hunt_id"]

    bad = client.patch(f"/api/v1/admin/hunts/{hunt_id}", headers=ADMIN, params={"tenant_id": "default"}, json={"indicator": "", "query": {}})

    assert bad.status_code == 400
    assert bad.json()["detail"] == "indicator_or_query_required"
