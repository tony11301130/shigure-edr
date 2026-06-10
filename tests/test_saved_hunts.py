from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_saved_hunt_create_run_and_list_results(tmp_path):
    client = TestClient(create_app(tmp_path / "hunts.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "HUNT01", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    agent_id = auth["agent_id"]
    headers = {"Authorization": f"Bearer {auth['agent_token']}"}

    event = {"source":"internal", "event_type":"network_connection", "tenant_id":"default", "host":"HUNT01", "process_name":"powershell.exe", "process_id":"321", "remote_ip":"203.0.113.10", "remote_port":443, "severity":"info", "raw":{"source":"saved-hunt-test"}}
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events":[event]})
    assert ingest.status_code == 200

    create = client.post("/api/v1/admin/hunts", headers=ADMIN, json={"tenant_id":"default", "name":"Safe IOC sweep", "indicator":"203.0.113.10", "description":"smoke IOC hunt"})
    assert create.status_code == 200, create.text
    hunt_id = create.json()["hunt_id"]

    hunts = client.get("/api/v1/admin/hunts", headers=ADMIN, params={"tenant_id":"default"})
    assert hunts.status_code == 200
    assert hunts.json()[0]["name"] == "Safe IOC sweep"

    run = client.post(f"/api/v1/admin/hunts/{hunt_id}/run", headers=ADMIN, params={"tenant_id":"default"})
    assert run.status_code == 200, run.text
    result = run.json()["result"]
    assert result["event_count"] >= 1
    assert result["alert_count"] >= 1
    assert result["hosts"] == ["HUNT01"]

    runs = client.get(f"/api/v1/admin/hunts/{hunt_id}/runs", headers=ADMIN, params={"tenant_id":"default"})
    assert runs.status_code == 200
    assert runs.json()[0]["run_id"] == run.json()["run_id"]


def test_saved_hunt_requires_indicator_or_query(tmp_path):
    client = TestClient(create_app(tmp_path / "hunt-validation.sqlite3", create_dev_token=True))
    res = client.post("/api/v1/admin/hunts", headers=ADMIN, json={"tenant_id":"default", "name":"empty"})
    assert res.status_code == 400
    assert res.json()["detail"] == "indicator_or_query_required"
