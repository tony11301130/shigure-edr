from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_get_alert_by_id_and_exact_event(tmp_path):
    client = TestClient(create_app(tmp_path / "parity.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "FID01", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    agent_id = auth["agent_id"]
    headers = {"Authorization": f"Bearer {auth['agent_token']}"}

    event = {"source":"internal", "event_type":"process_start", "tenant_id":"default", "host":"FID01", "process_name":"powershell.exe", "process_id":"9001", "command_line":"powershell -enc SQBFAFgA", "severity":"info", "raw":{"source":"parity-test"}}
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events":[event]})
    assert ingest.status_code == 200

    events = client.get("/api/v1/admin/events", headers=ADMIN, params={"tenant_id":"default", "host":"FID01"}).json()
    event_id = events[0]["id"]
    exact_event = client.get(f"/api/v1/admin/events/{event_id}", headers=ADMIN, params={"tenant_id":"default"})
    assert exact_event.status_code == 200
    assert exact_event.json()["process_id"] == "9001"

    alerts = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id":"default"}).json()
    alert_id = alerts[0]["alert_id"]
    exact_alert = client.get(f"/api/v1/admin/alerts/{alert_id}", headers=ADMIN, params={"tenant_id":"default"})
    assert exact_alert.status_code == 200
    assert exact_alert.json()["title"] == "Suspicious encoded PowerShell command"

    assert client.get(f"/api/v1/admin/events/{event_id}", headers=ADMIN, params={"tenant_id":"other"}).status_code == 404
    assert client.get(f"/api/v1/admin/alerts/{alert_id}", headers=ADMIN, params={"tenant_id":"other"}).status_code == 404
