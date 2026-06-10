from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_alert_list_filters_by_severity_and_host(tmp_path):
    client = TestClient(create_app(tmp_path / "alert-filters.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "ALERT01", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    headers = {"Authorization": f"Bearer {auth['agent_token']}"}
    event = {"source": "internal", "event_type": "process_start", "tenant_id": "default", "host": "ALERT01", "process_name": "powershell.exe", "command_line": "powershell -enc SQBFAFgA", "severity": "info"}
    ingest = client.post(f"/api/v1/agents/{auth['agent_id']}/events", headers=headers, json={"events": [event]})
    assert ingest.status_code == 200

    hit = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "severity": "high", "host": "ALERT01"})
    assert hit.status_code == 200
    assert len(hit.json()) == 1
    assert hit.json()[0]["title"] == "Suspicious encoded PowerShell command"

    miss = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "severity": "critical", "host": "ALERT01"})
    assert miss.status_code == 200
    assert miss.json() == []
