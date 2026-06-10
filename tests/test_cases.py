from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_alert_to_case_evidence_workflow(tmp_path):
    app = create_app(tmp_path / "cases.sqlite3", create_dev_token=True)
    client = TestClient(app)
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "CASE01", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    agent_id = auth["agent_id"]
    headers = {"Authorization": f"Bearer {auth['agent_token']}"}

    event = {"source":"internal", "event_type":"process_start", "tenant_id":"default", "host":"CASE01", "process_name":"powershell.exe", "command_line":"powershell -enc SQBFAFgA", "severity":"info", "raw":{"source":"test"}}
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events":[event]})
    assert ingest.status_code == 200

    alerts = client.get("/api/v1/admin/alerts?tenant_id=default", headers=ADMIN).json()
    alert_id = alerts[0]["alert_id"]

    create = client.post("/api/v1/admin/cases", headers=ADMIN, json={"tenant_id":"default", "title":"Investigate encoded PowerShell", "severity":"high", "alert_id": alert_id, "description":"auto-created from alert"})
    assert create.status_code == 200, create.text
    case = create.json()
    assert case["status"] == "open"
    assert case["alert_id"] == alert_id

    events = client.get("/api/v1/admin/events?tenant_id=default&indicator=SQBFAFgA", headers=ADMIN).json()
    ev_ref = events[0]["id"]
    evidence = client.post(f"/api/v1/admin/cases/{case['case_id']}/evidence?tenant_id=default", headers=ADMIN, json={"evidence_type":"event", "ref_id": ev_ref, "summary":"Encoded PowerShell event", "data":{"raw_ref": events[0]["raw_ref"]}})
    assert evidence.status_code == 200

    update = client.patch(f"/api/v1/admin/cases/{case['case_id']}?tenant_id=default", headers=ADMIN, json={"status":"investigating", "assignee":"analyst", "summary":"Needs process tree review"})
    assert update.status_code == 200
    assert update.json()["status"] == "investigating"

    fetched = client.get(f"/api/v1/admin/cases/{case['case_id']}?tenant_id=default", headers=ADMIN).json()
    assert fetched["case"]["summary"] == "Needs process tree review"
    assert fetched["evidence"][0]["ref_id"] == ev_ref
