from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def _enroll(client: TestClient, host: str = "MDR01"):
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": host, "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    return auth, {"Authorization": f"Bearer {auth['agent_token']}"}


def test_mdr_workspace_runs_alert_to_handoff_loop(tmp_path):
    app = create_app(tmp_path / "mdr-workspace.sqlite3", create_dev_token=True)
    client = TestClient(app)
    auth, agent_headers = _enroll(client)
    agent_id = auth["agent_id"]
    parent_entity = "peid:MDR01:boot-a:100:2026-07-15T01:00:00Z"
    child_entity = "peid:MDR01:boot-a:200:2026-07-15T01:02:00Z"

    events = [
        {
            "source": "internal",
            "event_type": "process_start",
            "tenant_id": "default",
            "host": "MDR01",
            "process_name": "explorer.exe",
            "process_id": "100",
            "process_entity_id": parent_entity,
            "boot_id": "boot-a",
            "process_create_time": "2026-07-15T01:00:00Z",
            "severity": "info",
            "raw": {"seq": 1},
        },
        {
            "source": "internal",
            "event_type": "process_start",
            "tenant_id": "default",
            "host": "MDR01",
            "process_name": "powershell.exe",
            "process_id": "200",
            "parent_process_id": "100",
            "process_entity_id": child_entity,
            "parent_process_entity_id": parent_entity,
            "boot_id": "boot-a",
            "process_create_time": "2026-07-15T01:02:00Z",
            "command_line": "powershell -enc SQBFAFgA",
            "user": "ACME\\jane",
            "severity": "info",
            "raw": {"seq": 2},
        },
        {
            "source": "internal",
            "event_type": "network_connection",
            "tenant_id": "default",
            "host": "MDR01",
            "process_name": "powershell.exe",
            "process_id": "200",
            "process_entity_id": child_entity,
            "remote_ip": "203.0.113.10",
            "remote_port": 443,
            "user": "ACME\\jane",
            "severity": "info",
            "raw": {"seq": 3},
        },
    ]
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=agent_headers, json={"events": events})
    assert ingest.status_code == 200, ingest.text

    alerts = client.get(
        "/api/v1/admin/alerts",
        headers=ADMIN,
        params={"tenant_id": "default", "title": "Suspicious encoded PowerShell command"},
    ).json()
    alert_id = alerts[0]["alert_id"]

    started = client.post(
        "/api/v1/admin/investigate/workspace/start",
        headers=ADMIN,
        json={"tenant_id": "default", "alert_id": alert_id, "assignee": "analyst-1", "priority": "high"},
    )
    assert started.status_code == 200, started.text
    workspace = started.json()
    case = workspace["case"]
    assert workspace["workflow"]["status"] == "investigating"
    assert workspace["workflow"]["case_link"] == f"/api/v1/admin/cases/{case['case_id']}"
    assert case["alert_id"] == alert_id
    assert case["status"] == "investigating"
    assert case["assignee"] == "analyst-1"
    assert case["priority"] == "high"
    assert case["classification"] == "unclassified"
    assert workspace["endpoint_context"]["host"] == "MDR01"
    assert workspace["process_graph"]["process_entity_id"] == child_entity
    assert {event["event_type"] for event in workspace["related_timeline"]} >= {"process_start", "network_connection"}
    assert workspace["hunt"]["summary"]["impacted_endpoints"] == ["MDR01"]
    assert workspace["hunt"]["summary"]["impacted_users"] == ["ACME\\jane"]
    assert workspace["hunt"]["summary"]["event_count"] == 1
    assert workspace["hunt"]["summary"]["related_alert_count"] >= 1
    assert workspace["evidence_links"]

    queued = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={
            "tenant_id": "default",
            "agent_id": agent_id,
            "task_type": "read_file_chunk",
            "args": {"path": "C:/Temp/stager.ps1", "offset": 0, "max_bytes": 512, "reason": "triage", "case_id": case["case_id"]},
        },
    )
    assert queued.status_code == 200, queued.text
    task = queued.json()
    completed = client.post(
        f"/api/v1/agents/{agent_id}/tasks/{task['task_id']}/result",
        headers=agent_headers,
        json={"status": "succeeded", "result": {"path": "C:/Temp/stager.ps1", "size": 512, "sha256": "a" * 64}},
    )
    assert completed.status_code == 200, completed.text

    other_case = client.post("/api/v1/admin/cases", headers=ADMIN, json={"tenant_id": "default", "title": "Unrelated case", "severity": "low"})
    assert other_case.status_code == 200, other_case.text
    mismatch = client.post(
        "/api/v1/admin/investigate/workspace/attach-task-evidence",
        headers=ADMIN,
        json={"tenant_id": "default", "case_id": other_case.json()["case_id"], "task_id": task["task_id"]},
    )
    assert mismatch.status_code == 400
    assert mismatch.json()["detail"] == "task_case_mismatch"

    attached = client.post(
        "/api/v1/admin/investigate/workspace/attach-task-evidence",
        headers=ADMIN,
        json={"tenant_id": "default", "case_id": case["case_id"], "task_id": task["task_id"], "summary": "Collected suspicious script chunk"},
    )
    assert attached.status_code == 200, attached.text
    evidence = attached.json()
    assert evidence["evidence_type"] == "task_result"
    assert evidence["data"]["raw_ref"].startswith("sqlite://raw_evidence/default/task_result/")
    assert evidence["data"]["raw_hash"]
    assert evidence["data"]["size"] == 512
    assert evidence["data"]["audit"]["reason"] == "triage"
    assert evidence["data"]["audit"]["case_id"] == case["case_id"]

    closed = client.patch(
        f"/api/v1/admin/cases/{case['case_id']}",
        headers=ADMIN,
        params={"tenant_id": "default"},
        json={"status": "closed", "classification": "true_positive", "summary": "Encoded PowerShell staged outbound C2-like traffic."},
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["classification"] == "true_positive"

    handoff = client.get(f"/api/v1/admin/cases/{case['case_id']}/handoff", headers=ADMIN, params={"tenant_id": "default"})
    assert handoff.status_code == 200, handoff.text
    export = handoff.json()
    assert export["case"]["classification"] == "true_positive"
    assert export["summary"] == "Encoded PowerShell staged outbound C2-like traffic."
    assert {item["evidence_type"] for item in export["evidence"]} >= {"alert", "raw_evidence", "task_result"}
    assert export["raw_evidence_refs"]
    assert export["handoff"]["format"] == "json"
