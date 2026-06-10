from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app


def test_m0_enroll_ingest_detect_task_loop(tmp_path):
    app = create_app(tmp_path / "m0.sqlite3", create_dev_token=True)
    client = TestClient(app)

    enroll = client.post("/api/v1/enroll", json={
        "enrollment_token": "dev-token",
        "host": "POS01",
        "ip_address": "10.0.0.10",
        "os": "Windows",
        "agent_version": "dev-test",
    })
    assert enroll.status_code == 200, enroll.text
    auth = enroll.json()
    agent_id = auth["agent_id"]
    headers = {"Authorization": f"Bearer {auth['agent_token']}"}

    hb = client.post(f"/api/v1/agents/{agent_id}/heartbeat", headers=headers, json={"host": "POS01", "os": "Windows", "agent_version": "dev-test"})
    assert hb.status_code == 200
    assert hb.json()["status"] == "ok"

    event = {
        "source": "internal",
        "event_type": "process_start",
        "tenant_id": "attacker-supplied-tenant-should-be-overridden",
        "host": "POS01",
        "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process_id": "4242",
        "parent_process_id": "100",
        "command_line": "powershell.exe -enc SQBFAFgA",
        "severity": "info",
    }
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events": [event]})
    assert ingest.status_code == 200, ingest.text
    assert ingest.json() == {"accepted": 1, "alerts_generated": 1}

    alerts = client.get("/api/v1/admin/alerts?tenant_id=default").json()
    assert len(alerts) == 1
    assert alerts[0]["title"] == "Suspicious encoded PowerShell command"
    assert alerts[0]["raw"]["tenant_id"] == "default"

    task = client.post("/api/v1/admin/tasks", json={"tenant_id": "default", "agent_id": agent_id, "task_type": "process_list", "args": {}})
    assert task.status_code == 200, task.text
    task_id = task.json()["task_id"]

    claim = client.post(f"/api/v1/agents/{agent_id}/tasks/claim", headers=headers, json={"max_tasks": 1})
    assert claim.status_code == 200
    claimed = claim.json()["tasks"]
    assert len(claimed) == 1
    assert claimed[0]["task_id"] == task_id
    assert claimed[0]["status"] == "claimed"

    result = client.post(f"/api/v1/agents/{agent_id}/tasks/{task_id}/result", headers=headers, json={"status": "succeeded", "result": {"processes": []}})
    assert result.status_code == 200

    events = client.get("/api/v1/admin/events?tenant_id=default&host=POS01").json()
    assert len(events) == 1
    assert events[0]["tenant_id"] == "default"

    hunted = client.get("/api/v1/admin/events?tenant_id=default&indicator=SQBFAFgA").json()
    assert len(hunted) == 1

    process_events = client.get("/api/v1/admin/events?tenant_id=default&event_type=process_start&process_name=powershell").json()
    assert len(process_events) == 1

    tasks = client.get(f"/api/v1/admin/tasks?tenant_id=default&agent_id={agent_id}").json()
    assert tasks[0]["task_id"] == task_id
    assert tasks[0]["status"] == "succeeded"
