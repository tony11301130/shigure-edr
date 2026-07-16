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

    config_update = client.put("/api/v1/admin/config?tenant_id=default", headers={"Authorization":"Bearer dev-admin-token"}, json={"version": 1, "task_poll_seconds": 7, "heartbeat_seconds": 30, "upload_interval_seconds": 15, "max_snapshot_events": 3, "collect_snapshot": True, "collect_process_snapshot": True, "collect_network_snapshot": False, "collect_windows_event_logs": True, "demo_suspicious_event": False, "features": {"windows_etw": False}})
    assert config_update.status_code == 200
    assert config_update.json()["version"] >= 2

    hb = client.post(f"/api/v1/agents/{agent_id}/heartbeat", headers=headers, json={"host": "POS01", "os": "Windows", "agent_version": "dev-test"})
    assert hb.status_code == 200
    assert hb.json()["status"] == "ok"
    assert hb.json()["config"]["task_poll_seconds"] == 7
    assert hb.json()["config"]["max_snapshot_events"] == 3
    assert hb.json()["config"]["collect_network_snapshot"] is False
    assert hb.json()["config"]["features"]["collector_gates_explicit"] is True

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

    alerts = client.get("/api/v1/admin/alerts?tenant_id=default", headers={"Authorization":"Bearer dev-admin-token"}).json()
    assert len(alerts) == 1
    assert alerts[0]["title"] == "Suspicious encoded PowerShell command"
    assert alerts[0]["raw"]["tenant_id"] == "default"
    assert alerts[0]["raw_ref"]
    assert alerts[0]["raw_hash"]

    task = client.post("/api/v1/admin/tasks", headers={"Authorization":"Bearer dev-admin-token"}, json={"tenant_id": "default", "agent_id": agent_id, "task_type": "process_list", "args": {}})
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

    events = client.get("/api/v1/admin/events?tenant_id=default&host=POS01", headers={"Authorization":"Bearer dev-admin-token"}).json()
    assert len(events) == 1
    assert events[0]["tenant_id"] == "default"
    assert events[0]["raw_ref"]
    assert events[0]["raw_hash"]
    raw = client.get("/api/v1/admin/raw-evidence", headers={"Authorization":"Bearer dev-admin-token"}, params={"tenant_id":"default", "raw_ref": events[0]["raw_ref"]})
    assert raw.status_code == 200
    assert raw.json()["sha256"] == events[0]["raw_hash"]

    hunted = client.get("/api/v1/admin/events?tenant_id=default&indicator=SQBFAFgA", headers={"Authorization":"Bearer dev-admin-token"}).json()
    assert len(hunted) == 1

    process_events = client.get("/api/v1/admin/events?tenant_id=default&event_type=process_start&process_name=powershell", headers={"Authorization":"Bearer dev-admin-token"}).json()
    assert len(process_events) == 1

    tasks = client.get(f"/api/v1/admin/tasks?tenant_id=default&agent_id={agent_id}", headers={"Authorization":"Bearer dev-admin-token"}).json()
    assert tasks[0]["task_id"] == task_id
    assert tasks[0]["status"] == "succeeded"
    assert tasks[0]["raw_ref"]
    assert tasks[0]["raw_hash"]
    task_raw = client.get("/api/v1/admin/raw-evidence", headers={"Authorization":"Bearer dev-admin-token"}, params={"tenant_id":"default", "raw_ref": tasks[0]["raw_ref"]})
    assert task_raw.status_code == 200
    assert task_raw.json()["kind"] == "task_result"

    summary = client.get("/api/v1/admin/summary?tenant_id=default", headers={"Authorization":"Bearer dev-admin-token"})
    assert summary.status_code == 200
    assert summary.json()["counts"]["agents"] == 1
    assert summary.json()["counts"]["events"] == 1
    assert summary.json()["counts"]["alerts"] == 1
    assert summary.json()["task_status"]["succeeded"] == 1


def test_agent_ingest_accepts_windows_collector_sources(tmp_path):
    app = create_app(tmp_path / "windows-collector-sources.sqlite3", create_dev_token=True)
    client = TestClient(app)

    enroll = client.post("/api/v1/enroll", json={
        "enrollment_token": "dev-token",
        "host": "WINCOL01",
        "ip_address": "10.0.0.20",
        "os": "Windows",
        "agent_version": "dev-test",
    })
    assert enroll.status_code == 200, enroll.text
    auth = enroll.json()
    agent_id = auth["agent_id"]
    headers = {"Authorization": f"Bearer {auth['agent_token']}"}

    events = [
        {
            "source": "windows_event_log",
            "event_type": "endpoint_state",
            "tenant_id": "attacker-supplied-tenant-should-be-overridden",
            "host": "WINCOL01",
            "source_event_id": "7045",
            "severity": "info",
            "raw": {
                "collector": "windows_event_log",
                "platform": "windows_evtsubscribe",
                "query": "service_control_manager",
                "event_id": 7045,
                "record_id": 123,
                "message": "A service was installed in the system.",
            },
        },
        {
            "source": "windows_etw",
            "event_type": "process_start",
            "tenant_id": "attacker-supplied-tenant-should-be-overridden",
            "host": "WINCOL01",
            "process_name": "cmd.exe",
            "process_id": "4242",
            "parent_process_id": "1000",
            "severity": "info",
            "raw": {
                "collector": "windows_etw_process",
                "platform": "windows_etw",
                "kind": "process_start",
            },
        },
        {
            "source": "windows_etw",
            "event_type": "process_stop",
            "tenant_id": "attacker-supplied-tenant-should-be-overridden",
            "host": "WINCOL01",
            "process_name": "cmd.exe",
            "process_id": "4242",
            "process_exit_time": "2026-07-16T08:20:00Z",
            "severity": "info",
            "raw": {
                "collector": "windows_etw_process",
                "platform": "windows_etw",
                "kind": "process_stop",
            },
        },
    ]
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events": events})
    assert ingest.status_code == 200, ingest.text
    assert ingest.json() == {"accepted": 3, "alerts_generated": 1}

    listed = client.get("/api/v1/admin/events?tenant_id=default&host=WINCOL01", headers={"Authorization": "Bearer dev-admin-token"}).json()
    assert {event["source"] for event in listed} == {"windows_event_log", "windows_etw"}
    assert {event["event_type"] for event in listed} == {"endpoint_state", "process_start", "process_stop"}
    assert {event["tenant_id"] for event in listed} == {"default"}

    alerts = client.get("/api/v1/admin/alerts?tenant_id=default", headers={"Authorization": "Bearer dev-admin-token"}).json()
    assert [alert["title"] for alert in alerts] == ["Windows service installed"]
