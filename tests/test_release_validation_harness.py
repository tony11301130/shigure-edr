import copy
import json
from pathlib import Path

from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app
from open_edr_mdr_agent.api.release_validation import load_release_report, validate_release_report

ADMIN = {"Authorization": "Bearer dev-admin-token"}
FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "release_validation_golden.json").read_text())


def _enroll(client: TestClient, host: str):
    enroll = client.post(
        "/api/v1/enroll",
        json={"enrollment_token": "dev-token", "host": host, "os": "Windows", "agent_version": "release-validation"},
    )
    assert enroll.status_code == 200, enroll.text
    auth = enroll.json()
    return auth, {"Authorization": f"Bearer {auth['agent_token']}"}


def test_release_gate_manifest_fails_closed_on_missing_evidence_and_blockers():
    ok = validate_release_report(FIXTURE["release_report_example"])
    assert ok["status"] == "passed"
    assert ok["failures"] == []
    assert validate_release_report(load_release_report(Path(__file__).parent / "fixtures" / "release_report_example.json"))["status"] == "passed"

    broken = copy.deepcopy(FIXTURE["release_report_example"])
    broken["automated_gates"].pop("golden_dataset_replay")
    broken["known_gap_review"]["blockers"]["silent_graph_uncertainty"] = True
    broken["load_scenarios"] = [scenario for scenario in broken["load_scenarios"] if scenario["id"] != "process_graph"]
    result = validate_release_report(broken)

    assert result["status"] == "failed"
    assert "missing_gate:golden_dataset_replay" in result["failures"]
    assert "release_blocker:silent_graph_uncertainty" in result["failures"]
    assert "missing_load_scenario:process_graph" in result["failures"]


def test_golden_process_graph_replay_asserts_entity_identity_gaps_and_timeline(tmp_path):
    graph_fixture = FIXTURE["process_graph"]
    client = TestClient(create_app(tmp_path / "release-graph.sqlite3", create_dev_token=True))
    auth, headers = _enroll(client, graph_fixture["host"])

    ingest = client.post(f"/api/v1/agents/{auth['agent_id']}/events", headers=headers, json={"events": graph_fixture["events"]})
    assert ingest.status_code == 200, ingest.text

    for expectation in graph_fixture["expectations"].values():
        response = client.get(
            "/api/v1/admin/investigate/process-graph",
            headers=ADMIN,
            params={
                "tenant_id": "default",
                "host": graph_fixture["host"],
                "process_entity_id": expectation["process_entity_id"],
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert [event["process_entity_id"] for event in body["ancestors"]] == expectation["ancestors"]
        assert [event["process_entity_id"] for event in body["descendants"]] == expectation["descendants"]
        assert body["gaps"] == expectation["gaps"]
        if "timeline_event_types" in expectation:
            assert [event["event_type"] for event in body["timeline"]] == expectation["timeline_event_types"]


def test_detection_replay_dataset_generates_expected_mvp_alerts(tmp_path):
    client = TestClient(create_app(tmp_path / "release-detection.sqlite3", create_dev_token=True))
    auth, headers = _enroll(client, "REL-DET01")

    for scenario in FIXTURE["detection_replay"]:
        ingest = client.post(f"/api/v1/agents/{auth['agent_id']}/events", headers=headers, json={"events": scenario["events"]})
        assert ingest.status_code == 200, ingest.text
        assert ingest.json()["alerts_generated"] >= len(scenario["expected_alerts"])

    alerts = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "limit": 100}).json()
    titles = {alert["title"] for alert in alerts}
    for scenario in FIXTURE["detection_replay"]:
        assert set(scenario["expected_alerts"]).issubset(titles)


def test_release_workflow_replay_preserves_audited_evidence_and_handoff(tmp_path):
    client = TestClient(create_app(tmp_path / "release-workflow.sqlite3", create_dev_token=True))
    auth, headers = _enroll(client, "REL-WORK01")
    agent_id = auth["agent_id"]
    parent_entity = "peid:REL-WORK01:boot-w1:100:2026-07-15T04:00:00Z"
    child_entity = "peid:REL-WORK01:boot-w1:200:2026-07-15T04:01:00Z"

    events = [
        {
            "source": "internal",
            "event_type": "process_start",
            "tenant_id": "default",
            "host": "REL-WORK01",
            "process_name": "explorer.exe",
            "process_id": "100",
            "process_entity_id": parent_entity,
            "process_identity_confidence": "high",
            "severity": "info",
            "raw": {"release_workflow": "parent"},
        },
        {
            "source": "internal",
            "event_type": "process_start",
            "tenant_id": "default",
            "host": "REL-WORK01",
            "process_name": "powershell.exe",
            "process_id": "200",
            "parent_process_id": "100",
            "process_entity_id": child_entity,
            "parent_process_entity_id": parent_entity,
            "command_line": "powershell -enc SQBFAFgA",
            "user": "ACME\\release",
            "process_identity_confidence": "high",
            "severity": "info",
            "raw": {"release_workflow": "alert_source"},
        },
        {
            "source": "internal",
            "event_type": "network_connection",
            "tenant_id": "default",
            "host": "REL-WORK01",
            "process_name": "powershell.exe",
            "process_id": "200",
            "process_entity_id": child_entity,
            "remote_ip": "203.0.113.10",
            "remote_port": 443,
            "user": "ACME\\release",
            "severity": "info",
            "raw": {"release_workflow": "network"},
        },
    ]
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events": events})
    assert ingest.status_code == 200, ingest.text

    alerts = client.get(
        "/api/v1/admin/alerts",
        headers=ADMIN,
        params={"tenant_id": "default", "title": "Suspicious encoded PowerShell command"},
    ).json()
    workspace = client.post(
        "/api/v1/admin/investigate/workspace/start",
        headers=ADMIN,
        json={"tenant_id": "default", "alert_id": alerts[0]["alert_id"], "assignee": "release-owner", "priority": "high"},
    )
    assert workspace.status_code == 200, workspace.text
    case = workspace.json()["case"]
    assert workspace.json()["process_graph"]["gaps"] == []

    task = client.post(
        "/api/v1/admin/tasks",
        headers=ADMIN,
        json={
            "tenant_id": "default",
            "agent_id": agent_id,
            "task_type": "read_file_chunk",
            "args": {"path": "C:/Temp/release.ps1", "offset": 0, "max_bytes": 256, "reason": "release validation", "case_id": case["case_id"]},
            "requested_by": "release-owner",
        },
    )
    assert task.status_code == 200, task.text
    completed = client.post(
        f"/api/v1/agents/{agent_id}/tasks/{task.json()['task_id']}/result",
        headers=headers,
        json={"status": "succeeded", "result": {"path": "C:/Temp/release.ps1", "size": 256, "sha256": "b" * 64}},
    )
    assert completed.status_code == 200, completed.text

    attached = client.post(
        "/api/v1/admin/investigate/workspace/attach-task-evidence",
        headers=ADMIN,
        json={"tenant_id": "default", "case_id": case["case_id"], "task_id": task.json()["task_id"], "summary": "Release validation evidence"},
    )
    assert attached.status_code == 200, attached.text
    evidence = attached.json()
    assert evidence["data"]["raw_ref"].startswith("object://raw-evidence/default/task_result/")
    assert evidence["data"]["raw_hash"]
    assert evidence["data"]["audit"]["reason"] == "release validation"

    closed = client.patch(
        f"/api/v1/admin/cases/{case['case_id']}",
        headers=ADMIN,
        params={"tenant_id": "default"},
        json={"status": "closed", "classification": "true_positive", "summary": "Release validation workflow complete."},
    )
    assert closed.status_code == 200, closed.text
    handoff = client.get(f"/api/v1/admin/cases/{case['case_id']}/handoff", headers=ADMIN, params={"tenant_id": "default"})
    assert handoff.status_code == 200, handoff.text
    body = handoff.json()
    assert body["case"]["classification"] == "true_positive"
    assert body["raw_evidence_refs"]
    assert all(ref["raw_hash"] for ref in body["raw_evidence_refs"])


def test_release_load_scenarios_cover_mvp_query_paths():
    scenario_ids = {scenario["id"] for scenario in FIXTURE["load_scenarios"]}
    assert {"alert_queue", "endpoint_timeline", "process_graph", "indicator_hunt", "case_evidence"} == scenario_ids
    assert all(scenario["query_path"].startswith("/api/v1/admin/") for scenario in FIXTURE["load_scenarios"])
    assert all(scenario["metric_targets"] for scenario in FIXTURE["load_scenarios"])
