import json
from pathlib import Path

from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}
FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _enroll(client: TestClient, host: str = "GRAPH01"):
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": host, "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    return auth, {"Authorization": f"Bearer {auth['agent_token']}"}


def test_process_graph_api_returns_entity_first_graph_timeline_and_evidence(tmp_path):
    app = create_app(tmp_path / "process-graph.sqlite3", create_dev_token=True)
    client = TestClient(app)
    auth, headers = _enroll(client)
    agent_id = auth["agent_id"]

    fixture = json.loads((FIXTURE_DIR / "process_graph_golden.json").read_text())
    parent_entity = fixture["parent_entity"]
    child_entity = fixture["child_entity"]
    grandchild_entity = fixture["grandchild_entity"]
    reused_pid_entity = fixture["reused_pid_entity"]
    orphan_entity = fixture["orphan_entity"]

    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events": fixture["events"]})
    assert ingest.status_code == 200, ingest.text

    graph = client.get(
        "/api/v1/admin/investigate/process-graph",
        headers=ADMIN,
        params={"tenant_id": "default", "host": "GRAPH01", "process_entity_id": child_entity},
    )
    assert graph.status_code == 200, graph.text
    body = graph.json()

    assert body["identity_mode"] == "process_entity"
    assert body["process"]["process_entity_id"] == child_entity
    assert body["process"]["process_id"] == "200"
    assert body["process"]["parent_process_id"] == "100"
    assert [event["process_entity_id"] for event in body["ancestors"]] == [parent_entity]
    assert [event["process_entity_id"] for event in body["descendants"]] == [grandchild_entity]
    assert reused_pid_entity not in {event["process_entity_id"] for event in body["descendants"]}
    assert body["gaps"] == []

    timeline_entities = [event["process_entity_id"] for event in body["timeline"] if event.get("process_entity_id")]
    assert timeline_entities == [child_entity, child_entity, grandchild_entity, grandchild_entity]
    evidence = body["evidence"]
    assert {item["kind"] for item in evidence} == {"event"}
    assert {item["event_type"] for item in evidence} >= {"network_connection", "file_event"}
    assert all(item["raw_ref"].startswith("object://raw-evidence/default/event/") for item in evidence)

    compat_chain = client.get(
        "/api/v1/admin/investigate/process-chain",
        headers=ADMIN,
        params={"tenant_id": "default", "host": "GRAPH01", "process_entity_id": child_entity},
    )
    assert compat_chain.status_code == 200, compat_chain.text
    assert compat_chain.json()["deprecated_by"] == "/api/v1/admin/investigate/process-graph"

    orphan = client.get(
        "/api/v1/admin/investigate/process-graph",
        headers=ADMIN,
        params={"tenant_id": "default", "host": "GRAPH01", "process_entity_id": orphan_entity},
    )
    assert orphan.status_code == 200, orphan.text
    assert orphan.json()["gaps"] == [
        {
            "process_entity_id": orphan_entity,
            "parent_process_entity_id": None,
            "missing_parent_reason": "agent_restart_gap",
            "process_identity_confidence": "low",
        }
    ]
