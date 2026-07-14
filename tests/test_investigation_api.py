from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def _enroll(client: TestClient, host: str = "INV01"):
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": host, "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    return auth, {"Authorization": f"Bearer {auth['agent_token']}"}


def test_investigation_hunt_context_and_process_chain(tmp_path):
    app = create_app(tmp_path / "investigate.sqlite3", create_dev_token=True)
    client = TestClient(app)
    auth, headers = _enroll(client)
    agent_id = auth["agent_id"]

    events = [
        {"source":"internal", "event_type":"process_start", "tenant_id":"default", "host":"INV01", "process_name":"explorer.exe", "process_id":"100", "command_line":"explorer.exe", "severity":"info", "raw":{"seq":1}},
        {"source":"internal", "event_type":"process_start", "tenant_id":"default", "host":"INV01", "process_name":"powershell.exe", "process_id":"200", "parent_process_id":"100", "command_line":"powershell -enc SQBFAFgA", "severity":"info", "raw":{"seq":2}},
        {"source":"internal", "event_type":"network_connection", "tenant_id":"default", "host":"INV01", "process_name":"powershell.exe", "process_id":"200", "remote_ip":"203.0.113.10", "remote_port":443, "severity":"info", "raw":{"seq":3}},
    ]
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events": events})
    assert ingest.status_code == 200

    hunt = client.get("/api/v1/admin/investigate/hunt", headers=ADMIN, params={"tenant_id":"default", "indicator":"203.0.113.10"})
    assert hunt.status_code == 200
    assert hunt.json()["hosts"] == ["INV01"]
    assert len(hunt.json()["events"]) == 1

    context = client.get("/api/v1/admin/investigate/endpoint-context", headers=ADMIN, params={"tenant_id":"default", "host":"INV01"})
    assert context.status_code == 200
    assert len(context.json()["agents"]) == 1
    assert len(context.json()["recent_events"]) >= 3
    assert "Suspicious encoded PowerShell command" in {a["title"] for a in context.json()["recent_alerts"]}

    chain = client.get("/api/v1/admin/investigate/process-chain", headers=ADMIN, params={"tenant_id":"default", "host":"INV01", "process_id":"200"})
    assert chain.status_code == 200
    names = [e["process_name"] for e in chain.json()["chain"]]
    assert names == ["powershell.exe", "explorer.exe"]

    count = client.get("/api/v1/admin/events/count", headers=ADMIN, params={"tenant_id":"default", "host":"INV01"})
    assert count.status_code == 200
    assert count.json()["count"] == 3

    related = client.get("/api/v1/admin/events/related", headers=ADMIN, params={"tenant_id":"default", "entity_type":"process_id", "value":"200"})
    assert related.status_code == 200
    assert len(related.json()) == 2

    behavior = client.get("/api/v1/admin/investigate/behavior-context", headers=ADMIN, params={"tenant_id":"default", "host":"INV01", "process_id":"200"})
    assert behavior.status_code == 200
    assert behavior.json()["counts_by_type"]["process_start"] == 1
    assert behavior.json()["counts_by_type"]["network_connection"] == 1

    network = client.get("/api/v1/admin/investigate/network-context", headers=ADMIN, params={"tenant_id":"default", "host":"INV01", "process_id":"200"})
    assert network.status_code == 200
    assert network.json()["remotes"] == ["203.0.113.10:443"]


def test_process_entity_identity_is_preserved_and_preferred_for_process_chain(tmp_path):
    app = create_app(tmp_path / "process-identity.sqlite3", create_dev_token=True)
    client = TestClient(app)
    auth, headers = _enroll(client, host="PEI01")
    agent_id = auth["agent_id"]

    parent_entity = "peid:PEI01:boot-a:100:2026-07-14T01:00:00Z"
    child_entity = "peid:PEI01:boot-a:200:2026-07-14T01:02:00Z"
    reused_pid_entity = "peid:PEI01:boot-a:100:2026-07-14T02:00:00Z"
    orphan_entity = "peid:PEI01:boot-a:300:2026-07-14T03:00:00Z"

    events = [
        {
            "source": "internal",
            "event_type": "process_start",
            "tenant_id": "default",
            "host": "PEI01",
            "process_name": "explorer.exe",
            "process_id": "100",
            "process_entity_id": parent_entity,
            "boot_id": "boot-a",
            "process_create_time": "2026-07-14T01:00:00Z",
            "image_path": "C:/Windows/explorer.exe",
            "image_hash": "a" * 64,
            "process_identity_confidence": "high",
            "severity": "info",
            "raw": {"seq": 1},
        },
        {
            "source": "internal",
            "event_type": "process_start",
            "tenant_id": "default",
            "host": "PEI01",
            "process_name": "powershell.exe",
            "process_id": "200",
            "parent_process_id": "100",
            "process_entity_id": child_entity,
            "parent_process_entity_id": parent_entity,
            "boot_id": "boot-a",
            "process_create_time": "2026-07-14T01:02:00Z",
            "image_path": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "image_hash": "b" * 64,
            "process_identity_confidence": "high",
            "command_line": "powershell -enc SQBFAFgA",
            "severity": "info",
            "raw": {"seq": 2},
        },
        {
            "source": "internal",
            "event_type": "process_start",
            "tenant_id": "default",
            "host": "PEI01",
            "process_name": "notepad.exe",
            "process_id": "100",
            "process_entity_id": reused_pid_entity,
            "boot_id": "boot-a",
            "process_create_time": "2026-07-14T02:00:00Z",
            "process_identity_confidence": "high",
            "severity": "info",
            "raw": {"seq": 3},
        },
        {
            "source": "internal",
            "event_type": "process_start",
            "tenant_id": "default",
            "host": "PEI01",
            "process_name": "unknown-parent.exe",
            "process_id": "300",
            "parent_process_id": "999",
            "process_entity_id": orphan_entity,
            "boot_id": "boot-a",
            "process_create_time": "2026-07-14T03:00:00Z",
            "process_identity_confidence": "low",
            "missing_parent_reason": "parent_not_observed",
            "severity": "info",
            "raw": {"seq": 4},
        },
    ]
    ingest = client.post(f"/api/v1/agents/{agent_id}/events", headers=headers, json={"events": events})
    assert ingest.status_code == 200, ingest.text

    listed = client.get("/api/v1/admin/events", headers=ADMIN, params={"tenant_id": "default", "process_entity_id": child_entity})
    assert listed.status_code == 200, listed.text
    assert len(listed.json()) == 1
    assert listed.json()[0]["process_id"] == "200"
    assert listed.json()[0]["process_entity_id"] == child_entity
    assert listed.json()[0]["parent_process_entity_id"] == parent_entity
    assert listed.json()[0]["process_identity_confidence"] == "high"

    related = client.get(
        "/api/v1/admin/events/related",
        headers=ADMIN,
        params={"tenant_id": "default", "entity_type": "process_entity_id", "value": child_entity},
    )
    assert related.status_code == 200, related.text
    assert [event["process_entity_id"] for event in related.json()] == [child_entity]

    parent_related = client.get(
        "/api/v1/admin/events/related",
        headers=ADMIN,
        params={"tenant_id": "default", "entity_type": "parent_process_entity_id", "value": parent_entity},
    )
    assert parent_related.status_code == 200, parent_related.text
    assert [event["process_entity_id"] for event in parent_related.json()] == [child_entity]

    chain = client.get(
        "/api/v1/admin/investigate/process-chain",
        headers=ADMIN,
        params={"tenant_id": "default", "host": "PEI01", "process_entity_id": child_entity},
    )
    assert chain.status_code == 200, chain.text
    body = chain.json()
    assert body["identity_mode"] == "process_entity"
    assert [event["process_entity_id"] for event in body["chain"]] == [child_entity, parent_entity]
    assert [event["process_name"] for event in body["children"]] == []

    orphan_chain = client.get(
        "/api/v1/admin/investigate/process-chain",
        headers=ADMIN,
        params={"tenant_id": "default", "host": "PEI01", "process_entity_id": orphan_entity},
    )
    assert orphan_chain.status_code == 200, orphan_chain.text
    assert orphan_chain.json()["chain"][0]["missing_parent_reason"] == "parent_not_observed"
    assert orphan_chain.json()["gaps"] == [
        {
            "process_entity_id": orphan_entity,
            "parent_process_entity_id": None,
            "missing_parent_reason": "parent_not_observed",
            "process_identity_confidence": "low",
        }
    ]

    legacy_reuse = client.get(
        "/api/v1/admin/investigate/process-chain",
        headers=ADMIN,
        params={"tenant_id": "default", "host": "PEI01", "process_id": "100"},
    )
    assert legacy_reuse.status_code == 200, legacy_reuse.text
    assert legacy_reuse.json()["identity_mode"] == "pid_compat"
    assert legacy_reuse.json()["chain"][0]["process_id"] == "100"
