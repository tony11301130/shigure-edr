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
