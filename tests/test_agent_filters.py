from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_agent_list_filters_by_status(tmp_path):
    app = create_app(tmp_path / "agent-filters.sqlite3", create_dev_token=True)
    client = TestClient(app)

    stale = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "STALE01", "os": "Windows", "agent_version": "dev"})
    live = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "LIVE01", "os": "Windows", "agent_version": "dev"})
    assert stale.status_code == 200
    assert live.status_code == 200

    with app.state.store.connect() as conn:
        conn.execute("update agents set status='offline' where agent_id=?", (stale.json()["agent_id"],))

    offline = client.get("/api/v1/admin/agents", headers=ADMIN, params={"tenant_id": "default", "status": "offline"})
    assert offline.status_code == 200
    assert [agent["host"] for agent in offline.json()["agents"]] == ["STALE01"]

    online = client.get("/api/v1/admin/agents", headers=ADMIN, params={"tenant_id": "default", "status": "online"})
    assert online.status_code == 200
    assert [agent["host"] for agent in online.json()["agents"]] == ["LIVE01"]
