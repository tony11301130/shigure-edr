from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app


def test_agent_health_detection_generates_gap_alert(tmp_path):
    app = create_app(tmp_path / "health.sqlite3", create_dev_token=True)
    client = TestClient(app)
    res = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "STALE01", "os": "Windows", "agent_version": "dev"})
    assert res.status_code == 200
    agent_id = res.json()["agent_id"]

    with app.state.store.connect() as conn:
        conn.execute("update agents set last_seen='2000-01-01T00:00:00+00:00' where agent_id=?", (agent_id,))

    run = client.post("/api/v1/admin/detections/agent-health?tenant_id=default&stale_after_seconds=60")
    assert run.status_code == 200
    assert run.json()["alerts_generated"] == 1

    alerts = client.get("/api/v1/admin/alerts?tenant_id=default").json()
    assert alerts[0]["title"] == "Agent offline or telemetry gap"
    assert alerts[0]["raw"]["agent_id"] == agent_id
