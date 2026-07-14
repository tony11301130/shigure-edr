from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_agent_heartbeat_spool_health_is_visible_to_admin(tmp_path):
    client = TestClient(create_app(tmp_path / "spool-health.sqlite3", create_dev_token=True))
    enrolled = client.post(
        "/api/v1/enroll",
        json={"enrollment_token": "dev-token", "host": "SPOOL01", "os": "Windows", "agent_version": "dev"},
    )
    assert enrolled.status_code == 200, enrolled.text
    auth = enrolled.json()

    heartbeat = client.post(
        f"/api/v1/agents/{auth['agent_id']}/heartbeat",
        headers={"Authorization": f"Bearer {auth['agent_token']}"},
        json={
            "host": "SPOOL01",
            "os": "Windows",
            "agent_version": "dev",
            "health": {
                "status": "ok",
                "spool": {
                    "bytes": 2048,
                    "records": 3,
                    "pressure_state": "pressure",
                    "dropped_records": 2,
                    "oldest_record_age_seconds": 47,
                    "uploaded_records": 5,
                    "retried_records": 1,
                },
            },
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text

    agent = client.get(f"/api/v1/admin/agents/{auth['agent_id']}", headers=ADMIN, params={"tenant_id": "default"})
    assert agent.status_code == 200, agent.text
    assert agent.json()["health"]["spool"]["pressure_state"] == "pressure"
    assert agent.json()["health"]["spool"]["dropped_records"] == 2
    assert agent.json()["health"]["spool"]["oldest_record_age_seconds"] == 47

    listing = client.get("/api/v1/admin/agents", headers=ADMIN, params={"tenant_id": "default"})
    assert listing.status_code == 200, listing.text
    assert listing.json()["agents"][0]["health"]["spool"]["records"] == 3
