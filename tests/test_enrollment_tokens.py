from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_enrollment_token_list_redacts_token_secret(tmp_path):
    client = TestClient(create_app(tmp_path / "tokens.sqlite3", create_dev_token=True))

    created = client.post("/api/v1/admin/enrollment-tokens", headers=ADMIN, params={"tenant_id": "default", "max_uses": 3})
    assert created.status_code == 200
    token = created.json()["token"]

    listed = client.get("/api/v1/admin/enrollment-tokens", headers=ADMIN, params={"tenant_id": "default"})
    assert listed.status_code == 200
    rows = listed.json()["tokens"]
    assert any(row["token_prefix"] == f"{token[:6]}..." and row["max_uses"] == 3 for row in rows)
    assert all("token" not in row for row in rows)


def test_enrollment_token_revoke_blocks_future_enrollment(tmp_path):
    client = TestClient(create_app(tmp_path / "tokens-revoke.sqlite3", create_dev_token=True))
    created = client.post("/api/v1/admin/enrollment-tokens", headers=ADMIN, params={"tenant_id": "default"})
    token = created.json()["token"]

    revoked = client.post("/api/v1/admin/enrollment-tokens/revoke", headers=ADMIN, params={"tenant_id": "default", "token": token})
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True

    enroll = client.post("/api/v1/enroll", json={"enrollment_token": token, "host": "REVOKED01", "os": "Windows", "agent_version": "dev"})
    assert enroll.status_code == 401
    assert enroll.json()["detail"] == "invalid_or_revoked_enrollment_token"
