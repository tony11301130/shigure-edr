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
