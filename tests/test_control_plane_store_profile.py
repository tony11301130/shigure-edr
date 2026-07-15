from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_admin_storage_profile_reports_sqlite_dev_control_plane(tmp_path):
    client = TestClient(create_app(tmp_path / "store-profile.sqlite3", profile="dev", create_dev_token=True))

    res = client.get("/api/v1/admin/storage-profile", headers=ADMIN)

    assert res.status_code == 200, res.text
    assert res.json() == {
        "profile": "dev",
        "control_plane_store": "sqlite",
        "telemetry_projection": {
            "storage_provider": "sqlite",
            "retention": {},
        },
        "raw_object_store": {
            "storage_provider": "local",
            "bucket": "raw-evidence",
            "endpoint_url": None,
            "raw_ref_scheme": "object",
        },
    }
