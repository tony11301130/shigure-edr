import builtins

import pytest
from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app
from open_edr_mdr_agent.api.store import SQLiteStore


def _production_test_store(tmp_path, name: str) -> SQLiteStore:
    return SQLiteStore(tmp_path / name)


def test_server_requires_explicit_profile_when_environment_is_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("OPEN_EDR_MDR_PROFILE", raising=False)

    with pytest.raises(ValueError, match="profile_required"):
        create_app(tmp_path / "missing-profile.sqlite3")


def test_production_profile_rejects_implicit_dev_enrollment_token_creation(tmp_path):
    with pytest.raises(ValueError, match="production_create_dev_token"):
        create_app(
            tmp_path / "prod-dev-token-creation.sqlite3",
            profile="production",
            admin_token="operator-admin-token",
            enrollment_token="tenant-bootstrap-token",
            server_trust="system",
            create_dev_token=True,
        )


def test_production_profile_omits_implicit_dev_enrollment_token(tmp_path):
    client = TestClient(
        create_app(
            tmp_path / "prod-no-implicit-token.sqlite3",
            profile="production",
            admin_token="operator-admin-token",
            enrollment_token="tenant-bootstrap-token",
            server_trust="system",
            store=_production_test_store(tmp_path, "prod-no-implicit-token.sqlite3"),
        )
    )

    tokens = client.get(
        "/api/v1/admin/enrollment-tokens",
        headers={"Authorization": "Bearer operator-admin-token"},
        params={"tenant_id": "default"},
    )

    assert tokens.status_code == 200
    assert tokens.json()["tokens"] == []


def test_production_profile_requires_postgresql_control_plane_store(tmp_path, monkeypatch):
    monkeypatch.delenv("OPEN_EDR_MDR_CONTROL_PLANE_STORE", raising=False)
    monkeypatch.delenv("OPEN_EDR_MDR_POSTGRES_DSN", raising=False)

    with pytest.raises(ValueError, match="production_postgresql_dsn_required"):
        create_app(
            tmp_path / "prod-sqlite-control-plane.sqlite3",
            profile="production",
            admin_token="operator-admin-token",
            enrollment_token="tenant-bootstrap-token",
            server_trust="system",
        )


def test_postgresql_control_plane_profile_requires_postgresql_driver(tmp_path, monkeypatch):
    monkeypatch.setenv("OPEN_EDR_MDR_CONTROL_PLANE_STORE", "postgresql")
    monkeypatch.setenv("OPEN_EDR_MDR_POSTGRES_DSN", "postgresql://shigure:shigure@127.0.0.1:65432/shigure")
    real_import = builtins.__import__

    def import_without_psycopg(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "psycopg" or name.startswith("psycopg."):
            raise ModuleNotFoundError("No module named 'psycopg'")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_without_psycopg)

    with pytest.raises(ValueError, match="postgresql_driver_missing"):
        create_app(
            tmp_path / "ignored-postgres.sqlite3",
            profile="production",
            admin_token="operator-admin-token",
            enrollment_token="tenant-bootstrap-token",
            server_trust="system",
        )


def test_production_profile_rejects_default_admin_token(tmp_path):
    with pytest.raises(ValueError, match="production_admin_token"):
        create_app(
            tmp_path / "prod-default-admin.sqlite3",
            profile="production",
            admin_token="dev-admin-token",
            enrollment_token="tenant-bootstrap-token",
            server_trust="system",
        )


def test_production_profile_rejects_default_enrollment_token(tmp_path):
    with pytest.raises(ValueError, match="production_enrollment_token"):
        create_app(
            tmp_path / "prod-default-enrollment.sqlite3",
            profile="production",
            admin_token="operator-admin-token",
            enrollment_token="dev-token",
            server_trust="system",
        )


def test_production_profile_requires_server_trust(tmp_path):
    with pytest.raises(ValueError, match="production_server_trust"):
        create_app(
            tmp_path / "prod-missing-trust.sqlite3",
            profile="production",
            admin_token="operator-admin-token",
            enrollment_token="tenant-bootstrap-token",
        )


def test_production_deployment_download_rejects_http_server_url(tmp_path):
    client = TestClient(
        create_app(
            tmp_path / "prod-download.sqlite3",
            create_dev_token=False,
            profile="production",
            admin_token="operator-admin-token",
            enrollment_token="tenant-bootstrap-token",
            server_trust="system",
            store=_production_test_store(tmp_path, "prod-download.sqlite3"),
        )
    )

    res = client.get(
        "/api/v1/admin/downloads/agent-config",
        headers={"Authorization": "Bearer operator-admin-token"},
        params={"tenant_id": "default", "server_url": "http://edr.intra"},
    )

    assert res.status_code == 400
    assert res.json()["detail"] == "production_requires_https_server_url"


def test_production_task_policy_blocks_destructive_tasks(tmp_path):
    client = TestClient(
        create_app(
            tmp_path / "prod-task-policy.sqlite3",
            create_dev_token=False,
            profile="production",
            admin_token="operator-admin-token",
            enrollment_token="tenant-bootstrap-token",
            server_trust="system",
            store=_production_test_store(tmp_path, "prod-task-policy.sqlite3"),
        )
    )
    token = client.post(
        "/api/v1/admin/enrollment-tokens",
        headers={"Authorization": "Bearer operator-admin-token"},
        params={"tenant_id": "default", "max_uses": 1},
    ).json()["token"]
    enrolled = client.post(
        "/api/v1/enroll",
        json={"enrollment_token": token, "host": "PROD-TASK01", "os": "Windows", "agent_version": "dev"},
    ).json()

    blocked = client.post(
        "/api/v1/admin/tasks",
        headers={"Authorization": "Bearer operator-admin-token"},
        json={"tenant_id": "default", "agent_id": enrolled["agent_id"], "task_type": "delete_file", "args": {"path": "C:/x", "confirm_sha256": "0" * 64}},
    )
    allowed = client.post(
        "/api/v1/admin/tasks",
        headers={"Authorization": "Bearer operator-admin-token"},
        json={"tenant_id": "default", "agent_id": enrolled["agent_id"], "task_type": "inventory", "args": {}},
    )
    catalog = client.get("/api/v1/admin/task-catalog", headers={"Authorization": "Bearer operator-admin-token"}).json()["tasks"]

    assert blocked.status_code == 200
    assert blocked.json()["status"] == "blocked_by_policy"
    assert blocked.json()["error"] == "destructive_task_blocked"
    assert blocked.json()["result"]["policy_version"] == "read_only_v1"
    assert allowed.status_code == 200, allowed.text
    assert "delete_file" not in {item["task_type"] for item in catalog}
    assert "copy_file" not in {item["task_type"] for item in catalog}


def test_dev_profile_keeps_local_http_and_dev_credentials_usable(tmp_path):
    client = TestClient(create_app(tmp_path / "dev-download.sqlite3", profile="dev", create_dev_token=True))

    res = client.get(
        "/api/v1/admin/downloads/agent-config",
        headers={"Authorization": "Bearer dev-admin-token"},
        params={"tenant_id": "default", "server_url": "http://127.0.0.1:8765"},
    )

    assert res.status_code == 200
    assert res.json()["server_url"] == "http://127.0.0.1:8765"
