import base64
import hashlib
import sqlite3

from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_agent_evidence_uses_configured_s3_compatible_object_refs(tmp_path, monkeypatch):
    object_root = tmp_path / "objects"
    monkeypatch.setenv("OPEN_EDR_MDR_RAW_OBJECT_STORE_PROVIDER", "s3_compatible")
    monkeypatch.setenv("OPEN_EDR_MDR_RAW_OBJECT_STORE_BUCKET", "shigure-evidence")
    monkeypatch.setenv("OPEN_EDR_MDR_RAW_OBJECT_STORE_ROOT", str(object_root))
    monkeypatch.setenv("OPEN_EDR_MDR_RAW_OBJECT_STORE_ENDPOINT", "http://minio.local:9000")
    client = TestClient(create_app(tmp_path / "object-storage.sqlite3", profile="dev", create_dev_token=True))
    enrolled = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "OBJ01", "os": "Windows", "agent_version": "dev"}).json()
    data = b"object evidence"
    sha = hashlib.sha256(data).hexdigest()

    upload = client.post(
        f"/api/v1/agents/{enrolled['agent_id']}/evidence",
        headers={"Authorization": f"Bearer {enrolled['agent_token']}"},
        json={
            "kind": "file",
            "path": "C:/Temp/object.txt",
            "sha256": sha,
            "size": len(data),
            "content_base64": base64.b64encode(data).decode(),
            "metadata": {"reason": "triage", "case_id": "case-obj", "requester": "analyst@example.test"},
        },
    )

    assert upload.status_code == 200, upload.text
    raw_ref = upload.json()["raw_ref"]
    assert raw_ref.startswith("s3://shigure-evidence/default/agent_file/")
    assert upload.json()["size"] == len(data)

    listed = client.get("/api/v1/admin/raw-evidence/list", headers=ADMIN, params={"tenant_id": "default", "kind": "agent_file"})
    assert listed.status_code == 200, listed.text
    listed_item = listed.json()["evidence"][0]
    assert listed_item["raw_ref"] == raw_ref
    assert listed_item["storage_provider"] == "s3_compatible"
    assert listed_item["object_key"].startswith("default/agent_file/")
    assert listed_item["size"] > 0
    assert listed_item["metadata"]["case_id"] == "case-obj"
    assert listed_item["metadata"]["reason"] == "triage"
    assert "payload" not in listed_item

    fetched = client.get("/api/v1/admin/raw-evidence", headers=ADMIN, params={"tenant_id": "default", "raw_ref": raw_ref})
    assert fetched.status_code == 200, fetched.text
    body = fetched.json()
    assert body["storage_provider"] == "s3_compatible"
    assert body["object_key"] == listed_item["object_key"]
    assert body["payload"]["path"] == "C:/Temp/object.txt"
    assert body["payload"]["metadata"]["requester"] == "analyst@example.test"

    with sqlite3.connect(tmp_path / "object-storage.sqlite3") as conn:
        row = conn.execute("select payload_json, object_key, storage_provider from raw_evidence where raw_ref=?", (raw_ref,)).fetchone()
    assert row == ("", listed_item["object_key"], "s3_compatible")

    by_hash = client.get(f"/api/v1/admin/raw-evidence/by-hash/{sha}", headers=ADMIN, params={"tenant_id": "default"})
    assert by_hash.status_code == 200, by_hash.text
    assert by_hash.json()["raw_ref"] == raw_ref

    config = client.get("/api/v1/admin/raw-evidence/storage-config", headers=ADMIN)
    assert config.status_code == 200, config.text
    assert config.json() == {
        "storage_provider": "s3_compatible",
        "bucket": "shigure-evidence",
        "endpoint_url": "http://minio.local:9000",
        "raw_ref_scheme": "s3",
    }


def test_case_alert_evidence_links_include_object_metadata(tmp_path):
    client = TestClient(create_app(tmp_path / "case-object-link.sqlite3", profile="dev", create_dev_token=True))
    enrolled = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "OBJCASE01", "os": "Windows", "agent_version": "dev"}).json()
    headers = {"Authorization": f"Bearer {enrolled['agent_token']}"}
    event = {
        "source": "internal",
        "event_type": "process_start",
        "tenant_id": "default",
        "host": "OBJCASE01",
        "process_name": "powershell.exe",
        "command_line": "powershell -enc SQBFAFgA",
        "severity": "info",
        "raw": {"source": "case-link-test"},
    }
    ingest = client.post(f"/api/v1/agents/{enrolled['agent_id']}/events", headers=headers, json={"events": [event]})
    assert ingest.status_code == 200, ingest.text
    alert = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default"}).json()[0]

    created = client.post(
        "/api/v1/admin/cases",
        headers=ADMIN,
        json={"tenant_id": "default", "title": "Object linked case", "severity": "high", "alert_id": alert["alert_id"]},
    )
    assert created.status_code == 200, created.text
    fetched = client.get(f"/api/v1/admin/cases/{created.json()['case_id']}", headers=ADMIN, params={"tenant_id": "default"})
    raw_link = next(item for item in fetched.json()["evidence"] if item["evidence_type"] == "raw_evidence")

    assert raw_link["ref_id"].startswith("object://raw-evidence/default/alert/")
    assert raw_link["data"]["raw_hash"] == alert["raw_hash"]
    assert raw_link["data"]["storage_provider"] == "local"
    assert raw_link["data"]["object_key"].startswith("default/alert/")
    assert raw_link["data"]["size"] > 0
