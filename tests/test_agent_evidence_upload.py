import base64
import hashlib

from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def _enrolled_client(tmp_path, db_name="evidence-upload.sqlite3"):
    client = TestClient(create_app(tmp_path / db_name, create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "EVD01", "os": "Windows", "agent_version": "dev"})
    assert enroll.status_code == 200
    return client, enroll.json()["agent_id"], enroll.json()["agent_token"]


def test_agent_evidence_upload_is_raw_evidence_and_hash_searchable(tmp_path):
    client, agent_id, token = _enrolled_client(tmp_path)
    data = b"hello evidence"
    sha = hashlib.sha256(data).hexdigest()

    upload = client.post(
        f"/api/v1/agents/{agent_id}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        json={"kind": "file", "path": "C:/Temp/evidence.txt", "sha256": sha, "size": len(data), "content_base64": base64.b64encode(data).decode(), "metadata": {"source": "test", "reason": "triage", "case_id": "case-1"}},
    )
    assert upload.status_code == 200, upload.text
    raw_ref = upload.json()["raw_ref"]
    assert upload.json()["sha256"] == sha

    fetched = client.get("/api/v1/admin/raw-evidence", headers=ADMIN, params={"tenant_id": "default", "raw_ref": raw_ref})
    assert fetched.status_code == 200
    assert fetched.json()["sha256"] == sha
    assert fetched.json()["payload"]["path"] == "C:/Temp/evidence.txt"

    by_hash = client.get(f"/api/v1/admin/raw-evidence/by-hash/{sha}", headers=ADMIN, params={"tenant_id": "default"})
    assert by_hash.status_code == 200
    assert by_hash.json()["raw_ref"] == raw_ref


def test_agent_evidence_upload_rejects_mismatched_hash(tmp_path):
    client, agent_id, token = _enrolled_client(tmp_path, "evidence-upload-bad-hash.sqlite3")
    upload = client.post(
        f"/api/v1/agents/{agent_id}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        json={"kind": "file", "path": "C:/Temp/evidence.txt", "sha256": "0" * 64, "size": 5, "content_base64": base64.b64encode(b"hello").decode(), "metadata": {"reason": "triage", "case_id": "case-1"}},
    )
    assert upload.status_code == 400
    assert upload.json()["detail"] == "evidence_sha256_mismatch"


def test_agent_evidence_upload_requires_reason_and_case_context(tmp_path):
    client, agent_id, token = _enrolled_client(tmp_path, "evidence-upload-audit.sqlite3")
    data = b"hello evidence"
    sha = hashlib.sha256(data).hexdigest()

    upload = client.post(
        f"/api/v1/agents/{agent_id}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        json={"kind": "file", "path": "C:/Temp/evidence.txt", "sha256": sha, "size": len(data), "content_base64": base64.b64encode(data).decode(), "metadata": {"reason": "triage"}},
    )

    assert upload.status_code == 400
    assert upload.json()["detail"] == "evidence_case_id_required"
