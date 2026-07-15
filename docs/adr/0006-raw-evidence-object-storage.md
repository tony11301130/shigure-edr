# ADR 0006: Raw Evidence Object Storage

Date: 2026-07-15

## Status

Accepted

## Context

Shigure's MDR investigation loop now links alerts, task results, case evidence,
and handoff exports through `raw_ref` values. The SQLite prototype previously
stored raw evidence payload JSON directly in the `raw_evidence` table and used
`sqlite://raw_evidence/...` references. That is acceptable for a local demo, but
not for a commercial MVP where file chunks, collect-file outputs, task result
payloads, and event exports can become large and need object lifecycle controls.

## Decision

Raw evidence payloads are stored behind a raw object storage adapter. The SQL
row is now an index and metadata record:

- `raw_ref`
- `tenant_id`
- `kind`
- `sha256`
- `size`
- `mime_type`
- `storage_provider`
- `object_key`
- `metadata_json`
- `created_at`

Local development and smoke tests use a filesystem-backed adapter with
`object://raw-evidence/...` refs. S3-compatible deployments use the same adapter
seam with `s3://<bucket>/...` refs and provider metadata, so MinIO or another
S3-compatible implementation can replace the backing store without changing the
case/evidence APIs.

Configuration is read from:

- `OPEN_EDR_MDR_RAW_OBJECT_STORE_PROVIDER`: `local` or `s3_compatible`
- `OPEN_EDR_MDR_RAW_OBJECT_STORE_BUCKET`
- `OPEN_EDR_MDR_RAW_OBJECT_STORE_ROOT`
- `OPEN_EDR_MDR_RAW_OBJECT_STORE_ENDPOINT`

Admins can inspect the active raw evidence storage profile via
`/api/v1/admin/raw-evidence/storage-config`.

## Retention And Deletion

The default MVP retention policy is:

- Raw evidence blobs: 180 days.
- Case-pinned evidence: retain while the case is open and for the case retention
  period after close.
- Metadata rows remain in the control plane for audit and handoff while the case
  or workflow record is retained.

Deletion should be two-phase in production:

1. Expire or delete the object according to bucket lifecycle rules.
2. Keep the SQL metadata row as a tombstone/audit reference until the related
   workflow retention period expires.

If an object is missing while metadata remains, API fetch should treat that as a
storage integrity issue rather than silently deleting the evidence link. The MVP
does not yet implement automated lifecycle deletion; deployment operators should
configure S3-compatible lifecycle policies for the raw evidence bucket.

## Consequences

- Existing local tests and demos keep working through the local adapter.
- New raw refs no longer imply SQLite storage.
- Case evidence links can carry object metadata without loading payload content.
- A future MinIO/S3 SDK adapter can be added behind the same store seam.
