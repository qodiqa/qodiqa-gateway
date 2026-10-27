-- QODIQA PostgreSQL Migration 025
-- remediation: durable key attribution for live executions.
--
-- Root cause ( and
--/§5): the signing key that
-- authorized a decision was never persisted as a protected, hash-chained
-- field on the audit chain entry — only as an unprotected sub-field of the
-- optional executionContext JSONB blob (or omitted entirely). This meant an
-- investigator could not durably or verifiably determine which key produced
-- a given historical execution.
--
-- src/core/audit/audit-log.js now writes a top-level, hash-protected
-- `publicKeyId` field (and a `schemaVersion` marker distinguishing entries
-- hashed under the new 11-field set from legacy 9-field entries) on every
-- new audit chain entry. This migration adds the matching columns to the
-- PostgreSQL mirror so the durable, queryable copy carries the same
-- attribution the file-based chain (the authoritative MANDATORY store)
-- already protects.
--
-- Both columns are NULLable with a default that exactly matches what
-- audit-log.js does for pre-existing entries (schema_version defaults to 1,
-- the implicit legacy version; public_key_id defaults to NULL, matching
-- entries where no field existed at all) — existing rows are unaffected and
-- remain fully readable; nothing about them is reinterpreted or backfilled.
--
-- IDEMPOTENT: ADD COLUMN IF NOT EXISTS; CREATE INDEX IF NOT EXISTS.
-- No RLS/grant changes needed — qodiqa_app already holds table-level
-- SELECT/INSERT on audit_chain (migration 002), which covers new columns
-- automatically; audit_chain remains INSERT/SELECT-only (no UPDATE/DELETE).

BEGIN;

ALTER TABLE audit_chain
  ADD COLUMN IF NOT EXISTS public_key_id  VARCHAR(256),
  ADD COLUMN IF NOT EXISTS schema_version SMALLINT NOT NULL DEFAULT 1;

-- Supports "which decisions did this key authorize" forensic/compliance
-- queries (e.g. a key-compromise investigation) without a full table scan.
CREATE INDEX IF NOT EXISTS idx_audit_chain_public_key_id
  ON audit_chain (public_key_id, recorded_at DESC)
  WHERE public_key_id IS NOT NULL;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (25, 'audit_chain_key_attribution', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
