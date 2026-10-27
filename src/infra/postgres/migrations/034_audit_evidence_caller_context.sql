-- QODIQA PostgreSQL Schema — Migration 034
-- Finding: Non-repudiation proves key-attribution only, not
--          caller-attribution (reconfirms TRUST-1 /)
-- Purpose: Extend audit_chain and evidence_chain_records with the immutable
--          authenticated-caller snapshot (callerId/callerName/environment/
--          credentialType) that /sign bound into the artifact's payload, so
--          exported evidence packages durably prove WHICH authenticated
--          caller requested a signature — not merely which shared tenant key
--          produced it.
--
-- Two tables, one finding (same shape as migration 033):
--   audit_chain            — must carry the same fields entryBuilder.js now
--                             hashes into schemaVersion 4 entries
--                             (CORE_HASH_FIELDS_V4), otherwise a distributed-
--                             mode restart/replica hydration would silently
--                             lose caller_context even though the stored
--                             `canonical`/`hash` still verify (they're frozen
--                             into the canonical string regardless) — see
--                             src/core/audit/distributedOrdering.js and
--                             src/infra/postgres/pg-audit-backend.js.
--   evidence_chain_records  — must carry the field chain.js now hashes into
--                             evidence_hash for schema_version 3 records
--                             (CANONICAL_FIELDS_V3) — see
--                             src/core/evidence/chain.js.
--
-- Design principles (same as migration 033):
--   1. schema_version defaults are untouched by this migration — existing
--      rows keep whatever schema_version they were written under and are
--      NEVER rehashed; computeEvidenceHash()/entryBuilder's hashFieldsFor()
--      dispatch on schema_version and recompute existing rows against the
--      original field set they were actually hashed under.
--   2. No detached/unhashed copy of callerId is added as its own column —
--      that would create a second, unsigned source of truth for a fact that
--      must be tamper-evident. caller_context JSONB is the sole source, and
--      it participates in both hash surfaces (entryBuilder.js's audit-chain
--      hash and chain.js's evidence hash). A functional index is used
--      instead for query performance.
--   3. Idempotent: safe to re-run (IF NOT EXISTS everywhere).

BEGIN;

-- ── audit_chain: PG copy of the ordering-authoritative / dual-write chain ──────

ALTER TABLE audit_chain
    ADD COLUMN IF NOT EXISTS caller_context JSONB;

COMMENT ON COLUMN audit_chain.caller_context IS
    'immutable authenticated-caller snapshot (callerId, callerName, '
    'environment, credentialType) bound into the artifact payload at /sign '
    'time, hash-protected as part of CORE_HASH_FIELDS_V4 for schema_version '
    '= 4 entries (entryBuilder.js). NULL for schema_version < 4, or for an '
    'artifact signed before this remediation shipped (key-attribution only '
    '— see NONREP-1-REMEDIATION-REPORT.md).';

CREATE INDEX IF NOT EXISTS idx_audit_chain_caller_id
    ON audit_chain ((caller_context ->> 'callerId'))
    WHERE caller_context IS NOT NULL;

-- ── evidence_chain_records ──────────────────────────────────────────────────

ALTER TABLE evidence_chain_records
    ADD COLUMN IF NOT EXISTS caller_context JSONB;

COMMENT ON COLUMN evidence_chain_records.caller_context IS
    'copy of the audit entry''s caller_context (see above), part '
    'of the hashed evidence_hash payload for schema_version >= 3 '
    '(CANONICAL_FIELDS_V3, src/core/evidence/chain.js). NULL when the source '
    'audit entry has none.';

CREATE INDEX IF NOT EXISTS idx_evidence_caller_id
    ON evidence_chain_records ((caller_context ->> 'callerId'))
    WHERE caller_context IS NOT NULL;

COMMIT;
