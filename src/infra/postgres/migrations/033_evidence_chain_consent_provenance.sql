-- QODIQA PostgreSQL Schema — Migration 033
-- Finding: TRACE-2 — Consent-record linkage absent from Audit Chain and Evidence Chain
-- Purpose: Extend audit_chain and evidence_chain_records with the immutable
--          consent-record and policy-rule provenance that authorized the
--          underlying decision, so exported evidence packages are fully
--          self-contained and offline verifiers no longer need to correlate
--          against the live consent registry or policy store.
--
-- Two tables, one finding:
--   audit_chain            — PostgreSQL's copy of the in-memory/NDJSON audit
--                             chain (src/infra/postgres/pg-audit-backend.js,
--                             src/core/audit/distributedOrdering.js). In
--                             QODIQA_AUDIT_ORDERING_MODE=distributed this
--                             table IS the ordering authority, so it must
--                             carry the same fields entryBuilder.js now hashes
--                             into schemaVersion 3 entries — otherwise a
--                             restart/replica hydration would silently lose
--                             consentProvenance/policyDecision even though the
--                             stored `canonical`/`hash` still verify (they're
--                             frozen into the canonical string regardless).
--   evidence_chain_records  — see the section below (unchanged from the
--                             original plan for this migration).
--
-- Design principles:
--   1. schema_version defaults to 1 for every existing row via ADD COLUMN ...
--      DEFAULT — Postgres backfills it for free. Historical rows are NEVER
--      rehashed: chain.js's computeEvidenceHash() dispatches on schema_version
--      and recomputes existing rows against the original (pre-TRACE-2) field
--      set, exactly as entryBuilder.js already does for audit chain
--      schemaVersion 1/2/3.
--   2. No detached/unhashed copy of consentId is added as its own column —
--      that would create a second, unsigned source of truth for a fact that
--      must be tamper-evident. consent_provenance/policy_decision JSONB are
--      the sole source, and they participate in the evidence_hash via
--      chain.js's CANONICAL_FIELDS_V2. A functional index is used instead for
--      query performance.
--   3. Idempotent: safe to re-run (IF NOT EXISTS everywhere).

BEGIN;

-- ── audit_chain: PG copy of the ordering-authoritative / dual-write chain ──────

ALTER TABLE audit_chain
    ADD COLUMN IF NOT EXISTS consent_provenance JSONB,
    ADD COLUMN IF NOT EXISTS policy_decision    JSONB;

COMMENT ON COLUMN audit_chain.consent_provenance IS
    'TRACE-2: immutable consent record snapshot, hash-protected as part of '
    'CORE_HASH_FIELDS_V3 for schema_version = 3 entries (entryBuilder.js). '
    'NULL for schema_version < 3 or when no REQUIRE_CONSENT policy applied.';

COMMENT ON COLUMN audit_chain.policy_decision IS
    'TRACE-2: immutable policy-rule decision provenance (matched rule id/'
    'version, engine version, ordered evaluation path), hash-protected as '
    'part of CORE_HASH_FIELDS_V3 for schema_version = 3 entries.';

CREATE INDEX IF NOT EXISTS idx_audit_chain_consent_id
    ON audit_chain ((consent_provenance ->> 'consentId'))
    WHERE consent_provenance IS NOT NULL;

-- ── evidence_chain_records ──────────────────────────────────────────────────

ALTER TABLE evidence_chain_records
    ADD COLUMN IF NOT EXISTS schema_version      INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS consent_provenance  JSONB,
    ADD COLUMN IF NOT EXISTS policy_decision     JSONB;

COMMENT ON COLUMN evidence_chain_records.schema_version IS
    'Evidence hash schema version (TRACE-2). 1 = legacy CANONICAL_FIELDS_V1 '
    '(10 fields, pre-TRACE-2). 2 = CANONICAL_FIELDS_V2, adds consent_provenance '
    'and policy_decision to the hashed canonical field set. Existing rows are '
    'never rehashed — they keep verifying against the field set they were '
    'originally written under. See src/core/evidence/chain.js.';

COMMENT ON COLUMN evidence_chain_records.consent_provenance IS
    'Immutable snapshot of the consent record that authorized (or denied) '
    'execution, captured at decision time from ConsentVerifier — consentId, '
    'version, timestamps, issuer, tenant, subject, scope, expiry, and the '
    'effective revocation status at that moment. NULL when no REQUIRE_CONSENT '
    'policy applied to the request. Part of the hashed evidence_hash payload '
    'for schema_version >= 2 — never write to this column outside of '
    'chain.buildEvidenceRecord().';

COMMENT ON COLUMN evidence_chain_records.policy_decision IS
    'Immutable policy-rule decision provenance: matched policyId/policyVersion, '
    'engine version, evaluation timestamp, and the complete ordered rule '
    'evaluation path. Part of the hashed evidence_hash payload for '
    'schema_version >= 2.';

-- Query support for "which evidence records cite consent X" without relying
-- on an unsigned denormalized column — reads straight from the hashed JSONB.
CREATE INDEX IF NOT EXISTS idx_evidence_consent_id
    ON evidence_chain_records ((consent_provenance ->> 'consentId'))
    WHERE consent_provenance IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_evidence_policy_rule_id
    ON evidence_chain_records ((policy_decision ->> 'policyId'))
    WHERE policy_decision IS NOT NULL;

COMMIT;
