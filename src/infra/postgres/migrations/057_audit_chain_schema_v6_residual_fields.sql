-- QODIQA PostgreSQL Schema — Migration 057
-- Finding: — residual
--          executionContext fields excluded from the protected audit-chain
--          hash
-- Purpose: Extend audit_chain with dedicated `stage`/`reason`/`semantic`/
--          `token_usage`/`response_id` columns so these fields are
--          hash-protected AND correctly reconstructible from PostgreSQL in
--          distributed-ordering mode, matching the same shape
--          `public_key_id` (migration 025), `consent_provenance`/
--          `policy_decision` (migration 033), `caller_context`
--          (migration 034), and `provider`/`model` (migration 039) already
--          established for this exact class of finding.
--
-- Before this migration, stage/reason/semantic/tokenUsage/responseId only
-- existed inside execution_context JSONB, which is NOT part of
-- entryBuilder.js's hashed core-field set — an attacker able to rewrite
-- audit_chain in place could silently change the stated reason for a BLOCK,
-- the recorded semantic classification, token-usage figures, or the linked
-- provider response id, without invalidating hash/canonical. See
-- for the full analysis.
--
-- Design principles (same as migrations 033/034/039):
--   1. schema_version defaults are untouched — existing rows keep whatever
--      schema_version they were written under and are NEVER rehashed;
--      entryBuilder.js's hashFieldsFor() dispatches on schema_version and
--      recomputes existing rows against the original field set they were
--      actually hashed under (V1-V5 rows never include these 5 fields in
--      their hash, by design — this is schema_version 6, CORE_HASH_FIELDS_V6).
--   2. `semantic` and `token_usage` are JSONB (objects or null), the same
--      round-trip contract already established for consent_provenance/
--      policy_decision/caller_context — the application layer is
--      responsible for JSON.stringify()/JSON.parse() at the boundary.
--   3. Idempotent: safe to re-run (IF NOT EXISTS everywhere).

BEGIN;

ALTER TABLE audit_chain
    ADD COLUMN IF NOT EXISTS stage        TEXT,
    ADD COLUMN IF NOT EXISTS reason       TEXT,
    ADD COLUMN IF NOT EXISTS semantic     JSONB,
    ADD COLUMN IF NOT EXISTS token_usage  JSONB,
    ADD COLUMN IF NOT EXISTS response_id  TEXT;

COMMENT ON COLUMN audit_chain.stage IS
    'decision-pipeline stage (e.g. "PROVIDER_EXECUTION") this entry '
    'was recorded at, hash-protected as part of CORE_HASH_FIELDS_V6 for '
    'schema_version = 6 entries (entryBuilder.js). NULL for schema_version < 6.';

COMMENT ON COLUMN audit_chain.reason IS
    'the stated reason for a BLOCK decision (e.g. a policy/semantic '
    'rule identifier) -- same hash-protection and NULL semantics as stage '
    'above. NULL for ALLOW entries and for BLOCKs with no rule-specific reason.';

COMMENT ON COLUMN audit_chain.semantic IS
    'the semantic-classifier score/family/family-max evidence object '
    'for this decision -- same hash-protection and NULL semantics as stage '
    'above. Round-trips as JSONB, mirroring consent_provenance/policy_decision.';

COMMENT ON COLUMN audit_chain.token_usage IS
    'provider token-accounting object ({inputTokens, outputTokens, '
    'totalTokens}) for this execution -- same hash-protection and NULL '
    'semantics as stage above. Round-trips as JSONB.';

COMMENT ON COLUMN audit_chain.response_id IS
    'the actual provider response id this decision was based on -- '
    'same hash-protection and NULL semantics as stage above.';

COMMIT;
