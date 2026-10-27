-- QODIQA PostgreSQL Schema — Migration 039
-- Finding: Provider/model identity excluded from the protected
--          audit-chain hash
-- Purpose: Extend audit_chain with dedicated `provider`/`model` columns so
--          the AI provider and model that actually executed (or would have
--          executed) a request are hash-protected, matching the same shape
--          `public_key_id` (migration 025), `consent_provenance`/
--          `policy_decision` (migration 033), and `caller_context`
--          (migration 034) already established for this exact class of
--          finding.
--
-- Before this migration, provider/model only existed inside
-- execution_context JSONB, which is NOT part of entryBuilder.js's hashed
-- core-field set — an attacker able to rewrite audit_chain in place could
-- silently change which provider/model a historical decision was
-- attributed to without invalidating hash/canonical. provider/model are
-- execution-changing metadata and must be tamper-evident.
--
-- Design principles (same as migrations 033/034):
--   1. schema_version defaults are untouched — existing rows keep whatever
--      schema_version they were written under and are NEVER rehashed;
--      entryBuilder.js's hashFieldsFor() dispatches on schema_version and
--      recomputes existing rows against the original field set they were
--      actually hashed under (V1-V4 rows never include provider/model in
--      their hash, by design — this is schema_version 5, CORE_HASH_FIELDS_V5).
--   2. No new "provider id"/"model id" concept is introduced — there is
--      none anywhere else in this codebase (services/providers/*); the
--      provider name and model string ARE the identifiers.
--   3. Idempotent: safe to re-run (IF NOT EXISTS everywhere).

BEGIN;

ALTER TABLE audit_chain
    ADD COLUMN IF NOT EXISTS provider TEXT,
    ADD COLUMN IF NOT EXISTS model    TEXT;

COMMENT ON COLUMN audit_chain.provider IS
    'AI provider identity (e.g. "anthropic", "openai") that executed '
    'or would have executed this request, hash-protected as part of '
    'CORE_HASH_FIELDS_V5 for schema_version = 5 entries (entryBuilder.js). '
    'NULL for schema_version < 5, or when no provider had been selected yet '
    '(e.g. an early-stage BLOCK).';

COMMENT ON COLUMN audit_chain.model IS
    'model identity (e.g. "claude-3-opus-20240229") — same '
    'hash-protection and NULL semantics as the provider column above.';

CREATE INDEX IF NOT EXISTS idx_audit_chain_provider
    ON audit_chain (provider)
    WHERE provider IS NOT NULL;

COMMIT;
