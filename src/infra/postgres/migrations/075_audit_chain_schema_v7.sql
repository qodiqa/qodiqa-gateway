-- QODIQA PostgreSQL Schema — Migration 075
-- Context: audit schema v7
-- Purpose: Extend audit_chain with dedicated columns for the v7 hashed fields that have no column yet, so v7 entries
--          are reconstructible from PostgreSQL (distributed ordering, hydration, the verifier's PG path) exactly as
--          entryBuilder.js built and hashed them — the same shape migrations 025/033/034/039/057 established for
--          every earlier hashed field:
--            entry_type          'DECISION' | 'INTENT' | 'STREAM_OPENED'                      (R-3)
--            output_hash         64-hex SHA256(QODIQA::OUTPUT::V1 ‖ delivered content), DECISION only (R-5)
--            request_id          the request id, now hashed; links INTENT / STREAM_OPENED to their DECISION (R-9)
--            organization_id     now hashed (R-4)
--            executing_provider  the provider that actually executed after routing/failover (R-7)
--          tenant_id and execution_context already have columns (execution_context becomes hashed at v7, R-6; the
--          column is unchanged).
--
-- Plus the one index R-16 approves: a NON-unique index on request_id for the INTENT ↔ DECISION / forensic lookups.
-- The existing UNIQUE(artifact_id) stays; lifecycle entries satisfy it through the deterministic `:intent` /
-- `:stream_opened` suffixes (R-9).
--
-- Design principles (same as migration 057):
--   1. Additive only. No existing row is rewritten, re-hashed or re-anchored; schema_version defaults are untouched.
--      Existing rows keep NULL in every new column. Writers store each entry's own value or NULL; for schema_version
--      < 7 these values are never hashed (entryBuilder.hashFieldsFor() excludes them), so a pre-v7 entry re-mirrored
--      later (recovery queue, file → PG migration) may carry its unhashed request_id / organization_id here without
--      affecting verification.
--   2. The qodiqa_audit_chain_* read functions RETURN SETOF audit_chain, so the new columns flow through them with no
--      function change; no grant changes (column privileges follow the existing table-level grants).
--   3. Idempotent: safe to re-run (IF NOT EXISTS everywhere).
--   4.: the explicit, schema-version-
--      independent mirror_encoding marker is added here, "in the same additive migration as the v7 columns" (§9).
--      0 = native/original per-field values (every existing row — NO back-fill, R-F5), 1 = every per-field column
--      written through the reversible projection P (every row written by the application after this change).

BEGIN;

ALTER TABLE audit_chain
    ADD COLUMN IF NOT EXISTS entry_type          TEXT,
    ADD COLUMN IF NOT EXISTS output_hash         TEXT,
    ADD COLUMN IF NOT EXISTS request_id          TEXT,
    ADD COLUMN IF NOT EXISTS organization_id     TEXT,
    ADD COLUMN IF NOT EXISTS executing_provider  TEXT,
    ADD COLUMN IF NOT EXISTS mirror_encoding     SMALLINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_audit_chain_request_id ON audit_chain (request_id);

COMMENT ON COLUMN audit_chain.entry_type IS
    'v7 (R-3): DECISION | INTENT | STREAM_OPENED, hash-protected as part of CORE_HASH_FIELDS_V7 for '
    'schema_version = 7 entries (entryBuilder.js). NULL for schema_version < 7.';

COMMENT ON COLUMN audit_chain.output_hash IS
    'v7 (R-5): 64-hex SHA256("QODIQA::OUTPUT::V1" || exact delivered output content) on DECISION entries (empty '
    'output -> hash of the empty byte string); NULL on INTENT / STREAM_OPENED and for schema_version < 7.';

COMMENT ON COLUMN audit_chain.request_id IS
    'v7 (R-9): request id, hash-protected for schema_version = 7; the link between an INTENT / STREAM_OPENED '
    'entry and its DECISION. Indexed (non-unique, R-16). Unhashed (informational) when schema_version < 7.';

COMMENT ON COLUMN audit_chain.organization_id IS
    'v7 (R-4): organization id, hash-protected for schema_version = 7; unhashed when schema_version < 7.';

COMMENT ON COLUMN audit_chain.executing_provider IS
    'v7 (R-7): the provider that actually executed (after routing/failover), hash-protected for schema_version = 7; '
    '`provider` keeps its v5 meaning (requested provider). NULL when no provider was called and for schema_version < 7.';

COMMENT ON COLUMN audit_chain.mirror_encoding IS
    '(R-F2): 0 = per-field columns hold native values (legacy rows, never back-filled); 1 = every per-field '
    'column holds P(value), the reversible JSON-style projection (W7-F6-UNICODE-PROJECTION-DESIGN.md §2); readers '
    'decode with P^-1 before use. canonical / hash / prev_hash are never projected. Independent of schema_version.';

COMMIT;
