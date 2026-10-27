-- QODIQA PostgreSQL Schema — Migration 083
-- Finding: audit schema v8
-- Purpose: Extend audit_chain with dedicated columns for the ten fields CORE_HASH_FIELDS_V8 adds to the v7 set, so v8
--          entries are reconstructible from PostgreSQL (distributed ordering, hydration, the verifier's PG path) exactly
--          as entryBuilder.js built and hashed them — the same shape migrations 033/034/039/057/075 established:
--            issued_at          BIGINT   the artifact's timestamp (ms) consumed by the entry
--            protocol_version   INTEGER  1 for an artifact without `qodiqa`, else qodiqa.v
--            agent_id, session_id, action_hash, approval_ref TEXT (agent / approval entries; NULL until)
--            action_seq         BIGINT   position of the action in the session (>= 1)
--            dlp                JSONB    { rules, action, inputHashBefore, inputHashAfter }
--            bytes_delivered    BIGINT   exact output bytes delivered (COMMIT)
--            completion_status  TEXT     COMPLETE | CANCELLED | ERROR | TIMEOUT | CLIENT_DISCONNECTED | OUTCOME_UNKNOWN
--
-- Design principles (same as migrations 057 / 075):
--   1. Additive only. No existing row is rewritten or re-hashed; existing rows keep NULL in every new column. For
--      schema_version < 8 these values are never hashed (entryBuilder.hashFieldsFor() excludes them).
--   2. The qodiqa_audit_chain_* read functions RETURN SETOF audit_chain, so the new columns flow through them with no
--      function change; no grant changes (column privileges follow the existing table-level grants).
--   3. Idempotent: safe to re-run (IF NOT EXISTS everywhere).
--   4. Writing v8 is a separate, one-way switch (QODIQA_AUDIT_SCHEMA_V8); this migration only makes the columns exist.

BEGIN;

ALTER TABLE audit_chain
    ADD COLUMN IF NOT EXISTS issued_at          BIGINT,
    ADD COLUMN IF NOT EXISTS protocol_version   INTEGER,
    ADD COLUMN IF NOT EXISTS agent_id           TEXT,
    ADD COLUMN IF NOT EXISTS session_id         TEXT,
    ADD COLUMN IF NOT EXISTS action_seq         BIGINT,
    ADD COLUMN IF NOT EXISTS action_hash        TEXT,
    ADD COLUMN IF NOT EXISTS approval_ref       TEXT,
    ADD COLUMN IF NOT EXISTS dlp                JSONB,
    ADD COLUMN IF NOT EXISTS bytes_delivered    BIGINT,
    ADD COLUMN IF NOT EXISTS completion_status  TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_chain_session_action_seq ON audit_chain (session_id, action_seq) WHERE session_id IS NOT NULL;

COMMENT ON COLUMN audit_chain.issued_at IS
    'Audit v8: the consumed artifact''s timestamp (ms since epoch), hash-protected for schema_version = 8; NULL for '
    'system entries and for schema_version < 8.';
COMMENT ON COLUMN audit_chain.protocol_version IS
    'Audit v8: 1 for an artifact without the `qodiqa` payload block, else qodiqa.v; hash-protected for schema_version = 8.';
COMMENT ON COLUMN audit_chain.completion_status IS
    'Audit v8: COMPLETE | CANCELLED | ERROR | TIMEOUT | CLIENT_DISCONNECTED | OUTCOME_UNKNOWN; hash-protected for schema_version = 8.';

COMMIT;
