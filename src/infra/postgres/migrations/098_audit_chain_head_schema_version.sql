-- QODIQA PostgreSQL Schema — Migration 098
-- Finding: (the distributed audit writer could append a v7 entry after a v8 head)
-- Purpose: audit_chain_head gains `tail_schema_version`, the schema version of the entry the head points at. The distributed
--          writer (distributedOrdering.js) reads it under the same `SELECT ... FOR UPDATE` that orders the append and refuses to
--          add an entry whose schema version is LOWER (a v7 after a v8 is SCHEMA_DOWNGRADE in every verifier); it writes the new
--          entry's version back in the same UPDATE. The rebuild script, the seed script and the DR restore maintain it too.
--
-- Additive: one column with a default (0 = genesis / unknown-old), backfilled from the tail row of audit_chain. No row of
-- audit_chain is touched; grants and row-level security are unchanged (the existing UPDATE policy of audit_chain_head covers it).
-- Idempotent: ADD COLUMN IF NOT EXISTS, and the backfill only ever sets the value the tail row dictates.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

ALTER TABLE audit_chain_head ADD COLUMN IF NOT EXISTS tail_schema_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE audit_chain_head DROP CONSTRAINT IF EXISTS audit_chain_head_schema_version_check;
ALTER TABLE audit_chain_head ADD CONSTRAINT audit_chain_head_schema_version_check CHECK (tail_schema_version >= 0);

-- Backfill (the migration role bypasses row-level security): the version of the entry the head points at.
UPDATE audit_chain_head h
   SET tail_schema_version = COALESCE((SELECT a.schema_version FROM audit_chain a WHERE a.hash = h.tail_hash LIMIT 1), 0)
 WHERE h.tail_schema_version = 0;

COMMENT ON COLUMN audit_chain_head.tail_schema_version IS
  'Schema version of the audit_chain entry this head points at (0 = genesis). Read under the head row lock by the distributed writer, which refuses a lower version (SCHEMA_DOWNGRADE).';

COMMIT;
