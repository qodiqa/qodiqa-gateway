-- Migration 026: Audit Chain Distributed Ordering (SCAL-11 remediation)
--
-- Promotes PostgreSQL from "queryable replica" (see
--) to the ordering authority for
-- QODIQA_AUDIT_ORDERING_MODE=distributed deployments. Single-node
-- mode (the default) is completely unaffected by this migration — it adds
-- new structures, it does not touch existing audit_chain rows or behavior.
--
-- ── audit_chain_head ─────────────────────────────────────────────────────────
-- A single mutable row holding "the current tail of the chain". Concurrent
-- appenders serialize by taking `SELECT ... FOR UPDATE` on this ONE row and
-- then UPDATE-ing it as part of the same transaction that INSERTs the new
-- audit_chain row. This is deliberately a dedicated row, not
-- `SELECT ... FROM audit_chain ORDER BY seq DESC LIMIT 1 FOR UPDATE` (the
-- pattern used by transparency_log_entries/evidence_chain_records — see
-- src/core/transparency/logStore.js getLatestEntry): FOR UPDATE only forces
-- a blocked reader to re-fetch a fresh value once unblocked if the row it
-- locked was itself UPDATEd. Locking a row in audit_chain that a concurrent
-- writer never updates (it only INSERTs a new sibling row elsewhere) can let
-- a blocked-then-unblocked reader return a stale "latest" hash, and two
-- writers can then link to the same prevHash — a silent fork. Locking and
-- updating the SAME physical row here closes that gap by construction.
--
-- Keeping the mutation on a separate table (not audit_chain itself) also
-- preserves the existing hard invariant from migration 002
-- ("audit_chain is append-only — application can INSERT and SELECT only;
-- UPDATE and DELETE are explicitly NOT granted"): qodiqa_app still never
-- gets UPDATE on audit_chain. Only this new one-row pointer table is
-- mutable.
--
-- ── prev_hash UNIQUE index ───────────────────────────────────────────────────
-- Defense-in-depth: even if some future code path bypassed the head-lock
-- transaction, the database itself refuses to accept two rows claiming the
-- same prevHash. A pre-flight check aborts the migration (loudly) rather
-- than silently adding a constraint that existing data would already
-- violate.
--
-- Note: idx_audit_chain_nonce (UNIQUE, partial) already exists from
-- migration 021 — nonce replay detection at the PG layer needs no new index
-- here.
--
-- Idempotent: safe to re-run.

BEGIN;

-- ── Pre-flight integrity check ────────────────────────────────────────────────
-- Refuses to proceed if audit_chain already contains a forked lineage
-- (two rows with the same prev_hash) — adding the UNIQUE index below would
-- otherwise fail with an opaque constraint-violation error instead of this
-- explicit, actionable one.

DO $$
DECLARE
  dupes INT;
BEGIN
  SELECT count(*) INTO dupes FROM (
    SELECT prev_hash FROM audit_chain GROUP BY prev_hash HAVING count(*) > 1
  ) forked;

  IF dupes > 0 THEN
    RAISE EXCEPTION
      'AUDIT_CHAIN_INTEGRITY_VIOLATION: % duplicate prev_hash value(s) found in audit_chain — cannot safely add UNIQUE(prev_hash). Investigate before re-running this migration.',
      dupes;
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_prev_hash_unique
  ON audit_chain (prev_hash);

COMMENT ON INDEX idx_audit_chain_prev_hash_unique IS
  'Defense-in-depth: the database refuses two entries claiming the same prevHash, regardless of application-level bugs.';

-- ── audit_chain_head ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_chain_head (
  id        BOOLEAN   PRIMARY KEY DEFAULT TRUE,
  tail_hash CHAR(64)  NOT NULL,
  tail_seq  BIGINT    NOT NULL,

  CONSTRAINT audit_chain_head_singleton CHECK (id = TRUE)
);

COMMENT ON TABLE audit_chain_head IS
  'Single-row ordering pointer for distributed audit chain appends. Locked via SELECT ... FOR UPDATE and UPDATEd atomically with each audit_chain INSERT so concurrent replicas serialize correctly. See migration 026 header for why this is a dedicated row rather than "lock the last row of audit_chain".';

-- Seed from the current tail of audit_chain (works whether audit_chain is
-- empty — GENESIS/0 — or already has dual-written history).
INSERT INTO audit_chain_head (id, tail_hash, tail_seq)
SELECT
  TRUE,
  COALESCE((SELECT hash FROM audit_chain ORDER BY seq DESC LIMIT 1), 'GENESIS'),
  COALESCE((SELECT seq  FROM audit_chain ORDER BY seq DESC LIMIT 1), 0)
ON CONFLICT (id) DO NOTHING;

-- ── Row-level security ────────────────────────────────────────────────────────
-- Mirrors audit_chain's RLS shape (migration 002), except UPDATE is granted —
-- this table, unlike audit_chain, is meant to be mutated in place.

ALTER TABLE audit_chain_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_head FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_chain_head_select ON audit_chain_head;
CREATE POLICY audit_chain_head_select ON audit_chain_head FOR SELECT USING (TRUE);

DROP POLICY IF EXISTS audit_chain_head_insert ON audit_chain_head;
CREATE POLICY audit_chain_head_insert ON audit_chain_head FOR INSERT
  WITH CHECK (current_user = 'qodiqa_app');

DROP POLICY IF EXISTS audit_chain_head_update ON audit_chain_head;
CREATE POLICY audit_chain_head_update ON audit_chain_head FOR UPDATE
  USING (current_user = 'qodiqa_app')
  WITH CHECK (current_user = 'qodiqa_app');

-- ── Grants ────────────────────────────────────────────────────────────────────
-- UPDATE is intentionally scoped to this one-row pointer table only —
-- audit_chain itself remains INSERT+SELECT-only for qodiqa_app (migration 002).

GRANT SELECT, INSERT, UPDATE ON audit_chain_head TO qodiqa_app;
GRANT SELECT                  ON audit_chain_head TO qodiqa_read;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (26, 'audit_chain_distributed_ordering', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
