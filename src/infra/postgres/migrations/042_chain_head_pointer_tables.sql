-- Migration 042: Chain-Head Pointer Tables for evidence_chain_records,
-- transparency_log_entries, transparency_roots (FINDING-EVIDENCE-CHAIN-FORK-RACE)
--
-- Closes the same defect class migration 026 already closed for audit_chain:
-- `SELECT ... ORDER BY id DESC LIMIT 1 FOR UPDATE` (or, for
-- evidence_chain_records specifically, a transaction-scoped advisory lock —
-- see FINDING-EVIDENCE-CHAIN-RECORDS-PERMISSION-REPORT.md) locks a row that
-- the locking transaction never itself UPDATEs; it only INSERTs a new
-- sibling row elsewhere. FOR UPDATE's EvalPlanQual re-fetch-on-unblock only
-- applies to a row that was actually UPDATEd by the blocking transaction, so
-- a blocked-then-unblocked reader can still return a stale "latest" value,
-- and two writers can link to the same prevHash -- a silent fork. Confirmed
-- deterministically (3/3 forced-overlap runs, pg_blocking_pids()-verified
-- genuine lock-wait, both writers under REPEATABLE READ) in
-- FINDING-EVIDENCE-CHAIN-FORK-RACE-REPORT.md.
--
-- This migration adds three dedicated, single-row pointer tables -- one per
-- ledger -- following migration 026's audit_chain_head pattern exactly:
-- SELECT ... FOR UPDATE locks AND (via a subsequent UPDATE in the same
-- transaction) mutates the SAME physical row, so EvalPlanQual re-fetch
-- closes the gap by construction.
--
-- NULL-for-genesis convention: unlike audit_chain (which uses the string
-- sentinel 'GENESIS', see migration 026), evidence_chain_records,
-- transparency_log_entries, and transparency_roots all use NULL for their
-- first row's previous-hash column (migrations 010, 011). tail_hash below
-- mirrors that: NULL means "chain is empty", not a sentinel string.
--
-- Least-privilege grants (design decision, this finding): qodiqa_app gets
-- SELECT + UPDATE only on all three pointer tables -- no INSERT. The
-- singleton row is seeded once, by this migration, as qodiqa_mig; from
-- then on the row always exists and every write path only ever needs to
-- lock-and-UPDATE it, never INSERT. If a future runtime path is found that
-- genuinely needs INSERT (e.g. a repair/reseed tool), that must be proven
-- and documented at that time, not assumed here.
--
-- Ledger-table ACL/RLS ends this migration at SELECT+INSERT-only for
-- qodiqa_app on all three ledgers -- no UPDATE grant is ADDED to any of
-- them, anywhere, by this migration. This preserves the immutability
-- contract that made "GRANT UPDATE on the ledger" (Option A) get rejected
-- in the sibling permission finding.
--
-- evidence_chain_records was already SELECT+INSERT-only and stays that
-- way untouched. transparency_log_entries/transparency_roots, however,
-- currently hold an UPDATE grant plus tle_tenant_update/tr_update RLS
-- policies from migration 024 -- added solely to satisfy the ACL
-- requirement of the `FOR UPDATE` chain-head lock this migration removes
-- (migration 024's own header: "no application code ever issues a real
-- UPDATE statement against either table"). That grant is now unused dead
-- capability, not a live requirement, so this migration REVOKEs it and
-- drops the two now-pointless policies (see the dedicated section below),
-- bringing all three ledgers to the same least-privilege posture.
--
-- Idempotent: safe to re-run.

BEGIN;

-- ── Pre-flight integrity checks ────────────────────────────────────────────
-- Refuses to proceed if any ledger already contains a forked lineage (two
-- rows with the same prev-hash) -- adding the UNIQUE indexes below would
-- otherwise fail with an opaque constraint-violation error instead of this
-- explicit, actionable one. (Confirmed clean against the live qodiqa
-- database as of this finding's read-only check: 0 duplicate
-- previous_evidence_hash / previous_entry_hash values found on either
-- table. transparency_roots was not separately queried in that check but
-- is gated here regardless, for any environment this migration runs
-- against.)

DO $$
DECLARE
  dupes INT;
BEGIN
  SELECT count(*) INTO dupes FROM (
    SELECT previous_evidence_hash FROM evidence_chain_records
    WHERE previous_evidence_hash IS NOT NULL
    GROUP BY previous_evidence_hash HAVING count(*) > 1
  ) forked;

  IF dupes > 0 THEN
    RAISE EXCEPTION
      'EVIDENCE_CHAIN_INTEGRITY_VIOLATION: % duplicate previous_evidence_hash value(s) found in evidence_chain_records -- cannot safely add UNIQUE(previous_evidence_hash) or seed evidence_chain_head. Investigate before re-running this migration.',
      dupes;
  END IF;
END $$;

DO $$
DECLARE
  dupes INT;
BEGIN
  SELECT count(*) INTO dupes FROM (
    SELECT previous_entry_hash FROM transparency_log_entries
    WHERE previous_entry_hash IS NOT NULL
    GROUP BY previous_entry_hash HAVING count(*) > 1
  ) forked;

  IF dupes > 0 THEN
    RAISE EXCEPTION
      'TRANSPARENCY_LOG_INTEGRITY_VIOLATION: % duplicate previous_entry_hash value(s) found in transparency_log_entries -- cannot safely add UNIQUE(previous_entry_hash) or seed transparency_log_head. Investigate before re-running this migration.',
      dupes;
  END IF;
END $$;

DO $$
DECLARE
  dupes INT;
BEGIN
  SELECT count(*) INTO dupes FROM (
    SELECT previous_root_hash FROM transparency_roots
    WHERE previous_root_hash IS NOT NULL
    GROUP BY previous_root_hash HAVING count(*) > 1
  ) forked;

  IF dupes > 0 THEN
    RAISE EXCEPTION
      'TRANSPARENCY_ROOTS_INTEGRITY_VIOLATION: % duplicate previous_root_hash value(s) found in transparency_roots -- cannot safely add UNIQUE(previous_root_hash) or seed transparency_roots_head. Investigate before re-running this migration.',
      dupes;
  END IF;
END $$;

-- ── Defense-in-depth UNIQUE indexes ─────────────────────────────────────────
-- Mirrors migration 026's idx_audit_chain_prev_hash_unique: even if the
-- pointer-row locking discipline were somehow bypassed, the database itself
-- refuses to accept two rows claiming the same prev-hash.

-- evidence_chain_records already has a non-unique idx_ecr_prev_hash
-- (migration 010) on this exact column -- superseded by the UNIQUE index
-- below, dropped here to avoid carrying a redundant duplicate index.
DROP INDEX IF EXISTS idx_ecr_prev_hash;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ecr_prev_hash_unique
  ON evidence_chain_records (previous_evidence_hash)
  WHERE previous_evidence_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tle_prev_hash_unique
  ON transparency_log_entries (previous_entry_hash)
  WHERE previous_entry_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tr_prev_hash_unique
  ON transparency_roots (previous_root_hash)
  WHERE previous_root_hash IS NOT NULL;

COMMENT ON INDEX idx_ecr_prev_hash_unique IS
  'Defense-in-depth: the database refuses two evidence records claiming the same previous_evidence_hash, regardless of application-level bugs.';
COMMENT ON INDEX idx_tle_prev_hash_unique IS
  'Defense-in-depth: the database refuses two transparency log entries claiming the same previous_entry_hash, regardless of application-level bugs.';
COMMENT ON INDEX idx_tr_prev_hash_unique IS
  'Defense-in-depth: the database refuses two transparency roots claiming the same previous_root_hash, regardless of application-level bugs.';

-- ── evidence_chain_head ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS evidence_chain_head (
  id         BOOLEAN      PRIMARY KEY DEFAULT TRUE,
  tail_hash  VARCHAR(64)  NULL,       -- NULL = chain empty; matches evidence_chain_records' own NULL-for-genesis convention
  tail_id    BIGINT       NOT NULL DEFAULT 0,  -- evidence_chain_records.id of the tail row (0 = no rows yet)

  CONSTRAINT evidence_chain_head_singleton   CHECK (id = TRUE),
  CONSTRAINT evidence_chain_head_hash_length CHECK (tail_hash IS NULL OR LENGTH(tail_hash) = 64)
);

COMMENT ON TABLE evidence_chain_head IS
  'Single-row ordering pointer for evidence_chain_records. Locked via SELECT ... FOR UPDATE and UPDATEd atomically with each evidence_chain_records INSERT so concurrent writers serialize correctly. See migration 042 header and FINDING-EVIDENCE-CHAIN-FORK-RACE-REPORT.md for why this is a dedicated row rather than locking evidence_chain_records itself.';

INSERT INTO evidence_chain_head (id, tail_hash, tail_id)
SELECT
  TRUE,
  (SELECT evidence_hash FROM evidence_chain_records ORDER BY id DESC LIMIT 1),
  COALESCE((SELECT id FROM evidence_chain_records ORDER BY id DESC LIMIT 1), 0)
ON CONFLICT (id) DO NOTHING;

-- ── transparency_log_head ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS transparency_log_head (
  id         BOOLEAN      PRIMARY KEY DEFAULT TRUE,
  tail_hash  VARCHAR(64)  NULL,
  tail_id    BIGINT       NOT NULL DEFAULT 0,  -- transparency_log_entries.id of the tail row (0 = no rows yet)

  CONSTRAINT transparency_log_head_singleton   CHECK (id = TRUE),
  CONSTRAINT transparency_log_head_hash_length CHECK (tail_hash IS NULL OR LENGTH(tail_hash) = 64)
);

COMMENT ON TABLE transparency_log_head IS
  'Single-row ordering pointer for transparency_log_entries. Locked via SELECT ... FOR UPDATE and UPDATEd atomically with each transparency_log_entries INSERT so concurrent writers serialize correctly. tail_id also serves as generateRoot()''s seqTo without a separate lookup. See migration 042 header and FINDING-EVIDENCE-CHAIN-FORK-RACE-REPORT.md.';

INSERT INTO transparency_log_head (id, tail_hash, tail_id)
SELECT
  TRUE,
  (SELECT entry_hash FROM transparency_log_entries ORDER BY id DESC LIMIT 1),
  COALESCE((SELECT id FROM transparency_log_entries ORDER BY id DESC LIMIT 1), 0)
ON CONFLICT (id) DO NOTHING;

-- ── transparency_roots_head ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS transparency_roots_head (
  id         BOOLEAN      PRIMARY KEY DEFAULT TRUE,
  tail_hash  VARCHAR(64)  NULL,
  tail_id    BIGINT       NOT NULL DEFAULT 0,  -- transparency_roots.id of the tail row (0 = no rows yet)

  CONSTRAINT transparency_roots_head_singleton   CHECK (id = TRUE),
  CONSTRAINT transparency_roots_head_hash_length CHECK (tail_hash IS NULL OR LENGTH(tail_hash) = 64)
);

COMMENT ON TABLE transparency_roots_head IS
  'Single-row ordering pointer for transparency_roots. Locked via SELECT ... FOR UPDATE and UPDATEd atomically with each transparency_roots INSERT so concurrent root generators serialize correctly. generateRoot() looks up seq_to from transparency_roots by tail_hash (root_hash is UNIQUE) inside the same locked transaction when it needs it -- tail_id here is the roots table''s own row id, for parity with the other two pointer tables, not seq_to. See migration 042 header and FINDING-EVIDENCE-CHAIN-FORK-RACE-REPORT.md.';

INSERT INTO transparency_roots_head (id, tail_hash, tail_id)
SELECT
  TRUE,
  (SELECT root_hash FROM transparency_roots ORDER BY id DESC LIMIT 1),
  COALESCE((SELECT id FROM transparency_roots ORDER BY id DESC LIMIT 1), 0)
ON CONFLICT (id) DO NOTHING;

-- ── Row-level security ────────────────────────────────────────────────────────
-- Mirrors audit_chain_head's mutable-pointer-table shape (migration 026),
-- except no INSERT policy/grant -- see the header comment on least
-- privilege above.

ALTER TABLE evidence_chain_head       ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_chain_head       FORCE ROW LEVEL SECURITY;
ALTER TABLE transparency_log_head     ENABLE ROW LEVEL SECURITY;
ALTER TABLE transparency_log_head     FORCE ROW LEVEL SECURITY;
ALTER TABLE transparency_roots_head   ENABLE ROW LEVEL SECURITY;
ALTER TABLE transparency_roots_head   FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS evidence_chain_head_select ON evidence_chain_head;
CREATE POLICY evidence_chain_head_select ON evidence_chain_head FOR SELECT USING (TRUE);
DROP POLICY IF EXISTS evidence_chain_head_update ON evidence_chain_head;
CREATE POLICY evidence_chain_head_update ON evidence_chain_head FOR UPDATE
  USING     (current_user = 'qodiqa_app')
  WITH CHECK (current_user = 'qodiqa_app');

DROP POLICY IF EXISTS transparency_log_head_select ON transparency_log_head;
CREATE POLICY transparency_log_head_select ON transparency_log_head FOR SELECT USING (TRUE);
DROP POLICY IF EXISTS transparency_log_head_update ON transparency_log_head;
CREATE POLICY transparency_log_head_update ON transparency_log_head FOR UPDATE
  USING     (current_user = 'qodiqa_app')
  WITH CHECK (current_user = 'qodiqa_app');

DROP POLICY IF EXISTS transparency_roots_head_select ON transparency_roots_head;
CREATE POLICY transparency_roots_head_select ON transparency_roots_head FOR SELECT USING (TRUE);
DROP POLICY IF EXISTS transparency_roots_head_update ON transparency_roots_head;
CREATE POLICY transparency_roots_head_update ON transparency_roots_head FOR UPDATE
  USING     (current_user = 'qodiqa_app')
  WITH CHECK (current_user = 'qodiqa_app');

-- ── Grants ────────────────────────────────────────────────────────────────────
-- SELECT + UPDATE only for qodiqa_app -- no INSERT (the singleton row is
-- seeded above, by this migration, as qodiqa_mig; every subsequent write
-- path only ever needs to lock-and-UPDATE the existing row).

GRANT SELECT, UPDATE ON evidence_chain_head     TO qodiqa_app;
GRANT SELECT          ON evidence_chain_head     TO qodiqa_read;
GRANT SELECT, UPDATE ON transparency_log_head   TO qodiqa_app;
GRANT SELECT          ON transparency_log_head   TO qodiqa_read;
GRANT SELECT, UPDATE ON transparency_roots_head TO qodiqa_app;
GRANT SELECT          ON transparency_roots_head TO qodiqa_read;

-- ── Revoke migration 024's now-vestigial UPDATE capability ─────────────────────
-- Migration 024 granted UPDATE (plus tle_tenant_update/tr_update RLS
-- policies) on transparency_log_entries/transparency_roots solely to
-- satisfy the ACL requirement of the `SELECT ... FOR UPDATE` chain-head
-- lock that logStore.js used to issue directly against these ledger
-- tables (migration 024's own header: "no application code ever issues a
-- real UPDATE statement against either table"). That locking clause is
-- gone as of this migration -- registrar.js now locks
-- transparency_log_head/transparency_roots_head instead (see above) -- so
-- the grant is unused dead capability, not a live requirement. Revoking it
-- here brings both tables back to the same INSERT+SELECT-only posture
-- evidence_chain_records has always had, closing the gap rather than
-- leaving a policy+grant pair around that nothing exercises. Idempotent:
-- DROP POLICY IF EXISTS / REVOKE are no-ops if already absent.

DROP POLICY IF EXISTS tle_tenant_update ON transparency_log_entries;
DROP POLICY IF EXISTS tr_update         ON transparency_roots;

REVOKE UPDATE ON transparency_log_entries FROM qodiqa_app;
REVOKE UPDATE ON transparency_roots       FROM qodiqa_app;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (42, 'chain_head_pointer_tables', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
