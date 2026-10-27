-- Migration 037: audit chain hash-sentinel columns CHAR(64) padding fix
--
-- Root cause: migration 026 declared audit_chain_head.tail_hash as CHAR(64).
-- PostgreSQL's CHAR(n) type right-pads any value shorter than n with spaces
-- on storage. The seed row's initial value is the literal 'GENESIS' sentinel
-- (7 characters) whenever a distributed-mode chain has never had an entry
-- appended yet — so a fresh/never-before-appended deployment's seed row is
-- actually stored (and read back) as 'GENESIS' followed by 57 trailing
-- spaces, not the exact 7-character string every JS-side hash-chain walk
-- compares against via strict equality (audit-log.js's _walkChain default
-- startPrevHash, entryBuilder.js). This broke, from first boot:
--   - hydrateFromPgIfDistributed() at startup of the FIRST-EVER distributed-
--     mode deployment (before any entry has been appended) — the loaded
--     genesis-linked entry's prevHash would fail to match 'GENESIS'.
--   - Any full from-genesis PG chain re-verification (e.g. the ChainVerifier
--     FULL scan in distributed mode, or an operator diagnostic re-walking
--     loadChainFromPg() from the start).
--
-- Confirmed Finding B's new 50-concurrent-writer regression test
-- (test/integration/audit-chain-distributed.integration.test.js ADC-01) run against a
-- genuinely fresh, just-migrated database — the very first entry ever
-- appended in distributed mode links off this padded value and fails
-- verification. Not a concurrency bug itself, but discovered while building
-- the concurrency regression test requires, and it is a real,
-- previously-undetected correctness gap in the same append/ordering
-- pipeline asks this WP to review.
--
-- audit_chain.prev_hash (migration 001) already uses the CORRECT type for
-- this exact situation — VARCHAR(64), with an explicit CHECK constraint
-- (`prev_hash = 'GENESIS' OR LENGTH(prev_hash) = 64`) — this migration
-- brings audit_chain_head.tail_hash into line with that established,
-- correct pattern instead of leaving a second, inconsistent one in place.
--
-- The SAME bug class exists in audit_chain_verifier_state.last_verified_hash
-- (migration 031, also CHAR(64)): ChainVerifier.js's _verifyPgAuthoritative()
-- persists the literal 'GENESIS' string into that column whenever a scan
-- completes having found zero rows (e.g. a FULL scan of a distributed chain
-- that has never had an entry appended yet) — CHAR(64) pads it the same way,
-- and the padded value is then read back and reused as the next scan's
-- starting hash, producing a FALSE-POSITIVE AUDIT_CHAIN_BROKEN/tampering
-- violation the first time that scan reaches a real entry. Fixed identically
-- here, in the same migration, since it is the same root cause in the same
-- audit-chain persistence layer.
--
-- TRIM strips any padding a deployment that already ran migration 026/031
-- may already have stored, so this repairs existing installs, not just new
-- ones.
--
-- Idempotent: safe to re-run (ALTER COLUMN TYPE to the target type and
-- re-adding an already-satisfied CHECK constraint are both no-ops on rerun).

BEGIN;

ALTER TABLE audit_chain_head
  ALTER COLUMN tail_hash TYPE VARCHAR(64) USING TRIM(TRAILING ' ' FROM tail_hash);

ALTER TABLE audit_chain_head
  DROP CONSTRAINT IF EXISTS audit_chain_head_tail_hash_genesis;

ALTER TABLE audit_chain_head
  ADD CONSTRAINT audit_chain_head_tail_hash_genesis
  CHECK (tail_hash = 'GENESIS' OR LENGTH(tail_hash) = 64);

COMMENT ON COLUMN audit_chain_head.tail_hash IS
  'VARCHAR(64), not CHAR(64) — must exactly equal the literal ''GENESIS'' sentinel (7 chars) or a 64-char SHA-256 hex hash, with no padding. See migration 037 header for the CHAR(64) padding bug this replaced.';

ALTER TABLE audit_chain_verifier_state
  ALTER COLUMN last_verified_hash TYPE VARCHAR(64) USING TRIM(TRAILING ' ' FROM last_verified_hash);

ALTER TABLE audit_chain_verifier_state
  DROP CONSTRAINT IF EXISTS audit_chain_verifier_state_last_verified_hash_genesis;

ALTER TABLE audit_chain_verifier_state
  ADD CONSTRAINT audit_chain_verifier_state_last_verified_hash_genesis
  CHECK (last_verified_hash IS NULL OR last_verified_hash = 'GENESIS' OR LENGTH(last_verified_hash) = 64);

COMMENT ON COLUMN audit_chain_verifier_state.last_verified_hash IS
  'VARCHAR(64), not CHAR(64) — NULL, or must exactly equal the literal ''GENESIS'' sentinel (7 chars), or a 64-char SHA-256 hex hash, with no padding. See migration 037 header for the CHAR(64) padding bug this replaced.';

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (37, 'audit_chain_hash_columns_varchar_fix', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
