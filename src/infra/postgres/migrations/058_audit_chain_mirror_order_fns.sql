-- Migration 058: audit_chain mirror ordering helpers
--
-- ROOT CAUSE: in single-node mode the PG
-- mirror write was fired without awaiting and without serialization
-- (audit-log.js), and seq = nextval() is drawn when each INSERT executes, so
-- concurrent mirror writes committed out of hash-chain order (auditor: 7 link
-- breaks per 500 concurrent real appends). Recovery-queue replays inserted
-- later still, with higher seq. Every seq-ordered consumer then reported a
-- broken chain on a chain whose hashes all verify.
--
-- The fix makes ordering structural: a mirror row is INSERTed only once its
-- parent (prev_hash) is already committed (or it is the GENESIS entry). With
-- the existing UNIQUE(prev_hash) (migration 026) the chain is linear, so
-- "every child is inserted after its parent" means seq order IS chain order,
-- for every writer (live writer, recovery replay, backfill), under any
-- concurrency or replay order.
--
-- The parent check must see rows of every tenant, but audit_chain's SELECT is
-- tenant-scoped by RLS (ac_tenant_select, migration 018). Same narrow
-- SECURITY DEFINER pattern as migrations 043/048: pure reads, no tenant
-- parameter, no writes, EXECUTE granted only to qodiqa_app/qodiqa_read.
--
--   qodiqa_audit_chain_hash_exists(hash) -> boolean
--     existence only (no row data), used by the guarded mirror INSERT.
--   qodiqa_audit_chain_true_tail() -> (hash, seq)
--     the chain tail defined by LINKS (the one row no other row names as its
--     prev_hash), not by max(seq) -- max(seq) is the wrong tail on a mirror
--     that still carries historical seq inversions.
--
-- Additive only; no existing object is changed.

BEGIN;

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_hash_exists(target_hash CHARACTER(64))
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT EXISTS (SELECT 1 FROM audit_chain WHERE hash = target_hash)
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_hash_exists(CHARACTER) IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS to answer only whether a hash exists (no row data). used by pg-audit-backend.js''s guarded mirror INSERT so a row is inserted only after its parent is committed, which keeps seq order equal to hash-chain order.';

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_true_tail()
RETURNS TABLE(hash CHARACTER(64), seq BIGINT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT a.hash, a.seq
  FROM audit_chain a
  WHERE NOT EXISTS (SELECT 1 FROM audit_chain b WHERE b.prev_hash = a.hash)
  ORDER BY a.seq DESC
  LIMIT 1
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_true_tail() IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS to return the chain tail defined by hash links (the row no other row names as prev_hash; hash + seq only). replaces max(seq) as the single-node hydration tail, which is wrong while historical seq inversions exist.';

REVOKE ALL ON FUNCTION qodiqa_audit_chain_hash_exists(CHARACTER) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_true_tail()            FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_hash_exists(CHARACTER) TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_true_tail()            TO qodiqa_app, qodiqa_read;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (58, 'audit_chain_mirror_order_fns', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
