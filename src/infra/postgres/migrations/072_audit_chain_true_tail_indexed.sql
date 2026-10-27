-- QODIQA PostgreSQL Migration 072
-- S1 (owner instruction 2026-10-01: implement S0 + S1, premise guard
-- in the migration — approved option "Guard in migration").
--
-- qodiqa_audit_chain_true_tail() (migration 058) compares audit_chain.prev_hash (varchar(64)) with audit_chain.hash
-- (char(64)). PostgreSQL resolves that to bpchar equality (a.hash = b.prev_hash::bpchar), which cannot use
-- idx_audit_chain_prev_hash_unique: every call was a hash anti-join over TWO sequential scans of audit_chain —
-- 122-143 ms / ~444 MB read at 117k rows, ~0.4-0.5 s / ~1.4 GB at 360k, run on every signed audit checkpoint
--.
--
-- The function is redefined with the SAME predicate and the SAME result contract, and one explicit cast so the
-- comparison is varchar equality on prev_hash's own type: an index-only probe per examined row, examined in
-- idx_audit_chain_seq order from the top. On a mirror where seq order = hash-link order
-- that is one row: O(log n).
--
-- Equivalence premise (checked below, fail-closed): bpchar equality ignores trailing blanks on both sides; varchar
-- equality does not. The two agree for every row whose prev_hash has no trailing blank. The guard refuses this
-- migration unless every row has hash = 64 lowercase hex and prev_hash = 'GENESIS' or 64 lowercase hex (no blank,
-- by construction of the regex) — the premise approved. Rows written later are produced by the
-- application from SHA-256 hex digests (entryBuilder) with prev_hash = the parent's hash.
-- One O(n) pass, once, at migration time.
--
-- Signature, SECURITY DEFINER, pinned search_path, STABLE, owner and grants (migration 061: EXECUTE to
-- qodiqa_system only) are unchanged — CREATE OR REPLACE keeps the function's ACL. Migration 058 is not edited.

BEGIN;

DO $$
DECLARE
  v_bad_hash BIGINT;
  v_bad_prev BIGINT;
BEGIN
  SELECT count(*) FILTER (WHERE hash !~ '^[0-9a-f]{64}$'),
         count(*) FILTER (WHERE prev_hash <> 'GENESIS' AND prev_hash !~ '^[0-9a-f]{64}$')
    INTO v_bad_hash, v_bad_prev
    FROM audit_chain;
  IF v_bad_hash > 0 OR v_bad_prev > 0 THEN
    RAISE EXCEPTION 'migration 072 refused: % audit_chain row(s) with a hash that is not 64 lowercase hex and % with a prev_hash that is neither GENESIS nor 64 lowercase hex — the indexed true_tail predicate is equivalent to the current one only when no such row exists', v_bad_hash, v_bad_prev;
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_true_tail()
RETURNS TABLE(hash CHARACTER(64), seq BIGINT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT a.hash, a.seq
  FROM audit_chain a
  WHERE NOT EXISTS (SELECT 1 FROM audit_chain b WHERE b.prev_hash = a.hash::varchar)
  ORDER BY a.seq DESC
  LIMIT 1
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_true_tail() IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS to return the chain tail defined by hash links (the row no other row names as prev_hash; hash + seq only). replaces max(seq) as the single-node hydration tail, which is wrong while historical seq inversions exist. S1 (migration 072): same predicate with prev_hash compared as varchar so idx_audit_chain_prev_hash_unique is used (O(log n) instead of two sequential scans).';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (72, 'w11_audit_chain_true_tail_indexed', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
