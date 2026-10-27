-- Migration 049: transparency_log_entries GapScanner RLS-bypass functions
--
-- Same defect class as migrations 043/044/048 (audit_chain): a plain SELECT
-- against transparency_log_entries as qodiqa_app is subject to
-- tle_tenant_select (migration 018 -- USING (tenant_id IS NULL OR tenant_id =
-- qodiqa_current_tenant())), so any caller running with no tenant context set
-- only ever sees platform-level (tenant_id IS NULL) rows, not the real chain.
--
-- GapScanner.js (src/core/transparency/scanner/GapScanner.js) runs its whole
-- scan inside pgPool.withTransaction() -- the plain, non-tenant transaction --
-- because it is legitimately a GLOBAL, cross-tenant integrity sweep: the
-- transparency log's id/previous_entry_hash sequence is one single chain
-- spanning every entry regardless of tenant, exactly like audit_chain's own
-- seq/hash chain. withTenantTransaction() would be the wrong fix here (it
-- would scope the scan to one tenant's slice, misreading real cross-tenant-
-- boundary continuity as false sequence/hash breaks either way) -- the same
-- reasoning already established for validateChainLinks() and friends.
--
-- transparency_roots is NOT touched by this migration: its own tr_select
-- policy (migration 011) is USING (true) and was never superseded (migration
-- 018 explicitly classifies it under "TABLES EXCLUDED -- no tenant ownership,
-- global/system data") -- GapScanner's root-table reads were never blind.
--
-- Three distinct query shapes in GapScanner.js, each mirrored exactly (same
-- predicates, same ORDER BY/LIMIT) so the query planner can still push the id
-- range/index lookup down inside the bypassed read -- no query-plan
-- regression versus the pre-fix, RLS-scoped version, only the RLS bypass
-- itself changes. Same idiom as 043/044/048: SECURITY DEFINER, STABLE,
-- LANGUAGE sql, SET search_path = pg_catalog, public -- a narrow, deliberate,
-- auditable exception per query shape, never a blanket bypass grant on the
-- table itself. EXECUTE granted to qodiqa_app and qodiqa_read, REVOKEd from
-- PUBLIC.

BEGIN;

-- ── _fetchBatch()'s paginated id-range read ────────────────────────────────
-- Mirrors GapScanner.js's _fetchBatch() exactly (WHERE id >= $1 ORDER BY id
-- ASC LIMIT $2). RETURNS SETOF transparency_log_entries per 044/048's own
-- reasoning: a strict superset of the caller's SELECT column list, always
-- correct by construction, no hand-typed column list to keep in sync.

CREATE OR REPLACE FUNCTION qodiqa_transparency_log_fetch_batch(from_id BIGINT, batch_size INT)
RETURNS SETOF transparency_log_entries
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM transparency_log_entries WHERE id >= from_id ORDER BY id ASC LIMIT batch_size
$$;

COMMENT ON FUNCTION qodiqa_transparency_log_fetch_batch(BIGINT, INT) IS
  'SECURITY DEFINER: bypasses transparency_log_entries'' per-tenant RLS (tle_tenant_select) for the transparency gap scanner''s paginated id-range batch read./RLS-1 remediation -- see migration 048''s header for the identical precedent on audit_chain. Used by GapScanner.js''s _fetchBatch().';

-- ── _fetchEntryHashesInRange()'s id-range lookup ───────────────────────────
-- Mirrors GapScanner.js's _fetchEntryHashesInRange() exactly -- feeds root
-- hash/entry-count verification in _scanRoots(); an RLS-undercounted result
-- here was producing false CHECKPOINT_DIVERGENCE gaps whenever a root's
-- seq_from..seq_to range included any tenant-owned entry, the same false-
-- positive shape found for validateChainLinks().

CREATE OR REPLACE FUNCTION qodiqa_transparency_log_fetch_hashes_in_range(seq_from BIGINT, seq_to BIGINT)
RETURNS TABLE (id BIGINT, entry_hash CHAR(64))
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT id, entry_hash FROM transparency_log_entries
  WHERE id >= seq_from AND id <= seq_to
  ORDER BY id ASC
$$;

COMMENT ON FUNCTION qodiqa_transparency_log_fetch_hashes_in_range(BIGINT, BIGINT) IS
  'SECURITY DEFINER: bypasses transparency_log_entries'' per-tenant RLS for the transparency gap scanner''s root-verification id-range hash lookup./RLS-1 remediation. Used by GapScanner.js''s _fetchEntryHashesInRange().';

-- ── Boundary-row lookback (chain-continuity across scan-batch edges) ──────
-- Mirrors the identical inline query in GapScanner.js's _scanEntries()
-- (`WHERE id < $1 ORDER BY id DESC LIMIT 1`) -- loads the last entry before
-- an incremental scan's own start position so the first batch's hash-chain
-- link can still be verified against it.

CREATE OR REPLACE FUNCTION qodiqa_transparency_log_fetch_boundary(before_id BIGINT)
RETURNS TABLE (id BIGINT, entry_hash CHAR(64))
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT id, entry_hash FROM transparency_log_entries
  WHERE id < before_id ORDER BY id DESC LIMIT 1
$$;

COMMENT ON FUNCTION qodiqa_transparency_log_fetch_boundary(BIGINT) IS
  'SECURITY DEFINER: bypasses transparency_log_entries'' per-tenant RLS for the transparency gap scanner''s incremental-scan boundary-row lookback./RLS-1 remediation. Used by GapScanner.js''s _scanEntries().';

-- ── Grants ──────────────────────────────────────────────────────────────────

REVOKE ALL ON FUNCTION qodiqa_transparency_log_fetch_batch(BIGINT, INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_transparency_log_fetch_hashes_in_range(BIGINT, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_transparency_log_fetch_boundary(BIGINT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_fetch_batch(BIGINT, INT)              TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_fetch_hashes_in_range(BIGINT, BIGINT)  TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_fetch_boundary(BIGINT)                 TO qodiqa_app, qodiqa_read;

-- ── Migration record ─────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (49, 'transparency_log_gap_scanner_rls_bypass', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
