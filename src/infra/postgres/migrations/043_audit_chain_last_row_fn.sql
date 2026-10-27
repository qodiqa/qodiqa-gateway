-- Migration 043: audit_chain last-row lookup function
-- (FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION)
--
-- Closes the root cause: single-node mode's audit-log.js computes prevHash
-- purely from its own in-memory/file chain (process-local, reset to
-- 'GENESIS' on every fresh process per setupEnv.js-style test isolation, and
-- generally on any restart that doesn't durably carry the file forward),
-- with zero awareness of what pg-audit-backend.js's fire-and-forget dual
-- write has already durably committed to the shared, persistent audit_chain
-- table. idx_audit_chain_prev_hash_unique (migration 026) is a GLOBAL,
-- non-partial unique index -- only the very first process, ever, against a
-- given database, can successfully claim 'GENESIS'. Every later fresh
-- process's first write collides (23505), and because the failure is
-- absorbed (non-fatal, by design), every entry appended for the rest of
-- that process's lifetime chains off a hash that was never actually
-- persisted -- a silent, permanent orphaned link in the PG mirror.
-- See FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION-REPORT.md for the full
-- root-cause trace and reproduction.
--
-- The fix (audit-log.js, this session) hydrates _tailHash from audit_chain's
-- true last-inserted row at first append, when PG is enabled and the file
-- yielded no history -- but audit_chain carries per-tenant RLS
-- (ac_tenant_select, migration 018-family), and _tailHash is a SINGLE,
-- process-wide value with no notion of "current tenant" at startup. A plain
-- SELECT as qodiqa_app, with no qodiqa.tenant_id session context set, would
-- only see tenant_id IS NULL rows -- confirmed empirically (0 rows returned
-- against a disposable DB that genuinely had 3 tenant-tagged rows) -- which
-- would silently reproduce the exact bug this migration exists to close.
--
-- This function is the narrowly-scoped exception: SECURITY DEFINER, owned
-- by the migration role (superuser in this environment), so its internal
-- SELECT bypasses RLS entirely (superusers always bypass RLS, independent
-- of FORCE ROW LEVEL SECURITY, which only affects non-superuser table
-- owners) -- a deliberately narrow read (hash + seq only, one row) rather
-- than a blanket bypass grant on the table itself. EXECUTE is granted to
-- qodiqa_app only, not PUBLIC.
--
-- Idempotent: safe to re-run (CREATE OR REPLACE FUNCTION, GRANT is a no-op
-- if already granted).

BEGIN;

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_last_row()
RETURNS TABLE(hash CHARACTER(64), seq BIGINT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT hash, seq FROM audit_chain ORDER BY seq DESC LIMIT 1
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_last_row() IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS (ac_tenant_select) to return the true global last-inserted row (hash + seq only), regardless of which tenant wrote it. Narrow, deliberate exception -- see FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION-REPORT.md. Used only by audit-log.js''s single-node startup hydration, to determine the correct prevHash instead of unconditionally assuming GENESIS on every fresh process.';

REVOKE EXECUTE ON FUNCTION qodiqa_audit_chain_last_row() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_last_row() TO qodiqa_app;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (43, 'audit_chain_last_row_fn', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
