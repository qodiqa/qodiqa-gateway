-- Migration 044: Ledger RLS asymmetry fix + full-chain SECURITY DEFINER read
-- (Findings Group A, read-only inventory + M024 pre-decision step)
--
-- Runs as a superuser in this environment (the
-- historical qodiqa_mig/postgres applied_by split documented in
-- docs/operations/database-role-management.md is codified as
-- documented-intentional, not fixed here -- migrations 018-043 were
-- overwhelmingly superuser-applied and this one follows that established,
-- pattern rather than reopening it).
--
-- M024 resolution (see CHECKPOINT M024, this session): migration 042
-- (chain_head_pointer_tables) already, deliberately, DROPped
-- tle_tenant_update/tr_update and REVOKEd the matching UPDATE grant on
-- transparency_log_entries/transparency_roots once its head-pointer tables
-- replaced the FOR-UPDATE-locking need those policies existed for. That is
-- correct, intentional, and confirmed against live pg_policies -- this
-- migration does NOT resurrect either policy.
--
-- tr_select (transparency_roots, USING (true), unconditional) is
-- documented-intentional and is NOT touched here: transparency_roots has no
-- tenant_id column (roots aggregate across the whole log; see migration 011
-- and 018's header, which never touched this table), so an unconditional
-- SELECT policy is the correct shape for it, unlike evidence_chain_records
-- below, which DOES have a tenant_id column.
--
-- ── Statement 1: evidence_chain_records SELECT-policy asymmetry ───────────
-- Root cause: migration 010 created
-- ecr_select (FOR SELECT TO qodiqa_app, qodiqa_read USING (true) --
-- unconditional). Migration 018 added ecr_tenant_select (FOR SELECT TO
-- qodiqa_app, qodiqa_read USING (tenant_id IS NULL OR tenant_id =
-- qodiqa_current_tenant()) -- tenant-scoped) alongside it, WITHOUT dropping
-- the original ecr_select (018's own DROP POLICY IF EXISTS block at
-- src/infra/postgres/migrations/018_rls_tenant_isolation.sql:326-327 only
-- self-guards ecr_tenant_select/ecr_system_insert -- 018's own new policy
-- names -- for idempotent re-run; it never references ecr_select or
-- ecr_insert by name). Postgres ORs multiple permissive policies for the
-- same command+role together, so ecr_select's unconditional USING (true)
-- silently defeats ecr_tenant_select -- every row is visible regardless of
-- tenant context today, confirmed against live pg_policies in the
-- report. This statement removes the dead, unconditional policy, leaving
-- ecr_tenant_select as the sole SELECT policy -- the same shape audit_chain
-- (ac_tenant_select) and transparency_log_entries (tle_tenant_select)
-- already have.
--
-- Pre-flight hard-asserts BOTH ecr_select AND ecr_tenant_select exist
-- before dropping (a deliberate requirement) -- this is a deliberate
-- departure from this repo's usual "safe to blindly re-run" convention
-- (DROP POLICY IF EXISTS): under normal operation migrate.js applies each
-- version exactly once (qodiqa_migrations tracks applied versions), so this
-- is not a re-run hazard in practice; the hard assert instead catches any
-- unexpected prior state (e.g. someone having already manually dropped
-- ecr_select, or ecr_tenant_select never having been created) before this
-- migration's core change proceeds, rather than silently producing a table
-- with zero SELECT policies for qodiqa_app/qodiqa_read.
--
-- ── Statement 2: evidence_chain_records INSERT-policy duplication ─────────
-- ecr_insert (migration 010: FOR INSERT TO qodiqa_app WITH CHECK (true))
-- and ecr_system_insert (migration 018: FOR INSERT TO qodiqa_app WITH CHECK
-- (true)) are functionally IDENTICAL -- same command, same role, same
-- WITH CHECK -- unlike the SELECT pair above, this pair causes no behavior
-- asymmetry (multiple identical permissive policies just OR together to the
-- same result). Source evidence checked: migration 018's DROP POLICY IF
-- EXISTS block (018_rls_tenant_isolation.sql:326-327) never references
-- ecr_insert by name -- unlike its treatment of compliance_reports in the
-- very same file (018_rls_tenant_isolation.sql:345-350), where 018 DOES
-- explicitly list the pre-existing policy names it means to replace
-- (cr_select, cr_insert, cr_update) alongside its own new ones. The absence
-- of any such reference to ecr_insert here means there is no textual
-- evidence 018 intended to supersede it -- judged AMBIGUOUS intent, not
-- clear supersession, so ecr_insert is deliberately KEPT (not dropped) per
-- the chosen policy for the ambiguous case. Documented here
-- rather than acted on; a future migration may still consolidate the
-- duplicate if a reason to touch this table again arises.
--
-- ── Statement 3: qodiqa_audit_chain_full_read() -- SECURITY DEFINER ───────
-- Same defect class as migration 043's qodiqa_audit_chain_last_row(): a
-- SELECT against audit_chain as qodiqa_app is subject to ac_tenant_select
-- (migration 018), so pg-audit-backend.js's loadChainFromPg() -- a plain
-- `SELECT ... FROM audit_chain ORDER BY seq ASC` run via pgPool.query,
-- src/infra/postgres/pg-audit-backend.js:226-246 -- only ever sees the
-- current session's tenant (or NULL-tenant) rows, not the full chain. This
-- is exactly the "mirrorConsistencyCheck sees a partial chain" scenario the
-- Group A worklist flags as fatal. Modeled on 043 exactly: SECURITY
-- DEFINER, STABLE, LANGUAGE sql, SET search_path = pg_catalog, public, so
-- its internal SELECT bypasses RLS the same narrow way (superuser-owned
-- function, deliberate exception, not a blanket bypass grant on the
-- table). Unlike 043 (which returns only 2 scalar columns, hand-typed),
-- this function returns every column loadChainFromPg needs -- rather than
-- hand-declaring a ~20-column RETURNS TABLE(...) list (risking a
-- type/length mismatch against columns whose types have changed across
-- migrations 025/033/034/037/039), it returns SETOF audit_chain, i.e. the
-- table's own row type, which is always exactly correct by construction
-- and is a strict superset of loadChainFromPg's current SELECT column list
-- (quoted below for the record, as):
--
--   SELECT
--     hash, prev_hash AS "prevHash", canonical,
--     artifact_id AS "artifactId", decision,
--     high_res_time AS "highResTime",
--     input_hash AS "inputHash",
--     signature,
--     request_hash AS "requestHash",
--     policy_hash AS "policyHash",
--     verification_result AS "verificationResult",
--     nonce, tenant_id AS "tenantId",
--     execution_context AS "executionContext",
--     public_key_id AS "publicKeyId",
--     schema_version AS "schemaVersion",
--     consent_provenance AS "consentProvenance",
--     policy_decision AS "policyDecision",
--     caller_context AS "callerContext",
--     provider, model
--   FROM audit_chain
--   ORDER BY seq ASC
--   (src/infra/postgres/pg-audit-backend.js:226-246, current as)
--
-- The src/ change rerouting loadChainFromPg through this function
-- (`FROM qodiqa_audit_chain_full_read()` in place of `FROM audit_chain`,
-- same column list/aliases/ORDER BY) is A-impl-2 -- deliberately NOT part
-- of this migration. Per DEC-3 (differs from 043, which granted qodiqa_app
-- only): EXECUTE is granted to BOTH qodiqa_app and qodiqa_read, and
-- REVOKEd from PUBLIC.
--
-- ── Statement 4: idx_tle_prev_hash removal ─────────────────────────────────
-- idx_tle_prev_hash (migration 011:128, non-unique btree on
-- previous_entry_hash WHERE previous_entry_hash IS NOT NULL) is strictly
-- subsumed by idx_tle_prev_hash_unique (migration 042:134, UNIQUE btree,
-- identical column and identical partial predicate) -- confirmed via live
-- pg_indexes in the report: a unique index serves every query
-- pattern (lookup, range, ordering) the non-unique index would, on an
-- identical expression/predicate. Same class of cleanup as migration 042's
-- own removal of idx_ecr. Pre-flight hard-asserts idx_tle_prev_hash_unique
-- exists (the reason dropping the old index is safe); the DROP itself uses
-- IF EXISTS, so this statement remains safe to re-run even though the
-- pre-flight is a hard assert -- re-running after success finds the unique
-- index still present (assert passes) and the old index already gone
-- (IF EXISTS no-ops).
--
-- IDEMPOTENCY STANCE, per statement:
--   1. NOT blindly re-runnable (hard-asserts a specific two-policy state,
--      then an unconditional DROP POLICY with no IF EXISTS) -- deliberate,
--      by design; safe under migrate.js's normal
--      apply-once-per-version operation.
--   2. No-op (comment only, no DDL) -- trivially re-runnable.
--   3. CREATE OR REPLACE FUNCTION + GRANT -- idempotent, matching 043.
--   4. Hard-asserts a precondition, but the DROP itself is IF EXISTS --
--      re-runnable after success.

BEGIN;

-- ── Statement 1 ─────────────────────────────────────────────────────────────

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'evidence_chain_records' AND policyname = 'ecr_select'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'evidence_chain_records' AND policyname = 'ecr_tenant_select'
  ) THEN
    RAISE EXCEPTION
      'MIGRATION_044_PREFLIGHT_FAILED: expected both ecr_select and ecr_tenant_select policies to exist on evidence_chain_records before dropping ecr_select -- found state does not match. Investigate before re-running this migration.';
  END IF;
END
$$;

DROP POLICY ecr_select ON evidence_chain_records;

-- ── Statement 2 ─────────────────────────────────────────────────────────────
-- ecr_insert kept as-is -- see header (ambiguous supersession intent). No
-- DDL for this statement; documentation only.

-- ── Statement 3 ─────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_full_read()
RETURNS SETOF audit_chain
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM audit_chain ORDER BY seq ASC
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_full_read() IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS (ac_tenant_select) to return the FULL chain (every row, every tenant), ordered by seq ASC. Narrow, deliberate exception mirroring qodiqa_audit_chain_last_row() (migration 043) -- see FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION-REPORT.md and Findings Group A. Used by pg-audit-backend.js''s loadChainFromPg() so mirror-consistency checks and startup chain hydration see the true global chain instead of only the calling session''s tenant-visible slice.';

REVOKE ALL ON FUNCTION qodiqa_audit_chain_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_full_read() TO qodiqa_app, qodiqa_read;

-- ── Statement 4 ─────────────────────────────────────────────────────────────

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE schemaname = 'public' AND indexname = 'idx_tle_prev_hash_unique'
  ) THEN
    RAISE EXCEPTION
      'MIGRATION_044_PREFLIGHT_FAILED: idx_tle_prev_hash_unique not found -- refusing to drop idx_tle_prev_hash without its confirmed replacement in place. Investigate before re-running this migration.';
  END IF;
END
$$;

DROP INDEX IF EXISTS idx_tle_prev_hash;

-- ── Migration record ─────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (44, 'evidence_chain_rls_and_full_chain_read', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
