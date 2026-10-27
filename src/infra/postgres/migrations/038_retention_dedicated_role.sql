-- QODIQA PostgreSQL Migration 038
-- Retention role separation — true least-privilege execution for the
-- automated audit-retention cleanup cycle (src/core/audit/retention.js's
-- stampRetentionDates()/expireEvents(), run via the new
-- src/infra/postgres/retentionPool.js).
--
-- ROOT CAUSE (see retention.js's former module header and migration 027's
-- header): the retention cleanup cycle has always executed its UPDATE/DELETE
-- statements through qodiqa_app — the same broad application role every
-- request-serving code path uses. qodiqa_app holds SELECT/INSERT/UPDATE/
-- DELETE on most of the schema (migration 002), far more than an unattended
-- job that only stamps and deletes expired platform_audit_events rows needs.
--
-- WHAT THIS MIGRATION DOES:
--   Creates a new, narrower role — qodiqa_retention — and grants it exactly
--   the three privileges the retention cycle's real code paths issue:
--     - SELECT on audit_retention_policies   (stampRetentionDates() reads policies)
--     - SELECT, INSERT on audit_retention_runs (runRetentionCycle() journals every run)
--     - SELECT, UPDATE, DELETE on platform_audit_events (the actual stamping/expiry)
--   Nothing else: no other table, no schema-modification (DDL) rights, no
--   administrative tables (rbac_users, policies, signing_keys, ...), no
--   sequence access beyond what audit_retention_runs' SERIAL id requires.
--
-- WHAT THIS MIGRATION DELIBERATELY DOES NOT DO:
--   It does not revoke or alter qodiqa_app's existing grants (including the
--   UPDATE/DELETE on platform_audit_events that migration 027 already
--   granted it) — existing application roles must remain unchanged. Legal
--   hold management (placeLegalHold/releaseLegalHold) and retention-policy
--   CRUD (upsertPolicy) remain on qodiqa_app: those are human-triggered,
--   RBAC-gated admin-API operations, not part of the unattended cleanup
--   cycle this migration scopes.
--
-- RLS: platform_audit_events already has FORCE ROW LEVEL SECURITY enabled
-- (migration 003) with only INSERT/SELECT policies for qodiqa_app and a
-- system-wide UPDATE/DELETE policy added for qodiqa_app by migration 027.
-- New policies below grant the equivalent SELECT/UPDATE/DELETE access to
-- qodiqa_retention specifically, mirroring 027's unconditional USING (true)
-- shape and its documented reasoning (retention is a cross-tenant background
-- job — qodiqa.tenant_id is never set for it, so a tenant-scoped policy
-- would block every row).
--
-- A dedicated SELECT policy (pae_retention_select) is required, not just
-- UPDATE/DELETE: PostgreSQL RLS requires a row to be visible under an
-- applicable SELECT policy before an UPDATE or DELETE policy's USING clause
-- is even consulted (the same "SELECT visibility gates UPDATE/DELETE"
-- behavior migration 027's header documents for FOR UPDATE SKIP LOCKED
-- subqueries — here it applies to the plain UPDATE/DELETE statements
-- themselves, confirmed empirically: without this policy, qodiqa_retention's
-- UPDATE/DELETE silently affect 0 rows despite holding the base GRANT and
-- their own unconditional UPDATE/DELETE policies). The existing pae_select
-- policy (migration 003) is deliberately left untouched rather than adding
-- qodiqa_retention to its role list — a new, dedicated policy keeps this
-- migration self-contained and keeps qodiqa_retention's grant surface
-- entirely defined in one place.
--
-- IDEMPOTENT: role creation guarded by IF NOT EXISTS (matching 002); DROP
-- POLICY IF EXISTS before CREATE POLICY (matching 027); GRANT is itself
-- idempotent.
--
-- the GRANT CONNECT statement below used to
-- hardcode the literal database name "qodiqa", identical to migration 002's
-- own bug (same root cause, same live reproduction, see 002's own header for
-- the full account). Migration 045 previously attempted to patch this
-- specific instance via a new additive migration — that pattern is
-- structurally incapable of working here: this whole migration is one
-- BEGIN/COMMIT, so the GRANT CONNECT failure rolls back CREATE ROLE
-- qodiqa_retention too, and migrate.js aborts the entire run before 045 (a
-- later migration) is ever reached. Fixed directly, in this file, as an
-- exception to the normal "never edit an applied migration" rule — see
-- docs/operations/database-role-management.md ("Exception: migrations 002
-- and 038 hardcoded-database-name fix,"). Migration 045 is left in place
-- (now a harmless idempotent no-op re-grant) rather than deleted, since it
-- is itself already an applied migration on every real deployment.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_retention') THEN
        CREATE ROLE qodiqa_retention LOGIN PASSWORD 'REPLACE_WITH_VAULT_SECRET_RETENTION';
    END IF;
END
$$;

-- ── qodiqa_retention permissions ──────────────────────────────────────────────

DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO qodiqa_retention', current_database()); END $$;
GRANT USAGE ON SCHEMA public TO qodiqa_retention;

GRANT SELECT               ON audit_retention_policies TO qodiqa_retention;

GRANT SELECT, INSERT       ON audit_retention_runs     TO qodiqa_retention;
GRANT USAGE, SELECT ON SEQUENCE audit_retention_runs_id_seq TO qodiqa_retention;

GRANT SELECT, UPDATE, DELETE ON platform_audit_events   TO qodiqa_retention;

-- ── Row-level security: platform_audit_events SELECT/UPDATE/DELETE for qodiqa_retention ─

DROP POLICY IF EXISTS pae_retention_select ON platform_audit_events;
DROP POLICY IF EXISTS pae_retention_update ON platform_audit_events;
DROP POLICY IF EXISTS pae_retention_delete ON platform_audit_events;

CREATE POLICY pae_retention_select
  ON platform_audit_events
  FOR SELECT TO qodiqa_retention
  USING (true);

CREATE POLICY pae_retention_update
  ON platform_audit_events
  FOR UPDATE TO qodiqa_retention
  USING     (true)
  WITH CHECK (true);

CREATE POLICY pae_retention_delete
  ON platform_audit_events
  FOR DELETE TO qodiqa_retention
  USING (true);

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (38, 'retention_dedicated_role', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
