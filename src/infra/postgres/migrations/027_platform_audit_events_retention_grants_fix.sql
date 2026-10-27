-- QODIQA PostgreSQL Migration 027
-- Fixes a privilege gap in platform_audit_events that leaves the
-- automated retention job (src/core/audit/retention.js) completely unable
-- to write to the table it exists to maintain, once QODIQA_PG_ENABLED=true.
--
-- ROOT CAUSE:
-- Migration 003 granted qodiqa_app only SELECT, INSERT on platform_audit_events
-- (line 211 of 003_audit_store.sql). Migration 018 enabled FORCE ROW LEVEL
-- SECURITY on the table and defined only pae_tenant_select (SELECT) and
-- pae_system_insert (INSERT) policies. No migration has ever granted UPDATE
-- or DELETE, and no UPDATE or DELETE policy has ever existed for this table.
-- That gap breaks two independent code paths in retention.js:
--
--   1. stampRetentionDates() issues a direct
--        UPDATE platform_audit_events SET retain_until = $n WHERE ...
--      which requires both the base UPDATE privilege and a passing UPDATE
--      RLS policy. Neither exists — every call fails with
--      "permission denied for table platform_audit_events".
--
--   2. expireEvents() issues
--        DELETE FROM platform_audit_events WHERE id IN (
--          SELECT id FROM platform_audit_events WHERE ... FOR UPDATE SKIP LOCKED
--        )
--      which requires the base DELETE privilege and a passing DELETE policy
--      for the outer DELETE — AND, per PostgreSQL's row-security semantics
--      (confirmed in this codebase by migration 024's identical finding for
--      transparency_log_entries/transparency_roots: "Postgres requires a row
--      to satisfy an applicable UPDATE-command RLS policy, in addition to the
--      SELECT policy, for FOR UPDATE/FOR SHARE locking to succeed on a table
--      with FORCE ROW LEVEL SECURITY"), the inner SELECT ... FOR UPDATE SKIP
--      LOCKED subquery ALSO requires the base UPDATE privilege and a passing
--      UPDATE policy, even though it never writes a column. Neither the
--      DELETE nor the UPDATE requirement is met today.
--
-- Both operations run through the standard qodiqa_app application pool
-- (pgPool.query), not a separate maintenance role, and neither sets a tenant
-- context (retention is a platform-wide background job, not a per-request,
-- per-tenant operation) — stampRetentionDates() updates rows across every
-- tenant in a single statement and expireEvents() deletes across every
-- tenant in a single statement. A tenant-scoped policy (as used for SELECT
-- via pae_tenant_select) would therefore block every row, since
-- qodiqa_current_tenant() evaluates to NULL outside of a tenant transaction.
-- The new policies below are accordingly unconditional (USING true), mirroring
-- the existing pae_system_insert policy's shape and scope: qodiqa_app already
-- holds unconditional INSERT on this exact table for the same structural
-- reason (audit events are written cross-tenant by the request pipeline).
--
-- LEAST PRIVILEGE:
--   - Only qodiqa_app receives UPDATE/DELETE — qodiqa_read (read-only
--     reporting role) receives neither, preserving its read-only guarantee.
--   - qodiqa_mig already bypasses RLS (BYPASSRLS, migration 018) and is never
--     used at runtime — untouched here.
--   - The grants are scoped to exactly one table (platform_audit_events) and
--     exactly the two privileges retention.js's existing code requires.
--     ENFORCEMENT-category events remain undeletable in practice: retention.js
--     itself never stamps or targets them (stampRetentionDates() excludes
--     event_category != 'ENFORCEMENT'; expireEvents() repeats the same guard
--     in its DELETE WHERE clause) — this migration does not alter that
--     application-level invariant, it only unblocks the privilege layer
--     beneath it.
--
-- IDEMPOTENT: DROP POLICY IF EXISTS before CREATE POLICY; GRANT is itself
-- idempotent (re-granting an already-held privilege is a no-op), consistent
-- with every other grants-fix migration (022, 024).

BEGIN;

DROP POLICY IF EXISTS pae_system_update ON platform_audit_events;
DROP POLICY IF EXISTS pae_system_delete ON platform_audit_events;

CREATE POLICY pae_system_update
  ON platform_audit_events
  FOR UPDATE TO qodiqa_app
  USING     (true)
  WITH CHECK (true);

CREATE POLICY pae_system_delete
  ON platform_audit_events
  FOR DELETE TO qodiqa_app
  USING (true);

GRANT UPDATE, DELETE ON platform_audit_events TO qodiqa_app;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (27, 'platform_audit_events_retention_grants_fix', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
