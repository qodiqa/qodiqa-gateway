-- QODIQA PostgreSQL Migration 054
-- qodiqa_retention has no RLS policy on audit_retention_policies --
-- the automated retention job's stampRetentionDates() reads this table via
-- retentionPool (role qodiqa_retention), which migration 038 already grants
-- a base SELECT privilege on this exact table, but no CREATE POLICY was ever
-- added naming qodiqa_retention. With FORCE ROW LEVEL SECURITY and zero
-- applicable policy for that role, every SELECT it runs returns zero rows
-- unconditionally -- stampRetentionDates() can never see a single retention
-- policy, tenant-scoped or platform-wide, so no event category's retain_until
-- date is ever stamped and configured retention silently never applies.
--
-- SCOPE DECISION ( D2, resolving the register's
-- own recorded blocker "platform-only vs. all-tenant read" -- not deferred to
-- an owner, determined by the already-shipped code this policy must serve):
-- ALL-TENANT READ. stampRetentionDates() reads every policy row (platform-wide
-- AND every tenant's) in one unscoped query, then applies each policy's own
-- tenant_id (if any) as a per-row WHERE clause in a SEPARATE UPDATE against
-- platform_audit_events. A platform-only policy would silently stop every
-- tenant-scoped retention rule from ever being read -- a regression, not a
-- fix. This exactly mirrors pae_retention_select's own already-shipped shape
-- in the SAME migration (038) for the SAME role on the sibling table --
-- completing a pattern the original author already applied once and
-- evidently omitted here, not introducing a new one.
--
-- LEAST PRIVILEGE: SELECT only -- stampRetentionDates() never writes to
-- audit_retention_policies (confirmed by reading retention.js in full; no
-- INSERT/UPDATE/DELETE against this table exists anywhere in the codebase).
-- No other privilege is added. qodiqa_retention's existing grant set
-- (migration 038) is otherwise completely untouched -- this migration adds
-- exactly one RLS policy, nothing else.
--
-- RLS UNCHANGED FOR EVERY OTHER ROLE: arp_tenant_select/_insert/_update/_delete
-- (migration 018, qodiqa_app/qodiqa_read) are not modified, dropped, or
-- recreated. This migration ADDS a new, additional permissive policy for a
-- role (qodiqa_retention) that previously had none on this table -- it does
-- not touch any existing policy on any table.
--
-- IDEMPOTENT: DROP POLICY IF EXISTS before CREATE POLICY, matching every
-- other RLS migration in this chain (018, 027, 038, 052, 053).

BEGIN;

DROP POLICY IF EXISTS arp_retention_select ON audit_retention_policies;

CREATE POLICY arp_retention_select
  ON audit_retention_policies
  FOR SELECT TO qodiqa_retention
  USING (true);

COMMENT ON TABLE audit_retention_policies IS
  'Configurable audit-event retention rules; tenant_id nullable (NULL = platform-wide policy, non-NULL = one tenant''s policy). '
  ': added arp_retention_select granting qodiqa_retention unconditional SELECT, mirroring '
  'platform_audit_events'' pae_retention_select (migration 038) for the same role -- the automated retention '
  'cycle''s stampRetentionDates() must see every policy row (platform-wide and every tenant''s) in one read, then '
  'applies each policy''s own tenant_id as a per-row filter in a separate statement. qodiqa_app''s existing tenant-'
  'scoped policies (arp_tenant_select/_insert/_update/_delete, migration 018) are unchanged.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (54, 'rem062_retention_policy_read_grant', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
