-- QODIQA PostgreSQL Migration 024
-- Fixes the same gap in transparency_log_entries/transparency_roots that
-- migration 022 fixed for consent_records: registrar.js's register() and
-- generateRoot() use `SELECT ... FOR UPDATE` (logStore.js's getLatestEntry/
-- getLatestRoot) to serialize concurrent writers. Postgres requires a row
-- to satisfy an applicable UPDATE-command RLS policy (in addition to the
-- SELECT policy) for FOR UPDATE/FOR SHARE locking to succeed on a table
-- with FORCE ROW LEVEL SECURITY enabled (both tables have had this set
-- since migration 011). Neither migration 011 (original SELECT/INSERT-only
-- policies) nor migration 018 (later tenant-aware SELECT/INSERT overrides)
-- ever added an UPDATE policy or an UPDATE grant for either table —
-- meaning every transparency-log write (registrar.register(),
-- registrar.generateRoot()) has always failed under RLS enforcement with
-- "permission denied for table transparency_log_entries" /
-- "... transparency_roots". Confirmed via the acceptance test framework
-- (AT-076) against a fresh, fully-migrated Postgres instance.
--
-- The UPDATE policy exists solely to satisfy the FOR UPDATE locking
-- requirement — no application code ever issues a real UPDATE statement
-- against either table (both are append-only ledgers).
--
-- transparency_log_entries has a tenant_id column and was given a
-- tenant-aware SELECT policy (tle_tenant_select) by migration 018 — the
-- new UPDATE policy mirrors that same condition for consistency.
-- transparency_roots has NO tenant_id column (roots aggregate across the
-- whole log; migration 018 never touched this table), and its live
-- SELECT/INSERT policies (tr_select/tr_insert, from migration 011) are
-- unconditional (USING/WITH CHECK true) — the new UPDATE policy matches
-- that same unconditional shape.
--
-- IDEMPOTENT: DROP POLICY IF EXISTS before CREATE POLICY; GRANT is itself
-- idempotent (re-granting an already-held privilege is a no-op).

BEGIN;

DROP POLICY IF EXISTS tle_tenant_update ON transparency_log_entries;
DROP POLICY IF EXISTS tr_update         ON transparency_roots;

CREATE POLICY tle_tenant_update
  ON transparency_log_entries
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY tr_update
  ON transparency_roots
  FOR UPDATE TO qodiqa_app
  USING (true)
  WITH CHECK (true);

GRANT UPDATE ON transparency_log_entries TO qodiqa_app;
GRANT UPDATE ON transparency_roots       TO qodiqa_app;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (24, 'transparency_log_grants_fix', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
