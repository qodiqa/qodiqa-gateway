-- QODIQA PostgreSQL Migration 062
--.
--
-- 1. tenants / organizations (D2): the SELECT policies returned EVERY row when
--    qodiqa.tenant_id was unset or '' (tenants_isolation, orgs_admin_select),
--    FORCE RLS was off, and the write policies referenced roles that do not
--    exist (rds_superuser, qodiqa_admin). After: zero rows without tenant
--    context, FORCE RLS on, writes denied by policy (the owner/migrator bypasses
--    RLS via BYPASSRLS; the file stores stay authoritative until).
--
-- 2. platform_audit_events (D3): qodiqa_app could UPDATE and DELETE any row
--    (policies pae_system_update / pae_system_delete, USING true). After: the
--    app keeps INSERT, plus column-level UPDATE (legal_hold) for placing a legal
--    hold (src/core/audit/retention.js). A BEFORE UPDATE/DELETE trigger refuses
--    anything else unless the session role is qodiqa_retention (retention
--    stamping/deletion) or a BYPASSRLS role (owner/migrator, and the owner-run
--    erase function of migration 063).
--
-- 3. audit_checksum_anchor (D3): the app UPSERTs {count, tail_hash} on every
--    append (checksumAnchor.js). A BEFORE UPDATE/DELETE trigger makes it
--    forward-only for everyone but BYPASSRLS roles: count may not decrease, and
--    tail_hash may not change without count increasing. A rollback attempt fails
--    (checksumAnchor.js logs AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED; the append is
--    unaffected).
--
-- IDENTITY: policy and trigger DDL require the table owner — qodiqa_mig after
-- (055) on deployments, qodiqa_test on disposable DBs.

BEGIN;

-- ── 1. tenants / organizations ────────────────────────────────────────────────
DROP POLICY IF EXISTS tenants_isolation   ON tenants;
DROP POLICY IF EXISTS tenants_admin_write ON tenants;
CREATE POLICY tenants_isolation ON tenants FOR SELECT
  USING (tenant_id = current_setting('qodiqa.tenant_id', true));
CREATE POLICY tenants_admin_write ON tenants FOR ALL
  USING (false) WITH CHECK (false);
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS orgs_admin_select ON organizations;
DROP POLICY IF EXISTS orgs_admin_write  ON organizations;
CREATE POLICY orgs_admin_select ON organizations FOR SELECT
  USING (organization_id IN (SELECT t.organization_id FROM tenants t
                              WHERE t.tenant_id = current_setting('qodiqa.tenant_id', true)));
CREATE POLICY orgs_admin_write ON organizations FOR ALL
  USING (false) WITH CHECK (false);
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;

-- ── 2. platform_audit_events: append-only for the app role ────────────────────
REVOKE UPDATE, DELETE, TRUNCATE ON platform_audit_events FROM qodiqa_app;
GRANT UPDATE (legal_hold) ON platform_audit_events TO qodiqa_app;
DROP POLICY IF EXISTS pae_system_delete ON platform_audit_events;

CREATE OR REPLACE FUNCTION qodiqa_platform_audit_events_append_only_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF current_user = 'qodiqa_retention'
     OR (SELECT r.rolbypassrls FROM pg_roles r WHERE r.rolname = current_user) THEN
    RETURN COALESCE(NEW, OLD);
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'platform_audit_events is append-only for role %', current_user USING ERRCODE = '42501';
  END IF;
  IF NOT (OLD.legal_hold = false AND NEW.legal_hold = true)
     OR (to_jsonb(NEW) - 'legal_hold') IS DISTINCT FROM (to_jsonb(OLD) - 'legal_hold') THEN
    RAISE EXCEPTION 'platform_audit_events: role % may only place a legal hold (legal_hold false -> true)', current_user
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS platform_audit_events_append_only_guard ON platform_audit_events;
CREATE TRIGGER platform_audit_events_append_only_guard
  BEFORE UPDATE OR DELETE ON platform_audit_events
  FOR EACH ROW EXECUTE FUNCTION qodiqa_platform_audit_events_append_only_guard();

-- ── 3. audit_checksum_anchor: forward-only ─────────────────────────────────────
REVOKE DELETE, TRUNCATE ON audit_checksum_anchor FROM qodiqa_app;

CREATE OR REPLACE FUNCTION qodiqa_audit_checksum_anchor_monotonic_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF (SELECT r.rolbypassrls FROM pg_roles r WHERE r.rolname = current_user) THEN
    RETURN COALESCE(NEW, OLD);
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'audit_checksum_anchor cannot be deleted by role %', current_user USING ERRCODE = '42501';
  END IF;
  IF NEW.count < OLD.count
     OR (NEW.count = OLD.count AND NEW.tail_hash IS DISTINCT FROM OLD.tail_hash) THEN
    RAISE EXCEPTION 'audit_checksum_anchor is forward-only: count % -> % refused for role %', OLD.count, NEW.count, current_user
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS audit_checksum_anchor_monotonic_guard ON audit_checksum_anchor;
CREATE TRIGGER audit_checksum_anchor_monotonic_guard
  BEFORE UPDATE OR DELETE ON audit_checksum_anchor
  FOR EACH ROW EXECUTE FUNCTION qodiqa_audit_checksum_anchor_monotonic_guard();

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (62, 'w5_tenant_rls_append_only', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
