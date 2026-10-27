-- Migration 020: Organization and Tenant Persistence — Component #39
--
-- Creates durable storage for the organization and tenant registry.
-- The in-memory registries (organizationRegistry.js, tenantRegistry.js) are
-- the authoritative source of truth for the enforcement path.  These tables
-- serve as the durable backing store that survives process restarts.
--
-- Enforcement reads always go through in-memory registries (loaded at startup
-- from JSON files or provisioned via the admin API).  PostgreSQL is the
-- secondary persistence layer and is not on the request hot path.
--
-- Row-Level Security: both tables follow the strict isolation pattern from
-- migration 018 — rows are only visible to the tenant that owns them.
-- Cross-tenant queries require SUPERUSER or a set qodiqa.tenant_id that matches.

BEGIN;

-- ── organizations ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS organizations (
  organization_id   TEXT        PRIMARY KEY,
  organization_name TEXT        NOT NULL,
  status            TEXT        NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'suspended', 'disabled')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata          JSONB       NOT NULL DEFAULT '{}',
  quotas            JSONB       NOT NULL DEFAULT '{
    "maxRequestsPerMinute": 5000,
    "maxRequestsPerKeyPerMin": 100,
    "maxStreamingSessions": 500,
    "retentionDays": 365
  }'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_organizations_status
  ON organizations (status);

CREATE INDEX IF NOT EXISTS idx_organizations_created_at
  ON organizations (created_at DESC);

COMMENT ON TABLE  organizations                      IS 'Top-level billing and administrative entities (Component #39)';
COMMENT ON COLUMN organizations.organization_id      IS 'UUID v4 primary key, immutable';
COMMENT ON COLUMN organizations.status               IS 'active|suspended|disabled — suspended/disabled block all tenant execution';
COMMENT ON COLUMN organizations.quotas               IS 'Per-org quota overrides; merged with platform defaults at enforcement time';

-- ── tenants ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
  tenant_id         TEXT        PRIMARY KEY,
  tenant_name       TEXT        NOT NULL,
  organization_id   TEXT        REFERENCES organizations(organization_id) ON DELETE SET NULL,
  status            TEXT        NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'suspended', 'disabled', 'inactive')),
  quotas            JSONB,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenants_organization_id
  ON tenants (organization_id);

CREATE INDEX IF NOT EXISTS idx_tenants_status
  ON tenants (status);

COMMENT ON TABLE  tenants                IS 'Isolated execution contexts belonging to an organization (Component #39)';
COMMENT ON COLUMN tenants.tenant_id      IS 'Matches the clientId prefix in publicKeyId: "${tenantId}:key_v${N}"';
COMMENT ON COLUMN tenants.quotas         IS 'Per-tenant quota overrides; NULL falls through to org-level quotas';

-- ── Row-Level Security — Organizations ───────────────────────────────────────
--
-- Organizations have no tenant_id column — they ARE the top-level entities.
-- Admin-level read access is intentionally open (any authenticated session can
-- read org metadata for display).  Writes require explicit admin authorization
-- enforced at the application layer (ops auth + RBAC).

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

-- Admin sessions (no tenant context set) can read all organizations
CREATE POLICY orgs_admin_select ON organizations
  FOR SELECT USING (current_setting('qodiqa.tenant_id', true) IS NULL
                    OR current_setting('qodiqa.tenant_id', true) = '');

-- Only superuser may insert/update/delete
CREATE POLICY orgs_admin_write ON organizations
  FOR ALL USING (pg_has_role(current_user, 'rds_superuser', 'USAGE')
                 OR current_user = 'qodiqa_admin');

-- ── Row-Level Security — Tenants ─────────────────────────────────────────────

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

-- A session may see its own tenant record, or all records if no tenant context is set
CREATE POLICY tenants_isolation ON tenants
  FOR SELECT USING (
    current_setting('qodiqa.tenant_id', true) IS NULL
    OR current_setting('qodiqa.tenant_id', true) = ''
    OR tenant_id = current_setting('qodiqa.tenant_id', true)
  );

-- Only superuser / admin may write tenant records
CREATE POLICY tenants_admin_write ON tenants
  FOR ALL USING (pg_has_role(current_user, 'rds_superuser', 'USAGE')
                 OR current_user = 'qodiqa_admin');

-- ── platform_audit_events — backfill organization_id column ──────────────────
--
-- The existing platform_audit_events table (from prior migrations) receives an
-- optional organization_id column.  Existing rows remain valid (NULL = no org).

ALTER TABLE platform_audit_events
  ADD COLUMN IF NOT EXISTS organization_id TEXT REFERENCES organizations(organization_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_audit_events_organization_id
  ON platform_audit_events (organization_id)
  WHERE organization_id IS NOT NULL;

COMMENT ON COLUMN platform_audit_events.organization_id
  IS 'Owning organization at the time of event; NULL for events before Component #39';

-- ── Update timestamp trigger ──────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS set_organizations_updated_at ON organizations;
CREATE TRIGGER set_organizations_updated_at
  BEFORE UPDATE ON organizations
  FOR EACH ROW EXECUTE FUNCTION qodiqa_set_updated_at();

DROP TRIGGER IF EXISTS set_tenants_updated_at ON tenants;
CREATE TRIGGER set_tenants_updated_at
  BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION qodiqa_set_updated_at();

COMMIT;
