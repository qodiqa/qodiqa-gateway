-- Migration 051: Per-tenant policy sets + per-tenant semantic configuration
--
--
-- PROVENANCE NOTE: this migration was created AND finalized inside the one
-- session before its first commit (8fa1254) — it was
-- iterated on against local development databases only during that session,
-- and the "never edit an already-applied migration" rule applies to it in
-- full from that commit onward.
--
-- Two configuration tables, one row per tenant, PostgreSQL authoritative:
--
--   tenant_policy_sets       — the tenant's complete policy array (same
--                              schema as policies.json), replacing the
--                              global set for that tenant's evaluation when
--                              present (aiChat.js's existing semantics).
--   tenant_semantic_configs  — the tenant's TIGHTEN-ONLY semantic overlay
--                              (tier thresholds / WARN_BLOCKS / embedding
--                              score bar). Loosening is rejected at write
--                              time and clamped at load time in the
--                              application layer (tenantSemanticRegistry);
--                              this schema stores whatever the governed
--                              publish step accepted.
--
-- Both are written ONLY by the governed publish step
-- (PolicyGovernanceService.publish() → tenantConfigStore.js), which sets
-- the transaction-local tenant context first — so the strict RLS model
-- below (migration 018's NOT NULL tenant_id idiom) holds for every write.
--
-- Boot hydration reads ALL tenants' rows (platform-wide, no tenant
-- context) — served by the two SECURITY DEFINER full-read functions below,
-- the 043/044/048/049/050 idiom: a narrow, deliberate, auditable exception
-- per query shape, never a blanket bypass grant on the table itself.

BEGIN;

-- ── tenant_policy_sets ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenant_policy_sets (
    tenant_id          VARCHAR(128)  PRIMARY KEY,
    policies           JSONB         NOT NULL,
    policies_hash      VARCHAR(64)   NOT NULL,
    version            INTEGER       NOT NULL DEFAULT 1,
    change_request_id  UUID,
    updated_by         VARCHAR(256),
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT tps_policies_is_array CHECK (jsonb_typeof(policies) = 'array')
);

ALTER TABLE tenant_policy_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_policy_sets FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tps_tenant_select ON tenant_policy_sets;
DROP POLICY IF EXISTS tps_tenant_insert ON tenant_policy_sets;
DROP POLICY IF EXISTS tps_tenant_update ON tenant_policy_sets;

CREATE POLICY tps_tenant_select ON tenant_policy_sets
    FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY tps_tenant_insert ON tenant_policy_sets
    FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY tps_tenant_update ON tenant_policy_sets
    FOR UPDATE USING (tenant_id = qodiqa_current_tenant())
               WITH CHECK (tenant_id = qodiqa_current_tenant());

GRANT SELECT, INSERT, UPDATE ON tenant_policy_sets TO qodiqa_app;
GRANT SELECT                 ON tenant_policy_sets TO qodiqa_read;

-- ── tenant_semantic_configs ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenant_semantic_configs (
    tenant_id          VARCHAR(128)  PRIMARY KEY,
    config             JSONB         NOT NULL,
    config_hash        VARCHAR(64)   NOT NULL,
    version            INTEGER       NOT NULL DEFAULT 1,
    change_request_id  UUID,
    updated_by         VARCHAR(256),
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT tsc_config_is_object CHECK (jsonb_typeof(config) = 'object')
);

ALTER TABLE tenant_semantic_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_semantic_configs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tsc_tenant_select ON tenant_semantic_configs;
DROP POLICY IF EXISTS tsc_tenant_insert ON tenant_semantic_configs;
DROP POLICY IF EXISTS tsc_tenant_update ON tenant_semantic_configs;

CREATE POLICY tsc_tenant_select ON tenant_semantic_configs
    FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY tsc_tenant_insert ON tenant_semantic_configs
    FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY tsc_tenant_update ON tenant_semantic_configs
    FOR UPDATE USING (tenant_id = qodiqa_current_tenant())
               WITH CHECK (tenant_id = qodiqa_current_tenant());

GRANT SELECT, INSERT, UPDATE ON tenant_semantic_configs TO qodiqa_app;
GRANT SELECT                 ON tenant_semantic_configs TO qodiqa_read;

-- ── Platform-wide hydration reads (SECURITY DEFINER, per-shape) ─────────────
-- Read by tenantConfigHydrator.js at boot and on the periodic refresh: the
-- platform process has no tenant context (deliberately), so a plain SELECT
-- would see zero rows under the strict policies above. One function per
-- table, full-row SETOF returns (a strict superset of any caller column
-- list — 044's reasoning), STABLE, search_path pinned.

CREATE OR REPLACE FUNCTION qodiqa_tenant_policy_sets_full_read()
RETURNS SETOF tenant_policy_sets
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$ SELECT * FROM tenant_policy_sets ORDER BY tenant_id $$;

CREATE OR REPLACE FUNCTION qodiqa_tenant_semantic_configs_full_read()
RETURNS SETOF tenant_semantic_configs
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$ SELECT * FROM tenant_semantic_configs ORDER BY tenant_id $$;

REVOKE ALL ON FUNCTION qodiqa_tenant_policy_sets_full_read()      FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_tenant_semantic_configs_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_tenant_policy_sets_full_read()      TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_tenant_semantic_configs_full_read() TO qodiqa_app, qodiqa_read;

-- ── Governance by-id read across tenant scopes ──────────────────────────────
-- The lifecycle (submit/review/approve/publish, ChangeRequestStore.
-- findById) is an OPERATOR surface: operators legitimately act on change
-- requests across every tenant, but migration 029's nullable-model RLS
-- hides a tenant-scoped policy_change_requests row from the contextless
-- findById() read — which is one of the reasons tenant_id support in this
-- schema was never actually usable end to end. Same
-- reasoning as the verifier bypass functions: a genuinely-global admin
-- operation gets a narrow, per-shape SECURITY DEFINER read, never a
-- blanket bypass. All WRITES still run under the request's own tenant
-- context (pool.withTenantTransaction — see PolicyGovernanceService).
CREATE OR REPLACE FUNCTION qodiqa_policy_change_request_by_id(p_id UUID)
RETURNS SETOF policy_change_requests
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$ SELECT * FROM policy_change_requests WHERE id = p_id $$;

REVOKE ALL ON FUNCTION qodiqa_policy_change_request_by_id(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_policy_change_request_by_id(UUID) TO qodiqa_app, qodiqa_read;

-- ── Migration record ─────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (51, 'tenant_policy_config', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
