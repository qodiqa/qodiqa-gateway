-- QODIQA PostgreSQL Migration 052
-- close the RLS gap on the tables that carry no Row-Level Security
-- at all.
--
-- BACKGROUND: an earlier schema inventory
-- recorded "43/52 tables FORCE RLS; nine tables without" at audit time. The
-- schema has grown considerably since then (74 tables now exist in schema
-- public), and a fresh live catalog query for this migration found 13
-- tables with relrowsecurity = false, not 9: two of the originally-named
-- nine (kms_provider_events, kms_wrapping_key_rotations) already gained
-- RLS+FORCE via migration 018's own "Consolidation" section and are no
-- longer in the gap; six further tables that either postdate the original
-- audit or were never counted in it (policy_history, policy_versions,
-- qodiqa_migrations, rbac_users, signing_key_legacy_map, signing_keys) are
-- newly identified as lacking RLS. This migration closes the CURRENT gap
-- (13 tables), not merely the seven still-open names from the original
-- nine. for the full per-table
-- reconstruction this migration is based on.
--
-- DISPOSITION (11 of 13 tables — GENUINELY GLOBAL, RLS deliberately NOT
-- added,'s own target: "every tenant-relevant table has RLS +
-- FORCE RLS, OR a written justification for exclusion"):
--
--   qodiqa_migrations            — schema-migration bookkeeping; one schema,
--                                   shared by every tenant; no tenant column,
--                                   no code path connects it to a tenant.
--   rbac_users                   — QODIQA PLATFORM OPERATOR accounts (role
--                                   CHECK constraint: admin/auditor/
--                                   compliance/operator/viewer — the same
--                                   non-tenant-scoped RBAC model's
--                                   own audit already confirmed has no
--                                   tenant concept at all). The live RBAC
--                                   store is file-based (src/core/rbac/
--                                   store.js, data/rbac-users.json); this
--                                   table is a dormant one-time-migrated
--                                   snapshot with no tenant filter anywhere
--                                   it is read.
--   policies, policy_versions,
--   policy_history                — the platform's single global default
--                                   enforcement rule set (src/core/policy/
--                                   store.js, policies.json/data/policy-
--                                   store.json — file-based, not read from
--                                   these tables in production). Distinct
--                                   from tenant_policy_sets/
--                                   tenant_semantic_configs (051, correctly
--                                   tenant-scoped by tenant_id PRIMARY KEY)
--                                   and policy_change_requests (029,
--                                   correctly tenant-scoped via nullable
--                                   tenant_id) — those two families already
--                                   have RLS; this one never had a tenant
--                                   column because it isn't tenant data.
--   investigations,
--   investigation_artifacts,
--   investigation_audit_events    — internal forensic-investigation tooling
--                                   (src/core/investigation/store.js, file-
--                                   based). No tenant column anywhere in the
--                                   family; investigator is a human
--                                   investigator identity, not a tenant. No
--                                   HTTP route exposes any of these three
--                                   tables. A forensic investigation can
--                                   legitimately span artifacts from any
--                                   tenant by its very nature.
--   evidence_packages             — has zero application readers or writers
--                                   anywhere in src/ (confirmed by direct
--                                   search — not even the one-time file-to-
--                                   Postgres migration script populates it);
--                                   no tenant column exists to key a policy
--                                   on. Dormant. If this table is ever wired
--                                   up to a live feature, tenant relevance
--                                   must be re-assessed at that time — see
--                                   the FOLLOW-UP note in this migration's
--                                   evidence package.
--   audit_retention_runs           — global retention-job execution log.
--                                   Traced the policy_id -> audit_retention_
--                                   policies(tenant_id) foreign key
--                                   explicitly: policy_id is never populated
--                                   by the live retention engine (src/core/
--), and one "run"
--                                   always processes every retention policy
--                                   (platform-wide and tenant-scoped alike)
--                                   against the single shared
--                                   platform_audit_events table in one pass
--                                   — a run record summarizes one platform-
--                                   wide cycle, not one tenant's policy
--                                   execution. No route or parameter scopes
--                                   either the trigger or the read to one
--                                   tenant.
--   gap_scanner_state              — CONSTRAINT gss_single_row CHECK (id = 1)
--                                   enforces exactly one row can ever exist
--                                   in this table. Tenant isolation is not a
--                                   coherent concept for a single-row,
--                                   platform-wide background-scanner
--                                   checkpoint. No route exposes it.
--
-- DISPOSITION (2 of 13 tables — TENANT-RELEVANT, remediated by this
-- migration):
--
--   signing_keys                   — client_id VARCHAR(64) NOT NULL is,
--                                   per this codebase's own tenancy module
--                                   (src/core/tenancy/tenantRegistry.js:
--                                   "The clientId IS the tenantId — pulled
--                                   from the publicKeyId prefix"), literally
--                                   the tenant identifier. Migration 018's
--                                   original "TABLES EXCLUDED" list named
--                                   this table as having "no tenant
--                                   ownership" — that predates or overlooked
--                                   tenantRegistry.js's own documentation
--                                   and is corrected here. A signing key's
--                                   metadata (algorithm, status, rotation/
--                                   expiry timestamps — not the encrypted
--                                   private key material, which the
--                                   application never even selects from
--                                   this table) belongs to exactly one
--                                   client/tenant and must not be visible to
--                                   another. The live application persists
--                                   keys to a file (services/artifact/
--                                   keyStore.js, data/keys.json) — this
--                                   table is a dormant one-time-migrated
--                                   snapshot today, but its data
--                                   classification is unambiguous, and if it
--                                   is ever revived as a live store the RLS
--                                   boundary must already exist.
--   signing_key_legacy_map         — no client_id column of its own, but
--                                   new_key_id is a NOT NULL FK to
--                                   signing_keys(key_id), and every key_id
--                                   embeds its owning client_id as the
--                                   'clientId:key_vN' prefix — an
--                                   unambiguous indirect tenant link,
--                                   isolated here via the same FK-subquery
--                                   idiom migration 018 already established
--                                   for webhook_delivery_log (no tenant_id
--                                   column of its own; isolated via a
--                                   subquery on the FK parent).
--
-- POLICY MODEL (mirrors migration 018's existing idioms exactly — same
-- qodiqa_current_tenant() session-variable mechanism, transaction-local,
-- proven safe's adversarial harness):
--   signing_keys      — strict tenant isolation (client_id NOT NULL, no
--                       platform-level NULL-tenant case): SELECT/INSERT/
--                       UPDATE gated on client_id = qodiqa_current_tenant().
--                       No DELETE policy — qodiqa_app has no DELETE grant on
--                       this table (lifecycle is via the status column:
--                       active/deprecated/revoked, never a real row
--                       deletion — same non-destructive pattern
--                       webhook_endpoints/deleteEndpoint already uses).
--   signing_key_legacy_map — SELECT gated via a subquery on
--                       signing_keys.client_id (FK-based isolation, the
--                       webhook_delivery_log pattern); INSERT gated the same
--                       way (qodiqa_app has no UPDATE/DELETE grant on this
--                       table, so no policy is needed for those commands —
--                       consistent with "only create policies for
--                       operations the application actually requires").
--
-- IDEMPOTENT: DROP POLICY IF EXISTS before CREATE POLICY. Safe to re-run.
-- ADDITIVE ONLY: no existing migration is edited; no existing policy on any
-- other table is touched, weakened, or removed.

BEGIN;

-- ── signing_keys — tenant isolation keyed on client_id ─────────────────────

DROP POLICY IF EXISTS sk_tenant_select ON signing_keys;
DROP POLICY IF EXISTS sk_tenant_insert ON signing_keys;
DROP POLICY IF EXISTS sk_tenant_update ON signing_keys;

ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys FORCE ROW LEVEL SECURITY;

-- SELECT: only the current tenant's own keys; NULL context -> 0 rows (fail-closed)
CREATE POLICY sk_tenant_select ON signing_keys
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (client_id = qodiqa_current_tenant());

-- INSERT: new row's client_id must match the active tenant context
CREATE POLICY sk_tenant_insert ON signing_keys
  FOR INSERT TO qodiqa_app
  WITH CHECK (client_id = qodiqa_current_tenant());

-- UPDATE: existing row AND new values must belong to the active tenant
-- (prevents a tenant from reassigning its own key to another client_id)
CREATE POLICY sk_tenant_update ON signing_keys
  FOR UPDATE TO qodiqa_app
  USING     (client_id = qodiqa_current_tenant())
  WITH CHECK (client_id = qodiqa_current_tenant());

COMMENT ON TABLE signing_keys IS
  'Ed25519 signing keys. Private material encrypted at rest with AES-256-GCM. '
  'client_id is the tenant identifier (src/core/tenancy/tenantRegistry.js) — '
  'tenant-isolated via RLS as of migration 052.';

-- ── signing_key_legacy_map — tenant isolation via FK to signing_keys ───────

DROP POLICY IF EXISTS sklm_tenant_select ON signing_key_legacy_map;
DROP POLICY IF EXISTS sklm_tenant_insert ON signing_key_legacy_map;

ALTER TABLE signing_key_legacy_map ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_key_legacy_map FORCE ROW LEVEL SECURITY;

-- SELECT: only mappings whose new_key_id belongs to the current tenant's own key
CREATE POLICY sklm_tenant_select ON signing_key_legacy_map
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (
    new_key_id IN (
      SELECT key_id FROM signing_keys
      WHERE client_id = qodiqa_current_tenant()
    )
  );

-- INSERT: the referenced new_key_id must belong to the active tenant's own key
CREATE POLICY sklm_tenant_insert ON signing_key_legacy_map
  FOR INSERT TO qodiqa_app
  WITH CHECK (
    new_key_id IN (
      SELECT key_id FROM signing_keys
      WHERE client_id = qodiqa_current_tenant()
    )
  );

COMMENT ON TABLE signing_key_legacy_map IS
  'Legacy key ID remapping (old format -> new versioned format). Tenant-'
  'isolated via a subquery on signing_keys.client_id as of migration 052 '
  ' — mirrors webhook_delivery_log''s FK-based isolation pattern '
  '(migration 018), since this table carries no tenant_id/client_id column '
  'of its own.';

-- ── Written exclusion justifications for the 11 genuinely global tables ────
-- (No RLS added. COMMENT ON TABLE records the justification in the catalog
-- itself, alongside the full reasoning in this migration's own header and
--.)

COMMENT ON TABLE qodiqa_migrations IS
  'Tracks applied schema migrations. Never modify applied rows. '
  ': no RLS — schema-migration bookkeeping has no '
  'tenant concept; one schema is shared by every tenant.';

COMMENT ON TABLE rbac_users IS
  'RBAC user registry. Migrated from data/rbac-users.json. '
  ': no RLS — these are QODIQA platform-operator '
  'accounts (admin/auditor/compliance/operator/viewer), not tenant end '
  'users; this codebase''s RBAC model has no tenant-scoped role or '
  'permission at all (confirmed independently''s own audit).';

COMMENT ON TABLE policies IS
  'Policy definitions. Migrated from policies.json + data/policy-store.json. '
  ': no RLS — this is the platform''s single global '
  'default enforcement rule set, distinct from tenant_policy_sets (051, '
  'tenant-scoped) and policy_change_requests (029, tenant-scoped); no '
  'tenant column exists because this is not tenant data.';

COMMENT ON TABLE policy_versions IS
  ': no RLS — versioned snapshots of the global policy '
  'table above; same disposition, same reasoning.';

COMMENT ON TABLE policy_history IS
  'Immutable audit trail of policy lifecycle events. '
  ': no RLS — history of the global policy table '
  'above; same disposition, same reasoning.';

COMMENT ON TABLE investigations IS
  'Forensic investigations. Migrated from data/investigations.json. '
  ': no RLS — internal forensic-investigation tooling '
  'with no tenant column; an investigation can legitimately span artifacts '
  'from any tenant by its nature. No HTTP route exposes this table.';

COMMENT ON TABLE investigation_artifacts IS
  ': no RLS — child table of investigations above; '
  'same disposition, same reasoning.';

COMMENT ON TABLE investigation_audit_events IS
  ': no RLS — child table of investigations above; '
  'same disposition, same reasoning.';

COMMENT ON TABLE evidence_packages IS
  ': no RLS — zero application readers or writers '
  'exist anywhere in this codebase (confirmed by direct search); no '
  'tenant column exists to key a policy on. Dormant. Re-assess tenant '
  'relevance if this table is ever wired up to a live feature.';

COMMENT ON TABLE audit_retention_runs IS
  ': no RLS — global retention-job execution log. '
  'The policy_id FK to audit_retention_policies (which does have '
  'tenant_id) is never populated by the live retention engine, and one '
  'run always processes every policy platform-wide in a single pass; a '
  'run record is not one tenant''s policy execution.';

COMMENT ON TABLE gap_scanner_state IS
  ': no RLS — CONSTRAINT gss_single_row CHECK (id = 1) '
  'enforces exactly one row can ever exist; tenant isolation is not a '
  'coherent concept for a single-row, platform-wide scanner checkpoint.';

-- ── Migration record ─────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (52, 'rem007_rls_gap_closure', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
