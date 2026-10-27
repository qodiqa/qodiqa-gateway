-- QODIQA PostgreSQL Migration 018
-- Component #31: Full Row-Level Security for Tenant Isolation
--
-- Enforces tenant isolation at the database layer as a defense-in-depth
-- addition to the existing application-layer WHERE tenant_id = $1 filtering.
--
-- DESIGN:
--   qodiqa_current_tenant()  — session variable 'qodiqa.tenant_id' (transaction-local)
--   SET in application via:  SELECT set_config('qodiqa.tenant_id', $1, true)
--   The third param (true) = transaction-local: resets at transaction end.
--   This guarantees no tenant context leaks across pooled connections.
--
-- POLICY MODEL:
--   Tables with NOT NULL tenant_id (webhook_endpoints):
--     SELECT/INSERT/UPDATE → strict: tenant_id = qodiqa_current_tenant()
--     No-context → 0 rows (fail-closed)
--
--   Tables with nullable tenant_id (audit logs, consent, compliance, alerts):
--     SELECT → tenant_id IS NULL (platform-level rows) OR tenant_id = qodiqa_current_tenant()
--     INSERT → permissive for append-only system logs; tenant-matched for mutable data
--     No-context → platform-level rows visible; tenant rows not visible (fail-closed for tenant data)
--
--   Tables with no tenant_id (webhook_delivery_log):
--     SELECT → subquery: endpoint must belong to current tenant
--     INSERT → permissive (delivery system logs without tenant context)
--
-- ADMINISTRATIVE BYPASS:
--   qodiqa_mig role receives BYPASSRLS.
--   Use ONLY for maintenance tasks (migrations, data repairs, retention jobs).
--   Never grant BYPASSRLS to qodiqa_app.
--   Never disable RLS globally.
--
-- TABLES EXCLUDED (no tenant ownership, global/system data):
--   qodiqa_migrations, rbac_users, signing_keys, policies, policy_versions,
--   policy_history, investigations, evidence_packages, attestations,
--   certifications, certificate_artifacts, portal_verifications,
--   transparency_roots, transparency_verifications,
--   consent_scopes, policy_provenance_versions, policy_provenance_integrity_runs,
--   evidence_chain_verifications, compliance_frameworks, compliance_controls,
--   compliance_control_assessments, compliance_evidence_refs,
--   compliance_report_signatures, compliance_report_exports,
--   kms_provider_events, kms_wrapping_key_rotations, qodiqa_alert_stats
--
-- TABLES WITH TENANT ISOLATION (covered below):
--   webhook_endpoints, webhook_delivery_log (FK-based),
--   consent_records, consent_audit_log, consent_scopes,
--   audit_chain, platform_audit_events, audit_retention_policies, audit_legal_holds,
--   evidence_chain_records, compliance_reports,
--   qodiqa_alerts, qodiqa_incidents,
--   qodiqa_alert_history (FK-based), qodiqa_notification_deliveries (FK-based),
--   qodiqa_escalation_records (FK-based), qodiqa_suppression_rules,
--   qodiqa_anomaly_baselines, qodiqa_alert_stats,
--   revocation_events, transparency_log_entries, kms_encrypted_data_keys
--
-- IDEMPOTENT: DROP POLICY IF EXISTS before CREATE POLICY.
-- Safe to re-run on an already-migrated database.

BEGIN;

-- ── Helper function ────────────────────────────────────────────────────────────
--
-- Returns the current tenant ID from the session variable.
-- Returns NULL when not set (missing_ok=true prevents ERROR).
-- NULL causes all tenant_id comparisons to return NULL (fail-closed).
-- STABLE: evaluated once per query, not per row.

CREATE OR REPLACE FUNCTION qodiqa_current_tenant()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY INVOKER
AS $$
  SELECT NULLIF(current_setting('qodiqa.tenant_id', true), '')
$$;

COMMENT ON FUNCTION qodiqa_current_tenant() IS
  'Returns the active tenant ID from the qodiqa.tenant_id session variable. '
  'Returns NULL if not set (fail-closed: NULL = X is always NULL/false). '
  'Set transaction-locally via: SELECT set_config(''qodiqa.tenant_id'', $1, true)';

-- ── Administrative bypass role ─────────────────────────────────────────────────
--
-- qodiqa_mig already exists (migration 002). Grant BYPASSRLS so it can run
-- maintenance jobs (retention sweeps, data repairs) without RLS interference.
-- NEVER grant BYPASSRLS to qodiqa_app.

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_mig') THEN
    ALTER ROLE qodiqa_mig BYPASSRLS;
  END IF;
END $$;

-- ── webhook_endpoints — strict tenant isolation ────────────────────────────────
--
-- tenant_id VARCHAR(128) NOT NULL — every endpoint belongs to exactly one tenant.
-- All four operations (SELECT/INSERT/UPDATE/DELETE) require matching tenant context.
-- Application must call withTenantTransaction(tenantId, ...) before any operation.

DROP POLICY IF EXISTS we_select ON webhook_endpoints;
DROP POLICY IF EXISTS we_insert ON webhook_endpoints;
DROP POLICY IF EXISTS we_update ON webhook_endpoints;
DROP POLICY IF EXISTS we_delete ON webhook_endpoints;
DROP POLICY IF EXISTS we_tenant_select ON webhook_endpoints;
DROP POLICY IF EXISTS we_tenant_insert ON webhook_endpoints;
DROP POLICY IF EXISTS we_tenant_update ON webhook_endpoints;

ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints FORCE ROW LEVEL SECURITY;

-- SELECT: only current tenant's endpoints; NULL context → 0 rows (fail-closed)
CREATE POLICY we_tenant_select ON webhook_endpoints
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id = qodiqa_current_tenant());

-- INSERT: tenant_id in new row must match active tenant context
CREATE POLICY we_tenant_insert ON webhook_endpoints
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id = qodiqa_current_tenant());

-- UPDATE: existing row AND new values must belong to active tenant
CREATE POLICY we_tenant_update ON webhook_endpoints
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id = qodiqa_current_tenant());

-- ── webhook_delivery_log — tenant isolation via endpoint FK ────────────────────
--
-- No direct tenant_id column. Isolation enforced via subquery:
-- a delivery log row is visible only when its endpoint belongs to the current tenant.
-- INSERT is permissive: the delivery system logs without setting tenant context
-- (the log is an internal audit trail, not user-facing tenant data).

DROP POLICY IF EXISTS wdl_select ON webhook_delivery_log;
DROP POLICY IF EXISTS wdl_insert ON webhook_delivery_log;
DROP POLICY IF EXISTS wdl_tenant_select ON webhook_delivery_log;
DROP POLICY IF EXISTS wdl_system_insert ON webhook_delivery_log;

ALTER TABLE webhook_delivery_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery_log FORCE ROW LEVEL SECURITY;

-- SELECT: only log entries for the current tenant's endpoints
CREATE POLICY wdl_tenant_select ON webhook_delivery_log
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (
    endpoint_id IN (
      SELECT id FROM webhook_endpoints
      WHERE tenant_id = qodiqa_current_tenant()
    )
  );

-- INSERT: permissive — delivery system writes without tenant context
CREATE POLICY wdl_system_insert ON webhook_delivery_log
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── consent_records — tenant-aware isolation ──────────────────────────────────
--
-- tenant_id VARCHAR(128) nullable. NULL = platform-level consent (not tenant-specific).
-- Platform-level rows are visible/writable from any context.
-- Tenant-specific rows are visible/writable only when context matches.

DROP POLICY IF EXISTS consent_app_bypass ON consent_records;
DROP POLICY IF EXISTS cr_tenant_select   ON consent_records;
DROP POLICY IF EXISTS cr_tenant_insert   ON consent_records;
DROP POLICY IF EXISTS cr_tenant_update   ON consent_records;

ALTER TABLE consent_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent_records FORCE ROW LEVEL SECURITY;

-- SELECT: platform-level (NULL) rows always visible; tenant rows need matching context
CREATE POLICY cr_tenant_select ON consent_records
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- INSERT: platform-level allowed always; tenant-specific needs matching context
CREATE POLICY cr_tenant_insert ON consent_records
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- UPDATE: tenant_id must match before and after (or be NULL for platform-level)
CREATE POLICY cr_tenant_update ON consent_records
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- ── consent_audit_log — immutable append-only ─────────────────────────────────
--
-- tenant_id VARCHAR(128) nullable. Immutable: no UPDATE, no DELETE.
-- INSERT is permissive: the consent store writes without per-entry tenant context.
-- SELECT filters: platform rows (NULL) are always visible; tenant rows need context.

DROP POLICY IF EXISTS consent_audit_app_bypass ON consent_audit_log;
DROP POLICY IF EXISTS cal_tenant_select        ON consent_audit_log;
DROP POLICY IF EXISTS cal_system_insert        ON consent_audit_log;

ALTER TABLE consent_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent_audit_log FORCE ROW LEVEL SECURITY;

CREATE POLICY cal_tenant_select ON consent_audit_log
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY cal_system_insert ON consent_audit_log
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- consent_scopes: global reference table — keep permissive (no tenant ownership)
DROP POLICY IF EXISTS consent_scopes_app_bypass ON consent_scopes;
DROP POLICY IF EXISTS csc_select                ON consent_scopes;
DROP POLICY IF EXISTS csc_insert                ON consent_scopes;
DROP POLICY IF EXISTS csc_update                ON consent_scopes;

ALTER TABLE consent_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent_scopes FORCE ROW LEVEL SECURITY;

CREATE POLICY csc_select ON consent_scopes
  FOR SELECT TO qodiqa_app, qodiqa_read USING (true);
CREATE POLICY csc_insert ON consent_scopes
  FOR INSERT TO qodiqa_app WITH CHECK (true);
CREATE POLICY csc_update ON consent_scopes
  FOR UPDATE TO qodiqa_app USING (true) WITH CHECK (true);

-- ── audit_chain — immutable, tenant-aware ─────────────────────────────────────
--
-- tenant_id VARCHAR(128) nullable. Cryptographic append-only chain.
-- INSERT is permissive: audit system writes without per-entry tenant context.
-- SELECT filters by tenant; no UPDATE or DELETE permitted.

DROP POLICY IF EXISTS audit_chain_select ON audit_chain;
DROP POLICY IF EXISTS audit_chain_insert ON audit_chain;
DROP POLICY IF EXISTS ac_tenant_select   ON audit_chain;
DROP POLICY IF EXISTS ac_system_insert   ON audit_chain;

ALTER TABLE audit_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain FORCE ROW LEVEL SECURITY;

CREATE POLICY ac_tenant_select ON audit_chain
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY ac_system_insert ON audit_chain
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── platform_audit_events — immutable, tenant-aware ───────────────────────────
--
-- tenant_id VARCHAR(128) nullable. Immutable event store.
-- INSERT permissive; SELECT filtered by tenant.

DROP POLICY IF EXISTS pae_insert_only    ON platform_audit_events;
DROP POLICY IF EXISTS pae_select         ON platform_audit_events;
DROP POLICY IF EXISTS pae_tenant_select  ON platform_audit_events;
DROP POLICY IF EXISTS pae_system_insert  ON platform_audit_events;

ALTER TABLE platform_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY pae_tenant_select ON platform_audit_events
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY pae_system_insert ON platform_audit_events
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── audit_retention_policies — tenant-aware ───────────────────────────────────
--
-- tenant_id VARCHAR(128) nullable. Management table for retention configuration.
-- Platform-level policies (NULL) are visible/writable from any context.

DROP POLICY IF EXISTS arp_tenant_select ON audit_retention_policies;
DROP POLICY IF EXISTS arp_tenant_insert ON audit_retention_policies;
DROP POLICY IF EXISTS arp_tenant_update ON audit_retention_policies;
DROP POLICY IF EXISTS arp_tenant_delete ON audit_retention_policies;

ALTER TABLE audit_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_retention_policies FORCE ROW LEVEL SECURITY;

CREATE POLICY arp_tenant_select ON audit_retention_policies
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY arp_tenant_insert ON audit_retention_policies
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY arp_tenant_update ON audit_retention_policies
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY arp_tenant_delete ON audit_retention_policies
  FOR DELETE TO qodiqa_app
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- ── audit_legal_holds — tenant-aware ──────────────────────────────────────────
--
-- tenant_id VARCHAR(128) nullable. Platform-level holds (NULL) are global.

DROP POLICY IF EXISTS alh_tenant_select ON audit_legal_holds;
DROP POLICY IF EXISTS alh_tenant_insert ON audit_legal_holds;
DROP POLICY IF EXISTS alh_tenant_update ON audit_legal_holds;

ALTER TABLE audit_legal_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_legal_holds FORCE ROW LEVEL SECURITY;

CREATE POLICY alh_tenant_select ON audit_legal_holds
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY alh_tenant_insert ON audit_legal_holds
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY alh_tenant_update ON audit_legal_holds
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- ── evidence_chain_records — immutable, tenant-aware ─────────────────────────
--
-- tenant_id VARCHAR(128) nullable. Cryptographic evidence chain.
-- INSERT permissive; SELECT filtered by tenant.

DROP POLICY IF EXISTS ecr_tenant_select ON evidence_chain_records;
DROP POLICY IF EXISTS ecr_system_insert ON evidence_chain_records;

ALTER TABLE evidence_chain_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_chain_records FORCE ROW LEVEL SECURITY;

CREATE POLICY ecr_tenant_select ON evidence_chain_records
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY ecr_system_insert ON evidence_chain_records
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── compliance_reports — tenant-aware ─────────────────────────────────────────
--
-- tenant_id VARCHAR(128) nullable. One compliance report per framework run.
-- Platform reports (NULL) are visible to all; tenant reports are isolated.

DROP POLICY IF EXISTS cr_select  ON compliance_reports;
DROP POLICY IF EXISTS cr_insert  ON compliance_reports;
DROP POLICY IF EXISTS cr_update  ON compliance_reports;
DROP POLICY IF EXISTS crp_tenant_select ON compliance_reports;
DROP POLICY IF EXISTS crp_tenant_insert ON compliance_reports;
DROP POLICY IF EXISTS crp_tenant_update ON compliance_reports;

ALTER TABLE compliance_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_reports FORCE ROW LEVEL SECURITY;

CREATE POLICY crp_tenant_select ON compliance_reports
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY crp_tenant_insert ON compliance_reports
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY crp_tenant_update ON compliance_reports
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- ── qodiqa_alerts — tenant-aware ─────────────────────────────────────────────
--
-- tenant_id VARCHAR(128) nullable. Alerts can be global or tenant-specific.
-- INSERT permissive: alert engine writes without per-alert tenant context.
-- SELECT filters by tenant.

DROP POLICY IF EXISTS qodiqa_app_bypass  ON qodiqa_alerts;
DROP POLICY IF EXISTS qa_tenant_select   ON qodiqa_alerts;
DROP POLICY IF EXISTS qa_system_insert   ON qodiqa_alerts;
DROP POLICY IF EXISTS qa_tenant_update   ON qodiqa_alerts;

ALTER TABLE qodiqa_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_alerts FORCE ROW LEVEL SECURITY;

CREATE POLICY qa_tenant_select ON qodiqa_alerts
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY qa_system_insert ON qodiqa_alerts
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

CREATE POLICY qa_tenant_update ON qodiqa_alerts
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- ── qodiqa_incidents — tenant-aware ──────────────────────────────────────────
--
-- tenant_id VARCHAR(128) nullable. Same pattern as alerts.

DROP POLICY IF EXISTS qi_tenant_select ON qodiqa_incidents;
DROP POLICY IF EXISTS qi_system_insert ON qodiqa_incidents;
DROP POLICY IF EXISTS qi_tenant_update ON qodiqa_incidents;

ALTER TABLE qodiqa_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_incidents FORCE ROW LEVEL SECURITY;

CREATE POLICY qi_tenant_select ON qodiqa_incidents
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY qi_system_insert ON qodiqa_incidents
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

CREATE POLICY qi_tenant_update ON qodiqa_incidents
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- ── revocation_events — immutable, tenant-aware ────────────────────────────────
--
-- tenant_id TEXT nullable. Append-only revocation event log.
-- NULL = cross-tenant/global revocation, visible from any context.
-- Tenant-specific rows visible only to the owning tenant.
-- INSERT permissive: revocation publisher writes without per-event tenant context.
-- No UPDATE, no DELETE (immutable log).

DROP POLICY IF EXISTS re_tenant_select ON revocation_events;
DROP POLICY IF EXISTS re_system_insert ON revocation_events;

ALTER TABLE revocation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE revocation_events FORCE ROW LEVEL SECURITY;

CREATE POLICY re_tenant_select ON revocation_events
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY re_system_insert ON revocation_events
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── transparency_log_entries — immutable, tenant-aware ─────────────────────────
--
-- tenant_id VARCHAR(128) nullable.
-- NULL = platform-level log entry, visible to all.
-- Tenant entries are visible only to the owning tenant.
-- Supersedes the permissive tle_select / tle_insert policies from migration 011.

DROP POLICY IF EXISTS tle_select ON transparency_log_entries;
DROP POLICY IF EXISTS tle_insert ON transparency_log_entries;
DROP POLICY IF EXISTS tle_tenant_select ON transparency_log_entries;
DROP POLICY IF EXISTS tle_system_insert ON transparency_log_entries;

ALTER TABLE transparency_log_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE transparency_log_entries FORCE ROW LEVEL SECURITY;

CREATE POLICY tle_tenant_select ON transparency_log_entries
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY tle_system_insert ON transparency_log_entries
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── kms_encrypted_data_keys — tenant-aware ─────────────────────────────────────
--
-- tenant_id TEXT nullable. EDK registry — each EDK blob belongs to one tenant.
-- NULL = platform-level EDK (shared infrastructure), visible to all.
-- Tenant EDKs are visible only to the owning tenant.
-- Supersedes permissive policies from migration 004.

DROP POLICY IF EXISTS kedk_select ON kms_encrypted_data_keys;
DROP POLICY IF EXISTS kedk_insert ON kms_encrypted_data_keys;
DROP POLICY IF EXISTS kedk_tenant_select ON kms_encrypted_data_keys;
DROP POLICY IF EXISTS kedk_tenant_insert ON kms_encrypted_data_keys;
DROP POLICY IF EXISTS kedk_tenant_update ON kms_encrypted_data_keys;

ALTER TABLE kms_encrypted_data_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE kms_encrypted_data_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY kedk_tenant_select ON kms_encrypted_data_keys
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY kedk_tenant_insert ON kms_encrypted_data_keys
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY kedk_tenant_update ON kms_encrypted_data_keys
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- ── qodiqa_suppression_rules — tenant-aware ────────────────────────────────────
--
-- tenant_id VARCHAR(128) nullable. NULL = global rule matching all tenants.
-- Tenant-specific rules are visible/writable only to the owning tenant.
-- Global rules (NULL) are visible/writable from any context.

DROP POLICY IF EXISTS qsr_tenant_select ON qodiqa_suppression_rules;
DROP POLICY IF EXISTS qsr_tenant_insert ON qodiqa_suppression_rules;
DROP POLICY IF EXISTS qsr_tenant_update ON qodiqa_suppression_rules;
DROP POLICY IF EXISTS qsr_tenant_delete ON qodiqa_suppression_rules;

ALTER TABLE qodiqa_suppression_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_suppression_rules FORCE ROW LEVEL SECURITY;

CREATE POLICY qsr_tenant_select ON qodiqa_suppression_rules
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY qsr_tenant_insert ON qodiqa_suppression_rules
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY qsr_tenant_update ON qodiqa_suppression_rules
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY qsr_tenant_delete ON qodiqa_suppression_rules
  FOR DELETE TO qodiqa_app
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- ── qodiqa_anomaly_baselines — tenant-aware ────────────────────────────────────
--
-- tenant_id VARCHAR(128) nullable. NULL = global baseline (all tenants share it).
-- Tenant baselines are visible/writable only to the owning tenant.

DROP POLICY IF EXISTS qab_tenant_select ON qodiqa_anomaly_baselines;
DROP POLICY IF EXISTS qab_tenant_insert ON qodiqa_anomaly_baselines;
DROP POLICY IF EXISTS qab_tenant_update ON qodiqa_anomaly_baselines;

ALTER TABLE qodiqa_anomaly_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_anomaly_baselines FORCE ROW LEVEL SECURITY;

CREATE POLICY qab_tenant_select ON qodiqa_anomaly_baselines
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY qab_tenant_insert ON qodiqa_anomaly_baselines
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY qab_tenant_update ON qodiqa_anomaly_baselines
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

-- ── qodiqa_alert_history — FK-based isolation ─────────────────────────────────
--
-- No direct tenant_id. Isolation via FK: a history row is visible only when its
-- parent alert belongs to the current tenant (or is a global NULL-tenant alert).
-- INSERT is permissive: the alert engine writes history without per-row tenant context.
-- No UPDATE, no DELETE (immutable audit trail).
--
-- FK SAFETY: The subquery re-evaluates qodiqa_current_tenant() per query, not per row.
-- An attacker cannot escalate to another tenant's alert history by crafting a JOIN
-- because the subquery scope is fully controlled by the RLS filter on qodiqa_alerts.

DROP POLICY IF EXISTS qah_tenant_select ON qodiqa_alert_history;
DROP POLICY IF EXISTS qah_system_insert ON qodiqa_alert_history;

ALTER TABLE qodiqa_alert_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_alert_history FORCE ROW LEVEL SECURITY;

CREATE POLICY qah_tenant_select ON qodiqa_alert_history
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (
    alert_id IN (
      SELECT id FROM qodiqa_alerts
      WHERE tenant_id IS NULL OR tenant_id = qodiqa_current_tenant()
    )
  );

CREATE POLICY qah_system_insert ON qodiqa_alert_history
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── qodiqa_notification_deliveries — FK-based isolation ───────────────────────
--
-- No direct tenant_id. Isolation via FK to qodiqa_alerts.
-- INSERT/UPDATE permissive: delivery system manages retry state without tenant context.

DROP POLICY IF EXISTS qnd_tenant_select ON qodiqa_notification_deliveries;
DROP POLICY IF EXISTS qnd_system_insert ON qodiqa_notification_deliveries;
DROP POLICY IF EXISTS qnd_system_update ON qodiqa_notification_deliveries;

ALTER TABLE qodiqa_notification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_notification_deliveries FORCE ROW LEVEL SECURITY;

CREATE POLICY qnd_tenant_select ON qodiqa_notification_deliveries
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (
    alert_id IN (
      SELECT id FROM qodiqa_alerts
      WHERE tenant_id IS NULL OR tenant_id = qodiqa_current_tenant()
    )
  );

CREATE POLICY qnd_system_insert ON qodiqa_notification_deliveries
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

CREATE POLICY qnd_system_update ON qodiqa_notification_deliveries
  FOR UPDATE TO qodiqa_app
  USING (true) WITH CHECK (true);

-- ── qodiqa_escalation_records — FK-based isolation ────────────────────────────
--
-- No direct tenant_id. Isolation via FK to qodiqa_alerts.
-- INSERT permissive: escalation engine writes without per-record tenant context.
-- No UPDATE, no DELETE (immutable escalation trail).

DROP POLICY IF EXISTS qer_tenant_select ON qodiqa_escalation_records;
DROP POLICY IF EXISTS qer_system_insert ON qodiqa_escalation_records;

ALTER TABLE qodiqa_escalation_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_escalation_records FORCE ROW LEVEL SECURITY;

CREATE POLICY qer_tenant_select ON qodiqa_escalation_records
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (
    alert_id IN (
      SELECT id FROM qodiqa_alerts
      WHERE tenant_id IS NULL OR tenant_id = qodiqa_current_tenant()
    )
  );

CREATE POLICY qer_system_insert ON qodiqa_escalation_records
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── qodiqa_alert_stats — global aggregation table ─────────────────────────────
--
-- No tenant_id. Pre-aggregated statistics across all tenants for dashboard use.
-- Access is unrestricted within the application role — this is intentional.
-- Tenant-specific stats are not exposed here; only aggregate counts are stored.

DROP POLICY IF EXISTS qas_select ON qodiqa_alert_stats;
DROP POLICY IF EXISTS qas_insert ON qodiqa_alert_stats;
DROP POLICY IF EXISTS qas_update ON qodiqa_alert_stats;

ALTER TABLE qodiqa_alert_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_alert_stats FORCE ROW LEVEL SECURITY;

CREATE POLICY qas_select ON qodiqa_alert_stats
  FOR SELECT TO qodiqa_app, qodiqa_read USING (true);

CREATE POLICY qas_insert ON qodiqa_alert_stats
  FOR INSERT TO qodiqa_app WITH CHECK (true);

CREATE POLICY qas_update ON qodiqa_alert_stats
  FOR UPDATE TO qodiqa_app USING (true) WITH CHECK (true);

-- ── Consolidation: FORCE ROW LEVEL SECURITY for all global tables ──────────────
--
-- Earlier migrations used invalid syntax `FORCE ROW LEVEL SECURITY ON table`.
-- The correct form is `ALTER TABLE table FORCE ROW LEVEL SECURITY`.
-- These statements are idempotent and ensure every table that has RLS enabled
-- also enforces it for the table owner, providing complete defense-in-depth.

ALTER TABLE kms_provider_events              FORCE ROW LEVEL SECURITY;
ALTER TABLE kms_wrapping_key_rotations       FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_frameworks            FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_controls              FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_control_assessments   FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_evidence_refs         FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_report_signatures     FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_report_exports        FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_provenance_versions       FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_provenance_integrity_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence_chain_verifications     FORCE ROW LEVEL SECURITY;
ALTER TABLE transparency_roots               FORCE ROW LEVEL SECURITY;
ALTER TABLE transparency_verifications       FORCE ROW LEVEL SECURITY;
ALTER TABLE portal_verifications             FORCE ROW LEVEL SECURITY;
ALTER TABLE attestations                     FORCE ROW LEVEL SECURITY;
ALTER TABLE certifications                   FORCE ROW LEVEL SECURITY;
ALTER TABLE certificate_artifacts            FORCE ROW LEVEL SECURITY;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (18, 'rls_tenant_isolation', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
