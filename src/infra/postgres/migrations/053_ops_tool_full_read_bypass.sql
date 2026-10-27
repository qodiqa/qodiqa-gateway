-- QODIQA PostgreSQL Migration 053
-- SECURITY DEFINER full-read bypass functions for RBAC-gated,
-- ops-only, cross-tenant search/analytics/forensic tools whose reads were
-- silently pre-filtered to platform-level (NULL-tenant) rows by RLS, with
-- no session tenant context ever set for these code paths and no tenant-
-- scoping middleware on their routes -- the exact same defect class
-- already remediated for pg-audit-backend.js (migrations 044/048), applied
-- here to the additional call sites's own investigation found:
--   centralStore.js       (platform_audit_events)  -- 9 methods
--   chainStore.js         (evidence_chain_records)  -- 5 methods + 1 lookup
--   AlertStore.js         (qodiqa_alerts, qodiqa_alert_history) -- 4 methods
--   ConsentStore.js       (consent_audit_log)        -- verifyConsentAuditIntegrity
--   retention.js          (audit_retention_policies, audit_legal_holds) --
--                         listPolicies/listLegalHolds ONLY (their GET routes
--                         accept no tenantId at all -- ops-wide listing;
--                         upsertPolicy/placeLegalHold's INSERT paths DO carry
--                         a caller-supplied target tenantId and are fixed via
--                         withTenantTransaction instead -- see
-- D1)
--
-- Each of these methods is reached ONLY through a route mounted behind an
-- RBAC ops permission (READ_AUDIT/MANAGE_RETENTION, READ_EVIDENCE_CHAIN/
-- VERIFY_EVIDENCE_CHAIN, the alerts router's opsAuth) or, for
-- verifyConsentAuditIntegrity, only by the live audit chain verifier's own
-- FULL system-wide integrity scan -- never by tenant-scoped business logic.
-- None of these routes set qodiqa.tenant_id, and none are gated by tenant
-- identity at all -- RBAC is the real authorization boundary here, unchanged
-- by this migration. Before this fix, every one of these reads was silently
-- restricted by RLS to platform-level (tenant_id IS NULL) rows only, making
-- the tool blind to real tenant activity -- fail-closed in the
-- under-reporting direction, never a cross-tenant leak, but a real
-- correctness/security-monitoring defect.
--
-- Each function below is a narrow, read-only, STABLE bypass mirroring
-- qodiqa_audit_chain_full_read() (migration 044) EXACTLY: no parameters, no
-- filtering (the calling application SQL supplies WHERE/ORDER/LIMIT as an
-- outer query against the function's result set, same idiom
-- countGenesisRows()/validateChainLinks() already use). None touch INSERT/
-- UPDATE/DELETE. None weaken FORCE ROW LEVEL SECURITY. None grant BYPASSRLS
-- to any role. ADDITIVE ONLY: no existing migration is edited, no existing
-- policy on any table is touched, weakened, or removed.
--
-- IDEMPOTENT: CREATE OR REPLACE FUNCTION. Safe to re-run.

BEGIN;

-- ── platform_audit_events ──────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_platform_audit_events_full_read()
RETURNS SETOF platform_audit_events
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM platform_audit_events
$$;

COMMENT ON FUNCTION qodiqa_platform_audit_events_full_read() IS
  'SECURITY DEFINER: bypasses platform_audit_events''s per-tenant RLS (pae_tenant_select) to return every row, every tenant, unordered/unfiltered -- the caller supplies WHERE/ORDER/LIMIT. remediation, mirrors qodiqa_audit_chain_full_read() (migration 044). Used by centralStore.js''s search/getEvent/correlate/correlateByTrace/artifactTimeline/actorActivity/stats/ingestionRate/topEventTypes -- all reached only via the RBAC-gated /audit-store ops console, never by tenant-scoped business logic.';

REVOKE ALL ON FUNCTION qodiqa_platform_audit_events_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_platform_audit_events_full_read() TO qodiqa_app, qodiqa_read;

-- ── evidence_chain_records ──────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_evidence_chain_records_full_read()
RETURNS SETOF evidence_chain_records
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM evidence_chain_records
$$;

COMMENT ON FUNCTION qodiqa_evidence_chain_records_full_read() IS
  'SECURITY DEFINER: bypasses evidence_chain_records''s per-tenant RLS (ecr_tenant_select) to return every row, every tenant. remediation, mirrors qodiqa_audit_chain_full_read() (migration 044). Used by chainStore.js''s getByEvidenceId/getByArtifactId/searchEvidence/getChain/aggregateStats and verifyEvidence''s priorRecord lookup -- all reached only via the RBAC-gated /evidence-chain forensic-investigation console, never by tenant-scoped business logic.';

REVOKE ALL ON FUNCTION qodiqa_evidence_chain_records_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_evidence_chain_records_full_read() TO qodiqa_app, qodiqa_read;

-- ── qodiqa_alerts ────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_qodiqa_alerts_full_read()
RETURNS SETOF qodiqa_alerts
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM qodiqa_alerts
$$;

COMMENT ON FUNCTION qodiqa_qodiqa_alerts_full_read() IS
  'SECURITY DEFINER: bypasses qodiqa_alerts''s per-tenant RLS (qa_tenant_select) to return every row, every tenant. remediation, mirrors qodiqa_audit_chain_full_read() (migration 044). Used by AlertStore.js''s getAlert, listAlerts (no-tenantId-filter branch) and getStats -- all reached only via the RBAC-gated /alerts ops console (opsAuth), never by tenant-scoped business logic.';

REVOKE ALL ON FUNCTION qodiqa_qodiqa_alerts_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_qodiqa_alerts_full_read() TO qodiqa_app, qodiqa_read;

-- ── qodiqa_alert_history ─────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_qodiqa_alert_history_full_read()
RETURNS SETOF qodiqa_alert_history
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM qodiqa_alert_history
$$;

COMMENT ON FUNCTION qodiqa_qodiqa_alert_history_full_read() IS
  'SECURITY DEFINER: bypasses qodiqa_alert_history''s FK-based per-tenant RLS (qah_tenant_select) to return every row, every alert, every tenant. remediation, mirrors qodiqa_audit_chain_full_read() (migration 044). Used by AlertStore.js''s getAlertHistory -- reached only via the RBAC-gated /alerts ops console (opsAuth), never by tenant-scoped business logic.';

REVOKE ALL ON FUNCTION qodiqa_qodiqa_alert_history_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_qodiqa_alert_history_full_read() TO qodiqa_app, qodiqa_read;

-- ── consent_audit_log ────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_consent_audit_log_full_read()
RETURNS SETOF consent_audit_log
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM consent_audit_log
$$;

COMMENT ON FUNCTION qodiqa_consent_audit_log_full_read() IS
  'SECURITY DEFINER: bypasses consent_audit_log''s per-tenant RLS (cal_tenant_select) to return every row, every tenant. remediation, mirrors qodiqa_audit_chain_full_read() (migration 044). Used by ConsentStore.js''s verifyConsentAuditIntegrity() ONLY -- the live audit chain verifier''s FULL system-wide tamper scan (src/core/audit/verifier/ChainVerifier.js), never tenant-scoped business logic (getAuditLog stays RLS-scoped via withTenantTransaction, unchanged by this function).';

REVOKE ALL ON FUNCTION qodiqa_consent_audit_log_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_consent_audit_log_full_read() TO qodiqa_app, qodiqa_read;

-- ── audit_retention_policies ─────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_audit_retention_policies_full_read()
RETURNS SETOF audit_retention_policies
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM audit_retention_policies
$$;

COMMENT ON FUNCTION qodiqa_audit_retention_policies_full_read() IS
  'SECURITY DEFINER: bypasses audit_retention_policies''s per-tenant RLS (arp_tenant_select) to return every policy, every tenant. remediation, mirrors qodiqa_audit_chain_full_read() (migration 044). Used by retention.js''s listPolicies() ONLY -- its GET /audit-store/retention/policies route accepts no tenantId at all (ops-wide listing); upsertPolicy() keeps using withTenantTransaction for its caller-supplied target tenantId, unaffected by this function.';

REVOKE ALL ON FUNCTION qodiqa_audit_retention_policies_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_audit_retention_policies_full_read() TO qodiqa_app, qodiqa_read;

-- ── audit_legal_holds ────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_audit_legal_holds_full_read()
RETURNS SETOF audit_legal_holds
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM audit_legal_holds
$$;

COMMENT ON FUNCTION qodiqa_audit_legal_holds_full_read() IS
  'SECURITY DEFINER: bypasses audit_legal_holds''s per-tenant RLS (alh_tenant_select) to return every hold, every tenant. remediation, mirrors qodiqa_audit_chain_full_read() (migration 044). Used by retention.js''s listLegalHolds() ONLY -- its GET /audit-store/retention/holds route accepts no tenantId at all (ops-wide listing); placeLegalHold()/releaseLegalHold() are unaffected by this function.';

REVOKE ALL ON FUNCTION qodiqa_audit_legal_holds_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_audit_legal_holds_full_read() TO qodiqa_app, qodiqa_read;

-- ── compliance_reports ───────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_compliance_reports_full_read()
RETURNS SETOF compliance_reports
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM compliance_reports
$$;

COMMENT ON FUNCTION qodiqa_compliance_reports_full_read() IS
  'SECURITY DEFINER: bypasses compliance_reports''s per-tenant RLS (crp_tenant_select) to return every report, every tenant. remediation, mirrors qodiqa_audit_chain_full_read() (migration 044). Used by reportGenerator.js''s getReport() (unconditionally -- its GET /compliance/report/:id route carries no tenant scoping at all) and listReports()''s no-tenantId-filter branch -- both reached only via the RBAC-gated /compliance ops console (READ_COMPLIANCE), never by tenant-scoped business logic. generateReport()''s WRITE path is unaffected -- it keeps withTenantTransaction for its caller-supplied target tenantId.';

REVOKE ALL ON FUNCTION qodiqa_compliance_reports_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_compliance_reports_full_read() TO qodiqa_app, qodiqa_read;

-- ── Migration record ─────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (53, 'rem061_ops_tool_full_read_bypass', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
