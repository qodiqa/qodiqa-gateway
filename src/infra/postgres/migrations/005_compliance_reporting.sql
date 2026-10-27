-- Migration 005: Compliance Reporting Framework
-- Provides storage for compliance report runs, control assessments, evidence
-- references, and cryptographic report signatures.
--
-- Integrates with: platform_audit_events, audit_chain, policies, signing_keys,
--                  rbac_users, evidence_packages, investigations.
-- RLS: FORCE on all tables; qodiqa_app INSERT + SELECT; qodiqa_read SELECT only.

-- ── Compliance Framework Registry ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_frameworks (
  id              VARCHAR(32)   PRIMARY KEY,
  name            VARCHAR(256)  NOT NULL,
  version         VARCHAR(64)   NOT NULL,
  description     TEXT          NOT NULL DEFAULT '',
  issuer          TEXT          NOT NULL,
  effective_date  DATE          NULL,
  enabled         BOOLEAN       NOT NULL DEFAULT TRUE,
  metadata        JSONB         NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE compliance_frameworks IS 'Registry of supported compliance frameworks (GDPR, EU AI Act, ISO 42001, NIST AI RMF).';

INSERT INTO compliance_frameworks (id, name, version, description, issuer, effective_date) VALUES
  ('GDPR',       'General Data Protection Regulation',           '2016/679',   'EU data protection and privacy law',                     'European Parliament',  '2018-05-25'),
  ('EU_AI_ACT',  'EU Artificial Intelligence Act',               '2024/1689',  'EU regulatory framework for artificial intelligence',     'European Parliament',  '2024-08-01'),
  ('ISO_42001',  'ISO/IEC 42001:2023 AI Management System',      '2023',       'International standard for AI management systems',       'ISO/IEC JTC 1/SC 42',  '2023-12-18'),
  ('NIST_AI_RMF','NIST AI Risk Management Framework',            '1.0',        'US framework for managing risks in AI systems',          'NIST',                 '2023-01-26')
ON CONFLICT (id) DO NOTHING;

-- ── Compliance Control Catalog ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_controls (
  id                  VARCHAR(64)   PRIMARY KEY,
  framework_id        VARCHAR(32)   NOT NULL REFERENCES compliance_frameworks(id),
  control_ref         VARCHAR(64)   NOT NULL,
  title               VARCHAR(512)  NOT NULL,
  description         TEXT          NOT NULL DEFAULT '',
  category            VARCHAR(128)  NOT NULL,
  weight              NUMERIC(4,2)  NOT NULL DEFAULT 1.00 CHECK (weight > 0 AND weight <= 10),
  is_critical         BOOLEAN       NOT NULL DEFAULT FALSE,
  evidence_required   TEXT[]        NOT NULL DEFAULT '{}',
  evidence_queries    JSONB         NOT NULL DEFAULT '[]',
  validation_logic    TEXT          NOT NULL DEFAULT '',
  remediation_hint    TEXT          NOT NULL DEFAULT '',
  enabled             BOOLEAN       NOT NULL DEFAULT TRUE
);

COMMENT ON TABLE compliance_controls IS 'Catalog of compliance controls per framework with evidence source mappings.';
COMMENT ON COLUMN compliance_controls.weight IS 'Weight for framework scoring (1.0=normal, 2.0=double weight for critical).';
COMMENT ON COLUMN compliance_controls.evidence_required IS 'Array of evidence type identifiers required for this control.';
COMMENT ON COLUMN compliance_controls.evidence_queries IS 'JSON array of query descriptors for automated evidence collection.';

-- ── Compliance Report Runs ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_reports (
  id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  report_ref          VARCHAR(64)   NOT NULL UNIQUE,
  framework_id        VARCHAR(32)   NOT NULL REFERENCES compliance_frameworks(id),
  framework_name      VARCHAR(256)  NOT NULL,
  tenant_id           VARCHAR(128)  NULL,
  title               VARCHAR(512)  NOT NULL,
  period_start        TIMESTAMPTZ   NOT NULL,
  period_end          TIMESTAMPTZ   NOT NULL,
  generated_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  generated_by        VARCHAR(128)  NOT NULL,
  generated_by_role   VARCHAR(64)   NULL,
  generator_version   VARCHAR(32)   NOT NULL DEFAULT '1.0.0',
  schema_version      VARCHAR(16)   NOT NULL DEFAULT '1.0',
  status              VARCHAR(16)   NOT NULL DEFAULT 'GENERATING'
    CHECK (status IN ('GENERATING','COMPLETE','FAILED','VOID')),
  overall_score       NUMERIC(5,2)  NULL     CHECK (overall_score IS NULL OR (overall_score >= 0 AND overall_score <= 100)),
  controls_total      INTEGER       NOT NULL DEFAULT 0,
  controls_pass       INTEGER       NOT NULL DEFAULT 0,
  controls_partial    INTEGER       NOT NULL DEFAULT 0,
  controls_fail       INTEGER       NOT NULL DEFAULT 0,
  evidence_count      INTEGER       NOT NULL DEFAULT 0,
  findings_count      INTEGER       NOT NULL DEFAULT 0,
  critical_findings   INTEGER       NOT NULL DEFAULT 0,
  executive_summary   TEXT          NULL,
  overall_verdict     VARCHAR(32)   NULL
    CHECK (overall_verdict IS NULL OR overall_verdict IN ('COMPLIANT','PARTIALLY_COMPLIANT','NON_COMPLIANT')),
  report_hash         CHAR(64)      NULL,
  signed              BOOLEAN       NOT NULL DEFAULT FALSE,
  error_message       TEXT          NULL,
  metadata            JSONB         NOT NULL DEFAULT '{}'
);

COMMENT ON TABLE compliance_reports IS 'Top-level compliance report records. One row per report generation run.';
COMMENT ON COLUMN compliance_reports.report_ref IS 'Human-readable reference e.g. RPT-GDPR-20260620-001.';
COMMENT ON COLUMN compliance_reports.report_hash IS 'SHA-256 of the canonical JSON report payload for integrity verification.';

CREATE INDEX idx_cr_framework    ON compliance_reports (framework_id, generated_at DESC);
CREATE INDEX idx_cr_tenant       ON compliance_reports (tenant_id)   WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_cr_status       ON compliance_reports (status, generated_at DESC);
CREATE INDEX idx_cr_generated_at ON compliance_reports (generated_at DESC);

-- ── Per-Control Assessment Results ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_control_assessments (
  id              BIGSERIAL     PRIMARY KEY,
  report_id       UUID          NOT NULL REFERENCES compliance_reports(id) ON DELETE CASCADE,
  control_id      VARCHAR(64)   NOT NULL REFERENCES compliance_controls(id),
  framework_id    VARCHAR(32)   NOT NULL,
  status          VARCHAR(16)   NOT NULL
    CHECK (status IN ('PASS','PARTIAL','FAIL','NOT_APPLICABLE','ERROR')),
  score           NUMERIC(5,2)  NOT NULL CHECK (score >= 0 AND score <= 100),
  evidence_count  INTEGER       NOT NULL DEFAULT 0,
  findings        JSONB         NOT NULL DEFAULT '[]',
  detail          TEXT          NOT NULL DEFAULT '',
  assessed_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE compliance_control_assessments IS 'Per-control assessment results for each report. One row per control per report.';

CREATE INDEX idx_cca_report   ON compliance_control_assessments (report_id);
CREATE INDEX idx_cca_control  ON compliance_control_assessments (control_id, status);
CREATE UNIQUE INDEX idx_cca_report_control ON compliance_control_assessments (report_id, control_id);

-- ── Evidence References ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_evidence_refs (
  id              BIGSERIAL     PRIMARY KEY,
  report_id       UUID          NOT NULL REFERENCES compliance_reports(id) ON DELETE CASCADE,
  control_id      VARCHAR(64)   NULL,
  evidence_type   VARCHAR(64)   NOT NULL,
  source_table    VARCHAR(64)   NOT NULL,
  source_id       TEXT          NOT NULL,
  occurred_at     TIMESTAMPTZ   NULL,
  summary         TEXT          NOT NULL DEFAULT '',
  valid           BOOLEAN       NOT NULL DEFAULT TRUE,
  integrity_ok    BOOLEAN       NOT NULL DEFAULT TRUE,
  metadata        JSONB         NOT NULL DEFAULT '{}'
);

COMMENT ON TABLE compliance_evidence_refs IS 'Pointers to evidence items collected during a compliance assessment.';
COMMENT ON COLUMN compliance_evidence_refs.source_table IS 'Source table name: platform_audit_events, audit_chain, policies, signing_keys, etc.';
COMMENT ON COLUMN compliance_evidence_refs.source_id IS 'Primary key value in the source table (UUID, VARCHAR, or BIGSERIAL as text).';

CREATE INDEX idx_cer_report   ON compliance_evidence_refs (report_id);
CREATE INDEX idx_cer_control  ON compliance_evidence_refs (control_id) WHERE control_id IS NOT NULL;
CREATE INDEX idx_cer_type     ON compliance_evidence_refs (evidence_type);

-- ── Report Signatures ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_report_signatures (
  id              BIGSERIAL     PRIMARY KEY,
  report_id       UUID          NOT NULL UNIQUE REFERENCES compliance_reports(id) ON DELETE CASCADE,
  key_id          VARCHAR(128)  NOT NULL,
  algorithm       VARCHAR(32)   NOT NULL DEFAULT 'ed25519',
  signature_b64   TEXT          NOT NULL,
  report_hash     CHAR(64)      NOT NULL,
  signed_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  signer_id       VARCHAR(128)  NOT NULL,
  verified        BOOLEAN       NOT NULL DEFAULT FALSE,
  verified_at     TIMESTAMPTZ   NULL
);

COMMENT ON TABLE compliance_report_signatures IS 'Ed25519 cryptographic signatures over compliance reports. Enables independent verification.';

-- ── Report Export Cache ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_report_exports (
  id              BIGSERIAL     PRIMARY KEY,
  report_id       UUID          NOT NULL REFERENCES compliance_reports(id) ON DELETE CASCADE,
  format          VARCHAR(8)    NOT NULL CHECK (format IN ('JSON','PDF','HTML')),
  content_hash    CHAR(64)      NOT NULL,
  byte_size       BIGINT        NOT NULL,
  generated_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ   NULL,
  storage_ref     TEXT          NULL
);

COMMENT ON TABLE compliance_report_exports IS 'Metadata for generated export artifacts (JSON, PDF, HTML). Actual content served from memory or object storage.';

CREATE INDEX idx_cre_report  ON compliance_report_exports (report_id, format);

-- ── Row Level Security ─────────────────────────────────────────────────────────

ALTER TABLE compliance_frameworks            ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_controls              ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_reports               ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_control_assessments   ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_evidence_refs         ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_report_signatures     ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_report_exports        ENABLE ROW LEVEL SECURITY;

ALTER TABLE compliance_frameworks            FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_controls              FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_reports               FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_control_assessments   FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_evidence_refs         FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_report_signatures     FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_report_exports        FORCE ROW LEVEL SECURITY;

-- Read policies (all authenticated roles)
CREATE POLICY cf_select    ON compliance_frameworks          AS PERMISSIVE FOR SELECT TO qodiqa_app, qodiqa_read USING (true);
CREATE POLICY cc_select    ON compliance_controls            AS PERMISSIVE FOR SELECT TO qodiqa_app, qodiqa_read USING (true);
CREATE POLICY cr_select    ON compliance_reports             AS PERMISSIVE FOR SELECT TO qodiqa_app, qodiqa_read USING (true);
CREATE POLICY cca_select   ON compliance_control_assessments AS PERMISSIVE FOR SELECT TO qodiqa_app, qodiqa_read USING (true);
CREATE POLICY cer_select   ON compliance_evidence_refs       AS PERMISSIVE FOR SELECT TO qodiqa_app, qodiqa_read USING (true);
CREATE POLICY crs_select   ON compliance_report_signatures   AS PERMISSIVE FOR SELECT TO qodiqa_app, qodiqa_read USING (true);
CREATE POLICY cre_select   ON compliance_report_exports      AS PERMISSIVE FOR SELECT TO qodiqa_app, qodiqa_read USING (true);

-- Write policies (app role only)
CREATE POLICY cr_insert    ON compliance_reports             FOR INSERT TO qodiqa_app WITH CHECK (true);
CREATE POLICY cr_update    ON compliance_reports             AS PERMISSIVE FOR UPDATE TO qodiqa_app USING (true);
CREATE POLICY cca_insert   ON compliance_control_assessments FOR INSERT TO qodiqa_app WITH CHECK (true);
CREATE POLICY cer_insert   ON compliance_evidence_refs       FOR INSERT TO qodiqa_app WITH CHECK (true);
CREATE POLICY crs_insert   ON compliance_report_signatures   FOR INSERT TO qodiqa_app WITH CHECK (true);
CREATE POLICY crs_update   ON compliance_report_signatures   AS PERMISSIVE FOR UPDATE TO qodiqa_app USING (true);
CREATE POLICY cre_insert   ON compliance_report_exports      FOR INSERT TO qodiqa_app WITH CHECK (true);

-- Grant statements
GRANT SELECT           ON compliance_frameworks             TO qodiqa_app, qodiqa_read;
GRANT SELECT, INSERT, UPDATE ON compliance_reports          TO qodiqa_app;
GRANT SELECT           ON compliance_reports                TO qodiqa_read;
GRANT SELECT, INSERT   ON compliance_controls               TO qodiqa_app;
GRANT SELECT           ON compliance_controls               TO qodiqa_read;
GRANT SELECT, INSERT   ON compliance_control_assessments    TO qodiqa_app;
GRANT SELECT           ON compliance_control_assessments    TO qodiqa_read;
GRANT SELECT, INSERT   ON compliance_evidence_refs          TO qodiqa_app;
GRANT SELECT           ON compliance_evidence_refs          TO qodiqa_read;
GRANT SELECT, INSERT, UPDATE ON compliance_report_signatures TO qodiqa_app;
GRANT SELECT           ON compliance_report_signatures      TO qodiqa_read;
GRANT SELECT, INSERT   ON compliance_report_exports         TO qodiqa_app;
GRANT SELECT           ON compliance_report_exports         TO qodiqa_read;

GRANT USAGE, SELECT ON SEQUENCE compliance_control_assessments_id_seq TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE compliance_evidence_refs_id_seq        TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE compliance_report_signatures_id_seq    TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE compliance_report_exports_id_seq       TO qodiqa_app;
