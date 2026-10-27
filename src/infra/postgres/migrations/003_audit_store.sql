-- QODIQA Migration 003: Centralized Platform Audit Store
-- Adds platform_audit_events, retention policies, legal holds, and retention run history.
-- All enforcement-category events are exempt from automated deletion.
-- Row-level security mirrors audit_chain: INSERT only for qodiqa_app, no UPDATE/DELETE.

BEGIN;

-- ── Canonical event category enum ─────────────────────────────────────────────

DO $$ BEGIN
  CREATE TYPE audit_category AS ENUM (
    'ENFORCEMENT',
    'SECURITY',
    'LIFECYCLE',
    'OPERATIONAL',
    'ACCESS_CONTROL',
    'KEY_MANAGEMENT',
    'POLICY',
    'PROVIDER',
    'AUDIT_CHAIN',
    'INVESTIGATION',
    'EVIDENCE',
    'INFRASTRUCTURE'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ── Central platform audit events ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS platform_audit_events (
  id              BIGSERIAL       NOT NULL,
  event_id        UUID            NOT NULL DEFAULT gen_random_uuid(),
  schema_version  VARCHAR(8)      NOT NULL DEFAULT '1.0',

  -- Timing: occurred_at is the event source timestamp; ingested_at is when we stored it.
  occurred_at     TIMESTAMPTZ     NOT NULL,
  ingested_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

  -- Classification
  event_type      VARCHAR(128)    NOT NULL,
  event_category  audit_category  NOT NULL,
  severity        VARCHAR(16)     NOT NULL,
  component       VARCHAR(64)     NOT NULL,

  -- Correlation identifiers
  request_id      UUID,
  correlation_id  UUID,
  artifact_id     VARCHAR(128),

  -- Actor context
  actor_id        VARCHAR(128),
  actor_username  VARCHAR(128),
  actor_role      VARCHAR(64),

  -- Resource context
  policy_id       VARCHAR(128),
  key_id          VARCHAR(128),
  tenant_id       VARCHAR(128),

  -- Outcome classification
  outcome         VARCHAR(16),

  -- Full structured payload (JSONB for ad-hoc filtering)
  payload         JSONB           NOT NULL DEFAULT '{}',

  -- Retention control
  retain_until    TIMESTAMPTZ,
  legal_hold      BOOLEAN         NOT NULL DEFAULT false,

  CONSTRAINT platform_audit_events_pkey         PRIMARY KEY (id),
  CONSTRAINT platform_audit_events_event_id_uq  UNIQUE (event_id),
  CONSTRAINT platform_audit_events_severity_chk CHECK (
    severity IN ('FATAL', 'CRITICAL', 'ERROR', 'WARN', 'INFO')
  ),
  CONSTRAINT platform_audit_events_outcome_chk  CHECK (
    outcome IS NULL OR outcome IN ('ALLOW', 'BLOCK', 'SUCCESS', 'FAILURE', 'WARNING')
  )
);

-- ── Retention policies ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_retention_policies (
  id                  SERIAL          PRIMARY KEY,
  name                VARCHAR(128)    NOT NULL,
  description         TEXT,
  event_category      audit_category,
  event_type_pattern  VARCHAR(256),
  tenant_id           VARCHAR(128),
  severity            VARCHAR(16),
  retain_days         INTEGER         NOT NULL,
  compliance_profile  VARCHAR(128),
  is_default          BOOLEAN         NOT NULL DEFAULT false,
  created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

  CONSTRAINT audit_retention_policies_name_uq       UNIQUE (name),
  CONSTRAINT audit_retention_policies_retain_days_chk CHECK (retain_days >= 0)
);

-- ── Legal holds ───────────────────────────────────────────────────────────────
-- Prevents deletion of specific artifacts, tenants, or event categories
-- regardless of retain_until. Released only by explicit action.

CREATE TABLE IF NOT EXISTS audit_legal_holds (
  id              SERIAL          PRIMARY KEY,
  hold_name       VARCHAR(256)    NOT NULL,
  reason          TEXT            NOT NULL,
  artifact_id     VARCHAR(128),
  event_id        UUID,
  tenant_id       VARCHAR(128),
  event_category  audit_category,
  held_by         VARCHAR(128)    NOT NULL,
  held_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
  released_at     TIMESTAMPTZ,
  released_by     VARCHAR(128),

  CONSTRAINT audit_legal_holds_target_chk CHECK (
    artifact_id IS NOT NULL OR event_id IS NOT NULL
    OR tenant_id IS NOT NULL OR event_category IS NOT NULL
  )
);

-- ── Retention run history ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_retention_runs (
  id              SERIAL          PRIMARY KEY,
  run_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
  policy_id       INTEGER         REFERENCES audit_retention_policies(id) ON DELETE SET NULL,
  events_examined BIGINT          NOT NULL DEFAULT 0,
  events_expired  BIGINT          NOT NULL DEFAULT 0,
  events_held     BIGINT          NOT NULL DEFAULT 0,
  duration_ms     INTEGER,
  status          VARCHAR(16)     NOT NULL DEFAULT 'COMPLETE',
  error           TEXT,

  CONSTRAINT audit_retention_runs_status_chk CHECK (status IN ('COMPLETE', 'FAILED', 'RUNNING'))
);

-- ── Indexes for platform_audit_events ─────────────────────────────────────────

-- Time-range queries: most common operational and forensic pattern
CREATE INDEX IF NOT EXISTS idx_pae_occurred_at
  ON platform_audit_events (occurred_at DESC);

-- Category + time: "show SECURITY events last 24h"
CREATE INDEX IF NOT EXISTS idx_pae_category_time
  ON platform_audit_events (event_category, occurred_at DESC);

-- Event type + time: "all RBAC_DENY events this week"
CREATE INDEX IF NOT EXISTS idx_pae_event_type
  ON platform_audit_events (event_type, occurred_at DESC);

-- Artifact forensics: "every event touching artifact X"
-- Partial index: artifact_id is populated for a minority of events
CREATE INDEX IF NOT EXISTS idx_pae_artifact_id
  ON platform_audit_events (artifact_id, occurred_at DESC)
  WHERE artifact_id IS NOT NULL;

-- Request correlation: "all events within a single request"
CREATE INDEX IF NOT EXISTS idx_pae_request_id
  ON platform_audit_events (request_id, occurred_at DESC)
  WHERE request_id IS NOT NULL;

-- Tenant isolation: "events for tenant T" (multi-tenant future path)
CREATE INDEX IF NOT EXISTS idx_pae_tenant_id
  ON platform_audit_events (tenant_id, occurred_at DESC)
  WHERE tenant_id IS NOT NULL;

-- Actor audit trail: "all actions performed by actor U"
CREATE INDEX IF NOT EXISTS idx_pae_actor_id
  ON platform_audit_events (actor_id, occurred_at DESC)
  WHERE actor_id IS NOT NULL;

-- Severity + time: "all ERROR and above last hour"
CREATE INDEX IF NOT EXISTS idx_pae_severity_time
  ON platform_audit_events (severity, occurred_at DESC);

-- Retention enforcement: background job selects by retain_until
-- Partial index omits events without an expiry (legal forever) and under holds
CREATE INDEX IF NOT EXISTS idx_pae_retention
  ON platform_audit_events (retain_until ASC)
  WHERE retain_until IS NOT NULL AND legal_hold = false;

-- JSONB GIN for ad-hoc payload field search
CREATE INDEX IF NOT EXISTS idx_pae_payload_gin
  ON platform_audit_events USING GIN (payload);

-- ── Row-Level Security ────────────────────────────────────────────────────────
-- Mirrors audit_chain RLS: app role can INSERT, never UPDATE or DELETE.
-- Retention deletes run under a dedicated maintenance role (qodiqa_mig or superuser).

ALTER TABLE platform_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_audit_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pae_insert_only ON platform_audit_events;
CREATE POLICY pae_insert_only
  ON platform_audit_events
  FOR INSERT
  TO qodiqa_app
  WITH CHECK (true);

DROP POLICY IF EXISTS pae_select ON platform_audit_events;
CREATE POLICY pae_select
  ON platform_audit_events
  FOR SELECT
  TO qodiqa_app, qodiqa_read
  USING (true);

-- ── Service account grants ────────────────────────────────────────────────────

GRANT SELECT, INSERT ON platform_audit_events TO qodiqa_app;
GRANT SELECT            ON platform_audit_events TO qodiqa_read;
GRANT USAGE, SELECT ON SEQUENCE platform_audit_events_id_seq TO qodiqa_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON audit_retention_policies TO qodiqa_app;
GRANT SELECT                          ON audit_retention_policies TO qodiqa_read;
GRANT USAGE, SELECT ON SEQUENCE audit_retention_policies_id_seq TO qodiqa_app;

GRANT SELECT, INSERT, UPDATE ON audit_legal_holds TO qodiqa_app;
GRANT SELECT                  ON audit_legal_holds TO qodiqa_read;
GRANT USAGE, SELECT ON SEQUENCE audit_legal_holds_id_seq TO qodiqa_app;

GRANT SELECT, INSERT ON audit_retention_runs TO qodiqa_app;
GRANT SELECT          ON audit_retention_runs TO qodiqa_read;
GRANT USAGE, SELECT ON SEQUENCE audit_retention_runs_id_seq TO qodiqa_app;

-- ── Default retention policies ────────────────────────────────────────────────
-- retain_days = 0 means retain indefinitely.
-- Enforcement decisions (ALLOW/BLOCK) are always retained indefinitely — they
-- are cryptographic evidence and must never be subject to automated expiry.

INSERT INTO audit_retention_policies
  (name, description, event_category, retain_days, compliance_profile, is_default)
VALUES
  ('enforcement-forever',
   'Enforcement decisions (ALLOW/BLOCK) — immutable audit evidence, retained indefinitely',
   'ENFORCEMENT', 0, NULL, true),

  ('security-events-7-years',
   'Security events: replay attacks, tampering, SSRF, anomalies — SOC2/ISO27001 requirement',
   'SECURITY', 2555, 'SOC2', true),

  ('key-management-7-years',
   'Key lifecycle: rotation, expiry, provisioning — 7-year retention for compliance',
   'KEY_MANAGEMENT', 2555, 'SOC2', true),

  ('access-control-2-years',
   'RBAC decisions: ALLOW, DENY, user creation/deletion — 2-year retention',
   'ACCESS_CONTROL', 730, NULL, true),

  ('policy-events-2-years',
   'Policy lifecycle: create, update, enable, disable, rollback — 2-year retention',
   'POLICY', 730, NULL, true),

  ('evidence-2-years',
   'Evidence package generation events',
   'EVIDENCE', 730, NULL, true),

  ('audit-chain-events-forever',
   'Audit chain integrity verification events — retained indefinitely',
   'AUDIT_CHAIN', 0, NULL, true),

  ('provider-events-90-days',
   'AI provider execution events — operational, 90-day retention',
   'PROVIDER', 90, NULL, true),

  ('infrastructure-30-days',
   'Redis, PostgreSQL, startup/shutdown infrastructure events — 30-day operational retention',
   'INFRASTRUCTURE', 30, NULL, true),

  ('operational-30-days',
   'General operational events, ops middleware — 30-day retention',
   'OPERATIONAL', 30, NULL, true),

  ('lifecycle-30-days',
   'Gateway start/stop, policy reload lifecycle events — 30-day retention',
   'LIFECYCLE', 30, NULL, true)

ON CONFLICT (name) DO NOTHING;

COMMIT;
