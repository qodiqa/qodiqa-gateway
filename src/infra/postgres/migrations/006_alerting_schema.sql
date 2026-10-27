-- QODIQA PostgreSQL Schema — Migration 006
-- Component: Alerting & Notification Framework
-- Purpose: Persistent storage for alerts, incidents, escalation history,
--          notification delivery records, anomaly baselines, and suppression rules.
--
-- Design principles:
--   1. Alerts are immutable once closed (status transitions only)
--   2. All state changes append to alert_history (full audit trail)
--   3. Incidents aggregate correlated alerts (normalized M:N join)
--   4. Notification delivery tracked per-channel with retry state
--   5. Escalation history preserved for SLA reporting
--   6. Suppression rules expire automatically via suppressed_until
--   7. Anomaly baselines stored as JSON for flexible schema evolution
--   8. All timestamps in UTC (enforced by SET TIME ZONE 'UTC' per connection)
--   9. Idempotent: safe to re-run; all DDL uses IF NOT EXISTS

BEGIN;

-- ── Alerts ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS qodiqa_alerts (
    id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Classification
    alert_type          VARCHAR(32)   NOT NULL,
    alert_subtype       VARCHAR(64)   NOT NULL,
    severity            VARCHAR(16)   NOT NULL,
    status              VARCHAR(32)   NOT NULL DEFAULT 'OPEN',

    -- Risk
    risk_score          SMALLINT      NOT NULL DEFAULT 0
                                      CHECK (risk_score BETWEEN 0 AND 100),
    confidence          SMALLINT      NOT NULL DEFAULT 100
                                      CHECK (confidence BETWEEN 0 AND 100),

    -- Content
    title               VARCHAR(256)  NOT NULL,
    description         TEXT          NOT NULL DEFAULT '',
    tags                TEXT[]        NOT NULL DEFAULT '{}',

    -- Detection source context
    source_event        VARCHAR(128),           -- originating platform event name
    request_id          UUID,
    artifact_id         VARCHAR(256),
    tenant_id           VARCHAR(128),
    public_key_id       VARCHAR(128),
    client_ip           VARCHAR(64),
    actor_id            VARCHAR(256),
    component           VARCHAR(64),

    -- Evidence payload (full structured detection evidence)
    evidence            JSONB         NOT NULL DEFAULT '{}',

    -- Context payload (enriched environmental context at detection time)
    context             JSONB         NOT NULL DEFAULT '{}',

    -- Lifecycle
    detected_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    acknowledged_at     TIMESTAMPTZ,
    acknowledged_by     VARCHAR(256),
    resolved_at         TIMESTAMPTZ,
    resolved_by         VARCHAR(256),
    resolution_note     TEXT,
    suppressed_until    TIMESTAMPTZ,

    -- Escalation tracking
    escalation_level    SMALLINT      NOT NULL DEFAULT 0,
    last_escalated_at   TIMESTAMPTZ,
    next_escalation_at  TIMESTAMPTZ,

    -- Incident linkage (NULL until correlated)
    incident_id         UUID,

    -- Retention
    retain_until        TIMESTAMPTZ   NOT NULL,

    -- Deduplication key (prevents identical alerts in suppression window)
    dedup_key           VARCHAR(256),
    deduplicated_count  INTEGER       NOT NULL DEFAULT 1,
    last_seen_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT qodiqa_alerts_type_check CHECK (
        alert_type IN ('REPLAY_ATTACK','SIGNATURE_FAILURE','POLICY_FAILURE','ANOMALY','OPERATIONAL','GOVERNANCE')
    ),
    CONSTRAINT qodiqa_alerts_severity_check CHECK (
        severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')
    ),
    CONSTRAINT qodiqa_alerts_status_check CHECK (
        status IN ('OPEN','ACKNOWLEDGED','INVESTIGATING','RESOLVED','SUPPRESSED','CLOSED','FALSE_POSITIVE')
    )
);

-- Indexes optimized for dashboard queries, API filtering, and escalation scans
CREATE INDEX IF NOT EXISTS idx_alerts_status          ON qodiqa_alerts (status)          WHERE status IN ('OPEN','ACKNOWLEDGED','INVESTIGATING');
CREATE INDEX IF NOT EXISTS idx_alerts_severity        ON qodiqa_alerts (severity, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_type            ON qodiqa_alerts (alert_type, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at     ON qodiqa_alerts (detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant          ON qodiqa_alerts (tenant_id, detected_at DESC) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_request         ON qodiqa_alerts (request_id)     WHERE request_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_artifact        ON qodiqa_alerts (artifact_id)    WHERE artifact_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_incident        ON qodiqa_alerts (incident_id)    WHERE incident_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_escalation      ON qodiqa_alerts (next_escalation_at) WHERE next_escalation_at IS NOT NULL AND status IN ('OPEN','INVESTIGATING');
CREATE INDEX IF NOT EXISTS idx_alerts_dedup_key       ON qodiqa_alerts (dedup_key, detected_at DESC) WHERE dedup_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_retain_until    ON qodiqa_alerts (retain_until);
CREATE INDEX IF NOT EXISTS idx_alerts_evidence        ON qodiqa_alerts USING gin (evidence);
CREATE INDEX IF NOT EXISTS idx_alerts_tags            ON qodiqa_alerts USING gin (tags);

COMMENT ON TABLE qodiqa_alerts IS
    'Central alert store for the QODIQA Alerting & Notification Framework. '
    'All security, governance, and operational alerts are written here. '
    'Status transitions only; rows are never deleted within retain_until.';

-- ── Alert History (audit trail of all state transitions) ─────────────────────

CREATE TABLE IF NOT EXISTS qodiqa_alert_history (
    id          BIGSERIAL     PRIMARY KEY,
    alert_id    UUID          NOT NULL REFERENCES qodiqa_alerts (id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    action      VARCHAR(64)   NOT NULL,   -- CREATED, STATUS_CHANGED, ESCALATED, NOTIFICATION_SENT, etc.
    actor       VARCHAR(256),             -- system | username | channel name
    from_status VARCHAR(32),
    to_status   VARCHAR(32),
    detail      JSONB         NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_alert_history_alert_id ON qodiqa_alert_history (alert_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_alert_history_ts       ON qodiqa_alert_history (ts DESC);

COMMENT ON TABLE qodiqa_alert_history IS
    'Immutable event log of all actions taken on each alert. '
    'Supports SLA audits, forensic review, and incident retrospectives.';

-- ── Incidents (correlated alert groups) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS qodiqa_incidents (
    id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    title           VARCHAR(256)  NOT NULL,
    description     TEXT          NOT NULL DEFAULT '',
    severity        VARCHAR(16)   NOT NULL,
    status          VARCHAR(32)   NOT NULL DEFAULT 'OPEN',
    alert_count     INTEGER       NOT NULL DEFAULT 0,
    alert_types     TEXT[]        NOT NULL DEFAULT '{}',
    tenant_id       VARCHAR(128),
    correlation_key VARCHAR(256)  NOT NULL,  -- hash of correlation context
    opened_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    closed_at       TIMESTAMPTZ,
    closed_by       VARCHAR(256),
    summary         TEXT,
    retain_until    TIMESTAMPTZ   NOT NULL,

    CONSTRAINT qodiqa_incidents_severity_check CHECK (
        severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')
    ),
    CONSTRAINT qodiqa_incidents_status_check CHECK (
        status IN ('OPEN','INVESTIGATING','RESOLVED','CLOSED','FALSE_POSITIVE')
    )
);

CREATE INDEX IF NOT EXISTS idx_incidents_status        ON qodiqa_incidents (status) WHERE status IN ('OPEN','INVESTIGATING');
CREATE INDEX IF NOT EXISTS idx_incidents_severity      ON qodiqa_incidents (severity, opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant        ON qodiqa_incidents (tenant_id, opened_at DESC) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_incidents_correlation   ON qodiqa_incidents (correlation_key);
CREATE INDEX IF NOT EXISTS idx_incidents_opened_at     ON qodiqa_incidents (opened_at DESC);

COMMENT ON TABLE qodiqa_incidents IS
    'Correlated alert groups representing a single security or operational incident. '
    'Created automatically by the CorrelationEngine when multiple related alerts are detected.';

-- ── Notification Delivery Records ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS qodiqa_notification_deliveries (
    id              BIGSERIAL     PRIMARY KEY,
    alert_id        UUID          NOT NULL REFERENCES qodiqa_alerts (id) ON DELETE CASCADE,
    channel         VARCHAR(32)   NOT NULL,
    recipient       VARCHAR(512)  NOT NULL,
    status          VARCHAR(16)   NOT NULL DEFAULT 'PENDING',   -- PENDING, SENT, FAILED, RATE_LIMITED
    attempt_count   SMALLINT      NOT NULL DEFAULT 0,
    max_attempts    SMALLINT      NOT NULL DEFAULT 3,
    attempted_at    TIMESTAMPTZ,
    sent_at         TIMESTAMPTZ,
    next_retry_at   TIMESTAMPTZ,
    error_message   TEXT,
    response_code   INTEGER,
    payload_hash    CHAR(64),    -- SHA-256 of sent payload for audit

    CONSTRAINT qodiqa_nd_channel_check CHECK (
        channel IN ('EMAIL','WEBHOOK','SLACK','TEAMS','SIEM','PAGERDUTY','SMS')
    ),
    CONSTRAINT qodiqa_nd_status_check CHECK (
        status IN ('PENDING','SENT','FAILED','RATE_LIMITED','SKIPPED')
    )
);

CREATE INDEX IF NOT EXISTS idx_nd_alert_id       ON qodiqa_notification_deliveries (alert_id);
CREATE INDEX IF NOT EXISTS idx_nd_status_retry   ON qodiqa_notification_deliveries (status, next_retry_at)
    WHERE status IN ('PENDING','FAILED') AND next_retry_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_nd_channel        ON qodiqa_notification_deliveries (channel, sent_at DESC);

COMMENT ON TABLE qodiqa_notification_deliveries IS
    'Tracks every outbound notification attempt with retry state. '
    'Enables delivery auditing and retry queue management.';

-- ── Escalation Records ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS qodiqa_escalation_records (
    id              BIGSERIAL     PRIMARY KEY,
    alert_id        UUID          NOT NULL REFERENCES qodiqa_alerts (id) ON DELETE CASCADE,
    escalated_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    from_level      SMALLINT      NOT NULL,
    to_level        SMALLINT      NOT NULL,
    trigger_reason  VARCHAR(128)  NOT NULL,  -- ACK_TIMEOUT, SEVERITY_UPGRADE, MANUAL, etc.
    notified_roles  TEXT[]        NOT NULL DEFAULT '{}',
    notified_actors TEXT[]        NOT NULL DEFAULT '{}',
    acknowledged_by VARCHAR(256),
    acknowledged_at TIMESTAMPTZ,
    detail          JSONB         NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_escalation_alert_id  ON qodiqa_escalation_records (alert_id, escalated_at DESC);
CREATE INDEX IF NOT EXISTS idx_escalation_at        ON qodiqa_escalation_records (escalated_at DESC);

COMMENT ON TABLE qodiqa_escalation_records IS
    'Full escalation audit trail for every alert. Supports SLA breach analysis '
    'and compliance reporting on mean-time-to-acknowledge (MTTA).';

-- ── Alert Suppression Rules ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS qodiqa_suppression_rules (
    id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(128)  NOT NULL,
    description     TEXT,
    alert_type      VARCHAR(32),   -- NULL = match all types
    alert_subtype   VARCHAR(64),   -- NULL = match all subtypes
    severity        VARCHAR(16),   -- NULL = match all severities
    tenant_id       VARCHAR(128),  -- NULL = match all tenants
    match_pattern   JSONB         NOT NULL DEFAULT '{}',  -- additional field matchers
    enabled         BOOLEAN       NOT NULL DEFAULT TRUE,
    created_by      VARCHAR(256)  NOT NULL,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,                            -- NULL = never expires
    suppressed_count INTEGER      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_suppression_enabled ON qodiqa_suppression_rules (enabled, expires_at)
    WHERE enabled = TRUE;

COMMENT ON TABLE qodiqa_suppression_rules IS
    'Alert suppression rules for known maintenance windows, false-positive patterns, '
    'or noise reduction. All suppressions are audited and expire automatically.';

-- ── Anomaly Baselines ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS qodiqa_anomaly_baselines (
    id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_key      VARCHAR(256)  NOT NULL UNIQUE,   -- e.g. "global.requests_per_min"
    tenant_id       VARCHAR(128),
    window_type     VARCHAR(32)   NOT NULL DEFAULT 'ROLLING',  -- ROLLING, HOURLY, DAILY
    window_seconds  INTEGER       NOT NULL,
    baseline_mean   DOUBLE PRECISION,
    baseline_stddev DOUBLE PRECISION,
    baseline_p95    DOUBLE PRECISION,
    baseline_p99    DOUBLE PRECISION,
    current_value   DOUBLE PRECISION,
    threshold_low   DOUBLE PRECISION,
    threshold_high  DOUBLE PRECISION,
    threshold_multiplier DOUBLE PRECISION NOT NULL DEFAULT 3.0,  -- N-sigma for anomaly
    sample_count    BIGINT        NOT NULL DEFAULT 0,
    last_updated    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    data_points     JSONB         NOT NULL DEFAULT '[]'   -- recent samples for recalculation
);

CREATE INDEX IF NOT EXISTS idx_baselines_metric_key ON qodiqa_anomaly_baselines (metric_key);
CREATE INDEX IF NOT EXISTS idx_baselines_tenant     ON qodiqa_anomaly_baselines (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_baselines_updated    ON qodiqa_anomaly_baselines (last_updated DESC);

COMMENT ON TABLE qodiqa_anomaly_baselines IS
    'Statistical baselines for anomaly detection. Updated incrementally on each observation. '
    'Thresholds auto-adapt to historical traffic patterns.';

-- ── Alert Statistics Cache (pre-aggregated for dashboard speed) ───────────────

CREATE TABLE IF NOT EXISTS qodiqa_alert_stats (
    bucket_time     TIMESTAMPTZ   NOT NULL,
    bucket_minutes  SMALLINT      NOT NULL DEFAULT 60,
    alert_type      VARCHAR(32)   NOT NULL,
    severity        VARCHAR(16)   NOT NULL,
    alert_count     INTEGER       NOT NULL DEFAULT 0,
    incident_count  INTEGER       NOT NULL DEFAULT 0,
    resolved_count  INTEGER       NOT NULL DEFAULT 0,
    mean_ttack_ms   BIGINT,   -- mean time to acknowledge
    mean_ttrec_ms   BIGINT,   -- mean time to resolve
    PRIMARY KEY (bucket_time, bucket_minutes, alert_type, severity)
);

CREATE INDEX IF NOT EXISTS idx_alert_stats_bucket ON qodiqa_alert_stats (bucket_time DESC, bucket_minutes);

COMMENT ON TABLE qodiqa_alert_stats IS
    'Pre-aggregated hourly alert statistics for dashboard trends and compliance reports. '
    'Updated by AlertEngine after each alert state change.';

-- ── Row-level security (enable but keep policies in application layer) ────────

ALTER TABLE qodiqa_alerts                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_alert_history           ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_incidents               ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_notification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_escalation_records      ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_suppression_rules       ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_anomaly_baselines       ENABLE ROW LEVEL SECURITY;
ALTER TABLE qodiqa_alert_stats             ENABLE ROW LEVEL SECURITY;

-- Application user (qodiqa_app) bypasses RLS — policies enforced at application layer
DO $$
BEGIN
    -- Only create policy if the user exists; skip in dev environments without the role
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_app') THEN
        EXECUTE 'ALTER TABLE qodiqa_alerts FORCE ROW LEVEL SECURITY';
        EXECUTE 'CREATE POLICY qodiqa_app_bypass ON qodiqa_alerts TO qodiqa_app USING (true)';
    END IF;
EXCEPTION WHEN duplicate_object THEN NULL;
END;
$$;

COMMIT;
