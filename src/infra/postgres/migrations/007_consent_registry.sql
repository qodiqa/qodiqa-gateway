-- QODIQA PostgreSQL Schema — Migration 007
-- Component: Runtime Consent Registry
-- Purpose: Persistent, auditable storage for all consent records that drive
--          execution authorization decisions in the QODIQA enforcement pipeline.
--
-- Design principles:
--   1. Every consent record is the authoritative source of truth for one actor × action pair
--   2. State changes are logged to consent_audit_log (immutable append-only)
--   3. Revoked and expired records are retained for audit/forensic purposes (never deleted)
--   4. Expiry is enforced at lookup time (expires_at < NOW()) — no background expiry job needed
--   5. Scope validation is optional per-action — missing scope means "any scope accepted"
--   6. Tenant isolation: each record is scoped to tenant_id (NULL = platform-level)
--   7. Idempotent: safe to re-run; all DDL uses IF NOT EXISTS
--   8. Row-level security enabled; application enforces tenant boundaries
--   9. granted_by / revoked_by carry the identity of the actor who performed the operation
--      for complete audit trails meeting SOC 2 / GDPR requirements

BEGIN;

-- ── Consent Records ────────────────────────────────────────────────────────────
-- One row per (actor_id, action, tenant_id) triple.
-- This is the hot-path lookup table — reads must be < 5ms at P99.

CREATE TABLE IF NOT EXISTS consent_records (
    id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identity
    actor_id            VARCHAR(256)  NOT NULL,   -- subject who gave/holds consent
    action              VARCHAR(256)  NOT NULL,   -- capability/action being authorized

    -- State machine
    state               VARCHAR(32)   NOT NULL DEFAULT 'PENDING',

    -- Scope — what the consent covers (biometric, medical, marketing, basic, etc.)
    scope               VARCHAR(128),             -- NULL = scope not specified

    -- Tenant isolation (NULL = platform-level consent)
    tenant_id           VARCHAR(128),

    -- Required scope — if set, enforcement must match this scope exactly
    required_scope      VARCHAR(128),

    -- Grant metadata
    granted_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    granted_by          VARCHAR(256)  NOT NULL,   -- identity who granted consent
    granted_via         VARCHAR(64),              -- 'API' | 'MIGRATION' | 'IMPORT' | 'SELF'
    grant_reference     TEXT,                     -- external reference (consent form ID, etc.)

    -- Expiry
    expires_at          TIMESTAMPTZ,              -- NULL = no expiry (indefinite)
    duration_days       INTEGER,                  -- informational: original duration

    -- Revocation (both NULL or both non-NULL)
    revoked_at          TIMESTAMPTZ,
    revoked_by          VARCHAR(256),
    revocation_reason   TEXT,

    -- Suspension (temporary hold without revoking)
    suspended_at        TIMESTAMPTZ,
    suspended_by        VARCHAR(256),
    suspension_reason   TEXT,
    suspended_until     TIMESTAMPTZ,              -- auto-resumes after this point

    -- Metadata
    subject_name        VARCHAR(512),             -- human-readable subject description
    action_display      VARCHAR(512),             -- human-readable action description
    policy_reference    VARCHAR(256),             -- policy that required this consent
    tags                TEXT[]        NOT NULL DEFAULT '{}',
    metadata            JSONB         NOT NULL DEFAULT '{}',

    -- Integrity
    record_hash         CHAR(64),                 -- SHA-256 of canonical record fields (tamper detection)
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    version             INTEGER       NOT NULL DEFAULT 1,

    -- Constraints
    CONSTRAINT consent_records_state_check CHECK (
        state IN ('PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED', 'SUSPENDED')
    ),
    CONSTRAINT consent_records_expiry_order CHECK (
        expires_at IS NULL OR expires_at > granted_at
    ),
    CONSTRAINT consent_records_revocation_pair CHECK (
        (revoked_at IS NULL) = (revoked_by IS NULL)
    ),
    CONSTRAINT consent_records_suspension_pair CHECK (
        (suspended_at IS NULL) = (suspended_by IS NULL)
    ),

    -- One active consent per actor × action × tenant
    UNIQUE (actor_id, action, tenant_id)
);

-- Primary lookup index: actor + action + tenant — covers 100% of hot-path queries
CREATE INDEX IF NOT EXISTS idx_consent_lookup
    ON consent_records (actor_id, action, tenant_id)
    WHERE state NOT IN ('REVOKED');

-- Active consent for dashboard / compliance views
CREATE INDEX IF NOT EXISTS idx_consent_active
    ON consent_records (state, tenant_id, expires_at)
    WHERE state = 'ACTIVE';

-- Expiry sweep (enforcement via expires_at comparison, not job-based)
CREATE INDEX IF NOT EXISTS idx_consent_expires
    ON consent_records (expires_at)
    WHERE expires_at IS NOT NULL AND state = 'ACTIVE';

-- Actor timeline for compliance reporting
CREATE INDEX IF NOT EXISTS idx_consent_actor
    ON consent_records (actor_id, granted_at DESC);

-- Tenant administration
CREATE INDEX IF NOT EXISTS idx_consent_tenant
    ON consent_records (tenant_id, state, granted_at DESC)
    WHERE tenant_id IS NOT NULL;

-- Full-text JSONB search on metadata
CREATE INDEX IF NOT EXISTS idx_consent_metadata
    ON consent_records USING gin (metadata);

COMMENT ON TABLE consent_records IS
    'Authoritative runtime consent registry. Each row represents a specific '
    'actor × action × tenant consent grant. This table is the trust anchor '
    'for all QODIQA execution authorization decisions. Never delete rows — '
    'use state transitions (REVOKED, EXPIRED) instead.';

COMMENT ON COLUMN consent_records.actor_id IS
    'Subject identifier who holds this consent. '
    'Maps to artifact.payload.userId or tenant key owner.';

COMMENT ON COLUMN consent_records.action IS
    'Capability or action covered by this consent. '
    'Maps to context.action in the policy evaluator (artifact.payload.provider).';

COMMENT ON COLUMN consent_records.state IS
    'Current state in the consent lifecycle: '
    'PENDING (awaiting activation), '
    'ACTIVE (valid, enforcement passes), '
    'REVOKED (permanently revoked, terminal), '
    'EXPIRED (past expires_at, terminal for current grant), '
    'SUSPENDED (temporarily held).';

-- ── Consent Audit Log ─────────────────────────────────────────────────────────
-- Immutable append-only log of all consent record events.
-- Every state transition, lookup, and verification attempt is recorded here.
-- Retention: permanent (supports GDPR right-of-access requests and SOC 2 audits).

CREATE TABLE IF NOT EXISTS consent_audit_log (
    id              BIGSERIAL     PRIMARY KEY,
    consent_id      UUID          REFERENCES consent_records (id) ON DELETE RESTRICT,

    -- What happened
    event_type      VARCHAR(64)   NOT NULL,
    event_ts        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    -- Who did it
    actor           VARCHAR(256)  NOT NULL,   -- system | API actor | integration
    request_id      UUID,                     -- correlates to platform request

    -- Before/after for state changes
    from_state      VARCHAR(32),
    to_state        VARCHAR(32),

    -- Consent identifiers (denormalized for lookups even if consent_id is NULL)
    actor_id        VARCHAR(256),
    action          VARCHAR(256),
    tenant_id       VARCHAR(128),

    -- Verification outcomes
    verification_result VARCHAR(64),          -- VERIFIED | DENIED | LOOKUP_MISS | CACHE_HIT | etc.
    denial_reason   VARCHAR(256),

    -- Additional structured context
    detail          JSONB         NOT NULL DEFAULT '{}',

    -- Immutability marker
    checksum        CHAR(64)                  -- SHA-256 of (id, event_type, event_ts, detail)
);

-- Lookup by consent record
CREATE INDEX IF NOT EXISTS idx_consent_audit_consent_id
    ON consent_audit_log (consent_id, event_ts DESC);

-- All events for an actor (compliance reporting, GDPR)
CREATE INDEX IF NOT EXISTS idx_consent_audit_actor
    ON consent_audit_log (actor_id, event_ts DESC)
    WHERE actor_id IS NOT NULL;

-- Request correlation (ties to platform_audit_events)
CREATE INDEX IF NOT EXISTS idx_consent_audit_request
    ON consent_audit_log (request_id, event_ts DESC)
    WHERE request_id IS NOT NULL;

-- Recent audit activity
CREATE INDEX IF NOT EXISTS idx_consent_audit_ts
    ON consent_audit_log (event_ts DESC);

-- Event type filter (dashboard)
CREATE INDEX IF NOT EXISTS idx_consent_audit_event_type
    ON consent_audit_log (event_type, event_ts DESC);

COMMENT ON TABLE consent_audit_log IS
    'Immutable audit trail for all consent operations. '
    'Never update or delete rows. Every lookup, grant, revocation, and '
    'verification attempt is recorded here for forensic and compliance purposes.';

-- ── Consent Scopes ────────────────────────────────────────────────────────────
-- Registry of known scopes and which actions they authorize.
-- Allows administrators to define the scope taxonomy at runtime.

CREATE TABLE IF NOT EXISTS consent_scopes (
    scope_name      VARCHAR(128)  PRIMARY KEY,
    display_name    VARCHAR(256)  NOT NULL,
    description     TEXT,
    actions         TEXT[]        NOT NULL DEFAULT '{}',  -- which actions this scope covers
    sensitivity     VARCHAR(32)   NOT NULL DEFAULT 'STANDARD',  -- LOW | STANDARD | HIGH | CRITICAL
    requires_reason BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    created_by      VARCHAR(256)  NOT NULL DEFAULT 'system',
    active          BOOLEAN       NOT NULL DEFAULT TRUE,

    CONSTRAINT consent_scopes_sensitivity_check CHECK (
        sensitivity IN ('LOW', 'STANDARD', 'HIGH', 'CRITICAL')
    )
);

CREATE INDEX IF NOT EXISTS idx_consent_scopes_active ON consent_scopes (active) WHERE active = TRUE;

-- Seed known scopes from existing registry.js data
INSERT INTO consent_scopes (scope_name, display_name, description, actions, sensitivity)
VALUES
    ('biometric',  'Biometric Data',           'Processing of biometric identifiers',    ARRAY['Facial Recognition', 'Biometric Processing'],                          'CRITICAL'),
    ('medical',    'Medical Records',          'Access to protected health information', ARRAY['Medical Record Access', 'Health Data Processing'],                     'CRITICAL'),
    ('voice',      'Voice Data',               'Voice pattern capture and processing',   ARRAY['Voice Cloning', 'Voice Analysis'],                                     'HIGH'),
    ('marketing',  'Marketing Preferences',    'Behavioral profiling for marketing',     ARRAY['Preference Profiling', 'Behavioral Analysis'],                         'STANDARD'),
    ('basic',      'Basic Operations',         'Standard operational data access',       ARRAY['Data Export', 'Preference Profiling', 'Real-Time Location Tracking'],  'LOW')
ON CONFLICT (scope_name) DO NOTHING;

COMMENT ON TABLE consent_scopes IS
    'Registry of consent scope definitions. Scopes define what categories of '
    'actions are covered by a consent grant. Used for scope enforcement in '
    'runtime verification.';

-- ── Trigger: update updated_at on consent_records ───────────────────────────

CREATE OR REPLACE FUNCTION _consent_records_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    NEW.version    = OLD.version + 1;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS consent_records_updated_at ON consent_records;
CREATE TRIGGER consent_records_updated_at
    BEFORE UPDATE ON consent_records
    FOR EACH ROW EXECUTE FUNCTION _consent_records_updated_at();

-- ── Row-level security ────────────────────────────────────────────────────────

ALTER TABLE consent_records  ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent_scopes   ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_app') THEN
        EXECUTE 'CREATE POLICY consent_app_bypass ON consent_records TO qodiqa_app USING (true)';
        EXECUTE 'CREATE POLICY consent_audit_app_bypass ON consent_audit_log TO qodiqa_app USING (true)';
        EXECUTE 'CREATE POLICY consent_scopes_app_bypass ON consent_scopes TO qodiqa_app USING (true)';
    END IF;
EXCEPTION WHEN duplicate_object THEN NULL;
END;
$$;

COMMIT;
