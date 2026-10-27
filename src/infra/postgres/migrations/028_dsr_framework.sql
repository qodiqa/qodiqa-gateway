-- QODIQA PostgreSQL Schema — Migration 028
-- GDPR Data Subject Rights (Articles 16, 17, 18, 20)
--
-- ROOT CAUSE:
-- No API, service, database support, or audit trail exists anywhere in the
-- platform for rectification, erasure, restriction, or portability requests.
-- independently confirms the same gap
-- from a legal-assessment angle and identifies actor_id (consent_records /
-- consent_audit_log, see 007_consent_registry.sql) as the only person-like
-- identifier QODIQA holds — QODIQA has no end-user accounts of its own.
--
-- SCOPE:
-- This migration adds request-tracking and evidence tables only. It does
-- NOT touch consent_records / consent_audit_log column definitions (Article
-- 16/17/18 execution reuses ConsentStore's existing state machine and
-- audit-log mechanism — see src/core/consent/ConsentStore.js rectify()/
-- anonymize() and src/core/dsr/*Service.js) and it does NOT touch audit_chain
-- / platform_audit_events (the cryptographic hash chain has no actor_id
-- field and no delete/redact primitive — see entryBuilder.js and
-- audit-log.js — and retention.js already hard-excludes ENFORCEMENT
-- category events from deletion; erasure legally relies on that existing
-- Art. 17(3)(b)/(e) posture rather than altering it).
--
-- DESIGN:
--   dsr_requests        — one row per DSR request; the case file. UPDATEable
--                          (status/result progress in place) but never
--                          DELETEd — the request record is itself permanent
--                          DSR evidence.
--   dsr_request_events   — append-only lifecycle audit trail for the request
--                          itself (RECEIVED -> IDENTITY_VERIFIED -> ... ->
--                          COMPLETED), same checksum pattern as
--                          consent_audit_log. INSERT-only, mirrors
--                          "the audit log is append-only" (ConsentStore.js:9-10).
--   dsr_rectifications   — append-only corrective-record trail for Article 16
--                          (old value -> new value, never overwritten).
--   dsr_exports          — Article 20 evidence only: checksum + size, never
--                          the export payload itself, so portability doesn't
--                          create a second at-rest copy of personal data.
--
-- Idempotent: safe to re-run. All DDL uses IF NOT EXISTS; grants are
-- naturally idempotent; migration record insert uses ON CONFLICT DO NOTHING,
-- consistent with every prior migration in this directory.

BEGIN;

-- ── DSR Requests ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS dsr_requests (
    id                              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),

    request_type                    VARCHAR(32)   NOT NULL,
    actor_id                        VARCHAR(256)  NOT NULL,
    tenant_id                       VARCHAR(128),

    status                          VARCHAR(32)   NOT NULL DEFAULT 'RECEIVED',

    requested_by                    VARCHAR(256)  NOT NULL,
    requested_at                    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    -- Identity verification (Article 12(6)) — see src/core/dsr/identityVerification.js.
    -- QODIQA has no end-user session of its own; verification is an explicit,
    -- recorded attestation by the authenticated (RBAC) operator handling the
    -- request, not a new consumer-auth mechanism.
    identity_verification_method    VARCHAR(64),
    identity_verification_result    VARCHAR(32),
    identity_verification_evidence  TEXT,
    identity_verified_by            VARCHAR(256),
    identity_verified_at            TIMESTAMPTZ,

    legal_basis                     TEXT,
    justification                   TEXT,

    approved_by                     VARCHAR(256),
    approved_at                     TIMESTAMPTZ,
    completed_at                    TIMESTAMPTZ,

    -- Structured result: actions taken, fields anonymized/pseudonymized,
    -- records retained with legal justification, export checksum reference.
    result                          JSONB         NOT NULL DEFAULT '{}',
    export_checksum                 CHAR(64),
    error                           TEXT,

    created_at                      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT dsr_requests_type_check CHECK (
        request_type IN ('RECTIFICATION', 'ERASURE', 'RESTRICTION', 'PORTABILITY')
    ),
    CONSTRAINT dsr_requests_status_check CHECK (
        status IN ('RECEIVED', 'IDENTITY_VERIFIED', 'APPROVED', 'IN_PROGRESS',
                   'COMPLETED', 'REJECTED', 'FAILED')
    ),
    CONSTRAINT dsr_requests_verification_result_check CHECK (
        identity_verification_result IS NULL OR
        identity_verification_result IN ('VERIFIED', 'FAILED')
    )
);

CREATE INDEX IF NOT EXISTS idx_dsr_requests_actor
    ON dsr_requests (actor_id, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_dsr_requests_tenant
    ON dsr_requests (tenant_id, status, requested_at DESC)
    WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_dsr_requests_status
    ON dsr_requests (status, requested_at DESC);

COMMENT ON TABLE dsr_requests IS
    'GDPR Data Subject Rights request case file. One row per '
    'rectification/erasure/restriction/portability request. Never delete '
    'rows — this record is itself the DSR compliance evidence.';

CREATE OR REPLACE FUNCTION _dsr_requests_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS dsr_requests_updated_at ON dsr_requests;
CREATE TRIGGER dsr_requests_updated_at
    BEFORE UPDATE ON dsr_requests
    FOR EACH ROW EXECUTE FUNCTION _dsr_requests_updated_at();

-- ── DSR Request Events (append-only lifecycle audit trail) ─────────────────

CREATE TABLE IF NOT EXISTS dsr_request_events (
    id              BIGSERIAL     PRIMARY KEY,
    request_id      UUID          NOT NULL REFERENCES dsr_requests (id) ON DELETE RESTRICT,
    tenant_id       VARCHAR(128),

    event_type      VARCHAR(64)   NOT NULL,
    occurred_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    actor           VARCHAR(256)  NOT NULL,

    detail          JSONB         NOT NULL DEFAULT '{}',
    checksum        CHAR(64)      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dsr_request_events_request
    ON dsr_request_events (request_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_dsr_request_events_tenant
    ON dsr_request_events (tenant_id, occurred_at DESC)
    WHERE tenant_id IS NOT NULL;

COMMENT ON TABLE dsr_request_events IS
    'Immutable lifecycle audit trail for DSR requests. Never update or '
    'delete rows — every validation, approval, execution, and failure is '
    'recorded here, mirroring consent_audit_log (ConsentStore.js).';

-- ── DSR Rectifications (Article 16 — append-only corrective records) ───────

CREATE TABLE IF NOT EXISTS dsr_rectifications (
    id              BIGSERIAL     PRIMARY KEY,
    request_id      UUID          NOT NULL REFERENCES dsr_requests (id) ON DELETE RESTRICT,
    consent_id      UUID          REFERENCES consent_records (id) ON DELETE RESTRICT,
    actor_id        VARCHAR(256)  NOT NULL,
    tenant_id       VARCHAR(128),

    field_name      VARCHAR(128)  NOT NULL,
    old_value       JSONB,
    new_value       JSONB,

    rectified_by    VARCHAR(256)  NOT NULL,
    rectified_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dsr_rectifications_actor
    ON dsr_rectifications (actor_id, rectified_at DESC);

CREATE INDEX IF NOT EXISTS idx_dsr_rectifications_request
    ON dsr_rectifications (request_id, rectified_at DESC);

COMMENT ON TABLE dsr_rectifications IS
    'Article 16 corrective-record trail. Superseded values are never '
    'overwritten — each correction appends a new row, preserving complete '
    'traceability from original to corrected value.';

-- ── DSR Exports (Article 20 — evidence only, never the payload) ────────────

CREATE TABLE IF NOT EXISTS dsr_exports (
    id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID          NOT NULL REFERENCES dsr_requests (id) ON DELETE RESTRICT,
    actor_id        VARCHAR(256)  NOT NULL,
    tenant_id       VARCHAR(128),

    format          VARCHAR(16)   NOT NULL,
    checksum        CHAR(64)      NOT NULL,
    size_bytes      INTEGER       NOT NULL,

    generated_by    VARCHAR(256)  NOT NULL,
    generated_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT dsr_exports_format_check CHECK (format IN ('JSON', 'CSV'))
);

CREATE INDEX IF NOT EXISTS idx_dsr_exports_actor
    ON dsr_exports (actor_id, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_dsr_exports_request
    ON dsr_exports (request_id);

COMMENT ON TABLE dsr_exports IS
    'Article 20 portability export evidence — checksum and size only. The '
    'export payload itself is generated on demand and returned in the API '
    'response; it is intentionally never persisted here, so portability '
    'does not create an additional at-rest copy of personal data.';

-- ── Grants ───────────────────────────────────────────────────────────────────
-- Same shape as consent_records/consent_audit_log (022_consent_registry_grants_fix.sql):
-- dsr_requests is mutable in place (status/result progress) so gets UPDATE;
-- the three append-only tables get SELECT+INSERT only, no UPDATE/DELETE ever.

GRANT SELECT, INSERT, UPDATE ON dsr_requests         TO qodiqa_app;
GRANT SELECT                 ON dsr_requests         TO qodiqa_read;

GRANT SELECT, INSERT ON dsr_request_events           TO qodiqa_app;
GRANT SELECT         ON dsr_request_events           TO qodiqa_read;

GRANT SELECT, INSERT ON dsr_rectifications           TO qodiqa_app;
GRANT SELECT         ON dsr_rectifications           TO qodiqa_read;

GRANT SELECT, INSERT ON dsr_exports                  TO qodiqa_app;
GRANT SELECT         ON dsr_exports                  TO qodiqa_read;

GRANT USAGE, SELECT ON SEQUENCE dsr_request_events_id_seq  TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE dsr_rectifications_id_seq  TO qodiqa_app;

-- ── Row-level security ────────────────────────────────────────────────────────
-- Same tenant-aware model as consent_records/consent_audit_log (018_rls_tenant_isolation.sql):
-- tenant_id nullable; NULL rows are platform-level and always visible;
-- tenant-scoped rows require a matching qodiqa_current_tenant() context.

ALTER TABLE dsr_requests       ENABLE ROW LEVEL SECURITY;
ALTER TABLE dsr_requests       FORCE ROW LEVEL SECURITY;
ALTER TABLE dsr_request_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE dsr_request_events FORCE ROW LEVEL SECURITY;
ALTER TABLE dsr_rectifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE dsr_rectifications FORCE ROW LEVEL SECURITY;
ALTER TABLE dsr_exports        ENABLE ROW LEVEL SECURITY;
ALTER TABLE dsr_exports        FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dsr_req_tenant_select ON dsr_requests;
DROP POLICY IF EXISTS dsr_req_tenant_insert ON dsr_requests;
DROP POLICY IF EXISTS dsr_req_tenant_update ON dsr_requests;

CREATE POLICY dsr_req_tenant_select ON dsr_requests
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY dsr_req_tenant_insert ON dsr_requests
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY dsr_req_tenant_update ON dsr_requests
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

DROP POLICY IF EXISTS dsr_evt_tenant_select ON dsr_request_events;
DROP POLICY IF EXISTS dsr_evt_system_insert ON dsr_request_events;

CREATE POLICY dsr_evt_tenant_select ON dsr_request_events
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY dsr_evt_system_insert ON dsr_request_events
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

DROP POLICY IF EXISTS dsr_rect_tenant_select ON dsr_rectifications;
DROP POLICY IF EXISTS dsr_rect_system_insert ON dsr_rectifications;

CREATE POLICY dsr_rect_tenant_select ON dsr_rectifications
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY dsr_rect_system_insert ON dsr_rectifications
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

DROP POLICY IF EXISTS dsr_exp_tenant_select ON dsr_exports;
DROP POLICY IF EXISTS dsr_exp_system_insert ON dsr_exports;

CREATE POLICY dsr_exp_tenant_select ON dsr_exports
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY dsr_exp_system_insert ON dsr_exports
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (28, 'dsr_framework', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
