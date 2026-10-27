-- QODIQA PostgreSQL Schema — Migration 029
-- Maker-Checker (Four-Eyes) Separation for Policy Lifecycle
--
-- ROOT CAUSE:
-- src/core/policy/store.js's mutators (createPolicy, updatePolicy,
-- setEnabled, rollbackPolicy) are single-call, single-actor, and
-- immediately effective — the write to policies.json (the live enforcement
-- set) happens synchronously inside the same function that creates the
-- change. A single administrator can therefore create AND activate
-- production policy with no independent second actor. The existing
-- policy_provenance_versions table (migration 009) is a deliberately
-- read-only, append-only, after-the-fact forensic ledger (no UPDATE/DELETE
-- grant or RLS policy exists for it) — it cannot gate a mutation before it
-- happens, and this migration does not alter it.
--
-- SCOPE:
-- This migration adds a workflow-gate layer only. It does NOT touch
-- policies.json / data/policy-store.json (the file-based live-enforcement
-- store remains the source of truth for the hot enforcement path — see
-- src/core/policy/governance/PolicyGovernanceService.js, which invokes the
-- existing store.js mutators only once a change request reaches
-- PUBLISHED) and does NOT touch policy_provenance_versions' schema, grants,
-- or RLS policies.
--
-- DESIGN:
--   policy_change_requests      — the workflow object (one row per proposed
--                                  change). Mutable in place through its own
--                                  lifecycle, optimistic-locked via `version`
--                                  (trigger-bumped, same pattern as
--                                  consent_records.version — closes the
--                                  "two checkers approve the same stale
--                                  proposal" race). Never DELETEd — the
--                                  request record is itself governance
--                                  evidence.
--   policy_reviews               — append-only review-round decisions.
--   policy_approvals             — append-only approval/rejection decisions.
--   policy_rollbacks             — rollback-specific governance evidence,
--                                  including the original publisher of the
--                                  version being rolled back (enforces
--                                  "rollback approver != original activator").
--   policy_publications          — append-only record of every actual
--                                  live-effect activation (the moment a
--                                  request's payload was applied to
--                                  store.js), joinable to
--                                  policy_provenance_versions by
--                                  (policy_id, resulting_policy_version).
--   policy_emergency_activations — emergency/break-glass workflow: mandatory
--                                  incident reference, justification,
--                                  time-limited, mandatory retrospective
--                                  approval, automatic expiry.
--   approval_events               — unified, hash-chained, immutable audit
--                                  trail for the whole workflow (one chain
--                                  per change_request_id), mirroring
--                                  entryBuilder.js/provenance.js's existing
--                                  previous_hash -> hash chaining approach,
--                                  using the new ARTIFACT_DOMAINS.
--                                  POLICY_GOVERNANCE hash domain
--                                  (src/infra/crypto/hashing.js).
--
-- Idempotent: safe to re-run. All DDL uses IF NOT EXISTS; grants are
-- naturally idempotent; migration record insert uses ON CONFLICT DO NOTHING,
-- consistent with every prior migration in this directory.

BEGIN;

-- ── Policy Change Requests ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_change_requests (
    id                   UUID          PRIMARY KEY DEFAULT gen_random_uuid(),

    policy_id            VARCHAR(64)   NOT NULL,
    tenant_id            VARCHAR(128),

    request_type         VARCHAR(16)   NOT NULL,
    status               VARCHAR(16)   NOT NULL DEFAULT 'DRAFT',

    payload              JSONB         NOT NULL DEFAULT '{}',
    payload_hash         CHAR(64),

    change_reason        TEXT          NOT NULL,

    author_id            VARCHAR(256)  NOT NULL,
    author_username      VARCHAR(256)  NOT NULL,
    author_role          VARCHAR(32)   NOT NULL,
    created_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    submitted_by         VARCHAR(256),
    submitted_at         TIMESTAMPTZ,

    reviewer_id          VARCHAR(256),
    reviewer_username    VARCHAR(256),
    reviewed_at          TIMESTAMPTZ,
    review_decision      VARCHAR(24),

    approver_id          VARCHAR(256),
    approver_username    VARCHAR(256),
    approved_at          TIMESTAMPTZ,

    publisher_id         VARCHAR(256),
    publisher_username   VARCHAR(256),
    published_at         TIMESTAMPTZ,
    resulting_policy_version INTEGER,

    scheduled_for        TIMESTAMPTZ,

    rejected_by          VARCHAR(256),
    rejected_at          TIMESTAMPTZ,
    rejection_reason     TEXT,

    withdrawn_by         VARCHAR(256),
    withdrawn_at         TIMESTAMPTZ,

    error                TEXT,

    version              INTEGER       NOT NULL DEFAULT 1,
    updated_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT pcr_request_type_check CHECK (
        request_type IN ('CREATE', 'UPDATE', 'ENABLE', 'DISABLE', 'ROLLBACK', 'ARCHIVE')
    ),
    CONSTRAINT pcr_status_check CHECK (
        status IN ('DRAFT', 'SUBMITTED', 'IN_REVIEW', 'REVIEWED', 'APPROVED',
                   'SCHEDULED', 'PUBLISHED', 'REJECTED', 'WITHDRAWN', 'EXPIRED')
    ),
    CONSTRAINT pcr_review_decision_check CHECK (
        review_decision IS NULL OR review_decision IN ('APPROVED', 'CHANGES_REQUESTED')
    )
);

CREATE INDEX IF NOT EXISTS idx_pcr_policy_id  ON policy_change_requests (policy_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pcr_status     ON policy_change_requests (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pcr_author     ON policy_change_requests (author_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pcr_tenant     ON policy_change_requests (tenant_id, status, created_at DESC)
    WHERE tenant_id IS NOT NULL;

COMMENT ON TABLE policy_change_requests IS
    'Maker-checker workflow object for the policy lifecycle. One '
    'row per proposed change (create/update/enable/disable/rollback/archive). '
    'Never delete rows — this record is itself governance evidence. Mutable '
    'in place, optimistic-locked via version.';

CREATE OR REPLACE FUNCTION _pcr_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    NEW.version     = OLD.version + 1;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS policy_change_requests_updated_at ON policy_change_requests;
CREATE TRIGGER policy_change_requests_updated_at
    BEFORE UPDATE ON policy_change_requests
    FOR EACH ROW EXECUTE FUNCTION _pcr_updated_at();

-- ── Policy Reviews (append-only) ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_reviews (
    id                 BIGSERIAL     PRIMARY KEY,
    change_request_id  UUID          NOT NULL REFERENCES policy_change_requests (id) ON DELETE RESTRICT,
    tenant_id          VARCHAR(128),

    reviewer_id        VARCHAR(256)  NOT NULL,
    reviewer_username  VARCHAR(256)  NOT NULL,
    decision           VARCHAR(24)   NOT NULL,
    notes              TEXT,

    reviewed_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    checksum           CHAR(64)      NOT NULL,

    CONSTRAINT pr_decision_check CHECK (decision IN ('APPROVED', 'CHANGES_REQUESTED'))
);

CREATE INDEX IF NOT EXISTS idx_pr_change_request ON policy_reviews (change_request_id, reviewed_at DESC);

COMMENT ON TABLE policy_reviews IS
    'Immutable append-only review-round trail. A change request '
    'may cycle through multiple review rounds before formal approval.';

-- ── Policy Approvals (append-only) ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_approvals (
    id                 BIGSERIAL     PRIMARY KEY,
    change_request_id  UUID          NOT NULL REFERENCES policy_change_requests (id) ON DELETE RESTRICT,
    tenant_id          VARCHAR(128),

    approver_id        VARCHAR(256)  NOT NULL,
    approver_username  VARCHAR(256)  NOT NULL,
    decision           VARCHAR(16)   NOT NULL,
    notes              TEXT,

    approved_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    checksum           CHAR(64)      NOT NULL,

    CONSTRAINT pa_decision_check CHECK (decision IN ('APPROVED', 'REJECTED'))
);

CREATE INDEX IF NOT EXISTS idx_pa_change_request ON policy_approvals (change_request_id, approved_at DESC);

COMMENT ON TABLE policy_approvals IS
    'Immutable append-only approval/rejection decision trail.';

-- ── Policy Rollbacks (append-only) ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_rollbacks (
    id                        BIGSERIAL     PRIMARY KEY,
    change_request_id         UUID          NOT NULL REFERENCES policy_change_requests (id) ON DELETE RESTRICT,
    tenant_id                 VARCHAR(128),

    policy_id                 VARCHAR(64)   NOT NULL,
    from_version               INTEGER       NOT NULL,
    to_version                 INTEGER       NOT NULL,

    -- Who activated the version being rolled back — looked up from
    -- policy_publications at request time. Enforces "rollback approver !=
    -- original activator" independently of whether
    -- that activator is also this rollback's author.
    original_publisher_id      VARCHAR(256)  NOT NULL,

    requested_by               VARCHAR(256)  NOT NULL,
    rollback_approver_id       VARCHAR(256),
    rollback_approver_username VARCHAR(256),

    reason                     TEXT          NOT NULL,
    evidence_ref                TEXT,

    requested_at                TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    approved_at                 TIMESTAMPTZ,
    checksum                    CHAR(64)      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_prb_policy_id       ON policy_rollbacks (policy_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_prb_change_request  ON policy_rollbacks (change_request_id);

COMMENT ON TABLE policy_rollbacks IS
    'Rollback-specific governance evidence: affected policy '
    'version, original activator, independent approval chain, reason.';

-- ── Policy Publications (append-only) ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_publications (
    id                        BIGSERIAL     PRIMARY KEY,
    change_request_id         UUID          NOT NULL REFERENCES policy_change_requests (id) ON DELETE RESTRICT,
    tenant_id                 VARCHAR(128),

    policy_id                 VARCHAR(64)   NOT NULL,
    published_by               VARCHAR(256)  NOT NULL,
    published_username         VARCHAR(256)  NOT NULL,
    resulting_policy_version   INTEGER       NOT NULL,
    policy_hash                 CHAR(64),
    emergency                   BOOLEAN       NOT NULL DEFAULT FALSE,

    published_at                TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    checksum                     CHAR(64)      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pp_policy_id       ON policy_publications (policy_id, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_pp_change_request  ON policy_publications (change_request_id);

COMMENT ON TABLE policy_publications IS
    'Immutable append-only record of every live-effect policy activation '
    ' — the moment a change request''s payload was actually applied '
    'to store.js/policies.json. Joinable to policy_provenance_versions by '
    '(policy_id, resulting_policy_version).';

-- ── Policy Emergency Activations ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_emergency_activations (
    id                          UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    change_request_id           UUID          REFERENCES policy_change_requests (id) ON DELETE RESTRICT,
    tenant_id                   VARCHAR(128),

    policy_id                   VARCHAR(64)   NOT NULL,
    activated_by                 VARCHAR(256)  NOT NULL,
    activated_username           VARCHAR(256)  NOT NULL,
    incident_reference           VARCHAR(256)  NOT NULL,
    justification                 TEXT          NOT NULL,

    activated_at                  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    expires_at                    TIMESTAMPTZ   NOT NULL,

    retrospective_status          VARCHAR(16)   NOT NULL DEFAULT 'PENDING',
    retrospective_approved_by     VARCHAR(256),
    retrospective_approved_username VARCHAR(256),
    retrospective_notes           TEXT,
    retrospective_decided_at      TIMESTAMPTZ,

    reverted_at                    TIMESTAMPTZ,

    checksum                        CHAR(64)      NOT NULL,

    CONSTRAINT pea_retro_status_check CHECK (
        retrospective_status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')
    )
);

CREATE INDEX IF NOT EXISTS idx_pea_policy_id ON policy_emergency_activations (policy_id, activated_at DESC);
CREATE INDEX IF NOT EXISTS idx_pea_pending   ON policy_emergency_activations (expires_at)
    WHERE retrospective_status = 'PENDING';

COMMENT ON TABLE policy_emergency_activations IS
    'Emergency/break-glass policy activation workflow: mandatory '
    'incident reference, justification, time-limited, mandatory '
    'retrospective approval, automatic expiry if not retrospectively '
    'approved in time.';

-- ── Approval Events (unified, hash-chained, immutable audit trail) ─────────

CREATE TABLE IF NOT EXISTS approval_events (
    id                    BIGSERIAL     PRIMARY KEY,
    event_id              UUID          NOT NULL DEFAULT gen_random_uuid(),

    change_request_id     UUID          REFERENCES policy_change_requests (id) ON DELETE RESTRICT,
    policy_id             VARCHAR(64),
    tenant_id             VARCHAR(128),

    event_type            VARCHAR(40)   NOT NULL,
    previous_status        VARCHAR(16),
    new_status              VARCHAR(16),

    actor_id                VARCHAR(256)  NOT NULL,
    actor_username           VARCHAR(256)  NOT NULL,
    actor_role                VARCHAR(32)   NOT NULL,
    source_ip                  VARCHAR(64),
    session_id                  VARCHAR(128),

    reason                       TEXT,
    detail                        JSONB         NOT NULL DEFAULT '{}',

    -- Hash chain: one chain per change_request_id, mirroring
    -- entryBuilder.js/provenance.js's existing previous_hash -> hash
    -- approach. previous_event_hash = NULL for the first event in a chain.
    previous_event_hash          CHAR(64),
    event_hash                    CHAR(64)      NOT NULL,

    occurred_at                    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ae_change_request ON approval_events (change_request_id, occurred_at ASC);
CREATE INDEX IF NOT EXISTS idx_ae_policy_id       ON approval_events (policy_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ae_tenant          ON approval_events (tenant_id, occurred_at DESC)
    WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_ae_event_id  ON approval_events (event_id);

COMMENT ON TABLE approval_events IS
    'Unified, hash-chained, immutable audit trail for the entire policy '
    'governance workflow: who/when/why/previous state/new state/ '
    'approval id/request id/tenant/IP/cryptographic digest. Never update or '
    'delete rows.';

-- ── Grants ───────────────────────────────────────────────────────────────────
-- policy_change_requests is mutable in place (workflow progress) so gets
-- UPDATE; the five evidence tables are append-only — SELECT+INSERT only,
-- no UPDATE/DELETE ever. Same shape as migration 028's dsr_requests vs
-- dsr_request_events/dsr_rectifications/dsr_exports.

GRANT SELECT, INSERT, UPDATE ON policy_change_requests      TO qodiqa_app;
GRANT SELECT                 ON policy_change_requests      TO qodiqa_read;

GRANT SELECT, INSERT ON policy_reviews                      TO qodiqa_app;
GRANT SELECT         ON policy_reviews                      TO qodiqa_read;

GRANT SELECT, INSERT ON policy_approvals                    TO qodiqa_app;
GRANT SELECT         ON policy_approvals                    TO qodiqa_read;

GRANT SELECT, INSERT ON policy_rollbacks                    TO qodiqa_app;
GRANT SELECT         ON policy_rollbacks                    TO qodiqa_read;

GRANT SELECT, INSERT ON policy_publications                 TO qodiqa_app;
GRANT SELECT         ON policy_publications                 TO qodiqa_read;

-- policy_emergency_activations is mutable in place (retrospective approval /
-- auto-revert bookkeeping updates the same row) — UPDATE granted, no DELETE.
GRANT SELECT, INSERT, UPDATE ON policy_emergency_activations TO qodiqa_app;
GRANT SELECT                 ON policy_emergency_activations TO qodiqa_read;

GRANT SELECT, INSERT ON approval_events                      TO qodiqa_app;
GRANT SELECT         ON approval_events                      TO qodiqa_read;

GRANT USAGE, SELECT ON SEQUENCE policy_reviews_id_seq       TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE policy_approvals_id_seq     TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE policy_rollbacks_id_seq     TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE policy_publications_id_seq  TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE approval_events_id_seq      TO qodiqa_app;

-- ── Row-level security ────────────────────────────────────────────────────────
-- Same tenant-aware model as consent_records/dsr_requests: tenant_id
-- nullable; NULL rows are platform-level and always visible; tenant-scoped
-- rows require a matching qodiqa_current_tenant() context.

ALTER TABLE policy_change_requests       ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_change_requests       FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_reviews               ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_reviews               FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_approvals             ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_approvals             FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_rollbacks             ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_rollbacks             FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_publications          ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_publications          FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_emergency_activations ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_emergency_activations FORCE ROW LEVEL SECURITY;
ALTER TABLE approval_events              ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_events              FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pcr_tenant_select ON policy_change_requests;
DROP POLICY IF EXISTS pcr_tenant_insert ON policy_change_requests;
DROP POLICY IF EXISTS pcr_tenant_update ON policy_change_requests;

CREATE POLICY pcr_tenant_select ON policy_change_requests
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY pcr_tenant_insert ON policy_change_requests
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY pcr_tenant_update ON policy_change_requests
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

DROP POLICY IF EXISTS pr_tenant_select ON policy_reviews;
DROP POLICY IF EXISTS pr_system_insert ON policy_reviews;

CREATE POLICY pr_tenant_select ON policy_reviews
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY pr_system_insert ON policy_reviews
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

DROP POLICY IF EXISTS pa_tenant_select ON policy_approvals;
DROP POLICY IF EXISTS pa_system_insert ON policy_approvals;

CREATE POLICY pa_tenant_select ON policy_approvals
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY pa_system_insert ON policy_approvals
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

DROP POLICY IF EXISTS prb_tenant_select ON policy_rollbacks;
DROP POLICY IF EXISTS prb_system_insert ON policy_rollbacks;

CREATE POLICY prb_tenant_select ON policy_rollbacks
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY prb_system_insert ON policy_rollbacks
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

DROP POLICY IF EXISTS pp_tenant_select ON policy_publications;
DROP POLICY IF EXISTS pp_system_insert ON policy_publications;

CREATE POLICY pp_tenant_select ON policy_publications
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY pp_system_insert ON policy_publications
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

DROP POLICY IF EXISTS pea_tenant_select ON policy_emergency_activations;
DROP POLICY IF EXISTS pea_tenant_insert ON policy_emergency_activations;
DROP POLICY IF EXISTS pea_tenant_update ON policy_emergency_activations;

CREATE POLICY pea_tenant_select ON policy_emergency_activations
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY pea_tenant_insert ON policy_emergency_activations
  FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY pea_tenant_update ON policy_emergency_activations
  FOR UPDATE TO qodiqa_app
  USING     (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
  WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

DROP POLICY IF EXISTS ae_tenant_select ON approval_events;
DROP POLICY IF EXISTS ae_system_insert ON approval_events;

CREATE POLICY ae_tenant_select ON approval_events
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant());

CREATE POLICY ae_system_insert ON approval_events
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (29, 'policy_governance', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
