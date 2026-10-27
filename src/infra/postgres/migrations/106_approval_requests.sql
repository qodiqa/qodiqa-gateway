-- QODIQA PostgreSQL Schema — Migration 106
-- Finding: (human approval bound to ONE action)
-- Purpose: an action whose tool requires approval does not get an artifact; it gets an approval request. The request fixes the action it is about (session, seq, actionHash,
--          tool, arguments - all FIXED at insert) and moves through PENDING -> APPROVED | DENIED | EXPIRED | CANCELLED. The decision is a statement SIGNED by the gateway after the
--          approver's MFA step-up (decision_token, domain QODIQA::APPROVAL::V1), naming the approver, the actionHash, the window [not_before, approval_expires_at]. The approver is never
--          the requester. An approval is used at most once (used_at): the artifact that carries it is issued once.
--
-- Additive: one new table. Tenant-scoped: row-level security FORCED on qodiqa_current_tenant(). Never deleted by the application.
-- Idempotent: IF NOT EXISTS / DROP POLICY IF EXISTS. The ledger number is 106.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

CREATE TABLE IF NOT EXISTS approval_requests (
  id                   BIGSERIAL     PRIMARY KEY,
  tenant_id            VARCHAR(128)  NOT NULL,
  approval_id          UUID          NOT NULL,
  session_id           UUID          NOT NULL,
  agent_id             VARCHAR(36)   NOT NULL,
  seq                  BIGINT        NOT NULL CHECK (seq >= 1),
  action_hash          CHAR(64)      NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  prev_action_hash     CHAR(64)      CHECK (prev_action_hash IS NULL OR prev_action_hash ~ '^[0-9a-f]{64}$'),
  server_id            VARCHAR(128)  NOT NULL,
  tool_name            VARCHAR(128)  NOT NULL,
  schema_hash          CHAR(64)      NOT NULL CHECK (schema_hash ~ '^[0-9a-f]{64}$'),
  action_class         TEXT          NOT NULL,
  args                 JSONB         NOT NULL CHECK (jsonb_typeof(args) = 'object'),
  parent_request_hash  CHAR(64)      CHECK (parent_request_hash IS NULL OR parent_request_hash ~ '^[0-9a-f]{64}$'),
  plan_id              UUID,
  delegation_id        UUID,
  requester_id         VARCHAR(256)  NOT NULL,
  requester_user_id    VARCHAR(256),
  policy_rule_id       VARCHAR(128)  NOT NULL,
  status               TEXT          NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED')),
  requested_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
  expires_at           TIMESTAMPTZ   NOT NULL,
  approver_id          VARCHAR(256),
  decided_at           TIMESTAMPTZ,
  decision_reason      VARCHAR(500),
  not_before           TIMESTAMPTZ,
  approval_expires_at  TIMESTAMPTZ,
  decision_token       JSONB,
  mfa                  TEXT,
  used_at              TIMESTAMPTZ,
  used_request_id      UUID,
  cancelled_by         VARCHAR(256),
  cancelled_at         TIMESTAMPTZ,
  expired_at           TIMESTAMPTZ,
  CONSTRAINT approval_requests_unique UNIQUE (tenant_id, approval_id),
  CONSTRAINT approval_requests_session_fk FOREIGN KEY (tenant_id, session_id) REFERENCES agent_sessions (tenant_id, session_id),
  CONSTRAINT approval_requests_independent CHECK (approver_id IS NULL OR (approver_id <> requester_id AND (requester_user_id IS NULL OR approver_id <> requester_user_id))),
  CONSTRAINT approval_requests_decided_consistent CHECK ((status IN ('APPROVED', 'DENIED')) = (decided_at IS NOT NULL AND approver_id IS NOT NULL AND decision_token IS NOT NULL) OR status IN ('EXPIRED', 'CANCELLED')),
  CONSTRAINT approval_requests_window CHECK (status <> 'APPROVED' OR (not_before IS NOT NULL AND approval_expires_at IS NOT NULL AND approval_expires_at > not_before)),
  CONSTRAINT approval_requests_used_only_approved CHECK (used_at IS NULL OR approver_id IS NOT NULL)
);

-- A position in a session's chain is held by at most ONE live request: a request that ends unapproved gives its position back (the next action takes it), so
-- only PENDING / APPROVED requests are unique per position.
CREATE UNIQUE INDEX IF NOT EXISTS approval_requests_position_live ON approval_requests (tenant_id, session_id, seq) WHERE status IN ('PENDING', 'APPROVED');
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests (tenant_id, status, requested_at);

COMMENT ON TABLE approval_requests IS 'human approval bound to one action (actionHash). The action facts are fixed at insert; only the decision moves. RLS forced by tenant. Never deleted by the application.';

ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS approval_requests_select ON approval_requests;
DROP POLICY IF EXISTS approval_requests_insert ON approval_requests;
DROP POLICY IF EXISTS approval_requests_update ON approval_requests;
CREATE POLICY approval_requests_select ON approval_requests FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY approval_requests_insert ON approval_requests FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY approval_requests_update ON approval_requests FOR UPDATE USING (tenant_id = qodiqa_current_tenant()) WITH CHECK (tenant_id = qodiqa_current_tenant());

GRANT SELECT, INSERT ON approval_requests TO qodiqa_app;
GRANT UPDATE (status, approver_id, decided_at, decision_reason, not_before, approval_expires_at, decision_token, mfa, used_at, used_request_id, cancelled_by, cancelled_at, expired_at) ON approval_requests TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE approval_requests_id_seq TO qodiqa_app;
GRANT SELECT ON approval_requests TO qodiqa_read;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_owner') THEN
    ALTER TABLE approval_requests OWNER TO qodiqa_owner;
    ALTER SEQUENCE approval_requests_id_seq OWNER TO qodiqa_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_backup') THEN
    GRANT SELECT ON approval_requests TO qodiqa_backup;
    GRANT SELECT ON SEQUENCE approval_requests_id_seq TO qodiqa_backup;
  END IF;
END
$$;

COMMIT;
