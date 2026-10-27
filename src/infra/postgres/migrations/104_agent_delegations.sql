-- QODIQA PostgreSQL Schema — Migration 104
-- Finding:.1-F6D.4 (delegation of authority between agents: signed tokens, chains, cascade revocation, traceability)
-- Purpose: agent_delegations holds every delegation token issued (the signed envelope is stored whole, so a chain can be re-verified offline) with its mutable
--          STATE - active / revoked, the usage counter against max_actions. A token's content is fixed at insert (the application role may only change state);
--          revocation cascades to every descendant in one statement. delegation_uses records, for each authorised action request, the delegation chain it ran
--          under (chain_hash, depth, root agent): the trace that links an ACTION_INTENT / ACTION_COMMIT to the chain of agents that produced it.
--
-- Additive: two new tables. Tenant-scoped: row-level security FORCED on qodiqa_current_tenant(). Never deleted by the application.
-- Idempotent: IF NOT EXISTS / DROP POLICY IF EXISTS. The ledger number is 104.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

CREATE TABLE IF NOT EXISTS agent_delegations (
  id               BIGSERIAL     PRIMARY KEY,
  tenant_id        VARCHAR(128)  NOT NULL,
  delegation_id    UUID          NOT NULL,
  parent_id        UUID,
  root_agent_id    VARCHAR(36)   NOT NULL,
  issuer_agent_id  VARCHAR(36)   NOT NULL,
  subject_agent_id VARCHAR(36)   NOT NULL,
  depth            INTEGER       NOT NULL CHECK (depth BETWEEN 1 AND 8),
  max_depth        INTEGER       NOT NULL CHECK (max_depth BETWEEN 1 AND 8),
  classes          TEXT[]        NOT NULL CHECK (cardinality(classes) >= 1),
  tools            JSONB,
  max_actions      INTEGER       CHECK (max_actions IS NULL OR max_actions BETWEEN 1 AND 100000),
  actions_used     INTEGER       NOT NULL DEFAULT 0 CHECK (actions_used >= 0),
  status           TEXT          NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  token            JSONB         NOT NULL,
  token_digest     CHAR(64)      NOT NULL CHECK (token_digest ~ '^[0-9a-f]{64}$'),
  issued_at        TIMESTAMPTZ   NOT NULL,
  expires_at       TIMESTAMPTZ   NOT NULL,
  created_by       VARCHAR(256)  NOT NULL,
  created_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
  revoked_at       TIMESTAMPTZ,
  revoked_reason   VARCHAR(256),
  revoked_by       VARCHAR(256),
  CONSTRAINT agent_delegations_unique UNIQUE (tenant_id, delegation_id),
  CONSTRAINT agent_delegations_parent_fk FOREIGN KEY (tenant_id, parent_id) REFERENCES agent_delegations (tenant_id, delegation_id),
  CONSTRAINT agent_delegations_issuer_fk FOREIGN KEY (tenant_id, issuer_agent_id) REFERENCES agent_identities (tenant_id, agent_id),
  CONSTRAINT agent_delegations_subject_fk FOREIGN KEY (tenant_id, subject_agent_id) REFERENCES agent_identities (tenant_id, agent_id),
  CONSTRAINT agent_delegations_depth_bound CHECK (depth <= max_depth),
  CONSTRAINT agent_delegations_not_self CHECK (issuer_agent_id <> subject_agent_id),
  CONSTRAINT agent_delegations_budget CHECK (max_actions IS NULL OR actions_used <= max_actions),
  CONSTRAINT agent_delegations_root_shape CHECK ((parent_id IS NULL) = (depth = 1)),
  CONSTRAINT agent_delegations_revoked_consistent CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  CONSTRAINT agent_delegations_token_object CHECK (jsonb_typeof(token) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_agent_delegations_subject ON agent_delegations (tenant_id, subject_agent_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_delegations_issuer ON agent_delegations (tenant_id, issuer_agent_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_delegations_parent ON agent_delegations (tenant_id, parent_id);

CREATE TABLE IF NOT EXISTS delegation_uses (
  tenant_id     VARCHAR(128)  NOT NULL,
  request_id    UUID          NOT NULL,
  delegation_id UUID          NOT NULL,
  chain_hash    CHAR(64)      NOT NULL CHECK (chain_hash ~ '^[0-9a-f]{64}$'),
  depth         INTEGER       NOT NULL CHECK (depth BETWEEN 1 AND 8),
  root_agent_id VARCHAR(36)   NOT NULL,
  agent_id      VARCHAR(36)   NOT NULL,
  session_id    UUID          NOT NULL,
  used_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
  CONSTRAINT delegation_uses_pk PRIMARY KEY (tenant_id, request_id),
  CONSTRAINT delegation_uses_delegation_fk FOREIGN KEY (tenant_id, delegation_id) REFERENCES agent_delegations (tenant_id, delegation_id)
);

COMMENT ON TABLE agent_delegations IS 'signed delegation tokens (whole envelope) with their state. Content fixed at insert; revocation cascades. RLS forced by tenant. Never deleted by the application.';
COMMENT ON TABLE delegation_uses IS 'the delegation chain each authorised action request ran under. Insert-only. RLS forced by tenant.';

ALTER TABLE agent_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_delegations FORCE ROW LEVEL SECURITY;
ALTER TABLE delegation_uses ENABLE ROW LEVEL SECURITY;
ALTER TABLE delegation_uses FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_delegations_select ON agent_delegations;
DROP POLICY IF EXISTS agent_delegations_insert ON agent_delegations;
DROP POLICY IF EXISTS agent_delegations_update ON agent_delegations;
DROP POLICY IF EXISTS delegation_uses_select ON delegation_uses;
DROP POLICY IF EXISTS delegation_uses_insert ON delegation_uses;
CREATE POLICY agent_delegations_select ON agent_delegations FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY agent_delegations_insert ON agent_delegations FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY agent_delegations_update ON agent_delegations FOR UPDATE USING (tenant_id = qodiqa_current_tenant()) WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY delegation_uses_select ON delegation_uses FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY delegation_uses_insert ON delegation_uses FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());

-- The token and everything it states are fixed at insert; only the state moves.
GRANT SELECT, INSERT ON agent_delegations TO qodiqa_app;
GRANT UPDATE (status, actions_used, revoked_at, revoked_reason, revoked_by) ON agent_delegations TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE agent_delegations_id_seq TO qodiqa_app;
GRANT SELECT, INSERT ON delegation_uses TO qodiqa_app;
GRANT SELECT ON agent_delegations TO qodiqa_read;
GRANT SELECT ON delegation_uses TO qodiqa_read;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_owner') THEN
    ALTER TABLE agent_delegations OWNER TO qodiqa_owner;
    ALTER TABLE delegation_uses OWNER TO qodiqa_owner;
    ALTER SEQUENCE agent_delegations_id_seq OWNER TO qodiqa_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_backup') THEN
    GRANT SELECT ON agent_delegations TO qodiqa_backup;
    GRANT SELECT ON delegation_uses TO qodiqa_backup;
    GRANT SELECT ON SEQUENCE agent_delegations_id_seq TO qodiqa_backup;
  END IF;
END
$$;

COMMIT;
