-- QODIQA PostgreSQL Schema — Migration 100
-- Finding: (agent identities and sessions)
-- Purpose: an AGENT is a named, tenant-owned, revocable identity that acts on behalf of a user; a SESSION is one bounded run of
--          an agent: it expires (TTL), has an action budget and a maximum number of actions, a cost budget, a per-session action sequence (next_seq,
--          last_action_hash - the chain builds on) and can be ended or force-stopped. Both tables are tenant-scoped: row-level security is
--          FORCED and keyed on qodiqa_current_tenant() (no tenant context = no rows).
--
-- Additive: two new tables. Never deleted by the application (revoked / ended rows stay as evidence). Idempotent: IF NOT EXISTS / DROP POLICY IF EXISTS.
-- The ledger number is 100 (reserved 086 was not used: 096-099 were applied first and the order is the number).

BEGIN;

SET LOCAL search_path = public, pg_catalog;

CREATE TABLE IF NOT EXISTS agent_identities (
  id                       BIGSERIAL     PRIMARY KEY,
  tenant_id                VARCHAR(128)  NOT NULL,
  agent_id                 VARCHAR(36)   NOT NULL,                        -- gateway-issued UUID v4
  display_name             TEXT          NOT NULL,
  status                   TEXT          NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
  owner_user_id            VARCHAR(128),                                  -- the user the agent acts for (privilege separation); NULL = acts for the tenant itself
  public_key               TEXT,                                          -- the agent's own Ed25519 public key (SPKI DER, base64), when it signs
  allowed_action_classes   TEXT[]        NOT NULL DEFAULT '{}',           -- the classes of action it may be authorised for; empty = none
  max_actions_per_session  INTEGER       CHECK (max_actions_per_session IS NULL OR max_actions_per_session >= 0),
  max_session_seconds      INTEGER       CHECK (max_session_seconds IS NULL OR max_session_seconds >= 1),
  cost_budget_micros       BIGINT        CHECK (cost_budget_micros IS NULL OR cost_budget_micros >= 0),
  created_by               VARCHAR(256)  NOT NULL,
  created_at               TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at               TIMESTAMPTZ   NOT NULL DEFAULT now(),
  revoked_at               TIMESTAMPTZ,
  CONSTRAINT agent_identities_unique UNIQUE (tenant_id, agent_id),
  CONSTRAINT agent_identities_id_shape CHECK (agent_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),   -- gateway-issued UUID v4 (V2-FREEZE 5.1)
  CONSTRAINT agent_identities_revoked_consistent CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS agent_sessions (
  id                  BIGSERIAL     PRIMARY KEY,
  tenant_id           VARCHAR(128)  NOT NULL,
  session_id          UUID          NOT NULL,
  agent_id            VARCHAR(36)   NOT NULL,
  status              TEXT          NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'ended', 'expired', 'killed')),
  started_at          TIMESTAMPTZ   NOT NULL DEFAULT now(),
  expires_at          TIMESTAMPTZ   NOT NULL,
  ended_at            TIMESTAMPTZ,
  ended_reason        TEXT,
  max_actions         INTEGER       NOT NULL CHECK (max_actions >= 0),
  actions_used        INTEGER       NOT NULL DEFAULT 0 CHECK (actions_used >= 0),
  cost_budget_micros  BIGINT        CHECK (cost_budget_micros IS NULL OR cost_budget_micros >= 0),
  cost_used_micros    BIGINT        NOT NULL DEFAULT 0 CHECK (cost_used_micros >= 0),
  next_seq            BIGINT        NOT NULL DEFAULT 1 CHECK (next_seq >= 1),
  last_action_hash    CHAR(64),
  created_by          VARCHAR(256)  NOT NULL,
  updated_at          TIMESTAMPTZ   NOT NULL DEFAULT now(),
  CONSTRAINT agent_sessions_unique UNIQUE (tenant_id, session_id),
  CONSTRAINT agent_sessions_agent_fk FOREIGN KEY (tenant_id, agent_id) REFERENCES agent_identities (tenant_id, agent_id),
  CONSTRAINT agent_sessions_budget CHECK (actions_used <= max_actions),
  CONSTRAINT agent_sessions_cost CHECK (cost_budget_micros IS NULL OR cost_used_micros <= cost_budget_micros),
  CONSTRAINT agent_sessions_ended_consistent CHECK ((status = 'active') = (ended_at IS NULL)),
  CONSTRAINT agent_sessions_hash_shape CHECK (last_action_hash IS NULL OR last_action_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_agent ON agent_sessions (tenant_id, agent_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_expiry ON agent_sessions (expires_at) WHERE status = 'active';

COMMENT ON TABLE agent_identities IS 'tenant-owned, revocable agent identities (who acts, on behalf of whom, with which limits). RLS forced by tenant. Never deleted by the application.';
COMMENT ON TABLE agent_sessions IS 'one bounded run of an agent (TTL, action budget, max actions, cost budget, per-session action sequence). RLS forced by tenant. Never deleted by the application.';

ALTER TABLE agent_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_identities FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_sessions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agent_identities_select ON agent_identities;
DROP POLICY IF EXISTS agent_identities_insert ON agent_identities;
DROP POLICY IF EXISTS agent_identities_update ON agent_identities;
CREATE POLICY agent_identities_select ON agent_identities FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY agent_identities_insert ON agent_identities FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY agent_identities_update ON agent_identities FOR UPDATE USING (tenant_id = qodiqa_current_tenant()) WITH CHECK (tenant_id = qodiqa_current_tenant());

DROP POLICY IF EXISTS agent_sessions_select ON agent_sessions;
DROP POLICY IF EXISTS agent_sessions_insert ON agent_sessions;
DROP POLICY IF EXISTS agent_sessions_update ON agent_sessions;
CREATE POLICY agent_sessions_select ON agent_sessions FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY agent_sessions_insert ON agent_sessions FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY agent_sessions_update ON agent_sessions FOR UPDATE USING (tenant_id = qodiqa_current_tenant()) WITH CHECK (tenant_id = qodiqa_current_tenant());

-- Column-scoped writes: identity and ownership columns are fixed at creation.
GRANT SELECT, INSERT ON agent_identities TO qodiqa_app;
GRANT UPDATE (display_name, status, owner_user_id, public_key, allowed_action_classes, max_actions_per_session, max_session_seconds, cost_budget_micros, updated_at, revoked_at)
  ON agent_identities TO qodiqa_app;
GRANT SELECT, INSERT ON agent_sessions TO qodiqa_app;
GRANT UPDATE (status, ended_at, ended_reason, actions_used, cost_used_micros, next_seq, last_action_hash, updated_at) ON agent_sessions TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE agent_identities_id_seq, agent_sessions_id_seq TO qodiqa_app;
GRANT SELECT ON agent_identities, agent_sessions TO qodiqa_read;

-- (migration 081): objects created after the schema-owner role belong to it; the backup role reads every table.
-- Both tables are listed in post_081_tables of scripts/dr/schema-ownership.sql.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_owner') THEN
    ALTER TABLE agent_identities OWNER TO qodiqa_owner;
    ALTER TABLE agent_sessions OWNER TO qodiqa_owner;
    ALTER SEQUENCE agent_identities_id_seq OWNER TO qodiqa_owner;
    ALTER SEQUENCE agent_sessions_id_seq OWNER TO qodiqa_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_backup') THEN
    GRANT SELECT ON agent_identities, agent_sessions TO qodiqa_backup;
    GRANT SELECT ON SEQUENCE agent_identities_id_seq, agent_sessions_id_seq TO qodiqa_backup;
  END IF;
END
$$;

COMMIT;
