-- QODIQA PostgreSQL Schema — Migration 103
-- Finding: (separation of the execution plan: a plan is authorised ONCE, every action is then authorised individually against it)
-- Purpose: a plan is the declared set of tool steps an agent session intends to use: [{ server, name, maxCalls }], fixed at creation (plan_hash = SHA-256 of
--          the canonical steps). While a session has an active plan, /v1/actions/authorize refuses any action that is not a step of that plan, or whose
--          step is used up (ACTION_NOT_IN_PLAN / ACTION_PLAN_STEP_EXHAUSTED). The counters move only through the statement that checks the bound.
--
-- Additive: one new table. Tenant-scoped: row-level security FORCED on qodiqa_current_tenant(). Never deleted by the application.
-- Idempotent: IF NOT EXISTS / DROP POLICY IF EXISTS. The ledger number is 103.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

CREATE TABLE IF NOT EXISTS action_plans (
  id           BIGSERIAL     PRIMARY KEY,
  tenant_id    VARCHAR(128)  NOT NULL,
  plan_id      UUID          NOT NULL,
  session_id   UUID          NOT NULL,
  agent_id     VARCHAR(36)   NOT NULL,
  steps        JSONB         NOT NULL,
  used         JSONB         NOT NULL,
  plan_hash    CHAR(64)      NOT NULL CHECK (plan_hash ~ '^[0-9a-f]{64}$'),
  status       TEXT          NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'closed')),
  created_by   VARCHAR(256)  NOT NULL,
  created_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ   NOT NULL,
  closed_at    TIMESTAMPTZ,
  CONSTRAINT action_plans_unique UNIQUE (tenant_id, plan_id),
  CONSTRAINT action_plans_session_fk FOREIGN KEY (tenant_id, session_id) REFERENCES agent_sessions (tenant_id, session_id),
  CONSTRAINT action_plans_steps_shape CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) BETWEEN 1 AND 50),
  CONSTRAINT action_plans_used_shape CHECK (jsonb_typeof(used) = 'array' AND jsonb_array_length(used) = jsonb_array_length(steps)),
  CONSTRAINT action_plans_closed_consistent CHECK ((status = 'closed') = (closed_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_action_plans_session ON action_plans (tenant_id, session_id, status);

COMMENT ON TABLE action_plans IS 'the execution plan of an agent session, authorised once; individual actions are authorised against its steps. RLS forced by tenant. Never deleted by the application.';

ALTER TABLE action_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_plans FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS action_plans_select ON action_plans;
DROP POLICY IF EXISTS action_plans_insert ON action_plans;
DROP POLICY IF EXISTS action_plans_update ON action_plans;
CREATE POLICY action_plans_select ON action_plans FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY action_plans_insert ON action_plans FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY action_plans_update ON action_plans FOR UPDATE USING (tenant_id = qodiqa_current_tenant()) WITH CHECK (tenant_id = qodiqa_current_tenant());

-- The steps, the session and the hash are fixed at creation; only the counters and the close move.
GRANT SELECT, INSERT ON action_plans TO qodiqa_app;
GRANT UPDATE (used, status, closed_at) ON action_plans TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE action_plans_id_seq TO qodiqa_app;
GRANT SELECT ON action_plans TO qodiqa_read;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_owner') THEN
    ALTER TABLE action_plans OWNER TO qodiqa_owner;
    ALTER SEQUENCE action_plans_id_seq OWNER TO qodiqa_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_backup') THEN
    GRANT SELECT ON action_plans TO qodiqa_backup;
    GRANT SELECT ON SEQUENCE action_plans_id_seq TO qodiqa_backup;
  END IF;
END
$$;

COMMIT;
