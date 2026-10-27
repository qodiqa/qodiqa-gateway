-- QODIQA PostgreSQL Schema — Migration 102
-- Finding: (the execution ledger of authorised agent actions)
-- Purpose: an action artifact is consumed EXACTLY ONCE and in ORDER. One row per consumed artifact:
--            PRIMARY KEY (tenant_id, session_id, seq)   a sequence number executes once (replay of the same seq, or a second artifact for it, is refused)
--            UNIQUE      (tenant_id, request_id)        an artifact (its requestId) executes once, in any session
--          Order (seq n runs only after seq n-1 has been consumed) is enforced by the executor inside the same transaction as the insert. The row is the
--          durable half of the INTENT / COMMIT pair: `intent` while the action runs, then `completed` / `failed` (or `unknown` when the process died, set by
--          the reconciler) - the audit chain entries ACTION_INTENT / ACTION_COMMIT (schema v8) are written from it.
--
-- Additive: one new table. Tenant-scoped: row-level security FORCED on qodiqa_current_tenant(). Never deleted by the application.
-- Idempotent: IF NOT EXISTS / DROP POLICY IF EXISTS. The ledger number is 102.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

CREATE TABLE IF NOT EXISTS action_executions (
  tenant_id    VARCHAR(128)  NOT NULL,
  session_id   UUID          NOT NULL,
  seq          BIGINT        NOT NULL CHECK (seq >= 1),
  request_id   UUID          NOT NULL,
  agent_id     VARCHAR(36)   NOT NULL,
  action_hash  CHAR(64)      NOT NULL CHECK (action_hash ~ '^[0-9a-f]{64}$'),
  server_id    VARCHAR(128)  NOT NULL,
  tool_name    VARCHAR(128)  NOT NULL,
  approval_ref VARCHAR(128),
  status       TEXT          NOT NULL DEFAULT 'intent' CHECK (status IN ('intent', 'completed', 'failed', 'unknown')),
  output_hash  CHAR(64)      CHECK (output_hash IS NULL OR output_hash ~ '^[0-9a-f]{64}$'),
  started_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
  finished_at  TIMESTAMPTZ,
  CONSTRAINT action_executions_pk PRIMARY KEY (tenant_id, session_id, seq),
  CONSTRAINT action_executions_request_unique UNIQUE (tenant_id, request_id),
  CONSTRAINT action_executions_finished_consistent CHECK ((status = 'intent') = (finished_at IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_action_executions_open ON action_executions (tenant_id, started_at) WHERE status = 'intent';

COMMENT ON TABLE action_executions IS 'one row per consumed action artifact (exactly once, in order). RLS forced by tenant. Never deleted by the application.';

ALTER TABLE action_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_executions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS action_executions_select ON action_executions;
DROP POLICY IF EXISTS action_executions_insert ON action_executions;
DROP POLICY IF EXISTS action_executions_update ON action_executions;
CREATE POLICY action_executions_select ON action_executions FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY action_executions_insert ON action_executions FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY action_executions_update ON action_executions FOR UPDATE USING (tenant_id = qodiqa_current_tenant()) WITH CHECK (tenant_id = qodiqa_current_tenant());

-- Only the outcome moves; what was consumed (session, seq, requestId, hash, tool) is fixed at insert.
GRANT SELECT, INSERT ON action_executions TO qodiqa_app;
GRANT UPDATE (status, output_hash, finished_at) ON action_executions TO qodiqa_app;
GRANT SELECT ON action_executions TO qodiqa_read;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_owner') THEN
    ALTER TABLE action_executions OWNER TO qodiqa_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_backup') THEN
    GRANT SELECT ON action_executions TO qodiqa_backup;
  END IF;
END
$$;

COMMIT;
