-- QODIQA PostgreSQL Schema — Migration 101
-- Finding: (tool registry: approved tools, per-tool policy, argument schema, versions)
-- Purpose: the allowlist of tools an agent action may name. A tool is (tenant, server, name) with VERSIONS: each version carries the argument JSON Schema (and its
--          schema_hash = SHA-256("QODIQA::TOOL_SCHEMA::V1" || JCS-P1(schema))), the action class, whether it is reversible, and the per-tool policy. A tool seen for
--          the first time, or seen with a different schema / class / reversibility, becomes a new version in `pending_review` and is NOT callable until an operator
--          approves it; a call whose actionHash names another schema_hash than the active version is refused (TOOL_SCHEMA_CHANGED).
--
-- Additive: one new table. Tenant-scoped: row-level security FORCED on qodiqa_current_tenant(). Never deleted by the application (superseded / disabled rows stay).
-- Idempotent: IF NOT EXISTS / DROP POLICY IF EXISTS. The ledger number is 101.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

CREATE TABLE IF NOT EXISTS tool_registry (
  id                BIGSERIAL     PRIMARY KEY,
  tenant_id         VARCHAR(128)  NOT NULL,
  server_id         VARCHAR(128)  NOT NULL,
  tool_name         VARCHAR(128)  NOT NULL,
  version           INTEGER       NOT NULL CHECK (version >= 1),
  status            TEXT          NOT NULL CHECK (status IN ('active', 'pending_review', 'superseded', 'disabled')),
  schema            JSONB         NOT NULL,
  schema_hash       CHAR(64)      NOT NULL CHECK (schema_hash ~ '^[0-9a-f]{64}$'),
  action_class      TEXT          NOT NULL CHECK (action_class IN ('read', 'write', 'file', 'database', 'external_api', 'command', 'communication', 'financial', 'delegate')),
  reversible        BOOLEAN       NOT NULL,
  requires_approval BOOLEAN       NOT NULL DEFAULT false,
  policy            JSONB         NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(policy) = 'object'),
  description       TEXT,
  created_by        VARCHAR(256)  NOT NULL,
  created_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
  approved_by       VARCHAR(256),
  approved_at       TIMESTAMPTZ,
  CONSTRAINT tool_registry_unique_version UNIQUE (tenant_id, server_id, tool_name, version),
  CONSTRAINT tool_registry_schema_is_object CHECK (jsonb_typeof(schema) = 'object')
);

-- at most ONE active version per tool
CREATE UNIQUE INDEX IF NOT EXISTS tool_registry_one_active ON tool_registry (tenant_id, server_id, tool_name) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_tool_registry_status ON tool_registry (tenant_id, status);

COMMENT ON TABLE tool_registry IS 'approved tools with versioned argument schemas (schema_hash), action class, reversibility and per-tool policy. RLS forced by tenant. Never deleted by the application.';

ALTER TABLE tool_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_registry FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tool_registry_select ON tool_registry;
DROP POLICY IF EXISTS tool_registry_insert ON tool_registry;
DROP POLICY IF EXISTS tool_registry_update ON tool_registry;
CREATE POLICY tool_registry_select ON tool_registry FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY tool_registry_insert ON tool_registry FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY tool_registry_update ON tool_registry FOR UPDATE USING (tenant_id = qodiqa_current_tenant()) WITH CHECK (tenant_id = qodiqa_current_tenant());

-- A version's schema, class and reversibility are fixed at creation (a change is a NEW version); only status, policy and approval metadata move.
GRANT SELECT, INSERT ON tool_registry TO qodiqa_app;
GRANT UPDATE (status, requires_approval, policy, description, updated_at, approved_by, approved_at) ON tool_registry TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE tool_registry_id_seq TO qodiqa_app;
GRANT SELECT ON tool_registry TO qodiqa_read;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_owner') THEN
    ALTER TABLE tool_registry OWNER TO qodiqa_owner;
    ALTER SEQUENCE tool_registry_id_seq OWNER TO qodiqa_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_backup') THEN
    GRANT SELECT ON tool_registry TO qodiqa_backup;
    GRANT SELECT ON SEQUENCE tool_registry_id_seq TO qodiqa_backup;
  END IF;
END
$$;

COMMIT;
