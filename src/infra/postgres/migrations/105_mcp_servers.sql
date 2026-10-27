-- QODIQA PostgreSQL Schema — Migration 105
-- Finding: (registry of MCP servers: the only destinations the tool gateway will ever call)
-- Purpose: an MCP server is registered per tenant with its URL (validated at registration AND at every call by the SSRF guard), its pinned IDENTITY (the SHA-256 of
--          the server certificate's public key; a plain-HTTP or unpinned server exists only where the operator explicitly allows local destinations) and a
--          config_hash over exactly those facts, recomputed and compared on every call. `server_id` is the `server` of the tool registry (migration 101): a tool
--          can only be called through a server that is registered here and active.
--
-- Additive: one new table. Tenant-scoped: row-level security FORCED on qodiqa_current_tenant(). Never deleted by the application.
-- Idempotent: IF NOT EXISTS / DROP POLICY IF EXISTS. The ledger number is 105.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

CREATE TABLE IF NOT EXISTS mcp_servers (
  id                 BIGSERIAL     PRIMARY KEY,
  tenant_id          VARCHAR(128)  NOT NULL,
  server_id          VARCHAR(128)  NOT NULL,
  url                TEXT          NOT NULL CHECK (char_length(url) BETWEEN 8 AND 2048),
  transport          TEXT          NOT NULL DEFAULT 'streamable-http' CHECK (transport IN ('streamable-http')),
  identity           JSONB         NOT NULL,
  config_hash        CHAR(64)      NOT NULL CHECK (config_hash ~ '^[0-9a-f]{64}$'),
  status             TEXT          NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  local_destination  BOOLEAN       NOT NULL DEFAULT false,
  description        VARCHAR(500),
  created_by         VARCHAR(256)  NOT NULL,
  created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
  disabled_at        TIMESTAMPTZ,
  disabled_reason    VARCHAR(256),
  disabled_by        VARCHAR(256),
  last_refresh_at    TIMESTAMPTZ,
  last_refresh_tools INTEGER,
  last_error         VARCHAR(500),
  CONSTRAINT mcp_servers_unique UNIQUE (tenant_id, server_id),
  CONSTRAINT mcp_servers_id_shape CHECK (server_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  CONSTRAINT mcp_servers_identity_object CHECK (jsonb_typeof(identity) = 'object'),
  CONSTRAINT mcp_servers_disabled_consistent CHECK ((status = 'disabled') = (disabled_at IS NOT NULL))
);

COMMENT ON TABLE mcp_servers IS 'MCP servers a tenant''s tool gateway may call (URL, pinned identity, config hash). RLS forced by tenant. Never deleted by the application.';

ALTER TABLE mcp_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_servers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mcp_servers_select ON mcp_servers;
DROP POLICY IF EXISTS mcp_servers_insert ON mcp_servers;
DROP POLICY IF EXISTS mcp_servers_update ON mcp_servers;
CREATE POLICY mcp_servers_select ON mcp_servers FOR SELECT USING (tenant_id = qodiqa_current_tenant());
CREATE POLICY mcp_servers_insert ON mcp_servers FOR INSERT WITH CHECK (tenant_id = qodiqa_current_tenant());
CREATE POLICY mcp_servers_update ON mcp_servers FOR UPDATE USING (tenant_id = qodiqa_current_tenant()) WITH CHECK (tenant_id = qodiqa_current_tenant());

-- The URL and the destination class are fixed at registration (a different URL is a different server); the pinned identity can be rotated together with its hash.
GRANT SELECT, INSERT ON mcp_servers TO qodiqa_app;
GRANT UPDATE (identity, config_hash, status, description, updated_at, disabled_at, disabled_reason, disabled_by, last_refresh_at, last_refresh_tools, last_error) ON mcp_servers TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE mcp_servers_id_seq TO qodiqa_app;
GRANT SELECT ON mcp_servers TO qodiqa_read;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_owner') THEN
    ALTER TABLE mcp_servers OWNER TO qodiqa_owner;
    ALTER SEQUENCE mcp_servers_id_seq OWNER TO qodiqa_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_backup') THEN
    GRANT SELECT ON mcp_servers TO qodiqa_backup;
    GRANT SELECT ON SEQUENCE mcp_servers_id_seq TO qodiqa_backup;
  END IF;
END
$$;

COMMIT;
