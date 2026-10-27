-- QODIQA PostgreSQL Migration 065
-- a dedicated LOGIN role for the
-- control plane — the store of signing identities, operator (RBAC) users and
-- custom roles, tenants, organizations, tenant-portal users, the policy state
-- and the signing-key status timeline, which move from per-process JSON files
-- to PostgreSQL (migration 066).
--
--   qodiqa_control   reads and writes control_plane_records ONLY (066 grants).
--                    No BYPASSRLS, SUPERUSER, CREATEDB or CREATEROLE, and no
--                    privilege on any tenant-data table. qodiqa_app — the
--                    request-serving role — gets NO privilege on the control
--                    plane, so an app-role compromise can neither read the
--                    stored key hashes nor write an RBAC grant or un-revoke.
--
-- IDENTITY: like 002 / 038 / 060, this migration creates a role, so it needs
-- an identity with CREATEROLE (qodiqa_test locally, the bootstrap/superuser
-- identity elsewhere); qodiqa_mig cannot run it. See
-- docs/operations/database-role-management.md ("control role").
--
-- PASSWORD: the placeholder below follows 002/038/060 — every deployment
-- rotates it (ALTER ROLE ... PASSWORD) and provides it to the process as
-- QODIQA_PG_CONTROL_PASSWORD. Production boot refuses a missing or placeholder
-- value (bootValidator rule control_plane).

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_control') THEN
        CREATE ROLE qodiqa_control LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD 'REPLACE_WITH_VAULT_SECRET_CONTROL';
    END IF;
END
$$;

DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO qodiqa_control', current_database()); END $$;
GRANT USAGE ON SCHEMA public TO qodiqa_control;

COMMENT ON ROLE qodiqa_control IS
  'control-plane store (control_plane_records only). NOBYPASSRLS, no tenant-data privileges.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (65, 'w6_control_role', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
