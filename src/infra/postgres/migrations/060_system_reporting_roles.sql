-- QODIQA PostgreSQL Migration 060
-- two dedicated LOGIN roles for the only
-- sanctioned cross-tenant readers.
--
--   qodiqa_system     platform-integrity and background work: the global audit
--                     chain tail / append checks, the chain verifier, the
--                     transparency root scheduler and gap scanner, boot
--                     hydration of tenant configs, the emergency sweep and the
--                     GDPR erase function.
--   qodiqa_reporting  operator consoles (RBAC-gated admin routes): audit store,
--                     alerts, compliance reports, evidence-chain search,
--                     transparency admin views, audit viewer.
--
-- Neither role has BYPASSRLS, SUPERUSER, CREATEDB or CREATEROLE, and neither
-- receives any table privilege: every cross-tenant read happens only through
-- an explicitly granted SECURITY DEFINER function (migration 061). qodiqa_app —
-- the request-serving role — loses EXECUTE on all of them (061).
--
-- IDENTITY: like 002 / 038 / 055, this migration creates roles, so it needs an
-- identity with CREATEROLE (qodiqa_test locally, the bootstrap/superuser
-- identity elsewhere); qodiqa_mig cannot run it. See
-- docs/operations/database-role-management.md ("roles").
--
-- PASSWORDS: the placeholders below are the same pattern as 002/038 — every
-- deployment rotates them (ALTER ROLE ... PASSWORD) before use and provides
-- them to the process as QODIQA_PG_SYSTEM_PASSWORD / QODIQA_PG_REPORTING_PASSWORD.
-- Production boot refuses a missing value (bootValidator rule pg.role_pools).

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_system') THEN
        CREATE ROLE qodiqa_system LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD 'REPLACE_WITH_VAULT_SECRET_SYSTEM';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_reporting') THEN
        CREATE ROLE qodiqa_reporting LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD 'REPLACE_WITH_VAULT_SECRET_REPORTING';
    END IF;
END
$$;

DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO qodiqa_system, qodiqa_reporting', current_database()); END $$;
GRANT USAGE ON SCHEMA public TO qodiqa_system, qodiqa_reporting;

COMMENT ON ROLE qodiqa_system IS
  'platform-integrity / background cross-tenant reads, via granted SECURITY DEFINER functions only. No table grants, NOBYPASSRLS.';
COMMENT ON ROLE qodiqa_reporting IS
  'operator-console cross-tenant reads (RBAC-gated admin routes), via granted SECURITY DEFINER functions only. No table grants, NOBYPASSRLS.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (60, 'w5_system_reporting_roles', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
