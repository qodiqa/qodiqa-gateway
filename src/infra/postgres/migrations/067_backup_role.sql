-- QODIQA PostgreSQL Migration 067
-- step 5: a dedicated, READ-ONLY backup role for both backup paths —
-- scripts/pg-backup.sh (pg_dump) and scripts/dr/postgres.js (the JSON DR dump).
--
-- Why: both ran as qodiqa_app. Under the per-tenant RLS policies the JSON dump
-- silently kept only NULL-tenant rows (independent audit 2026-09-28, A3-02:
-- audit_chain 936/2,800, evidence 301/900, 5 tables unreadable) and the
-- manifest recorded the truncated counts, so dr:verify passed; pg_dump failed
-- every full backup ("permission denied ... LOCK TABLE", A3-03).
--
--   qodiqa_backup   LOGIN, BYPASSRLS (every row of every RLS table), and READ
--                   access only: member of pg_read_all_data where the
--                   migrating identity may grant it, and explicit SELECT on
--                   every table and sequence in public either way, with
--                   default privileges for tables and sequences created later.
--                   No INSERT/UPDATE/DELETE, SUPERUSER, CREATEDB or CREATEROLE.
--
-- pg_read_all_data: granting a predefined role needs ADMIN OPTION on it (or
-- superuser); the local bootstrap identity (qodiqa_test) does not hold it, so
-- the grant is attempted and, if refused, left to a one-time superuser action
-- (docs/operations/database-role-management.md, "backup role"). The
-- explicit grants below give the same read coverage for every existing table,
-- and the dump itself fails closed on any table it cannot fully read, so an
-- incomplete grant can never again produce a silently incomplete backup.
--
-- IDENTITY: creates a role (CREATEROLE) with BYPASSRLS, so the migrating
-- identity must hold BYPASSRLS itself (qodiqa_test locally, the bootstrap/
-- superuser identity elsewhere), like 002 / 038 / 060 / 065.
--
-- PASSWORD: the placeholder follows 002/038/060/065 — every deployment rotates
-- it (ALTER ROLE ... PASSWORD) and supplies it to the backup jobs only
-- (secret key postgres-backup-password / PGPASSWORD in backup.env).

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_backup') THEN
        CREATE ROLE qodiqa_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS PASSWORD 'REPLACE_WITH_VAULT_SECRET_BACKUP';
    END IF;
END
$$;

DO $$
BEGIN
    GRANT pg_read_all_data TO qodiqa_backup;
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE '% may not grant pg_read_all_data; explicit SELECT grants apply instead (superuser: GRANT pg_read_all_data TO qodiqa_backup).', current_user;
END
$$;

DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO qodiqa_backup', current_database()); END $$;
GRANT USAGE ON SCHEMA public TO qodiqa_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO qodiqa_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO qodiqa_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO qodiqa_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO qodiqa_backup;
-- Later migrations normally run as qodiqa_mig (tables owned by it since 055): cover what IT creates as well.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_mig')
       AND current_user <> 'qodiqa_mig' AND pg_has_role(current_user, 'qodiqa_mig', 'MEMBER') THEN
        ALTER DEFAULT PRIVILEGES FOR ROLE qodiqa_mig IN SCHEMA public GRANT SELECT ON TABLES TO qodiqa_backup;
        ALTER DEFAULT PRIVILEGES FOR ROLE qodiqa_mig IN SCHEMA public GRANT SELECT ON SEQUENCES TO qodiqa_backup;
    END IF;
END
$$;

COMMENT ON ROLE qodiqa_backup IS
  'read-only backup role for pg-backup.sh and the DR JSON dump. BYPASSRLS, SELECT only.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (67, 'w10_backup_role', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
