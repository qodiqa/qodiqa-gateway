-- D-P: ONE-TIME, owner-reviewed provisioning of the backup role's predefined-role grant.
--
-- Migration 067 attempts GRANT pg_read_all_data TO qodiqa_backup and continues with a NOTICE when the migrating
-- identity may not grant it (a non-superuser bootstrap such as qodiqa_test). Since D-P every backup path refuses to
-- run unless the dumping role is RLS-exempt AND a pg_read_all_data member (BACKUP_ROLE_READ_ALL_DATA_MISSING), so a
-- cluster migrated by a non-superuser needs this file run ONCE, by a superuser, before its first backup:
--
--   psql -X -v ON_ERROR_STOP=1 -U <superuser> -d postgres -f scripts/db/provision-backup-role.superuser.sql
--
-- Roles are cluster-wide: this affects every database on the cluster. It grants nothing else, contains no credential,
-- and is idempotent. Never run it against a cluster you are not authorized to change (the LIVE cluster needs an
-- explicit approval). pg_read_all_data is READ-ONLY (SELECT on all tables/views/sequences, USAGE on schemas).

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_backup') THEN
    RAISE EXCEPTION 'qodiqa_backup does not exist on this cluster: run the migration chain (067) first';
  END IF;
  IF NOT (SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_backup') THEN
    RAISE EXCEPTION 'qodiqa_backup is not BYPASSRLS — fix the role (migration 067) before granting pg_read_all_data';
  END IF;
END
$$;

GRANT pg_read_all_data TO qodiqa_backup;

SELECT rolname,
       rolbypassrls                                         AS bypass_rls,
       pg_has_role('qodiqa_backup', 'pg_read_all_data', 'MEMBER') AS read_all_data,
       rolsuper, rolcreaterole, rolcreatedb
  FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_backup';
