-- closure: ROLLBACK of migration 081 (schema owner qodiqa_owner). PREFER FORWARD RECOVERY.
--
-- Returns every table, non-definer function and the enum type to the identity running this file (the bootstrap
-- superuser on a compose deployment — re-opening the superuser-only restore), gives qodiqa_mig back
-- ownership of the 12 migration-001 tables (audit_chain included — re-opening its control over the audit guards),
-- restores migration 067's backup-SELECT default privileges for the running identity and for qodiqa_mig, and deletes
-- qodiqa_migrations row 81 so the runner re-applies 081 on forward recovery. Run it BEFORE docs/operations/er16-
-- rollback.sql when rolling back 079/080 too. It changes no data and never drops the cluster-wide role qodiqa_owner
-- (an approved destructive step); it removes that role's privileges in THIS database instead.
-- Tested: test/integration/definerOwnership.integration.test.js DO-13 (rollback, then forward recovery, catalog identical).
--
--   psql -X -v ON_ERROR_STOP=1 -d <database> -f deploy/sql/rollback-schema-owner.sql

BEGIN;

SET LOCAL search_path = public, pg_catalog;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relowner = 'qodiqa_owner'::regrole
  LOOP
    IF r.relname IN ('qodiqa_migrations', 'rbac_users', 'signing_keys', 'signing_key_legacy_map', 'policies', 'policy_versions',
                     'policy_history', 'audit_chain', 'investigations', 'investigation_artifacts', 'investigation_audit_events',
                     'evidence_packages') THEN
      EXECUTE format('ALTER TABLE public.%I OWNER TO qodiqa_mig', r.relname);   -- migration 055's owner
    ELSE
      EXECUTE format('ALTER TABLE public.%I OWNER TO %I', r.relname, current_user);
    END IF;
  END LOOP;
  FOR r IN SELECT p.oid::regprocedure AS f FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND NOT p.prosecdef AND p.proowner = 'qodiqa_owner'::regrole
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO %I', r.f, current_user);
  END LOOP;
  FOR r IN SELECT t.typname FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
            WHERE n.nspname = 'public' AND t.typtype = 'e' AND t.typowner = 'qodiqa_owner'::regrole
  LOOP
    EXECUTE format('ALTER TYPE public.%I OWNER TO %I', r.typname, current_user);
  END LOOP;
END
$$;

ALTER DEFAULT PRIVILEGES FOR ROLE qodiqa_owner IN SCHEMA public REVOKE SELECT ON TABLES FROM qodiqa_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE qodiqa_owner IN SCHEMA public REVOKE SELECT ON SEQUENCES FROM qodiqa_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO qodiqa_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO qodiqa_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE qodiqa_mig IN SCHEMA public GRANT SELECT ON TABLES TO qodiqa_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE qodiqa_mig IN SCHEMA public GRANT SELECT ON SEQUENCES TO qodiqa_backup;
REVOKE ALL ON SCHEMA public FROM qodiqa_owner;

DELETE FROM qodiqa_migrations WHERE version = 81;

COMMIT;
