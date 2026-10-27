-- ROLLBACK of migrations 079 + 080. PREFER FORWARD RECOVERY — read this first.
--
-- Rolling back RE-OPENS the 47 SECURITY DEFINER functions return to the identity running this file (the
-- bootstrap superuser on a compose deployment, i.e. superuser execution again) and qodiqa_erasure_targets() returns to
-- migration 063's catalog discovery (a planted actor_id table would be erased by the definer again). Use it only when
-- 079/080 break a deployment and no forward fix is available, and re-apply them (node src/infra/postgres/migrate.js)
-- as soon as the cause is fixed — that forward recovery is tested by test/integration/definerOwnership.integration.test.js DO-13.
--
-- Run as the identity that ran the migration chain (it must own, or be a member of the owner of, every function):
--   psql -X -v ON_ERROR_STOP=1 -d <database> -f deploy/sql/rollback-definer-ownership.sql
-- It changes no data. It does NOT drop the cluster-wide role qodiqa_definer (dropping a role is a separate,
-- approved destructive step); it removes every privilege the role holds in THIS database instead, so it can do
-- nothing here. It deletes the two qodiqa_migrations rows (79, 80) so the runner re-applies them on forward recovery.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

-- 1. definer ownership back to the running identity
DO $$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.prosecdef AND p.proowner = 'qodiqa_definer'::regrole
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO %I', f, current_user);
  END LOOP;
END
$$;

-- 2. migration 063's catalog-discovery erasure targets (verbatim body and settings)
CREATE OR REPLACE FUNCTION qodiqa_erasure_targets()
RETURNS TABLE (table_name text, column_name text, has_tenant boolean)
LANGUAGE sql STABLE
SET search_path = pg_catalog, public
AS $$
  -- pg_catalog, not information_schema: the latter lists only columns the
  -- CALLER holds privileges on, and qodiqa_system/qodiqa_reporting hold none.
  -- Partitions are skipped (an UPDATE on the parent covers them).
  SELECT c.relname::text, a.attname::text,
         EXISTS (SELECT 1 FROM pg_attribute ta
                  WHERE ta.attrelid = c.oid AND ta.attname = 'tenant_id' AND ta.attnum > 0 AND NOT ta.attisdropped)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid
   WHERE n.nspname = 'public'
     AND c.relkind IN ('r', 'p')
     AND NOT c.relispartition
     AND a.attnum > 0 AND NOT a.attisdropped
     AND a.attname IN ('actor_id', 'subject_id')
     AND c.relname NOT IN ('consent_records', 'dsr_requests', 'subject_pseudonym_keys',
                           'approval_events', 'policy_provenance_versions')
   ORDER BY 1, 2
$$;
COMMENT ON FUNCTION qodiqa_erasure_targets() IS NULL;

-- 3. qodiqa_definer holds nothing in this database
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM qodiqa_definer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM qodiqa_definer;
REVOKE ALL ON FUNCTION qodiqa_erasure_targets() FROM qodiqa_definer;
REVOKE ALL ON SCHEMA public FROM qodiqa_definer;

-- 4. let the runner re-apply 079/080 (forward recovery)
DELETE FROM qodiqa_migrations WHERE version IN (79, 80, 82); -- 82 narrows a grant 079 made; it must re-run after 079 on forward recovery

COMMIT;
