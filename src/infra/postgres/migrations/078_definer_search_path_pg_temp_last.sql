-- QODIQA PostgreSQL Migration 078
-- SECURITY DEFINER functions must resolve pg_temp LAST.
--
-- Every SECURITY DEFINER function pins `search_path = pg_catalog, public`. PostgreSQL searches the session's temporary
-- schema FIRST for relations whenever pg_temp is not listed explicitly, so any caller with the TEMP privilege (PUBLIC
-- holds it on the database by default) could create a temporary table named like a real one and the definer function
-- (owner's privileges, RLS-bypassing) would read or write the temporary table instead. Reproduced on a disposable
-- database as qodiqa_app, rolled back: the transparency read functions returned a forged row from a temporary
-- `transparency_log_entries`, and the audit_chain mirror-count trigger updated a temporary `audit_chain_mirror_count`
-- (desynchronising the integrity counter) —
--
-- This is the PostgreSQL documentation's own rule for SECURITY DEFINER functions ("Writing SECURITY DEFINER Functions
-- Safely": put pg_temp last). After this migration every SECURITY DEFINER function in schema public has exactly
-- `search_path = pg_catalog, public, pg_temp`. Function bodies, owners and grants are unchanged.
--
-- Additive only (ALTER FUNCTION ... SET; no applied migration is edited). LIVE `qodiqa` is held at 057 by design decision;
-- this migration is applied only where the chain is applied until 058+ is approved.

BEGIN;

DO $$
DECLARE
  f regprocedure;
BEGIN
  FOR f IN
    SELECT p.oid::regprocedure
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.prosecdef
  LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
  END LOOP;
END
$$;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (78, 'definer_search_path_pg_temp_last', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
