-- QODIQA PostgreSQL Migration 080
-- the GDPR erasure path uses an EXPLICIT allowlist of target tables, never catalog discovery.
--
-- WHY: migration 063's qodiqa_erasure_targets() returned every public table with an actor_id / subject_id column
-- (minus five exclusions), and qodiqa_erase_subject (SECURITY DEFINER) runs a dynamic UPDATE on each. Anyone able to
-- create a table in schema public (qodiqa_mig: CREATE on public since migration 002) could therefore make the definer
-- UPDATE a table of their choosing, firing that table's triggers with the definer owner's identity — the superuser on
-- compose deployments before migration 079.
--
-- WHAT: qodiqa_erasure_targets() keeps its signature and result shape, and now returns exactly the seven approved
-- (table, identifier column) pairs that 063/069 resolved to on every shipped schema:
--   consent_audit_log.actor_id   dsr_exports.actor_id   dsr_rectifications.actor_id   platform_audit_events.actor_id
--   qodiqa_alerts.actor_id       request_trails.actor_id   revocation_events.subject_id
-- It FAILS CLOSED (SQLSTATE 55000, nothing erased) when:
--   * an approved target is missing or incompatible: not an ordinary, non-partition public table; identifier column
--     missing or not text / varchar; no tenant_id column; or
--   * a public table carries an actor_id / subject_id column that is neither approved nor a declared exclusion — 063's
--     guarantee that a new subject-identifier column is never silently skipped is kept, but such a table is now
--     REFUSED (erasure stops until a migration declares its treatment) instead of being erased automatically.
-- Declared exclusions are 063's, unchanged: consent_records (erased by the application), dsr_requests (pseudonymized
-- by finalize), subject_pseudonym_keys (destroyed by finalize), approval_events and policy_provenance_versions (operator
-- identifiers, never data subjects).
--
-- Unchanged: the erasure functions themselves (tenant scoping, batching, finalize's completeness gate, the ledger), and
-- this function's EXECUTE grants (CREATE OR REPLACE keeps the ACL). search_path gains pg_temp last.
-- Migrations 063 and 069 are not edited.

BEGIN;

CREATE OR REPLACE FUNCTION qodiqa_erasure_targets()
RETURNS TABLE (table_name text, column_name text, has_tenant boolean)
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  approved_tables  CONSTANT text[] := ARRAY['consent_audit_log', 'dsr_exports', 'dsr_rectifications', 'platform_audit_events',
                                            'qodiqa_alerts', 'request_trails', 'revocation_events'];
  approved_columns CONSTANT text[] := ARRAY['actor_id', 'actor_id', 'actor_id', 'actor_id',
                                            'actor_id', 'actor_id', 'subject_id'];
  excluded         CONSTANT text[] := ARRAY['consent_records', 'dsr_requests', 'subject_pseudonym_keys',
                                            'approval_events', 'policy_provenance_versions'];
  i          integer;
  undeclared text;
BEGIN
  FOR i IN 1 .. array_length(approved_tables, 1) LOOP
    IF NOT EXISTS (
         SELECT 1
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_attribute a ON a.attrelid = c.oid
          WHERE n.nspname = 'public' AND c.relname = approved_tables[i]
            AND c.relkind IN ('r', 'p') AND NOT c.relispartition
            AND a.attname = approved_columns[i] AND a.attnum > 0 AND NOT a.attisdropped
            AND a.atttypid IN ('text'::regtype, 'character varying'::regtype))
       OR NOT EXISTS (
         SELECT 1
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_attribute a ON a.attrelid = c.oid
          WHERE n.nspname = 'public' AND c.relname = approved_tables[i]
            AND a.attname = 'tenant_id' AND a.attnum > 0 AND NOT a.attisdropped) THEN
      RAISE EXCEPTION 'erasure target %.% is missing or incompatible (needs an ordinary public table with a text/varchar % column and a tenant_id column) — erasure refused',
        approved_tables[i], approved_columns[i], approved_columns[i] USING ERRCODE = '55000';
    END IF;
  END LOOP;

  SELECT string_agg(c.relname || '.' || a.attname, ', ' ORDER BY c.relname, a.attname) INTO undeclared
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid
   WHERE n.nspname = 'public'
     AND c.relkind IN ('r', 'p') AND NOT c.relispartition
     AND a.attnum > 0 AND NOT a.attisdropped
     AND a.attname IN ('actor_id', 'subject_id')
     AND NOT (c.relname = ANY (approved_tables))
     AND NOT (c.relname = ANY (excluded));
  IF undeclared IS NOT NULL THEN
    RAISE EXCEPTION 'erasure refused: undeclared subject-identifier column(s) % — a migration must declare each as an approved erasure target or an exclusion; nothing was erased',
      undeclared USING ERRCODE = '55000';
  END IF;

  RETURN QUERY
    SELECT t.tbl, t.col, true
      FROM unnest(approved_tables, approved_columns) AS t(tbl, col)
     ORDER BY 1, 2;
END
$$;

COMMENT ON FUNCTION qodiqa_erasure_targets() IS
  '(migration 080): the seven approved erasure targets (explicit allowlist, never catalog discovery). Fails closed (55000) on a missing/incompatible target or an undeclared actor_id/subject_id column.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (80, 'er16_erasure_target_allowlist', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
