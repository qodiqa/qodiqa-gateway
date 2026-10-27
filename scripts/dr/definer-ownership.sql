-- re-establish and verify SECURITY DEFINER ownership on a RESTORED database.
--
-- pg_restore --no-owner (scripts/pg-backup.sh restore) makes the restoring role the owner of every restored object,
-- including the 47 SECURITY DEFINER functions, which would then run as that role (a superuser when the restore runs
-- with QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE=true). scripts/pg-backup.sh runs this file right after pg_restore, as the
-- same role, and treats any error as an INCOMPLETE restore. It transfers the explicit list below (the same list as
-- migration 079 and src/infra/postgres/definerOwnership.js, pinned equal by test/integration/definerOwnership.integration.test.js)
-- to qodiqa_definer and checks the same postconditions as migration 079. It never creates or alters a role: the
-- target cluster must already hold qodiqa_definer (migration 079, or the role bootstrap in
-- docs/operations/database-role-management.md).
--
-- Usage: psql -X -v ON_ERROR_STOP=1 -d <restored database> -f scripts/dr/definer-ownership.sql

BEGIN;

SET LOCAL search_path = public, pg_catalog;

DO $$
DECLARE
  approved CONSTANT text[] := ARRAY[
    'qodiqa_audit_chain_decisions(text[])',
    'qodiqa_audit_chain_detect_sequence_gaps(bigint,integer)',
    'qodiqa_audit_chain_fetch_batch(bigint,integer)',
    'qodiqa_audit_chain_fetch_by_artifact_id(character varying)',
    'qodiqa_audit_chain_fetch_replay_lineage(character varying)',
    'qodiqa_audit_chain_fetch_row_by_seq(bigint)',
    'qodiqa_audit_chain_full_read()',
    'qodiqa_audit_chain_hash_exists(character)',
    'qodiqa_audit_chain_max_seq()',
    'qodiqa_audit_chain_mirror_count()',
    'qodiqa_audit_chain_mirror_count_check()',
    'qodiqa_audit_chain_mirror_count_on_delete()',
    'qodiqa_audit_chain_mirror_count_on_insert()',
    'qodiqa_audit_chain_mirror_count_on_truncate()',
    'qodiqa_audit_chain_mirror_count_rebuild()',
    'qodiqa_audit_chain_true_tail()',
    'qodiqa_audit_legal_holds_full_read()',
    'qodiqa_audit_retention_policies_full_read()',
    'qodiqa_compliance_reports_full_read()',
    'qodiqa_consent_audit_log_full_read()',
    'qodiqa_erase_subject(text,text,text,integer)',
    'qodiqa_erase_subject_finalize(uuid,text,text,text,text,uuid,jsonb,text,text,text)',
    'qodiqa_erasure_ledger_list(bigint,integer)',
    'qodiqa_erasure_subject_candidates()',
    'qodiqa_evidence_chain_records_full_read()',
    'qodiqa_evidence_public_lookup(character varying,text)',
    'qodiqa_platform_audit_events_full_read()',
    'qodiqa_policy_change_request_by_id(uuid)',
    'qodiqa_policy_emergency_activations_full_read()',
    'qodiqa_qodiqa_alert_history_full_read()',
    'qodiqa_qodiqa_alerts_full_read()',
    'qodiqa_request_trails_by_ids(uuid,text)',
    'qodiqa_tenant_policy_sets_full_read()',
    'qodiqa_tenant_semantic_configs_full_read()',
    'qodiqa_transparency_log_fetch_batch(bigint,integer)',
    'qodiqa_transparency_log_fetch_boundary(bigint)',
    'qodiqa_transparency_log_fetch_by_artifact_id(character varying)',
    'qodiqa_transparency_log_fetch_by_entry_hash(character)',
    'qodiqa_transparency_log_fetch_by_transparency_id(uuid)',
    'qodiqa_transparency_log_fetch_hashes_in_range(bigint,bigint)',
    'qodiqa_transparency_log_fetch_range_full(bigint,bigint)',
    'qodiqa_transparency_log_latest_entry()',
    'qodiqa_transparency_log_read_all()',
    'qodiqa_transparency_public_entry(uuid)',
    'qodiqa_transparency_public_entry_by_hash(character)',
    'qodiqa_transparency_public_hashes_from_id(bigint,integer)',
    'qodiqa_transparency_public_list(text,text,text,timestamp with time zone,timestamp with time zone,integer,integer,boolean)'
  ];
  r        record;
  s        text;
  bad      text;
  is_super boolean := (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user);
BEGIN
  SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin, rolreplication, rolbypassrls
    INTO r FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_definer';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'restore: role qodiqa_definer does not exist on this cluster — create it as migration 079 does before restoring'
      USING ERRCODE = '42704';
  END IF;
  IF r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolcanlogin OR r.rolreplication OR NOT r.rolbypassrls THEN
    RAISE EXCEPTION 'restore: role qodiqa_definer has attributes outside NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS'
      USING ERRCODE = '42501';
  END IF;
  IF NOT is_super AND NOT pg_catalog.pg_has_role(current_user, 'qodiqa_definer', 'SET') THEN
    RAISE EXCEPTION 'restore: % cannot SET ROLE qodiqa_definer, so it cannot hand the restored definer functions to it — restore as the bootstrap/migration identity that ran migration 079',
      current_user USING ERRCODE = '42501';
  END IF;

  SELECT string_agg(p.oid::regprocedure::text, ', ' ORDER BY p.oid::regprocedure::text) INTO bad
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public' AND p.prosecdef AND NOT (p.oid::regprocedure::text = ANY (approved));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'restore: unexpected SECURITY DEFINER function(s) in the restored database: %', bad USING ERRCODE = '55000';
  END IF;
  FOREACH s IN ARRAY approved LOOP
    IF to_regprocedure(s) IS NULL OR NOT (SELECT prosecdef FROM pg_catalog.pg_proc WHERE oid = to_regprocedure(s)) THEN
      RAISE EXCEPTION 'restore: SECURITY DEFINER function % is missing from the restored database', s USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF NOT is_super THEN EXECUTE 'GRANT CREATE ON SCHEMA public TO qodiqa_definer'; END IF;
  FOREACH s IN ARRAY approved LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO qodiqa_definer', to_regprocedure(s));
  END LOOP;
  IF NOT is_super THEN EXECUTE 'REVOKE CREATE ON SCHEMA public FROM qodiqa_definer'; END IF;

  SELECT string_agg(p.oid::regprocedure::text || ' owner=' || o.rolname, ', ') INTO bad
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace JOIN pg_catalog.pg_roles o ON o.oid = p.proowner
   WHERE n.nspname = 'public' AND p.prosecdef
     AND (o.rolname <> 'qodiqa_definer' OR o.rolsuper
          OR NOT ('search_path=pg_catalog, public, pg_temp' = ANY (COALESCE(p.proconfig, '{}')))
          OR p.proacl IS NULL
          OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 0));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'restore postcondition failed: %', bad;
  END IF;
  SELECT string_agg(u.rolname, ', ') INTO bad
    FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid = m.roleid JOIN pg_catalog.pg_roles u ON u.oid = m.member
   WHERE g.rolname = 'qodiqa_definer'
     AND u.rolname IN ('qodiqa_app', 'qodiqa_read', 'qodiqa_mig', 'qodiqa_retention', 'qodiqa_system',
                       'qodiqa_reporting', 'qodiqa_control', 'qodiqa_backup');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'restore postcondition failed: runtime/migration role(s) % can assume qodiqa_definer', bad USING ERRCODE = '42501';
  END IF;
  IF has_schema_privilege('qodiqa_definer', 'public', 'CREATE') THEN
    RAISE EXCEPTION 'restore postcondition failed: qodiqa_definer holds CREATE on schema public' USING ERRCODE = '42501';
  END IF;
  RAISE NOTICE 'restore: 47 SECURITY DEFINER functions owned by qodiqa_definer (non-superuser, NOLOGIN)';
END
$$;

COMMIT;
