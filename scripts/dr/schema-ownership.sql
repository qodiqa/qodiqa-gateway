-- closure: re-establish and verify SCHEMA ownership (migration 081) on a RESTORED database.
--
-- pg_restore --no-owner makes the restoring role the owner of every restored object. On a schema at migration 081 or
-- later, scripts/pg-backup.sh restore and scripts/dr/pgDump.js run this file right after pg_restore (then
-- scripts/dr/definer-ownership.sql), as the same role, and treat any error as an INCOMPLETE restore. It hands the
-- explicit lists below (the same lists as migration 081, pinned equal by test/integration/definerOwnership.integration.test.js)
-- back to qodiqa_owner and verifies the 081 postconditions, including that qodiqa_backup can read every table and that
-- the only default privileges are qodiqa_owner's. It never creates or alters a role: the target cluster must hold
-- qodiqa_owner (migration 081 has run on it), and the restoring role must be a superuser or able to SET ROLE qodiqa_owner.
--
-- Usage: psql -X -v ON_ERROR_STOP=1 -d <restored database> -f scripts/dr/schema-ownership.sql

BEGIN;

SET LOCAL search_path = public, pg_catalog;

DO $$
DECLARE
  approved_tables CONSTANT text[] := ARRAY[
    'approval_events', 'attestations', 'audit_chain', 'audit_chain_checkpoints', 'audit_chain_head',
    'audit_chain_mirror_count', 'audit_chain_prunes', 'audit_chain_verification_progress', 'audit_chain_verifier_state',
    'audit_checksum_anchor', 'audit_legal_holds', 'audit_retention_policies', 'audit_retention_runs',
    'audit_signed_checkpoints', 'certificate_artifacts', 'certifications', 'compliance_control_assessments',
    'compliance_controls', 'compliance_evidence_refs', 'compliance_frameworks', 'compliance_report_exports',
    'compliance_report_signatures', 'compliance_reports', 'consent_audit_log', 'consent_records', 'consent_scopes',
    'control_plane_records', 'dsr_erasure_ledger', 'dsr_exports', 'dsr_rectifications', 'dsr_request_events',
    'dsr_requests', 'evidence_chain_head', 'evidence_chain_records', 'evidence_chain_verifications', 'evidence_packages',
    'gap_scanner_state', 'investigation_artifacts', 'investigation_audit_events', 'investigations',
    'kms_encrypted_data_keys', 'kms_provider_events', 'kms_wrapping_key_rotations', 'organizations',
    'persistence_recovery_queue', 'platform_audit_events', 'policies', 'policy_approvals', 'policy_change_requests',
    'policy_emergency_activations', 'policy_history', 'policy_provenance_integrity_runs', 'policy_provenance_versions',
    'policy_publications', 'policy_reviews', 'policy_rollbacks', 'policy_versions', 'portal_verifications',
    'qodiqa_alert_history', 'qodiqa_alert_stats', 'qodiqa_alerts', 'qodiqa_anomaly_baselines',
    'qodiqa_escalation_records', 'qodiqa_incidents', 'qodiqa_migrations', 'qodiqa_notification_deliveries',
    'qodiqa_suppression_rules', 'rbac_users', 'request_trails', 'revocation_events', 'signing_key_legacy_map',
    'signing_keys', 'subject_pseudonym_keys', 'tenant_policy_sets', 'tenant_semantic_configs', 'tenants',
    'transparency_log_entries', 'transparency_log_head', 'transparency_merkle_checkpoints', 'transparency_roots',
    'transparency_roots_head', 'transparency_verifications', 'webhook_delivery_log', 'webhook_endpoints'
  ];
  -- Tables created by migrations AFTER 081 (each one is created/owned by qodiqa_owner by its own migration). 081's list above is frozen and pinned equal to
  -- the migration; this list grows with the migrations that add tables and is verified here the same way.
  post_081_tables CONSTANT text[] := ARRAY['external_anchors', 'agent_identities', 'agent_sessions', 'tool_registry', 'action_executions', 'action_plans', 'agent_delegations', 'delegation_uses', 'mcp_servers', 'approval_requests'];
  approved_functions CONSTANT text[] := ARRAY[
    '_consent_records_updated_at()', '_dsr_requests_updated_at()', '_pcr_updated_at()',
    'qodiqa_audit_append_only_guard()', 'qodiqa_audit_chain_mirror_count_guard()',
    'qodiqa_audit_chain_prunes_append_only_guard()', 'qodiqa_audit_checksum_anchor_monotonic_guard()',
    'qodiqa_audit_maintenance_log()', 'qodiqa_audit_signed_checkpoints_append_only_guard()',
    'qodiqa_control_plane_guard()', 'qodiqa_current_tenant()', 'qodiqa_dsr_erasure_ledger_append_only_guard()',
    'qodiqa_erasure_targets()', 'qodiqa_platform_audit_events_append_only_guard()', 'qodiqa_set_updated_at()'
  ];
  approved_types CONSTANT text[] := ARRAY['audit_category'];
  r        record;
  s        text;
  bad      text;
  is_super boolean := (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user);
BEGIN
  SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin, rolreplication, rolbypassrls
    INTO r FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_owner';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'restore: role qodiqa_owner does not exist on this cluster — run migration 081 on this cluster first' USING ERRCODE = '42704';
  END IF;
  IF r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolcanlogin OR r.rolreplication OR r.rolbypassrls THEN
    RAISE EXCEPTION 'restore: role qodiqa_owner has attributes outside NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' USING ERRCODE = '42501';
  END IF;
  IF NOT is_super AND NOT pg_catalog.pg_has_role(current_user, 'qodiqa_owner', 'SET') THEN
    RAISE EXCEPTION 'restore: % cannot SET ROLE qodiqa_owner — restore as the bootstrap/migration identity that ran migration 081', current_user USING ERRCODE = '42501';
  END IF;
  SELECT string_agg(c.relname, ', ') INTO bad
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND NOT (c.relkind = 'r' AND (c.relname = ANY (approved_tables) OR c.relname = ANY (post_081_tables)));
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'restore: unexpected relation(s) %', bad USING ERRCODE = '55000'; END IF;
  FOREACH s IN ARRAY approved_tables LOOP
    IF to_regclass('public.' || quote_ident(s)) IS NULL THEN RAISE EXCEPTION 'restore: table % is missing', s USING ERRCODE = '55000'; END IF;
    EXECUTE format('ALTER TABLE public.%I OWNER TO qodiqa_owner', s);
  END LOOP;
  FOREACH s IN ARRAY post_081_tables LOOP
    -- a table of a later migration may be absent from a backup taken before that migration: only repair the ones that exist
    IF to_regclass('public.' || quote_ident(s)) IS NOT NULL THEN EXECUTE format('ALTER TABLE public.%I OWNER TO qodiqa_owner', s); END IF;
  END LOOP;
  FOREACH s IN ARRAY approved_functions LOOP
    IF to_regprocedure(s) IS NULL THEN RAISE EXCEPTION 'restore: function % is missing', s USING ERRCODE = '55000'; END IF;
    EXECUTE format('ALTER FUNCTION %s OWNER TO qodiqa_owner', to_regprocedure(s));
  END LOOP;
  FOREACH s IN ARRAY approved_types LOOP
    EXECUTE format('ALTER TYPE public.%I OWNER TO qodiqa_owner', s);
  END LOOP;

  SELECT string_agg(c.relname || '=' || pg_get_userbyid(c.relowner), ', ') INTO bad
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'i', 'I') AND c.relowner <> 'qodiqa_owner'::regrole;
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'restore postcondition: relation(s) not owned by qodiqa_owner: %', bad; END IF;
  SELECT string_agg(p.oid::regprocedure::text, ', ') INTO bad
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public' AND NOT p.prosecdef AND p.proowner <> 'qodiqa_owner'::regrole;
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'restore postcondition: non-definer function(s) not owned by qodiqa_owner: %', bad; END IF;
  SELECT string_agg(c.relname, ', ') INTO bad
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT has_table_privilege('qodiqa_backup', c.oid, 'SELECT');
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'restore postcondition: qodiqa_backup cannot read %', bad; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_default_acl WHERE defaclrole <> 'qodiqa_owner'::regrole AND defaclnamespace = 'public'::regnamespace) THEN
    RAISE EXCEPTION 'restore postcondition: default privileges for a role other than qodiqa_owner';
  END IF;
  IF has_table_privilege('qodiqa_mig', 'public.audit_chain', 'UPDATE') OR has_table_privilege('qodiqa_mig', 'public.audit_chain', 'TRUNCATE')
     OR has_table_privilege('qodiqa_mig', 'public.audit_chain', 'TRIGGER') OR has_table_privilege('qodiqa_mig', 'public.audit_chain', 'DELETE') THEN
    RAISE EXCEPTION 'restore postcondition: qodiqa_mig controls audit_chain';
  END IF;
  RAISE NOTICE 'restore: schema objects owned by qodiqa_owner (NOLOGIN, non-superuser); backup coverage and default privileges verified';
END
$$;

COMMIT;
