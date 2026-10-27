-- QODIQA PostgreSQL Migration 081
-- closure / D-R: every table, sequence, type and non-definer function in schema public is owned by
-- a dedicated NOLOGIN, non-superuser, non-BYPASSRLS role, qodiqa_owner. SECURITY DEFINER functions stay with
-- qodiqa_definer (migration 079) and are not touched here.
--
-- WHY:
--   * on compose deployments 72 tables / 36 sequences / 15 functions / 1 type were owned by the cluster bootstrap
--     SUPERUSER, so only a superuser could restore with --clean or run later DDL (the / OA4-F1 override);
--   * qodiqa_mig (a LOGIN role) owned the 12 tables of migration 001, audit_chain among them: owning audit_chain lets
--     that credential drop or replace the append-only guard and mirror-count triggers;
--   * pg_dump records ALTER DEFAULT PRIVILEGES FOR ROLE <creator>: with the creator being the deployment's bootstrap
--     superuser (any name) or qodiqa_mig, a restore on a cluster without that role, or by a non-member, stopped part
--     way (PL13-10 class; reproduced in the drills C2/R2).
--
-- WHAT:
--   1. qodiqa_owner: NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS, member of nothing; USAGE
--      and CREATE on schema public so a migration can create objects AS qodiqa_owner (SET LOCAL ROLE qodiqa_owner).
--   2. ALTER ... OWNER TO qodiqa_owner for an EXPLICIT list: 84 tables (their 41 serial sequences and every index
--      follow automatically), 15 non-definer functions, 1 enum type. The live set must equal the lists exactly — an
--      unexpected or missing table/function/type, or a standalone sequence, aborts the migration.
--   3. qodiqa_mig keeps the table privileges it held as owner of the 11 other migration-001 tables and their
--      sequences, but on audit_chain only SELECT and INSERT (what scripts/migrate-files-to-pg.js needs): no UPDATE,
--      DELETE, TRUNCATE, REFERENCES or TRIGGER and no ownership — the migration credential can no longer alter the
--      audit chain's guards. qodiqa_mig is NOT made a member of qodiqa_owner.
--   4. Default privileges: the backup role's SELECT defaults move to FOR ROLE qodiqa_owner; the defaults recorded for
--      the migrating identity and for qodiqa_mig (migration 067) are removed, so a dump no longer names the
--      deployment's bootstrap role. Any other default-ACL entry aborts the migration.
--   Grants, RLS policies, triggers, constraints and indexes are unchanged: PostgreSQL rewrites existing ACL entries to
--   the new owner as grantor and keeps every grantee.
--
-- IDENTITY: like 079 — a superuser (compose bootstrap, CI) or the CREATEROLE bootstrap role (qodiqa_test), which is
-- given INHERIT/SET membership in qodiqa_owner (PostgreSQL 16+: a role's creator otherwise holds only ADMIN). Run as
-- qodiqa_mig it fails closed. Later migrations that create objects must do so AS qodiqa_owner
-- (SET LOCAL ROLE qodiqa_owner) or end with ALTER ... OWNER TO qodiqa_owner; test/definerOwnership DO-14..
-- fail otherwise.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

-- ── 1. the owner role ────────────────────────────────────────────────────────
DO $$
DECLARE r record;
BEGIN
  SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin, rolreplication, rolbypassrls
    INTO r FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_owner';
  IF NOT FOUND THEN
    CREATE ROLE qodiqa_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    COMMENT ON ROLE qodiqa_owner IS
      'closure (migration 081): NOLOGIN owner of every table, sequence, type and non-definer function in schema public. Not superuser, no BYPASSRLS. Member of nothing.';
  ELSIF r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolcanlogin OR r.rolreplication OR r.rolbypassrls THEN
    RAISE EXCEPTION '081: role qodiqa_owner already exists with attributes outside NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
      USING ERRCODE = '42501';
  END IF;
END
$$;

DO $$
DECLARE can_set boolean;
BEGIN
  IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN
    BEGIN
      can_set := pg_catalog.pg_has_role(current_user, 'qodiqa_owner', 'SET');
    EXCEPTION WHEN invalid_parameter_value THEN
      can_set := pg_catalog.pg_has_role(current_user, 'qodiqa_owner', 'MEMBER');
    END;
    IF NOT can_set THEN
      BEGIN
        EXECUTE format('GRANT qodiqa_owner TO %I WITH INHERIT TRUE, SET TRUE', current_user);
      EXCEPTION WHEN syntax_error THEN
        EXECUTE format('GRANT qodiqa_owner TO %I', current_user);
      END;
    END IF;
  END IF;
END
$$;

GRANT USAGE, CREATE ON SCHEMA public TO qodiqa_owner;

-- ── 2. ownership transfer: explicit, reviewable lists ────────────────────────
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
  approved_functions CONSTANT text[] := ARRAY[
    '_consent_records_updated_at()', '_dsr_requests_updated_at()', '_pcr_updated_at()',
    'qodiqa_audit_append_only_guard()', 'qodiqa_audit_chain_mirror_count_guard()',
    'qodiqa_audit_chain_prunes_append_only_guard()', 'qodiqa_audit_checksum_anchor_monotonic_guard()',
    'qodiqa_audit_maintenance_log()', 'qodiqa_audit_signed_checkpoints_append_only_guard()',
    'qodiqa_control_plane_guard()', 'qodiqa_current_tenant()', 'qodiqa_dsr_erasure_ledger_append_only_guard()',
    'qodiqa_erasure_targets()', 'qodiqa_platform_audit_events_append_only_guard()', 'qodiqa_set_updated_at()'
  ];
  approved_types CONSTANT text[] := ARRAY['audit_category'];
  bad text;
  s   text;
BEGIN
  IF array_length(approved_tables, 1) <> 84 OR array_length(approved_functions, 1) <> 15 THEN
    RAISE EXCEPTION '081: the approved lists must hold 84 tables and 15 functions';
  END IF;
  SELECT string_agg(c.relname || ' (' || c.relkind::text || ')', ', ' ORDER BY c.relname) INTO bad
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
     AND NOT (c.relkind = 'r' AND c.relname = ANY (approved_tables));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION '081: unexpected relation(s) in schema public: % — refusing to guess their owner', bad USING ERRCODE = '55000';
  END IF;
  SELECT string_agg(c.relname, ', ') INTO bad
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind = 'S'
     AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
                       AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i'));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION '081: standalone sequence(s) % are not covered by the table cascade', bad USING ERRCODE = '55000';
  END IF;
  FOREACH s IN ARRAY approved_tables LOOP
    IF to_regclass('public.' || quote_ident(s)) IS NULL THEN
      RAISE EXCEPTION '081: approved table % is missing', s USING ERRCODE = '55000';
    END IF;
  END LOOP;
  SELECT string_agg(p.oid::regprocedure::text, ', ') INTO bad
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public' AND NOT p.prosecdef AND NOT (p.oid::regprocedure::text = ANY (approved_functions));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION '081: unexpected non-definer function(s): %', bad USING ERRCODE = '55000';
  END IF;
  FOREACH s IN ARRAY approved_functions LOOP
    IF to_regprocedure(s) IS NULL THEN
      RAISE EXCEPTION '081: approved function % is missing', s USING ERRCODE = '55000';
    END IF;
  END LOOP;
  SELECT string_agg(t.typname, ', ') INTO bad
    FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
   WHERE n.nspname = 'public' AND t.typtype IN ('e', 'd', 'r', 'm') AND NOT (t.typname = ANY (approved_types));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION '081: unexpected type(s): %', bad USING ERRCODE = '55000';
  END IF;

  FOREACH s IN ARRAY approved_tables LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO qodiqa_owner', s);
  END LOOP;
  FOREACH s IN ARRAY approved_functions LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO qodiqa_owner', to_regprocedure(s));
  END LOOP;
  FOREACH s IN ARRAY approved_types LOOP
    EXECUTE format('ALTER TYPE public.%I OWNER TO qodiqa_owner', s);
  END LOOP;
END
$$;

-- ── 3. qodiqa_mig: the table privileges it held as owner, minus control over audit_chain ──
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE
  evidence_packages, investigation_artifacts, investigation_audit_events, investigations, policies, policy_history,
  policy_versions, qodiqa_migrations, rbac_users, signing_key_legacy_map, signing_keys
  TO qodiqa_mig;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE
  investigation_audit_events_id_seq, policy_history_id_seq, policy_versions_id_seq, qodiqa_migrations_id_seq
  TO qodiqa_mig;
REVOKE ALL ON TABLE audit_chain FROM qodiqa_mig;
GRANT SELECT, INSERT ON TABLE audit_chain TO qodiqa_mig;
REVOKE ALL ON SEQUENCE audit_chain_seq_seq FROM qodiqa_mig;
GRANT USAGE, SELECT ON SEQUENCE audit_chain_seq_seq TO qodiqa_mig;

-- ── 4. default privileges: one owner, no deployment-specific role names in a dump ──
ALTER DEFAULT PRIVILEGES FOR ROLE qodiqa_owner IN SCHEMA public GRANT SELECT ON TABLES TO qodiqa_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE qodiqa_owner IN SCHEMA public GRANT SELECT ON SEQUENCES TO qodiqa_backup;
DO $$
DECLARE d record; bad text;
BEGIN
  -- only the documented backup-SELECT defaults of migration 067 may exist for roles other than qodiqa_owner
  SELECT string_agg(d2.defaclrole::regrole::text || ':' || d2.defaclobjtype::text || ':' || d2.defaclacl::text, '; ') INTO bad
    FROM pg_catalog.pg_default_acl d2
   WHERE d2.defaclrole <> 'qodiqa_owner'::regrole
     AND (d2.defaclnamespace <> 'public'::regnamespace OR d2.defaclobjtype NOT IN ('r', 'S')
          OR EXISTS (SELECT 1 FROM aclexplode(d2.defaclacl) a
                      WHERE a.grantee <> 'qodiqa_backup'::regrole OR a.privilege_type <> 'SELECT'));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION '081: unexpected default privileges %', bad USING ERRCODE = '55000';
  END IF;
  FOR d IN SELECT DISTINCT defaclrole::regrole::text AS r, defaclobjtype::text AS t FROM pg_catalog.pg_default_acl
            WHERE defaclrole <> 'qodiqa_owner'::regrole AND defaclnamespace = 'public'::regnamespace LOOP
    IF NOT pg_catalog.pg_has_role(current_user, d.r::regrole, 'MEMBER') THEN
      RAISE EXCEPTION '081: % holds default privileges but % is not a member of it — run as a superuser or the bootstrap identity',
        d.r, current_user USING ERRCODE = '42501';
    END IF;
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public REVOKE SELECT ON %s FROM qodiqa_backup',
                   d.r, CASE d.t WHEN 'r' THEN 'TABLES' ELSE 'SEQUENCES' END);
  END LOOP;
END
$$;

-- ── 5. postconditions (fail the migration, never a partial state) ────────────
DO $$
DECLARE bad text;
BEGIN
  SELECT string_agg(c.relname || '=' || pg_get_userbyid(c.relowner), ', ') INTO bad
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'i', 'I') AND c.relowner <> 'qodiqa_owner'::regrole;
  IF bad IS NOT NULL THEN RAISE EXCEPTION '081 postcondition: relation(s) not owned by qodiqa_owner: %', bad; END IF;
  SELECT string_agg(p.oid::regprocedure::text || '=' || pg_get_userbyid(p.proowner), ', ') INTO bad
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public'
     AND p.proowner <> CASE WHEN p.prosecdef THEN 'qodiqa_definer'::regrole ELSE 'qodiqa_owner'::regrole END;
  IF bad IS NOT NULL THEN RAISE EXCEPTION '081 postcondition: function owner(s) wrong: %', bad; END IF;
  SELECT string_agg(c.relname, ', ') INTO bad
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT has_table_privilege('qodiqa_backup', c.oid, 'SELECT');
  IF bad IS NOT NULL THEN RAISE EXCEPTION '081 postcondition: qodiqa_backup cannot read %', bad; END IF;
  IF has_table_privilege('qodiqa_mig', 'public.audit_chain', 'UPDATE') OR has_table_privilege('qodiqa_mig', 'public.audit_chain', 'DELETE')
     OR has_table_privilege('qodiqa_mig', 'public.audit_chain', 'TRUNCATE') OR has_table_privilege('qodiqa_mig', 'public.audit_chain', 'TRIGGER') THEN
    RAISE EXCEPTION '081 postcondition: qodiqa_mig still controls audit_chain';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid = m.roleid JOIN pg_catalog.pg_roles u ON u.oid = m.member
              WHERE g.rolname = 'qodiqa_owner' AND u.rolname IN ('qodiqa_app', 'qodiqa_read', 'qodiqa_mig', 'qodiqa_retention', 'qodiqa_system',
                                                                 'qodiqa_reporting', 'qodiqa_control', 'qodiqa_backup', 'qodiqa_definer'))
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles u ON u.oid = m.member WHERE u.rolname = 'qodiqa_owner') THEN
    RAISE EXCEPTION '081 postcondition: a runtime/migration role can assume qodiqa_owner, or qodiqa_owner is a member of a role' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_default_acl WHERE defaclrole <> 'qodiqa_owner'::regrole AND defaclnamespace = 'public'::regnamespace) THEN
    RAISE EXCEPTION '081 postcondition: default privileges remain for a role other than qodiqa_owner';
  END IF;
END
$$;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (81, 'er16_schema_owner_role', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
