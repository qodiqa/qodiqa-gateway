-- QODIQA PostgreSQL Migration 079
-- every SECURITY DEFINER function runs as a dedicated, NOLOGIN, non-superuser owner.
--
-- WHY: a SECURITY DEFINER function executes with its OWNER's privileges. The shipped compose procedure (and any
-- deployment that migrates as the cluster bootstrap superuser) left all 47 definer functions owned by that superuser,
-- so each one executed with superuser rights (verified on the compose-deployed rc077 stack, PostgreSQL 16.15:
--). None of them needs superuser: they need RLS bypass
-- plus a handful of table privileges.
--
-- WHAT:
--   1. qodiqa_definer: NOLOGIN (no credential exists for it), NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION,
--      BYPASSRLS. BYPASSRLS is required, not convenient: every table the definers read or write has FORCE ROW LEVEL
--      SECURITY with no policy for this role (it would see zero rows), and qodiqa_platform_audit_events_append_only_guard
--      admits the erasure UPDATE only for a BYPASSRLS role (migration 062).
--   2. Exactly the table privileges the 47 bodies use (derived from the bodies; pinned by
--      test/integration/definerOwnership.integration.test.js). No blanket grant. UPDATE is column-scoped except on audit_chain,
--      where it exists only because qodiqa_audit_chain_mirror_count_rebuild() takes LOCK TABLE audit_chain IN SHARE ROW
--      EXCLUSIVE MODE (a table-level UPDATE/DELETE/TRUNCATE privilege is required for that lock mode); row updates of
--      audit_chain stay refused by audit_chain_append_only_guard (migration 076) without a maintenance intent.
--   3. ALTER FUNCTION ... OWNER TO qodiqa_definer for an EXPLICIT list of 47 signatures. The live definer set must equal
--      the list exactly (an unexpected or missing definer aborts the migration). EXECUTE grants are carried over by
--      PostgreSQL (only the grantor changes to the new owner); search_path settings are untouched. Postconditions are
--      checked before COMMIT.
--
-- IDENTITY: a superuser (compose bootstrap, CI service, disposable clusters) transfers ownership directly. A
-- non-superuser migrator (the documented qodiqa_test bootstrap role) must own the functions (it created them) and must
-- be able to SET ROLE qodiqa_definer: the migration grants it membership in qodiqa_definer (it created the role, so it
-- holds ADMIN on it on PostgreSQL 16+) and keeps it, because future migrations that CREATE OR REPLACE a definer need
-- it, and because that role already owned every one of these functions. qodiqa_mig and every runtime role is refused
-- as a member (postcondition), so running this migration as qodiqa_mig fails closed. The temporary CREATE on schema
-- public that a non-superuser transfer needs is granted and revoked inside this transaction.
--
-- FUTURE MIGRATIONS that add or replace a SECURITY DEFINER function must end with ALTER FUNCTION ... OWNER TO
-- qodiqa_definer and add the signature to the pinned manifest; the test
-- fails otherwise.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

-- ── 1. the owner role ────────────────────────────────────────────────────────
DO $$
DECLARE r record;
BEGIN
  SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin, rolreplication, rolbypassrls
    INTO r FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_definer';
  IF NOT FOUND THEN
    CREATE ROLE qodiqa_definer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
    -- commented only by its creator: on PostgreSQL 16+ COMMENT ON ROLE needs ADMIN on the role, which a migrator that
    -- merely holds INHERIT/SET membership in a pre-existing qodiqa_definer does not have (and does not need)
    COMMENT ON ROLE qodiqa_definer IS
      '(migration 079): NOLOGIN owner of every SECURITY DEFINER function. BYPASSRLS + only the table privileges the definer bodies use. Never a member of any role; no runtime role may be a member of it.';
  ELSIF r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolcanlogin OR r.rolreplication OR NOT r.rolbypassrls THEN
    RAISE EXCEPTION 'role qodiqa_definer already exists with attributes outside NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS — refusing to make it the SECURITY DEFINER owner'
      USING ERRCODE = '42501';
  END IF;
END
$$;

-- a non-superuser migrator must be able to SET ROLE qodiqa_definer for ALTER ... OWNER TO. On PostgreSQL 16+ the role's
-- creator holds only an implicit ADMIN membership (no SET), so the check is the SET privilege, and the grant asks for
-- INHERIT and SET explicitly (the lesson for qodiqa_mig); PostgreSQL < 16 has neither option nor 'SET'.
DO $$
DECLARE can_set boolean;
BEGIN
  IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN
    BEGIN
      can_set := pg_catalog.pg_has_role(current_user, 'qodiqa_definer', 'SET');
    EXCEPTION WHEN invalid_parameter_value THEN
      can_set := pg_catalog.pg_has_role(current_user, 'qodiqa_definer', 'MEMBER');
    END;
    IF NOT can_set THEN
      BEGIN
        EXECUTE format('GRANT qodiqa_definer TO %I WITH INHERIT TRUE, SET TRUE', current_user);
      EXCEPTION WHEN syntax_error THEN
        EXECUTE format('GRANT qodiqa_definer TO %I', current_user);
      END;
    END IF;
  END IF;
END
$$;

-- ── 2. exactly the privileges the definer bodies use ─────────────────────────
-- reset first, so a pre-existing role carries nothing beyond the manifest in this database
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM qodiqa_definer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM qodiqa_definer;
REVOKE ALL ON SCHEMA public FROM qodiqa_definer;
-- functions: only grants ON functions it does not own (a re-run must not strip the owner's own ACL entry)
DO $$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proowner <> 'qodiqa_definer'::regrole
              AND EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 'qodiqa_definer'::regrole)
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM qodiqa_definer', f);
  END LOOP;
END
$$;

GRANT USAGE ON SCHEMA public TO qodiqa_definer;

-- reads: the fixed-SQL readers, the erasure functions' WHERE/count clauses, the mirror-count check/rebuild
GRANT SELECT ON TABLE
  audit_chain, audit_chain_mirror_count, audit_legal_holds, audit_retention_policies, compliance_reports,
  consent_audit_log, consent_records, dsr_erasure_ledger, dsr_exports, dsr_rectifications, dsr_requests,
  evidence_chain_records, platform_audit_events, policy_change_requests, policy_emergency_activations,
  qodiqa_alert_history, qodiqa_alerts, request_trails, revocation_events, subject_pseudonym_keys,
  tenant_policy_sets, tenant_semantic_configs, transparency_log_entries
  TO qodiqa_definer;

-- qodiqa_erase_subject: the seven approved identifier columns (migration 080) and the per-table scrubs
GRANT UPDATE (actor_id)                       ON consent_audit_log     TO qodiqa_definer;
GRANT UPDATE (actor_id)                       ON dsr_exports           TO qodiqa_definer;
GRANT UPDATE (actor_id, old_value, new_value) ON dsr_rectifications    TO qodiqa_definer;
GRANT UPDATE (actor_id, payload)              ON platform_audit_events TO qodiqa_definer;
GRANT UPDATE (actor_id, client_ip)            ON qodiqa_alerts         TO qodiqa_definer;
GRANT UPDATE (actor_id, caller_ip)            ON request_trails        TO qodiqa_definer;
GRANT UPDATE (subject_id, raw_payload)        ON revocation_events     TO qodiqa_definer;

-- qodiqa_erase_subject_finalize (SELECT ... FOR UPDATE on dsr_requests is covered by the column UPDATE grant)
GRANT UPDATE (actor_id, status, completed_at, result) ON dsr_requests TO qodiqa_definer;
GRANT INSERT ON TABLE dsr_request_events, dsr_erasure_ledger TO qodiqa_definer;
GRANT USAGE ON SEQUENCE dsr_request_events_id_seq, dsr_erasure_ledger_id_seq TO qodiqa_definer;
GRANT DELETE ON TABLE subject_pseudonym_keys TO qodiqa_definer;

-- the audit_chain mirror counter (migration 073): statement triggers and the owner-only rebuild
GRANT INSERT, UPDATE (row_count, updated_at, rebuilt_at) ON audit_chain_mirror_count TO qodiqa_definer;
GRANT UPDATE ON TABLE audit_chain TO qodiqa_definer;   -- LOCK TABLE ... SHARE ROW EXCLUSIVE in the rebuild only

-- the erasure functions call this (invoker) function
GRANT EXECUTE ON FUNCTION qodiqa_erasure_targets() TO qodiqa_definer;

-- ── 3. ownership transfer: an explicit, reviewable list ──────────────────────
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
  s        text;
  unlisted text;
  is_super boolean := (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user);
BEGIN
  IF array_length(approved, 1) <> 47 THEN
    RAISE EXCEPTION 'the approved definer list must hold 47 signatures, holds %', array_length(approved, 1);
  END IF;
  SELECT string_agg(p.oid::regprocedure::text, ', ' ORDER BY p.oid::regprocedure::text) INTO unlisted
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public' AND p.prosecdef AND NOT (p.oid::regprocedure::text = ANY (approved));
  IF unlisted IS NOT NULL THEN
    RAISE EXCEPTION 'SECURITY DEFINER function(s) not in the approved list: % — refusing to guess their owner', unlisted
      USING ERRCODE = '55000';
  END IF;
  FOREACH s IN ARRAY approved LOOP
    IF to_regprocedure(s) IS NULL OR NOT (SELECT prosecdef FROM pg_catalog.pg_proc WHERE oid = to_regprocedure(s)) THEN
      RAISE EXCEPTION 'approved SECURITY DEFINER function % is missing (or no longer SECURITY DEFINER)', s
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF NOT is_super THEN EXECUTE 'GRANT CREATE ON SCHEMA public TO qodiqa_definer'; END IF;
  FOREACH s IN ARRAY approved LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO qodiqa_definer', to_regprocedure(s));
  END LOOP;
  IF NOT is_super THEN EXECUTE 'REVOKE CREATE ON SCHEMA public FROM qodiqa_definer'; END IF;
END
$$;

-- ── 4. postconditions (fail the migration, never a partial state) ────────────
DO $$
DECLARE bad text;
BEGIN
  SELECT string_agg(p.oid::regprocedure::text || ' owner=' || r.rolname, ', ') INTO bad
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
   WHERE n.nspname = 'public' AND p.prosecdef
     AND (r.rolname <> 'qodiqa_definer' OR r.rolsuper
          OR NOT ('search_path=pg_catalog, public, pg_temp' = ANY (COALESCE(p.proconfig, '{}')))
          OR p.proacl IS NULL
          OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 0));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'postcondition: definer(s) not owned by qodiqa_definer, superuser-owned, without the pinned search_path, or PUBLIC-executable: %', bad;
  END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'public' AND p.prosecdef) <> 47 THEN
    RAISE EXCEPTION 'postcondition: expected 47 SECURITY DEFINER functions';
  END IF;
  SELECT string_agg(u.rolname, ', ') INTO bad
    FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid = m.roleid JOIN pg_catalog.pg_roles u ON u.oid = m.member
   WHERE g.rolname = 'qodiqa_definer'
     AND u.rolname IN ('qodiqa_app', 'qodiqa_read', 'qodiqa_mig', 'qodiqa_retention', 'qodiqa_system',
                       'qodiqa_reporting', 'qodiqa_control', 'qodiqa_backup');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'postcondition: runtime/migration role(s) % can assume qodiqa_definer — refused', bad USING ERRCODE = '42501';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles u ON u.oid = m.member WHERE u.rolname = 'qodiqa_definer') THEN
    RAISE EXCEPTION 'postcondition: qodiqa_definer must not be a member of any role' USING ERRCODE = '42501';
  END IF;
  IF has_schema_privilege('qodiqa_definer', 'public', 'CREATE') THEN
    RAISE EXCEPTION 'postcondition: qodiqa_definer must not hold CREATE on schema public' USING ERRCODE = '42501';
  END IF;
END
$$;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (79, 'er16_definer_owner_role', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
