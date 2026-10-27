-- QODIQA PostgreSQL Migration 061
--.
--
-- Before: all 32 SECURITY DEFINER functions (043/044/048/049/050/051/053/056/058)
-- are owned by a BYPASSRLS role and EXECUTE-able by qodiqa_app AND qodiqa_read;
-- none reads the tenant context. Any request-serving connection could read
-- every tenant's audit chain, evidence, transparency metadata, alerts,
-- platform events, compliance reports and tenant configs.
--
-- After:
--   1. EXECUTE on every cross-tenant function is revoked from qodiqa_app,
--      qodiqa_read and PUBLIC, and granted only to qodiqa_system (integrity,
--      background, boot hydration) and/or qodiqa_reporting (RBAC-gated operator
--      consoles) —
--   2. The two functions with no caller are dropped; their definitions are
--      preserved verbatim in quarantine/w5/definer-functions-removed.sql.
--   3. qodiqa_app keeps exactly five narrowly-scoped DEFINER functions, for the
--      public routes:
--        - transparency lookups returning only the fields a verifier needs
--          (no tenant_id, registered_by, signer_key_version or payload);
--        - two hash-only range readers for Merkle proofs / consistency;
--        - an evidence lookup that returns a record only when its tenant equals
--          the tenant claimed by the (signed) artifact being verified.
--
-- IDENTITY: GRANT/REVOKE on a function and DROP FUNCTION require its owner (or
-- a superuser). Run as the owner of the 043–058 functions (qodiqa_mig on
-- deployments migrated; qodiqa_test on disposable DBs).

BEGIN;

-- ── 1. revoke from the request-serving and read roles ─────────────────────────
DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY[
    'qodiqa_audit_chain_detect_sequence_gaps(bigint, integer)',
    'qodiqa_audit_chain_fetch_batch(bigint, integer)',
    'qodiqa_audit_chain_fetch_by_artifact_id(character varying)',
    'qodiqa_audit_chain_fetch_replay_lineage(character varying)',
    'qodiqa_audit_chain_fetch_row_by_seq(bigint)',
    'qodiqa_audit_chain_full_read()',
    'qodiqa_audit_chain_hash_exists(character)',
    'qodiqa_audit_chain_max_seq()',
    'qodiqa_audit_chain_true_tail()',
    'qodiqa_audit_legal_holds_full_read()',
    'qodiqa_audit_retention_policies_full_read()',
    'qodiqa_compliance_reports_full_read()',
    'qodiqa_consent_audit_log_full_read()',
    'qodiqa_evidence_chain_records_full_read()',
    'qodiqa_platform_audit_events_full_read()',
    'qodiqa_policy_change_request_by_id(uuid)',
    'qodiqa_policy_emergency_activations_full_read()',
    'qodiqa_qodiqa_alert_history_full_read()',
    'qodiqa_qodiqa_alerts_full_read()',
    'qodiqa_tenant_policy_sets_full_read()',
    'qodiqa_tenant_semantic_configs_full_read()',
    'qodiqa_transparency_log_fetch_batch(bigint, integer)',
    'qodiqa_transparency_log_fetch_boundary(bigint)',
    'qodiqa_transparency_log_fetch_by_artifact_id(character varying)',
    'qodiqa_transparency_log_fetch_by_entry_hash(character)',
    'qodiqa_transparency_log_fetch_by_transparency_id(uuid)',
    'qodiqa_transparency_log_fetch_hashes_in_range(bigint, bigint)',
    'qodiqa_transparency_log_fetch_range_full(bigint, bigint)',
    'qodiqa_transparency_log_latest_entry()',
    'qodiqa_transparency_log_read_all()'
  ] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, qodiqa_app, qodiqa_read', f);
  END LOOP;
END
$$;

-- ── 2. grants per PRIVILEGE-POLICY.md ─────────────────────────────────────────
-- qodiqa_system: integrity, background, boot hydration.
GRANT EXECUTE ON FUNCTION
  qodiqa_audit_chain_hash_exists(character),
  qodiqa_audit_chain_true_tail(),
  qodiqa_audit_chain_full_read(),
  qodiqa_audit_chain_fetch_batch(bigint, integer),
  qodiqa_audit_chain_detect_sequence_gaps(bigint, integer),
  qodiqa_audit_chain_fetch_row_by_seq(bigint),
  qodiqa_audit_chain_max_seq(),
  qodiqa_consent_audit_log_full_read(),
  qodiqa_policy_emergency_activations_full_read(),
  qodiqa_tenant_policy_sets_full_read(),
  qodiqa_tenant_semantic_configs_full_read(),
  qodiqa_transparency_log_latest_entry(),
  qodiqa_transparency_log_fetch_by_transparency_id(uuid),  -- public /verify integrity material (verdicts only leave the server)
  qodiqa_transparency_log_fetch_batch(bigint, integer),
  qodiqa_transparency_log_fetch_hashes_in_range(bigint, bigint),
  qodiqa_transparency_log_fetch_boundary(bigint)
TO qodiqa_system;

-- qodiqa_reporting: RBAC-gated operator consoles.
GRANT EXECUTE ON FUNCTION
  qodiqa_audit_chain_fetch_replay_lineage(character varying),
  qodiqa_audit_chain_fetch_by_artifact_id(character varying),
  qodiqa_evidence_chain_records_full_read(),
  qodiqa_platform_audit_events_full_read(),
  qodiqa_qodiqa_alerts_full_read(),
  qodiqa_qodiqa_alert_history_full_read(),
  qodiqa_audit_retention_policies_full_read(),
  qodiqa_audit_legal_holds_full_read(),
  qodiqa_compliance_reports_full_read(),
  qodiqa_policy_change_request_by_id(uuid),
  qodiqa_transparency_log_fetch_by_artifact_id(character varying),
  qodiqa_transparency_log_fetch_range_full(bigint, bigint),
  qodiqa_transparency_log_read_all()
TO qodiqa_reporting;

-- qodiqa_app: hash-only range reader for public Merkle proofs (id, entry_hash).
GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_fetch_hashes_in_range(bigint, bigint) TO qodiqa_app;

-- ── 3. remove the two functions with no caller (SQL preserved in quarantine/w5/) ─
DROP FUNCTION IF EXISTS qodiqa_audit_chain_last_row();
DROP FUNCTION IF EXISTS qodiqa_transparency_log_fetch_by_evidence_chain_id(uuid);

-- ── 4. minimized functions for the public routes ──────────────────────────────
-- Verification fields only: the 8 canonical entry-hash fields (log.js), the
-- entry hash, the signature, the internal id (needed to place the leaf in the
-- Merkle tree) and created_at. NOT returned: tenant_id, registered_by,
-- signer_key_version, payload.
CREATE OR REPLACE FUNCTION qodiqa_transparency_public_entry(target_id uuid)
RETURNS TABLE (id bigint, transparency_id uuid, entry_type varchar, artifact_id varchar, evidence_chain_id uuid,
               verification_id bigint, payload_hash char(64), previous_entry_hash varchar, entry_hash char(64),
               signer_key_id varchar, signature text, created_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public STABLE
AS $$
  SELECT e.id, e.transparency_id, e.entry_type, e.artifact_id, e.evidence_chain_id, e.verification_id, e.payload_hash,
         e.previous_entry_hash, e.entry_hash, e.signer_key_id, e.signature, e.created_at
    FROM transparency_log_entries e WHERE e.transparency_id = target_id LIMIT 1
$$;

CREATE OR REPLACE FUNCTION qodiqa_transparency_public_entry_by_hash(target_hash character)
RETURNS TABLE (id bigint, transparency_id uuid, entry_type varchar, artifact_id varchar, evidence_chain_id uuid,
               verification_id bigint, payload_hash char(64), previous_entry_hash varchar, entry_hash char(64),
               signer_key_id varchar, signature text, created_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public STABLE
AS $$
  SELECT e.id, e.transparency_id, e.entry_type, e.artifact_id, e.evidence_chain_id, e.verification_id, e.payload_hash,
         e.previous_entry_hash, e.entry_hash, e.signer_key_id, e.signature, e.created_at
    FROM transparency_log_entries e WHERE e.entry_hash = target_hash LIMIT 1
$$;

-- Public listing: no tenant filter exists, page capped at 500 rows.
CREATE OR REPLACE FUNCTION qodiqa_transparency_public_list(p_entry_type text, p_artifact_id text, p_signer_key_id text,
                                                           p_start timestamptz, p_end timestamptz,
                                                           p_limit integer, p_offset integer, p_desc boolean)
RETURNS TABLE (id bigint, transparency_id uuid, entry_type varchar, artifact_id varchar, evidence_chain_id uuid,
               verification_id bigint, payload_hash char(64), previous_entry_hash varchar, entry_hash char(64),
               signer_key_id varchar, signature text, created_at timestamptz, total_count bigint)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public STABLE
AS $$
  SELECT e.id, e.transparency_id, e.entry_type, e.artifact_id, e.evidence_chain_id, e.verification_id, e.payload_hash,
         e.previous_entry_hash, e.entry_hash, e.signer_key_id, e.signature, e.created_at, count(*) OVER () AS total_count
    FROM transparency_log_entries e
   WHERE (p_entry_type    IS NULL OR e.entry_type    = p_entry_type)
     AND (p_artifact_id   IS NULL OR e.artifact_id   = p_artifact_id)
     AND (p_signer_key_id IS NULL OR e.signer_key_id = p_signer_key_id)
     AND (p_start         IS NULL OR e.created_at   >= p_start)
     AND (p_end           IS NULL OR e.created_at   <= p_end)
   ORDER BY CASE WHEN p_desc THEN e.id END DESC, CASE WHEN NOT p_desc THEN e.id END ASC
   LIMIT LEAST(GREATEST(COALESCE(p_limit, 50), 1), 500) OFFSET GREATEST(COALESCE(p_offset, 0), 0)
$$;

-- Hash-only forward reader for public Merkle proofs (block checkpoint builder).
CREATE OR REPLACE FUNCTION qodiqa_transparency_public_hashes_from_id(from_id bigint, max_rows integer)
RETURNS TABLE (id bigint, entry_hash char(64))
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public STABLE
AS $$
  SELECT e.id, e.entry_hash FROM transparency_log_entries e
   WHERE e.id >= from_id ORDER BY e.id ASC LIMIT LEAST(GREATEST(max_rows, 1), 4096)
$$;

-- Public artifact verification (POST /portal/verify, /v1/attestation/verify):
-- an evidence record is returned only when its tenant equals the tenant claimed
-- by the artifact being verified (platform rows have tenant NULL).
CREATE OR REPLACE FUNCTION qodiqa_evidence_public_lookup(target_artifact_id character varying, claimed_tenant_id text)
RETURNS SETOF evidence_chain_records
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public STABLE
AS $$
  SELECT r.* FROM evidence_chain_records r
   WHERE r.artifact_id = target_artifact_id
     AND (r.tenant_id IS NULL OR r.tenant_id = claimed_tenant_id)
   LIMIT 1
$$;

DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY[
    'qodiqa_transparency_public_entry(uuid)',
    'qodiqa_transparency_public_entry_by_hash(character)',
    'qodiqa_transparency_public_list(text, text, text, timestamp with time zone, timestamp with time zone, integer, integer, boolean)',
    'qodiqa_transparency_public_hashes_from_id(bigint, integer)',
    'qodiqa_evidence_public_lookup(character varying, text)'
  ] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO qodiqa_app', f);
  END LOOP;
END
$$;
-- qodiqa_transparency_log_fetch_by_entry_hash keeps NO non-owner grant and
-- _fetch_by_transparency_id only qodiqa_system (public /verify integrity
-- material): every other public caller uses the minimized functions above
-- (least privilege, reconciled against the
-- call-site audit).

COMMENT ON FUNCTION qodiqa_transparency_public_entry(uuid) IS
  'public transparency lookup — verification fields only (no tenant_id, registered_by, signer_key_version, payload).';
COMMENT ON FUNCTION qodiqa_transparency_public_entry_by_hash(character) IS
  'public /verify prior-entry link check — verification fields only.';
COMMENT ON FUNCTION qodiqa_transparency_public_list(text, text, text, timestamp with time zone, timestamp with time zone, integer, integer, boolean) IS
  'public /transparency/entries — verification fields only, no tenant filter, page capped at 500.';
COMMENT ON FUNCTION qodiqa_transparency_public_hashes_from_id(bigint, integer) IS
  'hash-only (id, entry_hash) reader for public Merkle proofs and consistency; capped at 4096 rows.';
COMMENT ON FUNCTION qodiqa_evidence_public_lookup(character varying, text) IS
  'public artifact verification — returns the evidence record only when its tenant equals the tenant claimed by the artifact.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (61, 'w5_definer_privileges', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
