-- QODIQA PostgreSQL Migration 063
--.
--
-- GDPR Art. 17 erasure, complete and resumable:
--
-- 1. subject_pseudonym_keys — one random HMAC key per (tenant, data subject),
--    KEK-encrypted by the application (services/artifact/keyEncryption.js).
--    The subject's pseudonym is  ap1:<hex HMAC-SHA256(K_subject, tenant‖actor)>.
--    Erasure writes the pseudonym everywhere the subject's identifier sits in
--    an erasable table, then DELETES the key: the pseudonym (also used in new
--    audit-chain entries, D6) can no longer be linked back to the subject, and
--    no hash-protected store has to be rewritten. RLS + FORCE: a tenant sees
--    only its own keys; the app may SELECT/INSERT, never UPDATE/DELETE (keys
--    are destroyed only by qodiqa_erase_subject_finalize below).
--
-- 2. dsr_erasure_ledger — append-only record that an erasure ran:
--    subject_ref = HMAC-SHA256 under the ledger key, over a domain label ‖ tenant ‖ actor
--    computed by the application with a key erasure never destroys. After a
--    DR restore, scripts/dr/restore.js re-erases every ledger subject found in
--    the restored data before the service takes traffic (D5 backup option A).
--    No grants to app/read: written only by finalize, read only through
--    qodiqa_erasure_ledger_list (system, reporting).
--
-- 3. qodiqa_erasure_targets() — the erasable identifier columns, derived FROM
--    THE CATALOG: every public table with an actor_id / subject_id column,
--    minus a declared exclusion list. A new table carrying a subject identifier
--    is erased automatically; one without tenant_id makes erasure fail loudly
--    until its treatment is declared here (never a silent skip).
--
-- 4. qodiqa_erase_subject(...) — SECURITY DEFINER, owner-run, EXECUTE for
--    qodiqa_system only. One bounded batch per target per call; returns rows
--    updated and rows remaining so the caller loops until everything is 0.
--    Runs as the owner (BYPASSRLS), which is what lets it pass migration 062's
--    append-only guard on platform_audit_events — the guard stays closed to the
--    app role. consent_audit_log.actor_id is not covered by that table's
--    checksum (ConsentStore._auditChecksum: consent_id|event_type|actor|detail),
--    so pseudonymizing it leaves every checksum valid.
--
-- 5. qodiqa_erase_subject_finalize(...) — SECURITY DEFINER, qodiqa_system
--    only. Atomically: refuses unless the request is an IN_PROGRESS ERASURE
--    for this subject and NOTHING remains (COMPLETED only when all tables are
--    done — enforced here, not just in the caller); pseudonymizes dsr_requests
--    (group c); marks the request COMPLETED with its event row (checksum
--    computed by the application with DSRStore's formula); deletes the
--    subject's key; appends the ledger row.
--
-- 6. qodiqa_erasure_subject_candidates() / qodiqa_erasure_ledger_list() —
--    SECURITY DEFINER, for the restore re-erasure hook (system) and operators
--    (reporting).
--
-- IDENTITY: owner-run DEFINER functions — qodiqa_mig (055) on
-- deployments, qodiqa_test on disposable DBs (both BYPASSRLS).

BEGIN;

-- ── 1. subject_pseudonym_keys ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subject_pseudonym_keys (
  tenant_id   VARCHAR(256),
  actor_id    VARCHAR(256) NOT NULL,
  key_enc     JSONB        NOT NULL,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS subject_pseudonym_keys_subject_uq
  ON subject_pseudonym_keys (COALESCE(tenant_id, ''), actor_id);

ALTER TABLE subject_pseudonym_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject_pseudonym_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS spk_tenant_select ON subject_pseudonym_keys;
DROP POLICY IF EXISTS spk_tenant_insert ON subject_pseudonym_keys;
CREATE POLICY spk_tenant_select ON subject_pseudonym_keys FOR SELECT TO qodiqa_app
  USING (tenant_id IS NOT DISTINCT FROM qodiqa_current_tenant());
CREATE POLICY spk_tenant_insert ON subject_pseudonym_keys FOR INSERT TO qodiqa_app
  WITH CHECK (tenant_id IS NOT DISTINCT FROM qodiqa_current_tenant());
REVOKE ALL ON subject_pseudonym_keys FROM PUBLIC;
GRANT SELECT, INSERT ON subject_pseudonym_keys TO qodiqa_app;

-- ── 2. dsr_erasure_ledger ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dsr_erasure_ledger (
  id           BIGSERIAL    PRIMARY KEY,
  tenant_id    VARCHAR(256),
  subject_ref  CHAR(64)     NOT NULL CHECK (subject_ref ~ '^[0-9a-f]{64}$'),
  request_id   UUID,
  run_id       UUID         NOT NULL,
  erased_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  summary      JSONB        NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (run_id)
);
CREATE INDEX IF NOT EXISTS dsr_erasure_ledger_ref_idx ON dsr_erasure_ledger (subject_ref);
REVOKE ALL ON dsr_erasure_ledger FROM PUBLIC;
REVOKE ALL ON SEQUENCE dsr_erasure_ledger_id_seq FROM PUBLIC;

CREATE OR REPLACE FUNCTION qodiqa_dsr_erasure_ledger_append_only_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'dsr_erasure_ledger is append-only (% refused for role %)', TG_OP, current_user
    USING ERRCODE = '42501';
END
$$;
DROP TRIGGER IF EXISTS dsr_erasure_ledger_append_only_guard ON dsr_erasure_ledger;
CREATE TRIGGER dsr_erasure_ledger_append_only_guard
  BEFORE UPDATE OR DELETE ON dsr_erasure_ledger
  FOR EACH ROW EXECUTE FUNCTION qodiqa_dsr_erasure_ledger_append_only_guard();
DROP TRIGGER IF EXISTS dsr_erasure_ledger_no_truncate ON dsr_erasure_ledger;
CREATE TRIGGER dsr_erasure_ledger_no_truncate
  BEFORE TRUNCATE ON dsr_erasure_ledger
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_dsr_erasure_ledger_append_only_guard();

-- ── 3. erasure targets, from the catalog ──────────────────────────────────────
-- Declared exclusions (each is erased or retained ELSEWHERE, by design):
--   consent_records            group (a): erased by the application — record_hash
--                              is recomputed there (ConsentStore.eraseSubject)
--   dsr_requests               group (c): accountability record, pseudonymized
--                              by qodiqa_erase_subject_finalize
--   subject_pseudonym_keys     destroyed by qodiqa_erase_subject_finalize
--   approval_events,
--   policy_provenance_versions actor_id = the OPERATOR who approved/authored a
--                              policy change, never a data subject
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

-- ── 4. one bounded erasure batch per target ───────────────────────────────────
CREATE OR REPLACE FUNCTION qodiqa_erase_subject(p_tenant_id text, p_actor_id text, p_pseudonym text, p_batch integer)
RETURNS TABLE (target text, rows_updated bigint, remaining bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  t     record;
  n     bigint;
  left_ bigint;
  extra text;
  lim   integer := LEAST(GREATEST(COALESCE(p_batch, 500), 1), 5000);
BEGIN
  IF p_actor_id IS NULL OR p_actor_id = '' OR p_pseudonym IS NULL OR p_pseudonym !~ '^ap1:[0-9a-f]{64}$'
     OR p_actor_id = p_pseudonym THEN
    RAISE EXCEPTION 'erasure batch: invalid arguments' USING ERRCODE = '22023';
  END IF;

  FOR t IN SELECT * FROM qodiqa_erasure_targets() LOOP
    IF NOT t.has_tenant THEN
      RAISE EXCEPTION 'erasure target %.% has no tenant_id column: declare its treatment in qodiqa_erasure_targets (migration 063)',
        t.table_name, t.column_name USING ERRCODE = '55000';
    END IF;
    -- Per-table scrub of the matched rows' other personal fields, same statement.
    extra := CASE t.table_name
               WHEN 'dsr_rectifications' THEN ', old_value = NULL, new_value = NULL'
               WHEN 'qodiqa_alerts'      THEN ', client_ip = NULL'
               -- raw_payload is the original event (identifier included), kept "for replay";
               -- an erased subject's event is never replayed, so only a marker remains.
               WHEN 'revocation_events'  THEN ', raw_payload = jsonb_build_object(''erasedGdprArticle17'', true, ''subjectId'', $1::text)::text'
               ELSE '' END;
    EXECUTE format(
      'UPDATE %I SET %I = $1%s WHERE ctid IN (SELECT ctid FROM %I WHERE %I = $2 AND tenant_id IS NOT DISTINCT FROM $3 LIMIT $4)',
      t.table_name, t.column_name, extra, t.table_name, t.column_name)
      USING p_pseudonym, p_actor_id, p_tenant_id, lim;
    GET DIAGNOSTICS n = ROW_COUNT;
    EXECUTE format('SELECT count(*) FROM %I WHERE %I = $1 AND tenant_id IS NOT DISTINCT FROM $2', t.table_name, t.column_name)
      INTO left_ USING p_actor_id, p_tenant_id;
    target := t.table_name || '.' || t.column_name; rows_updated := n; remaining := left_;
    RETURN NEXT;
  END LOOP;

  -- Declared JSON path: platform_audit_events.payload.actorId.
  UPDATE platform_audit_events SET payload = jsonb_set(payload, '{actorId}', to_jsonb(p_pseudonym))
   WHERE ctid IN (SELECT ctid FROM platform_audit_events
                   WHERE payload->>'actorId' = p_actor_id AND tenant_id IS NOT DISTINCT FROM p_tenant_id LIMIT lim);
  GET DIAGNOSTICS n = ROW_COUNT;
  SELECT count(*) INTO left_ FROM platform_audit_events
   WHERE payload->>'actorId' = p_actor_id AND tenant_id IS NOT DISTINCT FROM p_tenant_id;
  target := 'platform_audit_events.payload.actorId'; rows_updated := n; remaining := left_;
  RETURN NEXT;
END
$$;

-- ── 5. finalize ───────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION qodiqa_erase_subject_finalize(
  p_request_id uuid, p_tenant_id text, p_actor_id text, p_pseudonym text, p_subject_ref text,
  p_run_id uuid, p_result jsonb, p_event_actor text, p_event_detail text, p_event_checksum text)
RETURNS SETOF dsr_requests
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  req   dsr_requests%ROWTYPE;
  t     record;
  left_ bigint;
BEGIN
  IF p_pseudonym IS NULL OR p_pseudonym !~ '^ap1:[0-9a-f]{64}$' OR p_subject_ref !~ '^[0-9a-f]{64}$'
     OR p_event_checksum !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'erasure finalize: invalid arguments' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO req FROM dsr_requests WHERE id = p_request_id FOR UPDATE;
  IF NOT FOUND OR req.request_type <> 'ERASURE' OR req.status <> 'IN_PROGRESS'
     OR req.actor_id <> p_actor_id OR req.tenant_id IS DISTINCT FROM p_tenant_id THEN
    RAISE EXCEPTION 'erasure finalize: request % is not an in-progress erasure of this subject', p_request_id
      USING ERRCODE = '55000';
  END IF;

  -- COMPLETED only when nothing remains, checked here.
  FOR t IN SELECT * FROM qodiqa_erasure_targets() LOOP
    EXECUTE format('SELECT count(*) FROM %I WHERE %I = $1 AND tenant_id IS NOT DISTINCT FROM $2', t.table_name, t.column_name)
      INTO left_ USING p_actor_id, p_tenant_id;
    IF left_ > 0 THEN
      RAISE EXCEPTION 'erasure incomplete: % row(s) remain in %.%', left_, t.table_name, t.column_name USING ERRCODE = '55000';
    END IF;
  END LOOP;
  SELECT count(*) INTO left_ FROM platform_audit_events
   WHERE payload->>'actorId' = p_actor_id AND tenant_id IS NOT DISTINCT FROM p_tenant_id;
  IF left_ > 0 THEN
    RAISE EXCEPTION 'erasure incomplete: % row(s) remain in platform_audit_events.payload.actorId', left_ USING ERRCODE = '55000';
  END IF;
  SELECT count(*) INTO left_ FROM consent_records WHERE actor_id = p_actor_id AND tenant_id IS NOT DISTINCT FROM p_tenant_id;
  IF left_ > 0 THEN
    RAISE EXCEPTION 'erasure incomplete: % row(s) remain in consent_records.actor_id', left_ USING ERRCODE = '55000';
  END IF;

  UPDATE dsr_requests SET actor_id = p_pseudonym
   WHERE actor_id = p_actor_id AND tenant_id IS NOT DISTINCT FROM p_tenant_id;
  UPDATE dsr_requests SET status = 'COMPLETED', completed_at = NOW(), result = p_result WHERE id = p_request_id;
  INSERT INTO dsr_request_events (request_id, tenant_id, event_type, actor, detail, checksum)
  VALUES (p_request_id, p_tenant_id, 'DSR_ERASURE_COMPLETED', p_event_actor, p_event_detail::jsonb, p_event_checksum);
  DELETE FROM subject_pseudonym_keys WHERE actor_id = p_actor_id AND tenant_id IS NOT DISTINCT FROM p_tenant_id;
  INSERT INTO dsr_erasure_ledger (tenant_id, subject_ref, request_id, run_id, summary)
  VALUES (p_tenant_id, p_subject_ref, p_request_id, p_run_id, COALESCE(p_result->'tables', '{}'::jsonb));

  RETURN QUERY SELECT * FROM dsr_requests WHERE id = p_request_id;
END
$$;

-- ── 6. restore re-erasure support + ledger listing ────────────────────────────
-- Every distinct (tenant, subject identifier) still in plaintext anywhere
-- erasure writes, so the restore hook can match them against ledger refs.
CREATE OR REPLACE FUNCTION qodiqa_erasure_subject_candidates()
RETURNS TABLE (tenant_id text, actor_id text)
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
  t   record;
  sql text := 'SELECT tenant_id::text, actor_id::text FROM consent_records'
           || ' UNION SELECT tenant_id::text, actor_id::text FROM dsr_requests'
           || ' UNION SELECT tenant_id::text, actor_id::text FROM subject_pseudonym_keys';
BEGIN
  FOR t IN SELECT * FROM qodiqa_erasure_targets() WHERE has_tenant LOOP
    sql := sql || format(' UNION SELECT tenant_id::text, %I::text FROM %I', t.column_name, t.table_name);
  END LOOP;
  RETURN QUERY EXECUTE 'SELECT DISTINCT s.tenant_id, s.actor_id FROM (' || sql || ') s(tenant_id, actor_id)'
                    || ' WHERE s.actor_id IS NOT NULL AND s.actor_id NOT LIKE ''ap1:%''';
END
$$;

CREATE OR REPLACE FUNCTION qodiqa_erasure_ledger_list(p_after_id bigint, p_limit integer)
RETURNS TABLE (id bigint, tenant_id varchar, subject_ref char(64), request_id uuid, run_id uuid, erased_at timestamptz, summary jsonb)
LANGUAGE sql SECURITY DEFINER STABLE
SET search_path = pg_catalog, public
AS $$
  SELECT l.id, l.tenant_id, l.subject_ref, l.request_id, l.run_id, l.erased_at, l.summary
    FROM dsr_erasure_ledger l
   WHERE l.id > COALESCE(p_after_id, 0)
   ORDER BY l.id
   LIMIT LEAST(GREATEST(COALESCE(p_limit, 1000), 1), 10000)
$$;

-- ── Privileges ────────────────
DO $$
DECLARE fn text;
BEGIN
  FOREACH fn IN ARRAY ARRAY[
    'qodiqa_erase_subject(text, text, text, integer)',
    'qodiqa_erase_subject_finalize(uuid, text, text, text, text, uuid, jsonb, text, text, text)',
    'qodiqa_erasure_subject_candidates()',
    'qodiqa_erasure_ledger_list(bigint, integer)',
    'qodiqa_erasure_targets()'
  ] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', fn);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM qodiqa_app, qodiqa_read', fn);
  END LOOP;
END
$$;
GRANT EXECUTE ON FUNCTION qodiqa_erase_subject(text, text, text, integer) TO qodiqa_system;
GRANT EXECUTE ON FUNCTION qodiqa_erase_subject_finalize(uuid, text, text, text, text, uuid, jsonb, text, text, text) TO qodiqa_system;
GRANT EXECUTE ON FUNCTION qodiqa_erasure_subject_candidates() TO qodiqa_system;
GRANT EXECUTE ON FUNCTION qodiqa_erasure_ledger_list(bigint, integer) TO qodiqa_system, qodiqa_reporting;
GRANT EXECUTE ON FUNCTION qodiqa_erasure_targets() TO qodiqa_system, qodiqa_reporting;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (63, 'w5_subject_erasure', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
