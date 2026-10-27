-- QODIQA PostgreSQL Migration 069
-- step 6, design decision: per-request trails for the aggregated routine events.
--
-- Migration 068 made fourteen routine success event types per-minute aggregates in platform_audit_events, so their
-- per-request rows are gone from there. correlate(requestId) and artifactTimeline(artifactId) keep their per-request
-- detail from two sources (src/core/audit/centralStore.js):
--   * decision facts from the AUDIT CHAIN (qodiqa_audit_chain_decisions(), below): decision, policy hash, provider
--     and the audit entry hash of an artifact;
--   * the step list from ONE compact trail row per request (request_trails, below): each step's type, timestamp and
--     request / artifact / trace / span ids, plus an allow-list of fields — provider latency, evidence id,
--     transparency id — and, in COLUMNS only, the caller IP (caller_ip) and identity id (actor_id).
--
-- Personal data (owner conditions):
--   * caller_ip and actor_id are erasable by the catalog-based GDPR erasure: actor_id + tenant_id make the table a
--     qodiqa_erasure_targets() target automatically, and qodiqa_erase_subject() (re-created below, one added line)
--     nulls caller_ip in the same statement. The step JSON never holds IP or identity.
--   * retention = the NON-ENFORCEMENT OPERATIONAL policy's period, never indefinite: src/core/audit/retention.js
--     stamps retain_until and deletes expired rows (qodiqa_retention: SELECT, UPDATE, DELETE below).
-- Additive; no existing table or column changes.

BEGIN;

CREATE TABLE IF NOT EXISTS request_trails (
  id                 BIGSERIAL     PRIMARY KEY,
  trail_key          TEXT          NOT NULL,               -- the request id, else the artifact id, of its steps
  request_ids        UUID[]        NOT NULL DEFAULT '{}',  -- every request_id its steps carry
  artifact_ids       TEXT[]        NOT NULL DEFAULT '{}',  -- every artifact_id its steps carry
  tenant_id          VARCHAR(128),
  actor_id           VARCHAR(128),                         -- identity id (personal data; erasure target)
  caller_ip          TEXT,                                 -- caller IP (personal data; scrubbed by erasure)
  steps              JSONB         NOT NULL,               -- [{t,at,r,a,tr,sp,o,ip?,id?,x?}] — see centralStore.js
  first_occurred_at  TIMESTAMPTZ   NOT NULL,
  last_occurred_at   TIMESTAMPTZ   NOT NULL,
  created_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  retain_until       TIMESTAMPTZ,
  legal_hold         BOOLEAN       NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_request_trails_request_ids  ON request_trails USING GIN (request_ids);
CREATE INDEX IF NOT EXISTS idx_request_trails_artifact_ids ON request_trails USING GIN (artifact_ids);
CREATE INDEX IF NOT EXISTS idx_request_trails_retain_until ON request_trails (retain_until) WHERE retain_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_request_trails_actor        ON request_trails (actor_id) WHERE actor_id IS NOT NULL;

ALTER TABLE request_trails ENABLE ROW LEVEL SECURITY;
ALTER TABLE request_trails FORCE ROW LEVEL SECURITY;

-- The request-serving role only appends (centralStore's batched writer). It cannot read, update or delete.
GRANT INSERT ON request_trails TO qodiqa_app;
GRANT USAGE ON SEQUENCE request_trails_id_seq TO qodiqa_app;
DROP POLICY IF EXISTS rt_app_insert ON request_trails;
CREATE POLICY rt_app_insert ON request_trails FOR INSERT TO qodiqa_app WITH CHECK (true);

-- Retention (same shape as platform_audit_events, migration 038: SELECT visibility gates UPDATE/DELETE).
GRANT SELECT, UPDATE, DELETE ON request_trails TO qodiqa_retention;
DROP POLICY IF EXISTS rt_retention_select ON request_trails;
DROP POLICY IF EXISTS rt_retention_update ON request_trails;
DROP POLICY IF EXISTS rt_retention_delete ON request_trails;
CREATE POLICY rt_retention_select ON request_trails FOR SELECT TO qodiqa_retention USING (true);
CREATE POLICY rt_retention_update ON request_trails FOR UPDATE TO qodiqa_retention USING (true) WITH CHECK (true);
CREATE POLICY rt_retention_delete ON request_trails FOR DELETE TO qodiqa_retention USING (true);

-- The RBAC-gated ops console reads trails like it reads platform_audit_events (migration 053 pattern): a SECURITY
-- DEFINER full read, executable by qodiqa_reporting only, filtered by the caller.
CREATE OR REPLACE FUNCTION qodiqa_request_trails_by_ids(p_request_id uuid, p_artifact_id text)
RETURNS SETOF request_trails
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM request_trails
   WHERE (p_request_id IS NOT NULL AND p_request_id = ANY(request_ids))
      OR (p_artifact_id IS NOT NULL AND p_artifact_id = ANY(artifact_ids))
$$;
REVOKE ALL ON FUNCTION qodiqa_request_trails_by_ids(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_request_trails_by_ids(uuid, text) TO qodiqa_reporting;

-- Decision facts from the audit chain, for the same console: exactly the fields AUDIT_EXECUTION_RECORDED reported.
CREATE OR REPLACE FUNCTION qodiqa_audit_chain_decisions(p_artifact_ids text[])
RETURNS TABLE (artifact_id text, decision text, policy_hash text, provider text, entry_hash text)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT ac.artifact_id::text, ac.decision::text, ac.policy_hash::text, ac.provider, ac.hash::text
    FROM audit_chain ac
   WHERE ac.artifact_id = ANY(p_artifact_ids)
$$;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_decisions(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_decisions(text[]) TO qodiqa_reporting;

-- erasure: identical to migration 063's definition except ONE added CASE branch (request_trails → caller_ip).
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
               -- step 6 (migration 069): the per-request trail's caller IP is personal data of the same subject.
               WHEN 'request_trails'     THEN ', caller_ip = NULL'
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

COMMENT ON TABLE request_trails IS
  'one compact row per request holding the step list of the aggregated routine events. caller_ip/actor_id are personal data; retention = the OPERATIONAL policy period, never indefinite.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (69, 'w10_request_trails', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
