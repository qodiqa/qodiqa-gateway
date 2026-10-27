-- QODIQA PostgreSQL Migration 066
-- the control plane moves to PostgreSQL.
--
-- One table holds every control-plane record, keyed by (store, record_id), with
-- the record itself as JSONB. The stores (src/core/controlPlane/collection.js)
-- keep a per-replica snapshot and pull changes incrementally by change_xid:
--
--   version     monotonic per row. A write names the version it read
--               (UPDATE ... WHERE version = $expected); a stale replica's write
--               matches no row and is refused (409 CONTROL_PLANE_VERSION_CONFLICT).
--               The trigger below makes the rule structural: every data change
--               is exactly version + 1.
--   change_xid  the writing transaction (pg_current_xact_id()). Replicas pull
--               rows with change_xid >= the xmin horizon of their previous pull,
--               so a transaction that commits late is never skipped.
--   deleted     soft delete (tombstone). A deleted record can never be
--               un-deleted (trigger), so no replica can resurrect a removed user
--               or identity, whatever it has cached.
--   last_used_at  observability only (/sign's touchLastUsed, coalesced to once
--               per identity per minute). Changing it alone does not move version.
--
-- Signing-key status (store = 'signing_key_status') is forward-only in the
-- database as well: active -> deprecated -> archived, and any -> revoked,
-- which is terminal. A stale replica cannot re-activate a key.
--
-- Privileges: qodiqa_control (065) gets SELECT/INSERT/UPDATE — never DELETE —
-- through an RLS policy; qodiqa_app and every other role get nothing. FORCE RLS
-- is on. Hard deletes are refused by trigger for any role without BYPASSRLS.
--
-- IDENTITY: table owner — qodiqa_mig on deployments, qodiqa_test on disposable DBs.

BEGIN;

CREATE TABLE IF NOT EXISTS control_plane_records (
  store         TEXT        NOT NULL CHECK (store IN (
                  'rbac_user', 'rbac_custom_role', 'tenant', 'organization',
                  'portal_user', 'policy', 'signing_identity', 'signing_key_status')),
  record_id     TEXT        NOT NULL CHECK (char_length(record_id) BETWEEN 1 AND 256),
  data          JSONB       NOT NULL,
  version       BIGINT      NOT NULL DEFAULT 1 CHECK (version >= 1),
  deleted       BOOLEAN     NOT NULL DEFAULT false,
  change_xid    XID8        NOT NULL DEFAULT pg_current_xact_id(),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by    TEXT,
  last_used_at  TIMESTAMPTZ,
  PRIMARY KEY (store, record_id)
);

CREATE INDEX IF NOT EXISTS idx_control_plane_records_change_xid
  ON control_plane_records (change_xid);

CREATE UNIQUE INDEX IF NOT EXISTS uq_control_plane_rbac_username
  ON control_plane_records (lower(data->>'username'))
  WHERE store = 'rbac_user' AND NOT deleted;

COMMENT ON TABLE control_plane_records IS
  'authoritative control-plane state (identities, RBAC, tenants, orgs, portal users, policy, signing-key status). Row-versioned, soft-deleted, pulled by change_xid.';

CREATE OR REPLACE FUNCTION qodiqa_control_plane_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  old_rank INT;
  new_rank INT;
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolbypassrls) THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'control_plane_records: hard delete refused (records are soft-deleted)'
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.version <> 1 THEN
      RAISE EXCEPTION 'control_plane_records: a new record starts at version 1' USING ERRCODE = 'check_violation';
    END IF;
    NEW.change_xid := pg_current_xact_id();
    NEW.updated_at := now();
    RETURN NEW;
  END IF;

  -- UPDATE
  IF NEW.store <> OLD.store OR NEW.record_id <> OLD.record_id OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'control_plane_records: store, record_id and created_at are immutable' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.deleted AND NOT NEW.deleted THEN
    RAISE EXCEPTION 'control_plane_records: a deleted record cannot be restored (%/%)', OLD.store, OLD.record_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.data IS NOT DISTINCT FROM OLD.data AND NEW.deleted = OLD.deleted THEN
    IF NEW.version <> OLD.version THEN
      RAISE EXCEPTION 'control_plane_records: a touch-only update must not change version' USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'control_plane_records: version must advance by exactly 1 (% -> %)', OLD.version, NEW.version
      USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.store = 'signing_key_status' THEN
    old_rank := CASE OLD.data->>'status' WHEN 'active' THEN 0 WHEN 'deprecated' THEN 1 WHEN 'archived' THEN 2 WHEN 'revoked' THEN 3 ELSE -1 END;
    new_rank := CASE NEW.data->>'status' WHEN 'active' THEN 0 WHEN 'deprecated' THEN 1 WHEN 'archived' THEN 2 WHEN 'revoked' THEN 3 ELSE -1 END;
    IF new_rank < 0 OR new_rank < old_rank THEN
      RAISE EXCEPTION 'control_plane_records: signing-key status may only move forward (% -> %)', OLD.data->>'status', NEW.data->>'status'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  NEW.change_xid := pg_current_xact_id();
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS control_plane_records_guard ON control_plane_records;
CREATE TRIGGER control_plane_records_guard
  BEFORE INSERT OR UPDATE OR DELETE ON control_plane_records
  FOR EACH ROW EXECUTE FUNCTION qodiqa_control_plane_guard();

REVOKE ALL ON control_plane_records FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_control_plane_guard() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON control_plane_records TO qodiqa_control;

ALTER TABLE control_plane_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_plane_records FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS control_plane_records_control ON control_plane_records;
CREATE POLICY control_plane_records_control ON control_plane_records
  FOR ALL TO qodiqa_control USING (true) WITH CHECK (true);

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (66, 'w6_control_plane_records', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
