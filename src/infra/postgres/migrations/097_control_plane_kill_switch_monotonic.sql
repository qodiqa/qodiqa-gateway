-- QODIQA PostgreSQL Schema — Migration 097
-- Finding: verifier defect 1 (kill switch could be lowered by tombstoning or rolling back its control-plane record)
-- Purpose: make the guard trigger of control_plane_records refuse, for store 'kill_switch' only, the two writes that silently
--          lower the switch: (a) soft-deleting the record (a missing record reads as "never activated"), and (b) a data change
--          whose `seq` does not strictly increase (rolling back to an older, validly signed, inactive record).
--
-- Additive: CREATE OR REPLACE of the function body — every rule of migration 066 is kept verbatim and one branch is added for
-- the new store; no row is touched and no privilege changes. Ownership stays qodiqa_owner (migration 081).
-- Idempotent: re-running leaves the same function.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

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

  IF NEW.store = 'kill_switch' THEN
    IF NEW.deleted AND NOT OLD.deleted THEN
      RAISE EXCEPTION 'control_plane_records: the kill-switch record cannot be deleted (a missing record reads as inactive)'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.data IS DISTINCT FROM OLD.data THEN
      IF NOT (COALESCE(NEW.data->>'seq', '') ~ '^[0-9]{1,15}$' AND COALESCE(OLD.data->>'seq', '') ~ '^[0-9]{1,15}$')
         OR (NEW.data->>'seq')::bigint <= (OLD.data->>'seq')::bigint THEN
        RAISE EXCEPTION 'control_plane_records: the kill-switch seq must strictly increase (% -> %)', OLD.data->>'seq', NEW.data->>'seq'
          USING ERRCODE = 'check_violation';
      END IF;
    END IF;
  END IF;

  NEW.change_xid := pg_current_xact_id();
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_owner') THEN
    ALTER FUNCTION qodiqa_control_plane_guard() OWNER TO qodiqa_owner;
  END IF;
END
$$;

COMMENT ON FUNCTION qodiqa_control_plane_guard() IS
  'control_plane_records guard (066): version +1, no resurrection, signing-key status forward-only; kill_switch: no soft-delete, seq strictly increasing (097)';

COMMIT;
