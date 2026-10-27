-- QODIQA PostgreSQL Schema — Migration 096
-- Finding: global kill switch
-- Purpose: let the control plane hold the kill-switch record. control_plane_records (migration 066) restricts `store` to a
--          closed list by a CHECK constraint; this migration adds 'kill_switch' to that list and changes nothing else.
--
-- Additive only: the constraint is replaced by one that accepts a strict superset of the old values, so no existing row
-- is affected, no privilege changes, and the row-level security policy, the guard trigger (version +1, no resurrection of a
-- deleted row) and the runtime role's grants (qodiqa_control: SELECT, INSERT, UPDATE) apply to the new store unchanged.
-- Idempotent: DROP ... IF EXISTS, then ADD (re-running leaves the same constraint).
--
-- The record itself is { active, scope, eventId, operatorId, reason, changedAt, seq, mac } with a MAC over its content
-- (macKeyring purpose KILL_SWITCH); a record without a valid MAC is treated as ACTIVE by every replica.

BEGIN;

ALTER TABLE control_plane_records DROP CONSTRAINT IF EXISTS control_plane_records_store_check;
ALTER TABLE control_plane_records ADD CONSTRAINT control_plane_records_store_check CHECK (store IN (
  'rbac_user', 'rbac_custom_role', 'tenant', 'organization',
  'portal_user', 'policy', 'signing_identity', 'signing_key_status', 'kill_switch'));

COMMIT;
