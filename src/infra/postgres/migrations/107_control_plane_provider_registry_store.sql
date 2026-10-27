-- QODIQA PostgreSQL Schema — Migration 107
-- Finding: dynamic registry of OpenAI-compatible providers
-- Purpose: let the control plane hold provider-registry records. control_plane_records (migration 066) restricts `store` to a
--          closed list by a CHECK constraint; this migration adds 'provider_registry' to that list and changes nothing else.
--
-- Additive only: the constraint is replaced by one that accepts a strict superset of the old values, so no existing row
-- is affected, no privilege changes, and the row-level security policy, the guard trigger (version +1, no resurrection of a
-- deleted row) and the runtime role's grants (qodiqa_control: SELECT, INSERT, UPDATE — never DELETE) apply to the new store unchanged.
-- Idempotent: DROP ... IF EXISTS, then ADD (re-running leaves the same constraint).
--
-- A record is { id, displayName, baseUrl, apiKeyEnv (the NAME of an environment variable, never a key), models, defaultModel,
-- timeoutMs, maxTokens, failoverProvider, enabled, ..., revision, mac } with a MAC over its content (macKeyring purpose
-- PROVIDER_REGISTRY); a record without a valid MAC is not callable.

BEGIN;

ALTER TABLE control_plane_records DROP CONSTRAINT IF EXISTS control_plane_records_store_check;
ALTER TABLE control_plane_records ADD CONSTRAINT control_plane_records_store_check CHECK (store IN (
  'rbac_user', 'rbac_custom_role', 'tenant', 'organization',
  'portal_user', 'policy', 'signing_identity', 'signing_key_status', 'kill_switch', 'provider_registry'));

COMMIT;
