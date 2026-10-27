-- QODIQA PostgreSQL Migration 056
-- SECURITY DEFINER full-read bypass
-- function for EmergencyPolicyService.sweepExpired(), the same defect class
-- already remediated for centralStore/chainStore/AlertStore/retention
-- (migration 053): sweepExpired() must see EVERY tenant's PENDING
-- policy_emergency_activations rows to auto-revert ones that expired without
-- retrospective approval, but ran on a plain pool.query() with no tenant
-- context, so pea_tenant_select's nullable RLS policy silently restricted it
-- to platform-level (tenant_id IS NULL) activations only -- a tenant-scoped
-- emergency activation that expired without retrospective approval was never
-- auto-reverted by this sweep (compensating-control failure, documented as
-- D7 and inline in
-- EmergencyPolicyService.js's sweepExpired()).
--
-- This function is reached ONLY by sweepExpired(), which is itself reached
-- only via the RBAC-gated POST /policy-governance/emergency/sweep admin
-- route (opsAuth) -- never by tenant-scoped business logic. RBAC is the real
-- authorization boundary here, unchanged by this migration.
--
-- Narrow, read-only, STABLE bypass mirroring qodiqa_audit_chain_full_read()
-- (migration 044) and migration 053's functions EXACTLY: no parameters, no
-- filtering (the calling application SQL supplies WHERE/ORDER/LIMIT as an
-- outer query against the function's result set, same idiom
-- centralStore.js/chainStore.js/AlertStore.js/retention.js already use via
-- migration 053). Does not touch INSERT/UPDATE/DELETE. Does not weaken FORCE
-- ROW LEVEL SECURITY. Does not grant BYPASSRLS to any role. ADDITIVE ONLY:
-- no existing migration is edited, no existing policy on any table is
-- touched, weakened, or removed.
--
-- IDEMPOTENT: CREATE OR REPLACE FUNCTION. Safe to re-run.

BEGIN;

-- ── policy_emergency_activations ─────────────────────────────────────────────

CREATE OR REPLACE FUNCTION qodiqa_policy_emergency_activations_full_read()
RETURNS SETOF policy_emergency_activations
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM policy_emergency_activations
$$;

COMMENT ON FUNCTION qodiqa_policy_emergency_activations_full_read() IS
  'SECURITY DEFINER: bypasses policy_emergency_activations''s per-tenant RLS (pea_tenant_select) to return every activation, every tenant. Mirrors qodiqa_audit_chain_full_read() (migration 044) and migration 053''s functions. Used by EmergencyPolicyService.js''s sweepExpired() ONLY -- reached only via the RBAC-gated POST /policy-governance/emergency/sweep admin route (opsAuth), never by tenant-scoped business logic. activate()/retroApprove()/get()/list() are unaffected by this function -- they keep their existing tenant-context / RBAC-reviewed access patterns (D3/D5/D6).';

REVOKE ALL ON FUNCTION qodiqa_policy_emergency_activations_full_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_policy_emergency_activations_full_read() TO qodiqa_app, qodiqa_read;

-- ── Migration record ─────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (56, 'rem_ep201_emergency_sweep_full_read_bypass', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
