'use strict';

// the floor merge lives one layer up (tenantPolicyFloor.js) — this
// stays the plain tenantId → policy-array map it always was, so a raw
// setPolicies()/getPoliciesForTenant() round-trip is still byte-identical.
const tenantPolicyFloor = require('./tenantPolicyFloor');

const _policies = new Map(); // tenantId → policy array

function setPolicies(tenantId, policies) {
  if (typeof tenantId !== 'string' || !tenantId) throw new Error('TENANT_CONTEXT_MISSING');
  _policies.set(tenantId, policies);
}

function getPoliciesForTenant(tenantId) {
  if (!tenantId) return null;
  return _policies.get(tenantId) || null;
}

/**
 * the effective set an evaluation should actually use: floor ∪ the
 * tenant's own stored set. Returns
 * null exactly when getPoliciesForTenant() would (no stored set at all — the
 * existing GLOBAL_FALLBACK semantics are unchanged), so every consumer's
 * null branch keeps meaning what it always meant. Recomputed on every call
 * from whatever is currently stored — no write-time gap.
 */
function getEffectivePoliciesForTenant(tenantId) {
  const raw = getPoliciesForTenant(tenantId);
  if (!raw) return null;
  return tenantPolicyFloor.mergeForEvaluation(raw);
}

function hasPolicies(tenantId) {
  return _policies.has(tenantId);
}

function deletePolicies(tenantId) {
  _policies.delete(tenantId);
}

function _reset() { _policies.clear(); }

module.exports = {
  setPolicies, getPoliciesForTenant, getEffectivePoliciesForTenant, hasPolicies, deletePolicies, _reset,
};
