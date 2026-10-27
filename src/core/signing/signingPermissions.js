'use strict';

/**
 * Signing Permission Matrix — TRUST-1 remediation.
 *
 * Separate from src/core/rbac/roles.js on purpose: RBAC roles/permissions
 * model human operators of the admin console (admin/auditor/compliance/
 * operator/viewer). Signing identities are machine callers (SDKs, CI/CD
 * pipelines, service accounts) with a fundamentally different lifecycle and
 * scoping model (tenant + environment + provider scope, not console roles).
 * Reusing the RBAC role set for them would conflate two identity domains.
 *
 * This is intentionally a flat permission set, not a role hierarchy — today
 * there is exactly one capability a signing identity can hold. It exists as
 * its own module (rather than a hardcoded boolean) so future capabilities
 * (e.g. requesting key rotation, signing for additional bound-path classes)
 * can be added here without changing the store or middleware shape.
 */

const SIGNING_PERMISSIONS = Object.freeze(new Set([
  'SIGN_ARTIFACT',
]));

function isValidSigningPermission(permission) {
  return typeof permission === 'string' && SIGNING_PERMISSIONS.has(permission);
}

function isSigningPermitted(permissions, permission) {
  if (!Array.isArray(permissions)) return false;
  if (!isValidSigningPermission(permission)) return false;
  return permissions.includes(permission);
}

module.exports = {
  SIGNING_PERMISSIONS,
  isValidSigningPermission,
  isSigningPermitted,
};
