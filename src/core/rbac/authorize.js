'use strict';

/**
 * RBAC Authorization Composition Layer
 *
 * `./roles.js` remains the single source of truth for the fixed,
 * five-role canonical permission matrix — it is unmodified by this module
 * and unaware that custom roles exist. `./customRoleStore.js` is the single
 * source of truth for operator-defined custom roles (each a named
 * permission set, always identified by a `custom:`-prefixed ID). This
 * module composes the two into the one function callers actually need:
 * "is this role, whatever kind it is, permitted to do this."
 *
 * `src/middleware/rbac.js`'s `createRequirePermission()` calls `isPermitted`
 * from here (not from `./roles.js` directly) so that RBAC-gated routes
 * transparently support both canonical and custom roles without any
 * per-route change. Behavior for canonical roles is byte-for-byte identical
 * to calling `./roles.js`'s own `isPermitted` — this module adds a branch,
 * it does not alter the existing one.
 */

const rolesModule = require('./roles');
const customRoleStore = require('./customRoleStore');

/**
 * True if `role` is either one of the five canonical roles, or an existing,
 * enabled-or-not custom role ID. Mirrors `./roles.js`'s `isValidRole` for
 * canonical roles; a disabled custom role is still a "valid role" in the
 * sense that it identifies a real, addressable role — `isPermitted` is
 * where "disabled" actually takes effect (always denies).
 */
function isValidRoleOrCustom(role) {
  if (rolesModule.isValidRole(role)) return true;
  return customRoleStore.isCustomRoleId(role) && !!customRoleStore.getRole(role);
}

/**
 * Deterministic, fail-closed permission check across both role kinds.
 * Returns true only when role is a valid, enabled role of either kind AND
 * it grants the requested permission. Any missing, invalid, or disabled
 * input returns false — never throws.
 */
function isPermitted(role, permission) {
  if (!role || !permission) return false;
  if (rolesModule.isValidRole(role)) {
    return rolesModule.isPermitted(role, permission);
  }
  if (customRoleStore.isCustomRoleId(role)) {
    return customRoleStore.isPermittedForRole(role, permission);
  }
  return false;
}

/**
 * Every permission granted to a role, canonical or custom. [] for an
 * unknown or invalid role.
 */
function permissionsForRole(role) {
  if (rolesModule.isValidRole(role)) return rolesModule.permissionsForRole(role);
  if (customRoleStore.isCustomRoleId(role)) return customRoleStore.permissionsForCustomRole(role);
  return [];
}

module.exports = {
  isValidRoleOrCustom,
  isPermitted,
  permissionsForRole,
  // Re-exported for call sites that only need permission-name validity
  // (unaffected by custom roles — custom roles only ever grant existing
  // canonical permission names, never introduce new ones).
  isValidPermission: rolesModule.isValidPermission,
};
