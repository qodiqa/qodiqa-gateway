'use strict';

/**
 * RBAC Custom Role Store
 *
 * Control-plane-backed registry (PostgreSQL in production; memory mode seeded once from the legacy file in dev/test) of operator-defined custom roles. A
 * custom role is a named, admin-managed collection of permissions drawn
 * from the fixed permission matrix in `./roles.js` — it never introduces a
 * new permission, and it never changes what the five built-in roles
 * (admin/auditor/compliance/operator/viewer) can do.
 *
 * Every custom role ID is namespaced under the `custom:` prefix
 * (`CUSTOM_ROLE_ID_PREFIX`), which guarantees it can never collide with a
 * canonical role string — today's five or any added in the future — without
 * needing to hardcode an exclusion list against `./roles.js`.
 *
 * This module intentionally does NOT depend on `./store.js` (the RBAC user
 * store) to avoid a circular require. Composing custom-role authorization
 * with the canonical matrix is done one layer up, in `./authorize.js`;
 * checking whether a role is "in use" by any user before deletion is done
 * by the route layer (`src/api/routes/rbacAdmin.js`), which already depends
 * on both stores.
 *
 * Legacy seed file: QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH, default data/rbac-custom-roles.json — read once in memory mode, never
 * written. Persistence and cross-replica consistency are the control plane's (see "Storage" below), mirroring
 * `./store.js`.
 */

const { emit } = require('../../../services/logger');
const { isValidPermission, ROLE_SET } = require('./roles');
const cp = require('../controlPlane');
const { Collection } = require('../controlPlane/collection');
const { readSeed } = require('../controlPlane/seed');

// ── Custom role ID namespace ──────────────────────────────────────────────────
//
// Every custom role ID starts with this prefix. This is what lets a custom
// role and a canonical role never collide: `admin` (canonical) and
// `custom:admin` (a custom role someone tried to name "admin") are always
// distinct strings, so a custom role can never be mistaken for — or silently
// shadow — a built-in role.

const CUSTOM_ROLE_ID_PREFIX = 'custom:';

function isCustomRoleId(id) {
  return typeof id === 'string' && id.startsWith(CUSTOM_ROLE_ID_PREFIX);
}

// ── Storage ───────────────────────────────────────────────────────
// Records (keyed by role ID, e.g. "custom:policy-reviewer") live in the
// control plane — PostgreSQL in production, so disabling a role on one replica
// revokes its permissions on every replica within the 5 s bound. Dev/test
// memory mode seeds once from the legacy file and never writes it.

function _seed() {
  const s = readSeed('rbac_custom_role');
  if (s.exists && s.raw !== null && Object.keys(s.records).length === 0) {
    try { JSON.parse(s.raw); } catch (e) { emit('ERROR', 'RBAC_CUSTOM_ROLE_STORE_LOAD_FAILED', { path: s.path, error: e.message }); }
  }
  return s.records;
}

const _col = new Collection('rbac_custom_role', { seed: _seed });

function _ensureLoaded() { _col.ensure(); }

// ── Error class ───────────────────────────────────────────────────────────────

class CustomRoleStoreError extends Error {
  constructor(message, code, details) {
    super(message);
    this.name = 'CustomRoleStoreError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

// ── Validation ────────────────────────────────────────────────────────────────

const ROLE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 _.\-]{1,79}$/;
const ROLE_SLUG_RE = /^[a-z0-9][a-z0-9_-]{1,49}$/;

function _slugify(name) {
  return String(name)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-+|-+$/g, '');
}

function _validateName(name) {
  if (typeof name !== 'string' || !ROLE_NAME_RE.test(name)) {
    throw new CustomRoleStoreError(
      'Role name must be 2-80 characters: letters, numbers, spaces, and _.- (must start with a letter or number)',
      'INVALID_NAME'
    );
  }
}

function _validateSlug(slug) {
  if (!ROLE_SLUG_RE.test(slug)) {
    throw new CustomRoleStoreError(
      `Role name "${slug}" does not produce a usable identifier — use letters, numbers, hyphens, or underscores`,
      'INVALID_NAME'
    );
  }
  if (ROLE_SET.has(slug)) {
    throw new CustomRoleStoreError(
      `"${slug}" is a reserved, built-in role name and cannot be used for a custom role`,
      'RESERVED_ROLE_NAME'
    );
  }
}

/**
 * Validate a permissions array against the fixed permission matrix.
 * Throws CustomRoleStoreError with .code:
 *   INVALID_PERMISSIONS_STRUCTURE — not an array, or contains a non-string/empty entry
 *   EMPTY_PERMISSIONS             — array has zero entries
 *   UNKNOWN_PERMISSION            — one or more entries are not real permission names
 *   DUPLICATE_PERMISSION          — one or more entries repeat
 * Returns a fresh array copy on success (exported for the standalone
 * "Validate Permissions" API and reused internally by create/update).
 */
function validatePermissionsList(permissions) {
  if (!Array.isArray(permissions)) {
    throw new CustomRoleStoreError('permissions must be an array', 'INVALID_PERMISSIONS_STRUCTURE');
  }
  if (permissions.length === 0) {
    throw new CustomRoleStoreError('permissions must contain at least one permission', 'EMPTY_PERMISSIONS');
  }

  const seen       = new Set();
  const duplicates = new Set();
  const unknown     = [];

  for (const p of permissions) {
    if (typeof p !== 'string' || !p) {
      throw new CustomRoleStoreError('every permission must be a non-empty string', 'INVALID_PERMISSIONS_STRUCTURE');
    }
    if (seen.has(p)) duplicates.add(p);
    seen.add(p);
    if (!isValidPermission(p)) unknown.push(p);
  }

  if (unknown.length > 0) {
    throw new CustomRoleStoreError(
      `Unknown permission(s): ${unknown.join(', ')}`,
      'UNKNOWN_PERMISSION',
      { unknown }
    );
  }
  if (duplicates.size > 0) {
    throw new CustomRoleStoreError(
      `Duplicate permission(s): ${[...duplicates].join(', ')}`,
      'DUPLICATE_PERMISSION',
      { duplicates: [...duplicates] }
    );
  }

  return [...permissions];
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

/**
 * Create a new custom role.
 * The role's ID is derived from `name` (slugified) and is immutable —
 * renaming a role via updateRole() never changes its ID, so existing user
 * assignments never silently break on rename.
 *
 * Throws CustomRoleStoreError with .code:
 *   INVALID_NAME          — name fails validation or slugifies to nothing usable
 *   RESERVED_ROLE_NAME     — slug collides with a canonical role name
 *   ROLE_EXISTS            — a custom role with this ID already exists
 *   (+ validatePermissionsList()'s codes)
 */
function createRole({ name, description = '', permissions, createdBy = 'system' }) {
  _ensureLoaded();
  _validateName(name);
  const slug = _slugify(name);
  _validateSlug(slug);

  const id = CUSTOM_ROLE_ID_PREFIX + slug;
  if (_col.get(id)) {
    throw new CustomRoleStoreError(`A custom role named "${name}" already exists`, 'ROLE_EXISTS');
  }

  const validPermissions = validatePermissionsList(permissions);
  const now  = new Date().toISOString();
  const role = Object.freeze({
    id,
    name,
    description: typeof description === 'string' ? description : '',
    permissions: Object.freeze(validPermissions),
    enabled:     true,
    builtIn:     false,
    createdAt:   now,
    createdBy,
    updatedAt:   now,
    updatedBy:   createdBy,
  });

  return cp.after(_col.put(id, role, { create: true, updatedBy: createdBy }), () => {
    emit('INFO', 'RBAC_CUSTOM_ROLE_CREATED', { roleId: id, name, permissions: validPermissions, createdBy });
    return { ...role };
  });
}

/**
 * Get a custom role by ID. Returns null if not found (including when `id`
 * is not even in the `custom:` namespace).
 */
function getRole(id) {
  if (!isCustomRoleId(id)) return null;
  _ensureLoaded();
  const r = _col.get(id);
  return r ? { ...r } : null;
}

/**
 * List all custom roles (copies, sorted by createdAt ascending).
 */
function listRoles() {
  _ensureLoaded();
  return _col.values()
    .map(r => ({ ...r }))
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

/**
 * Update a custom role's name, description, permissions, or enabled flag.
 * The role's `id` never changes, even when `name` changes.
 *
 * Throws CustomRoleStoreError with .code:
 *   NOT_FOUND     — role ID not in store
 *   INVALID_NAME  — new name fails validation
 *   (+ validatePermissionsList()'s codes, if permissions provided)
 */
function updateRole(id, { name, description, permissions, enabled, updatedBy = 'system' }) {
  _ensureLoaded();
  const existing = _col.get(id);
  if (!existing) {
    throw new CustomRoleStoreError(`Custom role "${id}" not found`, 'NOT_FOUND');
  }

  if (name !== undefined) _validateName(name);
  const newPermissions = permissions !== undefined
    ? validatePermissionsList(permissions)
    : existing.permissions;

  const updated = Object.freeze({
    ...existing,
    name:        name        !== undefined ? name        : existing.name,
    description: description !== undefined ? description : existing.description,
    permissions: Object.freeze(newPermissions),
    enabled:     enabled     !== undefined ? enabled      : existing.enabled,
    updatedAt:   new Date().toISOString(),
    updatedBy,
  });

  return cp.after(_col.put(id, updated, { updatedBy }), () => {
    emit('INFO', 'RBAC_CUSTOM_ROLE_UPDATED', {
      roleId: id, updatedBy,
      changes: { name, description, permissions, enabled },
    });
    return { ...updated };
  });
}

/**
 * Delete a custom role permanently.
 * Throws CustomRoleStoreError:
 *   NOT_FOUND — role ID not in store
 *
 * Callers are responsible for checking whether any user is currently
 * assigned this role before calling this function (see
 * `src/api/routes/rbacAdmin.js`'s DELETE /rbac/roles/:id, which checks
 * `store.listUsers()` and returns 409 unless `?force=true` is passed) — this
 * module deliberately does not depend on the user store to avoid a
 * circular require.
 */
function deleteRole(id, { deletedBy = 'system' } = {}) {
  _ensureLoaded();
  const existing = _col.get(id);
  if (!existing) {
    throw new CustomRoleStoreError(`Custom role "${id}" not found`, 'NOT_FOUND');
  }

  return cp.after(_col.remove(id, { updatedBy: deletedBy }), () => {
    emit('INFO', 'RBAC_CUSTOM_ROLE_DELETED', { roleId: id, name: existing.name, deletedBy });
  });
}

/**
 * Fail-closed permission check for a custom role. Returns false (never
 * throws) for: a non-custom-role ID, a role that doesn't exist, a disabled
 * role, or a permission the role's set doesn't include. Disabling a role
 * (`enabled: false`) immediately revokes every permission it grants without
 * needing to touch any user record — the same fail-closed pattern
 * `src/middleware/rbac.js` uses everywhere else.
 */
function isPermittedForRole(id, permission) {
  if (!isCustomRoleId(id) || !permission) return false;
  _ensureLoaded();
  const role = _col.get(id);
  if (!role || !role.enabled) return false;
  return role.permissions.includes(permission);
}

/**
 * Returns every permission a custom role currently, effectively grants —
 * i.e. what isPermittedForRole() would allow for each entry. Returns [] for
 * a non-custom-role ID, an unknown role, or a disabled role, mirroring
 * isPermittedForRole()'s fail-closed behavior so effective-permission
 * introspection (e.g. GET /rbac/users/:id/permissions) never shows a
 * permission the role can't currently actually use.
 */
function permissionsForCustomRole(id) {
  if (!isCustomRoleId(id)) return [];
  _ensureLoaded();
  const role = _col.get(id);
  if (!role || !role.enabled) return [];
  return [...role.permissions];
}

// ── Testing helpers ───────────────────────────────────────────────────────────

function _reset() {
  _col._reset();
}

// Memory mode: drop the snapshot and re-seed from the legacy file (tests).
function _reload() {
  _col._reset();
  _ensureLoaded();
}

// Tests / offline dev tooling (memory mode only): write the snapshot as the seed fixture.
function exportSeedFixture() { return _col.exportSeedFixture(); }

module.exports = {
  CUSTOM_ROLE_ID_PREFIX,
  isCustomRoleId,
  validatePermissionsList,
  createRole,
  getRole,
  listRoles,
  updateRole,
  deleteRole,
  isPermittedForRole,
  permissionsForCustomRole,
  _reset,
  _reload,
  exportSeedFixture,
  CustomRoleStoreError,
};
