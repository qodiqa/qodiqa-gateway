'use strict';

const { isControlPlaneError } = require('../../core/controlPlane');

/**
 * RBAC Administration Router
 *
 * Factory: createRbacAdminRouter({ store, customRoleStore, requirePermission })
 *
 * Mounted at /rbac in server.js, behind the full ops middleware stack
 * plus RBAC resolution.  All routes require MANAGE_USERS or READ_USERS.
 *
 * Routes:
 * GET /rbac/roles — list role definitions
 *   POST   /rbac/roles                  — create custom role     [MANAGE_USERS]
 *   POST   /rbac/roles/validate         — validate a permission set without persisting [READ_USERS]
 *   GET    /rbac/roles/:id              — get one role (built-in or custom)
 *   PATCH  /rbac/roles/:id              — update a custom role   [MANAGE_USERS]
 *   PUT    /rbac/roles/:id              — DEPRECATED alias of PATCH above; see API-9 note below
 *   DELETE /rbac/roles/:id              — delete a custom role   [MANAGE_USERS]
 *   GET    /rbac/permissions            — list permission matrix
 *   GET    /rbac/users                  — list all users         [READ_USERS]
 *   POST   /rbac/users                  — create user            [MANAGE_USERS]
 *   GET    /rbac/users/:id              — get user by ID         [READ_USERS]
 *   PATCH  /rbac/users/:id              — update user            [MANAGE_USERS]
 *   PUT    /rbac/users/:id              — DEPRECATED alias of PATCH above; see API-9 note below
 *   DELETE /rbac/users/:id              — delete user            [MANAGE_USERS]
 *   GET    /rbac/users/:id/permissions  — effective permissions  [READ_USERS]
 *
 * API-9 remediation: both "update" routes only ever apply a partial
 * update (at least one field, not a full resource replacement), which is
 * PATCH semantics, not PUT. PATCH is now canonical; the original PUT routes
 * keep working, unchanged, via the shared src/middleware/deprecation.js
 * helper so existing callers aren't broken. Schema-validation failures on
 * this router now return 400 (previously 422) to match the rest of the API
 * surface — 422 is reserved for post-parse business-rule violations
 * (e.g. CANNOT_MODIFY_BUILTIN, ROLE_EXISTS-adjacent store errors).
 *
 * Custom roles: the five built-in roles (admin/auditor/
 * compliance/operator/viewer) remain exactly as defined in
 * src/core/rbac/roles.js — this router never lets a caller create, modify,
 * or delete one (their `id`s never start with the `custom:` namespace a
 * custom role always uses). A custom role is a named collection of
 * permissions drawn from that same fixed matrix; the authorization engine
 * (src/core/rbac/authorize.js, used by src/middleware/rbac.js) evaluates
 * permissions, never role names, for both kinds identically. Existing
 * deployments that never create a custom role are entirely unaffected —
 * every built-in-role code path is byte-for-byte unchanged.
 */

const { Router }  = require('express');
const { emit }    = require('../../../services/logger');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { ROLES, ROLE_META, PERMISSIONS, permissionsForRole: canonicalPermissionsForRole } = require('../../core/rbac/roles');
const { permissionsForRole } = require('../../core/rbac/authorize');
const { RbacStoreError } = require('../../core/rbac/store');
const mfa = require('../../core/rbac/mfa');
const { CustomRoleStoreError } = require('../../core/rbac/customRoleStore');
const {
  createUserSchema, updateUserSchema,
  createRoleSchema, updateRoleSchema, validatePermissionsSchema,
} = require('../../validation/schemas/rbac.schema');
const { success, failure } = require('../response');
const { sendDeprecationHeaders } = require('../../middleware/deprecation');
const {
  parsePagination, paginateArray, isPaginationRequested,
} = require('../../utils/pagination');

// ── Helpers ───────────────────────────────────────────────────────────────────

// Thin adapters over the canonical envelope (src/api/response.js) that keep
// this file's existing (req, status) call-site ergonomics — the actual
// envelope shape is built in exactly one place, response.js.
function _ok(res, req, data, status = 200) {
  return success(res, data, status);
}

function _err(res, req, status, code, detail) {
  emit('WARN', `RBAC_ADMIN_${code}`, { requestId: req.requestId, detail });
  return failure(res, code, detail, status);
}

function _storeError(res, req, err) {
  // control-plane refusals keep their status — 409 stale write, 503 stale snapshot.
  if (isControlPlaneError(err)) return _err(res, req, err.status, err.code, err.message);
  if (err instanceof RbacStoreError) {
    const HTTP = {
      NOT_FOUND:        404,
      NO_API_KEY:       422,
      USERNAME_TAKEN:   409,
      INVALID_USERNAME: 422,
      INVALID_ROLE:     422,
      LAST_ADMIN:       409,
    };
    const status = HTTP[err.code] ?? 422;
    return _err(res, req, status, err.code, err.message);
  }
  if (err instanceof CustomRoleStoreError) {
    const HTTP = {
      NOT_FOUND:                    404,
      ROLE_EXISTS:                  409,
      INVALID_NAME:                 422,
      RESERVED_ROLE_NAME:           422,
      INVALID_PERMISSIONS_STRUCTURE: 422,
      EMPTY_PERMISSIONS:            422,
      UNKNOWN_PERMISSION:           422,
      DUPLICATE_PERMISSION:         422,
    };
    const status = HTTP[err.code] ?? 422;
    return _err(res, req, status, err.code, err.message);
  }
  emit('ERROR', 'RBAC_ADMIN_INTERNAL', { requestId: req.requestId, error: err.message });
  return _err(res, req, 500, 'INTERNAL_ERROR', 'An unexpected error occurred');
}

function _actor(req) {
  const h = req.rbacUser?.username;
  return typeof h === 'string' && h.trim() ? h.trim().slice(0, 64) : 'operator';
}

// ──: privilege ceiling and dual control ──────────────────────────
// MANAGE_USERS used to be a path to admin — a custom role or a user's role could carry permissions the
// caller does not hold, and a caller could change their own role. Now nobody grants what they do not hold, and
// nobody changes their own role.
// one admin could mint (and read) a working API key for another admin, or reset another admin's MFA,
// and so act as two people. A credential for ANOTHER operator is now issued over HTTP only when that operator's
// permissions are a strict subset of the caller's; a peer's or superior's key is issued out of band
// (node scripts/rbac-bootstrap-key.js --user <username>, host access required).
const _callerPerms = (req) => new Set(permissionsForRole(req.rbacUser?.role));
function _notHeld(req, permissions) {
  const held = _callerPerms(req);
  // unknown names are left to the store's own validation (422 UNKNOWN_PERMISSION)
  return [...new Set(permissions)].filter((p) => Object.prototype.hasOwnProperty.call(PERMISSIONS, p) && !held.has(p));
}
function _ceiling(req, res, permissions, what) {
  const missing = _notHeld(req, permissions);
  if (!missing.length) return true;
  emit('WARN', 'RBAC_ADMIN_PRIVILEGE_CEILING', { requestId: req.requestId, actor: _actor(req), what, missing });
  _err(res, req, 403, 'PRIVILEGE_CEILING', `You cannot ${what}: it carries permissions you do not hold (${missing.join(', ')})`);
  return false;
}
function _strictlySubordinate(req, user) {
  const theirs = permissionsForRole(user.role);
  const held = _callerPerms(req);
  return theirs.every((p) => held.has(p)) && theirs.length < held.size;
}

// ── Router factory ────────────────────────────────────────────────────────────

function createRbacAdminRouter({ store, customRoleStore, requirePermission }) {
  const router = Router();
  const _rl    = createRateLimitMiddleware('rbac_admin', { envelope: 'legacyFailure' });
  router.use(_rl);

  const _canRead   = requirePermission('READ_USERS');
  const _canManage = requirePermission('MANAGE_USERS');

  // ── GET /roles ──────────────────────────────────────────────────────────────
  // Public within the ops auth boundary — any authenticated caller can read
  // role definitions.  No user permission check required. Lists both the
  // five built-in roles and every operator-defined custom role.
  // authenticated reads now carry the same permission as their siblings.
  router.get('/roles', _canRead, (req, res) => {
    const builtIn = Object.entries(ROLE_META).map(([id, meta]) => ({
      id,
      ...meta,
      permissions: canonicalPermissionsForRole(id),
      builtIn:     true,
    }));
    const custom = customRoleStore.listRoles().map(_safeRole);
    _ok(res, req, { roles: [...builtIn, ...custom] });
  });

  // ── POST /roles ─────────────────────────────────────────────────────────────
  // Create a custom role — a named collection of permissions drawn from the
  // fixed matrix (GET /permissions). The five built-in roles are untouched;
  // this only ever adds a new "custom:"-namespaced role.
  router.post('/roles', _canManage, async (req, res) => {
    const parsed = createRoleSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return _err(res, req, 400, 'MISSING_FIELDS', parsed.error.issues[0]?.message ?? 'name and permissions are required');
    }
    const { name, description, permissions } = parsed.data;
    const actor = _actor(req);
    if (Array.isArray(permissions) && !_ceiling(req, res, permissions, 'create this role')) return;
    try {
      const role = await customRoleStore.createRole({ name, description, permissions, createdBy: actor });
      emit('INFO', 'RBAC_ADMIN_CUSTOM_ROLE_CREATED', { requestId: req.requestId, actor, roleId: role.id });
      _ok(res, req, { role: _safeRole(role) }, 201);
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // ── POST /roles/validate ─────────────────────────────────────────────────────
  // Dry-run permission validation — does not create or modify anything.
  // Registered ahead of GET/PUT/DELETE /roles/:id so "validate" is never
  // captured as a role ID.
  router.post('/roles/validate', _canRead, (req, res) => {
    const parsed = validatePermissionsSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return _err(res, req, 400, 'MISSING_FIELDS', parsed.error.issues[0]?.message ?? 'permissions is required');
    }
    try {
      const validated = customRoleStore.validatePermissionsList(parsed.data.permissions);
      _ok(res, req, { valid: true, permissions: validated });
    } catch (e) {
      if (e instanceof CustomRoleStoreError) {
        return _ok(res, req, { valid: false, code: e.code, message: e.message, details: e.details ?? null });
      }
      _storeError(res, req, e);
    }
  });

  // ── GET /roles/:id ───────────────────────────────────────────────────────────
  router.get('/roles/:id', _canRead, (req, res) => { //
    const { id } = req.params;
    if (ROLE_META[id]) {
      return _ok(res, req, { role: { id, ...ROLE_META[id], permissions: canonicalPermissionsForRole(id), builtIn: true } });
    }
    const role = customRoleStore.getRole(id);
    if (!role) return _err(res, req, 404, 'NOT_FOUND', `Role "${id}" not found`);
    _ok(res, req, { role: _safeRole(role) });
  });

  // ── PATCH /roles/:id (canonical) / PUT /roles/:id (deprecated alias) ───────
  // Always a partial update — PATCH semantics (API-9 remediation).
  async function _updateRole(req, res) {
    const { id } = req.params;
    if (ROLE_META[id]) {
      return _err(res, req, 422, 'CANNOT_MODIFY_BUILTIN', `"${id}" is a built-in role and cannot be modified`);
    }
    const parsed = updateRoleSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return _err(res, req, 400, 'MISSING_FIELDS', parsed.error.issues[0]?.message ?? 'At least one field must be provided');
    }
    const actor = _actor(req);
    if (Array.isArray(parsed.data.permissions) && !_ceiling(req, res, parsed.data.permissions, 'give this role these permissions')) return;
    try {
      const role = await customRoleStore.updateRole(id, { ...parsed.data, updatedBy: actor });
      emit('INFO', 'RBAC_ADMIN_CUSTOM_ROLE_UPDATED', { requestId: req.requestId, actor, roleId: id });
      _ok(res, req, { role: _safeRole(role) });
    } catch (e) {
      _storeError(res, req, e);
    }
  }
  router.patch('/roles/:id', _canManage, _updateRole);
  router.put('/roles/:id', _canManage, (req, res) => {
    sendDeprecationHeaders(res, {
      successorLink: `/rbac/roles/${encodeURIComponent(req.params.id)}`,
      warnEvent:     'RBAC_ADMIN_PUT_ROLE_DEPRECATED_USED',
      warnDetails:   { requestId: req.requestId, roleId: req.params.id,
        message: 'PUT /rbac/roles/:id is deprecated: this route only ever performs a partial update. Use PATCH /rbac/roles/:id instead.' },
    });
    return _updateRole(req, res);
  });

  // ── DELETE /roles/:id ────────────────────────────────────────────────────────
  // Refuses to delete a role currently assigned to any user unless
  // ?force=true is passed — a forced delete leaves those users' role
  // reference pointing at nothing, which fails closed (isPermitted denies
  // every permission for an unknown role) rather than granting anything.
  router.delete('/roles/:id', _canManage, async (req, res) => {
    const { id } = req.params;
    if (ROLE_META[id]) {
      return _err(res, req, 422, 'CANNOT_MODIFY_BUILTIN', `"${id}" is a built-in role and cannot be deleted`);
    }
    const force = req.query.force === 'true';
    if (!force) {
      const inUse = store.listUsers().filter(u => u.role === id);
      if (inUse.length > 0) {
        return _err(res, req, 409, 'ROLE_IN_USE', `Role "${id}" is assigned to ${inUse.length} user(s); pass ?force=true to delete anyway`);
      }
    }
    const actor = _actor(req);
    try {
      await customRoleStore.deleteRole(id, { deletedBy: actor });
      emit('INFO', 'RBAC_ADMIN_CUSTOM_ROLE_DELETED', { requestId: req.requestId, actor, roleId: id, forced: force });
      _ok(res, req, { deleted: true, roleId: id });
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // ── GET /permissions ────────────────────────────────────────────────────────
  router.get('/permissions', _canRead, (req, res) => { //
    const matrix = Object.entries(PERMISSIONS).map(([permission, allowedRoles]) => ({
      permission,
      allowedRoles: [...allowedRoles],
    }));
    _ok(res, req, { matrix, totalPermissions: matrix.length });
  });

  // ── GET /users ──────────────────────────────────────────────────────────────
  //
  // Opt-in pagination (API-4 remediation): omitting page/pageSize/limit/offset
  // preserves this endpoint's original unbounded response for backward
  // compatibility; supplying any of them switches to sliced output with
  // canonical pagination metadata.
  router.get('/users', _canRead, (req, res) => {
    try {
      const users = store.listUsers().map(u => _safeUser(u));
      emit('INFO', 'RBAC_ADMIN_LIST_USERS', { requestId: req.requestId, actor: _actor(req), count: users.length });
      if (!isPaginationRequested(req.query)) {
        return _ok(res, req, { users, total: users.length });
      }
      const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 500 });
      const { items, ...meta } = paginateArray(users, { page, pageSize });
      _ok(res, req, { users: items, total: users.length, ...meta });
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // ── POST /users ─────────────────────────────────────────────────────────────
  router.post('/users', _canManage, async (req, res) => {
    const parsed = createUserSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return _err(res, req, 400, 'MISSING_FIELDS', parsed.error.issues[0]?.message ?? 'username and role are required');
    }
    const { username, role, externalIdentity } = parsed.data;
    const actor = _actor(req);
    if (!_ceiling(req, res, permissionsForRole(role), `create a user with role "${role}"`)) return;

    try {
      const user = await store.createUser({ username, role, createdBy: actor, createdById: req.rbacUser?.id ?? null, externalIdentity });
      emit('INFO', 'RBAC_ADMIN_USER_CREATED', { requestId: req.requestId, actor, userId: user.id, username, role });
      _ok(res, req, { user: _safeUser(user) }, 201);
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // ── GET /users/:id ──────────────────────────────────────────────────────────
  router.get('/users/:id', _canRead, (req, res) => {
    const { id } = req.params;
    try {
      const user = store.getUser(id);
      if (!user) return _err(res, req, 404, 'NOT_FOUND', `User "${id}" not found`);
      _ok(res, req, { user: _safeUser(user) });
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // ── PATCH /users/:id (canonical) / PUT /users/:id (deprecated alias) ───────
  // Always a partial update — PATCH semantics (API-9 remediation).
  async function _updateUser(req, res) {
    const { id } = req.params;
    const actor  = _actor(req);
    const parsed = updateUserSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return _err(res, req, 400, 'MISSING_FIELDS', parsed.error.issues[0]?.message ?? 'At least one of username, role, or enabled must be provided');
    }
    const { username, role, enabled, externalIdentity } = parsed.data;
    const target = store.getUser(id);
    if (target) {
      if (role !== undefined && role !== target.role && req.rbacUser?.id === id) {
        emit('WARN', 'RBAC_ADMIN_SELF_ROLE_CHANGE_REFUSED', { requestId: req.requestId, actor, userId: id });
        return _err(res, req, 403, 'SELF_ROLE_CHANGE', 'You cannot change your own role');
      }
      // nor disable yourself — account self-protection, so an operator cannot lock the plane out from under
      // the remaining admins by accident or under coercion; another admin must do it.
      if (enabled === false && target.enabled !== false && req.rbacUser?.id === id) {
        emit('WARN', 'RBAC_ADMIN_SELF_DISABLE_REFUSED', { requestId: req.requestId, actor, userId: id });
        return _err(res, req, 403, 'SELF_DISABLE', 'You cannot disable your own account');
      }
      if (!_ceiling(req, res, permissionsForRole(target.role), `modify user "${target.username}"`)) return;
      if (role !== undefined && !_ceiling(req, res, permissionsForRole(role), `assign role "${role}"`)) return;
    }

    try {
      const user = await store.updateUser(id, { username, role, enabled, externalIdentity, updatedBy: actor });
      emit('INFO', 'RBAC_ADMIN_USER_UPDATED', { requestId: req.requestId, actor, userId: id });
      _ok(res, req, { user: _safeUser(user) });
    } catch (e) {
      _storeError(res, req, e);
    }
  }
  router.patch('/users/:id', _canManage, _updateUser);
  router.put('/users/:id', _canManage, (req, res) => {
    sendDeprecationHeaders(res, {
      successorLink: `/rbac/users/${encodeURIComponent(req.params.id)}`,
      warnEvent:     'RBAC_ADMIN_PUT_USER_DEPRECATED_USED',
      warnDetails:   { requestId: req.requestId, userId: req.params.id,
        message: 'PUT /rbac/users/:id is deprecated: this route only ever performs a partial update. Use PATCH /rbac/users/:id instead.' },
    });
    return _updateUser(req, res);
  });

  // ── DELETE /users/:id ───────────────────────────────────────────────────────
  router.delete('/users/:id', _canManage, async (req, res) => {
    const { id } = req.params;
    const actor  = _actor(req);
    const target = store.getUser(id);
    if (target && req.rbacUser?.id === id) {
      emit('WARN', 'RBAC_ADMIN_SELF_DELETE_REFUSED', { requestId: req.requestId, actor, userId: id });
      return _err(res, req, 403, 'SELF_DELETE', 'You cannot delete your own account'); //
    }
    if (target && !_ceiling(req, res, permissionsForRole(target.role), `delete user "${target.username}"`)) return;
    try {
      await store.deleteUser(id, { deletedBy: actor });
      emit('INFO', 'RBAC_ADMIN_USER_DELETED', { requestId: req.requestId, actor, userId: id });
      _ok(res, req, { deleted: true, userId: id });
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // ── POST /users/:id/api-key ──────────────────────────────────────────────────
  // Issue or rotate an API key for an operator.
  // The plaintext key is returned exactly once — store it securely.
  // Subsequent issuance on the same user silently rotates (invalidates old key).
  router.post('/users/:id/api-key', _canManage, async (req, res) => {
    const { id } = req.params;
    const actor  = _actor(req);
    const target = store.getUser(id);
    const self = req.rbacUser?.id === id;
    if (target && !self && !_strictlySubordinate(req, target)) {
      emit('WARN', 'RBAC_ADMIN_PEER_CREDENTIAL_REFUSED', { requestId: req.requestId, actor, userId: id, action: 'api-key' });
      return _err(res, req, 403, 'PEER_CREDENTIAL_FORBIDDEN',
        `An API key for "${target.username}" (permissions not strictly below yours) cannot be issued to you over HTTP; issue it out of band: node scripts/rbac-bootstrap-key.js --user ${target.username}`);
    }
    try {
      // a SELF-rotation inherits the previous issuer. Whoever issued (and so knew) this identity's key could
      // otherwise call this route AS the identity and clear the record — laundering the key for maker-checker. The
      // taint is cleared only by an out-of-band rotation (scripts/rbac-bootstrap-key.js --user), never over HTTP.
      const issuedById = self ? (target && target.apiKeyIssuedById ? target.apiKeyIssuedById : null) : (req.rbacUser?.id ?? null);
      const issuedBy   = self && target && target.apiKeyIssuedById ? target.apiKeyIssuedBy : actor;
      const { plaintext, issuedAt, expiresAt, previousKeyGraceUntil } = await store.issueApiKey(id, { issuedBy, issuedById });
      emit('INFO', 'RBAC_ADMIN_API_KEY_ISSUED', {
        requestId: req.requestId, actor, userId: id,
      });
      _ok(res, req, {
        apiKey:   plaintext,
        issuedAt,
        expiresAt:             expiresAt ?? null,             // (D5)
        previousKeyGraceUntil: previousKeyGraceUntil ?? null, // (D5): old key's rotation grace
        message:  'Store this API key securely — it will not be displayed again.',
      }, 201);
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // ── DELETE /users/:id/api-key ────────────────────────────────────────────────
  // Revoke an operator's API key immediately.
  // After revocation the key is invalid for all subsequent requests.
  router.delete('/users/:id/api-key', _canManage, async (req, res) => {
    const { id } = req.params;
    const actor  = _actor(req);
    // the same privilege ceiling as modifying/deleting that user. Without it any MANAGE_USERS holder
    // could revoke a MORE privileged operator's key (denial of service against superiors). Revoking your own key, or
    // that of an operator whose permissions you all hold, is unchanged — so a peer's compromised key can still be cut.
    const target = store.getUser(id);
    if (target && req.rbacUser?.id !== id && !_ceiling(req, res, permissionsForRole(target.role), `revoke the API key of "${target.username}"`)) return;
    try {
      await store.revokeApiKey(id, { revokedBy: actor });
      emit('INFO', 'RBAC_ADMIN_API_KEY_REVOKED', {
        requestId: req.requestId, actor, userId: id,
      });
      _ok(res, req, { revoked: true, userId: id });
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // ── GET /users/:id/permissions ───────────────────────────────────────────────
  router.get('/users/:id/permissions', _canRead, (req, res) => {
    const { id } = req.params;
    try {
      const user = store.getUser(id);
      if (!user) return _err(res, req, 404, 'NOT_FOUND', `User "${id}" not found`);
      const permissions = permissionsForRole(user.role);
      _ok(res, req, {
        userId:      user.id,
        username:    user.username,
        role:        user.role,
        permissions,
        total:       permissions.length,
      });
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // ── Operator MFA ───────────────────────────────────────────
  // Self-service: any authenticated operator manages their OWN enrolment. The
  // mount-level step-up (src/app.js) exempts exactly enroll/confirm; enrolment
  // is refused once MFA exists, so replacing it needs the admin reset below,
  // which is itself a step-up action. Secrets/codes are returned once, never
  // logged, never stored in clear.
  const _self = (req, res) => {
    const u = req.rbacUser;
    if (!u || !u.id) { _err(res, req, 403, 'OPERATOR_IDENTITY_REQUIRED', 'MFA requires a per-operator API key'); return null; }
    return u;
  };
  const _mfaError = (res, req, e) => {
    if (e instanceof mfa.MfaError) {
      const st = { MFA_ALREADY_ENROLLED: 409, MFA_NO_PENDING_ENROLLMENT: 409, MFA_ENROLLMENT_EXPIRED: 409, MFA_INVALID: 401 }[e.code] ?? 400;
      return _err(res, req, st, e.code, e.message);
    }
    return _storeError(res, req, e);
  };

  router.get('/me/mfa', (req, res) => {
    const u = _self(req, res); if (!u) return;
    try { _ok(res, req, { userId: u.id, required: mfa.isRequired(), ...mfa.status(u.id) }); } catch (e) { _mfaError(res, req, e); }
  });

  router.post('/me/mfa/enroll', async (req, res) => {
    const u = _self(req, res); if (!u) return;
    try {
      const { secret, otpauthUri } = await mfa.beginEnrollment(u);
      res.set('Cache-Control', 'no-store');
      _ok(res, req, { secret, otpauthUri, message: 'Add this secret to an authenticator app, then POST /rbac/me/mfa/confirm with a current code. It will not be displayed again.' }, 201);
    } catch (e) { _mfaError(res, req, e); }
  });

  router.post('/me/mfa/confirm', async (req, res) => {
    const u = _self(req, res); if (!u) return;
    try {
      const { recoveryCodes } = await mfa.confirmEnrollment(u, req.body?.code);
      res.set('Cache-Control', 'no-store');
      _ok(res, req, { enrolled: true, recoveryCodes, message: 'Store these recovery codes securely — each works once and they will not be displayed again.' });
    } catch (e) { _mfaError(res, req, e); }
  });

  router.delete('/users/:id/mfa', _canManage, async (req, res) => {
    const { id } = req.params;
    try {
      const target = store.getUser(id);
      if (!target) return _err(res, req, 404, 'NOT_FOUND', `User "${id}" not found`);
      if (req.rbacUser?.id !== id && !_strictlySubordinate(req, target)) {
        emit('WARN', 'RBAC_ADMIN_PEER_CREDENTIAL_REFUSED', { requestId: req.requestId, actor: _actor(req), userId: id, action: 'mfa-reset' });
        return _err(res, req, 403, 'PEER_CREDENTIAL_FORBIDDEN', `MFA of "${target.username}" (permissions not strictly below yours) cannot be reset by you; reset it out of band`);
      }
      await mfa.reset(id, { by: _actor(req), store });
      _ok(res, req, { reset: true, userId: id });
    } catch (e) { _mfaError(res, req, e); }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => _err(res, req, 405, 'METHOD_NOT_ALLOWED', 'Method not allowed'));

  return router;
}

// ── Safe role projection ────────────────────────────────────────────────────────

function _safeRole(role) {
  return {
    id:          role.id,
    name:        role.name,
    description: role.description,
    permissions: role.permissions,
    enabled:     role.enabled,
    builtIn:     false,
    createdAt:   role.createdAt,
    createdBy:   role.createdBy,
    updatedAt:   role.updatedAt,
    updatedBy:   role.updatedBy,
  };
}

// ── Safe user projection (never exposes internal fields) ──────────────────────

function _safeUser(user) {
  return {
    id:             user.id,
    username:       user.username,
    role:           user.role,
    enabled:        user.enabled,
    hasApiKey:      !!(user.apiKeyHash),       // boolean — hash is never exposed
    apiKeyIssuedAt: user.apiKeyIssuedAt ?? null,
    apiKeyExpiresAt: user.apiKeyExpiresAt ?? null,  // (D5)
    mfaEnabled:     !!(user.mfa && user.mfa.enabled), // (D4) — never the secret or codes
    externalIdentity: user.externalIdentity ?? null,    //
    createdAt:      user.createdAt,
    createdBy:      user.createdBy,
    updatedAt:      user.updatedAt,
    updatedBy:      user.updatedBy,
  };
}

module.exports = createRbacAdminRouter;
