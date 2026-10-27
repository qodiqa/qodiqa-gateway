'use strict';

/**
 * RBAC User Store
 *
 * User registry held in the control plane (src/core/controlPlane): PostgreSQL in production, memory mode in dev/test.
 * Each user has an ID, username, role, and lifecycle timestamps. The JSON file at QODIQA_RBAC_STORE_PATH (default
 * data/rbac-users.json) is only the legacy SEED read once in memory mode — it is never written. (this
 * header used to describe the earlier file-backed, atomic tmp→rename store.)
 *
 * Bootstrap: if QODIQA_RBAC_BOOTSTRAP_ADMIN_ID is set (default "bootstrap-admin"),
 * bootstrapAdmin() creates that user as Admin when no admin users exist.
 * This is idempotent and safe to call on every startup.
 *
 * Concurrency: cross-replica consistency comes from the control plane (versioned rows, 5 s bounded staleness — see
 * "Storage" below), not from this process.
 */

const crypto = require('crypto');
const { randomUUID } = require('crypto');
const { emit } = require('../../../services/logger');
const { isValidRole, ROLES } = require('./roles');
const { isCustomRoleId, getRole: getCustomRole } = require('./customRoleStore');
const cp = require('../controlPlane');
const { Collection } = require('../controlPlane/collection');
const { readSeed } = require('../controlPlane/seed');

// ── API key constants ─────────────────────────────────────────────────────────

const API_KEY_PREFIX = 'ok_';
const API_KEY_BYTES  = 32; // 256 bits of entropy

function _generateApiKey() {
  return API_KEY_PREFIX + crypto.randomBytes(API_KEY_BYTES).toString('hex');
}

function _hashApiKey(plaintext) {
  return crypto.createHash('sha256').update(plaintext, 'utf8').digest('hex');
}

// ── Storage ───────────────────────────────────────────────────────
// Records (including's MFA state and API-key expiry/grace fields, which
// live on the user record) are held in the control plane
// (src/core/controlPlane): PostgreSQL in production, a per-replica snapshot
// refused once stale (5 s). Dev/test memory mode seeds once from the legacy
// file (QODIQA_RBAC_STORE_PATH) and never writes it. Mutators return
// synchronously in memory mode and a Promise in pg mode — callers await.

let _keyHashIndex = new Map();    // keyHash → userId (O(1) lookup)
// (D5): previous key hash → userId, valid only inside its rotation grace window.
let _prevKeyHashIndex = new Map();
const keyLifecycle = require('../security/apiKeyLifecycle');

// (issuer, subject) of a user authenticated by single sign-on -> user id
let _externalIndex = new Map();
const _extKey = (issuer, subject) => `${issuer}\n${subject}`;

function _rebuildKeyIndex() {
  _keyHashIndex = new Map();
  _prevKeyHashIndex = new Map();
  _externalIndex = new Map();
  for (const user of _col.rawValues()) {
    if (user.externalIdentity) _externalIndex.set(_extKey(user.externalIdentity.issuer, user.externalIdentity.subject), user.id);
    if (user.apiKeyHash) {
      _keyHashIndex.set(user.apiKeyHash, user.id);
    }
    if (user.previousApiKeyHash) _prevKeyHashIndex.set(user.previousApiKeyHash, user.id);
  }
}

// (D5): a key issued has no expiry. It is given
// max(issuedAt + TTL, now + warning) ONCE, so existing keys do not all expire
// at deploy time and operators get the warning window. Memory mode applies it
// to the seed; pg mode writes it (versioned) after the first pull.
function _withExpiry(u, now) {
  if (!u.apiKeyHash || u.apiKeyExpiresAt) return null;
  const apiKeyExpiresAt = keyLifecycle.transitionExpiry(u.apiKeyIssuedAt, now);
  emit('INFO', 'RBAC_API_KEY_EXPIRY_ASSIGNED', { userId: u.id, username: u.username, apiKeyIssuedAt: u.apiKeyIssuedAt ?? null, apiKeyExpiresAt });
  return Object.freeze({ ...u, apiKeyExpiresAt });
}

function _seed() {
  const { records } = readSeed('rbac_user');
  const now = Date.now();
  for (const [id, u] of Object.entries(records)) records[id] = _withExpiry(u, now) || u;
  return records;
}

const _col = new Collection('rbac_user', { seed: _seed, onChange: () => _rebuildKeyIndex() });
_col._afterStart = async () => {
  const now = Date.now();
  for (const u of _col.rawValues()) {
    const next = _withExpiry(u, now);
    if (next) await _col.put(u.id, next, { updatedBy: 'system' }).catch(() => { /* another replica won */ });
  }
};

function _ensureLoaded() { _col.ensure(); }

// the last-admin rule, re-checked by PostgreSQL under a lock shared by every admin-reducing write (see
// controlPlane.writeRow `invariant`). The snapshot check below stays as the fast path and the memory-mode rule;
// this closes the race where two replicas each demote/disable/delete "the other" admin.
function _lastAdminInvariant(id, message) {
  return {
    lockKey: 'rbac_user.admins',
    sql: `SELECT count(*)::int AS n FROM control_plane_records
           WHERE store = 'rbac_user' AND NOT deleted AND record_id <> $1
             AND data->>'role' = $2 AND data->'enabled' = 'true'::jsonb`,
    params: [id, ROLES.ADMIN],
    holds: (rows) => Number(rows[0] && rows[0].n) > 0,
    refusal: () => new RbacStoreError(message, 'LAST_ADMIN'),
  };
}

// A concurrent create of the same username on another replica is caught by
// the database's unique index; report it the way a local duplicate is reported.
function _mapConflict(err) {
  if (err && err.code === 'CONTROL_PLANE_UNIQUE_CONFLICT') {
    throw new RbacStoreError('Username is already taken', 'USERNAME_TAKEN');
  }
  throw err;
}
function _put(id, rec, opts) {
  const r = _col.put(id, rec, opts);
  return (r && typeof r.then === 'function') ? r.catch(_mapConflict) : r;
}

// ── Error class ───────────────────────────────────────────────────────────────

class RbacStoreError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'RbacStoreError';
    this.code = code;
  }
}

// ── Username uniqueness ───────────────────────────────────────────────────────

function _userByUsername(username) {
  return _col.values().find(
    u => u.username.toLowerCase() === username.toLowerCase()
  ) ?? null;
}

// ── Validation ────────────────────────────────────────────────────────────────

const USERNAME_RE = /^[A-Za-z0-9_@.\-]{2,64}$/;

function _validateUsername(username) {
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    throw new RbacStoreError(
      `Username must be 2–64 characters, alphanumeric, _, @, ., or -`,
      'INVALID_USERNAME'
    );
  }
}

/**
 * Accepts either a canonical role (admin/auditor/compliance/operator/
 * viewer) or the ID of an existing custom role ("custom:"
 * namespace — see ./customRoleStore.js). A custom role's own `enabled`
 * flag is intentionally NOT checked here: assigning a currently-disabled
 * custom role to a user is allowed (e.g. provisioning ahead of a role's
 * activation), and disabling it later already fail-closed-denies every
 * permission it would have granted (./authorize.js), without needing to
 * touch every user record that references it.
 */
function _validateRole(role) {
  if (isValidRole(role)) return;
  if (isCustomRoleId(role) && getCustomRole(role)) return;
  throw new RbacStoreError(
    `Role "${role}" is not a valid RBAC role`,
    'INVALID_ROLE'
  );
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

/**
 * Create a new user.
 * Throws RbacStoreError with .code:
 *   INVALID_USERNAME  — username fails validation
 *   INVALID_ROLE      — role not in approved list
 *   USERNAME_TAKEN    — username already exists (case-insensitive)
 */
const ISSUER_RE = /^(?:https?:\/\/[^\s?#]{1,512}|ldap:[a-z][a-z0-9-]{0,30})$/;   // an OIDC/SAML issuer URL, or `ldap:<provider id>`
/** the (issuer, subject) a user signs in with through single sign-on; null/undefined = none. Unique across users. */
function _validateExternalIdentity(e, selfId = null) {
  if (e === undefined || e === null) return null;
  if (typeof e !== 'object' || Array.isArray(e) || Object.keys(e).some((k) => k !== 'issuer' && k !== 'subject')) throw new RbacStoreError('externalIdentity is { issuer, subject }', 'INVALID_EXTERNAL_IDENTITY');
  if (typeof e.issuer !== 'string' || !ISSUER_RE.test(e.issuer)) throw new RbacStoreError('externalIdentity.issuer must be the issuer URL (or ldap:<provider id>)', 'INVALID_EXTERNAL_IDENTITY');
  if (typeof e.subject !== 'string' || !e.subject || e.subject.length > 255 || /[\u0000-\u001f\u007f]/.test(e.subject)) throw new RbacStoreError('externalIdentity.subject must be a non-empty string of at most 255 characters', 'INVALID_EXTERNAL_IDENTITY');
  const holder = _externalIndex.get(_extKey(e.issuer, e.subject));
  if (holder && holder !== selfId) throw new RbacStoreError('that external identity is already linked to another user', 'EXTERNAL_IDENTITY_EXISTS');
  return { issuer: e.issuer, subject: e.subject };
}

function createUser({ username, role, createdBy = 'system', createdById = null, externalIdentity }) {
  _ensureLoaded();
  _validateUsername(username);
  _validateRole(role);
  const ext = _validateExternalIdentity(externalIdentity);

  if (_userByUsername(username)) {
    throw new RbacStoreError(
      `Username "${username}" is already taken`,
      'USERNAME_TAKEN'
    );
  }

  const now  = new Date().toISOString();
  const user = Object.freeze({
    id:         randomUUID(),
    username,
    role,
    enabled:    true,
    createdAt:  now,
    createdBy,
    // the creating operator's id, so maker-checker can refuse a reviewer or
    // approver the author provisioned (makerCheckerRules.assertActorNotProvisionedByAuthor).
    ...(createdById ? { createdById } : {}),
    ...(ext ? { externalIdentity: ext } : {}),
    updatedAt:  now,
    updatedBy:  createdBy,
  });

  return cp.after(_put(user.id, user, { create: true, updatedBy: createdBy }), () => {
    emit('INFO', 'RBAC_USER_CREATED', { userId: user.id, username, role, createdBy });
    return { ...user };
  });
}

/**
 * Get a user by ID.  Returns null if not found.
 */
function getUser(id) {
  _ensureLoaded();
  const u = _col.get(id);
  return u ? { ...u } : null;
}

/**
 * Get a user by username (case-insensitive).  Returns null if not found.
 */
function getUserByUsername(username) {
  _ensureLoaded();
  if (typeof username !== 'string') return null;
  const u = _userByUsername(username);
  return u ? { ...u } : null;
}

/**
 * List all users (copies, sorted by createdAt ascending).
 */
function listUsers() {
  _ensureLoaded();
  return _col.values()
    .map(u => ({ ...u }))
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

/**
 * Update a user's username, role, or enabled flag.
 * Throws RbacStoreError with .code:
 *   NOT_FOUND         — user ID not in store
 *   INVALID_USERNAME  — new username fails validation
 *   INVALID_ROLE      — new role not in approved list
 *   USERNAME_TAKEN    — new username already taken by another user
 *   LAST_ADMIN        — cannot disable or demote the last enabled admin
 */
function updateUser(id, { username, role, enabled, externalIdentity, updatedBy = 'system' }) {
  _ensureLoaded();
  const existing = _col.get(id);
  if (!existing) {
    throw new RbacStoreError(`User "${id}" not found`, 'NOT_FOUND');
  }

  const newUsername = username !== undefined ? username : existing.username;
  const newRole     = role     !== undefined ? role     : existing.role;
  const newEnabled  = enabled  !== undefined ? enabled  : existing.enabled;

  if (username !== undefined) _validateUsername(newUsername);
  if (role     !== undefined) _validateRole(newRole);

  // Check username uniqueness only if changing
  if (username !== undefined && username.toLowerCase() !== existing.username.toLowerCase()) {
    if (_userByUsername(username)) {
      throw new RbacStoreError(`Username "${username}" is already taken`, 'USERNAME_TAKEN');
    }
  }

  // Protect last admin: cannot disable or demote if they are the only enabled admin
  const isLosingAdmin = existing.role === ROLES.ADMIN &&
    (newRole !== ROLES.ADMIN || newEnabled === false);
  if (isLosingAdmin) {
    const otherAdmins = _col.values().filter(
      u => u.id !== id && u.role === ROLES.ADMIN && u.enabled
    );
    if (otherAdmins.length === 0) {
      throw new RbacStoreError(
        'Cannot demote or disable the last enabled admin user',
        'LAST_ADMIN'
      );
    }
  }

  const newExternal = externalIdentity === undefined ? existing.externalIdentity : _validateExternalIdentity(externalIdentity, id);
  const updated = Object.freeze({
    ...existing,
    username: newUsername,
    role:     newRole,
    enabled:  newEnabled,
    ...(externalIdentity !== undefined ? { externalIdentity: newExternal || undefined } : {}),
    updatedAt: new Date().toISOString(),
    updatedBy,
  });

  const putOpts = isLosingAdmin && cp.isPg()
    ? { updatedBy, invariant: _lastAdminInvariant(id, 'Cannot demote or disable the last enabled admin user') }
    : { updatedBy };
  return cp.after(_put(id, updated, putOpts), () => {
    emit('INFO', 'RBAC_USER_UPDATED', { userId: id, updatedBy, changes: { username, role, enabled } });
    return { ...updated };
  });
}

/**
 * Delete a user permanently.
 * Throws RbacStoreError:
 *   NOT_FOUND  — user ID not in store
 *   LAST_ADMIN — cannot delete the last enabled admin
 */
function deleteUser(id, { deletedBy = 'system' } = {}) {
  _ensureLoaded();
  const existing = _col.get(id);
  if (!existing) {
    throw new RbacStoreError(`User "${id}" not found`, 'NOT_FOUND');
  }

  if (existing.role === ROLES.ADMIN && existing.enabled) {
    const otherAdmins = _col.values().filter(
      u => u.id !== id && u.role === ROLES.ADMIN && u.enabled
    );
    if (otherAdmins.length === 0) {
      throw new RbacStoreError(
        'Cannot delete the last enabled admin user',
        'LAST_ADMIN'
      );
    }
  }

  const removeOpts = existing.role === ROLES.ADMIN && existing.enabled && cp.isPg()
    ? { updatedBy: deletedBy, invariant: _lastAdminInvariant(id, 'Cannot delete the last enabled admin user') }
    : { updatedBy: deletedBy };
  return cp.after(_col.remove(id, removeOpts), () => {
    emit('INFO', 'RBAC_USER_DELETED', { userId: id, username: existing.username, deletedBy });
  });
}

/**
 * Bootstrap the initial admin user.
 *
 * Safe to call on every startup — idempotent.
 * Creates an admin user only when NO enabled admin exists in the store.
 * Never creates additional users after bootstrap.
 *
 * @returns {object|null} The admin user if created, null if one already existed
 */
function bootstrapAdmin() {
  _ensureLoaded();

  const existingAdmins = _col.values().filter(
    u => u.role === ROLES.ADMIN && u.enabled
  );

  if (existingAdmins.length > 0) {
    emit('INFO', 'RBAC_BOOTSTRAP_SKIPPED', {
      reason: 'admin_exists',
      count:  existingAdmins.length,
    });
    return null;
  }

  const adminId   = process.env.QODIQA_RBAC_BOOTSTRAP_ADMIN_ID       || 'bootstrap-admin';
  const adminName = process.env.QODIQA_RBAC_BOOTSTRAP_ADMIN_USERNAME  || 'admin';

  // If the bootstrap ID is already used as a non-admin, update it to admin role.
  const byId = _col.get(adminId);
  if (byId) {
    return cp.after(updateUser(adminId, {
      role:      ROLES.ADMIN,
      enabled:   true,
      updatedBy: 'BOOTSTRAP',
    }), (upgraded) => {
      emit('WARN', 'RBAC_BOOTSTRAP_UPGRADED', { userId: adminId, username: upgraded.username });
      return upgraded;
    });
  }

  // Create fresh bootstrap admin
  const now  = new Date().toISOString();
  const user = Object.freeze({
    id:        adminId,
    username:  adminName,
    role:      ROLES.ADMIN,
    enabled:   true,
    createdAt: now,
    createdBy: 'BOOTSTRAP',
    updatedAt: now,
    updatedBy: 'BOOTSTRAP',
  });

  return cp.after(_put(adminId, user, { create: true, updatedBy: 'BOOTSTRAP' }), () => {
    emit('WARN', 'RBAC_BOOTSTRAP_ADMIN_CREATED', {
      userId:   adminId,
      username: adminName,
      message:  'Bootstrap admin created. Set QODIQA_RBAC_BOOTSTRAP_ADMIN_ID to customise.',
    });
    return { ...user };
  });
}

// ── API key management ────────────────────────────────────────────────────────

/**
 * Issue or rotate an API key for an operator.
 * Returns the plaintext key once — it is never stored or returned again.
 * The SHA-256 hash is stored in the user record.
 *
 * @param {string} userId
 * @param {{ issuedBy?: string }} opts
 * @returns {{ plaintext: string, issuedAt: string }}
 */
function issueApiKey(userId, { issuedBy = 'system', issuedById = null } = {}) {
  _ensureLoaded();
  const existing = _col.get(userId);
  if (!existing) {
    throw new RbacStoreError(`User "${userId}" not found`, 'NOT_FOUND');
  }

  const plaintext = _generateApiKey();
  const keyHash   = _hashApiKey(plaintext);
  const now       = new Date().toISOString();

  // (D5): expiry, and a grace window for the previous key on rotation.
  const lifecycle = keyLifecycle.issueFields(existing, keyHash, Date.parse(now));
  const next = Object.freeze({
    ...existing,
    ...lifecycle,
    apiKeyIssuedAt: now,
    // who holds knowledge of this key's plaintext besides its owner (null = self-issued / out-of-band CLI).
    apiKeyIssuedBy:   issuedBy,
    apiKeyIssuedById: issuedById,
    updatedAt:      now,
    updatedBy:      issuedBy,
  });

  return cp.after(_put(userId, next, { updatedBy: issuedBy }), () => {
    emit('INFO', 'RBAC_API_KEY_ISSUED', {
      userId,
      username:  existing.username,
      issuedBy,
      issuedAt:  now,
      rotation:  !!(existing.apiKeyHash),
      expiresAt: lifecycle.apiKeyExpiresAt,
      previousKeyGraceUntil: lifecycle.previousApiKeyGraceUntil,
    });
    return { plaintext, issuedAt: now, expiresAt: lifecycle.apiKeyExpiresAt, previousKeyGraceUntil: lifecycle.previousApiKeyGraceUntil };
  });
}

/**
 * Revoke the API key for an operator.
 * After revocation the key is immediately invalid.
 *
 * @param {string} userId
 * @param {{ revokedBy?: string }} opts
 */
function revokeApiKey(userId, { revokedBy = 'system' } = {}) {
  _ensureLoaded();
  const existing = _col.get(userId);
  if (!existing) {
    throw new RbacStoreError(`User "${userId}" not found`, 'NOT_FOUND');
  }
  if (!existing.apiKeyHash) {
    throw new RbacStoreError(
      `User "${userId}" has no active API key`,
      'NO_API_KEY',
    );
  }

  const now = new Date().toISOString();
  const next = Object.freeze({
    ...existing,
    ...keyLifecycle.revokeFields(), // (D5): the previous key's grace ends too
    updatedAt:      now,
    updatedBy:      revokedBy,
  });

  return cp.after(_put(userId, next, { updatedBy: revokedBy }), () => {
    emit('INFO', 'RBAC_API_KEY_REVOKED', {
      userId,
      username:   existing.username,
      revokedBy,
    });
  });
}

/**
 * Resolve a plaintext API key to its owning operator.
 *
 * - Computes SHA-256 of the provided key.
 * - O(1) index lookup by hash.
 * - Constant-time hash comparison as a belt-and-suspenders guard.
 * - Returns the full user record, or null if no match.
 *
 * @param {string} plaintextKey
 * @returns {object|null}
 */
function resolveOperatorKey(plaintextKey) {
  // (D5): an expired key (or a previous key past its grace) resolves to
  // nothing for every caller of this function (ops auth, health auth ...).
  const d = resolveOperatorKeyDetailed(plaintextKey);
  return d && d.status !== 'expired' ? d.user : null;
}

/**
 * (D5): resolve a key AND report its lifecycle state.
 * @returns {{ user: object, status: 'valid'|'expiring'|'grace'|'expired', expiresAt: string|null, via: 'current'|'previous' }|null}
 */
function resolveOperatorKeyDetailed(plaintextKey) {
  if (typeof plaintextKey !== 'string' || !plaintextKey) return null;
  _ensureLoaded();

  const providedHash = _hashApiKey(plaintextKey);
  let via = 'current';
  let userId = _keyHashIndex.get(providedHash);
  if (!userId) { userId = _prevKeyHashIndex.get(providedHash); via = 'previous'; }
  if (!userId) return null;

  const user = _col.get(userId);
  const stored = user && (via === 'current' ? user.apiKeyHash : user.previousApiKeyHash);
  if (!stored) return null;

  // Belt-and-suspenders: constant-time comparison of hex digest strings.
  const a = Buffer.from(providedHash, 'utf8');
  const b = Buffer.from(stored,       'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  const { status, expiresAt } = keyLifecycle.keyStatus(user, via);
  return { user: { ...user }, status, expiresAt, via };
}

// ── Testing helpers ───────────────────────────────────────────────────────────

/**
 * Reset the in-memory store — for testing only.
 */
/** the user linked to a verified (issuer, subject), or null. The caller applies the usual enabled / role checks. */
function resolveByExternalIdentity(issuer, subject) {
  if (typeof issuer !== 'string' || typeof subject !== 'string') return null;
  _ensureLoaded();
  const id = _externalIndex.get(_extKey(issuer, subject));
  const u = id ? _col.get(id) : null;
  if (!u || !u.externalIdentity || u.externalIdentity.issuer !== issuer || u.externalIdentity.subject !== subject) return null;
  return { ...u };
}

function _reset() {
  _col._reset();
  _keyHashIndex = new Map();
  _prevKeyHashIndex = new Map();
}

// ── MFA state ────────────────────────────────────────────────────────
// Stored on the user record behind this store's interface — moved it to
// PostgreSQL with the record. The TOTP secret is AES-GCM encrypted by
// src/core/rbac/mfa.js before it reaches this store; recovery codes are hashes.

function getMfaState(userId) {
  _ensureLoaded();
  const u = _col.get(userId);
  if (!u) throw new RbacStoreError(`User "${userId}" not found`, 'NOT_FOUND');
  return u.mfa ? { ...u.mfa } : null;
}

function setMfaState(userId, mfa, { updatedBy = 'system' } = {}) {
  _ensureLoaded();
  const u = _col.get(userId);
  if (!u) throw new RbacStoreError(`User "${userId}" not found`, 'NOT_FOUND');
  return cp.after(_put(userId, Object.freeze({ ...u, mfa: mfa ? Object.freeze({ ...mfa }) : null, updatedAt: new Date().toISOString(), updatedBy }), { updatedBy }), () => undefined);
}

/**
 * Memory mode: drop the snapshot and re-seed from the legacy file (tests).
 */
function _reload() {
  _col._reset();
  _ensureLoaded();
}

// Tests / offline dev tooling (memory mode only): write the snapshot as the seed fixture.
function exportSeedFixture() { return _col.exportSeedFixture(); }

module.exports = {
  createUser,
  getUser,
  getUserByUsername,
  listUsers,
  updateUser,
  deleteUser,
  bootstrapAdmin,
  issueApiKey,
  revokeApiKey,
  resolveOperatorKey,
  resolveOperatorKeyDetailed,
  resolveByExternalIdentity,
  getMfaState,
  setMfaState,
  _reset,
  _reload,
  exportSeedFixture,
  RbacStoreError,
};
