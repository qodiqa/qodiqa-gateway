'use strict';

/**
 * Signing Identity Store — TRUST-1 remediation.
 *
 * Replaces the single static QODIQA_SIGN_TOKEN shared secret with per-caller
 * signing identities, modeled on the same persistence pattern as
 * src/core/rbac/store.js (atomic tmp->rename writes, SHA-256 API key hashing,
 * O(1) hash-index lookup, constant-time comparison) but deliberately kept as
 * a SEPARATE store: signing identities are machine callers (SDKs, CI/CD,
 * service accounts) scoped by tenant/environment/provider, not human console
 * operators scoped by role. Conflating the two would either weaken RBAC's
 * role model or force signing scope concepts onto it that don't fit.
 *
 * Every signing identity carries:
 *   - tenantId       REQUIRED. Must name a real keyManager/tenant client ID.
 *                    This is the multi-tenant isolation boundary: a signing
 *                    identity can only ever produce artifacts keyed to ITS
 *                    tenant's signing key — never an operator-supplied or
 *                    globally-shared clientId (the prior QODIQA_CLIENT_ID
 *                    env var applied to every caller regardless of identity).
 *   - environment    REQUIRED. One of ENVIRONMENTS below. Scopes which
 *                    deployment environment this credential is trusted in;
 *                    checked against QODIQA_ENVIRONMENT at request time.
 *   - allowedProviders  OPTIONAL. When set, restricts which AI provider
 *                    names this identity may bind an artifact to. `null`
 *                    means "whatever the tenant has enabled" (no additional
 *                    restriction) — never "any provider unconditionally".
 *   - permissions    REQUIRED, non-empty, validated against
 *                    src/core/signing/signingPermissions.js. An identity
 *                    with no SIGN_ARTIFACT permission cannot sign, even with
 *                    a valid, enabled, unrevoked credential — authentication
 *                    and authorization are independent checks.
 *   - credentialType Reserved for future non-API-key identity types (OAuth
 *                    client, JWT subject, mTLS certificate, workload
 *                    identity) without a storage-format break. Only
 *                    'api-key' is implemented today.
 *   - maxTtlMs       OPTIONAL per-identity cap, tighter than the global
 *                    MAX_TTL_MS in src/validation/schemas/sign.schema.js.
 *
 * Storage: the control plane (src/core/controlPlane) —
 * PostgreSQL in production. The legacy file (QODIQA_SIGNING_STORE_PATH,
 * default data/signing-identities.json) is import-only: dev/test memory mode
 * seeds from it once, and nothing writes it. Mutators return synchronously in
 * memory mode and a Promise in pg mode — callers await.
 *
 * Fail-closed contract: resolveSigningIdentity() returns the raw record (or
 * null) — callers (signAuth middleware) are responsible for checking
 * enabled/revoked/permissions before treating a resolved identity as
 * authorized. This mirrors rbacStore.resolveOperatorKey()'s contract exactly
 * so the two stores stay auditable against the same mental model.
 */

const crypto = require('crypto');
const { randomUUID } = require('crypto');
const { emit } = require('../../../services/logger');
const { isValidSigningPermission } = require('./signingPermissions');
const cp = require('../controlPlane');
const { Collection } = require('../controlPlane/collection');
const { readSeed } = require('../controlPlane/seed');

// ── Scoping constants ─────────────────────────────────────────────────────────

const ENVIRONMENTS = Object.freeze([
  'development', 'test', 'ci', 'staging', 'production',
]);
const ENVIRONMENT_SET = Object.freeze(new Set(ENVIRONMENTS));

const CREDENTIAL_TYPES = Object.freeze(['api-key', 'oidc']);       // 'oidc' - the identity is authenticated by an OIDC bearer token of the linked (issuer, subject); it holds no API key
const CREDENTIAL_TYPE_SET = Object.freeze(new Set(CREDENTIAL_TYPES));

const NAME_RE      = /^[A-Za-z0-9_@.\-]{2,128}$/;
const TENANT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/; // matches keyStore.js's CLIENT_ID_RE
const PROVIDER_RE  = /^[a-z0-9_-]{1,64}$/i;

// ── API key constants ─────────────────────────────────────────────────────────

const API_KEY_PREFIX = 'sk_'; // distinct from RBAC operator keys (ok_) —
                               // a signing key must never be usable as an
                               // operator credential or vice versa.
const API_KEY_BYTES  = 32; // 256 bits of entropy

function _generateApiKey() {
  return API_KEY_PREFIX + crypto.randomBytes(API_KEY_BYTES).toString('hex');
}

function _hashApiKey(plaintext) {
  return crypto.createHash('sha256').update(plaintext, 'utf8').digest('hex');
}

// ── Storage ───────────────────────────────────────────────────────
// Records live in the control plane (src/core/controlPlane): PostgreSQL in
// production, with a per-replica snapshot that is refused once stale (5 s);
// dev/test memory mode seeds once from the legacy JSON file and never writes
// it. No write path touches a file any more (the old whole-file rewrite on
// every /sign is gone — touchLastUsed is coalesced, see below).

let _keyHashIndex = new Map();  // keyHash → identityId (O(1) lookup)

// (D5): previous key hash → identity id, valid only inside its rotation grace.
let _prevKeyHashIndex = new Map();
const keyLifecycle = require('../security/apiKeyLifecycle');

// (issuer, subject) of an 'oidc' identity -> identity id
let _externalIndex = new Map();
const _extKey = (issuer, subject) => `${issuer}\n${subject}`;

function _rebuildKeyIndex() {
  _keyHashIndex = new Map();
  _prevKeyHashIndex = new Map();
  _externalIndex = new Map();
  for (const identity of _col.rawValues()) {
    if (identity.externalIdentity) _externalIndex.set(_extKey(identity.externalIdentity.issuer, identity.externalIdentity.subject), identity.id);
    if (identity.apiKeyHash) {
      _keyHashIndex.set(identity.apiKeyHash, identity.id);
    }
    if (identity.previousApiKeyHash) _prevKeyHashIndex.set(identity.previousApiKeyHash, identity.id);
  }
}

// (D5): earlier keys get max(issuedAt + TTL, now + warning) once. Memory
// mode applies it to the seed; pg mode writes it (versioned) after the first
// pull, and the import script assigns it at import time.
function _withExpiry(ident, now) {
  if (!ident.apiKeyHash || ident.apiKeyExpiresAt) return null;
  const apiKeyExpiresAt = keyLifecycle.transitionExpiry(ident.apiKeyIssuedAt, now);
  emit('INFO', 'SIGNING_KEY_EXPIRY_ASSIGNED', { identityId: ident.id, name: ident.name, apiKeyIssuedAt: ident.apiKeyIssuedAt ?? null, apiKeyExpiresAt });
  return Object.freeze({ ...ident, apiKeyExpiresAt });
}

function _seed() {
  const { records } = readSeed('signing_identity');
  const now = Date.now();
  for (const [id, ident] of Object.entries(records)) records[id] = _withExpiry(ident, now) || ident;
  return records;
}

const _col = new Collection('signing_identity', { seed: _seed, onChange: () => _rebuildKeyIndex(), touchField: 'lastUsedAt' });
_col._afterStart = async () => {
  const now = Date.now();
  for (const ident of _col.rawValues()) {
    const next = _withExpiry(ident, now);
    if (next) await _col.put(ident.id, next, { updatedBy: 'system' }).catch(() => { /* another replica won; the pull brings its value */ });
  }
};

function _ensureLoaded() { _col.ensure(); }

// ── Error class ───────────────────────────────────────────────────────────────

class SigningStoreError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'SigningStoreError';
    this.code = code;
  }
}

// ── Validation ────────────────────────────────────────────────────────────────

function _validateName(name) {
  if (typeof name !== 'string' || !NAME_RE.test(name)) {
    throw new SigningStoreError(
      'name must be 2–128 characters, alphanumeric, _, @, ., or -',
      'INVALID_NAME',
    );
  }
}

function _validateTenantId(tenantId) {
  if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) {
    throw new SigningStoreError(
      'tenantId is required and must match [A-Za-z0-9_-]{1,64} — no default or fallback tenant is permitted',
      'INVALID_TENANT_ID',
    );
  }
}

function _validateEnvironment(environment) {
  if (!ENVIRONMENT_SET.has(environment)) {
    throw new SigningStoreError(
      `environment must be one of: ${ENVIRONMENTS.join(', ')}`,
      'INVALID_ENVIRONMENT',
    );
  }
}

function _validateAllowedProviders(allowedProviders) {
  if (allowedProviders === null || allowedProviders === undefined) return null;
  if (!Array.isArray(allowedProviders) || allowedProviders.length === 0) {
    throw new SigningStoreError(
      'allowedProviders must be null (unrestricted) or a non-empty array of provider names',
      'INVALID_ALLOWED_PROVIDERS',
    );
  }
  for (const p of allowedProviders) {
    if (typeof p !== 'string' || !PROVIDER_RE.test(p)) {
      throw new SigningStoreError(`invalid provider name in allowedProviders: ${JSON.stringify(p)}`, 'INVALID_ALLOWED_PROVIDERS');
    }
  }
  return [...new Set(allowedProviders)];
}

function _validatePermissions(permissions) {
  if (!Array.isArray(permissions) || permissions.length === 0) {
    throw new SigningStoreError(
      'permissions must be a non-empty array — least privilege forbids an implicit default permission set',
      'INVALID_PERMISSIONS',
    );
  }
  for (const perm of permissions) {
    if (!isValidSigningPermission(perm)) {
      throw new SigningStoreError(`unknown signing permission: ${JSON.stringify(perm)}`, 'INVALID_PERMISSIONS');
    }
  }
  return [...new Set(permissions)];
}

function _validateCredentialType(credentialType) {
  if (!CREDENTIAL_TYPE_SET.has(credentialType)) {
    throw new SigningStoreError(
      `credentialType must be one of: ${CREDENTIAL_TYPES.join(', ')}`,
      'INVALID_CREDENTIAL_TYPE',
    );
  }
}

const ISSUER_RE = /^https:\/\/[^\s?#]{1,512}$/;
/** the (issuer, subject) an 'oidc' identity is linked to. Required for 'oidc', refused for any other credential type. */
function _validateExternalIdentity(credentialType, externalIdentity) {
  if (credentialType !== 'oidc') {
    if (externalIdentity !== undefined && externalIdentity !== null) throw new SigningStoreError('externalIdentity is only for credentialType "oidc"', 'INVALID_EXTERNAL_IDENTITY');
    return null;
  }
  const e = externalIdentity;
  if (!e || typeof e !== 'object' || Array.isArray(e) || Object.keys(e).some((k) => k !== 'issuer' && k !== 'subject')) throw new SigningStoreError('externalIdentity is { issuer, subject }', 'INVALID_EXTERNAL_IDENTITY');
  if (typeof e.issuer !== 'string' || !ISSUER_RE.test(e.issuer)) throw new SigningStoreError('externalIdentity.issuer must be the https issuer URL', 'INVALID_EXTERNAL_IDENTITY');
  if (typeof e.subject !== 'string' || !e.subject || e.subject.length > 255 || /[\u0000-\u001f\u007f]/.test(e.subject)) throw new SigningStoreError('externalIdentity.subject must be a non-empty string of at most 255 characters', 'INVALID_EXTERNAL_IDENTITY');
  const holder = _externalIndex.get(_extKey(e.issuer, e.subject));
  return { issuer: e.issuer, subject: e.subject, _holder: holder || null };
}

/** an oidc identity may demand that its token carries the identity provider's second-factor assurance (provider `assurance`). Not for API-key identities (a machine key has no second factor). */
function _validateRequireAssurance(credentialType, v) {
  if (v === undefined || v === null || v === false) return false;
  if (v !== true) throw new SigningStoreError('requireAssurance is a boolean', 'INVALID_REQUIRE_ASSURANCE');
  if (credentialType !== 'oidc') throw new SigningStoreError('requireAssurance is only for credentialType "oidc"', 'INVALID_REQUIRE_ASSURANCE');
  return true;
}

function _validateMaxTtlMs(maxTtlMs) {
  if (maxTtlMs === null || maxTtlMs === undefined) return null;
  if (!Number.isFinite(maxTtlMs) || maxTtlMs <= 0) {
    throw new SigningStoreError('maxTtlMs must be a positive finite number when provided', 'INVALID_MAX_TTL');
  }
  return maxTtlMs;
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

/**
 * Create a new signing identity. Disabled-by-default is NOT the model here —
 * an identity is created enabled but has no API key until issueSigningKey()
 * is called, so it cannot authenticate anything until a key is explicitly
 * issued (least privilege: existence of the record grants nothing by itself).
 *
 * Throws SigningStoreError with .code on any validation failure.
 */
function createSigningIdentity({
  name, tenantId, environment, allowedProviders = null, permissions,
  credentialType = 'api-key', maxTtlMs = null, createdBy = 'system', externalIdentity, requireAssurance,
}) {
  _ensureLoaded();
  _validateName(name);
  _validateTenantId(tenantId);
  _validateEnvironment(environment);
  const normalizedProviders = _validateAllowedProviders(allowedProviders);
  const normalizedPermissions = _validatePermissions(permissions);
  _validateCredentialType(credentialType);
  const ext = _validateExternalIdentity(credentialType, externalIdentity);
  const needAssurance = _validateRequireAssurance(credentialType, requireAssurance);
  if (ext && ext._holder) throw new SigningStoreError('that external identity is already linked to another signing identity', 'EXTERNAL_IDENTITY_EXISTS');
  const normalizedMaxTtlMs = _validateMaxTtlMs(maxTtlMs);

  const now = new Date().toISOString();
  const identity = Object.freeze({
    id:               randomUUID(),
    name,
    tenantId,
    environment,
    allowedProviders: normalizedProviders,
    permissions:      normalizedPermissions,
    credentialType,
    ...(ext ? { externalIdentity: { issuer: ext.issuer, subject: ext.subject } } : {}),
    ...(needAssurance ? { requireAssurance: true } : {}),
    maxTtlMs:         normalizedMaxTtlMs,
    enabled:          true,
    revoked:          false,
    revokedAt:        null,
    revokedBy:        null,
    revokedReason:    null,
    apiKeyHash:       null,
    apiKeyIssuedAt:   null,
    lastUsedAt:       null,
    createdAt:        now,
    createdBy,
    updatedAt:        now,
    updatedBy:        createdBy,
  });

  return cp.after(_col.put(identity.id, identity, { create: true, updatedBy: createdBy }), () => {
    emit('INFO', 'SIGNING_IDENTITY_CREATED', {
      identityId: identity.id, name, tenantId, environment,
      allowedProviders: normalizedProviders, permissions: normalizedPermissions,
      createdBy,
    });
    return { ...identity };
  });
}

function getSigningIdentity(id) {
  _ensureLoaded();
  const i = _col.get(id);
  return i ? { ...i } : null;
}

function listSigningIdentities() {
  _ensureLoaded();
  return _col.values()
    .map(i => ({ ...i }))
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

/**
 * Update mutable fields of a signing identity (scope, permissions, enabled).
 * Does NOT touch the API key — use issueSigningKey/revokeSigningKey for that.
 * Throws SigningStoreError with .code:
 *   NOT_FOUND | INVALID_* (same validators as createSigningIdentity)
 */
function updateSigningIdentity(id, {
  name, tenantId, environment, allowedProviders, permissions, maxTtlMs, enabled, externalIdentity, requireAssurance,
  updatedBy = 'system',
}) {
  _ensureLoaded();
  const existing = _col.get(id);
  if (!existing) throw new SigningStoreError(`Signing identity "${id}" not found`, 'NOT_FOUND');

  const next = { ...existing };
  if (name             !== undefined) { _validateName(name);              next.name = name; }
  if (tenantId         !== undefined) { _validateTenantId(tenantId);      next.tenantId = tenantId; }
  if (environment      !== undefined) { _validateEnvironment(environment); next.environment = environment; }
  if (allowedProviders !== undefined) { next.allowedProviders = _validateAllowedProviders(allowedProviders); }
  if (permissions      !== undefined) { next.permissions = _validatePermissions(permissions); }
  if (maxTtlMs         !== undefined) { next.maxTtlMs = _validateMaxTtlMs(maxTtlMs); }
  if (enabled          !== undefined) { next.enabled = !!enabled; }
  if (requireAssurance !== undefined) next.requireAssurance = _validateRequireAssurance(existing.credentialType, requireAssurance) || undefined;
  if (externalIdentity !== undefined) {
    const ext = _validateExternalIdentity(existing.credentialType, externalIdentity);
    if (ext && ext._holder && ext._holder !== id) throw new SigningStoreError('that external identity is already linked to another signing identity', 'EXTERNAL_IDENTITY_EXISTS');
    next.externalIdentity = ext ? { issuer: ext.issuer, subject: ext.subject } : undefined;
  }

  const updated = Object.freeze({
    ...next,
    updatedAt: new Date().toISOString(),
    updatedBy,
  });

  return cp.after(_col.put(id, updated, { updatedBy }), () => {
    emit('INFO', 'SIGNING_IDENTITY_UPDATED', { identityId: id, updatedBy });
    return { ...updated };
  });
}

/**
 * Issue or rotate the API key for a signing identity.
 * Returns the plaintext key once — it is never stored or returned again.
 */
function issueSigningKey(id, { issuedBy = 'system' } = {}) {
  _ensureLoaded();
  const existing = _col.get(id);
  if (!existing) throw new SigningStoreError(`Signing identity "${id}" not found`, 'NOT_FOUND');
  if (existing.credentialType === 'oidc') throw new SigningStoreError('an "oidc" identity authenticates with an OIDC token, it has no API key', 'INVALID_OPERATION');   //

  const plaintext = _generateApiKey();
  const keyHash   = _hashApiKey(plaintext);
  const now       = new Date().toISOString();

  // (D5): expiry, and a grace window for the previous key on rotation.
  const lifecycle = keyLifecycle.issueFields(existing.revoked ? { ...existing, apiKeyHash: null } : existing, keyHash, Date.parse(now));
  const next = Object.freeze({
    ...existing,
    ...lifecycle,
    apiKeyIssuedAt: now,
    revoked:        false,
    revokedAt:      null,
    revokedBy:      null,
    revokedReason:  null,
    updatedAt:      now,
    updatedBy:      issuedBy,
  });

  return cp.after(_col.put(id, next, { updatedBy: issuedBy }), () => {
    emit('INFO', 'SIGNING_KEY_ISSUED', {
      identityId: id, name: existing.name, issuedBy, issuedAt: now,
      rotation: !!existing.apiKeyHash,
      expiresAt: lifecycle.apiKeyExpiresAt, previousKeyGraceUntil: lifecycle.previousApiKeyGraceUntil,
    });
    return { plaintext, issuedAt: now, expiresAt: lifecycle.apiKeyExpiresAt, previousKeyGraceUntil: lifecycle.previousApiKeyGraceUntil };
  });
}

/**
 * Revoke the API key for a signing identity. Immediately invalidates it —
 * resolveSigningIdentity() will no longer find this hash, and the identity
 * record itself is marked revoked for audit visibility even if a new key is
 * later issued (issueSigningKey clears the revoked flag on rotation).
 */
function revokeSigningKey(id, { revokedBy = 'system', reason = null } = {}) {
  _ensureLoaded();
  const existing = _col.get(id);
  if (!existing) throw new SigningStoreError(`Signing identity "${id}" not found`, 'NOT_FOUND');
  if (!existing.apiKeyHash && existing.credentialType !== 'oidc') {   // an oidc identity has no key; revoking it revokes the identity itself
    throw new SigningStoreError(`Signing identity "${id}" has no active API key`, 'NO_API_KEY');
  }

  const now = new Date().toISOString();
  const next = Object.freeze({
    ...existing,
    ...keyLifecycle.revokeFields(), // (D5): the previous key's grace ends too
    revoked:        true,
    revokedAt:      now,
    revokedBy,
    revokedReason:  reason,
    updatedAt:      now,
    updatedBy:      revokedBy,
  });

  return cp.after(_col.put(id, next, { updatedBy: revokedBy }), () => {
    emit('WARN', 'SIGNING_KEY_REVOKED', { identityId: id, name: existing.name, revokedBy, reason });
  });
}

/**
 * Permanently delete a signing identity record (admin-only, rarely needed —
 * prefer disabling/revoking, which preserves audit history).
 */
function deleteSigningIdentity(id, { deletedBy = 'system' } = {}) {
  _ensureLoaded();
  const existing = _col.get(id);
  if (!existing) throw new SigningStoreError(`Signing identity "${id}" not found`, 'NOT_FOUND');

  return cp.after(_col.remove(id, { updatedBy: deletedBy }), () => {
    emit('WARN', 'SIGNING_IDENTITY_DELETED', { identityId: id, name: existing.name, deletedBy });
  });
}

/**
 * Resolve a plaintext signing API key to its owning identity.
 *
 * Returns the RAW record (even if disabled/revoked) or null if the hash
 * doesn't match any stored identity — mirrors rbacStore.resolveOperatorKey().
 * Callers (signAuth middleware) must check .enabled/.revoked/.permissions
 * before treating the result as authorization.
 */
function resolveSigningIdentity(plaintextKey) {
  // (D5): an expired key (or a previous key past its grace) resolves to nothing.
  const d = resolveSigningIdentityDetailed(plaintextKey);
  return d && d.status !== 'expired' ? d.identity : null;
}

/**
 * (D5): resolve a signing key AND report its lifecycle state.
 * @returns {{ identity: object, status: 'valid'|'expiring'|'grace'|'expired', expiresAt: string|null, via: 'current'|'previous' }|null}
 */
function resolveSigningIdentityDetailed(plaintextKey) {
  if (typeof plaintextKey !== 'string' || !plaintextKey) return null;
  _ensureLoaded();

  const providedHash = _hashApiKey(plaintextKey);
  let via = 'current';
  let identityId = _keyHashIndex.get(providedHash);
  if (!identityId) { identityId = _prevKeyHashIndex.get(providedHash); via = 'previous'; }
  if (!identityId) return null;

  const identity = _col.get(identityId);
  const stored = identity && (via === 'current' ? identity.apiKeyHash : identity.previousApiKeyHash);
  if (!stored) return null;

  // Belt-and-suspenders: constant-time comparison of hex digest strings.
  const a = Buffer.from(providedHash, 'utf8');
  const b = Buffer.from(stored,       'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  const { status, expiresAt } = keyLifecycle.keyStatus(identity, via);
  return { identity: { ...identity }, status, expiresAt, via };
}

/**
 * Best-effort last-used timestamp update. Never throws — a failure here must
 * never block or fail a signing request; it is observability only.
 *
 * no longer rewrites the whole store on every /sign. The
 * snapshot is updated in memory; in pg mode the timestamp is flushed as a
 * single-column update at most once per identity per minute, and it never
 * moves the record's version — so it can never collide with, or undo, a
 * revocation written by another replica.
 */
/**
 * the 'oidc' identity linked to a verified (issuer, subject), or null. The record is returned as is - the caller (signAuth) applies the same enabled / revoked /
 * permission checks as for an API-key identity.
 */
function resolveByExternalIdentity(issuer, subject) {
  if (typeof issuer !== 'string' || typeof subject !== 'string') return null;
  _ensureLoaded();
  const id = _externalIndex.get(_extKey(issuer, subject));
  const identity = id ? _col.get(id) : null;
  if (!identity || identity.credentialType !== 'oidc' || !identity.externalIdentity) return null;
  if (identity.externalIdentity.issuer !== issuer || identity.externalIdentity.subject !== subject) return null;
  return { ...identity };
}

function touchLastUsed(id) {
  try {
    _col.touch(id, new Date().toISOString());
  } catch (e) {
    emit('WARN', 'SIGNING_IDENTITY_TOUCH_FAILED', { identityId: id, error: e.message });
  }
}

// ── Testing helpers ───────────────────────────────────────────────────────────

function _reset() {
  _col._reset();
  _keyHashIndex = new Map();
  _prevKeyHashIndex = new Map();
}

// Memory mode: drop the snapshot and re-seed from the legacy file.
function _reload() {
  _col._reset();
  _ensureLoaded();
}

// Tests / offline dev tooling (memory mode only): write the snapshot as the seed fixture.
function exportSeedFixture() { return _col.exportSeedFixture(); }

module.exports = {
  ENVIRONMENTS,
  CREDENTIAL_TYPES,
  API_KEY_PREFIX,
  createSigningIdentity,
  getSigningIdentity,
  listSigningIdentities,
  updateSigningIdentity,
  issueSigningKey,
  revokeSigningKey,
  deleteSigningIdentity,
  resolveSigningIdentity,
  resolveSigningIdentityDetailed,
  resolveByExternalIdentity,
  touchLastUsed,
  _reset,
  _reload,
  exportSeedFixture,
  SigningStoreError,
};
