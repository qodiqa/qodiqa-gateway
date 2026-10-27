'use strict';

const { isControlPlaneError } = require('../../../core/controlPlane');

/**
 * Signing Identity Administration Router — TRUST-1 remediation.
 *
 * Factory: createSigningIdentitiesAdminRouter({ store, requirePermission })
 *
 * Mounted at /signing-identities in server.js, behind the full admin/ops
 * middleware stack (rate limit, IP allowlist, ops auth, RBAC resolve) plus
 * MANAGE_SIGNING_IDENTITIES / READ_SIGNING_IDENTITIES (src/core/rbac/roles.js).
 * This is the ONLY HTTP-reachable way to provision a signing identity — there
 * is no bootstrap/default identity created implicitly, mirroring how RBAC
 * users are provisioned (see scripts/rbac-bootstrap-key.js for the equivalent
 * out-of-band bootstrap path: scripts/provision-signing-identity.js).
 *
 * Routes:
 *   GET    /signing-identities              — list identities        [READ_SIGNING_IDENTITIES]
 *   POST   /signing-identities              — create identity        [MANAGE_SIGNING_IDENTITIES]
 *   GET    /signing-identities/:id          — get identity by ID     [READ_SIGNING_IDENTITIES]
 *   PATCH  /signing-identities/:id          — update scope/enabled    [MANAGE_SIGNING_IDENTITIES]
 *   PUT    /signing-identities/:id          — DEPRECATED alias of PATCH above; see API-9 note below
 *   DELETE /signing-identities/:id          — permanently delete      [MANAGE_SIGNING_IDENTITIES]
 *   POST   /signing-identities/:id/api-key  — issue/rotate key       [MANAGE_SIGNING_IDENTITIES]
 *   DELETE /signing-identities/:id/api-key  — revoke key             [MANAGE_SIGNING_IDENTITIES]
 *
 * API-9 remediation: the update route only ever applies a partial
 * update, which is PATCH semantics, not PUT. PATCH is now canonical; the
 * original PUT route keeps working, unchanged, via the shared
 * src/middleware/deprecation.js helper. Schema-validation failures on this
 * router now return 400 (previously 422) to match the rest of the API
 * surface — 422 is reserved for post-parse business-rule violations (the
 * INVALID_* store-level codes below).
 */

const { Router } = require('express');
const { emit }    = require('../../../../services/logger');
const store       = require('../../../core/signing/signingIdentityStore');
const { SigningStoreError } = require('../../../core/signing/signingIdentityStore');
const { createSigningIdentitySchema, updateSigningIdentitySchema } = require('../../../validation/schemas/signingIdentity.schema');
const { success, failure } = require('../../response');
const { sendDeprecationHeaders } = require('../../../middleware/deprecation');
const {
  parsePagination, paginateArray, isPaginationRequested,
} = require('../../../utils/pagination');

// Thin adapters over the canonical envelope (src/api/response.js) that keep
// this file's existing (req, status) call-site ergonomics — the actual
// envelope shape is built in exactly one place, response.js.
function _ok(res, req, data, status = 200) {
  return success(res, data, status);
}

function _err(res, req, status, code, detail) {
  emit('WARN', `SIGNING_IDENTITY_ADMIN_${code}`, { requestId: req.requestId, detail });
  return failure(res, code, detail, status);
}

function _storeError(res, req, err) {
  // control-plane refusals keep their status — 409 stale write, 503 stale snapshot.
  if (isControlPlaneError(err)) return _err(res, req, err.status, err.code, err.message);
  if (err instanceof SigningStoreError) {
    const HTTP = {
      NOT_FOUND:               404,
      NO_API_KEY:              422,
      INVALID_NAME:            422,
      INVALID_TENANT_ID:       422,
      INVALID_ENVIRONMENT:     422,
      INVALID_ALLOWED_PROVIDERS: 422,
      INVALID_PERMISSIONS:     422,
      INVALID_CREDENTIAL_TYPE: 422,
      INVALID_MAX_TTL:         422,
    };
    const status = HTTP[err.code] ?? 422;
    return _err(res, req, status, err.code, err.message);
  }
  emit('ERROR', 'SIGNING_IDENTITY_ADMIN_INTERNAL', { requestId: req.requestId, error: err.message });
  return _err(res, req, 500, 'INTERNAL_ERROR', 'An unexpected error occurred');
}

function _actor(req) {
  const h = req.rbacUser?.username;
  return typeof h === 'string' && h.trim() ? h.trim().slice(0, 64) : 'operator';
}

function _safeIdentity(identity) {
  return {
    id:               identity.id,
    name:             identity.name,
    tenantId:         identity.tenantId,
    environment:      identity.environment,
    allowedProviders: identity.allowedProviders,
    permissions:      identity.permissions,
    credentialType:   identity.credentialType,
    externalIdentity: identity.externalIdentity ?? null,   //
    requireAssurance: identity.requireAssurance === true,  //
    maxTtlMs:         identity.maxTtlMs,
    enabled:          identity.enabled,
    revoked:          identity.revoked,
    revokedAt:        identity.revokedAt,
    revokedBy:        identity.revokedBy,
    revokedReason:    identity.revokedReason,
    hasApiKey:        !!identity.apiKeyHash, // boolean — hash never exposed
    apiKeyIssuedAt:   identity.apiKeyIssuedAt,
    apiKeyExpiresAt:  identity.apiKeyExpiresAt ?? null, // (D5)
    lastUsedAt:        identity.lastUsedAt,
    createdAt:        identity.createdAt,
    createdBy:        identity.createdBy,
    updatedAt:        identity.updatedAt,
    updatedBy:        identity.updatedBy,
  };
}

function createSigningIdentitiesAdminRouter({ requirePermission }) {
  const router = Router();

  const _canRead   = requirePermission('READ_SIGNING_IDENTITIES');
  const _canManage = requirePermission('MANAGE_SIGNING_IDENTITIES');

  // Opt-in pagination (API-4 remediation): omitting page/pageSize/limit/offset
  // preserves this endpoint's original unbounded response for backward
  // compatibility; supplying any of them switches to sliced output with
  // canonical pagination metadata.
  router.get('/', _canRead, (req, res) => {
    try {
      const identities = store.listSigningIdentities().map(_safeIdentity);
      if (!isPaginationRequested(req.query)) {
        return _ok(res, req, { identities, total: identities.length });
      }
      const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 500 });
      const { items, ...meta } = paginateArray(identities, { page, pageSize });
      _ok(res, req, { identities: items, total: identities.length, ...meta });
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  router.post('/', _canManage, async (req, res) => {
    const parsed = createSigningIdentitySchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return _err(res, req, 400, 'INVALID_REQUEST', parsed.error.issues[0]?.message ?? 'invalid request body');
    }
    const actor = _actor(req);
    try {
      const identity = await store.createSigningIdentity({ ...parsed.data, createdBy: actor });
      emit('INFO', 'SIGNING_IDENTITY_ADMIN_CREATED', { requestId: req.requestId, actor, identityId: identity.id });
      _ok(res, req, { identity: _safeIdentity(identity) }, 201);
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  router.get('/:id', _canRead, (req, res) => {
    const identity = store.getSigningIdentity(req.params.id);
    if (!identity) return _err(res, req, 404, 'NOT_FOUND', `Signing identity "${req.params.id}" not found`);
    _ok(res, req, { identity: _safeIdentity(identity) });
  });

  async function _updateIdentity(req, res) {
    const parsed = updateSigningIdentitySchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return _err(res, req, 400, 'INVALID_REQUEST', parsed.error.issues[0]?.message ?? 'invalid request body');
    }
    const actor = _actor(req);
    try {
      const identity = await store.updateSigningIdentity(req.params.id, { ...parsed.data, updatedBy: actor });
      emit('INFO', 'SIGNING_IDENTITY_ADMIN_UPDATED', { requestId: req.requestId, actor, identityId: req.params.id });
      _ok(res, req, { identity: _safeIdentity(identity) });
    } catch (e) {
      _storeError(res, req, e);
    }
  }
  router.patch('/:id', _canManage, _updateIdentity);
  router.put('/:id', _canManage, (req, res) => {
    sendDeprecationHeaders(res, {
      successorLink: `/signing-identities/${encodeURIComponent(req.params.id)}`,
      warnEvent:     'SIGNING_IDENTITY_ADMIN_PUT_DEPRECATED_USED',
      warnDetails:   { requestId: req.requestId, identityId: req.params.id,
        message: 'PUT /signing-identities/:id is deprecated: this route only ever performs a partial update. Use PATCH /signing-identities/:id instead.' },
    });
    return _updateIdentity(req, res);
  });

  router.delete('/:id', _canManage, async (req, res) => {
    const actor = _actor(req);
    try {
      await store.deleteSigningIdentity(req.params.id, { deletedBy: actor });
      emit('WARN', 'SIGNING_IDENTITY_ADMIN_DELETED', { requestId: req.requestId, actor, identityId: req.params.id });
      _ok(res, req, { deleted: true, identityId: req.params.id });
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // Issue or rotate the signing API key. Plaintext returned exactly once.
  router.post('/:id/api-key', _canManage, async (req, res) => {
    const actor = _actor(req);
    try {
      const { plaintext, issuedAt, expiresAt, previousKeyGraceUntil } = await store.issueSigningKey(req.params.id, { issuedBy: actor });
      emit('INFO', 'SIGNING_IDENTITY_ADMIN_KEY_ISSUED', { requestId: req.requestId, actor, identityId: req.params.id });
      _ok(res, req, {
        apiKey:  plaintext,
        issuedAt,
        expiresAt:             expiresAt ?? null,             // (D5)
        previousKeyGraceUntil: previousKeyGraceUntil ?? null, // (D5)
        message: 'Store this signing API key securely — it will not be displayed again.',
      }, 201);
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  // Immediately invalidate the signing API key.
  router.delete('/:id/api-key', _canManage, async (req, res) => {
    const actor = _actor(req);
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.slice(0, 512) : null;
    try {
      await store.revokeSigningKey(req.params.id, { revokedBy: actor, reason });
      emit('WARN', 'SIGNING_IDENTITY_ADMIN_KEY_REVOKED', { requestId: req.requestId, actor, identityId: req.params.id });
      _ok(res, req, { revoked: true, identityId: req.params.id });
    } catch (e) {
      _storeError(res, req, e);
    }
  });

  router.use((req, res) => _err(res, req, 405, 'METHOD_NOT_ALLOWED', 'Method not allowed'));

  return router;
}

module.exports = { createSigningIdentitiesAdminRouter };
