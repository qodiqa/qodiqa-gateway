'use strict';

// Key administration API — protected by opsAuth middleware (applied in server.js).
//
// Routes:
//   GET  /key-admin/health                     — aggregate health across all tenants
//   GET  /key-admin/inventory                  — full classified key inventory
//   GET  /key-admin/rotation-scheduler/status  — automatic rotation scheduler status
//   POST /key-admin/purge-expired              — archive and remove expired deprecated keys
//   POST /key-admin/kek/rotate — rotate the KMS provider's own wrapping key
//   GET  /key-admin/:clientId/status           — per-tenant key health
//   POST /key-admin/:clientId/rotate — EMERGENCY rotate: revokes the outgoing key
//   POST /key-admin/:clientId/rotate-graceful  — PLANNED rotate: deprecates (keeps verifiable) the outgoing key
//   POST /key-admin/:clientId/revoke           — revoke a specific key (keyId in body)
//   POST /key-admin/:clientId/recover          — provision new active key for no-key clients

const { Router }         = require('express');
const tenantKeyManager   = require('../../../services/artifact/tenantKeyManager');
const keyManager         = require('../../../services/artifact/keyManager');
const keyStore           = require('../../../services/artifact/keyStore');
const rotationLock       = require('../../infra/keys/rotationLock');
const { getDefaultScheduler } = require('../../../services/artifact/rotationScheduler');
const keyProviderFactory = require('../../infra/keys/keyProviderFactory');
const { emit }           = require('../../../services/logger');
const { success, failure } = require('../response');
const {
  parsePagination, paginateArray, isPaginationRequested,
} = require('../../utils/pagination');
const {
  clientIdParamSchema,
  purgeExpiredBodySchema,
  revokeKeyBodySchema,
} = require('../../validation/schemas/keyAdmin.schema');

const router = Router();

// ── remediation ──────────────────────────────────────────────────────────
// Manual admin rotation/recovery used to call the synchronous keyManager.rotate()
// directly, bypassing the distributed rotation lock the automatic scheduler
// acquires before every rotation (services/artifact/rotationScheduler.js
// _rotateWithRetry). In a multi-instance deployment sharing keys.json (single
// PVC/EFS mount — see docs/deployment/topology.md), that meant an operator-triggered
// rotation could race the scheduler's own rotation for the same client, or two
// operators (or a retried request) rotating the same client concurrently could
// race each other — exactly the "two active keys" / "lost rotation" class of
// bug the lock exists to prevent. This is the CRYPTO-1 concurrency requirement:
// concurrent requests must never observe two signing keys or zero signing keys.
//
// _withRotationLock() gives every manual, lock-protected mutation (rotate,
// recover) the same acquire-before-mutate / release-after guarantee the
// scheduler already has, using the SAME Redis-backed lock and the SAME
// fail-closed contract: if the lock cannot be acquired (held by another
// rotation) or Redis is unreachable, the mutation is refused — never performed
// unlocked.
const ROTATE_LOCK_TTL_MS = parseInt(process.env.QODIQA_KEY_ROTATION_LOCK_TTL_MS || '30000', 10);

async function _withRotationLock(clientId, reqId, fn) {
  let lockResult;
  try {
    lockResult = await rotationLock.acquire(clientId, ROTATE_LOCK_TTL_MS);
  } catch (err) {
    emit('ERROR', 'KEY_ADMIN_ROTATION_LOCK_UNAVAILABLE', { clientId, error: err.message, requestId: reqId });
    const unavailable = new Error('LOCK_UNAVAILABLE');
    unavailable.code = 'LOCK_UNAVAILABLE';
    throw unavailable;
  }
  if (!lockResult.acquired) {
    emit('WARN', 'KEY_ADMIN_ROTATION_LOCKED', { clientId, requestId: reqId });
    const busy = new Error('ROTATION_IN_PROGRESS');
    busy.code = 'ROTATION_IN_PROGRESS';
    throw busy;
  }
  try {
    // the lock's fencing token goes to the keystore, which refuses a commit whose fence
    // is not newer than the last one it accepted — a rotation that outlived its lock (GC pause, slow KMS/HSM) can no
    // longer overwrite the rotation that took the lock over. Both outcomes surface as the existing 409.
    return await fn({ fence: lockResult.fence });
  } catch (err) {
    if (err && (err.code === 'KEYSTORE_STALE_FENCE' || err.code === 'KEY_ROTATION_LOCK_LOST')) {
      emit('WARN', 'KEY_ADMIN_ROTATION_SUPERSEDED', { clientId, requestId: reqId, cause: err.code });
      const busy = new Error('ROTATION_IN_PROGRESS');
      busy.code = 'ROTATION_IN_PROGRESS';
      throw busy;
    }
    throw err;
  } finally {
    await rotationLock.release(clientId, lockResult.token);
  }
}

// ── GET /health ───────────────────────────────────────────────────────────────

// ── GET /inventory ────────────────────────────────────────────────────────────

// Opt-in pagination (API-4 remediation): omitting page/pageSize/limit/offset
// preserves this endpoint's original unbounded `entries` array for backward
// compatibility; supplying any of them slices `entries` and adds canonical
// pagination metadata, leaving the summary counts (totalKeys, activeKeys, …)
// untouched since they always describe the full inventory.
router.get('/inventory', (req, res) => {
  const reqId = req.requestId ?? null;
  try {
    const inventory = keyStore.getInventory();
    emit('INFO', 'KEY_ADMIN_INVENTORY', {
      totalKeys:    inventory.totalKeys,
      activeKeys:   inventory.activeKeys,
      requestId:    reqId,
    });
    if (!isPaginationRequested(req.query)) {
      return success(res, inventory);
    }
    const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 500 });
    const { items, ...meta } = paginateArray(inventory.entries, { page, pageSize });
    return success(res, { ...inventory, entries: items, ...meta });
  } catch (err) {
    emit('ERROR', 'KEY_ADMIN_INVENTORY_ERROR', { error: err.message, requestId: reqId });
    return failure(res, 'INTERNAL_ERROR', 'Failed to load key inventory', 500);
  }
});

// ── POST /purge-expired ───────────────────────────────────────────────────────
// Body (optional): { "clientId": "<clientId>" }
// Omit clientId to purge expired deprecated keys across all clients.

router.post('/purge-expired', (req, res) => {
  const reqId  = req.requestId ?? null;
  const parsed = purgeExpiredBodySchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    return failure(res, 'INVALID_CLIENT_ID', 'Invalid clientId', 400);
  }
  const { clientId } = parsed.data;

  try {
    const result = keyStore.purgeExpiredDeprecated(clientId);
    emit('INFO', 'KEY_ADMIN_PURGED', {
      purged:    result.purged,
      clientId:  clientId ?? 'ALL',
      requestId: reqId,
    });
    return success(res, { purged: result.purged, archived: result.archived });
  } catch (err) {
    emit('ERROR', 'KEY_ADMIN_PURGE_ERROR', { error: err.message, clientId: clientId ?? 'ALL', requestId: reqId });
    return failure(res, 'PURGE_FAILED', 'Failed to purge expired keys', 500);
  }
});

// ── GET /rotation-scheduler/status ────────────────────────────────────────────

router.get('/rotation-scheduler/status', (req, res) => {
  const reqId = req.requestId ?? null;
  try {
    const status = getDefaultScheduler().getStatus();
    return success(res, status);
  } catch (err) {
    emit('ERROR', 'KEY_ADMIN_ROTATION_SCHEDULER_STATUS_ERROR', { error: err.message, requestId: reqId });
    return failure(res, 'INTERNAL_ERROR', 'Failed to load rotation scheduler status', 500);
  }
});

router.get('/health', (req, res) => {
  const reqId = req.requestId ?? null;
  try {
    const summary = tenantKeyManager.getKeyHealthSummary();
    return success(res, summary);
  } catch (err) {
    emit('ERROR', 'KEY_ADMIN_HEALTH_ERROR', { error: err.message, requestId: reqId });
    return failure(res, 'INTERNAL_ERROR', 'Failed to load key health summary', 500);
  }
});

// ── GET /:clientId/status ─────────────────────────────────────────────────────

router.get('/:clientId/status', (req, res) => {
  const reqId = req.requestId ?? null;
  const pParsed = clientIdParamSchema.safeParse(req.params);
  if (!pParsed.success) {
    return failure(res, 'INVALID_CLIENT_ID', 'Invalid clientId', 400);
  }
  const { clientId } = pParsed.data;

  try {
    const status = tenantKeyManager.getTenantKeyStatus(clientId);
    if (status.keyCount === 0) {
      return failure(res, 'NOT_FOUND', 'No keys found for client', 404, { clientId });
    }
    return success(res, status);
  } catch (err) {
    emit('ERROR', 'KEY_ADMIN_STATUS_ERROR', { clientId, error: err.message, requestId: reqId });
    return failure(res, 'INTERNAL_ERROR', 'Failed to load key status', 500);
  }
});

// ── POST /kek/rotate ──────────────────────────────────────────────────────────
// rotates the active KMS provider's own wrapping key (KEK) — the key
// that encrypts artifact-signing private key material at rest. Distinct from
// /:clientId/rotate, which rotates an artifact signing key. Registered ABOVE
// /:clientId/rotate (a literal "kek" clientId segment would otherwise be
// swallowed by that route first).
//
// Lock-protected with a fixed pseudo-clientId ('__KEK__') via the same
// distributed rotation lock used for per-client rotation — this
// reuses existing infrastructure rather than introducing new locking logic,
// and prevents two concurrent KEK rotation requests (or a retried request)
// from racing the underlying KMS provider's own rotateWrappingKey() call.
//
// Rotating the KEK does NOT retroactively re-encrypt keys.json's existing
// ciphertext — that ciphertext remains valid and decryptable (the old KEK is
// still known to the KMS provider's own history), but new key material will
// be encrypted under the new KEK going forward. Run
// scripts/migrate-keys-json-kek.js afterward (dry-run by default) to migrate
// existing stored key material onto the new KEK, mirroring the
// migration pattern (scripts/migrate-webhook-secrets-kek.js).

router.post('/kek/rotate', async (req, res) => {
  const reqId = req.requestId ?? null;
  const operator = req.rbacUser?.username || req.rbacUser?.id
    || (req.operatorAuthMethod === 'shared-token' ? 'shared-token' : null);

  // the local provider's rotateWrappingKey() changes
  // nothing (the KEK is QODIQA_KEY_ENCRYPTION_KEY; rotating it is an operator
  // env-var replacement + migration). Answering rotated:true and emitting
  // KEY_ADMIN_KEK_ROTATED for it was a false audit record — refuse explicitly.
  const kekProviderType = typeof keyProviderFactory.getKekProviderType === 'function'
    ? keyProviderFactory.getKekProviderType() : undefined;
  if (kekProviderType === 'local') {
    emit('WARN', 'KEY_ADMIN_KEK_ROTATE_NOT_SUPPORTED', { requestId: reqId, operator, kekProvider: 'local' });
    return failure(res, 'KEK_ROTATION_NOT_SUPPORTED',
      'The local KEK provider cannot rotate its wrapping key in-process: replace QODIQA_KEY_ENCRYPTION_KEY and run scripts/migrate-keys-json-kek.js', 409,
      { kekProvider: 'local', rotated: false });
  }

  try {
    const result = await _withRotationLock('__KEK__', reqId, () => keyProviderFactory.rotateWrappingKey());
    emit('INFO', 'KEY_ADMIN_KEK_ROTATED', { requestId: reqId, operator, version: result?.version ?? null });
    return success(res, {
      rotated:           true,
      version:            result?.version ?? null,
      migrationRequired:  true,
      migrationScript:    'scripts/migrate-keys-json-kek.js',
    });
  } catch (err) {
    if (err.code === 'ROTATION_IN_PROGRESS') {
      return failure(res, 'ROTATION_IN_PROGRESS', 'A KEK rotation is already in progress', 409);
    }
    if (err.code === 'LOCK_UNAVAILABLE') {
      return failure(res, 'LOCK_UNAVAILABLE', 'Could not acquire the rotation lock', 503);
    }
    emit('ERROR', 'KEY_ADMIN_KEK_ROTATE_FAILED', { error: err.message, requestId: reqId, operator });
    return failure(res, 'KEK_ROTATION_FAILED', 'KEK rotation failed', 500);
  }
});

// ── POST /mac-keys/rotate ───────────────────────────────────
// Rotates the keystore MAC keyring (src/core/security/macKeyring.js) that signs
// consent-cache entries and the revocation / org-status pub/sub messages. The
// previous key stays verifiable for one more rotation, so in-flight messages and
// cached entries (≤ 60 s) keep verifying on every node that shares the file.
// Lock-protected like /kek/rotate (fixed pseudo-clientId); registered before
// /:clientId/rotate so a literal "mac-keys" is never captured as {clientId}.
// The response carries key ids only — never key material.

router.post('/mac-keys/rotate', async (req, res) => {
  const reqId = req.requestId ?? null;
  const operator = req.rbacUser?.username || req.rbacUser?.id
    || (req.operatorAuthMethod === 'shared-token' ? 'shared-token' : null);
  try {
    const macKeyring = require('../../core/security/macKeyring');
    const result = await _withRotationLock('__MAC_KEYRING__', reqId, () => macKeyring.rotate({ by: operator || 'unknown' }));
    emit('INFO', 'KEY_ADMIN_MAC_KEYRING_ROTATED', { requestId: reqId, operator, activeKid: result.activeKid, previousKid: result.previousKid });
    return success(res, { rotated: true, activeKid: result.activeKid, previousKid: result.previousKid });
  } catch (err) {
    if (err.code === 'ROTATION_IN_PROGRESS') {
      return failure(res, 'ROTATION_IN_PROGRESS', 'A MAC keyring rotation is already in progress', 409);
    }
    if (err.code === 'LOCK_UNAVAILABLE') {
      return failure(res, 'LOCK_UNAVAILABLE', 'Could not acquire the rotation lock', 503);
    }
    emit('ERROR', 'KEY_ADMIN_MAC_KEYRING_ROTATE_FAILED', { error: err.message, code: err.code ?? null, requestId: reqId, operator });
    return failure(res, 'MAC_KEYRING_ROTATION_FAILED', 'MAC keyring rotation failed', 500);
  }
});

// ── POST /:clientId/rotate ────────────────────────────────────────────────────
// EMERGENCY rotation — this is the operator's ordinary
// "rotate the key" action, and it now defaults to keyManager.rotateAsync()'s
// 'emergency' mode: the outgoing key is REVOKED, not deprecated, so it loses
// both signing and verification capability in the same call. This closes the
// gap where rotation alone left a potentially compromised key fully able to
// verify signatures. If you need the previous behavior (outgoing key kept
// verifiable for a planned migration, NOT a suspected compromise), use the
// separate POST /:clientId/rotate-graceful endpoint below — it is a distinct
// operation, never a flag on this one, so a compromise-response rotation can
// never accidentally fall back to the weaker semantics.
//
// Lock-protected: acquires the same distributed rotation lock the
// automatic scheduler uses before mutating keys.json, so a manual rotation can
// never race the scheduler or another manual rotation for the same clientId.

router.post('/:clientId/rotate', async (req, res) => {
  const reqId = req.requestId ?? null;
  const pParsed = clientIdParamSchema.safeParse(req.params);
  if (!pParsed.success) {
    return failure(res, 'INVALID_CLIENT_ID', 'Invalid clientId', 400);
  }
  const { clientId } = pParsed.data;

  const operator = req.rbacUser?.username || req.rbacUser?.id
    || (req.operatorAuthMethod === 'shared-token' ? 'shared-token' : null);

  try {
    const result = await _withRotationLock(clientId, reqId, (lock) => keyManager.rotateAsync(clientId, {
      fence:       lock.fence, //
      // mode is mandatory — rotateKey()/rotateKeyAsync() no longer
      // default to 'emergency' when omitted. This route's whole purpose IS
      // emergency (incident-response) rotation, so it now says so explicitly
      // rather than relying on the (removed) implicit default.
      mode:        'emergency',
      reason:      'MANUAL_ADMIN_ROTATION',
      triggeredBy: operator ? `operator:${operator}` : 'operator',
    }));
    emit('INFO', 'KEY_ADMIN_ROTATED', {
      clientId, newKeyId: result.keyId, requestId: reqId, operator,
      mode: result.mode, previousKeyId: result.previousKeyId, previousKeyStatus: result.previousKeyStatus,
    });
    return success(res, {
      keyId:             result.keyId,
      version:           result.version,
      clientId,
      mode:              result.mode,
      previousKeyId:     result.previousKeyId,
      previousKeyStatus: result.previousKeyStatus,
    });
  } catch (err) {
    if (err.code === 'ROTATION_IN_PROGRESS') {
      return failure(res, 'ROTATION_IN_PROGRESS', 'A rotation is already in progress for this client', 409);
    }
    if (err.code === 'LOCK_UNAVAILABLE') {
      return failure(res, 'LOCK_UNAVAILABLE', 'Could not acquire the rotation lock', 503);
    }
    if (err.code === 'NATIVE_REVOCATION_FAILED') {
      return failure(res, 'NATIVE_REVOCATION_FAILED', 'Native provider revocation failed', 502, { nativeRevocation: err.nativeRevocation ?? null });
    }
    emit('ERROR', 'KEY_ADMIN_ROTATE_FAILED', { clientId, error: err.message, requestId: reqId });
    const httpStatus = err.message.includes('invariant violation') ? 409 : 500;
    return failure(res, 'ROTATION_FAILED', 'Key rotation failed', httpStatus);
  }
});

// ── POST /:clientId/rotate-graceful ───────────────────────────────────────────
// PLANNED rotation — the outgoing key is DEPRECATED, not revoked: it
// can no longer sign, but remains verifiable so artifacts signed just before
// this rotation continue to pass verification. Use this ONLY for planned,
// non-incident maintenance rotation. Never use this in response to a
// suspected key compromise — use POST /:clientId/rotate (emergency default)
// or POST /:clientId/revoke instead. This is a deliberately separate
// endpoint, not a body flag on /rotate, so the emergency default can never be
// silently downgraded by a caller.
//
// Lock-protected identically to /rotate.

router.post('/:clientId/rotate-graceful', async (req, res) => {
  const reqId = req.requestId ?? null;
  const pParsed = clientIdParamSchema.safeParse(req.params);
  if (!pParsed.success) {
    return failure(res, 'INVALID_CLIENT_ID', 'Invalid clientId', 400);
  }
  const { clientId } = pParsed.data;

  const operator = req.rbacUser?.username || req.rbacUser?.id
    || (req.operatorAuthMethod === 'shared-token' ? 'shared-token' : null);

  try {
    const result = await _withRotationLock(clientId, reqId, (lock) => keyManager.rotateGracefullyAsync(clientId, {
      fence:       lock.fence, //
      reason:      'MANUAL_ADMIN_GRACEFUL_ROTATION',
      triggeredBy: operator ? `operator:${operator}` : 'operator',
    }));
    emit('INFO', 'KEY_ADMIN_ROTATED', {
      clientId, newKeyId: result.keyId, requestId: reqId, operator,
      mode: result.mode, previousKeyId: result.previousKeyId, previousKeyStatus: result.previousKeyStatus,
    });
    return success(res, {
      keyId:             result.keyId,
      version:           result.version,
      clientId,
      mode:              result.mode,
      previousKeyId:     result.previousKeyId,
      previousKeyStatus: result.previousKeyStatus,
    });
  } catch (err) {
    if (err.code === 'ROTATION_IN_PROGRESS') {
      return failure(res, 'ROTATION_IN_PROGRESS', 'A rotation is already in progress for this client', 409);
    }
    if (err.code === 'LOCK_UNAVAILABLE') {
      return failure(res, 'LOCK_UNAVAILABLE', 'Could not acquire the rotation lock', 503);
    }
    emit('ERROR', 'KEY_ADMIN_ROTATE_FAILED', { clientId, error: err.message, requestId: reqId, mode: 'graceful' });
    const httpStatus = err.message.includes('invariant violation') ? 409 : 500;
    return failure(res, 'ROTATION_FAILED', 'Key rotation failed', httpStatus);
  }
});

// ── POST /:clientId/revoke ────────────────────────────────────────────────────
// Body: { "keyId": "<clientId>:key_v<n>", "reason"?: "<free text>" }
//
// Revocation propagates to the active native signing provider (Vault Transit /
// HSM) when one is configured — see keyManager.revoke() / keyStore.revokeKeyAsync()
//. The operator identity attached by opsAuth (req.rbacUser) is recorded
// in the audit trail alongside the provider's own revocation outcome.

router.post('/:clientId/revoke', async (req, res) => {
  const reqId = req.requestId ?? null;

  const pParsed = clientIdParamSchema.safeParse(req.params);
  if (!pParsed.success) {
    return failure(res, 'INVALID_CLIENT_ID', 'Invalid clientId', 400);
  }
  const { clientId } = pParsed.data;

  const bParsed = revokeKeyBodySchema.safeParse(req.body ?? {});
  if (!bParsed.success) {
    return failure(res, 'INVALID_KEY_ID', 'Invalid keyId', 400);
  }
  const { keyId, reason } = bParsed.data;

  // Ownership: the keyId prefix must match the clientId in the route.
  const keyClientId = keyId.slice(0, keyId.indexOf(':'));
  if (keyClientId !== clientId) {
    return failure(res, 'KEY_CLIENT_MISMATCH', 'keyId does not belong to this client', 400);
  }

  const operator = req.rbacUser?.username || req.rbacUser?.id
    || (req.operatorAuthMethod === 'shared-token' ? 'shared-token' : null);

  try {
    const result = await keyManager.revoke(clientId, keyId, { reason: reason ?? null, operator });
    emit('INFO', 'KEY_ADMIN_REVOKED', {
      clientId, keyId, requestId: reqId, operator,
      nativeRevocation: result?.nativeRevocation ?? null,
    });
    return success(res, {
      revoked:          true,
      keyId,
      clientId,
      nativeRevocation: result?.nativeRevocation ?? null,
    });
  } catch (err) {
    emit('ERROR', 'KEY_ADMIN_REVOKE_FAILED', {
      clientId, keyId, error: err.message, requestId: reqId, operator,
      code: err.code || null,
    });

    // A native provider was reachable and rejected the request, or accepted
    // it locally but failed to propagate — either way this is NOT a 404/500
    // client-input problem, it's an upstream-provider failure. Surfaced as
    // 502 with the partial revocation state so operators know the local key
    // is already blocked while the provider boundary may not be.
    if (err.code === 'NATIVE_REVOCATION_FAILED') {
      return failure(res, 'NATIVE_REVOCATION_FAILED', 'Native provider revocation failed', 502, { nativeRevocation: err.nativeRevocation ?? null });
    }

    const httpStatus = err.message.includes('unknown') ? 404 : 500;
    return failure(res, httpStatus === 404 ? 'NOT_FOUND' : 'REVOCATION_FAILED', 'Key revocation failed', httpStatus);
  }
});

// ── POST /:clientId/recover ───────────────────────────────────────────────────
// Provisions a new active key for a client that has existing key history but
// no current active key (e.g. all previous keys deprecated or revoked).
// For clients with no history at all, use POST /:clientId/rotate instead.
//
// Lock-protected: the "no active key" check and the provisioning it
// gates both run inside the same rotation-lock critical section, so two
// concurrent recover calls (or a recover racing a rotate/the scheduler) can
// never both observe "no active key" and both provision — see
// _withRotationLock() above.

router.post('/:clientId/recover', async (req, res) => {
  const reqId = req.requestId ?? null;
  const pParsed = clientIdParamSchema.safeParse(req.params);
  if (!pParsed.success) {
    return failure(res, 'INVALID_CLIENT_ID', 'Invalid clientId', 400);
  }
  const { clientId } = pParsed.data;

  const operator = req.rbacUser?.username || req.rbacUser?.id
    || (req.operatorAuthMethod === 'shared-token' ? 'shared-token' : null);

  try {
    const result = await _withRotationLock(clientId, reqId, async (lock) => {
      const status = tenantKeyManager.getTenantKeyStatus(clientId);
      if (status.activeKeyCount > 0) {
        const conflict = new Error('ALREADY_HAS_ACTIVE_KEY');
        conflict.code = 'ALREADY_HAS_ACTIVE_KEY';
        conflict.activeKeyId = status.activeKey?.keyId;
        throw conflict;
      }
      return keyManager.rotateAsync(clientId, {
        fence: lock.fence, //
        // mode is mandatory on every rotateAsync() call now. It is a
        // no-op here in practice — this branch only ever runs when the
        // client has NO active key (checked immediately above, inside the
        // same lock), so keyStore.js's recovery path never reaches the
        // mode-resolution branch at all — but every call site must still
        // supply a valid value rather than relying on the removed default.
        mode:        'emergency',
        reason:      'MANUAL_ADMIN_RECOVERY',
        triggeredBy: operator ? `operator:${operator}` : 'operator',
      });
    });
    emit('INFO', 'KEY_ADMIN_RECOVERED', { clientId, newKeyId: result.keyId, requestId: reqId, operator });
    return success(res, {
      recovered:  true,
      keyId:      result.keyId,
      version:    result.version,
      clientId,
    });
  } catch (err) {
    if (err.code === 'ALREADY_HAS_ACTIVE_KEY') {
      return failure(res, 'ALREADY_HAS_ACTIVE_KEY', 'Client already has an active key', 409, { activeKeyId: err.activeKeyId });
    }
    if (err.code === 'ROTATION_IN_PROGRESS') {
      return failure(res, 'ROTATION_IN_PROGRESS', 'A rotation is already in progress for this client', 409);
    }
    if (err.code === 'LOCK_UNAVAILABLE') {
      return failure(res, 'LOCK_UNAVAILABLE', 'Could not acquire the rotation lock', 503);
    }
    emit('ERROR', 'KEY_ADMIN_RECOVER_FAILED', { clientId, error: err.message, requestId: reqId });
    return failure(res, 'RECOVERY_FAILED', 'Key recovery failed', 500);
  }
});

router.use((req, res) => {
  failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405);
});

module.exports = router;
