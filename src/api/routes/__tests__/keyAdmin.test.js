'use strict';

// Tests for the /key-admin route handlers.
// tenantKeyManager and keyManager are mocked.

jest.mock('../../../../services/artifact/tenantKeyManager');
jest.mock('../../../../services/artifact/keyManager');
jest.mock('../../../infra/keys/rotationLock');
jest.mock('../../../infra/keys/keyProviderFactory');
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const request         = require('supertest');
const express         = require('express');
const keyAdminRouter  = require('../keyAdmin');
const tenantKeyManager = require('../../../../services/artifact/tenantKeyManager');
const keyManager      = require('../../../../services/artifact/keyManager');
const rotationLock    = require('../../../infra/keys/rotationLock');
const keyProviderFactory = require('../../../infra/keys/keyProviderFactory');

// Default: lock always free and grantable — individual tests override this to
// exercise the busy/unavailable paths. Mirrors the real module's contract:
// acquire() resolves { acquired, token }, release() resolves a boolean.
function _installFreeLock() {
  let counter = 0;
  rotationLock.acquire.mockImplementation(async () => ({ acquired: true, token: `tok-${++counter}` }));
  rotationLock.release.mockImplementation(async () => true);
}

const VALID_HEALTH_SUMMARY = {
  timestamp:       '2024-06-01T00:00:00.000Z',
  totalTenants:    2,
  healthyTenants:  2,
  warningTenants:  0,
  criticalTenants: 0,
  overallStatus:   'HEALTHY',
  tenants: [
    {
      clientId:       'client-a',
      status:         'HEALTHY',
      issues:         [],
      activeKey:      { keyId: 'client-a:key_v1', version: 1, createdAt: '2024-01-01T00:00:00.000Z', expiresAt: '2024-07-01T00:00:00.000Z', rotationDeadline: '2024-04-01T00:00:00.000Z', daysUntilExpiry: 30, daysUntilRotation: -61 },
      keyCount:       1,
      activeKeyCount: 1,
    },
  ],
};

const VALID_TENANT_STATUS = {
  clientId:       'client-a',
  status:         'HEALTHY',
  issues:         [],
  activeKey:      { keyId: 'client-a:key_v1', version: 1, createdAt: '2024-01-01T00:00:00.000Z', expiresAt: '2024-07-01T00:00:00.000Z', rotationDeadline: '2024-04-01T00:00:00.000Z', daysUntilExpiry: 30, daysUntilRotation: -61 },
  keyCount:       1,
  activeKeyCount: 1,
};

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => { req.requestId = 'test-req-id'; res.locals.requestId = 'test-req-id'; next(); });
  app.use('/key-admin', keyAdminRouter);
  return app;
}

beforeEach(() => {
  jest.clearAllMocks();
  _installFreeLock();
});

// ── GET /key-admin/health ─────────────────────────────────────────────────────

describe('GET /key-admin/health', () => {
  it('returns 200 with health summary', async () => {
    tenantKeyManager.getKeyHealthSummary.mockReturnValue(VALID_HEALTH_SUMMARY);
    const res = await request(buildApp()).get('/key-admin/health');
    expect(res.status).toBe(200);
    expect(res.body.data.totalTenants).toBe(2);
    expect(res.body.data.overallStatus).toBe('HEALTHY');
  });

  it('includes requestId in response', async () => {
    tenantKeyManager.getKeyHealthSummary.mockReturnValue(VALID_HEALTH_SUMMARY);
    const res = await request(buildApp()).get('/key-admin/health');
    expect(res.body.requestId).toBe('test-req-id');
  });

  it('returns 500 when getKeyHealthSummary throws', async () => {
    tenantKeyManager.getKeyHealthSummary.mockImplementation(() => { throw new Error('store error'); });
    const res = await request(buildApp()).get('/key-admin/health');
    expect(res.status).toBe(500);
    expect(res.body.status).toBe('error');
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
  });

  it('response has CRITICAL overallStatus when store has critical tenant', async () => {
    tenantKeyManager.getKeyHealthSummary.mockReturnValue({ ...VALID_HEALTH_SUMMARY, overallStatus: 'CRITICAL', criticalTenants: 1, healthyTenants: 1 });
    const res = await request(buildApp()).get('/key-admin/health');
    expect(res.status).toBe(200);
    expect(res.body.data.overallStatus).toBe('CRITICAL');
  });
});

// ── GET /key-admin/:clientId/status ───────────────────────────────────────────

describe('GET /key-admin/:clientId/status', () => {
  it('returns 200 with tenant status for known client', async () => {
    tenantKeyManager.getTenantKeyStatus.mockReturnValue(VALID_TENANT_STATUS);
    const res = await request(buildApp()).get('/key-admin/client-a/status');
    expect(res.status).toBe(200);
    expect(res.body.data.clientId).toBe('client-a');
    expect(res.body.data.status).toBe('HEALTHY');
  });

  it('includes requestId in response', async () => {
    tenantKeyManager.getTenantKeyStatus.mockReturnValue(VALID_TENANT_STATUS);
    const res = await request(buildApp()).get('/key-admin/client-a/status');
    expect(res.body.requestId).toBe('test-req-id');
  });

  it('returns 404 when keyCount is 0 (unknown client)', async () => {
    tenantKeyManager.getTenantKeyStatus.mockReturnValue({ ...VALID_TENANT_STATUS, keyCount: 0, activeKeyCount: 0, activeKey: null });
    const res = await request(buildApp()).get('/key-admin/unknown-client/status');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  it('returns 400 for invalid clientId', async () => {
    const res = await request(buildApp()).get('/key-admin/bad client!/status');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_CLIENT_ID');
  });

  it('returns 500 when getTenantKeyStatus throws', async () => {
    tenantKeyManager.getTenantKeyStatus.mockImplementation(() => { throw new Error('db error'); });
    const res = await request(buildApp()).get('/key-admin/client-a/status');
    expect(res.status).toBe(500);
    expect(res.body.status).toBe('error');
  });

  it('returns CRITICAL status for tenant with expired key', async () => {
    tenantKeyManager.getTenantKeyStatus.mockReturnValue({
      ...VALID_TENANT_STATUS,
      status: 'CRITICAL',
      issues: ['KEY_EXPIRED'],
    });
    const res = await request(buildApp()).get('/key-admin/client-a/status');
    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('CRITICAL');
    expect(res.body.data.issues).toContain('KEY_EXPIRED');
  });
});

// ── POST /key-admin/mac-keys/rotate ────────────────────────

describe('POST /key-admin/mac-keys/rotate', () => {
  const macKeyring = require('../../../core/security/macKeyring');
  afterEach(() => jest.restoreAllMocks());

  it('rotates the MAC keyring under the rotation lock and returns key ids only', async () => {
    const before = macKeyring.status().activeKid;
    const res = await request(buildApp()).post('/key-admin/mac-keys/rotate');
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ rotated: true, activeKid: expect.stringMatching(/^mk_/), previousKid: before });
    expect(macKeyring.status().activeKid).toBe(res.body.data.activeKid);
    expect(rotationLock.acquire).toHaveBeenCalledWith('__MAC_KEYRING__', expect.any(Number));
    expect(rotationLock.release).toHaveBeenCalledWith('__MAC_KEYRING__', expect.any(String));
    expect(keyManager.rotateAsync).not.toHaveBeenCalled(); // "mac-keys" never captured as {clientId}
  });

  it('returns 409 when a rotation holds the lock, 503 when the lock backend is down — never rotates unlocked', async () => {
    const spy = jest.spyOn(macKeyring, 'rotate');
    rotationLock.acquire.mockResolvedValueOnce({ acquired: false });
    expect((await request(buildApp()).post('/key-admin/mac-keys/rotate')).status).toBe(409);
    rotationLock.acquire.mockRejectedValueOnce(new Error('Redis not connected'));
    expect((await request(buildApp()).post('/key-admin/mac-keys/rotate')).status).toBe(503);
    expect(spy).not.toHaveBeenCalled();
  });

  it('returns 500 MAC_KEYRING_ROTATION_FAILED when the keyring cannot be rotated', async () => {
    jest.spyOn(macKeyring, 'rotate').mockImplementation(() => { throw new Error('boom'); });
    const res = await request(buildApp()).post('/key-admin/mac-keys/rotate');
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('MAC_KEYRING_ROTATION_FAILED');
  });
});

// ── POST /key-admin/kek/rotate ────────────────────────────────────────

describe('POST /key-admin/kek/rotate', () => {
  it('returns 200 and calls keyProviderFactory.rotateWrappingKey()', async () => {
    keyProviderFactory.rotateWrappingKey.mockResolvedValue({ version: '3' });
    const res = await request(buildApp()).post('/key-admin/kek/rotate');
    expect(res.status).toBe(200);
    expect(res.body.data.rotated).toBe(true);
    expect(res.body.data.version).toBe('3');
    expect(keyProviderFactory.rotateWrappingKey).toHaveBeenCalledTimes(1);
  });

  it('response points the operator at the required migration script', async () => {
    keyProviderFactory.rotateWrappingKey.mockResolvedValue({ version: '3' });
    const res = await request(buildApp()).post('/key-admin/kek/rotate');
    expect(res.body.data.migrationRequired).toBe(true);
    expect(res.body.data.migrationScript).toBe('scripts/migrate-keys-json-kek.js');
  });

  it('a literal "kek" clientId segment is NOT captured by /:clientId/rotate — the dedicated route wins', async () => {
    keyProviderFactory.rotateWrappingKey.mockResolvedValue({ version: '1' });
    await request(buildApp()).post('/key-admin/kek/rotate');
    expect(keyManager.rotateAsync).not.toHaveBeenCalled();
    expect(keyProviderFactory.rotateWrappingKey).toHaveBeenCalledTimes(1);
  });

  it('is lock-protected: acquires and releases the distributed rotation lock under a fixed pseudo-clientId', async () => {
    keyProviderFactory.rotateWrappingKey.mockResolvedValue({ version: '2' });
    await request(buildApp()).post('/key-admin/kek/rotate');
    expect(rotationLock.acquire).toHaveBeenCalledWith('__KEK__', expect.any(Number));
    expect(rotationLock.release).toHaveBeenCalledWith('__KEK__', expect.any(String));
  });

  it('returns 409 ROTATION_IN_PROGRESS when the lock is already held', async () => {
    rotationLock.acquire.mockResolvedValue({ acquired: false });
    const res = await request(buildApp()).post('/key-admin/kek/rotate');
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('ROTATION_IN_PROGRESS');
    expect(keyProviderFactory.rotateWrappingKey).not.toHaveBeenCalled();
  });

  it('returns 503 LOCK_UNAVAILABLE when the lock backend is unreachable — never rotates unlocked', async () => {
    rotationLock.acquire.mockRejectedValue(new Error('Redis not connected'));
    const res = await request(buildApp()).post('/key-admin/kek/rotate');
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('LOCK_UNAVAILABLE');
    expect(keyProviderFactory.rotateWrappingKey).not.toHaveBeenCalled();
  });

  it('returns 500 KEK_ROTATION_FAILED when the provider rotation throws', async () => {
    keyProviderFactory.rotateWrappingKey.mockRejectedValue(new Error('KMS unreachable'));
    const res = await request(buildApp()).post('/key-admin/kek/rotate');
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('KEK_ROTATION_FAILED');
  });

  it('includes requestId in response', async () => {
    keyProviderFactory.rotateWrappingKey.mockResolvedValue({ version: '1' });
    const res = await request(buildApp()).post('/key-admin/kek/rotate');
    expect(res.body.requestId).toBe('test-req-id');
  });

  // the local provider's rotation is a no-op — never report rotated:true for it.
  describe('local KEK provider', () => {
    afterEach(() => { keyProviderFactory.getKekProviderType.mockReset(); });

    it('returns 409 KEK_ROTATION_NOT_SUPPORTED, does not call the provider, emits no KEY_ADMIN_KEK_ROTATED', async () => {
      const { emit } = require('../../../../services/logger');
      emit.mockClear();
      keyProviderFactory.getKekProviderType.mockReturnValue('local');
      keyProviderFactory.rotateWrappingKey.mockResolvedValue({ version: 'env:manual' });
      const res = await request(buildApp()).post('/key-admin/kek/rotate');
      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('KEK_ROTATION_NOT_SUPPORTED');
      expect(keyProviderFactory.rotateWrappingKey).not.toHaveBeenCalled();
      expect(rotationLock.acquire).not.toHaveBeenCalled();
      expect(emit.mock.calls.map((c) => c[1])).not.toContain('KEY_ADMIN_KEK_ROTATED');
      expect(emit.mock.calls.map((c) => c[1])).toContain('KEY_ADMIN_KEK_ROTATE_NOT_SUPPORTED');
    });

    it('a real KMS KEK provider still rotates (200)', async () => {
      keyProviderFactory.getKekProviderType.mockReturnValue('aws-kms');
      keyProviderFactory.rotateWrappingKey.mockResolvedValue({ version: 'aws:kms:rotated:x' });
      const res = await request(buildApp()).post('/key-admin/kek/rotate');
      expect(res.status).toBe(200);
      expect(res.body.data.rotated).toBe(true);
      expect(keyProviderFactory.rotateWrappingKey).toHaveBeenCalledTimes(1);
    });
  });
});

// ── POST /key-admin/:clientId/rotate ─────────────────────────────────────────

describe('POST /key-admin/:clientId/rotate', () => {
  it('returns 200 with new keyId on success', async () => {
    keyManager.rotateAsync.mockResolvedValue({ keyId: 'client-a:key_v2', version: 2, clientId: 'client-a' });
    const res = await request(buildApp()).post('/key-admin/client-a/rotate');
    expect(res.status).toBe(200);
    expect(res.body.data.keyId).toBe('client-a:key_v2');
    expect(res.body.data.version).toBe(2);
    expect(res.body.data.clientId).toBe('client-a');
  });

  it('includes requestId in response', async () => {
    keyManager.rotateAsync.mockResolvedValue({ keyId: 'client-a:key_v2', version: 2, clientId: 'client-a' });
    const res = await request(buildApp()).post('/key-admin/client-a/rotate');
    expect(res.body.requestId).toBe('test-req-id');
  });

  it('returns 400 for invalid clientId', async () => {
    const res = await request(buildApp()).post('/key-admin/bad client!/rotate');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_CLIENT_ID');
    expect(keyManager.rotateAsync).not.toHaveBeenCalled();
    expect(rotationLock.acquire).not.toHaveBeenCalled();
  });

  it('returns 409 when rotation fails with invariant violation', async () => {
    keyManager.rotateAsync.mockRejectedValue(new Error('invariant violation — 2 active keys'));
    const res = await request(buildApp()).post('/key-admin/client-a/rotate');
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('ROTATION_FAILED');
  });

  it('returns 500 when rotation fails for other reasons', async () => {
    keyManager.rotateAsync.mockRejectedValue(new Error('disk full'));
    const res = await request(buildApp()).post('/key-admin/client-a/rotate');
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('ROTATION_FAILED');
  });

  it('calls keyManager.rotateAsync with the correct clientId and a MANUAL_ADMIN_ROTATION reason', async () => {
    keyManager.rotateAsync.mockResolvedValue({ keyId: 'my-tenant:key_v3', version: 3, clientId: 'my-tenant' });
    await request(buildApp()).post('/key-admin/my-tenant/rotate');
    expect(keyManager.rotateAsync).toHaveBeenCalledWith('my-tenant', expect.objectContaining({
      reason: 'MANUAL_ADMIN_ROTATION',
    }));
  });

  // ── /rotate surfaces the outgoing key's new status explicitly ────────

  it('surfaces mode=emergency and the revoked previous key in the response', async () => {
    keyManager.rotateAsync.mockResolvedValue({
      keyId: 'client-a:key_v2', version: 2, clientId: 'client-a',
      previousKeyId: 'client-a:key_v1', previousKeyStatus: 'revoked', mode: 'emergency',
    });
    const res = await request(buildApp()).post('/key-admin/client-a/rotate');
    expect(res.status).toBe(200);
    expect(res.body.data.mode).toBe('emergency');
    expect(res.body.data.previousKeyId).toBe('client-a:key_v1');
    expect(res.body.data.previousKeyStatus).toBe('revoked');
  });

  it('returns 502 NATIVE_REVOCATION_FAILED when emergency-mode rotation cannot confirm provider-side revocation', async () => {
    const err = new Error('native revocation failed');
    err.code = 'NATIVE_REVOCATION_FAILED';
    err.nativeRevocation = { attempted: true, supported: true, provider: 'vault:transit', success: false };
    keyManager.rotateAsync.mockRejectedValue(err);
    const res = await request(buildApp()).post('/key-admin/client-a/rotate');
    expect(res.status).toBe(502);
    expect(res.body.error.code).toBe('NATIVE_REVOCATION_FAILED');
    expect(res.body.error.details.nativeRevocation).toEqual(expect.objectContaining({ success: false }));
  });

  // ── remediation: manual rotation is lock-protected ─────────────────────

  it('acquires the distributed rotation lock before rotating, and releases it after', async () => {
    keyManager.rotateAsync.mockResolvedValue({ keyId: 'client-a:key_v2', version: 2, clientId: 'client-a' });
    await request(buildApp()).post('/key-admin/client-a/rotate');
    expect(rotationLock.acquire).toHaveBeenCalledWith('client-a', expect.any(Number));
    expect(rotationLock.release).toHaveBeenCalledWith('client-a', expect.any(String));
    // Rotation must happen strictly between acquire and release.
    const acquireOrder = rotationLock.acquire.mock.invocationCallOrder[0];
    const rotateOrder  = keyManager.rotateAsync.mock.invocationCallOrder[0];
    const releaseOrder = rotationLock.release.mock.invocationCallOrder[0];
    expect(acquireOrder).toBeLessThan(rotateOrder);
    expect(rotateOrder).toBeLessThan(releaseOrder);
  });

  it('releases the lock even when rotation throws', async () => {
    keyManager.rotateAsync.mockRejectedValue(new Error('disk full'));
    await request(buildApp()).post('/key-admin/client-a/rotate');
    expect(rotationLock.release).toHaveBeenCalledWith('client-a', expect.any(String));
  });

  it('returns 409 ROTATION_IN_PROGRESS when the lock is already held (e.g. by the scheduler)', async () => {
    rotationLock.acquire.mockResolvedValue({ acquired: false });
    const res = await request(buildApp()).post('/key-admin/client-a/rotate');
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('ROTATION_IN_PROGRESS');
    expect(keyManager.rotateAsync).not.toHaveBeenCalled();
  });

  it('returns 503 LOCK_UNAVAILABLE when the lock backend is unreachable — never rotates unlocked', async () => {
    rotationLock.acquire.mockRejectedValue(new Error('Redis not connected'));
    const res = await request(buildApp()).post('/key-admin/client-a/rotate');
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('LOCK_UNAVAILABLE');
    expect(keyManager.rotateAsync).not.toHaveBeenCalled();
  });

  it('two concurrent rotate requests for the same client never both proceed (no split-brain)', async () => {
    // Deterministic ordering: rather than guessing how many event-loop ticks a
    // real supertest HTTP round-trip needs before the route reaches
    // rotationLock.acquire() (a timing assumption that is inherently flaky and
    // can hang the test if wrong), the acquire() mock itself signals exactly
    // when the FIRST caller has taken the lock. The second request is only
    // ever issued after that signal fires, so this test can never race —
    // either it observes the lock correctly serializing the two requests, or
    // it fails fast, but it cannot deadlock waiting on ambiguous timing.
    let held = null;
    const firstAcquired = (() => { let resolve; const p = new Promise(r => { resolve = r; }); return { p, resolve }; })();
    rotationLock.acquire.mockImplementation(async (clientId) => {
      if (held === clientId) return { acquired: false };
      held = clientId;
      firstAcquired.resolve();
      return { acquired: true, token: 'excl-tok' };
    });
    rotationLock.release.mockImplementation(async (clientId, token) => {
      if (held === clientId && token === 'excl-tok') { held = null; return true; }
      return false;
    });

    const gate = (() => { let resolve; const p = new Promise(r => { resolve = r; }); return { p, resolve }; })();
    let callCount = 0;
    keyManager.rotateAsync.mockImplementation(async () => {
      callCount++;
      await gate.p;
      return { keyId: 'client-a:key_v2', version: 2, clientId: 'client-a' };
    });

    const app = buildApp();
    // supertest Test objects are LAZY thenables — the underlying HTTP request
    // is not actually dispatched until the promise is consumed (.then/await).
    // Chaining .then(res => res) forces it to fire immediately instead of
    // sitting inert until `first` is awaited far below — without this, the
    // request never reaches the route at all and `firstAcquired.p` (and
    // therefore this whole test) hangs until the Jest timeout.
    const first = request(app).post('/key-admin/client-a/rotate').then(res => res);
    await firstAcquired.p; // the first request has definitely taken the lock now
    const secondRes = await request(app).post('/key-admin/client-a/rotate');

    expect(secondRes.status).toBe(409);
    expect(secondRes.body.error.code).toBe('ROTATION_IN_PROGRESS');
    expect(callCount).toBe(1); // the second request never entered rotateAsync at all

    gate.resolve();
    const firstRes = await first;
    expect(firstRes.status).toBe(200);
  });
});

// ── POST /key-admin/:clientId/rotate-graceful ─────────────────────────
// Separate, explicit endpoint for planned/compatibility rotation — must never
// be reachable as a side effect of calling /rotate, and must call the
// distinct keyManager.rotateGracefullyAsync() facade, not rotateAsync().

describe('POST /key-admin/:clientId/rotate-graceful', () => {
  it('returns 200 with mode=graceful and the deprecated previous key', async () => {
    keyManager.rotateGracefullyAsync.mockResolvedValue({
      keyId: 'client-a:key_v2', version: 2, clientId: 'client-a',
      previousKeyId: 'client-a:key_v1', previousKeyStatus: 'deprecated', mode: 'graceful',
    });
    const res = await request(buildApp()).post('/key-admin/client-a/rotate-graceful');
    expect(res.status).toBe(200);
    expect(res.body.data.keyId).toBe('client-a:key_v2');
    expect(res.body.data.mode).toBe('graceful');
    expect(res.body.data.previousKeyId).toBe('client-a:key_v1');
    expect(res.body.data.previousKeyStatus).toBe('deprecated');
  });

  it('calls keyManager.rotateGracefullyAsync — never rotateAsync (the emergency default)', async () => {
    keyManager.rotateGracefullyAsync.mockResolvedValue({ keyId: 'client-a:key_v2', version: 2, clientId: 'client-a' });
    await request(buildApp()).post('/key-admin/client-a/rotate-graceful');
    expect(keyManager.rotateGracefullyAsync).toHaveBeenCalledWith('client-a', expect.objectContaining({
      reason: 'MANUAL_ADMIN_GRACEFUL_ROTATION',
    }));
    expect(keyManager.rotateAsync).not.toHaveBeenCalled();
  });

  it('returns 400 for invalid clientId', async () => {
    const res = await request(buildApp()).post('/key-admin/bad client!/rotate-graceful');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_CLIENT_ID');
    expect(keyManager.rotateGracefullyAsync).not.toHaveBeenCalled();
  });

  it('is lock-protected identically to /rotate', async () => {
    keyManager.rotateGracefullyAsync.mockResolvedValue({ keyId: 'client-a:key_v2', version: 2, clientId: 'client-a' });
    await request(buildApp()).post('/key-admin/client-a/rotate-graceful');
    expect(rotationLock.acquire).toHaveBeenCalledWith('client-a', expect.any(Number));
    expect(rotationLock.release).toHaveBeenCalledWith('client-a', expect.any(String));
  });

  it('returns 409 ROTATION_IN_PROGRESS when the lock is already held', async () => {
    rotationLock.acquire.mockResolvedValue({ acquired: false });
    const res = await request(buildApp()).post('/key-admin/client-a/rotate-graceful');
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('ROTATION_IN_PROGRESS');
    expect(keyManager.rotateGracefullyAsync).not.toHaveBeenCalled();
  });

  it('returns 503 LOCK_UNAVAILABLE when the lock backend is unreachable — never rotates unlocked', async () => {
    rotationLock.acquire.mockRejectedValue(new Error('Redis not connected'));
    const res = await request(buildApp()).post('/key-admin/client-a/rotate-graceful');
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('LOCK_UNAVAILABLE');
    expect(keyManager.rotateGracefullyAsync).not.toHaveBeenCalled();
  });

  it('returns 500 ROTATION_FAILED when graceful rotation fails for other reasons', async () => {
    keyManager.rotateGracefullyAsync.mockRejectedValue(new Error('disk full'));
    const res = await request(buildApp()).post('/key-admin/client-a/rotate-graceful');
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('ROTATION_FAILED');
  });

  it('returns 405 for GET /key-admin/:clientId/rotate-graceful', async () => {
    const res = await request(buildApp()).get('/key-admin/client-a/rotate-graceful');
    expect(res.status).toBe(405);
  });
});

// ── POST /key-admin/:clientId/revoke ─────────────────────────────────────────

describe('POST /key-admin/:clientId/revoke', () => {
  it('returns 200 with revoked:true on success', async () => {
    keyManager.revoke.mockResolvedValue({ clientId: 'client-a', keyId: 'client-a:key_v1', status: 'revoked', nativeRevocation: null });
    const res = await request(buildApp())
      .post('/key-admin/client-a/revoke')
      .send({ keyId: 'client-a:key_v1' });
    expect(res.status).toBe(200);
    expect(res.body.data.revoked).toBe(true);
    expect(res.body.data.keyId).toBe('client-a:key_v1');
    expect(res.body.data.clientId).toBe('client-a');
  });

  it('includes the provider nativeRevocation outcome in the response', async () => {
    const nativeRevocation = { attempted: true, provider: 'vault:transit:qodiqa', method: 'destroy', success: true };
    keyManager.revoke.mockResolvedValue({ clientId: 'client-a', keyId: 'client-a:key_v1', status: 'revoked', nativeRevocation });
    const res = await request(buildApp())
      .post('/key-admin/client-a/revoke')
      .send({ keyId: 'client-a:key_v1' });
    expect(res.status).toBe(200);
    expect(res.body.data.nativeRevocation).toEqual(nativeRevocation);
  });

  it('includes requestId in response', async () => {
    keyManager.revoke.mockResolvedValue({ clientId: 'client-a', keyId: 'client-a:key_v1', status: 'revoked', nativeRevocation: null });
    const res = await request(buildApp())
      .post('/key-admin/client-a/revoke')
      .send({ keyId: 'client-a:key_v1' });
    expect(res.body.requestId).toBe('test-req-id');
  });

  it('returns 400 for invalid clientId', async () => {
    const res = await request(buildApp())
      .post('/key-admin/bad client!/revoke')
      .send({ keyId: 'valid:key_v1' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_CLIENT_ID');
  });

  it('returns 400 when keyId is missing from body', async () => {
    const res = await request(buildApp()).post('/key-admin/client-a/revoke').send({});
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_KEY_ID');
  });

  it('item 9 audit: rejects an unrecognised extra body key (revokeKeyBodySchema was .passthrough(), now .strict())', async () => {
    const res = await request(buildApp())
      .post('/key-admin/client-a/revoke')
      .send({ keyId: 'client-a:key_v1', unexpectedKey: 'nope' });
    expect(res.status).toBe(400);
    expect(keyManager.revoke).not.toHaveBeenCalled();
  });

  it('returns 400 when keyId has wrong format', async () => {
    const res = await request(buildApp())
      .post('/key-admin/client-a/revoke')
      .send({ keyId: 'not-a-valid-key-id' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_KEY_ID');
  });

  it('returns 400 when keyId clientId prefix does not match route clientId', async () => {
    const res = await request(buildApp())
      .post('/key-admin/client-a/revoke')
      .send({ keyId: 'other-client:key_v1' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('KEY_CLIENT_MISMATCH');
  });

  it('returns 404 when keyId is unknown', async () => {
    keyManager.revoke.mockRejectedValue(new Error('unknown keyId "client-a:key_v1"'));
    const res = await request(buildApp())
      .post('/key-admin/client-a/revoke')
      .send({ keyId: 'client-a:key_v1' });
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  it('returns 500 for unexpected revocation errors', async () => {
    keyManager.revoke.mockRejectedValue(new Error('I/O error'));
    const res = await request(buildApp())
      .post('/key-admin/client-a/revoke')
      .send({ keyId: 'client-a:key_v1' });
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('REVOCATION_FAILED');
  });

  it('returns 502 with nativeRevocation detail when native provider revocation fails', async () => {
    const err = new Error('key "client-a:key_v1" was revoked locally but native revocation failed');
    err.code = 'NATIVE_REVOCATION_FAILED';
    err.nativeRevocation = { attempted: true, provider: 'vault:transit:qodiqa', method: 'destroy', success: false, error: 'vault unreachable' };
    keyManager.revoke.mockRejectedValue(err);
    const res = await request(buildApp())
      .post('/key-admin/client-a/revoke')
      .send({ keyId: 'client-a:key_v1' });
    expect(res.status).toBe(502);
    expect(res.body.error.code).toBe('NATIVE_REVOCATION_FAILED');
    expect(res.body.error.details.nativeRevocation).toEqual(err.nativeRevocation);
  });

  it('calls keyManager.revoke with clientId, keyId, and an opts object', async () => {
    keyManager.revoke.mockResolvedValue({ clientId: 'my-tenant', keyId: 'my-tenant:key_v2', status: 'revoked', nativeRevocation: null });
    await request(buildApp())
      .post('/key-admin/my-tenant/revoke')
      .send({ keyId: 'my-tenant:key_v2' });
    expect(keyManager.revoke).toHaveBeenCalledWith('my-tenant', 'my-tenant:key_v2', expect.objectContaining({ reason: null }));
  });

  it('passes an operator-supplied reason through to keyManager.revoke', async () => {
    keyManager.revoke.mockResolvedValue({ clientId: 'my-tenant', keyId: 'my-tenant:key_v2', status: 'revoked', nativeRevocation: null });
    await request(buildApp())
      .post('/key-admin/my-tenant/revoke')
      .send({ keyId: 'my-tenant:key_v2', reason: 'key compromised' });
    expect(keyManager.revoke).toHaveBeenCalledWith('my-tenant', 'my-tenant:key_v2', expect.objectContaining({ reason: 'key compromised' }));
  });
});

// ── POST /key-admin/:clientId/recover ─────────────────────────────────────────

describe('POST /key-admin/:clientId/recover', () => {
  it('returns 200 with new keyId when the client has no active key', async () => {
    tenantKeyManager.getTenantKeyStatus.mockReturnValue({ ...VALID_TENANT_STATUS, activeKeyCount: 0, activeKey: null });
    keyManager.rotateAsync.mockResolvedValue({ keyId: 'client-a:key_v2', version: 2, clientId: 'client-a' });
    const res = await request(buildApp()).post('/key-admin/client-a/recover');
    expect(res.status).toBe(200);
    expect(res.body.data.recovered).toBe(true);
    expect(res.body.data.keyId).toBe('client-a:key_v2');
  });

  it('calls keyManager.rotateAsync with a MANUAL_ADMIN_RECOVERY reason', async () => {
    tenantKeyManager.getTenantKeyStatus.mockReturnValue({ ...VALID_TENANT_STATUS, activeKeyCount: 0, activeKey: null });
    keyManager.rotateAsync.mockResolvedValue({ keyId: 'client-a:key_v2', version: 2, clientId: 'client-a' });
    await request(buildApp()).post('/key-admin/client-a/recover');
    expect(keyManager.rotateAsync).toHaveBeenCalledWith('client-a', expect.objectContaining({
      reason: 'MANUAL_ADMIN_RECOVERY',
    }));
  });

  it('returns 409 ALREADY_HAS_ACTIVE_KEY without calling rotateAsync when an active key already exists', async () => {
    tenantKeyManager.getTenantKeyStatus.mockReturnValue(VALID_TENANT_STATUS); // activeKeyCount: 1
    const res = await request(buildApp()).post('/key-admin/client-a/recover');
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('ALREADY_HAS_ACTIVE_KEY');
    expect(res.body.error.details.activeKeyId).toBe(VALID_TENANT_STATUS.activeKey.keyId);
    expect(keyManager.rotateAsync).not.toHaveBeenCalled();
  });

  it('returns 400 for invalid clientId', async () => {
    const res = await request(buildApp()).post('/key-admin/bad client!/recover');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_CLIENT_ID');
  });

  it('returns 500 when recovery fails for other reasons', async () => {
    tenantKeyManager.getTenantKeyStatus.mockReturnValue({ ...VALID_TENANT_STATUS, activeKeyCount: 0, activeKey: null });
    keyManager.rotateAsync.mockRejectedValue(new Error('disk full'));
    const res = await request(buildApp()).post('/key-admin/client-a/recover');
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('RECOVERY_FAILED');
  });

  // ── remediation: recovery is lock-protected ─────────────────────────────

  it('the no-active-key check and provisioning run inside the same lock — the check is race-free', async () => {
    // Same deterministic-ordering approach as the /rotate concurrency test
    // above: the second request is only issued once the acquire() mock
    // signals the first has actually taken the lock, so this cannot hang on
    // an ambiguous number of event-loop ticks for the real HTTP round-trip.
    let held = null;
    const firstAcquired = (() => { let resolve; const p = new Promise(r => { resolve = r; }); return { p, resolve }; })();
    rotationLock.acquire.mockImplementation(async (clientId) => {
      if (held === clientId) return { acquired: false };
      held = clientId;
      firstAcquired.resolve();
      return { acquired: true, token: 'excl-tok' };
    });
    rotationLock.release.mockImplementation(async (clientId, token) => {
      if (held === clientId && token === 'excl-tok') { held = null; return true; }
      return false;
    });

    // Both requests see "no active key" from the mock (a stale/racy read would
    // be the bug left open for /rotate; recover's own status check makes
    // this a second, independent race unless it too runs under the lock).
    tenantKeyManager.getTenantKeyStatus.mockReturnValue({ ...VALID_TENANT_STATUS, activeKeyCount: 0, activeKey: null });
    const gate = (() => { let resolve; const p = new Promise(r => { resolve = r; }); return { p, resolve }; })();
    keyManager.rotateAsync.mockImplementation(async () => {
      await gate.p;
      return { keyId: 'client-a:key_v1', version: 1, clientId: 'client-a' };
    });

    const app = buildApp();
    // See the identical .then(res => res) note in the /rotate concurrency test
    // above — without it, this lazy supertest request never fires and the
    // test hangs on firstAcquired.p until the Jest timeout.
    const first = request(app).post('/key-admin/client-a/recover').then(res => res);
    await firstAcquired.p; // the first request has definitely taken the lock now
    const secondRes = await request(app).post('/key-admin/client-a/recover');

    expect(secondRes.status).toBe(409);
    expect(secondRes.body.error.code).toBe('ROTATION_IN_PROGRESS');

    gate.resolve();
    const firstRes = await first;
    expect(firstRes.status).toBe(200);
    expect(keyManager.rotateAsync).toHaveBeenCalledTimes(1);
  });

  it('returns 503 LOCK_UNAVAILABLE when the lock backend is unreachable', async () => {
    rotationLock.acquire.mockRejectedValue(new Error('Redis not connected'));
    const res = await request(buildApp()).post('/key-admin/client-a/recover');
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('LOCK_UNAVAILABLE');
    expect(tenantKeyManager.getTenantKeyStatus).not.toHaveBeenCalled();
  });
});

// ── Security: method not allowed ──────────────────────────────────────────────

describe('method not allowed', () => {
  it('returns 405 for GET /key-admin/:clientId/rotate', async () => {
    const res = await request(buildApp()).get('/key-admin/client-a/rotate');
    expect(res.status).toBe(405);
    expect(res.body.error.code).toBe('METHOD_NOT_ALLOWED');
  });

  it('returns 405 for DELETE /key-admin/health', async () => {
    const res = await request(buildApp()).delete('/key-admin/health');
    expect(res.status).toBe(405);
  });
});

// ── Response shape consistency ────────────────────────────────────────────────

describe('response shape consistency', () => {
  it('error responses always include status, error.code, error.message, requestId', async () => {
    tenantKeyManager.getKeyHealthSummary.mockImplementation(() => { throw new Error('x'); });
    const res = await request(buildApp()).get('/key-admin/health');
    expect(res.body).toHaveProperty('status', 'error');
    expect(res.body.error).toHaveProperty('code');
    expect(res.body.error).toHaveProperty('message');
    expect(res.body).toHaveProperty('requestId');
  });

  it('400 validation errors have error status', async () => {
    const res = await request(buildApp()).post('/key-admin/bad client!/rotate');
    expect(res.body.status).toBe('error');
  });
});
