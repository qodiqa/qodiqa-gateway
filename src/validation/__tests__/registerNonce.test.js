'use strict';

/**
 * registerNonce() — pass-through contract conformance
 *
 * Regression suite for the defect fixed in "NonceStore Key Format Remediation":
 * registerNonce() used to build `scopedKey = tenantId ? \`${tenantId}:${requestId}\`
 * : requestId` and pass that single composite STRING to store.register() as
 * if it were the requestId. Key construction now belongs entirely to the
 * store (nonceStore.buildNonceKey) — registerNonce must forward requestId and
 * tenantId as SEPARATE, unmodified arguments.
 */

const { registerNonce } = require('../registerNonce');
const { generateRequestId } = require('../requestId');

function makeSpyStore(overrides = {}) {
  const calls = [];
  return {
    calls,
    async register(requestId, expiryMs, tenantId) {
      calls.push({ requestId, expiryMs, tenantId });
      if (overrides.register) return overrides.register(requestId, expiryMs, tenantId);
      return { registered: true };
    },
  };
}

describe('registerNonce — forwards requestId and tenantId separately (no pre-concatenation)', () => {
  test('with tenantId: store.register receives the BARE requestId, not a composite string', async () => {
    const store     = makeSpyStore();
    const requestId = generateRequestId();
    const expiry    = Date.now() + 60_000;

    const result = await registerNonce(requestId, expiry, { _store: store, tenantId: 'acme-corp' });

    expect(result.ok).toBe(true);
    expect(store.calls).toHaveLength(1);
    expect(store.calls[0].requestId).toBe(requestId); // exact match — no ":" concatenation
    expect(store.calls[0].requestId).not.toContain(':');
    expect(store.calls[0].tenantId).toBe('acme-corp');
    expect(store.calls[0].expiryMs).toBe(expiry);
  });

  test('without tenantId: store.register receives tenantId as undefined', async () => {
    const store     = makeSpyStore();
    const requestId = generateRequestId();
    const expiry    = Date.now() + 60_000;

    await registerNonce(requestId, expiry, { _store: store });

    expect(store.calls[0].requestId).toBe(requestId);
    expect(store.calls[0].tenantId).toBeUndefined();
  });

  test('null tenantId is forwarded as null, not coerced to a string', async () => {
    const store     = makeSpyStore();
    const requestId = generateRequestId();

    await registerNonce(requestId, Date.now() + 60_000, { _store: store, tenantId: null });

    expect(store.calls[0].tenantId).toBeNull();
  });

  test('store replay result maps to REPLAY_DETECTED', async () => {
    const store = makeSpyStore({ register: async () => ({ registered: false }) });
    const r = await registerNonce(generateRequestId(), Date.now() + 60_000, { _store: store, tenantId: 'acme' });
    expect(r).toEqual({ ok: false, reason: 'REPLAY_DETECTED', details: { requestId: expect.any(String) } });
  });

  test('store throw maps to NONCE_STORE_ERROR — including the store rejecting a malformed composite key', async () => {
    // Simulates the pre-fix production failure mode: if something upstream of
    // registerNonce ever again tried handing the store a non-UUID requestId,
    // the store throws and this must map to NONCE_STORE_ERROR, not crash.
    const store = {
      async register(requestId) {
        throw new TypeError(`NONCE_STORE_V2: requestId must be a UUID v4`);
      },
    };
    const r = await registerNonce(generateRequestId(), Date.now() + 60_000, { _store: store, tenantId: 'acme' });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('NONCE_STORE_ERROR');
  });

  test('two different tenants registering the same requestId both reach the store as ok:true (store owns isolation)', async () => {
    const backing = new Map();
    const store = {
      async register(requestId, expiryMs, tenantId) {
        const key = tenantId ? `${tenantId}:${requestId}` : requestId; // store's own scoping, opaque to registerNonce
        if (backing.has(key)) return { registered: false };
        backing.set(key, expiryMs);
        return { registered: true };
      },
    };
    const requestId = generateRequestId();
    const r1 = await registerNonce(requestId, Date.now() + 60_000, { _store: store, tenantId: 'tenant-a' });
    const r2 = await registerNonce(requestId, Date.now() + 60_000, { _store: store, tenantId: 'tenant-b' });
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
  });
});

describe('registerNonce — input validation (unchanged by the key-format fix)', () => {
  test('malformed requestId → MALFORMED_REQUEST_ID, store never called', async () => {
    const store = makeSpyStore();
    const r = await registerNonce('not-a-uuid', Date.now() + 60_000, { _store: store, tenantId: 'acme' });
    expect(r).toEqual({ ok: false, reason: 'MALFORMED_REQUEST_ID', details: { requestId: 'not-a-uuid' } });
    expect(store.calls).toHaveLength(0);
  });

  test('invalid expiryMs → INVALID_EXPIRY, store never called', async () => {
    const store = makeSpyStore();
    const r = await registerNonce(generateRequestId(), NaN, { _store: store, tenantId: 'acme' });
    expect(r.reason).toBe('INVALID_EXPIRY');
    expect(store.calls).toHaveLength(0);
  });

  test('already-expired expiryMs → EXPIRED, store never called (avoids writing a dead key)', async () => {
    const store = makeSpyStore();
    const r = await registerNonce(generateRequestId(), Date.now() - 1, { _store: store, tenantId: 'acme' });
    expect(r.reason).toBe('EXPIRED');
    expect(store.calls).toHaveLength(0);
  });
});
