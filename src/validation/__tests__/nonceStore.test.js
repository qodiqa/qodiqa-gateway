'use strict';

/**
 * NonceStore Key Format Conformance — QODIQA-PROTOCOL-SPEC.md §27.11
 *
 * Regression suite for the defect fixed in "NonceStore Key Format Remediation":
 * registerNonce() used to pre-concatenate `${tenantId}:${requestId}` and hand
 * that composite string to nonceStore.register() as if it were the requestId.
 * The store then prefixed it with KEY_PREFIX, producing
 * `qodiqa:req:v2:${tenantId}:${requestId}` — wrong field order versus the
 * spec's `${tenantId}:qodiqa:req:v2:${requestId}` — AND the composite string
 * failed the store's own UUID-v4 validation, throwing on every tenant-scoped
 * registration in production (masked in tests by lenient in-memory doubles).
 *
 * This suite talks to nonceStore.js directly with a mocked Redis client so the
 * exact key bytes sent over the wire can be inspected.
 */

jest.mock('redis', () => ({ createClient: jest.fn() }));
jest.mock('../../infra/redis/persistenceCheck', () => ({ checkRedisPersistence: jest.fn() }));
jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));

const { createClient } = require('redis');
const { generateRequestId } = require('../requestId');
const nonceStore = require('../nonceStore');

function makeFakeRedisClient() {
  const map   = new Map();
  const zsets = new Map(); // key -> [{ member, score }, ...] — mirrors anomalyStore.js's ZSET windows
  const seqs  = new Map(); // key -> last seq number (mirrors the Lua script's INCR key..':seq')
  return {
    isReady: true,
    on:    jest.fn(),
    once:  jest.fn(),
    off:   jest.fn(),
    connect:    jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    ping:  jest.fn().mockResolvedValue('PONG'),
    set: jest.fn(async (key, value, opts) => {
      if (opts && opts.NX && map.has(key)) return null;
      map.set(key, value);
      return 'OK';
    }),
    get:    jest.fn(async (key) => (map.has(key) ? map.get(key) : null)),
    del:    jest.fn(async (key) => { map.delete(key); return 1; }),
    exists: jest.fn(async (key) => (map.has(key) ? 1 : 0)),
    // Faithful JS mirror of nonceStore.js's COMBINED_REGISTER_SCRIPT — same
    // SET NX -> per-key slide -> global slide early-exit order, same
    // ZREMRANGEBYSCORE(0, cutoff) eviction rule (score > cutoff survives,
    // matching anomalyDetection.test.js's makeTestAnomalyStore convention).
    eval: jest.fn(async (_script, { keys, arguments: args }) => {
      // register() runs the single-key REGISTER_SCRIPT (SET NX + restart
      // barrier); the barrier needs a real Redis start time and is exercised by
      // test/integration/replayDurability.integration.test.js against a real Redis.
      if (keys.length === 1) {
        if (map.has(keys[0])) return [-1];
        map.set(keys[0], '1');
        return [1];
      }
      const [nonceKey, perKeyKey, globalKey] = keys;
      const [ttlStr, nowStr, windowStr, perKeyMaxStr, globalMaxStr] = args;
      void ttlStr;

      if (map.has(nonceKey)) return [-1];
      map.set(nonceKey, '1');

      const now    = Number(nowStr);
      const window = Number(windowStr);
      const cutoff = now - window;

      function slide(key) {
        const survivors = (zsets.get(key) || []).filter(e => e.score > cutoff);
        const seq = (seqs.get(key) || 0) + 1;
        seqs.set(key, seq);
        survivors.push({ member: `${now}:${seq}`, score: now });
        zsets.set(key, survivors);
        return survivors.length;
      }

      const perKeyCount = slide(perKeyKey);
      if (perKeyCount > Number(perKeyMaxStr)) return [0, perKeyCount];

      const globalCount = slide(globalKey);
      if (globalCount > Number(globalMaxStr)) return [1, perKeyCount, globalCount];

      return [2, perKeyCount, globalCount];
    }),
    _map:   map,
    _zsets: zsets,
  };
}

let fakeClient;

beforeEach(() => {
  fakeClient = makeFakeRedisClient();
  createClient.mockReturnValue(fakeClient);
});

afterEach(async () => {
  await nonceStore.disconnect();
});

const FUTURE = () => Date.now() + 300_000;

// ── buildNonceKey: the canonical, single-source-of-truth key builder ─────────

describe('buildNonceKey — §27.11 test vectors', () => {
  test('Vector: tenantId=acme-corp, requestId=550e8400-e29b-41d4-a716-446655440000', () => {
    expect(nonceStore.buildNonceKey('550e8400-e29b-41d4-a716-446655440000', 'acme-corp'))
      .toBe('acme-corp:qodiqa:req:v2:550e8400-e29b-41d4-a716-446655440000');
  });

  test('Vector: no tenantId, requestId=550e8400-e29b-41d4-a716-446655440000', () => {
    expect(nonceStore.buildNonceKey('550e8400-e29b-41d4-a716-446655440000'))
      .toBe('qodiqa:req:v2:550e8400-e29b-41d4-a716-446655440000');
  });

  test('null tenantId is treated identically to absent tenantId', () => {
    const id = generateRequestId();
    expect(nonceStore.buildNonceKey(id, null)).toBe(nonceStore.buildNonceKey(id));
  });

  test('empty-string tenantId is treated identically to absent tenantId', () => {
    const id = generateRequestId();
    expect(nonceStore.buildNonceKey(id, '')).toBe(nonceStore.buildNonceKey(id));
  });

  test('tenantId prefixes the WHOLE key, not just the requestId (order matters)', () => {
    const key = nonceStore.buildNonceKey('x', 'acme');
    expect(key.startsWith('acme:qodiqa:req:v2:')).toBe(true);
    expect(key).not.toBe('qodiqa:req:v2:acme:x'); // the pre-fix (wrong) order
  });

  test('case sensitivity: "Acme" and "acme" tenants produce different keys (no normalization)', () => {
    const id = generateRequestId();
    expect(nonceStore.buildNonceKey(id, 'Acme')).not.toBe(nonceStore.buildNonceKey(id, 'acme'));
  });

  test('Unicode tenantId round-trips deterministically', () => {
    const id  = generateRequestId();
    const key = nonceStore.buildNonceKey(id, 'テナント-🏢');
    expect(key).toBe(`テナント-🏢:qodiqa:req:v2:${id}`);
  });
});

// ── register(): exact wire key + validation ───────────────────────────────────

describe('register() — key construction and validation', () => {
  test('no tenant: writes exactly qodiqa:req:v2:<requestId> to Redis', async () => {
    const id = generateRequestId();
    await nonceStore.register(id, FUTURE());
    expect(fakeClient._map.has(`qodiqa:req:v2:${id}`)).toBe(true);
    expect(fakeClient.eval).toHaveBeenCalledWith(
      expect.stringContaining("'SET', KEYS[1], '1', 'NX', 'PX', ARGV[1]"), expect.objectContaining({ keys: [`qodiqa:req:v2:${id}`] }),
    );
  });

  test('with tenant: writes exactly <tenantId>:qodiqa:req:v2:<requestId> to Redis', async () => {
    const id = generateRequestId();
    await nonceStore.register(id, FUTURE(), 'acme-corp');
    expect(fakeClient._map.has(`acme-corp:qodiqa:req:v2:${id}`)).toBe(true);
  });

  test('malformed requestId (not UUID v4) throws before touching Redis', async () => {
    await expect(nonceStore.register('not-a-uuid', FUTURE())).rejects.toThrow(/UUID v4/);
    expect(fakeClient.set).not.toHaveBeenCalled();
  });

  test('null requestId throws before touching Redis', async () => {
    await expect(nonceStore.register(null, FUTURE())).rejects.toThrow();
    expect(fakeClient.set).not.toHaveBeenCalled();
  });

  test('empty string requestId throws before touching Redis', async () => {
    await expect(nonceStore.register('', FUTURE())).rejects.toThrow();
    expect(fakeClient.set).not.toHaveBeenCalled();
  });

  test('non-string tenantId (number) throws before touching Redis', async () => {
    await expect(nonceStore.register(generateRequestId(), FUTURE(), 42)).rejects.toThrow(/tenantId/);
    expect(fakeClient.set).not.toHaveBeenCalled();
  });

  test('non-string tenantId (object) throws before touching Redis', async () => {
    await expect(nonceStore.register(generateRequestId(), FUTURE(), {})).rejects.toThrow(/tenantId/);
    expect(fakeClient.set).not.toHaveBeenCalled();
  });

  test('empty-string tenantId is accepted (treated as no tenant), not rejected', async () => {
    const id = generateRequestId();
    await expect(nonceStore.register(id, FUTURE(), '')).resolves.toEqual({ registered: true });
    expect(fakeClient._map.has(`qodiqa:req:v2:${id}`)).toBe(true);
  });

  test('NaN expiryMs throws before touching Redis', async () => {
    await expect(nonceStore.register(generateRequestId(), NaN)).rejects.toThrow();
    expect(fakeClient.set).not.toHaveBeenCalled();
  });

  test('negative expiryMs throws before touching Redis', async () => {
    await expect(nonceStore.register(generateRequestId(), -1)).rejects.toThrow();
    expect(fakeClient.set).not.toHaveBeenCalled();
  });

  test('already-expired expiryMs throws before touching Redis (boundary: ttlMs <= 0)', async () => {
    await expect(nonceStore.register(generateRequestId(), Date.now())).rejects.toThrow(/already expired/);
    expect(fakeClient.set).not.toHaveBeenCalled();
  });

  test('boundary: expiryMs 50ms in the future succeeds (ttlMs > 0)', async () => {
    await expect(nonceStore.register(generateRequestId(), Date.now() + 50))
      .resolves.toEqual({ registered: true });
  });

  test('replay: same requestId + same tenant registered twice → second is { registered: false }', async () => {
    const id = generateRequestId();
    expect(await nonceStore.register(id, FUTURE(), 'acme')).toEqual({ registered: true });
    expect(await nonceStore.register(id, FUTURE(), 'acme')).toEqual({ registered: false });
  });

  test('namespace isolation: same requestId under two different tenants both succeed', async () => {
    const id = generateRequestId();
    expect(await nonceStore.register(id, FUTURE(), 'tenant-a')).toEqual({ registered: true });
    expect(await nonceStore.register(id, FUTURE(), 'tenant-b')).toEqual({ registered: true });
    expect(fakeClient._map.has(`tenant-a:qodiqa:req:v2:${id}`)).toBe(true);
    expect(fakeClient._map.has(`tenant-b:qodiqa:req:v2:${id}`)).toBe(true);
  });

  test('same requestId with tenant vs. without tenant are independent registrations', async () => {
    const id = generateRequestId();
    expect(await nonceStore.register(id, FUTURE())).toEqual({ registered: true });
    expect(await nonceStore.register(id, FUTURE(), 'acme')).toEqual({ registered: true });
  });
});

// ── isRegistered(): read-only check mirrors register() exactly ───────────────

describe('isRegistered() — key construction and validation', () => {
  test('returns false for a never-registered requestId', async () => {
    expect(await nonceStore.isRegistered(generateRequestId())).toBe(false);
  });

  test('returns true after register() with no tenant', async () => {
    const id = generateRequestId();
    await nonceStore.register(id, FUTURE());
    expect(await nonceStore.isRegistered(id)).toBe(true);
  });

  test('returns true after register() with a tenant, only when the SAME tenant is queried', async () => {
    const id = generateRequestId();
    await nonceStore.register(id, FUTURE(), 'tenant-a');
    expect(await nonceStore.isRegistered(id, 'tenant-a')).toBe(true);
    expect(await nonceStore.isRegistered(id, 'tenant-b')).toBe(false);
    expect(await nonceStore.isRegistered(id)).toBe(false); // unscoped check does not see tenant-scoped entry
  });

  test('malformed requestId returns false rather than throwing', async () => {
    expect(await nonceStore.isRegistered('not-a-uuid')).toBe(false);
  });

  test('invalid tenantId type returns false rather than throwing', async () => {
    expect(await nonceStore.isRegistered(generateRequestId(), 42)).toBe(false);
  });
});

// ── registerAndCheckAnomaly(): combined-Lua marshaling (item 17) ─────────────
//
// Verifies KEYS/ARGV construction and result-code parsing against a faithful
// JS mirror of COMBINED_REGISTER_SCRIPT (see makeFakeRedisClient().eval
// above) — the same level of coverage nonceStore's own register() gets from
// this file's mocked .set(). Actual Lua-interpreter correctness is confirmed
// separately via a live-Redis smoke test (ITEM-17-REMEDIATION-REPORT.md §6),
// matching the convention item 16 established for CHECK_AND_INCR_BATCH_SCRIPT.

describe('registerAndCheckAnomaly() — combined script marshaling', () => {
  const T = Object.freeze({ windowMs: 60_000, perKeyMax: 5, globalMax: 10 });

  function anomalyParams(overrides = {}) {
    return { publicKeyId: 'default:key_v1', nowMs: Date.now(), windowMs: T.windowMs, perKeyMax: T.perKeyMax, globalMax: T.globalMax, ...overrides };
  }

  test('all pass: returns ALLOWED with counts 1/1 on a fresh key', async () => {
    const id     = generateRequestId();
    const result = await nonceStore.registerAndCheckAnomaly(id, FUTURE(), null, anomalyParams());
    expect(result).toEqual({ phase: 'ALLOWED', perKeyCount: 1, globalCount: 1 });
  });

  test('sends exactly [nonceKey, perKeyKey, globalKey] as KEYS, no tenant', async () => {
    const id = generateRequestId();
    await nonceStore.registerAndCheckAnomaly(id, FUTURE(), null, anomalyParams({ publicKeyId: 'keyX' }));
    expect(fakeClient.eval).toHaveBeenCalledWith(expect.any(String), {
      keys: [`qodiqa:req:v2:${id}`, 'anomaly:v2:key:keyX', 'anomaly:v2:global'],
      arguments: expect.any(Array),
    });
  });

  test('sends exactly [nonceKey, perKeyKey, globalKey] as KEYS, tenant-scoped', async () => {
    const id = generateRequestId();
    await nonceStore.registerAndCheckAnomaly(id, FUTURE(), 'acme', anomalyParams({ publicKeyId: 'keyX' }));
    expect(fakeClient.eval).toHaveBeenCalledWith(expect.any(String), {
      keys: [`acme:qodiqa:req:v2:${id}`, 'anomaly:v2:tenant:acme:key:keyX', 'anomaly:v2:tenant:acme:global'],
      arguments: expect.any(Array),
    });
  });

  test('replay: second call with the same requestId returns REPLAY; anomaly untouched', async () => {
    const id = generateRequestId();
    const first  = await nonceStore.registerAndCheckAnomaly(id, FUTURE(), null, anomalyParams());
    expect(first.phase).toBe('ALLOWED');

    const second = await nonceStore.registerAndCheckAnomaly(id, FUTURE(), null, anomalyParams());
    expect(second).toEqual({ phase: 'REPLAY' });

    // Anomaly windows must not have grown from the replayed attempt.
    expect(fakeClient._zsets.get('anomaly:v2:key:default:key_v1').length).toBe(1);
    expect(fakeClient._zsets.get('anomaly:v2:global').length).toBe(1);
  });

  test('SIGNATURE_BURST: per-key over threshold stops before the global window is touched', async () => {
    const result = await nonceStore.registerAndCheckAnomaly(
      generateRequestId(), FUTURE(), null, anomalyParams({ perKeyMax: 0 }),
    );
    expect(result).toEqual({ phase: 'SIGNATURE_BURST', perKeyCount: 1 });
    expect(fakeClient._zsets.has('anomaly:v2:global')).toBe(false);
  });

  test('RATE_BURST: global over threshold, per-key still ok', async () => {
    const result = await nonceStore.registerAndCheckAnomaly(
      generateRequestId(), FUTURE(), null, anomalyParams({ globalMax: 0 }),
    );
    expect(result).toEqual({ phase: 'RATE_BURST', perKeyCount: 1, globalCount: 1 });
  });

  test('malformed requestId throws before touching Redis', async () => {
    await expect(nonceStore.registerAndCheckAnomaly('not-a-uuid', FUTURE(), null, anomalyParams()))
      .rejects.toThrow(/UUID v4/);
    expect(fakeClient.eval).not.toHaveBeenCalled();
  });

  test('already-expired expiryMs throws before touching Redis', async () => {
    await expect(nonceStore.registerAndCheckAnomaly(generateRequestId(), Date.now(), null, anomalyParams()))
      .rejects.toThrow(/already expired/);
    expect(fakeClient.eval).not.toHaveBeenCalled();
  });

  test('buildAnomalyKeys() matches checkAnomaly.js\'s inline key convention exactly', () => {
    const { buildAnomalyKeys } = require('../anomalyStore');
    // checkAnomaly.js computes `${prefix}key:${publicKeyId}` / `${prefix}global`
    // (short form, passed to anomalyStore.record()), which record() then
    // prefixes with its own KEY_PREFIX ('anomaly:v2:'). buildAnomalyKeys()
    // must produce exactly that same full string for the combined path to
    // read/write the SAME Redis keys checkAnomaly()'s sequential path does.
    expect(buildAnomalyKeys('keyX', null)).toEqual({
      perKeyKey: 'anomaly:v2:key:keyX',
      globalKey: 'anomaly:v2:global',
    });
    expect(buildAnomalyKeys('keyX', 'acme')).toEqual({
      perKeyKey: 'anomaly:v2:tenant:acme:key:keyX',
      globalKey: 'anomaly:v2:tenant:acme:global',
    });
  });
});
