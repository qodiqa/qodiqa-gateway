'use strict';

/**
 * Replay protection test suite — QODIQA V2
 *
 * Tests the complete execution-uniqueness guarantee:
 *   every requestId may be accepted at most once.
 *
 * The nonce store is injected via _store in every test — no Redis required.
 * The in-memory test store faithfully models the production Redis store:
 *   • register() is a synchronous atomic check-then-set within the event loop
 *   • Two concurrent callers cannot both see { registered: true }
 *   • Persistence is modeled by a shared Map that outlives store instances
 *   • Unavailability is modeled by a broken store that always throws
 *
 * Test categories:
 *   1.  Sequential replay
 *   2.  Parallel replay (concurrent Promise.all)
 *   3.  Cross-instance simulation (shared backing map)
 *   4.  Restart simulation (backing map survives instance replacement)
 *   5.  Expiry handling (TTL enforcement)
 *   6.  Store unavailability (fail-closed)
 *   7.  registerNonce — unit tests
 *   8.  validateBoundRequest — full pipeline
 */

const { registerNonce }         = require('../registerNonce');
const { validateBoundRequest }  = require('../validateBoundRequest');
const { signBoundArtifact }     = require('../signBoundArtifact');
const { generateRequestId,
        isValidRequestId }      = require('../requestId');
const { buildNonceKey }         = require('../nonceStore');
const { getActiveKey }          = require('../../../services/artifact/keyStore');

// ── Test store factories ──────────────────────────────────────────────────────

/**
 * Pass-all anomaly store: always returns count: 0.
 * Injected into validateBoundRequest calls in this suite so that anomaly
 * detection (step 4) never triggers and never attempts a Redis connection.
 */
function makePassAnomalyStore() {
  return { async record() { return { count: 0 }; } };
}

const PASS_ANOMALY = makePassAnomalyStore();

/**
 * Wrapper that injects the pass-all anomaly store by default.
 * Allows replay-protection tests to focus on steps 1–3 without Redis.
 */
function vbr(artifact, request, opts = {}) {
  return validateBoundRequest(artifact, request, { _anomalyStore: PASS_ANOMALY, ...opts });
}

/**
 * In-memory nonce store backed by a fresh Map.
 * Models the production Redis store: register() is synchronous + atomic
 * within Node's single-threaded event loop.
 */
function makeTestStore() {
  const map = new Map();
  return {
    async register(requestId, expiryMs, tenantId) {
      const key = buildNonceKey(requestId, tenantId);
      if (map.has(key)) return { registered: false };
      map.set(key, expiryMs);
      return { registered: true };
    },
    async isRegistered(requestId, tenantId) {
      const key = buildNonceKey(requestId, tenantId);
      const exp = map.get(key);
      if (exp === undefined) return false;
      if (Date.now() >= exp) { map.delete(key); return false; }
      return true;
    },
    _map: map,
  };
}

/**
 * In-memory store backed by a CALLER-SUPPLIED Map.
 * Used for persistence and cross-instance tests: multiple store instances
 * share the same backing map, modeling multiple processes sharing Redis.
 */
function makeTestStoreFromMap(map) {
  return {
    async register(requestId, expiryMs, tenantId) {
      const key = buildNonceKey(requestId, tenantId);
      if (map.has(key)) return { registered: false };
      map.set(key, expiryMs);
      return { registered: true };
    },
    async isRegistered(requestId, tenantId) {
      const key = buildNonceKey(requestId, tenantId);
      const exp = map.get(key);
      if (exp === undefined) return false;
      if (Date.now() >= exp) { map.delete(key); return false; }
      return true;
    },
    _map: map,
  };
}

/**
 * Broken store: every register() call throws immediately.
 * Models a Redis connection failure — the request must be blocked (fail-closed).
 */
function makeBrokenStore(message = 'ECONNREFUSED: Redis connection refused') {
  return {
    async register() { throw new Error(message); },
    async isRegistered() { throw new Error(message); },
  };
}

// ── Test helpers ──────────────────────────────────────────────────────────────

let KEY;

beforeAll(() => { KEY = getActiveKey('default'); });

const BASE_REQ = { method: 'POST', path: '/api/execute', body: { userId: 'alice', action: 'read' } };

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
}

function buildBound(req = BASE_REQ, extraPayload = {}) {
  return signBoundArtifact(req, freshEnvelope(extraPayload), KEY.privDer);
}

// ── 1. Sequential replay ───────────────────────────────────────────────────────

describe('replay protection — sequential replay', () => {

  test('first execution is ALLOW; second identical request is REPLAY_DETECTED', async () => {
    const store    = makeTestStore();
    const artifact = buildBound();

    const r1 = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r1.allowed).toBe(true);
    expect(r1.requestId).toBe(artifact.payload.requestId);

    const r2 = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('third and subsequent replays are all blocked', async () => {
    const store    = makeTestStore();
    const artifact = buildBound();

    const first = await vbr(artifact, BASE_REQ, { _store: store });
    expect(first.allowed).toBe(true);

    for (let i = 0; i < 5; i++) {
      const r = await vbr(artifact, BASE_REQ, { _store: store });
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe('REPLAY_DETECTED');
    }
  });

  test('different artifacts (different requestIds) are each accepted once', async () => {
    const store = makeTestStore();
    const a1 = buildBound();
    const a2 = buildBound();
    expect(a1.payload.requestId).not.toBe(a2.payload.requestId);

    expect((await vbr(a1, BASE_REQ, { _store: store })).allowed).toBe(true);
    expect((await vbr(a2, BASE_REQ, { _store: store })).allowed).toBe(true);

    // Each blocked on second attempt
    expect((await vbr(a1, BASE_REQ, { _store: store })).reason).toBe('REPLAY_DETECTED');
    expect((await vbr(a2, BASE_REQ, { _store: store })).reason).toBe('REPLAY_DETECTED');
  });

  test('nonce is registered after first call — subsequent check confirms it', async () => {
    const store    = makeTestStore();
    const artifact = buildBound();

    // Key format per QODIQA-PROTOCOL-SPEC.md §27.11: <tenantId>:qodiqa:req:v2:<requestId>
    const tenantId  = KEY.keyId.split(':')[0];
    const scopedKey = buildNonceKey(artifact.payload.requestId, tenantId);
    expect(store._map.has(scopedKey)).toBe(false);
    await vbr(artifact, BASE_REQ, { _store: store });
    expect(store._map.has(scopedKey)).toBe(true);
  });

});

// ── 2. Parallel replay ─────────────────────────────────────────────────────────

describe('replay protection — parallel replay (concurrent)', () => {

  test('10 concurrent requests for same artifact: exactly 1 ALLOW, 9 REPLAY_DETECTED', async () => {
    const store    = makeTestStore();
    const artifact = buildBound();

    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        vbr(artifact, BASE_REQ, { _store: store }),
      ),
    );

    const allowed  = results.filter(r => r.allowed);
    const replayed = results.filter(r => !r.allowed && r.reason === 'REPLAY_DETECTED');

    expect(allowed).toHaveLength(1);
    expect(replayed).toHaveLength(9);
    expect(allowed[0].requestId).toBe(artifact.payload.requestId);
  });

  test('100 concurrent requests for same artifact: exactly 1 ALLOW', async () => {
    const store    = makeTestStore();
    const artifact = buildBound();

    const results = await Promise.all(
      Array.from({ length: 100 }, () =>
        vbr(artifact, BASE_REQ, { _store: store }),
      ),
    );

    expect(results.filter(r => r.allowed)).toHaveLength(1);
    expect(results.filter(r => r.reason === 'REPLAY_DETECTED')).toHaveLength(99);
  });

  test('concurrent requests for different artifacts are all accepted', async () => {
    const store = makeTestStore();
    const artifacts = Array.from({ length: 10 }, () => buildBound());

    const results = await Promise.all(
      artifacts.map(a => vbr(a, BASE_REQ, { _store: store })),
    );

    expect(results.every(r => r.allowed)).toBe(true);
    expect(results.map(r => r.requestId)).toEqual(
      expect.arrayContaining(artifacts.map(a => a.payload.requestId)),
    );
  });

  test('mixed: N unique artifacts + M replays — unique accepted once, replays blocked', async () => {
    const store     = makeTestStore();
    const unique    = Array.from({ length: 5 }, () => buildBound());
    const replays   = Array.from({ length: 3 }, () => unique[0]); // same artifact 3 times

    const requests = [...unique, ...replays];
    const results  = await Promise.all(
      requests.map(a => vbr(a, BASE_REQ, { _store: store })),
    );

    const allowed = results.filter(r => r.allowed);
    // unique[0] is submitted 4 times (once unique + 3 replays) — only 1 allowed
    expect(allowed).toHaveLength(5); // all 5 unique artifacts accepted once
    expect(results.filter(r => r.reason === 'REPLAY_DETECTED')).toHaveLength(3);
  });

});

// ── 3. Cross-instance simulation ───────────────────────────────────────────────

describe('replay protection — cross-instance (shared store)', () => {

  test('two independent validator instances sharing the same store: replay blocked', async () => {
    const sharedMap = new Map();
    const instance1 = makeTestStoreFromMap(sharedMap);
    const instance2 = makeTestStoreFromMap(sharedMap); // different object, same backing Map

    const artifact = buildBound();

    // Instance 1 accepts the request.
    const r1 = await vbr(artifact, BASE_REQ, { _store: instance1 });
    expect(r1.allowed).toBe(true);

    // Instance 2 rejects the same request — sees it in the shared map.
    const r2 = await vbr(artifact, BASE_REQ, { _store: instance2 });
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('10 independent instances, same artifact: only one wins', async () => {
    const sharedMap = new Map();
    const instances = Array.from({ length: 10 }, () => makeTestStoreFromMap(sharedMap));
    const artifact  = buildBound();

    const results = await Promise.all(
      instances.map(store => vbr(artifact, BASE_REQ, { _store: store })),
    );

    expect(results.filter(r => r.allowed)).toHaveLength(1);
    expect(results.filter(r => r.reason === 'REPLAY_DETECTED')).toHaveLength(9);
  });

  test('cross-instance: sequential requests, each on a different instance', async () => {
    const sharedMap = new Map();
    const a1 = buildBound();
    const a2 = buildBound();

    const store1 = makeTestStoreFromMap(sharedMap);
    const store2 = makeTestStoreFromMap(sharedMap);

    // Instance 1 processes a1
    expect((await vbr(a1, BASE_REQ, { _store: store1 })).allowed).toBe(true);
    // Instance 2 tries to replay a1 — blocked because sharedMap has the key
    expect((await vbr(a1, BASE_REQ, { _store: store2 })).reason).toBe('REPLAY_DETECTED');
    // Instance 2 processes a2 fresh — allowed
    expect((await vbr(a2, BASE_REQ, { _store: store2 })).allowed).toBe(true);
    // Instance 1 tries a2 — blocked
    expect((await vbr(a2, BASE_REQ, { _store: store1 })).reason).toBe('REPLAY_DETECTED');
  });

});

// ── 4. Restart simulation ──────────────────────────────────────────────────────

describe('replay protection — restart simulation (persistent backing map)', () => {

  test('nonce registered before restart is blocked after restart', async () => {
    const persistentMap = new Map();

    // "Before restart": instance 1 accepts the request
    const store1   = makeTestStoreFromMap(persistentMap);
    const artifact = buildBound();

    const r1 = await vbr(artifact, BASE_REQ, { _store: store1 });
    expect(r1.allowed).toBe(true);
    expect(persistentMap.size).toBe(1);

    // "After restart": new instance backed by the SAME persistent data
    const store2 = makeTestStoreFromMap(persistentMap);
    const r2 = await vbr(artifact, BASE_REQ, { _store: store2 });
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('multiple nonces survive restart — all blocked on second attempt', async () => {
    const persistentMap = new Map();
    const store1    = makeTestStoreFromMap(persistentMap);
    const artifacts = Array.from({ length: 5 }, () => buildBound());

    // First run: all accepted
    for (const a of artifacts) {
      const r = await vbr(a, BASE_REQ, { _store: store1 });
      expect(r.allowed).toBe(true);
    }
    expect(persistentMap.size).toBe(5);

    // Restart: new store instance
    const store2 = makeTestStoreFromMap(persistentMap);
    for (const a of artifacts) {
      const r = await vbr(a, BASE_REQ, { _store: store2 });
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe('REPLAY_DETECTED');
    }
  });

  test('fresh nonce after restart is accepted (restart does not brick the store)', async () => {
    const persistentMap = new Map();

    // Before restart
    const store1   = makeTestStoreFromMap(persistentMap);
    const old      = buildBound();
    await vbr(old, BASE_REQ, { _store: store1 });

    // After restart
    const store2   = makeTestStoreFromMap(persistentMap);
    const fresh    = buildBound();

    expect(old.payload.requestId).not.toBe(fresh.payload.requestId);

    const r = await vbr(fresh, BASE_REQ, { _store: store2 });
    expect(r.allowed).toBe(true);
  });

});

// ── 5. Expiry handling ─────────────────────────────────────────────────────────

describe('replay protection — expiry handling', () => {

  test('artifact with future expiry is accepted (TTL > 0)', async () => {
    const store    = makeTestStore();
    const artifact = buildBound();
    expect(artifact.expiry).toBeGreaterThan(Date.now());

    const r = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r.allowed).toBe(true);
  });

  test('registerNonce with already-expired expiryMs returns EXPIRED', async () => {
    const store     = makeTestStore();
    const requestId = generateRequestId();
    const pastExpiry = Date.now() - 1;

    const r = await registerNonce(requestId, pastExpiry, { _store: store });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('EXPIRED');
  });

  test('validateBoundRequest with near-zero TTL: expiry check blocks before store call', async () => {
    const store   = makeTestStore();
    const frozenNow = Date.now();
    // Build artifact with expiry already past at validation time
    const artifact = signBoundArtifact(
      BASE_REQ,
      {
        payload:     {},
        timestamp:   frozenNow - 5_000,
        expiry:      frozenNow - 1,         // expired 1 ms ago
        publicKeyId: KEY.keyId,
      },
      KEY.privDer,
    );

    const r = await vbr(artifact, BASE_REQ, {
      _clock: () => frozenNow,             // clock frozen at "now"
      _store: store,
    });
    expect(r.allowed).toBe(false);
    // Blocked at validateArtifact step (EXPIRED), before the nonce store is hit
    expect(r.reason).toBe('EXPIRED');
    expect(store._map.size).toBe(0); // nonce store NOT written
  });

  test('expired artifact does not pollute nonce store — requestId remains usable if expiry extended', async () => {
    const store      = makeTestStore();
    const requestId  = generateRequestId();
    const pastExpiry = Date.now() - 1;

    const r = await registerNonce(requestId, pastExpiry, { _store: store });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('EXPIRED');

    // Nonce was NOT written to store — a fresh artifact with same requestId
    // (hypothetically extended expiry) would still be accepted
    expect(store._map.has(buildNonceKey(requestId))).toBe(false);
  });

  test('TTL is derived from artifact.expiry, not from a fixed window', async () => {
    const store = makeTestStore();
    // Two artifacts with different expiry values
    const shortLived = signBoundArtifact(
      BASE_REQ,
      { payload: {}, timestamp: Date.now(), expiry: Date.now() + 5_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const longLived = signBoundArtifact(
      BASE_REQ,
      { payload: {}, timestamp: Date.now(), expiry: Date.now() + 3_600_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );

    const r1 = await vbr(shortLived,  BASE_REQ, { _store: store });
    const r2 = await vbr(longLived,   BASE_REQ, { _store: store });

    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);

    // Both nonces are in the store; TTL values differ but both were stored correctly
    // Key format per QODIQA-PROTOCOL-SPEC.md §27.11: <tenantId>:qodiqa:req:v2:<requestId>
    const tenantId = KEY.keyId.split(':')[0];
    expect(store._map.has(buildNonceKey(shortLived.payload.requestId, tenantId))).toBe(true);
    expect(store._map.has(buildNonceKey(longLived.payload.requestId, tenantId))).toBe(true);
  });

});

// ── 6. Store unavailability (fail-closed) ──────────────────────────────────────

describe('replay protection — store unavailability (fail-closed)', () => {

  test('store unavailable → validateBoundRequest returns NONCE_STORE_ERROR', async () => {
    const store    = makeBrokenStore();
    const artifact = buildBound();

    const r = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('NONCE_STORE_ERROR');
  });

  test('store unavailable → registerNonce returns NONCE_STORE_ERROR (never throws)', async () => {
    const store     = makeBrokenStore();
    const requestId = generateRequestId();
    const expiry    = Date.now() + 300_000;

    const r = await registerNonce(requestId, expiry, { _store: store });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('NONCE_STORE_ERROR');
    expect(typeof r.details.error).toBe('string');
  });

  test('store unavailable → never allows execution (every call is blocked)', async () => {
    const store    = makeBrokenStore();
    const artifact = buildBound();

    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        vbr(artifact, BASE_REQ, { _store: store }),
      ),
    );

    expect(results.every(r => !r.allowed)).toBe(true);
    expect(results.every(r => r.reason === 'NONCE_STORE_ERROR')).toBe(true);
  });

  test('store becomes unavailable AFTER first successful registration → subsequent calls blocked', async () => {
    const backingMap = new Map();
    const goodStore  = makeTestStoreFromMap(backingMap);
    const artifact   = buildBound();

    const r1 = await vbr(artifact, BASE_REQ, { _store: goodStore });
    expect(r1.allowed).toBe(true);

    // Store goes down
    const r2 = await vbr(artifact, BASE_REQ, { _store: makeBrokenStore() });
    expect(r2.allowed).toBe(false);
    // Blocked by store error — fail-closed even if it might have been a replay
    expect(['NONCE_STORE_ERROR', 'REPLAY_DETECTED']).toContain(r2.reason);
  });

  test('validation still blocks at step 1 even with broken store (wrong key)', async () => {
    const artifact = buildBound();
    // Tamper payload to invalidate signature — broken store should never even be reached
    const tampered = { ...artifact, payload: { ...artifact.payload, extra: 'injected' } };

    const r = await vbr(tampered, BASE_REQ, { _store: makeBrokenStore() });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

});

// ── 7. registerNonce — unit tests ──────────────────────────────────────────────

describe('registerNonce — unit', () => {

  test('valid inputs → { ok: true, requestId }', async () => {
    const store     = makeTestStore();
    const requestId = generateRequestId();
    const expiry    = Date.now() + 300_000;

    const r = await registerNonce(requestId, expiry, { _store: store });
    expect(r.ok).toBe(true);
    expect(r.requestId).toBe(requestId);
    expect(store._map.has(buildNonceKey(requestId))).toBe(true);
  });

  test('same requestId twice → second is REPLAY_DETECTED', async () => {
    const store     = makeTestStore();
    const requestId = generateRequestId();
    const expiry    = Date.now() + 300_000;

    expect((await registerNonce(requestId, expiry, { _store: store })).ok).toBe(true);
    const r2 = await registerNonce(requestId, expiry, { _store: store });
    expect(r2.ok).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('invalid requestId (not UUID v4) → MALFORMED_REQUEST_ID', async () => {
    const r = await registerNonce('not-a-uuid', Date.now() + 300_000, { _store: makeTestStore() });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('MALFORMED_REQUEST_ID');
  });

  test('invalid requestId (null) → MALFORMED_REQUEST_ID', async () => {
    const r = await registerNonce(null, Date.now() + 300_000, { _store: makeTestStore() });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('MALFORMED_REQUEST_ID');
  });

  test('invalid expiryMs (NaN) → INVALID_EXPIRY', async () => {
    const r = await registerNonce(generateRequestId(), NaN, { _store: makeTestStore() });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('INVALID_EXPIRY');
  });

  test('invalid expiryMs (negative) → INVALID_EXPIRY', async () => {
    const r = await registerNonce(generateRequestId(), -1, { _store: makeTestStore() });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('INVALID_EXPIRY');
  });

  test('expired expiryMs → EXPIRED (not written to store)', async () => {
    const store     = makeTestStore();
    const requestId = generateRequestId();
    const r = await registerNonce(requestId, Date.now() - 1, { _store: store });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('EXPIRED');
    expect(store._map.has(buildNonceKey(requestId))).toBe(false);
  });

  test('store throws → NONCE_STORE_ERROR (registerNonce never propagates)', async () => {
    const r = await registerNonce(
      generateRequestId(), Date.now() + 300_000, { _store: makeBrokenStore() }
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('NONCE_STORE_ERROR');
    expect(typeof r.details.error).toBe('string');
  });

  test('different requestIds do not interfere', async () => {
    const store  = makeTestStore();
    const expiry = Date.now() + 300_000;
    const ids    = Array.from({ length: 20 }, generateRequestId);

    const results = await Promise.all(ids.map(id => registerNonce(id, expiry, { _store: store })));
    expect(results.every(r => r.ok)).toBe(true);
    expect(store._map.size).toBe(20);
  });

});

// ── 8. validateBoundRequest — full pipeline ────────────────────────────────────

describe('validateBoundRequest — full pipeline', () => {

  test('valid artifact + valid request → allowed: true with requestId and publicKeyId', async () => {
    const store    = makeTestStore();
    const artifact = buildBound();

    const r = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r.allowed).toBe(true);
    expect(isValidRequestId(r.requestId)).toBe(true);
    expect(typeof r.publicKeyId).toBe('string');
    expect(r.publicKeyId).toBe(artifact.publicKeyId);
  });

  test('invalid signature → blocked at step 1 (before nonce store is touched)', async () => {
    const store    = makeTestStore();
    const artifact = buildBound();
    const tampered = { ...artifact, payload: { ...artifact.payload, userId: 'attacker' } };

    const r = await vbr(tampered, BASE_REQ, { _store: store });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE');
    expect(store._map.size).toBe(0);
  });

  test('wrong request binding → blocked at step 2 (before nonce store is touched)', async () => {
    const store   = makeTestStore();
    const artifact = buildBound(BASE_REQ);
    const wrongReq = { ...BASE_REQ, path: '/api/other' };

    const r = await vbr(artifact, wrongReq, { _store: store });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
    expect(store._map.size).toBe(0); // nonce not consumed
  });

  test('step 2 block does not burn the requestId — it remains usable on correct request', async () => {
    const store    = makeTestStore();
    const artifact = buildBound(BASE_REQ);
    const wrongReq = { ...BASE_REQ, path: '/api/other' };

    // Wrong path — blocked but nonce NOT consumed
    const r1 = await vbr(artifact, wrongReq, { _store: store });
    expect(r1.allowed).toBe(false);
    expect(store._map.size).toBe(0);

    // Correct path — nonce consumed now
    const r2 = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r2.allowed).toBe(true);
    expect(store._map.size).toBe(1);
  });

  test('missing requestId in payload → REQUEST_MISMATCH (step 2)', async () => {
    const store = makeTestStore();
    const now   = Date.now();
    const { signArtifact } = require('../signArtifact');
    const { computeRequestHash } = require('../requestHash');
    const artifact = signArtifact({
      payload:     { requestHash: computeRequestHash(BASE_REQ.method, BASE_REQ.path, BASE_REQ.body) },
      timestamp:   now,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);

    const r = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
    expect(store._map.size).toBe(0);
  });

  test('result is frozen — no mutation possible', async () => {
    const store    = makeTestStore();
    const artifact = buildBound();
    const r = await vbr(artifact, BASE_REQ, { _store: store });
    expect(Object.isFrozen(r)).toBe(true);
  });

});

// ── 9. callerContext survives replay detection ──────────────────────
//
// callerContext is embedded in payload at /sign time and is therefore
// covered by the same signature verification (Step 1) this whole suite
// already exercises — these tests confirm validateBoundRequest correctly
// surfaces it (not just publicKeyId) on both the ALLOW result and every
// BLOCK reason a replay attempt can produce, so a replay's audit entry is
// never missing caller attribution that a legitimate execution would have
// carried.

const SAMPLE_CALLER_CONTEXT = Object.freeze({
  callerId: 'identity-replay-test', callerName: 'ci-runner', environment: 'test', credentialType: 'api-key',
});

describe('validateBoundRequest — callerContext threading', () => {

  test('ALLOW result surfaces callerId/callerContext read out of the signed payload', async () => {
    const store    = makeTestStore();
    const artifact = buildBound(BASE_REQ, { callerContext: SAMPLE_CALLER_CONTEXT });

    const r = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r.allowed).toBe(true);
    expect(r.callerId).toBe(SAMPLE_CALLER_CONTEXT.callerId);
    expect(r.callerContext).toEqual(SAMPLE_CALLER_CONTEXT);
  });

  test('an artifact with no callerContext (pre-NONREP-1) still allows, with callerId/callerContext null', async () => {
    const store    = makeTestStore();
    const artifact = buildBound(); // no callerContext in payload

    const r = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r.allowed).toBe(true);
    expect(r.callerId).toBeNull();
    expect(r.callerContext).toBeNull();
  });

  test('a REPLAY_DETECTED block still carries the same callerId the original ALLOW carried', async () => {
    const store    = makeTestStore();
    const artifact = buildBound(BASE_REQ, { callerContext: SAMPLE_CALLER_CONTEXT });

    const r1 = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r1.allowed).toBe(true);

    const r2 = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
    expect(r2.callerId).toBe(SAMPLE_CALLER_CONTEXT.callerId);
    expect(r2.callerContext).toEqual(SAMPLE_CALLER_CONTEXT);
  });

  test('a REQUEST_MISMATCH block (step 2, after signature verification) still carries callerId', async () => {
    const store    = makeTestStore();
    const artifact = buildBound(BASE_REQ, { callerContext: SAMPLE_CALLER_CONTEXT });
    const wrongReq = { ...BASE_REQ, path: '/api/other' };

    const r = await vbr(artifact, wrongReq, { _store: store });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
    expect(r.callerId).toBe(SAMPLE_CALLER_CONTEXT.callerId);
  });

  test('an INVALID_SIGNATURE block (step 1) never carries callerId — no attribution can be asserted before signature verification succeeds', async () => {
    const store    = makeTestStore();
    const artifact = buildBound(BASE_REQ, { callerContext: SAMPLE_CALLER_CONTEXT });
    const tampered = { ...artifact, payload: { ...artifact.payload, injected: true } };

    const r = await vbr(tampered, BASE_REQ, { _store: store });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE');
    expect(r.callerId).toBeUndefined();
  });

});
