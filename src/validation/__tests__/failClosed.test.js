'use strict';

/**
 * Fail-closed validation suite — QODIQA V2
 *
 * Security guarantee under test:
 *   If ANY critical dependency (nonce store, anomaly store) fails at runtime,
 *   the system MUST return BLOCK.  No request may be ALLOWED during a failure.
 *
 * Every test in this file verifies one invariant:
 *
 *   ∀ store failure F, ∀ valid request R: validate(R) → { allowed: false }
 *
 * Test categories:
 *   FC-01 … FC-06  Nonce store failure
 *   FC-07 … FC-11  Anomaly store failure
 *   FC-12 … FC-16  Partial failure (mid-pipeline)
 *   FC-17 … FC-21  Total store failure (all components down)
 *   FC-22 … FC-26  Recovery (store restored → normal operation resumes)
 *   FC-27 … FC-30  No-silent-fallback proof (no ALLOW path during failure)
 */

const { validateBoundRequest } = require('../validateBoundRequest');
const { registerNonce }        = require('../registerNonce');
const { checkAnomaly }         = require('../checkAnomaly');
const { signBoundArtifact }    = require('../signBoundArtifact');
const { isValidRequestId }     = require('../requestId');
const { buildNonceKey }        = require('../nonceStore');
const { getActiveKey }         = require('../../../services/artifact/keyStore');

// ── Store factories ───────────────────────────────────────────────────────────

/** Healthy nonce store. */
function makeNonceStore() {
  const map = new Map();
  return {
    async register(requestId, expiryMs, tenantId) {
      const key = buildNonceKey(requestId, tenantId);
      if (map.has(key)) return { registered: false };
      map.set(key, expiryMs);
      return { registered: true };
    },
    _map: map,
  };
}

/** Healthy anomaly store (always passes). */
function makeAnomalyStore() {
  const windows = new Map();
  return {
    async record(key, nowMs, windowMs) {
      const existing = windows.get(key) || [];
      const fresh    = existing.filter(t => t > nowMs - windowMs);
      fresh.push(nowMs);
      windows.set(key, fresh);
      return { count: fresh.length };
    },
    _windows: windows,
  };
}

/**
 * Store that throws on every call — simulates complete Redis failure.
 * message is embedded so assertions can verify the error propagated.
 */
function makeDeadStore(message = 'ECONNREFUSED: Redis connection refused') {
  return {
    async register() { throw new Error(message); },
    async record()   { throw new Error(message); },
    async isRegistered() { throw new Error(message); },
  };
}

/**
 * Store that succeeds for N calls then permanently fails.
 * Simulates a mid-stream connection drop.
 */
function makeFlakeyNonceStore(successCount) {
  const map   = new Map();
  let   calls = 0;
  return {
    async register(requestId, expiryMs) {
      if (calls++ >= successCount) throw new Error('ETIMEDOUT: mid-stream failure');
      if (map.has(requestId)) return { registered: false };
      map.set(requestId, expiryMs);
      return { registered: true };
    },
    _map: map,
  };
}

/**
 * Anomaly store that succeeds for the per-key call then fails on global.
 * Simulates partial Redis failure after the first sorted-set query.
 */
function makeFlakeyAnomalyStore() {
  const windows = new Map();
  let   calls   = 0;
  return {
    async record(key, nowMs, windowMs) {
      if (calls++ > 0) throw new Error('ETIMEDOUT: anomaly store dropped mid-pipeline');
      const existing = windows.get(key) || [];
      const fresh    = existing.filter(t => t > nowMs - windowMs);
      fresh.push(nowMs);
      windows.set(key, fresh);
      return { count: fresh.length };
    },
  };
}

/**
 * Wraps makeNonceStore() so its `register` can be dynamically toggled to fail.
 * Simulates a store that was healthy then lost its Redis connection.
 */
function makeSwitchableNonceStore() {
  const map  = new Map();
  let   down = false;
  return {
    async register(requestId, expiryMs, tenantId) {
      if (down) throw new Error('ECONNRESET: store went down');
      const key = buildNonceKey(requestId, tenantId);
      if (map.has(key)) return { registered: false };
      map.set(key, expiryMs);
      return { registered: true };
    },
    _map: map,
    goDown()  { down = true;  },
    comeUp()  { down = false; },
  };
}

/** Switchable anomaly store — can be toggled to fail at runtime. */
function makeSwitchableAnomalyStore() {
  const windows = new Map();
  let   down    = false;
  return {
    async record(key, nowMs, windowMs) {
      if (down) throw new Error('ECONNRESET: anomaly store went down');
      const existing = windows.get(key) || [];
      const fresh    = existing.filter(t => t > nowMs - windowMs);
      fresh.push(nowMs);
      windows.set(key, fresh);
      return { count: fresh.length };
    },
    _windows: windows,
    goDown()  { down = true;  },
    comeUp()  { down = false; },
  };
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });

const BASE_REQ = { method: 'POST', path: '/api/execute', body: { userId: 'u1', action: 'run' } };

const OPEN_THRESH = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1_000, GLOBAL_MAX: 100_000 });

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
}

function buildBound(req = BASE_REQ, extra = {}) {
  return signBoundArtifact(req, freshEnvelope(extra), KEY.privDer);
}

// Convenience: run full pipeline with explicit store injection.
function run(artifact, req, nonceStore, anomalyStore, extra = {}) {
  return validateBoundRequest(artifact, req, {
    _store:        nonceStore,
    _anomalyStore: anomalyStore,
    _thresholds:   OPEN_THRESH,
    ...extra,
  });
}

// ── FC-01 … FC-06  Nonce store failure ────────────────────────────────────────

describe('FC nonce store failure', () => {

  // FC-01
  test('FC-01  nonce store throws → NONCE_STORE_ERROR, allowed: false', async () => {
    const artifact = buildBound();
    const result   = await run(artifact, BASE_REQ, makeDeadStore(), makeAnomalyStore());

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('NONCE_STORE_ERROR');
  });

  // FC-02
  // remediation: publicKeyId is now included on this BLOCK path —
  // Step 1's Ed25519 signature verification has already succeeded by the
  // time a nonce-store failure occurs (Step 3), so the key is genuinely
  // verified, not untrustworthy, and durable audit attribution requires the
  // caller (aiChat.js's _writeAuditBlock) to receive it. publicKeyId is
  // public information regardless — served unauthenticated at
  // /.well-known/qodiqa/keys — so this is not a confidentiality regression.
  // requestId remains withheld here: unlike REPLAY_DETECTED, this reason
  // does not need it for replay-lineage correlation.
  test('FC-02  nonce store failure carries no requestId, but does carry the signature-verified publicKeyId', async () => {
    const artifact = buildBound();
    const result   = await run(artifact, BASE_REQ, makeDeadStore(), makeAnomalyStore());

    expect(result.allowed).toBe(false);
    expect(result.requestId).toBeUndefined();
    expect(result.publicKeyId).toBe(KEY.keyId);
  });

  // FC-03
  test('FC-03  100 concurrent requests with dead nonce store — all blocked', async () => {
    const artifact = buildBound();
    const dead     = makeDeadStore();
    const results  = await Promise.all(
      Array.from({ length: 100 }, () => run(artifact, BASE_REQ, dead, makeAnomalyStore())),
    );

    expect(results.every(r => !r.allowed)).toBe(true);
    expect(results.every(r => r.reason === 'NONCE_STORE_ERROR')).toBe(true);
  });

  // FC-04
  test('FC-04  different artifacts, all with dead nonce store — all blocked', async () => {
    const dead     = makeDeadStore();
    const results  = await Promise.all(
      Array.from({ length: 10 }, () => {
        const a = buildBound();
        return run(a, BASE_REQ, dead, makeAnomalyStore());
      }),
    );

    expect(results.every(r => !r.allowed)).toBe(true);
  });

  // FC-05
  test('FC-05 store fails with a custom error message — fail-closed, and the raw text never reaches the client', async () => {
    const artifact = buildBound();
    const result   = await run(artifact, BASE_REQ, makeDeadStore('CUSTOM_REDIS_FAILURE'), makeAnomalyStore());

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('NONCE_STORE_ERROR');
    // details are client-visible; the store's own message is logged server-side
    // (NONCE_STORE_ERROR event) and replaced by a stable code here.
    expect(result.details.error).toBe('NONCE_STORE_UNAVAILABLE');
    expect(JSON.stringify(result.details)).not.toMatch(/CUSTOM_REDIS_FAILURE/);
  });

  // FC-06
  test('FC-06  nonce store fails mid-stream (after N successes) — all subsequent blocked', async () => {
    const flakey      = makeFlakeyNonceStore(2); // first 2 succeed, rest fail
    const anomaly     = makeAnomalyStore();
    const results     = await Promise.all(
      Array.from({ length: 5 }, () => {
        const a = buildBound();
        return run(a, BASE_REQ, flakey, anomaly);
      }),
    );

    const allowed = results.filter(r => r.allowed);
    const blocked = results.filter(r => !r.allowed && r.reason === 'NONCE_STORE_ERROR');
    expect(allowed.length).toBe(2);
    expect(blocked.length).toBe(3);
  });

});

// ── FC-07 … FC-11  Anomaly store failure ──────────────────────────────────────

describe('FC anomaly store failure', () => {

  // FC-07
  test('FC-07  anomaly store throws → ANOMALY_DETECTED, allowed: false', async () => {
    const artifact = buildBound();
    const result   = await run(artifact, BASE_REQ, makeNonceStore(), makeDeadStore());

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('ANOMALY_DETECTED');
    expect(result.details.type).toBe('STORE_ERROR');
  });

  // FC-08
  // remediation: same rationale as FC-02 — Step 1 signature
  // verification has already succeeded by the time anomaly detection (Step 4)
  // runs, so publicKeyId is genuinely verified and now recorded for durable
  // audit attribution. requestId is still withheld.
  test('FC-08  anomaly store failure carries no requestId, but does carry the signature-verified publicKeyId', async () => {
    const artifact = buildBound();
    const result   = await run(artifact, BASE_REQ, makeNonceStore(), makeDeadStore());

    expect(result.allowed).toBe(false);
    expect(result.requestId).toBeUndefined();
    expect(result.publicKeyId).toBe(KEY.keyId);
  });

  // FC-09
  test('FC-09  100 concurrent requests with dead anomaly store — all blocked', async () => {
    const dead    = makeDeadStore('ANOMALY_REDIS_DOWN');
    const results = await Promise.all(
      Array.from({ length: 100 }, () => {
        const a = buildBound();
        return run(a, BASE_REQ, makeNonceStore(), dead);
      }),
    );

    expect(results.every(r => !r.allowed)).toBe(true);
    expect(results.every(r => r.reason === 'ANOMALY_DETECTED')).toBe(true);
  });

  // FC-10
  test('FC-10  anomaly store fails on global check (partial failure) — still blocked', async () => {
    const artifact = buildBound();
    const result   = await run(artifact, BASE_REQ, makeNonceStore(), makeFlakeyAnomalyStore());

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('ANOMALY_DETECTED');
    expect(result.details.type).toBe('STORE_ERROR');
  });

  // FC-11
  test('FC-11  nonce IS consumed before anomaly fails — replay still blocked after anomaly recovers', async () => {
    const nonceStore   = makeNonceStore();
    const artifact     = buildBound();

    // First call: nonce store succeeds, anomaly store fails
    const r1 = await run(artifact, BASE_REQ, nonceStore, makeDeadStore());
    expect(r1.allowed).toBe(false);
    expect(r1.reason).toBe('ANOMALY_DETECTED');

    // The requestId was registered in the nonce store before anomaly was checked
    // Key format per QODIQA-PROTOCOL-SPEC.md §27.11: <tenantId>:qodiqa:req:v2:<requestId>
    const tenantId  = KEY.keyId.split(':')[0];
    const scopedKey = buildNonceKey(artifact.payload.requestId, tenantId);
    expect(nonceStore._map.has(scopedKey)).toBe(true);

    // Second call: now with a healthy anomaly store — replay is caught
    const r2 = await run(artifact, BASE_REQ, nonceStore, makeAnomalyStore());
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

});

// ── FC-12 … FC-16  Partial failure (mid-pipeline) ─────────────────────────────

describe('FC partial failure — mid-pipeline', () => {

  // FC-12
  test('FC-12  steps 1–3 pass, step 4 (anomaly) fails → BLOCK, no execution', async () => {
    const artifact = buildBound();
    const result   = await run(artifact, BASE_REQ, makeNonceStore(), makeDeadStore());

    expect(result.allowed).toBe(false);
    // Blocked at step 4, not earlier
    expect(result.reason).toBe('ANOMALY_DETECTED');
  });

  // FC-13
  test('FC-13  steps 1–2 pass, step 3 (nonce) fails → BLOCK before step 4 runs', async () => {
    // Use a dead store that tracks whether anomaly was called
    let anomalyCalled = false;
    const spyAnomalyStore = {
      async record() { anomalyCalled = true; return { count: 0 }; },
    };

    const artifact = buildBound();
    const result   = await run(artifact, BASE_REQ, makeDeadStore(), spyAnomalyStore);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('NONCE_STORE_ERROR');
    // Anomaly store must NOT be called when nonce registration fails
    expect(anomalyCalled).toBe(false);
  });

  // FC-14
  test('FC-14  step 1 (artifact) fails → BLOCK before nonce and anomaly are touched', async () => {
    let nonceCalled   = false;
    let anomalyCalled = false;
    const spyNonce  = { async register() { nonceCalled   = true; return { registered: true }; } };
    const spyAnomaly = { async record()  { anomalyCalled = true; return { count: 0 }; } };

    const tampered = { ...buildBound(), payload: { ...buildBound().payload, extra: 'injected' } };
    const result   = await run(tampered, BASE_REQ, spyNonce, spyAnomaly);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('INVALID_SIGNATURE');
    expect(nonceCalled).toBe(false);
    expect(anomalyCalled).toBe(false);
  });

  // FC-15
  test('FC-15  step 2 (binding) fails → BLOCK before nonce and anomaly are touched', async () => {
    let nonceCalled   = false;
    let anomalyCalled = false;
    const spyNonce   = { async register() { nonceCalled   = true; return { registered: true }; } };
    const spyAnomaly = { async record()   { anomalyCalled = true; return { count: 0 }; } };

    const artifact   = buildBound(BASE_REQ);
    const wrongReq   = { ...BASE_REQ, path: '/api/other' };
    const result     = await run(artifact, wrongReq, spyNonce, spyAnomaly);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('REQUEST_MISMATCH');
    expect(nonceCalled).toBe(false);
    expect(anomalyCalled).toBe(false);
  });

  // FC-16
  test('FC-16  checkAnomaly never returns allowed when store throws', async () => {
    // Direct unit test: no wrapping pipeline
    const dead    = makeDeadStore('DIRECT_UNIT_THROW');
    const results = await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        checkAnomaly(`keyId${i % 5}`, { _store: dead, _thresholds: OPEN_THRESH }),
      ),
    );

    expect(results.every(r => r.block)).toBe(true);
    expect(results.every(r => r.reason === 'ANOMALY_DETECTED')).toBe(true);
    expect(results.every(r => r.type === 'STORE_ERROR')).toBe(true);
  });

});

// ── FC-17 … FC-21  Total store failure ────────────────────────────────────────

describe('FC total store failure — all components down', () => {

  // FC-17
  test('FC-17  both stores dead → every request blocked, zero allowed', async () => {
    const deadNonce   = makeDeadStore('NONCE_REDIS_DOWN');
    const deadAnomaly = makeDeadStore('ANOMALY_REDIS_DOWN');
    const results     = await Promise.all(
      Array.from({ length: 50 }, () => {
        const a = buildBound();
        return run(a, BASE_REQ, deadNonce, deadAnomaly);
      }),
    );

    const allowed = results.filter(r => r.allowed);
    expect(allowed).toHaveLength(0);
  });

  // FC-18
  test('FC-18  total failure: nonce store error is reported (not silently caught as ALLOW)', async () => {
    const deadNonce   = makeDeadStore();
    const deadAnomaly = makeDeadStore();
    const artifact    = buildBound();

    const result = await run(artifact, BASE_REQ, deadNonce, deadAnomaly);

    expect(result.allowed).toBe(false);
    // Step 3 fires first — must report NONCE_STORE_ERROR (not ANOMALY_DETECTED)
    expect(result.reason).toBe('NONCE_STORE_ERROR');
  });

  // FC-19
  test('FC-19  total failure blocks unique artifacts, not just replays', async () => {
    const deadNonce   = makeDeadStore();
    const deadAnomaly = makeDeadStore();

    // All distinct artifacts — still all blocked
    const results = await Promise.all(
      Array.from({ length: 20 }, () => {
        const a = buildBound();
        return run(a, BASE_REQ, deadNonce, deadAnomaly);
      }),
    );

    expect(results.every(r => !r.allowed)).toBe(true);
  });

  // FC-20
  test('FC-20  registerNonce never returns ok: true when store throws', async () => {
    const dead    = makeDeadStore('NONCE_UNIT_THROW');
    const results = await Promise.all(
      Array.from({ length: 50 }, (_, i) => {
        const { generateRequestId } = require('../requestId');
        return registerNonce(generateRequestId(), Date.now() + 300_000, { _store: dead });
      }),
    );

    expect(results.every(r => !r.ok)).toBe(true);
    expect(results.every(r => r.reason === 'NONCE_STORE_ERROR')).toBe(true);
  });

  // FC-21
  test('FC-21  total failure result is frozen and contains no allowed field set to true', async () => {
    const dead     = makeDeadStore();
    const artifact = buildBound();
    const result   = await run(artifact, BASE_REQ, dead, dead);

    expect(Object.isFrozen(result)).toBe(true);
    expect(result.allowed).toBe(false);
    // Guard: no property on the result evaluates to true "allowed"
    expect(result.allowed).not.toBe(true);
    expect(result.allowed).not.toBe(1);
    expect(result.allowed).not.toBeTruthy();
  });

});

// ── FC-22 … FC-26  Recovery behavior ──────────────────────────────────────────

describe('FC recovery — store restored → normal operation resumes', () => {

  // FC-22
  test('FC-22  nonce store: down → BLOCK; restored → ALLOW; no state corruption', async () => {
    const nonceStore   = makeSwitchableNonceStore();
    const anomalyStore = makeAnomalyStore();

    const a1 = buildBound();
    const a2 = buildBound();

    // Store is healthy — a1 allowed
    const r1 = await run(a1, BASE_REQ, nonceStore, anomalyStore);
    expect(r1.allowed).toBe(true);

    // Store goes down — a2 blocked
    nonceStore.goDown();
    const r2 = await run(a2, BASE_REQ, nonceStore, anomalyStore);
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('NONCE_STORE_ERROR');

    // Store restored — fresh artifact a3 is allowed
    nonceStore.comeUp();
    const a3 = buildBound();
    const r3 = await run(a3, BASE_REQ, nonceStore, anomalyStore);
    expect(r3.allowed).toBe(true);
  });

  // FC-23
  test('FC-23  anomaly store: down → BLOCK; restored → ALLOW; no state corruption', async () => {
    const nonceStore   = makeNonceStore();
    const anomalyStore = makeSwitchableAnomalyStore();

    const a1 = buildBound();

    // Store healthy — allowed
    const r1 = await run(a1, BASE_REQ, nonceStore, anomalyStore);
    expect(r1.allowed).toBe(true);

    // Store goes down
    anomalyStore.goDown();
    const a2 = buildBound();
    const r2 = await run(a2, BASE_REQ, nonceStore, anomalyStore);
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('ANOMALY_DETECTED');

    // Store restored — fresh artifact allowed
    anomalyStore.comeUp();
    const a3 = buildBound();
    const r3 = await run(a3, BASE_REQ, nonceStore, anomalyStore);
    expect(r3.allowed).toBe(true);
  });

  // FC-24
  test('FC-24  artifact blocked during outage is NOT replayed after recovery', async () => {
    const nonceStore   = makeSwitchableNonceStore();
    const anomalyStore = makeAnomalyStore();
    const artifact     = buildBound();

    // Outage: request blocked at nonce registration — nonce NOT written
    nonceStore.goDown();
    const blocked = await run(artifact, BASE_REQ, nonceStore, anomalyStore);
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toBe('NONCE_STORE_ERROR');
    expect(nonceStore._map.has(artifact.payload.requestId)).toBe(false);

    // Recovery: same artifact is now accepted (nonce was never registered)
    nonceStore.comeUp();
    const recovered = await run(artifact, BASE_REQ, nonceStore, anomalyStore);
    expect(recovered.allowed).toBe(true);

    // Replay attempt after recovery is blocked
    const replay = await run(artifact, BASE_REQ, nonceStore, anomalyStore);
    expect(replay.allowed).toBe(false);
    expect(replay.reason).toBe('REPLAY_DETECTED');
  });

  // FC-25
  test('FC-25  nonces registered before outage are intact after recovery — replay still blocked', async () => {
    const nonceStore   = makeSwitchableNonceStore();
    const anomalyStore = makeAnomalyStore();
    const artifact     = buildBound();

    // Before outage: a1 accepted, nonce written
    const r1 = await run(artifact, BASE_REQ, nonceStore, anomalyStore);
    expect(r1.allowed).toBe(true);
    // Key format per QODIQA-PROTOCOL-SPEC.md §27.11: <tenantId>:qodiqa:req:v2:<requestId>
    const tenantId  = KEY.keyId.split(':')[0];
    expect(nonceStore._map.has(buildNonceKey(artifact.payload.requestId, tenantId))).toBe(true);

    // Outage
    nonceStore.goDown();
    nonceStore.comeUp();

    // After recovery: replay is blocked — nonce persisted through outage
    const replay = await run(artifact, BASE_REQ, nonceStore, anomalyStore);
    expect(replay.allowed).toBe(false);
    expect(replay.reason).toBe('REPLAY_DETECTED');
  });

  // FC-26
  test('FC-26  multiple outage cycles — system is consistent across each cycle', async () => {
    const nonceStore   = makeSwitchableNonceStore();
    const anomalyStore = makeAnomalyStore();

    for (let cycle = 0; cycle < 3; cycle++) {
      const a = buildBound();

      // Healthy: allowed
      const rAllow = await run(a, BASE_REQ, nonceStore, anomalyStore);
      expect(rAllow.allowed).toBe(true);

      // Down: blocked
      nonceStore.goDown();
      const rBlock = await run(buildBound(), BASE_REQ, nonceStore, anomalyStore);
      expect(rBlock.allowed).toBe(false);

      // Restored
      nonceStore.comeUp();
    }
  });

});

// ── FC-27 … FC-30  No silent fallback ────────────────────────────────────────

describe('FC no silent fallback — no ALLOW path during failure', () => {

  // FC-27
  test('FC-27  every path through validateBoundRequest with failing nonce store ends in allowed: false', async () => {
    const dead = makeDeadStore('FC27');
    // Try 5 different well-formed artifacts — none must be allowed
    const results = await Promise.all(
      Array.from({ length: 5 }, () => {
        const a = buildBound();
        return validateBoundRequest(a, BASE_REQ, {
          _store:        dead,
          _anomalyStore: makeAnomalyStore(),
          _thresholds:   OPEN_THRESH,
        });
      }),
    );

    // Invariant: allowed is strictly false (not undefined, not 0, not null)
    for (const r of results) {
      expect(r.allowed).toBe(false);
      expect(typeof r.reason).toBe('string');
      expect(r.reason.length).toBeGreaterThan(0);
    }
  });

  // FC-28
  test('FC-28  every path with failing anomaly store ends in allowed: false', async () => {
    const dead = makeDeadStore('FC28');
    const results = await Promise.all(
      Array.from({ length: 5 }, () => {
        const a = buildBound();
        return validateBoundRequest(a, BASE_REQ, {
          _store:        makeNonceStore(),
          _anomalyStore: dead,
          _thresholds:   OPEN_THRESH,
        });
      }),
    );

    for (const r of results) {
      expect(r.allowed).toBe(false);
      expect(typeof r.reason).toBe('string');
    }
  });

  // FC-29
  test('FC-29  failure response is a frozen object — callers cannot mutate it to allowed', async () => {
    const dead     = makeDeadStore('FC29');
    const artifact = buildBound();
    const result   = await run(artifact, BASE_REQ, dead, makeAnomalyStore());

    expect(Object.isFrozen(result)).toBe(true);

    // Attempt to mutate — must be silently ignored in strict mode or throw
    let mutationPrevented = false;
    try {
      result.allowed = true;
    } catch {
      mutationPrevented = true;
    }
    // Either it threw or the assignment was silently ignored — either way allowed is still false
    expect(result.allowed).toBe(false);
  });

  // FC-30
  test('FC-30  exhaustive: no combination of store failures can produce allowed: true', async () => {
    const deadNonce   = makeDeadStore('FC30_NONCE');
    const deadAnomaly = makeDeadStore('FC30_ANOMALY');

    const combos = [
      // [nonceStore,         anomalyStore]
      [deadNonce,             deadAnomaly],
      [deadNonce,             makeAnomalyStore()],
      [makeNonceStore(),      deadAnomaly],
      [makeFlakeyNonceStore(0), makeAnomalyStore()],
      [makeNonceStore(),      makeFlakeyAnomalyStore()],
    ];

    for (const [nonceStore, anomalyStore] of combos) {
      const artifact = buildBound();
      const result   = await validateBoundRequest(artifact, BASE_REQ, {
        _store:        nonceStore,
        _anomalyStore: anomalyStore,
        _thresholds:   OPEN_THRESH,
      });
      expect(result.allowed).toBe(false);
    }
  });

});
