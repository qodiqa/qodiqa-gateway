'use strict';

/**
 * Replay Regression Tests
 *
 * Pins the nonce store's replay detection behavior. These tests must pass
 * without modification to the nonce store implementation — any change that
 * breaks replay protection will cause these tests to fail.
 *
 * Tests cover:
 *   - Nonce uniqueness: each artifact has a unique requestId
 *   - Single-use guarantee: second use of same nonce is always rejected
 *   - TTL expiry: nonces expire after the artifact's expiry window
 *   - Store failure: nonce store unavailability is fail-closed (BLOCK)
 *   - Concurrency: duplicate nonces under parallel requests
 */

jest.mock('../../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const { signBoundArtifact }    = require('../../src/validation/signBoundArtifact');
const { validateBoundRequest } = require('../../src/validation/validateBoundRequest');
const { getActiveKey, rotateKey } = require('../../services/artifact/keyStore');
const { makeNonceStore,
        makeOpenAnomalyStore,
        makeDeadStore }        = require('../../src/testing/stores');

// ── Fixtures ──────────────────────────────────────────────────────────────────

let KEY;
beforeAll(() => {
  try   { KEY = getActiveKey('default'); }
  catch { rotateKey('default'); KEY = getActiveKey('default'); }
});

const BASE_REQ = { method: 'POST', path: '/ai/chat', body: { prompt: 'hello', model: 'gpt-4' } };

function buildArtifact(expiryOffsetMs = 300_000) {
  const now = Date.now();
  const envelope = {
    payload:     { provider: 'openai' },
    timestamp:   now,
    expiry:      now + expiryOffsetMs,
    publicKeyId: KEY.keyId,
  };
  return signBoundArtifact(BASE_REQ, envelope, KEY.privDer);
}

function validate(artifact, store, anomaly) {
  return validateBoundRequest(artifact, BASE_REQ, {
    _store:        store,
    _anomalyStore: anomaly || makeOpenAnomalyStore(),
  });
}

// ── 1. Basic nonce uniqueness ─────────────────────────────────────────────────

describe('REP-01 Nonce uniqueness', () => {

  test('each artifact has a unique requestId embedded in payload', () => {
    const ids = new Set();
    for (let i = 0; i < 50; i++) {
      const a = buildArtifact();
      // signBoundArtifact injects a fresh UUID into payload.requestId each call
      ids.add(a.payload.requestId);
    }
    expect(ids.size).toBe(50);
  });

  test('each artifact validates successfully on first use with fresh store', async () => {
    for (let i = 0; i < 5; i++) {
      const store    = makeNonceStore();
      const artifact = buildArtifact();
      const result   = await validate(artifact, store);
      expect(result.allowed).toBe(true);
    }
  });
});

// ── 2. Single-use guarantee ───────────────────────────────────────────────────

describe('REP-02 Single-use guarantee', () => {

  test('second validation of same artifact → REPLAY_DETECTED', async () => {
    const store    = makeNonceStore();
    const artifact = buildArtifact();

    const r1 = await validate(artifact, store);
    expect(r1.allowed).toBe(true);

    const r2 = await validate(artifact, store);
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('third and subsequent replays all return REPLAY_DETECTED', async () => {
    const store    = makeNonceStore();
    const artifact = buildArtifact();

    await validate(artifact, store); // first use: allowed
    for (let i = 0; i < 5; i++) {
      const result = await validate(artifact, store);
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('REPLAY_DETECTED');
    }
  });

  test('different artifacts can be used simultaneously (not interfering)', async () => {
    const store = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();
    const artifacts = Array.from({ length: 10 }, () => buildArtifact());

    const results = await Promise.all(
      artifacts.map(a => validateBoundRequest(a, BASE_REQ, { _store: store, _anomalyStore: anomaly }))
    );
    expect(results.every(r => r.allowed)).toBe(true);
  });
});

// ── 3. Replay across independent stores ──────────────────────────────────────

describe('REP-03 Independent nonce stores do not share state', () => {

  test('same artifact validates on first use against different independent stores', async () => {
    const artifact = buildArtifact();
    const storeA   = makeNonceStore();
    const storeB   = makeNonceStore();

    const rA = await validate(artifact, storeA);
    const rB = await validate(artifact, storeB);

    expect(rA.allowed).toBe(true);
    expect(rB.allowed).toBe(true);
  });

  test('second use detected only in the store that recorded it', async () => {
    const artifact = buildArtifact();
    const storeA   = makeNonceStore();
    const storeB   = makeNonceStore();

    await validate(artifact, storeA); // register in store A

    const rA2 = await validate(artifact, storeA); // replay against A → blocked
    const rB  = await validate(artifact, storeB); // first use against B → allowed

    expect(rA2.allowed).toBe(false);
    expect(rA2.reason).toBe('REPLAY_DETECTED');
    expect(rB.allowed).toBe(true);
  });
});

// ── 4. Store failure — fail-closed ────────────────────────────────────────────

describe('REP-04 Nonce store failure is fail-closed', () => {

  test('dead nonce store → request BLOCKED (never ALLOWED)', async () => {
    const artifact = buildArtifact();
    const result   = await validate(artifact, makeDeadStore());
    expect(result.allowed).toBe(false);
  });

  test('dead nonce store rejection does not expose internal error details', async () => {
    const artifact = buildArtifact();
    const result   = await validate(artifact, makeDeadStore());
    expect(result.allowed).toBe(false);
    // reason should be a clean code, not a stack trace
    if (result.reason) {
      expect(typeof result.reason).toBe('string');
      expect(result.reason).not.toContain('Error:');
      expect(result.reason).not.toContain('at ');
    }
  });
});

// ── 5. Concurrency — parallel duplicate nonce attempts ────────────────────────

describe('REP-05 Concurrent replay attempts', () => {

  test('parallel use of same artifact: exactly one ALLOW, rest REPLAY_DETECTED', async () => {
    const store    = makeNonceStore();
    const anomaly  = makeOpenAnomalyStore();
    const artifact = buildArtifact();

    // Fire 10 requests with the same artifact concurrently
    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        validateBoundRequest(artifact, BASE_REQ, { _store: store, _anomalyStore: anomaly })
      )
    );

    const allowed = results.filter(r => r.allowed);
    const blocked = results.filter(r => !r.allowed);

    // In an in-memory store (synchronous), all requests race — exactly one wins
    expect(allowed.length).toBe(1);
    expect(blocked.length).toBe(9);
    expect(blocked.every(r => r.reason === 'REPLAY_DETECTED')).toBe(true);
  });

  test('100 unique artifacts in parallel: all allowed', async () => {
    const store   = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();
    const arts    = Array.from({ length: 100 }, () => buildArtifact());

    const results = await Promise.all(
      arts.map(a => validateBoundRequest(a, BASE_REQ, { _store: store, _anomalyStore: anomaly }))
    );

    expect(results.every(r => r.allowed)).toBe(true);
  });
});

// ── 6. Expired artifact replay ────────────────────────────────────────────────

describe('REP-06 Expired artifacts cannot be replayed', () => {

  test('artifact with expiry in the past → EXPIRED, not REPLAY', async () => {
    const store    = makeNonceStore();
    const now      = Date.now();
    const envelope = {
      payload:     { provider: 'openai' },
      timestamp:   now - 600_000,
      expiry:      now - 1,        // already expired
      publicKeyId: KEY.keyId,
    };
    const expired = signBoundArtifact(BASE_REQ, envelope, KEY.privDer);
    const result  = await validate(expired, store);
    expect(result.allowed).toBe(false);
    // Expired artifacts should be rejected with an expiry reason, not replay
    expect(result.reason).not.toBe('REPLAY_DETECTED');
    expect(result.reason).toMatch(/EXPIR/);
  });
});
