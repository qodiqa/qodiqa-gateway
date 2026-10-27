'use strict';

/**
 * Concurrency Tests
 *
 * Validates that the enforcement pipeline is correct under parallel load:
 *   - 100 simultaneous valid requests all succeed independently
 *   - 100 simultaneous requests using the SAME artifact: exactly one ALLOW
 *   - Anomaly counters are consistent under parallel increments
 *   - Nonce store has no lost-update vulnerabilities under parallel writes
 *   - Policy evaluation is stateless and safe to call concurrently
 *
 * Race Condition Tests
 *   - Duplicate nonce under parallel requests (proven single-use)
 *   - Concurrent anomaly threshold enforcement
 */

jest.mock('../../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const { signBoundArtifact }    = require('../../src/validation/signBoundArtifact');
const { validateBoundRequest } = require('../../src/validation/validateBoundRequest');
const { getActiveKey, rotateKey } = require('../../services/artifact/keyStore');
const { makeNonceStore,
        makeOpenAnomalyStore,
        makeCountingAnomalyStore } = require('../../src/testing/stores');
const { validateAndPrepare }  = require('../../services/policy/loader');
const { createStore }         = require('../../services/policy/store');
const { evaluate }            = require('../../services/policy/engine');

// ── Fixtures ──────────────────────────────────────────────────────────────────

let KEY;
beforeAll(() => {
  try   { KEY = getActiveKey('default'); }
  catch { rotateKey('default'); KEY = getActiveKey('default'); }
});

const BASE_REQ = { method: 'POST', path: '/ai/chat', body: { prompt: 'concurrent test', model: 'gpt-4' } };

function buildArtifact() {
  const now = Date.now();
  return signBoundArtifact(BASE_REQ, {
    payload:     { provider: 'openai' },
    timestamp:   now,
    expiry:      now + 300_000,
    publicKeyId: KEY.keyId,
  }, KEY.privDer);
}

// ── 1. 100 Parallel valid requests ────────────────────────────────────────────

describe('100 parallel unique requests — all succeed', () => {

  test('100 unique artifacts validated simultaneously', async () => {
    const store   = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();

    const artifacts = Array.from({ length: 100 }, () => buildArtifact());
    const results   = await Promise.all(
      artifacts.map(a => validateBoundRequest(a, BASE_REQ, { _store: store, _anomalyStore: anomaly }))
    );

    const allowed = results.filter(r => r.allowed).length;
    expect(allowed).toBe(100);
  }, 15_000);

  test('all 100 parallel requests return a valid requestId', async () => {
    const store   = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();

    const artifacts = Array.from({ length: 100 }, () => buildArtifact());
    const results   = await Promise.all(
      artifacts.map(a => validateBoundRequest(a, BASE_REQ, { _store: store, _anomalyStore: anomaly }))
    );

    for (const r of results) {
      expect(r.allowed).toBe(true);
      expect(typeof r.requestId).toBe('string');
      expect(r.requestId.length).toBeGreaterThan(0);
    }
  }, 15_000);
});

// ── 2. Duplicate nonce race — exactly one winner ──────────────────────────────

describe('Duplicate nonce race — single-use invariant under concurrency', () => {

  test('same artifact used by 50 parallel requests: exactly one ALLOW', async () => {
    const store    = makeNonceStore();
    const anomaly  = makeOpenAnomalyStore();
    const artifact = buildArtifact();

    const results = await Promise.all(
      Array.from({ length: 50 }, () =>
        validateBoundRequest(artifact, BASE_REQ, { _store: store, _anomalyStore: anomaly })
      )
    );

    const allowed  = results.filter(r => r.allowed);
    const replayed = results.filter(r => !r.allowed && r.reason === 'REPLAY_DETECTED');

    expect(allowed.length).toBe(1);
    expect(replayed.length).toBe(49);
  }, 15_000);

  test('same artifact in 10 parallel bursts of 10: exactly one ALLOW total', async () => {
    const store    = makeNonceStore();
    const anomaly  = makeOpenAnomalyStore();
    const artifact = buildArtifact();

    // 10 bursts, each burst has 10 parallel attempts
    const allResults = [];
    for (let burst = 0; burst < 10; burst++) {
      const batch = await Promise.all(
        Array.from({ length: 10 }, () =>
          validateBoundRequest(artifact, BASE_REQ, { _store: store, _anomalyStore: anomaly })
        )
      );
      allResults.push(...batch);
    }

    const allowed = allResults.filter(r => r.allowed);
    expect(allowed.length).toBe(1);
  }, 15_000);
});

// ── 3. Policy engine concurrency ──────────────────────────────────────────────

describe('Policy engine concurrency — no shared state corruption', () => {
  const POLICIES = validateAndPrepare({ policies: [{
    id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
    config: { requireValidArtifact: true },
  }] });

  test('50 parallel policy evaluations all return EXECUTE', async () => {
    const context = {
      artifact:  { valid: true },
      userId:    'user-test',
      action:    'openai.chat.completions',
      ip:        '127.0.0.1',
      timestamp: Math.floor(Date.now() / 1000),
    };

    const results = await Promise.all(
      Array.from({ length: 50 }, () => evaluate(context, POLICIES, createStore()))
    );

    expect(results.every(r => r.decision === 'EXECUTE')).toBe(true);
  }, 10_000);

  test('policy evaluations with different contexts are independent', async () => {
    const makeCtx = (userId) => ({
      artifact:  { valid: true },
      userId,
      action:    'openai.chat.completions',
      ip:        '127.0.0.1',
      timestamp: Math.floor(Date.now() / 1000),
    });

    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        evaluate(makeCtx(`user-${i}`), POLICIES, createStore())
      )
    );

    expect(results.every(r => r.decision === 'EXECUTE')).toBe(true);
  }, 10_000);
});

// ── 4. Anomaly counter consistency ────────────────────────────────────────────

describe('Anomaly counter consistency under parallel load', () => {

  test('50 parallel requests with tight threshold: all exceeding threshold are blocked', async () => {
    const PER_KEY_MAX = 5;
    const store   = makeNonceStore();
    const anomaly = makeCountingAnomalyStore();

    const artifacts = Array.from({ length: 50 }, () => buildArtifact());
    const results   = await Promise.all(
      artifacts.map(a => validateBoundRequest(a, BASE_REQ, {
        _store:        store,
        _anomalyStore: anomaly,
        _thresholds:   { WINDOW_MS: 60_000, PER_KEY_MAX, GLOBAL_MAX: 1_000_000 },
      }))
    );

    const allowed  = results.filter(r => r.allowed).length;
    const blocked  = results.filter(r => !r.allowed).length;

    // Exactly PER_KEY_MAX requests should be allowed (anomaly counter caps at threshold)
    expect(allowed).toBe(PER_KEY_MAX);
    expect(blocked).toBe(50 - PER_KEY_MAX);
  }, 15_000);
});

// ── 5. 500 parallel requests (stress) ────────────────────────────────────────

describe('500 parallel requests (stress test)', () => {

  test('500 unique artifacts: all allowed, no errors thrown', async () => {
    const store   = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();

    const artifacts = Array.from({ length: 500 }, () => buildArtifact());
    let results;
    try {
      results = await Promise.all(
        artifacts.map(a => validateBoundRequest(a, BASE_REQ, { _store: store, _anomalyStore: anomaly }))
      );
    } catch (err) {
      throw new Error(`Pipeline threw under 500 parallel requests: ${err.message}`);
    }

    const allowed = results.filter(r => r.allowed).length;
    expect(allowed).toBe(500);
  }, 30_000);
});
