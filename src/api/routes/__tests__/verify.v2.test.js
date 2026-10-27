'use strict';

// Mock consent registry — /verify/v2 tests exercise verification and policy
// engine correctness; the consent evaluator is tested in src/core/consent/.
jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * POST /verify/v2 — test suite
 *
 * Validates the V2 verification endpoint against its three guarantees:
 *
 *   1. Decision parity    — /verify/v2 returns ALLOW iff validateBoundRequest
 *                           would allow the same artifact at the same instant.
 *
 *   2. No side effects    — calling /verify/v2 never writes to the nonce store
 *                           or increments anomaly counters.
 *
 *   3. Fail-closed        — any store unavailability returns BLOCK, never ALLOW.
 *
 * Every test injects stores via the createVerifyRouter factory so that no
 * Redis connection is attempted.
 *
 * Test categories:
 *   V2-01 … V2-06  Input validation
 *   V2-07 … V2-12  Decision correctness (matches runtime)
 *   V2-13 … V2-17  No side effects
 *   V2-18 … V2-22  Fail-closed (store failures)
 *   V2-23 … V2-30  Consistency (verify === runtime for same input)
 */

const request         = require('supertest');
const express         = require('express');
const createVerifyRouter       = require('../verify');
const { validateBoundRequest } = require('../../../validation/validateBoundRequest');
const { signBoundArtifact }    = require('../../../validation/signBoundArtifact');
const { signArtifact }         = require('../../../validation/signArtifact');
const { computeRequestHash }   = require('../../../validation/requestHash');
const { isValidRequestId }     = require('../../../validation/requestId');
const { buildNonceKey }        = require('../../../validation/nonceStore');
const { getActiveKey }         = require('../../../../services/artifact/keyStore');
const { validateAndPrepare }   = require('../../../../services/policy/loader');
const { createStore }          = require('../../../../services/policy/store');
const { makeDeadStore }        = require('../../../testing/stores');

// ── Store factories ───────────────────────────────────────────────────────────

/**
 * Backing nonce map — shared between runtime and dry-run stores so both see
 * the same registration state.  In production this is Redis.
 */
function makeBackingMap() { return new Map(); }

/**
 * Runtime nonce store: register() writes to the backing map.
 */
function makeRuntimeNonceStore(backingMap) {
  return {
    async register(requestId, expiryMs, tenantId) {
      const key = buildNonceKey(requestId, tenantId);
      if (backingMap.has(key)) return { registered: false };
      backingMap.set(key, expiryMs);
      return { registered: true };
    },
    async isRegistered(requestId, tenantId) {
      return backingMap.has(buildNonceKey(requestId, tenantId));
    },
    _map: backingMap,
  };
}

/**
 * Dry-run nonce store: isRegistered() reads the backing map, register() never writes.
 * Injected as _dryRunNonceStore in the verify router factory — the factory wraps it
 * in makeDryRunNonceStore() which calls .isRegistered().
 */
function makeDryRunNonceBackend(backingMap) {
  return {
    async isRegistered(requestId, tenantId) {
      return backingMap.has(buildNonceKey(requestId, tenantId));
    },
  };
}

/**
 * Backing anomaly windows — shared between runtime and dry-run stores.
 */
function makeAnomalyBackend() {
  const windows = new Map();
  return {
    // Used by runtime validateBoundRequest via checkAnomaly
    async record(key, nowMs, windowMs) {
      const existing = windows.get(key) || [];
      const fresh    = existing.filter(t => t > nowMs - windowMs);
      fresh.push(nowMs);
      windows.set(key, fresh);
      return { count: fresh.length };
    },
    // Used by dry-run store via makeDryRunAnomalyStore → peek
    async peek(key, nowMs, windowMs) {
      const existing = windows.get(key) || [];
      const fresh    = existing.filter(t => t > nowMs - windowMs);
      return { count: fresh.length };
    },
    _windows: windows,
  };
}

// makeOpenAnomalyBackend — delegates to shared makeOpenAnomalyStore from src/testing/stores.js.
const { makeOpenAnomalyStore } = require('../../../testing/stores');
const makeOpenAnomalyBackend   = makeOpenAnomalyStore;

// makeDeadBackend — delegates to shared makeDeadStore from src/testing/stores.js.
// Local alias preserves all existing call sites without renaming.
const makeDeadBackend = makeDeadStore;

// ── Fixture helpers ───────────────────────────────────────────────────────────

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });

const BASE_REQ = { method: 'POST', path: '/api/run', body: { userId: 'alice', action: 'read' } };

const OPEN_THRESH = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1_000_000, GLOBAL_MAX: 1_000_000 });

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
}

function buildBound(req = BASE_REQ, extraPayload = {}) {
  return signBoundArtifact(req, freshEnvelope({ provider: 'openai', ...extraPayload }), KEY.privDer);
}

// Default permissive policy set — passes for all valid artifacts.
// REQUIRE_CONSENT passes when artifact.valid === true, which checkPolicy
// always sets after validateBoundRequest succeeds.
const _DEFAULT_POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });
const _DEFAULT_POLICY_STORE = createStore();

/**
 * Build an Express app with /verify mounted using injected test stores.
 *
 * nonceBackend   — implements isRegistered() (used by dry-run nonce wrapper)
 * anomalyBackend — implements peek() (used by dry-run anomaly wrapper)
 * thresholds     — anomaly thresholds override
 * getPolicies    — policy getter; defaults to a permissive REQUIRE_CONSENT set
 * policyStore    — real policy store passed to dry-run wrapper; defaults to fresh store
 */
function makeApp(nonceBackend, anomalyBackend, thresholds = OPEN_THRESH, getPolicies, policyStore) {
  const app = express();
  app.use(express.json());
  app.use('/verify', createVerifyRouter({
    _dryRunNonceStore:   nonceBackend,
    _dryRunAnomalyStore: anomalyBackend,
    _thresholds:         thresholds,
    _getPolicies:        getPolicies  || (() => _DEFAULT_POLICIES),
    _policyStore:        policyStore  || _DEFAULT_POLICY_STORE,
  }));
  return app;
}

function post(app, body) {
  return request(app).post('/verify/v2').send(body);
}

// ── V2-01 … V2-06  Input validation ──────────────────────────────────────────

describe('POST /verify/v2 — input validation', () => {

  test('V2-01  missing body → 400', async () => {
    const app  = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const resp = await request(app).post('/verify/v2').set('Content-Type', 'application/json').send('{}');
    // {} is valid JSON but has neither artifact nor request → 400
    expect(resp.status).toBe(400);
    expect(resp.body.reason).toMatch(/MISSING/);
  });

  test('V2-02  artifact missing → 400 MISSING_ARTIFACT', async () => {
    const app  = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const resp = await post(app, { request: BASE_REQ });
    expect(resp.status).toBe(400);
    expect(resp.body.reason).toBe('MISSING_ARTIFACT');
  });

  test('V2-03  request missing → 400 MISSING_REQUEST', async () => {
    const app      = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const artifact = buildBound();
    const resp     = await post(app, { artifact });
    expect(resp.status).toBe(400);
    expect(resp.body.reason).toBe('MISSING_REQUEST');
  });

  test('V2-04  artifact is a string → 400 INVALID_ARTIFACT_TYPE', async () => {
    const app  = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const resp = await post(app, { artifact: 'base64string', request: BASE_REQ });
    expect(resp.status).toBe(400);
    expect(resp.body.reason).toBe('INVALID_ARTIFACT_TYPE');
  });

  test('V2-05  artifact is an array → 400 INVALID_ARTIFACT_TYPE', async () => {
    const app  = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const resp = await post(app, { artifact: [1, 2, 3], request: BASE_REQ });
    expect(resp.status).toBe(400);
    expect(resp.body.reason).toBe('INVALID_ARTIFACT_TYPE');
  });

  test('V2-06  request is a string → 400 INVALID_REQUEST_TYPE', async () => {
    const app      = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const artifact = buildBound();
    const resp     = await post(app, { artifact, request: 'POST /api/run' });
    expect(resp.status).toBe(400);
    expect(resp.body.reason).toBe('INVALID_REQUEST_TYPE');
  });

});

// ── V2-07 … V2-12  Decision correctness ──────────────────────────────────────

describe('POST /verify/v2 — decision correctness', () => {

  test('V2-07  valid artifact + valid request → 200 EXECUTE', async () => {
    const backing  = makeBackingMap();
    const app      = makeApp(makeDryRunNonceBackend(backing), makeOpenAnomalyBackend());
    const artifact = buildBound();
    const resp     = await post(app, { artifact, request: BASE_REQ });

    expect(resp.status).toBe(200);
    expect(resp.body.decision).toBe('EXECUTE');
    expect(resp.body.reason).toBe('ALL_CHECKS_PASSED');
    expect(isValidRequestId(resp.body.artifactId)).toBe(true);
    expect(resp.body.keyId).toBe(KEY.keyId);
  });

  test('V2-08  tampered payload (invalid signature) → BLOCK INVALID_SIGNATURE', async () => {
    const app      = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const artifact = buildBound();
    const tampered = { ...artifact, payload: { ...artifact.payload, extra: 'injected' } };
    const resp     = await post(app, { artifact: tampered, request: BASE_REQ });

    expect(resp.status).toBe(200);
    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('INVALID_SIGNATURE');
  });

  test('V2-09  expired artifact → BLOCK EXPIRED', async () => {
    const now      = Date.now();
    const artifact = signBoundArtifact(
      BASE_REQ,
      { payload: {}, timestamp: now - 5_000, expiry: now - 1, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const app  = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const resp = await post(app, { artifact, request: BASE_REQ });

    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('EXPIRED');
  });

  test('V2-10  request method mismatch → BLOCK REQUEST_MISMATCH', async () => {
    const app      = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const artifact = buildBound(BASE_REQ);
    const resp     = await post(app, { artifact, request: { ...BASE_REQ, method: 'GET' } });

    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('REQUEST_MISMATCH');
  });

  test('V2-11  request path mismatch → BLOCK REQUEST_MISMATCH', async () => {
    const app      = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const artifact = buildBound(BASE_REQ);
    const resp     = await post(app, { artifact, request: { ...BASE_REQ, path: '/api/other' } });

    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('REQUEST_MISMATCH');
  });

  test('V2-12  request body mismatch → BLOCK REQUEST_MISMATCH', async () => {
    const app      = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const artifact = buildBound(BASE_REQ);
    const resp     = await post(app, { artifact, request: { ...BASE_REQ, body: { userId: 'eve' } } });

    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('REQUEST_MISMATCH');
  });

});

// ── V2-13 … V2-17  No side effects ───────────────────────────────────────────

describe('POST /verify/v2 — no side effects', () => {

  test('V2-13  calling /verify/v2 does NOT register the nonce — requestId remains fresh', async () => {
    const backing  = makeBackingMap();
    const app      = makeApp(makeDryRunNonceBackend(backing), makeOpenAnomalyBackend());
    const artifact = buildBound();

    // Call /verify/v2 N times — never writes the nonce
    for (let i = 0; i < 5; i++) {
      const resp = await post(app, { artifact, request: BASE_REQ });
      expect(resp.body.decision).toBe('EXECUTE');
    }

    // Backing map must still be empty — nothing was written
    expect(backing.size).toBe(0);
  });

  test('V2-14  calling /verify/v2 does NOT affect anomaly counters', async () => {
    const anomalyBackend = makeAnomalyBackend();
    const app            = makeApp(makeDryRunNonceBackend(makeBackingMap()), anomalyBackend);

    // Send 20 verify requests
    for (let i = 0; i < 20; i++) {
      const a    = buildBound();
      const resp = await post(app, { artifact: a, request: BASE_REQ });
      expect(resp.body.decision).toBe('EXECUTE');
    }

    // Anomaly windows must remain empty (no events recorded)
    expect(anomalyBackend._windows.size).toBe(0);
  });

  test('V2-15  replay detection works without consuming the nonce', async () => {
    const backing  = makeBackingMap();
    const app      = makeApp(makeDryRunNonceBackend(backing), makeOpenAnomalyBackend());
    const artifact = buildBound();

    // Pre-register the nonce (as if runtime already executed it)
    // Key format per QODIQA-PROTOCOL-SPEC.md §27.11: <tenantId>:qodiqa:req:v2:<requestId>
    const tenantId = KEY.keyId.split(':')[0];
    backing.set(buildNonceKey(artifact.payload.requestId, tenantId), Date.now() + 300_000);

    // /verify/v2 correctly reports REPLAY_DETECTED
    const resp = await post(app, { artifact, request: BASE_REQ });
    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('REPLAY_DETECTED');

    // Backing map still has exactly the one entry we put there — /verify/v2 added nothing
    expect(backing.size).toBe(1);
  });

  test('V2-16  multiple verify calls for the same replay — each correctly blocks, none writes', async () => {
    const backing  = makeBackingMap();
    const app      = makeApp(makeDryRunNonceBackend(backing), makeOpenAnomalyBackend());
    const artifact = buildBound();

    // Mark as already used — key format per QODIQA-PROTOCOL-SPEC.md §27.11
    const tenantId = KEY.keyId.split(':')[0];
    backing.set(buildNonceKey(artifact.payload.requestId, tenantId), Date.now() + 300_000);
    const before = backing.size;

    for (let i = 0; i < 5; i++) {
      const resp = await post(app, { artifact, request: BASE_REQ });
      expect(resp.body.decision).toBe('BLOCK');
      expect(resp.body.reason).toBe('REPLAY_DETECTED');
    }

    // No new entries added
    expect(backing.size).toBe(before);
  });

  test('V2-17  verify of a request that would trigger anomaly — counter NOT incremented', async () => {
    const anomalyBackend = makeAnomalyBackend();
    const thresh         = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 2, GLOBAL_MAX: 1_000_000 });
    const app            = makeApp(makeDryRunNonceBackend(makeBackingMap()), anomalyBackend, thresh);
    const now            = Date.now();

    // Pre-fill the per-key window to the limit (key is tenant-scoped)
    const tenantId    = KEY.keyId.split(':')[0];
    const scopedKey   = `tenant:${tenantId}:key:${KEY.keyId}`;
    for (let i = 0; i < thresh.PER_KEY_MAX; i++) {
      await anomalyBackend.record(scopedKey, now, thresh.WINDOW_MS);
    }
    const countBefore = (anomalyBackend._windows.get(scopedKey) || []).length;

    // Verify returns BLOCK (would be over limit) but does NOT add to window
    const a    = buildBound();
    const resp = await post(app, { artifact: a, request: BASE_REQ });
    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('ANOMALY_DETECTED');

    const countAfter = (anomalyBackend._windows.get(scopedKey) || []).length;
    expect(countAfter).toBe(countBefore);
  });

});

// ── V2-18 … V2-22  Fail-closed ───────────────────────────────────────────────

describe('POST /verify/v2 — fail-closed (store failures)', () => {

  test('V2-18  nonce store unavailable → 200 BLOCK', async () => {
    const app      = makeApp(makeDeadBackend('NONCE_REDIS_DOWN'), makeOpenAnomalyBackend());
    const artifact = buildBound();
    const resp     = await post(app, { artifact, request: BASE_REQ });

    expect(resp.status).toBe(200);
    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).not.toBe('ALLOW');
    expect(resp.body.reason).not.toBeUndefined();
  });

  test('V2-19  anomaly store unavailable → 200 BLOCK', async () => {
    const app      = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeDeadBackend('ANOMALY_REDIS_DOWN'));
    const artifact = buildBound();
    const resp     = await post(app, { artifact, request: BASE_REQ });

    expect(resp.status).toBe(200);
    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('ANOMALY_DETECTED');
    expect(resp.body.details.type).toBe('STORE_ERROR');
  });

  test('V2-20  both stores unavailable → 200 BLOCK (nonce failure reported first)', async () => {
    const dead     = makeDeadBackend('TOTAL_OUTAGE');
    const app      = makeApp(dead, dead);
    const artifact = buildBound();
    const resp     = await post(app, { artifact, request: BASE_REQ });

    expect(resp.status).toBe(200);
    expect(resp.body.decision).toBe('BLOCK');
    // Nonce store is step 3 (before anomaly at step 4), so nonce error is reported
    expect(resp.body.reason).toBe('NONCE_STORE_ERROR');
  });

  test('V2-21  100 concurrent requests with dead nonce store — all BLOCK', async () => {
    const app     = makeApp(makeDeadBackend(), makeOpenAnomalyBackend());
    const results = await Promise.all(
      Array.from({ length: 100 }, () => {
        const a = buildBound();
        return post(app, { artifact: a, request: BASE_REQ });
      }),
    );

    // Rate limiting (429) and enforcement blocking (200 BLOCK) are both valid
    // fail-closed responses.  The invariant is that no request reaches EXECUTE.
    expect(results.every(r => r.status === 200 || r.status === 429)).toBe(true);
    expect(results.every(r => r.body.decision === 'BLOCK')).toBe(true);
    expect(results.every(r => r.body.decision !== 'EXECUTE')).toBe(true);
  });

  test('V2-22  fail-closed result never leaks requestId or publicKeyId', async () => {
    const app      = makeApp(makeDeadBackend(), makeDeadBackend());
    const artifact = buildBound();
    const resp     = await post(app, { artifact, request: BASE_REQ });

    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.details?.requestId).toBeUndefined();
    expect(resp.body.details?.publicKeyId).toBeUndefined();
  });

});

// ── V2-23 … V2-30  Consistency (verify === runtime) ─────────────────────────

describe('POST /verify/v2 — consistency with runtime', () => {

  // Helper: run the full runtime pipeline with the same stores
  function runRuntime(artifact, req, runtimeNonceStore, anomalyBackend, thresholds = OPEN_THRESH) {
    return validateBoundRequest(artifact, req, {
      _store:        runtimeNonceStore,
      _anomalyStore: anomalyBackend,
      _thresholds:   thresholds,
    });
  }

  test('V2-23  valid artifact: verify says ALLOW, runtime says ALLOW', async () => {
    const backing       = makeBackingMap();
    const anomalyBk     = makeAnomalyBackend();
    const runtimeNonce  = makeRuntimeNonceStore(backing);
    const verifyApp     = makeApp(makeDryRunNonceBackend(backing), anomalyBk);
    const artifact      = buildBound();

    const verifyResp    = await post(verifyApp, { artifact, request: BASE_REQ });
    const runtimeResult = await runRuntime(artifact, BASE_REQ, runtimeNonce, anomalyBk);

    expect(verifyResp.body.decision).toBe('EXECUTE');
    expect(runtimeResult.allowed).toBe(true);
  });

  test('V2-24  invalid signature: verify says BLOCK, runtime says BLOCK — same reason', async () => {
    const backing      = makeBackingMap();
    const anomalyBk    = makeAnomalyBackend();
    const runtimeNonce = makeRuntimeNonceStore(backing);
    const verifyApp    = makeApp(makeDryRunNonceBackend(backing), anomalyBk);

    const artifact = buildBound();
    const tampered = { ...artifact, payload: { ...artifact.payload, extra: 'evil' } };

    const verifyResp    = await post(verifyApp, { artifact: tampered, request: BASE_REQ });
    const runtimeResult = await runRuntime(tampered, BASE_REQ, runtimeNonce, anomalyBk);

    expect(verifyResp.body.decision).toBe('BLOCK');
    expect(runtimeResult.allowed).toBe(false);
    expect(verifyResp.body.reason).toBe(runtimeResult.reason);
  });

  test('V2-25  request mismatch: verify and runtime agree on BLOCK + reason', async () => {
    const backing      = makeBackingMap();
    const anomalyBk    = makeAnomalyBackend();
    const runtimeNonce = makeRuntimeNonceStore(backing);
    const verifyApp    = makeApp(makeDryRunNonceBackend(backing), anomalyBk);

    const artifact  = buildBound(BASE_REQ);
    const wrongReq  = { ...BASE_REQ, body: { userId: 'mallory' } };

    const verifyResp    = await post(verifyApp, { artifact, request: wrongReq });
    const runtimeResult = await runRuntime(artifact, wrongReq, runtimeNonce, anomalyBk);

    expect(verifyResp.body.decision).toBe('BLOCK');
    expect(runtimeResult.allowed).toBe(false);
    expect(verifyResp.body.reason).toBe(runtimeResult.reason);
  });

  test('V2-26  after runtime executes, verify correctly reports REPLAY_DETECTED', async () => {
    const backing      = makeBackingMap();
    const anomalyBk    = makeAnomalyBackend();
    const runtimeNonce = makeRuntimeNonceStore(backing);
    const verifyApp    = makeApp(makeDryRunNonceBackend(backing), anomalyBk);
    const artifact     = buildBound();

    // Runtime executes first — registers the nonce
    const runtimeResult = await runRuntime(artifact, BASE_REQ, runtimeNonce, anomalyBk);
    expect(runtimeResult.allowed).toBe(true);
    // Key format per QODIQA-PROTOCOL-SPEC.md §27.11: <tenantId>:qodiqa:req:v2:<requestId>
    const tenantId = KEY.keyId.split(':')[0];
    expect(backing.has(buildNonceKey(artifact.payload.requestId, tenantId))).toBe(true);

    // Verify now sees the nonce is taken → REPLAY_DETECTED
    const verifyResp = await post(verifyApp, { artifact, request: BASE_REQ });
    expect(verifyResp.body.decision).toBe('BLOCK');
    expect(verifyResp.body.reason).toBe('REPLAY_DETECTED');
  });

  test('V2-27  verify before runtime, then runtime: both ALLOW (verify does not burn nonce)', async () => {
    const backing      = makeBackingMap();
    const anomalyBk    = makeAnomalyBackend();
    const runtimeNonce = makeRuntimeNonceStore(backing);
    const verifyApp    = makeApp(makeDryRunNonceBackend(backing), anomalyBk);
    const artifact     = buildBound();

    // Verify first — should EXECUTE without writing nonce
    const verifyResp = await post(verifyApp, { artifact, request: BASE_REQ });
    expect(verifyResp.body.decision).toBe('EXECUTE');
    expect(backing.size).toBe(0);   // nonce not written

    // Runtime executes — also ALLOW (nonce still fresh)
    const runtimeResult = await runRuntime(artifact, BASE_REQ, runtimeNonce, anomalyBk);
    expect(runtimeResult.allowed).toBe(true);
    expect(backing.size).toBe(1);   // nonce now written

    // Verify again — REPLAY_DETECTED (runtime wrote it)
    const verifyResp2 = await post(verifyApp, { artifact, request: BASE_REQ });
    expect(verifyResp2.body.decision).toBe('BLOCK');
    expect(verifyResp2.body.reason).toBe('REPLAY_DETECTED');
  });

  test('V2-28  anomaly burst: verify and runtime agree on BLOCK + SIGNATURE_BURST', async () => {
    const thresh       = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 3, GLOBAL_MAX: 1_000_000 });
    const backing      = makeBackingMap();
    const anomalyBk    = makeAnomalyBackend();
    const runtimeNonce = makeRuntimeNonceStore(backing);
    const verifyApp    = makeApp(makeDryRunNonceBackend(backing), anomalyBk, thresh);
    const now          = Date.now();

    // Fill anomaly window via runtime (3 successful requests)
    for (let i = 0; i < thresh.PER_KEY_MAX; i++) {
      const a = buildBound();
      await runRuntime(a, BASE_REQ, runtimeNonce, anomalyBk, thresh);
    }

    // One more via runtime — blocked as SIGNATURE_BURST
    const overA         = buildBound();
    const runtimeResult = await runRuntime(overA, BASE_REQ, runtimeNonce, anomalyBk, thresh);
    expect(runtimeResult.allowed).toBe(false);
    expect(runtimeResult.reason).toBe('ANOMALY_DETECTED');

    // Verify (different artifact, same key) — same decision
    // Note: verify uses peek (doesn't increment), but window is already full
    const newA       = buildBound();
    const verifyResp = await post(verifyApp, { artifact: newA, request: BASE_REQ });
    expect(verifyResp.body.decision).toBe('BLOCK');
    expect(verifyResp.body.reason).toBe('ANOMALY_DETECTED');
  });

  test('V2-29  verify response is deterministic for same input at same window state', async () => {
    const backing  = makeBackingMap();
    const anomalyBk = makeAnomalyBackend();
    const verifyApp = makeApp(makeDryRunNonceBackend(backing), anomalyBk);
    const artifact  = buildBound();

    const responses = await Promise.all(
      Array.from({ length: 5 }, () => post(verifyApp, { artifact, request: BASE_REQ })),
    );

    // All 5 should give EXECUTE (nonce not in backing map, no anomaly)
    expect(responses.every(r => r.body.decision === 'EXECUTE')).toBe(true);
    expect(responses.every(r => r.body.reason   === 'ALL_CHECKS_PASSED')).toBe(true);
  });

  test('V2-29b  verify and runtime agree on EXECUTE when policies pass', async () => {
    // Proves that policy evaluation in /verify/v2 uses the same logic as runtime.
    const backing      = makeBackingMap();
    const anomalyBk    = makeAnomalyBackend();
    const runtimeNonce = makeRuntimeNonceStore(backing);
    const policies     = _DEFAULT_POLICIES;
    const polStore     = createStore();

    const verifyApp = makeApp(
      makeDryRunNonceBackend(backing), anomalyBk,
      OPEN_THRESH, () => policies, polStore,
    );

    const artifact = buildBound();

    const verifyResp    = await post(verifyApp, { artifact, request: BASE_REQ });
    const runtimeResult = await runRuntime(artifact, BASE_REQ, runtimeNonce, anomalyBk);

    expect(verifyResp.body.decision).toBe('EXECUTE');
    expect(runtimeResult.allowed).toBe(true);
  });

  test('V2-30  verify result is a plain JSON object with no extra fields when EXECUTE', async () => {
    const app      = makeApp(makeDryRunNonceBackend(makeBackingMap()), makeOpenAnomalyBackend());
    const artifact = buildBound();
    const resp     = await post(app, { artifact, request: BASE_REQ });

    expect(resp.status).toBe(200);
    expect(resp.body).toMatchObject({
      decision:   'EXECUTE',
      reason:     'ALL_CHECKS_PASSED',
      artifactId: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/),
      keyId:      expect.any(String),
    });

    // Only the expected top-level fields (tenantId added multi-tenancy;
    // callerId added by the remediation)
    const keys = Object.keys(resp.body);
    expect(keys).toEqual(expect.arrayContaining(['decision', 'reason', 'artifactId', 'keyId', 'callerId', 'requestId', 'tenantId']));
    expect(keys).toHaveLength(7);
  });

});

// ── V2-31 … V2-34  Policy parity — verify decisions match runtime ─────────────
//
// These tests prove that /verify/v2 step 5 (policy enforcement) uses the same
// shared checkPolicy module as /ai/chat, producing identical BLOCK reasons.

describe('POST /verify/v2 — policy parity with runtime', () => {

  test('V2-31  policy step runs: empty policy list → BLOCK NO_POLICIES_LOADED', async () => {
    // Passing () => [] proves policy evaluation is active in /verify/v2.
    // If the policy step were absent, a valid artifact would return EXECUTE.
    const app      = makeApp(
      makeDryRunNonceBackend(makeBackingMap()),
      makeOpenAnomalyBackend(),
      OPEN_THRESH,
      () => [],         // deliberately empty → BLOCK
      createStore(),
    );
    const artifact = buildBound();
    const resp     = await post(app, { artifact, request: BASE_REQ });

    expect(resp.status).toBe(200);
    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('NO_POLICIES_LOADED');
  });

  test('V2-32  BLOCK_IP policy: verify blocks same IP as runtime would', async () => {
    const blockIpPolicies = validateAndPrepare({ policies: [
      { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true } },
      { id: 'POL-BLOCK',   type: 'BLOCK_IP',        priority: 20, enabled: true,
        config: { blocklist: ['1.2.3.4'], cidrs: [] } },
    ] });

    const app = makeApp(
      makeDryRunNonceBackend(makeBackingMap()),
      makeOpenAnomalyBackend(),
      OPEN_THRESH,
      () => blockIpPolicies,
      createStore(),
    );

    const artifact = buildBound();

    // Inject clientIp via middleware before /verify
    const blockedApp = express();
    blockedApp.use(express.json());
    blockedApp.use((req, _res, next) => { req.clientIp = '1.2.3.4'; next(); });
    blockedApp.use('/verify', createVerifyRouter({
      _dryRunNonceStore:   makeDryRunNonceBackend(makeBackingMap()),
      _dryRunAnomalyStore: makeOpenAnomalyBackend(),
      _thresholds:         OPEN_THRESH,
      _getPolicies:        () => blockIpPolicies,
      _policyStore:        createStore(),
    }));

    const resp = await request(blockedApp).post('/verify/v2').send({ artifact, request: BASE_REQ });
    expect(resp.status).toBe(200);
    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('IP_BLOCKED');
  });

  test('V2-33  all policies disabled → BLOCK NO_ENABLED_POLICIES (same as runtime)', async () => {
    const disabledPolicies = [Object.freeze({
      id: 'POL-OFF', type: 'REQUIRE_CONSENT', priority: 10, enabled: false,
      config: Object.freeze({ requireValidArtifact: true }),
    })];
    const app      = makeApp(
      makeDryRunNonceBackend(makeBackingMap()),
      makeOpenAnomalyBackend(),
      OPEN_THRESH,
      () => disabledPolicies,
      createStore(),
    );
    const artifact = buildBound();
    const resp     = await post(app, { artifact, request: BASE_REQ });

    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('NO_ENABLED_POLICIES');
  });

  test('V2-34  dry-run policy store does not increment rate-limit counter', async () => {
    const polStore = createStore();

    // Pre-fill the rate-limit counter to exactly 1 below the limit
    const RATE_LIMIT_MAX = 3;
    const ratePolicies = validateAndPrepare({ policies: [
      { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
        config: { requireValidArtifact: true } },
      { id: 'POL-RATE', type: 'RATE_LIMIT', priority: 20, enabled: true,
        config: { keyBy: 'ip', windowSeconds: 60, maxRequests: RATE_LIMIT_MAX } },
    ] });

    const app = makeApp(
      makeDryRunNonceBackend(makeBackingMap()),
      makeOpenAnomalyBackend(),
      OPEN_THRESH,
      () => ratePolicies,
      polStore,
    );

    const countBefore = polStore.getCount('POL-RATE:null', 60);

    // Multiple verify calls — none should increment the counter
    for (let i = 0; i < 5; i++) {
      const a    = buildBound();
      const resp = await post(app, { artifact: a, request: BASE_REQ });
      // Should EXECUTE or BLOCK based on rate limit, but counter must not grow
      expect(resp.body.decision).toBeDefined();
    }

    const countAfter = polStore.getCount('POL-RATE:null', 60);
    // Counter must be unchanged — verify is read-only for rate limits
    expect(countAfter).toBe(countBefore);
  });

});
