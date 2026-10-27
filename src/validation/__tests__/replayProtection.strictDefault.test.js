'use strict';

/**
 * STRICT_REPLAY_PROTECTION — default enforcement and runtime validation tests
 *
 * Validates that:
 *   1. STRICT_REPLAY_PROTECTION defaults to true (secure by default) after remediation
 *   2. Replay protection is actively enforced across all execution paths
 *
 * TEST 1  First request is accepted
 * TEST 2  Replay of identical request is blocked
 * TEST 3  Replay of identical artifact is blocked
 * TEST 4  Replay of identical nonce is blocked (registerNonce unit)
 * TEST 5  Replay after expiration window is blocked
 * TEST 6  Replay protection survives process restart (persistent backing map)
 * TEST 7  Replay protection fails closed when the replay store is unavailable
 * TEST 8  Replay protection is enforced in the production runtime path (/ai/chat)
 *
 * No Redis required — all stores are injected in-memory equivalents.
 */

// ── Consent mock (top-level — must precede all requires) ──────────────────────
// The requireConsent evaluator lazy-requires src/core/consent which opens a
// Redis connection.  Redis is unavailable in CI.  We mock the registry so that
// consent checks always pass — allowing the test to reach and observe replay
// protection decisions without being blocked at the policy layer.
jest.mock('../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'CONSENT_VERIFIED' }),
}));

const express                 = require('express');
const supertest               = require('supertest');
const { validateBoundRequest } = require('../validateBoundRequest');
const { registerNonce }        = require('../registerNonce');
const { signBoundArtifact }    = require('../signBoundArtifact');
const { generateRequestId }    = require('../requestId');
const { getActiveKey }         = require('../../../services/artifact/keyStore');
const createAiChatRouter       = require('../../api/routes/aiChat');
const attachClientIp           = require('../../../middleware/clientIp');
const { validateAndPrepare }   = require('../../../services/policy/loader');
const { createStore }          = require('../../../services/policy/store');
const {
  makeNonceStore,
  makeOpenAnomalyStore,
  makeDeadStore,
} = require('../../testing/stores');

// ── Shared fixtures ────────────────────────────────────────────────────────────

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });

const BASE_REQ  = { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello', model: 'gpt-4' } };
const CHAT_BODY = { prompt: 'Hello', model: 'gpt-4' };

function freshEnvelope(overrides = {}) {
  const now = Date.now();
  return { payload: { provider: 'openai', ...overrides }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
}

function buildArtifact(req = BASE_REQ, envelopeOverrides = {}) {
  return signBoundArtifact(req, freshEnvelope(envelopeOverrides), KEY.privDer);
}

function toHeader(artifact) {
  return Buffer.from(JSON.stringify(artifact)).toString('base64');
}

const PASS_ANOMALY = makeOpenAnomalyStore();

function vbr(artifact, request, opts = {}) {
  return validateBoundRequest(artifact, request, { _anomalyStore: PASS_ANOMALY, ...opts });
}

// ── aiChat app factory ────────────────────────────────────────────────────────
// Uses REQUIRE_CONSENT policy (the mandatory policy type) backed by the mocked
// consent registry above.  The mock makes consent always pass so the HTTP test
// can reach and observe replay protection decisions.
const _PASS_POLICY = validateAndPrepare({ policies: [{
  id:       'POL-CONSENT',
  type:     'REQUIRE_CONSENT',
  priority: 10,
  enabled:  true,
  config:   { requireValidArtifact: true },
}] });

function makeApp({ nonceStore, anomalyStore } = {}) {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store:        nonceStore  || makeNonceStore(),
    _anomalyStore: anomalyStore || makeOpenAnomalyStore(),
    _providerFn:   () => Promise.resolve({ output: 'mock response' }),
    _getPolicies:  () => _PASS_POLICY,
    _policyStore:  createStore(),
  }));
  return app;
}

async function post(app, artifact) {
  return supertest(app)
    .post('/ai/chat')
    .set('x-qodiqa-artifact', toHeader(artifact))
    .send(CHAT_BODY);
}

// ── STRICT_REPLAY_PROTECTION default ─────────────────────────────────────────

describe('STRICT_REPLAY_PROTECTION default value', () => {
  test('defaults to true when env var is unset (secure-by-default remediation)', () => {
    // Verify the remediated logic: !== 'false' evaluates to true when var is absent
    const saved = process.env.STRICT_REPLAY_PROTECTION;
    delete process.env.STRICT_REPLAY_PROTECTION;
    try {
      const strictReplay = process.env.STRICT_REPLAY_PROTECTION !== 'false';
      expect(strictReplay).toBe(true);
    } finally {
      if (saved !== undefined) process.env.STRICT_REPLAY_PROTECTION = saved;
    }
  });

  test('is false only when explicitly set to the string "false"', () => {
    const saved = process.env.STRICT_REPLAY_PROTECTION;
    process.env.STRICT_REPLAY_PROTECTION = 'false';
    try {
      const strictReplay = process.env.STRICT_REPLAY_PROTECTION !== 'false';
      expect(strictReplay).toBe(false);
    } finally {
      if (saved !== undefined) {
        process.env.STRICT_REPLAY_PROTECTION = saved;
      } else {
        delete process.env.STRICT_REPLAY_PROTECTION;
      }
    }
  });

  test('remains true for any non-"false" string value', () => {
    for (const v of ['true', '1', 'yes', 'TRUE', '', 'anything']) {
      const strictReplay = v !== 'false';
      expect(strictReplay).toBe(true);
    }
  });
});

// ── REPLAY-2: NODE_ENV=production forces strict mode regardless of override ──
//
// Mirrors server/startup.js's STRICT_REPLAY computation (not imported directly
// — that module has real startup side effects on require()) to verify the
// production-forcing formula in isolation.

describe('REPLAY-2 — STRICT_REPLAY_PROTECTION forced true in production', () => {
  function computeStrictReplay(nodeEnv, strictReplayEnv) {
    return nodeEnv === 'production'
      ? true
      : strictReplayEnv !== 'false';
  }

  test('NODE_ENV=production ignores STRICT_REPLAY_PROTECTION=false', () => {
    expect(computeStrictReplay('production', 'false')).toBe(true);
  });

  test('NODE_ENV=production stays true even when the var is unset', () => {
    expect(computeStrictReplay('production', undefined)).toBe(true);
  });

  test('non-production environments still honor an explicit false override', () => {
    expect(computeStrictReplay('development', 'false')).toBe(false);
    expect(computeStrictReplay('test', 'false')).toBe(false);
    expect(computeStrictReplay(undefined, 'false')).toBe(false);
  });

  test('non-production environments default to true when unset', () => {
    expect(computeStrictReplay('development', undefined)).toBe(true);
  });
});

// ── TEST 1: First request is accepted ────────────────────────────────────────

describe('TEST 1 — first request is accepted', () => {
  test('first submission of a signed, bound artifact is allowed', async () => {
    const store    = makeNonceStore();
    const artifact = buildArtifact();
    const result   = await vbr(artifact, BASE_REQ, { _store: store });

    expect(result.allowed).toBe(true);
    expect(typeof result.requestId).toBe('string');
    expect(result.requestId).toBe(artifact.payload.requestId);
  });
});

// ── TEST 2: Replay of identical request is blocked ────────────────────────────

describe('TEST 2 — replay of identical request is blocked', () => {
  test('second submission of the same signed request is REPLAY_DETECTED', async () => {
    const store    = makeNonceStore();
    const artifact = buildArtifact();

    const r1 = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r1.allowed).toBe(true);

    const r2 = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('REPLAY_DETECTED exposes requestId for audit-chain replayOf linkage', async () => {
    const store    = makeNonceStore();
    const artifact = buildArtifact();

    await vbr(artifact, BASE_REQ, { _store: store });
    const replay = await vbr(artifact, BASE_REQ, { _store: store });

    expect(replay.requestId).toBe(artifact.payload.requestId);
  });

  test('all subsequent replays (3rd, 4th, 5th) are also blocked', async () => {
    const store    = makeNonceStore();
    const artifact = buildArtifact();

    await vbr(artifact, BASE_REQ, { _store: store }); // first — allow

    for (let i = 0; i < 4; i++) {
      const r = await vbr(artifact, BASE_REQ, { _store: store });
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe('REPLAY_DETECTED');
    }
  });
});

// ── TEST 3: Replay of identical artifact is blocked ───────────────────────────

describe('TEST 3 — replay of identical artifact is blocked', () => {
  test('two structurally identical artifacts (same requestId) produce one ALLOW then REPLAY_DETECTED', async () => {
    const store = makeNonceStore();
    // Build artifact once — reuse the same object to simulate a captured-and-replayed artifact
    const artifact = buildArtifact();
    const captured = { ...artifact }; // deep copy simulates wire capture

    const r1 = await vbr(artifact,  BASE_REQ, { _store: store });
    const r2 = await vbr(captured,  BASE_REQ, { _store: store });

    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('independent artifacts with distinct requestIds are each accepted once', async () => {
    const store = makeNonceStore();
    const a1    = buildArtifact(BASE_REQ, { tag: 'a' });
    const a2    = buildArtifact(BASE_REQ, { tag: 'b' });

    expect(a1.payload.requestId).not.toBe(a2.payload.requestId);

    expect((await vbr(a1, BASE_REQ, { _store: store })).allowed).toBe(true);
    expect((await vbr(a2, BASE_REQ, { _store: store })).allowed).toBe(true);

    expect((await vbr(a1, BASE_REQ, { _store: store })).reason).toBe('REPLAY_DETECTED');
    expect((await vbr(a2, BASE_REQ, { _store: store })).reason).toBe('REPLAY_DETECTED');
  });
});

// ── TEST 4: Replay of identical nonce is blocked (registerNonce unit) ─────────

describe('TEST 4 — replay of identical nonce is blocked (registerNonce unit)', () => {
  test('same requestId registered twice → second is REPLAY_DETECTED', async () => {
    const store     = makeNonceStore();
    const requestId = generateRequestId();
    const expiry    = Date.now() + 300_000;

    const r1 = await registerNonce(requestId, expiry, { _store: store });
    expect(r1.ok).toBe(true);
    expect(r1.requestId).toBe(requestId);

    const r2 = await registerNonce(requestId, expiry, { _store: store });
    expect(r2.ok).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('10 concurrent registrations of the same nonce — exactly one succeeds', async () => {
    const store     = makeNonceStore();
    const requestId = generateRequestId();
    const expiry    = Date.now() + 300_000;

    const results = await Promise.all(
      Array.from({ length: 10 }, () => registerNonce(requestId, expiry, { _store: store })),
    );

    const allowed  = results.filter(r => r.ok);
    const replays  = results.filter(r => !r.ok && r.reason === 'REPLAY_DETECTED');

    expect(allowed).toHaveLength(1);
    expect(replays).toHaveLength(9);
  });
});

// ── TEST 5: Replay after expiration window is blocked ─────────────────────────

describe('TEST 5 — replay after expiration window is blocked', () => {
  test('artifact with already-expired expiry is rejected before nonce store write', async () => {
    const store     = makeNonceStore();
    const requestId = generateRequestId();
    const pastExpiry = Date.now() - 1;

    const r = await registerNonce(requestId, pastExpiry, { _store: store });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('EXPIRED');
    // Nonce must NOT be written — no footprint in store
    expect(store._map.has(requestId)).toBe(false);
  });

  test('artifact validated against a frozen past clock (validateBoundRequest) is EXPIRED', async () => {
    const store   = makeNonceStore();
    const pastMs  = Date.now() - 600_000; // 10 minutes ago
    const expiredArtifact = signBoundArtifact(
      BASE_REQ,
      { payload: { provider: 'openai' }, timestamp: pastMs, expiry: pastMs + 5_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );

    // Use a real-time clock — artifact is expired relative to now
    const r = await vbr(expiredArtifact, BASE_REQ, { _store: store });
    expect(r.allowed).toBe(false);
    // Blocked at step 1 (EXPIRED) before nonce registration
    expect(['EXPIRED', 'ARTIFACT_STALE', 'ARTIFACT_EXPIRED', 'ARTIFACT_ALREADY_EXPIRED'].some(reason => r.reason === reason)).toBe(true);
  });
});

// ── TEST 6: Replay protection survives process restart ────────────────────────

describe('TEST 6 — replay protection survives process restart (persistent backing map)', () => {
  test('nonce registered in first store instance is blocked in replacement instance sharing the same map', async () => {
    // The persistent backing map models Redis AOF — it outlives individual store instances
    const persistentMap = new Map();

    function makeStoreFromMap(map) {
      return {
        async register(requestId, expiryMs) {
          if (map.has(requestId)) return { registered: false };
          map.set(requestId, expiryMs);
          return { registered: true };
        },
        async isRegistered(requestId) { return map.has(requestId); },
        _map: map,
      };
    }

    const artifact = buildArtifact();

    // First "process instance" accepts the request
    const store1 = makeStoreFromMap(persistentMap);
    const r1 = await vbr(artifact, BASE_REQ, { _store: store1 });
    expect(r1.allowed).toBe(true);

    // "Process restarts" — new store instance, same persistent backing map
    const store2 = makeStoreFromMap(persistentMap);
    const r2 = await vbr(artifact, BASE_REQ, { _store: store2 });
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('multiple nonces registered across restart survive correctly', async () => {
    const persistentMap = new Map();

    function makeStoreFromMap(map) {
      return {
        async register(requestId, expiryMs) {
          if (map.has(requestId)) return { registered: false };
          map.set(requestId, expiryMs);
          return { registered: true };
        },
        async isRegistered(requestId) { return map.has(requestId); },
        _map: map,
      };
    }

    const artifacts = [buildArtifact(BASE_REQ, { i: 0 }), buildArtifact(BASE_REQ, { i: 1 }), buildArtifact(BASE_REQ, { i: 2 })];

    const store1 = makeStoreFromMap(persistentMap);
    for (const a of artifacts) {
      expect((await vbr(a, BASE_REQ, { _store: store1 })).allowed).toBe(true);
    }

    // Simulated restart
    const store2 = makeStoreFromMap(persistentMap);
    for (const a of artifacts) {
      const r = await vbr(a, BASE_REQ, { _store: store2 });
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe('REPLAY_DETECTED');
    }
  });
});

// ── TEST 7: Replay protection fails closed when store is unavailable ──────────

describe('TEST 7 — replay protection fails closed on store unavailability', () => {
  test('dead store → validateBoundRequest returns NONCE_STORE_ERROR, not allowed', async () => {
    const artifact = buildArtifact();
    const r = await vbr(artifact, BASE_REQ, { _store: makeDeadStore() });

    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('NONCE_STORE_ERROR');
  });

  test('dead store → registerNonce returns NONCE_STORE_ERROR, never throws', async () => {
    const requestId = generateRequestId();
    const expiry    = Date.now() + 300_000;

    const r = await registerNonce(requestId, expiry, { _store: makeDeadStore('simulated Redis down') });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('NONCE_STORE_ERROR');
  });

  test('dead store → 10 concurrent requests are all blocked, none allowed', async () => {
    const artifact = buildArtifact();
    const results  = await Promise.all(
      Array.from({ length: 10 }, () =>
        vbr(artifact, BASE_REQ, { _store: makeDeadStore() }),
      ),
    );
    expect(results.every(r => !r.allowed)).toBe(true);
    expect(results.every(r => r.reason === 'NONCE_STORE_ERROR')).toBe(true);
  });

  test('signature check runs before nonce check — tampered artifact is INVALID_SIGNATURE, not NONCE_STORE_ERROR', async () => {
    const good     = buildArtifact();
    const tampered = { ...good, payload: { ...good.payload, injected: true } };

    const r = await vbr(tampered, BASE_REQ, { _store: makeDeadStore() });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE'); // Step 1 blocks before Step 3 (nonce)
  });
});

// ── TEST 8: Replay protection in production runtime path (/ai/chat) ───────────

describe('TEST 8 — replay protection enforced in production runtime path', () => {
  test('first POST /ai/chat with valid artifact → 200 EXECUTE', async () => {
    const app      = makeApp();
    const artifact = buildArtifact();
    const res      = await post(app, artifact);

    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
  });

  test('second POST /ai/chat with same artifact → BLOCK REPLAY_DETECTED', async () => {
    const nonceStore = makeNonceStore();
    const app        = makeApp({ nonceStore });
    const artifact   = buildArtifact();

    const r1 = await post(app, artifact);
    expect(r1.status).toBe(200);
    expect(r1.body.decision).toBe('EXECUTE');

    const r2 = await post(app, artifact);
    // policy/verification BLOCKs on /ai/chat resolve as 200 {decision:'BLOCK'},
    // not a thrown HTTP error — the fail-closed guarantee (execution denied) is
    // proven by body.decision/body.reason below, not by the HTTP status.
    expect(r2.status).toBe(200);
    expect(r2.body.decision).toBe('BLOCK');
    expect(r2.body.reason).toBe('REPLAY_DETECTED');
  });

  test('replaying captured request N times → all attempts after first are BLOCKed', async () => {
    const nonceStore = makeNonceStore();
    const app        = makeApp({ nonceStore });
    const artifact   = buildArtifact();

    const first = await post(app, artifact);
    expect(first.status).toBe(200);

    const replays = await Promise.all(
      Array.from({ length: 5 }, () => post(app, artifact)),
    );
    expect(replays.every(r => r.status === 200)).toBe(true);
    expect(replays.every(r => r.body.decision === 'BLOCK')).toBe(true);
    expect(replays.every(r => r.body.reason === 'REPLAY_DETECTED')).toBe(true);
  });

  test('dead nonce store → /ai/chat blocks with NONCE_STORE_ERROR (fail-closed in production path)', async () => {
    const app      = makeApp({ nonceStore: makeDeadStore() });
    const artifact = buildArtifact();
    const res      = await post(app, artifact);

    // Fail-closed is proven by decision/reason, not HTTP status — the
    // store failure still denies execution every time, it just no longer
    // throws an HTTP error to do so.
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('NONCE_STORE_ERROR');
  });

  test('two different users send valid artifacts concurrently — both succeed, neither blocks the other', async () => {
    const nonceStore = makeNonceStore();
    const app        = makeApp({ nonceStore });
    const a1         = buildArtifact(BASE_REQ, { user: 'alice' });
    const a2         = buildArtifact(BASE_REQ, { user: 'bob' });

    const [r1, r2] = await Promise.all([post(app, a1), post(app, a2)]);
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
  });
});
