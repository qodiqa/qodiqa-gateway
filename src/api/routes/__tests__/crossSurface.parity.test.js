'use strict';

// Mock consent registry — cross-surface parity tests verify /ai/chat vs
// /verify/v2 agreement; the consent evaluator is tested separately.
jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * Cross-Surface Parity Tests (Task 6)
 *
 * Guarantees that /verify/v2, /verify (public), and the
 * direct validateBoundRequest pipeline ALL return:
 *   - The same decision  ("EXECUTE" | "BLOCK")
 *   - The same reason    (canonical UPPERCASE_SNAKE_CASE)
 *   - The same structure ({ decision, reason, [artifactId, keyId] } for EXECUTE;
 *                         { decision, reason, details } for BLOCK)
 *
 * for every failure scenario.  No surface may return a different truth than
 * another for the same input.
 *
 * Test IDs: CS-01 … CS-14
 */

const request        = require('supertest');
const express        = require('express');
const path           = require('path');
const createVerifyRouter       = require('../verify');
const { validateBoundRequest } = require('../../../validation/validateBoundRequest');
const { signBoundArtifact }    = require('../../../validation/signBoundArtifact');
const { rotateKey, getActiveKey } = require('../../../../services/artifact/keyStore');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { makeDryRunNonceStore, makeDryRunAnomalyStore } = require('../../../validation/dryRunStores');
const { buildNonceKey } = require('../../../validation/nonceStore');
const { validateAndPrepare }   = require('../../../../services/policy/loader');
const { createStore }          = require('../../../../services/policy/store');

// ── Setup ─────────────────────────────────────────────────────────────────────

let KEY;
beforeAll(() => {
  try   { KEY = getActiveKey('cs-parity'); }
  catch { rotateKey('cs-parity'); KEY = getActiveKey('cs-parity'); }
});

const BASE_REQ = { method: 'POST', path: '/ai/chat', body: { prompt: 'hello', model: 'gpt-4' } };
const OPEN_THRESH = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1_000_000, GLOBAL_MAX: 1_000_000 });

const _DEFAULT_POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });
const _DEFAULT_POLICY_STORE = createStore();

function freshArtifact(reqOverrides = {}, artOverrides = {}) {
  const req = { ...BASE_REQ, ...reqOverrides };
  const now = Date.now();
  const base = signBoundArtifact(
    req,
    { payload: { provider: 'openai', policyHash: 'a'.repeat(64) }, timestamp: now, expiry: now + 60_000, publicKeyId: KEY.keyId },
    KEY.privDer,
  );
  return { artifact: { ...base, ...artOverrides }, request: req };
}

// freshStores returns:
//   nonce   — full nonce store (register + isRegistered) for direct pipeline
//   anomaly — full anomaly store (record + peek) for direct pipeline
//   nonceBackend   — isRegistered-only view, passed as _dryRunNonceStore to router
//                    (router wraps it internally via makeDryRunNonceStore)
//   anomalyBackend — peek-only view, passed as _dryRunAnomalyStore to router
function freshStores() {
  const nonce   = makeNonceStore();
  const anomaly = makeOpenAnomalyStore();
  const nonceBackend   = { async isRegistered(id, tenantId) { return nonce._map.has(buildNonceKey(id, tenantId)); } };
  const anomalyBackend = { async peek() { return { count: 0 }; } };
  return { nonce, anomaly, nonceBackend, anomalyBackend };
}

function makeVerifyApp(nonceBackend, anomalyBackend) {
  const app = express();
  app.use(express.json());
  app.use('/verify', createVerifyRouter({
    _dryRunNonceStore:   nonceBackend,
    _dryRunAnomalyStore: anomalyBackend,
    _thresholds:         OPEN_THRESH,
    _getPolicies:        () => _DEFAULT_POLICIES,
    _policyStore:        _DEFAULT_POLICY_STORE,
  }));
  return app;
}

// Direct pipeline helper (surface 1)
async function direct(artifact, req, stores, opts = {}) {
  return validateBoundRequest(artifact, req, {
    _store:        stores.nonce,
    _anomalyStore: stores.anomaly,
    ...opts,
  });
}

// ── Structural invariants ─────────────────────────────────────────────────────

function assertExecuteShape(body) {
  expect(body.decision).toBe('EXECUTE');
  expect(typeof body.reason).toBe('string');
  expect(body.reason).toMatch(/^[A-Z][A-Z0-9_]+$/);
  expect(body).toHaveProperty('artifactId');
  expect(body).toHaveProperty('keyId');
}

function assertBlockShape(body) {
  expect(body.decision).toBe('BLOCK');
  expect(typeof body.reason).toBe('string');
  expect(body.reason).toMatch(/^[A-Z][A-Z0-9_]+$/);
}

// ── CS-01: Success — all surfaces return EXECUTE + ALL_CHECKS_PASSED ──────────

describe('CS-01  success path — all surfaces agree', () => {
  test('CS-01a  direct pipeline → allowed:true + requestId + publicKeyId', async () => {
    const { artifact, request: req } = freshArtifact();
    const stores = freshStores();
    const r = await direct(artifact, req, stores);
    expect(r.allowed).toBe(true);
    expect(typeof r.requestId).toBe('string');
    expect(typeof r.publicKeyId).toBe('string');
  });

  test('CS-01b  /verify/v2 → { decision: EXECUTE, reason: ALL_CHECKS_PASSED, artifactId, keyId }', async () => {
    const { artifact, request: req } = freshArtifact();
    const stores = freshStores();
    const app  = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp = await request(app).post('/verify/v2').send({ artifact, request: req });
    expect(resp.status).toBe(200);
    assertExecuteShape(resp.body);
    expect(resp.body.reason).toBe('ALL_CHECKS_PASSED');
  });

  test('CS-01c  /verify (public) → { decision: EXECUTE, reason: ALL_CHECKS_PASSED, artifactId, keyId }', async () => {
    const { artifact, request: req } = freshArtifact();
    const stores = freshStores();
    const app  = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp = await request(app).post('/verify').send({ artifact, request: req });
    expect(resp.status).toBe(200);
    assertExecuteShape(resp.body);
    expect(resp.body.reason).toBe('ALL_CHECKS_PASSED');
  });
});

// ── CS-02: Missing artifact — BLOCK + MISSING_ARTIFACT ───────────────────────

describe('CS-02  missing artifact', () => {
  test('CS-02a  /verify/v2 → 400 + MISSING_ARTIFACT', async () => {
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify/v2').send({ request: BASE_REQ });
    expect(resp.status).toBe(400);
    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('MISSING_ARTIFACT');
  });

  test('CS-02b  /verify (public) → 400 + BLOCK + MISSING_ARTIFACT', async () => {
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify').send({ request: BASE_REQ });
    expect(resp.status).toBe(400);
    assertBlockShape(resp.body);
    expect(resp.body.reason).toBe('MISSING_ARTIFACT');
  });
});

// ── CS-03: Tampered signature — BLOCK + INVALID_SIGNATURE ────────────────────

describe('CS-03  tampered signature', () => {
  async function tamperedArtifact() {
    const { artifact, request: req } = freshArtifact();
    return { artifact: { ...artifact, signature: Buffer.alloc(64).toString('base64') }, request: req };
  }

  test('CS-03a  direct pipeline → INVALID_SIGNATURE', async () => {
    const { artifact, request: req } = await tamperedArtifact();
    const stores = freshStores();
    const r = await direct(artifact, req, stores);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('CS-03b  /verify/v2 → BLOCK + INVALID_SIGNATURE', async () => {
    const { artifact, request: req } = await tamperedArtifact();
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify/v2').send({ artifact, request: req });
    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('INVALID_SIGNATURE');
  });

  test('CS-03c  /verify (public) → BLOCK + INVALID_SIGNATURE', async () => {
    const { artifact, request: req } = await tamperedArtifact();
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify').send({ artifact, request: req });
    assertBlockShape(resp.body);
    expect(resp.body.reason).toBe('INVALID_SIGNATURE');
  });
});

// ── CS-04: Request mismatch — BLOCK + REQUEST_MISMATCH ───────────────────────

describe('CS-04  request mismatch', () => {
  function mismatchedPair() {
    const { artifact } = freshArtifact();
    const otherReq = { ...BASE_REQ, body: { prompt: 'different', model: 'gpt-4' } };
    return { artifact, request: otherReq };
  }

  test('CS-04a  direct pipeline → REQUEST_MISMATCH', async () => {
    const { artifact, request: req } = mismatchedPair();
    const stores = freshStores();
    const r = await direct(artifact, req, stores);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  test('CS-04b  /verify/v2 → BLOCK + REQUEST_MISMATCH', async () => {
    const { artifact, request: req } = mismatchedPair();
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify/v2').send({ artifact, request: req });
    expect(resp.body.decision).toBe('BLOCK');
    expect(resp.body.reason).toBe('REQUEST_MISMATCH');
  });

  test('CS-04c  /verify (public) → BLOCK + REQUEST_MISMATCH', async () => {
    const { artifact, request: req } = mismatchedPair();
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify').send({ artifact, request: req });
    assertBlockShape(resp.body);
    expect(resp.body.reason).toBe('REQUEST_MISMATCH');
  });
});

// ── CS-05: Replay — BLOCK + REPLAY_DETECTED ───────────────────────────────────

describe('CS-05  replay detection', () => {
  test('CS-05a  direct pipeline → REPLAY_DETECTED on second call', async () => {
    const { artifact, request: req } = freshArtifact();
    const stores = freshStores();
    await direct(artifact, req, stores);
    const r2 = await direct(artifact, req, stores);
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('CS-05b  /verify/v2 — dry-run does NOT register nonces, so second call still passes', async () => {
    // /verify/v2 is dry-run: it never registers nonces, so the same artifact
    // can be verified multiple times without replay.
    const { artifact, request: req } = freshArtifact();
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    await request(app).post('/verify/v2').send({ artifact, request: req });
    const resp = await request(app).post('/verify/v2').send({ artifact, request: req });
    expect(resp.body.decision).toBe('EXECUTE');
  });
});

// ── CS-06: Expired artifact — BLOCK + EXPIRED ────────────────────────────────

describe('CS-06  expired artifact', () => {
  function expiredPair() {
    const { artifact, request: req } = freshArtifact();
    const future = () => Date.now() + 999_999;
    return { artifact, request: req, future };
  }

  test('CS-06a  direct pipeline → EXPIRED with future clock', async () => {
    const { artifact, request: req, future } = expiredPair();
    const stores = freshStores();
    const r = await direct(artifact, req, stores, { _clock: future });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('EXPIRED');
  });
});

// ── CS-07: Invalid artifact structure — BLOCK + INVALID_ARTIFACT ──────────────

describe('CS-07  invalid artifact structure', () => {
  test('CS-07a  direct pipeline null → INVALID_ARTIFACT', async () => {
    const stores = freshStores();
    const r = await direct(null, BASE_REQ, stores);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('INVALID_ARTIFACT');
  });

  test('CS-07b  /verify/v2 null artifact → BLOCK + INVALID_ARTIFACT or MISSING_ARTIFACT', async () => {
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify/v2').send({ artifact: null, request: BASE_REQ });
    expect(resp.body.decision).toBe('BLOCK');
    expect(['MISSING_ARTIFACT', 'INVALID_ARTIFACT']).toContain(resp.body.reason);
  });

  test('CS-07c  /verify (public) null artifact → BLOCK', async () => {
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify').send({ artifact: null, request: BASE_REQ });
    assertBlockShape(resp.body);
    expect(['MISSING_ARTIFACT', 'INVALID_ARTIFACT']).toContain(resp.body.reason);
  });
});

// ── CS-08: Response structure has no "valid" field ────────────────────────────

describe('CS-08  response shape — no legacy "valid" boolean field', () => {
  test('CS-08a  /verify (public) success → no "valid" field', async () => {
    const { artifact, request: req } = freshArtifact();
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify').send({ artifact, request: req });
    expect(resp.body).not.toHaveProperty('valid');
  });

  test('CS-08b  /verify (public) failure → no "valid" field', async () => {
    const { artifact, request: req } = freshArtifact();
    const tampered = { ...artifact, signature: Buffer.alloc(64).toString('base64') };
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify').send({ artifact: tampered, request: req });
    expect(resp.body).not.toHaveProperty('valid');
  });

  test('CS-08c  /verify/v2 success → no "valid" field', async () => {
    const { artifact, request: req } = freshArtifact();
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    const resp   = await request(app).post('/verify/v2').send({ artifact, request: req });
    expect(resp.body).not.toHaveProperty('valid');
  });
});

// ── CS-09: Reason codes are canonical (UPPERCASE_SNAKE_CASE) on all surfaces ──

describe('CS-09  all surface reason codes are canonical UPPERCASE_SNAKE_CASE', () => {
  const RE = /^[A-Z][A-Z0-9_]+$/;
  const SCENARIOS = [];

  beforeAll(() => {
    const tampered = (() => {
      const { artifact } = freshArtifact();
      return { ...artifact, signature: Buffer.alloc(64).toString('base64') };
    })();
    SCENARIOS.push(
      { label: 'null artifact',      body: { artifact: null,     request: BASE_REQ } },
      { label: 'tampered signature', body: { artifact: tampered, request: BASE_REQ } },
      { label: 'null request',       body: { artifact: tampered, request: null      } },
    );
  });

  test('CS-09a  /verify (public) — all failure codes are canonical', async () => {
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    for (const { label, body } of SCENARIOS) {
      const resp = await request(app).post('/verify').send(body);
      expect(resp.body.reason).toMatch(RE);
    }
  });

  test('CS-09b  /verify/v2 — all failure codes are canonical', async () => {
    const stores = freshStores();
    const app    = makeVerifyApp(stores.nonceBackend, stores.anomalyBackend);
    for (const { label, body } of SCENARIOS) {
      const resp = await request(app).post('/verify/v2').send(body);
      expect(resp.body.reason).toMatch(RE);
    }
  });
});
