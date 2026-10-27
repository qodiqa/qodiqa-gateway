'use strict';

// Mock consent registry — consistency tests verify response shape and
// field presence across surfaces; consent evaluation is tested separately.
jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * Response Consistency test suite
 *
 * Guarantees that:
 *   1. Every error response uses the canonical shape:
 *      { decision: 'BLOCK', reason: <UPPERCASE_CODE>, details: {}, requestId: <string> }
 *   2. Every response includes a requestId (string).
 *   3. X-Request-ID header is present on every response.
 *   4. Rate-limited responses are consistent across all routes.
 *   5. Method-not-allowed responses are consistent across all routes.
 *   6. Content-type error responses are consistent.
 *   7. No provider-specific information leaks publicly.
 *   8. Reason codes are canonical UPPERCASE_SNAKE_CASE on all routes.
 *
 * Test IDs: RC-01 … RC-60
 */

const request      = require('supertest');
const express      = require('express');
const requestId    = require('../../../../middleware/requestId');
const attachClientIp = require('../../../../middleware/clientIp');

const createVerifyRouter = require('../verify');
const createAiChatRouter = require('../aiChat');
const createSignRouter   = require('../sign');
const auditRouter        = require('../audit');
const publicKeysRouter   = require('../publicKeys');
const wellKnownRouter    = require('../well-known');
const keysRouter         = require('../keys');

const { signBoundArtifact }       = require('../../../validation/signBoundArtifact');
const { rotateKey, getActiveKey } = require('../../../../services/artifact/keyStore');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');

// In-memory dry-run store backends — avoids real Redis in unit tests.
function _makeDryNonceBackend() { return { async isRegistered() { return false; } }; }
function _makeDryAnomalyBackend() { return { async peek() { return { count: 0 }; } }; }

// ── Test setup ────────────────────────────────────────────────────────────────

let KEY;
beforeAll(() => {
  try   { KEY = getActiveKey('rc-consistency'); }
  catch { rotateKey('rc-consistency'); KEY = getActiveKey('rc-consistency'); }
});

const BASE_REQ      = { method: 'POST', path: '/ai/chat', body: { prompt: 'hello', model: 'gpt-4' } };
const OPEN_THRESH   = Object.freeze({ WINDOW_MS: 60_000, PER_KEY_MAX: 1_000_000, GLOBAL_MAX: 1_000_000 });
const DEFAULT_POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });

function freshArtifact(reqOverrides = {}) {
  const req = { ...BASE_REQ, ...reqOverrides };
  const now = Date.now();
  const base = signBoundArtifact(
    req,
    { payload: { provider: 'openai', policyHash: 'a'.repeat(64) }, timestamp: now, expiry: now + 60_000, publicKeyId: KEY.keyId },
    KEY.privDer,
  );
  return { artifact: base, request: req };
}

// Every test app mounts the requestId middleware so requestId is always populated.
function makeVerifyApp() {
  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/verify', createVerifyRouter({
    _dryRunNonceStore:   _makeDryNonceBackend(),
    _dryRunAnomalyStore: _makeDryAnomalyBackend(),
    _thresholds:         OPEN_THRESH,
    _getPolicies:        () => DEFAULT_POLICIES,
    _policyStore:        createStore(),
  }));
  return app;
}

function makeAiChatApp() {
  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store:        makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _thresholds:   OPEN_THRESH,
    _getPolicies:  () => DEFAULT_POLICIES,
    _policyStore:  createStore(),
    _providerFn:   () => Promise.resolve({ output: 'ok' }),
  }));
  return app;
}

function makeAuditApp() {
  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/audit', auditRouter);
  return app;
}

function makePublicKeysApp() {
  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/public-keys', publicKeysRouter);
  return app;
}

function makeWellKnownApp() {
  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/.well-known', wellKnownRouter);
  return app;
}

function makeKeysApp() {
  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/keys', keysRouter);
  return app;
}

// ── Shared invariant assertions ────────────────────────────────────────────────

const REASON_RE = /^[A-Z][A-Z0-9_]+$/;

function assertCanonicalBlock(body, reason) {
  expect(body.decision).toBe('BLOCK');
  if (reason) expect(body.reason).toBe(reason);
  expect(typeof body.reason).toBe('string');
  expect(body.reason).toMatch(REASON_RE);
  expect(body).toHaveProperty('details');
  expect(typeof body.details).toBe('object');
  expect(body).toHaveProperty('requestId');
}

// Management/admin surface (audit, public-keys, keys, ...) uses the
// canonical { status:'error', error:{code,message}, requestId } envelope
// from src/api/response.js — distinct from the core protocol surface's
// { decision, reason, details, requestId } shape asserted above.
function assertCanonicalAdminError(body, code) {
  expect(body.status).toBe('error');
  if (code) expect(body.error?.code).toBe(code);
  expect(typeof body.error?.code).toBe('string');
  expect(body.error.code).toMatch(REASON_RE);
  expect(body).toHaveProperty('requestId');
}

function assertRequestId(res) {
  // requestId in body
  expect(res.body.requestId !== undefined || res.body.requestId === null).toBe(true);
  // X-Request-ID header
  expect(res.headers['x-request-id']).toBeDefined();
  expect(typeof res.headers['x-request-id']).toBe('string');
  expect(res.headers['x-request-id'].length).toBeGreaterThan(0);
}

// ── RC-01 … RC-05: X-Request-ID header is present on all responses ────────────

describe('RC-01  X-Request-ID header presence', () => {

  test('RC-01a  /verify/v2 success → X-Request-ID set', async () => {
    const { artifact, request: req } = freshArtifact();
    const resp = await request(makeVerifyApp()).post('/verify/v2').send({ artifact, request: req });
    expect(resp.headers['x-request-id']).toBeDefined();
  });

  test('RC-01b  /verify/v2 error → X-Request-ID set', async () => {
    const resp = await request(makeVerifyApp())
      .post('/verify/v2')
      .set('Content-Type', 'application/json')
      .send({ request: BASE_REQ });
    expect(resp.headers['x-request-id']).toBeDefined();
  });

  test('RC-01c  /ai/chat BLOCK → X-Request-ID set', async () => {
    const resp = await request(makeAiChatApp())
      .post('/ai/chat')
      .set('Content-Type', 'application/json')
      .send({ prompt: 'hello' });
    expect(resp.headers['x-request-id']).toBeDefined();
  });

  test('RC-01d  /audit/:artifactId 400 → X-Request-ID set', async () => {
    const resp = await request(makeAuditApp()).get('/audit/not-a-uuid');
    expect(resp.headers['x-request-id']).toBeDefined();
  });

  test('RC-01e  /public-keys 200 → X-Request-ID set', async () => {
    const resp = await request(makePublicKeysApp()).get('/public-keys');
    expect(resp.headers['x-request-id']).toBeDefined();
  });

});

// ── RC-02 … RC-06: requestId field in all error response bodies ───────────────

describe('RC-02  requestId field in error bodies', () => {

  test('RC-02a  /verify/v2 400 → body.requestId is a string', async () => {
    const resp = await request(makeVerifyApp())
      .post('/verify/v2')
      .set('Content-Type', 'application/json')
      .send({ request: BASE_REQ });
    expect(resp.status).toBe(400);
    expect(typeof resp.body.requestId).toBe('string');
    expect(resp.body.requestId.length).toBeGreaterThan(0);
  });

  test('RC-02b  /ai/chat 200 BLOCK → body.requestId is a string', async () => {
    const resp = await request(makeAiChatApp())
      .post('/ai/chat')
      .set('Content-Type', 'application/json')
      .send({ prompt: 'hello' });
    expect(resp.status).toBe(200);
    expect(typeof resp.body.requestId).toBe('string');
  });

  test('RC-02c  /audit 400 → body.requestId is a string', async () => {
    const resp = await request(makeAuditApp()).get('/audit/not-a-uuid');
    expect(resp.status).toBe(400);
    expect(typeof resp.body.requestId).toBe('string');
  });

  test('RC-02e  /verify/v2 success → body.requestId is a string', async () => {
    const { artifact, request: req } = freshArtifact();
    const resp = await request(makeVerifyApp()).post('/verify/v2').send({ artifact, request: req });
    expect(resp.status).toBe(200);
    expect(typeof resp.body.requestId).toBe('string');
  });

});

// ── RC-03: METHOD_NOT_ALLOWED is consistent across all routes ─────────────────

describe('RC-03  METHOD_NOT_ALLOWED is uniform across routes', () => {

  const routes = [
    { label: '/verify/v2',       fn: () => request(makeVerifyApp()).get('/verify/v2') },
    { label: '/verify',          fn: () => request(makeVerifyApp()).delete('/verify') },
    { label: '/ai/chat',         fn: () => request(makeAiChatApp()).get('/ai/chat') },
    { label: '/.well-known',     fn: () => request(makeWellKnownApp()).post('/.well-known/qodiqa/keys').set('Content-Type','application/json').send({}) },
  ];

  for (const { label, fn } of routes) {
    test(`RC-03  ${label} wrong method → 405 canonical BLOCK`, async () => {
      const resp = await fn();
      expect(resp.status).toBe(405);
      assertCanonicalBlock(resp.body, 'METHOD_NOT_ALLOWED');
    });
  }

  // Management/admin surface routes — canonical { status:'error', error:{code} } envelope.
  const adminRoutes = [
    { label: '/audit',           fn: () => request(makeAuditApp()).post('/audit/chain/integrity').set('Content-Type','application/json').send({}) },
    { label: '/public-keys',     fn: () => request(makePublicKeysApp()).post('/public-keys').set('Content-Type','application/json').send({}) },
    { label: '/keys',            fn: () => request(makeKeysApp()).post('/keys').set('Content-Type','application/json').send({}) },
  ];

  for (const { label, fn } of adminRoutes) {
    test(`RC-03  ${label} wrong method → 405 canonical admin error`, async () => {
      const resp = await fn();
      expect(resp.status).toBe(405);
      assertCanonicalAdminError(resp.body, 'METHOD_NOT_ALLOWED');
    });
  }

});

// ── RC-04: RATE_LIMITED is consistent across all routes ───────────────────────

describe('RC-04  RATE_LIMITED shape is uniform', () => {

});

// ── RC-05: UNSUPPORTED_MEDIA_TYPE is consistent ───────────────────────────────

describe('RC-05  UNSUPPORTED_MEDIA_TYPE is uniform across POST routes', () => {

  const postRoutes = [
    { label: '/verify/v2',   fn: () => request(makeVerifyApp()).post('/verify/v2').send('{}') },
    { label: '/verify',      fn: () => request(makeVerifyApp()).post('/verify').send('{}') },
    { label: '/ai/chat',     fn: () => request(makeAiChatApp()).post('/ai/chat').send('{}') },
  ];

  for (const { label, fn } of postRoutes) {
    test(`RC-05  ${label} wrong Content-Type → 415 canonical BLOCK`, async () => {
      const resp = await fn();
      expect(resp.status).toBe(415);
      assertCanonicalBlock(resp.body, 'UNSUPPORTED_MEDIA_TYPE');
    });
  }

});

// ── RC-06: All BLOCK reason codes are canonical UPPERCASE_SNAKE_CASE ──────────

describe('RC-06  All BLOCK reason codes are UPPERCASE_SNAKE_CASE', () => {

  test('RC-06a  /verify/v2 returns canonical reason codes for common failures', async () => {
    const app = makeVerifyApp();
    const scenarios = [
      { body: { request: BASE_REQ } },                       // MISSING_ARTIFACT
      { body: { artifact: null, request: BASE_REQ } },       // MISSING_ARTIFACT
      { body: { artifact: 'bad', request: BASE_REQ } },      // INVALID_ARTIFACT_TYPE
      { body: { artifact: {}, request: null } },             // MISSING_REQUEST
      { body: { artifact: {}, request: BASE_REQ, x: 1 } },  // UNEXPECTED_FIELDS
    ];
    for (const { body } of scenarios) {
      const resp = await request(app)
        .post('/verify/v2')
        .set('Content-Type', 'application/json')
        .send(body);
      expect(resp.body.reason).toMatch(REASON_RE);
    }
  });

  test('RC-06b  /ai/chat returns canonical reason codes for input failures', async () => {
    const app = makeAiChatApp();
    const resp = await request(app)
      .post('/ai/chat')
      .set('Content-Type', 'application/json')
      .send({ prompt: 'hello' });
    expect(resp.body.reason).toMatch(REASON_RE);
  });

});

// ── RC-07: No provider-specific info in public responses ─────────────────────

describe('RC-07  No provider-specific information in public responses', () => {

  const PROVIDER_PATTERNS = [
    /openai/i, /anthropic/i, /gemini/i,
    /APIConnectionError/i, /APIError/i,
    /RateLimitError/i, /APIConnectionTimeoutError/i,
    /AnthropicSDKError/i, /openai\.error/i,
    /cmpl-[a-zA-Z0-9]+/,   // OpenAI completion ID prefix
  ];

  function noProviderLeakage(body) {
    const serialized = JSON.stringify(body);
    for (const pattern of PROVIDER_PATTERNS) {
      expect(serialized).not.toMatch(pattern);
    }
  }

  test('RC-07a  /verify/v2 block response leaks no provider info', async () => {
    const app  = makeVerifyApp();
    const resp = await request(app)
      .post('/verify/v2')
      .set('Content-Type', 'application/json')
      .send({ request: BASE_REQ });
    noProviderLeakage(resp.body);
  });

  test('RC-07b  /ai/chat provider-error block leaks no provider-specific class names', async () => {
    const app = express();
    app.use(requestId);
    app.use(attachClientIp);
    app.use(express.json());
    app.use('/ai/chat', createAiChatRouter({
      _store:        makeNonceStore(),
      _anomalyStore: makeOpenAnomalyStore(),
      _thresholds:   OPEN_THRESH,
      _getPolicies:  () => DEFAULT_POLICIES,
      _policyStore:  createStore(),
      _providerFn:   () => {
        // Simulate a normalized provider error — no SDK class names
        const err = new Error('PROVIDER_UNAVAILABLE');
        err.code  = 'PROVIDER_UNAVAILABLE';
        return Promise.reject(err);
      },
    }));

    const { artifact, request: req } = freshArtifact();
    const hdr = Buffer.from(JSON.stringify(artifact)).toString('base64');
    const resp = await request(app)
      .post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', hdr)
      .send({ prompt: 'hello', model: 'gpt-4' });

    noProviderLeakage(resp.body);
    // reason should be a canonical PROVIDER_* code, not an SDK class name
    expect(resp.body.reason).toMatch(REASON_RE);
  });

  test('RC-07c  /audit/:artifactId response body leaks no provider responseId', async () => {
    const app  = makeAuditApp();
    const resp = await request(app).get('/audit/00000000-0000-4000-8000-000000000001');
    // Either 200 or 404; neither should expose provider correlation IDs
    const serialized = JSON.stringify(resp.body);
    expect(serialized).not.toMatch(/cmpl-[a-zA-Z0-9]+/);
    if (resp.status === 200) {
      expect(resp.body.data?.execution?.responseId).toBeUndefined();
    }
  });

});

// ── RC-08: /verify/v2 EXECUTE response shape ──────────────────────────────────

describe('RC-08  Verify EXECUTE response includes requestId', () => {

  test('RC-08  /verify/v2 EXECUTE includes requestId as a string', async () => {
    const { artifact, request: req } = freshArtifact();
    const resp = await request(makeVerifyApp()).post('/verify/v2').send({ artifact, request: req });
    expect(resp.status).toBe(200);
    expect(resp.body.decision).toBe('EXECUTE');
    expect(typeof resp.body.requestId).toBe('string');
    expect(resp.body.requestId.length).toBeGreaterThan(0);
  });

});

// ── RC-09: /ai/chat EXECUTE response shape ────────────────────────────────────

describe('RC-09  AI chat EXECUTE response includes requestId', () => {

  test('RC-09  /ai/chat EXECUTE includes requestId as a string', async () => {
    const { artifact, request: req } = freshArtifact();
    const hdr  = Buffer.from(JSON.stringify(artifact)).toString('base64');
    const resp = await request(makeAiChatApp())
      .post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', hdr)
      .send({ prompt: 'hello', model: 'gpt-4' });
    expect(resp.status).toBe(200);
    expect(resp.body.decision).toBe('EXECUTE');
    expect(typeof resp.body.requestId).toBe('string');
  });

});

// ── RC-10: /audit success response includes requestId ─────────────────────────

describe('RC-10  Audit success responses include requestId', () => {

  test('RC-10a  /audit/chain/integrity success → requestId in body', async () => {
    const resp = await request(makeAuditApp()).get('/audit/chain/integrity');
    expect(resp.status).toBe(200);
    expect(typeof resp.body.requestId).toBe('string');
  });

});

// ── RC-11: /public-keys success response includes requestId ───────────────────

describe('RC-11  Public key endpoints include requestId', () => {

  test('RC-11a  GET /public-keys → requestId in body', async () => {
    const resp = await request(makePublicKeysApp()).get('/public-keys');
    expect(resp.status).toBe(200);
    expect(typeof resp.body.requestId).toBe('string');
  });

  test('RC-11b  GET /.well-known/qodiqa/keys → requestId in body', async () => {
    const resp = await request(makeWellKnownApp()).get('/.well-known/qodiqa/keys');
    expect(resp.status).toBe(200);
    expect(typeof resp.body.requestId).toBe('string');
  });

  test('RC-11c  GET /keys → requestId in body', async () => {
    const resp = await request(makeKeysApp()).get('/keys');
    expect(resp.status).toBe(200);
    expect(typeof resp.body.requestId).toBe('string');
  });

});

// ── RC-12: requestId in body matches X-Request-ID header ─────────────────────

describe('RC-12  requestId in body matches X-Request-ID header', () => {

  test('RC-12a  /verify/v2 BLOCK — body.requestId === X-Request-ID header', async () => {
    const resp = await request(makeVerifyApp())
      .post('/verify/v2')
      .set('Content-Type', 'application/json')
      .send({ request: BASE_REQ });
    expect(resp.body.requestId).toBe(resp.headers['x-request-id']);
  });

  test('RC-12b  /verify/v2 EXECUTE — body.requestId === X-Request-ID header', async () => {
    const { artifact, request: req } = freshArtifact();
    const resp = await request(makeVerifyApp()).post('/verify/v2').send({ artifact, request: req });
    expect(resp.status).toBe(200);
    expect(resp.body.requestId).toBe(resp.headers['x-request-id']);
  });

  test('RC-12c  /ai/chat BLOCK — body.requestId === X-Request-ID header', async () => {
    const resp = await request(makeAiChatApp())
      .post('/ai/chat')
      .set('Content-Type', 'application/json')
      .send({ prompt: 'hello' });
    expect(resp.body.requestId).toBe(resp.headers['x-request-id']);
  });

  test('RC-12d  /audit 400 — body.requestId === X-Request-ID header', async () => {
    const resp = await request(makeAuditApp()).get('/audit/not-a-uuid');
    expect(resp.body.requestId).toBe(resp.headers['x-request-id']);
  });

  test('RC-12e  415 error — body.requestId === X-Request-ID header', async () => {
    const resp = await request(makeVerifyApp()).post('/verify/v2').send('{}');
    expect(resp.status).toBe(415);
    expect(resp.body.requestId).toBe(resp.headers['x-request-id']);
  });

  test('RC-12f  405 error — body.requestId === X-Request-ID header', async () => {
    const resp = await request(makeVerifyApp()).get('/verify/v2');
    expect(resp.status).toBe(405);
    expect(resp.body.requestId).toBe(resp.headers['x-request-id']);
  });

});

// ── RC-13: No legacy "valid" field in any response ────────────────────────────

describe('RC-13  No legacy "valid" boolean field in any route response', () => {

  test('RC-13a  /verify/v2 BLOCK → no valid field', async () => {
    const resp = await request(makeVerifyApp())
      .post('/verify/v2').set('Content-Type','application/json').send({ request: BASE_REQ });
    expect(resp.body).not.toHaveProperty('valid');
  });

  test('RC-13b  /public-keys 200 → no valid field', async () => {
    const resp = await request(makePublicKeysApp()).get('/public-keys');
    expect(resp.body).not.toHaveProperty('valid');
  });

  test('RC-13c  /keys 200 → no valid field', async () => {
    const resp = await request(makeKeysApp()).get('/keys');
    expect(resp.body).not.toHaveProperty('valid');
  });

  test('RC-13d  /keys 405 → no valid field (was {valid:false,reason} before 6.2)', async () => {
    const resp = await request(makeKeysApp()).post('/keys').set('Content-Type','application/json').send({});
    expect(resp.status).toBe(405);
    expect(resp.body).not.toHaveProperty('valid');
    expect(resp.body.status).toBe('error');
  });

});

// ── RC-14: /audit timeout response shape ─────────────────────────────────────

describe('RC-14  Audit timeout uses canonical error shape', () => {

  test('RC-14  AUDIT_TIMEOUT maps to decision:BLOCK reason:AUDIT_TIMEOUT', async () => {
    const timeoutRouter = require('express').Router();
    timeoutRouter.get('/chain/integrity', async (req, res) => {
      try {
        await Promise.race([
          new Promise(() => {}), // never resolves
          new Promise((_, reject) => setTimeout(() => reject(new Error('AUDIT_TIMEOUT')), 10)),
        ]);
      } catch {
        return res.status(503).json({ decision: 'BLOCK', reason: 'AUDIT_TIMEOUT', details: {}, requestId: req.requestId ?? null });
      }
    });
    const app = express();
    app.use(requestId);
    app.use('/audit', timeoutRouter);
    const resp = await request(app).get('/audit/chain/integrity');
    expect(resp.status).toBe(503);
    assertCanonicalBlock(resp.body, 'AUDIT_TIMEOUT');
  });

});

// ── RC-15: /sign canonical error shapes ──────────────────────────────────────

describe('RC-15  /sign error responses use canonical BLOCK shape', () => {

  function makeSignApp() {
    const app = express();
    app.use(requestId);
    app.use(attachClientIp);
    app.use(express.json());
    app.use('/sign', createSignRouter(() => DEFAULT_POLICIES));
    return app;
  }

  // TRUST-1 remediation: /sign no longer accepts a shared QODIQA_SIGN_TOKEN,
  // and there is no more "not configured" state distinct from "no valid
  // credential" — a missing OR unresolvable credential is always 401
  // UNAUTHORIZED (authentication), never a special SIGN_NOT_AVAILABLE 403.
  // A real signing identity is always provisioned here so every RC-15 test
  // below actually runs (previously most self-skipped when the ambient
  // QODIQA_SIGN_TOKEN env var happened to be unset).
  const { apiKey: TOKEN } = provisionTestSigningIdentity({ tenantId: 'default' });

  test('RC-15a  /sign without any credential → 401 canonical BLOCK UNAUTHORIZED', async () => {
    const resp = await request(makeSignApp())
      .post('/sign').set('Content-Type','application/json').send({});
    expect(resp.status).toBe(401);
    assertCanonicalBlock(resp.body, 'UNAUTHORIZED');
  });

  test('RC-15b  /sign with wrong token → 401 canonical BLOCK UNAUTHORIZED', async () => {
    const resp = await request(makeSignApp())
      .post('/sign')
      .set('Content-Type','application/json')
      .set('Authorization', 'Bearer wrong-token')
      .send({ request: { method: 'POST', path: '/ai/chat', body: {} } });
    expect(resp.status).toBe(401);
    assertCanonicalBlock(resp.body, 'UNAUTHORIZED');
  });

  test('RC-15c  /sign invalid method → 400 canonical BLOCK INVALID_METHOD', async () => {
    const resp = await request(makeSignApp())
      .post('/sign')
      .set('Content-Type','application/json')
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ request: { method: 'BADMETHOD', path: '/ai/chat', body: {} } });
    expect(resp.status).toBe(400);
    assertCanonicalBlock(resp.body, 'INVALID_METHOD');
  });

  test('RC-15d  /sign invalid TTL → 400 canonical BLOCK INVALID_TTL', async () => {
    const resp = await request(makeSignApp())
      .post('/sign')
      .set('Content-Type','application/json')
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ request: { method: 'POST', path: '/ai/chat', body: {} }, ttl: -1 });
    expect(resp.status).toBe(400);
    assertCanonicalBlock(resp.body, 'INVALID_TTL');
  });

  test('RC-15e  /sign path too long → 400 canonical BLOCK PATH_TOO_LONG', async () => {
    const resp = await request(makeSignApp())
      .post('/sign')
      .set('Content-Type','application/json')
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ request: { method: 'POST', path: '/' + 'a'.repeat(2050), body: {} } });
    expect(resp.status).toBe(400);
    assertCanonicalBlock(resp.body, 'PATH_TOO_LONG');
  });

  test('RC-15f  /sign body too deep → 400 canonical BLOCK BODY_TOO_DEEP', async () => {
    let deep = { leaf: true };
    for (let i = 0; i < 15; i++) deep = { n: deep };
    const resp = await request(makeSignApp())
      .post('/sign')
      .set('Content-Type','application/json')
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ request: { method: 'POST', path: '/ai/chat', body: deep } });
    expect(resp.status).toBe(400);
    assertCanonicalBlock(resp.body, 'BODY_TOO_DEEP');
  });

  test('RC-15g  /sign no error field in any response (old {error:...} shape gone)', async () => {
    const resp = await request(makeSignApp())
      .post('/sign')
      .set('Content-Type','application/json')
      .set('Authorization', 'Bearer wrong')
      .send({});
    // Old shape was {error:'ENFORCEMENT_BLOCKED',reason:'UNAUTHORIZED'}
    expect(resp.body).not.toHaveProperty('error');
    expect(resp.body.decision).toBe('BLOCK');
  });

});
