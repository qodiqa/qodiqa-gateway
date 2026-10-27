'use strict';

/**
 * Response Envelope Governance Test — (API-1 remediation) drift
 * prevention.
 *
 * src/api/responseEnvelopes.js is a hand-maintained registry (see its own
 * header) — nothing forces it to stay in sync with response.js's prose
 * documentation or with what route handlers actually send. This test is
 * that missing force. It checks, in order:
 *
 *   A. Every route file in routeMounts.js's MOUNTS list has an entry in
 *      ROUTE_ENVELOPES (sanity — true by construction today, guards a
 *      future refactor of the registry's defaulting logic).
 *   B. Every envelope type name in ENVELOPE_TYPES appears in response.js's
 *      header comment — doc/registry drift fails the build.
 *   C. Every route file defaulted to the management envelope
 *      (MANAGEMENT_SUCCESS/MANAGEMENT_ERROR — i.e. NOT given an explicit
 *      override in responseEnvelopes.js) actually requires response.js and
 *      calls success()/failure(). A route file that silently grows its own
 *      response shape without gaining an explicit override fails here —
 *      this is the "new undocumented response type" gate.
 * D. Runtime shape assertions: for the route files explicitly
 *      names (keys.js, publicKeys.js, public-key.js, health.js, ready.js,
 *      healthRedis.js, well-known.js), actually invoke the handler and
 *      assert the real response body's top-level key set matches its
 *      registered envelope type exactly (or, for 'subset' types, contains
 *      the required keys). This is genuine runtime-vs-registry parity, not
 *      just a static claim.
 *   E. Synthetic mutation test: checkEnvelopeShape() (the same function
 *      used in D) is fed a deliberately mismatched body/type pair and must
 *      report the mismatch — proving detection is sound.
 *   F. Middleware-owned envelopes (item 27 — ITEM-26-RESPONSE-ENVELOPE-
 *      DECISION-RECORD.md, CP0 approval): envelopes emitted by
 *      application-wide middleware rather than any route file live in
 *      responseEnvelopes.js's MIDDLEWARE_ENVELOPES map instead of
 *      ROUTE_ENVELOPES/MOUNTS, so they need their own coverage —
 *      (a) static: every key resolves to a real file, every type exists in
 *      ENVELOPE_TYPES, every type name is documented in response.js's header
 *      (same rule as B); (b) runtime: mounts the middleware directly, forces
 *      its state via the module's own documented test-only isolation
 *      mechanism, and asserts both the top-level shape and the nested
 *      fields the top-level-only shape check can't see. Both halves iterate
 *      MIDDLEWARE_ENVELOPES — no hardcoded duplicate file list.
 */

// Item 27 §D extension: aiChat.js/verify.js run the real (non-semantic)
// policy engine, whose REQUIRE_CONSENT evaluator calls src/core/consent's
// verify() regardless of the requireValidArtifact:true config flag (that
// flag is a config-shape validation requirement, not a bypass — confirmed
// by reading services/policy/evaluators/requireConsent.js directly). Mocked
// here for the same reason aiChat.test.js/verify.v2.test.js mock it: these
// envelope-shape assertions exercise routing/response-shape, not consent
// evaluator correctness (tested elsewhere, src/core/consent/).
jest.mock('../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const fs   = require('fs');
const path = require('path');
const request = require('supertest');
const express  = require('express');

const { MOUNTS } = require('../../openapi/routeMounts');
const { ENVELOPE_TYPES, ROUTE_ENVELOPES, MIDDLEWARE_ENVELOPES, checkEnvelopeShape } = require('../responseEnvelopes');

const ROOT = path.join(__dirname, '..', '..', '..');
const DEFAULT_ENVELOPES = ['MANAGEMENT_SUCCESS', 'MANAGEMENT_ERROR'];

function readFile(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

// ── A. Coverage ──────────────────────────────────────────────────────────

describe('response envelope governance — registry coverage', () => {
  test('every MOUNTS route file has a ROUTE_ENVELOPES entry', () => {
    const files = new Set(MOUNTS.map(m => m.file));
    for (const file of files) {
      // toHaveProperty(file) would misparse the dot in e.g. "healthRedis.js"
      // as a nested-path separator — pass the key as a one-element array so
      // it's treated as a literal property name instead.
      expect(ROUTE_ENVELOPES).toHaveProperty([file]);
      expect(Array.isArray(ROUTE_ENVELOPES[file])).toBe(true);
      expect(ROUTE_ENVELOPES[file].length).toBeGreaterThan(0);
    }
  });

  test('every type referenced by ROUTE_ENVELOPES exists in ENVELOPE_TYPES', () => {
    for (const [file, types] of Object.entries(ROUTE_ENVELOPES)) {
      for (const t of types) {
        expect(ENVELOPE_TYPES).toHaveProperty(t);
      }
      void file;
    }
  });
});

// ── B. Doc/registry drift ────────────────────────────────────────────────

describe('response envelope governance — response.js is the authoritative spec', () => {
  const responseJsSource = readFile('src/api/response.js');

  test.each(Object.keys(ENVELOPE_TYPES))('response.js header documents envelope type %s', (typeName) => {
    expect(responseJsSource).toEqual(expect.stringContaining(typeName));
  });
});

// ── C. Static check: management-classified files actually use response.js ──

describe('response envelope governance — management-envelope files use response.js', () => {
  const managementFiles = Object.entries(ROUTE_ENVELOPES)
    .filter(([, types]) => types.length === DEFAULT_ENVELOPES.length && types.every(t => DEFAULT_ENVELOPES.includes(t)))
    .map(([file]) => file);

  // Sanity: this should be the large majority of the API surface.
  test('a substantial number of files use the default management envelope', () => {
    expect(managementFiles.length).toBeGreaterThan(20);
  });

  test.each(managementFiles)('%s requires response.js and calls success()/failure()', (file) => {
    const src = readFile(file);
    expect(src).toMatch(/require\(['"`][^'"`]*\bresponse(?:\.js)?['"`]\)/);
    expect(src).toMatch(/\b(?:success|failure)\s*\(/);
  });
});

// ── D. Runtime shape assertions for the files explicitly names ─────

function assertEnvelope(body, typeName) {
  const result = checkEnvelopeShape(body, typeName);
  if (!result.ok) throw new Error(`body does not match ${typeName}: ${result.reason}`);
}

describe('response envelope governance — runtime shape matches the registry', () => {
  test('GET /public-keys body matches MANAGEMENT_SUCCESS', async () => {
    const publicKeysRouter = require('../routes/publicKeys');
    const app = express();
    app.use('/public-keys', publicKeysRouter);
    const res = await request(app).get('/public-keys');
    expect(res.status).toBe(200);
    assertEnvelope(res.body, 'MANAGEMENT_SUCCESS');
  });

  test('GET /keys body matches MANAGEMENT_SUCCESS', async () => {
    const keysRouter = require('../routes/keys');
    const app = express();
    app.use('/keys', keysRouter);
    const res = await request(app).get('/keys');
    expect(res.status).toBe(200);
    assertEnvelope(res.body, 'MANAGEMENT_SUCCESS');
  });

  test('GET /public-key body matches MANAGEMENT_SUCCESS or MANAGEMENT_ERROR', async () => {
    const publicKeyRouter = require('../routes/public-key');
    const app = express();
    app.use('/public-key', publicKeyRouter);
    const res = await request(app).get('/public-key');
    expect([200, 500]).toContain(res.status);
    assertEnvelope(res.body, res.status === 200 ? 'MANAGEMENT_SUCCESS' : 'MANAGEMENT_ERROR');
  });

  test('GET /health body matches INFRA_HEALTH', async () => {
    const healthRouter = require('../routes/health');
    const app = express();
    app.use('/health', healthRouter);
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    assertEnvelope(res.body, 'INFRA_HEALTH');
  });

  test('GET /health/redis body matches INFRA_HEALTH_REDIS', async () => {
    const healthRedisRouter = require('../routes/healthRedis');
    const app = express();
    app.use('/health/redis', healthRedisRouter);
    const res = await request(app).get('/health/redis');
    assertEnvelope(res.body, 'INFRA_HEALTH_REDIS');
  });

  test('GET /ready body matches INFRA_READY', async () => {
    jest.resetModules();
    jest.doMock('../../validation/nonceStore', () => ({ isReady: () => true }));
    jest.doMock('../../validation/anomalyStore', () => ({ isReady: () => true }));
    jest.doMock('../../../services/policy/store', () => ({ isReady: () => true }));
    jest.doMock('../../infra/postgres/pool', () => ({ isEnabled: () => false, isHealthy: () => true }));
    jest.doMock('../../core/consent/revocation/RevocationSubscriber', () => ({ isReady: () => true }));
    jest.doMock('../../core/consent/ConsentCache', () => ({ isReady: () => true }));

    const readyRouter = require('../routes/ready');
    const app = express();
    app.use('/ready', readyRouter);
    const res = await request(app).get('/ready');
    assertEnvelope(res.body, 'INFRA_READY');

    jest.dontMock('../../validation/nonceStore');
    jest.dontMock('../../validation/anomalyStore');
    jest.dontMock('../../../services/policy/store');
    jest.dontMock('../../infra/postgres/pool');
    jest.dontMock('../../core/consent/revocation/RevocationSubscriber');
    jest.dontMock('../../core/consent/ConsentCache');
    jest.resetModules();
  });

  test('GET /.well-known/qodiqa/keys body matches WELL_KNOWN_LIST', async () => {
    const wellKnownRouter = require('../routes/well-known');
    const app = express();
    app.use('/.well-known', wellKnownRouter);
    const res = await request(app).get('/.well-known/qodiqa/keys');
    expect(res.status).toBe(200);
    assertEnvelope(res.body, 'WELL_KNOWN_LIST');
  });

  test('GET /.well-known/qodiqa/keys/{bad-id} body matches WELL_KNOWN_ERROR', async () => {
    const wellKnownRouter = require('../routes/well-known');
    const app = express();
    app.use('/.well-known', wellKnownRouter);
    const res = await request(app).get('/.well-known/qodiqa/keys/not-a-valid-key-id');
    expect(res.status).toBe(404);
    assertEnvelope(res.body, 'WELL_KNOWN_ERROR');
  });
});

// ── D-extension. Item 27 (§5 point 5) — sign.js, aiChat.js, verify.js, ────
// alertRoutes.js runtime shape coverage, previously absent from §D.
//
// Assertions are written against CURRENT runtime behavior (ground truth per
// ITEM-26-RESPONSE-ENVELOPE-DECISION-RECORD.md's own instruction) — nothing
// here changes aiChat.js/verify.js/sign.js/alertRoutes.js themselves.

describe('response envelope governance — extended runtime shape coverage (§D extension, item 27)', () => {
  const { getActiveKey }         = require('../../../services/artifact/keyStore');
  const { signBoundArtifact }    = require('../../validation/signBoundArtifact');
  const { validateAndPrepare }   = require('../../../services/policy/loader');
  const { createStore }          = require('../../../services/policy/store');
  const { makeNonceStore, makeOpenAnomalyStore } = require('../../testing/stores');
  const { resetStats }           = require('../../../services/execution-guard');
  const { provisionTestSigningIdentity } = require('../../../test/helpers/signingIdentity');

  let KEY;
  beforeAll(() => { KEY = getActiveKey('default'); });
  beforeEach(() => resetStats());

  // Permissive REQUIRE_CONSENT policy — passes once the artifact is valid
  // (checkPolicy sets artifact.valid after validateBoundRequest succeeds);
  // same shape aiChat.test.js/verify.v2.test.js already use.
  const _POLICIES = validateAndPrepare({ policies: [{
    id: 'POL-D-EXT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
    config: { requireValidArtifact: true },
  }] });
  const _POLICY_STORE = createStore();

  function freshEnvelope(payload = {}) {
    const now = Date.now();
    return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
  }

  function toHeader(artifact) {
    return Buffer.from(JSON.stringify(artifact)).toString('base64');
  }

  // ── sign.js — SIGN_SUCCESS ──────────────────────────────────────────────

  test('POST /sign (success) body matches SIGN_SUCCESS (corrected entry)', async () => {
    const createSignRouter = require('../routes/sign');
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });

    const app = express();
    app.use(express.json());
    app.use('/sign', createSignRouter(() => _POLICIES));

    const res = await request(app)
      .post('/sign')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ request: { method: 'POST', path: '/orders/create', body: { sku: 'SKU-1' } } });

    expect(res.status).toBe(200);
    assertEnvelope(res.body, 'SIGN_SUCCESS');
  });

  // ── aiChat.js — ENFORCEMENT_DECISION, EXECUTE and BLOCK ─────────────────

  describe('POST /ai/chat', () => {
    const CHAT_PATH = '/ai/chat';
    const CHAT_BODY = { prompt: 'Hello, world!' };

    function makeAiChatApp() {
      const createAiChatRouter = require('../routes/aiChat');
      const app = express();
      app.use(express.json());
      app.use('/ai/chat', createAiChatRouter({
        _store:        makeNonceStore(),
        _anomalyStore: makeOpenAnomalyStore(),
        _providerFn:   () => Promise.resolve({ output: 'mock AI response' }),
        _getPolicies:  () => _POLICIES,
        _policyStore:  _POLICY_STORE,
      }));
      return app;
    }

    test('EXECUTE response matches ENFORCEMENT_DECISION', async () => {
      const app = makeAiChatApp();
      const artifact = signBoundArtifact(
        { method: 'POST', path: CHAT_PATH, body: CHAT_BODY },
        freshEnvelope({ provider: 'openai' }),
        KEY.privDer,
      );

      const res = await request(app)
        .post(CHAT_PATH)
        .set('x-qodiqa-artifact', toHeader(artifact))
        .send(CHAT_BODY);

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('EXECUTE');
      assertEnvelope(res.body, 'ENFORCEMENT_DECISION');
    });

    test('BLOCK response (MISSING_ARTIFACT) matches ENFORCEMENT_DECISION', async () => {
      const app = makeAiChatApp();
      const res = await request(app).post(CHAT_PATH).send(CHAT_BODY); // no x-qodiqa-artifact header

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('BLOCK');
      assertEnvelope(res.body, 'ENFORCEMENT_DECISION');
    });
  });

  // ── verify.js — ENFORCEMENT_DECISION ────────────────────────────────────
  //
  // EXECUTE only (not BLOCK) — BLOCK's shape is already proven identical
  // across every ENFORCEMENT_DECISION producer above and in §E; the value
  // specific to verify.js is its EXECUTE shape, which D26-4 (decision
  // record) codifies as intentionally different from aiChat.js's (no
  // `response`/`transparency`, has `tenantId`/`callerId` instead).

  test('POST /verify/v2 EXECUTE response matches ENFORCEMENT_DECISION', async () => {
    const createVerifyRouter = require('../routes/verify');
    const app = express();
    app.use(express.json());
    app.use('/verify', createVerifyRouter({
      _dryRunNonceStore:   makeNonceStore(),
      _dryRunAnomalyStore: makeOpenAnomalyStore(),
      _getPolicies:        () => _POLICIES,
      _policyStore:        _POLICY_STORE,
    }));

    const req = { method: 'POST', path: '/api/run', body: { userId: 'alice', action: 'read' } };
    const artifact = signBoundArtifact(req, freshEnvelope({ provider: 'openai' }), KEY.privDer);

    const res = await request(app)
      .post('/verify/v2')
      .send({ artifact, request: req });

    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
    assertEnvelope(res.body, 'ENFORCEMENT_DECISION');
  });

  // ── alertRoutes.js — ALERTS_OK and ALERTS_ERROR ─────────────────────────

  function makeAlertApp() {
    const { createAlertRouter } = require('../../alerting/api/alertRoutes');
    const app = express();
    app.use(express.json());
    app.use('/alerts', createAlertRouter());
    return app;
  }

  test('GET /alerts/counters matches ALERTS_OK', async () => {
    const res = await request(makeAlertApp()).get('/alerts/counters');
    expect(res.status).toBe(200);
    assertEnvelope(res.body, 'ALERTS_OK');
  });

  test('POST /alerts/test/:channel with an unknown channel matches ALERTS_ERROR', async () => {
    const res = await request(makeAlertApp()).post('/alerts/test/NOT_A_REAL_CHANNEL');
    expect(res.status).toBe(400);
    assertEnvelope(res.body, 'ALERTS_ERROR');
  });
});

// ── E. Synthetic mutation test — proves the checker itself is sound ───────

describe('response envelope governance — synthetic mutation detection', () => {
  test('checkEnvelopeShape reports a missing-key mutation', () => {
    const mutated = { status: 'success', timestamp: 'x', requestId: null }; // missing `data`
    const result = checkEnvelopeShape(mutated, 'MANAGEMENT_SUCCESS');
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/data/);
  });

  test('checkEnvelopeShape reports an extra-key mutation', () => {
    const mutated = { status: 'ok', uptime: 1, extraField: true }; // INFRA_HEALTH + drift
    const result = checkEnvelopeShape(mutated, 'INFRA_HEALTH');
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/extraField/);
  });

  test('checkEnvelopeShape reports a renamed-key mutation', () => {
    const mutated = { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', correlationId: 'x' }; // requestId renamed
    const result = checkEnvelopeShape(mutated, 'ENFORCEMENT_DECISION');
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/requestId/);
  });

  test('checkEnvelopeShape accepts a correctly-shaped body', () => {
    const body = { status: 'success', timestamp: 'x', requestId: null, data: {} };
    expect(checkEnvelopeShape(body, 'MANAGEMENT_SUCCESS')).toEqual({ ok: true });
  });
});

// ── F. Middleware-owned envelopes ───────────────────────────────────────────

describe('response envelope governance — middleware-owned envelopes (§F)', () => {
  // §F(a): static — mirrors §A/§B's checks, but over MIDDLEWARE_ENVELOPES
  // instead of ROUTE_ENVELOPES/MOUNTS (responseEnvelopes.js's own comment
  // explains why middleware-owned envelopes get a separate map).
  test('every MIDDLEWARE_ENVELOPES key resolves to an existing file', () => {
    for (const file of Object.keys(MIDDLEWARE_ENVELOPES)) {
      expect(fs.existsSync(path.join(ROOT, file))).toBe(true);
    }
  });

  test('every type referenced by MIDDLEWARE_ENVELOPES exists in ENVELOPE_TYPES', () => {
    for (const types of Object.values(MIDDLEWARE_ENVELOPES)) {
      for (const t of types) {
        expect(ENVELOPE_TYPES).toHaveProperty(t);
      }
    }
  });

  test("every MIDDLEWARE_ENVELOPES type name appears in response.js's header comment", () => {
    const responseJsSource = readFile('src/api/response.js');
    for (const types of Object.values(MIDDLEWARE_ENVELOPES)) {
      for (const t of types) {
        expect(responseJsSource).toEqual(expect.stringContaining(t));
      }
    }
  });

  // §F(b): runtime — mounts the middleware directly (it is not a route
  // file, so §D's supertest-against-a-router pattern doesn't apply as-is),
  // forces the shutdown state via requestDrain.js's own documented
  // test-only isolation mechanism (beginShutdown()/_reset() — see that
  // file's header comment), and asserts both the top-level envelope shape
  // (checkEnvelopeShape, the same top-level-only key-set check every other
  // section uses) AND the nested error.code/error.message fields that
  // top-level-only check cannot see — the assertion the registry's own
  // ALERTS_ERROR comment points at this section for.
  test.each(Object.entries(MIDDLEWARE_ENVELOPES))(
    '%s: forced-shutdown response matches its registered envelope(s)',
    async (file, types) => {
      // eslint-disable-next-line global-require
      const mw  = require(path.join(ROOT, file));
      const app = express();
      app.use(mw.middleware);
      app.get('/probe', (_req, res) => res.status(200).json({ probed: true }));

      mw.beginShutdown();
      try {
        const res = await request(app).get('/probe');
        expect(res.status).toBe(503);
        for (const t of types) assertEnvelope(res.body, t);

        expect(res.body.error).toBeTruthy();
        expect(res.body.error.code).toBe('SERVICE_SHUTTING_DOWN');
        expect(typeof res.body.error.message).toBe('string');
        expect(res.body.error.message.length).toBeGreaterThan(0);
      } finally {
        mw._reset();
      }
    },
  );
});
