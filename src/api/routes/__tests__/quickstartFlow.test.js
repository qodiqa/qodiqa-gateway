'use strict';
// v7 (R-12 / R-14): audit appends pseudonymize consentProvenance.subject / callerContext.callerId, which needs
// PostgreSQL in production (fail-closed without it). This suite runs without a database, so it opts in to the
// EXPLICIT test-only pseudonym stand-in (test/helpers/subjectPseudonymMock.js).
jest.mock('../../../core/dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));
const { PROVIDER_FIXTURE_KEYS } = require('../../../../test/helpers/providerFixtureKeys'); // format-valid fake keys

// Consent is mocked to always pass — this suite proves the documented
// Quickstart /sign → /ai/chat flow reaches EXECUTE; consent evaluation itself
// is covered separately in src/core/consent/.
jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * regression: proves the docs/guides/quickstart.md documented request — signed and
 * executed EXACTLY as published, with no undocumented fields — reaches a
 * successful EXECUTE decision. Before the /sign provider-resolution fix
 * (src/api/routes/sign.js), this exact flow BLOCKed at /ai/chat with
 * MISSING_PROVIDER because the Quickstart's /sign example never set
 * payload.provider.
 *
 * This test IS the Quickstart example — keeping it here means a future
 * change that breaks the documented flow fails CI, not just a code review.
 */

// services/providers/config.js freezes its provider CONFIGS at require()
// time — must be set before the first require below.
process.env.QODIQA_CLIENT_ID  = 'default';
process.env.OPENAI_API_KEY    = process.env.OPENAI_API_KEY || PROVIDER_FIXTURE_KEYS.openai;

const request = require('supertest');
const express = require('express');

const createSignRouter   = require('../sign');
const createAiChatRouter = require('../aiChat');
const attachClientIp     = require('../../../../middleware/clientIp');
const { getActiveKey, rotateKey } = require('../../../../services/artifact/keyStore');
const { validateAndPrepare }      = require('../../../../services/policy/loader');
const { createStore }             = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

// TRUST-1 remediation: /sign no longer accepts a shared QODIQA_SIGN_TOKEN via
// x-qodiqa-sign-token — every caller authenticates with its own per-identity
// signing API key via Authorization: Bearer.
const { apiKey: SIGN_TOKEN } = provisionTestSigningIdentity({ tenantId: 'default' });

beforeAll(() => {
  try   { getActiveKey('default'); }
  catch { rotateKey('default'); }
});

// Same policy set /sign and /ai/chat share in production (server.js mounts
// both routers against the same `policies` variable).
const POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });
const POLICY_STORE = createStore();

function makeApp() {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/sign', createSignRouter(() => POLICIES));
  app.use('/ai/chat', createAiChatRouter({
    _store:        makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _getPolicies:  () => POLICIES,
    _policyStore:  POLICY_STORE,
    _providerFn:   () => Promise.resolve({ output: '2 + 2 equals 4.' }),
  }));
  return app;
}

describe('Quickstart flow — documented /sign + /ai/chat curl example', () => {
  test('QUICKSTART-01 the exact documented /sign body (no payload.provider) followed by /ai/chat reaches EXECUTE', async () => {
    const app = makeApp();

    // Step 1 — docs/guides/quickstart.md's documented /sign curl body, verbatim.
    const signRes = await request(app)
      .post('/sign')
      .set('Content-Type', 'application/json')
      .set('Authorization', `Bearer ${SIGN_TOKEN}`)
      .send({
        request: {
          method: 'POST',
          path:   '/ai/chat',
          body:   { prompt: 'Hello, what is 2 + 2?' },
        },
      });

    expect(signRes.status).toBe(200);
    expect(signRes.body.artifact.payload.provider).toBe('openai');

    // Step 2 — base64-encode exactly as docs/guides/quickstart.md instructs.
    const artifactHeader = Buffer.from(JSON.stringify(signRes.body.artifact)).toString('base64');

    // Step 3 — execute with the artifact attached, same body as signed.
    const chatRes = await request(app)
      .post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', artifactHeader)
      .send({ prompt: 'Hello, what is 2 + 2?' });

    expect(chatRes.status).toBe(200);
    expect(chatRes.body.decision).toBe('EXECUTE');
    expect(chatRes.body.reason).toBe('ALL_CHECKS_PASSED');
    expect(chatRes.body.response).toBe('2 + 2 equals 4.');
  });

  test('QUICKSTART-02 the unauthorized request example (no artifact) still BLOCKs with MISSING_ARTIFACT', async () => {
    const app = makeApp();
    const res = await request(app)
      .post('/ai/chat')
      .set('Content-Type', 'application/json')
      .send({ prompt: 'Hello, what is 2 + 2?' });

    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('MISSING_ARTIFACT');
  });
});
