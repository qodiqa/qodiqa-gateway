'use strict';
// v7 (R-12 / R-14): audit appends pseudonymize consentProvenance.subject / callerContext.callerId, which needs
// PostgreSQL in production (fail-closed without it). This suite runs without a database, so it opts in to the
// EXPLICIT test-only pseudonym stand-in (test/helpers/subjectPseudonymMock.js).
jest.mock('../../../core/dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));

/**
 * final architectural proof — mutation testing.
 *
 * Builds a faithful test double for the innermost provider layer
 * (services/providers/router.js's REGISTRY + services/providers/config.js's
 * CONFIGS — the only two things that are ever hardcoded) and drives BOTH
 * POST /sign and POST /ai/chat through the SAME mocked instance in each
 * scenario, using otherwise entirely real code: real sign.js, real
 * aiChat.js, real execution.js, real services/providers.js (the
 * resolveProvider/listEnabledProviders re-export layer is NOT mocked — it
 * delegates to the mocked router.js, so this proves that layer of
 * indirection carries the mutation through correctly).
 *
 * The router.js test double below reimplements the REAL router.js's own
 * algorithm (see services/providers/router.js:82-193) against a
 * caller-supplied REGISTRY/CONFIGS, rather than returning arbitrary
 * canned answers — so passing this suite is evidence about the real
 * production algorithm's behavior under registry/config mutation, not
 * just about a mock's own scripted responses.
 */

const request = require('supertest');
const express = require('express');

// TRUST-1 remediation: /sign no longer accepts a shared QODIQA_SIGN_TOKEN.
// Provision one signing identity, persisted to an isolated store file, ONCE
// up front — buildApps() below calls jest.resetModules() per scenario, which
// gives signingIdentityStore a fresh in-memory cache each time too, but since
// the identity is persisted to disk it is found again on first access.
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
const { apiKey: SIGN_TOKEN } = provisionTestSigningIdentity({ tenantId: 'default' });

function buildRouterDouble(registry, configs) {
  return {
    listProviders: () => Object.keys(registry),
    listEnabledProviders: () =>
      Object.keys(registry).filter((name) => configs[name] && configs[name].enabled),
    // Faithful reimplementation of router.js's _dispatch() gating order
    // (REGISTRY membership, then CONFIGS.enabled) — see
    // services/providers/router.js:94-124.
    routeProviderCall: async (provider) => {
      const handler = registry[provider];
      if (!handler) {
        const err = new Error('PROVIDER_UNAVAILABLE');
        err.code  = 'PROVIDER_UNAVAILABLE';
        throw err;
      }
      const cfg = configs[provider];
      if (!cfg || !cfg.enabled) {
        const err = new Error('PROVIDER_NOT_CONFIGURED');
        err.code  = 'PROVIDER_NOT_CONFIGURED';
        throw err;
      }
      return handler();
    },
  };
}

function buildConfigDouble(configs) {
  return {
    getProviderConfig: (name) => configs[name] || null,
    getEnabledProviders: () => Object.keys(configs).filter((n) => configs[n].enabled),
    // aiChat.js now resolves an omitted `model` via
    // resolveDefaultModel() rather than a hardcoded constant — this double
    // must implement it too, or aiChat.js throws (resolveDefaultModel is
    // not a function) the moment any scenario reaches _executeAI(). None of
    // this suite's scenario configs define `defaultModel`, so this always
    // returns null here, matching the real function's contract for a
    // provider with no configured default; the mocked router's handler()
    // below is called with no arguments anyway, so the resolved model value
    // never affects any scenario's canned response.
    resolveDefaultModel: (name) =>
      (configs[name] && typeof configs[name].defaultModel === 'string' && configs[name].defaultModel)
        ? configs[name].defaultModel : null,
  };
}

/**
 * Wires a fresh app with REAL sign.js + REAL aiChat.js against a mutated
 * registry/configs pair. Consent is mocked to pass (standard practice
 * throughout this test suite — see aiChat.test.js) so BLOCK/status
 * differences observed are attributable only to the provider layer.
 */
function buildApps(registry, configs) {
  jest.resetModules();
  process.env.QODIQA_CLIENT_ID  = 'default';

  jest.doMock('../../../../services/providers/router', () => buildRouterDouble(registry, configs));
  jest.doMock('../../../../services/providers/config', () => buildConfigDouble(configs));
  jest.doMock('../../../core/consent', () => ({
    verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
  }));
  // SEM-C session 3: this suite is about the provider layer, not the
  // embedding-similarity gate — test/support/jest.setup.afterEnv.js's global test double
  // does not survive this function's own jest.resetModules() call above
  // (a fresh, un-initialized module instance), so mock the gate directly
  // here, at the same point every other post-reset dependency is re-mocked.
  jest.doMock('../../../core/semantic/embeddingGate', () => ({
    checkText: jest.fn().mockResolvedValue({ blocks: false, decision: 'ALLOW', reason: null, evidence: null }),
  }));

  const createSignRouter   = require('../sign');
  const createAiChatRouter = require('../aiChat');
  const { getActiveKey, rotateKey } = require('../../../../services/artifact/keyStore');
  const { validateAndPrepare }      = require('../../../../services/policy/loader');
  const { createStore }             = require('../../../../services/policy/store');
  const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');

  let KEY;
  try   { KEY = getActiveKey('default'); }
  catch { rotateKey('default'); KEY = getActiveKey('default'); }

  const policies = validateAndPrepare({ policies: [{
    id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
    config: { requireValidArtifact: true },
  }] });
  const policyStore = createStore();

  const app = express();
  app.use(express.json());
  app.use('/sign', createSignRouter(() => policies));
  app.use('/ai/chat', createAiChatRouter({
    _store:        makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _getPolicies:  () => policies,
    _policyStore:  policyStore,
  }));

  return { app, KEY };
}

async function signRequest(app, payload) {
  return request(app)
    .post('/sign')
    .set('Content-Type', 'application/json')
    .set('Authorization', `Bearer ${SIGN_TOKEN}`)
    .send({
      request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hi' } },
      ...(payload !== undefined ? { payload } : {}),
    });
}

// Directly signs an artifact bearing an arbitrary provider — used to reach
// /ai/chat with a provider value /sign itself would already refuse to mint,
// simulating "what if such an artifact existed" (e.g. issued before a
// registry mutation, or by a future bug elsewhere) to test /ai/chat's OWN
// independent enforcement, not merely /sign's.
function signArtifactWithProvider(KEY, provider) {
  const { signBoundArtifact } = require('../../../validation/signBoundArtifact');
  const req = { method: 'POST', path: '/ai/chat', body: { prompt: 'hi' } };
  const now = Date.now();
  return signBoundArtifact(
    req,
    { payload: { provider }, timestamp: now, expiry: now + 60_000, publicKeyId: KEY.keyId },
    KEY.privDer,
  );
}

async function chatRequestWithArtifact(app, artifact) {
  const header = Buffer.from(JSON.stringify(artifact)).toString('base64');
  return request(app)
    .post('/ai/chat')
    .set('Content-Type', 'application/json')
    .set('x-qodiqa-artifact', header)
    .send({ prompt: 'hi' });
}

describe('Scenario 1 — provider in CONFIGS but absent from REGISTRY ("ghost")', () => {
  const registry = { openai: () => ({ output: 'ok' }) };            // "ghost" NOT wired to a handler
  const configs  = { openai: { enabled: true }, ghost: { enabled: true } }; // CONFIGS thinks ghost is enabled

  test('/sign rejects an explicit ghost selection', async () => {
    const { app } = buildApps(registry, configs);
    const res = await signRequest(app, { provider: 'ghost' });
    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('PROVIDER_NOT_SUPPORTED');
  });

  test('/ai/chat rejects an artifact bearing ghost (same root cause: absent from REGISTRY)', async () => {
    const { app, KEY } = buildApps(registry, configs);
    const artifact = signArtifactWithProvider(KEY, 'ghost');
    const res = await chatRequestWithArtifact(app, artifact);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('PROVIDER_UNAVAILABLE');
    // Documented finding, not asserted as a defect: the two endpoints agree
    // on WHY (both driven by REGISTRY absence — resolveProvider() returns
    // false in both), but surface DIFFERENT reason strings by design
    // (/sign fails fast pre-execution with PROVIDER_NOT_SUPPORTED; /ai/chat
    // surfaces the generic execution-time PROVIDER_UNAVAILABLE). This
    // mirrors the codebase's own documented precedent that reason
    // vocabulary is endpoint-specific (see
    // src/api/routes/__tests__/errorCodeEndpointStatus.conformance.test.js).
  });
});

describe('Scenario 2 — provider in REGISTRY but disabled in CONFIGS ("local")', () => {
  const registry = { local: () => ({ output: 'ok' }) };
  const configs  = { local: { enabled: false } }; // registered, but not enabled

  test('/sign rejects auto-resolution (zero enabled providers)', async () => {
    const { app } = buildApps(registry, configs);
    const res = await signRequest(app, undefined);
    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('PROVIDER_REQUIRED');
    expect(res.body.details.enabledProviders).toEqual([]);
  });

  test('/sign rejects an explicit selection of the disabled provider', async () => {
    const { app } = buildApps(registry, configs);
    const res = await signRequest(app, { provider: 'local' });
    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('PROVIDER_NOT_CONFIGURED');
  });

  test('/ai/chat rejects execution against the disabled provider, same reason string as /sign', async () => {
    const { app, KEY } = buildApps(registry, configs);
    const artifact = signArtifactWithProvider(KEY, 'local');
    const res = await chatRequestWithArtifact(app, artifact);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('PROVIDER_NOT_CONFIGURED'); // identical reason string to /sign
  });
});

describe('Scenario 3 — a brand-new provider correctly added to BOTH REGISTRY and CONFIGS', () => {
  const registry = { brandnew: () => ({ output: 'brand new provider response' }) };
  const configs  = { brandnew: { enabled: true } };

  test('/sign automatically recognizes and auto-resolves to it — zero changes to sign.js required', async () => {
    const { app } = buildApps(registry, configs);
    const res = await signRequest(app, undefined);
    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.provider).toBe('brandnew');
  });

  test('/ai/chat executes it end-to-end using the artifact /sign minted', async () => {
    const { app } = buildApps(registry, configs);
    const signRes = await signRequest(app, undefined);
    const res = await chatRequestWithArtifact(app, signRes.body.artifact);
    expect(res.body.decision).toBe('EXECUTE');
    expect(res.body.response).toBe('brand new provider response');
  });
});

describe('Scenario 4 — renaming an existing provider leaves no stale name in sign.js', () => {
  // "openai" renamed to "openai-v2" in both REGISTRY and CONFIGS — the old
  // name no longer exists anywhere in the shared provider infrastructure.
  const registry = { 'openai-v2': () => ({ output: 'renamed provider response' }) };
  const configs  = { 'openai-v2': { enabled: true } };

  test('/sign auto-resolves to the renamed provider (sign.js has no hardcoded "openai" anywhere)', async () => {
    const { app } = buildApps(registry, configs);
    const res = await signRequest(app, undefined);
    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.provider).toBe('openai-v2');
  });

  test('/sign rejects the stale pre-rename name exactly like any other unregistered name', async () => {
    const { app } = buildApps(registry, configs);
    const res = await signRequest(app, { provider: 'openai' });
    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('PROVIDER_NOT_SUPPORTED');
  });

  test('/ai/chat also rejects an artifact bearing the stale pre-rename name', async () => {
    const { app, KEY } = buildApps(registry, configs);
    const artifact = signArtifactWithProvider(KEY, 'openai');
    const res = await chatRequestWithArtifact(app, artifact);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('PROVIDER_UNAVAILABLE');
  });

  test('/ai/chat executes the renamed provider end-to-end', async () => {
    const { app } = buildApps(registry, configs);
    const signRes = await signRequest(app, undefined);
    const res = await chatRequestWithArtifact(app, signRes.body.artifact);
    expect(res.body.decision).toBe('EXECUTE');
    expect(res.body.response).toBe('renamed provider response');
  });
});
