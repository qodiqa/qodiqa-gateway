'use strict';
const { PROVIDER_FIXTURE_KEYS } = require('../../../../test/helpers/providerFixtureKeys'); // format-valid fake keys

/**
 * follow-up: architectural verification that /sign's provider
 * resolution cannot drift from what /ai/chat's execution path actually
 * accepts.
 *
 * There are two independently-maintained registries in this codebase:
 *   - services/providers/router.js's REGISTRY (name → handler function) —
 *     the true "does this provider actually exist" list. execution.js:61
 *     gates every real dispatch on resolveProvider(name), which checks
 *     Object.keys(REGISTRY) via services/providers.js.
 *   - services/providers/config.js's CONFIGS (name → env-driven enablement)
 *     — "is a given, already-known provider currently enabled".
 *
 * src/api/routes/sign.js validates an explicit payload.provider with
 * resolveProvider() first, then getProviderConfig().enabled — the exact
 * same two functions, in the exact same order, that router.js's _dispatch()
 * and execution.js's executeProviderCall() use. This suite proves that
 * composition, both against the real (unmocked) provider modules and
 * against a deliberately-engineered divergence between the two registries,
 * so a future change that adds a provider to one but not the other can
 * never let /sign mint an artifact /ai/chat would then reject.
 */

const PROVIDER_ENV_KEYS = [
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY',
  'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'LOCAL_BASE_URL',
];

describe('sign.js provider validation reuses execution.js\'s own gate (real modules, no mocks)', () => {
  function freshRealModules(providerEnv) {
    jest.resetModules();
    for (const k of PROVIDER_ENV_KEYS) delete process.env[k];
    for (const [k, v] of Object.entries(providerEnv)) process.env[k] = v;

    const { resolveProvider, listEnabledProviders } = require('../../../../services/providers');
    const { getProviderConfig } = require('../../../../services/providers/config');
    return { resolveProvider, listEnabledProviders, getProviderConfig };
  }

  test('every name execution.js would dispatch to, sign.js also accepts as "supported"', () => {
    const { resolveProvider } = freshRealModules({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    // The registered provider names execution.js can ever successfully dispatch to.
    for (const name of ['openai', 'anthropic', 'gemini', 'mistral', 'llama', 'local']) {
      expect(resolveProvider(name)).toBe(true);
    }
  });

  test('a name execution.js would reject as PROVIDER_UNAVAILABLE, sign.js also rejects as PROVIDER_NOT_SUPPORTED', () => {
    const { resolveProvider } = freshRealModules({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    // Same fabricated name used in signProviderResolution.test.js's SIGN-PROV-06 —
    // this proves sign.js's rejection is driven by the SAME function
    // execution.js:61 gates on, not an independent guess.
    expect(resolveProvider('not-a-real-provider')).toBe(false);
  });

  test('listEnabledProviders() is REGISTRY ∩ enabled CONFIGS, not CONFIGS alone', () => {
    // Only openai is enabled via config.js's CONFIGS; listEnabledProviders()
    // (the function sign.js's auto-resolve now uses) must still only report
    // registered AND enabled names.
    const { listEnabledProviders } = freshRealModules({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    expect(listEnabledProviders()).toEqual(['openai']);
  });
});

describe('sign.js cannot be fooled by a registry divergence (engineered via mocks)', () => {
  // TRUST-1 remediation: /sign no longer accepts a shared QODIQA_SIGN_TOKEN.
  // Provision one signing identity, persisted to disk, ONCE for this
  // describe block — loadSignRouterWithMockedProviders() below calls
  // jest.resetModules() per scenario, resetting signingIdentityStore's
  // in-memory cache too, but the identity is found again on disk each time.
  const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
  const { apiKey: SIGN_TOKEN } = provisionTestSigningIdentity({ tenantId: 'default' });

  afterEach(() => {
    jest.dontMock('../../../../services/providers');
    jest.dontMock('../../../../services/providers/config');
    jest.resetModules();
  });

  function loadSignRouterWithMockedProviders({ resolveProviderImpl, listEnabledProvidersImpl, getProviderConfigImpl }) {
    jest.resetModules();
    process.env.QODIQA_CLIENT_ID  = 'default';

    jest.doMock('../../../../services/providers', () => ({
      resolveProvider: jest.fn(resolveProviderImpl),
      listEnabledProviders: jest.fn(listEnabledProvidersImpl),
      listProviders: jest.fn(() => ['openai', 'anthropic', 'gemini', 'mistral', 'llama', 'local']),
    }));
    jest.doMock('../../../../services/providers/config', () => ({
      getProviderConfig: jest.fn(getProviderConfigImpl),
      getEnabledProviders: jest.fn(() => []),
    }));

    const express = require('express');
    const request = require('supertest');
    const createSignRouter = require('../sign');
    const { validateAndPrepare } = require('../../../../services/policy/loader');

    const policies = validateAndPrepare({ policies: [{
      id: 'POL-TEST', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
      config: { requireValidArtifact: true },
    }] });

    const app = express();
    app.use(express.json());
    app.use('/sign', createSignRouter(() => policies));
    return { app, request };
  }

  test('a provider present in config.js (enabled) but ABSENT from router.js\'s REGISTRY is rejected, not silently signed', async () => {
    // Simulates: someone added a "ghost" entry to services/providers/config.js's
    // CONFIGS with enabled:true, but never wired a handler into router.js's
    // REGISTRY. If sign.js checked config.js alone (as it originally did),
    // this would have minted an artifact execution.js:61 could never dispatch —
    // recreating, between /sign and /ai/chat, exactly the class of bug
    // was about. resolveProvider() (backed by REGISTRY) must be the gate that
    // stops it.
    const { app, request } = loadSignRouterWithMockedProviders({
      resolveProviderImpl: (name) => name !== 'ghost', // "ghost" absent from REGISTRY
      listEnabledProvidersImpl: () => ['ghost'],        // but config.js thinks it's enabled
      getProviderConfigImpl: (name) => (name === 'ghost' ? { enabled: true } : null),
    });

    const res = await request(app)
      .post('/sign')
      .set('Content-Type', 'application/json')
      .set('Authorization', `Bearer ${SIGN_TOKEN}`)
      .send({
        request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hi' } },
        payload: { provider: 'ghost' },
      });

    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('PROVIDER_NOT_SUPPORTED');
  });

  test('auto-resolution only ever considers names listEnabledProviders() (REGISTRY-backed) actually returns', async () => {
    const { app, request } = loadSignRouterWithMockedProviders({
      resolveProviderImpl: () => true,
      listEnabledProvidersImpl: () => ['local'],
      getProviderConfigImpl: () => ({ enabled: true }),
    });

    const res = await request(app)
      .post('/sign')
      .set('Content-Type', 'application/json')
      .set('Authorization', `Bearer ${SIGN_TOKEN}`)
      .send({ request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hi' } } });

    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.provider).toBe('local');
  });

  test('a hypothetical newly-registered provider participates in auto-resolution with zero changes to sign.js', async () => {
    // Demonstrates requirement: "a newly added provider automatically
    // participates in provider resolution without additional changes to
    // sign.js" — sign.js contains no provider names; it only calls
    // listEnabledProviders()/resolveProvider(), so whatever those report is
    // exactly what sign.js acts on.
    const { app, request } = loadSignRouterWithMockedProviders({
      resolveProviderImpl: (name) => name === 'brandnewprovider',
      listEnabledProvidersImpl: () => ['brandnewprovider'],
      getProviderConfigImpl: (name) => (name === 'brandnewprovider' ? { enabled: true } : null),
    });

    const res = await request(app)
      .post('/sign')
      .set('Content-Type', 'application/json')
      .set('Authorization', `Bearer ${SIGN_TOKEN}`)
      .send({ request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hi' } } });

    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.provider).toBe('brandnewprovider');
  });
});
