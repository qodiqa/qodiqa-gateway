'use strict';
const { PROVIDER_FIXTURE_KEYS } = require('../../../../test/helpers/providerFixtureKeys'); // format-valid fake keys

/**
 * POST /sign — AI provider resolution.
 *
 * Root cause: /sign treated payload.provider as fully optional, but
 * src/api/routes/aiChat.js's _executeAI() has always required
 * artifact.payload.provider to be a non-empty string (MISSING_PROVIDER
 * otherwise) — so a signed artifact minted without it could never reach
 * EXECUTE at /ai/chat. docs/guides/quickstart.md's documented curl flow never set
 * payload.provider, leaving no documented path to a successful EXECUTE
 * request.
 *
 * Fix: /sign now resolves payload.provider itself — but ONLY for requests
 * bound to the AI chat execution path (request.path === '/ai/chat').
 * /sign is generic artifact-signing infrastructure used for arbitrary
 * paths (which binds to
 * /orders/create), so this suite also proves non-AI-chat signing is
 * completely unaffected.
 */

const request = require('supertest');
const express = require('express');

const PROVIDER_ENV_KEYS = [
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY',
  'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'LOCAL_BASE_URL',
];

// TRUST-1 remediation: /sign no longer accepts a shared QODIQA_SIGN_TOKEN —
// provision one signing identity, persisted to an isolated store file, ONCE
// up front. Every loadApp() call below does jest.resetModules() (needed for
// the provider-config env-freeze reset), which gives signingIdentityStore a
// fresh in-memory cache each time too — but since the identity is already
// persisted to disk at QODIQA_SIGNING_STORE_PATH, each fresh module instance
// finds it again on first access, exactly like the real key store does.
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
const { apiKey: SIGN_TOKEN } = provisionTestSigningIdentity({ tenantId: 'default' });

// Reloads services/providers/config (env-frozen at require time) and
// src/api/routes/sign fresh for each scenario, mirroring the pattern used by
// services/providers/__tests__/config.test.js.
function loadApp(providerEnv = {}) {
  jest.resetModules();

  for (const k of PROVIDER_ENV_KEYS) delete process.env[k];
  for (const [k, v] of Object.entries(providerEnv)) process.env[k] = v;

  process.env.QODIQA_CLIENT_ID  = 'default'; // provisioned by test/support/jest.setup.js

  const createSignRouter       = require('../sign');
  const { validateAndPrepare } = require('../../../../services/policy/loader');

  // /sign only needs a valid policy set to compute policyHash — it never
  // evaluates policies itself. Content is irrelevant to this suite.
  const policies = validateAndPrepare({ policies: [{
    id: 'POL-TEST', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
    config: { requireValidArtifact: true },
  }] });

  const app = express();
  app.use(express.json());
  app.use('/sign', createSignRouter(() => policies));
  return app;
}

function post(app, body) {
  return request(app)
    .post('/sign')
    .set('Content-Type', 'application/json')
    .set('Authorization', `Bearer ${SIGN_TOKEN}`)
    .send(body);
}

function aiChatSignBody(payload) {
  return {
    request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello, what is 2 + 2?' } },
    ...(payload !== undefined ? { payload } : {}),
  };
}

// remediation: loadApp() (used by every scenario in this file) deletes
// then rewrites PROVIDER_ENV_KEYS on process.env with no restoration — since
// process.env is shared for the lifetime of the Jest WORKER process (not
// just this file), the last scenario to run (loadApp({}), an AI-PROV-07/08
// zero-providers case) leaves all six keys deleted for every other test file
// that happens to share this worker afterward, including this machine's only
// configured provider (LOCAL_BASE_URL). Reproduced directly: confirmed
// LOCAL_BASE_URL goes from a real value to `undefined` after simulating this
// file's own mutation sequence. Snapshot/restore mirrors the correct pattern
// already used by test/serverStartupSmoke.test.js.
const _envSnapshot = {};
beforeAll(() => {
  for (const k of PROVIDER_ENV_KEYS) _envSnapshot[k] = process.env[k];
});
afterAll(() => {
  for (const k of PROVIDER_ENV_KEYS) {
    if (_envSnapshot[k] === undefined) delete process.env[k];
    else process.env[k] = _envSnapshot[k];
  }
});

describe('POST /sign — provider resolution for AI chat requests', () => {
  test('SIGN-PROV-01 auto-resolves to the single enabled provider when payload.provider is omitted', async () => {
    const app = loadApp({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    const res = await post(app, aiChatSignBody());

    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.provider).toBe('openai');
  });

  test('SIGN-PROV-02 documented Quickstart request body (no payload key at all) auto-resolves', async () => {
    const app = loadApp({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    // Exactly the body documented in docs/guides/quickstart.md's curl example.
    const res = await post(app, {
      request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello, what is 2 + 2?' } },
    });

    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.provider).toBe('openai');
    expect(typeof res.body.artifact.payload.requestHash).toBe('string');
  });

  test('SIGN-PROV-03 400 PROVIDER_REQUIRED when zero providers are enabled', async () => {
    const app = loadApp({});
    const res = await post(app, aiChatSignBody());

    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('PROVIDER_REQUIRED');
    expect(res.body.details.enabledProviders).toEqual([]);
  });

  test('SIGN-PROV-04 400 PROVIDER_REQUIRED when multiple providers are enabled and none specified', async () => {
    const app = loadApp({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai, ANTHROPIC_API_KEY: PROVIDER_FIXTURE_KEYS.anthropic });
    const res = await post(app, aiChatSignBody());

    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('PROVIDER_REQUIRED');
    expect(res.body.details.enabledProviders.slice().sort()).toEqual(['anthropic', 'openai']);
  });

  test('SIGN-PROV-05 explicit payload.provider is honored over auto-resolution', async () => {
    const app = loadApp({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai, ANTHROPIC_API_KEY: PROVIDER_FIXTURE_KEYS.anthropic });
    const res = await post(app, aiChatSignBody({ provider: 'anthropic' }));

    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.provider).toBe('anthropic');
  });

  test('SIGN-PROV-06 400 PROVIDER_NOT_SUPPORTED for an unregistered provider name', async () => {
    const app = loadApp({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    const res = await post(app, aiChatSignBody({ provider: 'not-a-real-provider' }));

    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('PROVIDER_NOT_SUPPORTED');
  });

  test('SIGN-PROV-07 400 PROVIDER_NOT_CONFIGURED for a registered but disabled provider', async () => {
    const app = loadApp({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai }); // anthropic registered, not enabled
    const res = await post(app, aiChatSignBody({ provider: 'anthropic' }));

    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('PROVIDER_NOT_CONFIGURED');
  });

  test('SIGN-PROV-08 empty-string payload.provider is treated as omitted (auto-resolves)', async () => {
    const app = loadApp({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    const res = await post(app, aiChatSignBody({ provider: '' }));

    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.provider).toBe('openai');
  });
});

describe('POST /sign — non-AI-chat requests are unaffected by provider resolution', () => {
  test('SIGN-PROV-09 signing a non-/ai/chat path with zero providers enabled still succeeds, and payload.provider stays absent', async () => {
    const app = loadApp({}); // zero providers enabled — would 400 for an /ai/chat-bound request
    const res = await post(app, {
      request: { method: 'POST', path: '/orders/create', body: { sku: 'SKU-1', quantity: 1 } },
      payload: { note: 'arbitrary application context' },
    });

    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.provider).toBeUndefined();
    expect(res.body.artifact.payload.note).toBe('arbitrary application context');
  });

  test('SIGN-PROV-10 an explicit but unregistered payload.provider on a non-/ai/chat path passes through unvalidated', async () => {
    const app = loadApp({}); // zero providers enabled
    const res = await post(app, {
      request: { method: 'POST', path: '/orders/create', body: {} },
      payload: { provider: 'not-a-real-provider' },
    });

    expect(res.status).toBe(200);
    expect(res.body.artifact.payload.provider).toBe('not-a-real-provider');
  });
});
