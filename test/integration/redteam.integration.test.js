'use strict';

// Mock consent registry — red team tests verify replay protection, tampering
// detection, and enforcement correctness; consent is tested in src/core/consent/.
jest.mock('../../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * RED TEAM INTEGRATION TEST SUITE
 *
 * Proves that AI execution through /ai/chat is correctly enforced end-to-end.
 * Uses supertest against an in-process express app — no real server required.
 * Provider calls are intercepted by _providerFn — no real API calls.
 */

const express    = require('express');
const supertest  = require('supertest');
const crypto     = require('crypto');

const createAiChatRouter    = require('../../src/api/routes/aiChat');
const { signBoundArtifact } = require('../../src/validation/signBoundArtifact');
const { signArtifact }      = require('../../src/validation/signArtifact');
const { rotateKey, getActiveKey } = require('../../services/artifact/keyStore');
const { validateAndPrepare } = require('../../services/policy/loader');
const { createStore }        = require('../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../helpers/sharedMocks');

// ── Shared state ──────────────────────────────────────────────────────────────

let KEY;
let app;
let agent;

// A single nonce store shared across the whole suite — replay tests depend on
// nonces remaining registered between requests in the same test.
const NONCE_STORE = makeNonceStore();

const ANOMALY_STORE = makeOpenAnomalyStore();

const _POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });
const _POLICY_STORE = createStore();

function mockProvider() {
  return Promise.resolve({ output: 'Mock AI response' });
}

// ── App setup ─────────────────────────────────────────────────────────────────

beforeAll(() => {
  rotateKey('inttest');
  KEY = getActiveKey('inttest');

  app = express();
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store:        NONCE_STORE,
    _anomalyStore: ANOMALY_STORE,
    _providerFn:   mockProvider,
    _getPolicies:  () => _POLICIES,
    _policyStore:  _POLICY_STORE,
  }));

  agent = supertest(app);
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildArtifact(requestBody) {
  const now = Date.now();
  return Buffer.from(JSON.stringify(
    signBoundArtifact(
      { method: 'POST', path: '/ai/chat', body: requestBody },
      { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    ),
  )).toString('base64');
}

// ═════════════════════════════════════════════════════════════════════════════
// TEST CASES
// ═════════════════════════════════════════════════════════════════════════════

// ── 1. Missing artifact ───────────────────────────────────────────────────────

describe('RED TEAM 1 — Missing artifact', () => {
  const body = { prompt: 'test-missing', model: 'gpt-3.5-turbo' };

  test('1a. No x-qodiqa-artifact header → BLOCK', async () => {
    const res = await agent.post('/ai/chat').send(body);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('MISSING_ARTIFACT');
  });

  test('1b. Empty string header → BLOCK', async () => {
    const res = await agent.post('/ai/chat').set('x-qodiqa-artifact', '').send(body);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('MISSING_ARTIFACT');
  });
});

// ── 2. Invalid artifact ───────────────────────────────────────────────────────

describe('RED TEAM 2 — Invalid artifact', () => {
  const body = { prompt: 'test-invalid', model: 'gpt-3.5-turbo' };

  test('2a. Random bytes (not valid JSON) → BLOCK', async () => {
    const garbage = crypto.randomBytes(128).toString('base64');
    const res     = await agent.post('/ai/chat').set('x-qodiqa-artifact', garbage).send(body);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('2b. Valid JSON but wrong shape {evil:true} → BLOCK', async () => {
    const hdr = Buffer.from(JSON.stringify({ evil: true })).toString('base64');
    const res  = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('2c. Forged full envelope — random signature → BLOCK', async () => {
    const now   = Date.now();
    const forged = {
      expiry:      now + 300_000,
      payload:     { provider: 'openai', requestHash: 'a'.repeat(64), requestId: crypto.randomUUID() },
      publicKeyId: KEY.keyId,
      signature:   crypto.randomBytes(64).toString('base64'),
      timestamp:   now,
    };
    const hdr = Buffer.from(JSON.stringify(forged)).toString('base64');
    const res  = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('2d. Artifact signed for wrong path /other → BLOCK (request binding)', async () => {
    const now = Date.now();
    const artifact = signBoundArtifact(
      { method: 'POST', path: '/other', body },
      { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const hdr = Buffer.from(JSON.stringify(artifact)).toString('base64');
    const res  = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('2e. Artifact signed for wrong HTTP method → BLOCK', async () => {
    const now = Date.now();
    const artifact = signBoundArtifact(
      { method: 'GET', path: '/ai/chat', body },
      { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const hdr = Buffer.from(JSON.stringify(artifact)).toString('base64');
    const res  = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('2f. Expired artifact → BLOCK', async () => {
    const now = Date.now();
    const artifact = signBoundArtifact(
      { method: 'POST', path: '/ai/chat', body },
      { payload: { provider: 'openai' }, timestamp: now - 400_000, expiry: now - 100_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const hdr = Buffer.from(JSON.stringify(artifact)).toString('base64');
    const res  = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });
});

// ── 3. Tampered body ──────────────────────────────────────────────────────────

describe('RED TEAM 3 — Tampered body', () => {
  test('3a. Artifact signed for body A, request sends body B → BLOCK', async () => {
    const originalBody = { prompt: 'original-prompt', model: 'gpt-3.5-turbo' };
    const tamperedBody = { prompt: 'injected-payload', model: 'gpt-3.5-turbo' };
    const hdr = buildArtifact(originalBody);
    const res  = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(tamperedBody);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('3b. Extra field injected into body → BLOCK', async () => {
    const originalBody = { prompt: 'hello-test', model: 'gpt-3.5-turbo' };
    const tamperedBody = { prompt: 'hello-test', model: 'gpt-3.5-turbo', admin: true };
    const hdr = buildArtifact(originalBody);
    const res  = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(tamperedBody);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('3c. Model field swapped → BLOCK', async () => {
    const originalBody = { prompt: 'model-swap', model: 'gpt-3.5-turbo' };
    const tamperedBody = { prompt: 'model-swap', model: 'gpt-4' };
    const hdr = buildArtifact(originalBody);
    const res  = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(tamperedBody);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });
});

// ── 4. Replay attack ──────────────────────────────────────────────────────────

describe('RED TEAM 4 — Replay attack', () => {
  test('4a. Same artifact submitted twice — second must BLOCK', async () => {
    const body    = { prompt: `replay-${crypto.randomUUID()}`, model: 'gpt-3.5-turbo' };
    const hdr     = buildArtifact(body);

    const first  = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body);
    const second = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body);

    expect(second.status).toBe(200);
    expect(second.body.decision).toBe('BLOCK');
  });

  test('4b. Three rapid submissions of same artifact — at most one ALLOW', async () => {
    const body    = { prompt: `replay3-${crypto.randomUUID()}`, model: 'gpt-3.5-turbo' };
    const hdr     = buildArtifact(body);

    const [r1, r2, r3] = await Promise.all([
      agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body),
      agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body),
      agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body),
    ]);

    // BLOCK is also HTTP 200 now — distinguish by body.decision, not status.
    const results = [r1, r2, r3];
    const blocked = results.filter(r => r.body.decision === 'BLOCK');
    const allowed = results.filter(r => r.body.decision === 'EXECUTE');

    expect(allowed.length).toBeLessThanOrEqual(1);
    expect(blocked.length).toBeGreaterThanOrEqual(2);
  });
});

// ── 5. /proxy/openai — does not exist in this app ────────────────────────────

describe('RED TEAM 5 — POST /proxy/openai', () => {
  test('5a. /proxy/openai is not registered — 404', async () => {
    const res = await agent.post('/proxy/openai').send({ prompt: 'bypass', model: 'gpt-3.5-turbo' });
    expect(res.status).toBe(404);
  });

  test('5b. /proxy/openai with artifact header — still 404', async () => {
    const body = { prompt: 'proxy-with-artifact', model: 'gpt-3.5-turbo' };
    const hdr  = buildArtifact(body);
    const res  = await agent.post('/proxy/openai').set('x-qodiqa-artifact', hdr).send(body);
    expect(res.status).toBe(404);
  });
});

// ── 6. Direct call to execution layer — gate ──────────────────────────────────

describe('RED TEAM 6 — executeProviderCall execution gate', () => {
  const { executeProviderCall } = require('../../services/execution');

  test('6a. No verifiedCtx (undefined) → throws UNVERIFIED_EXECUTION_ATTEMPT', () => {
    return expect(
      executeProviderCall('openai', { messages: [] }, undefined),
    ).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('6b. verifiedCtx = null → throws UNVERIFIED_EXECUTION_ATTEMPT', () => {
    return expect(
      executeProviderCall('openai', { messages: [] }, null),
    ).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('6c. verifiedCtx.verified = false → throws UNVERIFIED_EXECUTION_ATTEMPT', () => {
    return expect(
      executeProviderCall('openai', { messages: [] }, {
        verified: false, requestHash: 'a'.repeat(64), artifactId: 'id',
      }),
    ).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('6d. verifiedCtx.verified = "true" (string coercion) → throws UNVERIFIED_EXECUTION_ATTEMPT', () => {
    return expect(
      executeProviderCall('openai', { messages: [] }, {
        verified: 'true', requestHash: 'a'.repeat(64), artifactId: 'id',
      }),
    ).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('6e. Missing requestHash → throws UNVERIFIED_EXECUTION_ATTEMPT', () => {
    return expect(
      executeProviderCall('openai', { messages: [] }, { verified: true, artifactId: 'id' }),
    ).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('6f. requestHash invalid format (not 64-char hex) → throws UNVERIFIED_EXECUTION_ATTEMPT', () => {
    return expect(
      executeProviderCall('openai', { messages: [] }, {
        verified: true, requestHash: 'not-hex', artifactId: 'id',
      }),
    ).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('6g. Missing artifactId → throws UNVERIFIED_EXECUTION_ATTEMPT', () => {
    return expect(
      executeProviderCall('openai', { messages: [] }, {
        verified: true, requestHash: 'a'.repeat(64),
      }),
    ).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('6h. Empty string artifactId → throws UNVERIFIED_EXECUTION_ATTEMPT', () => {
    return expect(
      executeProviderCall('openai', { messages: [] }, {
        verified: true, requestHash: 'a'.repeat(64), artifactId: '',
      }),
    ).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });
});

// ── 7. /mock/openai — does not exist in this app ─────────────────────────────

describe('RED TEAM 7 — POST /mock/openai', () => {
  test('7a. /mock/openai is not registered — 404', async () => {
    const res = await agent.post('/mock/openai').send({ messages: [{ role: 'user', content: 'bypass' }] });
    expect(res.status).toBe(404);
  });

  test('7b. /mock/openai empty body — 404', async () => {
    const res = await agent.post('/mock/openai').send({});
    expect(res.status).toBe(404);
  });
});

// ── 8. Valid request → ALLOW ──────────────────────────────────────────────────

describe('RED TEAM 8 — Valid request → EXECUTE', () => {
  test('8a. Correctly signed artifact with matching body → 200 EXECUTE with response', async () => {
    const body = { prompt: `redteam-valid-${crypto.randomUUID()}`, model: 'gpt-3.5-turbo' };
    const hdr  = buildArtifact(body);
    const res  = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
    expect(typeof res.body.response).toBe('string');
    expect(res.body.response.length).toBeGreaterThan(0);
    expect(typeof res.body.artifactId).toBe('string');
    expect(res.body.artifactId.length).toBeGreaterThan(0);
  });

  test('8b. Response artifactId matches payload.requestId of signed artifact', async () => {
    const body        = { prompt: `binding-${crypto.randomUUID()}`, model: 'gpt-3.5-turbo' };
    const now         = Date.now();
    const artifactObj = signBoundArtifact(
      { method: 'POST', path: '/ai/chat', body },
      { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const hdr = Buffer.from(JSON.stringify(artifactObj)).toString('base64');
    const res = await agent.post('/ai/chat').set('x-qodiqa-artifact', hdr).send(body);
    expect(res.status).toBe(200);
    expect(res.body.artifactId).toBe(artifactObj.payload.requestId);
  });

  test('8c. Two consecutive requests with distinct artifacts both → 200 EXECUTE', async () => {
    const body1 = { prompt: `seq-1-${crypto.randomUUID()}`, model: 'gpt-3.5-turbo' };
    const body2 = { prompt: `seq-2-${crypto.randomUUID()}`, model: 'gpt-3.5-turbo' };
    const [res1, res2] = await Promise.all([
      agent.post('/ai/chat').set('x-qodiqa-artifact', buildArtifact(body1)).send(body1),
      agent.post('/ai/chat').set('x-qodiqa-artifact', buildArtifact(body2)).send(body2),
    ]);
    expect(res1.status).toBe(200);
    expect(res1.body.decision).toBe('EXECUTE');
    expect(res2.status).toBe(200);
    expect(res2.body.decision).toBe('EXECUTE');
  });
});
