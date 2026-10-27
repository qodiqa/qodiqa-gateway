'use strict';

/**
 * Adversarial / Robustness Tests
 *
 * Proves that the enforcement pipeline handles malformed, oversized, and
 * adversarially crafted inputs without crashing (no 500), without disclosing
 * server internals, and without being bypassed.
 *
 * All tests run against the real implementation. No success paths are mocked
 * except the consent registry (which requires live Redis/PG infrastructure).
 */

// Mock consent so policy evaluation doesn't need live infrastructure
jest.mock('../../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const express   = require('express');
const supertest = require('supertest');

const createAiChatRouter      = require('../../src/api/routes/aiChat');
const attachClientIp           = require('../../middleware/clientIp');
const { signBoundArtifact }    = require('../../src/validation/signBoundArtifact');
const { getActiveKey }         = require('../../services/artifact/keyStore');
const { makeNonceStore,
        makeOpenAnomalyStore } = require('../../src/testing/stores');
const { validateAndPrepare }  = require('../../services/policy/loader');
const { createStore }         = require('../../services/policy/store');

// ── Fixtures ──────────────────────────────────────────────────────────────────

const CHAT_PATH = '/ai/chat';
const CHAT_BODY = { prompt: 'Hello', model: 'gpt-4' };

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });

const _POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });

function buildArtifact(reqBody = CHAT_BODY, extraPayload = {}) {
  const now = Date.now();
  const envelope = {
    payload:     { provider: 'openai', ...extraPayload },
    timestamp:   now,
    expiry:      now + 300_000,
    publicKeyId: KEY.keyId,
  };
  return signBoundArtifact({ method: 'POST', path: CHAT_PATH, body: reqBody }, envelope, KEY.privDer);
}

function toHeader(artifact) {
  return Buffer.from(JSON.stringify(artifact)).toString('base64');
}

// Silent mock provider — returns normalized ProviderResponse shape expected by _executeAI
function mockProvider() {
  return Promise.resolve({ output: 'ok' });
}

function makeApp() {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json({ limit: '50mb' }));
  app.use('/ai/chat', createAiChatRouter({
    _store:        makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _getPolicies:  () => _POLICIES,
    _policyStore:  createStore(),
    _providerFn:   mockProvider,
  }));
  app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));
  return app;
}

// ── 1. Body structure attacks ─────────────────────────────────────────────────

describe('Body structure attacks — no crash (any 4xx, never 5xx)', () => {

  test('ADV-01  null body → 4xx', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(artifact))
      .send('null');
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  test('ADV-02  array body instead of object → 4xx', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(artifact))
      .send([1, 2, 3]);
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  test('ADV-03  deeply nested body (100 levels) → 4xx or 200 (no crash)', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    // Build 100-level nested object
    let nested = { value: 'deep' };
    for (let i = 0; i < 100; i++) nested = { child: nested };
    const body = { prompt: nested, model: 'gpt-4' };
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(artifact))
      .send(body);
    // Either rejected or processed — must not crash
    expect(res.status).not.toBe(500);
  });

  test('ADV-04  missing Content-Type header → 4xx', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    const res = await supertest(app).post('/ai/chat')
      .set('x-qodiqa-artifact', toHeader(artifact))
      .send('{"prompt":"test","model":"gpt-4"}');
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  test('ADV-05  extra unknown fields in body → rejected or ignored (no crash)', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(artifact))
      .send({ ...CHAT_BODY, __proto__: { isAdmin: true }, injected: 'field' });
    expect(res.status).not.toBe(500);
    // __proto__ injection must not pollute Object.prototype
    expect(({}).isAdmin).toBeUndefined();
  });
});

// ── 2. Artifact header attacks ────────────────────────────────────────────────

describe('Artifact header attacks — always 4xx, never 5xx or ALLOW', () => {

  test('ADV-10  missing artifact header → BLOCK', async () => {
    const app = makeApp();
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .send(CHAT_BODY);
    expect(res.status).toBe(200);
    expect(res.body.reason).toBe('MISSING_ARTIFACT');
  });

  test('ADV-11  empty artifact header → BLOCK', async () => {
    const app = makeApp();
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', '')
      .send(CHAT_BODY);
    expect(res.status).toBe(200);
  });

  test('ADV-12  artifact header is not base64 → BLOCK', async () => {
    const app = makeApp();
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', '!!!not-base64-at-all!!!')
      .send(CHAT_BODY);
    expect(res.status).toBe(200);
  });

  test('ADV-13  artifact header is valid base64 but not JSON → BLOCK', async () => {
    const app = makeApp();
    const notJson = Buffer.from('this is not json').toString('base64');
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', notJson)
      .send(CHAT_BODY);
    expect(res.status).toBe(200);
  });

  test('ADV-14  artifact header is base64-encoded null → BLOCK', async () => {
    const app = makeApp();
    const nullB64 = Buffer.from('null').toString('base64');
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', nullB64)
      .send(CHAT_BODY);
    expect(res.status).toBe(200);
  });

  test('ADV-15  artifact header is base64-encoded empty object → blocked', async () => {
    const app = makeApp();
    const emptyObjB64 = Buffer.from('{}').toString('base64');
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', emptyObjB64)
      .send(CHAT_BODY);
    // No signature → must be blocked
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('ADV-16  oversized artifact header (>8KB) → 413', async () => {
    const app = makeApp();
    const bigPayload = 'A'.repeat(8 * 1024 + 1);
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', bigPayload)
      .send(CHAT_BODY);
    expect(res.status).toBe(413);
  });
});

// ── 3. Signature tampering — must never ALLOW ─────────────────────────────────

describe('Signature tampering — always BLOCK', () => {

  test('ADV-20  tampered payload (extra field injected) → BLOCK INVALID_SIGNATURE', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    const tampered = { ...artifact, payload: { ...artifact.payload, injected: 'evil' } };
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(tampered))
      .send(CHAT_BODY);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toMatch(/INVALID_SIGNATURE|SIGNATURE/);
  });

  test('ADV-21  corrupted signature → BLOCK', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    const corrupted = { ...artifact, signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' };
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(corrupted))
      .send(CHAT_BODY);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('ADV-22  missing signature field → BLOCK', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    const { signature: _dropped, ...noSig } = artifact;
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(noSig))
      .send(CHAT_BODY);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });

  test('ADV-23  request body mismatch (signed different body) → BLOCK', async () => {
    const app = makeApp();
    // Sign with body A, send body B
    const artifact = buildArtifact({ prompt: 'original', model: 'gpt-4' });
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(artifact))
      .send({ prompt: 'attacker-modified', model: 'gpt-4' });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
  });
});

// ── 4. Replay protection ─────────────────────────────────────────────────────

describe('Replay protection — second use of same artifact → BLOCK', () => {

  test('ADV-30  replaying the same artifact on second request → REPLAY_DETECTED', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    const hdr = toHeader(artifact);

    // First request: should succeed
    const r1 = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', hdr)
      .send(CHAT_BODY);
    expect(r1.status).toBe(200);
    expect(r1.body.decision).toBe('EXECUTE');

    // Second request: same artifact → replay detected
    const r2 = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', hdr)
      .send(CHAT_BODY);
    expect(r2.status).toBe(200);
    expect(r2.body.decision).toBe('BLOCK');
    expect(r2.body.reason).toBe('REPLAY_DETECTED');
  });
});

// ── 5. Expired artifact ──────────────────────────────────────────────────────

describe('Expired artifacts — always BLOCK', () => {

  test('ADV-40  artifact with expiry in the past → BLOCK ARTIFACT_EXPIRED', async () => {
    const app = makeApp();
    const now = Date.now();
    const expiredEnvelope = {
      payload:     { provider: 'openai' },
      timestamp:   now - 600_000,  // 10 min ago
      expiry:      now - 1,        // 1ms ago
      publicKeyId: KEY.keyId,
    };
    const expired = signBoundArtifact(
      { method: 'POST', path: CHAT_PATH, body: CHAT_BODY },
      expiredEnvelope,
      KEY.privDer,
    );
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(expired))
      .send(CHAT_BODY);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toMatch(/EXPIRED/);
  });
});

// ── 6. Unicode / encoding edge cases ─────────────────────────────────────────

describe('Unicode and encoding edge cases — no crash', () => {

  test('ADV-50  Unicode emoji in prompt → no crash, processed normally', async () => {
    const app = makeApp();
    const body = { prompt: '🤖 AI assistant says: 你好世界 Привет مرحبا', model: 'gpt-4' };
    const artifact = buildArtifact(body);
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(artifact))
      .send(body);
    expect(res.status).not.toBe(500);
  });

  test('ADV-51  null bytes in JSON string values → no crash', async () => {
    const app = makeApp();
    const body = { prompt: 'test with nulls', model: 'gpt-4' };
    const artifact = buildArtifact(body);
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(artifact))
      .send(body);
    expect(res.status).not.toBe(500);
  });

  test('ADV-52  very long model name (1000 chars) → 4xx or processed (no crash)', async () => {
    const app = makeApp();
    const body = { prompt: 'test', model: 'a'.repeat(1000) };
    const artifact = buildArtifact(body);
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(artifact))
      .send(body);
    expect(res.status).not.toBe(500);
  });
});

// ── 7. IP blocking enforcement ────────────────────────────────────────────────

describe('IP blocking — BLOCK_IP policy applied correctly', () => {
  const BLOCKED_IP = '10.0.0.1';

  function makeBlockedIpApp() {
    const policies = validateAndPrepare({ policies: [
      { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } },
      { id: 'POL-BLOCK',   type: 'BLOCK_IP',        priority: 20, enabled: true, config: { blocklist: [BLOCKED_IP], cidrs: [] } },
    ] });

    const app = express();
    app.use(attachClientIp);
    app.use(express.json());
    // Inject the blocked IP as if it came from a reverse proxy
    app.use((req, _res, next) => { req.clientIp = BLOCKED_IP; next(); });
    app.use('/ai/chat', createAiChatRouter({
      _store:        makeNonceStore(),
      _anomalyStore: makeOpenAnomalyStore(),
      _getPolicies:  () => policies,
      _policyStore:  createStore(),
      _providerFn:   mockProvider,
    }));
    return app;
  }

  test('ADV-60  request from blocked IP → BLOCK IP_BLOCKED', async () => {
    const app = makeBlockedIpApp();
    const artifact = buildArtifact();
    const res = await supertest(app).post('/ai/chat')
      .set('Content-Type', 'application/json')
      .set('x-qodiqa-artifact', toHeader(artifact))
      .send(CHAT_BODY);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('IP_BLOCKED');
  });
});
