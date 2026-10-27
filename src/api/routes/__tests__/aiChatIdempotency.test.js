'use strict';

// Mock consent registry — mirrors aiChat.test.js; the consent evaluator
// itself is tested in src/core/consent/.
jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * API-2 — POST /ai/chat Idempotency-Key end-to-end integration suite.
 *
 * Proves, at the full HTTP router level:
 *   1. A first request with an Idempotency-Key executes normally.
 *   2. An identical retry (same key, same body) replays the stored response
 *      WITHOUT invoking the provider again.
 *   3. Concurrent duplicate requests invoke the provider exactly once.
 *   4. A different Idempotency-Key executes independently.
 *   5. The same key with a different body is rejected (409/422), never
 *      silently treated as either a replay or a fresh request.
 *   6. Malformed / oversized keys are rejected before reaching the pipeline.
 *   7. Tenant isolation: identical key + identical body under a different
 *      tenant is an independent execution, never a cross-tenant replay.
 *   8. Idempotency-Key + streaming is explicitly rejected.
 *
 * All stores (nonce/anomaly/idempotency) are injected — no Redis required.
 * Provider calls are intercepted by _providerFn — no real provider calls.
 */

const express   = require('express');
const supertest = require('supertest');

const createAiChatRouter      = require('../aiChat');
const requestId                = require('../../../../middleware/requestId');
const attachClientIp          = require('../../../../middleware/clientIp');
const { signBoundArtifact }   = require('../../../validation/signBoundArtifact');
const { getActiveKey, rotateKey } = require('../../../../services/artifact/keyStore');
const { validateAndPrepare }  = require('../../../../services/policy/loader');
const { createStore }         = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore, makeIdempotencyStore } = require('../../../testing/stores');

let KEY;
let KEY_B;
beforeAll(() => {
  KEY = getActiveKey('default');
  try { rotateKey('idem-tenant-b'); } catch { /* already provisioned by an earlier test file in this worker */ }
  KEY_B = getActiveKey('idem-tenant-b');
});

const MOCK_RESPONSE = 'Mock AI response';
const CHAT_PATH  = '/ai/chat';
const CHAT_BODY  = { prompt: 'Hello, world!', model: 'gpt-4' };

function freshEnvelope(payload = {}, key = KEY) {
  const now = Date.now();
  return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: key.keyId };
}

function buildArtifact(reqBody = CHAT_BODY, extraPayload = {}, key = KEY) {
  const req = { method: 'POST', path: CHAT_PATH, body: reqBody };
  return signBoundArtifact(req, freshEnvelope({ provider: 'openai', ...extraPayload }, key), key.privDer);
}

function toHeader(artifact) {
  return Buffer.from(JSON.stringify(artifact)).toString('base64');
}

const _DEFAULT_POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });

function makeApp({ providerFn, idempotencyStore, callCounter } = {}) {
  const _policyStore = createStore();
  const _idemStore = idempotencyStore || makeIdempotencyStore();
  const _providerFn = providerFn || (async () => {
    if (callCounter) callCounter.count += 1;
    return { output: MOCK_RESPONSE };
  });

  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store:        makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _providerFn,
    _getPolicies:  () => _DEFAULT_POLICIES,
    _policyStore,
    _idempotencyStore: _idemStore,
  }));
  app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));
  return { app, idemStore: _idemStore };
}

async function post(app, artifact, body = CHAT_BODY, idempotencyKey) {
  const req = supertest(app).post('/ai/chat').set('x-qodiqa-artifact', toHeader(artifact));
  if (idempotencyKey !== undefined) req.set('Idempotency-Key', idempotencyKey);
  return req.send(body);
}

describe('POST /ai/chat — Idempotency-Key', () => {
  test('no Idempotency-Key header: behaves exactly as before (unaffected)', async () => {
    const { app } = makeApp();
    const res = await post(app, buildArtifact());
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
    expect(res.headers['idempotency-key']).toBeUndefined();
  });

  test('first request with a key executes normally and echoes the key', async () => {
    const { app } = makeApp();
    const res = await post(app, buildArtifact(), CHAT_BODY, 'first-key-1');
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
    expect(res.body.response).toBe(MOCK_RESPONSE);
    expect(res.headers['idempotency-key']).toBe('first-key-1');
    expect(res.headers['idempotency-replayed']).toBeUndefined();
  });

  test('identical retry (same key, same body) replays — provider is NOT invoked again', async () => {
    const callCounter = { count: 0 };
    const { app, idemStore } = makeApp({ callCounter });

    const first = await post(app, buildArtifact(), CHAT_BODY, 'retry-key-1');
    expect(first.status).toBe(200);
    expect(callCounter.count).toBe(1);

    // A retry re-signs a fresh artifact (new requestId/timestamp — exactly
    // what a real client does after a timeout) but sends the SAME
    // Idempotency-Key and the SAME body.
    const second = await post(app, buildArtifact(), CHAT_BODY, 'retry-key-1');
    expect(second.status).toBe(200);
    expect(second.body.decision).toBe('EXECUTE');
    expect(second.body.response).toBe(first.body.response);
    expect(second.body.artifactId).toBe(first.body.artifactId); // same canonical execution
    expect(second.body.transparency).toEqual(first.body.transparency);
    expect(second.headers['idempotency-replayed']).toBe('true');
    expect(callCounter.count).toBe(1); // provider still called exactly once

    void idemStore; // sanity: store instance is shared/injected correctly (used above implicitly)
  });

  test('requestId in the response body reflects the CURRENT call, even on replay', async () => {
    const { app } = makeApp();
    const first  = await post(app, buildArtifact(), CHAT_BODY, 'reqid-key');
    const second = await post(app, buildArtifact(), CHAT_BODY, 'reqid-key');
    expect(second.status).toBe(200);
    // requestId is a per-HTTP-call correlation id (middleware/requestId.js) —
    // it must differ between two separate HTTP calls even though everything
    // else about the (replayed) response is identical.
    expect(typeof second.body.requestId).toBe('string');
    expect(typeof first.body.requestId).toBe('string');
    expect(second.body.requestId).not.toBe(first.body.requestId);
  });

  test('concurrent duplicate requests: provider invoked exactly once', async () => {
    let callCount = 0;
    const providerFn = async () => {
      callCount += 1;
      await new Promise((r) => setTimeout(r, 60));
      return { output: MOCK_RESPONSE };
    };
    const { app } = makeApp({ providerFn });

    const [r1, r2] = await Promise.all([
      post(app, buildArtifact(), CHAT_BODY, 'concurrent-key-1'),
      post(app, buildArtifact(), CHAT_BODY, 'concurrent-key-1'),
    ]);

    expect(callCount).toBe(1);
    const statuses = [r1.status, r2.status].sort();
    // Both may observe 200 (one proceed, one replay) depending on timing —
    // the invariant that matters is single provider execution, asserted above.
    expect(statuses.every((s) => s === 200 || s === 409)).toBe(true);
    const succeeded = [r1, r2].filter((r) => r.status === 200);
    expect(succeeded.length).toBeGreaterThanOrEqual(1);
    // Every 200 response carries the SAME canonical artifactId.
    const artifactIds = new Set(succeeded.map((r) => r.body.artifactId));
    expect(artifactIds.size).toBe(1);
  });

  test('audit 3.15 — N=25 simultaneous requests, one Idempotency-Key, 25 distinct artifacts: exactly ONE execution, 24 replays, one identical result', async () => {
    let callCount = 0;
    const providerFn = async () => {
      callCount += 1;
      await new Promise((r) => setTimeout(r, 120));
      return { output: MOCK_RESPONSE };
    };
    const { app } = makeApp({ providerFn });
    const N = 25;

    const responses = await Promise.all(
      Array.from({ length: N }, () => post(app, buildArtifact(), CHAT_BODY, 'concurrent-key-N')),
    );

    expect(callCount).toBe(1);                                              // the provider ran once
    expect(responses.map((r) => r.status)).toEqual(Array(N).fill(200));     // nobody was rejected or double-executed
    const replays = responses.filter((r) => r.headers['idempotency-replayed'] === 'true');
    expect(replays).toHaveLength(N - 1);                                    // exactly one original, N-1 replays
    expect(new Set(responses.map((r) => r.body.artifactId)).size).toBe(1);  // one result for all
    expect(new Set(responses.map((r) => r.body.response)).size).toBe(1);
    expect(responses.filter((r) => r.headers['idempotency-replayed'] !== 'true')).toHaveLength(1);
  });

  test('different Idempotency-Key: independent execution, provider invoked twice', async () => {
    const callCounter = { count: 0 };
    const { app } = makeApp({ callCounter });

    const r1 = await post(app, buildArtifact(), CHAT_BODY, 'independent-key-a');
    const r2 = await post(app, buildArtifact(), CHAT_BODY, 'independent-key-b');

    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(callCounter.count).toBe(2);
    expect(r1.body.artifactId).not.toBe(r2.body.artifactId);
  });

  test('same key, different body: rejected, never replayed and never silently executed', async () => {
    const callCounter = { count: 0 };
    const { app } = makeApp({ callCounter });

    const first = await post(app, buildArtifact(CHAT_BODY), CHAT_BODY, 'conflict-key');
    expect(first.status).toBe(200);
    expect(callCounter.count).toBe(1);

    const differentBody = { prompt: 'A completely different prompt', model: 'gpt-4' };
    const second = await post(app, buildArtifact(differentBody), differentBody, 'conflict-key');
    // API-9 remediation: a reused idempotency key is a conflict (409), matching
    // IDEMPOTENCY_REQUEST_IN_PROGRESS — not a 422 business-rule/unprocessable failure.
    expect(second.status).toBe(409);
    expect(second.body.decision).toBe('BLOCK');
    expect(second.body.reason).toBe('IDEMPOTENCY_KEY_CONFLICT');
    expect(callCounter.count).toBe(1); // provider never invoked for the conflicting attempt
  });

  test('malformed key (contains whitespace) is rejected before the pipeline runs', async () => {
    const { app } = makeApp();
    const res = await post(app, buildArtifact(), CHAT_BODY, 'has a space');
    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('IDEMPOTENCY_KEY_INVALID');
  });

  test('oversized key is rejected with 413', async () => {
    const { app } = makeApp();
    const res = await post(app, buildArtifact(), CHAT_BODY, 'x'.repeat(300));
    expect(res.status).toBe(413);
    expect(res.body.reason).toBe('IDEMPOTENCY_KEY_TOO_LARGE');
  });

  test('tenant isolation: identical key + identical body under a different tenant executes independently', async () => {
    const callCounter = { count: 0 };
    const { app, idemStore } = makeApp({ callCounter });

    const r1 = await post(app, buildArtifact(CHAT_BODY, {}, KEY), CHAT_BODY, 'shared-key-across-tenants');
    expect(r1.status).toBe(200);

    const r2 = await post(app, buildArtifact(CHAT_BODY, {}, KEY_B), CHAT_BODY, 'shared-key-across-tenants');
    expect(r2.status).toBe(200);

    expect(callCounter.count).toBe(2); // NOT a replay across tenants
    expect(r2.headers['idempotency-replayed']).toBeUndefined();
    expect(r1.body.artifactId).not.toBe(r2.body.artifactId);
    void idemStore;
  });

  test('Idempotency-Key + streaming is explicitly rejected', async () => {
    const { app } = makeApp();
    const streamingBody = { ...CHAT_BODY, stream: true };
    const res = await post(app, buildArtifact(streamingBody), streamingBody, 'stream-key');
    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('IDEMPOTENCY_STREAMING_UNSUPPORTED');
  });

  test('a request blocked before reaching the idempotency gate never poisons the key — a corrected retry succeeds', async () => {
    // Tampering the signature fails validateBoundRequest's Step 1 — before
    // tenantId is even resolved, so the idempotency gate never engages at
    // all (no reservation is made). Confirms an unrelated early failure
    // under a given key can never block a subsequent legitimate attempt
    // under that same key.
    const callCounter = { count: 0 };
    const { app } = makeApp({ callCounter });

    const tampered = { ...buildArtifact(), signature: Buffer.alloc(64).toString('base64') }; // invalid signature
    const blocked = await post(app, tampered, CHAT_BODY, 'recover-key');
    expect(blocked.status).toBe(200);
    expect(callCounter.count).toBe(0);

    const recovered = await post(app, buildArtifact(), CHAT_BODY, 'recover-key');
    expect(recovered.status).toBe(200);
    expect(callCounter.count).toBe(1);
  });
});
