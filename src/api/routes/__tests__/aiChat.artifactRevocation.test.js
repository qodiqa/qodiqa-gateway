'use strict';

/**
 * Per-artifact revocation on /ai/chat: a revoked artifact is refused after its signature and binding are verified and
 * before its nonce is consumed — no provider call, an ordinary audited BLOCK, and the same artifact works again if the
 * revocation is gone (the nonce was never spent).
 *
 * AAR-01  revoked ⇒ 200 BLOCK ARTIFACT_REVOKED (decision mode), provider never called, BLOCK recorded at stage VALIDATION
 * AAR-02  status mode ⇒ 403 (class artifact_invalid)
 * AAR-03  a not-revoked artifact next to it is unaffected
 */

jest.mock('../../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));
const mockRegister = jest.fn();
jest.mock('../../../core/transparency/registrar', () => ({ register: (...a) => mockRegister(...a) }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const express = require('express');
const supertest = require('supertest');

const createAiChatRouter = require('../aiChat');
const attachClientIp = require('../../../../middleware/clientIp');
const { signBoundArtifact } = require('../../../validation/signBoundArtifact');
const { getActiveKey } = require('../../../../services/artifact/keyStore');
const { resetStats } = require('../../../../services/execution-guard');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore } = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const artifactRevocation = require('../../../core/artifactRevocation');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => {
  resetStats();
  mockRegister.mockReset();
  mockRegister.mockResolvedValue({ transparencyId: 'tid-1', entryHash: 'e'.repeat(64), signature: 'sig', keyId: 'tr-default:key_v1', persisted: true });
});

const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
const POLICIES = validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
const POLICY_STORE = createStore();
function buildArtifact() {
  const now = Date.now();
  return signBoundArtifact({ method: 'POST', path: '/ai/chat', body: CHAT_BODY }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 60_000, publicKeyId: KEY.keyId }, KEY.privDer);
}
function makeApp(provider) {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: provider, _getPolicies: () => POLICIES, _policyStore: POLICY_STORE }));
  return app;
}
const post = (app, a) => supertest(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(a)).toString('base64')).send(CHAT_BODY);
const revoke = (a) => artifactRevocation.revoke({ requestId: a.payload.requestId, operatorId: 'op-alice', reason: 'test' });

describe('AAR — revoked artifact on /ai/chat', () => {
  test('AAR-01 refused before the provider, as an audited BLOCK at the VALIDATION stage', async () => {
    const provider = jest.fn(() => Promise.resolve({ output: 'never' }));
    const app = makeApp(provider);
    const a = buildArtifact();
    await revoke(a);
    const res = await post(app, a);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'ARTIFACT_REVOKED' });
    expect(provider).not.toHaveBeenCalled();
    const blocks = mockRegister.mock.calls.map(([r]) => r).filter((r) => r.payload.decision === 'BLOCK');
    expect(blocks).toHaveLength(1);
    expect(blocks[0].payload).toMatchObject({ reason: 'ARTIFACT_REVOKED', stage: 'VALIDATION' });
    expect(mockRegister.mock.calls.map(([r]) => r).some((r) => r.payload.decision === 'ALLOW')).toBe(false);
  });

  test('AAR-02 in status mode the BLOCK carries 403', async () => {
    process.env.QODIQA_BLOCK_HTTP_MODE = 'status';
    try {
      const app = makeApp(() => Promise.resolve({ output: 'x' }));
      const a = buildArtifact();
      await revoke(a);
      const res = await post(app, a);
      expect(res.status).toBe(403);
      expect(res.body.reason).toBe('ARTIFACT_REVOKED');
    } finally { delete process.env.QODIQA_BLOCK_HTTP_MODE; }
  });

  test('AAR-03 a different artifact is unaffected', async () => {
    const provider = jest.fn(() => Promise.resolve({ output: 'fine' }));
    const app = makeApp(provider);
    await revoke(buildArtifact());                    // some other artifact
    const res = await post(app, buildArtifact());
    expect(res.body.decision).toBe('EXECUTE');
    expect(provider).toHaveBeenCalledTimes(1);
  });
});
