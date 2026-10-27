'use strict';

/**
 * verification finding (3.14): when the provider has ALREADY executed and the mandatory transparency write then fails
 * (503), the Idempotency-Key reservation used to be released, so a retry with the same key and a fresh artifact called the
 * provider a second time. The reservation is now kept until its short TTL expires.
 */

process.env.IDEMPOTENCY_WAIT_TIMEOUT_MS = '400';

jest.mock('../../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));

const mockRegister = jest.fn();
jest.mock('../../../core/transparency/registrar', () => ({ register: (...a) => mockRegister(...a) }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const express   = require('express');
const supertest = require('supertest');
const createAiChatRouter    = require('../aiChat');
const requestId             = require('../../../../middleware/requestId');
const attachClientIp        = require('../../../../middleware/clientIp');
const { signBoundArtifact } = require('../../../validation/signBoundArtifact');
const { getActiveKey }      = require('../../../../services/artifact/keyStore');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore, makeIdempotencyStore } = require('../../../testing/stores');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });

const OK_REG = { transparencyId: 'tid-1', entryHash: 'e'.repeat(64), signature: 'sig', keyId: 'tr-default:key_v1', persisted: true };
const BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
const POLICIES = validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });

function artifact() {
  const now = Date.now();
  return signBoundArtifact({ method: 'POST', path: '/ai/chat', body: BODY },
    { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
}

test('F1-IDEM-01 after a post-provider transparency failure, a retry with the same key does not call the provider again', async () => {
  mockRegister.mockReset();
  // reject only the DECISION leaf (the INTENT leaf registers, so the provider IS called first)
  mockRegister.mockImplementation(async (r) => { if (r.payload.entryType) return OK_REG; throw new Error('transparency store down'); });
  const calls = { n: 0 };
  const app = express();
  app.use(requestId); app.use(attachClientIp); app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _getPolicies: () => POLICIES, _policyStore: createStore(),
    _idempotencyStore: makeIdempotencyStore(), _providerFn: async () => { calls.n += 1; return { output: 'x' }; },
  }));
  const send = () => supertest(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(artifact())).toString('base64'))
    .set('Idempotency-Key', 'f1-key-1').send(BODY);

  const first = await send();
  expect(first.status).toBe(503);
  expect(calls.n).toBe(1);

  const retry = await send();
  expect(calls.n).toBe(1);                      // before the fix: 2
  expect(retry.body.decision).toBe('BLOCK');
});
