'use strict';

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * ABAC rules on the real /ai/chat route and on the tool authorisation.
 *   AC-01  model allow-list (attribute from the body)
 *   AC-02  a declared purpose is required (REQUIRE refuses when it is missing)
 *   AC-03  data classification limit: the gateway classifies the request (DLP classifier) and refuses above the limit
 *   AC-04  the same decision on /verify/v2 (a dry run sees the same attributes)
 *   AC-05  tool scope: a rule on the tool class refuses at authorisation, before anything is reserved
 */

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
const T = require('../../../../services/policy/abac/templates');
const { luhn } = require('../../../../enterprise/dlp/detectors');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => resetStats());

const consent = { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 100, enabled: true, config: { requireValidArtifact: true } };
const card = (() => { const b = '411111111111111'; for (let c = 0; c < 10; c++) if (luhn(b + c)) return b + c; throw new Error('x'); })();

function app(rules, providerFn) {
  const a = express(); a.use(attachClientIp); a.use(express.json());
  const set = validateAndPrepare({ policies: [consent, ...rules] });
  a.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: providerFn, _getPolicies: () => set, _policyStore: createStore() }));
  return a;
}
function post(a, body) {
  const now = Date.now();
  const art = signBoundArtifact({ method: 'POST', path: '/ai/chat', body }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
  return supertest(a).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(art)).toString('base64')).send(body);
}
const provider = () => jest.fn(async () => ({ output: 'fine', model: 'gpt-4', executionMetadata: { responseId: 'r1' } }));

describe('ABAC on /ai/chat', () => {
  test('AC-01 model allow-list', async () => {
    const p = provider(); const a = app([T.modelAllowList(['gpt-4'])], p);
    expect((await post(a, { prompt: 'hello there', model: 'gpt-4' })).body.decision).toBe('EXECUTE');
    const r = await post(a, { prompt: 'hello there', model: 'gpt-4o' });
    expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'ABAC_MODEL_NOT_ALLOWED' }); expect(p).toHaveBeenCalledTimes(1);
  });
  test('AC-02 a declared purpose is required', async () => {
    const p = provider(); const a = app([T.purposeRequired(['support', 'billing'])], p);
    expect((await post(a, { prompt: 'hello there', model: 'gpt-4' })).body).toMatchObject({ decision: 'BLOCK', reason: 'ABAC_PURPOSE_NOT_DECLARED' });
    expect((await post(a, { prompt: 'hello there', model: 'gpt-4', purpose: 'marketing' })).body.reason).toBe('ABAC_PURPOSE_NOT_DECLARED');
    expect((await post(a, { prompt: 'hello there', model: 'gpt-4', purpose: 'support' })).body.decision).toBe('EXECUTE');
    expect(p).toHaveBeenCalledTimes(1);
  });
  test('AC-03 data classification limit', async () => {
    const p = provider(); const a = app([T.dataClassLimit('INTERNAL')], p);
    expect((await post(a, { prompt: 'what is the weather like', model: 'gpt-4' })).body.decision).toBe('EXECUTE');
    const r = await post(a, { prompt: `my card is ${card}`, model: 'gpt-4' });
    expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'ABAC_DATA_CLASS_TOO_HIGH' });
    expect((await post(a, { prompt: 'Strictly confidential: merger plan', model: 'gpt-4' })).body.reason).toBe('ABAC_DATA_CLASS_TOO_HIGH');
    expect(p).toHaveBeenCalledTimes(1);
  });
  test('AC-03b a conversation is classified as a whole (the most sensitive message counts)', async () => {
    const a = app([T.dataCategoryDeny(['CARD'])], provider());
    const r = await post(a, { model: 'gpt-4', messages: [{ role: 'user', content: 'hi' }, { role: 'assistant', content: 'hello' }, { role: 'user', content: `pay with ${card}` }] });
    expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'ABAC_DATA_CATEGORY_DENIED' });
  });
  test('AC-04 /verify/v2 reaches the same decision', async () => {
    const createVerifyRouter = require('../verify');
    const set = validateAndPrepare({ policies: [consent, T.modelAllowList(['gpt-4'])] });
    const a = express(); a.use(attachClientIp); a.use(express.json());
    a.use('/verify', createVerifyRouter({ _dryRunNonceStore: { async isRegistered() { return false; } }, _dryRunAnomalyStore: { async peek() { return { count: 0 }; } }, _thresholds: { WINDOW_MS: 60_000, PER_KEY_MAX: 1_000_000, GLOBAL_MAX: 1_000_000 }, _getPolicies: () => set, _policyStore: createStore() }));
    const verify = (body) => { const now = Date.now(); const art = signBoundArtifact({ method: 'POST', path: '/ai/chat', body }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
      return supertest(a).post('/verify/v2').send({ artifact: art, request: { method: 'POST', path: '/ai/chat', body } }); };
    const bad = await verify({ prompt: 'hello there', model: 'gpt-4o' });
    expect(bad.body).toMatchObject({ decision: 'BLOCK' }); expect(String(bad.body.reason)).toMatch(/ABAC_MODEL_NOT_ALLOWED/);
    expect((await verify({ prompt: 'hello there', model: 'gpt-4' })).body.decision).not.toBe('BLOCK');
  });
});
