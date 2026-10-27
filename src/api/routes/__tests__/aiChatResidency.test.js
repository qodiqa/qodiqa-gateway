'use strict';

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * data residency on the real /ai/chat route. The artifact names provider "openai"; the DATA_RESIDENCY rule says where that provider processes.
 *   RS-01  provider in an allowed region: executes
 *   RS-02  provider in another region: BLOCK RESIDENCY_CROSS_REGION_BLOCKED, the provider is never called
 *   RS-03  provider with no declared region: BLOCK (fail closed)
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

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => resetStats());

const consent = { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } };
const res = (providerRegions, allowedRegions = ['eu']) => ({ id: 'POL-RES', type: 'DATA_RESIDENCY', priority: 5, enabled: true, config: { residencyFormat: 1, tenantRegion: 'eu', allowedRegions, providerRegions } });
const BODY = { prompt: 'Please help me with something ordinary.', model: 'gpt-4' };

function post(policies, providerFn) {
  const app = express();
  app.use(attachClientIp); app.use(express.json());
  const set = validateAndPrepare({ policies });
  app.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: providerFn, _getPolicies: () => set, _policyStore: createStore() }));
  const now = Date.now();
  const art = signBoundArtifact({ method: 'POST', path: '/ai/chat', body: BODY }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
  return supertest(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(art)).toString('base64')).send(BODY);
}
const provider = () => jest.fn(async () => ({ output: 'fine', model: 'gpt-4', executionMetadata: { responseId: 'r1' } }));

describe('data residency on /ai/chat', () => {
  test('RS-01 a provider in an allowed region executes', async () => {
    const p = provider();
    const r = await post([consent, res({ openai: 'eu' })], p);
    expect(r.body.decision).toBe('EXECUTE'); expect(p).toHaveBeenCalledTimes(1);
  });
  test('RS-02 a provider in another region is blocked before it is called', async () => {
    const p = provider();
    const r = await post([consent, res({ openai: 'us' })], p);
    expect(r.status).toBe(200); expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'RESIDENCY_CROSS_REGION_BLOCKED' });
    expect(p).not.toHaveBeenCalled();
  });
  test('RS-03 a provider with no declared region is blocked (fail closed)', async () => {
    const p = provider();
    const r = await post([consent, res({ local: 'eu' })], p);
    expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'RESIDENCY_PROVIDER_REGION_UNKNOWN' });
    expect(p).not.toHaveBeenCalled();
  });
});
