'use strict';

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * custom content rules on the real /ai/chat route.
 *   CC-01  input rule blocks before the provider; the matched text is not echoed
 *   CC-02  per-model threshold
 *   CC-03  output rule blocks the answer
 *   CC-04  DETECT lets the request through
 *   CC-05  stream: input rule refuses, output rule makes the stream unsupported
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

const consent = { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 100, enabled: true, config: { requireValidArtifact: true } };
const cr = (config, id = 'POL-CR') => ({ id, type: 'CONTENT_RULE', priority: 20, enabled: true, config: { contentFormat: 1, direction: 'input', action: 'BLOCK', ...config } });
const items = [{ id: 'proj', kind: 'phrase', value: 'project nightingale' }, { id: 'code', kind: 'regex', value: 'nx-[0-9]{4}' }];

function make(rules, providerFn) {
  const set = validateAndPrepare({ policies: [consent, ...rules] });
  const a = express(); a.use(attachClientIp); a.use(express.json());
  a.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: providerFn, _getPolicies: () => set, _policyStore: createStore() }));
  return (body) => {
    const now = Date.now();
    const art = signBoundArtifact({ method: 'POST', path: '/ai/chat', body }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
    return supertest(a).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(art)).toString('base64')).send(body);
  };
}
const ok = (text = 'fine') => jest.fn(async () => ({ output: text, model: 'gpt-4', tokenUsage: null, executionMetadata: { responseId: 'r1' } }));

describe('content rules on /ai/chat', () => {
  test('CC-01 an input rule blocks before the provider and never echoes the text', async () => {
    const p = ok(); const post = make([cr({ items, threshold: 1 })], p);
    const r = await post({ prompt: 'tell me about Project   Nightingale please', model: 'gpt-4' });
    expect(r.status).toBe(200); expect(r.body).toMatchObject({ decision: "BLOCK", reason: "CONTENT_RULE_BLOCKED" });
    expect(r.body.details.contentRule[0]).toMatchObject({ ruleId: 'POL-CR', items: ['proj'] });
    expect(JSON.stringify(r.body)).not.toMatch(/nightingale/i); expect(p).not.toHaveBeenCalled();
    expect((await post({ prompt: 'a harmless question', model: 'gpt-4' })).body.decision).toBe('EXECUTE');
  });
  test('CC-02 the threshold can differ per model', async () => {
    const p = ok(); const post = make([cr({ items, threshold: 2, thresholds: [{ models: ['strict'], threshold: 1 }] })], p);
    expect((await post({ prompt: 'project nightingale', model: 'gpt-4' })).body.decision).toBe('EXECUTE');
    expect((await post({ prompt: 'project nightingale', model: 'strict' })).body.reason).toBe('CONTENT_RULE_BLOCKED');
    expect((await post({ prompt: 'project nightingale and NX-1234', model: 'gpt-4' })).body.reason).toBe('CONTENT_RULE_BLOCKED');
  });
  test('CC-03 an output rule blocks the answer', async () => {
    const post = make([cr({ direction: 'output', items })], ok('the code is NX-4242'));
    const r = await post({ prompt: 'what is the code?', model: 'gpt-4' });
    expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'CONTENT_RULE_BLOCKED' }); expect(JSON.stringify(r.body)).not.toMatch(/4242/);
  });
  test('CC-04 DETECT lets the request through', async () => {
    const p = ok(); const post = make([cr({ action: 'DETECT', items })], p);
    expect((await post({ prompt: 'project nightingale', model: 'gpt-4' })).body.decision).toBe('EXECUTE'); expect(p).toHaveBeenCalledTimes(1);
  });
  test('CC-05 streaming: an input rule refuses, an output rule makes the stream unsupported', async () => {
    const a = await make([cr({ items })], ok())({ prompt: 'project nightingale', model: 'gpt-4', stream: true });
    expect(a.body.reason).toBe('CONTENT_RULE_BLOCKED');
    const b = await make([cr({ direction: 'output', items })], ok())({ prompt: 'hello there', model: 'gpt-4', stream: true });
    expect(b.body.reason).toBe('CONTENT_RULE_STREAMING_UNSUPPORTED');
  });
});
