'use strict';

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * DLP on the real /ai/chat route: the DLP rules of the policy set are applied to what the provider receives and to what the caller receives.
 *   DC-01  input REDACT: the provider never sees the e-mail address; the caller gets the answer; the request binding (signed over the ORIGINAL body) still holds
 *   DC-02  input BLOCK: provider not called, decision BLOCK, reason DLP_BLOCKED
 *   DC-03  output REDACT: an address in the answer is replaced before delivery
 *   DC-04  output BLOCK, and a stream is refused while an output rule is configured
 *   DC-05  fail closed without a token key
 *   DC-06  no DLP rule: behaviour unchanged (the provider receives the text untouched)
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
beforeAll(() => { KEY = getActiveKey('default'); process.env.QODIQA_DLP_TOKEN_KEY = 'z'.repeat(40); });
afterAll(() => { delete process.env.QODIQA_DLP_TOKEN_KEY; });
beforeEach(() => resetStats());

const MAIL = 'jane.roe@example.org';
const CHAT_PATH = '/ai/chat';
const consent = { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } };
const dlp = (config, id = 'POL-DLP') => ({ id, type: 'DLP', priority: 50, enabled: true, config: { dlpFormat: 1, direction: 'input', action: 'REDACT', rules: ['EMAIL'], ...config } });
const policiesOf = (...extra) => validateAndPrepare({ policies: [consent, ...extra] });

function buildArtifact(body) {
  const now = Date.now();
  return signBoundArtifact({ method: 'POST', path: CHAT_PATH, body }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
}
const header = (a) => Buffer.from(JSON.stringify(a)).toString('base64');

function makeApp(policies, providerFn) {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: providerFn, _getPolicies: () => policies, _policyStore: createStore() }));
  return app;
}
const post = (app, body) => supertest(app).post('/ai/chat').set('x-qodiqa-artifact', header(buildArtifact(body))).send(body);
const provider = (output) => jest.fn(async () => ({ output, model: 'gpt-4', executionMetadata: { responseId: 'r1' } }));

describe('DLP on /ai/chat', () => {
  test('DC-01 input REDACT: the provider never receives the address, the caller still gets an answer', async () => {
    const p = provider('Understood.');
    const body = { prompt: `Please write to ${MAIL} about the invoice`, model: 'gpt-4' };
    const res = await post(makeApp(policiesOf(dlp({})), p), body);
    expect(res.status).toBe(200); expect(res.body.decision).toBe('EXECUTE'); expect(res.body.response).toBe('Understood.');
    expect(p).toHaveBeenCalledTimes(1);
    const sent = JSON.stringify(p.mock.calls[0]);
    expect(sent).not.toContain('jane.roe'); expect(sent).toMatch(/\[\[EMAIL:[0-9a-f]{12}\]\]/);
  });

  test('DC-02 input BLOCK: the provider is not called', async () => {
    const p = provider('x');
    const res = await post(makeApp(policiesOf(dlp({ action: 'BLOCK' })), p), { prompt: `my mail is ${MAIL}`, model: 'gpt-4' });
    expect(res.status).toBe(200); expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'DLP_BLOCKED' });
    expect(res.body.details.dlp).toEqual({ direction: 'input', rules: ['EMAIL'] });
    expect(p).not.toHaveBeenCalled(); expect(JSON.stringify(res.body)).not.toContain('jane.roe');
  });

  test('DC-03 output REDACT: the answer is redacted before delivery', async () => {
    const p = provider(`Sure, contact ${MAIL} for details.`);
    const res = await post(makeApp(policiesOf(dlp({ direction: 'output' })), p), { prompt: 'Who do I contact?', model: 'gpt-4' });
    expect(res.status).toBe(200); expect(res.body.decision).toBe('EXECUTE');
    expect(res.body.response).toMatch(/^Sure, contact \[\[EMAIL:[0-9a-f]{12}\]\] for details\.$/);
    expect(JSON.stringify(res.body)).not.toContain('jane.roe');
  });

  test('DC-04 output BLOCK withholds the answer; a stream is refused while an output rule exists', async () => {
    const app = makeApp(policiesOf(dlp({ direction: 'output', action: 'BLOCK' })), provider(`mail ${MAIL}`));
    const res = await post(app, { prompt: 'Who do I contact?', model: 'gpt-4' });
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'DLP_BLOCKED' }); expect(JSON.stringify(res.body)).not.toContain('jane.roe');
    const sres = await post(app, { prompt: 'Who do I contact?', model: 'gpt-4', stream: true });
    expect(sres.body).toMatchObject({ decision: 'BLOCK', reason: 'DLP_OUTPUT_STREAMING_UNSUPPORTED' });
  });

  test('DC-05 fail closed: REDACT without a token key blocks', async () => {
    const saved = process.env.QODIQA_DLP_TOKEN_KEY; delete process.env.QODIQA_DLP_TOKEN_KEY;
    try {
      const p = provider('x');
      const res = await post(makeApp(policiesOf(dlp({})), p), { prompt: 'hello there', model: 'gpt-4' });
      expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'DLP_UNAVAILABLE' }); expect(p).not.toHaveBeenCalled();
    } finally { process.env.QODIQA_DLP_TOKEN_KEY = saved; }
  });

  test('DC-06 without a DLP rule nothing changes', async () => {
    const p = provider('ok');
    const res = await post(makeApp(policiesOf(), p), { prompt: `mail ${MAIL}`, model: 'gpt-4' });
    expect(res.body.decision).toBe('EXECUTE'); expect(JSON.stringify(p.mock.calls[0])).toContain('jane.roe');
  });
  test('DC-07 exfiltration on the answer: data the caller typed is not new; data the model adds is', async () => {
    const pol = policiesOf(dlp({ direction: 'output', action: 'DETECT', rules: ['*'], exfiltration: { action: 'BLOCK' } }));
    const echoed = await post(makeApp(pol, provider(`You wrote ${MAIL}.`)), { prompt: `my address is ${MAIL}`, model: 'gpt-4' });
    expect(echoed.body.decision).toBe('EXECUTE');
    const added = await post(makeApp(pol, provider('The account holder is other.person@example.net.')), { prompt: 'who is the account holder?', model: 'gpt-4' });
    expect(added.body).toMatchObject({ decision: 'BLOCK', reason: 'DLP_BLOCKED' }); expect(added.body.details.dlp.rules).toContain('EXFIL:NEW_SENSITIVE_IN_OUTPUT');
  });
});
