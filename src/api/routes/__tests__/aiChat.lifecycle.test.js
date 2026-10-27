'use strict';

/**
 * audit schema v7 — /ai/chat INTENT lifecycle.
 *
 *   AL-01  order: INTENT audit entry → INTENT transparency leaf → provider call → DECISION entry → DECISION leaf;
 *          INTENT carries the fixed values + suffixed artifact id; DECISION carries outputHash(delivered response) and
 *          executingProvider
 *   AL-02  INTENT audit append fails → provider NEVER called, 503 AUDIT_PERSISTENCE_FAILED, no content, a best-effort
 *          BLOCK DECISION (stage PROVIDER_DISPATCH, executingProvider null) closes the lifecycle, CRITICAL + metric INTENT
 *   AL-03  INTENT transparency leaf fails → provider NEVER called, 503 TRANSPARENCY_PERSISTENCE_FAILED
 *   AL-04  R-14: the INTENT append refused for want of a subject pseudonym → provider NEVER called, 503
 *   AL-05  provider error after dispatch → BLOCK DECISION with executingProvider = the dispatched provider, nothing delivered
 *   AL-06  BLOCK before dispatch (replay) → no INTENT at all; DECISION executingProvider null
 */

jest.mock('../../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));

const mockLog = [];
const mockAppendMandatory = jest.fn();
jest.mock('../../../core/audit/audit-log', () => ({ appendMandatory: (...a) => mockAppendMandatory(...a) }));
const mockRegister = jest.fn();
jest.mock('../../../core/transparency/registrar', () => ({ register: (...a) => mockRegister(...a) }));
const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ emit: (...a) => mockEmit(...a) }));

const express   = require('express');
const supertest = require('supertest');
const createAiChatRouter    = require('../aiChat');
const attachClientIp        = require('../../../../middleware/clientIp');
const { signBoundArtifact } = require('../../../validation/signBoundArtifact');
const { getActiveKey }      = require('../../../../services/artifact/keyStore');
const { resetStats }        = require('../../../../services/execution-guard');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { outputHashOf }       = require('../../../core/audit/entryBuilder');
const metrics = require('../../../observability/metrics');

const RESPONSE = 'v7 delivered output — é 😀';
let providerCalls = 0;
let providerImpl = null;
async function mockProvider() { providerCalls++; mockLog.push('provider'); return providerImpl ? providerImpl() : { output: RESPONSE }; }

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => {
  resetStats(); mockLog.length = 0; providerCalls = 0; providerImpl = null;
  mockAppendMandatory.mockReset();
  mockAppendMandatory.mockImplementation(async (f, o) => { mockLog.push(`append:${o && o.stage}`); return { hash: 'h'.repeat(64), artifactId: f.artifactId }; });
  mockRegister.mockReset();
  mockRegister.mockImplementation(async (r) => { mockLog.push(`leaf:${r.payload.entryType || r.payload.decision}`); return { transparencyId: 'tid', entryHash: 'e'.repeat(64), signature: 's', keyId: 'tr-default:key_v1', persisted: true }; });
  mockEmit.mockClear();
  jest.spyOn(metrics.auditFailClosedRejectionsTotal, 'inc');
});
afterEach(() => { metrics.auditFailClosedRejectionsTotal.inc.mockRestore(); });

const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
function buildArtifact() {
  const now = Date.now();
  return signBoundArtifact({ method: 'POST', path: '/ai/chat', body: CHAT_BODY }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
}
const POLICIES = validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
const STORE = createStore();
function makeApp() {
  const app = express();
  app.use(attachClientIp); app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: mockProvider, _getPolicies: () => POLICIES, _policyStore: STORE }));
  return app;
}
const post = (app, a) => supertest(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(a)).toString('base64')).send(CHAT_BODY);
const appended = (stage) => mockAppendMandatory.mock.calls.filter(([, o]) => o && o.stage === stage).map(([f]) => f);

describe('v7 — /ai/chat INTENT lifecycle', () => {
  test('AL-01 INTENT (entry + leaf) precedes the provider call; DECISION binds the delivered output', async () => {
    const res = await post(makeApp(), buildArtifact());
    expect(res.status).toBe(200);
    expect(res.body.response).toBe(RESPONSE);
    expect(mockLog).toEqual(['append:INTENT', 'leaf:INTENT', 'provider', 'append:ALLOW', 'leaf:ALLOW']);
    const [intent] = appended('INTENT');
    const [dec] = appended('ALLOW');
    expect(intent).toMatchObject({ entryType: 'INTENT', decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', outputHash: null, reason: null, tokenUsage: null,
      artifactId: `${dec.artifactId}:intent`, requestId: dec.requestId, executingProvider: 'openai', provider: 'openai', verificationResult: true,
      executionContext: expect.objectContaining({ stage: 'PROVIDER_DISPATCH', provider: 'openai' }) });
    expect(dec).toMatchObject({ entryType: 'DECISION', decision: 'ALLOW', outputHash: outputHashOf(RESPONSE), executingProvider: 'openai' });
    const intentLeaf = mockRegister.mock.calls[0][0];
    expect(intentLeaf).toMatchObject({ artifactId: `${dec.artifactId}:intent`, payload: expect.objectContaining({ entryType: 'INTENT', decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', requestId: dec.requestId }) });
  });

  test('AL-02 INTENT audit append fails → provider never called, 503 AUDIT_PERSISTENCE_FAILED, BLOCK DECISION closes the lifecycle', async () => {
    mockAppendMandatory.mockImplementation(async (f, o) => {
      mockLog.push(`append:${o && o.stage}`);
      if (o && o.stage === 'INTENT') throw Object.assign(new Error('AUDIT_PERSISTENCE_FAILED: ENOSPC'), { code: 'AUDIT_PERSISTENCE_FAILED' });
      return { hash: 'h'.repeat(64), artifactId: f.artifactId };
    });
    const res = await post(makeApp(), buildArtifact());
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'AUDIT_PERSISTENCE_FAILED' });
    expect(JSON.stringify(res.body)).not.toContain(RESPONSE);
    expect(providerCalls).toBe(0);
    expect(mockLog).not.toContain('provider');
    const [blk] = appended('BLOCK');
    expect(blk).toMatchObject({ decision: 'BLOCK', entryType: 'DECISION', stage: 'PROVIDER_DISPATCH', executingProvider: null, reason: 'AUDIT_PERSISTENCE_FAILED' });
    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'AUDIT_APPEND_FAILED', expect.objectContaining({ stage: 'INTENT' }));
    expect(metrics.auditFailClosedRejectionsTotal.inc).toHaveBeenCalledWith({ stage: 'INTENT' });
  });

  test('AL-03 INTENT transparency leaf fails → provider never called, 503 TRANSPARENCY_PERSISTENCE_FAILED', async () => {
    mockRegister.mockImplementation(async (r) => { if (r.payload.entryType === 'INTENT') throw new Error('signing key unavailable'); return { transparencyId: 't', entryHash: 'e'.repeat(64), signature: 's', keyId: 'k', persisted: true }; });
    const res = await post(makeApp(), buildArtifact());
    expect(res.status).toBe(503);
    expect(res.body.reason).toBe('TRANSPARENCY_PERSISTENCE_FAILED');
    expect(providerCalls).toBe(0);
    expect(appended('INTENT')).toHaveLength(1);                                     // the entry itself was recorded …
    expect(appended('BLOCK')[0]).toMatchObject({ stage: 'PROVIDER_DISPATCH', executingProvider: null });   // … and closed
  });

  test('AL-04 R-14: the INTENT refused for want of a subject pseudonym → provider never called, 503', async () => {
    mockAppendMandatory.mockImplementation(async (f, o) => {
      if (o && o.stage === 'INTENT') throw Object.assign(new Error('subject_pseudonym_unavailable: v7 audit entries require the subject pseudonym'), { code: 'SUBJECT_PSEUDONYM_UNAVAILABLE' });
      return { hash: 'h'.repeat(64), artifactId: f.artifactId };
    });
    const res = await post(makeApp(), buildArtifact());
    expect(res.status).toBe(503);
    expect(res.body.reason).toBe('AUDIT_PERSISTENCE_FAILED');
    expect(providerCalls).toBe(0);
  });

  test('AL-05 provider error after dispatch → BLOCK DECISION with executingProvider set and nothing delivered', async () => {
    providerImpl = () => { throw Object.assign(new Error('upstream down'), { code: 'PROVIDER_UNAVAILABLE' }); };
    const res = await post(makeApp(), buildArtifact());
    expect(res.status).toBe(503);
    expect(providerCalls).toBe(1);
    const [blk] = appended('BLOCK');
    expect(blk).toMatchObject({ decision: 'BLOCK', entryType: 'DECISION', stage: 'PROVIDER_EXECUTION', reason: 'PROVIDER_UNAVAILABLE', executingProvider: 'openai' });
    expect(blk.outputHash).toBeUndefined();   // BLOCK → entryBuilder states the empty-bytes hash
    expect(mockLog.indexOf('append:INTENT')).toBeLessThan(mockLog.indexOf('provider'));
  });

  test('AL-06 a BLOCK before dispatch (replay) writes no INTENT and records executingProvider null', async () => {
    const app = makeApp(); const a = buildArtifact();
    await post(app, a);
    mockAppendMandatory.mockClear(); mockLog.length = 0;
    const res = await post(app, a);
    expect(res.body.reason).toBe('REPLAY_DETECTED');
    expect(appended('INTENT')).toHaveLength(0);
    expect(appended('BLOCK')[0]).toMatchObject({ entryType: 'DECISION', executingProvider: null });
  });
});
