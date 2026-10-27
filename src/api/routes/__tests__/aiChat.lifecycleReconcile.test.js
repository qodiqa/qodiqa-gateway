'use strict';

/**
 *. Acceptance L-1, L-2:
 *
 * Same harness as aiChat.auditFailClosed.test.js: appendMandatory is replaced per stage.
 *
 *   RL-1  the ALLOW append fails after the provider ran → 503, no content, lifecycle registered; while the store still
 *         fails nothing is appended and it stays pending; once it recovers ONE closing BLOCK DECISION is appended
 *         (requestId of the INTENT, reason PROVIDER_OUTCOME_UNRECORDED, executingProvider = dispatched provider,
 *         closes the lifecycle) and later retries append nothing more
 *   RL-2  a closing BLOCK that fails on the provider-error path is retried as the SAME record (its own reason)
 *   RL-3  a retry that finds the decision already in the chain ("already_executed") counts as closed
 */

jest.mock('../../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));
const mockAppendMandatory = jest.fn();
jest.mock('../../../core/audit/audit-log', () => ({ appendMandatory: (...args) => mockAppendMandatory(...args) }));
jest.mock('../../../../services/logger', () => ({ emit: () => {} }));

const express   = require('express');
const supertest = require('supertest');
const createAiChatRouter    = require('../aiChat');
const reconciler            = require('../../../core/audit/lifecycleReconciler');
const attachClientIp        = require('../../../../middleware/clientIp');
const { signBoundArtifact } = require('../../../validation/signBoundArtifact');
const { getActiveKey }      = require('../../../../services/artifact/keyStore');
const { resetStats }        = require('../../../../services/execution-guard');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');

let KEY; let appended; let failing;
beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => {
  resetStats(); reconciler._resetForTests(); appended = []; failing = new Set();
  mockAppendMandatory.mockReset();
  mockAppendMandatory.mockImplementation(async (fields, opts) => {
    const stage = opts && opts.stage;
    if (failing.has(stage) || failing.has('*')) { const e = new Error('AUDIT_PERSISTENCE_FAILED: store down'); e.code = 'AUDIT_PERSISTENCE_FAILED'; throw e; }
    if (appended.some((a) => a.fields.artifactId === fields.artifactId)) throw new Error(`already_executed: ${fields.artifactId}`);
    appended.push({ stage, fields });
    return { hash: String(appended.length).padStart(64, '0'), artifactId: fields.artifactId };
  });
});

const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
const POL = validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
function makeApp(providerFn) {
  const app = express();
  app.use(attachClientIp); app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: providerFn,
    _getPolicies: () => POL, _policyStore: createStore() }));
  return app;
}
function post(app) {
  const now = Date.now();
  const art = signBoundArtifact({ method: 'POST', path: '/ai/chat', body: CHAT_BODY },
    { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
  return supertest(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(art)).toString('base64')).send(CHAT_BODY);
}
const intents = () => appended.filter((a) => a.fields.entryType === 'INTENT');
const closers = (rid) => appended.filter((a) => a.fields.entryType === 'DECISION' && a.fields.requestId === rid);

test('RL-1 ALLOW append fails → 503; closed by ONE BLOCK PROVIDER_OUTCOME_UNRECORDED once the store recovers', async () => {
  failing.add('ALLOW');
  const res = await post(makeApp(() => Promise.resolve({ output: 'SECRET CONTENT' })));
  expect(res.status).toBe(503);
  expect(res.text).not.toContain('SECRET CONTENT');
  const rid = intents()[0].fields.requestId;
  expect(closers(rid)).toHaveLength(0);
  expect(reconciler.pendingCount()).toBe(1);

  failing.add('*');                                   // the store is still down: nothing appended, still pending
  expect(await reconciler.retryOpenLifecycles()).toEqual({ closed: 0, pending: 1 });
  expect(closers(rid)).toHaveLength(0);

  failing.clear();                                    // recovered
  expect(await reconciler.retryOpenLifecycles()).toEqual({ closed: 1, pending: 0 });
  const c = closers(rid);
  expect(c).toHaveLength(1);
  expect(c[0].fields).toMatchObject({ decision: 'BLOCK', entryType: 'DECISION', reason: 'PROVIDER_OUTCOME_UNRECORDED', requestId: rid,
    artifactId: rid, executingProvider: 'openai', stage: 'PROVIDER_EXECUTION' });
  expect(await reconciler.retryOpenLifecycles()).toEqual({ closed: 0, pending: 0 });
  expect(closers(rid)).toHaveLength(1);
});

test('RL-2 a closing BLOCK on the provider-error path is retried as the same record', async () => {
  failing.add('BLOCK');
  const err = Object.assign(new Error('upstream exploded'), { code: 'PROVIDER_ERROR' });
  const res = await post(makeApp(() => Promise.reject(err)));
  expect(res.status).toBeGreaterThanOrEqual(500);
  const rid = intents()[0].fields.requestId;
  expect(reconciler.pendingCount()).toBe(1);
  failing.clear();
  await reconciler.retryOpenLifecycles();
  const c = closers(rid);
  expect(c).toHaveLength(1);
  expect(c[0].fields).toMatchObject({ decision: 'BLOCK', reason: 'PROVIDER_ERROR', stage: 'PROVIDER_EXECUTION', requestId: rid, executingProvider: 'openai' });
  expect(reconciler.pendingCount()).toBe(0);
});

test('RL-3 a retry that finds the decision already recorded counts as closed', async () => {
  failing.add('ALLOW');
  await post(makeApp(() => Promise.resolve({ output: 'x' })));
  const rid = intents()[0].fields.requestId;
  appended.push({ stage: 'BLOCK', fields: { artifactId: rid, requestId: rid, entryType: 'DECISION' } });   // it did land
  failing.clear();
  expect(await reconciler.retryOpenLifecycles()).toEqual({ closed: 1, pending: 0 });
  expect(closers(rid)).toHaveLength(1);
});
