'use strict';

/**
 * 2026-10-06 —.
 * A genuine provider failure on /ai/chat increments qodiqa_provider_failures_total{provider,code} with bounded labels;
 * a cancellation does not (it stays on qodiqa_provider_execution_cancelled_total); the HTTP outcome is unchanged.
 * Harness mirrors src/api/routes/__tests__/aiChatBlockEvidence.test.js (real router, real audit chain, stubbed deps).
 *
 *   PF-01 provider error with an UPPER_SNAKE code → {provider="openai", code=<code>} +1, request still fails (5xx)
 *   PF-02 provider error with an unbounded code    → {code="OTHER"} (no free-form label values)
 *   PF-03 provider cancellation                    → provider_failures_total unchanged, cancelled counter +1
 */

process.env.AI_CHAT_TIMEOUT_MS = '5000';

jest.mock('../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));
jest.mock('../../core/semantic/embeddingGate', () => ({ checkText: jest.fn().mockResolvedValue({ blocks: false }) }));

const express   = require('express');
const supertest = require('supertest');

const metrics                = require('../metrics');
const createAiChatRouter     = require('../../api/routes/aiChat');
const attachClientIp         = require('../../../middleware/clientIp');
const { signBoundArtifact }  = require('../../validation/signBoundArtifact');
const { getActiveKey }       = require('../../../services/artifact/keyStore');
const { resetStats }         = require('../../../services/execution-guard');
const { validateAndPrepare } = require('../../../services/policy/loader');
const { createStore }        = require('../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../testing/stores');
const { drainPendingWrites } = require('../../core/audit/audit-log');

jest.setTimeout(30_000);

const CHAT_PATH = '/ai/chat';
const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
const POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true },
}] });
let KEY;

function buildArtifact() {
  const now = Date.now();
  return signBoundArtifact({ method: 'POST', path: CHAT_PATH, body: CHAT_BODY },
    { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
}
function makeApp(provider) {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: provider,
    _getPolicies: () => POLICIES, _policyStore: createStore(),
  }));
  return app;
}
const post = (app) => supertest(app).post('/ai/chat')
  .set('x-qodiqa-artifact', Buffer.from(JSON.stringify(buildArtifact())).toString('base64')).send(CHAT_BODY);
const fail = (code) => () => Promise.reject(Object.assign(new Error('provider failed'), { code }));
const val = (m, key) => m._values.get(key) || 0;

beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => resetStats());
afterAll(async () => { await drainPendingWrites(); });

describe('provider failure counter', () => {
  test('PF-01 a provider error increments provider_failures_total with provider and code', async () => {
    const key = 'code="PROVIDER_UPSTREAM_502",provider="openai"';
    const before = val(metrics.providerFailuresTotal, key);
    const res = await post(makeApp(fail('PROVIDER_UPSTREAM_502')));
    expect(res.status).toBeGreaterThanOrEqual(500);
    expect(val(metrics.providerFailuresTotal, key)).toBe(before + 1);
  });

  test('PF-02 an unbounded error code is reported as OTHER', async () => {
    const key = 'code="OTHER",provider="openai"';
    const before = val(metrics.providerFailuresTotal, key);
    await post(makeApp(fail('weird code: <html>')));
    await post(makeApp(fail(undefined)));
    expect(val(metrics.providerFailuresTotal, key)).toBe(before + 2);
    expect([...metrics.providerFailuresTotal._values.keys()].filter((k) => /html|weird/.test(k))).toEqual([]);
  });

  test('PF-03 a cancellation is not a provider failure', async () => {
    const total = () => [...metrics.providerFailuresTotal._values.values()].reduce((a, b) => a + b, 0);
    const before = total();
    const cancelled0 = val(metrics.providerExecutionCancelledTotal, 'reason="PROVIDER_CANCELLED"');
    await post(makeApp(fail('PROVIDER_CANCELLED')));
    expect(total()).toBe(before);
    expect(val(metrics.providerExecutionCancelledTotal, 'reason="PROVIDER_CANCELLED"')).toBe(cancelled0 + 1);
  });
});
