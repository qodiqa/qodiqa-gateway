'use strict';

/**
 * A request cancelled while its INTENT evidence entry is being written must not start the provider call, and its budget reservation is returned.
 *
 * AAI-01  the latency limit fires during the INTENT write: the provider is never called and the reservation is refunded (the next request is not refused)
 * AAI-02  the same cancellation arriving after the provider was called keeps the estimate charged (unchanged behaviour, so the repair does not refund too much)
 */

jest.mock('../../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));

const mockAppendMandatory = jest.fn();
jest.mock('../../../core/audit/audit-log', () => ({ appendMandatory: (...args) => mockAppendMandatory(...args) }));

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
const { resolveDefaultModel } = require('../../../../services/providers/config');

const LIMIT_MS = 4321;   // an unusual value, so that only this policy's timer is replaced
let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => { resetStats(); mockAppendMandatory.mockReset(); });

const consent = { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 100, enabled: true, config: { requireValidArtifact: true } };
const budget = { id: 'B', type: 'BUDGET', priority: 50, enabled: true, config: { budgetFormat: 1, scope: 'tenant', period: 'day', limits: { requests: 1 }, perRequest: { maxLatencyMs: LIMIT_MS } } };
const DEF = resolveDefaultModel('openai');

function make(providerFn) {
  const store = createStore(); const set = validateAndPrepare({ policies: [consent, budget] });
  const app = express(); app.use(attachClientIp); app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: providerFn, _getPolicies: () => set, _policyStore: store }));
  return (body) => {
    const now = Date.now();
    const art = signBoundArtifact({ method: 'POST', path: '/ai/chat', body }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
    return supertest(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(art)).toString('base64')).send(body);
  };
}

/** every timer armed for the policy's limit is ours; the others stay real */
function ownLatencyClock() {
  const real = AbortSignal.timeout.bind(AbortSignal); const armed = [];
  const spy = jest.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => { if (ms !== LIMIT_MS) return real(ms); const c = new AbortController(); armed.push(c); return c.signal; });
  const expire = () => armed.shift().abort(new DOMException('The operation was aborted due to timeout', 'TimeoutError'));
  return { spy, expire };
}

describe('cancellation during the INTENT write', () => {
  test('AAI-01 the provider is not called and the reservation is returned', async () => {
    const clock = ownLatencyClock();
    try {
      const provider = jest.fn(async () => ({ output: 'fine', model: 'm', tokenUsage: null, executionMetadata: { responseId: 'r' } }));
      let first = true;
      mockAppendMandatory.mockImplementation(async (fields, opts) => {
        if (first && opts && opts.stage === 'INTENT') { first = false; clock.expire(); }   // the limit fires while the INTENT entry is being written
        return { hash: 'i'.repeat(64), artifactId: fields.artifactId };
      });
      const post = make(provider);
      const r1 = await post({ prompt: 'cancelled during intent', model: DEF });
      expect(r1.body.decision).not.toBe('EXECUTE');
      expect(provider).not.toHaveBeenCalled();
      // the reservation went back: a second request fits into limits.requests = 1 and is served
      const r2 = await post({ prompt: 'next request', model: DEF });
      expect(r2.body.decision).toBe('EXECUTE');
      expect(provider).toHaveBeenCalledTimes(1);
    } finally { clock.spy.mockRestore(); }
  });

  test('AAI-02 a limit that fires after the provider was called stays charged', async () => {
    const clock = ownLatencyClock();
    try {
      mockAppendMandatory.mockImplementation(async (fields) => ({ hash: 'i'.repeat(64), artifactId: fields.artifactId }));
      const provider = jest.fn(() => { clock.expire(); return new Promise(() => {}); });   // dispatched, then the limit fires, and the provider never answers
      const post = make(provider);
      expect((await post({ prompt: 'slow', model: DEF })).body.decision).not.toBe('EXECUTE');
      expect(provider).toHaveBeenCalledTimes(1);
      expect((await post({ prompt: 'again', model: DEF })).body.reason).toBe('BUDGET_EXCEEDED_REQUESTS');
      expect(provider).toHaveBeenCalledTimes(1);
    } finally { clock.spy.mockRestore(); }
  });
});
