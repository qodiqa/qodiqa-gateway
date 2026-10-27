'use strict';
// v7 (R-12 / R-14): audit appends pseudonymize subjects — explicit test-only stand-in (no database here).
jest.mock('../../../core/dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));

/**
 * A4 — /ai/chat route-level proofs. Harness = aiChat.auditFailClosed.test.js's (real router,
 * real enforcement, mocked consent registry, mocked audit-log appendMandatory, mocked provider function).
 *
 * A4-01 provider circuit OPEN → 503 PROVIDER_CIRCUIT_OPEN + Retry-After = ceil(PROVIDER_CB_RECOVERY_MS/1000)
 *          (was 500, no Retry-After)
 * A4-02 provider registered but not enabled → 503 PROVIDER_NOT_CONFIGURED, no Retry-After (was 500)
 * A4-03 PROVIDER_HEALTH_DEGRADED → 503 + Retry-After (was 500)
 * A4-04 UNVERIFIED_EXECUTION_ATTEMPT stays 500 (internal invariant breach), no Retry-After
 * A4-05 the default QODIQA_BLOCK_HTTP_MODE=decision contract is untouched: an enforcement BLOCK is still 200
 * A4-06 route → latch: consecutive AUDIT_PERSISTENCE_FAILED responses latch auditPersistenceHealth (so
 *          /ready turns 503), one successful request clears it
 */

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));
const mockAppendMandatory = jest.fn();
jest.mock('../../../core/audit/audit-log', () => ({
  appendMandatory: (...args) => mockAppendMandatory(...args),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

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
const { CIRCUIT_BREAKER_CONFIG } = require('../../../../services/providers/circuitBreakerConfig');
const auditHealth = require('../../auditPersistenceHealth');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => {
  resetStats();
  auditHealth._resetForTests();
  mockAppendMandatory.mockReset();
  mockAppendMandatory.mockImplementation(async (fields) => ({ hash: 'i'.repeat(64), artifactId: fields.artifactId }));
});

const CHAT_PATH = '/ai/chat';
const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
function buildArtifact() {
  const now = Date.now();
  return signBoundArtifact({ method: 'POST', path: CHAT_PATH, body: CHAT_BODY },
    { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
}
const toHeader = (a) => Buffer.from(JSON.stringify(a)).toString('base64');

const POLICIES = validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
const POLICY_STORE = createStore();

function makeApp(providerFn) {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: providerFn,
    _getPolicies: () => POLICIES, _policyStore: POLICY_STORE,
  }));
  return app;
}
const post = (app) => supertest(app).post('/ai/chat').set('x-qodiqa-artifact', toHeader(buildArtifact())).send(CHAT_BODY);
const throwing = (code) => async () => { const e = new Error(code); e.code = code; throw e; };

describe('provider failure HTTP status', () => {
  test('A4-01 PROVIDER_CIRCUIT_OPEN → 503 + Retry-After', async () => {
    const res = await post(makeApp(throwing('PROVIDER_CIRCUIT_OPEN')));
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'PROVIDER_CIRCUIT_OPEN' });
    expect(res.headers['retry-after']).toBe(String(Math.ceil(CIRCUIT_BREAKER_CONFIG.cbRecoveryMs / 1000)));
  });

  test('A4-02 PROVIDER_NOT_CONFIGURED → 503, no Retry-After', async () => {
    const res = await post(makeApp(throwing('PROVIDER_NOT_CONFIGURED')));
    expect(res.status).toBe(503);
    expect(res.body.reason).toBe('PROVIDER_NOT_CONFIGURED');
    expect(res.headers['retry-after']).toBeUndefined();
  });

  test('A4-03 PROVIDER_HEALTH_DEGRADED → 503 + Retry-After', async () => {
    const res = await post(makeApp(throwing('PROVIDER_HEALTH_DEGRADED')));
    expect(res.status).toBe(503);
    expect(res.headers['retry-after']).toBeDefined();
  });

  test('A4-04 UNVERIFIED_EXECUTION_ATTEMPT stays 500', async () => {
    const res = await post(makeApp(throwing('UNVERIFIED_EXECUTION_ATTEMPT')));
    expect(res.status).toBe(500);
    expect(res.body.reason).toBe('UNVERIFIED_EXECUTION_ATTEMPT');
    expect(res.headers['retry-after']).toBeUndefined();
  });

  test('A4-05 decision mode (default): an enforcement BLOCK is still HTTP 200', async () => {
    const saved = process.env.QODIQA_BLOCK_HTTP_MODE; delete process.env.QODIQA_BLOCK_HTTP_MODE;
    try {
      const res = await supertest(makeApp(async () => ({ output: 'x' }))).post('/ai/chat').send(CHAT_BODY); // no artifact
      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('BLOCK');
    } finally { if (saved !== undefined) process.env.QODIQA_BLOCK_HTTP_MODE = saved; }
  });
});

describe('route → readiness latch', () => {
  test('A4-06 consecutive AUDIT_PERSISTENCE_FAILED latch the readiness component; a success clears it', async () => {
    const fail = () => Object.assign(new Error('AUDIT_PERSISTENCE_FAILED: ENOSPC'), { code: 'AUDIT_PERSISTENCE_FAILED' });
    mockAppendMandatory.mockImplementation(async () => { throw fail(); });
    const app = makeApp(async () => ({ output: 'ok' }));
    for (let i = 0; i < auditHealth.FAILURE_THRESHOLD; i++) {
      const res = await post(app);
      expect(res.status).toBe(503);
      expect(res.body.reason).toBe('AUDIT_PERSISTENCE_FAILED');
    }
    expect(auditHealth.state().latched).toBe(true);
    expect(auditHealth.isHealthy({ probe: () => false, now: Date.now() + 60_000 })).toBe(false);

    mockAppendMandatory.mockImplementation(async (fields) => ({ hash: 'i'.repeat(64), artifactId: fields.artifactId }));
    const ok = await post(app);
    expect(ok.status).toBe(200);
    expect(auditHealth.state().latched).toBe(false);
  });
});
