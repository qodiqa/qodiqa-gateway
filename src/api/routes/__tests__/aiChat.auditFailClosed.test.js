'use strict';

/**
 * Fail-closed audit evidence recording — /ai/chat (V2)
 *
 * Regression suite for the defect fixed in "Audit/Evidence Pipeline Fail-
 * Closed Remediation": the ALLOW-path audit write used to be wrapped in a
 * try/catch that only logged the failure — a request whose mandatory audit
 * entry could not be durably recorded would still receive a 200 EXECUTE
 * response with the AI-generated content. That is a direct violation of the
 * platform's evidence-first design: a request must never be reported as
 * successful while its required audit evidence is silently lost.
 *
 * AFC-01…04  ALLOW path: audit persistence failure → fail-closed (no 200, no leaked content)
 * AFC-05…06  ALLOW path: audit persistence succeeds → normal 200 EXECUTE (control)
 * AFC-07…09  BLOCK path: audit persistence failure does not change the 403 response
 * AFC-10…11  Escalation: CRITICAL log + fail-closed-rejection metric on ALLOW failure
 * AFC-12     Non-retryable audit error (e.g. duplicate) is not treated as a fresh failure
 *
 * audit schema v7 : the request's INTENT entry is appended (stage label 'INTENT') BEFORE the
 * provider is called, fail-closed. The ALLOW-path tests below therefore reject only the ALLOW DECISION append (stage
 * label 'ALLOW'), so they keep exercising the post-provider fail-closed path they were written for; the INTENT-append
 * failure path (provider never called) is covered by aiChat.lifecycle.test.js.
 */

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const mockAppendMandatory = jest.fn();
jest.mock('../../../core/audit/audit-log', () => ({
  appendMandatory: (...args) => mockAppendMandatory(...args),
}));

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ emit: (...args) => mockEmit(...args) }));

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
const metrics = require('../../../observability/metrics');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => {
  resetStats();
  mockAppendMandatory.mockReset();
  mockEmit.mockClear();
  jest.spyOn(metrics.auditFailClosedRejectionsTotal, 'inc');
});
afterEach(() => {
  metrics.auditFailClosedRejectionsTotal.inc.mockRestore();
});

/** Reject only the ALLOW DECISION append; every other append (the INTENT entry) succeeds. */
function rejectAllowAppend(err) {
  mockAppendMandatory.mockImplementation(async (fields, opts) => {
    if (opts && opts.stage === 'ALLOW') throw err;
    return { hash: 'i'.repeat(64), artifactId: fields.artifactId };
  });
}

const MOCK_RESPONSE = 'Mock AI response — should never reach the client on audit failure';
function mockProvider() { return Promise.resolve({ output: MOCK_RESPONSE }); }

const CHAT_PATH = '/ai/chat';
const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
}
function buildArtifact(reqBody = CHAT_BODY, extraPayload = {}) {
  const req = { method: 'POST', path: CHAT_PATH, body: reqBody };
  return signBoundArtifact(req, freshEnvelope({ provider: 'openai', ...extraPayload }), KEY.privDer);
}
function toHeader(artifact) {
  return Buffer.from(JSON.stringify(artifact)).toString('base64');
}

const _DEFAULT_POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });
const _DEFAULT_POLICY_STORE = createStore();

function makeApp() {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store:        makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _providerFn:   mockProvider,
    _getPolicies:  () => _DEFAULT_POLICIES,
    _policyStore:  _DEFAULT_POLICY_STORE,
  }));
  app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));
  return app;
}

async function post(app, artifact, body = CHAT_BODY) {
  return supertest(app)
    .post('/ai/chat')
    .set('x-qodiqa-artifact', toHeader(artifact))
    .send(body);
}

// ═════════════════════════════════════════════════════════════════════════════
// AFC-01…04  ALLOW path: audit persistence failure → fail-closed
// ═════════════════════════════════════════════════════════════════════════════

describe('ALLOW path — audit persistence failure is fail-closed', () => {
  test('AFC-01: appendMandatory exhausting retries → 503, not 200', async () => {
    const failure = new Error('AUDIT_PERSISTENCE_FAILED: ENOSPC: no space left on device');
    failure.code  = 'AUDIT_PERSISTENCE_FAILED';
    rejectAllowAppend(failure);

    const app      = makeApp();
    const artifact = buildArtifact();
    const res      = await post(app, artifact);

    expect(res.status).toBe(503);
    expect(res.status).not.toBe(200);
  });

  test('AFC-02: fail-closed response reports AUDIT_PERSISTENCE_FAILED, not success', async () => {
    const failure = new Error('AUDIT_PERSISTENCE_FAILED: disk full');
    failure.code  = 'AUDIT_PERSISTENCE_FAILED';
    rejectAllowAppend(failure);

    const res = await post(makeApp(), buildArtifact());

    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('AUDIT_PERSISTENCE_FAILED');
  });

  test('AFC-03: the AI-generated response text is never leaked to the client on audit failure', async () => {
    const failure = new Error('AUDIT_PERSISTENCE_FAILED: fsync failed');
    failure.code  = 'AUDIT_PERSISTENCE_FAILED';
    rejectAllowAppend(failure);

    const res = await post(makeApp(), buildArtifact());

    expect(JSON.stringify(res.body)).not.toContain(MOCK_RESPONSE);
    expect(res.body.response).toBeUndefined();
  });

  test('AFC-04: a generic (non-AUDIT_PERSISTENCE_FAILED) thrown error also fails closed, never 200', async () => {
    rejectAllowAppend(new Error('unexpected error'));

    const res = await post(makeApp(), buildArtifact());

    expect(res.status).not.toBe(200);
    expect(res.body.response).toBeUndefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// AFC-05…06  ALLOW path control case — audit succeeds
// ═════════════════════════════════════════════════════════════════════════════

describe('ALLOW path — control case (audit succeeds)', () => {
  test('AFC-05: appendMandatory resolving → normal 200 EXECUTE with response content', async () => {
    mockAppendMandatory.mockResolvedValue({ hash: 'deadbeef', artifactId: 'a1' });

    const res = await post(makeApp(), buildArtifact());

    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
    expect(res.body.response).toBe(MOCK_RESPONSE);
  });

  test('AFC-06: appendMandatory is invoked with decision ALLOW and the ALLOW stage label', async () => {
    mockAppendMandatory.mockResolvedValue({ hash: 'x', artifactId: 'a1' });

    await post(makeApp(), buildArtifact());

    expect(mockAppendMandatory).toHaveBeenCalledWith(
      expect.objectContaining({ decision: 'ALLOW' }),
      expect.objectContaining({ stage: 'ALLOW' }),
    );
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// AFC-07…09  BLOCK path — audit failure does not change the response
// ═════════════════════════════════════════════════════════════════════════════

describe('BLOCK path — audit persistence failure does not change the BLOCK outcome', () => {
  // a missing artifact is a pre-auth reject and no longer reaches
  // the audit chain at all, so these guarantees are exercised with a genuine
  // post-auth BLOCK — a replay (valid signature, nonce already consumed).
  async function replayApp() {
    const app = makeApp();
    const artifact = buildArtifact();
    mockAppendMandatory.mockResolvedValueOnce({ hash: 'x0', artifactId: 'a0' });
    await post(app, artifact); // ALLOW, consumes the nonce
    mockAppendMandatory.mockClear();
    return { app, artifact };
  }

  test('AFC-07: a post-auth BLOCK (replay) still returns 200 BLOCK even when appendMandatory rejects', async () => {
    const { app, artifact } = await replayApp();
    mockAppendMandatory.mockRejectedValue(new Error('disk full'));

    const res = await post(app, artifact);

    expect(res.status).toBe(200);
    expect(res.body.reason).toBe('REPLAY_DETECTED');
    expect(mockAppendMandatory).toHaveBeenCalled();
  });

  test('AFC-07b: a pre-auth reject (missing artifact) never calls appendMandatory', async () => {
    const res = await supertest(makeApp()).post('/ai/chat').send(CHAT_BODY);
    expect(res.status).toBe(200);
    expect(res.body.reason).toBe('MISSING_ARTIFACT');
    expect(mockAppendMandatory).not.toHaveBeenCalled();
  });

  test('AFC-08: appendMandatory is called with stage BLOCK for a BLOCK decision', async () => {
    const { app, artifact } = await replayApp();
    mockAppendMandatory.mockResolvedValue({ hash: 'x', artifactId: 'a1' });

    await post(app, artifact);

    expect(mockAppendMandatory).toHaveBeenCalledWith(
      expect.objectContaining({ decision: 'BLOCK' }),
      expect.objectContaining({ stage: 'BLOCK' }),
    );
  });

  test('AFC-09: repeated BLOCK-path audit failures never crash the route (still responds)', async () => {
    const { app, artifact } = await replayApp();
    mockAppendMandatory.mockRejectedValue(new Error('persistent failure'));

    for (let i = 0; i < 3; i++) {
      const res = await post(app, artifact);
      expect(res.status).toBe(200);
      expect(res.body.reason).toBe('REPLAY_DETECTED');
    }
    expect(mockAppendMandatory).toHaveBeenCalledTimes(3);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// AFC-10…11  Escalation: CRITICAL log + metric
// ═════════════════════════════════════════════════════════════════════════════

describe('Escalation on ALLOW-path audit failure', () => {
  test('AFC-10: a CRITICAL AUDIT_APPEND_FAILED event is emitted', async () => {
    const failure = new Error('AUDIT_PERSISTENCE_FAILED: boom');
    failure.code  = 'AUDIT_PERSISTENCE_FAILED';
    rejectAllowAppend(failure);

    await post(makeApp(), buildArtifact());

    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'AUDIT_APPEND_FAILED', expect.objectContaining({
      stage: 'ALLOW',
    }));
  });

  test('AFC-11: the fail-closed-rejections metric is incremented with stage ALLOW', async () => {
    const failure = new Error('AUDIT_PERSISTENCE_FAILED: boom');
    failure.code  = 'AUDIT_PERSISTENCE_FAILED';
    rejectAllowAppend(failure);

    await post(makeApp(), buildArtifact());

    expect(metrics.auditFailClosedRejectionsTotal.inc).toHaveBeenCalledWith({ stage: 'ALLOW' });
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// AFC-12  Non-retryable / duplicate audit error handling
// ═════════════════════════════════════════════════════════════════════════════

describe('Non-retryable audit error handling', () => {
  test('AFC-12: an already_executed error on the ALLOW path is NOT silently treated as success', async () => {
    // appendMandatory (per audit-log.js contract) rethrows already_executed
    // immediately without retry — the route must still fail closed, since an
    // ALLOW decision whose audit entry could not be freshly written is not
    // proof that THIS execution's evidence was recorded.
    rejectAllowAppend(new Error('already_executed: artifactId already in audit log'));

    const res = await post(makeApp(), buildArtifact());

    expect(res.status).not.toBe(200);
  });
});
