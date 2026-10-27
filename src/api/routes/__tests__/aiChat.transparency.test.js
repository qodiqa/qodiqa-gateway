'use strict';

/**
 * Live Enforcement → Transparency Log wiring — /ai/chat
 *
 * Regression suite for the fix wiring the RFC6962 transparency log into the
 * live /ai/chat enforcement pipeline (previously the transparency log was
 * only reachable from certification/attestation workflows — see
 * TRANS-2 /). Mirrors the
 * structure of aiChat.auditFailClosed.test.js, which covers the equivalent
 * behavior for the audit chain write this transparency write sits next to.
 *
 * TRANS-AI-01…02  EXECUTE (ALLOW) request creates a transparency entry + evidence in response
 * TRANS-AI-03…05  DENY (BLOCK): post-auth BLOCKs create a transparency entry; pre-auth rejects
 * (no artifact, expired/invalid artifact) do NOT
 * TRANS-AI-06…09  ALLOW path: transparency registration failure → fail-closed (503, no leak)
 * TRANS-AI-10…11  BLOCK path: transparency registration failure does not change the 200 BLOCK
 * TRANS-AI-12     Exactly one registration call per request (no duplicates)
 * TRANS-AI-13     Concurrent requests each register their own distinct transparency entry
 * TRANS-AI-14     Escalation: CRITICAL log + fail-closed-rejection metric on ALLOW failure
 *
 * audit schema v7 : an EXECUTE now registers TWO leaves — the INTENT leaf (written before
 * provider dispatch, payload.entryType 'INTENT', artifactId '<requestId>:intent') and the DECISION leaf. "Exactly one"
 * below therefore means exactly one DECISION leaf (+ exactly one INTENT leaf on the provider path). The ALLOW-path
 * failure tests reject only the DECISION leaf, so they keep exercising the post-provider fail-closed path they were
 * written for; the INTENT-leaf failure path (provider never called) is covered by aiChat.lifecycle.test.js.
 */

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const mockRegister = jest.fn();
jest.mock('../../../core/transparency/registrar', () => ({
  register: (...args) => mockRegister(...args),
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
  mockRegister.mockReset();
  mockRegister.mockResolvedValue({
    transparencyId: 'tid-1', entryHash: 'e'.repeat(64), signature: 'sig', keyId: 'tr-default:key_v1', persisted: true,
  });
  mockEmit.mockClear();
  jest.spyOn(metrics.transparencyFailClosedRejectionsTotal, 'inc');
  jest.spyOn(metrics.transparencyEnforcementFailuresTotal, 'inc');
  jest.spyOn(metrics.transparencyEnforcementEntriesTotal, 'inc');
});
afterEach(() => {
  metrics.transparencyFailClosedRejectionsTotal.inc.mockRestore();
  metrics.transparencyEnforcementFailuresTotal.inc.mockRestore();
  metrics.transparencyEnforcementEntriesTotal.inc.mockRestore();
});

// v7: leaf classification by payload — lifecycle leaves carry payload.entryType; DECISION leaves do not.
const decisionLeaves = () => mockRegister.mock.calls.filter(([r]) => !r.payload.entryType);
const intentLeaves   = () => mockRegister.mock.calls.filter(([r]) => r.payload.entryType === 'INTENT');
const OK_REG = { transparencyId: 'tid-1', entryHash: 'e'.repeat(64), signature: 'sig', keyId: 'tr-default:key_v1', persisted: true };
/** Reject only the DECISION leaf (the INTENT leaf still registers, so the provider IS called first). */
function rejectDecisionLeaf(err) {
  mockRegister.mockImplementation(async (r) => { if (r.payload.entryType) return OK_REG; throw err; });
}

const MOCK_RESPONSE = 'Mock AI response';
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

// a genuine post-authentication BLOCK — a replay (valid
// signature, nonce already consumed). Pre-auth rejects no longer reach the
// transparency log, so every BLOCK-path guarantee below is exercised with this.
async function replayBlock(app) {
  const artifact = buildArtifact();
  await post(app, artifact);          // ALLOW, consumes the nonce
  mockRegister.mockClear();
  return post(app, artifact);         // REPLAY_DETECTED (post-auth BLOCK)
}

// ═════════════════════════════════════════════════════════════════════════════
// TRANS-AI-01…02  EXECUTE creates a transparency entry + evidence in response
// ═════════════════════════════════════════════════════════════════════════════

describe('EXECUTE (ALLOW) — transparency entry registration', () => {
  test('TRANS-AI-01: a successful request registers exactly one AUDIT-type DECISION entry (+ its INTENT leaf)', async () => {
    const res = await post(makeApp(), buildArtifact());

    expect(res.status).toBe(200);
    expect(mockRegister).toHaveBeenCalledTimes(2);
    expect(decisionLeaves()).toHaveLength(1);
    expect(intentLeaves()).toHaveLength(1);
    expect(decisionLeaves()[0][0]).toEqual(expect.objectContaining({
      entryType: 'AUDIT',
      payload:   expect.objectContaining({ decision: 'ALLOW', stage: 'PROVIDER_EXECUTION' }),
    }));
    // R-9 / R-10: the INTENT leaf precedes the DECISION leaf and registers under the suffixed artifact id
    const [intent] = intentLeaves()[0];
    expect(mockRegister.mock.calls[0][0]).toBe(intent);
    expect(intent.artifactId).toBe(decisionLeaves()[0][0].artifactId + ':intent');
    expect(intent.payload).toEqual(expect.objectContaining({ decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', entryType: 'INTENT' }));
  });

  test('TRANS-AI-02: the 200 response includes transparency evidence fields', async () => {
    const res = await post(makeApp(), buildArtifact());

    expect(res.status).toBe(200);
    expect(res.body.transparency).toEqual(expect.objectContaining({
      transparencyId: 'tid-1',
      entryHash:      'e'.repeat(64),
      signerKeyId:    'tr-default:key_v1',
      persisted:      true,
    }));
    expect(typeof res.body.transparency.leafHash).toBe('string');
    expect(res.body.transparency.leafHash).toHaveLength(64);
    expect(res.body.transparency.inclusionProofRef).toBe('/v1/transparency/proof/tid-1'); // R-18
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// persisted:false emits a WARN signal instead of staying silent
// ═════════════════════════════════════════════════════════════════════════════

describe('EXECUTE (ALLOW) — transparency sign-only degradation signal', () => {
  test('persisted:false emits TRANSPARENCY_PERSISTENCE_DEGRADED at WARN', async () => {
    mockRegister.mockResolvedValueOnce(OK_REG);   // the INTENT leaf registers first
    mockRegister.mockResolvedValueOnce({
      transparencyId: 'tid-degraded', entryHash: 'f'.repeat(64), signature: 'sig', keyId: 'tr-default:key_v1', persisted: false,
    });

    const res = await post(makeApp(), buildArtifact());

    expect(res.status).toBe(200);
    expect(res.body.transparency.persisted).toBe(false);
    expect(mockEmit).toHaveBeenCalledWith('WARN', 'TRANSPARENCY_PERSISTENCE_DEGRADED', expect.objectContaining({
      transparencyId: 'tid-degraded',
    }));
  });

  test('persisted:true does NOT emit TRANSPARENCY_PERSISTENCE_DEGRADED', async () => {
    const res = await post(makeApp(), buildArtifact());

    expect(res.status).toBe(200);
    expect(res.body.transparency.persisted).toBe(true);
    expect(mockEmit).not.toHaveBeenCalledWith('WARN', 'TRANSPARENCY_PERSISTENCE_DEGRADED', expect.anything());
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// TRANS-AI-03…05  DENY (BLOCK) requests each create a transparency entry
// ═════════════════════════════════════════════════════════════════════════════

describe('DENY (BLOCK) — transparency entry registration at every stage', () => {
  // inverted. A request with no artifact is anonymous; it
  // used to get a signed transparency leaf (evidence flooding). It is now
  // counted (qodiqa_preauth_rejects_total) and never registered. Same response.
  test('TRANS-AI-03: missing artifact (pre-auth) → same 200 BLOCK, NO transparency entry, counted', async () => {
    const before = metrics.preAuthRejectsTotal._values.get('reason="MISSING_ARTIFACT",route="/ai/chat"') ?? 0;
    const res = await supertest(makeApp()).post('/ai/chat').send(CHAT_BODY);

    expect(res.status).toBe(200);
    expect(res.body.reason).toBe('MISSING_ARTIFACT');
    expect(mockRegister).not.toHaveBeenCalled();
    expect(metrics.preAuthRejectsTotal._values.get('reason="MISSING_ARTIFACT",route="/ai/chat"')).toBe(before + 1);
  });

  test('TRANS-AI-04: an expired artifact (pre-auth VALIDATION) → same 200 BLOCK, NO transparency entry', async () => {
    const req = { method: 'POST', path: CHAT_PATH, body: CHAT_BODY };
    const now = Date.now();
    const artifact = signBoundArtifact(req, {
      payload: { provider: 'openai' }, timestamp: now - 400_000, expiry: now - 300_000, publicKeyId: KEY.keyId,
    }, KEY.privDer);

    const res = await post(makeApp(), artifact);

    // an expired artifact fails validateArtifact (no verified
    // key) — pre-auth, so no leaf. Same 200 BLOCK response as before.
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(mockRegister).not.toHaveBeenCalled();
  });

  test('TRANS-AI-05: a duplicate/replayed request still registers its own BLOCK transparency entry', async () => {
    const app      = makeApp();
    const artifact = buildArtifact();
    await post(app, artifact); // consumes the nonce (ALLOW)
    mockRegister.mockClear();

    const res = await post(app, artifact); // replay
    expect(res.status).toBe(200);
    expect(res.body.reason).toBe('REPLAY_DETECTED');
    expect(mockRegister).toHaveBeenCalledWith(expect.objectContaining({
      payload: expect.objectContaining({ decision: 'BLOCK', reason: 'REPLAY_DETECTED' }),
    }));
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// BLOCK-path companion to persisted:false must also WARN, not stay silent
// ═════════════════════════════════════════════════════════════════════════════
//
// (above) only added this check to the ALLOW branch. Code-hygiene batch
// found the BLOCK-path registerEnforcementDecision() call had
// the identical persisted:false degraded-success path with no WARN — filed
// and fixed as.

describe('DENY (BLOCK) — transparency sign-only degradation signal', () => {
  test('persisted:false on a BLOCK decision emits TRANSPARENCY_PERSISTENCE_DEGRADED at WARN', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    await post(app, artifact);
    mockRegister.mockResolvedValueOnce({
      transparencyId: 'tid-block-degraded', entryHash: 'a'.repeat(64), signature: 'sig', keyId: 'tr-default:key_v1', persisted: false,
    });

    const res = await post(app, artifact); // a post-auth BLOCK (replay) — pre-auth rejects register nothing

    expect(res.status).toBe(200);
    expect(res.body.reason).toBe('REPLAY_DETECTED');
    expect(mockEmit).toHaveBeenCalledWith('WARN', 'TRANSPARENCY_PERSISTENCE_DEGRADED', expect.objectContaining({
      transparencyId: 'tid-block-degraded',
    }));
  });

  test('persisted:true on a BLOCK decision does NOT emit TRANSPARENCY_PERSISTENCE_DEGRADED', async () => {
    const res = await replayBlock(makeApp()); // default mock: persisted:true

    expect(res.status).toBe(200);
    expect(res.body.reason).toBe('REPLAY_DETECTED');
    expect(mockRegister).toHaveBeenCalledTimes(1);
    expect(mockEmit).not.toHaveBeenCalledWith('WARN', 'TRANSPARENCY_PERSISTENCE_DEGRADED', expect.anything());
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// TRANS-AI-06…09  ALLOW path — transparency failure is fail-closed
// ═════════════════════════════════════════════════════════════════════════════

describe('ALLOW path — transparency registration failure is fail-closed', () => {
  test('TRANS-AI-06: registrar.register rejecting → 503, not 200', async () => {
    rejectDecisionLeaf(new Error('signing key unavailable'));

    const res = await post(makeApp(), buildArtifact());

    expect(res.status).toBe(503);
    expect(res.status).not.toBe(200);
  });

  test('TRANS-AI-07: fail-closed response reports TRANSPARENCY_PERSISTENCE_FAILED, not success', async () => {
    rejectDecisionLeaf(new Error('signing key unavailable'));

    const res = await post(makeApp(), buildArtifact());

    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).toBe('TRANSPARENCY_PERSISTENCE_FAILED');
  });

  test('TRANS-AI-07b (audit 3.14): the 503 states exactly what happened — provider executed, audit recorded, transparency not, response withheld', async () => {
    rejectDecisionLeaf(new Error('signing key unavailable'));

    const res = await post(makeApp(), buildArtifact());

    expect(res.status).toBe(503);
    expect(res.body.details).toEqual({ providerExecuted: true, auditRecorded: true, transparencyRecorded: false, responseWithheld: true });
  });

  test('TRANS-AI-08: the AI-generated response text is never leaked when transparency registration fails', async () => {
    rejectDecisionLeaf(new Error('signing key unavailable'));

    const res = await post(makeApp(), buildArtifact());

    expect(JSON.stringify(res.body)).not.toContain(MOCK_RESPONSE);
    expect(res.body.response).toBeUndefined();
  });

  test('TRANS-AI-09: a generic thrown error also fails closed, never 200', async () => {
    rejectDecisionLeaf(new Error('unexpected'));

    const res = await post(makeApp(), buildArtifact());

    expect(res.status).not.toBe(200);
    expect(res.body.response).toBeUndefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// TRANS-AI-10…11  BLOCK path — transparency failure does not change the response
// ═════════════════════════════════════════════════════════════════════════════

describe('BLOCK path — transparency registration failure does not change the 200 BLOCK outcome', () => {
  test('TRANS-AI-10: a post-auth BLOCK (replay) still returns 200 BLOCK even when registrar.register rejects', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    await post(app, artifact);
    mockRegister.mockRejectedValue(new Error('transparency backend down'));

    const res = await post(app, artifact);

    expect(res.status).toBe(200);
    expect(res.body.reason).toBe('REPLAY_DETECTED');
    expect(mockRegister).toHaveBeenCalled();
  });

  test('TRANS-AI-11: repeated BLOCK-path transparency failures never crash the route (still responds)', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    await post(app, artifact);
    mockRegister.mockClear();
    mockRegister.mockRejectedValue(new Error('persistent failure'));

    // post-auth BLOCKs (replays) — pre-auth rejects never reach the writer.
    for (let i = 0; i < 3; i++) {
      const res = await post(app, artifact);
      expect(res.status).toBe(200);
      expect(res.body.reason).toBe('REPLAY_DETECTED');
    }
    expect(mockRegister).toHaveBeenCalledTimes(3);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// TRANS-AI-12  No duplicate transparency entries
// ═════════════════════════════════════════════════════════════════════════════

test('TRANS-AI-12: a single request registers exactly one DECISION transparency entry (ALLOW or BLOCK)', async () => {
  await post(makeApp(), buildArtifact());
  expect(decisionLeaves()).toHaveLength(1);
  expect(intentLeaves()).toHaveLength(1);   // v7 (R-10): the ALLOW path's INTENT leaf — exactly one
  expect(mockRegister).toHaveBeenCalledTimes(2);

  // the BLOCK half uses a post-auth BLOCK (replay); a pre-auth
  // reject registers zero entries (TRANS-AI-03).
  await replayBlock(makeApp());
  expect(mockRegister).toHaveBeenCalledTimes(1);
});

// ═════════════════════════════════════════════════════════════════════════════
// TRANS-AI-13  Concurrent requests each register their own entry
// ═════════════════════════════════════════════════════════════════════════════

test('TRANS-AI-13: concurrent requests each register their own distinct transparency entry', async () => {
  const app = makeApp();
  const artifacts = Array.from({ length: 5 }, () => buildArtifact());

  const responses = await Promise.all(artifacts.map(a => post(app, a)));
  responses.forEach(res => expect(res.status).toBe(200));

  expect(mockRegister).toHaveBeenCalledTimes(10);   // v7: one INTENT + one DECISION leaf per request
  const requestIds = decisionLeaves().map(([opts]) => opts.artifactId);
  expect(new Set(requestIds).size).toBe(5);
  const intentIds = intentLeaves().map(([opts]) => opts.artifactId);
  expect(intentIds.sort()).toEqual(requestIds.map((id) => id + ':intent').sort());
});

// ═════════════════════════════════════════════════════════════════════════════
// TRANS-AI-14  Escalation: CRITICAL log + metrics
// ═════════════════════════════════════════════════════════════════════════════

describe('Escalation on ALLOW-path transparency failure', () => {
  test('TRANS-AI-14a: a CRITICAL TRANSPARENCY_APPEND_FAILED event is emitted', async () => {
    rejectDecisionLeaf(new Error('boom'));

    await post(makeApp(), buildArtifact());

    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'TRANSPARENCY_APPEND_FAILED', expect.objectContaining({
      stage: 'ALLOW',
    }));
  });

  test('TRANS-AI-14b: the transparency fail-closed-rejections metric is incremented with stage ALLOW', async () => {
    rejectDecisionLeaf(new Error('boom'));

    await post(makeApp(), buildArtifact());

    expect(metrics.transparencyFailClosedRejectionsTotal.inc).toHaveBeenCalledWith({ stage: 'ALLOW' });
    expect(metrics.transparencyEnforcementFailuresTotal.inc).toHaveBeenCalledWith({ stage: 'ALLOW' });
  });

  test('TRANS-AI-14c: on success, the enforcement-entries metric is incremented with decision ALLOW', async () => {
    await post(makeApp(), buildArtifact());

    expect(metrics.transparencyEnforcementEntriesTotal.inc).toHaveBeenCalledWith({ decision: 'ALLOW' });
  });

  test('TRANS-AI-14d: on a BLOCK decision, the enforcement-entries metric is incremented with decision BLOCK', async () => {
    await replayBlock(makeApp()); // a post-auth BLOCK — pre-auth rejects register nothing

    expect(metrics.transparencyEnforcementEntriesTotal.inc).toHaveBeenCalledWith({ decision: 'BLOCK' });
  });
});
