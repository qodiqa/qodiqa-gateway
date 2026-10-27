'use strict';

/**
 * Signed receipt on /ai/chat.
 *
 * RCPT-01  EXECUTE carries a receipt: eight fields, the audit DECISION entry hash, the Merkle leaf hash of the registered
 *          leaf, a transparency key, a signature that verifies offline (independently recomputed, no src verifier)
 * RCPT-02  the receipt is stored for retrieval and is the very object returned (signed once, never re-signed)
 * RCPT-03  persisted:false / pending / registration failure → the field is ABSENT (never null)
 * RCPT-04  a post-authentication BLOCK carries the receipt of its own decision; a pre-authentication reject carries none
 * RCPT-05  a signing failure never changes the decided response: no receipt, CRITICAL RECEIPT_ISSUE_FAILED
 * RCPT-07  the receipt discloses no tenant and no reason
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

let mockSignFails = false;
jest.mock('../../../core/transparency/transparencySigner', () => {
  const actual = jest.requireActual('../../../core/transparency/transparencySigner');
  return {
    ...actual,
    getTransparencySigner: () => {
      const real = actual.getTransparencySigner();
      return {
        getActiveKeyInfo: () => real.getActiveKeyInfo(),
        verify: (...a) => real.verify(...a),
        sign: (...a) => { if (mockSignFails) return Promise.reject(new Error('simulated signing failure')); return real.sign(...a); },
      };
    },
  };
});

const crypto    = require('crypto');
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
const { leafHash: merkleLeafHash } = require('../../../core/transparency/merkle');
const { getReceipt, _resetForTests: resetReceiptStore } = require('../../../core/transparency/receiptStore');
const { verifyReceipt } = require('../../../core/transparency/receipt');
const { getTransparencySigner } = jest.requireActual('../../../core/transparency/transparencySigner');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });
const LEAF_ENTRY_HASH = 'e'.repeat(64);
const OK_REG = { transparencyId: 'tid-1', entryHash: LEAF_ENTRY_HASH, signature: 'sig', keyId: 'tr-default:key_v1', persisted: true };
beforeEach(() => {
  resetStats();
  resetReceiptStore();
  mockSignFails = false;
  mockRegister.mockReset();
  mockRegister.mockResolvedValue(OK_REG);
  mockEmit.mockClear();
});

const decisionLeaf = () => mockRegister.mock.calls.map(([r]) => r).find((r) => !r.payload.entryType);
const RECEIPT_FIELDS = ['decision', 'entryHash', 'issuedAt', 'keyId', 'leafHash', 'requestId', 'signature', 'v'];

const CHAT_PATH = '/ai/chat';
const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
function freshEnvelope(payload = {}) { const now = Date.now(); return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }; }
function buildArtifact(reqBody = CHAT_BODY) {
  return signBoundArtifact({ method: 'POST', path: CHAT_PATH, body: reqBody }, freshEnvelope({ provider: 'openai' }), KEY.privDer);
}
const toHeader = (a) => Buffer.from(JSON.stringify(a)).toString('base64');
const POLICIES = validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
const POLICY_STORE = createStore();
function makeApp() {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: () => Promise.resolve({ output: 'Mock AI response' }), _getPolicies: () => POLICIES, _policyStore: POLICY_STORE }));
  return app;
}
const post = (app, artifact, body = CHAT_BODY) => supertest(app).post(CHAT_PATH).set('x-qodiqa-artifact', toHeader(artifact)).send(body);

/** Offline verification written from the document, not from src: SHA-256(domain || canonical JSON) → Ed25519 with the key's SPKI. */
function independentlyVerified(receipt) {
  const { signature, ...unsigned } = receipt;
  const canonical = JSON.stringify(Object.fromEntries(Object.keys(unsigned).sort().map((k) => [k, unsigned[k]])));   // strings + one integer: JCS-P1 form
  const digest = crypto.createHash('sha256').update('QODIQA::RECEIPT::V1', 'utf8').update(canonical, 'utf8').digest();
  const { pubDer } = getTransparencySigner().getVerificationKey(receipt.keyId);
  return crypto.verify(null, digest, crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' }), Buffer.from(receipt.signature, 'base64'));
}

describe('RCPT — EXECUTE', () => {
  test('RCPT-01 the response carries a receipt that binds the audit entry and the leaf and verifies offline', async () => {
    const artifact = buildArtifact();
    const res = await post(makeApp(), artifact);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
    const r = res.body.receipt;
    expect(Object.keys(r).sort()).toEqual(RECEIPT_FIELDS);
    expect(r).toMatchObject({ v: 1, requestId: artifact.payload.requestId, decision: 'ALLOW' });
    expect(r.entryHash).toBe(decisionLeaf().payload.auditEntryHash);          // the audit DECISION entry
    expect(r.entryHash).toMatch(/^[0-9a-f]{64}$/);
    expect(r.leafHash).toBe(merkleLeafHash(LEAF_ENTRY_HASH));                   // the Merkle leaf of the registered leaf
    expect(r.leafHash).toBe(res.body.transparency.leafHash);
    expect(r.keyId).toMatch(/^tr-/);                                           // a TRANSPARENCY key, never an artifact key
    expect(Number.isSafeInteger(r.issuedAt)).toBe(true);
    expect(Buffer.from(r.signature, 'base64')).toHaveLength(64);
    expect(verifyReceipt(r)).toEqual({ ok: true, reason: null });
    expect(independentlyVerified(r)).toBe(true);
  });

  test('RCPT-02 the receipt is stored for retrieval and is the same object that was returned', async () => {
    const artifact = buildArtifact();
    const res = await post(makeApp(), artifact);
    expect(await getReceipt(artifact.payload.requestId)).toEqual(res.body.receipt);
  });

  test('RCPT-03 an unpersisted, pending or failed leaf gives no receipt: the field is absent, never null', async () => {
    mockRegister.mockResolvedValueOnce(OK_REG);   // the INTENT leaf
    mockRegister.mockResolvedValueOnce({ ...OK_REG, persisted: false });
    let res = await post(makeApp(), buildArtifact());
    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('receipt');
    expect(JSON.stringify(res.body)).not.toMatch(/"receipt":null/);

    mockRegister.mockResolvedValueOnce(OK_REG);
    mockRegister.mockResolvedValueOnce({ transparencyId: 'tid-p', entryHash: null, signature: null, keyId: null, persisted: 'pending', payloadHash: 'a'.repeat(64) });
    res = await post(makeApp(), buildArtifact());
    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('receipt');

    mockRegister.mockImplementation(async (r) => { if (r.payload.entryType) return OK_REG; throw new Error('leaf store down'); });
    res = await post(makeApp(), buildArtifact());
    expect(res.status).toBe(503);                       // fail-closed as before; and no receipt on it
    expect(res.body).not.toHaveProperty('receipt');
  });

  test('RCPT-05 a signing failure never changes the decided response: EXECUTE without a receipt, escalated', async () => {
    mockSignFails = true;
    const artifact = buildArtifact();
    const res = await post(makeApp(), artifact);
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
    expect(res.body).not.toHaveProperty('receipt');
    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'RECEIPT_ISSUE_FAILED', expect.objectContaining({ requestId: artifact.payload.requestId, decision: 'ALLOW' }));
    expect(await getReceipt(artifact.payload.requestId)).toBeNull();
  });

  test('RCPT-07 the receipt discloses no tenant and no reason', async () => {
    const res = await post(makeApp(), buildArtifact());
    const text = JSON.stringify(res.body.receipt);
    expect(text).not.toMatch(/tenant|reason|ALL_CHECKS_PASSED/i);
  });
});

describe('RCPT — BLOCK', () => {
  test('RCPT-04 a post-authentication BLOCK carries the receipt of its own decision; a pre-authentication reject carries none', async () => {
    require('../../../core/consent').verify.mockResolvedValueOnce({ pass: false, reason: 'NO_CONSENT_RECORD' });
    const app = makeApp();
    const artifact = buildArtifact();
    const res = await post(app, artifact);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.reason).not.toBe('REPLAY_DETECTED');
    expect(res.body.receipt).toBeDefined();
    expect(Object.keys(res.body.receipt).sort()).toEqual(RECEIPT_FIELDS);
    expect(res.body.receipt).toMatchObject({ requestId: artifact.payload.requestId, decision: 'BLOCK' });
    expect(res.body.receipt.entryHash).toBe(decisionLeaf().payload.auditEntryHash);
    expect(res.body.receipt.leafHash).toBe(merkleLeafHash(LEAF_ENTRY_HASH));
    expect(verifyReceipt(res.body.receipt).ok).toBe(true);
    expect(independentlyVerified(res.body.receipt)).toBe(true);
    expect(await getReceipt(artifact.payload.requestId)).toEqual(res.body.receipt);

    const pre = await supertest(app).post(CHAT_PATH).send(CHAT_BODY);   // no artifact at all: pre-authentication, nothing recorded
    expect(pre.body.decision).toBe('BLOCK');
    expect(pre.body).not.toHaveProperty('receipt');
  });

  test('RCPT-04b a replay is not a second request: its BLOCK carries no receipt (the receipt of the first request is the one for that requestId)', async () => {
    const app = makeApp();
    const artifact = buildArtifact();
    const first = await post(app, artifact);
    const replay = await post(app, artifact);
    expect(replay.body).toMatchObject({ decision: 'BLOCK', reason: 'REPLAY_DETECTED' });
    expect(replay.body).not.toHaveProperty('receipt');
    expect(await getReceipt(artifact.payload.requestId)).toEqual(first.body.receipt);
  });
});
