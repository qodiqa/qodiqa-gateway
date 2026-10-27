'use strict';

/**
 * ST23-07 / (GET /transparency/consistency) and ST23-04 / (GET /transparency/proof), 2026-10-13.
 *
 * Both verifiers are structural/hash-only by design. Before this change the routes reported that structural result as
 * `valid` — a hash-consistent proof over forged, unsigned or revoked-key roots/entries was "valid". The routes now add
 * the authentication half through the shared signatureTrust.js (the ST23-03 root-audit check), resolving keys exactly
 * like /verify (keyManager → transparency key store; the artifact store is never consulted):
 *   valid = structurallyValid && authenticated; a SKIP (unusable key store) is not authenticated (fail-closed);
 *   structurallyValid / authenticated keep the two halves distinguishable; structural checks keep their rows.
 *
 * Records are genuinely signed with a key derived's PUBLISHED test seed — never a deployment key.
 *
 *   /consistency  CA-01 genuine → valid · CA-02 forged to-root signature · CA-03 unknown key · CA-04 revoked key ·
 *                 CA-05 deprecated key stays valid · CA-06 key store unavailable → SKIP, not valid · CA-07 missing
 *                 signature · CA-08 a cached proof is re-authenticated per request (revocation takes effect) ·
 *                 CA-09 structural failure keeps precedence · CA-10 malformed ids → 400
 *   /proof        PA-01 genuine → valid · PA-02 entry signature invalid · PA-03 root signature invalid · PA-04 unknown
 *                 key · PA-05 revoked key · PA-06 key store unavailable · PA-07 structural failure kept · PA-08 no
 *                 covering root → proof null, unchanged · PA-09 malformed id → 400
 */

const express = require('express');
const request = require('supertest');
const crypto  = require('crypto');
const { randomUUID } = crypto;

jest.mock('../../../core/transparency/logStore', () => ({
  getByTransparencyId: jest.fn(),
  getRootById:         jest.fn(),
  getHashesInRange:    jest.fn(),
  recordVerification:  jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../core/transparency/proofLookup', () => ({ getInclusionProofForEntry: jest.fn() }));
jest.mock('../../../../services/artifact/keyManager', () => ({
  getVerificationKey:             jest.fn(() => { throw new Error('artifact key store must not resolve transparency keys'); }),
  getTransparencyKeyStatus:       jest.fn(),
  getTransparencyVerificationKey: jest.fn(),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const logStore    = require('../../../core/transparency/logStore');
const proofLookup = require('../../../core/transparency/proofLookup');
const keyManager  = require('../../../../services/artifact/keyManager');
const log         = require('../../../core/transparency/log');
const { createTransparencyPublicRouter } = require('../transparencyLog');

//'s PUBLISHED test seed.
const TEST_SEED = Buffer.from('7717'.repeat(16), 'hex');
const TEST_PRIV = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), TEST_SEED]), format: 'der', type: 'pkcs8' });
const TEST_PUB_DER = crypto.createPublicKey(TEST_PRIV).export({ format: 'der', type: 'spki' });
const OTHER_PRIV = crypto.generateKeyPairSync('ed25519').privateKey; // in-memory only: the "forger"
const KEY_ID = 'tr-test:key_v1';

function useKeys(statusByKey) {
  keyManager.getTransparencyKeyStatus.mockImplementation((k) => (k in statusByKey ? statusByKey[k] : null));
  keyManager.getTransparencyVerificationKey.mockImplementation((k) => {
    const s = statusByKey[k];
    if (!s) throw new Error('unknown transparency keyId');
    if (s === 'revoked') throw new Error('transparency key is revoked');
    return { pubDer: TEST_PUB_DER, status: s };
  });
}

const app = () => { const a = express(); a.use('/transparency', createTransparencyPublicRouter({ optionalAuth: (_q, _s, n) => n() })); return a; };

// ── Records ──────────────────────────────────────────────────────────────────

function entryHashes(n, salt) {
  const out = []; let prev = null;
  for (let i = 1; i <= n; i++) {
    const h = log.computeEntryHash({ transparencyId: `t-${salt}-${i}`, entryType: 'ARTIFACT', artifactId: `a-${i}`, evidenceChainId: null,
      verificationId: null, payloadHash: 'a'.repeat(64), previousEntryHash: prev, signerKeyId: KEY_ID });
    out.push({ id: i, entry_hash: h }); prev = h;
  }
  return out;
}

function signedRootRow(hashes, seqTo, { prev = null, priv = TEST_PRIV, keyId = KEY_ID } = {}) {
  const row = {
    id: seqTo, root_id: randomUUID(), seq_from: '1', seq_to: String(seqTo), entry_count: seqTo,
    root_hash: log.computeRootHash(hashes.slice(0, seqTo).map((h) => h.entry_hash)), previous_root_hash: prev,
    signer_key_id: keyId, generated_at: new Date().toISOString(),
  };
  row.signature = priv ? crypto.sign(null, log.computeRootSigningBuffer({ rootId: row.root_id, seqFrom: 1, seqTo, entryCount: seqTo,
    rootHash: row.root_hash, previousRootHash: prev }), priv).toString('base64') : null;
  return row;
}

function signedEntryRow({ priv = TEST_PRIV, keyId = KEY_ID } = {}) {
  const rec = { transparencyId: randomUUID(), entryType: 'ARTIFACT', artifactId: 'art-1', evidenceChainId: null, verificationId: null,
    payloadHash: 'b'.repeat(64), previousEntryHash: null, signerKeyId: keyId };
  const entryHash = log.computeEntryHash(rec);
  return {
    id: 1, transparency_id: rec.transparencyId, entry_type: rec.entryType, artifact_id: rec.artifactId, evidence_chain_id: null,
    verification_id: null, payload_hash: rec.payloadHash, previous_entry_hash: null, entry_hash: entryHash, signer_key_id: keyId,
    signature: crypto.sign(null, Buffer.from(entryHash, 'hex'), priv).toString('base64'), created_at: new Date().toISOString(),
  };
}

// ── /consistency ────────────────────────────────────────────────────────────

describe('GET /transparency/consistency — root authentication (ST23-07 /)', () => {
  let hashes;
  beforeEach(() => {
    jest.clearAllMocks();
    hashes = entryHashes(3, randomUUID());
    logStore.getHashesInRange.mockImplementation(async (from, to) => hashes.filter((h) => h.id >= from && h.id <= to));
    useKeys({ [KEY_ID]: 'active' });
  });

  async function consistency(oldRoot, newRoot) {
    logStore.getRootById.mockImplementation(async (id) => (id === oldRoot.root_id ? oldRoot : id === newRoot.root_id ? newRoot : null));
    const res = await request(app()).get(`/transparency/consistency/${oldRoot.root_id}/${newRoot.root_id}`);
    expect(res.status).toBe(200);
    return res.body.data.verification;
  }

  test('CA-01 two genuine roots: valid, structurallyValid and authenticated', async () => {
    const a = signedRootRow(hashes, 1); const b = signedRootRow(hashes, 3, { prev: a.root_hash });
    const v = await consistency(a, b);
    expect(v).toEqual(expect.objectContaining({ valid: true, structurallyValid: true, authenticated: true, failedCheck: null, failureReason: null }));
    expect(v.checks.map((c) => [c.check, c.result])).toEqual([['CONSISTENCY_PROOF', 'PASS'], ['FROM_ROOT_SIGNATURE', 'PASS'], ['TO_ROOT_SIGNATURE', 'PASS']]);
    expect(keyManager.getVerificationKey).not.toHaveBeenCalled();
  });

  test('CA-02 a hash-consistent to-root signed by an untrusted key is NOT valid (structure still verifies)', async () => {
    const a = signedRootRow(hashes, 1); const b = signedRootRow(hashes, 3, { prev: a.root_hash, priv: OTHER_PRIV });
    const v = await consistency(a, b);
    expect(v).toEqual(expect.objectContaining({ valid: false, structurallyValid: true, authenticated: false, failedCheck: 'TO_ROOT_SIGNATURE', failureReason: 'SIGNATURE_INVALID' }));
  });

  test('CA-03 an unknown signer key fails as UNKNOWN_KEY', async () => {
    const a = signedRootRow(hashes, 1, { keyId: 'tr-gone:key_v9' }); const b = signedRootRow(hashes, 3, { prev: a.root_hash });
    const v = await consistency(a, b);
    expect(v).toEqual(expect.objectContaining({ valid: false, authenticated: false, failedCheck: 'FROM_ROOT_SIGNATURE', failureReason: 'UNKNOWN_KEY' }));
  });

  test('CA-04 a revoked signer key fails as KEY_NOT_VERIFIABLE', async () => {
    useKeys({ [KEY_ID]: 'revoked' });
    const a = signedRootRow(hashes, 1); const b = signedRootRow(hashes, 3, { prev: a.root_hash });
    const v = await consistency(a, b);
    expect(v.valid).toBe(false);
    expect(v.checks.find((c) => c.check === 'FROM_ROOT_SIGNATURE')).toEqual({ check: 'FROM_ROOT_SIGNATURE', result: 'FAIL', reason: 'KEY_NOT_VERIFIABLE', keyStatus: 'revoked' });
  });

  test('CA-05 a deprecated signer key keeps historical roots valid', async () => {
    useKeys({ [KEY_ID]: 'deprecated' });
    const a = signedRootRow(hashes, 1); const b = signedRootRow(hashes, 3, { prev: a.root_hash });
    const v = await consistency(a, b);
    expect(v).toEqual(expect.objectContaining({ valid: true, authenticated: true }));
    expect(v.checks.find((c) => c.check === 'TO_ROOT_SIGNATURE').keyStatus).toBe('deprecated');
  });

  test('CA-06 an unusable key store is SKIP and the proof is NOT valid (fail-closed)', async () => {
    keyManager.getTransparencyKeyStatus.mockImplementation(() => { throw new Error('store bootstrap failed'); });
    const a = signedRootRow(hashes, 1); const b = signedRootRow(hashes, 3, { prev: a.root_hash });
    const v = await consistency(a, b);
    expect(v).toEqual(expect.objectContaining({ valid: false, structurallyValid: true, authenticated: false, failedCheck: 'FROM_ROOT_SIGNATURE', failureReason: 'KEY_STORE_UNAVAILABLE' }));
    expect(v.checks.find((c) => c.check === 'TO_ROOT_SIGNATURE').result).toBe('SKIP');
  });

  test('CA-07 a root with no signature fails as SIGNATURE_MISSING', async () => {
    const a = signedRootRow(hashes, 1); const b = signedRootRow(hashes, 3, { prev: a.root_hash, priv: null });
    const v = await consistency(a, b);
    expect(v).toEqual(expect.objectContaining({ valid: false, failedCheck: 'TO_ROOT_SIGNATURE', failureReason: 'SIGNATURE_MISSING' }));
  });

  test('CA-08 a cached proof is re-authenticated on every request: a later revocation takes effect', async () => {
    const a = signedRootRow(hashes, 1); const b = signedRootRow(hashes, 3, { prev: a.root_hash });
    expect((await consistency(a, b)).valid).toBe(true);
    useKeys({ [KEY_ID]: 'revoked' });
    const v = await consistency(a, b);
    expect(v).toEqual(expect.objectContaining({ valid: false, structurallyValid: true, authenticated: false, failureReason: 'KEY_NOT_VERIFIABLE' }));
    expect(logStore.getHashesInRange).toHaveBeenCalledTimes(1);   // second request served the structural proof from cache
  });

  test('CA-09 a structural failure keeps precedence in failedCheck', async () => {
    const a = signedRootRow(hashes, 1);
    const b = signedRootRow(hashes, 3, { prev: a.root_hash });
    b.root_hash = 'f'.repeat(64);                                 // hash relation broken (signature now also invalid)
    const v = await consistency(a, b);
    expect(v).toEqual(expect.objectContaining({ valid: false, structurallyValid: false, failedCheck: 'CONSISTENCY_PROOF' }));
  });

  test('CA-10 malformed root ids are rejected with 400', async () => {
    const res = await request(app()).get('/transparency/consistency/not-a-uuid/also-not');
    expect(res.status).toBe(400);
  });
});

// ── /proof ──────────────────────────────────────────────────────────────────

describe('GET /transparency/proof — entry + root authentication (ST23-04 /)', () => {
  const STRUCTURAL_OK = { valid: true, checks: [{ check: 'MERKLE_PATH', result: 'PASS' }, { check: 'ROOT_HASH_MATCH', result: 'PASS' }], failedCheck: null, failureReason: null };

  beforeEach(() => { jest.clearAllMocks(); useKeys({ [KEY_ID]: 'active' }); });

  async function proofFor(entryRow, rootRow, structural = STRUCTURAL_OK) {
    logStore.getByTransparencyId.mockResolvedValue(entryRow);
    const proof = log.buildInclusionProof(entryRow, { leafIndex: 0, treeSize: 1, merklePath: [], merkleRoot: rootRow.root_hash }, rootRow);
    proofLookup.getInclusionProofForEntry.mockResolvedValue({ proof, proofVerification: structural, message: null });
    const res = await request(app()).get(`/transparency/proof/${entryRow.transparency_id}`);
    expect(res.status).toBe(200);
    return res.body.data;
  }
  const rootOver = (entryRow, opts) => signedRootRow([{ id: 1, entry_hash: entryRow.entry_hash }], 1, opts);

  test('PA-01 genuine entry and root: valid, structurallyValid and authenticated', async () => {
    const e = signedEntryRow();
    const d = await proofFor(e, rootOver(e));
    expect(d.proofVerification).toEqual(expect.objectContaining({ valid: true, structurallyValid: true, authenticated: true, failedCheck: null }));
    expect(d.proofVerification.checks.map((c) => [c.check, c.result])).toEqual([['MERKLE_PATH', 'PASS'], ['ROOT_HASH_MATCH', 'PASS'], ['ENTRY_SIGNATURE', 'PASS'], ['ROOT_SIGNATURE', 'PASS']]);
    expect(keyManager.getVerificationKey).not.toHaveBeenCalled();
  });

  test('PA-02 an entry signed by an untrusted key: not valid, failedCheck ENTRY_SIGNATURE', async () => {
    const e = signedEntryRow({ priv: OTHER_PRIV });
    const d = await proofFor(e, rootOver(e));
    expect(d.proofVerification).toEqual(expect.objectContaining({ valid: false, structurallyValid: true, authenticated: false, failedCheck: 'ENTRY_SIGNATURE', failureReason: 'SIGNATURE_INVALID' }));
  });

  test('PA-03 a root signed by an untrusted key: not valid, failedCheck ROOT_SIGNATURE', async () => {
    const e = signedEntryRow();
    const d = await proofFor(e, rootOver(e, { priv: OTHER_PRIV }));
    expect(d.proofVerification).toEqual(expect.objectContaining({ valid: false, authenticated: false, failedCheck: 'ROOT_SIGNATURE', failureReason: 'SIGNATURE_INVALID' }));
  });

  test('PA-04 an unknown signer key: not valid (UNKNOWN_KEY)', async () => {
    useKeys({});
    const e = signedEntryRow();
    const d = await proofFor(e, rootOver(e));
    expect(d.proofVerification).toEqual(expect.objectContaining({ valid: false, failedCheck: 'ENTRY_SIGNATURE', failureReason: 'UNKNOWN_KEY' }));
  });

  test('PA-05 a revoked signer key: not valid (KEY_NOT_VERIFIABLE)', async () => {
    useKeys({ [KEY_ID]: 'revoked' });
    const e = signedEntryRow();
    const d = await proofFor(e, rootOver(e));
    expect(d.proofVerification).toEqual(expect.objectContaining({ valid: false, failureReason: 'KEY_NOT_VERIFIABLE' }));
  });

  test('PA-06 an unusable key store: SKIP, not valid (fail-closed)', async () => {
    keyManager.getTransparencyKeyStatus.mockImplementation(() => { throw new Error('store bootstrap failed'); });
    const e = signedEntryRow();
    const d = await proofFor(e, rootOver(e));
    expect(d.proofVerification).toEqual(expect.objectContaining({ valid: false, structurallyValid: true, authenticated: false, failureReason: 'KEY_STORE_UNAVAILABLE' }));
    expect(d.proofVerification.checks.filter((c) => c.result === 'SKIP').map((c) => c.check)).toEqual(['ENTRY_SIGNATURE', 'ROOT_SIGNATURE']);
  });

  test('PA-07 a structural failure is kept (and wins failedCheck) even when signatures authenticate', async () => {
    const e = signedEntryRow();
    const structural = { valid: false, checks: [{ check: 'MERKLE_PATH', result: 'FAIL', reason: 'path mismatch' }], failedCheck: 'MERKLE_PATH', failureReason: 'path mismatch' };
    const d = await proofFor(e, rootOver(e), structural);
    expect(d.proofVerification).toEqual(expect.objectContaining({ valid: false, structurallyValid: false, authenticated: true, failedCheck: 'MERKLE_PATH', failureReason: 'path mismatch' }));
  });

  test('PA-08 no covering root yet: proof null with the message, unchanged', async () => {
    const e = signedEntryRow();
    logStore.getByTransparencyId.mockResolvedValue(e);
    proofLookup.getInclusionProofForEntry.mockResolvedValue({ proof: null, proofVerification: null, message: 'No root has been generated covering this entry yet.' });
    const res = await request(app()).get(`/transparency/proof/${e.transparency_id}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ transparencyId: e.transparency_id, proof: null, message: 'No root has been generated covering this entry yet.' });
  });

  test('PA-09 a malformed transparency id is rejected with 400', async () => {
    const res = await request(app()).get('/transparency/proof/not-a-uuid');
    expect(res.status).toBe(400);
  });
});
