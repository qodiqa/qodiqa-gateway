'use strict';

/**
 * CLN-01: GET /transparency/verify/:transparencyId used to fetch its "prior
 * entry" via a query (listEntries({page:1, pageSize:1})) that could never
 * return the entry matching previous_entry_hash, and discarded the result
 * unused — priorRecord was always null, so CHAIN_LINK was permanently SKIP
 * for every non-genesis entry regardless of whether the chain was intact or
 * spliced. This suite asserts the fixed behavior: the route resolves the
 * real prior entry via logStore.getByEntryHash(), and a claimed-but-
 * unresolved prior (the signature of a spliced/deleted entry) is reported
 * as a FAIL, not silently skipped.
 *
 * Stage 27: the route resolved the entry's signer key through the
 * ARTIFACT key store (keyManager.getVerificationKey), which never holds the
 * transparency (tr-*) keys leaves are signed with — so signatureValid was
 * always null and the verdict was integrity-only (a genuine leaf read VALID with
 * its signature never checked; observed at runtime in Stage 26). The route now
 * resolves through the TRANSPARENCY key store and the SIGNATURE check is part of
 * the verdict (SV-01 … SV-12 below). Entries here are genuinely signed with a key
 * derived's PUBLISHED test seed — never a deployment key.
 */

const express = require('express');
const request = require('supertest');
const crypto  = require('crypto');
const { randomUUID } = crypto;

jest.mock('../../../core/transparency/logStore', () => ({
  getByTransparencyId: jest.fn(),
  // /verify loads its full row (payload included) as qodiqa_system via getForVerification().
  getForVerification: jest.fn(),
  getByEntryHash:      jest.fn(),
  recordVerification:  jest.fn().mockResolvedValue(undefined),
}));

// Transparency-purpose resolvers are driven per test; the ARTIFACT resolver must never be consulted for a
// transparency signer key (SV-11).
jest.mock('../../../../services/artifact/keyManager', () => ({
  getVerificationKey:             jest.fn(() => { throw new Error('artifact key store must not resolve transparency keys'); }),
  getTransparencyKeyStatus:       jest.fn(),
  getTransparencyVerificationKey: jest.fn(),
}));

jest.mock('../../../../services/logger', () => ({
  emit: jest.fn(),
}));

const logStore   = require('../../../core/transparency/logStore');
const keyManager = require('../../../../services/artifact/keyManager');
const metrics    = require('../../../observability/metrics');
const log        = require('../../../core/transparency/log');
const { createTransparencyPublicRouter } = require('../transparencyLog');

//'s PUBLISHED test seed.
const TEST_SEED = Buffer.from('7717'.repeat(16), 'hex');
const TEST_PRIV = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), TEST_SEED]), format: 'der', type: 'pkcs8' });
const TEST_PUB_DER = crypto.createPublicKey(TEST_PRIV).export({ format: 'der', type: 'spki' });
const OTHER_PRIV = crypto.generateKeyPairSync('ed25519').privateKey; // in-memory only: "a different key" for SV-05
const TR_KEY_ID = 'tr-test:key_v1';

function useTransparencyKey(status) {
  keyManager.getTransparencyKeyStatus.mockReturnValue(status);
  keyManager.getTransparencyVerificationKey.mockReturnValue({ pubDer: TEST_PUB_DER, status });
}

function makeApp({ authed = false } = {}) {
  const optionalAuth = authed
    ? (req, _res, next) => { req.rbacUser = Object.freeze({ id: 'op-1', username: 'op', role: 'admin', enabled: true }); next(); }
    : (_q, _s, n) => n();
  const app = express();
  app.use('/transparency', createTransparencyPublicRouter({ optionalAuth }));
  return app;
}

function makeDbRow(camelRecord, id) {
  return {
    id,
    transparency_id:     camelRecord.transparencyId,
    entry_type:          camelRecord.entryType,
    artifact_id:         camelRecord.artifactId        ?? null,
    evidence_chain_id:   camelRecord.evidenceChainId   ?? null,
    verification_id:     camelRecord.verificationId    ?? null,
    payload:             camelRecord.payload            ?? {},
    payload_hash:        camelRecord.payloadHash,
    previous_entry_hash: camelRecord.previousEntryHash ?? null,
    entry_hash:          camelRecord.entryHash,
    signer_key_id:       camelRecord.signerKeyId,
    signer_key_version:  null,
    signature:           camelRecord.signature,
    registered_by:       'system',
    tenant_id:           null,
    created_at:          new Date().toISOString(),
  };
}

function makeEntry(overrides = {}, { signWith = TEST_PRIV } = {}) {
  const payload     = { event: 'test', value: 1 };
  const payloadHash = log.computePayloadHash(payload);
  const base = {
    transparencyId:    randomUUID(),
    entryType:         'ARTIFACT',
    artifactId:        'art-001',
    evidenceChainId:   null,
    verificationId:    null,
    payloadHash,
    previousEntryHash: null,
    signerKeyId:       TR_KEY_ID,
    ...overrides,
  };
  const entryHash = log.computeEntryHash(base);
  const signature = crypto.sign(null, Buffer.from(entryHash, 'hex'), signWith).toString('base64');
  return { ...base, entryHash, payload, signature };
}

describe('GET /transparency/verify/:transparencyId — chain link verification', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    useTransparencyKey('active');
  });

  test('reports CHAIN_LINK as FAIL (overall INVALID) when the claimed prior entry cannot be resolved (spliced/deleted)', async () => {
    const fakePriorHash = 'aa'.repeat(32);
    const entry = makeEntry({ previousEntryHash: fakePriorHash });
    const dbRow = makeDbRow(entry, 2);

    logStore.getForVerification.mockResolvedValue(dbRow);
    logStore.getByEntryHash.mockResolvedValue(null); // prior does not exist

    const app  = makeApp();
    const resp = await request(app).get(`/transparency/verify/${entry.transparencyId}`);

    expect(resp.status).toBe(200);
    expect(logStore.getByEntryHash).toHaveBeenCalledWith(fakePriorHash);

    const chainLinkCheck = resp.body.data.integrityChecks.find(c => c.check === 'CHAIN_LINK');
    expect(chainLinkCheck.result).toBe('FAIL');
    expect(resp.body.data.firstFailure.check).toBe('CHAIN_LINK');
    expect(resp.body.data.result).toBe('INVALID');
  });

  test('reports CHAIN_LINK as PASS (overall VALID) when the prior entry resolves and its hash matches', async () => {
    const priorEntry = makeEntry({ previousEntryHash: null });
    const priorDbRow = makeDbRow(priorEntry, 1);
    const childEntry = makeEntry({ previousEntryHash: priorEntry.entryHash });
    const childDbRow = makeDbRow(childEntry, 2);

    logStore.getForVerification.mockResolvedValue(childDbRow);
    logStore.getByEntryHash.mockResolvedValue(priorDbRow);

    const app  = makeApp();
    const resp = await request(app).get(`/transparency/verify/${childEntry.transparencyId}`);

    expect(resp.status).toBe(200);
    expect(logStore.getByEntryHash).toHaveBeenCalledWith(priorEntry.entryHash);

    const chainLinkCheck = resp.body.data.integrityChecks.find(c => c.check === 'CHAIN_LINK');
    expect(chainLinkCheck.result).toBe('PASS');
    expect(resp.body.data.signatureValid).toBe(true);
    expect(resp.body.data.result).toBe('VALID');
  });

  test('genesis entry (no previousEntryHash) never triggers a prior lookup and passes CHAIN_LINK', async () => {
    const entry = makeEntry({ previousEntryHash: null });
    const dbRow = makeDbRow(entry, 1);

    logStore.getForVerification.mockResolvedValue(dbRow);

    const app  = makeApp();
    const resp = await request(app).get(`/transparency/verify/${entry.transparencyId}`);

    expect(resp.status).toBe(200);
    expect(logStore.getByEntryHash).not.toHaveBeenCalled();

    const chainLinkCheck = resp.body.data.integrityChecks.find(c => c.check === 'CHAIN_LINK');
    expect(chainLinkCheck.result).toBe('PASS');
    expect(resp.body.data.signatureValid).toBe(true);
    expect(resp.body.data.result).toBe('VALID');
  });
});

describe('GET /transparency/verify/:transparencyId — signature verification (Stage 27)', () => {
  let failuresInc;
  let verificationsInc;
  beforeEach(() => {
    jest.clearAllMocks();
    failuresInc      = jest.spyOn(metrics.transparencyVerificationFailuresTotal, 'inc');
    verificationsInc = jest.spyOn(metrics.transparencyVerificationsTotal, 'inc');
  });
  afterEach(() => { failuresInc.mockRestore(); verificationsInc.mockRestore(); });

  async function verify(entry, { authed = false } = {}) {
    logStore.getForVerification.mockResolvedValue(makeDbRow(entry, 1));
    const resp = await request(makeApp({ authed })).get(`/transparency/verify/${entry.transparencyId}`);
    expect(resp.status).toBe(200);
    return resp.body.data;
  }

  test('SV-01 valid signature under an ACTIVE transparency key → VALID, signatureValid true, status active', async () => {
    useTransparencyKey('active');
    const d = await verify(makeEntry());
    expect(d).toMatchObject({ result: 'VALID', signatureValid: true, signerKeyStatus: 'active', firstFailure: null });
    expect(d.integrityChecks.map((c) => [c.check, c.result])).toEqual([['PAYLOAD_HASH', 'PASS'], ['ENTRY_HASH', 'PASS'], ['CHAIN_LINK', 'PASS']]);
    expect(failuresInc).not.toHaveBeenCalled();
    expect(verificationsInc).toHaveBeenCalledWith({ result: 'VALID' });
  });

  test('SV-02 valid signature under a DEPRECATED key → VALID (existing lifecycle policy: historical entries stay verifiable)', async () => {
    useTransparencyKey('deprecated');
    const d = await verify(makeEntry());
    expect(d).toMatchObject({ result: 'VALID', signatureValid: true, signerKeyStatus: 'deprecated' });
  });

  test('SV-03 UNKNOWN signer key → INVALID, signatureValid false, SIGNATURE FAIL (UNKNOWN_KEY); never VALID', async () => {
    keyManager.getTransparencyKeyStatus.mockReturnValue(null);
    const d = await verify(makeEntry());
    expect(d).toMatchObject({ result: 'INVALID', signatureValid: false, signerKeyStatus: 'unknown' });
    expect(d.firstFailure).toMatchObject({ check: 'SIGNATURE', result: 'FAIL', reason: 'UNKNOWN_KEY' });
    expect(keyManager.getTransparencyVerificationKey).not.toHaveBeenCalled();
    expect(failuresInc).toHaveBeenCalledTimes(1);
  });

  test('SV-04 REVOKED signer key → INVALID, signatureValid false, status revoked (KEY_NOT_VERIFIABLE); no key material is fetched', async () => {
    keyManager.getTransparencyKeyStatus.mockReturnValue('revoked');
    const d = await verify(makeEntry());
    expect(d).toMatchObject({ result: 'INVALID', signatureValid: false, signerKeyStatus: 'revoked' });
    expect(d.firstFailure).toMatchObject({ check: 'SIGNATURE', result: 'FAIL', reason: 'KEY_NOT_VERIFIABLE' });
    expect(keyManager.getTransparencyVerificationKey).not.toHaveBeenCalled();
    expect(failuresInc).toHaveBeenCalledTimes(1);
  });

  test('SV-05 signature by a DIFFERENT key (valid encoding) → INVALID (SIGNATURE_INVALID)', async () => {
    useTransparencyKey('active');
    const d = await verify(makeEntry({}, { signWith: OTHER_PRIV }));
    expect(d).toMatchObject({ result: 'INVALID', signatureValid: false, signerKeyStatus: 'active' });
    expect(d.firstFailure).toMatchObject({ check: 'SIGNATURE', result: 'FAIL', reason: 'SIGNATURE_INVALID' });
  });

  test('SV-06 MALFORMED signature → INVALID (SIGNATURE_INVALID)', async () => {
    useTransparencyKey('active');
    const d = await verify({ ...makeEntry(), signature: 'not-a-signature' });
    expect(d).toMatchObject({ result: 'INVALID', signatureValid: false });
    expect(d.firstFailure).toMatchObject({ check: 'SIGNATURE', reason: 'SIGNATURE_INVALID' });
  });

  test('SV-07 integrity-valid entry whose signature CANNOT be verified (key store unavailable) → PARTIAL, never VALID', async () => {
    keyManager.getTransparencyKeyStatus.mockImplementation(() => { throw new Error('store down'); });
    const d = await verify(makeEntry());
    expect(d.result).toBe('PARTIAL');
    expect(d).toMatchObject({ signatureValid: null, signerKeyStatus: null, firstFailure: null });
    expect(d.integrityChecks.every((c) => c.result === 'PASS')).toBe(true);
    expect(failuresInc).not.toHaveBeenCalled();
    expect(verificationsInc).toHaveBeenCalledWith({ result: 'PARTIAL' });
  });

  test('SV-08 missing signer keyId → INVALID (SIGNER_KEY_ID_MISSING)', async () => {
    useTransparencyKey('active');
    const e = makeEntry();
    const d = await verify({ ...e, signerKeyId: null });
    expect(d.result).toBe('INVALID');
    expect(d.signatureValid).toBe(false);
    // The keyId is part of the entry hash, so ENTRY_HASH fails first; the SIGNATURE check still fails independently.
    expect(d.firstFailure.check).toBe('ENTRY_HASH');
    expect(keyManager.getTransparencyKeyStatus).not.toHaveBeenCalled();
  });

  test('SV-09 integrity failure is NOT masked by a valid signature: tampered payload → INVALID, firstFailure PAYLOAD_HASH', async () => {
    useTransparencyKey('active');
    const e = makeEntry();
    const d = await verify({ ...e, payload: { event: 'tampered', value: 2 } });
    expect(d.result).toBe('INVALID');
    expect(d.signatureValid).toBe(true);                     // the signature covers the entry hash, which is intact
    expect(d.firstFailure.check).toBe('PAYLOAD_HASH');
  });

  test('SV-10 integrity failure AND bad signature → firstFailure is the integrity check, not SIGNATURE', async () => {
    keyManager.getTransparencyKeyStatus.mockReturnValue('revoked');
    const e = makeEntry();
    const d = await verify({ ...e, payload: { event: 'tampered', value: 2 } });
    expect(d.result).toBe('INVALID');
    expect(d.firstFailure.check).toBe('PAYLOAD_HASH');
  });

  test('SV-11 the ARTIFACT key store is never used to resolve a transparency signer key', async () => {
    useTransparencyKey('active');
    await verify(makeEntry());
    expect(keyManager.getVerificationKey).not.toHaveBeenCalled();
    expect(keyManager.getTransparencyKeyStatus).toHaveBeenCalledWith(TR_KEY_ID);
    expect(keyManager.getTransparencyVerificationKey).toHaveBeenCalledWith(TR_KEY_ID);
  });

  test('SV-12 persisted record (authenticated caller): verificationResult and checksPerformed carry the SIGNATURE outcome', async () => {
    useTransparencyKey('active');
    await verify(makeEntry(), { authed: true });
    let rec = logStore.recordVerification.mock.calls[0][0];
    expect(rec.verificationResult).toBe('VALID');
    expect(rec.checksPerformed.map((c) => [c.check, c.result])).toEqual([['PAYLOAD_HASH', 'PASS'], ['ENTRY_HASH', 'PASS'], ['CHAIN_LINK', 'PASS'], ['SIGNATURE', 'PASS']]);
    expect(rec.failedCheck).toBeNull();

    logStore.recordVerification.mockClear();
    keyManager.getTransparencyKeyStatus.mockReturnValue('revoked');
    await verify(makeEntry(), { authed: true });
    rec = logStore.recordVerification.mock.calls[0][0];
    expect(rec).toMatchObject({ verificationResult: 'INVALID', failedCheck: 'SIGNATURE', failureReason: 'KEY_NOT_VERIFIABLE' });
    expect(rec.checksPerformed.find((c) => c.check === 'SIGNATURE')).toMatchObject({ result: 'FAIL', reason: 'KEY_NOT_VERIFIABLE' });

    logStore.recordVerification.mockClear();
    keyManager.getTransparencyKeyStatus.mockImplementation(() => { throw new Error('store down'); });
    await verify(makeEntry(), { authed: true });
    rec = logStore.recordVerification.mock.calls[0][0];
    expect(rec.verificationResult).toBe('PARTIAL');
    expect(rec.checksPerformed.find((c) => c.check === 'SIGNATURE')).toMatchObject({ result: 'SKIP', reason: 'KEY_STORE_UNAVAILABLE' });
  });

  test('SV-13 responses never carry key material or error text', async () => {
    keyManager.getTransparencyKeyStatus.mockImplementation(() => { throw new Error('secret-detail-from-store'); });
    const d = await verify(makeEntry());
    const body = JSON.stringify(d);
    expect(body).not.toMatch(/secret-detail-from-store/);
    expect(body).not.toContain(TEST_PUB_DER.toString('base64'));
  });

  // ── Stage 29 (G-2): the status lookup succeeds, the SECOND lookup (getTransparencyVerificationKey) does not ──────
  // Current classification, asserted unchanged: SIGNATURE SKIP / KEY_STORE_UNAVAILABLE → PARTIAL, never VALID, and no
  // signature verification is attempted.

  test('SV-14 status verifiable, second lookup THROWS → PARTIAL, SIGNATURE SKIP (KEY_STORE_UNAVAILABLE), no error text', async () => {
    const verifySpy = jest.spyOn(log, 'verifyEntrySignature');
    keyManager.getTransparencyKeyStatus.mockReturnValue('active');
    keyManager.getTransparencyVerificationKey.mockImplementation(() => { throw new Error('second-lookup-internal-detail'); });
    const d = await verify(makeEntry(), { authed: true });
    expect(d).toMatchObject({ result: 'PARTIAL', signatureValid: null, signerKeyStatus: 'active', firstFailure: null });
    expect(JSON.stringify(d)).not.toMatch(/second-lookup-internal-detail/);
    const rec = logStore.recordVerification.mock.calls[0][0];
    expect(rec.verificationResult).toBe('PARTIAL');
    expect(rec.checksPerformed.find((c) => c.check === 'SIGNATURE')).toEqual({ check: 'SIGNATURE', result: 'SKIP', reason: 'KEY_STORE_UNAVAILABLE' });
    expect(verifySpy).not.toHaveBeenCalled();
    verifySpy.mockRestore();
  });

  test.each([
    ['no pubDer field', { status: 'active' }],
    ['pubDer not a Buffer', { pubDer: 'not-a-buffer', status: 'active' }],
    ['null result', null],
  ])('SV-15 status verifiable, second lookup returns an unusable key (%s) → PARTIAL, SIGNATURE SKIP (KEY_STORE_UNAVAILABLE)', async (_label, keyInfo) => {
    const verifySpy = jest.spyOn(log, 'verifyEntrySignature');
    keyManager.getTransparencyKeyStatus.mockReturnValue('active');
    keyManager.getTransparencyVerificationKey.mockReturnValue(keyInfo);
    const d = await verify(makeEntry(), { authed: true });
    expect(d).toMatchObject({ result: 'PARTIAL', signatureValid: null, firstFailure: null });
    expect(d.result).not.toBe('VALID');
    expect(logStore.recordVerification.mock.calls[0][0].checksPerformed.find((c) => c.check === 'SIGNATURE'))
      .toEqual({ check: 'SIGNATURE', result: 'SKIP', reason: 'KEY_STORE_UNAVAILABLE' });
    expect(verifySpy).not.toHaveBeenCalled();
    verifySpy.mockRestore();
  });

  test('SV-16 revoked BETWEEN the two lookups (status says active, key lookup then refuses as revoked) → PARTIAL, never VALID (Stage 28 R-2: current classification, unchanged)', async () => {
    keyManager.getTransparencyKeyStatus.mockReturnValue('active');
    keyManager.getTransparencyVerificationKey.mockImplementation(() => { throw new Error('TransparencyKeyStore: transparency key "tr-test:key_v1" is revoked'); });
    const d = await verify(makeEntry());
    expect(d.result).toBe('PARTIAL');
    expect(d.signatureValid).toBeNull();
    expect(JSON.stringify(d)).not.toMatch(/is revoked/);
  });

  // ── Stage 29 (G-3): an unexpected status fails closed ─────────────────────────────────────────────────────────────

  test.each(['compromised', 'ACTIVE', '', 'pending'])('SV-17 unexpected key status %p → INVALID, SIGNATURE FAIL (KEY_NOT_VERIFIABLE), no verification attempted', async (status) => {
    const verifySpy = jest.spyOn(log, 'verifyEntrySignature');
    keyManager.getTransparencyKeyStatus.mockReturnValue(status);
    const d = await verify(makeEntry(), { authed: true });
    expect(d).toMatchObject({ result: 'INVALID', signatureValid: false, signerKeyStatus: status });
    expect(d.firstFailure).toEqual({ check: 'SIGNATURE', result: 'FAIL', reason: 'KEY_NOT_VERIFIABLE' });
    expect(keyManager.getTransparencyVerificationKey).not.toHaveBeenCalled();
    expect(verifySpy).not.toHaveBeenCalled();
    expect(logStore.recordVerification.mock.calls[0][0]).toMatchObject({ verificationResult: 'INVALID', failedCheck: 'SIGNATURE', failureReason: 'KEY_NOT_VERIFIABLE' });
    expect(JSON.stringify(d)).not.toContain(TEST_PUB_DER.toString('base64'));
    verifySpy.mockRestore();
  });
});
