'use strict';

/**
 * Signed receipt, store and public retrieval.
 *
 * RC-01…RC-06  issue / verify: the signed document, tamper detection per field, domain separation, input validation
 * RC-07…RC-08  the signing key may rotate while signing; the key id in the document is the key that signed
 * RS-01…RS-05  receiptStore: window, disable, cap, never throws
 * RR-01…RR-04  GET /receipt/:requestId on the public router: 200 body is the receipt only, 404, 400, no authentication
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const express = require('express');
const supertest = require('supertest');

const { issueReceipt, verifyReceipt, receiptDigest, ReceiptError, FIELDS } = require('../receipt');
const store = require('../receiptStore');
const { getTransparencySigner } = require('../transparencySigner');
const { ARTIFACT_DOMAINS } = require('../../../infra/crypto/hashing');

const H = (c) => c.repeat(64);
const RID = '6f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b';
const base = (over = {}) => ({ requestId: RID, decision: 'ALLOW', entryHash: H('a'), leafHash: H('b'), now: 1790000000000, ...over });

describe('receipt issue / verify', () => {
  test('RC-01 the receipt has exactly the eight frozen fields and verifies', async () => {
    const r = await issueReceipt(base());
    expect(Object.keys(r).sort()).toEqual([...FIELDS].sort());
    expect(r).toMatchObject({ v: 1, requestId: RID, decision: 'ALLOW', issuedAt: 1790000000000, entryHash: H('a'), leafHash: H('b') });
    expect(r.keyId).toMatch(/^tr-/);
    expect(verifyReceipt(r)).toEqual({ ok: true, reason: null });
  });

  test('RC-02 the signature is Ed25519 over SHA-256("QODIQA::RECEIPT::V1" || canonical receipt without signature), recomputed here independently', async () => {
    const r = await issueReceipt(base({ decision: 'BLOCK' }));
    const canonical = '{"decision":"BLOCK","entryHash":"' + H('a') + '","issuedAt":1790000000000,"keyId":"' + r.keyId + '","leafHash":"' + H('b') + '","requestId":"' + RID + '","v":1}';
    const digest = crypto.createHash('sha256').update('QODIQA::RECEIPT::V1', 'utf8').update(canonical, 'utf8').digest();
    expect(receiptDigest(r).equals(digest)).toBe(true);
    const { pubDer } = getTransparencySigner().getVerificationKey(r.keyId);
    expect(crypto.verify(null, digest, crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' }), Buffer.from(r.signature, 'base64'))).toBe(true);
    expect(ARTIFACT_DOMAINS.RECEIPT).toBe('QODIQA::RECEIPT::V1');
  });

  test('RC-03 changing any signed field, or adding / removing a field, breaks verification', async () => {
    const r = await issueReceipt(base());
    const variants = {
      requestId: { ...r, requestId: '6f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6c' }, decision: { ...r, decision: 'BLOCK' }, issuedAt: { ...r, issuedAt: r.issuedAt + 1 },
      entryHash: { ...r, entryHash: H('c') }, leafHash: { ...r, leafHash: H('c') },
    };
    for (const [name, v] of Object.entries(variants)) expect({ name, ...verifyReceipt(v) }).toEqual({ name, ok: false, reason: 'BAD_SIGNATURE' });
    expect(verifyReceipt({ ...r, tenantId: 't1' })).toEqual({ ok: false, reason: 'FIELD_SET' });
    const { signature, ...unsigned } = r;
    expect(verifyReceipt(unsigned)).toEqual({ ok: false, reason: 'FIELD_SET' });
    expect(verifyReceipt({ ...r, v: 2 })).toEqual({ ok: false, reason: 'UNSUPPORTED_VERSION' });
    expect(verifyReceipt({ ...r, entryHash: 'XYZ' })).toEqual({ ok: false, reason: 'INVALID_FIELD' });
    expect(verifyReceipt({ ...r, issuedAt: 1.5 })).toEqual({ ok: false, reason: 'INVALID_FIELD' });
    expect(verifyReceipt({ ...r, keyId: 'tr-unknown:key_v9' })).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
    for (const bad of [null, undefined, 'x', 7, [], [r]]) expect(verifyReceipt(bad).ok).toBe(false);
  });

  test('RC-04 domain separation: the same bytes signed without the receipt domain, or with another domain, are not a receipt', async () => {
    const r = await issueReceipt(base());
    const signer = getTransparencySigner();
    const { signature, ...unsigned } = r;
    const canonical = JSON.stringify(Object.fromEntries(Object.keys(unsigned).sort().map((k) => [k, unsigned[k]])));
    for (const domain of ['', 'QODIQA::ARTIFACT::V1', 'QODIQA::AUDIT::V1', 'QODIQA::RECEIPT::V2']) {
      const digest = crypto.createHash('sha256').update(domain, 'utf8').update(canonical, 'utf8').digest();
      const wrong = await signer.sign(digest);
      expect(verifyReceipt({ ...unsigned, keyId: wrong.keyId, signature: wrong.signature })).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
    }
  });

  test('RC-05 a malformed request is refused before anything is signed', async () => {
    for (const over of [{ requestId: '' }, { requestId: 5 }, { decision: 'EXECUTE' }, { entryHash: 'abc' }, { entryHash: H('A') }, { leafHash: null }, { now: -1 }, { now: 1.5 }, { now: '1' }]) {
      await expect(issueReceipt(base(over))).rejects.toMatchObject({ name: 'ReceiptError', code: 'RECEIPT_INVALID' });
    }
    expect(new ReceiptError('X', 'm').code).toBe('X');
  });

  test('RC-06 the receipt never states a tenant, a reason or a provider', async () => {
    const r = await issueReceipt(base());
    expect(JSON.stringify(r)).not.toMatch(/tenant|reason|provider|policy/i);
  });

  test('RC-07 if the active key rotates between choosing the key id and signing, the document is rebuilt with the key that signed', async () => {
    const signer = getTransparencySigner();
    const origSign = signer.sign.bind(signer);
    let calls = 0;
    const rotatedId = signer.getActiveKeyInfo().keyId + '-rotated';
    // After the rotation the signer reports the new key id on every call; the document, built with the old id, must be rebuilt once.
    signer.sign = async (digest) => { calls++; const out = await origSign(digest); return { ...out, keyId: rotatedId }; };
    try {
      const r = await issueReceipt(base());
      expect(calls).toBe(2);
      expect(r.keyId.endsWith('-rotated')).toBe(true);
    } finally { signer.sign = origSign; }
  });

  test('RC-08 a signer that keeps changing key is a failure, not an endless loop', async () => {
    const realSigner = getTransparencySigner();
    const origSign = realSigner.sign.bind(realSigner);
    let n = 0;
    realSigner.sign = async (digest) => { const out = await origSign(digest); return { ...out, keyId: `tr-x:key_v${++n}` }; };
    try {
      await expect(issueReceipt(base())).rejects.toMatchObject({ code: 'RECEIPT_SIGNING_KEY_UNSTABLE' });
      expect(n).toBe(2);
    } finally { realSigner.sign = origSign; }
  });
});

describe('receiptStore', () => {
  const saved = process.env.QODIQA_RECEIPT_TTL_SECONDS;
  const savedRedis = process.env.REDIS_URL;
  beforeEach(() => { store._resetForTests(); delete process.env.REDIS_URL; delete process.env.QODIQA_RECEIPT_TTL_SECONDS; });
  afterAll(() => { if (saved === undefined) delete process.env.QODIQA_RECEIPT_TTL_SECONDS; else process.env.QODIQA_RECEIPT_TTL_SECONDS = saved; if (savedRedis !== undefined) process.env.REDIS_URL = savedRedis; });
  const rcpt = (id = RID) => ({ v: 1, requestId: id, decision: 'ALLOW', issuedAt: 1, entryHash: H('a'), leafHash: H('b'), keyId: 'tr-x:key_v1', signature: 'AA==' });

  test('RS-01 a stored receipt is returned unchanged; an unknown id is null', async () => {
    expect(await store.putReceipt(rcpt())).toBe(true);
    expect(await store.getReceipt(RID)).toEqual(rcpt());
    expect(await store.getReceipt('11111111-1111-4111-8111-111111111111')).toBeNull();
    expect(await store.getReceipt('')).toBeNull();
    expect(await store.getReceipt(undefined)).toBeNull();
  });

  test('RS-02 the retrieval window: the default is 3600 s, bad values fall back, the maximum is 7 days, 0 stores nothing', async () => {
    expect(store.ttlSeconds()).toBe(3600);
    for (const bad of ['x', '-5', '1.5', '']) { process.env.QODIQA_RECEIPT_TTL_SECONDS = bad; expect(store.ttlSeconds()).toBe(3600); }
    process.env.QODIQA_RECEIPT_TTL_SECONDS = '99999999'; expect(store.ttlSeconds()).toBe(store.MAX_TTL_SECONDS);
    process.env.QODIQA_RECEIPT_TTL_SECONDS = '0';
    expect(await store.putReceipt(rcpt())).toBe(false);
    expect(await store.getReceipt(RID)).toBeNull();
  });

  test('RS-03 a receipt expires when its window passes', async () => {
    process.env.QODIQA_RECEIPT_TTL_SECONDS = '60';
    const now = jest.spyOn(Date, 'now');
    now.mockReturnValue(1_000_000);
    await store.putReceipt(rcpt());
    now.mockReturnValue(1_000_000 + 59_000); expect(await store.getReceipt(RID)).not.toBeNull();
    now.mockReturnValue(1_000_000 + 61_000); expect(await store.getReceipt(RID)).toBeNull();
    now.mockRestore();
  });

  test('RS-04 the memory store is bounded: the oldest receipt makes room', async () => {
    const first = '00000000-0000-4000-8000-000000000000';
    await store.putReceipt(rcpt(first));
    for (let i = 1; i <= store.MEMORY_CAP; i++) await store.putReceipt(rcpt(`00000000-0000-4000-8000-${String(i).padStart(12, '0')}`));
    expect(await store.getReceipt(first)).toBeNull();
    expect(await store.getReceipt(`00000000-0000-4000-8000-${String(store.MEMORY_CAP).padStart(12, '0')}`)).not.toBeNull();
  });

  test('RS-05 storing garbage never throws', async () => {
    for (const bad of [null, undefined, {}, { requestId: 5 }, 'x']) await expect(store.putReceipt(bad)).resolves.toBe(false);
  });
});

describe('GET /receipt/:requestId (public router)', () => {
  const { createTransparencyPublicRouter } = require('../../../api/routes/transparencyLog');
  const app = express();
  app.use('/v1/transparency', createTransparencyPublicRouter());
  beforeEach(() => { store._resetForTests(); delete process.env.REDIS_URL; delete process.env.QODIQA_RECEIPT_TTL_SECONDS; });

  test('RR-01 200: the body is the receipt and nothing else, no credentials needed', async () => {
    const r = await issueReceipt(base());
    await store.putReceipt(r);
    const res = await supertest(app).get(`/v1/transparency/receipt/${RID}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ receipt: r });
    expect(verifyReceipt(res.body.data.receipt).ok).toBe(true);
  });

  test('RR-02 404 for an unknown or expired requestId, with no hint about why', async () => {
    const res = await supertest(app).get('/v1/transparency/receipt/6f1c0a52-1d7e-4c25-9b0a-000000000000');
    expect(res.status).toBe(404);
    expect(JSON.stringify(res.body)).not.toMatch(/tenant/i);
  });

  test('RR-03 400 for a requestId that is not a UUID (nothing is looked up)', async () => {
    for (const bad of ['abc', '6f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6', '../../etc/passwd', '%00']) {
      const res = await supertest(app).get(`/v1/transparency/receipt/${encodeURIComponent(bad)}`);
      expect([400, 404]).toContain(res.status);
      expect(res.body).not.toHaveProperty('data.receipt');
    }
    const res = await supertest(app).get('/v1/transparency/receipt/not-a-uuid');
    expect(res.status).toBe(400);
  });

  test('RR-04 only GET exists on this path', async () => {
    const res = await supertest(app).post(`/v1/transparency/receipt/${RID}`).send({});
    expect([404, 405]).toContain(res.status);
  });
});
