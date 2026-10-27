import crypto from 'node:crypto';
import { MockServer } from './mock-server';
import {
  QodiqaClient,
  KillSwitchError,
  ServerError,
  VerificationError,
  VERIFICATION_REASONS,
  verifyReceipt,
  receiptBindsTo,
  receiptDigest,
  RECEIPT_DOMAIN,
} from '../src/index';
import { createError } from '../src/errors';
import type { Receipt, SignV2Options, ChatResponse } from '../src/types';

// protocol V2 on the SDK side: bound-request options on sign(), the signed receipt (read, fetch, verify offline),
// the kill switch and the revoked artifact as errors.

const H = (c: string) => c.repeat(64);
const RID = '6f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b';

// A receipt signed exactly as section 6 says, WITHOUT the SDK's own digest function: a published-spec check.
function makeKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { publicKey: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'), privateKey };
}
function signReceipt(privateKey: crypto.KeyObject, keyId: string, over: Partial<Receipt> = {}): Receipt {
  const unsigned = { v: 1 as const, requestId: RID, decision: 'ALLOW' as const, issuedAt: 1790000000000, entryHash: H('a'), leafHash: H('b'), keyId, ...over };
  const canonical = JSON.stringify(Object.fromEntries(Object.keys(unsigned).sort().map((k) => [k, (unsigned as Record<string, unknown>)[k]])));
  const digest = crypto.createHash('sha256').update('QODIQA::RECEIPT::V1', 'utf8').update(canonical, 'utf8').digest();
  return { ...unsigned, signature: crypto.sign(null, digest, privateKey).toString('base64') };
}

describe('verifyReceipt', () => {
  const key = makeKey();
  const keys = [{ keyId: 'tr-default:key_v1', publicKey: key.publicKey, status: 'active' }];
  const receipt = signReceipt(key.privateKey, 'tr-default:key_v1');

  it('verifies a receipt signed per the specification (and the digest is the documented one)', () => {
    expect(verifyReceipt(receipt, keys)).toEqual({ ok: true, reason: null });
    expect(verifyReceipt(receipt, { keys })).toEqual({ ok: true, reason: null });      // the body of /.well-known/qodiqa/transparency-keys
    expect(RECEIPT_DOMAIN).toBe('QODIQA::RECEIPT::V1');
    const { signature: _s, ...unsigned } = receipt;
    const canonical = JSON.stringify(Object.fromEntries(Object.keys(unsigned).sort().map((k) => [k, (unsigned as Record<string, unknown>)[k]])));
    expect(receiptDigest(receipt).equals(crypto.createHash('sha256').update('QODIQA::RECEIPT::V1').update(canonical).digest())).toBe(true);
  });

  it.each([
    ['requestId', { requestId: RID.replace('6f', '7f') }],
    ['decision', { decision: 'BLOCK' as const }],
    ['issuedAt', { issuedAt: 1790000000001 }],
    ['entryHash', { entryHash: H('c') }],
    ['leafHash', { leafHash: H('c') }],
  ])('rejects a receipt whose %s was changed', (_f, patch) => {
    expect(verifyReceipt({ ...receipt, ...patch }, keys)).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
  });

  it('rejects malformed receipts, unknown fields and versions, unknown keys, and signatures by another key', () => {
    for (const bad of [null, undefined, 'x', 7, [], [receipt]]) expect(verifyReceipt(bad, keys).ok).toBe(false);
    expect(verifyReceipt({ ...receipt, tenantId: 't1' }, keys)).toEqual({ ok: false, reason: 'FIELD_SET' });
    const { keyId: _k, ...noKey } = receipt;
    expect(verifyReceipt(noKey, keys)).toEqual({ ok: false, reason: 'FIELD_SET' });
    expect(verifyReceipt({ ...receipt, v: 2 }, keys)).toEqual({ ok: false, reason: 'UNSUPPORTED_VERSION' });
    expect(verifyReceipt({ ...receipt, entryHash: H('A') }, keys)).toEqual({ ok: false, reason: 'INVALID_FIELD' });
    expect(verifyReceipt({ ...receipt, issuedAt: 1.5 }, keys)).toEqual({ ok: false, reason: 'INVALID_FIELD' });
    expect(verifyReceipt({ ...receipt, decision: 'EXECUTE' }, keys)).toEqual({ ok: false, reason: 'INVALID_FIELD' });
    expect(verifyReceipt({ ...receipt, keyId: 'tr-other:key_v1' }, keys)).toEqual({ ok: false, reason: 'UNKNOWN_KEY' });
    const other = makeKey();
    expect(verifyReceipt(receipt, [{ keyId: 'tr-default:key_v1', publicKey: other.publicKey, status: 'active' }])).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
    expect(verifyReceipt({ ...receipt, signature: 'AA==' }, keys)).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
  });

  it('a receipt of a since-revoked key verifies only in the timed mode (trustedAt before revokedAt)', () => {
    const revoked = (extra: Record<string, unknown> = {}) => [{ keyId: 'tr-default:key_v1', publicKey: key.publicKey, status: 'revoked', revokedAt: 1790000100000, ...extra }];
    expect(verifyReceipt(receipt, revoked())).toEqual({ ok: false, reason: 'REVOKED_KEY' });
    expect(verifyReceipt(receipt, revoked(), { trustedAt: 1790000050000 })).toEqual({ ok: true, reason: null });
    expect(verifyReceipt(receipt, revoked(), { trustedAt: 1790000100000 })).toEqual({ ok: false, reason: 'REVOKED_KEY' });
    expect(verifyReceipt(receipt, revoked({ revokedAt: undefined }), { trustedAt: 1 })).toEqual({ ok: false, reason: 'REVOKED_KEY' });
    expect(verifyReceipt(receipt, revoked({ revokedAt: new Date(1790000100000).toISOString() }), { trustedAt: 1790000050000 }).ok).toBe(true);
  });

  it('receiptBindsTo names the values that differ', () => {
    expect(receiptBindsTo(receipt, { entryHash: H('a'), leafHash: H('b'), requestId: RID, decision: 'ALLOW' })).toEqual({ ok: true, mismatches: [] });
    expect(receiptBindsTo(receipt, { entryHash: H('c'), decision: 'BLOCK' })).toEqual({ ok: false, mismatches: ['entryHash', 'decision'] });
  });
});

describe('bound requests, receipts and the new errors over HTTP', () => {
  let server: MockServer;
  let baseUrl: string;
  beforeAll(async () => { server = new MockServer(); baseUrl = await server.start(); });
  afterAll(async () => { await server.stop(); });
  beforeEach(() => { server.reset(); });
  const client = () => new QodiqaClient({ baseUrl, timeout: 5000, maxRetries: 0, signToken: 'sk_test' });

  it('sign() sends the V2 block, the query and the bound headers exactly as given', async () => {
    server.mock('POST', '/sign', { status: 200, body: { artifactId: RID, artifact: { expiry: 2, payload: { requestId: RID, requestHash: H('d'), policyHash: H('e'), tenantId: 't' }, publicKeyId: 'k', timestamp: 1, signature: 's' }, meta: { keyId: 'k', expiresAt: 2, tenantId: 't', callerId: 'c' }, requestId: 'r' } });
    const v2: SignV2Options = { bind: { headers: ['x-tenant'] }, model: 'gpt-4', limits: { maxTokens: 256 }, crit: ['limits'] };
    await client().sign.sign({ request: { method: 'POST', path: '/v1/ai/chat', query: 'stream=true&a=%2B', headers: { 'x-tenant': 'acme' }, body: { prompt: 'hi', model: 'gpt-4' } }, v2 });
    const sent = server.getCallLog()[0]!.body as Record<string, any>;
    expect(sent.v2).toEqual(v2);
    expect(sent.request).toMatchObject({ method: 'POST', path: '/v1/ai/chat', query: 'stream=true&a=%2B', headers: { 'x-tenant': 'acme' } });
  });

  it('chat.create() returns the receipt of an EXECUTE untouched; a response without one has no receipt key', async () => {
    const key = makeKey();
    const receipt = signReceipt(key.privateKey, 'tr-default:key_v1');
    server.mock('POST', '/ai/chat', { status: 200, body: { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', response: 'hello', requestId: 'r1', receipt } });
    const res: ChatResponse = await client().chat.create('QQ==', { prompt: 'hi' });
    expect(res.receipt).toEqual(receipt);
    expect(verifyReceipt(res.receipt, [{ keyId: 'tr-default:key_v1', publicKey: key.publicKey, status: 'active' }]).ok).toBe(true);
    server.reset();
    server.mock('POST', '/ai/chat', { status: 200, body: { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', response: 'hello', requestId: 'r2' } });
    expect(Object.prototype.hasOwnProperty.call(await client().chat.create('QQ==', { prompt: 'hi' }), 'receipt')).toBe(false);
  });

  it('transparency.getReceipt() reads GET /v1/transparency/receipt/:requestId', async () => {
    const key = makeKey();
    const receipt = signReceipt(key.privateKey, 'tr-default:key_v1');
    server.mock('GET', `/v1/transparency/receipt/${RID}`, { status: 200, body: { status: 'success', timestamp: 't', requestId: 'x', data: { receipt } } });
    const res = await client().transparency.getReceipt(RID);
    expect(res.data.receipt).toEqual(receipt);
    await expect(client().transparency.getReceipt('')).rejects.toThrow();
  });

  it('an expired receipt window is a NotFoundError', async () => {
    server.mock('GET', `/v1/transparency/receipt/${RID}`, { status: 404, body: { status: 'error', error: { code: 'NOT_FOUND', message: 'Receipt not found' } } });
    await expect(client().transparency.getReceipt(RID)).rejects.toMatchObject({ name: 'NotFoundError' });
  });

  it('the kill switch (503 BLOCK KILL_SWITCH_ACTIVE) is a KillSwitchError, a ServerError, and is not retried', async () => {
    server.mock('POST', '/ai/chat', { status: 503, body: { decision: 'BLOCK', reason: 'KILL_SWITCH_ACTIVE', details: {}, requestId: 'r' }, headers: { 'Retry-After': '30' } });
    const retrying = new QodiqaClient({ baseUrl, timeout: 5000, maxRetries: 2, signToken: 'sk_test' });
    const err = await retrying.chat.create('QQ==', { prompt: 'hi' }).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(KillSwitchError);
    expect(err).toBeInstanceOf(ServerError);
    expect((err as KillSwitchError).reason).toBe('KILL_SWITCH_ACTIVE');
    expect((err as KillSwitchError).status).toBe(503);
    expect(server.getCallLog().filter((c) => c.path === '/ai/chat')).toHaveLength(1);   // not resent
  });

  it('createError maps both kill-switch reasons, with the server retryAfter hint when present', () => {
    for (const reason of ['KILL_SWITCH_ACTIVE', 'KILL_SWITCH_STATE_UNAVAILABLE']) {
      const e = createError(503, reason, 'x', 'r', { retryAfter: 30 });
      expect(e).toBeInstanceOf(KillSwitchError);
      expect((e as KillSwitchError).retryAfter).toBe(30);
    }
    expect(createError(503, 'SERVER_OVERLOADED', 'x')).not.toBeInstanceOf(KillSwitchError);
  });

  it('a revoked artifact is a VerificationError (it is in the artifact-rejection inventory)', async () => {
    expect(VERIFICATION_REASONS.has('ARTIFACT_REVOKED')).toBe(true);
    server.mock('POST', '/ai/chat', { status: 200, body: { decision: 'BLOCK', reason: 'ARTIFACT_REVOKED', details: {}, requestId: 'r' } });
    await expect(client().chat.create('QQ==', { prompt: 'hi' })).rejects.toBeInstanceOf(VerificationError);
  });
});
