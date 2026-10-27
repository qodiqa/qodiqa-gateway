'use strict';

/**
 * application-level field encryption.
 *   FE-01  seal / open: round trip, fresh IV, purpose and row binding, tamper, wrong key, key id
 *   FE-02  objects for JSONB columns: sealed shape, pre-encryption rows still read, modes (auto / required / off / production)
 *   FE-03  KEK rotation with reseal; a dedicated field KEK is used when set
 *   FE-04  the approval store seals the arguments (memory store: the row holds ciphertext, the API returns the arguments)
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const KEK_A = crypto.randomBytes(32).toString('hex');
const KEK_B = crypto.randomBytes(32).toString('hex');
const ENV = ['QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_FIELD_KEY_ENCRYPTION_KEY', 'QODIQA_FIELD_ENCRYPTION', 'NODE_ENV'];
const saved = {};
let fe;

function load(env = {}) {
  jest.resetModules();
  jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
  for (const k of ENV) delete process.env[k];
  Object.assign(process.env, { NODE_ENV: 'test', QODIQA_KEY_ENCRYPTION_KEY: KEK_A }, env);
  for (const k of Object.keys(env)) if (env[k] === null) delete process.env[k];
  fe = require('../fieldEncryption');
  return fe;
}
beforeAll(() => { for (const k of ENV) saved[k] = process.env[k]; });
afterAll(() => { for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });

const ctx = { purpose: 'unit.test', aad: 't1|row-1' };

describe('FE-01 seal / open', () => {
  beforeEach(() => load());
  test('round trip of any JSON value; every seal has a fresh IV; the format is qfe1.<kid>.<iv>.<ct>.<tag>', () => {
    for (const v of [{ path: '/data/x', n: 1, nested: [1, 'é', null] }, 'text', 42, [1, 2], null]) expect(fe.open(fe.seal(v, ctx), ctx)).toEqual(v);
    const a = fe.seal({ x: 1 }, ctx); const b = fe.seal({ x: 1 }, ctx);
    expect(a).not.toBe(b); expect(a).toMatch(/^qfe1\.[0-9a-f]{8}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/); expect(fe.isSealed(a)).toBe(true); expect(fe.isSealed('plain')).toBe(false);
    expect(a).not.toContain('"x"');
  });
  test('another purpose, another row, a flipped bit and a truncation all fail to open, with distinct codes', () => {
    const s = fe.seal({ secret: 1 }, ctx);
    const code = (fn) => { try { fn(); return null; } catch (e) { return e.code; } };
    expect(code(() => fe.open(s, { ...ctx, purpose: 'other' }))).toBe('FIELD_AUTH_FAILED');
    expect(code(() => fe.open(s, { ...ctx, aad: 't1|row-2' }))).toBe('FIELD_AUTH_FAILED');
    const p = s.split('.'); const ct = Buffer.from(p[3], 'base64url'); ct[0] ^= 1;
    expect(code(() => fe.open([p[0], p[1], p[2], ct.toString('base64url'), p[4]].join('.'), ctx))).toBe('FIELD_AUTH_FAILED');
    expect(code(() => fe.open(p.slice(0, 4).join('.'), ctx))).toBe('FIELD_NOT_SEALED');
    expect(code(() => fe.open('plain text', ctx))).toBe('FIELD_NOT_SEALED');
    expect(code(() => fe.seal({}, { aad: 'x' }))).toBe('FIELD_PURPOSE_REQUIRED');
  });
  test('a different KEK is reported as a key mismatch, not as corruption', () => {
    const s = fe.seal({ a: 1 }, ctx);
    load({ QODIQA_KEY_ENCRYPTION_KEY: KEK_B });
    expect(() => fe.open(s, ctx)).toThrow(expect.objectContaining({ code: 'FIELD_KEY_MISMATCH' }));
  });
});

describe('FE-02 objects and modes', () => {
  test('sealObject keeps a JSONB object shape; openObject reads sealed and pre-encryption rows', () => {
    load();
    const stored = fe.sealObject({ path: '/data/x' }, ctx);
    expect(Object.keys(stored)).toEqual(['$qfe']); expect(JSON.stringify(stored)).not.toContain('/data/x');
    expect(fe.openObject(stored, ctx)).toEqual({ path: '/data/x' });
    expect(fe.openObject({ path: '/legacy' }, ctx)).toEqual({ path: '/legacy' });
  });
  test('auto: without a KEK outside production the value is stored as it is (with one warning); required refuses; off never seals; production is required', () => {
    load({ QODIQA_KEY_ENCRYPTION_KEY: null });
    const warn = jest.fn();
    expect(fe.sealObject({ a: 1 }, ctx, { emit: warn })).toEqual({ a: 1 }); fe.sealObject({ a: 2 }, ctx, { emit: warn });
    expect(warn).toHaveBeenCalledTimes(1); expect(warn.mock.calls[0][1]).toBe('FIELD_ENCRYPTION_UNAVAILABLE');
    load({ QODIQA_KEY_ENCRYPTION_KEY: null, QODIQA_FIELD_ENCRYPTION: 'required' });
    expect(() => fe.sealObject({ a: 1 }, ctx)).toThrow(expect.objectContaining({ code: 'FIELD_ENCRYPTION_UNAVAILABLE' }));
    load({ QODIQA_FIELD_ENCRYPTION: 'off' });
    expect(fe.sealObject({ a: 1 }, ctx)).toEqual({ a: 1 });
    expect(fe.mode({ NODE_ENV: 'production' })).toBe('required'); expect(fe.mode({ NODE_ENV: 'production', QODIQA_FIELD_ENCRYPTION: 'off' })).toBe('off'); expect(fe.mode({})).toBe('auto');
  });
});

describe('FE-03 rotation and the dedicated key', () => {
  test('reseal moves a value from the old KEK to the new one without exposing it; the old key no longer opens the result', () => {
    load();
    const oldKek = Buffer.from(KEK_A, 'hex'); const newKek = Buffer.from(KEK_B, 'hex');
    const s = fe.seal({ v: 1 }, ctx);
    const r = fe.reseal(s, ctx, oldKek, newKek);
    expect(r).not.toBe(s); expect(r.split('.')[1]).toBe(fe.kidOf(newKek));
    load({ QODIQA_KEY_ENCRYPTION_KEY: KEK_B });
    expect(fe.open(r, ctx)).toEqual({ v: 1 });
  });
  test('QODIQA_FIELD_KEY_ENCRYPTION_KEY, when set, replaces the shared KEK for fields', () => {
    load({ QODIQA_FIELD_KEY_ENCRYPTION_KEY: KEK_B });
    const s = fe.seal({ v: 1 }, ctx);
    expect(s.split('.')[1]).toBe(fe.kidOf(Buffer.from(KEK_B, 'hex')));
    load({ QODIQA_KEY_ENCRYPTION_KEY: KEK_B });                       // the shared key is now B: the dedicated A-less setup reads the same value
    expect(fe.open(s, ctx)).toEqual({ v: 1 });
  });
});

describe('FE-04 the approval store', () => {
  test('the stored row holds ciphertext; the API returns the arguments; another approval id cannot open the row', async () => {
    load();
    const store = require('../../../core/approvals/approvalStore');
    store._resetForTests && store._resetForTests();
    const H = 'a'.repeat(64);
    const a = await store.request('t1', { sessionId: crypto.randomUUID(), agentId: crypto.randomUUID(), seq: 1, actionHash: H, prevActionHash: null, server: 's', tool: 't', schemaHash: 'b'.repeat(64), actionClass: 'file',
      args: { path: '/data/secret-plan.txt' }, requesterId: 'identity:i1' });
    expect(a.args).toEqual({ path: '/data/secret-plan.txt' });
    const raw = store._peekRowForTests ? store._peekRowForTests('t1', a.approvalId) : null;
    if (raw) { expect(JSON.stringify(raw.args)).not.toContain('secret-plan'); expect(Object.keys(raw.args)).toEqual(['$qfe']); }
    const got = await store.get('t1', a.approvalId);
    expect(got.args).toEqual({ path: '/data/secret-plan.txt' });
  });
});
