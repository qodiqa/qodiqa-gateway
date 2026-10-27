'use strict';

/**
 * Per-artifact revocation.
 *
 * AR-01…AR-06  the store and the API: revoke / lookup, idempotence, TTL, input validation, failure is loud
 * AR-07…AR-10  validateBoundRequest: refused after signature + binding and BEFORE the nonce (the nonce is not consumed),
 *              an unavailable store refuses, a not-revoked artifact is unaffected
 * AR-11…AR-14  the Redis store against a faithful fake client (NX, EX, not-ready)
 * AA-01…AA-05  admin routes
 */

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ emit: (...a) => mockEmit(...a) }));

const express = require('express');
const supertest = require('supertest');

const ar = require('..');
const { validateBoundRequest } = require('../../../validation/validateBoundRequest');
const { signBoundArtifact } = require('../../../validation/signBoundArtifact');
const { getActiveKey } = require('../../../../services/artifact/keyStore');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { createArtifactRevocationsAdminRouter } = require('../../../api/routes/admin/artifactRevocations');

const RID = '8d1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b';
const OP = 'op-alice';
beforeEach(() => mockEmit.mockClear());

describe('AR — store and API', () => {
  test('AR-01 revoke then lookup: the record carries who, why, when; an unknown id is not revoked', async () => {
    const store = ar.createMemoryStore();
    const out = await ar.revoke({ requestId: RID, operatorId: OP, reason: 'leaked in a ticket', tenantId: 't1' }, { _store: store, now: () => 1790000000000 });
    expect(out).toMatchObject({ created: true, ttlSeconds: ar.REVOCATION_TTL_SECONDS });
    expect(out.record).toEqual({ requestId: RID, operatorId: OP, reason: 'leaked in a ticket', tenantId: 't1', revokedAt: new Date(1790000000000).toISOString() });
    expect(await ar.isRevoked(RID, { _store: store })).toEqual(out.record);
    expect(await ar.isRevoked('11111111-1111-4111-8111-111111111111', { _store: store })).toBeNull();
    for (const bad of [undefined, null, '', 5]) expect(await ar.isRevoked(bad, { _store: store })).toBeNull();
  });

  test('AR-02 repeating a revocation is idempotent and keeps the first record', async () => {
    const store = ar.createMemoryStore();
    await ar.revoke({ requestId: RID, operatorId: OP, reason: 'first' }, { _store: store });
    const again = await ar.revoke({ requestId: RID, operatorId: 'op-bob', reason: 'second' }, { _store: store });
    expect(again.created).toBe(false);
    expect((await ar.isRevoked(RID, { _store: store })).operatorId).toBe(OP);
  });

  test('AR-03 the revocation outlives the 60 s artifact life plus skew, then disappears on its own', async () => {
    expect(ar.REVOCATION_TTL_SECONDS).toBeGreaterThanOrEqual(60 + 30);
    const store = ar.createMemoryStore();
    const now = jest.spyOn(Date, 'now');
    now.mockReturnValue(1_000_000);
    await ar.revoke({ requestId: RID, operatorId: OP, reason: 'r' }, { _store: store });
    now.mockReturnValue(1_000_000 + (ar.REVOCATION_TTL_SECONDS - 1) * 1000);
    expect(await ar.isRevoked(RID, { _store: store })).not.toBeNull();
    now.mockReturnValue(1_000_000 + (ar.REVOCATION_TTL_SECONDS + 1) * 1000);
    expect(await ar.isRevoked(RID, { _store: store })).toBeNull();
    now.mockRestore();
  });

  test('AR-04 only a real artifact id, an operator and a bounded reason are accepted', async () => {
    const store = ar.createMemoryStore();
    for (const requestId of [undefined, '', 'abc', 'not-a-uuid', `${RID}x`, '../../etc', 5]) {
      await expect(ar.revoke({ requestId, operatorId: OP, reason: 'r' }, { _store: store })).rejects.toMatchObject({ code: 'INVALID_REQUEST_ID' });
    }
    await expect(ar.revoke({ requestId: RID, operatorId: '', reason: 'r' }, { _store: store })).rejects.toMatchObject({ code: 'OPERATOR_REQUIRED', status: 401 });
    for (const reason of [undefined, '', '   ', 'x'.repeat(501), 'a\nb', 'a\u0000b', 7, {}]) {
      await expect(ar.revoke({ requestId: RID, operatorId: OP, reason }, { _store: store })).rejects.toMatchObject({ code: 'INVALID_REASON' });
    }
    expect(store._size()).toBe(0);
  });

  test('AR-05 the operator action is escalated at CRITICAL with who, what and why', async () => {
    await ar.revoke({ requestId: RID, operatorId: OP, reason: 'drill' }, { _store: ar.createMemoryStore() });
    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'ARTIFACT_REVOKED', expect.objectContaining({ requestId: RID, operatorId: OP, reason: 'drill', created: true }));
  });

  test('AR-06 a store that fails makes the revocation fail loudly: the artifact is NOT revoked and the caller is told', async () => {
    const broken = { async revoke() { throw new Error('redis down'); }, async isRevoked() { return null; } };
    await expect(ar.revoke({ requestId: RID, operatorId: OP, reason: 'r' }, { _store: broken })).rejects.toMatchObject({ code: 'REVOCATION_STORE_UNAVAILABLE', status: 503 });
    expect(mockEmit).toHaveBeenCalledWith('CRITICAL', 'ARTIFACT_REVOCATION_FAILED', expect.objectContaining({ requestId: RID }));
  });
});

describe('AR — in validateBoundRequest', () => {
  const KEY = getActiveKey('default');
  const reqOf = (body) => ({ method: 'POST', path: '/ai/chat', body });
  function artifact(body = { prompt: 'hi', model: 'gpt-4' }) {
    const now = Date.now();
    return { art: signBoundArtifact(reqOf(body), { payload: { provider: 'openai' }, timestamp: now, expiry: now + 60_000, publicKeyId: KEY.keyId }, KEY.privDer), body };
  }
  const run = (art, body, extra = {}) => validateBoundRequest(art, reqOf(body), { _store: extra._store || makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), ...extra });

  test('AR-07 a revoked artifact is refused with ARTIFACT_REVOKED (403 class, no key detail leaked)', async () => {
    const { art, body } = artifact();
    const store = ar.createMemoryStore();
    await ar.revoke({ requestId: art.payload.requestId, operatorId: OP, reason: 'leaked' }, { _store: store });
    const res = await run(art, body, { _revocationStore: store });
    expect(res).toMatchObject({ allowed: false, reason: 'ARTIFACT_REVOKED', details: {} });
    expect(res.publicKeyId).toBe(KEY.keyId);          // authenticated: the BLOCK is attributable and audited like any post-signature BLOCK
  });

  test('AR-08 the check runs BEFORE the nonce: a revoked attempt does not consume it, so the same artifact is still usable if the revocation is gone', async () => {
    const { art, body } = artifact();
    const nonces = makeNonceStore();
    const revoking = ar.createMemoryStore();
    await ar.revoke({ requestId: art.payload.requestId, operatorId: OP, reason: 'oops' }, { _store: revoking });
    expect((await run(art, body, { _store: nonces, _revocationStore: revoking })).reason).toBe('ARTIFACT_REVOKED');
    expect((await run(art, body, { _store: nonces, _revocationStore: ar.createMemoryStore() })).allowed).toBe(true);   // nonce was still free
    expect((await run(art, body, { _store: nonces, _revocationStore: ar.createMemoryStore() })).reason).toBe('REPLAY_DETECTED'); // …and now it is spent
  });

  test('AR-09 a store that cannot answer refuses the request (fail closed) without consuming the nonce', async () => {
    const { art, body } = artifact();
    const nonces = makeNonceStore();
    const broken = { async isRevoked() { throw new Error('redis down'); }, async revoke() {} };
    const res = await run(art, body, { _store: nonces, _revocationStore: broken });
    expect(res).toMatchObject({ allowed: false, reason: 'ARTIFACT_REVOCATION_STATE_UNAVAILABLE' });
    expect(mockEmit).toHaveBeenCalledWith('ERROR', 'ARTIFACT_REVOCATION_CHECK_FAILED', expect.any(Object));
    expect((await run(art, body, { _store: nonces, _revocationStore: ar.createMemoryStore() })).allowed).toBe(true);
  });

  test('AR-10 another artifact, and a not-revoked one, are unaffected; a tampered artifact is still refused by the signature first', async () => {
    const a = artifact({ prompt: 'one', model: 'gpt-4' });
    const b = artifact({ prompt: 'two', model: 'gpt-4' });
    const store = ar.createMemoryStore();
    await ar.revoke({ requestId: a.art.payload.requestId, operatorId: OP, reason: 'r' }, { _store: store });
    expect((await run(b.art, b.body, { _revocationStore: store })).allowed).toBe(true);
    const forged = { ...a.art, payload: { ...a.art.payload, provider: 'anthropic' } };      // changes the signed content
    const res = await run(forged, a.body, { _revocationStore: store });
    expect(res.allowed).toBe(false);
    expect(res.reason).not.toBe('ARTIFACT_REVOKED');                                      // the signature is checked first
  });
});

describe('AR — Redis store (fake client with real NX / EX semantics)', () => {
  function fakeClient({ ready = true } = {}) {
    const kv = new Map(); const ttl = new Map();
    return {
      isReady: ready, kv, ttl,
      async get(k) { return kv.has(k) ? kv.get(k) : null; },
      async set(k, v, { EX, NX } = {}) { if (NX && kv.has(k)) return null; kv.set(k, v); ttl.set(k, EX); return 'OK'; },
      async expire(k, s) { ttl.set(k, s); return 1; },
    };
  }

  test('AR-11 revoke writes artrev:v1:<id> with an EX of REVOCATION_TTL_SECONDS and NX; lookup reads it back', async () => {
    const c = fakeClient();
    const store = ar.createRedisStore(c);
    const out = await ar.revoke({ requestId: RID, operatorId: OP, reason: 'r' }, { _store: store });
    expect(out.created).toBe(true);
    expect(c.kv.has(`artrev:v1:${RID}`)).toBe(true);
    expect(c.ttl.get(`artrev:v1:${RID}`)).toBe(ar.REVOCATION_TTL_SECONDS);
    expect((await ar.isRevoked(RID, { _store: store })).operatorId).toBe(OP);
  });

  test('AR-12 a repeated revocation does not overwrite the first record but refreshes the TTL', async () => {
    const c = fakeClient();
    const store = ar.createRedisStore(c);
    await ar.revoke({ requestId: RID, operatorId: OP, reason: 'first' }, { _store: store });
    c.ttl.set(`artrev:v1:${RID}`, 5);
    const again = await ar.revoke({ requestId: RID, operatorId: 'op-bob', reason: 'second' }, { _store: store });
    expect(again.created).toBe(false);
    expect(JSON.parse(c.kv.get(`artrev:v1:${RID}`)).operatorId).toBe(OP);
    expect(c.ttl.get(`artrev:v1:${RID}`)).toBe(ar.REVOCATION_TTL_SECONDS);
  });

  test('AR-13 a client that is not ready fails both operations (never "not revoked")', async () => {
    const store = ar.createRedisStore(fakeClient({ ready: false }));
    await expect(ar.isRevoked(RID, { _store: store })).rejects.toThrow(/not connected/);
    await expect(ar.revoke({ requestId: RID, operatorId: OP, reason: 'r' }, { _store: store })).rejects.toMatchObject({ code: 'REVOCATION_STORE_UNAVAILABLE' });
  });

  test('AR-14 the key never contains anything but the artifact id', async () => {
    const c = fakeClient();
    await ar.revoke({ requestId: RID, operatorId: OP, reason: 'secret-ish reason', tenantId: 'tenant-x' }, { _store: ar.createRedisStore(c) });
    expect([...c.kv.keys()]).toEqual([`artrev:v1:${RID}`]);
  });
});

describe('AR — case, timeout and first-call behaviour', () => {
  test('AR-20 the id is matched case-insensitively: revoking in upper case revokes the lower-case artifact (and the reverse)', async () => {
    const store = ar.createMemoryStore();
    await ar.revoke({ requestId: RID.toUpperCase(), operatorId: OP, reason: 'upper' }, { _store: store });
    expect(await ar.isRevoked(RID.toLowerCase(), { _store: store })).toMatchObject({ requestId: RID.toLowerCase() });
    expect(await ar.isRevoked(RID.toUpperCase(), { _store: store })).not.toBeNull();
  });

  test('AR-21 a store that never answers is "cannot tell": the lookup rejects after the bound instead of hanging', async () => {
    jest.useFakeTimers();
    try {
      const hung = { kind: 'hung', isRevoked: () => new Promise(() => {}), revoke: () => new Promise(() => {}) };
      const p = ar.isRevoked(RID, { _store: hung });
      const assertion = expect(p).rejects.toThrow(/timed out/);
      await jest.advanceTimersByTimeAsync(ar.STORE_TIMEOUT_MS + 10);
      await assertion;
      const w = ar.revoke({ requestId: RID, operatorId: OP, reason: 'x' }, { _store: hung });
      const wAssertion = expect(w).rejects.toMatchObject({ code: 'REVOCATION_STORE_UNAVAILABLE' });
      await jest.advanceTimersByTimeAsync(ar.STORE_TIMEOUT_MS + 10);
      await wAssertion;
    } finally { jest.useRealTimers(); }
  });

  test('AR-22 the first lookups wait for the in-flight connect instead of failing while Redis is still connecting', async () => {
    const kv = new Map();
    const c = { isReady: false, async get(k) { return kv.has(k) ? kv.get(k) : null; }, async set() { return 'OK'; }, async expire() { return 1; } };
    const connecting = new Promise((resolve) => setTimeout(() => { c.isReady = true; resolve(); }, 30));
    const store = ar.createRedisStore(c, { connecting });
    expect(await store.isRevoked(RID)).toBeNull();      // would have thrown 'Redis not connected' before the fix
    const never = ar.createRedisStore({ isReady: false }, { connecting: Promise.resolve() });
    await expect(never.isRevoked(RID)).rejects.toThrow(/not connected/);
  });
});

describe('AA — admin routes', () => {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.rbacUser = { id: 'u1', username: 'alice', role: 'admin' }; next(); });
  app.use('/v1/admin/artifact-revocations', createArtifactRevocationsAdminRouter());
  const ID2 = '9e1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b';

  test('AA-01 POST revokes; GET shows it; the operator comes from the authenticated request', async () => {
    const post = await supertest(app).post('/v1/admin/artifact-revocations').send({ requestId: ID2, reason: 'ticket 4711' });
    expect(post.status).toBe(200);
    expect(post.body.data).toMatchObject({ created: true, ttlSeconds: ar.REVOCATION_TTL_SECONDS });
    expect(post.body.data.record.operatorId).not.toBe('unattributed-operator');
    const get = await supertest(app).get(`/v1/admin/artifact-revocations/${ID2}`);
    expect(get.status).toBe(200);
    expect(get.body.data).toMatchObject({ revoked: true });
    expect(get.body.data.record.reason).toBe('ticket 4711');
  });

  test('AA-02 repeating is a 200 with created:false', async () => {
    const again = await supertest(app).post('/v1/admin/artifact-revocations').send({ requestId: ID2, reason: 'again' });
    expect(again.status).toBe(200);
    expect(again.body.data.created).toBe(false);
  });

  test('AA-03 a bad id or reason is a 400 and nothing is stored', async () => {
    const bad = await supertest(app).post('/v1/admin/artifact-revocations').send({ requestId: 'nope', reason: 'r' });
    expect(bad.status).toBe(400);
    expect(JSON.stringify(bad.body)).toMatch(/INVALID_REQUEST_ID/);
    const noReason = await supertest(app).post('/v1/admin/artifact-revocations').send({ requestId: '7f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b' });
    expect(noReason.status).toBe(400);
    expect(JSON.stringify(noReason.body)).toMatch(/INVALID_REASON/);
    expect((await supertest(app).get('/v1/admin/artifact-revocations/7f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b')).body.data.revoked).toBe(false);
  });

  test('AA-04 GET with a non-UUID id is a 400 (nothing is looked up)', async () => {
    const res = await supertest(app).get('/v1/admin/artifact-revocations/not-a-uuid');
    expect(res.status).toBe(400);
  });

  test('AA-05 an unexpected failure is a generic 500 that does not echo internals', async () => {
    const spy = jest.spyOn(ar, 'revoke').mockRejectedValue(new Error('redis password=secret'));
    try {
      const res = await supertest(app).post('/v1/admin/artifact-revocations').send({ requestId: ID2, reason: 'r' });
      expect(res.status).toBe(500);
      expect(JSON.stringify(res.body)).not.toMatch(/secret/);
    } finally { spy.mockRestore(); }
  });
});
