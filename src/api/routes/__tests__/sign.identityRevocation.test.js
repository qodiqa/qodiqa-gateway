'use strict';

// on POST /sign:
//   SW-01..05 the granted ttl is capped at the 60 s max artifact age;
//              above it the ttl is CLAMPED (not rejected) and the response says so
//   SW-06 /sign never rewrites the signing-identity store (the
//              old touchLastUsed whole-file rewrite) — the file is byte-identical after
//              many requests, and the snapshot still records lastUsedAt

const express = require('express');
const request = require('supertest');
const fs = require('fs');
const crypto = require('crypto');

process.env.QODIQA_CLIENT_ID = 'default';
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
const { apiKey: SIGN_TOKEN, identityId, storePath } = provisionTestSigningIdentity({ tenantId: 'default' });
const { validateAndPrepare } = require('../../../../services/policy/loader');
const createSignRouter = require('../sign');
const signingStore = require('../../../core/signing/signingIdentityStore');

const policies = validateAndPrepare({ policies: [{ id: 'POL-TEST', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
const app = express();
app.use(express.json());
app.use('/sign', createSignRouter(() => policies));

const sign = (ttl) => request(app).post('/sign').set('Authorization', `Bearer ${SIGN_TOKEN}`)
  .send({ request: { method: 'POST', path: '/orders/create', body: { sku: 'A' } }, ...(ttl === undefined ? {} : { ttl }) });

describe('POST /sign', () => {
  test('SW-01 ttl above 60 s is clamped to 60 s, not rejected; ttlClamped = true', async () => {
    const res = await sign(120_000);
    expect(res.status).toBe(200);
    expect(res.body.meta).toMatchObject({ ttlClamped: true, effectiveTtlMs: 60_000 });
    expect(res.body.artifact.expiry - res.body.artifact.timestamp).toBe(60_000);
  });

  test('SW-02 ttl exactly 60 s is granted as asked; ttlClamped = false', async () => {
    const res = await sign(60_000);
    expect(res.body.meta).toMatchObject({ ttlClamped: false, effectiveTtlMs: 60_000 });
  });

  test('SW-03 ttl below 60 s is granted as asked', async () => {
    const res = await sign(30_000);
    expect(res.body.meta).toMatchObject({ ttlClamped: false, effectiveTtlMs: 30_000 });
    expect(res.body.artifact.expiry - res.body.artifact.timestamp).toBe(30_000);
  });

  test('SW-04 no ttl → the max artifact age (60 s), not the old 5 min', async () => {
    const res = await sign(undefined);
    expect(res.body.meta).toMatchObject({ ttlClamped: false, effectiveTtlMs: 60_000 });
  });

  test('SW-05 a 24 h request (the schema maximum) is clamped too', async () => {
    const res = await sign(86_400_000);
    expect(res.status).toBe(200);
    expect(res.body.meta).toMatchObject({ ttlClamped: true, effectiveTtlMs: 60_000 });
  });

  test('SW-06 /sign never rewrites the signing-identity store; lastUsedAt is still recorded in the snapshot', async () => {
    const digest = () => crypto.createHash('sha256').update(fs.readFileSync(storePath)).digest('hex');
    const before = digest();
    const mtime = fs.statSync(storePath).mtimeMs;
    for (let i = 0; i < 25; i++) expect((await sign(10_000)).status).toBe(200);
    expect(digest()).toBe(before);
    expect(fs.statSync(storePath).mtimeMs).toBe(mtime);
    expect(signingStore.getSigningIdentity(identityId).lastUsedAt).toEqual(expect.any(String));
  });
});
