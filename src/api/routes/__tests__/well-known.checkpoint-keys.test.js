'use strict';

/**
 * step 6 — GET /.well-known/qodiqa/checkpoint-keys(/:keyId): the audit-checkpoint public keys,
 * published for verifiers. Same contract as the transparency-keys routes (well-known.transparency-keys.test.js).
 *
 *   WK-CP-01  the set lists the active checkpoint key: {keyId, algorithm, publicKey, status} only, no private material
 *   WK-CP-02  a published key verifies a signed checkpoint independently (node:crypto only)
 *   WK-CP-03  by id: 200 for the active key; identical 404 for malformed, unknown, revoked; transparency ids unknown here
 *   WK-CP-04  non-GET → 405
 */

const crypto = require('crypto');
const request = require('supertest');
const express = require('express');

describe('GET /.well-known/qodiqa/checkpoint-keys', () => {
  let app; let ks; let cp;
  beforeAll(() => {
    ks = require('../../../core/audit/checkpoint/checkpointKeyStore');
    cp = require('../../../core/audit/checkpoint/checkpoint');
    ks.ensureActiveKey();
    app = express();
    app.use('/.well-known', require('../well-known'));
  });

  test('WK-CP-01 lists the active key with the minimal shape and no private material', async () => {
    const r = await request(app).get('/.well-known/qodiqa/checkpoint-keys');
    expect(r.status).toBe(200);
    const active = ks.getActiveKey();
    const k = r.body.keys.find((x) => x.keyId === active.keyId);
    expect(k).toEqual({ keyId: active.keyId, algorithm: 'ed25519', publicKey: active.pubDer.toString('base64'), status: 'active' });
    expect(JSON.stringify(r.body)).not.toMatch(/privDer|privateKey|encrypted|BEGIN PRIVATE|createdAt|purpose/);
  });

  test('WK-CP-02 a published key verifies a signed checkpoint independently', async () => {
    const s = cp.signCheckpoint({ chainLength: 7, headHash: 'f'.repeat(64) });
    const r = await request(app).get(`/.well-known/qodiqa/checkpoint-keys/${encodeURIComponent(s.payload.keyId)}`);
    expect(r.status).toBe(200);
    const pub = crypto.createPublicKey({ key: Buffer.from(r.body.publicKey, 'base64'), format: 'der', type: 'spki' });
    expect(crypto.verify(null, cp.checkpointDigest(s.payload), pub, Buffer.from(s.signature, 'base64'))).toBe(true);
  });

  test('WK-CP-03 identical 404 for malformed, unknown and revoked ids; transparency ids are unknown here', async () => {
    const old = ks.getActiveKey().keyId;
    ks.rotateKey();                                                    // emergency: `old` revoked
    const tr = require('../../../core/transparency/transparencyKeyStore').listKeys()[0];
    const ids = ['not a key id', 'cp-default:key_v999', old, ...(tr ? [tr.keyId] : [])];
    const bodies = [];
    for (const id of ids) {
      const r = await request(app).get(`/.well-known/qodiqa/checkpoint-keys/${encodeURIComponent(id)}`);
      expect(r.status).toBe(404);
      bodies.push({ ...r.body, requestId: null });
    }
    expect(new Set(bodies.map((b) => JSON.stringify(b))).size).toBe(1);
    const list = await request(app).get('/.well-known/qodiqa/checkpoint-keys');
    expect(list.body.keys.some((k) => k.keyId === old)).toBe(false);
  });

  test('WK-CP-04 non-GET → 405', async () => {
    expect((await request(app).post('/.well-known/qodiqa/checkpoint-keys')).status).toBe(405);
    expect((await request(app).delete(`/.well-known/qodiqa/checkpoint-keys/${encodeURIComponent(ks.getActiveKey().keyId)}`)).status).toBe(405);
  });
});
