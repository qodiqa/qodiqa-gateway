'use strict';

/**
 * /keys vs /public-keys parity — (API-8 remediation).
 *
 * Both routers delegate to the single shared listPublicKeysForApi()
 * (../shared/publicKeyListing.js). This suite proves that's genuinely true
 * — not coincidental — by mocking the underlying key source with all three
 * real key lifecycle states (active, deprecated, revoked — see
 * services/artifact/keyStore.js) and asserting both endpoints produce
 * byte-identical `data.keys` output as that set changes, plus that only
 * /keys carries the deprecation signal.
 */

const request = require('supertest');
const express  = require('express');

jest.mock('../../../../services/artifact/keyManager');
const keyManager = require('../../../../services/artifact/keyManager');

const keysRouter       = require('../keys');
const publicKeysRouter = require('../publicKeys');

function makeApp(mountPath, router) {
  const app = express();
  app.use(mountPath, router);
  return app;
}

const THREE_STATE_FIXTURE = [
  { clientId: 'parity-client', keyId: 'parity-client:key_v2', version: 2, algorithm: 'ed25519', publicKeyB64: 'AAAAAAAAAAAAAAAAAAAAAA==', status: 'active',     createdAt: '2026-01-01T00:00:00.000Z' },
  { clientId: 'parity-client', keyId: 'parity-client:key_v1', version: 1, algorithm: 'ed25519', publicKeyB64: 'BBBBBBBBBBBBBBBBBBBBBB==', status: 'deprecated', createdAt: '2025-06-01T00:00:00.000Z' },
  { clientId: 'parity-client', keyId: 'parity-client:key_v0', version: 0, algorithm: 'ed25519', publicKeyB64: 'CCCCCCCCCCCCCCCCCCCCCC==', status: 'revoked',    createdAt: '2025-01-01T00:00:00.000Z' },
];

beforeEach(() => {
  keyManager.listPublicKeys = jest.fn(() => THREE_STATE_FIXTURE);
});

describe('GET /keys vs GET /public-keys — output parity across all three key states', () => {
  test('both endpoints return the identical filtered, serialized key set', async () => {
    const publicKeysRes = await request(makeApp('/public-keys', publicKeysRouter)).get('/public-keys');
    const keysRes        = await request(makeApp('/keys', keysRouter)).get('/keys');

    expect(publicKeysRes.status).toBe(200);
    expect(keysRes.status).toBe(200);

    // Revoked key filtered out of both — only active + deprecated remain.
    expect(publicKeysRes.body.data.keys).toHaveLength(2);
    expect(keysRes.body.data.keys).toHaveLength(2);

    expect(keysRes.body.data.keys).toEqual(publicKeysRes.body.data.keys);
  });

  test('every returned key has exactly {keyId, publicKey, algorithm, status, activatedAt, retiredAt} — no divergent shapes (dates added by audit 5.5)', async () => {
    const res = await request(makeApp('/public-keys', publicKeysRouter)).get('/public-keys');
    for (const k of res.body.data.keys) {
      expect(Object.keys(k).sort()).toEqual(['activatedAt', 'algorithm', 'keyId', 'publicKey', 'retiredAt', 'status']);
    }
  });

  test('algorithm is sourced from the real key record, not a hardcoded literal', async () => {
    keyManager.listPublicKeys = jest.fn(() => [
      { ...THREE_STATE_FIXTURE[0], algorithm: 'some-future-algorithm' },
    ]);
    const publicKeysRes = await request(makeApp('/public-keys', publicKeysRouter)).get('/public-keys');
    const keysRes        = await request(makeApp('/keys', keysRouter)).get('/keys');

    expect(publicKeysRes.body.data.keys[0].algorithm).toBe('some-future-algorithm');
    expect(keysRes.body.data.keys[0].algorithm).toBe('some-future-algorithm');
  });

  test('adding a fresh active key to the set keeps both endpoints identical', async () => {
    keyManager.listPublicKeys = jest.fn(() => [
      ...THREE_STATE_FIXTURE,
      { clientId: 'parity-client-2', keyId: 'parity-client-2:key_v1', version: 1, algorithm: 'ed25519', publicKeyB64: 'DDDDDDDDDDDDDDDDDDDDDD==', status: 'active', createdAt: '2026-02-01T00:00:00.000Z' },
    ]);
    const publicKeysRes = await request(makeApp('/public-keys', publicKeysRouter)).get('/public-keys');
    const keysRes        = await request(makeApp('/keys', keysRouter)).get('/keys');

    expect(publicKeysRes.body.data.keys).toHaveLength(3);
    expect(keysRes.body.data.keys).toEqual(publicKeysRes.body.data.keys);
  });
});

describe('GET /keys deprecation signal', () => {
  test('/keys sets Deprecation and Link headers', async () => {
    const res = await request(makeApp('/keys', keysRouter)).get('/keys');
    expect(res.headers['deprecation']).toBe('true');
    expect(res.headers['link']).toBe('</public-keys>; rel="successor-version"');
  });

  test('/public-keys does NOT set deprecation headers', async () => {
    const res = await request(makeApp('/public-keys', publicKeysRouter)).get('/public-keys');
    expect(res.headers['deprecation']).toBeUndefined();
    expect(res.headers['link']).toBeUndefined();
  });
});

describe('published key set carries activation / retirement dates', () => {
  const WITH_RETIREMENT = [
    { clientId: 'c', keyId: 'c:key_v2', version: 2, algorithm: 'ed25519', publicKeyB64: 'AAAAAAAAAAAAAAAAAAAAAA==', status: 'active',     createdAt: '2026-02-01T00:00:00.000Z', retiredAt: null },
    { clientId: 'c', keyId: 'c:key_v1', version: 1, algorithm: 'ed25519', publicKeyB64: 'BBBBBBBBBBBBBBBBBBBBBB==', status: 'deprecated', createdAt: '2026-01-01T00:00:00.000Z', retiredAt: '2026-02-01T00:00:00.000Z' },
  ];
  afterEach(() => { delete process.env.QODIQA_PUBLIC_KEY_DATES; });

  test('active key: activatedAt set, retiredAt null; deprecated key: both set', async () => {
    keyManager.listPublicKeys = jest.fn(() => WITH_RETIREMENT);
    const res = await request(makeApp('/public-keys', publicKeysRouter)).get('/public-keys');
    const byId = Object.fromEntries(res.body.data.keys.map((k) => [k.keyId, k]));
    expect(byId['c:key_v2']).toMatchObject({ activatedAt: '2026-02-01T00:00:00.000Z', retiredAt: null });
    expect(byId['c:key_v1']).toMatchObject({ activatedAt: '2026-01-01T00:00:00.000Z', retiredAt: '2026-02-01T00:00:00.000Z' });
  });

  test('QODIQA_PUBLIC_KEY_DATES=false restores the dateless shape', async () => {
    process.env.QODIQA_PUBLIC_KEY_DATES = 'false';
    keyManager.listPublicKeys = jest.fn(() => WITH_RETIREMENT);
    const res = await request(makeApp('/public-keys', publicKeysRouter)).get('/public-keys');
    for (const k of res.body.data.keys) expect(Object.keys(k).sort()).toEqual(['algorithm', 'keyId', 'publicKey', 'status']);
  });
});
