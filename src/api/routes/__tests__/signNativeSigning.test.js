'use strict';

/**
 * with a NativeSigningProvider active (Vault Transit / HSM) `/sign` used to answer 500 SIGNING_FAILED —
 * getSigningKey() returns { privDer: null, nativeSigning: true } and the route only knew the local path. The route now signs
 * through keyManager.nativeSign. The "Transit emulator" below has Vault Transit's contract for an ed25519 key: the private key lives
 * inside the emulator, `sign(keyId, hash32)` returns a PURE Ed25519 signature over those 32 bytes (see vault.js sign()).
 */
const request = require('supertest');
const express = require('express');
const crypto  = require('crypto');

const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

function makeTransitEmulator() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const calls = [];
  return {
    pubDer: publicKey.export({ format: 'der', type: 'spki' }),
    calls,
    sign: async (keyId, hash) => { calls.push({ keyId, len: hash.length }); return crypto.sign(null, hash, privateKey); },
  };
}

function loadApp(transit, { badSignature = false } = {}) {
  jest.resetModules();
  process.env.QODIQA_CLIENT_ID = 'default';
  const createSignRouter       = require('../sign');
  const keyManager             = require('../../../../services/artifact/keyManager');
  const { validateAndPrepare } = require('../../../../services/policy/loader');
  const policies = validateAndPrepare({ policies: [{ id: 'POL-TEST', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });

  jest.spyOn(keyManager, 'getSigningKey').mockImplementation((clientId) => ({ keyId: `${clientId}:key_v1`, privDer: null, pubDer: transit.pubDer, clientId, nativeSigning: true }));
  jest.spyOn(keyManager, 'nativeSign').mockImplementation(async (keyId, hash) => (badSignature ? Buffer.alloc(64, 1) : transit.sign(keyId, hash)));

  const app = express();
  app.use(express.json());
  app.use('/sign', createSignRouter(() => policies));
  return { app, keyManager };
}

const body = { request: { method: 'POST', path: '/orders/create', body: { sku: 'SKU-1' } } };
const post = (app, token) => request(app).post('/sign').set('Content-Type', 'application/json').set('Authorization', `Bearer ${token}`).send(body);

describe('POST /sign with a native signing provider (Vault Transit / HSM)', () => {
  afterEach(() => jest.restoreAllMocks());

  test('NATIVE-01 returns 200 and an artifact whose signature verifies against the provider public key; the key never leaves the emulator', async () => {
    const transit = makeTransitEmulator();
    const { app } = loadApp(transit);
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });

    const res = await post(app, apiKey);
    expect(res.status).toBe(200);

    const { envelopeHash } = require('../../../validation/canonicalize');
    const { verify } = require('../../../infra/crypto/ed25519');
    const a = res.body.artifact;
    expect(a.publicKeyId).toBe('default:key_v1');
    expect(verify(envelopeHash({ expiry: a.expiry, payload: a.payload, publicKeyId: a.publicKeyId, timestamp: a.timestamp }), a.signature, transit.pubDer)).toBe(true);
    expect(transit.calls).toEqual([{ keyId: 'default:key_v1', len: 32 }]);
  });

  test('NATIVE-02 a provider signature that does not verify against the registered public key is refused (500 SIGNING_FAILED), no artifact released', async () => {
    const transit = makeTransitEmulator();
    const { app } = loadApp(transit, { badSignature: true });
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });
    const res = await post(app, apiKey);
    expect(res.status).toBe(500);
    expect(JSON.stringify(res.body)).toMatch(/SIGNING_FAILED/);
    expect(res.body.artifact).toBeUndefined();
  });

  test('NATIVE-03 a provider outage fails closed (500 SIGNING_FAILED), never falls back to a local key', async () => {
    const transit = makeTransitEmulator();
    const { app, keyManager } = loadApp(transit);
    keyManager.nativeSign.mockImplementation(async () => { throw new Error('vault unreachable'); });
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });
    const res = await post(app, apiKey);
    expect(res.status).toBe(500);
    expect(res.body.artifact).toBeUndefined();
  });

  test('NATIVE-04 end to end through the REAL VaultTransitSigningProvider against a node-vault Transit emulator', async () => {
    const transit = makeTransitEmulator();
    const { app, keyManager } = loadApp(transit);
    // node-vault stand-in speaking the Transit wire contract: POST transit/sign/<key> {input:b64} -> vault:v1:<b64 sig>
    const vault = { health: async () => ({}), read: async () => ({ data: {} }),
      write: async (p, b) => { expect(p).toBe('transit/sign/default-key_v1'); expect(Object.keys(b)).toEqual(['input']);
        const sig = await transit.sign('default:key_v1', Buffer.from(b.input, 'base64')); return { data: { signature: `vault:v1:${sig.toString('base64')}` } }; } };
    jest.doMock('node-vault', () => () => vault, { virtual: true });
    const { VaultTransitSigningProvider } = require('../../../infra/keys/providers/vault');
    const provider = new VaultTransitSigningProvider({ token: 't' });
    await provider.initialize();
    keyManager.nativeSign.mockImplementation((keyId, hash) => provider.sign(keyId, hash));
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });
    const res = await post(app, apiKey);
    expect(res.status).toBe(200);
    expect(res.body.artifact.signature).toMatch(/^[A-Za-z0-9+/]{86}==$/);
    jest.dontMock('node-vault');
  });
});
