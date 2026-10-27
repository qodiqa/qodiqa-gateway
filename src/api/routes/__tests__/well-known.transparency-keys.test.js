'use strict';

/**
 * Tests for GET /.well-known/qodiqa/transparency-keys(/:keyId) —.
 *
 * Mirrors src/api/routes/__tests__/routeHardening.test.js's PH6-46..52
 * "Information exposure" block exactly, but for the transparency-signing key
 * discovery endpoint added so SDKs can locally verify Merkle inclusion-proof
 * entry/root signatures without trusting the server's own verdict.
 */

// test/support/jest.setup.js already provisions an active transparency key (via
// ensureActiveTransparencyKey()) in an isolated per-worker temp store before
// any test file runs — no manual key-store setup needed here, matching how
// routeHardening.test.js relies on the same ambient setup for the artifact
// key store's equivalent routes.

const request = require('supertest');
const express = require('express');

const wellKnownRouter = require('../well-known');

function makeApp() {
  const app = express();
  app.use('/.well-known', wellKnownRouter);
  return app;
}

describe('GET /.well-known/qodiqa/transparency-keys', () => {
  test('returns 200 with at least the provisioned active key', async () => {
    const resp = await request(makeApp()).get('/.well-known/qodiqa/transparency-keys');
    expect(resp.status).toBe(200);
    expect(Array.isArray(resp.body.keys)).toBe(true);
    expect(resp.body.keys.length).toBeGreaterThan(0);
  });

  test('each key has the minimal {keyId, algorithm, publicKey, status} shape', async () => {
    const resp = await request(makeApp()).get('/.well-known/qodiqa/transparency-keys');
    for (const k of resp.body.keys) {
      expect(k).toMatchObject({ algorithm: 'ed25519' });
      expect(typeof k.keyId).toBe('string');
      expect(typeof k.publicKey).toBe('string');
      expect(['active', 'deprecated']).toContain(k.status);
    }
  });

  test('does not include createdAt, clientId, or purpose (lifecycle metadata)', async () => {
    const resp = await request(makeApp()).get('/.well-known/qodiqa/transparency-keys');
    for (const k of resp.body.keys) {
      expect(k).not.toHaveProperty('createdAt');
      expect(k).not.toHaveProperty('clientId');
      expect(k).not.toHaveProperty('purpose');
    }
  });

  test('does not expose private key material', async () => {
    const resp = await request(makeApp()).get('/.well-known/qodiqa/transparency-keys');
    const body = JSON.stringify(resp.body);
    expect(body).not.toMatch(/privDer|privateKey|-----BEGIN PRIVATE/);
  });

  test('POST → 405', async () => {
    const resp = await request(makeApp()).post('/.well-known/qodiqa/transparency-keys');
    expect(resp.status).toBe(405);
  });
});

describe('GET /.well-known/qodiqa/transparency-keys/:keyId', () => {
  test('returns 200 for the provisioned active key, without createdAt', async () => {
    const listResp = await request(makeApp()).get('/.well-known/qodiqa/transparency-keys');
    const keyId    = listResp.body.keys[0].keyId;

    const resp = await request(makeApp()).get(`/.well-known/qodiqa/transparency-keys/${keyId}`);
    expect(resp.status).toBe(200);
    expect(resp.body).toMatchObject({ keyId, algorithm: 'ed25519' });
    expect(resp.body).not.toHaveProperty('createdAt');
  });

  test('malformed keyId → 404 (no enumeration)', async () => {
    const resp = await request(makeApp()).get('/.well-known/qodiqa/transparency-keys/../../etc/passwd');
    expect(resp.status).toBe(404);
  });

  test('unknown-but-valid-format keyId → 404', async () => {
    const resp = await request(makeApp()).get('/.well-known/qodiqa/transparency-keys/nonexistent:key_v9999');
    expect(resp.status).toBe(404);
  });

  test('artifact keyId is never resolvable via the transparency-keys endpoint', async () => {
    // Cross-trust-domain isolation: an artifact-signing keyId (no "tr-"
    // clientId prefix convention) must not resolve here even if it happens
    // to match the generic keyId regex.
    const resp = await request(makeApp()).get('/.well-known/qodiqa/transparency-keys/dev-local:key_v1');
    expect(resp.status).toBe(404);
  });

  test('POST → 405', async () => {
    const listResp = await request(makeApp()).get('/.well-known/qodiqa/transparency-keys');
    const keyId    = listResp.body.keys[0].keyId;
    const resp     = await request(makeApp()).post(`/.well-known/qodiqa/transparency-keys/${keyId}`);
    expect(resp.status).toBe(405);
  });
});
