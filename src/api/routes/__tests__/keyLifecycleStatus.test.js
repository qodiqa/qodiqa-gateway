'use strict';

/**
 * CRYPTO-7 / remediation — public key lifecycle status field
 *
 * /public-keys already included `status` (active/deprecated) prior to this
 * change. /keys and /public-key did not. This suite proves both now do,
 * mirroring the already-established /public-keys shape.
 */

const request        = require('supertest');
const express        = require('express');
const requestId       = require('../../../../middleware/requestId');
const attachClientIp  = require('../../../../middleware/clientIp');

const keysRouter      = require('../keys');
const publicKeyRouter = require('../public-key');
const { rotateKey, getActiveKey } = require('../../../../services/artifact/keyStore');

function makeApp(mountPath, router) {
  const app = express();
  app.use(requestId);
  app.use(attachClientIp);
  app.use(express.json());
  app.use(mountPath, router);
  return app;
}

describe('CRYPTO-7/KEY-13 — /keys includes lifecycle status', () => {
  let KEY;
  beforeAll(() => {
    try   { KEY = getActiveKey('kls-keys-client'); }
    catch { rotateKey('kls-keys-client'); KEY = getActiveKey('kls-keys-client'); }
  });

  test('every key in the /keys listing carries a status field', async () => {
    const resp = await request(makeApp('/keys', keysRouter)).get('/keys');
    expect(resp.status).toBe(200);
    expect(Array.isArray(resp.body.data.keys)).toBe(true);
    expect(resp.body.data.keys.length).toBeGreaterThan(0);
    for (const k of resp.body.data.keys) {
      expect(typeof k.status).toBe('string');
      expect(['active', 'deprecated']).toContain(k.status); // revoked keys are filtered out
    }
  });

  test('a deprecated key (graceful rotation) is listed with status "deprecated", not silently indistinguishable from active', async () => {
    rotateKey('kls-keys-client', { mode: 'graceful' });
    const resp = await request(makeApp('/keys', keysRouter)).get('/keys');
    const statuses = resp.body.data.keys
      .filter(k => k.keyId.startsWith('kls-keys-client:'))
      .map(k => k.status);
    expect(statuses).toContain('deprecated');
    expect(statuses).toContain('active');
  });
});

describe('CRYPTO-7/KEY-13 — /public-key includes lifecycle status', () => {
  beforeAll(() => {
    try   { getActiveKey('consent-signer'); }
    catch { rotateKey('consent-signer'); }
  });

  test('the JWKS-style /public-key response includes status: "active"', async () => {
    const resp = await request(makeApp('/public-key', publicKeyRouter)).get('/public-key');
    expect(resp.status).toBe(200);
    expect(resp.body.data.keys).toHaveLength(1);
    expect(resp.body.data.keys[0].status).toBe('active');
  });
});
