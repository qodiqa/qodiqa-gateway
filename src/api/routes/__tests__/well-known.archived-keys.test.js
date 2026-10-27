'use strict';

/**
 * Tests for GET /.well-known/qodiqa/keys/archived —.
 *
 * The archived discovery endpoint is the counterpart to keyStore.js's
 * getPublicKey() archive fallback: it exposes purged (formerly-'deprecated')
 * artifact-signing keys so verifiers (including the SDKs' RemoteKeyProvider)
 * can resolve a keyId that no longer appears in the live /qodiqa/keys list.
 *
 * test/support/jest.setup.js provisions an active 'default' artifact key before any test
 * file runs, in an isolated per-worker temp keys.json/key-archive.json pair
 * — no manual key-store setup needed for the "no archive yet" cases below.
 */

const request = require('supertest');
const express  = require('express');
const fs       = require('fs');
const os       = require('os');
const path     = require('path');

const wellKnownRouter = require('../well-known');
const keyStore        = require('../../../../services/artifact/keyStore');

// K1: this fixture edits keys.json deliberately, as a KEK holder would, so it re-seals the record MACs
// (an edit WITHOUT the KEK is exactly what src/infra/crypto/keyRecordSeal.js now refuses).
function resealKeys(d) {
  const seal = require('../../../infra/crypto/keyRecordSeal');
  return seal.sealFileData(d, require('../../../../services/artifact/keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO), 'artifact');
}

function makeApp() {
  const app = express();
  app.use('/.well-known', wellKnownRouter);
  return app;
}

// Builds a fully isolated keyStore + well-known router pair, pointed at a
// fresh temp dir, independent of the shared per-worker ambient store the
// rest of this file uses (see test/support/jest.setup.js). Needed whenever a test must
// control exactly what's on disk from the very first archive access — the
// shared ambient store may already have cached an (empty) archive index from
// an earlier test in this file, which would silently mask the scenario this
// is testing (e.g. corrupting the file AFTER something already cached it).
//
// process.env.QODIQA_KEYS_PATH/QODIQA_KEYS_ARCHIVE_PATH are process-global,
// NOT isolated per Jest test file the way the module registry is — leaving
// them pointed at this temp dir would leak into whichever test file runs
// next in this worker and break test/support/jest.setup.js's "only provision if unset"
// guard. Callers MUST invoke the returned `restore()` (e.g. in a `finally`
// block) before the test ends.
function makeIsolatedApp() {
  const prevKeysPath   = process.env.QODIQA_KEYS_PATH;
  const prevArchivePath = process.env.QODIQA_KEYS_ARCHIVE_PATH;

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-wk-archived-test-'));
  jest.resetModules();
  process.env.QODIQA_KEYS_PATH         = path.join(dir, 'keys.json');
  process.env.QODIQA_KEYS_ARCHIVE_PATH = path.join(dir, 'key-archive.json');
  const isolatedRouter = require('../well-known');
  const app = express();
  app.use('/.well-known', isolatedRouter);

  return {
    app,
    archivePath: process.env.QODIQA_KEYS_ARCHIVE_PATH,
    restore() {
      if (prevKeysPath === undefined) delete process.env.QODIQA_KEYS_PATH;
      else process.env.QODIQA_KEYS_PATH = prevKeysPath;
      if (prevArchivePath === undefined) delete process.env.QODIQA_KEYS_ARCHIVE_PATH;
      else process.env.QODIQA_KEYS_ARCHIVE_PATH = prevArchivePath;
    },
  };
}

describe('GET /.well-known/qodiqa/keys/archived', () => {
  test('returns 200 with an empty list when nothing has been purged yet', async () => {
    const resp = await request(makeApp()).get('/.well-known/qodiqa/keys/archived');
    expect(resp.status).toBe(200);
    expect(Array.isArray(resp.body.keys)).toBe(true);
  });

  test('POST → 405 (same guard pattern as the live discovery routes)', async () => {
    const resp = await request(makeApp()).post('/.well-known/qodiqa/keys/archived');
    expect(resp.status).toBe(405);
  });

  test('route ordering: "archived" is never swallowed by the /:keyId route', async () => {
    // If '/qodiqa/keys/archived' were registered after '/qodiqa/keys/:keyId',
    // this request would 404 (keyId="archived" failing KEY_ID_RE) instead of
    // reaching the archived-list handler.
    const resp = await request(makeApp()).get('/.well-known/qodiqa/keys/archived');
    expect(resp.status).not.toBe(404);
  });

  test('a purged key appears in the archived list with the expected shape', async () => {
    keyStore.rotateKey('wk-archived-client', { mode: 'graceful' });
    keyStore.rotateKeyGracefully('wk-archived-client');

    // Force purge-eligibility without waiting out the real retention window.
    const keysPath = process.env.QODIQA_KEYS_PATH;
    const data      = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    data.clients['wk-archived-client']['wk-archived-client:key_v1'].retiredAt =
      new Date(Date.now() - 200 * 86_400_000).toISOString();
    fs.writeFileSync(keysPath, JSON.stringify(resealKeys(data), null, 2), 'utf8');
    keyStore.reloadFromDisk();

    const purgeResult = keyStore.purgeExpiredDeprecated('wk-archived-client');
    expect(purgeResult.purged).toBe(1);

    const resp = await request(makeApp()).get('/.well-known/qodiqa/keys/archived');
    expect(resp.status).toBe(200);
    const entry = resp.body.keys.find(k => k.keyId === 'wk-archived-client:key_v1');
    expect(entry).toMatchObject({ algorithm: 'ed25519', status: 'archived', source: 'archived' });
    expect(typeof entry.publicKey).toBe('string');
    expect(entry.publicKey.length).toBeGreaterThan(0);
  });

  test('does not expose private key material', async () => {
    const resp = await request(makeApp()).get('/.well-known/qodiqa/keys/archived');
    const body = JSON.stringify(resp.body);
    expect(body).not.toMatch(/privDer|privateKey|-----BEGIN PRIVATE/);
  });

  test('a purged key is still resolvable via GET /.well-known/qodiqa/keys/:keyId is unaffected (live-only, unchanged)', async () => {
    // Regression guard: the pre-existing single-key discovery route must
    // remain live-only — it must NOT start resolving archived keys, since
    // that would be an (unrequested) behavior change to an existing endpoint.
    keyStore.rotateKey('wk-live-only-client', { mode: 'graceful' });
    keyStore.rotateKeyGracefully('wk-live-only-client');
    const keysPath = process.env.QODIQA_KEYS_PATH;
    const data      = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    data.clients['wk-live-only-client']['wk-live-only-client:key_v1'].retiredAt =
      new Date(Date.now() - 200 * 86_400_000).toISOString();
    fs.writeFileSync(keysPath, JSON.stringify(resealKeys(data), null, 2), 'utf8');
    keyStore.reloadFromDisk();
    keyStore.purgeExpiredDeprecated('wk-live-only-client');

    const resp = await request(makeApp()).get('/.well-known/qodiqa/keys/wk-live-only-client:key_v1');
    expect(resp.status).toBe(404);
  });

  test('a corrupt archive file on disk → 500 KEY_ARCHIVE_UNAVAILABLE, not a crash', async () => {
    // Uses makeIsolatedApp() (not the shared makeApp()) so the corrupt file
    // is guaranteed to be what the FIRST archive access on this instance
    // ever sees — the shared ambient store may already have cached an empty
    // index from an earlier test above, which would mask listArchivedKeys()
    // throwing (see KA-11/KA-12 in services/artifact/keyArchive.test.js for
    // the equivalent keyStore-level coverage of both the cold-cache
    // getPublicKey() fail-safe path and this fail-closed throw).
    const { app, archivePath, restore } = makeIsolatedApp();
    try {
      fs.writeFileSync(archivePath, '{not valid json at all');
      const resp = await request(app).get('/.well-known/qodiqa/keys/archived');
      expect(resp.status).toBe(500);
      expect(resp.body).toMatchObject({ decision: 'BLOCK', reason: 'KEY_ARCHIVE_UNAVAILABLE' });
    } finally {
      restore();
    }
  });

  // (D3 → C, design decision): 'well_known_archived' is a public-read traffic
  // bucket (failMode 'degrade'). With no backend it is enforced by the
  // per-process fallback — still limited, never open — and flagged degraded.
  test('RL_ENABLED with no rate-limit backend → per-process fallback: served, flagged degraded, 429 over the limit', async () => {
    const prevRlEnabled = process.env.RL_ENABLED;
    process.env.RL_ENABLED = 'true';
    // Same module registry for the limiter we inspect and the router under test
    // (an earlier test in this file calls jest.resetModules()).
    jest.resetModules();
    const rl = require('../../../core/rateLimit');
    rl._resetDegradedForTest();
    try {
      const app = express();
      app.use('/.well-known', require('../well-known'));
      const first = await request(app).get('/.well-known/qodiqa/keys/archived');
      expect(first.status).toBe(200);
      expect(rl._isDegraded('well_known_archived')).toBe(true);
      const limit = rl.getPolicy('well_known_archived').maxRequests;
      let last;
      for (let i = 1; i <= limit; i++) last = await request(app).get('/.well-known/qodiqa/keys/archived');
      expect(last.status).toBe(429);
      expect(last.body).toMatchObject({ decision: 'BLOCK', reason: 'RATE_LIMITED' });
    } finally {
      rl._resetDegradedForTest();
      if (prevRlEnabled === undefined) delete process.env.RL_ENABLED;
      else process.env.RL_ENABLED = prevRlEnabled;
    }
  });

  test('a failMode=closed bucket still fails closed with no backend; this bucket is declared degrade (D3)', async () => {
    // storage.initialize() only runs at real server startup, so enabling RL
    // here leaves the production Redis storage "not ready" — deterministic.
    const prevRlEnabled = process.env.RL_ENABLED;
    process.env.RL_ENABLED = 'true';
    try {
      const rl = require('../../../core/rateLimit');
      expect(rl.getPolicy('well_known_archived').failMode).toBe('degrade');
      expect(rl.getPolicy('sign').failMode).toBe('closed');
      const express = require('express');
      const closedApp = express();
      closedApp.get('/', rl.createRateLimitMiddleware('sign', { envelope: 'decision' }), (_q, r) => r.json({ ok: true }));
      const resp = await request(closedApp).get('/');
      expect(resp.status).toBe(429);
      expect(resp.body).toMatchObject({ decision: 'BLOCK', reason: 'RATE_LIMITED' });
    } finally {
      if (prevRlEnabled === undefined) delete process.env.RL_ENABLED;
      else process.env.RL_ENABLED = prevRlEnabled;
    }
  });
});
