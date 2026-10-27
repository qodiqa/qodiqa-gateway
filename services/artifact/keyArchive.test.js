'use strict';

/**
 * remediation — Tests
 *
 * Before this remediation, purgeExpiredDeprecated() archived and removed
 * purge-eligible deprecated keys to data/key-archive.json, but nothing ever
 * read that file back — an artifact signed by a purged key became
 * permanently unverifiable. These tests cover the archive-lookup fallback
 * added to getPublicKey(), the listArchivedKeys() discovery data source, the
 * archive index cache, and defensive parsing of a malformed archive file.
 *
 * Coverage:
 *   KA-01…03  getPublicKey() archive fallback (purged key resolves; unknown
 *             key still throws; revoked key never falls back to the archive)
 *   KA-04     listArchivedKeys() reflects a real purge
 *   KA-05     cache invalidation immediately after a purge (no TTL wait)
 *   KA-06…07  missing / empty archive file — graceful, not fail-closed
 *   KA-08     malformed archive entries are skipped, not fatal
 *   KA-09…10  archive index cache: served from cache within TTL, refreshed after TTL
 *   KA-11…12  cold-cache (never-yet-built index) corrupt archive file:
 *             getPublicKey() fails safe to "unknown keyId"; listArchivedKeys()
 *             fails closed with a catchable error (the HTTP-layer 500 path —
 *             see well-known.archived-keys.test.js)
 *   KA-13     non-object entries in the archive (string/number/null/array)
 *             are skipped like any other malformed entry, not a crash
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');

// K1: this fixture edits keys.json deliberately, as a KEK holder would, so it re-seals the record MACs
// (an edit WITHOUT the KEK is exactly what src/infra/crypto/keyRecordSeal.js now refuses).
function resealKeys(d) {
  const seal = require('../../src/infra/crypto/keyRecordSeal');
  return seal.sealFileData(d, require('./keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO), 'artifact');
}

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-karchive-test-'));
}

const TEST_KEK = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

// NOTE: does NOT touch QODIQA_KEY_ARCHIVE_CACHE_TTL_MS — tests that care about
// the archive cache TTL set it explicitly before calling this, and it must
// survive the call (it's read fresh by _archiveCacheTtlMs() on every archive
// lookup, not cached at require time, but resetModules() still requires a
// fresh require() of keyStore to get a clean in-memory _archiveIndex).
function loadFreshKeyStore(dir) {
  jest.resetModules();
  process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
  process.env.QODIQA_KEYS_PATH          = path.join(dir, 'keys.json');
  process.env.QODIQA_KEYS_ARCHIVE_PATH  = path.join(dir, 'key-archive.json');
  require('../secrets/secretsProvider')._clearCache();
  return require('./keyStore');
}

// Rewrites the on-disk retiredAt for a deprecated key so it becomes
// purge-eligible without needing to wait out the real 180-day window, then
// reloads the (already-open) keyStore instance from disk so it observes the
// edit — the same synchronous, fully-supported reload path tests use.
function backdateRetiredAt(keysPath, keyId, daysAgo) {
  const data = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  for (const clientData of Object.values(data.clients)) {
    if (clientData[keyId]) {
      clientData[keyId].retiredAt = new Date(Date.now() - daysAgo * 86_400_000).toISOString();
    }
  }
  fs.writeFileSync(keysPath, JSON.stringify(resealKeys(data), null, 2), 'utf8');
}

describe('archived key verification', () => {
  let dir, keysPath, archivePath, ks;

  beforeEach(() => {
    dir         = makeTempDir();
    keysPath    = path.join(dir, 'keys.json');
    archivePath = path.join(dir, 'key-archive.json');
    delete process.env.QODIQA_KEY_ARCHIVE_CACHE_TTL_MS;
    ks          = loadFreshKeyStore(dir);
  });

  // KA-01: a key purged from the live store resolves via getPublicKey()'s
  // archive fallback, reporting source 'archived' and a verifiable status.
  test('KA-01: getPublicKey() resolves a purged key via the archive, tagged source "archived"', () => {
    ks.rotateKey('ka-client', { mode: 'graceful' }); // provisions v1 active
    ks.rotateKeyGracefully('ka-client');              // v1 -> deprecated (retiredAt=now), v2 active

    const before = ks.getPublicKey('ka-client:key_v1');
    expect(before.source).toBe('live');
    expect(before.status).toBe('deprecated');
    const originalPubDer = Buffer.from(before.pubDer);

    backdateRetiredAt(keysPath, 'ka-client:key_v1', 200);
    ks.reloadFromDisk();

    const purgeResult = ks.purgeExpiredDeprecated('ka-client');
    expect(purgeResult.purged).toBe(1);
    expect(purgeResult.archived[0].keyId).toBe('ka-client:key_v1');

    // Live lookup now misses entirely (KeyStore: unknown keyId) without the
    // fallback — confirmed indirectly by the source below being 'archived'.
    const after = ks.getPublicKey('ka-client:key_v1');
    expect(after.source).toBe('archived');
    expect(after.status).toBe('deprecated');
    expect(after.clientId).toBe('ka-client');
    expect(after.pubDer.equals(originalPubDer)).toBe(true);
  });

  // KA-02: a keyId that was never provisioned, live or archived, still
  // throws the original "unknown keyId" error — no behavior change here.
  test('KA-02: a truly unknown keyId still throws', () => {
    expect(() => ks.getPublicKey('never-existed:key_v1')).toThrow(/unknown keyId/);
  });

  // KA-03: revocation always wins — a revoked live key never falls back to
  // the archive, even though the archive lookup path exists.
  test('KA-03: a revoked key throws the revoked error, never falls back to the archive', () => {
    ks.rotateKey('ka-revoked', { mode: 'emergency' }); // provisions v1 active
    ks.rotateKey('ka-revoked', { mode: 'emergency' }); // v1 -> revoked, v2 active

    expect(() => ks.getPublicKey('ka-revoked:key_v1')).toThrow(/revoked and cannot be used/);
  });

  // KA-04: listArchivedKeys() — the data source for GET
  // /.well-known/qodiqa/keys/archived — reflects a real purge.
  test('KA-04: listArchivedKeys() includes a purged key with its public material', () => {
    ks.rotateKey('ka-list', { mode: 'graceful' });
    ks.rotateKeyGracefully('ka-list');
    backdateRetiredAt(keysPath, 'ka-list:key_v1', 200);
    ks.reloadFromDisk();
    ks.purgeExpiredDeprecated('ka-list');

    const archived = ks.listArchivedKeys();
    const entry     = archived.find(e => e.keyId === 'ka-list:key_v1');
    expect(entry).toBeDefined();
    expect(entry.clientId).toBe('ka-list');
    expect(entry.algorithm).toBe('ed25519');
    expect(typeof entry.publicKeyB64).toBe('string');
    expect(entry.publicKeyB64.length).toBeGreaterThan(0);
  });

  // KA-05: the archive index cache is invalidated immediately after a purge
  // — a just-purged key must not wait out the cache TTL to become visible.
  test('KA-05: cache invalidates immediately after purgeExpiredDeprecated()', () => {
    process.env.QODIQA_KEY_ARCHIVE_CACHE_TTL_MS = String(60 * 60 * 1000); // 1h — would mask a missing invalidation
    ks = loadFreshKeyStore(dir);

    expect(ks.listArchivedKeys()).toEqual([]); // populates the (empty) cache

    ks.rotateKey('ka-cache', { mode: 'graceful' });
    ks.rotateKeyGracefully('ka-cache');
    backdateRetiredAt(keysPath, 'ka-cache:key_v1', 200);
    ks.reloadFromDisk();
    ks.purgeExpiredDeprecated('ka-cache');

    expect(ks.listArchivedKeys().some(e => e.keyId === 'ka-cache:key_v1')).toBe(true);
  });

  // KA-06: no archive file on disk at all — graceful empty result, not a throw.
  test('KA-06: missing archive file — listArchivedKeys() returns [] and getPublicKey() falls through to "unknown"', () => {
    expect(fs.existsSync(archivePath)).toBe(false);
    expect(ks.listArchivedKeys()).toEqual([]);
    expect(() => ks.getPublicKey('whatever:key_v1')).toThrow(/unknown keyId/);
  });

  // KA-07: an archive file that exists but is empty (zero bytes / whitespace)
  // is treated the same as "no file", not a JSON-parse failure.
  test('KA-07: empty archive file — graceful, not fail-closed', () => {
    fs.writeFileSync(archivePath, '');
    expect(ks.listArchivedKeys()).toEqual([]);

    fs.writeFileSync(archivePath, '   \n');
    ks = loadFreshKeyStore(dir); // fresh module instance -> fresh (empty) cache
    expect(ks.listArchivedKeys()).toEqual([]);
  });

  // KA-08: malformed entries (missing/invalid required fields) are skipped
  // individually rather than corrupting the whole archive read.
  test('KA-08: malformed archive entries are skipped; well-formed entries still resolve', () => {
    const goodPubB64 = require('crypto')
      .generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' } })
      .publicKey.toString('base64');

    fs.writeFileSync(archivePath, JSON.stringify({
      version: 1,
      entries: [
        { keyId: 'not-a-valid-keyid-format', clientId: 'x', algorithm: 'ed25519', publicKeyB64: goodPubB64 },
        { keyId: 'ka-good:key_v1', clientId: 'wrong-client', algorithm: 'ed25519', publicKeyB64: goodPubB64 }, // ownership mismatch
        { keyId: 'ka-good:key_v2', clientId: 'ka-good', algorithm: 'ed25519' }, // missing publicKeyB64
        { keyId: 'ka-good:key_v3', clientId: 'ka-good', algorithm: 'ed25519', publicKeyB64: '!!!' }, // decodes to zero bytes
        { keyId: 'ka-good:key_v4', clientId: 'ka-good', algorithm: 'ed25519', publicKeyB64: goodPubB64 }, // the only valid one
      ],
    }, null, 2));

    const archived = ks.listArchivedKeys();
    expect(archived).toHaveLength(1);
    expect(archived[0].keyId).toBe('ka-good:key_v4');

    const resolved = ks.getPublicKey('ka-good:key_v4');
    expect(resolved.source).toBe('archived');
    expect(resolved.status).toBe('deprecated');

    // key_v3's publicKeyB64 decodes to zero bytes — unusable key material,
    // must never surface as a resolvable key.
    expect(() => ks.getPublicKey('ka-good:key_v3')).toThrow(/unknown keyId/);
  });

  // KA-09: repeated lookups within the TTL are served from the cached index
  // — an archive file corrupted/removed after the first read doesn't break
  // subsequent lookups until the cache actually expires.
  test('KA-09: archive index is cached — a later on-disk change is not observed within the TTL', () => {
    process.env.QODIQA_KEY_ARCHIVE_CACHE_TTL_MS = String(60 * 60 * 1000); // 1h
    ks = loadFreshKeyStore(dir);

    const pubB64 = require('crypto')
      .generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' } })
      .publicKey.toString('base64');
    fs.writeFileSync(archivePath, JSON.stringify({
      version: 1,
      entries: [{ keyId: 'ka-ttl:key_v1', clientId: 'ka-ttl', algorithm: 'ed25519', publicKeyB64: pubB64 }],
    }));

    expect(ks.listArchivedKeys()).toHaveLength(1); // builds + caches the index

    // Corrupt the file on disk — if the cache were bypassed, this would throw.
    fs.writeFileSync(archivePath, '{not valid json');
    expect(ks.listArchivedKeys()).toHaveLength(1);
    expect(ks.getPublicKey('ka-ttl:key_v1').source).toBe('archived');
  });

  // KA-10: after the TTL elapses, the index is rebuilt from disk.
  test('KA-10: archive index refreshes after the TTL elapses', async () => {
    process.env.QODIQA_KEY_ARCHIVE_CACHE_TTL_MS = '1';
    ks = loadFreshKeyStore(dir);

    expect(ks.listArchivedKeys()).toEqual([]); // builds + caches an empty index

    const pubB64 = require('crypto')
      .generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' } })
      .publicKey.toString('base64');
    fs.writeFileSync(archivePath, JSON.stringify({
      version: 1,
      entries: [{ keyId: 'ka-fresh:key_v1', clientId: 'ka-fresh', algorithm: 'ed25519', publicKeyB64: pubB64 }],
    }));

    await new Promise(resolve => setTimeout(resolve, 10));
    expect(ks.listArchivedKeys().some(e => e.keyId === 'ka-fresh:key_v1')).toBe(true);
  });

  // KA-11: the archive file is ALREADY corrupt before the very first archive
  // access on this keyStore instance — i.e. _archiveIndex has never been
  // built yet, so this exercises _buildArchiveIndex()'s first-ever call
  // throwing out of _loadArchive(), NOT the "cache already populated, file
  // corrupted afterward" branch KA-09 covers. getPublicKey() must still fail
  // safe to "unknown keyId" rather than propagate the raw JSON parse error.
  test('KA-11: cold-cache corrupt archive file — getPublicKey() fails safe to "unknown keyId"', () => {
    fs.writeFileSync(archivePath, '{not valid json at all');
    // ks (from beforeEach) has never touched the archive yet — first touch happens here.
    expect(() => ks.getPublicKey('nowhere:key_v1')).toThrow(/unknown keyId/);
  });

  // KA-12: same cold-cache corrupt-file scenario, but through
  // listArchivedKeys() — the data source behind the HTTP endpoint. Unlike
  // getPublicKey()'s fail-safe fallback, this is documented to fail CLOSED
  // (throw) so the HTTP layer can map it to a 500 — see
  // well-known.archived-keys.test.js's "KEY_ARCHIVE_UNAVAILABLE" test.
  test('KA-12: cold-cache corrupt archive file — listArchivedKeys() throws (fail-closed)', () => {
    fs.writeFileSync(archivePath, '{not valid json at all');
    expect(() => ks.listArchivedKeys()).toThrow(/cannot read key archive/);
  });

  // KA-13: entries in the archive that aren't objects at all (a raw string,
  // number, null, or nested array — as opposed to KA-08's malformed-but-still
  // object entries) must be skipped individually, not crash index building.
  test('KA-13: non-object archive entries (string/number/null/array) are skipped, not fatal', () => {
    const goodPubB64 = require('crypto')
      .generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' } })
      .publicKey.toString('base64');

    fs.writeFileSync(archivePath, JSON.stringify({
      version: 1,
      entries: [
        'just-a-string',
        42,
        null,
        ['nested', 'array'],
        true,
        { keyId: 'ka-nonobj:key_v1', clientId: 'ka-nonobj', algorithm: 'ed25519', publicKeyB64: goodPubB64 },
      ],
    }));

    const archived = ks.listArchivedKeys();
    expect(archived).toHaveLength(1);
    expect(archived[0].keyId).toBe('ka-nonobj:key_v1');

    expect(ks.getPublicKey('ka-nonobj:key_v1').source).toBe('archived');
  });
});
