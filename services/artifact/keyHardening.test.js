'use strict';

/**
 * Key Storage Hardening tests
 *
 * Coverage:
 *   Migration tests:
 *     1.  Plaintext key → encrypted on bootstrap (KEY_MIGRATION_STARTED + COMPLETED emitted)
 *     2.  Field format migration (legacy ciphertext/tag → encryptedPrivateKey/authTag)
 *     3.  Duplicate migration prevention — already-encrypted file triggers no migration events
 *     4.  Lifecycle-only migration emits KEY_MIGRATION_STARTED + COMPLETED
 *
 *   Validation tests:
 *     5.  Post-migration scan: encrypted file → _scanFileForPlaintext returns []
 *     6.  Post-migration scan: file with privateKeyDer → entries returned
 *     7.  validateStartup refuses when plaintext key injected after bootstrap
 *     8.  validateStartup refuses when KEK missing
 *
 *   Failure tests:
 *     9.  KEY_MIGRATION_FAILED emitted when saveKeys cannot write
 *     10. Bootstrap throws on post-migration residual plaintext
 *
 *   Field structure tests:
 *     11. encryptKeyMaterial returns all required fields (keyId, algorithm, encryptedPrivateKey, iv, authTag, createdAt, updatedAt)
 *     12. encryptKeyMaterial metadata (keyId, createdAt) populated from argument
 *     13. decryptKeyMaterial accepts legacy ciphertext/tag format
 *     14. decryptKeyMaterial accepts new encryptedPrivateKey/authTag format
 *     15. Each encryption produces a unique IV (unique-IV guarantee)
 *
 *   Regression tests:
 *     16. Migrated keys: signing produces valid signature, verifiable after migration
 *     17. Pre-existing deprecated key public material unaffected by migration
 *     18. Idempotency: re-bootstrapping an already-encrypted file does not alter privDer
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');
// THROUGHPUT-12: services/logger.js batches INFO/WARN/ERROR stdout writes and
// flushes asynchronously (see that file's header comment). CRITICAL/FATAL
// still write synchronously to stderr, so stderr-only assertions below are
// unaffected; stdout-checking tests await a flush before reading `events`.
//
// This file calls jest.resetModules() extensively, which invalidates any
// logger.js reference captured before the reset (the module registry gives
// out a *new* logger.js instance, with its own separate write buffer, to
// whatever gets require()'d next) — so flush() must always be re-required
// fresh at the point of use, exactly like this file already does for
// secretsProvider and keyStore, never cached at module load time.
function _flushLogger() { return require('../../services/logger').flush(); }

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-harden-'));
  return path.join(dir, 'keys.json');
}

const TEST_KEK = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const ALT_KEK  = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function loadFreshKeyStore(keysPath, kek) {
  jest.resetModules();
  if (kek !== undefined) {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = kek;
  } else {
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
  }
  process.env.QODIQA_KEYS_PATH = keysPath;
  require('../../services/secrets/secretsProvider')._clearCache();
  return require('../../services/artifact/keyStore');
}

function loadFreshKeyManager(keysPath, kek) {
  jest.resetModules();
  if (kek !== undefined) {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = kek;
  } else {
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
  }
  process.env.QODIQA_KEYS_PATH = keysPath;
  require('../../services/secrets/secretsProvider')._clearCache();
  return require('../../services/artifact/keyManager');
}

function writeLegacyPlaintextFile(keysPath, clientId) {
  const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
  });
  const file = {
    version: 1,
    clients: {
      [clientId]: {
        [`${clientId}:key_v1`]: {
          clientId,
          keyId:         `${clientId}:key_v1`,
          version:       1,
          algorithm:     'ed25519',
          privateKeyDer: Buffer.from(priv).toString('base64'),
          publicKeyDer:  Buffer.from(pub).toString('base64'),
          status:        'active',
          createdAt:     new Date().toISOString(),
        },
      },
    },
    legacyMap: {},
  };
  fs.mkdirSync(path.dirname(keysPath), { recursive: true });
  fs.writeFileSync(keysPath, JSON.stringify(file, null, 2), 'utf8');
  return { privDer: Buffer.from(priv), pubDer: Buffer.from(pub) };
}

function writeLegacyFieldFormatFile(keysPath, clientId, kek) {
  // First create a real encrypted key with the current code, then rewrite the
  // encryptedPrivateKeyDer to use old field names (ciphertext/tag).
  const ks = loadFreshKeyStore(keysPath, kek);
  ks.rotateKey(clientId);

  const raw  = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  const cdata = raw.clients[clientId];
  const activeId = Object.keys(cdata).find(k => cdata[k].status === 'active');
  // K1: current code writes a SEALED file with an AAD-bound ciphertext, which cannot be relabelled as
  // legacy. Reproduce what pre-K1 code actually wrote: no recordSeal/recordMac and an AAD-less ciphertext.
  delete raw.recordSeal;
  for (const e of Object.values(cdata)) delete e.recordMac;
  const epk  = require('./keyEncryption').encryptKeyMaterial(ks.getActiveKey(clientId).privDer, { keyId: activeId });

  // Rewrite with legacy field names
  cdata[activeId].encryptedPrivateKeyDer = {
    algorithm:  epk.algorithm,
    iv:         epk.iv,
    ciphertext: epk.encryptedPrivateKey,
    tag:        epk.authTag,
  };
  fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');
}

// ── Capture structured log events from stdout/stderr ─────────────────────────

async function captureEvents(fn) {
  const events = [];
  const origStdout = process.stdout.write.bind(process.stdout);
  const origStderr = process.stderr.write.bind(process.stderr);

  const capture = (data) => {
    if (typeof data !== 'string') return;
    // A single write() call may contain multiple '\n'-joined records (see
    // services/logger.js batched stdout flush) — split before parsing.
    for (const line of data.split('\n')) {
      if (!line.trim()) continue;
      try { events.push(JSON.parse(line.trim())); } catch { /* not JSON */ }
    }
  };

  jest.spyOn(process.stdout, 'write').mockImplementation((data) => { capture(data); return origStdout(data); });
  jest.spyOn(process.stderr, 'write').mockImplementation((data) => { capture(data); return origStderr(data); });

  try {
    await fn();
    await _flushLogger();
  } finally {
    process.stdout.write.mockRestore();
    process.stderr.write.mockRestore();
  }

  return events;
}

// ── 1. Plaintext key → encrypted on bootstrap ─────────────────────────────────

describe('Migration — plaintext key to encrypted', () => {
  test('bootstrap migrates plaintext key and emits KEY_MIGRATION_STARTED + KEY_MIGRATION_COMPLETED', async () => {
    const keysPath = makeTempPath();
    writeLegacyPlaintextFile(keysPath, 'pt-migrate-1');

    let events = [];
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../services/secrets/secretsProvider')._clearCache();

    const origWrite = process.stdout.write.bind(process.stdout);
    jest.spyOn(process.stdout, 'write').mockImplementation((data) => {
      if (typeof data === 'string') {
        // A single write() may contain multiple '\n'-joined records (batched
        // stdout flush — see services/logger.js) — split before parsing.
        for (const line of data.split('\n')) {
          if (!line.trim()) continue;
          try { events.push(JSON.parse(line.trim())); } catch {}
        }
      }
      return origWrite(data);
    });

    try {
      // Migration is now deferred until first real store access — require()
      // itself is side-effect-free, so trigger the lazy bootstrap explicitly.
      require('../../services/artifact/keyStore').getActiveKey('pt-migrate-1');
      await _flushLogger();
    } finally {
      process.stdout.write.mockRestore();
    }

    const names = events.map(e => e.eventType);
    expect(names).toContain('KEY_MIGRATION_STARTED');
    expect(names).toContain('KEY_MIGRATION_COMPLETED');
  });

  test('after migration the file has encryptedPrivateKeyDer, not privateKeyDer', () => {
    const keysPath = makeTempPath();
    writeLegacyPlaintextFile(keysPath, 'pt-migrate-2');

    loadFreshKeyStore(keysPath, TEST_KEK).getActiveKey('pt-migrate-2'); // triggers migration

    const saved = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const entry = saved.clients['pt-migrate-2']['pt-migrate-2:key_v1'];
    expect(entry.privateKeyDer).toBeUndefined();
    expect(entry.encryptedPrivateKeyDer).toBeDefined();
    expect(entry.encryptedPrivateKeyDer.algorithm).toBe('aes-256-gcm');
    expect(entry.encryptedPrivateKeyDer.encryptedPrivateKey).toBeDefined();
    expect(entry.encryptedPrivateKeyDer.authTag).toBeDefined();
  });

  test('migrated key is still usable for signing', () => {
    const keysPath = makeTempPath();
    const { privDer } = writeLegacyPlaintextFile(keysPath, 'pt-sign');

    const ks  = loadFreshKeyStore(keysPath, TEST_KEK);
    const key = ks.getActiveKey('pt-sign');
    expect(key.privDer.equals(privDer)).toBe(true);
  });
});

// ── 2. Field format migration (ciphertext/tag → encryptedPrivateKey/authTag) ──

describe('Migration — legacy field format upgrade', () => {
  test('file with ciphertext/tag field names triggers migration and is rewritten', () => {
    const keysPath = makeTempPath();
    writeLegacyFieldFormatFile(keysPath, 'ff-migrate', TEST_KEK);

    // Verify file still uses old names before reload
    const before = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const clientBefore = before.clients['ff-migrate'];
    const activeIdBefore = Object.keys(clientBefore).find(k => clientBefore[k].status === 'active');
    expect(clientBefore[activeIdBefore].encryptedPrivateKeyDer.ciphertext).toBeDefined();
    expect(clientBefore[activeIdBefore].encryptedPrivateKeyDer.encryptedPrivateKey).toBeUndefined();

    // Bootstrap with new code → field format migration. Migration is deferred
    // until first real store access, so trigger it explicitly.
    loadFreshKeyStore(keysPath, TEST_KEK).getActiveKey('ff-migrate');

    const after = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const clientAfter = after.clients['ff-migrate'];
    const activeIdAfter = Object.keys(clientAfter).find(k => clientAfter[k].status === 'active');
    expect(clientAfter[activeIdAfter].encryptedPrivateKeyDer.encryptedPrivateKey).toBeDefined();
    expect(clientAfter[activeIdAfter].encryptedPrivateKeyDer.authTag).toBeDefined();
    expect(clientAfter[activeIdAfter].encryptedPrivateKeyDer.ciphertext).toBeUndefined();
    expect(clientAfter[activeIdAfter].encryptedPrivateKeyDer.tag).toBeUndefined();
  });

  test('field format migration emits KEY_MIGRATION_STARTED + KEY_MIGRATION_COMPLETED', async () => {
    const keysPath = makeTempPath();
    writeLegacyFieldFormatFile(keysPath, 'ff-events', TEST_KEK);

    const events = [];
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../services/secrets/secretsProvider')._clearCache();

    const origWrite = process.stdout.write.bind(process.stdout);
    jest.spyOn(process.stdout, 'write').mockImplementation((data) => {
      if (typeof data === 'string') {
        for (const line of data.split('\n')) {
          if (!line.trim()) continue;
          try { events.push(JSON.parse(line.trim())); } catch {}
        }
      }
      return origWrite(data);
    });
    try {
      // Migration is deferred until first real store access.
      require('../../services/artifact/keyStore').getActiveKey('ff-events');
      await _flushLogger();
    } finally {
      process.stdout.write.mockRestore();
    }

    const names = events.map(e => e.eventType);
    expect(names).toContain('KEY_MIGRATION_STARTED');
    expect(names).toContain('KEY_MIGRATION_COMPLETED');
  });

  test('decryptKeyMaterial still works on old-format entries (backward compat)', () => {
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    require('../../services/secrets/secretsProvider')._clearCache();
    const enc = require('../../services/artifact/keyEncryption');

    const privDer = crypto.randomBytes(48);
    const box     = enc.encryptKeyMaterial(privDer);
    // Downgrade to legacy field names
    const legacy  = { algorithm: box.algorithm, iv: box.iv, ciphertext: box.encryptedPrivateKey, tag: box.authTag };
    const result  = enc.decryptKeyMaterial(legacy);
    expect(result.equals(privDer)).toBe(true);
  });
});

// ── 3. Duplicate migration prevention (idempotency) ───────────────────────────

describe('Migration — idempotency', () => {
  test('already-encrypted file does NOT emit migration events on second bootstrap', async () => {
    const keysPath = makeTempPath();
    // First bootstrap: creates and saves encrypted key
    loadFreshKeyStore(keysPath, TEST_KEK).rotateKey('idem-test');

    // Second bootstrap: file is already in current format — no migration needed
    const events = [];
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../services/secrets/secretsProvider')._clearCache();

    const origWrite = process.stdout.write.bind(process.stdout);
    jest.spyOn(process.stdout, 'write').mockImplementation((data) => {
      if (typeof data === 'string') {
        for (const line of data.split('\n')) {
          if (!line.trim()) continue;
          try { events.push(JSON.parse(line.trim())); } catch {}
        }
      }
      return origWrite(data);
    });
    try {
      // Trigger the (now-lazy) load explicitly so this genuinely exercises
      // the idempotent-load path rather than trivially observing zero events
      // because nothing touched the store at all.
      require('../../services/artifact/keyStore').getActiveKey('idem-test');
      await _flushLogger();
    } finally {
      process.stdout.write.mockRestore();
    }

    const names = events.map(e => e.eventType);
    expect(names).not.toContain('KEY_MIGRATION_STARTED');
    expect(names).not.toContain('KEY_MIGRATION_COMPLETED');
  });

  test('re-bootstrapping an encrypted file preserves private key material', () => {
    const keysPath = makeTempPath();
    const ks1 = loadFreshKeyStore(keysPath, TEST_KEK);
    ks1.rotateKey('idem-key');
    const key1 = ks1.getActiveKey('idem-key');

    const ks2  = loadFreshKeyStore(keysPath, TEST_KEK);
    const key2 = ks2.getActiveKey('idem-key');

    expect(key2.privDer.equals(key1.privDer)).toBe(true);
    expect(key2.pubDer.equals(key1.pubDer)).toBe(true);
  });
});

// ── 4. Post-migration scan ─────────────────────────────────────────────────────

describe('Post-migration scan — _scanFileForPlaintext', () => {
  test('returns [] for a fully-encrypted key file', () => {
    const keysPath = makeTempPath();
    const ks = loadFreshKeyStore(keysPath, TEST_KEK);
    ks.rotateKey('scan-ok');

    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../services/secrets/secretsProvider')._clearCache();
    const ks2 = require('../../services/artifact/keyStore');
    expect(ks2._scanFileForPlaintext()).toEqual([]);
  });

  test('returns affected entries when privateKeyDer present in file', () => {
    const keysPath = makeTempPath();
    writeLegacyPlaintextFile(keysPath, 'scan-bad');

    // Manually read — bypass bootstrap migration by reading the raw function
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../services/secrets/secretsProvider')._clearCache();

    // To call _scanFileForPlaintext on the plaintext file we need the module
    // but bootstrap will migrate it. Instead, verify via reading file directly.
    // After migration, file should be clean. We verify the scanner by writing
    // a synthetic plaintext entry after migration.
    const ks = require('../../services/artifact/keyStore');
    // Migration is deferred until first real store access — trigger it now,
    // before injecting the synthetic plaintext entry below, so the file on
    // disk only still has the *injected* entry as plaintext.
    ks.getActiveKey('scan-bad');

    // Re-inject a plaintext entry into the file after migration (simulates tampering)
    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    raw.clients['injected'] = {
      'injected:key_v1': {
        clientId: 'injected', keyId: 'injected:key_v1', version: 1,
        algorithm: 'ed25519',
        publicKeyDer: 'AAAA',
        privateKeyDer: 'BBBB',
        status: 'active',
        createdAt: new Date().toISOString(),
      },
    };
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');

    const found = ks._scanFileForPlaintext();
    expect(found.length).toBe(1);
    expect(found[0].keyId).toBe('injected:key_v1');
    expect(found[0].clientId).toBe('injected');
  });

  test('returns [] when file does not exist', () => {
    const keysPath = path.join(os.tmpdir(), 'qodiqa-nonexistent-' + Date.now(), 'keys.json');
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../services/secrets/secretsProvider')._clearCache();
    const ks = require('../../services/artifact/keyStore');
    expect(ks._scanFileForPlaintext()).toEqual([]);
  });
});

// ── 5. validateStartup — startup refusal ──────────────────────────────────────

describe('validateStartup — startup refusal for plaintext keys', () => {
  test('validateStartup throws CRITICAL when plaintext key injected after bootstrap', () => {
    const keysPath = makeTempPath();
    const km = loadFreshKeyManager(keysPath, TEST_KEK);
    km.rotate('refusal-test');

    // Inject a plaintext key entry into the file after bootstrap
    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    raw.clients['tampered'] = {
      'tampered:key_v1': {
        clientId: 'tampered', keyId: 'tampered:key_v1', version: 1,
        algorithm: 'ed25519',
        publicKeyDer: 'AAAA',
        privateKeyDer: 'BBBB',
        status: 'active',
        createdAt: new Date().toISOString(),
      },
    };
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');

    // validateStartup should detect it and throw
    expect(() => km.validateStartup()).toThrow(/CRITICAL.*Unencrypted private key/i);
  });

  test('validateStartup emits CRITICAL KEY_PLAINTEXT_DETECTED before throwing', () => {
    const keysPath = makeTempPath();
    const km = loadFreshKeyManager(keysPath, TEST_KEK);
    km.rotate('critical-test');

    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    raw.clients['critical-client'] = {
      'critical-client:key_v1': {
        clientId: 'critical-client', keyId: 'critical-client:key_v1', version: 1,
        algorithm: 'ed25519', publicKeyDer: 'AAAA',
        privateKeyDer: 'BBBB', status: 'active',
        createdAt: new Date().toISOString(),
      },
    };
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');

    const events = [];
    const origStderr = process.stderr.write.bind(process.stderr);
    jest.spyOn(process.stderr, 'write').mockImplementation((data) => {
      if (typeof data === 'string') { try { events.push(JSON.parse(data.trim())); } catch {} }
      return origStderr(data);
    });
    try {
      km.validateStartup();
    } catch {
      // expected
    } finally {
      process.stderr.write.mockRestore();
    }

    const criticalEvents = events.filter(e => e.eventType === 'KEY_PLAINTEXT_DETECTED');
    expect(criticalEvents.length).toBeGreaterThan(0);
    expect(criticalEvents[0].severity).toBe('CRITICAL');
    expect(criticalEvents[0].keyId).toBe('critical-client:key_v1');
  });

  test('validateStartup succeeds when no plaintext keys exist', () => {
    const keysPath = makeTempPath();
    const km = loadFreshKeyManager(keysPath, TEST_KEK);
    km.rotate('valid-startup');
    expect(() => km.validateStartup()).not.toThrow();
  });

  test('validateStartup fails when KEK is missing', () => {
    const keysPath = makeTempPath();
    jest.resetModules();
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
    process.env.QODIQA_KEYS_PATH = keysPath;
    require('../../services/secrets/secretsProvider')._clearCache();
    const km = require('../../services/artifact/keyManager');
    expect(() => km.validateStartup()).toThrow(/QODIQA_KEY_ENCRYPTION_KEY/);
    // Restore
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    require('../../services/secrets/secretsProvider')._clearCache();
  });
});

// ── 6. KEY_MIGRATION_FAILED event ─────────────────────────────────────────────

describe('Migration — KEY_MIGRATION_FAILED on write error', () => {
  test('bootstrap emits KEY_MIGRATION_FAILED when saveKeys cannot write and rethrows', () => {
    const keysPath = makeTempPath();
    writeLegacyPlaintextFile(keysPath, 'fail-test');

    // Block the write. changed the injection
    // point: saveKeys() no longer writes a fixed DATA_PATH + '.tmp' (it writes
    // a unique <path>.<pid>.<random>.tmp via services/artifact/secureWrite.js),
    // so pre-creating a directory at the old fixed name no longer blocks it.
    // Fail the exclusive temp-file open for this store instead — same
    // behaviour under test (a write error during migration).
    const realOpenSync = fs.openSync;
    const openSpy = jest.spyOn(fs, 'openSync').mockImplementation((p, ...rest) => {
      if (typeof p === 'string' && p.startsWith(keysPath + '.') && p.endsWith('.tmp')) {
        const e = new Error(`EACCES: permission denied, open '${p}'`); e.code = 'EACCES'; throw e;
      }
      return realOpenSync(p, ...rest);
    });

    const events = [];
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../services/secrets/secretsProvider')._clearCache();

    const origStderr = process.stderr.write.bind(process.stderr);
    jest.spyOn(process.stderr, 'write').mockImplementation((data) => {
      if (typeof data === 'string') { try { events.push(JSON.parse(data.trim())); } catch {} }
      return origStderr(data);
    });

    let threw = false;
    try {
      // Migration (and its saveKeys() write) is deferred until first real
      // store access — trigger it explicitly.
      require('../../services/artifact/keyStore').getActiveKey('fail-test');
    } catch {
      threw = true;
    } finally {
      process.stderr.write.mockRestore();
      openSpy.mockRestore();
    }

    expect(threw).toBe(true);
    const failEvents = events.filter(e => e.eventType === 'KEY_MIGRATION_FAILED');
    expect(failEvents.length).toBeGreaterThan(0);
    expect(failEvents[0].severity).toBe('CRITICAL');
  });
});

// ── 7. Required encrypted structure fields ────────────────────────────────────

describe('Encrypted structure — required fields', () => {
  let enc;
  beforeEach(() => {
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    require('../../services/secrets/secretsProvider')._clearCache();
    enc = require('../../services/artifact/keyEncryption');
  });

  test('encryptKeyMaterial returns all required fields', () => {
    const privDer = crypto.randomBytes(48);
    const box     = enc.encryptKeyMaterial(privDer, { keyId: 'test:key_v1', createdAt: '2026-01-01T00:00:00.000Z' });
    expect(box.keyId).toBe('test:key_v1');
    expect(box.algorithm).toBe('aes-256-gcm');
    expect(typeof box.encryptedPrivateKey).toBe('string');
    expect(typeof box.iv).toBe('string');
    expect(typeof box.authTag).toBe('string');
    expect(box.createdAt).toBe('2026-01-01T00:00:00.000Z');
    expect(typeof box.updatedAt).toBe('string');
  });

  test('keyId and createdAt are populated from metadata', () => {
    const box = enc.encryptKeyMaterial(crypto.randomBytes(32), {
      keyId:     'client:key_v7',
      createdAt: '2025-06-01T10:00:00.000Z',
    });
    expect(box.keyId).toBe('client:key_v7');
    expect(box.createdAt).toBe('2025-06-01T10:00:00.000Z');
  });

  test('updatedAt is always set to current timestamp', () => {
    const before = Date.now();
    const box    = enc.encryptKeyMaterial(crypto.randomBytes(32));
    const after  = Date.now();
    const updatedMs = new Date(box.updatedAt).getTime();
    expect(updatedMs).toBeGreaterThanOrEqual(before);
    expect(updatedMs).toBeLessThanOrEqual(after);
  });

  test('each encryption produces a unique IV (unique-IV guarantee)', () => {
    const privDer = crypto.randomBytes(32);
    const ivs = new Set();
    for (let i = 0; i < 20; i++) {
      ivs.add(enc.encryptKeyMaterial(privDer).iv);
    }
    expect(ivs.size).toBe(20);
  });

  test('IV is 12 bytes (96 bits) — NIST recommendation for GCM', () => {
    const box   = enc.encryptKeyMaterial(crypto.randomBytes(32));
    const ivBuf = Buffer.from(box.iv, 'base64');
    expect(ivBuf.length).toBe(12);
  });

  test('authTag is 16 bytes (128-bit GCM tag)', () => {
    const box    = enc.encryptKeyMaterial(crypto.randomBytes(32));
    const tagBuf = Buffer.from(box.authTag, 'base64');
    expect(tagBuf.length).toBe(16);
  });

  test('persisted key file includes all required fields in encryptedPrivateKeyDer', () => {
    const keysPath = makeTempPath();
    const ks = loadFreshKeyStore(keysPath, TEST_KEK);
    ks.rotateKey('struct-test');

    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const client = raw.clients['struct-test'];
    const activeId = Object.keys(client).find(k => client[k].status === 'active');
    const epk = client[activeId].encryptedPrivateKeyDer;

    expect(epk.keyId).toBe(activeId);
    expect(epk.algorithm).toBe('aes-256-gcm');
    expect(typeof epk.encryptedPrivateKey).toBe('string');
    expect(typeof epk.iv).toBe('string');
    expect(typeof epk.authTag).toBe('string');
    expect(typeof epk.createdAt).toBe('string');
    expect(typeof epk.updatedAt).toBe('string');
    // Legacy field names must NOT be present
    expect(epk.ciphertext).toBeUndefined();
    expect(epk.tag).toBeUndefined();
  });
});

// ── 8. Regression — historical verification ───────────────────────────────────

describe('Regression — historical artifact verification', () => {
  test('key migrated from plaintext produces valid Ed25519 signature', () => {
    const keysPath = makeTempPath();
    writeLegacyPlaintextFile(keysPath, 'regression-sign');

    const ks  = loadFreshKeyStore(keysPath, TEST_KEK);
    const key = ks.getActiveKey('regression-sign');

    const { sign: ed25519Sign, verify: ed25519Verify } = require('../../src/infra/crypto/ed25519');
    const hash = crypto.createHash('sha256').update('test payload').digest();
    const sig  = ed25519Sign(hash, key.privDer);
    expect(ed25519Verify(hash, sig, key.pubDer)).toBe(true);
  });

  test('deprecated key public material remains verifiable after migration of active keys', () => {
    const keysPath = makeTempPath();

    // Create a file with one deprecated key and one plaintext active key
    const { privateKey: priv1, publicKey: pub1 } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding:  { type: 'spki',  format: 'der' },
    });
    const { privateKey: priv2, publicKey: pub2 } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding:  { type: 'spki',  format: 'der' },
    });
    const now = new Date().toISOString();
    const file = {
      version: 1,
      clients: {
        'hv-client': {
          'hv-client:key_v1': {
            clientId: 'hv-client', keyId: 'hv-client:key_v1', version: 1,
            algorithm: 'ed25519',
            publicKeyDer: Buffer.from(pub1).toString('base64'),
            status: 'deprecated', createdAt: now,
          },
          'hv-client:key_v2': {
            clientId: 'hv-client', keyId: 'hv-client:key_v2', version: 2,
            algorithm: 'ed25519',
            privateKeyDer: Buffer.from(priv2).toString('base64'),
            publicKeyDer:  Buffer.from(pub2).toString('base64'),
            status: 'active', createdAt: now,
          },
        },
      },
      legacyMap: {},
    };
    fs.writeFileSync(keysPath, JSON.stringify(file, null, 2), 'utf8');

    const ks = loadFreshKeyStore(keysPath, TEST_KEK);

    // Deprecated key v1 must still be retrievable
    const depKey = ks.getPublicKey('hv-client:key_v1');
    expect(Buffer.from(depKey.pubDer).equals(Buffer.from(pub1))).toBe(true);
    expect(depKey.status).toBe('deprecated');

    // Active key v2 must be migrated and usable
    const activeKey = ks.getActiveKey('hv-client');
    expect(activeKey.privDer.equals(Buffer.from(priv2))).toBe(true);
    expect(activeKey.keyId).toBe('hv-client:key_v2');
  });
});

// ── 9. Validation — invalid encrypted material ────────────────────────────────

describe('Validation — invalid encrypted material detected at load', () => {
  test('corrupted encryptedPrivateKey (tampered ciphertext) → bootstrap throws', () => {
    const keysPath = makeTempPath();
    loadFreshKeyStore(keysPath, TEST_KEK).rotateKey('corrupt-ct');

    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const client = raw.clients['corrupt-ct'];
    const activeId = Object.keys(client).find(k => client[k].status === 'active');
    // Corrupt the ciphertext
    const ctBytes = Buffer.from(client[activeId].encryptedPrivateKeyDer.encryptedPrivateKey, 'base64');
    ctBytes[0] ^= 0xff;
    client[activeId].encryptedPrivateKeyDer.encryptedPrivateKey = ctBytes.toString('base64');
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');

    expect(() => loadFreshKeyStore(keysPath, TEST_KEK).getActiveKey('corrupt-ct')).toThrow();
  });

  test('corrupted authTag → bootstrap throws', () => {
    const keysPath = makeTempPath();
    loadFreshKeyStore(keysPath, TEST_KEK).rotateKey('corrupt-tag');

    const raw = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const client = raw.clients['corrupt-tag'];
    const activeId = Object.keys(client).find(k => client[k].status === 'active');
    const tagBytes = Buffer.from(client[activeId].encryptedPrivateKeyDer.authTag, 'base64');
    tagBytes[0] ^= 0x01;
    client[activeId].encryptedPrivateKeyDer.authTag = tagBytes.toString('base64');
    fs.writeFileSync(keysPath, JSON.stringify(raw, null, 2), 'utf8');

    expect(() => loadFreshKeyStore(keysPath, TEST_KEK).getActiveKey('corrupt-tag')).toThrow();
  });

  test('wrong KEK → bootstrap throws (auth tag mismatch on decrypt)', () => {
    const keysPath = makeTempPath();
    loadFreshKeyStore(keysPath, TEST_KEK).rotateKey('wrong-kek-test2');

    expect(() => loadFreshKeyStore(keysPath, ALT_KEK).getActiveKey('wrong-kek-test2')).toThrow();
  });

  test('missing KEK when file has encrypted keys → bootstrap throws', () => {
    const keysPath = makeTempPath();
    loadFreshKeyStore(keysPath, TEST_KEK).rotateKey('missing-kek-test');

    expect(() => loadFreshKeyStore(keysPath, undefined).getActiveKey('missing-kek-test')).toThrow();
  });
});
