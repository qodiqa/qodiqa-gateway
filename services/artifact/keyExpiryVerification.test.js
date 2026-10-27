'use strict';

/**
 * Key expiresAt — signing vs. verification enforcement asymmetry.
 *
 * Protocol Specification §5.8 (Verification Failure Summary): a key whose
 * `expiresAt` is in the past blocks new SIGNING operations (KEY_EXPIRED at
 * /sign) but does NOT by itself block VERIFICATION of an artifact signed
 * before that date — verification is gated solely on key `status`
 * (`active`/`deprecated` succeed, `revoked` fails with KEY_NOT_FOUND).
 * This is intentional: `expiresAt` governs signing-key hygiene, not the
 * validity of already-issued, short-lived artifacts. Only `status: revoked`
 * (see docs/security/key-management.md / ConsentStore-style terminal-state semantics)
 * removes a key from the verification path.
 *
 * This suite proves that asymmetry end-to-end: getActiveKey() (signing)
 * rejects an expired active key, while getPublicKey() (verification) and
 * the full validateArtifact() pipeline continue to accept it — until the
 * key is explicitly revoked.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

// K1: this fixture edits keys.json deliberately, as a KEK holder would, so it re-seals the record MACs
// (an edit WITHOUT the KEK is exactly what src/infra/crypto/keyRecordSeal.js now refuses).
function resealKeys(d) {
  const seal = require('../../src/infra/crypto/keyRecordSeal');
  return seal.sealFileData(d, require('./keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO), 'artifact');
}

const TEST_KEK = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-key-expiry-test-'));
  return path.join(dir, 'keys.json');
}

function loadKeyStore(keysPath) {
  jest.resetModules();
  process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
  process.env.QODIQA_KEYS_PATH          = keysPath;
  require('../../services/secrets/secretsProvider')._clearCache();
  return require('../../services/artifact/keyStore');
}

// Backdates the active key's lifecycle timestamps on disk to simulate a key
// that silently crossed its expiry without being rotated (e.g. scheduler
// outage) — the next process to load the file sees an active-but-expired key.
function backdateActiveKeyExpiry(keysPath, clientId) {
  const raw      = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  const store    = raw.clients[clientId];
  const activeId = Object.keys(store).find(k => store[k].status === 'active');
  store[activeId].expiresAt        = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  store[activeId].rotationDeadline = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
  fs.writeFileSync(keysPath, JSON.stringify(resealKeys(raw), null, 2), 'utf8');
}

describe('Key expiresAt — verification is not gated on key expiry (protocol §5.8)', () => {
  const keysPath = makeTempPath();
  const clientId = 'expiry-verify-test';
  let keyId, privDer;

  beforeAll(() => {
    const ks1 = loadKeyStore(keysPath);
    ks1.rotateKey(clientId);
    const active = ks1.getActiveKey(clientId);
    keyId   = active.keyId;
    privDer = active.privDer;
    backdateActiveKeyExpiry(keysPath, clientId);
  });

  test('getActiveKey() (signing path) refuses an expired active key', () => {
    const ks = loadKeyStore(keysPath);
    expect(() => ks.getActiveKey(clientId)).toThrow(/KEY_EXPIRED/);
  });

  test('getPublicKey() (verification path) ignores expiresAt for an active key', () => {
    const ks = loadKeyStore(keysPath);
    const { pubDer, status } = ks.getPublicKey(keyId);
    expect(status).toBe('active');
    expect(Buffer.isBuffer(pubDer)).toBe(true);
  });

  test('validateArtifact() still verifies a signature produced by an active-but-expired key', () => {
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH          = keysPath;
    require('../../services/secrets/secretsProvider')._clearCache();
    const { signArtifact }     = require('../../src/validation/signArtifact');
    const { validateArtifact } = require('../../src/validation/validateArtifact');

    const now      = Date.now();
    const artifact = signArtifact({
      payload:     { userId: 'alice', action: 'query' },
      timestamp:   now,
      expiry:      now + 60_000,
      publicKeyId: keyId,
    }, privDer);

    const result = validateArtifact(artifact);

    expect(result.decision).toBe('EXECUTE');
    expect(result.reason).toBe('ALL_CHECKS_PASSED');
  });

  test('revoking the key (not expiring it) is what blocks verification', () => {
    const ks = loadKeyStore(keysPath);
    ks.revokeKey(keyId);
    expect(() => ks.getPublicKey(keyId)).toThrow(/revoked/);
  });
});
