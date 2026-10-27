'use strict';

/**
 * K1 — residual, end to end: a writer of keys.json WITHOUT the KEK injects a
 * public-only 'deprecated' record with retiredAt ≈ now and gets an artifact it forged with its own key EXECUTED by a
 * running gateway after the next reload. Before K1 this worked for up to ~65 s per write (A2's future-retiredAt bound
 * only capped it). With authenticated records the reload is refused and the forged artifact is BLOCKED.
 *
 *   K1-E01  injected key → forged artifact BLOCKED; the gateway's own artifacts keep executing
 *   K1-E02  an artifact signed before a legacy store's TOFU seal still verifies after it (backward compatibility)
 */

const fs = require('fs');
const crypto = require('crypto');

const keyStore = require('../../../services/artifact/keyStore');
const { signArtifact } = require('../signArtifact');
const { validateArtifact } = require('../validateArtifact');

function forge(clientId, version) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' } });
  const keyId = `${clientId}:key_v${version}`;
  const record = { clientId, keyId, version, algorithm: 'ed25519', publicKeyDer: Buffer.from(publicKey).toString('base64'),
    status: 'deprecated', createdAt: new Date(Date.now() - 3600e3).toISOString(),
    retiredAt: new Date(Date.now() + 2000).toISOString(), rotationDeadline: null, expiresAt: null };
  const now = Date.now();
  const artifact = signArtifact({ payload: { userId: 'mallory', action: 'wire-transfer' }, timestamp: now, expiry: now + 300_000, publicKeyId: keyId },
    Buffer.from(privateKey));
  return { record, artifact, keyId };
}

test('K1-E01 an injected public-only key is never adopted: the forged artifact is BLOCKED, genuine ones execute', () => {
  const clientId = 'k1-e2e-client';
  keyStore.rotateKey(clientId, { mode: 'graceful' });
  const { keyId, privDer } = keyStore.getActiveKey(clientId);
  const now = Date.now();
  const genuine = signArtifact({ payload: { userId: 'alice', action: 'query' }, timestamp: now, expiry: now + 300_000, publicKeyId: keyId }, privDer);

  const keysPath = process.env.QODIQA_KEYS_PATH;
  const { record, artifact, keyId: forgedKeyId } = forge(clientId, 9);
  const original = fs.readFileSync(keysPath, 'utf8');
  const d = JSON.parse(original);
  d.clients[clientId][forgedKeyId] = record; // the KEK-less write
  fs.writeFileSync(keysPath, JSON.stringify(d, null, 2));

  const r = keyStore.reloadFromDisk();         // the fleet reload tick
  expect(r.reloaded).toBe(false);
  expect(r.error).toMatch(/record MAC missing/);

  const forged = validateArtifact(artifact);
  expect(forged.decision).toBe('BLOCK');
  expect(validateArtifact(genuine)).toMatchObject({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED' });
  fs.writeFileSync(keysPath, original); // undo the injection for the next test (shared per-file store)
});

test('K1-E02 an artifact signed before a legacy store was sealed still verifies after the TOFU seal', () => {
  const clientId = 'k1-e2e-legacy';
  keyStore.rotateKey(clientId, { mode: 'graceful' });
  const { keyId, privDer } = keyStore.getActiveKey(clientId);
  const now = Date.now();
  const artifact = signArtifact({ payload: { userId: 'bob', action: 'query' }, timestamp: now, expiry: now + 300_000, publicKeyId: keyId }, privDer);

  // Rewrite the file as pre-K1 code wrote it (no seal, no MACs, AAD-less ciphertexts), then load it fresh.
  const keysPath = process.env.QODIQA_KEYS_PATH;
  const d = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  delete d.recordSeal;
  const { encryptKeyMaterial } = require('../../../services/artifact/keyEncryption');
  for (const [cid, cd] of Object.entries(d.clients)) {
    for (const [kid, e] of Object.entries(cd)) {
      delete e.recordMac;
      if (e.status === 'active') e.encryptedPrivateKeyDer = encryptKeyMaterial(keyStore.getActiveKey(cid).privDer, { keyId: kid, createdAt: e.createdAt });
    }
  }
  fs.writeFileSync(keysPath, JSON.stringify(d, null, 2));

  jest.resetModules();
  const ks2 = require('../../../services/artifact/keyStore');
  const { validateArtifact: validate2 } = require('../validateArtifact');
  expect(ks2.getActiveKey(clientId).keyId).toBe(keyId);       // TOFU seal on first load
  expect(JSON.parse(fs.readFileSync(keysPath, 'utf8')).recordSeal).toBeDefined();
  expect(validate2(artifact)).toMatchObject({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED' });
});
