'use strict';

/**
 *run the UNMODIFIED src/infra/keys/providers/hsm.js against SoftHSM2 over real PKCS#11
 * (pkcs11js). Runs INSIDE the qodiqa-dep11-softhsm image (scripts/dep11/hsm/Dockerfile) with the repository
 * bind-mounted read-only at /repo; launched by scripts/dep11/run-softhsm.js. Prints one JSON result line.
 *
 * The token and both PINs are created fresh per run from crypto.randomBytes — test values only.
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const LIB = '/usr/lib/softhsm/libsofthsm2.so';

// The bind-mounted repo's node_modules/pkcs11js is the HOST's (Windows) native build; resolve the image's Linux build
// instead. Test-harness only — hsm.js itself is loaded and run unmodified.
const Module = require('module');
const _resolve = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) {
  return _resolve.call(this, req === 'pkcs11js' ? '/hsm/node_modules/pkcs11js' : req, ...rest);
};
const { HsmSigningProvider } = require('/repo/src/infra/keys/providers/hsm.js');

// A fresh, empty token directory per run (SoftHSM reads SOFTHSM2_CONF at C_Initialize; nothing is ever cleared).
const tokDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dep11-tokens-'));
process.env.SOFTHSM2_CONF = path.join(tokDir, 'softhsm2.conf');
fs.writeFileSync(process.env.SOFTHSM2_CONF, `directories.tokendir = ${tokDir}
objectstore.backend = file
log.level = ERROR
`);

const PIN = crypto.randomBytes(8).toString('hex');
const SO_PIN = crypto.randomBytes(8).toString('hex');
execFileSync('softhsm2-util', ['--init-token', '--free', '--label', 'qodiqa-dep11', '--pin', PIN, '--so-pin', SO_PIN], { stdio: 'ignore' });

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dep11-hsm-'));
const results = [];
const open = [];

async function provider(opts = {}) {
  const p = new HsmSigningProvider({ libPath: LIB, slotIndex: 0, pin: PIN, keyIndexPath: path.join(tmp, 'index.json'), ...opts });
  open.push(p);
  await p.initialize();
  return p;
}
const verify = (der, msg, sig) => crypto.verify(null, msg, crypto.createPublicKey({ key: der, format: 'der', type: 'spki' }), sig);

async function t(id, title, fn) {
  try { await fn(); results.push({ id, title, status: 'passed' }); } catch (e) {
    results.push({ id, title, status: 'failed', error: String(e && e.stack || e).split('\n').slice(0, 4).join(' | ') });
  }
  while (open.length) await open.pop().shutdown();               // one session at a time, like the real process
}

(async () => {
  await t('HS-01', 'key generation + public-key retrieval: an ed25519 SPKI that round-trips', async () => {
    const p = await provider();
    const { publicKeyDer, keyName } = await p.generateKeyPair('qodiqa-default-key_v1');
    assert.strictEqual(keyName, 'qodiqa-default-key_v1');
    assert.strictEqual(crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' }).asymmetricKeyType, 'ed25519');
    const got = await p.getPublicKey('qodiqa-default-key_v1');
    assert.strictEqual(got.status, 'active');
    assert.ok(got.publicKeyDer.equals(publicKeyDer));
  });

  await t('HS-02', 'signing: a pure Ed25519 signature over the 32-byte prehash that verifies under the returned key', async () => {
    const p = await provider();
    const { publicKeyDer } = await p.generateKeyPair('sign-k');
    const h = crypto.createHash('sha256').update('QODIQA::ARTIFACT::V1|dep11').digest();
    const sig = await p.sign('sign-k', h);
    assert.strictEqual(sig.length, 64);
    assert.ok(verify(publicKeyDer, h, sig));
    assert.ok(!verify(publicKeyDer, crypto.randomBytes(32), sig));
    await assert.rejects(p.sign('sign-k', Buffer.alloc(31)), TypeError);
  });

  await t('HS-03', 'the private key object is sensitive and non-extractable on the token', async () => {
    const p = await provider();
    await p.generateKeyPair('sens-k');
    const pk = require('pkcs11js');
    const h = p._findPrivateKey('sens-k');
    const [attrs] = [p._pkcs11.C_GetAttributeValue(p._session, h, [{ type: pk.CKA_SENSITIVE }, { type: pk.CKA_EXTRACTABLE }])];
    assert.ok(attrs[0].value.equals(Buffer.from([1])), 'CKA_SENSITIVE');
    assert.ok(attrs[1].value.equals(Buffer.from([0])), 'CKA_EXTRACTABLE');
    assert.throws(() => p._pkcs11.C_GetAttributeValue(p._session, h, [{ type: pk.CKA_VALUE }]), /SENSITIVE|ATTRIBUTE/);
  });

  await t('HS-04', 'missing key: sign() and getPublicKey() for a label not on the token fail', async () => {
    const p = await provider();
    await assert.rejects(p.sign('no-such-key', crypto.randomBytes(32)), /not found on HSM/);
    await assert.rejects(p.getPublicKey('no-such-key'), /not in index/);
  });

  await t('HS-05', 'wrong key: a signature from key A does not verify under key B', async () => {
    const p = await provider();
    const a = await p.generateKeyPair('wa');
    const b = await p.generateKeyPair('wb');
    const h = crypto.randomBytes(32);
    const sig = await p.sign('wa', h);
    assert.ok(verify(a.publicKeyDer, h, sig));
    assert.ok(!verify(b.publicKeyDer, h, sig));
  });

  await t('HS-06', 'permission failure: a wrong PIN or no PIN fails initialize()', async () => {
    await assert.rejects(provider({ pin: PIN + 'x' }), /PIN_INCORRECT|CKR_/);
    const save = process.env.HSM_PKCS11_PIN; delete process.env.HSM_PKCS11_PIN;
    await assert.rejects(provider({ pin: undefined }), /no PIN configured/);
    if (save !== undefined) process.env.HSM_PKCS11_PIN = save;
  });

  await t('HS-07', 'rotation: a new key is generated, the old one is deprecated, each signs and verifies under its own key; persisted across sessions', async () => {
    const p = await provider();
    const k1 = await p.generateKeyPair('rot_v1');
    const k2 = await p.generateKeyPair('rot_v2');
    await p.deprecateKey('rot_v1');
    assert.ok(!k1.publicKeyDer.equals(k2.publicKeyDer));
    await p.shutdown();
    const q = await provider();                                   // a new session (restart) sees the token objects + index
    assert.strictEqual((await q.getPublicKey('rot_v1')).status, 'deprecated');
    assert.strictEqual((await q.getPublicKey('rot_v2')).status, 'active');
    const h = crypto.randomBytes(32);
    assert.ok(verify(k2.publicKeyDer, h, await q.sign('rot_v2', h)));
    assert.ok(!verify(k1.publicKeyDer, h, await q.sign('rot_v2', h)));
  });

  await t('HS-08', 'revocation: destroy removes both objects; the key can no longer sign; a second destroy fails loudly', async () => {
    const p = await provider();
    await p.generateKeyPair('gone');
    const r = await p.revokeKey('gone');
    assert.strictEqual(r.method, 'destroy');
    assert.strictEqual(r.providerResponse.destroyedObjectCount, 2);
    await assert.rejects(p.sign('gone', crypto.randomBytes(32)), /not found on HSM/);
    await assert.rejects(p.revokeKey('gone'), /nothing was destroyed/);
  });

  await t('HS-09', 'startup fails closed: no library, a library path that does not exist, or a slot that does not exist', async () => {
    await assert.rejects(provider({ libPath: '' }), /HSM_PKCS11_LIB is not set/);
    await assert.rejects(provider({ libPath: '/nonexistent/libpkcs11.so' }));
    await assert.rejects(provider({ slotIndex: 7 }), /slot 7 not found/);
  });

  const passed = results.filter((r) => r.status === 'passed').length;
  process.stdout.write(JSON.stringify({ softhsm: execFileSync('softhsm2-util', ['--version'], { encoding: 'utf8' }).trim(), node: process.version, passed, total: results.length, results }) + '\n');
  process.exit(passed === results.length ? 0 : 1);
})();
