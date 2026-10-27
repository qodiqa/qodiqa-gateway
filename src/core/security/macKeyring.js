'use strict';

/**
 * Symmetric MAC keyring —.
 *
 * One mechanism for the integrity uses that cross process boundaries (the keyring defines five PURPOSES — see PURPOSES below;
 * the three listed here are the original ones):
 *   - consent-cache entries in Redis (ConsentCache.js),
 *   - consent revocation pub/sub messages (RevocationEvent.js),
 *   - organization-status pub/sub messages and the qodiqa:org:status hash
 *     (OrgStatusEvent.js / OrgStatusStore.js).
 *
 * Storage: mac-keys.json next to the signing keystore (QODIQA_MAC_KEYS_PATH,
 * default: the directory of QODIQA_KEYS_PATH). Each key is 32 random bytes,
 * AES-256-GCM encrypted under the platform KEK (services/artifact/keyEncryption.js,
 * the same protection as the Ed25519 signing keys). It is therefore shared
 * across nodes exactly the way the signing keystore is — every node must see
 * the same file, or signed revocations would be rejected on other nodes.
 *
 * Tags: `<kid>.<base64url HMAC-SHA256(key, "<purpose>\n<message>")>` — the
 * purpose label domain-separates the three uses. verify() accepts the ACTIVE
 * and the PREVIOUS key (one rotation of overlap is enough: cache entries live
 * ≤ 60 s, pub/sub messages are accepted for 30 s); an unknown kid triggers at
 * most one reload per RELOAD_MIN_MS (another node may have rotated).
 *
 * Provisioning: outside production a missing keyring is generated on first use
 * (dev/test). In production it must already exist (boot rule
 * secret.pubsub_signing) — never silently generated, since a per-node key would
 * make every other node reject this node's revocations.
 * Rotation: rotate() (POST /key-admin/mac-keys/rotate — MANAGE_KEYS + MFA step-up).
 *
 *:
 *   - the document carries kekFingerprint (the same one-way KEK fingerprint as keys.json); a keyring written under
 *     another KEK fails with KEK_FINGERPRINT_MISMATCH BEFORE any decrypt. Older files without it still load; it is
 *     written by the next init()/rotate() (never at boot: a boot-time write on a shared volume could race a rotation).
 *   - rotate() re-encrypts every non-retired key under the CURRENT KEK, so a rotation after a KEK change can no longer
 *     write a mixed-KEK document whose older keys then fail to decrypt.
 *   - assertUsable() — called by server/startup.js in production — forces a fresh load, decrypts every non-retired
 *     key and runs a sign/verify self-test, so a wrong KEK or a corrupt keyring is FATAL at boot
 *     (MAC_KEYRING_STARTUP_FAILED) instead of surfacing at the first signed revocation.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { emit } = require('../../../services/logger');
const { monoNowMs } = require('../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows
const { encryptKeyMaterial, decryptKeyMaterial, computeKekFingerprint, assertKekFingerprint } = require('../../../services/artifact/keyEncryption');
const { writeFileAtomicSecure } = require('../../infra/fs/secureWrite');

const FILE_VERSION = 1;
const RELOAD_MIN_MS = 5000;
const PURPOSES = Object.freeze({
  CONSENT_CACHE:     'qodiqa-consent-cache-v1',
  REVOCATION:        'qodiqa-revocation-event-v2',
  ORG_STATUS:        'qodiqa-org-status-event-v2',
  ORG_STATUS_RECORD: 'qodiqa-org-status-record-v1',
  CONTROL_PLANE:     'qodiqa-control-plane-change-v1', // control-plane change notifications
  KILL_SWITCH:       'qodiqa-kill-switch-state-v1',    // the integrity MAC of the global kill-switch record
  PROVIDER_REGISTRY: 'qodiqa-provider-registry-v1',    // the integrity MAC of a dynamic provider-registry record
  OPERATOR_SESSION:  'qodiqa-operator-session-v1',     // the MAC of an operator session token minted after a single-sign-on login
  SAML_STATE:        'qodiqa-saml-relay-state-v1',     // the MAC of the SAML relay state (provider, request id, expiry)
});

let _state = null;          // { path, mtimeMs, keys: Map(kid -> { key, status }), active }
let _lastReloadAt = 0;

function keyringPath() {
  if (process.env.QODIQA_MAC_KEYS_PATH) return process.env.QODIQA_MAC_KEYS_PATH;
  const keysPath = process.env.QODIQA_KEYS_PATH || path.join(__dirname, '..', '..', '..', 'data', 'keys.json');
  return path.join(path.dirname(keysPath), 'mac-keys.json');
}

class MacKeyringError extends Error { constructor(message, code) { super(message); this.name = 'MacKeyringError'; this.code = code; } }

function _newKid() { return `mk_${new Date().toISOString().slice(0, 10).replace(/-/g, '')}_${crypto.randomBytes(4).toString('hex')}`; }

///-15: fsync + unique temp name (the 0600 mode was already set here).
function _writeFile(p, doc) {
  writeFileAtomicSecure(p, JSON.stringify(doc, null, 2));
}

function _generateDoc() {
  const kid = _newKid();
  const enc = encryptKeyMaterial(crypto.randomBytes(32), { keyId: kid });
  return { version: FILE_VERSION, kekFingerprint: computeKekFingerprint(), keys: [{ kid, status: 'active', createdAt: new Date().toISOString(), enc }] };
}

function _loadDoc(p) {
  const doc = JSON.parse(fs.readFileSync(p, 'utf8'));
  if (doc.version !== FILE_VERSION || !Array.isArray(doc.keys)) throw new MacKeyringError(`unsupported MAC keyring format at ${p}`, 'MAC_KEYRING_FORMAT');
  return doc;
}

function _materialize(p, doc, mtimeMs) {
  // wrong KEK -> a specific error before any decrypt (absent on files older than the guard).
  try { assertKekFingerprint(doc.kekFingerprint, p); } catch (err) { throw new MacKeyringError(err.message, 'MAC_KEYRING_KEK_MISMATCH'); }
  const keys = new Map(); let active = null;
  for (const k of doc.keys) {
    if (k.status === 'retired') continue;
    keys.set(k.kid, { key: decryptKeyMaterial(k.enc), status: k.status });
    if (k.status === 'active') active = k.kid;
  }
  if (!active) throw new MacKeyringError('MAC keyring has no active key', 'MAC_KEYRING_NO_ACTIVE');
  _state = { path: p, mtimeMs, keys, active };
  return _state;
}

function _ensure({ forceReload = false } = {}) {
  const p = keyringPath();
  if (_state && _state.path === p && !forceReload) return _state;
  if (!fs.existsSync(p)) {
    if (process.env.NODE_ENV === 'production') {
      throw new MacKeyringError(`MAC keyring missing at ${p} (production never generates one per node — provision it with scripts/security/macKeyring.js init)`, 'MAC_KEYRING_MISSING');
    }
    // a request path NEVER creates the key file. Development creates it at boot (server/startup.js -> init()); production
    // refuses to start without it. The one exception is a test harness: test/support/jest.setup.js registers a provisioning hook on globalThis (ignored in production).
    const hook = globalThis.__qodiqaMacKeyringAutoProvision;
    if (typeof hook === 'function') hook();
    else throw new MacKeyringError(`MAC keyring missing at ${p} (it is created at boot in development; provision it with scripts/security/macKeyring.js init)`, 'MAC_KEYRING_MISSING');
  }
  return _materialize(p, _loadDoc(p), fs.statSync(p).mtimeMs);
}

function _mac(key, purpose, message) {
  return crypto.createHmac('sha256', key).update(`${purpose}\n${message}`).digest('base64url');
}

/** @returns {string} `<kid>.<mac>` */
function sign(purpose, message) {
  const st = _ensure();
  return `${st.active}.${_mac(st.keys.get(st.active).key, purpose, String(message))}`;
}

/**
 * @returns {{ ok: true, kid: string } | { ok: false, reason: 'MISSING'|'MALFORMED'|'UNKNOWN_KEY'|'BAD_MAC' }}
 */
function verify(purpose, message, tag) {
  if (typeof tag !== 'string' || !tag) return { ok: false, reason: 'MISSING' };
  const dot = tag.indexOf('.');
  if (dot <= 0) return { ok: false, reason: 'MALFORMED' };
  const kid = tag.slice(0, dot); const macB64 = tag.slice(dot + 1);
  let st = _ensure();
  if (!st.keys.has(kid) && monoNowMs() - _lastReloadAt >= RELOAD_MIN_MS) { // monotonic (same-process)
    _lastReloadAt = monoNowMs();
    try { st = _ensure({ forceReload: true }); } catch { /* keep current keys */ }
  }
  const entry = st.keys.get(kid);
  if (!entry) return { ok: false, reason: 'UNKNOWN_KEY' };
  const expect = Buffer.from(_mac(entry.key, purpose, String(message)));
  const got = Buffer.from(macB64);
  if (expect.length !== got.length || !crypto.timingSafeEqual(expect, got)) return { ok: false, reason: 'BAD_MAC' };
  return { ok: true, kid };
}

/** Rotate: new active key; the old active becomes previous; older previous keys retire. */
function rotate({ by = 'system' } = {}) {
  const p = keyringPath();
  const st = _ensure();
  const doc = _loadDoc(p);
  // every key that stays verifiable is re-encrypted under the CURRENT KEK. Its material comes from
  // the file (decryptable when the KEK is unchanged — also picks up another node's newer keys) or, after an in-process
  // KEK change, from this process's already-decrypted copy. Neither -> refuse; never write a mixed-KEK document.
  for (const k of doc.keys) {
    if (k.status === 'retired') continue;
    let material = null;
    try { material = decryptKeyMaterial(k.enc); } catch { material = (st.path === p && st.keys.get(k.kid)) ? st.keys.get(k.kid).key : null; }
    if (!material) throw new MacKeyringError(`MAC keyring key ${k.kid} cannot be decrypted under the current KEK and is not held in memory — rotation refused`, 'MAC_KEYRING_REENCRYPT_FAILED');
    k.enc = encryptKeyMaterial(material, { keyId: k.kid });
  }
  doc.kekFingerprint = computeKekFingerprint();
  for (const k of doc.keys) {
    if (k.status === 'previous') { k.status = 'retired'; k.retiredAt = new Date().toISOString(); }
    else if (k.status === 'active') { k.status = 'previous'; k.rotatedAt = new Date().toISOString(); }
  }
  const kid = _newKid();
  doc.keys.push({ kid, status: 'active', createdAt: new Date().toISOString(), createdBy: by, enc: encryptKeyMaterial(crypto.randomBytes(32), { keyId: kid }) });
  _writeFile(p, doc);
  _materialize(p, doc, fs.statSync(p).mtimeMs);
  emit('WARN', 'MAC_KEYRING_ROTATED', { activeKid: kid, by });
  return { activeKid: kid, previousKid: doc.keys.find((k) => k.status === 'previous')?.kid ?? null };
}

/** Public status (never key material). */
function status() {
  const st = _ensure();
  return { path: st.path, activeKid: st.active, verifiableKids: [...st.keys.keys()] };
}

/**
 * boot check: fresh load (KEK-fingerprint guard, every non-retired key decrypted) plus a
 * sign/verify self-test with a purpose label no consumer uses. Throws (fail closed) on any problem; in production a
 * missing keyring throws MAC_KEYRING_MISSING. Returns public status only (never key material).
 */
function assertUsable() {
  const st = _ensure({ forceReload: true });
  const probe = crypto.randomBytes(16).toString('hex');
  const purpose = 'qodiqa-mac-keyring-boot-self-test-v1';
  const tag = `${st.active}.${_mac(st.keys.get(st.active).key, purpose, probe)}`;
  const res = verify(purpose, probe, tag);
  if (!res.ok) throw new MacKeyringError(`MAC keyring self-test failed (${/** @type {any} */ (res).reason})`, 'MAC_KEYRING_SELF_TEST_FAILED');
  let fingerprinted = false;
  try { fingerprinted = !!_loadDoc(st.path).kekFingerprint; } catch { /* already loaded above */ }
  return { path: st.path, activeKid: st.active, verifiableKids: [...st.keys.keys()], kekFingerprintChecked: fingerprinted };
}

/** Explicit provisioning (production): create the file if absent; never overwrites. */
function init() {
  const p = keyringPath();
  if (fs.existsSync(p)) return { created: false, path: p };
  _writeFile(p, _generateDoc());
  _state = null;
  emit('INFO', 'MAC_KEYRING_CREATED', { path: p });
  return { created: true, path: p };
}

function _resetForTest() { _state = null; _lastReloadAt = 0; }

module.exports = { sign, verify, rotate, status, init, assertUsable, keyringPath, PURPOSES, MacKeyringError, _resetForTest };
