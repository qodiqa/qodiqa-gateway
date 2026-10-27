'use strict';

const crypto              = require('crypto');
const fs                  = require('fs');
const path                = require('path');
const { sign: ed25519Sign,
        verify: ed25519Verify } = require('../../src/infra/crypto/ed25519');
const { encryptKeyMaterial,
        decryptKeyMaterial,
        computeKekFingerprint,
        assertKekFingerprint,
        deriveKekSubkey }      = require('./keyEncryption');
// K1: authenticated key records + AAD-bound private keys. See
// src/infra/crypto/keyRecordSeal.js and the "Persistence" section below.
const seal                     = require('../../src/infra/crypto/keyRecordSeal');
const SEAL_DOMAIN              = 'artifact';
const { registerTenant }       = require('../../src/core/tenancy/tenantRegistry');
// registration is idempotent and may be asynchronous (control plane
// in PostgreSQL) — never let it throw or reject into the key path.
function _registerTenantQuietly(cid) {
  try {
    const r = registerTenant(cid);
    if (r && typeof r.then === 'function') r.catch((err) => _emitEvent('WARN', 'KEY_TENANT_REGISTER_FAILED', { clientId: cid, error: err.message }));
  } catch (_) { /* already registered / invalid id */ }
}
const { pickStrongestRevocationMethod } = require('../../src/infra/keys/providers/base');
const { KEY_ID_PATTERN }       = require('./keyId');
const { writeFileAtomicSecure } = require('../../src/infra/fs/secureWrite'); // direct (the route-guard analyzer does not follow whole-module re-exports)

// ── Constants ─────────────────────────────────────────────────────────────────
//
// remediation: 'deprecated' remains a verifiable-but-non-signing status
// (VERIFIABLE_STATUSES below) for the sole purpose of an *explicit*, planned
// migration — see rotateKeyGracefully()/rotateKeyGracefullyAsync(). It must
// never be the status an operator's ordinary "rotate the key" action produces
// by default, because that silently preserves verification capability for a
// key that may be the reason rotation was triggered in the first place.
// rotateKey()/rotateKeyAsync() therefore default to 'emergency' mode, which
// moves the outgoing key straight to 'revoked' — see the "Rotation" section
// below for the full rationale.

const VERIFIABLE_STATUSES = new Set(['active', 'deprecated']);
const ALL_STATUSES        = new Set(['active', 'deprecated', 'revoked']);
const CLIENT_ID_RE        = /^[A-Za-z0-9_-]{1,64}$/;
const LEGACY_KEY_ID_RE    = /^[A-Za-z0-9_-]{1,64}$/;
const NEW_KEY_ID_RE       = KEY_ID_PATTERN;
const FILE_VERSION        = 1;

const ROTATION_DAYS       = 90;
const EXPIRY_DAYS         = 180;
const EXPIRY_WARNING_DAYS = 30;

const DATA_PATH = process.env.QODIQA_KEYS_PATH
  || path.join(__dirname, '..', '..', 'data', 'keys.json');
const ARCHIVE_PATH = process.env.QODIQA_KEYS_ARCHIVE_PATH
  || path.join(path.dirname(DATA_PATH), 'key-archive.json');

// ── Internal helpers ──────────────────────────────────────────────────────────

const { emit: _emitEvent } = require('../logger');

function _addDays(isoDate, n) {
  const d = new Date(isoDate);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString();
}

function _computeLifecycle(createdAt) {
  const base = createdAt || new Date().toISOString();
  return {
    rotationDeadline: _addDays(base, ROTATION_DAYS),
    expiresAt:        _addDays(base, EXPIRY_DAYS),
  };
}

function daysUntilExpiry(rec) {
  if (!rec || !rec.expiresAt) return Infinity;
  return (/** @type {any} */ (new Date(rec.expiresAt)) - Date.now()) / 86_400_000;
}

function daysUntilRotation(rec) {
  if (!rec || !rec.rotationDeadline) return Infinity;
  return (/** @type {any} */ (new Date(rec.rotationDeadline)) - Date.now()) / 86_400_000;
}

function isExpired(rec) {
  return daysUntilExpiry(rec) <= 0;
}

function isRotationDue(rec) {
  return daysUntilRotation(rec) <= 0;
}

function _selfTest(privDer, pubDer) {
  const probe = crypto.createHash('sha256').update('qodiqa-keystore-self-test', 'utf8').digest();
  const sig   = ed25519Sign(probe, privDer);
  if (!ed25519Verify(probe, sig, pubDer)) {
    throw new Error('FATAL: Ed25519 key self-test failed');
  }
}

function _privToPub(privDer) {
  const privObj = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  return Buffer.from(crypto.createPublicKey(/** @type {any} */ (privObj)).export({ type: 'spki', format: 'der' }));
}

// SHA-256 fingerprint of the SPKI DER public key, hex-encoded — a stable,
// human-diffable identifier for a key independent of its keyId string.
function _fingerprint(pubDer) {
  return crypto.createHash('sha256').update(pubDer).digest('hex');
}

// opts.skipSelfTest — set by the native-signing rotation path, where privDer
// is null (private material never leaves the external provider) and the
// equivalent self-test was already performed remotely via the provider's own
// sign()/verify() round-trip before this record was built.
function _buildRecord(privDer, pubDer, status, clientId, version, createdAt, opts) {
  if (!(opts && opts.skipSelfTest)) {
    _selfTest(privDer, pubDer);
  }
  const ts = createdAt || new Date().toISOString();
  // Guarantee lifecycle is always present: use opts if complete, otherwise compute from createdAt.
  // This invariant prevents any active key from existing without a lifecycle boundary.
  const lc = (opts && opts.rotationDeadline && opts.expiresAt)
    ? opts
    : _computeLifecycle(ts);
  return Object.freeze({
    _privDer:          privDer,
    publicKeyDer:      pubDer,
    publicKeyB64:      pubDer.toString('base64'),
    fingerprint:       _fingerprint(pubDer),
    status,
    createdAt:         ts,
    clientId,
    keyId:             `${clientId}:key_v${version}`,
    version,
    algorithm:         'ed25519',
    rotationDeadline:  lc.rotationDeadline,
    expiresAt:         lc.expiresAt,
  });
}

// explicitly zero private key bytes when a record transitions out of
// 'active' (deprecated or revoked), instead of relying on the Buffer becoming
// merely unreferenced and eventually garbage-collected. Mirrors the same
// explicit-zeroization pattern already used for KEK material on shutdown in
// src/infra/keys/providers/{awsKms,azureKeyVault,gcpKms}.js. A frozen record
// still permits this: Object.freeze locks property *bindings*, not the
// mutability of a Buffer's own bytes. No-op for native-signing keys, whose
// records never carry local private material (_privDer is null).
function _zeroizePrivateKey(rec) {
  if (rec && Buffer.isBuffer(rec._privDer)) {
    rec._privDer.fill(0);
  }
}

function _buildDeprecatedRecord(pubDer, clientId, version, createdAt, retiredAt) {
  const pubDerBuf = Buffer.isBuffer(pubDer) ? pubDer : Buffer.from(pubDer);
  return Object.freeze({
    publicKeyDer: pubDerBuf,
    publicKeyB64: pubDerBuf.toString('base64'),
    fingerprint:  _fingerprint(pubDerBuf),
    status:       'deprecated',
    createdAt:    createdAt || new Date().toISOString(),
    retiredAt:    retiredAt || null,
    clientId,
    keyId:        `${clientId}:key_v${version}`,
    version,
    algorithm:    'ed25519',
  });
}

// revokedAt is the ISO time of the active/deprecated -> revoked
// transition. undefined = "this call IS the transition, stamp now"; null = unknown
// (a file written before the field existed); a string = the persisted/known time.
function _buildRevokedRecord(pubDer, clientId, version, createdAt, revokedAt) {
  const pubDerBuf = Buffer.isBuffer(pubDer) ? pubDer : Buffer.from(pubDer);
  return Object.freeze({
    publicKeyDer: pubDerBuf,
    publicKeyB64: pubDerBuf.toString('base64'),
    fingerprint:  _fingerprint(pubDerBuf),
    status:       'revoked',
    createdAt:    createdAt || new Date().toISOString(),
    clientId,
    keyId:        `${clientId}:key_v${version}`,
    version,
    algorithm:    'ed25519',
    revokedAt:    revokedAt === undefined ? new Date().toISOString() : revokedAt,
  });
}

function _generateRecord(status, clientId, version) {
  const { privateKey: priv, publicKey: pub } =
    crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding:  { type: 'spki',  format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
  const createdAt = new Date().toISOString();
  return _buildRecord(Buffer.from(priv), Buffer.from(pub), status, clientId, version, createdAt, _computeLifecycle(createdAt));
}

// keyProviderFactory is Infrastructure (src/infra/keys/) and keyStore.js is
// Services (services/artifact/) — Services -> Infrastructure is an allowed
// dependency direction, and keyProviderFactory's own dependency tree never
// requires keyStore.js or keyManager.js back, so this is a plain static
// import, not a cycle workaround. keyProviderFactory's exported functions
// (isNativeSigning/getNativeSigningProvider) are safe to call before
// initialize() has run — they just report "no native provider yet".
const _kpf = require('../../src/infra/keys/keyProviderFactory');
function _getKpf() {
  return _kpf;
}

// Builds an active record for a key whose private material lives in an
// external NativeSigningProvider (Vault Transit / HSM).  The provider has
// already generated the key pair and returned its public DER; the "self-test"
// equivalent is a remote sign+verify round-trip performed by the caller
// (rotateKeyAsync) before this function runs, so _buildRecord's local
// self-test is skipped via skipSelfTest.
function _buildNativeRecord(pubDer, status, clientId, version, createdAt) {
  const ts = createdAt || new Date().toISOString();
  return _buildRecord(null, pubDer, status, clientId, version, ts, { ..._computeLifecycle(ts), skipSelfTest: true });
}

// Re-resolves the live per-client bucket at write time. Required by every
// async mutation site that captures a `_store[cid]` reference before an
// `await` (native provider round-trips in rotateKeyAsync/revokeKeyAsync):
// reloadFromDisk() can reassign the top-level `_store` to a brand
// new object graph while such an await is in flight, on the SAME instance,
// independent of and concurrent with the in-progress rotation/revocation.
// Writing through a reference captured before the await would land on the
// orphaned pre-reload object — invisible to saveKeys() (which serializes
// the CURRENT `_store`) and to every reader — silently discarding the
// operation's result. Always re-fetch immediately before the write instead.
function _liveClientStore(cid) {
  if (!_store[cid]) _store[cid] = {};
  return _store[cid];
}

function _nextVersion(clientStore) {
  let max = 0;
  for (const rec of Object.values(clientStore)) {
    if (rec.version > max) max = rec.version;
  }
  return max + 1;
}

// ── Persistence ───────────────────────────────────────────────────────────────
//
// File format (keys.json):
//   {
//     "version": 1,
//     "clients": {
//       "<clientId>": {
//         "<keyId>": {
//           "clientId", "keyId", "version", "algorithm",
//           "encryptedPrivateKeyDer": {        ← active keys only; AES-256-GCM wrapped
//             "keyId":               "<key identifier>",
//             "algorithm":           "aes-256-gcm",
//             "encryptedPrivateKey": "<base64>",
//             "iv":                  "<base64>",
//             "authTag":             "<base64>",
//             "createdAt":           "<ISO 8601>",
//             "updatedAt":           "<ISO 8601>"
//           },
//           "publicKeyDer": "<spki-der-base64>",
//           "status", "createdAt"
//         }
//       }
//     },
//     "legacyMap": { "<oldKeyId>": "<newKeyId>" }
//   }
//
// Legacy plaintext format used "privateKeyDer": "<pkcs8-der-base64>".
// Legacy field names used "ciphertext" and "tag" in encryptedPrivateKeyDer.
// Both are automatically migrated on load.  Startup fails closed if migration
// persistence or the post-migration plaintext scan fails.
//
// K1 — AUTHENTICATED RECORDS:
//   "recordSeal": { version: 1, ... } file marker — the file is SEALED
//   <entry>.recordMac                 HMAC-SHA256(HKDF(KEK, "qodiqa-keystore-record-mac-v1"), canonical public
//                                     fields + client bucket + map key + trust domain + encrypted-blob digest)
//   encryptedPrivateKeyDer.aad        AES-GCM AAD label; the AAD is the record identity (domain, keyId, clientId,
//                                     version, sha256(publicKeyDer)). Blobs without it (legacy) decrypt without AAD.
// A sealed file whose records are not ALL authentic is refused (CRITICAL KEY_RECORD_MAC_REFUSED; FATAL at bootstrap,
// in-memory store kept at reload). A legacy file is sealed once at bootstrap (trust on first use, WARN
// KEY_RECORDS_SEALED) -- never at reload once this process has seen a sealed file, and never when
// QODIQA_KEYSTORE_REQUIRE_SEALED=true. validateKeyStore() reports an unsealed/unauthentic file on disk as a violation.
//
// Writes are atomic: serialise → write to .tmp → rename over target.
// On POSIX rename(2) is atomic. On Windows Node.js falls back to a
// copy-then-unlink sequence if the destination already exists.

// Not guarded with _ensureBootstrapped(): saveKeys() is called internally by
// _ensureBootstrapped() itself during migration (before _bootstrapped is set),
// so guarding it here would recurse. Every external caller (rotateKey,
// rotateKeyAsync, revokeKey, purgeExpiredDeprecated) already calls
// _ensureBootstrapped() before ever touching _store, so by the time any of
// them calls saveKeys(), the store is guaranteed to already be loaded.
function _recordMacKey() { return deriveKekSubkey(seal.RECORD_MAC_INFO); }
function _recordAad(ids) { return { aad: seal.recordAad(SEAL_DOMAIN, ids), aadLabel: seal.AAD_LABEL }; }

function saveKeys() {
  const macKey = _recordMacKey(); // K1
  const payload = {
    version:       FILE_VERSION,
    // KEK-fingerprint guard rail: recomputed fresh on every save under the
    // currently-configured KEK, so it always describes what this write
    // actually encrypted under — see keyEncryption.js's computeKekFingerprint().
    kekFingerprint: computeKekFingerprint(),
    recordSeal:    seal.SEAL_DESCRIPTOR, // K1
    clients:       {},
    legacyMap:     _legacyMap,
    ...(Object.keys(_rotationFences).length ? { rotationFences: _rotationFences } : {}), //
  };

  for (const [clientId, clientStore] of Object.entries(_store)) {
    payload.clients[clientId] = {};
    for (const [keyId, rec] of Object.entries(clientStore)) {
      // Private key material is only persisted for the active signing key,
      // and always encrypted-at-rest using AES-256-GCM via the KEK from
      // SecretsProvider.  Deprecated and revoked records carry no private key.
      let encryptedEntry = {};
      let nativeKeyMarker = {};
      if (rec.status === 'active') {
        if (rec._privDer) {
          // K1: AAD-bound to the record identity.
          encryptedEntry = { encryptedPrivateKeyDer: encryptKeyMaterial(rec._privDer, { keyId: rec.keyId, createdAt: rec.createdAt,
            ..._recordAad({ keyId: rec.keyId, clientId: rec.clientId, version: rec.version, publicKeyDer: rec.publicKeyDer }) }) };
        } else {
          // Active key whose private material lives entirely inside a
          // NativeSigningProvider (Vault Transit / HSM) — never held locally
          // by design (see rotateKeyAsync/_buildNativeRecord). Without this
          // explicit marker, _tryLoadFromFile() cannot tell "legitimately
          // provider-only key" apart from "corrupted file missing its
          // private key" and would refuse to load — breaking both startup
          // and cross-instance reload for every native-provider deployment.
          nativeKeyMarker = { nativeKey: true };
        }
      }
      payload.clients[clientId][keyId] = {
        clientId:         rec.clientId,
        keyId:            rec.keyId,
        version:          rec.version,
        algorithm:        rec.algorithm,
        publicKeyDer:     rec.publicKeyDer.toString('base64'),
        status:           rec.status,
        createdAt:        rec.createdAt,
        retiredAt:        rec.retiredAt        || null,
        rotationDeadline: rec.rotationDeadline || null,
        expiresAt:        rec.expiresAt        || null,
        // Present only on revoked keys — records whether/how revocation
        // propagated to a native signing provider. See revokeKeyAsync().
        ...(rec.nativeRevocation !== undefined ? { nativeRevocation: rec.nativeRevocation } : {}),
        // when the key was revoked (revoked records only).
        ...(rec.status === 'revoked' ? { revokedAt: rec.revokedAt || null } : {}),
        ...encryptedEntry,
        ...nativeKeyMarker,
      };
      // K1: per-record MAC over the record exactly as persisted.
      const entry = payload.clients[clientId][keyId];
      entry.recordMac = seal.computeRecordMac(macKey, SEAL_DOMAIN, entry, { bucket: clientId, mapKey: keyId });
    }
  }

  ///-15, 0600, fsync, unique temp name, rename.
  const serialized = JSON.stringify(payload, null, 2);
  writeFileAtomicSecure(DATA_PATH, serialized);
  _lastFileHash = _sha256(serialized);
  _sealedSeen = true; // K1
  // every status change reaches this point — the key-status
  // timeline (src/core/signing/keyStatusTimeline.js) reconciles from here.
  for (const fn of _savedListeners) { try { fn(); } catch { /* a listener never breaks a save */ } }
}

// listeners notified after every successful saveKeys().
const _savedListeners = [];
function onKeysSaved(fn) { if (typeof fn === 'function') _savedListeners.push(fn); }

// the local status timeline of a live record — keys.json keeps
// createdAt, and retiredAt for a deprecated key; a revoked record never reaches
// verification (getPublicKey throws).
function _timelineOf(rec) {
  return {
    status:       rec.status,
    activatedAt:  rec.createdAt || null,
    deprecatedAt: rec.status === 'deprecated' ? (rec.retiredAt || null) : null,
    archivedAt:   null,
    revokedAt:    rec.status === 'revoked' ? (rec.revokedAt || null) : null, //
  };
}

// Scan the key file on disk for entries that store private key material as
// legacy plaintext (privateKeyDer field present).  Called after migration to
// verify the fail-closed invariant, and by validateStartup() for defence-in-depth.
// Returns [] when the file is absent or unparseable — other validators catch those.
function _scanFileForPlaintext() {
  if (!fs.existsSync(DATA_PATH)) return [];
  let data;
  try {
    data = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
  } catch {
    return [];
  }
  const found = [];
  for (const [clientId, clientData] of Object.entries(data.clients || {})) {
    if (typeof clientData !== 'object' || !clientData) continue;
    for (const [keyId, entry] of Object.entries(clientData)) {
      if (entry && entry.privateKeyDer) {
        found.push({ clientId, keyId });
      }
    }
  }
  return found;
}

function _sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

// K1: refuse an unauthenticated key file -- CRITICAL event + coded error (bootstrap: FATAL; reload: store kept).
function _refuseUnauthenticated(kind, detail) {
  _emitEvent('CRITICAL', 'KEY_RECORD_MAC_REFUSED', { file: DATA_PATH, kind, ...detail,
    message: `${DATA_PATH}: ${kind === 'unsealed' ? 'unsealed (unauthenticated) key file refused' : 'key record(s) with a missing or invalid MAC refused'} — the file was written without the KEK, or tampered with.` });
  /** @type {any} */ const e = new Error(`KeyStore: ${DATA_PATH} — ${kind === 'unsealed'
    ? `key file is not sealed (no record MACs) and ${detail.why}`
    : `record MAC ${detail.failures.map((f) => `${f.reason} for "${f.keyId}"`).join(', ')}`} — refusing unauthenticated key metadata`);
  e.code = 'KEYSTORE_RECORD_UNAUTHENTICATED';
  return e;
}

// K1: { sealed, failures } of a parsed file -- throws on an unknown marker or an unavailable KEK.
function _sealState(data) {
  if (!seal.isSealedFile(data)) return { sealed: false, failures: [] };
  const records = [];
  for (const [bucket, clientData] of Object.entries(data.clients || {})) {
    if (!clientData || typeof clientData !== 'object') { records.push({ entry: null, mapKey: String(bucket), bucket }); continue; }
    for (const [mapKey, entry] of Object.entries(clientData)) records.push({ entry, mapKey, bucket });
  }
  return { sealed: true, failures: seal.checkRecords(_recordMacKey(), SEAL_DOMAIN, records) };
}

function _countRecords(data) {
  let n = 0;
  for (const cd of Object.values((data && data.clients) || {})) n += (cd && typeof cd === 'object') ? Object.keys(cd).length : 1;
  return n;
}

// K1: seal violations of the file currently on disk ([] when absent, unparseable -- the loader reports that -- or empty).
function _scanFileSeal() {
  if (!fs.existsSync(DATA_PATH)) return [];
  let data;
  try { data = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8')); } catch { return []; }
  if (!data || typeof data !== 'object' || _countRecords(data) === 0) return [];
  try {
    const st = _sealState(data);
    if (!st.sealed) return [{ type: 'UNSEALED_KEY_STORE', clientId: null, detail: `${DATA_PATH} carries no record MACs (unauthenticated key metadata)` }];
    return st.failures.map((/** @type {any} */ f) => ({ type: 'KEY_RECORD_MAC_INVALID', clientId: f.bucket ?? null, keyId: f.keyId, detail: `record MAC ${f.reason} in ${DATA_PATH}` }));
  } catch (err) {
    return [{ type: 'KEY_SEAL_UNVERIFIABLE', clientId: null, detail: `${DATA_PATH}: ${err.message}` }];
  }
}

// opts.allowTofu: whether an unsealed (legacy) file may be accepted for the one-time seal migration (K1).
function _tryLoadFromFile(opts = {}) {
  if (!fs.existsSync(DATA_PATH)) return null;

  let raw;
  try {
    raw = fs.readFileSync(DATA_PATH, 'utf8');
  } catch (err) {
    throw new Error(`KeyStore: cannot read ${DATA_PATH} — ${err.message}`);
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw new Error(`KeyStore: ${DATA_PATH} is corrupted (invalid JSON) — ${err.message}`);
  }

  if (!data || typeof data !== 'object' || data.version !== FILE_VERSION) {
    throw new Error(`KeyStore: ${DATA_PATH} has unsupported format (expected version ${FILE_VERSION})`);
  }
  if (!data.clients || typeof data.clients !== 'object') {
    throw new Error(`KeyStore: ${DATA_PATH} is missing "clients" field`);
  }

  // KEK-fingerprint guard rail: check BEFORE any per-key decrypt attempt, so
  // a mismatched KEK fails fast with a specific, operator-actionable error
  // instead of a generic GCM auth-tag failure on the first active key
  // iterated below. A file written before this guard existed carries no
  // kekFingerprint and is backfilled on the next save (see kekFingerprintMigrationNeeded).
  // An EMPTY store (no clients) has nothing to backfill -- there is no key
  // material this fingerprint would ever protect yet -- so it is excluded
  // here rather than forcing a KEK-requiring saveKeys() call for a store
  // that has no reason to need one. The first save that actually adds a
  // client backfills it naturally: saveKeys() always writes a fresh
  // kekFingerprint (see saveKeys(), computeKekFingerprint()).
  assertKekFingerprint(data.kekFingerprint, DATA_PATH);
  const kekFingerprintMigrationNeeded = !data.kekFingerprint && Object.keys(data.clients || {}).length > 0;
  // K1: sealed or legacy? (KEK-free; an unknown marker throws.) Records are authenticated after the structural checks
  // below and before anything is returned -- nothing from an unauthenticated file is ever adopted.
  const sealed = seal.isSealedFile(data);

  const store     = {};
  const legacyMap = (data.legacyMap && typeof data.legacyMap === 'object') ? data.legacyMap : {};
  const rotationFences = (data.rotationFences && typeof data.rotationFences === 'object' && !Array.isArray(data.rotationFences)) ? { ...data.rotationFences } : {}; //
  let   migrationNeeded          = false; // active key has plaintext privateKeyDer
  let   fieldFormatMigrationNeeded = false; // encryptedPrivateKeyDer uses legacy ciphertext/tag names
  let   lifecycleMigrationNeeded = false; // active key missing lifecycle timestamps

  for (const [clientId, clientData] of Object.entries(data.clients)) {
    if (!CLIENT_ID_RE.test(clientId)) {
      throw new Error(`KeyStore: ${DATA_PATH} contains invalid clientId "${clientId}"`);
    }
    store[clientId] = {};
    for (const [keyId, entry] of Object.entries(clientData)) {
      if (!ALL_STATUSES.has(entry.status)) {
        throw new Error(`KeyStore: ${DATA_PATH} contains invalid status "${entry.status}" for key "${keyId}"`);
      }

      // Validate persisted lifecycle timestamps if present — corrupt values abort startup.
      if (entry.rotationDeadline != null && isNaN(new Date(entry.rotationDeadline).getTime())) {
        throw new Error(`KeyStore: ${DATA_PATH} contains invalid rotationDeadline for key "${keyId}"`);
      }
      if (entry.expiresAt != null && isNaN(new Date(entry.expiresAt).getTime())) {
        throw new Error(`KeyStore: ${DATA_PATH} contains invalid expiresAt for key "${keyId}"`);
      }
      if (entry.revokedAt != null && isNaN(new Date(entry.revokedAt).getTime())) {
        throw new Error(`KeyStore: ${DATA_PATH} contains invalid revokedAt for key "${keyId}"`);
      }

      let privDer, pubDer, isNativeKey = false;
      try {
        pubDer = Buffer.from(entry.publicKeyDer, 'base64');
        if (entry.status === 'active') {
          if (entry.encryptedPrivateKeyDer) {
            // Current format: AES-256-GCM encrypted private key.
            // K1: a sealed file only ever carries AAD-bound ciphertexts; a legacy file may carry AAD-less ones.
            if (sealed && entry.encryptedPrivateKeyDer.aad !== seal.AAD_LABEL) {
              throw new Error(`active key "${keyId}" in a sealed key file has a ciphertext without the record AAD binding`);
            }
            privDer = decryptKeyMaterial(entry.encryptedPrivateKeyDer, entry.encryptedPrivateKeyDer.aad !== undefined
              ? _recordAad({ keyId: entry.keyId, clientId: entry.clientId, version: entry.version, publicKeyDer: entry.publicKeyDer })
              : undefined);
            // Detect legacy field names (ciphertext/tag) — trigger format migration.
            if (!entry.encryptedPrivateKeyDer.encryptedPrivateKey && entry.encryptedPrivateKeyDer.ciphertext) {
              fieldFormatMigrationNeeded = true;
            }
          } else if (entry.privateKeyDer) {
            // Legacy plaintext format — loaded for immediate re-encryption.
            privDer = Buffer.from(entry.privateKeyDer, 'base64');
            migrationNeeded = true;
          } else if (entry.nativeKey === true) {
            // the marker is unauthenticated plaintext
            // JSON, so it is honoured ONLY when a NativeSigningProvider is
            // actually configured. In the default (local) deployment there is
            // never a legitimate provider-only active key — a planted/edited
            // record would otherwise load with no key-pair self-test and make
            // an attacker-chosen public key the active, verifying key.
            const _kpfLoad = _getKpf();
            if (!(_kpfLoad && typeof _kpfLoad.isNativeSigning === 'function' && _kpfLoad.isNativeSigning())) {
              throw new Error(`active key "${keyId}" carries nativeKey:true but no native signing provider is configured`);
            }
            // Active key generated inside a NativeSigningProvider (Vault
            // Transit / HSM) — its private material never enters this
            // process by design (see rotateKeyAsync/_buildNativeRecord), so
            // no encrypted/plaintext field is ever persisted for it. Without
            // this explicit marker there would be no way to distinguish
            // "legitimately provider-only key" from "corrupted file missing
            // its private key" — this is what makes the distinction safe
            // rather than silently loosening the corruption check below.
            isNativeKey = true;
          } else {
            throw new Error(`active key "${keyId}" has neither encryptedPrivateKeyDer nor privateKeyDer`);
          }
        }
        // Deprecated and revoked keys: private key not loaded regardless of file contents.
      } catch (err) {
        throw new Error(`KeyStore: ${DATA_PATH} contains invalid key material for "${keyId}" — ${err.message}`);
      }

      if (entry.status === 'active') {
        // Build lifecycle opts from disk values.  If either field is absent, _buildRecord
        // auto-computes both from createdAt — guaranteeing the invariant that every active
        // key in memory has non-null lifecycle.  Unconditional backfill: if the computed
        // expiresAt is in the past, startup validation will catch and fail-closed.
        const lifecycleOpts = {
          rotationDeadline: entry.rotationDeadline || null,
          expiresAt:        entry.expiresAt        || null,
        };
        if (!lifecycleOpts.rotationDeadline || !lifecycleOpts.expiresAt) {
          lifecycleMigrationNeeded = true;
          // _buildRecord will auto-compute from createdAt since opts is incomplete.
        }
        store[clientId][keyId] = isNativeKey
          // No local private material to self-test against — the equivalent
          // guarantee was already established remotely via _remoteSelfTest()
          // at creation time (see rotateKeyAsync). skipSelfTest mirrors
          // _buildNativeRecord(), but unlike that helper this preserves the
          // PERSISTED lifecycle timestamps via lifecycleOpts rather than
          // recomputing them from createdAt — this is a reload/restart of an
          // existing key, not the creation of a new one.
          ? _buildRecord(null, pubDer, entry.status, entry.clientId, entry.version, entry.createdAt, { ...lifecycleOpts, skipSelfTest: true })
          : _buildRecord(privDer, pubDer, entry.status, entry.clientId, entry.version, entry.createdAt, lifecycleOpts);
      } else if (entry.status === 'deprecated') {
        store[clientId][keyId] = _buildDeprecatedRecord(pubDer, entry.clientId, entry.version, entry.createdAt, entry.retiredAt || null);
      } else {
        // nativeRevocation is absent on files written before this field existed
        // (or on keys revoked while no native provider was configured) —
        // default to null rather than fabricating a value.
        // revokedAt is likewise absent on older files -> null.
        store[clientId][keyId] = Object.freeze({
          ..._buildRevokedRecord(pubDer, entry.clientId, entry.version, entry.createdAt, entry.revokedAt ?? null),
          nativeRevocation: entry.nativeRevocation ?? null,
        });
      }
    }
  }

  // K1: record authentication.
  let sealMigrationNeeded = false;
  if (sealed) {
    const failures = _sealState(data).failures;
    if (failures.length > 0) throw _refuseUnauthenticated('mac', { failures });
  } else if (_countRecords(data) > 0) {
    if (seal.sealRequired()) throw _refuseUnauthenticated('unsealed', { why: 'QODIQA_KEYSTORE_REQUIRE_SEALED=true forbids the one-time seal migration' });
    if (!opts.allowTofu) throw _refuseUnauthenticated('unsealed', { why: 'this process already holds a sealed store (a sealed file is never downgraded at reload)' });
    sealMigrationNeeded = true;
  }

  return { store, legacyMap, rotationFences, migrationNeeded, fieldFormatMigrationNeeded, lifecycleMigrationNeeded, kekFingerprintMigrationNeeded, sealMigrationNeeded, sealed, fileHash: _sha256(raw) };
}

// ── Store bootstrap ───────────────────────────────────────────────────────────
//
// Single loading path: persisted file (QODIQA_KEYS_PATH or data/keys.json).
// Key material MUST NOT be injected via environment variables or any source
// outside the canonical file.  If no file exists the store starts empty;
// keys must be provisioned before any signing operation via rotateKey().

// Mutable — populated on first use (see _ensureBootstrapped below), then
// mutated only by rotateKey / revokeKey.
let _store        = {};
let _legacyMap    = {};
// last ACCEPTED rotation-lock fence per client, persisted in keys.json
// (rotationFences) in the same write as the mutation it guards. A rotation commit carrying a fence that is not strictly
// greater than the recorded one comes from a holder whose lock expired and was taken by another rotator — refused
// (KEYSTORE_STALE_FENCE) instead of overwriting the newer rotation.
let _rotationFences = {};
function _fenceCheck(cid, opts) {
  const fence = opts && opts.fence;
  if (fence === undefined || fence === null) return false;
  const last = _rotationFences[cid] || 0;
  if (!(Number.isSafeInteger(fence) && fence > last)) {
    /** @type {any} */ const e = new Error(`KEYSTORE_STALE_FENCE: rotation fence ${fence} is not greater than the last accepted fence ${last} for "${cid}" — the rotation lock was lost to a newer rotator`);
    e.code = 'KEYSTORE_STALE_FENCE';
    throw e;
  }
  return true;
}
/** Check AND record (call right after the last re-read, immediately before the saveKeys() that commits the mutation). */
function _fenceGate(cid, opts) { if (_fenceCheck(cid, opts)) _rotationFences[cid] = opts.fence; }
let _bootstrapped = false;
// sha256 of the keys.json bytes this process
// last loaded or wrote. A mismatch before a mutation means another writer
// (another instance, a CLI) changed the file since — see _refreshBeforeMutation().
let _lastFileHash = null;
// K1: this process has loaded or written a sealed keys.json -- from then on an unsealed file is never accepted.
let _sealedSeen = false;

// Deliberately NOT run at module load time. require('./keyStore') must be
// side-effect-free — it must not touch disk, decrypt anything, or depend on
// QODIQA_KEY_ENCRYPTION_KEY being set. Loading (and, when needed, decrypting
// and migrating) the persisted key file is KEK-dependent work, and running it
// as a require()-time side effect meant it could execute — and throw as an
// uncaught exception — before server.js's own explicit, ordered startup
// checks (NO_PROVIDER_CONFIGURED → SIGN_TOKEN_NOT_CONFIGURED →
// KEY_ENCRYPTION_KEY_NOT_CONFIGURED → CLIENT_ID_NOT_CONFIGURED) ever ran,
// purely as an accident of require() ordering in server.js.
//
// Instead, every exported function below that reads or mutates
// _store/_legacyMap calls _ensureBootstrapped() first. In the real startup
// path this fires exactly once, the first time keyManager.validateStartup()
// calls validateKeyStore() — i.e. after server.js has already confirmed
// QODIQA_KEY_ENCRYPTION_KEY is set, and any failure propagates up through
// validateStartup() into server.js's existing
// `emit('FATAL', 'KEY_MANAGER_STARTUP_FAILED', ...); process.exit(1);`
// handling, instead of surfacing as an uncaught exception.
//
// _bootstrapped is set to true only after a fully successful load, so a
// failed attempt (missing/wrong KEK, corrupted file, failed migration) is
// retried — with the same, consistent error — on the next call, rather than
// silently leaving the store empty forever after a single failure.
function _ensureBootstrapped() {
  if (_bootstrapped) return;

  // Load persisted keys.  A missing file is normal (first run with empty store).
  // A corrupted or structurally invalid file is FATAL — do not start with an
  // empty store when a file exists but cannot be parsed, as that would silently
  // invalidate all existing verification without operator awareness.
  let fromFile = null;
  try {
    fromFile = _tryLoadFromFile({ allowTofu: !_sealedSeen });
  } catch (err) {
    throw new Error(`KeyStore: FATAL — key file cannot be loaded: ${err.message}`);
  }

  if (fromFile) {
    _store     = fromFile.store;
    _legacyMap = fromFile.legacyMap;
    _rotationFences = fromFile.rotationFences || {}; //
    _lastFileHash = fromFile.fileHash;
    if (fromFile.sealed) _sealedSeen = true; // K1

    // ── Lifecycle migration — backfill timestamps added ──────────
    // Emitted before the save so the event appears even if saveKeys() aborts.
    if (fromFile.lifecycleMigrationNeeded) {
      _emitEvent('INFO', 'KEY_LIFECYCLE_MIGRATION', {
        message: 'Lifecycle timestamps (rotationDeadline, expiresAt) backfilled for active keys ' +
                 'created before lifecycle timestamps were introduced. Startup will abort if persistence fails.',
      });
    }

    // ── Key migration — fail-closed ────────────────────────────────────────────
    // Covers: (1) plaintext privateKeyDer, (2) legacy field names (ciphertext/tag),
    // (3) missing lifecycle timestamps.  Emits KEY_MIGRATION_STARTED before the
    // write so the event is visible even if saveKeys() throws.
    // After a successful write the post-migration scan verifies no plaintext remains.
    const _anyMigration = fromFile.migrationNeeded || fromFile.fieldFormatMigrationNeeded || fromFile.lifecycleMigrationNeeded || fromFile.kekFingerprintMigrationNeeded || fromFile.sealMigrationNeeded;
    if (_anyMigration) {
      _emitEvent('INFO', 'KEY_MIGRATION_STARTED', {
        plaintextKeys:  fromFile.migrationNeeded,
        fieldFormat:    fromFile.fieldFormatMigrationNeeded,
        lifecycle:      fromFile.lifecycleMigrationNeeded,
        kekFingerprint: fromFile.kekFingerprintMigrationNeeded,
        recordSeal:     fromFile.sealMigrationNeeded, // K1
        message: 'Key store migration required. Re-encrypting with AES-256-GCM and updating ' +
                 'to current field format. Startup will abort if migration fails.',
      });

      try {
        saveKeys();
      } catch (err) {
        _emitEvent('CRITICAL', 'KEY_MIGRATION_FAILED', {
          message: `Key migration failed — startup aborted: ${err.message}`,
        });
        throw err;
      }

      // Second validation pass: verify no plaintext private keys remain on disk.
      // This is the fail-closed guarantee — any residual plaintext aborts startup.
      const residual = _scanFileForPlaintext();
      if (residual.length > 0) {
        _emitEvent('CRITICAL', 'KEY_MIGRATION_INCOMPLETE', {
          message:      'CRITICAL: Unencrypted private key detected after migration. Startup aborted.',
          affectedKeys: residual.map(r => r.keyId),
        });
        throw new Error(
          `CRITICAL: Unencrypted private key detected after migration attempt. ` +
          `Startup aborted. Keys still plaintext: ${residual.map(r => r.keyId).join(', ')}`,
        );
      }

      _emitEvent('INFO', 'KEY_MIGRATION_COMPLETED', {
        message: 'Key migration completed. All active keys are now encrypted-at-rest ' +
                 'with AES-256-GCM using current field format.',
      });
      if (fromFile.sealMigrationNeeded) {
        // K1: one-time trust-on-first-use seal of a legacy keys.json.
        _emitEvent('WARN', 'KEY_RECORDS_SEALED', {
          tofu: true,
          message: `${DATA_PATH} predated authenticated key records — sealed once on load (trust on first use). ` +
                   'From now on an unsealed or tampered record is refused. Set QODIQA_KEYSTORE_REQUIRE_SEALED=true to forbid this migration.',
        });
      }
    }
  }
  // If no file exists the store starts empty.  getActiveKey() will throw for any
  // client until an operator explicitly provisions keys via rotateKey().

  const clients = Object.keys(_store);
  const active  = Object.values(_store)
    .flatMap(cs => Object.values(cs))
    .filter(r => r.status === 'active')
    .map(r => ({ keyId: r.keyId, clientId: r.clientId }));
  _emitEvent('INFO', 'KEYSTORE_LOADED', { clients: clients.length, active: active.length, keys: active });

  _bootstrapped = true;
}

// ── Reload-before-mutation ───────────────────
//
// saveKeys() serialises the WHOLE store from this process's memory, which can
// be up to one reload interval (default 5 min) stale. Without this, instance B
// rotating client Y re-persisted B's stale view of client X and silently erased
// A's new key for X (its private key existed only in that file and in A's
// memory), or resurrected a key A had revoked (E3 in agent-distributed.md).
//
// Every keys.json mutation (rotate, revoke, purge — and the scheduler/admin
// routes that funnel into them) calls this first: if the file's bytes differ
// from what this process last loaded or wrote, the fresh file is loaded via
// reloadFromDisk() (which never un-revokes a key — see there) BEFORE the
// mutation is applied. Fail closed: if the changed file cannot be loaded, the
// mutation is refused (strict) rather than applied over a stale view.
// Non-strict mode is used only immediately after a native-provider await, where
// the provider-side action has already happened and must still be recorded.
//
// Residual (owner/design item): this narrows the lost-update window to the
// synchronous gap between this check and saveKeys()'s rename (plus the native
// provider await in the *Async paths); a store-wide lock / compare-before-
// rename is the complete fix and is NOT implemented here.
function _refreshBeforeMutation({ strict = true } = {}) {
  let raw;
  try {
    if (!fs.existsSync(DATA_PATH)) return;
    raw = fs.readFileSync(DATA_PATH, 'utf8');
  } catch (err) {
    if (!strict) return;
    /** @type {any} */ const e = new Error(`KeyStore: cannot re-read ${DATA_PATH} before mutation — ${err.message}`);
    e.code = 'KEYSTORE_RELOAD_FAILED';
    throw e;
  }
  if (_lastFileHash !== null && _sha256(raw) === _lastFileHash) return;
  const r = reloadFromDisk();
  if (!r.reloaded && r.error && strict) {
    /** @type {any} */ const e = new Error(`KeyStore: ${DATA_PATH} changed on disk and could not be reloaded — mutation refused: ${r.error}`);
    e.code = 'KEYSTORE_RELOAD_FAILED';
    throw e;
  }
}

// ── Internal lookup ───────────────────────────────────────────────────────────

function _resolveKeyId(rawKeyId) {
  if (NEW_KEY_ID_RE.test(rawKeyId))    return rawKeyId;
  if (LEGACY_KEY_ID_RE.test(rawKeyId)) return _legacyMap[rawKeyId] || null;
  return null;
}

function _lookupRecord(resolvedKeyId) {
  if (!resolvedKeyId) return null;
  const colonIdx = resolvedKeyId.indexOf(':');
  if (colonIdx === -1) return null;
  const clientId = resolvedKeyId.slice(0, colonIdx);
  return (_store[clientId] && _store[clientId][resolvedKeyId]) || null;
}

// Precondition: keyId must already have passed NEW_KEY_ID_RE (colon guaranteed present).
function _validateClientOwnership(clientId, keyId) {
  const embeddedClient = keyId.slice(0, keyId.indexOf(':'));
  if (embeddedClient !== clientId) {
    throw new Error(`KeyStore: clientId mismatch — keyId "${keyId}" does not belong to client "${clientId}"`);
  }
}

// ── Rotation ──────────────────────────────────────────────────────────────────
//
// remediation — "rotation moves the outgoing key to 'deprecated', not
// 'revoked', so a compromised key keeps verifying after the operator's most
// intuitive incident-response action."
//
// Rotation has two explicit, distinct modes:
//
//   'emergency' — the outgoing key is moved straight to 'revoked'. It
//                  immediately loses BOTH signing and verification
//                  capability, exactly like calling revokeKey()/
//                  revokeKeyAsync() on it directly. This is the correct
//                  choice for an operator's ordinary "rotate the key"
//                  incident-response action — it must not silently leave a
//                  potentially compromised key trusted.
//
//   'graceful'  — the previous, deprecate-and-keep-verifiable behavior. The
//                  outgoing key can no longer sign (private material is
//                  discarded either way) but remains verifiable so artifacts
//                  signed just before a *planned, non-incident* rotation
//                  don't fail. Routine, schedule-driven rotation
//                  (services/artifact/rotationScheduler.js) and startup
//                  auto-rotation of an aged-out (not suspected-compromised)
//                  key (services/artifact/tenantKeyManager.js) use this mode
//                  because those are planned maintenance, not compromise
//                  response.
//
// there is no implicit default. Before this remediation, an omitted
// or invalid `opts.mode` silently resolved to 'emergency' — every caller of
// rotateKey()/rotateKeyAsync() that actually rotates an EXISTING active key
// (the only branch where a mode decision is meaningful; first-time
// provisioning and no-active-key recovery never reach this function at all
// — there is no outgoing key for a mode to apply to) got emergency-mode
// revocation whether or not that was the intent. "Rotate the key" silently
// choosing a compromise-response outcome for what might have been routine
// maintenance is exactly the class of bug this closes: the caller MUST now
// say which outcome it wants. Every existing caller in this codebase that
// performs a genuine rotation already does — services/artifact/keyManager.js
// (rotate/rotateAsync pass through whatever opts.mode the caller supplied;
// rotateGracefully/rotateGracefullyAsync always supply 'graceful' explicitly),
// src/api/routes/keyAdmin.js's /rotate route, and the rotation scheduler
// above. A call that omits mode, or passes null/undefined/''/an unrecognized
// string, throws immediately — fail closed, never a silent default.
//
// Both modes discard private key material from the outgoing record
// immediately and never persist it for a non-active key — that part of the
// original design was already correct and is unchanged.

const VALID_ROTATION_MODES = new Set(['graceful', 'emergency']);

function _resolveRotationMode(opts) {
  const mode = opts && opts.mode;
  if (!VALID_ROTATION_MODES.has(mode)) {
    throw new TypeError(
      `rotateKey: opts.mode is required and must be exactly 'graceful' or 'emergency' — ` +
      `got ${JSON.stringify(mode)}. There is no default mode; the caller must ` +
      `explicitly choose the outcome for the outgoing active key. Use rotateKeyGracefully()/` +
      `rotateKeyGracefullyAsync() for planned maintenance, or pass { mode: 'emergency' } ` +
      `explicitly for incident response.`,
    );
  }
  return mode;
}

function _provisionFirstKey(cid, enrich) {
  _store[cid] = {};
  const keyId = `${cid}:key_v1`;
  _store[cid][keyId] = _generateRecord('active', cid, 1);
  saveKeys();
  _emitEvent('INFO', 'KEY_CREATED', { clientId: cid, keyId, version: 1, status: 'active', ...(enrich || {}) });
  _registerTenantQuietly(cid);
  return _store[cid][keyId];
}

// opts:
//   mode        — REQUIRED whenever an existing active key is being rotated
//                 (i.e. not the first-provisioning or no-active-key-recovery
//                 case — see _resolveRotationMode() above). Must be exactly
//                 'graceful' or 'emergency'; omitted/null/undefined/empty/
//                 unrecognized throws.
//   reason      — free-text rotation reason, e.g. 'SCHEDULED_ROTATION', 'MANUAL'.
//                 Included in emitted events only when supplied.
//   triggeredBy — 'scheduler' | 'operator:<username>' | null. Included in
//                 emitted events only when supplied.
function rotateKey(clientId, opts) {
  if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) {
    throw new TypeError(
      `rotateKey: clientId is required and must be a non-empty string matching [A-Za-z0-9_-]{1,64} — ` +
      `got ${JSON.stringify(clientId)}. No default or fallback client is permitted.`,
    );
  }
  _ensureBootstrapped();
  // (P4): this synchronous path always generates a LOCAL
  // software key. Under a NativeSigningProvider (Vault Transit / HSM) that
  // would silently put a software key into an HSM deployment — refuse, exactly
  // as revokeKey() already does. rotateKeyAsync() calls this function only on
  // its non-native branch, so that path is unaffected.
  const _kpfSync = _getKpf();
  if (_kpfSync && typeof _kpfSync.isNativeSigning === 'function' && _kpfSync.isNativeSigning()) {
    /** @type {any} */ const e = new Error(
      `rotateKey: a native signing provider ("${_kpfSync.getNativeSigningProvider().name}") is active — ` +
      `synchronous rotation would generate a LOCAL software key. Use rotateKeyAsync()/rotateKeyGracefullyAsync().`,
    );
    e.code = 'NATIVE_SIGNING_REQUIRES_ASYNC_ROTATION';
    throw e;
  }
  _refreshBeforeMutation(); //
  _fenceGate(clientId, opts); // no await between this re-read and the saveKeys() below
  const cid = clientId;
  // Only spread enrichment fields into emitted events when the caller actually
  // supplied opts — this keeps the event shape byte-identical for every
  // pre-existing call site that never passes a second argument.
  const _enrich = (opts && (opts.reason !== undefined || opts.triggeredBy !== undefined))
    ? { ...(opts.reason      !== undefined ? { reason:      opts.reason }      : {}),
        ...(opts.triggeredBy !== undefined ? { triggeredBy: opts.triggeredBy } : {}) }
    : null;

  if (!_store[cid]) {
    const rec = _provisionFirstKey(cid, _enrich);
    return { keyId: `${cid}:key_v1`, version: 1, clientId: cid, fingerprint: rec.fingerprint, previousKeyId: null, previousKeyStatus: null, mode: null };
  }

  const clientStore = _store[cid];

  const activeKeys = Object.entries(clientStore).filter(([, rec]) => rec.status === 'active');

  // Recovery path: client exists in the store but has no active key.
  // This occurs when all prior keys were deprecated or revoked without a
  // successor being provisioned (e.g. emergency revocation of the sole active key).
  // Use _nextVersion() so the new key never collides with an existing keyId.
  if (activeKeys.length === 0) {
    const nextVersion = _nextVersion(clientStore);
    const nextKeyId   = `${cid}:key_v${nextVersion}`;
    const newRec      = _generateRecord('active', cid, nextVersion);
    clientStore[nextKeyId] = newRec;
    saveKeys();
    _emitEvent('INFO', 'KEY_PROVISIONED_RECOVERY', {
      clientId: cid, keyId: nextKeyId, version: nextVersion, status: 'active',
      message: `Recovery: provisioned new active key for "${cid}" — no prior active key existed.`,
      ...(_enrich || {}),
    });
    _registerTenantQuietly(cid);
    return { keyId: nextKeyId, version: nextVersion, clientId: cid, fingerprint: newRec.fingerprint, previousKeyId: null, previousKeyStatus: null, mode: null };
  }

  if (activeKeys.length > 1) {
    throw new Error(`rotateKey: invariant violation — ${activeKeys.length} active keys found for client "${cid}"`);
  }

  const [activeId, activeRec] = activeKeys[0];
  const nextVersion            = activeRec.version + 1;
  const nextKeyId              = `${cid}:key_v${nextVersion}`;
  const newRec                 = _generateRecord('active', cid, nextVersion);
  const mode                   = _resolveRotationMode(opts);

  // Both branches discard private key material immediately — neither record
  // builder carries it, and non-active keys never persist it. the
  // outgoing record's own _privDer buffer is also explicitly zeroed below,
  // not just left to be garbage-collected.
  if (mode === 'graceful') {
    const retiredAt = new Date().toISOString();
    clientStore[activeId]  = _buildDeprecatedRecord(activeRec.publicKeyDer, activeRec.clientId, activeRec.version, activeRec.createdAt, retiredAt);
    clientStore[nextKeyId] = newRec;
    _zeroizePrivateKey(activeRec);

    saveKeys();

    _emitEvent('INFO', 'KEY_DEPRECATED', { clientId: cid, keyId: activeId,   version: activeRec.version, status: 'deprecated', retiredAt, mode, ...(_enrich || {}) });
    _emitEvent('INFO', 'KEY_ROTATED',    { clientId: cid, keyId: nextKeyId,  version: nextVersion,       status: 'active', fingerprint: newRec.fingerprint, mode, ...(_enrich || {}) });
  } else {
    // Emergency (default) — the outgoing key is revoked, not
    // deprecated, so it loses verification capability in the same instant it
    // loses signing capability. No native signing provider round trip here —
    // this is the local-Ed25519-only synchronous path; see rotateKeyAsync()
    // for the KMS/HSM-aware equivalent.
    const nativeRevocation = {
      attempted: false, supported: false, provider: null, method: null,
      reason: 'NO_NATIVE_SIGNING_PROVIDER_CONFIGURED',
    };
    clientStore[activeId] = Object.freeze({
      ..._buildRevokedRecord(activeRec.publicKeyDer, activeRec.clientId, activeRec.version, activeRec.createdAt),
      nativeRevocation,
    });
    clientStore[nextKeyId] = newRec;
    _zeroizePrivateKey(activeRec);

    saveKeys();

    _emitEvent('INFO', 'KEY_REVOKED', {
      clientId: cid, keyId: activeId, version: activeRec.version, status: 'revoked',
      nativeRevocation, revocationTrigger: 'ROTATION', mode, ...(_enrich || {}),
    });
    _emitEvent('INFO', 'KEY_ROTATED', { clientId: cid, keyId: nextKeyId, version: nextVersion, status: 'active', fingerprint: newRec.fingerprint, mode, ...(_enrich || {}) });
  }

  _registerTenantQuietly(cid);

  return {
    keyId: nextKeyId, version: nextVersion, clientId: cid, fingerprint: newRec.fingerprint,
    previousKeyId: activeId, previousKeyStatus: mode === 'graceful' ? 'deprecated' : 'revoked', mode,
  };
}

// Explicit, distinct entry point for planned/compatibility rotation that
// preserves verification capability for the outgoing key (status
// 'deprecated'). Never call this in response to a suspected key compromise —
// use rotateKey() (default 'emergency' mode) or revokeKey()/revokeKeyAsync()
// instead. See the "Rotation" section header above for the full rationale.
function rotateKeyGracefully(clientId, opts) {
  return rotateKey(clientId, { ...(opts || {}), mode: 'graceful' });
}

// ── Native-signing-aware rotation (async) ─────────────────────────────────────
//
// Used by automatic rotation (the scheduler) and available to any manual
// caller that wants provider-correct rotation under Vault Transit / HSM.
//
// When no NativeSigningProvider is active, this delegates entirely to the
// synchronous rotateKey() above — identical behavior, wrapped in a resolved
// Promise, so callers can use rotateKeyAsync() uniformly regardless of which
// KMS provider is configured.
//
// When a NativeSigningProvider IS active (QODIQA_KMS_PROVIDER=vault-transit
// or hsm), the new key pair is generated INSIDE the provider — private key
// material never enters this process — and the old key is deprecated inside
// the provider too, in addition to the same local bookkeeping performed by
// the synchronous path (deprecated/active records in keys.json carry only
// public material either way).
//
// Returns the same shape as rotateKey(): { keyId, version, clientId, fingerprint }.
async function rotateKeyAsync(clientId, opts = {}) {
  if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) {
    throw new TypeError(
      `rotateKeyAsync: clientId is required and must be a non-empty string matching [A-Za-z0-9_-]{1,64} — ` +
      `got ${JSON.stringify(clientId)}. No default or fallback client is permitted.`,
    );
  }
  _ensureBootstrapped();
  const cid = clientId;
  const kpf = _getKpf();
  const native = !!(kpf && kpf.isNativeSigning());

  if (!native) {
    return rotateKey(cid, opts);
  }

  const provider = kpf.getNativeSigningProvider();
  const _enrich  = { provider: provider.name, ...(opts.reason !== undefined ? { reason: opts.reason } : {}), ...(opts.triggeredBy !== undefined ? { triggeredBy: opts.triggeredBy } : {}) };
  _refreshBeforeMutation(); //
  _fenceCheck(cid, opts); // fail fast before any provider work

  if (!_store[cid]) {
    const keyId = `${cid}:key_v1`;
    const { publicKeyDer } = await provider.generateKeyPair(keyId);
    await _remoteSelfTest(provider, keyId, publicKeyDer);
    _refreshBeforeMutation({ strict: false }); //
    _fenceGate(cid, opts); // re-checked after the provider awaits (the pause is about): another writer may have saved during the awaits
    _store[cid] = {};
    _store[cid][keyId] = _buildNativeRecord(publicKeyDer, 'active', cid, 1);
    saveKeys();
    _emitEvent('INFO', 'KEY_CREATED', { clientId: cid, keyId, version: 1, status: 'active', ..._enrich });
    _registerTenantQuietly(cid);
    return { keyId, version: 1, clientId: cid, fingerprint: _store[cid][keyId].fingerprint, previousKeyId: null, previousKeyStatus: null, mode: null };
  }

  const clientStore = _store[cid];
  const activeKeys  = Object.entries(clientStore).filter(([, rec]) => rec.status === 'active');

  if (activeKeys.length > 1) {
    throw new Error(`rotateKeyAsync: invariant violation — ${activeKeys.length} active keys found for client "${cid}"`);
  }

  const nextVersion = activeKeys.length === 0 ? _nextVersion(clientStore) : activeKeys[0][1].version + 1;
  const nextKeyId    = `${cid}:key_v${nextVersion}`;

  const { publicKeyDer } = await provider.generateKeyPair(nextKeyId);
  await _remoteSelfTest(provider, nextKeyId, publicKeyDer);
  const newRec = _buildNativeRecord(publicKeyDer, 'active', cid, nextVersion);

  let previousKeyId = null, previousKeyStatus = null, mode = null;

  if (activeKeys.length === 0) {
    // Re-fetch: a concurrent reload may have swapped `_store` during the
    // awaits above — see _liveClientStore().
    _refreshBeforeMutation({ strict: false }); //
    _fenceGate(cid, opts); // re-checked after the provider awaits (the pause is about)
    _liveClientStore(cid)[nextKeyId] = newRec;
    saveKeys();
    _emitEvent('INFO', 'KEY_PROVISIONED_RECOVERY', {
      clientId: cid, keyId: nextKeyId, version: nextVersion, status: 'active',
      message: `Recovery: provisioned new active key for "${cid}" — no prior active key existed.`,
      ..._enrich,
    });
  } else {
    const [activeId, activeRec] = activeKeys[0];
    mode = _resolveRotationMode(opts);
    previousKeyId = activeId;
    previousKeyStatus = mode === 'graceful' ? 'deprecated' : 'revoked';

    if (mode === 'graceful') {
      const retiredAt = new Date().toISOString();

      try {
        await provider.deprecateKey(activeId);
      } catch (err) {
        // Fail closed: do not activate the new key if the provider could not
        // deprecate the old one — that would leave two provider-side signing
        // keys usable simultaneously, which is the exact inconsistency this
        // scheduler must prevent.
        _emitEvent('ERROR', 'KEY_ROTATION_PROVIDER_DEPRECATE_FAILED', {
          clientId: cid, keyId: activeId, provider: provider.name, error: err.message, ..._enrich,
        });
        throw err;
      }

      // Re-fetch: a concurrent reload may have swapped `_store` during either
      // await above — see _liveClientStore().
      _refreshBeforeMutation({ strict: false }); //
    _fenceGate(cid, opts); // re-checked after the provider awaits (the pause is about)
      const liveClientStore = _liveClientStore(cid);
      liveClientStore[activeId]  = _buildDeprecatedRecord(activeRec.publicKeyDer, activeRec.clientId, activeRec.version, activeRec.createdAt, retiredAt);
      liveClientStore[nextKeyId] = newRec;
      _zeroizePrivateKey(activeRec); //
      saveKeys();

      _emitEvent('INFO', 'KEY_DEPRECATED', { clientId: cid, keyId: activeId, version: activeRec.version, status: 'deprecated', retiredAt, mode, ..._enrich });
      _emitEvent('INFO', 'KEY_ROTATED',    { clientId: cid, keyId: nextKeyId, version: nextVersion, status: 'active', fingerprint: newRec.fingerprint, mode, ..._enrich });
    } else {
      // Emergency (default) — revoke the outgoing key at the native
      // provider boundary (strongest supported method) instead of merely
      // deprecating it. Fail closed identically to the graceful branch: if
      // the provider revocation fails, the rotation aborts before any local
      // state changes, and the old key remains the sole active key both
      // locally and at the provider.
      let nativeRevocation;
      try {
        nativeRevocation = await _revokeAtProvider(provider, activeId, cid, activeRec.version, _enrich);
      } catch (err) {
        _emitEvent('ERROR', 'KEY_ROTATION_PROVIDER_REVOKE_FAILED', {
          clientId: cid, keyId: activeId, provider: provider.name, error: err.message, ..._enrich,
        });
        throw err;
      }

      // Re-fetch: a concurrent reload may have swapped `_store` during the
      // awaits above — see _liveClientStore().
      _refreshBeforeMutation({ strict: false }); //
    _fenceGate(cid, opts); // re-checked after the provider awaits (the pause is about)
      const liveClientStore = _liveClientStore(cid);
      liveClientStore[activeId] = Object.freeze({
        ..._buildRevokedRecord(activeRec.publicKeyDer, activeRec.clientId, activeRec.version, activeRec.createdAt),
        nativeRevocation,
      });
      liveClientStore[nextKeyId] = newRec;
      _zeroizePrivateKey(activeRec); //
      saveKeys();

      _emitEvent('INFO', 'KEY_REVOKED', {
        clientId: cid, keyId: activeId, version: activeRec.version, status: 'revoked',
        nativeRevocation, revocationTrigger: 'ROTATION', mode, ..._enrich,
      });
      _emitEvent('INFO', 'KEY_ROTATED', { clientId: cid, keyId: nextKeyId, version: nextVersion, status: 'active', fingerprint: newRec.fingerprint, mode, ..._enrich });
    }
  }

  _registerTenantQuietly(cid);

  return {
    keyId: nextKeyId, version: nextVersion, clientId: cid, fingerprint: newRec.fingerprint,
    previousKeyId, previousKeyStatus, mode,
  };
}

// Explicit, distinct entry point mirroring rotateKeyGracefully() for the
// native-signing-aware (Vault Transit / HSM) path.
function rotateKeyGracefullyAsync(clientId, opts = {}) {
  return rotateKeyAsync(clientId, { ...opts, mode: 'graceful' });
}

// Remote equivalent of _selfTest(): signs a fixed probe message through the
// native provider and verifies the signature locally against the returned
// public key.  Throws if the provider generated a broken or mismatched pair —
// the same fail-closed guarantee _selfTest() gives the local Ed25519 path.
async function _remoteSelfTest(provider, keyId, publicKeyDer) {
  const probe = crypto.createHash('sha256').update('qodiqa-keystore-self-test', 'utf8').digest();
  const sig   = await provider.sign(keyId, probe);
  if (!ed25519Verify(probe, sig, publicKeyDer)) {
    throw new Error(`FATAL: native signing provider self-test failed for key "${keyId}"`);
  }
}

// ── Revocation ────────────────────────────────────────────────────────────────
//
// remediation: revoking a key inside QODIQA must never diverge from the
// native cryptographic backend (Vault Transit / HSM). There are two entry
// points:
//
//   revokeKey(...)       — synchronous, local-store-only. Kept for backward
//                           compatibility with deployments that run no
//                           NativeSigningProvider (the local-Ed25519 default),
//                           where local metadata IS the entire cryptographic
//                           boundary. Refuses (throws) when a native provider
//                           is active, because a sync call structurally
//                           cannot await a network round-trip to Vault/HSM —
//                           silently skipping that propagation is exactly the
//                           bug this remediation closes.
//
//   revokeKeyAsync(...)  — the native-aware path. Always safe to call
//                           regardless of which provider is configured;
//                           delegates to the same local-only behavior when no
//                           native provider is active.
//
// Both funnel through _revokeTargetFromArgs() for identical argument
// validation, and through the per-keyId mutex below for serialization against
// concurrent revoke calls and in-flight native signing.

function _revokeTargetFromArgs(clientIdOrKeyId, maybeKeyId) {
  let clientId, keyId;
  if (maybeKeyId === undefined) {
    // Single-arg form: revokeKey(keyId) — derives clientId from the keyId prefix.
    keyId = clientIdOrKeyId;
    if (typeof keyId !== 'string' || !NEW_KEY_ID_RE.test(keyId)) {
      throw new TypeError(`revokeKey: invalid keyId format "${keyId}"`);
    }
    clientId = keyId.slice(0, keyId.indexOf(':'));
  } else {
    // Two-arg form: revokeKey(clientId, keyId) — preserved for backward compat.
    clientId = clientIdOrKeyId;
    keyId    = maybeKeyId;
    if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) {
      throw new TypeError(`revokeKey: invalid clientId "${clientId}"`);
    }
    if (typeof keyId !== 'string' || !NEW_KEY_ID_RE.test(keyId)) {
      throw new TypeError(`revokeKey: invalid keyId format "${keyId}"`);
    }
    _validateClientOwnership(clientId, keyId);
  }
  return { clientId, keyId };
}

// ── Per-keyId mutex ────────────────────────────────────────────────────────
//
// Guarantees deterministic ordering between a revoke and an in-flight native
// sign for the SAME keyId within this process: whichever acquires the lock
// first for that keyId runs to completion before the other proceeds. A sign
// that has already acquired the lock is allowed to finish (the same
// trade-off real KMS/HSM backends make — in-flight operations complete, no
// new ones start); a revoke that acquires the lock first flips local status
// to 'revoked' before releasing, so a sign that was waiting sees the new
// status and refuses. See nativeSignLocked() and revokeKeyAsync().
//
// Cross-instance coordination (two processes revoking the same key at the
// same moment) is intentionally out of scope: revocation is a rare,
// operator-driven action, unlike automatic rotation which runs unattended on
// every instance and therefore needs the distributed lock in rotationLock.js.
// A second, concurrent revoke from another instance simply re-attempts
// provider revocation against an already-revoked key, which every provider
// implementation here treats as idempotent-safe to retry.
const _keyLocks = new Map();

function _withKeyLock(keyId, fn) {
  const tail = _keyLocks.get(keyId) || Promise.resolve();
  const run  = tail.then(fn);
  _keyLocks.set(keyId, run.catch(() => {}));
  return run;
}

function revokeKey(clientIdOrKeyId, maybeKeyId) {
  _ensureBootstrapped();
  const { clientId, keyId } = _revokeTargetFromArgs(clientIdOrKeyId, maybeKeyId);

  const kpf = _getKpf();
  if (kpf && kpf.isNativeSigning()) {
    throw new Error(
      `revokeKey: a native signing provider ("${kpf.getNativeSigningProvider().name}") is active — ` +
      `synchronous revocation cannot propagate to it and would silently leave the key usable at ` +
      `the provider boundary. Use revokeKeyAsync("${keyId}") instead.`,
    );
  }

  _refreshBeforeMutation(); //
  const clientStore = _store[clientId];
  if (!clientStore || !clientStore[keyId]) {
    throw new Error(`revokeKey: unknown keyId "${keyId}" for client "${clientId}"`);
  }

  const rec = clientStore[keyId];
  if (rec.status === 'revoked') return;

  const nativeRevocation = {
    attempted: false,
    supported: false,
    provider:  null,
    method:    null,
    reason:    'NO_NATIVE_SIGNING_PROVIDER_CONFIGURED',
  };

  // Build revoked record using only public key material — private key is
  // discarded from memory immediately on revocation, and its buffer bytes are
  // explicitly zeroed rather than left for GC.
  clientStore[keyId] = Object.freeze({
    ..._buildRevokedRecord(rec.publicKeyDer, rec.clientId, rec.version, rec.createdAt),
    nativeRevocation,
  });
  _zeroizePrivateKey(rec);

  saveKeys();
  _emitEvent('INFO', 'KEY_REVOKED', { clientId, keyId, version: rec.version, status: 'revoked', nativeRevocation });
}

/**
 * Native-signing-aware revocation. Always the correct entry point regardless
 * of which KMS/signing provider is configured — delegates to the same
 * local-only behavior as revokeKey() when no NativeSigningProvider is active.
 *
 * When a native provider IS active (Vault Transit / HSM):
 *   1. The local record is flipped to 'revoked' and persisted BEFORE the
 *      provider call — QODIQA itself will never again select this key for
 *      signing, regardless of what happens next. This is the fail-closed
 *      guarantee for QODIQA's own signing path.
 *   2. The provider's strongest supported revocation method (per
 *      getRevocationCapabilities()) is invoked.
 *   3. On success, the local record is updated with the provider's response
 *      and a KEY_REVOKED_NATIVE_SUCCESS audit event is emitted.
 *   4. On failure, the local record records the failure explicitly (it is
 *      NOT reported as a clean revocation), a KEY_REVOKED_NATIVE_FAILED audit
 *      event is emitted, and this function throws — the caller MUST treat
 *      the operation as failed and understand the key may still be usable at
 *      the provider boundary even though QODIQA will no longer use it.
 *
 * Idempotent: revoking an already-revoked key returns its recorded
 * nativeRevocation outcome without re-invoking the provider.
 *
 * @param {string} clientIdOrKeyId
 * @param {string} [maybeKeyId]  Omit (or pass opts here) for the single-arg form: revokeKeyAsync(keyId, opts).
 * @param {{ reason?: string, operator?: string }} [opts]
 * @returns {Promise<{ clientId: string, keyId: string, status: string, nativeRevocation: object, alreadyRevoked?: boolean }>}
 */
async function revokeKeyAsync(clientIdOrKeyId, maybeKeyId, opts = {}) {
  _ensureBootstrapped();
  // Disambiguate the two call shapes: revokeKeyAsync(keyId, opts) — single-arg
  // form with options — vs. revokeKeyAsync(clientId, keyId, opts). maybeKeyId
  // is only ever a keyId string in the latter; an object in that position
  // means the caller used the former.
  let resolvedMaybeKeyId = maybeKeyId;
  let resolvedOpts = opts;
  if (maybeKeyId !== undefined && typeof maybeKeyId === 'object' && maybeKeyId !== null) {
    resolvedOpts = maybeKeyId;
    resolvedMaybeKeyId = undefined;
  }
  const { clientId, keyId } = _revokeTargetFromArgs(clientIdOrKeyId, resolvedMaybeKeyId);
  const _enrich = { operator: resolvedOpts.operator ?? null, reason: resolvedOpts.reason ?? null };

  return _withKeyLock(keyId, async () => {
    _refreshBeforeMutation(); //
    const clientStore = _store[clientId];
    const rec = clientStore && clientStore[keyId];
    if (!rec) throw new Error(`revokeKeyAsync: unknown keyId "${keyId}" for client "${clientId}"`);

    if (rec.status === 'revoked') {
      return { clientId, keyId, status: 'revoked', alreadyRevoked: true, nativeRevocation: rec.nativeRevocation ?? null };
    }

    const kpf      = _getKpf();
    const native   = !!(kpf && kpf.isNativeSigning());
    const provider = native ? kpf.getNativeSigningProvider() : null;

    if (!native) {
      const nativeRevocation = {
        attempted: false,
        supported: false,
        provider:  null,
        method:    null,
        reason:    'NO_NATIVE_SIGNING_PROVIDER_CONFIGURED',
        detail:    'No NativeSigningProvider is configured (local Ed25519 mode) — there is no ' +
                   'external cryptographic boundary for this key beyond QODIQA itself. Local ' +
                   'revocation is the complete revocation.',
      };
      clientStore[keyId] = Object.freeze({
        ..._buildRevokedRecord(rec.publicKeyDer, rec.clientId, rec.version, rec.createdAt),
        nativeRevocation,
      });
      _zeroizePrivateKey(rec); //
      saveKeys();
      _emitEvent('INFO', 'KEY_REVOKED', { clientId, keyId, version: rec.version, status: 'revoked', nativeRevocation, ..._enrich });
      return { clientId, keyId, status: 'revoked', nativeRevocation };
    }

    const capabilities = _providerRevocationCapabilities(provider);
    const method        = pickStrongestRevocationMethod(capabilities);
    if (!method) {
      // Explicit, not silent: the provider is native-signing-capable but
      // declares no usable revocation method. Local state is NOT flipped to
      // revoked — QODIQA would otherwise report a security guarantee
      // ("revoked") it cannot back up for a key that remains fully live at
      // the provider boundary.
      _emitEvent('ERROR', 'KEY_REVOCATION_CAPABILITY_UNSUPPORTED', {
        clientId, keyId, provider: provider.name, declaredCapabilities: capabilities, ..._enrich,
      });
      throw new Error(
        `revokeKeyAsync: provider "${provider.name}" declares no supported revocation method ` +
        `(getRevocationCapabilities() returned ${JSON.stringify(capabilities)}) — refusing to report ` +
        `this key as revoked while it remains fully usable at the provider boundary.`,
      );
    }

    // Flip local state to 'revoked' and persist BEFORE the provider round-trip:
    // from this instant, getActiveKey()/getSigningKey()/nativeSignLocked() can
    // never again select this keyId, independent of the provider outcome below.
    let nativeRevocation = { attempted: true, supported: true, provider: provider.name, method, success: null };
    const localRevokedAt = new Date().toISOString(); // the local transition time, kept below
    clientStore[keyId] = Object.freeze({
      ..._buildRevokedRecord(rec.publicKeyDer, rec.clientId, rec.version, rec.createdAt, localRevokedAt),
      nativeRevocation,
    });
    _zeroizePrivateKey(rec); // local state is already 'revoked' at this point
    saveKeys();
    _emitEvent('INFO', 'KEY_REVOCATION_STARTED', { clientId, keyId, version: rec.version, provider: provider.name, method, ..._enrich });

    try {
      const result = await provider.revokeKey(keyId, { method });
      nativeRevocation = {
        attempted: true, supported: true, provider: provider.name, method,
        success: true, revokedAt: result?.revokedAt || new Date().toISOString(),
        providerResponse: (result && result.providerResponse) || null,
      };
      // Re-fetch: a concurrent reload may have swapped `_store` during the
      // provider round-trip above — see _liveClientStore(). The 'revoked'
      // status itself was already durably committed synchronously before
      // this await (line above the try block), so this update only refines
      // the recorded native-provider outcome; re-fetching just prevents that
      // refinement from being silently lost.
      _refreshBeforeMutation({ strict: false }); //
      _liveClientStore(clientId)[keyId] = Object.freeze({
        ..._buildRevokedRecord(rec.publicKeyDer, rec.clientId, rec.version, rec.createdAt, localRevokedAt),
        nativeRevocation,
      });
      saveKeys();
      _emitEvent('INFO', 'KEY_REVOKED_NATIVE_SUCCESS', {
        clientId, keyId, version: rec.version, provider: provider.name, method,
        providerResponse: nativeRevocation.providerResponse, ..._enrich,
      });
      return { clientId, keyId, status: 'revoked', nativeRevocation };
    } catch (err) {
      nativeRevocation = {
        attempted: true, supported: true, provider: provider.name, method,
        success: false, error: err.message, failedAt: new Date().toISOString(),
      };
      _refreshBeforeMutation({ strict: false }); //
      _liveClientStore(clientId)[keyId] = Object.freeze({
        ..._buildRevokedRecord(rec.publicKeyDer, rec.clientId, rec.version, rec.createdAt, localRevokedAt),
        nativeRevocation,
      });
      saveKeys();
      _emitEvent('ERROR', 'KEY_REVOKED_NATIVE_FAILED', {
        clientId, keyId, version: rec.version, provider: provider.name, method, error: err.message, ..._enrich,
      });
      /** @type {any} */ const wrapped = new Error(
        `revokeKeyAsync: key "${keyId}" was revoked locally (QODIQA will never select it again) but ` +
        `native revocation at provider "${provider.name}" via method "${method}" FAILED: ${err.message}. ` +
        `The key may still be able to produce valid signatures at the ${provider.name} boundary — treat ` +
        `this as a security incident: revoke manually at the provider, then retry revokeKeyAsync().`,
      );
      wrapped.code             = 'NATIVE_REVOCATION_FAILED';
      wrapped.nativeRevocation = nativeRevocation;
      throw wrapped;
    }
  });
}

// Shared by revokeKeyAsync() and rotateKeyAsync()'s default 'emergency' mode
// performs the provider-side revocation round trip and returns the
// nativeRevocation outcome on success. Throws — never resolves as if
// revocation succeeded — if the provider declares no usable revocation
// method, or if the provider call itself fails. Callers must not flip local
// state to 'revoked' based on a caller-visible success unless this resolves;
// on throw, the caller must leave existing state untouched (fail-closed).
async function _revokeAtProvider(provider, keyId, clientId, version, _enrich) {
  const capabilities = _providerRevocationCapabilities(provider);
  const method        = pickStrongestRevocationMethod(capabilities);
  if (!method) {
    _emitEvent('ERROR', 'KEY_REVOCATION_CAPABILITY_UNSUPPORTED', {
      clientId, keyId, provider: provider.name, declaredCapabilities: capabilities, ...(_enrich || {}),
    });
    throw new Error(
      `revokeKeyAsync: provider "${provider.name}" declares no supported revocation method ` +
      `(getRevocationCapabilities() returned ${JSON.stringify(capabilities)}) — refusing to report ` +
      `this key as revoked while it remains fully usable at the provider boundary.`,
    );
  }

  _emitEvent('INFO', 'KEY_REVOCATION_STARTED', { clientId, keyId, version, provider: provider.name, method, ...(_enrich || {}) });

  try {
    const result = await provider.revokeKey(keyId, { method });
    const nativeRevocation = {
      attempted: true, supported: true, provider: provider.name, method,
      success: true, revokedAt: result?.revokedAt || new Date().toISOString(),
      providerResponse: (result && result.providerResponse) || null,
    };
    _emitEvent('INFO', 'KEY_REVOKED_NATIVE_SUCCESS', {
      clientId, keyId, version, provider: provider.name, method,
      providerResponse: nativeRevocation.providerResponse, ...(_enrich || {}),
    });
    return nativeRevocation;
  } catch (err) {
    const nativeRevocation = {
      attempted: true, supported: true, provider: provider.name, method,
      success: false, error: err.message, failedAt: new Date().toISOString(),
    };
    _emitEvent('ERROR', 'KEY_REVOKED_NATIVE_FAILED', {
      clientId, keyId, version, provider: provider.name, method, error: err.message, ...(_enrich || {}),
    });
    /** @type {any} */ const wrapped = new Error(
      `key "${keyId}" native revocation at provider "${provider.name}" via method "${method}" FAILED: ${err.message}.`,
    );
    wrapped.code             = 'NATIVE_REVOCATION_FAILED';
    wrapped.nativeRevocation = nativeRevocation;
    throw wrapped;
  }
}

function _providerRevocationCapabilities(provider) {
  try {
    const caps = provider.getRevocationCapabilities();
    return Array.isArray(caps) ? caps : [];
  } catch (err) {
    return [];
  }
}

/**
 * Sign through the active NativeSigningProvider, re-validating the key's
 * local status inside the same per-keyId mutex revokeKeyAsync() uses. This
 * closes the TOCTOU window between keyManager.getSigningKey() reading "this
 * key is active" and the provider round-trip actually happening: if a
 * revoke wins the race for this keyId, this call observes the fresh
 * 'revoked' status and refuses — no signing operation can succeed once
 * revocation has locally committed. If this call wins the race first, it
 * completes normally and the revoke proceeds immediately after.
 *
 * @param {string} keyId
 * @param {Buffer} messageHash
 * @returns {Promise<Buffer>}
 */
async function nativeSignLocked(keyId, messageHash) {
  _ensureBootstrapped();
  const kpf = _getKpf();
  if (!kpf || !kpf.isNativeSigning()) {
    throw new Error('KeyStore.nativeSignLocked: no native signing provider is active');
  }
  const provider = kpf.getNativeSigningProvider();

  return _withKeyLock(keyId, async () => {
    const rec = _lookupRecord(keyId);
    if (!rec || rec.status !== 'active') {
      _emitEvent('WARN', 'KEY_SIGNING_BLOCKED', { keyId, reason: rec ? rec.status : 'unknown' });
      throw new Error(`KeyStore: key "${keyId}" is not active (status: ${rec ? rec.status : 'unknown'}) — refusing native signing operation`);
    }
    if (isExpired(rec)) {
      _emitEvent('WARN', 'KEY_SIGNING_BLOCKED', { keyId, reason: 'expired' });
      throw new Error(`KEY_EXPIRED: signing key "${keyId}" has expired (expiresAt: ${rec.expiresAt}) — rotate before signing`);
    }
    return provider.sign(keyId, messageHash);
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

function getActiveKey(clientId) {
  if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) {
    throw new Error(
      `KeyStore: clientId is required — caller must supply an explicit tenant identifier. ` +
      `Got ${JSON.stringify(clientId)}. No default or fallback client is permitted.`,
    );
  }
  _ensureBootstrapped();
  const cid = clientId;

  if (!_store[cid]) {
    throw new Error(`KeyStore: no key material for client "${cid}" — provision keys via rotateKey() before signing`);
  }

  const clientStore = _store[cid];

  let found = null;
  for (const [id, rec] of Object.entries(clientStore)) {
    if (rec.status === 'active') {
      if (isExpired(rec)) {
        _emitEvent('WARN', 'KEY_SIGNING_BLOCKED', { clientId: cid, keyId: id, reason: 'expired' });
        throw new Error(`KEY_EXPIRED: signing key "${id}" for client "${cid}" has expired (expiresAt: ${rec.expiresAt}) — rotate before signing`);
      }
      found = { keyId: id, privDer: rec._privDer, pubDer: rec.publicKeyDer, clientId: cid };
    }
  }
  if (!found) throw new Error(`KeyStore: no active key for client "${cid}" — refusing to sign`);
  return found;
}

function getKey(clientId, keyId) {
  if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) {
    throw new Error(`KeyStore: invalid clientId "${clientId}"`);
  }
  if (typeof keyId !== 'string' || !NEW_KEY_ID_RE.test(keyId)) {
    throw new Error(`KeyStore: invalid keyId format "${keyId}"`);
  }
  _ensureBootstrapped();

  _validateClientOwnership(clientId, keyId);

  const clientStore = _store[clientId];
  if (!clientStore) throw new Error(`KeyStore: unknown client "${clientId}"`);

  const rec = clientStore[keyId];
  if (!rec)                                  throw new Error(`KeyStore: unknown keyId "${keyId}"`);
  if (!VERIFIABLE_STATUSES.has(rec.status))  throw new Error(`KeyStore: key "${keyId}" is revoked`);

  return { pubDer: rec.publicKeyDer, status: rec.status, clientId: rec.clientId, version: rec.version };
}

function getKeysByClient(clientId) {
  if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) {
    throw new Error(`KeyStore: invalid clientId "${clientId}"`);
  }
  _ensureBootstrapped();
  const clientStore = _store[clientId];
  if (!clientStore) return [];

  return Object.values(clientStore).map(rec => ({
    clientId:     rec.clientId,
    keyId:        rec.keyId,
    version:      rec.version,
    algorithm:    rec.algorithm,
    publicKeyB64: rec.publicKeyB64,
    status:       rec.status,
    createdAt:    rec.createdAt,
  }));
}

function getPublicKey(keyId) {
  _ensureBootstrapped();
  const resolved = _resolveKeyId(keyId);
  if (!resolved) throw new Error(`KeyStore: invalid keyId format "${keyId}"`);

  const rec = _lookupRecord(resolved);
  if (rec) {
    if (!VERIFIABLE_STATUSES.has(rec.status)) throw new Error(`KeyStore: key "${keyId}" is revoked and cannot be used for verification`);

    // CRYPTO-6: rec.clientId is the AUTHORITATIVE clientId — for a legacy
    // (colon-less) keyId, _resolveKeyId() already mapped it through
    // _legacyMap to the real clientId:key_vN record above, so this is correct
    // even when the caller's raw `keyId` had no colon to parse. Callers should
    // use this instead of re-deriving clientId by re-parsing the raw keyId
    // string themselves (see validateBoundRequest.js, which previously did
    // exactly that and silently fell back to an un-tenant-scoped nonce
    // namespace for legacy keys as a result).
    return { pubDer: rec.publicKeyDer, status: rec.status, clientId: rec.clientId, source: 'live', timeline: _timelineOf(rec) };
  }

  // the live store has no record at all for this keyId — it may
  // have been a 'deprecated' key that purgeExpiredDeprecated() already
  // archived and removed from the live store. This is the ONLY case that
  // consults the archive: a live record that exists but is 'revoked' throws
  // above and never reaches here, so revocation always wins and the archive
  // can never resurrect a revoked key's verifiability (it wouldn't be there
  // to find anyway — see the "Archived key lookup" section above). The live
  // lookup is always attempted first and this fallback only runs on a full
  // miss, so live-key resolution latency is completely unaffected.
  const archived = _lookupArchivedKey(resolved);
  if (archived) {
    // an archived key is 'archived' on its timeline — it never
    // verifies a new artifact (keyLifecycle.checkExecution); only historical
    // verification of something it signed while active can use it.
    return { pubDer: archived.pubDer, status: 'deprecated', clientId: archived.clientId, source: 'archived',
      timeline: { status: 'archived', activatedAt: archived.createdAt || null, deprecatedAt: archived.retiredAt || null, archivedAt: archived.purgedAt || null, revokedAt: null } };
  }

  throw new Error(`KeyStore: unknown keyId "${keyId}"`);
}

function getKeyStatus(keyId) {
  _ensureBootstrapped();
  const resolved = _resolveKeyId(keyId);
  if (!resolved) return null;
  const rec = _lookupRecord(resolved);
  return rec ? rec.status : null;
}

function listKeys() {
  _ensureBootstrapped();
  const result = [];
  for (const clientStore of Object.values(_store)) {
    for (const rec of Object.values(clientStore)) {
      result.push({
        clientId:     rec.clientId,
        keyId:        rec.keyId,
        version:      rec.version,
        algorithm:    rec.algorithm,
        publicKeyB64: rec.publicKeyB64,
        status:       rec.status,
        createdAt:    rec.createdAt,
        retiredAt:    rec.retiredAt || null,
        expiresAt:    rec.expiresAt || null,
      });
    }
  }
  return result;
}

// every live key with its local status timeline (no key material).
function listKeyTimelines() {
  _ensureBootstrapped();
  const result = [];
  for (const clientStore of Object.values(_store)) {
    for (const rec of Object.values(clientStore)) {
      result.push({ keyId: rec.keyId, clientId: rec.clientId, version: rec.version, timeline: _timelineOf(rec) });
    }
  }
  return result;
}

// Full lifecycle audit of the in-memory store.
// Returns:
//   totalActive   — count of active keys across all clients
//   clients       — { [clientId]: { total, active } }
//   expiredKeys   — active keys where expiresAt < now  (fail-closed at startup)
//   expiringKeys  — active keys within EXPIRY_WARNING_DAYS of expiry (warn)
//   overdueKeys   — active keys past rotationDeadline but not expired (warn)
//   violations    — structural invariant failures (fail-closed at startup)
//
// violations types:
//   MULTIPLE_ACTIVE_KEYS  — more than one active key for a client
//   DUPLICATE_VERSION     — two keys share the same version number for a client
//   OWNERSHIP_VIOLATION   — keyId prefix does not match the client bucket it is stored under
//   INVALID_LIFECYCLE     — active key has null or unparseable lifecycle timestamps
function validateKeyStore() {
  _ensureBootstrapped();
  const clients     = {};
  let   totalActive = 0;
  const expiredKeys  = [];
  const expiringKeys = [];
  const overdueKeys  = [];
  const violations   = [];

  // K1: defence in depth -- after bootstrap sealed the store, the file on disk must still be sealed and
  // authentic. validateStartup() treats every violation as FATAL.
  for (const v of _scanFileSeal()) violations.push(v);

  for (const [clientId, clientStore] of Object.entries(_store)) {
    const recs = Object.values(clientStore);

    // Structural: ownership — keyId prefix must match the client bucket.
    for (const rec of recs) {
      const colonIdx = rec.keyId ? rec.keyId.indexOf(':') : -1;
      const embedded = colonIdx !== -1 ? rec.keyId.slice(0, colonIdx) : '';
      if (embedded !== clientId) {
        violations.push({
          type:     'OWNERSHIP_VIOLATION',
          clientId,
          keyId:    rec.keyId,
          detail:   `keyId prefix "${embedded}" does not match client bucket "${clientId}"`,
        });
      }
    }

    // Structural: duplicate versions within a client.
    const seenVersions = new Set();
    for (const rec of recs) {
      if (seenVersions.has(rec.version)) {
        violations.push({
          type:     'DUPLICATE_VERSION',
          clientId,
          keyId:    rec.keyId,
          detail:   `version ${rec.version} appears more than once for client "${clientId}"`,
        });
      }
      seenVersions.add(rec.version);
    }

    const activeRecs = recs.filter(r => r.status === 'active');
    clients[clientId] = { total: recs.length, active: activeRecs.length };
    totalActive += activeRecs.length;

    // Structural: at most one active key per client.
    if (activeRecs.length > 1) {
      violations.push({
        type:     'MULTIPLE_ACTIVE_KEYS',
        clientId,
        detail:   `${activeRecs.length} active keys found — expected exactly 1`,
      });
    }

    // Lifecycle checks — only on active keys.
    for (const rec of activeRecs) {
      // Defensive: lifecycle must be present migration.
      if (!rec.rotationDeadline || !rec.expiresAt ||
          isNaN(new Date(rec.rotationDeadline).getTime()) ||
          isNaN(new Date(rec.expiresAt).getTime())) {
        violations.push({
          type:     'INVALID_LIFECYCLE',
          clientId,
          keyId:    rec.keyId,
          detail:   'rotationDeadline or expiresAt is missing or unparseable on active key',
        });
        continue; // skip lifecycle checks — timestamps unreliable
      }

      if (isExpired(rec)) {
        expiredKeys.push({ clientId, keyId: rec.keyId, createdAt: rec.createdAt, expiresAt: rec.expiresAt });
      } else {
        const days = daysUntilExpiry(rec);
        if (days <= EXPIRY_WARNING_DAYS) {
          expiringKeys.push({ clientId, keyId: rec.keyId, daysRemaining: Math.ceil(days) });
        }
        if (isRotationDue(rec)) {
          overdueKeys.push({ clientId, keyId: rec.keyId, daysOverdue: Math.ceil(-daysUntilRotation(rec)) });
        }
      }
    }
  }

  _emitEvent('INFO', 'KEY_VALIDATED', { totalActive });
  return { totalActive, clients, expiredKeys, expiringKeys, overdueKeys, violations };
}

// ── Key archive ───────────────────────────────────────────────────────────────
//
// Append-only archive of retired key metadata.  Private key material is never
// present in deprecated records (stripped at rotation time) and therefore never
// written to the archive.  The archive file grows monotonically; entries are
// never modified or deleted.
//
// Archive file format (key-archive.json):
//   { "version": 1, "entries": [ { ...metadata } ] }

function _loadArchive() {
  if (!fs.existsSync(ARCHIVE_PATH)) {
    return { version: 1, entries: [] };
  }
  try {
    const raw = fs.readFileSync(ARCHIVE_PATH, 'utf8');
    // a zero-byte or whitespace-only archive file (e.g. touched but
    // never written) is treated the same as "file does not exist" rather
    // than a JSON parse failure — graceful, not fail-closed, since an empty
    // archive carries no verification-affecting information either way.
    if (raw.trim() === '') {
      return { version: 1, entries: [] };
    }
    const data = JSON.parse(raw);
    if (!data || data.version !== 1 || !Array.isArray(data.entries)) {
      throw new Error('unexpected archive format');
    }
    return data;
  } catch (err) {
    throw new Error(`KeyStore: cannot read key archive at ${ARCHIVE_PATH} — ${err.message}`);
  }
}

// ── Archived key lookup ─────────────────────────────────────────────
//
// Background: purgeExpiredDeprecated() archives and removes purge-eligible
// DEPRECATED keys (never REVOKED ones — see the purge loop below), but until
// this remediation nothing ever read data/key-archive.json back. The result
// was an undocumented verification ceiling: an artifact signed by a key that
// was later purged became permanently unverifiable the moment the purge ran,
// roughly 180-360 days after signing depending on retiredAt availability.
//
// getPublicKey() below closes that gap by falling back to the archive ONLY
// when the live in-memory lookup finds no record at all for a keyId — never
// when a live record exists and is 'revoked' (revocation must always win,
// and in any case a revoked key is never present in the archive: the purge
// loop only ever archives 'deprecated' keys). This keeps the live path's
// cost and behavior completely unchanged; the archive is consulted strictly
// on the slow/miss path.
//
// The archive index is a plain in-memory Map<keyId, entry> rebuilt from disk
// at most once per ARCHIVE_CACHE_TTL_MS (default 5 minutes, overridable via
// QODIQA_KEY_ARCHIVE_CACHE_TTL_MS) — the same "read once, trust for a bit"
// tradeoff already used elsewhere in this file (see the reload cadence in
// "Cross-instance reload" below), avoiding a disk read + full JSON
// parse of a monotonically-growing archive file on every miss. Purging new
// entries invalidates the cache immediately (see purgeExpiredDeprecated())
// so a just-purged key is verifiable right away rather than waiting out the
// TTL.

function _archiveCacheTtlMs() {
  const v = parseInt(process.env.QODIQA_KEY_ARCHIVE_CACHE_TTL_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 5 * 60 * 1000;
}

// Defensive parsing: the archive is server-written and
// append-only, but this validates every entry anyway before it can ever
// influence a verification outcome — a hand-edited or corrupted file must
// degrade to "entry skipped", never to a crash or to fabricated key material.
function _isValidArchiveEntry(entry) {
  return !!entry && typeof entry === 'object'
    && typeof entry.keyId === 'string' && NEW_KEY_ID_RE.test(entry.keyId)
    && typeof entry.clientId === 'string' && CLIENT_ID_RE.test(entry.clientId)
    // Ownership consistency — mirrors _validateClientOwnership()'s invariant
    // for the live store: a keyId's <clientId>: prefix must match its own
    // clientId field, or the entry is corrupt/suspicious and must not be
    // trusted to resolve under either identity.
    && entry.keyId.slice(0, entry.keyId.indexOf(':')) === entry.clientId
    && typeof entry.algorithm === 'string' && entry.algorithm.length > 0
    && typeof entry.publicKeyB64 === 'string' && entry.publicKeyB64.length > 0
    && _decodesToNonEmptyBuffer(entry.publicKeyB64);
}

function _decodesToNonEmptyBuffer(b64) {
  try {
    return Buffer.from(b64, 'base64').length > 0;
  } catch {
    return false;
  }
}

function _buildArchiveIndex() {
  const archive = _loadArchive();
  const index   = new Map();
  for (const entry of archive.entries) {
    if (!_isValidArchiveEntry(entry)) {
      _emitEvent('WARN', 'KEY_ARCHIVE_ENTRY_INVALID', {
        keyId:   entry && typeof entry === 'object' ? entry.keyId : undefined,
        message: 'Skipped malformed key-archive entry while building the archive lookup index.',
      });
      continue;
    }
    // Last-write-wins: the archive is append-only and each key is purged at
    // most once in normal operation, so a duplicate keyId should never occur
    // — but a hand-edited file could produce one, and silently preferring
    // the most recently appended entry is safer than an arbitrary pick.
    index.set(entry.keyId, entry);
  }
  return index;
}

let _archiveIndex         = null; // Map<keyId, entry> | null — null until first built
let _archiveIndexLoadedAt = 0;

function _getArchiveIndex() {
  const now = Date.now();
  if (_archiveIndex && (now - _archiveIndexLoadedAt) < _archiveCacheTtlMs()) {
    return _archiveIndex;
  }
  _archiveIndex         = _buildArchiveIndex();
  _archiveIndexLoadedAt = now;
  return _archiveIndex;
}

// Fail-safe, never throws: any archive read/parse problem is reported and
// treated as "no archived key found" rather than propagating out of
// getPublicKey() — an archive-tier problem must never break ordinary live-key
// verification for callers who never needed the archive in the first place.
function _lookupArchivedKey(resolvedKeyId) {
  let index;
  try {
    index = _getArchiveIndex();
  } catch (err) {
    _emitEvent('ERROR', 'KEY_ARCHIVE_LOOKUP_FAILED', {
      keyId:   resolvedKeyId,
      message: `Key archive lookup failed — treating as not found: ${err.message}`,
    });
    return null;
  }

  const entry = index.get(resolvedKeyId);
  if (!entry) return null;

  let pubDer;
  try {
    pubDer = Buffer.from(entry.publicKeyB64, 'base64');
    if (pubDer.length === 0) throw new Error('decoded to zero bytes');
  } catch (err) {
    _emitEvent('WARN', 'KEY_ARCHIVE_ENTRY_INVALID', {
      keyId:   resolvedKeyId,
      message: `Archived entry has unusable public key material — treating as not found: ${err.message}`,
    });
    return null;
  }

  return { keyId: entry.keyId, clientId: entry.clientId, pubDer, createdAt: entry.createdAt || null, retiredAt: entry.retiredAt || null, purgedAt: entry.purgedAt || null };
}

/**
 * List all archived (purged) keys — the data backing GET
 * /.well-known/qodiqa/keys/archived. Deliberately independent of
 * _ensureBootstrapped()/the live keys.json store: the archive is a separate
 * file with no KEK dependency, so listing it must keep working even if the
 * live store has never been bootstrapped.
 *
 * Never throws for a missing or empty archive (returns []); throws only if
 * the archive file exists but is structurally corrupt (invalid top-level
 * JSON/version/entries shape) — the same fail-closed posture _loadArchive()
 * already applies elsewhere.
 *
 * @returns {{ keyId: string, clientId: string, algorithm: string, publicKeyB64: string, purgedAt: string|null }[]}
 */
function listArchivedKeys() {
  const index = _getArchiveIndex();
  return Array.from(index.values()).map(entry => ({
    keyId:        entry.keyId,
    clientId:     entry.clientId,
    algorithm:    entry.algorithm,
    publicKeyB64: entry.publicKeyB64,
    purgedAt:     entry.purgedAt || null,
  }));
}

function _appendToArchive(newEntries) {
  if (!newEntries || newEntries.length === 0) return;
  const archive    = _loadArchive();
  archive.entries  = archive.entries.concat(newEntries);
  ///-15: 0600, fsync, unique temp name, rename.
  writeFileAtomicSecure(ARCHIVE_PATH, JSON.stringify(archive, null, 2));
}

// ── Key inventory ─────────────────────────────────────────────────────────────

/**
 * Returns a complete classified inventory of all keys in the live store.
 *
 * Classification:
 *   ACTIVE           — the signing key; may have private material in memory
 *   DEPRECATED       — retained for artifact verification; no private material
 *   PURGE_ELIGIBLE   — deprecated key past the artifact-retention window; safe to archive
 *   REVOKED          — permanently blocked from signing and verification
 *
 * The artifact-retention window is 2 × EXPIRY_DAYS when retiredAt is unknown
 * (conservative: assumes the key was deprecated at its maximum possible age).
 * When retiredAt is known, the window is EXPIRY_DAYS from that timestamp.
 *
 * No private key material is included in the output.
 */
function getInventory() {
  _ensureBootstrapped();
  const now     = Date.now();
  const entries = [];

  for (const [clientId, clientStore] of Object.entries(_store)) {
    for (const rec of Object.values(clientStore)) {
      const ageMs   = now - new Date(rec.createdAt).getTime();
      const ageDays = Math.floor(ageMs / 86_400_000);

      let classification;
      let purgeEligible = false;
      if (rec.status === 'active') {
        classification = 'ACTIVE';
      } else if (rec.status === 'deprecated') {
        // Use retiredAt if available for precise threshold; fall back to the
        // conservative 2×EXPIRY_DAYS from createdAt when retiredAt is absent.
        if (rec.retiredAt) {
          const retiredMs  = now - new Date(rec.retiredAt).getTime();
          purgeEligible    = retiredMs > EXPIRY_DAYS * 86_400_000;
        } else {
          purgeEligible    = ageMs > 2 * EXPIRY_DAYS * 86_400_000;
        }
        classification = purgeEligible ? 'PURGE_ELIGIBLE' : 'DEPRECATED';
      } else {
        classification = 'REVOKED';
      }

      entries.push({
        keyId:            rec.keyId,
        clientId:         rec.clientId,
        purpose:          'ed25519-artifact-signing',
        owner:            rec.clientId,
        version:          rec.version,
        algorithm:        rec.algorithm,
        status:           rec.status,
        classification,
        createdAt:        rec.createdAt,
        retiredAt:        rec.retiredAt        || null,
        rotationDeadline: rec.rotationDeadline || null,
        expiresAt:        rec.expiresAt        || null,
        // Only meaningful for REVOKED entries — see revokeKeyAsync(). Surfaces
        // whether a native signing provider (Vault Transit / HSM) confirmed
        // the key can no longer sign, so operators never assume a complete
        // revocation guarantee the provider hasn't actually confirmed.
        nativeRevocation: rec.nativeRevocation ?? null,
        revokedAt:        rec.status === 'revoked' ? (rec.revokedAt || null) : null, //
        ageDays,
        purgeEligible,
      });
    }
  }

  entries.sort((a, b) => {
    const order = { ACTIVE: 0, DEPRECATED: 1, PURGE_ELIGIBLE: 2, REVOKED: 3 };
    const diff  = (order[a.classification] ?? 9) - (order[b.classification] ?? 9);
    if (diff !== 0) return diff;
    return /** @type {any} */ (new Date(b.createdAt)) - /** @type {any} */ (new Date(a.createdAt));
  });

  const activeCount       = entries.filter(e => e.classification === 'ACTIVE').length;
  const deprecatedCount   = entries.filter(e => e.classification === 'DEPRECATED').length;
  const purgeEligible     = entries.filter(e => e.classification === 'PURGE_ELIGIBLE').length;
  const revokedCount      = entries.filter(e => e.classification === 'REVOKED').length;
  const clientsNoActive   = [...new Set(
    entries
      .filter(e => e.classification !== 'ACTIVE')
      .map(e => e.clientId)
      .filter(cid => !entries.some(e => e.clientId === cid && e.classification === 'ACTIVE')),
  )];

  return {
    generatedAt:        new Date().toISOString(),
    retentionPolicyDays: EXPIRY_DAYS,
    totalKeys:          entries.length,
    activeKeys:         activeCount,
    deprecatedKeys:     deprecatedCount,
    purgeEligibleKeys:  purgeEligible,
    revokedKeys:        revokedCount,
    clientsWithoutActiveKey: clientsNoActive,
    entries,
  };
}

// ── Deprecated key purge ──────────────────────────────────────────────────────

/**
 * Archives and removes deprecated keys that have exceeded the artifact-retention
 * window.  A key is eligible when all artifacts signed with it have expired:
 *
 *   • If retiredAt is known: eligible when (now − retiredAt) > EXPIRY_DAYS.
 *   • If retiredAt is absent (keys deprecated before this was tracked):
 *     eligible when (now − createdAt) > 2 × EXPIRY_DAYS.  This is conservative:
 *     it accounts for the maximum possible gap between key creation and deprecation.
 *
 * Active and revoked keys are never purged.
 * Archived entries are appended to key-archive.json before removal from the store.
 * If archive persistence fails the purge is aborted (fail-closed).
 *
 * @param {string} [clientId] - restrict to a single client; omit to purge all clients
 * @returns {{ purged: number, archived: object[] }}
 */
function purgeExpiredDeprecated(clientId) {
  if (clientId !== undefined &&
      (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId))) {
    throw new TypeError(`purgeExpiredDeprecated: invalid clientId "${clientId}"`);
  }
  _ensureBootstrapped();
  _refreshBeforeMutation(); //

  const targets  = clientId ? [clientId] : Object.keys(_store);
  const toArchive = [];
  const now       = Date.now();

  for (const cid of targets) {
    const clientStore = _store[cid];
    if (!clientStore) continue;

    for (const [keyId, rec] of Object.entries(clientStore)) {
      if (rec.status !== 'deprecated') continue;

      let eligible = false;
      if (rec.retiredAt) {
        eligible = (now - new Date(rec.retiredAt).getTime()) > EXPIRY_DAYS * 86_400_000;
      } else {
        eligible = (now - new Date(rec.createdAt).getTime()) > 2 * EXPIRY_DAYS * 86_400_000;
      }

      if (!eligible) continue;

      toArchive.push({
        keyId:             rec.keyId,
        clientId:          rec.clientId,
        purpose:           'ed25519-artifact-signing',
        owner:             rec.clientId,
        version:           rec.version,
        algorithm:         rec.algorithm,
        publicKeyB64:      rec.publicKeyB64,
        createdAt:         rec.createdAt,
        retiredAt:         rec.retiredAt || null,
        purgedAt:          new Date().toISOString(),
        retirementReason:  'RETENTION_PERIOD_EXPIRED',
        retentionDays:     EXPIRY_DAYS,
        replacedBy:        `${rec.clientId}:key_v${rec.version + 1}`,
        auditNotes:        rec.retiredAt
          ? `Purged after ${EXPIRY_DAYS}-day post-retirement retention window.`
          : `Purged after ${2 * EXPIRY_DAYS}-day conservative window (retiredAt unavailable).`,
      });
    }
  }

  if (toArchive.length === 0) {
    return { purged: 0, archived: [] };
  }

  // Persist archive entries BEFORE modifying the live store — fail-closed.
  _appendToArchive(toArchive);

  // invalidate the cached archive lookup index so these newly
  // purged keys are immediately resolvable via getPublicKey()'s archive
  // fallback / listArchivedKeys(), rather than waiting out
  // ARCHIVE_CACHE_TTL_MS. Cheap — the next lookup simply rebuilds it.
  _archiveIndex = null;

  // Remove from live store.
  for (const entry of toArchive) {
    delete _store[entry.clientId][entry.keyId];
  }

  saveKeys();

  _emitEvent('INFO', 'KEYS_PURGED', {
    purged:  toArchive.length,
    keyIds:  toArchive.map(e => e.keyId),
    message: `${toArchive.length} expired deprecated key(s) archived and removed from live store.`,
  });

  return { purged: toArchive.length, archived: toArchive };
}

// ── Cross-instance reload ───────────────────────────────────────────────
//
// When multiple QODIQA instances share the same keys.json (a single PVC or
// EFS mount — see docs/deployment/topology.md "Key store sharing"), any out-of-band
// change to the file — a rotation performed by another instance, an operator
// revoking a key via a different instance's admin API, or a directly edited
// trust store — is invisible to this instance until this is called: each
// instance normally only reads the file once, at process startup.
//
// This is called periodically by the reload half of the scheduler in
// services/artifact/rotationScheduler.js, on EVERY running instance, on a fixed
// cadence (QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS, default 5 minutes) that is
// completely independent of whether that instance's automatic rotation is
// enabled. That independence is what gives revocation and key-replacement
// propagation a deterministic, bounded upper time bound fleet-wide: no
// instance can be left trusting a revoked key indefinitely just because it
// has automatic rotation turned off.
//
// Fail-closed: if the file cannot be read, parsed, or decrypted, the LIVE
// in-memory store is left completely untouched and the failure is reported —
// an instance never loses its ability to sign or verify because of a
// transient reload error (e.g. another instance mid-write).
//
// Concurrency: this function is fully synchronous (readFileSync, JSON.parse,
// synchronous decrypt) and swaps `_store` with a single assignment. Node.js
// runs synchronous code to completion without preemption, so no concurrently
// executing request handler can ever observe a partially-replaced trust
// store — every verification either reads the fully-old or fully-new store.
//
// Returns { reloaded: false, error } when nothing changed on disk or the read
// failed, or { reloaded: true, clients, active, revoked, activeKeyChanges }
// after a successful swap.
function reloadFromDisk() {
  let fromFile;
  try {
    fromFile = _tryLoadFromFile({ allowTofu: !_sealedSeen }); // K1: no downgrade to an unsealed file at reload
  } catch (err) {
    _emitEvent('ERROR', 'KEYSTORE_RELOAD_FAILED', {
      message: `Reload aborted — existing in-memory key store retained: ${err.message}`,
      error:   err.message,
    });
    return { reloaded: false, error: err.message };
  }

  if (!fromFile) {
    // No file on disk (nothing to reload from) — not an error, just a no-op.
    return { reloaded: false, error: null };
  }

  // Snapshot the outgoing store so the swap below can be diffed for
  // observability: a plain reload event only reports totals, which
  // is not enough for an operator to see *what* changed — specifically,
  // whether a revocation or a key replacement propagated to this instance.
  const _previousStore = _store;

  // (P2): revocation is monotonic. A key this instance
  // knows to be revoked is NEVER un-revoked by a reload — a stale writer
  // re-persisting its old view (or a restored/edited file) must not resurrect
  // it as active/deprecated, nor drop its revoked record. The on-disk record is
  // replaced by the revoked one (any private material it carried is zeroed),
  // a CRITICAL event is emitted and the corrected store is written back below.
  const _regressed = [];
  for (const [cid, cs] of Object.entries(_previousStore)) {
    for (const [kid, prev] of Object.entries(cs)) {
      if (!prev || prev.status !== 'revoked') continue;
      const next = fromFile.store[cid] && fromFile.store[cid][kid];
      if (next && next.status === 'revoked') continue;
      if (next) _zeroizePrivateKey(next);
      if (!fromFile.store[cid]) fromFile.store[cid] = {};
      fromFile.store[cid][kid] = Object.freeze({
        ..._buildRevokedRecord(prev.publicKeyDer, prev.clientId, prev.version, prev.createdAt, prev.revokedAt ?? null),
        nativeRevocation: prev.nativeRevocation ?? null,
      });
      _regressed.push({ clientId: cid, keyId: kid, onDiskStatus: next ? next.status : 'missing' });
    }
  }

  _store     = fromFile.store;
  _legacyMap = fromFile.legacyMap;
    _rotationFences = fromFile.rotationFences || {}; //
  _lastFileHash = fromFile.fileHash;
  if (fromFile.sealed) _sealedSeen = true; // K1

  if (_regressed.length > 0) {
    _emitEvent('CRITICAL', 'KEY_REVOCATION_REGRESSION_DETECTED', {
      keys:    _regressed,
      message: `keys.json on disk no longer showed ${_regressed.length} key(s) this instance knows to be ` +
               'revoked (stale writer or edited/restored file). They stay revoked; the store is re-persisted.',
    });
    try {
      saveKeys();
    } catch (err) {
      _emitEvent('ERROR', 'KEY_REVOCATION_REGRESSION_REPAIR_FAILED', { error: err.message });
    }
  }

  // A successful reload is itself a complete load of the store — mark the
  // lazy bootstrap as satisfied so a later implicit _ensureBootstrapped()
  // call (from getActiveKey, rotateKey, etc.) does not redundantly reload
  // (and, unlike this function, attempt migration) over this fresh state.
  _bootstrapped = true;

  // ── Diff against the previous snapshot — surfaces exactly what propagated ──
  const _newlyRevoked  = [];
  const _activeChanged = [];
  for (const [clientId, clientStore] of Object.entries(_store)) {
    const prevClientStore = _previousStore[clientId] || {};

    for (const [keyId, rec] of Object.entries(clientStore)) {
      const prevRec = prevClientStore[keyId];
      if (rec.status === 'revoked' && prevRec && prevRec.status !== 'revoked') {
        _newlyRevoked.push({ clientId, keyId, version: rec.version });
      }
    }

    const prevActive = Object.values(prevClientStore).find(r => r.status === 'active') || null;
    const newActive   = Object.values(clientStore).find(r => r.status === 'active') || null;
    if (newActive && (!prevActive || prevActive.keyId !== newActive.keyId)) {
      _activeChanged.push({
        clientId,
        keyId:         newActive.keyId,
        previousKeyId: prevActive ? prevActive.keyId : null,
        fingerprint:   newActive.fingerprint,
      });
    }
  }

  for (const r of _newlyRevoked) {
    _emitEvent('WARN', 'KEY_REVOCATION_PROPAGATED', {
      ...r,
      message: `Revocation of "${r.keyId}" propagated to this instance via reload — ` +
               `it is no longer trusted for signing or verification.`,
    });
  }
  for (const r of _activeChanged) {
    _emitEvent('INFO', 'KEY_ACTIVE_KEY_CHANGED', {
      ...r,
      message: `Active signing key for client "${r.clientId}" is now "${r.keyId}" ` +
               `(previously "${r.previousKeyId ?? 'none'}") — propagated via reload.`,
    });
  }

  const clients = Object.keys(_store);
  const active  = Object.values(_store)
    .flatMap(cs => Object.values(cs))
    .filter(r => r.status === 'active')
    .map(r => ({ keyId: r.keyId, clientId: r.clientId, fingerprint: r.fingerprint }));

  _emitEvent('INFO', 'KEYSTORE_RELOADED', {
    clients: clients.length,
    active:  active.length,
    keys:    active,
    revoked: _newlyRevoked.length,
    activeKeyChanges: _activeChanged.length,
  });

  return {
    reloaded: true,
    clients:  clients.length,
    active:   active.length,
    revoked:  _newlyRevoked.length,
    activeKeyChanges: _activeChanged.length,
  };
}

module.exports = {
  getActiveKey,
  getKey,
  getKeysByClient,
  getPublicKey,
  getKeyStatus,
  listKeys,
  listKeyTimelines,
  validateKeyStore,
  rotateKey,
  rotateKeyAsync,
  rotateKeyGracefully,
  rotateKeyGracefullyAsync,
  revokeKey,
  revokeKeyAsync,
  nativeSignLocked,
  saveKeys,
  getInventory,
  purgeExpiredDeprecated,
  listArchivedKeys,
  reloadFromDisk,
  onKeysSaved,
  _scanFileForPlaintext,
  // Lifecycle helpers — canonical evaluation layer for all rotation/expiry decisions.
  isExpired,
  isRotationDue,
  daysUntilExpiry,
  daysUntilRotation,
  ROTATION_DAYS,
  EXPIRY_DAYS,
  EXPIRY_WARNING_DAYS,
  ARCHIVE_PATH,
};
