'use strict';

// KeyManager — single authorized entry point for all cryptographic key operations.
//
// Access control:
//   getSigningKey()      — returns private + public key material.
//                          Only the /sign route is authorized to call this.
//   getVerificationKey() — returns public key material only.
//   getActivePublicKey() — returns public key material only (no privDer).
//   listPublicKeys()     — returns public key metadata only.
//
// No component should call getActiveKey() directly from keyStore for
// production signing.  All production key access flows through this module.

const {
  getActiveKey,
  getPublicKey,
  getKey,
  getKeysByClient,
  listKeys,
  validateKeyStore,
  rotateKey,
  rotateKeyAsync,
  rotateKeyGracefully,
  rotateKeyGracefullyAsync,
  revokeKeyAsync,
  nativeSignLocked,
  reloadFromDisk,
  _scanFileForPlaintext,
} = require('./keyStore');
const { getKeyEncryptionKey, getProviderName } = require('../secrets/secretsProvider');
const { emit } = require('../logger');

// keyProviderFactory is Infrastructure (src/infra/keys/) and keyManager.js is
// Services (services/artifact/) — Services -> Infrastructure is an allowed
// dependency direction, and keyProviderFactory's own dependency tree never
// requires keyManager.js or keyStore.js back, so this is a plain static
// import, not a cycle workaround (verified via madge --circular over the
// whole src/ + services/ tree).
const _kpf = require('../../src/infra/keys/keyProviderFactory');
function _getKpf() {
  return _kpf;
}

// ── Signing key access ────────────────────────────────────────────────────────
// Returns full key material including privDer for local signing, OR a sentinel
// { keyId, pubDer, clientId, nativeSigning: true } when a NativeSigningProvider
// is active (Vault Transit / HSM) — the /sign route must check nativeSigning and
// call keyManager.nativeSign() instead of doing the Ed25519 operation locally.

const keyStatusTimeline = require('../../src/core/signing/keyStatusTimeline');

// the active key as the WHOLE cluster sees it. keys.json is
// re-read by other replicas only every 5 min; the control-plane status
// timeline reaches them within 5 s. If the timeline says this replica's
// "active" key was rotated out or revoked elsewhere, reload the keystore once
// and re-check — never sign with a key the cluster has retired (every artifact
// it produced would be refused anyway).
function _activeKeyForCluster(clientId) {
  const timelines = keyStatusTimeline;
  const isLive = (key) => {
    const t = timelines.effective(key.keyId, { status: 'active' });
    return !t || t.status === 'active';
  };
  let key = getActiveKey(clientId);
  if (isLive(key)) return key;
  reloadFromDisk();
  key = getActiveKey(clientId);
  if (isLive(key)) return key;
  throw new Error(`KeyManager: the active key "${key.keyId}" for client "${clientId}" has been retired cluster-wide — refusing to sign`);
}

function getSigningKey(clientId) {
  const kpf = _getKpf();
  if (kpf && kpf.isNativeSigning()) {
    // Native provider: no private key material is held locally.
    // Return the active public key so the caller can build the signed envelope.
    const key = _activeKeyForCluster(clientId);
    return {
      keyId:         key.keyId,
      privDer:       null,
      pubDer:        key.pubDer,
      clientId:      key.clientId,
      nativeSigning: true,
    };
  }
  const key = _activeKeyForCluster(clientId);
  if (!key || !key.privDer) {
    throw new Error(`KeyManager: no active signing key for client "${clientId}"`);
  }
  return {
    keyId:    key.keyId,
    privDer:  key.privDer,
    pubDer:   key.pubDer,
    clientId: key.clientId,
  };
}

/**
 * Delegate signing to the active NativeSigningProvider (Vault Transit / HSM).
 * Only call this when getSigningKey() returns { nativeSigning: true }.
 * @param {string} keyId       Full QODIQA key ID, e.g. "default:key_v3"
 * @param {Buffer} messageHash 32-byte SHA-256 digest of the signing envelope
 * @returns {Promise<Buffer>}  64-byte Ed25519 signature
 */
async function nativeSign(keyId, messageHash) {
  // Delegates to keyStore's lock-guarded native sign, which re-validates the
  // key's local status (active vs. revoked/expired) inside the same per-keyId
  // mutex used by revoke() — see keyStore.nativeSignLocked() for why this
  // matters: it is what makes "revoked keys never produce valid signatures"
  // hold even under concurrent revoke/sign requests.
  return nativeSignLocked(keyId, messageHash);
}

// ── Public key access — no private material ever returned ─────────────────────

function getVerificationKey(keyId) {
  return getPublicKey(keyId); // { pubDer, status }
}

// Returns only public material for the active key of a client.
// Use this instead of getSigningKey() in any context that does not need to sign.
function getActivePublicKey(clientId) {
  const key = getActiveKey(clientId);
  return {
    keyId:        key.keyId,
    pubDer:       key.pubDer,
    publicKeyB64: key.pubDer.toString('base64'),
    clientId:     key.clientId,
  };
}

function getKeyInfo(clientId, keyId) {
  return getKey(clientId, keyId); // { pubDer, status, clientId, version }
}

function getKeysByClientId(clientId) {
  return getKeysByClient(clientId);
}

function listPublicKeys() {
  return listKeys(); // array of { clientId, keyId, version, algorithm, publicKeyB64, status, createdAt }
}

// ── Key lifecycle ─────────────────────────────────────────────────────────────

// rotates a client's key with caller-specified `opts.mode` ('emergency'
// or 'graceful') — thin passthrough to keyStore.js's rotateKey(), which itself
// requires opts.mode explicitly and has no default (see its own
// _resolveRotationMode()). this function previously claimed to default
// to 'emergency' mode when opts is omitted — it does not; omitting opts.mode
// throws. `/key-admin/:clientId/rotate` (src/api/routes/keyAdmin.js) always
// passes `{ mode: 'emergency' }` explicitly, which is why that HTTP path
// behaves as "emergency by default" from an operator's perspective — this
// function itself has no default. "rotate the key" being the operator's most
// intuitive incident-response action is still the reason the HTTP endpoint
// hardcodes emergency mode; a direct caller of this function must do the same.
// See keyStore.js's "Rotation" section header.
function rotate(clientId, opts) {
  return rotateKey(clientId, opts);
}

// Native-signing-aware rotation. Used by the automatic rotation scheduler and
// by any manual caller that needs correct behavior under Vault Transit / HSM.
// Defaults to 'emergency' mode — see rotate() above.
// opts: { reason, triggeredBy, mode } — see keyStore.rotateKeyAsync for details.
// the admin paths return only after the new status timeline is in
// the control plane (pg), so "rotated"/"revoked" is true cluster-wide within 5 s.
async function _withTimeline(p) {
  const out = await p;
  await keyStatusTimeline.reconcileAll();
  return out;
}

function rotateAsync(clientId, opts) {
  return _withTimeline(rotateKeyAsync(clientId, opts));
}

// Explicit, distinct entry point for planned/compatibility rotation that
// keeps the outgoing key verifiable ('deprecated'). Never use this in
// response to a suspected key compromise — use rotate()/rotateAsync()
// (emergency default) or revoke() instead. Intended callers: the automatic
// rotation scheduler and startup auto-rotation of an aged-out (not
// suspected-compromised) key — both planned maintenance, not incident
// response.
function rotateGracefully(clientId, opts) {
  return rotateKeyGracefully(clientId, opts);
}

function rotateGracefullyAsync(clientId, opts) {
  return _withTimeline(rotateKeyGracefullyAsync(clientId, opts));
}

// Native-signing-aware revocation. Always the correct entry point —
// propagates to the active NativeSigningProvider (Vault Transit / HSM) when
// one is configured, and delegates to local-only revocation otherwise. See
// keyStore.revokeKeyAsync() for the full fail-closed / audit contract.
// opts: { reason, operator } — both optional, included in audit events when supplied.
function revoke(clientIdOrKeyId, maybeKeyId, opts) {
  return _withTimeline(revokeKeyAsync(clientIdOrKeyId, maybeKeyId, opts));
}

// Re-reads keys.json from disk and, on success, replaces the in-memory store.
// Used by the rotation scheduler on every instance so that a rotation
// performed by whichever instance won the distributed lock becomes visible
// fleet-wide without a manual rolling restart. Fail-closed: never mutates
// in-memory state on read/parse/decrypt failure.
function reload() {
  const result = reloadFromDisk();
  // (v): the transparency and audit-checkpoint stores ride the same fleet-wide reload tick, so a
  // revocation or rotation of THOSE keys on one instance reaches every other one within the reload interval. Each
  // store's reloadFromDisk() is fail-closed (keeps its live store, emits its own ERROR) and is a no-op until that
  // store has bootstrapped; requiring them is side-effect-free. The artifact result shape is unchanged.
  const trustDomains = {};
  for (const [name, mod] of [['transparency', '../../src/core/transparency/transparencyKeyStore'],
                             ['checkpoint', '../../src/core/audit/checkpoint/checkpointKeyStore']]) {
    try { trustDomains[name] = require(mod).reloadFromDisk(); } catch (err) { trustDomains[name] = { reloaded: false, error: err.message }; }
  }
  return { ...result, trustDomains };
}

// ── Startup validation — called by server.js; fail-closed ─────────────────────
//
// Validates that:
//   1. The key encryption key is configured and has the correct format.
//   2. The key store has at least one active key.
//
// Throws on any failure — caller (server.js) must treat this as FATAL.

function validateStartup() {
  // Step 0: defence-in-depth plaintext scan.  bootstrap() migrated any plaintext
  // keys and ran a post-migration scan.  This check catches the narrow window
  // between bootstrap and validateStartup() where file tampering could introduce
  // a plaintext key.  Any finding is a security invariant violation — fail closed.
  const plaintextKeys = _scanFileForPlaintext();
  if (plaintextKeys.length > 0) {
    for (const { clientId, keyId } of plaintextKeys) {
      emit('CRITICAL', 'KEY_PLAINTEXT_DETECTED', {
        message: 'CRITICAL: Unencrypted private key detected. Startup aborted.',
        clientId,
        keyId,
      });
    }
    throw new Error(
      `CRITICAL: Unencrypted private key detected. Startup aborted. ` +
      `Affected keys: ${plaintextKeys.map(k => k.keyId).join(', ')}`,
    );
  }

  // Step 1: validate KEK is present and well-formed.
  // getKeyEncryptionKey() throws with a descriptive message if not configured.
  const kek = getKeyEncryptionKey();
  if (!Buffer.isBuffer(kek) || kek.length !== 32) {
    throw new Error('KeyManager: key encryption key must be a 32-byte Buffer — secrets provider returned invalid material');
  }

  // Step 2: full lifecycle audit — fail-closed on violations and expired keys.
  const ks = validateKeyStore();

  // Step 3: structural violations — emit all, then throw.
  for (const v of ks.violations) {
    emit('ERROR', 'KEY_STORE_VIOLATION', {
      violationType: v.type,
      clientId:      v.clientId,
      keyId:         v.keyId  || null,
      detail:        v.detail,
    });
  }
  if (ks.violations.length > 0) {
    throw new Error(
      `KeyManager: key store has ${ks.violations.length} structural violation(s) — ` +
      `inspect KEY_STORE_VIOLATION events above and repair before starting`,
    );
  }

  // Step 4: expired active keys — emit all, then throw.
  for (const e of ks.expiredKeys) {
    emit('ERROR', 'KEY_EXPIRED_STARTUP', {
      clientId:  e.clientId,
      keyId:     e.keyId,
      createdAt: e.createdAt,
      expiresAt: e.expiresAt,
    });
  }
  if (ks.expiredKeys.length > 0) {
    throw new Error(
      `KeyManager: ${ks.expiredKeys.length} active key(s) have expired — ` +
      `rotate before starting (see KEY_EXPIRED_STARTUP events above)`,
    );
  }

  // Step 5: expiring keys — warn only, startup continues.
  for (const e of ks.expiringKeys) {
    emit('WARN', 'KEY_EXPIRING_SOON', {
      clientId:      e.clientId,
      keyId:         e.keyId,
      daysRemaining: e.daysRemaining,
    });
  }

  // Step 6: rotation-overdue keys — warn only, startup continues.
  for (const e of ks.overdueKeys) {
    emit('WARN', 'KEY_ROTATION_OVERDUE', {
      clientId:    e.clientId,
      keyId:       e.keyId,
      daysOverdue: e.daysOverdue,
    });
  }

  return {
    totalActive:         ks.totalActive,
    clients:             ks.clients,
    secretProvider:      getProviderName(),
    encryptionAlgorithm: 'aes-256-gcm',
  };
}

// ── Transparency key access — Component #30 ───────────────────────────────────
//
// Transparency signing keys are stored in a completely separate key store
// (src/core/transparency/transparencyKeyStore.js).  No artifact key is ever
// returned by these methods, and no transparency key is ever returned by the
// artifact-purpose methods above.  Purpose isolation is structural.
//
// Lazy-loaded NOT to avoid a circular dependency (transparencyKeyStore.js
// never requires this module or keyStore.js back — verified via madge) but
// because transparencyKeyStore.js bootstraps eagerly at require() time and
// throws if QODIQA_KEY_ENCRYPTION_KEY isn't set yet. keyManager.js is
// required very early and pervasively; a static top-level require here would
// make simply requiring keyManager.js fail before server.js's ordered
// startup checks ever run — exactly the hazard keyStore.js's own deferred-
// bootstrap comment (_ensureBootstrapped, below in that file) describes.
let _tKeyStore = null;
function _getTransparencyKeyStore() {
  if (!_tKeyStore) {
    _tKeyStore = require('../../src/core/transparency/transparencyKeyStore');
  }
  return _tKeyStore;
}

/**
 * Get the active transparency signing key.
 * Purpose: transparency — never returns an artifact key.
 *
 * @returns {{ keyId: string, privDer: Buffer, pubDer: Buffer, version: number }}
 */
function getTransparencySigningKey() {
  return _getTransparencyKeyStore().getActiveKey();
}

/**
 * Resolve a transparency verification key by keyId.
 * Returns deprecated keys — historical transparency roots remain verifiable.
 * Purpose: transparency — never consults the artifact key store.
 *
 * @param {string} keyId  Transparency key ID (e.g. 'tr-myapp:key_v1')
 * @returns {{ pubDer: Buffer, status: string }}
 */
function getTransparencyVerificationKey(keyId) {
  return _getTransparencyKeyStore().getPublicKey(keyId);
}

/**
 * Lifecycle status of a transparency key ('active' | 'deprecated' | 'revoked'),
 * or null when the transparency key store has no such keyId. Never throws for an
 * unknown keyId. Purpose: transparency — never consults the artifact key store.
 *
 * @param {string} keyId  Transparency key ID (e.g. 'tr-myapp:key_v1')
 * @returns {string|null}
 */
function getTransparencyKeyStatus(keyId) {
  return _getTransparencyKeyStore().getKeyStatus(keyId);
}

module.exports = {
  getSigningKey,
  nativeSign,
  getVerificationKey,
  getActivePublicKey,
  getKeyInfo,
  getKeysByClientId,
  listPublicKeys,
  rotate,
  rotateAsync,
  rotateGracefully,
  rotateGracefullyAsync,
  reload,
  revoke,
  validateStartup,
  // Transparency purpose (Component #30) — completely separate from artifact keys
  getTransparencySigningKey,
  getTransparencyVerificationKey,
  getTransparencyKeyStatus,
};
