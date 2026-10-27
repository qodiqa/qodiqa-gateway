'use strict';

/**
 * QODIQA Transparency Signer — Component #30
 *
 * Signing abstraction for transparency log entries and roots.
 * Enforces complete cryptographic separation from artifact signing.
 *
 * ABSTRACTION INTERFACE (TransparencySigner):
 *   sign(hashBuffer)              → Promise<{ signature, keyId, keyVersion }>
 *   verify(hashBuffer, sig, keyId) → boolean (never throws)
 *   getVerificationKey(keyId)     → { pubDer, status }
 *   getActiveKeyInfo()            → { keyId, pubDer, version }
 *   rotate(opts?)                 → { keyId, version, previousKeyId, previousKeyStatus, mode }
 *
 *   rotateGracefully()            → same shape, mode forced to 'graceful' (outgoing key deprecated)
 *   revoke(keyId)                 → void
 *   validateStartup()             → { signerType, activeKeyId, activeKeys, retiredKeys }
 *   metricsSnapshot()             → metrics object
 *
 * IMPLEMENTATIONS:
 *   SoftwareTransparencySigner — Ed25519 via transparencyKeyStore (default, production-ready)
 *   HsmTransparencySigner      — stub; future PKCS#11 / cloud HSM integration
 *
 * CONFIGURATION:
 *   TRANSPARENCY_SIGNER=software  (default)
 *   TRANSPARENCY_SIGNER=hsm       (future)
 *
 * FAIL CLOSED:
 *   Unknown signer type → throws at construction time.
 *   No active transparency key → sign() throws.
 *   HSM signer not supported in this release → throws at every operation.
 *   Wrong key purpose → structurally impossible (separate key stores).
 *
 * AUDIT:
 *   Every signing operation emits INFO TRANSPARENCY_ROOT_SIGNED.
 *   Every signing failure emits ERROR TRANSPARENCY_SIGNING_FAILED.
 *   Never logs private key material.
 */

const ed25519    = require('../../infra/crypto/ed25519');
const tKeyStore  = require('./transparencyKeyStore');
const { emit }   = require('../../../services/logger');

// ── In-process metrics ────────────────────────────────────────────────────────
//
// Lightweight counters — zero I/O, never throw.
// Exposed via metricsSnapshot() for monitoring integrations.

const _counters = {
  signaturesTotal:    0,
  verificationsTotal: 0,
  keyRotationsTotal:  0,
  signingFailures:    0,
};

// qodiqa_transparency_signer_* were defined and exported but never written — the signer kept only
// these private counters. Each event is now mirrored to its Prometheus counter.
const _PROM = { signaturesTotal: 'transparencySignerSignaturesTotal', signingFailures: 'transparencySignerFailuresTotal', keyRotationsTotal: 'transparencySignerKeyRotationsTotal' };
// Loaded ONCE at module load, never inside _inc(): a lazy require() here ran after the Jest environment was torn down (a late
// async sign in a finished test) and failed the whole coverage run with "You are trying to `require` a file after the Jest environment
// has been torn down".
let _metrics = null;
try { _metrics = require('../../observability/metrics'); } catch { /* metrics are best-effort; the signer must work without them */ }
function _inc(name) {
  try { _counters[name]++; } catch { /* infallible */ }
  try { if (_PROM[name] && _metrics) _metrics[_PROM[name]].inc({}); } catch { /* infallible */ }
}

// ── Software Transparency Signer ──────────────────────────────────────────────

/**
 * Production-ready software signer using Ed25519 + transparencyKeyStore.
 *
 * Uses ONLY the transparency key store — no artifact key is ever consulted.
 * Verified via structural separation: different key files, different code paths,
 * different key ID namespaces ('tr-*:key_vN' vs 'client:key_vN').
 */
class SoftwareTransparencySigner {
  get type() { return 'software'; }

  /**
   * Sign a 32-byte hash buffer with the active transparency signing key.
   * Fail-closed: throws if no active key, expired key, or signing failure.
   *
   * @param {Buffer} hashBuffer  32-byte SHA-256 digest
   * @returns {Promise<{ signature: string, keyId: string, keyVersion: number }>}
   */
  async sign(hashBuffer) {
    if (!Buffer.isBuffer(hashBuffer) || hashBuffer.length !== 32) {
      throw new TypeError('TransparencySigner.sign: hashBuffer must be a 32-byte Buffer');
    }

    let key;
    try {
      key = tKeyStore.getActiveKey();
    } catch (err) {
      _inc('signingFailures');
      emit('ERROR', 'TRANSPARENCY_SIGNING_FAILED', {
        reason: 'NO_ACTIVE_TRANSPARENCY_KEY',
        error:  err.message,
      });
      throw err;
    }

    let signature;
    try {
      signature = ed25519.sign(hashBuffer, key.privDer);
    } catch (err) {
      _inc('signingFailures');
      emit('ERROR', 'TRANSPARENCY_SIGNING_FAILED', {
        keyId:  key.keyId,
        reason: 'ED25519_SIGN_ERROR',
        error:  err.message,
      });
      throw err;
    }

    _inc('signaturesTotal');
    emit('INFO', 'TRANSPARENCY_ROOT_SIGNED', {
      keyId:   key.keyId,
      purpose: 'transparency',
    });

    return { signature, keyId: key.keyId, keyVersion: key.version };
  }

  /**
   * Verify a transparency signature. Never throws — returns false on any error.
   * Consults ONLY the transparency key store — never artifact keys.
   *
   * @param {Buffer} hashBuffer    32-byte SHA-256 digest
   * @param {string} signature     Base64-encoded Ed25519 signature
   * @param {string} keyId         Transparency key ID used to sign
   * @returns {boolean}
   */
  verify(hashBuffer, signature, keyId) {
    try {
      const { pubDer } = tKeyStore.getPublicKey(keyId);
      const ok = ed25519.verify(hashBuffer, signature, pubDer);
      _inc('verificationsTotal');
      return ok;
    } catch {
      return false;
    }
  }

  /**
   * Resolve a transparency verification key by keyId.
   * Returns deprecated keys — old roots remain verifiable indefinitely.
   * Throws for revoked or unknown keys (fail-closed).
   * Consults ONLY the transparency key store.
   *
   * @param {string} keyId
   * @returns {{ pubDer: Buffer, status: string }}
   */
  getVerificationKey(keyId) {
    return tKeyStore.getPublicKey(keyId);
  }

  /**
   * Get active transparency key metadata. No private material returned.
   * @returns {{ keyId: string, pubDer: Buffer, version: number }}
   */
  getActiveKeyInfo() {
    const key = tKeyStore.getActiveKey();
    return { keyId: key.keyId, pubDer: key.pubDer, version: key.version };
  }

  /**
   * Rotate the active transparency signing key.
   * defaults to 'emergency' mode — the outgoing key is revoked, not
   * deprecated, and immediately loses verification capability too. Pass
   * { mode: 'graceful' } — or call rotateGracefully() — only for planned,
   * non-incident migration.
   * Emits audit events; updates metrics.
   *
   * @param {{ mode?: 'emergency'|'graceful' }} [opts]
   * @returns {{ keyId: string, version: number, previousKeyId: string|null, previousKeyStatus: string|null, mode: string|null }}
   */
  rotate(opts) {
    const result = tKeyStore.rotateKey(opts);
    _inc('keyRotationsTotal');
    emit('INFO', 'TRANSPARENCY_KEY_ACTIVATED', {
      keyId:             result.keyId,
      version:           result.version,
      purpose:           'transparency',
      mode:              result.mode,
      previousKeyId:     result.previousKeyId,
      previousKeyStatus: result.previousKeyStatus,
    });
    return result;
  }

  /**
   * Explicit, distinct entry point for planned/compatibility rotation that
   * preserves verification capability for the outgoing key. Never call this
   * in response to a suspected key compromise — use rotate() (emergency
   * default) or revoke() instead.
   *
   * @returns {{ keyId: string, version: number, previousKeyId: string|null, previousKeyStatus: string|null, mode: string|null }}
   */
  rotateGracefully() {
    return this.rotate({ mode: 'graceful' });
  }

  /**
   * Revoke a transparency signing key.
   * Revoked keys cannot be used for signing or verification.
   *
   * @param {string} keyId
   */
  revoke(keyId) {
    tKeyStore.revokeKey(keyId);
    emit('INFO', 'TRANSPARENCY_KEY_REVOKED_VIA_SIGNER', { keyId, purpose: 'transparency' });
  }

  /**
   * Validate startup state.
   * Auto-provisions a transparency key if none exists.
   * Throws (fail-closed) on: violations, expired keys, or HSM unavailable.
   * Warns on: expiring keys, overdue rotation.
   *
   * @returns {{ signerType, activeKeyId, activeKeys, retiredKeys }}
   */
  validateStartup() {
    const audit = tKeyStore.validateKeyStore();

    if (audit.violations.length > 0) {
      for (const v of audit.violations) {
        emit('ERROR', 'TRANSPARENCY_KEY_STORE_VIOLATION', v);
      }
      throw new Error(
        `TransparencyKeyStore: ${audit.violations.length} structural violation(s) — ` +
        `see TRANSPARENCY_KEY_STORE_VIOLATION events`,
      );
    }

    if (audit.expiredKeys.length > 0) {
      for (const e of audit.expiredKeys) {
        emit('ERROR', 'TRANSPARENCY_KEY_EXPIRED_STARTUP', e);
      }
      throw new Error(
        `TransparencyKeyStore: ${audit.expiredKeys.length} active transparency key(s) expired — ` +
        `rotate before starting`,
      );
    }

    for (const e of audit.expiringKeys) {
      emit('WARN', 'TRANSPARENCY_KEY_EXPIRING_SOON', e);
    }
    for (const e of audit.overdueKeys) {
      emit('WARN', 'TRANSPARENCY_KEY_ROTATION_OVERDUE', e);
    }

    // Auto-provision if no active key exists (first run or after full revocation)
    if (audit.totalActive === 0) {
      emit('INFO', 'TRANSPARENCY_KEY_AUTO_PROVISIONING', {
        message: 'No active transparency signing key — provisioning new key at startup',
      });
      tKeyStore.rotateKey();
    }

    const allKeys     = tKeyStore.listKeys();
    const activeKeys  = allKeys.filter(k => k.status === 'active');
    const retiredKeys = allKeys.filter(k => k.status === 'deprecated');

    return {
      signerType:  this.type,
      activeKeyId: activeKeys[0]?.keyId ?? null,
      activeKeys:  activeKeys.length,
      retiredKeys: retiredKeys.length,
    };
  }

  /**
   * Metrics snapshot for monitoring.
   * @returns {object}
   */
  metricsSnapshot() {
    const allKeys = tKeyStore.listKeys();
    return {
      signerType:              this.type,
      signaturesTotal:         _counters.signaturesTotal,
      verificationsTotal:      _counters.verificationsTotal,
      keyRotationsTotal:       _counters.keyRotationsTotal,
      signingFailures:         _counters.signingFailures,
      activeTransparencyKeys:  allKeys.filter(k => k.status === 'active').length,
      retiredTransparencyKeys: allKeys.filter(k => k.status === 'deprecated').length,
    };
  }
}

// ── HSM Transparency Signer (future) ─────────────────────────────────────────

/**
 * Stub for future PKCS#11 / cloud HSM integration.
 * Every operation throws with a clear message until implemented.
 * Configuration: TRANSPARENCY_SIGNER=hsm
 */
class HsmTransparencySigner {
  get type() { return 'hsm'; }

  async sign(_hashBuffer) {
    throw new Error(
      'HsmTransparencySigner: HSM transparency signing is not supported in this release. ' +
      'Set TRANSPARENCY_SIGNER=software to use the software signer.',
    );
  }

  verify(_hashBuffer, _signature, _keyId) {
    return false;
  }

  getVerificationKey(_keyId) {
    throw new Error('HsmTransparencySigner: HSM transparency signing is not supported in this release');
  }

  getActiveKeyInfo() {
    throw new Error('HsmTransparencySigner: HSM transparency signing is not supported in this release');
  }

  rotate() {
    throw new Error('HsmTransparencySigner: HSM transparency signing is not supported in this release');
  }

  rotateGracefully() {
    throw new Error('HsmTransparencySigner: HSM transparency signing is not supported in this release');
  }

  revoke(_keyId) {
    throw new Error('HsmTransparencySigner: HSM transparency signing is not supported in this release');
  }

  validateStartup() {
    throw new Error(
      'HsmTransparencySigner: HSM transparency signing is not supported in this release. ' +
      'Set TRANSPARENCY_SIGNER=software for the current release.',
    );
  }

  metricsSnapshot() {
    return { signerType: 'hsm', error: 'unsupported' };
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

const SIGNER_TYPES = Object.freeze({
  software: SoftwareTransparencySigner,
  hsm:      HsmTransparencySigner,
});

/**
 * Create a new transparency signer instance.
 * Fails closed if the signer type is unknown.
 *
 * @param {string} [type]  Signer type; defaults to TRANSPARENCY_SIGNER env or 'software'
 * @returns {SoftwareTransparencySigner|HsmTransparencySigner}
 */
function createTransparencySigner(type) {
  const signerType = (type || process.env.TRANSPARENCY_SIGNER || 'software').toLowerCase();
  const SignerClass = SIGNER_TYPES[signerType];
  if (!SignerClass) {
    throw new Error(
      `TransparencySigner: unknown signer type "${signerType}". ` +
      `Supported types: ${Object.keys(SIGNER_TYPES).join(', ')}`,
    );
  }
  return new SignerClass();
}

// ── Singleton ─────────────────────────────────────────────────────────────────
//
// Lazy-initialised on first call — avoids circular dep and startup overhead.
// Re-entrant: any number of callers share the same instance.

let _signer = null;

/**
 * Get the process-singleton transparency signer.
 * @returns {SoftwareTransparencySigner|HsmTransparencySigner}
 */
function getTransparencySigner() {
  if (!_signer) {
    _signer = createTransparencySigner();
  }
  return _signer;
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  SoftwareTransparencySigner,
  HsmTransparencySigner,
  createTransparencySigner,
  getTransparencySigner,
  SIGNER_TYPES,
};
