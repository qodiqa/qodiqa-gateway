'use strict';

/**
 * PKCS#11 HSM Native Signing Provider
 *
 * Implements NativeSigningProvider for hardware security modules (HSMs) accessed
 * via PKCS#11 / PKCS11 URI.  Private key material is generated inside the HSM and
 * never leaves the hardware boundary.
 *
 * Ed25519 support via PKCS#11 requires CKM_EDDSA (introduced in PKCS#11 v3.0).
 * Verify that your HSM firmware supports this mechanism before deploying.
 *
 * Supported HSMs (tested configurations):
 *   - Thales Luna Network HSM 7 (firmware 7.7+, CKM_EDDSA via PKCS#11 v3.0)
 *   - AWS CloudHSM (via PKCS11 library with CKM_EDDSA support)
 *   - SoftHSM2 (development/test only — not for production)
 *
 * Architecture:
 *   - HSM key objects are identified by CKA_LABEL (the keyName passed to each method).
 *   - QODIQA generates a key pair on the HSM; the private key handle is opaque.
 *   - Signing: ED25519Sign(privateKeyHandle, preHashedEnvelope) → 64-byte signature.
 *   - The public key is exported as DER (CKA_EC_POINT extraction on the public object).
 *   - Key metadata (status, createdAt) is stored as CKA_LABEL suffix conventions or
 *     in a companion JSON index file at HSM_KEY_INDEX_PATH.
 *
 * Required environment variables:
 *   HSM_PKCS11_LIB        — path to the PKCS#11 shared library (.so / .dll)
 *   HSM_PKCS11_SLOT       — PKCS#11 slot index (default: 0)
 *   HSM_PKCS11_PIN        — HSM partition PIN (or use HSM_PKCS11_PIN_FILE)
 *   HSM_PKCS11_PIN_FILE   — path to file containing the PIN
 *   HSM_KEY_INDEX_PATH    — path for key metadata index (default: data/hsm-keys.json)
 *
 * Install: npm install pkcs11js
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { NativeSigningProvider, REVOCATION_METHODS, pickStrongestRevocationMethod } = require('./base');
const { writeFileAtomicSecure } = require('../../fs/secureWrite');

const KEY_INDEX_PATH_DEFAULT = path.join(process.cwd(), 'data', 'hsm-keys.json');

// PKCS#11 constants needed for Ed25519 (CKM_EDDSA, CKK_EC_EDWARDS, curve OID).
// Edwards curve OID for Ed25519: 1.3.101.112 — DER-encoded as hex.
const OID_ED25519_HEX = '06032b6570';
const CKM_EDDSA       = 0x00001057; // PKCS#11 v3.0 — the SIGNING mechanism
// key-pair GENERATION needs its own mechanism —
// C_GenerateKeyPair with CKM_EDDSA returned CKR_MECHANISM_INVALID on every token, so no key could ever be created.
const CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055; // PKCS#11 v3.0
// pkcs11js (~2.1.x) does not export CKK_EC_EDWARDS — `pkcs11.CKK_EC_EDWARDS` was undefined, so the find
// templates never matched the generated objects. The PKCS#11 v3.0 value, defined here.
const CKK_EC_EDWARDS = 0x00000040; // PKCS#11 v3.0
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function _requirePkcs11() {
  try {
    return require('pkcs11js');
  } catch {
    throw new Error(
      'HsmSigningProvider: pkcs11js is not installed. ' +
      'Run: npm install pkcs11js',
    );
  }
}

class HsmSigningProvider extends NativeSigningProvider {
  constructor(opts = {}) {
    super();
    this._libPath      = opts.libPath      || process.env.HSM_PKCS11_LIB;
    this._slotIndex    = opts.slotIndex    != null ? opts.slotIndex : parseInt(process.env.HSM_PKCS11_SLOT || '0', 10);
    this._pin          = opts.pin          || process.env.HSM_PKCS11_PIN;
    this._pinFile      = opts.pinFile      || process.env.HSM_PKCS11_PIN_FILE;
    this._keyIndexPath = opts.keyIndexPath || process.env.HSM_KEY_INDEX_PATH || KEY_INDEX_PATH_DEFAULT;
    this._pkcs11       = null;
    this._session      = null;
    this._keyIndex     = {};
  }

  get name() {
    return `hsm:pkcs11:${this._libPath}:slot${this._slotIndex}`;
  }

  _resolvePin() {
    if (this._pin) return this._pin;
    if (this._pinFile && fs.existsSync(this._pinFile)) {
      return fs.readFileSync(this._pinFile, 'utf8').trim();
    }
    throw new Error('HsmSigningProvider: no PIN configured. Set HSM_PKCS11_PIN or HSM_PKCS11_PIN_FILE.');
  }

  _loadKeyIndex() {
    if (fs.existsSync(this._keyIndexPath)) {
      try {
        this._keyIndex = JSON.parse(fs.readFileSync(this._keyIndexPath, 'utf8'));
      } catch {
        this._keyIndex = {};
      }
    } else {
      this._keyIndex = {};
    }
  }

  _saveKeyIndex() {
    // phase 6: unique 0600 temp file, fsync, rename (0700 for a new directory) -- the
    // fixed '.tmp' name could be stale (old mode) or shared with a concurrent writer, and nothing was fsync'ed.
    writeFileAtomicSecure(this._keyIndexPath, JSON.stringify(this._keyIndex, null, 2));
  }

  async initialize() {
    if (!this._libPath) {
      throw new Error('HsmSigningProvider: HSM_PKCS11_LIB is not set');
    }
    const pkcs11     = _requirePkcs11();
    this._pkcs11     = new pkcs11.PKCS11();
    this._pkcs11.load(this._libPath);
    this._pkcs11.C_Initialize();

    // a failure after C_Initialize must not leave the library initialized — otherwise every retry in this
    // process (the resilience layer retries initialize()) fails with CKR_CRYPTOKI_ALREADY_INITIALIZED, masking the
    // real cause (wrong PIN, missing slot). Release the session/library, then rethrow the original error.
    try {
      const slots = this._pkcs11.C_GetSlotList(true);
      if (!slots || slots.length <= this._slotIndex) {
        throw new Error(`HsmSigningProvider: slot ${this._slotIndex} not found (${slots?.length ?? 0} slots available)`);
      }

      this._session = this._pkcs11.C_OpenSession(
        slots[this._slotIndex],
        pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION,
      );
      const pin = this._resolvePin();
      this._pkcs11.C_Login(this._session, pkcs11.CKU_USER, pin);
      this._loadKeyIndex();
    } catch (err) {
      await this.shutdown();
      throw err;
    }
  }

  async generateKeyPair(keyName) {
    if (!this._session) throw new Error('HsmSigningProvider: not initialized');
    const pkcs11 = _requirePkcs11();

    const labelBuf  = Buffer.from(keyName, 'utf8');
    const oidBuf    = Buffer.from(OID_ED25519_HEX, 'hex');

    const pubTemplate = [
      { type: pkcs11.CKA_TOKEN,       value: true },
      { type: pkcs11.CKA_VERIFY,      value: true },
      { type: pkcs11.CKA_LABEL,       value: labelBuf },
      { type: pkcs11.CKA_KEY_TYPE,    value: CKK_EC_EDWARDS },
      { type: pkcs11.CKA_EC_PARAMS,   value: oidBuf },
    ];

    const privTemplate = [
      { type: pkcs11.CKA_TOKEN,       value: true },
      { type: pkcs11.CKA_SIGN,        value: true },
      { type: pkcs11.CKA_SENSITIVE,   value: true },
      { type: pkcs11.CKA_EXTRACTABLE, value: false }, // private key never leaves HSM
      { type: pkcs11.CKA_LABEL,       value: labelBuf },
      { type: pkcs11.CKA_KEY_TYPE,    value: CKK_EC_EDWARDS },
    ];

    // (SoftHSM2 emulator run): pkcs11js (the pinned ~2.1.x) returns a KeyPair OBJECT { publicKey, privateKey },
    // not an array — destructuring it as an array threw "object is not iterable" after the key was created.
    const { publicKey: pubHandle } = this._pkcs11.C_GenerateKeyPair(
      this._session,
      { mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN },
      pubTemplate,
      privTemplate,
    );

    // Export public key (EC point) as SPKI DER.
    const ecPoint      = this._pkcs11.C_GetAttributeValue(this._session, pubHandle, [
      { type: pkcs11.CKA_EC_POINT },
    ])[0].value;
    // ecPoint is the raw 32-byte Edwards point wrapped in an OCTET STRING (DER).
    // Build SPKI: SEQUENCE { SEQUENCE { OID(ed25519) }, BIT STRING { ecPoint } }
    const publicKeyDer = _buildEd25519Spki(ecPoint);

    this._keyIndex[keyName] = {
      keyName,
      status:    'active',
      createdAt: new Date().toISOString(),
      algorithm: 'ed25519',
    };
    this._saveKeyIndex();

    return { publicKeyDer, keyName };
  }

  async sign(keyName, messageHash) {
    if (!this._session) throw new Error('HsmSigningProvider: not initialized');
    if (!Buffer.isBuffer(messageHash) || messageHash.length !== 32) {
      throw new TypeError('HsmSigningProvider.sign: messageHash must be a 32-byte Buffer');
    }
    const pkcs11  = _requirePkcs11();
    const privKey = this._findPrivateKey(keyName);
    this._pkcs11.C_SignInit(this._session, { mechanism: CKM_EDDSA }, privKey);
    const sigBuf = this._pkcs11.C_Sign(this._session, messageHash, Buffer.alloc(64));
    return Buffer.from(sigBuf);
  }

  _findPrivateKey(keyName) {
    const pkcs11   = _requirePkcs11();
    const labelBuf = Buffer.from(keyName, 'utf8');
    this._pkcs11.C_FindObjectsInit(this._session, [
      { type: pkcs11.CKA_CLASS,     value: pkcs11.CKO_PRIVATE_KEY },
      { type: pkcs11.CKA_LABEL,     value: labelBuf },
      { type: pkcs11.CKA_KEY_TYPE,  value: CKK_EC_EDWARDS },
    ]);
    const handles = this._pkcs11.C_FindObjects(this._session, 1);
    this._pkcs11.C_FindObjectsFinal(this._session);
    if (!handles || handles.length === 0) {
      throw new Error(`HsmSigningProvider: private key "${keyName}" not found on HSM`);
    }
    return handles[0];
  }

  async getPublicKey(keyName) {
    const meta = this._keyIndex[keyName];
    if (!meta) throw new Error(`HsmSigningProvider: key "${keyName}" not in index`);
    const pkcs11   = _requirePkcs11();
    const labelBuf = Buffer.from(keyName, 'utf8');
    this._pkcs11.C_FindObjectsInit(this._session, [
      { type: pkcs11.CKA_CLASS,    value: pkcs11.CKO_PUBLIC_KEY },
      { type: pkcs11.CKA_LABEL,    value: labelBuf },
      { type: pkcs11.CKA_KEY_TYPE, value: CKK_EC_EDWARDS },
    ]);
    const handles = this._pkcs11.C_FindObjects(this._session, 1);
    this._pkcs11.C_FindObjectsFinal(this._session);
    if (!handles || handles.length === 0) {
      throw new Error(`HsmSigningProvider: public key "${keyName}" not found on HSM`);
    }
    const ecPoint   = this._pkcs11.C_GetAttributeValue(this._session, handles[0], [
      { type: pkcs11.CKA_EC_POINT },
    ])[0].value;
    const publicKeyDer = _buildEd25519Spki(ecPoint);
    return { publicKeyDer, status: meta.status };
  }

  async deprecateKey(keyName) {
    if (this._keyIndex[keyName]) {
      this._keyIndex[keyName].status = 'deprecated';
      this._saveKeyIndex();
    }
  }

  /** @returns {string[]} — PKCS#11 exposes only hard destruction of key objects. */
  getRevocationCapabilities() {
    return [REVOCATION_METHODS.DESTROY];
  }

  /**
   * Revoke a key on the HSM by destroying its private and public key objects.
   * PKCS#11 has no standard "disable" primitive that survives a session
   * restart without vendor extensions, so 'destroy' is the only method this
   * provider advertises (see getRevocationCapabilities()).
   *
   * Fails loudly rather than silently: finding zero key objects to destroy
   * (a state mismatch — QODIQA believed the key existed) throws instead of
   * resolving as a no-op success, and any C_DestroyObject failure is
   * surfaced with the underlying PKCS#11 error attached.
   *
   * @param {string} keyName
   * @param {{ method?: string }} [opts]
   * @returns {Promise<{ method: string, provider: string, revokedAt: string, providerResponse: object }>}
   */
  async revokeKey(keyName, opts = {}) {
    const method = opts.method || pickStrongestRevocationMethod(this.getRevocationCapabilities());
    if (method !== REVOCATION_METHODS.DESTROY) {
      throw new Error(
        `HsmSigningProvider.revokeKey: unsupported revocation method "${method}" — ` +
        `supported: ${this.getRevocationCapabilities().join(', ')}`,
      );
    }
    if (!this._session) throw new Error('HsmSigningProvider: not initialized');

    const pkcs11   = _requirePkcs11();
    const labelBuf = Buffer.from(keyName, 'utf8');
    let destroyedCount = 0;

    try {
      // Destroy both public and private key objects on the HSM.
      for (const cls of [pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY]) {
        this._pkcs11.C_FindObjectsInit(this._session, [
          { type: pkcs11.CKA_CLASS, value: cls },
          { type: pkcs11.CKA_LABEL, value: labelBuf },
        ]);
        const handles = this._pkcs11.C_FindObjects(this._session, 1);
        this._pkcs11.C_FindObjectsFinal(this._session);
        for (const h of (handles || [])) {
          this._pkcs11.C_DestroyObject(this._session, h);
          destroyedCount++;
        }
      }
    } catch (err) {
      /** @type {any} */ const wrapped = new Error(`HsmSigningProvider.revokeKey: C_DestroyObject failed for key "${keyName}": ${err.message}`);
      wrapped.cause  = err;
      wrapped.method = method;
      throw wrapped;
    }

    if (destroyedCount === 0) {
      throw new Error(`HsmSigningProvider.revokeKey: no key objects found on HSM for "${keyName}" — nothing was destroyed`);
    }

    // the index records WHEN the key was destroyed (the same instant this call reports).
    const revokedAt = new Date().toISOString();
    if (this._keyIndex[keyName]) {
      this._keyIndex[keyName].status = 'revoked';
      this._keyIndex[keyName].revokedAt = revokedAt;
      this._saveKeyIndex();
    }

    return {
      method, provider: this.name, revokedAt,
      providerResponse: { destroyedObjectCount: destroyedCount },
    };
  }

  async healthCheck() {
    try {
      if (!this._pkcs11 || !this._session) {
        return { healthy: false, detail: 'HSM session not open' };
      }
      const info = this._pkcs11.C_GetSessionInfo(this._session);
      return {
        healthy: true,
        detail:  `PKCS#11 session open; state: ${info.state}; slotID: ${info.slotID}`,
      };
    } catch (e) {
      return { healthy: false, detail: `PKCS#11 health check failed: ${e.message}` };
    }
  }

  async shutdown() {
    try {
      if (this._session && this._pkcs11) {
        this._pkcs11.C_Logout(this._session);
        this._pkcs11.C_CloseSession(this._session);
      }
    } catch { /* best-effort */ }
    try {
      if (this._pkcs11) this._pkcs11.C_Finalize();
    } catch { /* best-effort */ }
    this._session = null;
    this._pkcs11  = null;
  }
}

// ── DER encoding helper ───────────────────────────────────────────────────────
// Construct a minimal SPKI DER for an Ed25519 public key from the raw EC point.
// The EC point from PKCS#11 CKA_EC_POINT is a DER OCTET STRING wrapping the
// 32-byte Edwards point.  We need the 32-byte raw value to build the SPKI.
function _buildEd25519Spki(ecPointDer) {
  // ecPointDer = 04 20 <32 bytes> (OCTET STRING, length 32, value = raw point)
  const rawPoint = ecPointDer.length === 34 && ecPointDer[0] === 0x04 && ecPointDer[1] === 0x20 ? ecPointDer.slice(2) : ecPointDer;
  if (rawPoint.length !== 32) {
    throw new Error(`HsmSigningProvider: CKA_EC_POINT is not a 32-byte Ed25519 point (got ${ecPointDer.length} bytes)`);
  }
  // Node.js has no `format: 'raw'` key import (ERR_INVALID_ARG_VALUE on
  // Node 22 and 24), so this threw for every key. Build the fixed 12-byte Ed25519 SPKI header + point and let
  // createPublicKey validate it.
  const { createPublicKey } = require('crypto');
  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawPoint]), format: 'der', type: 'spki' });
  return Buffer.from(key.export({ type: 'spki', format: 'der' }));
}

module.exports = { HsmSigningProvider };
