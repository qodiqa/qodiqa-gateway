'use strict';

const crypto          = require('crypto');
const secretsProvider = require('../secrets/secretsProvider');

// Encrypted-at-rest key material storage using AES-256-GCM.
//
// Each private key is encrypted with a fresh random IV.  The authentication tag
// ensures that any tampering with ciphertext, IV, or tag is detected on decrypt.
//
// Encrypted structure (stored in keys.json as encryptedPrivateKeyDer):
//   {
//     "keyId":               "<key identifier>",
//     "algorithm":           "aes-256-gcm",
//     "encryptedPrivateKey": "<AES-256-GCM encrypted PKCS8 DER, base64>",
//     "iv":                  "<12-byte IV, base64>",
//     "authTag":             "<16-byte GCM auth tag, base64>",
//     "createdAt":           "<ISO 8601>",
//     "updatedAt":           "<ISO 8601>"
//   }
//
// Backward compatibility: legacy format used "ciphertext" and "tag" field names.
// decryptKeyMaterial() accepts both formats; encryptKeyMaterial() always produces
// the current format.  Migration at bootstrap re-writes legacy entries.

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES  = 12; // 96-bit IV — NIST recommended for GCM
const TAG_BYTES = 16; // 128-bit authentication tag

// KEK-fingerprint guard rail (tracked finding from the 2026-07-30 "Dev
// KeyStore startup failure" session — a silent QODIQA_KEY_ENCRYPTION_KEY
// edit orphaned 16 signing keys across two trust domains with no warning
// until the next decrypt attempt, surfacing only as a generic GCM
// auth-tag failure days later). A non-reversible binding of the
// configured KEK, stored alongside the ciphertext it protects (same file,
// same atomic write) so it can't drift out of sync via a partial
// copy/restore, and checked BEFORE any per-key decrypt attempt so a KEK
// mismatch fails fast with a specific, operator-actionable error instead
// of a generic per-key auth-tag failure.
const KEK_FINGERPRINT_LABEL = 'qodiqa-kek-fingerprint-v1';

/**
 * Encrypt private key DER bytes under AES-256-GCM using the active KEK.
 *
 * @param {Buffer} privDerBuffer                        - Raw PKCS8 DER private key
 * @param {{ keyId?: string, createdAt?: string, scope?: string, aad?: Buffer, aadLabel?: string }} [metadata] scope: a dedicated KEK (audit key stores); aad/aadLabel: K1 binding
 * @returns {{ keyId, algorithm, encryptedPrivateKey, iv, authTag, createdAt, updatedAt }}
 */
function encryptKeyMaterial(privDerBuffer, metadata = {}) {
  if (!Buffer.isBuffer(privDerBuffer) || privDerBuffer.length === 0) {
    throw new TypeError('encryptKeyMaterial: privDerBuffer must be a non-empty Buffer');
  }
  const bound  = _aadArgs(metadata);
  const kek    = secretsProvider.getKeyEncryptionKey(metadata.scope);   // metadata.scope selects a dedicated KEK (audit key stores)
  const iv     = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, kek, iv, { authTagLength: TAG_BYTES });
  if (bound) cipher.setAAD(bound.aad);
  const ct     = Buffer.concat([cipher.update(privDerBuffer), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return {
    keyId:               metadata.keyId    || null,
    algorithm:           ALGORITHM,
    encryptedPrivateKey: ct.toString('base64'),
    iv:                  iv.toString('base64'),
    authTag:             tag.toString('base64'),
    ...(bound ? { aad: bound.aadLabel } : {}),
    createdAt:           metadata.createdAt || new Date().toISOString(),
    updatedAt:           new Date().toISOString(),
  };
}

// K1: optional AES-GCM AAD binding. A caller passing metadata.aad (Buffer) + metadata.aadLabel
// (string) gets a blob carrying `aad: <label>`; decryptKeyMaterial() then REQUIRES the same AAD. Blobs without the
// field (every blob written before this change, and macKeyring / subjectPseudonym blobs) decrypt exactly as before.
function _aadArgs(o) {
  if (!o || (o.aad === undefined && o.aadLabel === undefined)) return null;
  if (!Buffer.isBuffer(o.aad) || o.aad.length === 0 || typeof o.aadLabel !== 'string' || !o.aadLabel) {
    throw new TypeError('keyEncryption: aad must be a non-empty Buffer and aadLabel a non-empty string (both or neither)');
  }
  return { aad: o.aad, aadLabel: o.aadLabel };
}

/**
 * Decrypt AES-256-GCM encrypted key material.
 * Accepts both current format (encryptedPrivateKey/authTag) and legacy
 * format (ciphertext/tag) for backward compatibility during migration.
 *
 * @param {object} encrypted
 * @param {{ aad?: Buffer, aadLabel?: string, scope?: string }} [opts] aad: required (and must match) when the blob carries `aad`; scope: the dedicated KEK of an audit key store
 * @returns {Buffer}
 */
function decryptKeyMaterial(encrypted, opts) {
  if (!encrypted || typeof encrypted !== 'object') {
    throw new TypeError('decryptKeyMaterial: encrypted must be a non-null object');
  }
  const { algorithm, iv } = encrypted;
  if (algorithm !== ALGORITHM) {
    throw new Error(
      `decryptKeyMaterial: unsupported algorithm "${algorithm}"; expected "${ALGORITHM}"`,
    );
  }
  // Accept both current field names (encryptedPrivateKey/authTag) and legacy (ciphertext/tag).
  const ciphertextB64 = encrypted.encryptedPrivateKey || encrypted.ciphertext;
  const authTagB64    = encrypted.authTag             || encrypted.tag;
  if (typeof iv !== 'string' || typeof ciphertextB64 !== 'string' || typeof authTagB64 !== 'string') {
    throw new TypeError(
      'decryptKeyMaterial: iv, encryptedPrivateKey (or ciphertext), and authTag (or tag) must be base64 strings',
    );
  }
  const kek      = secretsProvider.getKeyEncryptionKey(opts && opts.scope);
  const ivBuf    = Buffer.from(iv,             'base64');
  const ctBuf    = Buffer.from(ciphertextB64,  'base64');
  const tagBuf   = Buffer.from(authTagB64,     'base64');
  const decipher = crypto.createDecipheriv(ALGORITHM, kek, ivBuf, { authTagLength: TAG_BYTES });
  // K1: a blob that declares an AAD label is only ever decrypted with the caller's AAD for that label.
  if (encrypted.aad !== undefined) {
    const bound = _aadArgs(opts);
    if (!bound || bound.aadLabel !== encrypted.aad) {
      throw new Error(`decryptKeyMaterial: blob is AAD-bound ("${encrypted.aad}") but the caller supplied ${bound ? `"${bound.aadLabel}"` : 'no AAD'}`);
    }
    decipher.setAAD(bound.aad);
  }
  decipher.setAuthTag(tagBuf);
  try {
    return Buffer.concat([decipher.update(ctBuf), decipher.final()]);
  } catch (err) {
    throw new Error(`decryptKeyMaterial: decryption failed — ${err.message}`);
  }
}

/**
 * Compute the current KEK's fingerprint: HMAC-SHA256 of a fixed label under
 * the KEK. Never reversible to the KEK itself — two files sharing a
 * fingerprint provably share a KEK, but the fingerprint cannot be inverted
 * to recover it.
 *
 * @returns {string} hex-encoded HMAC-SHA256 digest
 */
function computeKekFingerprint(scope) {
  const kek = secretsProvider.getKeyEncryptionKey(scope);
  return crypto.createHmac('sha256', kek).update(KEK_FINGERPRINT_LABEL, 'utf8').digest('hex');
}

/**
 * Startup guard: verify a key file's stored KEK fingerprint (if any) matches
 * the currently configured KEK, BEFORE any per-key decrypt is attempted.
 * A missing storedFingerprint is treated as "predates this guard" and is not
 * an error — the caller is expected to backfill it on the next save.
 *
 * @param {string|null|undefined} storedFingerprint  the file's persisted "kekFingerprint" field
 * @param {string} filePath                          path of the file being checked, for the error message
 * @throws {Error} KEK_FINGERPRINT_MISMATCH if storedFingerprint is present and does not match
 */
function assertKekFingerprint(storedFingerprint, filePath, scope) {
  if (!storedFingerprint) return; // predates the guard — nothing recorded to check yet
  const current = computeKekFingerprint(scope);
  if (current !== storedFingerprint) {
    // name the variable actually in use for this file (a scoped KEK, or the shared one)
    const envName = (scope !== undefined && scope !== null && secretsProvider.hasScopedKek(scope)) ? secretsProvider.kekEnvName(scope) : 'QODIQA_KEY_ENCRYPTION_KEY';
    throw new Error(
      `KEK_FINGERPRINT_MISMATCH: the configured ${envName} does not match the KEK ` +
      `that encrypted ${filePath}. This means ${envName} was changed (or the wrong ` +
      `environment/.env is in use) since ${filePath} was last written — every active key in this ` +
      `file will fail to decrypt under the current KEK. Restore the correct ` +
      `${envName}, or if a key-material reset is intentional, move ${filePath} aside ` +
      `and let the operator re-provision fresh keys under the current KEK.` +
      (scope !== undefined && scope !== null && !secretsProvider.hasScopedKek(scope) ? ` If this store was encrypted under its own KEK, set ${secretsProvider.kekEnvName(scope)} again.` : ''),
    );
  }
}

/**
 * K1: a purpose-bound subkey of the KEK — HKDF-SHA256(KEK, salt = empty, info). Used for the
 * key-store record MAC (src/infra/crypto/keyRecordSeal.js, info = RECORD_MAC_INFO) so the raw KEK never leaves this
 * module. Distinct info labels give independent keys; none equals the KEK or the fingerprint HMAC output.
 *
 * @param {string} info  domain-separation label
 * @returns {Buffer} 32 bytes
 */
function deriveKekSubkey(info, scope) {
  if (typeof info !== 'string' || info.length < 8) throw new TypeError('deriveKekSubkey: info must be a label of at least 8 characters');
  const kek = secretsProvider.getKeyEncryptionKey(scope);
  return Buffer.from(crypto.hkdfSync('sha256', kek, Buffer.alloc(0), Buffer.from(info, 'utf8'), 32));
}

module.exports = { encryptKeyMaterial, decryptKeyMaterial, computeKekFingerprint, assertKekFingerprint, deriveKekSubkey };
