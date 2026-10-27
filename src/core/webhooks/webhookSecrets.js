'use strict';

/**
 * Webhook Secret Encryption — Component #28
 *
 * Encrypts and decrypts webhook signing secrets using AES-256-GCM.
 * The Key Encryption Key (KEK) is resolved through secretsProvider.js —
 * the same provider-agnostic abstraction used to protect Ed25519 private
 * key material (services/artifact/keyEncryption.js). Whichever KMS backend
 * is configured via QODIQA_KMS_PROVIDER (local env var, Vault, AWS/Azure/GCP
 * KMS, HSM) is transparently used here too; this module never reads
 * QODIQA_KEY_ENCRYPTION_KEY directly and has no provider-specific logic.
 *
 * Storage format (three columns in webhook_endpoints):
 *   secret_enc  — base64 AES-GCM ciphertext
 *   secret_iv   — base64 12-byte random IV
 *   secret_tag  — base64 16-byte GCM authentication tag
 *
 * Plaintext secrets are returned once at endpoint creation and never again.
 */

const crypto          = require('crypto');
const secretsProvider = require('../../../services/secrets/secretsProvider');

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES  = 12;

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Generate a new cryptographically random webhook signing secret.
 * Prefixed with 'whsec_' for easy identification.
 *
 * @returns {string}  e.g. 'whsec_<64 hex chars>'
 */
function generateSecret() {
  return 'whsec_' + crypto.randomBytes(32).toString('hex');
}

/**
 * Encrypt a plaintext webhook secret for storage.
 *
 * @param {string} plaintext
 * @returns {{ enc: string, iv: string, tag: string }}  base64-encoded fields
 */
function encryptSecret(plaintext) {
  const kek    = secretsProvider.getKeyEncryptionKey();
  const iv     = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, kek, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return {
    enc: enc.toString('base64'),
    iv:  iv.toString('base64'),
    tag: tag.toString('base64'),
  };
}

/**
 * Decrypt a stored webhook secret.
 *
 * @param {string} enc   base64 ciphertext
 * @param {string} iv    base64 IV
 * @param {string} tag   base64 auth tag
 * @returns {string}     plaintext secret
 */
function decryptSecret(enc, iv, tag) {
  const kek      = secretsProvider.getKeyEncryptionKey();
  const ivBuf    = Buffer.from(iv,  'base64');
  const tagBuf   = Buffer.from(tag, 'base64');
  const encBuf   = Buffer.from(enc, 'base64');
  const decipher = crypto.createDecipheriv(ALGORITHM, kek, ivBuf);
  decipher.setAuthTag(tagBuf);
  return Buffer.concat([decipher.update(encBuf), decipher.final()]).toString('utf8');
}

module.exports = { generateSecret, encryptSecret, decryptSecret };
