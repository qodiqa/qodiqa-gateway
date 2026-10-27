'use strict';

/**
 * Google Cloud KMS KEK Provider
 *
 * Uses Cloud KMS asymmetric-key wrapping (RSA-OAEP) or symmetric-key wrapping
 * (GOOGLE_SYMMETRIC_ENCRYPTION) to protect QODIQA's local 256-bit KEK.
 *
 * Architecture:
 *   - A CryptoKey lives permanently in a Cloud KMS KeyRing.
 *   - At startup (first run): generate a local 256-bit data key, wrap it with
 *     the Cloud KMS public key (RSA-OAEP) or encrypt it directly (symmetric),
 *     persist the ciphertext alongside the local keystore.
 *   - On subsequent startups: decrypt the ciphertext with Cloud KMS to recover
 *     the KEK.
 *   - For symmetric keys: Cloud KMS encrypt() / decrypt().
 *   - For asymmetric keys: local RSA-OAEP wrap with public key, Cloud KMS
 *     asymmetricDecrypt() to unwrap.
 *
 * Ed25519 note: GCP Cloud KMS supports EC (P-256, P-384) and RSA for signing,
 * but NOT Ed25519.  This provider supplies only the wrapping key.
 *
 * Required environment variables:
 *   GCP_KMS_PROJECT     — GCP project ID
 *   GCP_KMS_LOCATION    — e.g. "global" or "us-central1"
 *   GCP_KMS_KEYRING     — KeyRing name
 *   GCP_KMS_KEY         — CryptoKey name
 *   GCP_KMS_KEY_VERSION — CryptoKey version (for asymmetric; default "1")
 *   GCP_KMS_KEY_TYPE    — "symmetric" (default) or "asymmetric"
 *   GCP_WRAPPED_KEY_PATH — path for wrapped KEK file (default: data/kek.gcp)
 *   GCP credentials via Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS)
 *
 * Install: npm install @google-cloud/kms
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const { KekProvider } = require('./base');
const { assertMayGenerateWrappedKey, recordWrappedKeyProvisioned } = require('./wrappedKeyGuard'); //
const { writeFileAtomicSecure } = require('../../fs/secureWrite'); // phase 6

const WRAPPED_KEY_PATH_DEFAULT = path.join(process.cwd(), 'data', 'kek.gcp');

function _requireGcpKms() {
  try {
    return require('@google-cloud/kms');
  } catch {
    throw new Error(
      'GcpKmsKekProvider: @google-cloud/kms is not installed. ' +
      'Run: npm install @google-cloud/kms',
    );
  }
}

class GcpKmsKekProvider extends KekProvider {
  constructor(opts = {}) {
    super();
    this._project    = opts.project    || process.env.GCP_KMS_PROJECT;
    this._location   = opts.location   || process.env.GCP_KMS_LOCATION   || 'global';
    this._keyring    = opts.keyring    || process.env.GCP_KMS_KEYRING;
    this._key        = opts.key        || process.env.GCP_KMS_KEY;
    this._keyVersion = opts.keyVersion || process.env.GCP_KMS_KEY_VERSION || '1';
    this._keyType    = opts.keyType    || process.env.GCP_KMS_KEY_TYPE    || 'symmetric';
    this._wkPath     = opts.wrappedKeyPath || process.env.GCP_WRAPPED_KEY_PATH || WRAPPED_KEY_PATH_DEFAULT;
    this._kek        = null;
    this._client     = null;
  }

  get name() {
    return `gcp:kms:${this._project}/${this._location}/${this._keyring}/${this._key}`;
  }

  _cryptoKeyName() {
    return `projects/${this._project}/locations/${this._location}/keyRings/${this._keyring}/cryptoKeys/${this._key}`;
  }

  _cryptoKeyVersionName() {
    return `${this._cryptoKeyName()}/cryptoKeyVersions/${this._keyVersion}`;
  }

  async initialize() {
    if (!this._project)  throw new Error('GcpKmsKekProvider: GCP_KMS_PROJECT is not set');
    if (!this._keyring)  throw new Error('GcpKmsKekProvider: GCP_KMS_KEYRING is not set');
    if (!this._key)      throw new Error('GcpKmsKekProvider: GCP_KMS_KEY is not set');

    const { KeyManagementServiceClient } = _requireGcpKms();
    this._client = new KeyManagementServiceClient();

    if (fs.existsSync(this._wkPath)) {
      const wrappedB64 = fs.readFileSync(this._wkPath, 'utf8').trim();
      const wrapped    = Buffer.from(wrappedB64, 'base64');
      this._kek        = await this._decrypt(wrapped);
    } else {
      // explicit in production (QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY=true); nothing written otherwise.
      const { explicit } = assertMayGenerateWrappedKey('GcpKmsKekProvider', this._wkPath);
      const rawKek = crypto.randomBytes(32);
      const wrapped = await this._encrypt(rawKek);
      fs.mkdirSync(path.dirname(this._wkPath), { recursive: true });
      fs.writeFileSync(this._wkPath, wrapped.toString('base64'), { mode: 0o600, flag: 'wx' }); // never overwrite
      this._kek = rawKek;
      recordWrappedKeyProvisioned('GcpKmsKekProvider', this._wkPath, explicit);
    }

    if (!this._kek || this._kek.length !== 32) {
      throw new Error(
        `GcpKmsKekProvider: recovered KEK is ${this._kek?.length} bytes; expected 32`,
      );
    }
  }

  async _encrypt(plaintextBuffer) {
    if (this._keyType === 'symmetric') {
      const [result] = await this._client.encrypt({
        name:      this._cryptoKeyName(),
        plaintext: plaintextBuffer,
      });
      return Buffer.from(result.ciphertext);
    } else {
      // Asymmetric: get the public key, wrap locally with RSA-OAEP-SHA256.
      const [pubKeyRes] = await this._client.getPublicKey({
        name: this._cryptoKeyVersionName(),
      });
      const pubKeyPem = pubKeyRes.pem;
      const encrypted = crypto.publicEncrypt(
        { key: pubKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        plaintextBuffer,
      );
      return encrypted;
    }
  }

  async _decrypt(ciphertextBuffer) {
    if (this._keyType === 'symmetric') {
      const [result] = await this._client.decrypt({
        name:       this._cryptoKeyName(),
        ciphertext: ciphertextBuffer,
      });
      return Buffer.from(result.plaintext);
    } else {
      const [result] = await this._client.asymmetricDecrypt({
        name:       this._cryptoKeyVersionName(),
        ciphertext: ciphertextBuffer,
      });
      return Buffer.from(result.plaintext);
    }
  }

  async getWrappingKey() {
    if (!this._kek) throw new Error('GcpKmsKekProvider: not initialized');
    return this._kek;
  }

  async rotateWrappingKey() {
    const newKek    = crypto.randomBytes(32);
    const wrapped   = await this._encrypt(newKek);
    // Atomic + durable: unique 0600 temp file, fsync, rename (the fixed '.tmp' name could be stale or shared).
    writeFileAtomicSecure(this._wkPath, wrapped.toString('base64'));
    this._kek = newKek;
    return { version: 'gcp:kms:rotated:' + new Date().toISOString() };
  }

  async healthCheck() {
    try {
      await this._client.getCryptoKey({ name: this._cryptoKeyName() });
      return {
        healthy: true,
        detail:  `GCP KMS key "${this._key}" in keyring "${this._keyring}" reachable`,
      };
    } catch (e) {
      return { healthy: false, detail: `GCP KMS unreachable: ${e.message}` };
    }
  }

  async shutdown() {
    if (this._kek) {
      this._kek.fill(0);
      this._kek = null;
    }
    if (this._client?.close) await this._client.close();
    this._client = null;
  }
}

module.exports = { GcpKmsKekProvider };
