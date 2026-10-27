'use strict';

/**
 * AWS KMS KEK Provider
 *
 * Uses AWS KMS GenerateDataKey to obtain a 256-bit data key that becomes
 * the AES-256-GCM wrapping key for QODIQA's Ed25519 private keys.
 *
 * Architecture:
 *   - A CMK (Customer Master Key) lives permanently in AWS KMS.
 *   - At startup: GenerateDataKey(CMK) returns { plaintext, ciphertext }.
 *     The plaintext is used as the KEK for the session.
 *     The ciphertext (EDK) is persisted alongside the local key file.
 *   - On next startup: Decrypt(CMK, EDK) recovers the plaintext KEK.
 *   - The CMK never leaves AWS; only the EDK is stored locally.
 *   - AWS KMS automatic key rotation is supported for CMKs.
 *
 * Ed25519 note: AWS KMS does not support Ed25519 signing.  This provider
 * supplies only the wrapping key.  Signing remains local via keyStore.js.
 *
 * Required environment variables:
 *   AWS_KMS_KEY_ID    — ARN or alias, e.g. "arn:aws:kms:us-east-1:123:key/abc"
 *   AWS_KMS_REGION    — AWS region, e.g. "us-east-1"
 *   AWS_KMS_EDK_PATH  — path for encrypted data key file (default: data/kek.edk)
 *   AWS credentials via standard AWS SDK chain (env, ~/.aws, IMDS, ECS task role)
 *
 * Install: npm install @aws-sdk/client-kms
 */

const fs   = require('fs');
const path = require('path');
const { KekProvider } = require('./base');
const { assertMayGenerateWrappedKey, recordWrappedKeyProvisioned } = require('./wrappedKeyGuard'); //
const { writeFileAtomicSecure } = require('../../fs/secureWrite'); // phase 6

const EDK_PATH_DEFAULT = path.join(process.cwd(), 'data', 'kek.edk');

function _requireKms() {
  try {
    const { KMSClient, GenerateDataKeyCommand, DecryptCommand } = require('@aws-sdk/client-kms');
    return { KMSClient, GenerateDataKeyCommand, DecryptCommand };
  } catch {
    throw new Error(
      'AwsKmsKekProvider: @aws-sdk/client-kms is not installed. ' +
      'Run: npm install @aws-sdk/client-kms',
    );
  }
}

class AwsKmsKekProvider extends KekProvider {
  constructor(opts = {}) {
    super();
    this._keyId   = opts.keyId   || process.env.AWS_KMS_KEY_ID;
    this._region  = opts.region  || process.env.AWS_KMS_REGION;
    this._edkPath = opts.edkPath || process.env.AWS_KMS_EDK_PATH || EDK_PATH_DEFAULT;
    this._kek     = null;
    this._client  = null;
  }

  get name() {
    return `aws:kms:${this._keyId}`;
  }

  async initialize() {
    if (!this._keyId) {
      throw new Error('AwsKmsKekProvider: AWS_KMS_KEY_ID is not set');
    }
    if (!this._region) {
      throw new Error('AwsKmsKekProvider: AWS_KMS_REGION is not set');
    }

    const { KMSClient, GenerateDataKeyCommand, DecryptCommand } = _requireKms();
    this._client = new KMSClient({ region: this._region });

    if (fs.existsSync(this._edkPath)) {
      // Decrypt the persisted encrypted data key.
      const edkB64 = fs.readFileSync(this._edkPath, 'utf8').trim();
      const edk    = Buffer.from(edkB64, 'base64');
      const res    = await this._client.send(new DecryptCommand({
        KeyId:          this._keyId,
        CiphertextBlob: edk,
      }));
      this._kek = Buffer.from(res.Plaintext);
    } else {
      // First run: generate a new data key and persist the ciphertext.
      // in production a missing EDK is never silently replaced by a NEW KEK — minting one needs
      // the explicit QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY=true switch (checked BEFORE any KMS call; nothing is written).
      const { explicit } = assertMayGenerateWrappedKey('AwsKmsKekProvider', this._edkPath);
      const res = await this._client.send(new GenerateDataKeyCommand({
        KeyId:   this._keyId,
        KeySpec: 'AES_256',
      }));
      this._kek = Buffer.from(res.Plaintext);
      // Store only the ciphertext (EDK) — plaintext never persisted.
      fs.mkdirSync(path.dirname(this._edkPath), { recursive: true });
      fs.writeFileSync(
        this._edkPath,
        Buffer.from(res.CiphertextBlob).toString('base64'),
        { mode: 0o600, flag: 'wx' }, // never overwrite a wrapped key that appeared meanwhile
      );
      recordWrappedKeyProvisioned('AwsKmsKekProvider', this._edkPath, explicit);
    }

    if (!this._kek || this._kek.length !== 32) {
      throw new Error(
        `AwsKmsKekProvider: GenerateDataKey returned unexpected key length ${this._kek?.length}; expected 32`,
      );
    }
  }

  async getWrappingKey() {
    if (!this._kek) throw new Error('AwsKmsKekProvider: not initialized');
    return this._kek;
  }

  async rotateWrappingKey() {
    const { GenerateDataKeyCommand } = _requireKms();
    // Generate a new data key under the same CMK.
    const res = await this._client.send(new GenerateDataKeyCommand({
      KeyId:   this._keyId,
      KeySpec: 'AES_256',
    }));
    const newKek    = Buffer.from(res.Plaintext);
    const newEdkB64 = Buffer.from(res.CiphertextBlob).toString('base64');
    // Atomic write: tmp → rename.
    // Atomic + durable: unique 0600 temp file, fsync, rename (the fixed '.tmp' name could be stale or shared).
    writeFileAtomicSecure(this._edkPath, newEdkB64);
    this._kek = newKek;
    return { version: 'aws:kms:rotated:' + new Date().toISOString() };
  }

  async healthCheck() {
    try {
      const { DescribeKeyCommand } = require('@aws-sdk/client-kms');
      const res = await this._client.send(new DescribeKeyCommand({ KeyId: this._keyId }));
      const enabled = res.KeyMetadata?.KeyState === 'Enabled';
      return {
        healthy: enabled,
        detail:  `AWS KMS key ${this._keyId} state: ${res.KeyMetadata?.KeyState}`,
      };
    } catch (e) {
      return { healthy: false, detail: `AWS KMS unreachable: ${e.message}` };
    }
  }

  async shutdown() {
    // Zeroize the in-memory KEK on shutdown.
    if (this._kek) {
      this._kek.fill(0);
      this._kek = null;
    }
    if (this._client?.destroy) this._client.destroy();
    this._client = null;
  }
}

module.exports = { AwsKmsKekProvider };
