'use strict';

/**
 * Azure Key Vault KEK Provider
 *
 * Uses Azure Key Vault wrapKey / unwrapKey operations with an AES-256 or RSA-OAEP
 * key to protect QODIQA's local 256-bit Ed25519 wrapping key.
 *
 * Architecture:
 *   - A Key Encryption Key (AKV KEK) lives permanently in Azure Key Vault.
 *   - At startup (first run): generate a local 256-bit data key, wrapKey with
 *     the AKV KEK, persist the wrapped key blob alongside the local keystore.
 *   - On subsequent startups: unwrapKey(AKV KEK, wrapped blob) to recover the
 *     256-bit KEK and load key material.
 *   - For AES-256 AKV keys: uses A256KW (AES Key Wrap).
 *   - For RSA AKV keys:     uses RSA-OAEP-256.
 *
 * Ed25519 note: Azure Key Vault does not support Ed25519 signing.  This
 * provider supplies only the wrapping key.  Signing remains local.
 *
 * Required environment variables:
 *   AZURE_KEY_VAULT_URI    — e.g. https://my-vault.vault.azure.net
 *   AZURE_KEY_VAULT_KEY_NAME — AKV key name, e.g. "qodiqa-kek"
 *   AZURE_KEY_VAULT_KEY_VER  — specific key version (optional; omit for latest)
 *   AZURE_WRAPPED_KEY_PATH   — path for wrapped KEK file (default: data/kek.wk)
 *   Azure credentials via DefaultAzureCredential (env, managed identity, CLI)
 *
 * Install: npm install @azure/keyvault-keys @azure/identity
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const { KekProvider } = require('./base');
const { assertMayGenerateWrappedKey, recordWrappedKeyProvisioned } = require('./wrappedKeyGuard'); //
const { writeFileAtomicSecure } = require('../../fs/secureWrite'); // phase 6

const WRAPPED_KEY_PATH_DEFAULT = path.join(process.cwd(), 'data', 'kek.wk');

function _requireAzure() {
  try {
    const { KeyClient, CryptographyClient } = require('@azure/keyvault-keys');
    const { DefaultAzureCredential }        = require('@azure/identity');
    return { KeyClient, CryptographyClient, DefaultAzureCredential };
  } catch {
    throw new Error(
      'AzureKeyVaultKekProvider: @azure/keyvault-keys and @azure/identity are not installed. ' +
      'Run: npm install @azure/keyvault-keys @azure/identity',
    );
  }
}

class AzureKeyVaultKekProvider extends KekProvider {
  constructor(opts = {}) {
    super();
    this._vaultUri    = opts.vaultUri    || process.env.AZURE_KEY_VAULT_URI;
    this._keyName     = opts.keyName     || process.env.AZURE_KEY_VAULT_KEY_NAME;
    this._keyVersion  = opts.keyVersion  || process.env.AZURE_KEY_VAULT_KEY_VER || '';
    this._wkPath      = opts.wrappedKeyPath || process.env.AZURE_WRAPPED_KEY_PATH || WRAPPED_KEY_PATH_DEFAULT;
    this._kek         = null;
    this._cryptoClient = null;
    this._keyType      = null;
  }

  get name() {
    return `azure:keyvault:${this._vaultUri}/${this._keyName}`;
  }

  _chooseAlgorithm(keyType) {
    if (keyType === 'RSA' || keyType === 'RSA-HSM') return 'RSA-OAEP-256';
    return 'A256KW'; // AES-256 / AES-256-HSM
  }

  async initialize() {
    if (!this._vaultUri)  throw new Error('AzureKeyVaultKekProvider: AZURE_KEY_VAULT_URI is not set');
    if (!this._keyName)   throw new Error('AzureKeyVaultKekProvider: AZURE_KEY_VAULT_KEY_NAME is not set');

    const { KeyClient, CryptographyClient, DefaultAzureCredential } = _requireAzure();
    const credential  = new DefaultAzureCredential();
    const keyClient   = new KeyClient(this._vaultUri, credential);
    const key         = this._keyVersion
      ? await keyClient.getKey(this._keyName, { version: this._keyVersion })
      : await keyClient.getKey(this._keyName);

    this._keyType     = key.keyType;
    this._cryptoClient = new CryptographyClient(key.id, credential);
    const algorithm    = this._chooseAlgorithm(this._keyType);

    if (fs.existsSync(this._wkPath)) {
      const wkB64 = fs.readFileSync(this._wkPath, 'utf8').trim();
      const wk    = Buffer.from(wkB64, 'base64');
      const res   = await this._cryptoClient.unwrapKey(algorithm, wk);
      this._kek   = Buffer.from(res.result);
    } else {
      // explicit in production (QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY=true); nothing written otherwise.
      const { explicit } = assertMayGenerateWrappedKey('AzureKeyVaultKekProvider', this._wkPath);
      const rawKek = crypto.randomBytes(32);
      const res    = await this._cryptoClient.wrapKey(algorithm, rawKek);
      const wkB64  = Buffer.from(res.result).toString('base64');
      fs.mkdirSync(path.dirname(this._wkPath), { recursive: true });
      fs.writeFileSync(this._wkPath, wkB64, { mode: 0o600, flag: 'wx' }); // never overwrite
      this._kek = rawKek;
      recordWrappedKeyProvisioned('AzureKeyVaultKekProvider', this._wkPath, explicit);
    }

    if (!this._kek || this._kek.length !== 32) {
      throw new Error(
        `AzureKeyVaultKekProvider: unwrapped KEK is ${this._kek?.length} bytes; expected 32`,
      );
    }
  }

  async getWrappingKey() {
    if (!this._kek) throw new Error('AzureKeyVaultKekProvider: not initialized');
    return this._kek;
  }

  async rotateWrappingKey() {
    const algorithm = this._chooseAlgorithm(this._keyType);
    const crypto    = require('crypto');
    const newKek    = crypto.randomBytes(32);
    const res       = await this._cryptoClient.wrapKey(algorithm, newKek);
    const wkB64     = Buffer.from(res.result).toString('base64');
    // Atomic + durable: unique 0600 temp file, fsync, rename (the fixed '.tmp' name could be stale or shared).
    writeFileAtomicSecure(this._wkPath, wkB64);
    this._kek = newKek;
    return { version: 'azure:keyvault:rotated:' + new Date().toISOString() };
  }

  async healthCheck() {
    try {
      // Attempt a lightweight operation — get the key properties.
      const { KeyClient, DefaultAzureCredential } = _requireAzure();
      const cred      = new DefaultAzureCredential();
      const keyClient = new KeyClient(this._vaultUri, cred);
      const key       = await keyClient.getKey(this._keyName);
      const enabled   = key.properties?.enabled !== false;
      return {
        healthy: enabled,
        detail:  `Azure Key Vault key "${this._keyName}" enabled: ${enabled}`,
      };
    } catch (e) {
      return { healthy: false, detail: `Azure Key Vault unreachable: ${e.message}` };
    }
  }

  async shutdown() {
    if (this._kek) {
      this._kek.fill(0);
      this._kek = null;
    }
    this._cryptoClient = null;
  }
}

module.exports = { AzureKeyVaultKekProvider };
