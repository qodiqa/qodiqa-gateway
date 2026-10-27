'use strict';

/**
 * HashiCorp Vault Provider
 *
 * Implements BOTH interfaces from base.js:
 *
 *   VaultKekProvider        — KekProvider backed by Vault KV v2.
 *     Stores the 256-bit KEK as a Vault secret.  The KEK itself is protected by
 *     Vault's transit/seal encryption; access is gated by AppRole or Kubernetes
 *     auth.  Supports automatic versioning via KV v2.
 *
 *   VaultTransitSigningProvider — NativeSigningProvider backed by Vault Transit.
 *     Ed25519 key material is generated and stored inside Vault; private key
 *     bytes never leave the Vault boundary.  QODIQA signs by sending the
 *     pre-hashed envelope to POST /v1/transit/sign/:key and receives a
 *     base64-encoded Ed25519 signature.
 *
 * Required environment variables:
 *   VAULT_ADDR          — e.g. https://vault.internal:8200
 *   VAULT_TOKEN         — static token (dev); prefer VAULT_ROLE_ID + VAULT_SECRET_ID
 *   VAULT_ROLE_ID       — AppRole role_id (preferred over static token)
 *   VAULT_SECRET_ID     — AppRole secret_id
 *   VAULT_NAMESPACE     — Vault Enterprise namespace (optional)
 *   VAULT_KEK_PATH      — KV v2 secret path, e.g. "qodiqa/kek"
 *   VAULT_KEK_MOUNT     — KV v2 mount, default "secret"
 *   VAULT_TRANSIT_MOUNT — Transit mount, default "transit"
 *   VAULT_TLS_CA_CERT   — path to custom CA PEM for mTLS (optional)
 *
 * Install: npm install node-vault
 */

const {
  KekProvider,
  NativeSigningProvider,
  REVOCATION_METHODS,
  pickStrongestRevocationMethod,
} = require('./base');
const _defaultTaskRunner = require('../../../runtime/backgroundTasks/BackgroundTaskRunner');

const VAULT_ADDR_DEFAULT   = 'http://127.0.0.1:8200';
const TRANSIT_MOUNT_DEFAULT = 'transit';
const KEK_MOUNT_DEFAULT     = 'secret';
const QODIQA_KEY_PREFIX     = 'qodiqa';

// ── Shared Vault HTTP client ──────────────────────────────────────────────────

function _requireVault() {
  try {
    return require('node-vault');
  } catch {
    throw new Error(
      'VaultProvider: node-vault is not installed. ' +
      'Run: npm install node-vault',
    );
  }
}

async function _buildVaultClient(opts = {}) {
  const nodeVault = _requireVault();
  const https     = opts.tlsCa ? require('https') : undefined;

  /** @type {Record<string, any>} */
  const clientOpts = {
    apiVersion: 'v1',
    endpoint:   opts.addr || process.env.VAULT_ADDR || VAULT_ADDR_DEFAULT,
    ...(opts.namespace || process.env.VAULT_NAMESPACE
      ? { namespace: opts.namespace || process.env.VAULT_NAMESPACE }
      : {}),
  };

  if (opts.tlsCa || process.env.VAULT_TLS_CA_CERT) {
    const fs = require('fs');
    const caPath = opts.tlsCa || process.env.VAULT_TLS_CA_CERT;
    clientOpts.requestOptions = {
      agentOptions: { ca: fs.readFileSync(caPath) },
    };
  }

  const vault = nodeVault(clientOpts);

  // Auth: AppRole preferred, static token fallback.
  const roleId    = opts.roleId    || process.env.VAULT_ROLE_ID;
  const secretId  = opts.secretId  || process.env.VAULT_SECRET_ID;
  const token     = opts.token     || process.env.VAULT_TOKEN;

  if (roleId && secretId) {
    const authResult = await vault.approleLogin({ role_id: roleId, secret_id: secretId });
    vault.token = authResult.auth.client_token;
  } else if (token) {
    vault.token = token;
  } else {
    throw new Error(
      'VaultProvider: no Vault credentials configured. ' +
      'Set VAULT_ROLE_ID + VAULT_SECRET_ID (preferred) or VAULT_TOKEN.',
    );
  }

  return vault;
}

// ── Vault KV KEK Provider ─────────────────────────────────────────────────────

class VaultKekProvider extends KekProvider {
  constructor(opts = {}) {
    super();
    this._opts    = opts;
    this._vault   = null;
    this._kek     = null;
    this._mount   = opts.kekMount   || process.env.VAULT_KEK_MOUNT   || KEK_MOUNT_DEFAULT;
    this._path    = opts.kekPath    || process.env.VAULT_KEK_PATH    || `${QODIQA_KEY_PREFIX}/kek`;
    // Re-auth interval in ms (AppRole tokens have a TTL).
    this._reAuthMs = opts.reAuthMs  || 3_600_000; // 1 hour default
    this._reAuthTimer = null;
  }

  get name() {
    return `vault:kv:${this._path}`;
  }

  async initialize() {
    this._vault = await _buildVaultClient(this._opts);
    this._kek   = await this._fetchKek();
    this._scheduleReAuth();
  }

  async _fetchKek() {
    // KV v2: GET /v1/{mount}/data/{path}
    const secret = await this._vault.read(`${this._mount}/data/${this._path}`);
    const raw    = secret?.data?.data?.kek;
    if (!raw) {
      throw new Error(
        `VaultKekProvider: secret at "${this._mount}/data/${this._path}" ` +
        `has no "kek" field`,
      );
    }
    if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
      throw new Error(
        `VaultKekProvider: kek at "${this._path}" must be 64 hex characters`,
      );
    }
    return Buffer.from(raw, 'hex');
  }

  _scheduleReAuth() {
    if (this._reAuthTimer) clearInterval(this._reAuthTimer);
    const taskRunner = this._opts._taskRunner || _defaultTaskRunner;
    // Finding 3.6: runs through BackgroundTaskRunner for consistent
    // isolation/logging/metrics (replaces the previous local try/catch).
    // Non-fatal in-memory rotation failure; stale KEK cache remains until
    // next cycle.
    this._reAuthTimer = setInterval(() => {
      taskRunner.runTask('vault-kek-reauth', async () => {
        this._vault = await _buildVaultClient(this._opts);
        this._kek   = await this._fetchKek();
      }).catch(() => { /* 'critical' task never rejects; belt-and-suspenders */ });
    }, this._reAuthMs);
    if (this._reAuthTimer.unref) this._reAuthTimer.unref();
  }

  async getWrappingKey() {
    if (!this._kek) throw new Error('VaultKekProvider: not initialized');
    return this._kek;
  }

  async rotateWrappingKey() {
    // Write a new KEK version to KV v2.  The caller is responsible for
    // re-encrypting all local key material under the new KEK.
    const crypto    = require('crypto');
    const newKekHex = crypto.randomBytes(32).toString('hex');
    await this._vault.write(`${this._mount}/data/${this._path}`, {
      data: { kek: newKekHex },
    });
    this._kek = Buffer.from(newKekHex, 'hex');
    // KV v2 auto-versions — read secret metadata for the version number.
    const meta = await this._vault.read(`${this._mount}/metadata/${this._path}`);
    const version = String(meta?.data?.current_version ?? 'unknown');
    return { version };
  }

  async healthCheck() {
    try {
      await this._vault.health();
      const kekOk = this._kek !== null;
      return { healthy: kekOk, detail: kekOk ? 'Vault reachable; KEK loaded' : 'Vault reachable; KEK not loaded' };
    } catch (e) {
      return { healthy: false, detail: `Vault unreachable: ${e.message}` };
    }
  }

  async shutdown() {
    if (this._reAuthTimer) {
      clearInterval(this._reAuthTimer);
      this._reAuthTimer = null;
    }
    this._kek = null;
  }
}

// ── Vault Transit Native Signing Provider ─────────────────────────────────────

// Vault Transit returns an ed25519 key's
// `public_key` as base64 of the RAW 32-byte key, not as PEM (PEM is what it returns for RSA/ECDSA keys), so
// parsing it as PEM threw for every real Vault. Accept both forms; anything else is refused.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function _transitPublicKeyToDer(publicKey) {
  const crypto = require('crypto');
  if (typeof publicKey !== 'string' || publicKey.length === 0) {
    throw new Error('VaultTransitSigningProvider: Vault returned no public_key');
  }
  let keyObj;
  if (publicKey.includes('-----BEGIN')) {
    keyObj = crypto.createPublicKey({ key: publicKey, format: 'pem' });
  } else {
    const raw = Buffer.from(publicKey, 'base64');
    if (raw.length !== 32 || raw.toString('base64') !== publicKey) {
      throw new Error('VaultTransitSigningProvider: public_key is neither PEM nor a base64 raw 32-byte ed25519 key');
    }
    keyObj = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
  }
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new Error(`VaultTransitSigningProvider: expected an ed25519 key, got ${keyObj.asymmetricKeyType}`);
  }
  return Buffer.from(keyObj.export({ type: 'spki', format: 'der' }));
}

class VaultTransitSigningProvider extends NativeSigningProvider {
  constructor(opts = {}) {
    super();
    this._opts   = opts;
    this._vault  = null;
    this._mount  = opts.transitMount || process.env.VAULT_TRANSIT_MOUNT || TRANSIT_MOUNT_DEFAULT;
    this._reAuthMs    = opts.reAuthMs    || 3_600_000;
    this._reAuthTimer = null;
  }

  get name() {
    return `vault:transit:${this._mount}`;
  }

  async initialize() {
    this._vault = await _buildVaultClient(this._opts);
    this._scheduleReAuth();
  }

  _scheduleReAuth() {
    if (this._reAuthTimer) clearInterval(this._reAuthTimer);
    const taskRunner = this._opts._taskRunner || _defaultTaskRunner;
    // Finding 3.6: runs through BackgroundTaskRunner for consistent
    // isolation/logging/metrics (replaces the previous local try/catch).
    this._reAuthTimer = setInterval(() => {
      taskRunner.runTask('vault-transit-reauth', async () => {
        this._vault = await _buildVaultClient(this._opts);
      }).catch(() => { /* 'critical' task never rejects; belt-and-suspenders */ });
    }, this._reAuthMs);
    if (this._reAuthTimer.unref) this._reAuthTimer.unref();
  }

  _transitKeyPath(keyName) {
    // Sanitise: Vault Transit key names are alphanumeric + hyphens.
    return keyName.replace(/[^A-Za-z0-9_-]/g, '-');
  }

  async generateKeyPair(keyName) {
    const vaultKeyName = this._transitKeyPath(keyName);
    // Create a Vault Transit key of type ed25519.
    // Vault auto-creates the key pair internally; private key never leaves Vault.
    await this._vault.write(`${this._mount}/keys/${vaultKeyName}`, {
      type:                   'ed25519',
      exportable:             false,   // private key must never leave Vault
      allow_plaintext_backup: false,
    });
    // Retrieve the public key from Vault (exported public key, not private).
    const info = await this._vault.read(`${this._mount}/keys/${vaultKeyName}`);
    const latestVersion = info.data.latest_version;
    const publicKeyDer  = _transitPublicKeyToDer(info.data.keys[latestVersion].public_key);
    return { publicKeyDer, keyName: vaultKeyName };
  }

  async sign(keyName, messageHash) {
    if (!Buffer.isBuffer(messageHash) || messageHash.length !== 32) {
      throw new TypeError('VaultTransitSigningProvider.sign: messageHash must be a 32-byte Buffer');
    }
    const vaultKeyName = this._transitKeyPath(keyName);
    // Vault Transit sign endpoint expects base64-encoded input. QODIQA pre-hashes
    // (SHA-256("QODIQA::ARTIFACT::V1" || payload)) and the contract (base.js) is a PURE Ed25519 signature over
    // those 32 bytes — what an ed25519 Transit key produces for plain `input`.:
    // the previous `hash_algorithm: 'none', prehashed: true` is RSA-only in Vault and was rejected for every
    // ed25519 key ("hash_algorithm=none requires both prehashed=true and signature_algorithm=pkcs1v15"); and
    // `prehashed` on an ed25519 key would select Ed25519ph, a different signature QODIQA verifiers reject.
    const result = await this._vault.write(`${this._mount}/sign/${vaultKeyName}`, {
      input: messageHash.toString('base64'),
    });
    // Vault returns "vault:v1:<base64_sig>".
    const sigFull = result.data.signature;
    const sigB64  = sigFull.replace(/^vault:v\d+:/, '');
    return Buffer.from(sigB64, 'base64');
  }

  async getPublicKey(keyName) {
    const vaultKeyName = this._transitKeyPath(keyName);
    const info         = await this._vault.read(`${this._mount}/keys/${vaultKeyName}`);
    if (!info || !info.data) {
      throw new Error(`VaultTransitSigningProvider: key "${vaultKeyName}" not found`);
    }
    const latestVersion = info.data.latest_version;
    const publicKeyDer  = _transitPublicKeyToDer(info.data.keys[latestVersion].public_key);
    const minDeletion   = info.data.min_decryption_version;
    const status        = minDeletion > latestVersion ? 'revoked' : 'active';
    return { publicKeyDer, status };
  }

  async deprecateKey(keyName) {
    await this._disableFutureSigning(keyName);
  }

  // Advances min_encryption_version past the key's latest version, so Vault
  // refuses new sign operations for this key while historical verification
  // (which pins an explicit key version) still works. Shared by
  // deprecateKey() (soft, rotation-time retirement) and revokeKey with
  // method 'disable' (the strongest method available when the operator's
  // Vault policy denies the delete-key capability).
  async _disableFutureSigning(keyName) {
    const vaultKeyName = this._transitKeyPath(keyName);
    const info    = await this._vault.read(`${this._mount}/keys/${vaultKeyName}`);
    const current = info.data.latest_version;
    await this._vault.write(`${this._mount}/keys/${vaultKeyName}/config`, {
      min_encryption_version: current + 1,
    });
    return { minEncryptionVersion: current + 1, keyName: vaultKeyName };
  }

  /** @returns {string[]} — Vault Transit can hard-delete or soft-disable a key. */
  getRevocationCapabilities() {
    return [REVOCATION_METHODS.DESTROY, REVOCATION_METHODS.DISABLE];
  }

  /**
   * Revoke a Vault Transit key at the provider boundary.
   *
   *   method 'destroy' (default — the strongest method this provider supports):
   *     Permanently deletes the key. Vault Transit keys are delete-protected
   *     by default (`deletion_allowed` starts false); this sets that flag and
   *     then deletes the key. Irreversible.
   *
   *   method 'disable':
   *     Advances min_encryption_version so Vault refuses any new signature
   *     from this key without destroying key material. Use when the
   *     operator's Vault policy denies the delete-key capability — the
   *     caller (keyStore.js) falls back to this only when 'destroy' is not
   *     in getRevocationCapabilities(), which for this provider it always is;
   *     an explicit opts.method override exists for operator-directed use.
   *
   * @param {string} keyName
   * @param {{ method?: string }} [opts]
   * @returns {Promise<{ method: string, provider: string, revokedAt: string, providerResponse: object }>}
   */
  async revokeKey(keyName, opts = {}) {
    const method = opts.method || pickStrongestRevocationMethod(this.getRevocationCapabilities());
    const vaultKeyName = this._transitKeyPath(keyName);

    try {
      if (method === REVOCATION_METHODS.DISABLE) {
        const detail = await this._disableFutureSigning(keyName);
        return { method, provider: this.name, revokedAt: new Date().toISOString(), providerResponse: detail };
      }

      if (method !== REVOCATION_METHODS.DESTROY) {
        throw new Error(`unsupported revocation method "${method}" — supported: ${this.getRevocationCapabilities().join(', ')}`);
      }

      // Vault Transit keys are delete-protected by default; deletion_allowed
      // must be flipped on before DELETE will succeed.
      await this._vault.write(`${this._mount}/keys/${vaultKeyName}/config`, {
        deletion_allowed: true,
      });
      await this._vault.delete(`${this._mount}/keys/${vaultKeyName}`);
      return {
        method, provider: this.name, revokedAt: new Date().toISOString(),
        providerResponse: { deleted: true, keyName: vaultKeyName },
      };
    } catch (err) {
      /** @type {any} */ const wrapped = new Error(
        `VaultTransitSigningProvider.revokeKey: method "${method}" failed for key "${vaultKeyName}": ${err.message}`,
      );
      wrapped.cause  = err;
      wrapped.method = method;
      throw wrapped;
    }
  }

  async healthCheck() {
    try {
      await this._vault.health();
      return { healthy: true, detail: `Vault Transit mount "${this._mount}" reachable` };
    } catch (e) {
      return { healthy: false, detail: `Vault unreachable: ${e.message}` };
    }
  }

  async shutdown() {
    if (this._reAuthTimer) {
      clearInterval(this._reAuthTimer);
      this._reAuthTimer = null;
    }
    this._vault = null;
  }
}

module.exports = { VaultKekProvider, VaultTransitSigningProvider };
