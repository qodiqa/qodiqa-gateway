'use strict';

/**
 * HashiCorp Vault KV v2 config-secrets provider.
 *
 * Fetches the ENTIRE application-config secret map in one read from a single
 * KV v2 path and returns it verbatim (configSecretsFactory.js is responsible
 * for filtering it down to MANAGED_CONFIG_SECRET_NAMES). Chosen as QODIQA's
 * config-secrets backend because Vault KV v2 is already a first-class,
 * production-proven part of this codebase's KMS architecture
 * (src/infra/keys/providers/vault.js's VaultKekProvider uses the identical
 * KV v2 read pattern for the KEK) — see docs/security/secrets-management.md's "Application
 * config secrets" section for the full backend-selection rationale.
 *
 * Deliberately NOT a shared module with src/infra/keys/providers/vault.js:
 * that file is KMS/KEK-provider surface (a different, already heavily-tested
 * responsibility boundary — see managedSecrets.js's header comment on why
 * this stays a separate layer). The Vault HTTP client bootstrap below is a
 * small (~30-line), intentionally-duplicated subset of vault.js's
 * _buildVaultClient() — read-only KV v2 access only, no Transit signing, no
 * re-auth timer (this provider's fetch is a single one-shot startup read,
 * not a long-lived connection that needs periodic AppRole token renewal).
 *
 * Auth env vars (shared with the KMS vault-kv/vault-transit provider — same
 * Vault deployment, a different KV v2 path/mount for app-config secrets):
 *   VAULT_ADDR       — e.g. https://vault.internal:8200
 *   VAULT_TOKEN       — static token (dev); prefer VAULT_ROLE_ID + VAULT_SECRET_ID
 *   VAULT_ROLE_ID     — AppRole role_id (preferred over static token)
 *   VAULT_SECRET_ID   — AppRole secret_id
 *   VAULT_NAMESPACE   — Vault Enterprise namespace (optional)
 *   VAULT_TLS_CA_CERT — path to custom CA PEM for mTLS (optional)
 *
 * Provider-specific env vars:
 *   QODIQA_CONFIG_SECRETS_VAULT_MOUNT — KV v2 mount (default "secret")
 *   QODIQA_CONFIG_SECRETS_VAULT_PATH  — KV v2 secret path (default "qodiqa/app-config")
 *
 * Install: npm install node-vault (already an optionalDependency — shared
 * with the KMS vault-kv/vault-transit provider).
 */

const { ConfigSecretsProvider } = require('./base');

const VAULT_ADDR_DEFAULT  = 'http://127.0.0.1:8200';
const MOUNT_DEFAULT       = 'secret';
const PATH_DEFAULT        = 'qodiqa/app-config';

function _requireVault() {
  try {
    return require('node-vault');
  } catch {
    throw new Error(
      'VaultKvConfigSecretsProvider: node-vault is not installed. ' +
      'Run: npm install node-vault',
    );
  }
}

async function _buildVaultClient(opts = {}) {
  const nodeVault = _requireVault();

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

  const roleId   = opts.roleId   || process.env.VAULT_ROLE_ID;
  const secretId = opts.secretId || process.env.VAULT_SECRET_ID;
  const token    = opts.token    || process.env.VAULT_TOKEN;

  if (roleId && secretId) {
    const authResult = await vault.approleLogin({ role_id: roleId, secret_id: secretId });
    vault.token = authResult.auth.client_token;
  } else if (token) {
    vault.token = token;
  } else {
    throw new Error(
      'VaultKvConfigSecretsProvider: no Vault credentials configured. ' +
      'Set VAULT_ROLE_ID + VAULT_SECRET_ID (preferred) or VAULT_TOKEN.',
    );
  }

  return vault;
}

class VaultKvConfigSecretsProvider extends ConfigSecretsProvider {
  constructor(opts = {}) {
    super();
    this._opts  = opts;
    this._vault = null;
    this._mount = opts.mount || process.env.QODIQA_CONFIG_SECRETS_VAULT_MOUNT || MOUNT_DEFAULT;
    this._path  = opts.path  || process.env.QODIQA_CONFIG_SECRETS_VAULT_PATH  || PATH_DEFAULT;
  }

  get name() {
    return `vault-kv:${this._mount}/${this._path}`;
  }

  async initialize() {
    this._vault = await _buildVaultClient(this._opts);
  }

  /**
   * @returns {Promise<Object<string,string>>}
   * @throws on any Vault error — unreachable, auth failure, missing secret,
   *   or a non-object payload. Never returns a partial/best-effort result on
   *   error; the caller (configSecretsFactory.js) treats any throw here as
   * fatal,'s fail-closed requirement.
   */
  async fetchSecrets() {
    if (!this._vault) throw new Error('VaultKvConfigSecretsProvider: not initialized');

    // KV v2: GET /v1/{mount}/data/{path}
    const secret = await this._vault.read(`${this._mount}/data/${this._path}`);
    const data   = secret?.data?.data;

    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error(
        `VaultKvConfigSecretsProvider: secret at "${this._mount}/data/${this._path}" ` +
        'has no usable data (expected a flat object of NAME -> value).',
      );
    }

    for (const [key, value] of Object.entries(data)) {
      if (typeof value !== 'string') {
        throw new Error(
          `VaultKvConfigSecretsProvider: secret at "${this._mount}/data/${this._path}" ` +
          `has a non-string value for key "${key}" — every managed secret must be a plain string.`,
        );
      }
    }

    return data;
  }

  async healthCheck() {
    try {
      await this._vault.health();
      return { healthy: true, detail: `Vault reachable at "${this._mount}/data/${this._path}"` };
    } catch (e) {
      return { healthy: false, detail: `Vault unreachable: ${e.message}` };
    }
  }

  async shutdown() {
    this._vault = null;
  }
}

module.exports = { VaultKvConfigSecretsProvider };
