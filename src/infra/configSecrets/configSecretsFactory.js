'use strict';

/**
 * QODIQA Config-Secrets Provider Factory.
 *
 * Single entry point for configuring and initializing the active
 * application-config secrets backend, and for applying its output into
 * process.env before any consumer reads those variables.
 *
 * Provider selection — QODIQA_CONFIG_SECRETS_PROVIDER env var:
 *   "env"      — process.env already has the values (default; from `.env`
 *                via dotenv, or from the platform's own secret injection —
 *                Kubernetes Secret, Docker secret, etc.). No-op.
 *   "vault-kv" — HashiCorp Vault KV v2 (see ./providers/vaultKv.js).
 *
 * This is deliberately parallel to, and independent of,
 * src/infra/keys/keyProviderFactory.js (KEK/native-signing). See
 * managedSecrets.js's header comment for exactly why the two stay separate.
 *
 * Usage (in start.js, before server.js/server/startup.js is ever required —
 * several managed names are captured at MODULE-LOAD TIME by
 * services/providers/config.js and src/alerting/notification/channels/*.js,
 * so this must run and fully apply() before either is first required):
 *
 *   const csf = require('./src/infra/configSecrets/configSecretsFactory');
 *   await csf.bootstrapOrExit();
 */

const { emit } = require('../../../services/logger');
const { EnvConfigSecretsProvider }     = require('./providers/env');
const { VaultKvConfigSecretsProvider } = require('./providers/vaultKv');
const { MANAGED_CONFIG_SECRET_NAMES }  = require('./managedSecrets');

function _buildProvider(type, opts) {
  switch (type) {
    case 'env':
      return new EnvConfigSecretsProvider(opts);
    case 'vault-kv':
      return new VaultKvConfigSecretsProvider(opts);
    default: {
      const known = ['env', 'vault-kv'];
      throw new Error(
        `configSecretsFactory: unknown config-secrets provider "${type}". Valid values: ${known.join(', ')}`,
      );
    }
  }
}

// ── Module state ──────────────────────────────────────────────────────────────

let _provider     = null;
let _providerType = null;
let _initialized  = false;
let _applied      = false;

/**
 * Synchronous check for whether initialize() has already completed
 * successfully in this process — mirrors keyProviderFactory.isInitialized(),
 * used the same way by server.js's entrypoint gate.
 */
function isInitialized() {
  return _initialized;
}

function getProviderName() {
  return _provider ? _provider.name : null;
}

// ── Initialization ────────────────────────────────────────────────────────────

async function initialize(opts = {}) {
  if (_initialized) return;

  const providerType = opts.provider || process.env.QODIQA_CONFIG_SECRETS_PROVIDER || 'env';
  emit('INFO', 'CONFIG_SECRETS_PROVIDER_INIT_START', { provider: providerType });

  try {
    _provider = _buildProvider(providerType, opts);
    await _provider.initialize();
    _providerType = providerType;
    _initialized  = true;
    emit('INFO', 'CONFIG_SECRETS_PROVIDER_READY', { provider: _provider.name });
  } catch (err) {
    emit('ERROR', 'CONFIG_SECRETS_PROVIDER_INIT_FAILED', { provider: providerType, error: err.message });
    throw err;
  }
}

/**
 * Fetch secrets from the active provider and apply them to process.env.
 *
 * "env" provider: no-op — fetchSecrets() always returns {}, so no managed
 * name is ever touched. process.env keeps exactly what dotenv/the platform
 * already put there. This is what makes the default byte-identical to
 * pre-M-07 behavior.
 *
 * Any other provider: for every name in MANAGED_CONFIG_SECRET_NAMES —
 *   - present in the fetched map  → process.env[name] = fetched value
 *   - absent from the fetched map → delete process.env[name]
 * Once a non-"env" provider is selected, it becomes the EXCLUSIVE source of
 * truth for every managed name: a value dotenv already loaded from a
 * plaintext .env file is unconditionally cleared unless the secrets manager
 * itself supplies it. This is the mechanism that satisfies's "never
 * silently fall back to plaintext .env" requirement for the case where the
 * secrets manager is reachable but simply does not have a particular key —
 * downstream fail-closed checks (bootValidator.js [envValidation.js is quarantined, 2026-10-27], secretValidation.js,
 * pool.js, services/providers/config.js's hasAnyProvider(), etc.) then treat
 * that name exactly as they already treat any other absent env var.
 *
 * Throws (never partially applies to process.env) if fetchSecrets() throws —
 * the caller (bootstrapOrExit()) treats any throw here as fatal.
 */
async function apply() {
  if (!_initialized) {
    throw new Error('configSecretsFactory: initialize() must be called before apply()');
  }

  const fetched = await _provider.fetchSecrets();

  if (_providerType === 'env') {
    _applied = true;
    return { provider: _provider.name, appliedCount: 0, clearedCount: 0 };
  }

  const applied = [];
  const cleared = [];
  for (const name of MANAGED_CONFIG_SECRET_NAMES) {
    if (Object.prototype.hasOwnProperty.call(fetched, name)) {
      process.env[name] = fetched[name];
      applied.push(name);
    } else if (process.env[name] !== undefined) {
      delete process.env[name];
      cleared.push(name);
    }
  }

  _applied = true;

  // Never log fetched values here — only names/counts (see redact.js and
  // this module's own header on secret-leakage avoidance). `applied`/
  // `cleared` are variable NAMES, never values.
  emit('INFO', 'CONFIG_SECRETS_APPLIED', {
    provider:     _provider.name,
    appliedCount: applied.length,
    clearedCount: cleared.length,
  });

  return { provider: _provider.name, appliedCount: applied.length, clearedCount: cleared.length };
}

function isApplied() {
  return _applied;
}

/**
 * Run initialize() + apply() with process.exit(1) on any failure — the
 * fail-closed entry point start.js and server.js's entrypoint gate call.
 * Mirrors keyProviderFactory.bootstrapOrExit() exactly (same message shape,
 * same exit code), including on the exact failure mode's mandatory
 * negative test covers: a configured non-"env" backend that cannot be
 * reached. There is no fallback path here to a plaintext env value — a
 * thrown error always ends in process.exit(1), never in continuing with
 * whatever process.env already held.
 */
async function bootstrapOrExit() {
  const providerType = process.env.QODIQA_CONFIG_SECRETS_PROVIDER || 'env';
  try {
    await initialize();
  } catch (err) {
    process.stderr.write(
      `[FATAL] Config-secrets provider initialisation failed` +
      ` (QODIQA_CONFIG_SECRETS_PROVIDER=${providerType}): ${err.message}\n`,
    );
    process.exit(1);
  }
  try {
    await apply();
  } catch (err) {
    process.stderr.write(
      `[FATAL] Config-secrets provider failed to fetch application-config secrets` +
      ` (QODIQA_CONFIG_SECRETS_PROVIDER=${providerType}): ${err.message}\n`,
    );
    process.exit(1);
  }
}

// ── Health check ──────────────────────────────────────────────────────────────

async function healthCheck() {
  if (!_provider) return { healthy: false, detail: 'not initialized' };
  return _provider.healthCheck();
}

// ── Shutdown ──────────────────────────────────────────────────────────────────

async function shutdown() {
  if (_provider) {
    await _provider.shutdown().catch(() => {});
  }
  _provider     = null;
  _providerType = null;
  _initialized  = false;
  _applied      = false;
}

// ── Testing hooks ──────────────────────────────────────────────────────────────
//
// Deterministic provider injection for tests — no live Vault/cloud
// credentials required in CI. Mirrors services/secrets/secretsProvider.js's
// _setProvider() pattern.

/**
 * @param {import('./providers/base').ConfigSecretsProvider} provider
 * @param {string} [type] — defaults to 'test' (treated as non-"env": apply()
 *   will patch/clear managed names exactly like a real external provider).
 *   Pass 'env' to exercise the no-op path with a fake provider.
 */
function _setProvider(provider, type = 'test') {
  _provider     = provider;
  _providerType = type;
  _initialized  = true;
}

function _reset() {
  _provider     = null;
  _providerType = null;
  _initialized  = false;
  _applied      = false;
}

module.exports = {
  initialize,
  apply,
  isApplied,
  bootstrapOrExit,
  isInitialized,
  getProviderName,
  healthCheck,
  shutdown,
  _setProvider,
  _reset,
};
