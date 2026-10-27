'use strict';

const { ConfigSecretsProvider } = require('./base');

/**
 * EnvConfigSecretsProvider — the default/local/test backend.
 *
 * fetchSecrets() returns {} unconditionally: it supplies nothing, which
 * means configSecretsFactory.apply() makes NO changes to process.env for
 * this provider (see configSecretsFactory.js's apply() — deletion of
 * unmanaged names only happens for a NON-env provider). Managed secrets stay
 * exactly where they already are: whatever `.env` (via dotenv) or the
 * platform's own env injection (Kubernetes Secret, Docker secret, etc.)
 * already put in process.env.
 *
 * This is the default (`QODIQA_CONFIG_SECRETS_PROVIDER` unset or "env"),
 * preserving today's behavior byte-for-byte for local development, tests,
 * and any production deployment that intentionally injects secrets via its
 * orchestrator rather than a QODIQA-native Vault fetch.
 */
class EnvConfigSecretsProvider extends ConfigSecretsProvider {
  get name() {
    return 'env';
  }

  async fetchSecrets() {
    return {};
  }

  async healthCheck() {
    return { healthy: true, detail: 'env provider — no external backend to check' };
  }
}

module.exports = { EnvConfigSecretsProvider };
