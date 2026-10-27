'use strict';

/**
 * ConfigSecretsProvider — abstract base for application-config secret backends.
 *
 * Distinct from src/infra/keys/providers/base.js's KekProvider/
 * NativeSigningProvider: those supply cryptographic key material for the
 * signing-key subsystem. This contract supplies plain application
 * configuration secrets (DB/Redis passwords, API keys, webhook secrets, ...) —
 * see src/infra/configSecrets/managedSecrets.js for the exact list.
 *
 * A provider must implement fetchSecrets(): it either returns a plain object
 * of { NAME: value } for whichever managed names it can supply, or throws.
 * There is no partial-success contract — a provider that can reach its
 * backend but finds some managed names absent simply omits them from the
 * returned object (configSecretsFactory.js treats "not present in the
 * returned map" as "not managed by this backend right now", not as an
 * error) — only a genuine backend failure (unreachable, auth failure,
 * malformed response) should throw.
 */

class ConfigSecretsProvider {
  /** @returns {string} Human-readable provider identifier for observability events. */
  get name() {
    throw new Error(`${this.constructor.name}: name getter not implemented`);
  }

  /**
   * Perform any async setup (network handshake, credential exchange, etc.).
   * Called once by configSecretsFactory during process startup.
   */
  async initialize() {}

  /**
   * Fetch every managed secret this provider currently holds.
   * @returns {Promise<Object<string,string>>} a plain object of NAME -> value.
   *   Keys not present are treated as "not supplied by this backend."
   */
  async fetchSecrets() {
    throw new Error(`${this.constructor.name}: fetchSecrets() not implemented`);
  }

  /** @returns {Promise<{ healthy: boolean, detail: string }>} */
  async healthCheck() {
    throw new Error(`${this.constructor.name}: healthCheck() not implemented`);
  }

  /** Release connections / credentials on graceful shutdown. */
  async shutdown() {}
}

module.exports = { ConfigSecretsProvider };
