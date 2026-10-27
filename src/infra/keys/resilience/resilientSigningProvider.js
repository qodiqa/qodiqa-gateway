'use strict';

/**
 * ResilientSigningProvider — centralized resilience layer.
 *
 * Wraps ANY concrete NativeSigningProvider (Vault Transit, PKCS#11 HSM, or
 * any future implementation) with a single, uniform resilience contract:
 * hard deadline, bounded jittered retry (read-only operations only), a
 * per-provider circuit breaker, health tracking, metrics, and structured
 * logs. No provider file (vault.js, hsm.js, ...) is modified — every
 * provider gets identical behavior for free by being wrapped once in
 * keyProviderFactory.js before it is stored/initialized.
 *
 * All resilience mechanics (timeout, retry, circuit breaker, health, metrics,
 * logging) live in executor.js's executeResilientOperation() — this class
 * only declares, per method, which name to log under and whether the
 * operation is safe to retry. See executor.js for the "centralized,
 * not duplicated" requirement this split satisfies (ResilientKekProvider
 * shares the exact same executor).
 *
 * Retry eligibility (see retryPolicy.js for the full category table):
 *   sign(), getPublicKey(), healthCheck()  — read-only / side-effect-free.
 *     Retried up to SIGNING_MAX_RETRIES times, but ONLY for failure
 *     categories classified as transient (TIMEOUT, NETWORK,
 *     PROVIDER_UNAVAILABLE). Never retried for auth/authz/crypto/permanent
 *     failures.
 *   generateKeyPair(), deprecateKey(), revokeKey() — mutating operations.
 *     Single attempt only (still get the timeout + circuit breaker + health
 *     + metrics + logs). A timeout on a mutating call is inherently
 *     ambiguous — the provider may have already applied the change — so
 *     this layer never retries them automatically; the caller (keyStore.js)
 *     already treats revocation/rotation failures as fatal to the in-flight
 *     operation and surfaces them to the operator, which is the correct
 *     response to an ambiguous outcome.
 */

const { NativeSigningProvider } = require('../providers/base');
const { withDeadline } = require('./withDeadline');
const { getCircuitBreaker } = require('./circuitBreaker');
const { getHealthMonitor } = require('./healthMonitor');
const { executeResilientOperation } = require('./executor');
const { emit } = require('../../../../services/logger');

class ResilientSigningProvider extends NativeSigningProvider {
  /**
   * @param {import('../providers/base').NativeSigningProvider} inner
   * @param {object} [config]  defaults to resilience/config.js's defaultConfig
   */
  constructor(inner, config) {
    super();
    if (!inner) throw new TypeError('ResilientSigningProvider: inner provider is required');
    this._inner  = inner;
    this._config = config || require('./config').defaultConfig;
    this._circuitBreaker = getCircuitBreaker(inner.name, this._config);
    this._health          = getHealthMonitor(inner.name, this._config);
  }

  get name() { return this._inner.name; }

  /** The wrapped provider — used by tests and diagnostics only. */
  get innerProvider() { return this._inner; }

  async initialize() {
    const startedAt = Date.now();
    try {
      await withDeadline(
        (signal) => /** @type {any} */ (this._inner).initialize(signal),
        this._config.initTimeoutMs,
        { provider: this.name, operation: 'initialize' },
      );
    } catch (err) {
      emit('ERROR', 'SIGNING_PROVIDER_INIT_FAILED', {
        provider: this.name, error: err.message, elapsedMs: Date.now() - startedAt,
      });
      throw err;
    }
    // The periodic active probe doubles as the circuit breaker's HALF_OPEN
    // recovery probe when no real signing traffic is flowing — see
    // healthCheck() below, which is fully circuit-breaker-gated.
    this._health.startActiveProbing(() => this.healthCheck());
  }

  async shutdown() {
    this._health.stopActiveProbing();
    return this._inner.shutdown();
  }

  _ctx() {
    return { providerName: this.name, config: this._config, circuitBreaker: this._circuitBreaker, health: this._health };
  }

  async sign(keyName, messageHash) {
    return executeResilientOperation(this._ctx(), 'sign', () => this._inner.sign(keyName, messageHash), { retryable: true });
  }

  async getPublicKey(keyName) {
    return executeResilientOperation(this._ctx(), 'getPublicKey', () => this._inner.getPublicKey(keyName), { retryable: true });
  }

  async generateKeyPair(keyName) {
    return executeResilientOperation(this._ctx(), 'generateKeyPair', () => this._inner.generateKeyPair(keyName), { retryable: false });
  }

  async deprecateKey(keyName) {
    return executeResilientOperation(this._ctx(), 'deprecateKey', () => this._inner.deprecateKey(keyName), { retryable: false });
  }

  async revokeKey(keyName, opts) {
    return executeResilientOperation(this._ctx(), 'revokeKey', () => this._inner.revokeKey(keyName, opts), { retryable: false });
  }

  /**
   * healthCheck() never throws — matches every concrete provider's contract
   * (they catch their own errors and resolve { healthy: false, detail }).
   * This wrapper additionally treats a resolved-but-unhealthy result as a
   * failure for circuit-breaker/health-monitor bookkeeping purposes, so a
   * provider that "responds" with healthy:false still counts toward opening
   * the circuit — not just a hard network failure would.
   */
  async healthCheck() {
    return executeResilientOperation(this._ctx(), 'healthCheck', () => this._inner.healthCheck(), {
      retryable:       true,
      resultIsFailure: (result) => !!result && result.healthy === false,
      mapError:        (err) => err.__resultPayload ?? { healthy: false, detail: `resilience layer: ${err.message}` },
    });
  }

  getRevocationCapabilities() {
    return this._inner.getRevocationCapabilities();
  }
}

module.exports = { ResilientSigningProvider };
