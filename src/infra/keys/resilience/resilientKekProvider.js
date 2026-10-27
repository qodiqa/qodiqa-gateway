'use strict';

/**
 * ResilientKekProvider — centralized resilience layer.
 *
 * Wraps ANY concrete KekProvider (local, Vault KV, AWS KMS, Azure Key Vault,
 * GCP KMS) with the same resilience contract as ResilientSigningProvider —
 * both share the exact pipeline in executor.js, so there is exactly one
 * implementation of timeout/retry/circuit-breaker/health/metrics/logging
 * for the entire KMS/Vault surface.
 *
 * Retry eligibility:
 *   getWrappingKey(), healthCheck()  — read-only. Retried up to
 *     SIGNING_MAX_RETRIES times for transient failure categories only.
 *   rotateWrappingKey()              — mutating. Single attempt only: a
 *     timeout here is ambiguous (the provider may have already rotated the
 *     key), so automatic retry could produce two live wrapping-key versions
 *     — the caller must treat a failure as needing manual verification, not
 *     something safe to blindly retry.
 */

const { KekProvider } = require('../providers/base');
const { withDeadline } = require('./withDeadline');
const { getCircuitBreaker } = require('./circuitBreaker');
const { getHealthMonitor } = require('./healthMonitor');
const { executeResilientOperation } = require('./executor');
const { emit } = require('../../../../services/logger');

class ResilientKekProvider extends KekProvider {
  /**
   * @param {import('../providers/base').KekProvider} inner
   * @param {object} [config]
   */
  constructor(inner, config) {
    super();
    if (!inner) throw new TypeError('ResilientKekProvider: inner provider is required');
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
    this._health.startActiveProbing(() => this.healthCheck());
  }

  async shutdown() {
    this._health.stopActiveProbing();
    return this._inner.shutdown();
  }

  _ctx() {
    return { providerName: this.name, config: this._config, circuitBreaker: this._circuitBreaker, health: this._health };
  }

  async getWrappingKey() {
    return executeResilientOperation(this._ctx(), 'getWrappingKey', () => this._inner.getWrappingKey(), { retryable: true });
  }

  async rotateWrappingKey() {
    return executeResilientOperation(this._ctx(), 'rotateWrappingKey', () => this._inner.rotateWrappingKey(), { retryable: false });
  }

  async healthCheck() {
    return executeResilientOperation(this._ctx(), 'healthCheck', () => this._inner.healthCheck(), {
      retryable:       true,
      resultIsFailure: (result) => !!result && result.healthy === false,
      mapError:        (err) => err.__resultPayload ?? { healthy: false, detail: `resilience layer: ${err.message}` },
    });
  }
}

module.exports = { ResilientKekProvider };
