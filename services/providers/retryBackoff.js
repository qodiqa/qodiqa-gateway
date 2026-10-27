'use strict';

/**
 * Same-provider retry backoff — (#113 / 5.8).
 *
 * Replaces the previous fixed 1000ms `RETRY_DELAY_MS` used by every LLM
 * provider adapter (anthropic.js, openai.js, gemini.js, mistral.js,
 * llama.js, local.js) with exponential backoff + full jitter, reusing the
 * same battle-tested formula already used by the KMS/signing resilience
 * path (src/infra/keys/resilience/retryPolicy.js's computeBackoffMs).
 *
 * Only the delay computation changes. Retry eligibility (_isRetryable),
 * MAX_RETRIES, and error classification are untouched per-adapter — this
 * module does not decide whether to retry, only how long to wait before
 * the next attempt once a caller has already decided to retry.
 */

const { computeBackoffMs } = require('../../src/infra/keys/resilience/retryPolicy');

const INITIAL_BACKOFF_MS = parseInt(process.env.PROVIDER_RETRY_BASE_MS || '250', 10);
const MAX_BACKOFF_MS     = parseInt(process.env.PROVIDER_RETRY_MAX_MS  || '4000', 10);
const RETRY_JITTER       = process.env.PROVIDER_RETRY_JITTER !== 'false';

/**
 * @param {number} attempt  1-based attempt number (1 = delay before the first retry)
 * @param {Function} [_randomFn]  injected RNG for deterministic tests
 * @returns {number} delay in ms
 */
function computeProviderRetryDelayMs(attempt, _randomFn) {
  return computeBackoffMs(attempt, {
    initialBackoffMs: INITIAL_BACKOFF_MS,
    maxBackoffMs:      MAX_BACKOFF_MS,
    retryJitter:        RETRY_JITTER,
  }, _randomFn);
}

module.exports = {
  computeProviderRetryDelayMs,
  INITIAL_BACKOFF_MS,
  MAX_BACKOFF_MS,
  RETRY_JITTER,
};
