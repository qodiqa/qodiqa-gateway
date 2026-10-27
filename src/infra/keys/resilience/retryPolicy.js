'use strict';

/**
 * Signing Failure Classification & Retry Policy —
 *
 * Classifies errors raised by any KMS/Vault/HSM provider call into one of a
 * fixed set of categories, and decides — from that category alone — whether
 * a bounded retry is safe.
 *
 * Categories:
 *   TIMEOUT               — the application-defined deadline (withDeadline.js) elapsed.
 *   NETWORK                — connection reset/refused/unreachable, DNS failure, socket hang-up.
 *   PROVIDER_UNAVAILABLE   — HTTP 429/503/504, Vault sealed/uninitialized, leader election in flight.
 *   AUTHENTICATION         — invalid/expired credentials (HTTP 401, bad token, AppRole rejected).
 *   AUTHORIZATION          — permission denied (HTTP 403, policy denies capability).
 *   CONFIGURATION          — provider misconfigured (missing SDK, missing env var, bad key ID).
 *   CRYPTOGRAPHIC          — signature/self-test/key-material verification failure.
 *   INVALID_REQUEST        — malformed request the provider rejected (HTTP 400/422).
 *   PERMANENT_REJECTION    — provider permanently refuses the operation (revoked/disabled key,
 *                            HTTP 404/405/410).
 *   UNKNOWN                — unrecognised; treated as permanent (fail-closed).
 *
 * Retry eligibility:
 *   Retryable:     TIMEOUT, NETWORK, PROVIDER_UNAVAILABLE
 *   Never retried: AUTHENTICATION, AUTHORIZATION, CONFIGURATION, CRYPTOGRAPHIC,
 *                  INVALID_REQUEST, PERMANENT_REJECTION, UNKNOWN
 *
 * Retry eligibility here is necessary but not sufficient — resilientSigningProvider.js
 * additionally restricts automatic retry to read-only/side-effect-free operations
 * (sign, getPublicKey, getWrappingKey, healthCheck) so that a retried call can never
 * create a duplicate or inconsistent signing operation (e.g. two key pairs, a
 * double revocation attempt racing another caller).
 */

const CATEGORIES = Object.freeze({
  TIMEOUT:              'TIMEOUT',
  NETWORK:               'NETWORK',
  PROVIDER_UNAVAILABLE:  'PROVIDER_UNAVAILABLE',
  AUTHENTICATION:        'AUTHENTICATION',
  AUTHORIZATION:         'AUTHORIZATION',
  CONFIGURATION:         'CONFIGURATION',
  CRYPTOGRAPHIC:         'CRYPTOGRAPHIC',
  INVALID_REQUEST:       'INVALID_REQUEST',
  PERMANENT_REJECTION:   'PERMANENT_REJECTION',
  UNKNOWN:               'UNKNOWN',
});

const RETRYABLE_CATEGORIES = new Set([
  CATEGORIES.TIMEOUT,
  CATEGORIES.NETWORK,
  CATEGORIES.PROVIDER_UNAVAILABLE,
]);

const NETWORK_ERROR_CODES = new Set([
  'ECONNRESET', 'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH',
  'EPIPE', 'ENOTFOUND', 'EAI_AGAIN', 'ETIMEDOUT', 'ECONNABORTED',
]);

// Matches either a bare network error code appearing in the message text
// (some SDKs surface it there rather than as err.code) or a common
// connection-failure phrase.
const _NETWORK_MESSAGE_RE = new RegExp(
  `socket hang up|network error|getaddrinfo|${[...NETWORK_ERROR_CODES].join('|')}`,
  'i',
);

function _statusOf(err) {
  return err?.statusCode ?? err?.status ?? err?.response?.statusCode ?? err?.response?.status ?? null;
}

/**
 * Classify a raw error thrown by a KekProvider/NativeSigningProvider call
 * (or by the withDeadline() wrapper) into a fixed failure category.
 *
 * @param {Error & Record<string, any>} err
 * @returns {string} one of CATEGORIES
 */
function classifyFailure(err) {
  if (!err) return CATEGORIES.UNKNOWN;

  // Our own deadline wrapper marks timeouts explicitly — never guess.
  if (err.isSigningTimeout === true || err.code === 'SIGNING_DEADLINE_EXCEEDED') {
    return CATEGORIES.TIMEOUT;
  }

  const message = String(err.message || '');
  const status  = _statusOf(err);

  if (err.code && NETWORK_ERROR_CODES.has(err.code)) {
    return CATEGORIES.NETWORK;
  }
  if (_NETWORK_MESSAGE_RE.test(message)) {
    return CATEGORIES.NETWORK;
  }

  if (status === 429 || status === 503 || status === 504) {
    return CATEGORIES.PROVIDER_UNAVAILABLE;
  }
  if (/seal(ed)?|leader election|temporarily unavailable|service unavailable|too many requests/i.test(message)) {
    return CATEGORIES.PROVIDER_UNAVAILABLE;
  }

  if (status === 401 || /unauthoriz|invalid token|authentication fail|bad credentials|approle/i.test(message)) {
    return CATEGORIES.AUTHENTICATION;
  }
  if (status === 403 || /forbidden|permission denied|access denied|not permitted/i.test(message)) {
    return CATEGORIES.AUTHORIZATION;
  }

  if (/is not installed|is not set|not configured|no .* credentials configured|no pin configured/i.test(message)) {
    return CATEGORIES.CONFIGURATION;
  }

  if (/self-test failed|signature|verify.*fail|crypto/i.test(message)) {
    return CATEGORIES.CRYPTOGRAPHIC;
  }

  if (/revoked|disabled|deletion_allowed|not found on hsm|key .* not found/i.test(message) ||
      status === 404 || status === 405 || status === 410) {
    return CATEGORIES.PERMANENT_REJECTION;
  }

  if (status === 400 || status === 422 || /malformed|invalid request/i.test(message)) {
    return CATEGORIES.INVALID_REQUEST;
  }

  // Fail-closed: an unrecognised failure is never assumed safe to retry.
  return CATEGORIES.UNKNOWN;
}

/**
 * @param {string} category  one of CATEGORIES
 * @returns {boolean}
 */
function isRetryableCategory(category) {
  return RETRYABLE_CATEGORIES.has(/** @type {any} */ (category));
}

/**
 * Determine whether a failed attempt should be retried.
 *
 * @param {object} opts
 * @param {Error}  opts.error
 * @param {number} opts.attempt      1-based attempt number just completed
 * @param {number} opts.maxAttempts
 * @returns {{ retry: boolean, category: string, reason: string }}
 */
function shouldRetry({ error, attempt, maxAttempts }) {
  const category = classifyFailure(error);

  if (attempt >= maxAttempts) {
    return { retry: false, category, reason: `attempt ${attempt} reached the maximum of ${maxAttempts}` };
  }

  if (!isRetryableCategory(category)) {
    return { retry: false, category, reason: `"${category}" is not a transient failure; retrying would not help` };
  }

  return { retry: true, category, reason: `"${category}" is transient; scheduling retry` };
}

/**
 * Exponential backoff with optional full jitter.
 * delay = min(initialBackoffMs * 2^(attempt-1), maxBackoffMs)
 *
 * @param {number}   attempt   1-based attempt number (1 = first retry delay)
 * @param {object}   policy    { initialBackoffMs, maxBackoffMs, retryJitter }
 * @param {Function} [_randomFn]  injected RNG for deterministic tests
 * @returns {number} delay in ms, always a non-negative integer
 */
function computeBackoffMs(attempt, policy, _randomFn) {
  const { initialBackoffMs, maxBackoffMs, retryJitter } = policy;
  const randomFn = typeof _randomFn === 'function' ? _randomFn : Math.random;

  const exponential = Math.min(
    initialBackoffMs * Math.pow(2, attempt - 1),
    maxBackoffMs,
  );

  const delay = retryJitter ? Math.floor(randomFn() * exponential) : Math.floor(exponential);
  return Math.max(0, delay);
}

module.exports = {
  CATEGORIES,
  classifyFailure,
  isRetryableCategory,
  shouldRetry,
  computeBackoffMs,
};
