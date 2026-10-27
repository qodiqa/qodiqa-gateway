'use strict';

/**
 * Webhook Safe Retry Policy — Component 44.6
 *
 * Determines whether a failed webhook delivery attempt may be retried.
 * Enforces three independent gates that ALL must pass before a retry is allowed:
 *
 *   Gate 1 — Idempotency:
 *     HTTP POST requests are NOT retried by default because they carry side
 *     effects.  A delivery is allowed to retry only when the enqueuing caller
 *     has explicitly set isIdempotent = true, signalling that the receiving
 *     endpoint can safely deduplicate on the X-QODIQA-Event-ID header.
 *
 *   Gate 2 — Attempt limit:
 *     The attempt counter must be strictly less than maxAttempts.  This cap
 *     is enforced here — inside the webhook retry handler — independently of
 *     the persistence recovery queue's own MAX_RETRIES constant, so the limit
 *     can be tightened via WEBHOOK_MAX_RETRY_ATTEMPTS without touching shared
 *     infrastructure.
 *
 *   Gate 3 — Failure classification:
 *     HTTP status codes are classified as PERMANENT or TRANSIENT:
 *
 *       PERMANENT (never retry):
 *         400 Bad Request          — malformed payload; retrying won't help
 *         401 Unauthorized         — wrong credentials; retrying won't help
 *         403 Forbidden            — access denied; retrying won't help
 *         404 Not Found            — endpoint gone; retrying won't help
 *         405 Method Not Allowed   — POST not accepted; retrying won't help
 *         410 Gone                 — resource permanently removed
 *         501 Not Implemented      — endpoint won't implement this
 *         all other 4xx            — client-side errors; not transient by default
 *
 *       TRANSIENT (retryable when isIdempotent):
 *         408 Request Timeout      — gateway/proxy timeout; transient
 *         409 Conflict             — may resolve on next attempt
 *         429 Too Many Requests    — rate limited; retry after backoff
 *         500 Internal Server Error — may be transient
 *         502 Bad Gateway           — upstream unavailable
 *         503 Service Unavailable   — retry-after scenario
 *         504 Gateway Timeout       — upstream timeout
 *         null (network/timeout)    — no TCP connection or TLS failure
 *
 *       UNKNOWN / unexpected:
 *         Any status not listed above is treated as PERMANENT (fail-closed).
 *
 * Exponential backoff formula:
 *   delay = min(baseMs × 2^(attempt−1), maxMs)
 *   With full jitter: delay = floor(random() × delay)
 *   Without jitter:   delay = floor(delay)
 *
 *   Note: The actual scheduling of delay intervals is performed by the
 *   persistence recovery worker (RETRY_DELAYS_MS).  computeBackoffMs() provides
 *   the canonical formula for documentation, testing, and future use in any
 *   webhook-specific scheduler.
 *
 * Public API:
 *   classifyFailure(httpStatus)         → 'TRANSIENT' | 'PERMANENT'
 *   shouldRetry(opts)                   → { retry: boolean, reason: string }
 *   computeBackoffMs(attempt, policy)   → number (milliseconds)
 */

// ── HTTP status classification ─────────────────────────────────────────────────

const TRANSIENT_STATUSES = new Set([408, 409, 429, 500, 502, 503, 504]);

const PERMANENT_STATUSES = new Set([
  400, 401, 403, 404, 405, 406, 407, 410, 411, 412,
  413, 414, 415, 416, 417, 421, 422, 423, 424, 425,
  426, 428, 431, 451,
  501, 505, 506, 507, 508, 510, 511,
]);

/**
 * Classify an HTTP response status code.
 *
 * @param {number|null} httpStatus  HTTP status, or null for network/timeout errors
 * @returns {'TRANSIENT' | 'PERMANENT'}
 */
function classifyFailure(httpStatus) {
  if (httpStatus === null || httpStatus === undefined) {
    return 'TRANSIENT'; // network error, timeout — treat as transient
  }
  if (TRANSIENT_STATUSES.has(httpStatus)) return 'TRANSIENT';
  if (PERMANENT_STATUSES.has(httpStatus)) return 'PERMANENT';
  // Unknown: fail-closed — treat as permanent so we don't retry blindly
  return 'PERMANENT';
}

// ── Retry gate ────────────────────────────────────────────────────────────────

/**
 * Determine whether a failed delivery attempt should be retried.
 *
 * All three gates must pass:
 *   1. isIdempotent must be true (POST default = no retry)
 *   2. attempt must be < maxAttempts
 *   3. failure must be classified as TRANSIENT
 *
 * @param {object}      opts
 * @param {boolean}     opts.isIdempotent  Caller-declared idempotency of this delivery
 * @param {string}      opts.httpMethod    HTTP verb ('POST', 'GET', etc.)
 * @param {number}      opts.attempt       1-based attempt number (1 = first try)
 * @param {number}      opts.maxAttempts   Maximum allowed attempts (inclusive)
 * @param {number|null} opts.httpStatus    HTTP response status, or null for network errors
 *
 * @returns {{ retry: boolean, reason: string }}
 */
function shouldRetry({ isIdempotent, httpMethod, attempt, maxAttempts, httpStatus }) {
  // Gate 1: idempotency — POST is side-effectful; never retry unless explicitly safe
  if (!isIdempotent) {
    return {
      retry:  false,
      reason: `${httpMethod ?? 'POST'} request is not marked as idempotent; retries suppressed`,
    };
  }

  // Gate 2: attempt limit
  if (attempt >= maxAttempts) {
    return {
      retry:  false,
      reason: `attempt ${attempt} has reached the maximum of ${maxAttempts}`,
    };
  }

  // Gate 3: failure classification
  const classification = classifyFailure(httpStatus);
  if (classification === 'PERMANENT') {
    const label = httpStatus !== null ? `HTTP ${httpStatus}` : 'unknown';
    return {
      retry:  false,
      reason: `${label} is a permanent failure; retrying would have no effect`,
    };
  }

  return {
    retry:  true,
    reason: `${httpStatus === null ? 'network error' : `HTTP ${httpStatus}`} is transient; scheduling retry`,
  };
}

// ── Backoff formula ───────────────────────────────────────────────────────────

/**
 * Compute the exponential backoff delay for a given attempt.
 *
 * Formula: min(baseMs × 2^(attempt−1), maxMs)
 * With jitter (full jitter): floor(random() × exponential)
 *
 * @param {number}   attempt       1-based attempt number (1 = first delivery, 2 = first retry, …)
 * @param {object}   policy        Subset of webhookSecurityConfig
 * @param {number}   policy.retryBaseDelayMs
 * @param {number}   policy.retryMaxDelayMs
 * @param {boolean}  policy.retryJitter
 * @param {Function} [_randomFn]  Injected random function (default: Math.random) — for testing
 * @returns {number}  Delay in milliseconds (always an integer ≥ 0)
 */
function computeBackoffMs(attempt, policy, _randomFn) {
  const { retryBaseDelayMs, retryMaxDelayMs, retryJitter } = policy;
  const randomFn = typeof _randomFn === 'function' ? _randomFn : Math.random;

  const exponential = Math.min(
    retryBaseDelayMs * Math.pow(2, attempt - 1),
    retryMaxDelayMs,
  );

  const delay = retryJitter
    ? Math.floor(randomFn() * exponential)
    : Math.floor(exponential);

  return Math.max(0, delay);
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  classifyFailure,
  shouldRetry,
  computeBackoffMs,
  TRANSIENT_STATUSES,
  PERMANENT_STATUSES,
};
