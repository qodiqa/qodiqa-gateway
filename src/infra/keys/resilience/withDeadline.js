'use strict';

/**
 * Application-defined deadline enforcement —.
 *
 * The application (not the underlying HTTP/RPC client) is the source of
 * truth for how long a signing operation may take. `withDeadline()` races
 * the supplied function against a timer and ALWAYS settles within `ms`,
 * regardless of whether the underlying provider call ever settles.
 *
 * Cancellation note: an AbortSignal is passed to `fn` so providers whose SDK
 * supports it (e.g. AWS SDK v3's `abortSignal` request option) can release
 * the in-flight socket immediately. Providers built on SDKs without abort
 * support (node-vault, pkcs11js) cannot be force-cancelled from here without
 * provider-specific code — which explicitly rules out — so for those,
 * "cancel" means QODIQA stops waiting and returns a deterministic timeout
 * error immediately; the abandoned call is left to resolve/reject in the
 * background and its result is discarded (`.catch(() => {})` below prevents
 * an unhandled rejection). This still fully satisfies the acceptance
 * criterion that "no signing request can block indefinitely" — the caller,
 * and therefore every enforcement thread waiting on it, is released on time.
 */

class SigningTimeoutError extends Error {
  constructor(ms, meta = {}) {
    const provider  = meta.provider  ? ` provider="${meta.provider}"`  : '';
    const operation = meta.operation ? ` operation="${meta.operation}"` : '';
    super(`Signing operation exceeded deadline of ${ms}ms${operation}${provider}`);
    this.name             = 'SigningTimeoutError';
    this.isSigningTimeout = true;
    this.code             = 'SIGNING_DEADLINE_EXCEEDED';
    this.timeoutMs        = ms;
    this.provider         = meta.provider  ?? null;
    this.operation        = meta.operation ?? null;
  }
}

/**
 * @param {(signal: AbortSignal) => Promise<any>} fn
 * @param {number} ms
 * @param {{ provider?: string, operation?: string }} [meta]
 * @returns {Promise<any>}
 */
function withDeadline(fn, ms, meta = {}) {
  const controller = new AbortController();
  let timer;

  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new SigningTimeoutError(ms, meta));
    }, ms);
    if (timer.unref) timer.unref();
  });

  const work = Promise.resolve().then(() => fn(controller.signal));
  work.catch(() => { /* swallow post-timeout settlement — see module doc */ });

  return Promise.race([work, timeoutPromise]).finally(() => clearTimeout(timer));
}

module.exports = { withDeadline, SigningTimeoutError };
