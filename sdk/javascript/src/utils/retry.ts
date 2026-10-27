import { QodiqaError, RateLimitError, TimeoutError } from '../errors.js';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface RetryConfig {
  maxRetries: number;
  /** Base delay in ms before first retry. Default: 500 */
  baseDelay?: number;
  /** Maximum delay cap in ms. Default: 30 000 */
  maxDelay?: number;
  /** Whether to add random jitter. Default: true */
  jitter?: boolean;
  /**
   * Replaces the default retryability test: the HTTP client passes a method/path-aware predicate so
   * a non-idempotent request is retried only when the server guarantees it was not processed.
   */
  shouldRetry?: (err: unknown) => boolean;
  /**
   * Absolute deadline (epoch ms) of the caller's time budget. A retry whose wait would end at or
   * after it is not attempted: the real error is surfaced instead of sleeping into a client-side `TimeoutError`.
   */
  deadline?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Status codes that are safe to retry */
export function isRetryable(status: number): boolean {
  return status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
}

function computeDelay(
  attempt: number,
  baseDelay: number,
  maxDelay: number,
  jitter: boolean,
): number {
  // Exponential back-off: baseDelay * 2^attempt
  const exponential = Math.min(baseDelay * Math.pow(2, attempt), maxDelay);
  if (!jitter) return exponential;
  // Full jitter: random value in [0, exponential]
  return Math.floor(Math.random() * exponential);
}

/**
 * Parses an HTTP `Retry-After` value (RFC 9110 §10.2.3): delta-seconds or an HTTP-date. Returns seconds (>= 0), or
 * `undefined` when absent or unparseable — never `NaN` (P15-02: `Number('Wed, 21 Oct …')` used to yield NaN,
 * which then became a zero-length retry delay).
 */
export function parseRetryAfter(value: string | null | undefined, now: number = Date.now()): number | undefined {
  if (value === null || value === undefined) return undefined;
  const v = value.trim();
  if (v === '') return undefined;
  if (/^\d+(\.\d+)?$/.test(v)) return Number(v);
  const date = Date.parse(v);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, Math.ceil((date - now) / 1000));
}

/**
 * The server-stated wait, in seconds, carried by an error: `RateLimitError`/`MfaLockedError.retryAfter`, else the
 * parsed `Retry-After` header the HTTP client stores in `details.retryAfter` (any status — e.g. 503
 * `SERVER_OVERLOADED`, whose `Retry-After` the admission controller always sends).
 */
export function retryAfterOf(err: unknown): number | undefined {
  if (err instanceof RateLimitError && typeof err.retryAfter === 'number' && Number.isFinite(err.retryAfter)) {
    return err.retryAfter;
  }
  if (err instanceof QodiqaError) {
    const ra = err.details?.retryAfter;
    if (typeof ra === 'number' && Number.isFinite(ra) && ra >= 0) return ra;
  }
  return undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// withRetry
// ---------------------------------------------------------------------------

/**
 * Wraps an async function with exponential back-off retry logic.
 *
 * The function is retried when it throws an error whose `status` property
 * matches a retryable HTTP status code (429, 500, 502, 503, 504), or when it
 * throws a `RateLimitError` (or as `config.shouldRetry` decides). A
 * server-stated `Retry-After` is the wait before the next attempt; when it
 * exceeds `maxDelay` (or the `deadline`) the error is thrown instead.
 *
 * @param fn       The async operation to execute.
 * @param config   Retry settings.
 * @param onRetry  Optional callback invoked before each retry attempt.
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  config: RetryConfig,
  onRetry?: (attempt: number, delay: number, error: unknown) => void,
): Promise<T> {
  const baseDelay = config.baseDelay ?? 500;
  const maxDelay = config.maxDelay ?? 30_000;
  const jitter = config.jitter ?? true;

  let lastError: unknown;

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err: unknown) {
      lastError = err;

      // Never retry timeout errors — they already exceeded the user's budget
      if (err instanceof TimeoutError) throw err;

      // Determine whether the error is retryable
      const status =
        err instanceof Error && 'status' in err
          ? (err as { status?: number }).status
          : undefined;

      const retryable = config.shouldRetry
        ? config.shouldRetry(err)
        : err instanceof RateLimitError ||
          (typeof status === 'number' && isRetryable(status));

      if (!retryable) throw err;

      // No more attempts left
      if (attempt >= config.maxRetries) break;

      // P15-01: honour a server-stated Retry-After on ANY retryable error (429, and 503 SERVER_OVERLOADED /
      // AUTH_BACKEND_UNAVAILABLE, …), not only RateLimitError. Retrying before it is refused by construction, so a wait
      // longer than maxDelay (or past the caller's deadline) surfaces the error instead of retrying early.
      let delay: number;
      const retryAfter = retryAfterOf(err);
      if (retryAfter !== undefined) {
        delay = retryAfter * 1000;
        if (delay > maxDelay) throw err;
      } else {
        delay = computeDelay(attempt, baseDelay, maxDelay, jitter);
      }
      if (config.deadline !== undefined && Date.now() + delay >= config.deadline) throw err;

      onRetry?.(attempt + 1, delay, err);
      await sleep(delay);
    }
  }

  throw lastError;
}
