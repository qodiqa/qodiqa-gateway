// ---------------------------------------------------------------------------
// Base error
// ---------------------------------------------------------------------------

export interface QodiqaErrorOptions {
  status?: number;
  requestId?: string;
  details?: Record<string, unknown>;
  /** Machine-readable server reason / error code (e.g. `INVALID_SIGNATURE`, `MFA_REQUIRED`), when known. */
  reason?: string;
}

export class QodiqaError extends Error {
  readonly status: number | undefined;
  readonly requestId: string | undefined;
  readonly details: Record<string, unknown>;
  readonly reason: string | undefined;

  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message);
    this.name = this.constructor.name;
    this.status = options?.status;
    this.requestId = options?.requestId;
    this.details = options?.details ?? {};
    this.reason = options?.reason;

    // Maintain proper prototype chain in transpiled environments
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// Specific error classes
// ---------------------------------------------------------------------------

/** HTTP 401 — missing or invalid credentials */
export class AuthenticationError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, { status: 401, ...options });
  }
}

/** HTTP 403 — authenticated but not authorized */
export class AuthorizationError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, { status: 403, ...options });
  }
}

/** HTTP 400 / 422 — request payload or parameter is invalid */
export class ValidationError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, { status: 400, ...options });
  }
}

/** HTTP 404 — resource not found */
export class NotFoundError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, { status: 404, ...options });
  }
}

/** HTTP 429 — rate limit exceeded */
export class RateLimitError extends QodiqaError {
  readonly retryAfter: number | undefined;

  constructor(
    message: string,
    options?: QodiqaErrorOptions & { retryAfter?: number },
  ) {
    super(message, { status: 429, ...options });
    this.retryAfter = options?.retryAfter;
  }
}

/** HTTP 5xx — server-side error */
export class ServerError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, { status: 500, ...options });
  }
}

/**
 * The gateway's global kill switch is active (`KILL_SWITCH_ACTIVE`), or this replica cannot confirm its state (`KILL_SWITCH_STATE_UNAVAILABLE`):
 * every /sign and /ai/chat request is refused with HTTP 503 until an operator releases it. Nothing was signed, no nonce was consumed and no provider
 * was called, so retrying later is safe — but the SDK never retries it automatically (it can last hours). `retryAfter` (seconds) is the server's hint.
 */
export class KillSwitchError extends ServerError {
  public readonly retryAfter?: number;
  constructor(message: string, options?: QodiqaErrorOptions & { retryAfter?: number }) {
    super(message, { status: 503, ...options });
    this.retryAfter = options?.retryAfter;
  }
}

/** Artifact verification failed — signature invalid, expired, or tampered */
export class VerificationError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, { status: 400, ...options });
  }
}

/**
 * An enforcement `BLOCK` decision surfaced as an exception.
 *
 * `chat.create()` RETURNS a non-verification BLOCK (policy, consent, semantic, …) as its normal result — read
 * `decision`. `chat.stream()` cannot return a decision from an async generator, so a BLOCK decided before the stream
 * opened is thrown as this error (or as `VerificationError` for an artifact failure, on both paths alike).
 */
export class BlockedError extends QodiqaError {
  readonly decision = 'BLOCK' as const;
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, options);
  }
}

/**
 * HTTP 401 `MFA_REQUIRED` / `MFA_INVALID` — this operator mutation needs an MFA step-up code in `X-QODIQA-OTP`
 *. Configure `otpProvider` on the client to supply one automatically. Subclass of
 * `AuthenticationError`, so existing `catch (e instanceof AuthenticationError)` handlers still match.
 */
export class MfaRequiredError extends AuthenticationError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, options);
  }
}

/** HTTP 403 `MFA_ENROLLMENT_REQUIRED` — the operator must enroll MFA (POST /rbac/me/mfa/enroll + /confirm) first. */
export class MfaEnrollmentRequiredError extends AuthorizationError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, options);
  }
}

/** HTTP 429 `MFA_LOCKED` — too many failed MFA codes. Never retried automatically (a retry cannot succeed). */
export class MfaLockedError extends QodiqaError {
  readonly retryAfter: number | undefined;
  constructor(message: string, options?: QodiqaErrorOptions & { retryAfter?: number }) {
    super(message, { status: 429, ...options });
    this.retryAfter = options?.retryAfter;
  }
}

/** Network-level failure (DNS, connection refused, etc.) */
export class NetworkError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, options);
  }
}

/** Request exceeded the configured timeout */
export class TimeoutError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, options);
  }
}

/** Catch-all for unexpected situations */
export class UnknownError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, options);
  }
}

// ---------------------------------------------------------------------------
// Webhook verification errors
// ---------------------------------------------------------------------------

/** Webhook HMAC does not match any active secret */
export class InvalidSignatureError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, { status: 401, ...options });
  }
}

/** Webhook timestamp is outside the accepted tolerance window */
export class ExpiredSignatureError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, { status: 401, ...options });
  }
}

/** {@code X-QODIQA-Signature} header cannot be parsed */
export class MalformedSignatureError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, { status: 400, ...options });
  }
}

/** {@code X-QODIQA-Timestamp} header is missing or not a valid ISO-8601 UTC timestamp */
export class InvalidTimestampError extends QodiqaError {
  constructor(message: string, options?: QodiqaErrorOptions) {
    super(message, { status: 400, ...options });
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Maps an HTTP status code and QODIQA reason string to the appropriate
 * subclass of QodiqaError, populating all properties.
 */
/**
 * Enforcement BLOCK reasons that mean "the artifact itself was rejected" — the server's `artifact_malformed`,
 * `artifact_invalid`, `request_mismatch` and `replay` classes (src/api/blockHttpStatus.js). Mapped to
 * `VerificationError` at any HTTP status, by both `chat.create()` and `chat.stream()`.
 * Held equal to the server table by src/api/__tests__/ind14SdkContractDrift.test.js in the gateway repository.
 */
export const VERIFICATION_REASONS: ReadonlySet<string> = new Set([
  // artifact_malformed
  'MISSING_ARTIFACT', 'ARTIFACT_DECODE_FAILED', 'ARTIFACT_INVALID_TYPE', 'INVALID_JSON', 'NOT_OBJECT',
  'MISSING_SIGNATURE', 'MALFORMED_REQUEST_ID', 'VERSION_MISMATCH', 'UNSUPPORTED_PROTOCOL_VERSION', 'UNSUPPORTED_CRITICAL_CLAIM',
  // artifact_invalid
  'PROTOCOL_VERSION_TOO_LOW', 'WRONG_ARTIFACT_KIND', 'ARTIFACT_REVOKED',
  'INVALID_ARTIFACT', 'INVALID_SIGNATURE', 'SIGNATURE_UNVERIFIABLE', 'KEY_NOT_FOUND', 'KEY_REVOKED', 'KEY_ARCHIVED',
  'KEY_DEPRECATED', 'KEY_NOT_YET_ACTIVE', 'KEY_NOT_ACTIVE_AT_SIGNING_TIME', 'KEY_STATUS_UNKNOWN', 'SIGNING_TIME_UNKNOWN',
  'EXPIRED', 'FUTURE_TIMESTAMP', 'TIME_SKEW_EXCEEDED', 'INVALID_EXPIRY', 'MISSING_TIMESTAMP',
  // request_mismatch, replay
  'REQUEST_MISMATCH', 'REPLAY_DETECTED',
]);

/**
 * Maps an HTTP status code and QODIQA reason string to the appropriate
 * subclass of QodiqaError, populating all properties.
 */
export function createError(
  status: number,
  reason: string,
  message: string,
  requestId?: string,
  details?: Record<string, unknown>,
): QodiqaError {
  const opts: QodiqaErrorOptions = { status, requestId, details, reason };

  // / API-04: operator MFA step-up (src/middleware/mfaStepUp.js) — before the generic 401/403/429 branches.
  if (reason === 'MFA_REQUIRED' || reason === 'MFA_INVALID') {
    return new MfaRequiredError(message, opts);
  }
  if (reason === 'MFA_ENROLLMENT_REQUIRED') {
    return new MfaEnrollmentRequiredError(message, opts);
  }
  if (reason === 'MFA_LOCKED') {
    const retryAfter =
      typeof details?.retryAfter === 'number' ? details.retryAfter : undefined;
    return new MfaLockedError(message, { ...opts, retryAfter });
  }

  if (status === 401 || reason === 'UNAUTHORIZED' || reason === 'UNAUTHENTICATED') {
    return new AuthenticationError(message, opts);
  }

  // (SDK half): checked BEFORE the blanket status===403 branch below, so an artifact rejection is a
  // VerificationError whatever status the server's QODIQA_BLOCK_HTTP_MODE gives it (200 by default; 400/403/409 in
  // `status` mode). the list is the server's full artifact-rejection inventory, no longer 8 reasons.
  if (VERIFICATION_REASONS.has(reason)) {
    return new VerificationError(message, opts);
  }

  if (status === 403 || reason === 'FORBIDDEN') {
    return new AuthorizationError(message, opts);
  }

  if (status === 404 || reason === 'NOT_FOUND') {
    return new NotFoundError(message, opts);
  }

  if (status === 429 || reason === 'RATE_LIMITED' || reason === 'RATE_LIMIT_EXCEEDED') {
    const retryAfter =
      typeof details?.retryAfter === 'number' ? details.retryAfter : undefined;
    return new RateLimitError(message, { ...opts, retryAfter });
  }

  if (status === 400 || status === 422 || reason === 'VALIDATION_ERROR' || reason === 'INVALID_REQUEST') {
    return new ValidationError(message, opts);
  }

  // the global kill switch (HTTP 503 BLOCK) — a distinct class so callers can tell "stopped by an operator" from an outage.
  if (reason === 'KILL_SWITCH_ACTIVE' || reason === 'KILL_SWITCH_STATE_UNAVAILABLE') {
    const retryAfter = typeof details?.retryAfter === 'number' ? details.retryAfter : undefined;
    return new KillSwitchError(message, { ...opts, retryAfter });
  }

  if (status >= 500 && status < 600) {
    return new ServerError(message, opts);
  }

  // A 2xx enforcement BLOCK that reached an error path (only chat.stream(): the stream never opened).
  if (status >= 200 && status < 300) {
    return new BlockedError(message, opts);
  }

  return new UnknownError(message, opts);
}
