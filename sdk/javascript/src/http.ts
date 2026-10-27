import {
  createError,
  MfaRequiredError,
  NetworkError,
  QodiqaError,
  RateLimitError,
  TimeoutError,
} from './errors.js';
import type { ResolvedConfig } from './config.js';
import { isRetryable, parseRetryAfter, retryAfterOf, withRetry } from './utils/retry.js';
import { parseSSEStream } from './utils/sse.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
  query?: Record<string, string | number | boolean | undefined>;
  timeout?: number;
  signal?: AbortSignal;
  /** 'binary': a successful response body is returned as a Uint8Array (PDF, images) instead of being read as text. */
  responseType?: 'json' | 'binary';
}

interface PreparedFetch {
  url: string;
  init: RequestInit;
  controller: AbortController;
  timeoutId: ReturnType<typeof setTimeout> | null;
  timedOut: { value: boolean };
}

// ---------------------------------------------------------------------------
// Retry policy
// ---------------------------------------------------------------------------

const IDEMPOTENT_METHODS = new Set(['GET', 'PUT', 'DELETE']);
const CHAT_PATH = /(^|\/)ai\/chat(\/stream)?\/?$/;

/**
 * Whether a failed request may be sent again.
 *
 * - `SERVER_OVERLOADED` (503, admission control) refuses a request before it is decoded, verified or nonce-registered:
 *   always safe to resend, the artifact included.
 * - `MFA_LOCKED` is never retried — a retry cannot succeed before Retry-After.
 * - Idempotent methods (GET/PUT/DELETE): 429, 500, 502, 503, 504 as before.
 * - POST/PATCH: only a 429, which the request limiters answer before the handler runs — except on `/ai/chat`, where a
 *   429 may come from the per-identity limiter AFTER the artifact nonce was consumed (a resend would be a
 *   REPLAY_DETECTED that hides the original answer). A 5xx on a POST may have been processed; it is surfaced, not
 *   resent.
 */
export function shouldRetryRequest(err: unknown, method: string, path: string): boolean {
  if (!(err instanceof QodiqaError)) return false;
  if (err.reason === 'MFA_LOCKED') return false;
  if (err.reason === 'SERVER_OVERLOADED') return true;
  if (IDEMPOTENT_METHODS.has(method)) {
    return err instanceof RateLimitError || (typeof err.status === 'number' && isRetryable(err.status));
  }
  return err.status === 429 && !CHAT_PATH.test(path.split('?')[0]);
}

const OTP_HEADER = 'X-QODIQA-OTP';

const hasHeader = (headers: Record<string, string>, name: string): boolean =>
  Object.keys(headers).some((k) => k.toLowerCase() === name.toLowerCase());

// ---------------------------------------------------------------------------
// HttpClient
// ---------------------------------------------------------------------------

export class HttpClient {
  constructor(private readonly config: ResolvedConfig) {}

  // -------------------------------------------------------------------------
  // Public API — single JSON-response request/response calls
  // -------------------------------------------------------------------------

  async request<T>(options: RequestOptions): Promise<T> {
    try {
      return await this.attempt<T>(options);
    } catch (err: unknown) {
      // / API-04: operator MFA step-up. MFA_REQUIRED is answered before the handler runs, so resending the
      // same request once with a fresh code is safe. Never for MFA_INVALID (the code itself was wrong).
      // the resend is a fresh request (its own timer), so the wait for `otpProvider()` is not
      // charged against the first request's timeout budget.
      if (
        err instanceof MfaRequiredError &&
        err.reason === 'MFA_REQUIRED' &&
        this.config.otpProvider &&
        !hasHeader({ ...this.config.defaultHeaders, ...(options.headers ?? {}) }, OTP_HEADER)
      ) {
        const otp = String(await this.config.otpProvider());
        return await this.attempt<T>({
          ...options,
          headers: { ...(options.headers ?? {}), [OTP_HEADER]: otp },
        });
      }
      throw err;
    }
  }

  /** One request() call: a single timer covering the request and its retries. */
  private async attempt<T>(options: RequestOptions): Promise<T> {
    const { url, init, controller, timeoutId, timedOut } = this.prepareFetch(
      options,
      this.config.timeout,
    );
    const timeoutMs = options.timeout ?? this.config.timeout;
    const deadline = Date.now() + timeoutMs;
    // a request carrying an MFA code is never auto-retried. The server accepts a TOTP code at most
    // once per step, so a resend with the same code is refused as MFA_INVALID (hiding the original error) and counts
    // toward the operator's MFA lockout.
    const carriesOtp = hasHeader(init.headers as Record<string, string>, OTP_HEADER);

    const execute = async (): Promise<T> => {
      let response: Response;

      try {
        response = await fetch(url, init);
      } catch (err: unknown) {
        // If our timer fired, it's definitely a timeout regardless of error type
        if (timedOut.value || controller.signal.aborted) {
          throw new TimeoutError(
            `Request timed out after ${timeoutMs}ms: ${options.method} ${options.path}`,
          );
        }
        const isAbort = err instanceof Error && err.name === 'AbortError';
        if (isAbort) {
          throw new NetworkError(
            `Request was aborted: ${options.method} ${options.path}`,
          );
        }
        throw new NetworkError(
          `Network error on ${options.method} ${options.path}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }

      return this.parseResponse<T>(response, options.responseType === 'binary');
    };

    try {
      return await withRetry(execute, {
        maxRetries: this.config.maxRetries,
        baseDelay: 500,
        maxDelay: 30_000,
        jitter: true,
        shouldRetry: (err) => !carriesOtp && shouldRetryRequest(err, options.method, options.path),
        // P15-01: the single per-request() timer also covers the back-off waits; a wait that would outlive it
        // surfaces the real error (e.g. 503 SERVER_OVERLOADED) instead of a client-side TimeoutError.
        deadline,
      });
    } finally {
      if (timeoutId !== null) clearTimeout(timeoutId);
    }
  }

  async get<T>(path: string, options?: Partial<RequestOptions>): Promise<T> {
    return this.request<T>({ ...options, method: 'GET', path });
  }

  async post<T>(
    path: string,
    body?: unknown,
    options?: Partial<RequestOptions>,
  ): Promise<T> {
    return this.request<T>({ ...options, method: 'POST', path, body });
  }

  async put<T>(
    path: string,
    body?: unknown,
    options?: Partial<RequestOptions>,
  ): Promise<T> {
    return this.request<T>({ ...options, method: 'PUT', path, body });
  }

  async patch<T>(
    path: string,
    body?: unknown,
    options?: Partial<RequestOptions>,
  ): Promise<T> {
    return this.request<T>({ ...options, method: 'PATCH', path, body });
  }

  async delete<T>(path: string, options?: Partial<RequestOptions>): Promise<T> {
    return this.request<T>({ ...options, method: 'DELETE', path });
  }

  // -------------------------------------------------------------------------
  // Public API — SSE streaming
  // -------------------------------------------------------------------------

  /**
   * Sends `options` exactly like `request()`, but expects (on success) an
   * SSE response body and yields each parsed event as it arrives instead of
   * waiting for the response to complete.
   *
   * Deliberately not wrapped in `withRetry()` — a partially-consumed
   * streaming session is not restartable as a single idempotent HTTP call
   * the way a JSON request is (see `retry.ts`'s docstring and the server's
   * own `IDEMPOTENCY_STREAMING_UNSUPPORTED` rejection).
   *
   * No client-side timeout is applied unless the caller passes
   * `options.timeout` explicitly. Unlike `request()`, `this.config.timeout`
   * (default 30s) is intentionally NOT used as a default here — the server
   * bounds a streaming session at `STREAM_MAX_DURATION_MS` (default 5
   * minutes), and defaulting to a 30s
   * client timeout would silently truncate almost every real stream.
   */
  async *stream(options: RequestOptions): AsyncGenerator<unknown> {
    const { response, controller, timeoutId, timedOut } = await this.openStream(options);

    const clear = (): void => {
      if (timeoutId !== null) clearTimeout(timeoutId);
    };

    if (!response.body) {
      clear();
      throw new NetworkError(
        `Streaming response for ${options.method} ${options.path} had no readable body.`,
      );
    }

    let finishedNormally = false;
    try {
      const sawDone = yield* parseSSEStream(response.body);
      // P15-03: the server always writes `[DONE]` last (src/streaming/streamEnforcer.js). A body that ends
      // without it (a proxy idle timeout, a load-balancer reset that closes cleanly, a server crash between frames)
      // was truncated: surfacing that as a normal end would let a caller take a partial answer for a complete one.
      if (!sawDone) {
        throw new NetworkError(
          `Streaming response ended before the terminal [DONE] frame (truncated stream): ${options.method} ${options.path}`,
        );
      }
      finishedNormally = true;
    } catch (err: unknown) {
      if (timedOut.value) {
        throw new TimeoutError(
          `Streaming request timed out after ${options.timeout}ms: ${options.method} ${options.path}`,
        );
      }
      // A well-typed SDK error raised by parseSSEStream itself (currently:
      // ServerError for a malformed, non-"[DONE]" data frame) is already the
      // right shape to surface as-is. Anything else reaching here is a raw
      // low-level failure reading the body stream — a dropped connection, a
      // caller-triggered abort, or similar — normalized to NetworkError so
      // every error this method can throw is a QodiqaError subclass, same
      // as request().
      if (err instanceof QodiqaError) {
        throw err;
      }
      throw new NetworkError(
        `Streaming connection was interrupted: ${options.method} ${options.path}` +
          (err instanceof Error ? ` (${err.message})` : ''),
      );
    } finally {
      clear();
      // Consumer stopped iterating early (e.g. `break` in a `for await`) or
      // an error propagated out of the try block above — in either case the
      // underlying connection would otherwise be left open until the server
      // finishes writing or its own STREAM_MAX_DURATION_MS elapses. A clean
      // exhaustion of the generator (stream_completed/stream_cancelled +
      // [DONE] already read) needs no further action.
      if (!finishedNormally && !controller.signal.aborted) {
        controller.abort('stream_reader_stopped');
      }
    }
  }

  /**
   * Opens a streaming response: the fetch, the pre-stream error mapping, and the one pre-stream
   * refusal that is safe to resend — 503 `SERVER_OVERLOADED`. Admission control answers it before the artifact is
   * decoded, verified or nonce-registered (src/api/admission.js), so nothing was streamed and the same artifact may be
   * sent again after `Retry-After`; `chat.create()` already resent it, `stream()` used to surface it at once. Every
   * other pre-stream error, and anything after the stream opened, is never resent. Never for a request carrying an
   * MFA code.
   */
  private async openStream(options: RequestOptions): Promise<{
    response: Response;
    controller: AbortController;
    timeoutId: ReturnType<typeof setTimeout> | null;
    timedOut: { value: boolean };
  }> {
    const deadline = options.timeout !== undefined ? Date.now() + options.timeout : undefined;
    for (let attempt = 0; ; attempt++) {
      const remaining = deadline !== undefined ? Math.max(1, deadline - Date.now()) : undefined;
      const { url, init, controller, timeoutId, timedOut } = this.prepareFetch(
        { ...options, timeout: remaining },
        null,
      );
      const clear = (): void => {
        if (timeoutId !== null) clearTimeout(timeoutId);
      };

      let response: Response;
      try {
        response = await fetch(url, init);
      } catch (err: unknown) {
        clear();
        if (timedOut.value) {
          throw new TimeoutError(
            `Streaming request timed out after ${options.timeout}ms: ${options.method} ${options.path}`,
          );
        }
        const isAbort = err instanceof Error && err.name === 'AbortError';
        if (isAbort) {
          throw new NetworkError(
            `Streaming request was aborted: ${options.method} ${options.path}`,
          );
        }
        throw new NetworkError(
          `Network error on ${options.method} ${options.path}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }

      // a pre-stream policy/verification BLOCK now returns
      // HTTP 200 with a JSON body, not a non-2xx status — `!response.ok` alone
      // can no longer detect "enforcement failed before the SSE stream
      // opened". A real stream response is always `text/event-stream`; any
      // JSON content-type here (at ANY status) means enforcement never
      // reached the point of opening the stream. There is no sensible way to
      // represent "the stream never started" as a yielded SSE event, so this
      // still throws — same envelope, same error classification as the
      // non-streaming path ( "Response on enforcement
      // failure (before stream opens)") — just no longer gated on status.
      const contentType = response.headers.get('content-type') ?? '';
      if (response.ok && !contentType.includes('application/json')) {
        return { response, controller, timeoutId, timedOut };
      }

      clear();
      const body = await this.readBody(response);
      let err: unknown;
      try {
        this.handleErrorResponse(response, body);
      } catch (e: unknown) {
        err = e;
      }
      const carriesOtp = hasHeader(init.headers as Record<string, string>, OTP_HEADER);
      if (
        !(err instanceof QodiqaError) ||
        err.reason !== 'SERVER_OVERLOADED' ||
        carriesOtp ||
        attempt >= this.config.maxRetries
      ) {
        throw err;
      }
      const retryAfter = retryAfterOf(err);
      const delay = retryAfter !== undefined
        ? retryAfter * 1000
        : Math.floor(Math.random() * Math.min(500 * Math.pow(2, attempt), 30_000));
      if (delay > 30_000 || (deadline !== undefined && Date.now() + delay >= deadline)) throw err;
      await new Promise<void>((resolve) => setTimeout(resolve, delay));
      if (options.signal?.aborted) {
        throw new NetworkError(`Streaming request was aborted: ${options.method} ${options.path}`);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Builds the URL, headers, body, and a merged (caller signal + timeout)
   * AbortController shared by both `request()` and `stream()`.
   *
   * @param defaultTimeoutMs  Timeout to apply when `options.timeout` is not
   *   given. `null` means "no timer unless the caller opts in" — used by
   *   `stream()`; `request()` passes `this.config.timeout`.
   */
  private prepareFetch(
    options: RequestOptions,
    defaultTimeoutMs: number | null,
  ): PreparedFetch {
    const url = this.buildUrl(options.path, options.query);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': this.config.userAgent,
      Accept: 'application/json',
      ...this.config.defaultHeaders,
      ...options.headers,
    };

    const init: RequestInit = {
      method: options.method,
      headers,
    };

    if (options.body !== undefined) {
      // Deep-clone user input to prevent mutation side effects
      init.body = JSON.stringify(structuredClone(options.body));
    }

    const controller = new AbortController();
    const timedOut = { value: false };

    const timeoutMs = options.timeout ?? defaultTimeoutMs;
    let timeoutId: ReturnType<typeof setTimeout> | null = null;
    if (timeoutMs !== null) {
      timeoutId = setTimeout(() => {
        timedOut.value = true;
        controller.abort('timeout');
      }, timeoutMs);
    }

    if (options.signal) {
      // If caller's signal is already aborted, mirror it immediately
      if (options.signal.aborted) {
        controller.abort(options.signal.reason);
      } else {
        options.signal.addEventListener('abort', () => {
          controller.abort((options.signal as AbortSignal).reason);
        });
      }
    }

    init.signal = controller.signal;

    return { url, init, controller, timeoutId, timedOut };
  }

  private buildUrl(
    path: string,
    query?: Record<string, string | number | boolean | undefined>,
  ): string {
    const base = this.config.baseUrl.replace(/\/$/, '');
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    const url = new URL(`${base}${normalizedPath}`);

    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined) {
          url.searchParams.set(key, String(value));
        }
      }
    }

    return url.toString();
  }

  private async readBody(response: Response, binary = false): Promise<unknown> {
    if (binary && response.ok) return new Uint8Array(await response.arrayBuffer());
    const contentType = response.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      try {
        return await response.json();
      } catch {
        return null;
      }
    }
    const text = await response.text();
    return text || null;
  }

  private async parseResponse<T>(response: Response, binary = false): Promise<T> {
    const body = await this.readBody(response, binary);

    if (!response.ok) {
      this.handleErrorResponse(response, body);
    }

    return body as T;
  }

  private handleErrorResponse(response: Response, body: unknown): never {
    let reason = 'UNKNOWN';
    let message = `HTTP ${response.status} ${response.statusText}`;
    let requestId: string | undefined;
    let details: Record<string, unknown> = {};

    if (body !== null && typeof body === 'object') {
      const b = body as Record<string, unknown>;
      if (typeof b.reason === 'string') reason = b.reason;
      // a 2xx status here means a policy/verification BLOCK reached
      // this (streaming-only) path with no more specific message available
      // below — the generic `HTTP 200 OK` fallback above would read as "not
      // actually an error", exactly backwards for a thrown exception. Prefer
      // the reason code whenever the status can't carry the explanation.
      if (response.ok) message = `BLOCK: ${reason}`;
      if (typeof b.requestId === 'string') requestId = b.requestId;

      // Decision-style envelope: { decision, reason, details, requestId }
      if (typeof b.details === 'object' && b.details !== null) {
        details = b.details as Record<string, unknown>;
        if (typeof (details as Record<string, unknown>).message === 'string') {
          message = (details as Record<string, unknown>).message as string;
        }
      }

      // Success-style envelope with a nested error message
      if (typeof b.message === 'string') message = b.message;

      // MANAGEMENT_ERROR envelope: { status:'error', error:{code,message,details} }
      // — the management/admin/observability API surface (webhooks, attestation,
      // certification, transparency, RBAC, audit, and similar; see
      // src/api/response.js's buildFailureBody()). Distinct from the
      // ENFORCEMENT_DECISION envelope handled above (/ai/chat, /sign, /verify),
      // which has no nested `error` object — the two shapes never collide on
      // the same response, so this check is purely additive. Previously never
      // read at all (D26-7), silently dropping real diagnostic text and
      // falling back to the generic `HTTP {status} {statusText}` message.
      if (typeof b.error === 'object' && b.error !== null) {
        const errObj = b.error as Record<string, unknown>;
        if (typeof errObj.code === 'string') reason = errObj.code;
        if (typeof errObj.message === 'string') message = errObj.message;
        if (typeof errObj.details === 'object' && errObj.details !== null) {
          details = { ...details, ...(errObj.details as Record<string, unknown>) };
        }
      }

      // Flat protocol-limiter 429 body (src/core/rateLimit/middleware.js _deny429, used by /sign):
      // { error: '<CODE>', surface, dimension, reason: 'BURST'|'SUSTAINED'|..., retryAfterSeconds }. P15-04:
      // the machine code is `error`; that body's `reason` is the limiter's internal window name, which was surfacing
      // as err.reason. It stays available as details.blockedBy (compat path), with surface/dimension.
      if (typeof b.error === 'string' && /^[A-Z][A-Z0-9_]+$/.test(b.error)) {
        if (typeof b.reason === 'string') details = { ...details, blockedBy: b.reason };
        reason = b.error;
        for (const k of ['surface', 'dimension', 'retryAfterSeconds'] as const) {
          if (b[k] !== undefined && b[k] !== null) details = { ...details, [k]: b[k] };
        }
      }
    }

    // Retry-After header. P15-02: read for every body shape (a proxy's text/HTML 503 included) and parsed as
    // delta-seconds or an HTTP-date; an unparseable value is ignored rather than stored as NaN.
    const retryAfter = parseRetryAfter(response.headers.get('retry-after'));
    if (retryAfter !== undefined) {
      details = { ...details, retryAfter };
    }

    // bodies without a requestId (ServiceShuttingDown, the flat limiter 429, a proxy 502/504)
    // still carry the server's correlation id in the X-Request-ID response header.
    if (requestId === undefined) requestId = response.headers.get('x-request-id') ?? undefined;

    throw createError(response.status, reason, message, requestId, details);
  }
}
