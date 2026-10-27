import { BaseResource } from './base.js';
import type { ChatRequest, ChatResponse, ChatStreamEvent } from '../types.js';
import { assertNonEmpty } from '../utils/validation.js';
import { ValidationError } from '../errors.js';

/** A chat request needs a non-empty `prompt` or a non-empty `messages` array, not both (the gateway answers 400 PROMPT_AND_MESSAGES). */
function assertPromptOrMessages(request: ChatRequest): void {
  const hasMessages = Array.isArray(request.messages) && request.messages.length > 0;
  const hasPrompt = typeof request.prompt === 'string' && request.prompt.trim() !== '';
  if (hasPrompt && hasMessages) throw new ValidationError('"request.prompt" and "request.messages" are mutually exclusive.');
  if (!hasPrompt && !hasMessages) throw new ValidationError('"request.prompt" must be a non-empty string (or "request.messages" a non-empty array).');
}
import { createError, VERIFICATION_REASONS } from '../errors.js';

export interface ChatStreamOptions {
  /** Aborts the stream — the underlying connection is closed immediately. */
  signal?: AbortSignal;
  /**
   * Overall time budget for the streaming session, in ms. Unset by default
   * (no client-side cap) — the server itself terminates a session after
   * `STREAM_MAX_DURATION_MS` (default 5 minutes; see
   *), so most callers never need this.
   */
  timeout?: number;
}

export interface ChatCreateOptions {
  /**
   * Optional exactly-once retry token, sent as the `Idempotency-Key` header.
   * Re-sending the same key with the same (freshly signed) request after an outcome-unknown failure (e.g. a 504)
   * replays the original result instead of running the request twice. Not accepted by `stream()` — the server
   * rejects the combination with `IDEMPOTENCY_STREAMING_UNSUPPORTED`.
   */
  idempotencyKey?: string;
}

export class ChatResource extends BaseResource {
  /**
   * Execute an AI prompt through QODIQA enforcement via `POST /ai/chat`.
   *
   * @param artifact  Base64-encoded artifact string (obtained from POST /sign).
   * @param request   Chat request containing the prompt and optional model.
   * @param options Optional `idempotencyKey`.
   */
  async create(
    artifact: string,
    request: ChatRequest,
    options?: ChatCreateOptions,
  ): Promise<ChatResponse> {
    assertNonEmpty(artifact, 'artifact');
    assertPromptOrMessages(request);

    const headers: Record<string, string> = { ...this.auth.getArtifactHeader(artifact) };
    if (options?.idempotencyKey !== undefined) {
      assertNonEmpty(options.idempotencyKey, 'options.idempotencyKey');
      headers['Idempotency-Key'] = options.idempotencyKey;
    }

    const raw = await this.http.post<ChatResponse & { response?: string }>(
      '/ai/chat',
      request,
      { headers },
    );

    // The server's wire format returns the AI output text under `response`
    // (see src/api/routes/aiChat.js); the SDK's public ChatResponse type
    // exposes it as `aiText` (see docs/sdk/javascript/api.md and README.md
    // "Quick start"). Normalize here rather than changing the wire format,
    // which curl callers already depend on.
    if (raw.aiText === undefined && typeof raw.response === 'string') {
      raw.aiText = raw.response;
    }

    // / API-02: an artifact rejection is a VerificationError on BOTH paths and in both server modes. In the
    // default QODIQA_BLOCK_HTTP_MODE=decision the server answers it with HTTP 200, so it arrives here as a result;
    // stream() already threw for the same response. Other BLOCKs (policy, consent, semantic, …) stay a normal result.
    if (raw.decision === 'BLOCK' && typeof raw.reason === 'string' && VERIFICATION_REASONS.has(raw.reason)) {
      const r = raw as unknown as { requestId?: unknown; details?: unknown };
      throw createError(
        200,
        raw.reason,
        `BLOCK: ${raw.reason}`,
        typeof r.requestId === 'string' ? r.requestId : undefined,
        typeof r.details === 'object' && r.details !== null ? (r.details as Record<string, unknown>) : {},
      );
    }

    return raw;
  }

  /**
   * Execute an AI prompt through QODIQA enforcement via `POST /ai/chat` with
   * `stream: true`, yielding each SSE event as it arrives.
   *
   * `request` MUST be the same object (or same field values) passed as
   * `request.body` to `sign.sign()` — the server binds the artifact to the
   * exact request body via `requestHash`; this method sends `{ ...request,
   * stream: true }` on the wire, so `sign.sign()` must have been called with
   * `stream: true` already present in its `request.body` too, or the server
   * rejects the call with `REQUEST_MISMATCH` before the stream opens (see
   * `VerificationError`).
   *
   * Ends iteration after the terminal `stream_completed` or
   * `stream_cancelled` event — the raw `[DONE]` sentinel that follows it on
   * the wire is not itself yielded; a body that ends WITHOUT `[DONE]` was
   * truncated in transit and throws `NetworkError`. A
   * pre-stream 503 `SERVER_OVERLOADED` is resent after `Retry-After` (the
   * nonce was not consumed); nothing else is. Breaking out of the consuming loop early
   * (or aborting `options.signal`) closes the underlying connection.
   *
   * @param artifact  Base64-encoded artifact string (obtained from POST /sign,
   *                  called with `stream: true` in its request body).
   * @param request   Chat request containing the prompt and optional model.
   * @param options   Optional cancellation/timeout.
   */
  async *stream(
    artifact: string,
    request: ChatRequest,
    options?: ChatStreamOptions,
  ): AsyncGenerator<ChatStreamEvent> {
    assertNonEmpty(artifact, 'artifact');
    assertPromptOrMessages(request);

    const headers = this.auth.getArtifactHeader(artifact);

    yield* this.http.stream({
      method: 'POST',
      path: '/ai/chat',
      body: { ...request, stream: true },
      headers,
      signal: options?.signal,
      timeout: options?.timeout,
    }) as AsyncGenerator<ChatStreamEvent>;
  }
}
