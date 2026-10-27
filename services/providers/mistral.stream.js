'use strict';

/**
 * Mistral streaming adapter — yields incremental text chunks via AsyncGenerator.
 *
 * Mistral exposes an OpenAI-compatible chat completions API (mistral.js's own
 * header), so — exactly like local.stream.js does for the local provider —
 * this reuses the `openai` SDK with `stream: true` rather than hand-rolling a
 * second SSE parser (router.stream.js's STREAMING_REGISTRY previously
 * had no entry for mistral at all, so a streaming request silently fell back
 * to _wrapNonStreaming() — a single-chunk response, never true incremental
 * delivery. for why mistral
 * was chosen for native streaming while gemini was not).
 *
 * Called ONLY through executeStreamingProviderCall() in services/execution.stream.js.
 * Shares its lifecycle (validation, cancellation, logging, error normalization)
 * with every other adapter via services/providers/baseAdapter.js — only the
 * SDK client's own config resolution is specific to this file, mirroring
 * mistral.js's non-streaming counterpart exactly.
 *
 * Environment variables: same as services/providers/mistral.js
 *   MISTRAL_API_KEY     — required; enables this provider
 *   MISTRAL_BASE_URL    — optional; defaults to https://api.mistral.ai/v1
 *   MISTRAL_TIMEOUT_MS  — optional; timeout in ms (default 30 000)
 *
 * Yields: { delta: string }
 * Throws: canonical PROVIDER_* errors on any failure
 */

const { resolveTimeoutMs } = require('./timeout');
const { OpenAI }              = require('openai');
const { validateProviderUrl } = require('./ssrf');
const {
  TRANSPORTS, assertUrlSafeAtLoad, createLazyClient, runProviderStream, isOpenAICompatibleTerminalChunk,
} = require('./baseAdapter');

// ── Configuration ─────────────────────────────────────────────────────────────

const DEFAULT_BASE_URL    = 'https://api.mistral.ai/v1';
const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('MISTRAL_TIMEOUT_MS');

// ── Base URL validation ───────────────────────────────────────────────────────
// Mirrors mistral.js's own unconditional, module-load-time SSRF check (
// Finding A) — the streaming adapter must not be a weaker-guarded second copy
// of the same base URL.

const _effectiveUrl = process.env.MISTRAL_BASE_URL || DEFAULT_BASE_URL;

assertUrlSafeAtLoad({
  provider:     'mistral',
  url:          _effectiveUrl,
  check:        validateProviderUrl(_effectiveUrl),
  eventCode:    'PROVIDER_CONFIG_INVALID',
  logMessage:   'Mistral streaming adapter base URL failed SSRF validation — module cannot load.',
  errorMessage: 'PROVIDER_CONFIG_INVALID: mistral base URL ',
});

// ── Lazy client ───────────────────────────────────────────────────────────────

const lazyClient = createLazyClient({
  OpenAIClass: OpenAI,
  resolveConfig() {
    const apiKey  = process.env.MISTRAL_API_KEY;
    const baseURL = process.env.MISTRAL_BASE_URL || DEFAULT_BASE_URL;

    if (!apiKey) {
      const err = new Error('PROVIDER_AUTH_FAILED');
      err.code  = 'PROVIDER_AUTH_FAILED';
      throw err;
    }

    return { apiKey, baseURL, timeoutMs: PROVIDER_TIMEOUT_MS };
  },
});

// ── Provider spec ─────────────────────────────────────────────────────────────

const spec = {
  name:      'mistral',
  transport: TRANSPORTS.sdkStream,
  validate:  {},
  streamStartIncludesPolicyHash: false,

  transformRequest(body) {
    // R-23: optional output cap (MISTRAL_MAX_TOKENS via config.js); unset → exactly { model, messages, stream }.
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('mistral')?.maxTokens ?? null, body);
    return { model: body.model, messages: body.messages, stream: true, ...(maxTokens ? { max_tokens: maxTokens } : {}) };
  },

  async* execute(payload, ctx) {
    const client    = lazyClient.get();
    const sdkStream = await client.chat.completions.create(payload, ctx.signal ? { signal: ctx.signal } : undefined);
    // create() resolves only on an HTTP 2xx — the provider accepted the call; any later failure (including an
    // in-band `data: {"error":...}` frame before the first token) must never be failed over.
    if (typeof ctx.markStreamAccepted === 'function') ctx.markStreamAccepted();
    yield* sdkStream;
  },

  // a stream is complete only once a chunk carries a non-null choices.finish_reason (the OpenAI-
  // compatible protocol's terminal signal; see baseAdapter.isOpenAICompatibleTerminalChunk). A connection that
  // ends before it is a truncated stream and fails as PROVIDER_UNAVAILABLE (providerMayHaveExecuted) — never success.
  isTerminalChunk: isOpenAICompatibleTerminalChunk,

  parseChunk(chunk) {
    return chunk.choices?.[0]?.delta?.content;
  },
};

/**
 * Stream a Mistral chat completion.
 *
 * @param {{ model: string, messages: Array }}     body
 * @param {{ requestId, requestHash, policyHash }} meta
 * @param {AbortSignal}                            [signal]
 * @yields {{ delta: string }}
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callMistralStream(body, meta, signal) {
  return runProviderStream(spec, body, meta, signal);
}

// Export for testing
function _resetStreamClient() { lazyClient.reset(); }

module.exports = { callMistralStream, _resetStreamClient, _spec: spec }; // _spec: test seam (R-23 hostedLimits.test.js)
