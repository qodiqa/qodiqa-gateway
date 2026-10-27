'use strict';

/**
 * Llama streaming adapter — yields incremental text chunks via AsyncGenerator.
 *
 * Llama deployments (cloud-hosted or self-managed) expose an OpenAI-compatible
 * chat completions API — llama.js's own header describes the same deployments
 * this file targets. Like local.stream.js does for the local provider, this
 * reuses the `openai` SDK with `stream: true` rather than a bespoke parser
 * (router.stream.js's STREAMING_REGISTRY previously had no entry for
 * llama, so a streaming request silently fell back to _wrapNonStreaming() — a
 * single-chunk response, never true incremental delivery. See
 * for why llama was chosen for
 * native streaming while gemini was not).
 *
 * Called ONLY through executeStreamingProviderCall() in services/execution.stream.js.
 * Shares its lifecycle (validation, cancellation, logging, error normalization)
 * with every other adapter via services/providers/baseAdapter.js — only the
 * SDK client's own config resolution is specific to this file, mirroring
 * llama.js's non-streaming counterpart's dual (strict-then-local) URL
 * validator exactly.
 *
 * Environment variables: same as services/providers/llama.js
 *   LLAMA_BASE_URL     — required; enables this provider
 *   LLAMA_API_KEY      — optional; some deployments require authentication
 *   LLAMA_TIMEOUT_MS   — optional; timeout in ms (default 30 000)
 *
 * Yields: { delta: string }
 * Throws: canonical PROVIDER_* errors on any failure
 */

const { resolveTimeoutMs } = require('./timeout');
const { OpenAI }                    = require('openai');
const { validateProviderUrl,
        validateLocalProviderUrl, createGuardedAgent }  = require('./ssrf');
const { emit }                      = require('../logger');
const {
  TRANSPORTS, createLazyClient, runProviderStream, isOpenAICompatibleTerminalChunk,
} = require('./baseAdapter');

const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('LLAMA_TIMEOUT_MS');

// ── URL validation ────────────────────────────────────────────────────────────
// Identical dual-validator (strict public provider, then relaxed local) as
// llama.js's own _validateBaseUrl — deferred to first use (LLAMA_BASE_URL is
// deployment-specific, not a hardcoded canonical URL to check at module load).

function _validateBaseUrl(rawUrl) {
  if (!rawUrl) return { valid: false, reason: 'LLAMA_BASE_URL_NOT_SET' };

  const strict = validateProviderUrl(rawUrl);
  if (strict.valid) return strict;

  const local = validateLocalProviderUrl(rawUrl);
  if (local.valid) return local;

  return { valid: false, reason: strict.reason };
}

// ── Lazy client ───────────────────────────────────────────────────────────────

let _validated = false;

const lazyClient = createLazyClient({
  OpenAIClass: OpenAI,
  resolveConfig() {
    const baseURL = process.env.LLAMA_BASE_URL;

    if (!_validated) {
      const check = _validateBaseUrl(baseURL);
      if (!check.valid) {
        emit('CRITICAL', 'PROVIDER_CONFIG_INVALID', {
          provider: 'llama',
          reason:   check.reason,
          url:      (() => { try { return new URL(baseURL).origin; } catch { return null; } })(),     // F9R-02: never the raw value (it may carry credentials)
          message:  'LLAMA_BASE_URL failed URL validation — streaming provider cannot execute.',
        });
        const err = new Error(`PROVIDER_CONFIG_INVALID: ${check.reason}`);
        err.code  = 'PROVIDER_CONFIG_INVALID';
        throw err;
      }
      _validated = true;
    }

    const apiKey = process.env.LLAMA_API_KEY || 'llama';   // SDK requires non-empty apiKey
    return { apiKey, baseURL, timeoutMs: PROVIDER_TIMEOUT_MS, httpAgent: createGuardedAgent(baseURL) }; // item 3.8
  },
});

// ── Provider spec ─────────────────────────────────────────────────────────────

const spec = {
  name:      'llama',
  transport: TRANSPORTS.sdkStream,
  validate:  {},
  streamStartIncludesPolicyHash: false,

  transformRequest(body) {
    // R-23: optional output cap (LLAMA_MAX_TOKENS via config.js); unset → exactly { model, messages, stream }.
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('llama')?.maxTokens ?? null, body);
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
 * Stream a Llama chat completion.
 *
 * @param {{ model: string, messages: Array }}     body
 * @param {{ requestId, requestHash, policyHash }} meta
 * @param {AbortSignal}                            [signal]
 * @yields {{ delta: string }}
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callLlamaStream(body, meta, signal) {
  return runProviderStream(spec, body, meta, signal);
}

function _resetStreamClient() { lazyClient.reset(); _validated = false; }

module.exports = { callLlamaStream, _resetStreamClient, _spec: spec }; // _spec: test seam (R-23 hostedLimits.test.js)
