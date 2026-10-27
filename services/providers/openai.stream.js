'use strict';

/**
 * OpenAI streaming adapter — yields incremental text chunks via AsyncGenerator.
 *
 * Called ONLY through executeStreamingProviderCall() in services/execution.stream.js,
 * which asserts the execution invariant before any dispatch reaches this module.
 * Shares its lifecycle (validation, cancellation, logging, error normalization)
 * with every other adapter via services/providers/baseAdapter.js — only token
 * parsing is specific to this file.
 *
 * Environment variables: same as services/providers/openai.js
 *   OPENAI_API_KEY      — required
 *   OPENAI_TIMEOUT_MS   — optional (default 30 000 ms)
 *
 * Yields: { delta: string } — incremental text delta from the provider
 * Throws: canonical PROVIDER_* errors on any failure
 */

const { resolveTimeoutMs } = require('./timeout');
const { OpenAI }              = require('openai');
const { validateProviderUrl } = require('./ssrf');
const {
  TRANSPORTS, assertUrlSafeAtLoad, createLazyClient, runProviderStream, isOpenAICompatibleTerminalChunk,
} = require('./baseAdapter');

const CANONICAL_BASE_URL  = 'https://api.openai.com/v1';
const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('OPENAI_TIMEOUT_MS');

assertUrlSafeAtLoad({
  provider:     'openai',
  url:          CANONICAL_BASE_URL,
  check:        validateProviderUrl(CANONICAL_BASE_URL),
  eventCode:    'PROVIDER_SSRF_REJECTED',
  logMessage:   'OpenAI streaming adapter base URL failed SSRF validation — module cannot load.',
  errorMessage: 'PROVIDER_SSRF_REJECTED: ',
});

const lazyClient = createLazyClient({
  OpenAIClass: OpenAI,
  resolveConfig() {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      const err = new Error('PROVIDER_AUTH_FAILED');
      err.code  = 'PROVIDER_AUTH_FAILED';
      throw err;
    }
    return { apiKey, baseURL: CANONICAL_BASE_URL, timeoutMs: PROVIDER_TIMEOUT_MS };
  },
});

const spec = {
  name:      'openai',
  transport: TRANSPORTS.sdkStream,
  validate:  {},

  transformRequest(body) {
    // R-23: optional output cap (OPENAI_MAX_TOKENS via config.js); unset → exactly { model, messages, stream }.
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('openai')?.maxTokens ?? null, body);
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
 * Stream an OpenAI chat completion.
 *
 * @param {{ model: string, messages: Array }}            body
 * @param {{ requestId, requestHash, policyHash }}        meta
 * @param {AbortSignal}                                   [signal]
 * @yields {{ delta: string }}
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callOpenAIStream(body, meta, signal) {
  return runProviderStream(spec, body, meta, signal);
}

// added for test isolation only, mirroring the identical export every
// other createLazyClient()-based adapter already has (mistral.stream.js,
// llama.stream.js, local.stream.js, local.js) — never called outside tests.
// The lazy client is otherwise cached for the process lifetime; without
// this, a test that needs a fresh client (a different mocked response, a
// different env var) would silently reuse a prior test's cached client.
function _resetClient() { lazyClient.reset(); }

module.exports = { callOpenAIStream, _resetClient, _spec: spec }; // _spec: test seam (R-23 hostedLimits.test.js)
