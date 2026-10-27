'use strict';

/**
 * Local model streaming adapter — yields incremental chunks via AsyncGenerator.
 *
 * Local runtimes (Ollama, llama.cpp, LM Studio) expose OpenAI-compatible APIs,
 * so we use the OpenAI SDK with stream: true.
 * Called ONLY through executeStreamingProviderCall() in services/execution.stream.js.
 * Shares its lifecycle (validation, cancellation, logging, error normalization)
 * with every other adapter via services/providers/baseAdapter.js — only token
 * parsing is specific to this file.
 *
 * Environment variables: same as services/providers/local.js
 *   LOCAL_BASE_URL   — required
 *   LOCAL_API_KEY    — optional
 *   LOCAL_TIMEOUT_MS — optional (default 30 000 ms)
 *
 * Yields: { delta: string }
 * Throws: canonical PROVIDER_* errors on any failure
 */

const { resolveTimeoutMs } = require('./timeout');
const { OpenAI }                   = require('openai');
const { validateLocalProviderUrl, createGuardedAgent } = require('./ssrf');
const { emit }                     = require('../logger');
const {
  TRANSPORTS, createLazyClient, runProviderStream, isOpenAICompatibleTerminalChunk,
} = require('./baseAdapter');

const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('LOCAL_TIMEOUT_MS');

let _validated = false;

const lazyClient = createLazyClient({
  OpenAIClass: OpenAI,
  resolveConfig() {
    const baseURL = process.env.LOCAL_BASE_URL;

    if (!_validated) {
      if (!baseURL) {
        const err = new Error('PROVIDER_CONFIG_INVALID');
        err.code  = 'PROVIDER_CONFIG_INVALID';
        throw err;
      }
      const check = validateLocalProviderUrl(baseURL);
      if (!check.valid) {
        emit('CRITICAL', 'PROVIDER_CONFIG_INVALID', {
          provider: 'local',
          reason:   check.reason,
          url:      (() => { try { return new URL(baseURL).origin; } catch { return null; } })(),     // F9R-02: never the raw value (it may carry credentials)
          message:  'LOCAL_BASE_URL failed URL validation — streaming provider cannot execute.',
        });
        const err = new Error('PROVIDER_CONFIG_INVALID');
        err.code  = 'PROVIDER_CONFIG_INVALID';
        throw err;
      }
      _validated = true;
    }

    return {
      apiKey:    process.env.LOCAL_API_KEY || 'local',
      baseURL,
      timeoutMs: PROVIDER_TIMEOUT_MS,
      httpAgent: createGuardedAgent(baseURL), // item 3.8
    };
  },
});

const spec = {
  name:      'local',
  transport: TRANSPORTS.sdkStream,
  validate:  {},
  streamStartIncludesPolicyHash: false,

  transformRequest(body) {
    // R-06: optional output cap (LOCAL_MAX_TOKENS via config.js); unset → the body is exactly { model, messages, stream }.
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('local')?.maxTokens ?? null, body);
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
 * Stream a local model chat completion.
 *
 * @param {{ model: string, messages: Array }}     body
 * @param {{ requestId, requestHash, policyHash }} meta
 * @param {AbortSignal}                            [signal]
 * @yields {{ delta: string }}
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callLocalStream(body, meta, signal) {
  return runProviderStream(spec, body, meta, signal);
}

function _resetStreamClient() { lazyClient.reset(); _validated = false; }

module.exports = { callLocalStream, _resetStreamClient, _spec: spec }; // _spec: test seam (R-06 localLimits.test.js)
