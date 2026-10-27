'use strict';

/**
 * OpenAI provider — production execution handler.
 *
 * Called ONLY through executeProviderCall() in services/execution.js, which
 * asserts the execution invariant before dispatching here.  No enforcement
 * logic lives in this file — this file supplies only the OpenAI-specific
 * configuration (endpoint, auth, request/response shape) to the shared
 * execution pipeline in services/providers/baseAdapter.js, which owns SSRF
 * validation, outbound request validation, retry policy, timeout/cancellation,
 * error normalization, and structured telemetry.
 *
 * Returns a normalized ProviderResponse (see services/providers/normalize.js).
 *
 * SSRF protection:
 *   CANONICAL_BASE_URL is hardcoded and validated against the SSRF policy at
 *   module load time.  This overrides any OPENAI_BASE_URL environment variable
 *   the SDK would otherwise read, preventing dynamic base-URL injection.
 *   If validation fails the module throws immediately — the server cannot start.
 *
 * Environment variables:
 *   OPENAI_API_KEY     — required; validated at server startup (server.js)
 *   OPENAI_TIMEOUT_MS  — optional; outbound call timeout (default 30 000 ms)
 *
 * Error normalization — canonical codes:
 *   PROVIDER_TIMEOUT           timeout on connect or read
 *   PROVIDER_UNAVAILABLE       network error or 5xx from OpenAI
 *   PROVIDER_RATE_LIMITED      HTTP 429 from OpenAI
 *   PROVIDER_AUTH_FAILED       HTTP 401/403 — configuration error
 *   PROVIDER_INVALID_REQUEST   HTTP 400/422 or malformed outbound body
 *   PROVIDER_MODEL_NOT_ALLOWED requested model is not in the allowlist
 *   PROVIDER_REQUEST_REJECTED  payload exceeds size/count limits
 *   PROVIDER_INVALID_RESPONSE  response shape does not match contract
 */

const { resolveTimeoutMs } = require('./timeout');
const { OpenAI }              = require('openai');
const { validateProviderUrl } = require('./ssrf');
const { emit }                = require('../logger');
const {
  MAX_MESSAGES, MAX_CONTENT_BYTES, TRANSPORTS,
  assertUrlSafeAtLoad, createLazyClient, runProviderCall,
} = require('./baseAdapter');

// ── SSRF: canonical base URL ──────────────────────────────────────────────────

const CANONICAL_BASE_URL = 'https://api.openai.com/v1';

assertUrlSafeAtLoad({
  provider:     'openai',
  url:          CANONICAL_BASE_URL,
  check:        validateProviderUrl(CANONICAL_BASE_URL),
  eventCode:    'PROVIDER_SSRF_REJECTED',
  logMessage:   'Hardcoded provider base URL failed SSRF validation — module cannot load.',
  errorMessage: 'PROVIDER_SSRF_REJECTED: ',
});

// ── Configuration ─────────────────────────────────────────────────────────────

const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('OPENAI_TIMEOUT_MS');

// ── Lazy client ───────────────────────────────────────────────────────────────

const lazyClient = createLazyClient({
  OpenAIClass: OpenAI,
  resolveConfig() {
    if (process.env.OPENAI_BASE_URL) {
      emit('WARN', 'PROVIDER_BASE_URL_OVERRIDE_IGNORED', {
        message:          'OPENAI_BASE_URL is set but ignored — baseURL is hardcoded for SSRF protection.',
        canonicalBaseUrl: CANONICAL_BASE_URL,
      });
    }

    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      const err = new Error('PROVIDER_AUTH_FAILED');
      err.code  = 'PROVIDER_AUTH_FAILED';
      throw err;
    }

    return { apiKey, baseURL: CANONICAL_BASE_URL, timeoutMs: PROVIDER_TIMEOUT_MS };
  },
});

// ── Provider spec ─────────────────────────────────────────────────────────────

const spec = {
  name:      'openai',
  transport: TRANSPORTS.sdk,
  validate:  {},
  completeLogIncludesHash: true,

  getExecutionContext() {
    return { client: lazyClient.get() };
  },

  transformRequest(body) {
    // R-23: optional output cap (OPENAI_MAX_TOKENS via config.js); unset → the body is exactly { model, messages }.
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('openai')?.maxTokens ?? null, body);
    return { model: body.model, messages: body.messages, ...(maxTokens ? { max_tokens: maxTokens } : {}) };
  },

  execute(payload, ctx) {
    return ctx.client.chat.completions.create(payload, ctx.signal ? { signal: ctx.signal } : undefined);
  },

  logFields(raw) {
    return { responseId: raw.id ?? null, usage: raw.usage ?? null };
  },

  parseResponse(raw, ctx) {
    const output = raw?.choices?.[0]?.message?.content;
    return {
      output,
      model: raw.model || ctx.model,
      tokenUsage: {
        inputTokens:  raw.usage?.prompt_tokens     ?? null,
        outputTokens: raw.usage?.completion_tokens ?? null,
        totalTokens:  raw.usage?.total_tokens      ?? null,
      },
      executionMetadata: { responseId: raw.id ?? null },
    };
  },
};

/**
 * Execute a real OpenAI chat completion request.
 *
 * @param {{ model: string, messages: Array }} body
 * @param {{ requestId: string, requestHash: string|null, policyHash: string|null }} meta
 * @param {AbortSignal} [signal]    — cancellation: route-level timeout or client disconnect
 * @returns {Promise<object>}  Normalized ProviderResponse
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callOpenAI(body, meta, signal) {
  return runProviderCall(spec, body, meta, signal);
}

// added for test isolation only, mirroring the identical export every
// other createLazyClient()-based provider already has (mistral.js, llama.js,
// local.js, and — as of openai.stream.js) — never called outside
// tests. Without it, a test needing a fresh client (a different mocked
// response, a different OPENAI_API_KEY) would silently reuse a prior test's
// cached client, since createLazyClient() caches for the process lifetime.
function _resetClient() { lazyClient.reset(); }

module.exports = { callOpenAI, MAX_CONTENT_BYTES, MAX_MESSAGES, _resetClient, _spec: spec }; // _spec: test seam (R-23 hostedLimits.test.js)
