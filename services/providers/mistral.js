'use strict';

/**
 * Mistral provider — production execution handler.
 *
 * Called ONLY through executeProviderCall() in services/execution.js.
 * Mistral exposes an OpenAI-compatible chat completions API.
 * Uses the `openai` SDK (already a dependency) with Mistral's base URL.
 * Returns a normalized ProviderResponse (see services/providers/normalize.js).
 * Shares its execution pipeline with every other provider via
 * services/providers/baseAdapter.js.
 *
 * SSRF protection:
 *   The default base URL (https://api.mistral.ai/v1) is allowlisted.
 *   If MISTRAL_BASE_URL is set to a non-allowlisted hostname, the module
 *   validates the URL at client construction time.  Private-network
 *   destinations are rejected unless the URL passes validateProviderUrl.
 *
 * Environment variables:
 *   MISTRAL_API_KEY     — required; enables this provider
 *   MISTRAL_BASE_URL    — optional; defaults to https://api.mistral.ai/v1
 *   MISTRAL_TIMEOUT_MS  — optional; timeout in ms (default 30 000)
 *
 * Error normalization — canonical codes (same as openai.js):
 *   PROVIDER_TIMEOUT / PROVIDER_UNAVAILABLE / PROVIDER_RATE_LIMITED
 *   PROVIDER_AUTH_FAILED / PROVIDER_INVALID_REQUEST
 *   PROVIDER_MODEL_NOT_ALLOWED / PROVIDER_REQUEST_REJECTED
 *   PROVIDER_INVALID_RESPONSE
 */

const { resolveTimeoutMs } = require('./timeout');
const { OpenAI }              = require('openai');
const { validateProviderUrl } = require('./ssrf');
const {
  MAX_MESSAGES, MAX_CONTENT_BYTES, TRANSPORTS,
  assertUrlSafeAtLoad, createLazyClient, runProviderCall,
} = require('./baseAdapter');

// ── Configuration ─────────────────────────────────────────────────────────────

const DEFAULT_BASE_URL    = 'https://api.mistral.ai/v1';
const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('MISTRAL_TIMEOUT_MS');

// ── Base URL validation ───────────────────────────────────────────────────────
// Finding A: validate whichever URL will actually be used — the
// configured MISTRAL_BASE_URL override, or DEFAULT_BASE_URL otherwise —
// unconditionally, every time this module loads. Previously this only ran
// when MISTRAL_BASE_URL was explicitly set, so the DEFAULT_BASE_URL path
// (the common case — no override configured) never actually invoked the
// SSRF guard at all, unlike openai.js/anthropic.js/gemini.js, which each
// validate their hardcoded canonical URL unconditionally. A future typo in
// DEFAULT_BASE_URL above would previously have gone undetected; now it
// fails module load exactly like the other three hardcoded-URL providers.

const _effectiveUrl = process.env.MISTRAL_BASE_URL || DEFAULT_BASE_URL;

assertUrlSafeAtLoad({
  provider:     'mistral',
  url:          _effectiveUrl,
  check:        validateProviderUrl(_effectiveUrl),
  eventCode:    'PROVIDER_CONFIG_INVALID',
  logMessage:   'Mistral base URL failed SSRF validation — module cannot load.',
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
  transport: TRANSPORTS.sdk,
  validate:  {},

  getExecutionContext() {
    return { client: lazyClient.get() };
  },

  transformRequest(body) {
    // R-23: optional output cap (MISTRAL_MAX_TOKENS via config.js); unset → the body is exactly { model, messages }.
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('mistral')?.maxTokens ?? null, body);
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
 * Execute a Mistral chat completion request.
 *
 * @param {{ model: string, messages: Array }} body
 * @param {{ requestId: string, requestHash: string|null, policyHash: string|null }} meta
 * @param {AbortSignal} [signal]    — cancellation: route-level timeout or client disconnect
 * @returns {Promise<object>}  Normalized ProviderResponse
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callMistral(body, meta, signal) {
  return runProviderCall(spec, body, meta, signal);
}

// Export for testing
function _resetClient() { lazyClient.reset(); }

module.exports = { callMistral, _resetClient, MAX_CONTENT_BYTES, MAX_MESSAGES, _spec: spec }; // _spec: test seam (R-23 hostedLimits.test.js)
