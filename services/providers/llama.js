'use strict';

/**
 * Llama provider — production execution handler.
 *
 * Supports Llama deployments that expose an OpenAI-compatible chat completions
 * API.  This includes:
 *   - Cloud-hosted Llama endpoints (e.g. Groq, Together AI, Fireworks AI)
 *   - Self-managed GPU servers running llama.cpp, vLLM, or similar
 *
 * Called ONLY through executeProviderCall() in services/execution.js.
 * Uses the `openai` SDK with a configurable base URL. Shares its execution
 * pipeline with every other provider via services/providers/baseAdapter.js.
 * Returns a normalized ProviderResponse (see services/providers/normalize.js).
 *
 * SSRF protection:
 *   LLAMA_BASE_URL is validated at first client construction.
 *   Public (non-private) URLs must pass validateProviderUrl.
 *   Private-network URLs (localhost, 192.168.x, etc.) are allowed for
 *   self-managed deployments via validateLocalProviderUrl.
 *
 * Environment variables:
 *   LLAMA_BASE_URL     — required; enables this provider
 *   LLAMA_API_KEY      — optional; some deployments require authentication
 *   LLAMA_TIMEOUT_MS   — optional; timeout in ms (default 30 000)
 *
 * Model allowlist:
 *   The allowlist is empty by default — Llama model names are deployment-specific.
 *   Any non-empty string model is accepted.  Operators should restrict via policy
 *   if needed.
 */

const { resolveTimeoutMs } = require('./timeout');
const { OpenAI }                    = require('openai');
const { validateProviderUrl,
        validateLocalProviderUrl, createGuardedAgent }  = require('./ssrf');
const { emit }                      = require('../logger');
const {
  MAX_MESSAGES, MAX_CONTENT_BYTES, TRANSPORTS,
  createLazyClient, runProviderCall,
} = require('./baseAdapter');

// ── Configuration ─────────────────────────────────────────────────────────────

const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('LLAMA_TIMEOUT_MS');

// ── URL validation ────────────────────────────────────────────────────────────

function _validateBaseUrl(rawUrl) {
  if (!rawUrl) return { valid: false, reason: 'LLAMA_BASE_URL_NOT_SET' };

  // Try the strict public-provider validator first.
  // This covers cloud-hosted Llama (e.g. api.groq.com, api.together.xyz).
  const strict = validateProviderUrl(rawUrl);
  if (strict.valid) return strict;

  // Strict check fails for private/local URLs — try the relaxed local validator.
  const local = validateLocalProviderUrl(rawUrl);
  if (local.valid) return local;

  // Both validators reject the URL.
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
          url:      (() => { try { return new URL(baseURL).origin; } catch { return null; } })(),     // never the raw value (it may carry credentials)
          message:  'LLAMA_BASE_URL failed URL validation — provider cannot execute.',
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
  transport: TRANSPORTS.sdk,
  validate:  {},

  getExecutionContext() {
    return { client: lazyClient.get() };
  },

  transformRequest(body) {
    // R-23: optional output cap (LLAMA_MAX_TOKENS via config.js); unset → the body is exactly { model, messages }.
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('llama')?.maxTokens ?? null, body);
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
 * Execute a Llama chat completion request.
 *
 * @param {{ model: string, messages: Array }} body
 * @param {{ requestId: string, requestHash: string|null, policyHash: string|null }} meta
 * @param {AbortSignal} [signal]    — cancellation: route-level timeout or client disconnect
 * @returns {Promise<object>}  Normalized ProviderResponse
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callLlama(body, meta, signal) {
  return runProviderCall(spec, body, meta, signal);
}

// Export for testing
function _resetClient() { lazyClient.reset(); _validated = false; }

module.exports = { callLlama, MAX_CONTENT_BYTES, MAX_MESSAGES, _resetClient, _spec: spec }; // _spec: test seam (R-23 hostedLimits.test.js)
