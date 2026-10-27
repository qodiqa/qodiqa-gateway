'use strict';

/**
 * Local model provider — production execution handler.
 *
 * Supports self-hosted local AI runtimes that expose an OpenAI-compatible
 * chat completions API.  This includes:
 *   - Ollama (http://localhost:11434)
 *   - llama.cpp server
 *   - LM Studio
 *   - Jan.ai
 *   - Any future local runtime exposing POST /chat/completions
 *
 * Called ONLY through executeProviderCall() in services/execution.js.
 * Uses the `openai` SDK with a configurable local base URL. Shares its
 * execution pipeline with every other provider via
 * services/providers/baseAdapter.js.
 * Returns a normalized ProviderResponse (see services/providers/normalize.js).
 *
 * SSRF protection:
 *   LOCAL_BASE_URL is validated using the relaxed local validator which allows
 *   http:// and private-network destinations.  This is an intentional policy
 *   exception for operator-configured self-hosted endpoints.  The operator
 *   accepts full responsibility for the security of the local endpoint.
 *
 * Environment variables:
 *   LOCAL_BASE_URL     — required; enables this provider
 *   LOCAL_API_KEY      — optional; some local runtimes accept a key
 *   LOCAL_TIMEOUT_MS   — optional; timeout in ms (default 30 000)
 *
 * Model names:
 *   Model names are runtime-specific (e.g. 'llama3.2', 'mistral', 'phi3').
 *   Any non-empty string model name is accepted.
 */

const { resolveTimeoutMs } = require('./timeout');
const { OpenAI }                   = require('openai');
const { validateLocalProviderUrl, createGuardedAgent } = require('./ssrf');
const { emit }                     = require('../logger');
const {
  MAX_MESSAGES, MAX_CONTENT_BYTES, TRANSPORTS,
  createLazyClient, runProviderCall,
} = require('./baseAdapter');

// ── Configuration ─────────────────────────────────────────────────────────────

const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('LOCAL_TIMEOUT_MS');

// ── Lazy client ───────────────────────────────────────────────────────────────

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
          message:  'LOCAL_BASE_URL failed URL validation — provider cannot execute.',
        });
        const err = new Error(`PROVIDER_CONFIG_INVALID: ${check.reason}`);
        err.code  = 'PROVIDER_CONFIG_INVALID';
        throw err;
      }
      _validated = true;

      emit('INFO', 'LOCAL_PROVIDER_ENDPOINT_CONFIGURED', {
        baseUrl: (() => { try { return new URL(baseURL).origin; } catch { return null; } })(),
        message: 'Local model endpoint configured. Operator is responsible for endpoint security.',
      });
    }

    // The openai SDK requires a non-empty apiKey; use a placeholder for local
    // runtimes that don't enforce authentication.
    const apiKey = process.env.LOCAL_API_KEY || 'local';
    return { apiKey, baseURL, timeoutMs: PROVIDER_TIMEOUT_MS, httpAgent: createGuardedAgent(baseURL) }; // item 3.8
  },
});

// ── Provider spec ─────────────────────────────────────────────────────────────

const spec = {
  name:      'local',
  transport: TRANSPORTS.sdk,
  validate:  {},

  getExecutionContext() {
    return { client: lazyClient.get() };
  },

  transformRequest(body) {
    // R-06: optional output cap (LOCAL_MAX_TOKENS via config.js); unset → the body is exactly { model, messages }.
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('local')?.maxTokens ?? null, body);
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
 * Execute a local model chat completion request.
 *
 * @param {{ model: string, messages: Array }} body
 * @param {{ requestId: string, requestHash: string|null, policyHash: string|null }} meta
 * @param {AbortSignal} [signal]    — cancellation: route-level timeout or client disconnect
 * @returns {Promise<object>}  Normalized ProviderResponse
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callLocal(body, meta, signal) {
  return runProviderCall(spec, body, meta, signal);
}

// Export for testing
function _resetClient() { lazyClient.reset(); _validated = false; }

module.exports = { callLocal, MAX_CONTENT_BYTES, MAX_MESSAGES, _resetClient, _spec: spec }; // _spec: test seam (R-06 localLimits.test.js)
