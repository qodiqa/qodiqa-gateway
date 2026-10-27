'use strict';

/**
 * Anthropic provider — production execution handler.
 *
 * Called ONLY through executeProviderCall() in services/execution.js.
 * Implements the Anthropic Messages API using native fetch.
 * Shares its execution pipeline with every other provider via
 * services/providers/baseAdapter.js.
 * Returns a normalized ProviderResponse (see services/providers/normalize.js).
 *
 * SSRF protection:
 *   CANONICAL_BASE_URL is hardcoded and validated at module load time.
 *   The ANTHROPIC_BASE_URL environment variable is ignored.
 *
 * Environment variables:
 *   ANTHROPIC_API_KEY       — required; enables this provider
 *   ANTHROPIC_TIMEOUT_MS    — optional; timeout in ms (default 30 000)
 *   ANTHROPIC_MAX_TOKENS    — optional; max output tokens (default 4096)
 *
 * API:
 *   POST https://api.anthropic.com/v1/messages
 *   Headers:
 *     anthropic-version: 2023-06-01
 *     x-api-key: <ANTHROPIC_API_KEY>
 *     content-type: application/json
 *
 * Message transformation:
 *   system messages  → extracted into the top-level `system` field
 *   user/assistant   → messages array (roles preserved)
 *   Anthropic does not accept role 'system' inside the messages array.
 *
 * Error normalization — canonical codes:
 *   PROVIDER_TIMEOUT           network timeout
 *   PROVIDER_UNAVAILABLE       network error or 5xx
 *   PROVIDER_RATE_LIMITED      HTTP 429
 *   PROVIDER_AUTH_FAILED       HTTP 401/403
 *   PROVIDER_INVALID_REQUEST   HTTP 400/422
 *   PROVIDER_MODEL_NOT_ALLOWED model not in allowlist
 *   PROVIDER_REQUEST_REJECTED  payload too large
 *   PROVIDER_INVALID_RESPONSE  response missing expected fields
 */

const { resolveTimeoutMs } = require('./timeout');
const { validateProviderUrl } = require('./ssrf');
const {
  MAX_MESSAGES, MAX_CONTENT_BYTES, TRANSPORTS,
  assertUrlSafeAtLoad, fetchJSON, runProviderCall,
} = require('./baseAdapter');

// ── SSRF: canonical base URL ──────────────────────────────────────────────────

const CANONICAL_BASE_URL = 'https://api.anthropic.com';
const MESSAGES_PATH      = '/v1/messages';
const ANTHROPIC_VERSION  = '2023-06-01';

assertUrlSafeAtLoad({
  provider:     'anthropic',
  url:          CANONICAL_BASE_URL,
  check:        validateProviderUrl(CANONICAL_BASE_URL),
  eventCode:    'PROVIDER_SSRF_REJECTED',
  logMessage:   'Hardcoded Anthropic base URL failed SSRF validation — module cannot load.',
  errorMessage: 'PROVIDER_SSRF_REJECTED: ',
});

// ── Configuration ─────────────────────────────────────────────────────────────

const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('ANTHROPIC_TIMEOUT_MS');
const MAX_TOKENS          = parseInt(process.env.ANTHROPIC_MAX_TOKENS  || '4096',  10);

// ── Message transformation ────────────────────────────────────────────────────
// Anthropic's API does not accept 'system' role inside the messages array.
// System messages must be extracted into the top-level `system` field.

function _transformMessages(messages) {
  const systemParts  = [];
  const chatMessages = [];

  for (const msg of messages) {
    if (msg.role === 'system') {
      systemParts.push(msg.content);
    } else {
      chatMessages.push({ role: msg.role, content: msg.content });
    }
  }

  return {
    system:   systemParts.length > 0 ? systemParts.join('\n\n') : undefined,
    messages: chatMessages,
  };
}

// Anthropic requires at least one non-system message.
function _extraValidation(messages) {
  const hasNonSystem = messages.some(m => m.role !== 'system');
  return hasNonSystem ? null : 'PROVIDER_INVALID_REQUEST';
}

// ── Provider spec ─────────────────────────────────────────────────────────────

const spec = {
  name:      'anthropic',
  transport: TRANSPORTS.fetch,
  validate:  { extra: _extraValidation },

  beforeValidatedEmit() {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      const err = new Error('PROVIDER_AUTH_FAILED');
      err.code  = 'PROVIDER_AUTH_FAILED';
      throw err;
    }
  },

  completeLogIncludesHash: true,

  transformRequest(body) {
    const { system, messages: chatMessages } = _transformMessages(body.messages);
    return {
      model:      body.model,
      max_tokens: require('./limits').capMaxTokens(MAX_TOKENS, body),
      messages:   chatMessages,
      ...(system ? { system } : {}),
    };
  },

  execute(payload, ctx) {
    return fetchJSON(`${CANONICAL_BASE_URL}${MESSAGES_PATH}`, {
      method:  'POST',
      headers: {
        'content-type':      'application/json',
        'x-api-key':         process.env.ANTHROPIC_API_KEY,
        'anthropic-version': ANTHROPIC_VERSION,
      },
      body: JSON.stringify(payload),
    }, PROVIDER_TIMEOUT_MS, ctx.signal);
  },

  logFields(raw) {
    return { responseId: raw.id ?? null, usage: raw.usage ?? null };
  },

  parseResponse(raw, ctx) {
    // Anthropic response: { id, content: [{ type: 'text', text: '...' }], ... }
    const content   = Array.isArray(raw?.content) ? raw.content : [];
    const textBlock = content.find(b => b.type === 'text');
    const output    = textBlock?.text;

    return {
      output,
      model: raw.model || ctx.model,
      tokenUsage: {
        inputTokens:  raw.usage?.input_tokens  ?? null,
        outputTokens: raw.usage?.output_tokens ?? null,
        totalTokens:  (raw.usage?.input_tokens ?? 0) + (raw.usage?.output_tokens ?? 0) || null,
      },
      executionMetadata: { responseId: raw.id ?? null },
    };
  },
};

/**
 * Execute an Anthropic Messages API request.
 *
 * @param {{ model: string, messages: Array }} body
 * @param {{ requestId: string, requestHash: string|null, policyHash: string|null }} meta
 * @param {AbortSignal} [signal]    — cancellation: route-level timeout or client disconnect
 * @returns {Promise<object>}  Normalized ProviderResponse
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callAnthropic(body, meta, signal) {
  return runProviderCall(spec, body, meta, signal);
}

module.exports = { callAnthropic, MAX_CONTENT_BYTES, MAX_MESSAGES };
