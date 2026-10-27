'use strict';

/**
 * Google Gemini provider — production execution handler.
 *
 * Called ONLY through executeProviderCall() in services/execution.js.
 * Implements the Gemini REST API (generateContent) using native fetch.
 * Shares its execution pipeline with every other provider via
 * services/providers/baseAdapter.js.
 * Returns a normalized ProviderResponse (see services/providers/normalize.js).
 *
 * SSRF protection:
 *   CANONICAL_BASE_URL is hardcoded and validated at module load time.
 *
 * Environment variables:
 *   GEMINI_API_KEY      — required; enables this provider
 *   GEMINI_TIMEOUT_MS   — optional; timeout in ms (default 30 000)
 *
 * API endpoint:
 *   POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
 * Auth: `x-goog-api-key: {API_KEY}` request header
 *
 * Message transformation:
 *   user/assistant → contents array with role 'user'/'model'
 *   system         → injected as a user-role message at the start with
 *                    a "SYSTEM:" prefix, or as systemInstruction if supported.
 *   'assistant' role is mapped to 'model' (Gemini's term).
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

const CANONICAL_BASE_URL = 'https://generativelanguage.googleapis.com';
const API_VERSION        = 'v1beta';

assertUrlSafeAtLoad({
  provider:     'gemini',
  url:          CANONICAL_BASE_URL,
  check:        validateProviderUrl(CANONICAL_BASE_URL),
  eventCode:    'PROVIDER_SSRF_REJECTED',
  logMessage:   'Hardcoded Gemini base URL failed SSRF validation — module cannot load.',
  errorMessage: 'PROVIDER_SSRF_REJECTED: ',
});

// ── Configuration ─────────────────────────────────────────────────────────────

const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('GEMINI_TIMEOUT_MS');

// Role mapping: OpenAI → Gemini
const GEMINI_ROLE = { user: 'user', assistant: 'model' };

// ── Message transformation ────────────────────────────────────────────────────

function _transformMessages(messages) {
  const systemParts = [];
  const contents    = [];

  for (const msg of messages) {
    if (msg.role === 'system') {
      systemParts.push(msg.content);
      continue;
    }
    const geminiRole = GEMINI_ROLE[msg.role] || msg.role;
    contents.push({
      role:  geminiRole,
      parts: [{ text: msg.content }],
    });
  }

  // Gemini API v1beta supports systemInstruction for system prompts.
  // If there are system messages, prepend them as systemInstruction.
  const systemInstruction = systemParts.length > 0
    ? { role: 'user', parts: [{ text: systemParts.join('\n\n') }] }
    : null;

  return { systemInstruction, contents };
}

// Gemini requires at least one user-role message in the contents array.
function _extraValidation(messages) {
  const hasUserMessage = messages.some(m => m.role === 'user');
  return hasUserMessage ? null : 'PROVIDER_INVALID_REQUEST';
}

// ── Provider spec ─────────────────────────────────────────────────────────────

const spec = {
  name:      'gemini',
  transport: TRANSPORTS.fetch,
  validate:  { extra: _extraValidation },

  beforeValidatedEmit() {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      const err = new Error('PROVIDER_AUTH_FAILED');
      err.code  = 'PROVIDER_AUTH_FAILED';
      throw err;
    }
  },

  completeLogIncludesHash: true,

  transformRequest(body) {
    const { systemInstruction, contents } = _transformMessages(body.messages);
    // R-23: optional output cap (GEMINI_MAX_TOKENS via config.js) as generationConfig.maxOutputTokens; unset → unchanged.
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('gemini')?.maxTokens ?? null, body);
    return {
      contents,
      ...(systemInstruction ? { systemInstruction } : {}),
      ...(maxTokens ? { generationConfig: { maxOutputTokens: maxTokens } } : {}),
    };
  },

  execute(payload, ctx) {
    const apiKey = process.env.GEMINI_API_KEY;
    // the API key travels in Google's documented `x-goog-api-key` request
    // header, never in the URL query string — a URL is routinely written to proxy/egress/access logs and error
    // messages, a request header is not. The URL therefore carries no credential and is safe to log.
    // A3-01: the model id is a URL path segment: refuse anything that could change the path or the query
    if (typeof ctx.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(ctx.model) || ctx.model.includes('..')) { const e = new Error('PROVIDER_MODEL_NOT_ALLOWED'); e.code = 'PROVIDER_MODEL_NOT_ALLOWED'; throw e; }
    const url    = `${CANONICAL_BASE_URL}/${API_VERSION}/models/${ctx.model}:generateContent`;
    return fetchJSON(url, {
      method:  'POST',
      headers: { 'content-type': 'application/json', 'x-goog-api-key': apiKey },
      body:    JSON.stringify(payload),
    }, PROVIDER_TIMEOUT_MS, ctx.signal);
  },

  logFields(raw) {
    return { usage: raw.usageMetadata ?? null };
  },

  parseResponse(raw, ctx) {
    // Gemini: { candidates: [{ content: { parts: [{ text: '...' }] } }], usageMetadata: {...} }
    const output = raw?.candidates?.[0]?.content?.parts?.[0]?.text;
    const usage  = raw.usageMetadata;

    return {
      output,
      model: ctx.model,
      tokenUsage: {
        inputTokens:  usage?.promptTokenCount     ?? null,
        outputTokens: usage?.candidatesTokenCount ?? null,
        totalTokens:  usage?.totalTokenCount      ?? null,
      },
      executionMetadata: { responseId: null },   // Gemini does not return a response ID
    };
  },
};

/**
 * Execute a Gemini generateContent request.
 *
 * @param {{ model: string, messages: Array }} body
 * @param {{ requestId: string, requestHash: string|null, policyHash: string|null }} meta
 * @param {AbortSignal} [signal]    — cancellation: route-level timeout or client disconnect
 * @returns {Promise<object>}  Normalized ProviderResponse
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callGemini(body, meta, signal) {
  return runProviderCall(spec, body, meta, signal);
}

module.exports = { callGemini, MAX_CONTENT_BYTES, MAX_MESSAGES, _spec: spec }; // _spec: test seam (R-23 hostedLimits.test.js)
