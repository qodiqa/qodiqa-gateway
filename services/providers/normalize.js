'use strict';

/**
 * Unified provider response schema.
 *
 * All provider adapters MUST return a ProviderResponse object created by
 * buildResponse().  The rest of the QODIQA pipeline interacts ONLY with
 * this schema — no provider-specific shapes leak past the adapter layer.
 *
 * ProviderResponse shape:
 *   output            — string           — the AI text output
 *   model             — string | null    — model that produced the output
 *   provider          — string | null    — canonical provider name
 *   tokenUsage:
 *     inputTokens     — number | null    — prompt / input tokens consumed
 *     outputTokens    — number | null    — completion / output tokens consumed
 *     totalTokens     — number | null    — total tokens consumed
 *   executionMetadata:
 *     responseId      — string | null    — provider-assigned response identifier
 *     latencyMs       — number           — wall-clock time of the provider call
 */

/**
 * Build a frozen ProviderResponse.
 *
 * @param {{
 *   output:             string,
 *   model?:             string | null,
 *   provider?:          string | null,
 *   tokenUsage?: {
 *     inputTokens?:     number | null,
 *     outputTokens?:    number | null,
 *     totalTokens?:     number | null,
 *   },
 *   executionMetadata?: {
 *     responseId?:      string | null,
 *     latencyMs?:       number,
 *   },
 * }} fields
 * @returns {object}
 * @throws {Error} PROVIDER_INVALID_RESPONSE — if output is not a non-empty string
 */
function buildResponse(fields) {
  if (!fields || typeof fields !== 'object') {
    const err = new Error('PROVIDER_INVALID_RESPONSE');
    err.code  = 'PROVIDER_INVALID_RESPONSE';
    throw err;
  }

  if (typeof fields.output !== 'string') {
    const err = new Error('PROVIDER_INVALID_RESPONSE');
    err.code  = 'PROVIDER_INVALID_RESPONSE';
    throw err;
  }

  // an output the pipeline cannot carry or log safely is an invalid response, not a success
  if (fields.output.length > MAX_OUTPUT_CHARS || fields.output.includes('\u0000')) {
    const err = new Error('PROVIDER_INVALID_RESPONSE');
    err.code  = 'PROVIDER_INVALID_RESPONSE';
    throw err;
  }

  return Object.freeze({
    output:   fields.output,
    model:    typeof fields.model    === 'string' ? fields.model    : null,
    provider: typeof fields.provider === 'string' ? fields.provider : null,
    tokenUsage: Object.freeze({
      inputTokens:  _toNullableInt(fields.tokenUsage?.inputTokens),
      outputTokens: _toNullableInt(fields.tokenUsage?.outputTokens),
      totalTokens:  _toNullableInt(fields.tokenUsage?.totalTokens),
    }),
    executionMetadata: Object.freeze({
      responseId: typeof fields.executionMetadata?.responseId === 'string'
        ? fields.executionMetadata.responseId
        : null,
      latencyMs: typeof fields.executionMetadata?.latencyMs === 'number'
        ? fields.executionMetadata.latencyMs
        : 0,
    }),
  });
}

// provider-reported usage is untrusted input to billing and budgets: only a real number that is a plausible token count survives; a numeric string, NaN, a negative or an absurd
// value (1e308 would turn a cost counter into Infinity and refuse every later request) is dropped to null.
const MAX_TOKENS = 1_000_000_000;
function _toNullableInt(v) {
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > MAX_TOKENS) return null;
  return Math.round(v);
}
const MAX_OUTPUT_CHARS = 4 * 1024 * 1024;

module.exports = { buildResponse };
