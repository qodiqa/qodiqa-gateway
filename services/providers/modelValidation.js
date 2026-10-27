'use strict';

/**
 * Single authoritative model-allowlist validator.
 *
 * services/providers/config.js's `allowedModels` (per provider) is the only
 * source of truth for which models may be executed. This module is the only
 * code that reads it for enforcement purposes. Every execution path — the
 * non-streaming router (router.js), the streaming router (router.stream.js),
 * and each provider adapter's own defense-in-depth check — calls into this
 * module rather than keeping a private copy of the allowlist. Changing
 * config.js's allowedModels therefore changes runtime behavior everywhere,
 * automatically, with no other code to update.
 *
 * Normalization policy: NONE. A model identifier is treated as an opaque,
 * case-sensitive, byte-exact token.
 *   - No trimming: " gpt-4o" and "gpt-4o" are different strings; the padded
 *     one is rejected outright, never silently cleaned up and retried.
 *   - No case-folding: "GPT-4o" does not match "gpt-4o".
 *   - No Unicode normalization: a confusable/lookalike codepoint sequence
 *     will not byte-match a real allowlist entry and is rejected by the
 *     same exact-match check — there is no separate "detector" for
 *     lookalikes that could itself be bypassed.
 * Rejecting rather than canonicalizing means there is no transformation
 * step for an attacker to target: every non-exact string simply fails the
 * Set membership check.
 */

const { getProviderConfig } = require('./config');

// Longest real-world model identifier in config.js is well under 40 chars;
// 128 gives headroom for future names while still bounding the cost of the
// checks below and rejecting obviously-abusive (e.g. injected) input.
const MAX_MODEL_LENGTH = 128;

// C0 control characters + DEL — never legitimate inside a model identifier.
// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\x00-\x1F\x7F]/;

const MODEL_NOT_ALLOWED = Object.freeze({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
const OK                = Object.freeze({ ok: true });

/**
 * Validate a model identifier against an already-resolved provider config.
 * Pure function — does not fetch config itself, so callers that already
 * hold the resolved config object (the routers) don't pay for a second
 * lookup, and it can be unit-tested without mocking config.js.
 *
 * @param {{ allowedModels: Set<string> } | null | undefined} config
 * @param {unknown} model
 * @returns {{ ok: true } | { ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' }}
 */
function validateModelAgainstConfig(config, model) {
  if (typeof model !== 'string' || model.length === 0)   return MODEL_NOT_ALLOWED;
  if (model.length > MAX_MODEL_LENGTH)                    return MODEL_NOT_ALLOWED;
  if (CONTROL_CHAR_RE.test(model))                        return MODEL_NOT_ALLOWED;
  if (model.trim() !== model)                             return MODEL_NOT_ALLOWED;

  const allowedModels = config?.allowedModels;
  if (!(allowedModels instanceof Set)) return MODEL_NOT_ALLOWED;

  // Empty allowlist = deployment-specific models (llama/local — see
  // config.js). Any identifier that passed the generic shape checks above
  // is accepted; there is no fixed catalog to check it against.
  if (allowedModels.size === 0) return OK;

  return allowedModels.has(model) ? OK : MODEL_NOT_ALLOWED;
}

/**
 * Validate a model identifier for a named provider, resolving its config
 * from config.js. Convenience wrapper for callers (provider adapters) that
 * don't already hold a resolved config object.
 *
 * @param {string} provider
 * @param {unknown} model
 * @returns {{ ok: true } | { ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' }}
 */
function validateModel(provider, model) {
  return validateModelAgainstConfig(getProviderConfig(provider), model);
}

module.exports = { validateModel, validateModelAgainstConfig, MAX_MODEL_LENGTH };
