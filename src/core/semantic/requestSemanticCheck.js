'use strict';

/**
 * Shared REQUEST-side semantic evaluation core.
 *
 * Extracted from src/api/routes/aiChat.js's own request-side semantic step
 * so /ai/chat and /verify (src/api/routes/verify.js) run the IDENTICAL
 * pipeline against the IDENTICAL tenant-effective config — the keyword-
 * classifier engine (runSemanticPolicyEngine, which resolves the tenant's
 * semantic overlay internally from `tenantId`, same as's
 * mergeForEvaluation() does for policy sets), then the embedding-similarity
 * gate ONLY when the classifier engine did not already block (mirrors
 * embeddingGate.js's own "additive on top of a classifier ALLOW, never
 * substituted over a classifier DENY" contract — see aiChat.js's original
 * comment on this, preserved verbatim below).
 *
 * Side-effect-free by construction: this function itself never audits,
 * never touches transparency, never calls a provider, and never consumes
 * consent or rate-limit quota — it is a pure classification of text against
 * the live (tenant-effective) semantic config, exactly like
 * runSemanticPolicyEngine() and embeddingGate.checkText() already are on
 * their own (see their own module headers). What a caller DOES with the
 * verdict is the caller's decision, not this module's: aiChat.js's
 * _runSemanticCheck() wraps this call and writes an audit BLOCK entry when
 * it blocks; verify.js's dry-run handler does not — there is no second
 * copy of the classification logic to keep in sync, only one call site
 * with two different callers.
 */

const { runSemanticPolicyEngine } = require('./index');
const embeddingGate = require('./embeddingGate');

/**
 * @param {object} params
 * @param {string|null|undefined} params.prompt    the caller's prompt text
 * @param {string|null} params.provider             artifact.payload.provider
 * @param {string|null} params.tenantId
 * @param {string|null} params.requestId
 * @returns {Promise<{blocks:boolean, decision:string, reason:string|null, evidence:object}>}
 */
async function evaluateRequestSemantic({ prompt, provider = null, tenantId = null, requestId = null }) {
  const semantic = runSemanticPolicyEngine({ prompt, provider, tenantId, requestId });

  // SEM-C session 3: the embedding-similarity gate (Option B — a separate,
  // additive check, see embeddingGate.js's header) only runs when the
  // existing keyword-classifier engine did NOT already block, and its own
  // ALLOW result is never substituted in for the engine's — this is what
  // makes "no change to existing classifier behavior on inputs the
  // embedding layer doesn't flag" literally true: the returned verdict
  // stays byte-identical to `semantic` in every case except "keyword
  // engine allowed, but the embedding layer denied."
  if (semantic.blocks) return semantic;

  const embeddingResult = await embeddingGate.checkText(prompt, {
    requestId, tenantId, provider, surface: 'REQUEST',
  });

  if (embeddingResult.blocks) return embeddingResult;
  // the returned verdict stays the keyword engine's ALLOW, but when that ALLOW stands only because the
  // intent gate overrode an embedding DENY, the override travels with the evidence into the audit entry.
  const intentGate = embeddingResult.evidence && embeddingResult.evidence.intentGate;
  return intentGate ? { ...semantic, evidence: Object.freeze({ ...semantic.evidence, intentGate }) } : semantic;
}

/**
 * the request side of a body that may be a multi-turn conversation. A plain `prompt` goes through evaluateRequestSemantic exactly as before
 * (same call, same result object). A conversation screens EVERY piece of text the model will read - system, user AND assistant turns, in order - because
 * none of them is trusted: an assistant turn supplied by the caller is as much untrusted input as a user turn. The first text that blocks decides; the
 * evidence names its role and position. Each text is classified in full (nothing is truncated or concatenated, so a split payload cannot hide between turns).
 */
async function evaluateConversationSemantic({ body, provider = null, tenantId = null, requestId = null }) {
  const conv = require('../../validation/conversation');
  if (!conv.enabled() || !conv.hasConversationFields(body)) return evaluateRequestSemantic({ prompt: body && body.prompt, provider, tenantId, requestId });
  let last = null;
  for (const t of conv.screenTexts(body)) {
    const r = await evaluateRequestSemantic({ prompt: t.text, provider, tenantId, requestId });
    if (r.blocks) return { ...r, evidence: Object.freeze({ ...(r.evidence || {}), conversation: { role: t.role, messageIndex: t.index } }) };
    last = r;
  }
  return last || evaluateRequestSemantic({ prompt: '', provider, tenantId, requestId });
}

module.exports = { evaluateRequestSemantic, evaluateConversationSemantic };
