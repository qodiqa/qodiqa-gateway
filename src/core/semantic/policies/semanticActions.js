'use strict';

const { DECISION } = require('../reasons');

/**
 * Maps a semantic aggregate decision to the action the enforcement pipeline
 * takes, before any provider request is created.
 *
 * Every tier has explicit, deterministic runtime behavior — none of them
 * fall through to "not DENY, so proceed":
 *   - ALLOW  never blocks.
 *   - WARN   blocks if the deployment opted in globally
 *            (policy.enforcement.WARN_BLOCKS), OR if this specific reason is
 * named in policy.warnEscalate (per-reason escalation,
 *            independent of the global switch; see semanticPolicy.js's own
 *            header comment for why these are deliberately separate
 *            levers). Advisory by default in both dimensions, but that is a
 *            named configuration decision, not an accident of the tier not
 *            being DENY.
 *   - REVIEW blocks unless the deployment explicitly opted out
 *            (policy.enforcement.REVIEW_BLOCKS === false). A tier named
 *            "review" gates execution by default.
 *   - DENY   always blocks. Not configurable — there is no enforcement flag
 *            for it, by design.
 *
 * Every outcome — blocked or not — is fully recorded in evidence (see
 * semanticEvidence.js) for downstream review (e.g. a security-operations
 * queue or periodic audit sweep), never silently dropped. This mirrors the
 * rest of QODIQA's philosophy of recording every decision, not only
 * blocking ones.
 *
 * @param {{decision:string, reason:string|null}} aggregateResult
 * @param {{enforcement?: {WARN_BLOCKS?: boolean, REVIEW_BLOCKS?: boolean}, warnEscalate?: Set<string>}} [policy]
 */
function resolveAction(aggregateResult, policy) {
  const enforcement = (policy && policy.enforcement) || {};
  const warnEscalate = (policy && policy.warnEscalate) || null;

  let blocks;
  switch (aggregateResult.decision) {
    case DECISION.DENY:
      blocks = true;
      break;
    case DECISION.REVIEW:
      blocks = enforcement.REVIEW_BLOCKS !== false;
      break;
    case DECISION.WARN:
      // a reason explicitly escalated via policy.warnEscalate
      // blocks even when the global WARN_BLOCKS switch is off; the two
      // conditions are independent ORs, never a replacement of one by the
      // other, so enabling one cannot silently disable the other.
      blocks = enforcement.WARN_BLOCKS === true
        || (warnEscalate != null && aggregateResult.reason != null && warnEscalate.has(aggregateResult.reason));
      break;
    case DECISION.ALLOW:
    default:
      blocks = false;
      break;
  }

  return Object.freeze({
    blocks,
    decision: aggregateResult.decision,
    reason: aggregateResult.reason,
  });
}

module.exports = { resolveAction };
