'use strict';

const { defineClassifier } = require('../baseClassifier');
const { coOccurs } = require('../../textSignals');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');

/**
 * Detects attempts to have the model invoke tools/functions/commands outside
 * their intended, authorized scope — e.g. instructing arbitrary shell
 * execution, unrestricted file access, or invoking privileged/admin
 * functions the requester was never granted.
 *
 * Note: the three "you weren't given/authorized
 * access" / "outside intended scope" signals formerly declared here
 * (unauthorized_tool_phrase, tool_scope_escalation, chained_tool_escalation)
 * moved to their own sibling classifier, unauthorizedToolRequest.js, which
 * reports SEMANTIC_REASONS.UNAUTHORIZED_TOOL_REQUEST — this file's own
 * `reason` (TOOL_ABUSE_ATTEMPT, below) had been the ONLY reason those three
 * signals could ever report, under defineClassifier()'s one-reason-per-file
 * contract, even though they were never about generic tool misuse so much
 * as explicitly lacking authorization for the tool in question. The
 * remaining signals here (destructive/privileged/admin/self-granting tool
 * use) are about MISUSING a tool's capability, a distinct concept from
 * REQUESTING a tool one is known to lack authorization for — see
 * unauthorizedToolRequest.js's own header for that classifier's signals.
 *
 * Originally added:
 *   - direct_invocation_by_identifier: attackers naming a specific/invented
 *     function identifier and instructing direct invocation ("call
 *     deleteUser() directly, skip confirmation") rather than describing a
 *     generic privileged tool by category — retained here (see refine()
 *     below), since it's about direct/bypassing invocation, not an
 *     authorization claim.
 *
 * zero co-occurrences found for the structural check below): this
 * contain bare tool/execute/invoke vocabulary). INVOKE_VERB is declared as
 * its own signal at CAL-01-style low weight (0.15) specifically so that
 * bare glossary usage never solo-triggers; IDENTIFIER_TOKEN is deliberately
 * NOT declared as a signal at all — discussing a variable/function name in
 * an ordinary coding-help context is common and benign, so it only ever
 * contributes via the structural coOccurs proximity check in refine(),
 * never alone or in a simple pairwise combination.
 *
 * ARCHITECTURAL FINDING (discovered mid-implementation, corrected per owner
 * decision): every classifier's signals only ever see ctx.normalizedPrompt
 * (baseClassifier.js) / the `text` argument to refine() — both of which
 * come from textSignals.js's normalizeWithMeta(), which unconditionally
 * lowercases all text before any signal runs. This destroys case-based
 * distinctions for EVERY classifier, not just this one — a first version of
 * IDENTIFIER_TOKEN here tried to detect camelCase-shaped identifiers
 * (e.g. "deleteUser"), which is dead code by construction: by the time any
 * pattern sees it, "deleteUser" is already "deleteuser". Corrected to two
 * case-independent shapes instead: snake_case (underscores survive
 * lowercasing) and call-syntax (an identifier immediately followed by "("/
 * "()", which survives regardless of case — e.g. "deleteuser(" or
 * "sendEmail()" both still contain the parenthesis adjacency after
 * normalization). Genuine camelCase-only identifier detection (no
 * underscore, no call-syntax) remains a known gap, addressable only by
 * changing baseClassifier.js/textSignals.js's normalization pipeline itself
 * — out of Step 4's scope (outside the 4 named classifier files) and
 * recorded as a candidate post-G2 item, not silently absorbed here.
 */
const INVOKE_VERB = /\b(call|invoke|run|execute)\b/;
const IDENTIFIER_TOKEN = /\b[a-z][a-z0-9]*_[a-z0-9_]+\b|\b[a-z][a-z0-9_]*\(\)?/;
// the shape the ARCHITECTURAL FINDING above records as
// undetectable: a camelCase identifier with no underscore and no call
// syntax ("deleteUser"). Evaluated against the case-preserved text, so it
// is now reachable. INVOKE_VERB is re-declared case-insensitively for the
// same text because that text is, by construction, not lowercased.
const CAMEL_IDENTIFIER_TOKEN = /\b[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*\b/;
const INVOKE_VERB_ANY_CASE = /\b(call|invoke|run|execute)\b/i;
const BYPASS_QUALIFIER = /\b(directly|skip(?:ping)? (?:the )?confirmation|without (?:asking|authorization|permission)|bypass(?:ing)? (?:the )?(?:check|confirmation|approval))\b/;

const SIGNALS = [
  { pattern: /\b(run|execute) (this |the |arbitrary )?(shell |bash |system )?(command|code|script)\b/, weight: 0.35, tag: 'run_arbitrary_command' },
  { pattern: /\b(use|invoke|call) (your |the )?(shell|file ?system|admin|root) (tool|function|access)\b/, weight: 0.45, tag: 'invoke_privileged_tool' },
  { pattern: /\b(delete|remove|wipe) (all |every )?(files?|data|records?|logs?)\b/, weight: 0.30, tag: 'destructive_tool_request' },
  { pattern: /\binvoke (an?|the) (admin|administrator|root|privileged) (function|endpoint|command)\b/, weight: 0.50, tag: 'invoke_admin_function' },
  { pattern: /\bgrant (yourself|me) (admin|root|superuser|elevated) (access|privileges?|permissions?)\b/, weight: 0.50, tag: 'self_grant_privilege' },
  // unauthorized_tool_phrase, tool_scope_escalation, and
  // chained_tool_escalation moved to unauthorizedToolRequest.js (this
  // file's new sibling), which reports UNAUTHORIZED_TOOL_REQUEST — see this
  // file's header comment for why.
  // Bare-keyword half of the direct-invocation-by-identifier structural
  // check below — CAL-01 style: alone, "execute"/"call"/"run"/"invoke" is
  // common in wholly unrelated benign text (including the glossary-Q&A
  // template above), so this stays far below WARN on its own.
  { pattern: INVOKE_VERB, weight: 0.15, tag: 'invoke_verb_bare' },
];

module.exports = defineClassifier({
  id: 'tool-abuse',
  reason: SEMANTIC_REASONS.TOOL_ABUSE_ATTEMPT,
  severity: SEVERITY.HIGH,
  signals: SIGNALS,
  refine(text, base, casedText) {
    let confidence = base.confidence;
    // Direct-invocation-by-identifier: requires ALL THREE elements —
    // imperative invoke verb, a function/identifier-shaped token
    // (snake_case, or call-syntax like "deleteuser("/"sendEmail()" — see
    // the ARCHITECTURAL FINDING above for why camelCase-without-parens
    // isn't detectable here), AND a bypass/without-authorization qualifier
    // — anchored pairwise through the invoke verb. Any two alone (e.g. just
    // "call" + an identifier, which is ordinary coding-help conversation)
    // is not enough.
    //
    // the camelCase branch is now live. It is an ALTERNATIVE
    // way to satisfy the identifier element only — the invoke verb and the
    // bypass qualifier are still both required, so this cannot fire on
    // ordinary coding-help conversation that merely mentions a camelCase
    // contain a camelCase identifier (QODIQA's own `requestHash`/`policyHash`
    // field names in benign integration questions, HN-0475..HN-0484); 0 of
    // them contain an invoke verb and 0 contain a bypass qualifier, so none
    // can reach this gate.
    //
    // Each coOccurs() call is evaluated ENTIRELY WITHIN a single string.
    // `text` and `casedText` are not guaranteed to share character offsets
    // (see textSignals.js's note on fragment reconstruction), so mixing a
    // match position from one with a position from the other would be a
    // silent correctness bug. `casedText` may be undefined for a custom
    // classifier invoked without it — the optional chain keeps that path
    // behaving exactly as it did.
    const verbNearIdentifier = coOccurs(text, INVOKE_VERB, IDENTIFIER_TOKEN, 60)
      || (typeof casedText === 'string'
        && coOccurs(casedText, INVOKE_VERB_ANY_CASE, CAMEL_IDENTIFIER_TOKEN, 60));
    const verbNearBypass = coOccurs(text, INVOKE_VERB, BYPASS_QUALIFIER, 60);
    if (verbNearIdentifier && verbNearBypass) {
      confidence = Math.min(1, confidence + 0.45);
    }
    return { confidence, matched: base.matched };
  },
});
