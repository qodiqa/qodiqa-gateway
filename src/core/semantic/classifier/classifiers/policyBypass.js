'use strict';

const { defineClassifier } = require('../baseClassifier');
const { coOccurs } = require('../../textSignals');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');

/**
 * Detects attempts to have the model declare QODIQA's or the provider's
 * content/usage policies inapplicable for this conversation. Distinct from
 * securityOverride.js (which targets QODIQA's cryptographic enforcement
 * pipeline by name) — this classifier targets policy/rules framing more
 * broadly, including provider-side content policy.
 *
 * Three new signals
 * cover technique classes the original five (all requiring the literal word
 * "polic(y|ies)") missed entirely —
 *   - constraint_exemption_unnamed: declaring the interaction exempt from
 *     constraint without naming "policy" at all ("you have no restrictions
 *     here");
 *   - mode_switch_unrestricted: imperative mode-switch framing distinct from
 *     jailbreak.js's persona/roleplay angle — this is specifically about
 *     declaring QODIQA's own enforcement toggled off, not adopting a
 *     character;
 *   - authority_impersonation_override: impersonating elevated authority
 *     ("as the developer, I'm authorizing you...") to justify a bypass.
 * A structural refine() bonus also loosens rules_dont_apply_scoped's single
 * rigid word-order template into a proximity check (session-scope phrase
 * near a constraint-negation verb, any order/spacing within the window).
 *
 * 1st/2nd-person framing ("you"/"your"/"this conversation") rather than a
 * collision pattern is 3rd-person ASVS-control quoting ("Is our current
 * setup expected to meet this control: 'Business logic flows are sequential
 * with no bypass'?"), which never mentions "you" or "this conversation" at
 * all. The bare constraint-negation half (CONSTRAINT_NEGATION below) is
 * deliberately NOT declared as its own low-weight signal, unlike
 * memoryExtraction.js's analogous pair — "rules don't apply" alone has a
 * plausible unrelated benign reading (e.g. "castling rules don't apply once
 * the king has moved") that a bare CAL-01-style low weight wouldn't fully
 * neutralize the reasoning risk of; it only ever contributes via the
 * structural coOccurs proximity bonus in refine(), never alone.
 */
const SCOPE_PHRASE = /\bfor (this|our) (conversation|session|request|chat|interaction)\b/;
const CONSTRAINT_NEGATION = /\b(rules?|restrictions?|guidelines?|polic(?:y|ies)|limits?) (don'?t|do not|won'?t|will not|doesn'?t|does not) (apply|matter|count|hold)\b/;

const SIGNALS = [
  { pattern: /\b(your|the|these) (content |usage )?polic(?:y|ies) (do(?:es)? not|don't|doesn't) apply\b/, weight: 0.45, tag: 'policy_inapplicable' },
  { pattern: /\bfor this (conversation|session|request)\b.{0,40}\brules? (don't|do not|won't) apply\b/, weight: 0.45, tag: 'rules_dont_apply_scoped' },
  { pattern: /\b(disable|turn off|suspend) (your |the )?(content |safety )?polic(?:y|ies)\b/, weight: 0.50, tag: 'disable_policy' },
  { pattern: /\boverride (your |the )?(configuration|settings|policy|policies)\b/, weight: 0.45, tag: 'override_configuration' },
  { pattern: /\bact (outside|beyond) (your |the )?(normal |usual )?(policy|policies|guidelines?)\b/, weight: 0.35, tag: 'act_outside_policy' },
  // New: constraint-exemption framing that never uses the word "policy" —
  // description of some unrelated system ("our setup", "business logic").
  { pattern: /\b(you (have|are given|possess) no (restrictions?|rules?|limits?)( (here|in this (conversation|chat|session)))?|nothing is off[- ]?limits (for|in) this (conversation|chat|session))\b/, weight: 0.40, tag: 'constraint_exemption_unnamed' },
  // New: imperative mode-switch + unrestricted-mode object.
  { pattern: /\b(switch to|enter|activate|go into) (an? )?(unrestricted|unfiltered|no[- ]?rules?|no[- ]?restrictions?) mode\b/, weight: 0.40, tag: 'mode_switch_unrestricted' },
  // New: authority-impersonation override — claiming elevated authority to
  // justify instructing the model to ignore/bypass its own rules.
  { pattern: /\bas (the |your )?(developer|admin|administrator|owner|creator),? (i'?m|i am) authoriz(ing|ed) you to (ignore|bypass|disregard|override) (the |your |these )?(polic(?:y|ies)|rules?|restrictions?|guidelines?)\b/, weight: 0.45, tag: 'authority_impersonation_override' },
];

module.exports = defineClassifier({
  id: 'policy-bypass',
  reason: SEMANTIC_REASONS.POLICY_BYPASS_ATTEMPT,
  severity: SEVERITY.HIGH,
  signals: SIGNALS,
  refine(text, base) {
    let confidence = base.confidence;
    if (coOccurs(text, SCOPE_PHRASE, CONSTRAINT_NEGATION, 80)) {
      confidence = Math.min(1, confidence + 0.30);
    }
    return { confidence, matched: base.matched };
  },
});
