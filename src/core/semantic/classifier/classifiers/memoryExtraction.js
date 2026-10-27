'use strict';

const { defineClassifier } = require('../baseClassifier');
const { coOccurs } = require('../../textSignals');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');

/**
 * Detects attempts to have the model reveal other users' conversations,
 * cross-session memory, or verbatim training data — content that must
 * never cross a tenant/session boundary.
 *
 * Broadened past the
 * original four fixed-phrase templates to cover the same threat classes
 * structurally rather than by exact wording —
 *   - the boundary-crossing noun class (other_user_conversation) widened
 *     from user/customer/tenant to also cover account/chat/session/thread/
 *     workspace, since attackers vary that noun independently of the verb;
 *   - memory_probe_imperative / persistence_claim_probe are new signals for
 *     two technique classes the original four didn't cover at all (a direct
 *     "show me everything you remember" imperative, and "prove you remember
 *     me" persistence-claim probing);
 *   - EXTRACTION_VERB/TRAINING_DATA_NOUN + refine() loosens
 *     training_data_verbatim's single rigid phrase into a structural
 *     proximity check (verb near a training-data noun class), the same
 *     coOccurs technique securityOverride.js/piiExtraction.js already use.
 * Every new/broadened signal requires a verb-adjacent-object structure —
 * no bare noun (e.g. "memory", "remember") solo-triggers — per the
 */
const EXTRACTION_VERB = /\b(reveal|output|show|print|repeat|disclose|display)\b/;
const TRAINING_DATA_NOUN = /\b(training (data|examples|set|corpus)|documents you (were trained|learned) on|data you were trained on)\b/;

const SIGNALS = [
  { pattern: /\b(recall|remember|reveal) (previous |prior |other )?conversations? with (other|another) (user|customer|tenant|account|chat|session|thread|workspace)\b/, weight: 0.55, tag: 'other_user_conversation' },
  { pattern: /\bwhat did the (last|previous|another) (user|customer|person) (ask|say|request)\b/, weight: 0.50, tag: 'previous_user_request' },
  { pattern: /\b(repeat|reveal|output) (verbatim )?(text|data) (you|that you) (memorized|were trained on)\b/, weight: 0.40, tag: 'training_data_verbatim' },
  { pattern: /\baccess (your |the )?(training data|memory) from (other|previous) (sessions?|users?|conversations?)\b/, weight: 0.45, tag: 'cross_session_memory' },
  // New: direct imperative to dump whatever the model retains — requires an
  // object; a bare "remember"/"memory" noun (e.g. "help me remember a
  // movie", "what is memory management?") never matches this shape.
  { pattern: /\b(show|tell|display|list|print)( me| us)? (everything|all)( that)? (you|you've|you have) (remember|recall|know|have (stored|saved|learned))\b/, weight: 0.35, tag: 'memory_probe_imperative' },
  // New: adversarial-testing framing distinct from ordinary curiosity
  // ("do you remember me?") — "prove/demonstrate" is a challenge posture a
  // benign returning-user question doesn't use. Weight kept sub-WARN alone
  // (0.35 * 0.85 severity = 0.2975 < 0.35 WARN threshold) so it needs
  // corroboration from another signal, consistent with the CAL-01 house
  // style for any signal with residual ambiguity.
  { pattern: /\b(prove|demonstrate|show me) (that )?you (remember|recall|have memory of|retained?) (me|us|our (previous|prior|last) (conversation|session|chat))\b/, weight: 0.35, tag: 'persistence_claim_probe' },
  // Bare-keyword halves of the training-data-extraction structural check
  // below — deliberately very low weight (CAL-01 style) so either alone
  // (e.g. "reveal" in an unrelated sentence) stays far below WARN; real
  // signal comes from the coOccurs proximity bonus in refine().
  { pattern: EXTRACTION_VERB, weight: 0.15, tag: 'extraction_verb_bare' },
  { pattern: TRAINING_DATA_NOUN, weight: 0.15, tag: 'training_data_noun_bare' },
];

module.exports = defineClassifier({
  id: 'memory-extraction',
  reason: SEMANTIC_REASONS.MEMORY_EXTRACTION,
  severity: SEVERITY.HIGH,
  signals: SIGNALS,
  refine(text, base) {
    let confidence = base.confidence;
    if (coOccurs(text, EXTRACTION_VERB, TRAINING_DATA_NOUN, 100)) {
      confidence = Math.min(1, confidence + 0.35);
    }
    return { confidence, matched: base.matched };
  },
});
