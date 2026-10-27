'use strict';

const { defineClassifier } = require('../baseClassifier');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');
const { signalsFor } = require('../../i18nSignals');

/**
 * Detects generic prompt-injection framing: attempts to have the model
 * disregard its actual instructions/context in favor of attacker-supplied
 * ones, or to inject a fake conversation boundary (delimiter injection).
 *
 * TEST-3 / remediation: includes translated "ignore previous
 * instructions" equivalents (see i18nSignals.js) so this classifier is not
 * English-only — confirmed "a translated jailbreak phrase scores 0" as
 * a live bypass of this exact classifier family.
 */
const SIGNALS = [
  { pattern: /\bignore (all |any )?(the )?(previous|prior|above|earlier) (instructions?|prompts?|rules?|messages?)\b/, weight: 0.55, tag: 'ignore_prior_instructions' },
  { pattern: /\bdisregard (all |any )?(the )?(previous|prior|system|earlier) (instructions?|prompts?|rules?)\b/, weight: 0.55, tag: 'disregard_instructions' },
  { pattern: /\bnew (instructions?|rules?|system prompt)\s*:/, weight: 0.30, tag: 'new_instructions_marker' },
  { pattern: /\b(from now on|starting now|for the (rest|remainder) of this conversation)\b.{0,40}\b(you (are|will|must))\b/, weight: 0.25, tag: 'redefine_behavior' },
  { pattern: /###\s*(system|instruction|admin)/, weight: 0.35, tag: 'delimiter_injection' },
  { pattern: /\b(end|close) (of )?(system prompt|instructions?)\b/, weight: 0.30, tag: 'fake_boundary' },
  { pattern: /\beverything (above|before this) (is|was) (fake|a test|not real|to be ignored)\b/, weight: 0.40, tag: 'invalidate_context' },
  { pattern: /\bignore (your |the )?(safety|security|content) (policy|policies|guidelines?)\b/, weight: 0.45, tag: 'ignore_safety_policy' },
  ...signalsFor('IGNORE_INSTRUCTIONS'),
];

module.exports = defineClassifier({
  id: 'prompt-injection',
  reason: SEMANTIC_REASONS.PROMPT_INJECTION_ATTEMPT,
  severity: SEVERITY.HIGH,
  signals: SIGNALS,
});
