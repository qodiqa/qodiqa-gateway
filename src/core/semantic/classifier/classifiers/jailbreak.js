'use strict';

const { defineClassifier } = require('../baseClassifier');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');
const { signalsFor } = require('../../i18nSignals');

/**
 * Detects role-play / persona-based jailbreak framing — asking the model to
 * adopt an identity defined as having no restrictions, rather than directly
 * attacking QODIQA's controls (see securityOverride.js) or the model's
 * system prompt (see systemPromptExtraction.js).
 */
const SIGNALS = [
  // "Do anything now" is an unambiguous, well-documented jailbreak phrase
  // with essentially no benign use — weighted to cross WARN (0.35) alone
  // under HIGH severity (0.85). Split out from the bare "DAN" acronym below:
  // previously both shared one 0.35-weight signal, which (a) never crossed
  // if raised, since "dan" alone collides with the common given name and
  // martial-arts belt-rank usage ("third dan black belt"). See calibration
  // finding CAL-03 in docs/architecture/content-screening.md.
  { pattern: /\bdo anything now\b/, weight: 0.45, tag: 'do_anything_now_phrase' },
  // Bare "DAN" acronym kept deliberately low — a weak, ambiguous signal on
  // its own (name/acronym collision), meaningful mainly in combination with
  // another jailbreak signal via noisy-OR.
  { pattern: /\bdan\b/, weight: 0.20, tag: 'dan_acronym' },
  { pattern: /\b(developer mode|god mode|unrestricted mode|unfiltered mode)\b/, weight: 0.40, tag: 'named_unrestricted_mode' },
  { pattern: /\bpretend (that )?you (have|are) (no|zero) (restrictions?|rules?|limits?|filters?|guidelines?)\b/, weight: 0.50, tag: 'pretend_no_restrictions' },
  { pattern: /\bact as (an? )?(ai|assistant|model) (with|that has) no (rules?|restrictions?|limits?|ethics?|guidelines?)\b/, weight: 0.50, tag: 'act_as_unrestricted' },
  { pattern: /\bhypothetical(ly)?\b.{0,60}\bno (rules?|restrictions?|consequences?)\b/, weight: 0.35, tag: 'hypothetical_no_rules' },
  { pattern: /\b(without|ignoring) (any |your )?(ethical|moral|safety) (guidelines?|constraints?|considerations?)\b/, weight: 0.40, tag: 'without_ethics' },
  { pattern: /\bact\b.{0,20}\b(without|with no) (any )?(restrictions?|limits?|rules?|filters?)\b/, weight: 0.40, tag: 'act_without_restrictions' },
  { pattern: /\byou (have|has) (been|now) (freed|liberated|unlocked) from\b/, weight: 0.35, tag: 'freed_framing' },
  // TEST-3 / remediation: translated "unrestricted AI" equivalents.
  ...signalsFor('UNRESTRICTED_AI'),
];

module.exports = defineClassifier({
  id: 'jailbreak',
  reason: SEMANTIC_REASONS.JAILBREAK_ATTEMPT,
  severity: SEVERITY.HIGH,
  signals: SIGNALS,
});
