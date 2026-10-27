'use strict';

const { defineClassifier } = require('../baseClassifier');
const { coOccurs } = require('../../textSignals');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');

/**
 * Detects requests framed to extract personally identifiable information
 * about a named or described individual — the combination of a PII-category
 * term with a retrieval verb, not either alone (a prompt merely explaining
 * what a "social security number" is contains the term but not the intent).
 */
const PII_TERM = /\b(social security number|ssn|passport number|credit card number|home address|driver'?s license number|date of birth|bank account number)\b/;
const RETRIEVAL_VERB = /\b(give me|find|look ?up|reveal|list|provide|tell me)\b/;

const SIGNALS = [
  { pattern: PII_TERM, weight: 0.30, tag: 'pii_term' },
  { pattern: RETRIEVAL_VERB, weight: 0.15, tag: 'retrieval_verb' },
  { pattern: /\b(employees?|customers?|users?)\b.{0,30}\b(emails?|phone numbers?|addresses?)\b/, weight: 0.30, tag: 'bulk_contact_request' },
];

module.exports = defineClassifier({
  id: 'pii-extraction',
  reason: SEMANTIC_REASONS.PII_EXTRACTION,
  severity: SEVERITY.CRITICAL,
  signals: SIGNALS,
  refine(text, base) {
    let confidence = base.confidence;
    if (coOccurs(text, PII_TERM, RETRIEVAL_VERB, 100)) {
      confidence = Math.min(1, confidence + 0.35);
    }
    return { confidence, matched: base.matched };
  },
});
