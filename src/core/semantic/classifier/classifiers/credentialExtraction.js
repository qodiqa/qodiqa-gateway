'use strict';

const { defineClassifier } = require('../baseClassifier');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');
const { signalsFor } = require('../../i18nSignals');

/**
 * Detects attempts to extract QODIQA's own operational secrets — signing
 * tokens, encryption keys, API keys, environment variables — via the model.
 * Distinct from piiExtraction.js (which targets personal data about
 * individuals rather than platform credentials).
 */
const SIGNALS = [
  { pattern: /\b(qodiqa_sign_token|qodiqa_key_encryption_key|qodiqa_pg_password|qodiqa_ops_token)\b/, weight: 0.60, tag: 'named_secret_env_var' },
  { pattern: /\b(reveal|show|print|give me|dump) (your |the )?(api key|signing token|access token|secret key|private key)\b/, weight: 0.55, tag: 'reveal_credential' },
  { pattern: /\b(dump|list|print) (all |the )?(environment variables?|env vars?|secrets?)\b/, weight: 0.50, tag: 'dump_env' },
  { pattern: /\bwhat (is|are) your (api key|credentials?|password|secret)\b/, weight: 0.45, tag: 'what_is_credential' },
  // TEST-3 / remediation: translated "reveal your signing token" equivalents.
  ...signalsFor('REVEAL_CREDENTIAL'),
];

module.exports = defineClassifier({
  id: 'credential-extraction',
  reason: SEMANTIC_REASONS.CREDENTIAL_EXTRACTION,
  severity: SEVERITY.CRITICAL,
  signals: SIGNALS,
});
