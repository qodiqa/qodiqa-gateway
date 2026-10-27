'use strict';

const { defineClassifier } = require('../baseClassifier');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');

/**
 * Detects attempts to have the model send, forward, or upload conversation
 * data, results, or internal state to an external destination.
 */
const SIGNALS = [
  { pattern: /\b(send|forward|upload|exfiltrate|transmit) (this|these|the|all)\b.{0,50}\b(to|toward)\b.{0,30}\bhttps?:\/\//, weight: 0.55, tag: 'send_to_url' },
  // Bare mention of the word "exfiltration" (e.g. a benign question like "what
  // is data exfiltration?") must never solo-trigger WARN on its own — kept low
  // enough to only contribute via noisy-OR alongside a real action/destination
  // signal above. See calibration finding CAL-01 in docs/architecture/content-screening.md.
  { pattern: /\bexfiltrat(e|ion)\b/, weight: 0.15, tag: 'exfiltrate_keyword' },
  { pattern: /\b(email|post|upload) (this|these|the) (data|results?|conversation|logs?|output)\b.{0,40}\bto\b/, weight: 0.35, tag: 'transfer_to_destination' },
  { pattern: /\bforward (all |every )?(conversation|chat|message) history\b/, weight: 0.40, tag: 'forward_history' },
  { pattern: /\bcopy (this|the) (data|output|response) (out|externally|off[- ]?platform)\b/, weight: 0.30, tag: 'copy_off_platform' },
];

module.exports = defineClassifier({
  id: 'data-exfiltration',
  reason: SEMANTIC_REASONS.DATA_EXFILTRATION,
  severity: SEVERITY.CRITICAL,
  signals: SIGNALS,
});
