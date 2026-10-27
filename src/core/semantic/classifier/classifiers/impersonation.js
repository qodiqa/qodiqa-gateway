'use strict';

const { defineClassifier } = require('../baseClassifier');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');

/**
 * Detects requests to have the model impersonate a specific authority
 * figure or system role in a way framed to grant itself (or the requester)
 * elevated trust or approval authority — distinct from ordinary, benign
 * role-play ("write as if you were a pirate").
 */
const SIGNALS = [
  { pattern: /\b(pretend|act as if you are|respond as) (the |an? )?(ceo|administrator|system administrator|root user|security officer|auditor)\b/, weight: 0.40, tag: 'authority_persona' },
  { pattern: /\bimpersonat(e|ing)\b/, weight: 0.35, tag: 'impersonate_keyword' },
  { pattern: /\bact as (a |an )?qodiqa (system )?administrator\b/, weight: 0.55, tag: 'impersonate_qodiqa_admin' },
  { pattern: /\b(approve|authorize|sign off on) (this|the) (request|execution|transaction) as (if you were|the)\b/, weight: 0.45, tag: 'self_approve_as_authority' },
];

module.exports = defineClassifier({
  id: 'impersonation',
  reason: SEMANTIC_REASONS.IMPERSONATION_ATTEMPT,
  severity: SEVERITY.MEDIUM,
  signals: SIGNALS,
});
