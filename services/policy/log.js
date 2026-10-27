'use strict';

// Policy-level structured logger — separate from the gateway request logger.
// Writes one JSON line per evaluation to stdout. No timestamps derived from
// Date.now() in the output — callers supply the context timestamp when known.
//
// Schema:
//   ts          ISO-8601 wall-clock write time (for log ingestion ordering only)
//   level       INFO | WARN | ERROR (per log level convention)
//   event       POLICY_EXECUTE | POLICY_BLOCK | POLICY_LOAD | POLICY_ERROR
//   policyId    which policy produced the decision (or 'SYSTEM' / 'LOADER')
//   decision    EXECUTE | BLOCK
//   reason      enum string — never free-text from untrusted input
//   requestId   from gateway (optional)
//   userId      from context (optional — included only when decision is DENY)

const { emit: _emitStructured } = require('../logger');

const SAFE_REASON = /^[A-Z0-9_]{1,64}$/;

function _levelForEvent(event) {
  if (event === 'POLICY_BLOCK' || event === 'POLICY_RELOAD_FAILED') return 'WARN';
  if (event === 'POLICY_ERROR') return 'ERROR';
  return 'INFO';
}

function _emit(event, fields) {
  // Sanitise any free-text fields before they reach the log line.
  const safe = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined || v === null) continue;
    safe[k] = typeof v === 'string' ? _sanitize(v) : v;
  }
  try {
    _emitStructured(_levelForEvent(event), event, safe);
  } catch {
    // write failure must never propagate into the enforcement path.
  }
}

function _sanitize(str) {
  // Strip control characters and limit length — prevents log injection.
  return str.replace(/[\x00-\x1f\x7f]/g, '').slice(0, 256);
}

function _safeReason(reason) {
  // Enforce enum-like format: only uppercase letters and underscores.
  // If caller passes something unexpected, replace with a generic token.
  if (typeof reason === 'string' && SAFE_REASON.test(reason)) return reason;
  return 'UNKNOWN_REASON';
}

/**
 * Log a policy engine evaluation result.
 *
 * @param {{ decision, reason, policyId }} decisionObj
 * @param {object} [meta]  - { requestId, userId }
 */
function logDecision(decisionObj, meta = {}) {
  const event = decisionObj.decision === 'EXECUTE' ? 'POLICY_EXECUTE' : 'POLICY_BLOCK';
  _emit(event, {
    decision:  decisionObj.decision,
    reason:    _safeReason(decisionObj.reason),
    policyId:  decisionObj.policyId,
    requestId: meta.requestId  || undefined,
    // userId only on BLOCK to avoid PII in success-path logs
    userId:    decisionObj.decision !== 'EXECUTE' ? (meta.userId || undefined) : undefined,
  });
}

/**
 * Log a policy load / reload event.
 *
 * @param {'LOAD'|'RELOAD'|'RELOAD_FAILED'|'ACTIVE'} sub
 * @param {object} [meta]  - { count, source, hash, error }
 */
function logLoad(sub, meta = {}) {
  _emit(`POLICY_${sub}`, {
    count:  meta.count  || undefined,
    source: meta.source ? _sanitize(meta.source) : undefined,
    hash:   meta.hash   || undefined,
    error:  meta.error  || undefined,
  });
}

/**
 * Log the policyHash binding on an EXECUTE decision.
 * Called by the enforcement middleware after computing the hash so the exact
 * ruleset that permitted a request is recorded alongside the requestId.
 *
 * @param {string} policyHash  - 64-char hex SHA-256 of the active policy set
 * @param {object} [meta]      - { requestId }
 */
function logHashBound(policyHash, meta = {}) {
  _emit('POLICY_HASH_BOUND', {
    policyHash: typeof policyHash === 'string' ? policyHash.slice(0, 64) : undefined,
    requestId:  meta.requestId || undefined,
  });
}

/**
 * Log an unexpected engine or context error.
 *
 * @param {string} reason  - INVALID_CONTEXT | POLICY_ENGINE_ERROR | …
 * @param {object} [meta]  - { requestId, policyId, error }
 */
function logError(reason, meta = {}) {
  _emit('POLICY_ERROR', {
    reason:    _safeReason(reason),
    requestId: meta.requestId || undefined,
    policyId:  meta.policyId  || undefined,
    error:     meta.error     || undefined,
  });
}

module.exports = { logDecision, logLoad, logError, logHashBound };
