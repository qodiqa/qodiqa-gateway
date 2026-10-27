'use strict';

// Hard limits on string field lengths — prevents memory pressure and log
// injection via oversized input.
const MAX_STRING_LEN = 256;
const MAX_IP_LEN     = 45;  // longest possible IPv6 address

// Unix-second bounds: 2001-09-09T01:46:40Z → 2286-11-20T17:46:39Z
// Anything outside this range is either a millisecond timestamp mistake or
// garbage — reject it so evaluators never see nonsense dates.
const MIN_TIMESTAMP_S = 1_000_000_000;
const MAX_TIMESTAMP_S = 9_999_999_999;

// Keys that must never appear anywhere in a context object.
const POISON_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

class PolicyContextError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyContextError';
  }
}

/**
 * Validate and sanitize a raw context object before it reaches any evaluator.
 *
 * Guarantees returned object:
 *   - is a frozen plain object
 *   - contains only the known fields { artifact, userId, callerId, action, tenantId, requestId, ip, timestamp }
 *   - has no prototype-pollution keys
 *   - has correct types for every present field
 *   - has strings within safe length bounds
 *   - has timestamp within the valid Unix-second range (if present)
 *
 * Throws PolicyContextError on any violation — callers must treat this as
 * a DENY with reason INVALID_CONTEXT.
 *
 * @param {Record<string, any>} raw
 * @returns {Readonly<{ artifact: {valid:boolean}, userId:string|null,
 *                       callerId:string|null, action:string|null,
 *                       tenantId:string|null, requestId:string|null,
 *                       ip:string|null, timestamp:number|undefined }>}
 */
function validateContext(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new PolicyContextError('context must be a plain object');
  }

  _rejectPoisonKeys(raw);

  // ── artifact ─────────────────────────────────────────────────────────────
  const artifact = raw.artifact;
  if (artifact === null || typeof artifact !== 'object' || Array.isArray(artifact)) {
    throw new PolicyContextError('context.artifact must be a plain object');
  }
  _rejectPoisonKeys(artifact);

  // ── optional strings ─────────────────────────────────────────────────────
  _assertString('userId',    raw.userId,    MAX_STRING_LEN);
  // authenticated caller identity — omitted here since it
  // shipped (services/policy/evaluatePolicyDecision.js already builds it
  // into rawContext, and requireConsent.js already prefers it over userId),
  // so this whitelist silently dropped it before any evaluator ever saw it.
  // The consent lookup's "prefer callerId" fallback was structurally
  // unreachable from the day shipped — see Findings Register.
  _assertString('callerId',  raw.callerId,  MAX_STRING_LEN);
  _assertString('action',    raw.action,    MAX_STRING_LEN);
  _assertString('tenantId',  raw.tenantId,  MAX_STRING_LEN);
  _assertString('requestId', raw.requestId, MAX_STRING_LEN);
  _assertString('ip',        raw.ip,        MAX_IP_LEN);

  // ── attributes: what the request pipeline supplies to ABAC rules; catalogued, typed, bounded ──
  let attributes;
  if (raw.attributes !== undefined && raw.attributes !== null) {
    try { attributes = require('./abac/attributes').sanitizeSupplied(raw.attributes); } catch (e) { throw new PolicyContextError(`context.attributes: ${e.message}`); }
  }

  // ── timestamp ─────────────────────────────────────────────────────────────
  let timestamp;
  if (raw.timestamp !== undefined && raw.timestamp !== null) {
    if (typeof raw.timestamp !== 'number' || !Number.isFinite(raw.timestamp)) {
      throw new PolicyContextError('context.timestamp must be a finite number');
    }
    if (!Number.isInteger(raw.timestamp)) {
      throw new PolicyContextError('context.timestamp must be an integer (Unix seconds)');
    }
    if (raw.timestamp < MIN_TIMESTAMP_S || raw.timestamp > MAX_TIMESTAMP_S) {
      throw new PolicyContextError(
        `context.timestamp out of valid range [${MIN_TIMESTAMP_S}, ${MAX_TIMESTAMP_S}]`
      );
    }
    timestamp = raw.timestamp;
  }

  return Object.freeze({
    artifact:  Object.freeze({ valid: raw.artifact.valid === true }),
    userId:    _coerceString(raw.userId),
    callerId:  _coerceString(raw.callerId),
    action:    _coerceString(raw.action),
    tenantId:  _coerceString(raw.tenantId),
    requestId: _coerceString(raw.requestId),
    ip:        _coerceString(raw.ip),
    timestamp,
    ...(attributes ? { attributes } : {}),
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _rejectPoisonKeys(obj) {
  for (const key of Object.keys(obj)) {
    if (POISON_KEYS.has(key)) {
      throw new PolicyContextError(`context contains forbidden key: "${key}"`);
    }
  }
}

function _assertString(name, value, maxLen) {
  if (value === undefined || value === null) return;
  if (typeof value !== 'string') {
    throw new PolicyContextError(`context.${name} must be a string`);
  }
  if (value.length > maxLen) {
    throw new PolicyContextError(
      `context.${name} exceeds maximum length of ${maxLen} characters`
    );
  }
}

function _coerceString(value) {
  if (value === undefined || value === null) return null;
  return String(value).slice(0, MAX_STRING_LEN);
}

module.exports = { validateContext, PolicyContextError };
