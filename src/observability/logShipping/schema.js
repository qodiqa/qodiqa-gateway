'use strict';

// Standardized log event schema and redaction for outbound log shipping.
//
// normalizeEvent(raw, defaults) → standardized event object
//   Extracts known fields from any raw log event (from emit() or elsewhere),
//   applies redaction, and returns the QODIQA standard schema.
//
// Redaction policy:
//   Any field whose name (case-insensitive, symbols stripped) matches a known
//   sensitive key is replaced with '[REDACTED]'.  Redaction is applied to the
//   full event tree including nested objects.
//
//   Fail-closed: if redaction itself throws, a safe minimal event is returned
//   rather than the unredacted original.

// ── Redaction ─────────────────────────────────────────────────────────────────

// Canonical set of sensitive field name stems (normalized: lowercase, no symbols).
// Matched after lowercasing and stripping all non-alphanumeric characters from
// the field name being checked.
const SENSITIVE_STEMS = new Set([
  'authorization',
  'apikey',
  'apikeyid',
  'password',
  'passwd',
  'secret',
  'token',
  'privatekey',
  'signingkey',
  'signaturekey',
  'hsmref',
  'hsmkey',
  'credentials',
  'credential',
  'keycontents',
  'keydata',
  'bearer',
  'accesskey',
  'secretkey',
  'clientsecret',
]);

function _normalizeFieldName(key) {
  return String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function _isSensitive(key) {
  return SENSITIVE_STEMS.has(_normalizeFieldName(key));
}

function _redact(value, depth) {
  if (depth > 8) return value;
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(v => _redact(v, depth + 1));

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = _isSensitive(k) ? '[REDACTED]' : _redact(v, depth + 1);
  }
  return out;
}

// ── Normalization ─────────────────────────────────────────────────────────────

/**
 * Normalize a raw log event into the QODIQA standard outbound log schema.
 *
 * @param {object} raw       — raw event (from emit(), or any source)
 * @param {object} defaults  — service/environment defaults from config
 * @returns {object}         — normalized, redacted event
 */
function normalizeEvent(raw, defaults = {}) {
  const src = raw || {};

  const normalized = {
    timestamp:   src.timestamp   || src.ts          || new Date().toISOString(),
    service:     defaults.service     || src.service      || 'qodiqa',
    environment: defaults.environment || src.environment  || 'development',
    tenantId:    src.tenantId    || null,
    tenantSlug:  src.tenantSlug  || null,
    eventType:   src.eventType   || src.event        || 'LOG',
    severity:    src.severity    || src.level        || 'INFO',
    requestId:   src.requestId   || null,
    traceId:     src.traceId     || null,
    message:     src.message     || src.msg          || '',
    metadata:    _buildMetadata(src),
  };

  try {
    return _redact(normalized, 0);
  } catch {
    // Redaction failure: return a safe minimal envelope (fail-closed)
    return {
      timestamp:   normalized.timestamp,
      service:     normalized.service,
      environment: normalized.environment,
      tenantId:    null,
      tenantSlug:  null,
      eventType:   'LOG',
      severity:    'WARN',
      requestId:   null,
      traceId:     null,
      message:     '[REDACTION_FAILURE: log event suppressed]',
      metadata:    {},
    };
  }
}

// Extract metadata by excluding the well-known top-level schema fields.
const SCHEMA_KEYS = new Set([
  'timestamp', 'ts', 'service', 'environment',
  'tenantId', 'tenantSlug',
  'eventType', 'event',
  'severity', 'level',
  'requestId', 'traceId',
  'message', 'msg',
]);

function _buildMetadata(src) {
  const meta = {};
  for (const [k, v] of Object.entries(src)) {
    if (!SCHEMA_KEYS.has(k)) meta[k] = v;
  }
  return meta;
}

module.exports = { normalizeEvent, _redact, _isSensitive };
