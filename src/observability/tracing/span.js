'use strict';

// Span lifecycle management.
//
// Spans are mutable value objects — they accumulate attributes and events
// during a request and are serialized to OTLP JSON on export.
//
// Attribute redaction: any attribute whose key matches a sensitive stem
// (same policy as log shipping schema) is replaced with '[REDACTED]'.

const { _isSensitive } = require('../logShipping/schema');

// ── Constants (OTel spec values) ──────────────────────────────────────────────

const STATUS_UNSET    = 0;
const STATUS_OK       = 1;
const STATUS_ERROR    = 2;

const SPAN_KIND_INTERNAL = 1;
const SPAN_KIND_SERVER   = 2;
const SPAN_KIND_CLIENT   = 3;
const SPAN_KIND_PRODUCER = 4;
const SPAN_KIND_CONSUMER = 5;

// ── Helpers ───────────────────────────────────────────────────────────────────

function _msToNano(ms) {
  return String(BigInt(Math.round(ms)) * 1_000_000n);
}

function _redactAttrs(attrs) {
  if (!attrs || typeof attrs !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(attrs)) {
    out[k] = _isSensitive(k) ? '[REDACTED]' : v;
  }
  return out;
}

// ── Span factory ──────────────────────────────────────────────────────────────

/**
 * Create a new mutable span.
 *
 * @param {{ name, traceId, spanId, parentSpanId?, sampled?, kind?, attributes? }} opts
 * @returns {Span}
 */
function createSpan({
  name,
  traceId,
  spanId,
  parentSpanId = null,
  sampled      = true,
  kind         = SPAN_KIND_INTERNAL,
  attributes   = {},
}) {
  const _startMs = Date.now();
  let   _endMs   = null;
  let   _status  = { code: STATUS_UNSET };
  let   _attrs   = _redactAttrs(attributes);
  const _events  = [];
  let   _finished = false;

  const span = {
    name,
    traceId,
    spanId,
    parentSpanId,
    sampled,
    kind,

    get startMs()  { return _startMs; },
    get endMs()    { return _endMs; },
    get status()   { return _status; },
    get finished() { return _finished; },

    /** Merge additional attributes (ignored after end). */
    setAttributes(attrs) {
      if (_finished) return;
      Object.assign(_attrs, _redactAttrs(attrs));
    },

    /**
     * Set terminal status.
     * @param {'ok'|'error'} code
     * @param {string}       [message]
     */
    setStatus(code, message) {
      if (_finished) return;
      if (code === 'ok')    _status = { code: STATUS_OK };
      if (code === 'error') _status = { code: STATUS_ERROR, message: message || '' };
    },

    /** Record an exception as a span event and mark status ERROR. */
    recordException(err) {
      if (_finished) return;
      _events.push({
        name:          'exception',
        timeUnixNano:  _msToNano(Date.now()),
        attributes: {
          'exception.type':    err && err.name    ? err.name    : 'Error',
          'exception.message': err && err.message ? err.message : String(err),
          'exception.stack':   err && err.stack   ? err.stack   : '',
        },
      });
      _status = { code: STATUS_ERROR, message: err && err.message ? err.message : String(err) };
    },

    /** Mark the span as finished. Ignored if already ended. */
    end(endTime) {
      if (_finished) return;
      _endMs    = endTime !== undefined ? endTime : Date.now();
      _finished = true;
    },

    /** Serialize to OTLP JSON span object. */
    toOtlp() {
      const obj = {
        traceId,
        spanId,
        name,
        kind,
        startTimeUnixNano: _msToNano(_startMs),
        endTimeUnixNano:   _msToNano(_endMs !== null ? _endMs : Date.now()),
        attributes: Object.entries(_attrs).map(([k, v]) => ({
          key:   k,
          value: { stringValue: String(v) },
        })),
        events: _events,
        status: _status,
      };
      if (parentSpanId) obj.parentSpanId = parentSpanId;
      return obj;
    },
  };

  return span;
}

module.exports = {
  createSpan,
  STATUS_UNSET,
  STATUS_OK,
  STATUS_ERROR,
  SPAN_KIND_INTERNAL,
  SPAN_KIND_SERVER,
  SPAN_KIND_CLIENT,
  SPAN_KIND_PRODUCER,
  SPAN_KIND_CONSUMER,
};
