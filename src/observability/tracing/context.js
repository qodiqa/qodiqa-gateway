'use strict';

// W3C Trace Context propagation and AsyncLocalStorage-based active span management.
//
// W3C traceparent format:  00-<traceId:32hex>-<spanId:16hex>-<flags:2hex>
//   traceId   — 128-bit trace identifier (16 bytes, 32 lowercase hex chars)
//   spanId    — 64-bit span identifier  (8 bytes,  16 lowercase hex chars)
//   flags     — bit 0 = sampled (01 = yes, 00 = no)
//
// The active span context is stored in an AsyncLocalStorage, so it propagates
// automatically through async/await and Promise chains without explicit threading.

const crypto              = require('crypto');
const { AsyncLocalStorage } = require('async_hooks');

const _storage = new AsyncLocalStorage();

// ── ID generation ─────────────────────────────────────────────────────────────

function generateTraceId() {
  return crypto.randomBytes(16).toString('hex');
}

function generateSpanId() {
  return crypto.randomBytes(8).toString('hex');
}

// ── W3C traceparent parsing / formatting ──────────────────────────────────────

const TRACEPARENT_RE = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;

/**
 * Parse a W3C traceparent header value.
 * Returns null for any invalid or all-zero input.
 *
 * @param {string} header
 * @returns {{ traceId, parentSpanId, sampled }|null}
 */
function parseTraceparent(header) {
  if (!header || typeof header !== 'string') return null;
  const m = TRACEPARENT_RE.exec(header.trim().toLowerCase());
  if (!m) return null;
  const [, traceId, parentSpanId, flags] = m;
  if (traceId === '0'.repeat(32) || parentSpanId === '0'.repeat(16)) return null;
  return { traceId, parentSpanId, sampled: (parseInt(flags, 16) & 0x01) === 1 };
}

/**
 * Format a W3C traceparent header value.
 *
 * @param {{ traceId: string, spanId: string, sampled: boolean }} opts
 * @returns {string}
 */
function formatTraceparent({ traceId, spanId, sampled }) {
  return `00-${traceId}-${spanId}-${sampled ? '01' : '00'}`;
}

// ── AsyncLocalStorage context ─────────────────────────────────────────────────

/** @returns {{ traceId, spanId, sampled, span }|null} */
function currentContext() {
  return _storage.getStore() || null;
}

/**
 * Run fn synchronously in a new context.
 * If fn returns a Promise, the context is propagated through its resolution.
 */
function runWithContext(ctx, fn) {
  return _storage.run(ctx, fn);
}

/** @returns {any|null} */
function getActiveSpan() {
  const ctx = currentContext();
  return ctx ? ctx.span || null : null;
}

module.exports = {
  generateTraceId,
  generateSpanId,
  parseTraceparent,
  formatTraceparent,
  currentContext,
  runWithContext,
  getActiveSpan,
  _storage,
};
