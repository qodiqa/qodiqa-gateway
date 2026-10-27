'use strict';

/**
 * Pre-authentication rejects —.
 *
 * A request rejected BEFORE its caller is authenticated (no artifact, an
 * undecodable or oversized artifact, an invalid body, an invalid idempotency
 * key, and every artifact-validation failure — unknown key, bad signature,
 * expired / not-yet-valid — i.e. validateBoundRequest Step 1) is attacker-
 * controlled volume. each one was fsynced into the audit chain and
 * given a signed transparency leaf, so an anonymous caller could grow the
 * permanent evidence and its cost without limit.
 *
 * Those rejects now leave the chain and the transparency log untouched. They
 * are recorded as:
 *   - qodiqa_preauth_rejects_total{reason, route}   (every reject), and
 *   - a sampled WARN event PREAUTH_REJECT: the first SAMPLE_FIRST per
 *     (reason, client IP) per minute, then 1 in SAMPLE_EVERY; the rest are
 *     counted and summarised once per minute in PREAUTH_REJECTS_SUPPRESSED.
 * Memory is bounded (MAX_KEYS distinct (reason, IP) pairs per minute; beyond
 * that, new pairs are only counted). Nothing is persisted; the client response
 * is unchanged.
 *
 * Everything after a verified signature (tenant/org checks, request binding,
 * replay, anomaly, consent, policy, semantic, provider) still goes to the
 * audit chain and the transparency log — those decisions have an
 * authenticated key behind them.
 */

const { emit } = require('../../../services/logger');
const promMetrics = require('../../observability/metrics');

const SAMPLE_FIRST = 10;
const SAMPLE_EVERY = 100;
const WINDOW_MS    = 60_000;
const MAX_KEYS     = 10_000;

let _win = { start: Date.now(), counts: new Map(), suppressed: 0 };

function _roll(now) {
  if (now - _win.start < WINDOW_MS) return;
  if (_win.suppressed > 0) {
    emit('WARN', 'PREAUTH_REJECTS_SUPPRESSED', { suppressed: _win.suppressed, windowMs: WINDOW_MS, distinctSources: _win.counts.size });
  }
  _win = { start: now, counts: new Map(), suppressed: 0 };
}

/**
 * @param {{ route: string|null, reason: string, stage: string|null, clientIp: string|null, requestId: string|null, details?: object|null }} r
 */
function recordPreAuthReject({ route = null, reason, stage = null, clientIp = null, requestId = null, details = null }) {
  try { promMetrics.preAuthRejectsTotal.inc({ reason, route: route || 'unknown' }); } catch { /* fail-safe */ }
  const now = Date.now();
  _roll(now);
  const key = `${reason}|${clientIp ?? 'unknown'}`;
  if (!_win.counts.has(key) && _win.counts.size >= MAX_KEYS) { _win.suppressed++; return; }
  const n = (_win.counts.get(key) || 0) + 1;
  _win.counts.set(key, n);
  if (n <= SAMPLE_FIRST || n % SAMPLE_EVERY === 0) {
    emit('WARN', 'PREAUTH_REJECT', { route, reason, stage, clientIp, requestId, countThisMinute: n, sampled: n > SAMPLE_FIRST, ...(details ? { details } : {}) });
  } else {
    _win.suppressed++;
  }
}

function _resetForTest() { _win = { start: Date.now(), counts: new Map(), suppressed: 0 }; }

module.exports = { recordPreAuthReject, SAMPLE_FIRST, SAMPLE_EVERY, WINDOW_MS, MAX_KEYS, _resetForTest };
