'use strict';

/**
 * audit-persistence readiness latch.
 *
 * Problem: with the audit volume full (ENOSPC) or otherwise unwritable, every /ai/chat request fails closed with
 * 503 AUDIT_PERSISTENCE_FAILED, yet GET /ready kept answering 200 — a load balancer kept routing all traffic to an
 * instance that could not serve a single request.
 *
 * Rule (documented, deliberately non-flapping):
 *   • Only an AUDIT_PERSISTENCE_FAILED from appendMandatory() counts as a failure. Each one already represents
 *     1 + QODIQA_AUDIT_APPEND_MAX_RETRIES attempts with back-off, so a single transient fsync hiccup that the retry
 *     absorbs never reaches this module at all.
 *   • The latch ENGAGES after QODIQA_READY_AUDIT_FAILURE_THRESHOLD (default 3) CONSECUTIVE failures with no
 *     successful mandatory append in between. A single failed request never flips readiness.
 *   • Any successful mandatory append CLEARS the latch and the counter immediately.
 *   • While latched, isHealthy() runs a bounded writability probe of the audit directory (create/truncate + write +
 *     fsync of one small sentinel file, at most once every QODIQA_READY_AUDIT_PROBE_INTERVAL_MS, default 5000).
 *     A successful probe releases the latch. This exists because a not-ready instance receives no traffic, so
 *     without a probe it could never observe the success that clears it (a permanent self-inflicted outage after
 *     the disk is freed). If the probe passes but real appends still fail, the latch re-engages after another
 *     `threshold` consecutive failures — bounded flapping, never a stuck state.
 *   • Non-persistence errors (validation, duplicate, replay — deterministic, caller-caused) are neither success nor
 *     failure: they say nothing about the storage.
 *
 * Pure in-memory state; the only I/O is the latched-state probe. Never throws.
 */

const fs   = require('fs');
const path = require('path');

function _int(v, d) { const n = parseInt(v, 10); return Number.isFinite(n) && n > 0 ? n : d; }

const FAILURE_THRESHOLD = _int(process.env.QODIQA_READY_AUDIT_FAILURE_THRESHOLD, 3);
const PROBE_INTERVAL_MS = _int(process.env.QODIQA_READY_AUDIT_PROBE_INTERVAL_MS, 5000);
const PROBE_FILE        = '.qodiqa-ready-probe';

let _consecutive = 0;
let _latched     = false;
let _lastProbeAt = 0;
let _lastFailureAt = null;

function _emit(level, event, extra) {
  try { require('../../services/logger').emit(level, event, extra); } catch { /* logging is best-effort */ }
}

function recordSuccess() {
  if (_latched) _emit('INFO', 'READY_AUDIT_PERSISTENCE_RECOVERED', { via: 'append' });
  _consecutive = 0;
  _latched = false;
}

function recordFailure(threshold = FAILURE_THRESHOLD) {
  _consecutive++;
  _lastFailureAt = Date.now();
  if (!_latched && _consecutive >= threshold) {
    _latched = true;
    _lastProbeAt = Date.now(); // first probe one interval later — the failure just happened
    _emit('CRITICAL', 'READY_AUDIT_PERSISTENCE_FAILING', { consecutiveFailures: _consecutive, threshold });
  }
}

/** Wraps an appendMandatory-compatible function so its outcomes feed the latch. Behaviour is otherwise identical. */
function track(appendFn) {
  return async function trackedAppendMandatory(...args) {
    let entry;
    try {
      entry = await appendFn(...args);
    } catch (err) {
      if (err && err.code === 'AUDIT_PERSISTENCE_FAILED') recordFailure();
      throw err;
    }
    recordSuccess();
    return entry;
  };
}

function _defaultProbeDir() {
  try { return path.dirname(require('../core/audit/audit-log').LOG_PATH); } catch { return null; }
}

function _probe(dir) {
  if (!dir) return false;
  let fd = null;
  try {
    fd = fs.openSync(path.join(dir, PROBE_FILE), 'w');
    fs.writeSync(fd, `${Date.now()}\n`);
    fs.fsyncSync(fd);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* ignore */ } }
  }
}

/**
 * true unless the latch is engaged and the (rate-limited) writability probe still fails.
 * @param {object} [opts] test seams: now, probeDir, probe, intervalMs
 */
function isHealthy({ now = Date.now(), probeDir, probe = _probe, intervalMs = PROBE_INTERVAL_MS } = {}) {
  if (!_latched) return true;
  if (now - _lastProbeAt < intervalMs) return false;
  _lastProbeAt = now;
  const ok = probe(probeDir !== undefined ? probeDir : _defaultProbeDir());
  if (ok) {
    _emit('INFO', 'READY_AUDIT_PERSISTENCE_RECOVERED', { via: 'probe' });
    _consecutive = 0;
    _latched = false;
    return true;
  }
  return false;
}

function state() {
  return { latched: _latched, consecutiveFailures: _consecutive, threshold: FAILURE_THRESHOLD, lastFailureAt: _lastFailureAt };
}

function _resetForTests() { _consecutive = 0; _latched = false; _lastProbeAt = 0; _lastFailureAt = null; }

module.exports = { track, recordSuccess, recordFailure, isHealthy, state, FAILURE_THRESHOLD, PROBE_INTERVAL_MS, PROBE_FILE, _resetForTests };
