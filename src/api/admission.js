'use strict';

/**
 * admission control: an in-flight limit per route family with a small bounded FIFO queue.
 *
 * Above the ceiling the audit measured, and's baseline re-measured, collapse instead of refusal: nothing was
 * refused, requests queued inside the process for 10-60 s, the PG pool exhausted and the log flooded
 *. This limiter refuses cleanly and cheaply instead:
 *
 *   • a request is ADMITTED when fewer than maxInFlight requests of its family are in flight;
 *   • otherwise it WAITS in a FIFO queue of at most maxQueue, for at most queueTimeoutMs;
 *   • otherwise (queue full, or wait expired) it is REFUSED: 503 {decision:'BLOCK', reason:'SERVER_OVERLOADED'}
 *     with Retry-After, in both D7 block-HTTP modes.
 *
 * It is mounted in front of everything expensive — for /ai/chat right after the IP limiter and BEFORE content
 * type, schema, artifact decode, signature verification and nonce registration — so a refusal costs microseconds,
 * writes nothing to the audit chain or the transparency log, never reaches a provider, and leaves the artifact's
 * nonce unconsumed (a client may retry the SAME artifact after Retry-After; it is not a replay).
 *
 * A slot is held from admission until the response 'finish' or the connection 'close' (whichever comes first,
 * released exactly once). A queued request whose client disconnects leaves the queue.
 *
 * Observability: qodiqa_admission_rejected_total{route,cause} and qodiqa_admission_{inflight,queued}{route}; no
 * per-refusal log line (that would be the log flood again) — one ADMISSION_REJECTED_SUMMARY event per
 * SUMMARY_INTERVAL_MS while refusals happen. saturated() (queue full) drives GET /ready.
 */

const { emit } = require('../../services/logger');
const metrics = require('../observability/metrics');

const SUMMARY_INTERVAL_MS = 10_000;

// 2026-10-06: while the audit mirror backlog is above its bound (src/core/audit/audit-log.js
// mirrorBackpressureEngaged), new work is refused up front with cause audit_backlog — admitting it would only grow the
// in-memory backlog (and the heap) further. Lazy so this module never loads the audit chain at require time.
function _auditBacklogEngaged() {
  try { return require('../core/audit/audit-log').mirrorBackpressureEngaged() === true; } catch { return false; }
}

function _int(name, dflt, min, max) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return dflt;
  const v = Number(raw);
  return Number.isInteger(v) && v >= min && v <= max ? v : dflt; // the boot rule perf.admission refuses bad values
}

// The route families with a limiter, their environment prefix and defaults. /verify, the agent action surface and the tool gateway join /sign and /ai/chat. A tool call holds its slot
// for the whole upstream call (seconds), so tools get a family of their own and cannot starve the fast authorisation calls.
const FAMILIES = Object.freeze({
  sign:    { prefix: 'QODIQA_ADMISSION_SIGN',    inFlight: 64, queue: 128 },
  ai_chat: { prefix: 'QODIQA_ADMISSION_AI_CHAT', inFlight: 16, queue: 32 },
  verify:  { prefix: 'QODIQA_ADMISSION_VERIFY',  inFlight: 64, queue: 128 },
  actions: { prefix: 'QODIQA_ADMISSION_ACTIONS', inFlight: 64, queue: 128 },
  tools:   { prefix: 'QODIQA_ADMISSION_TOOLS',   inFlight: 16, queue: 32 },
});

function configFor(route) {
  const fam = FAMILIES[route];
  if (!fam) throw new Error(`unknown admission route family: ${route}`);
  const P = fam.prefix;
  const d = { inFlight: fam.inFlight, queue: fam.queue };
  return {
    maxInFlight:    _int(`${P}_MAX_INFLIGHT`, d.inFlight, 1, 100_000),
    maxQueue:       _int(`${P}_QUEUE`, d.queue, 0, 1_000_000),
    queueTimeoutMs: _int(`${P}_QUEUE_TIMEOUT_MS`, 1000, 1, 60_000),
    retryAfterSec:  _int('QODIQA_ADMISSION_RETRY_AFTER_SEC', 1, 1, 3600),
  };
}

function createAdmission(route, cfg = configFor(route), { auditBacklog = _auditBacklogEngaged } = {}) {
  let inFlight = 0;
  const queue = []; // { admit, refuse, timer }
  const rejected = { queue_full: 0, queue_timeout: 0, audit_backlog: 0 };
  let sinceSummary = { queue_full: 0, queue_timeout: 0, audit_backlog: 0 };
  let summaryTimer = null;

  const gauges = () => {
    try { metrics.admissionInFlight.set({ route }, inFlight); metrics.admissionQueued.set({ route }, queue.length); } catch { /* metrics are best-effort */ }
  };
  const summarize = () => {
    summaryTimer = null;
    if (sinceSummary.queue_full + sinceSummary.queue_timeout + sinceSummary.audit_backlog === 0) return;
    emit('WARN', 'ADMISSION_REJECTED_SUMMARY', { route, windowMs: SUMMARY_INTERVAL_MS, ...sinceSummary, inFlight, queued: queue.length, maxInFlight: cfg.maxInFlight, maxQueue: cfg.maxQueue });
    sinceSummary = { queue_full: 0, queue_timeout: 0, audit_backlog: 0 };
  };
  const countRejection = (cause) => {
    rejected[cause]++; sinceSummary[cause]++;
    try { metrics.admissionRejectedTotal.inc({ route, cause }); } catch { /* best-effort */ }
    if (!summaryTimer) { summaryTimer = setTimeout(summarize, SUMMARY_INTERVAL_MS); if (summaryTimer.unref) summaryTimer.unref(); }
  };
  const refuse = (req, res, cause) => {
    countRejection(cause);
    if (res.headersSent) return;
    res.set('Retry-After', String(cfg.retryAfterSec));
    res.status(503).json({ decision: 'BLOCK', reason: 'SERVER_OVERLOADED', details: {}, requestId: req.requestId ?? null });
  };
  const release = () => {
    inFlight--;
    while (queue.length && inFlight < cfg.maxInFlight) { const w = queue.shift(); clearTimeout(w.timer); w.admit(); }
    gauges();
  };
  const hold = (res) => {
    inFlight++;
    let done = false;
    const once = () => { if (done) return; done = true; release(); };
    res.once('finish', once);
    res.once('close', once);
    gauges();
  };

  function middleware(req, res, next) {
    if (auditBacklog()) return refuse(req, res, 'audit_backlog');
    if (inFlight < cfg.maxInFlight) { hold(res); return next(); }
    if (queue.length >= cfg.maxQueue) return refuse(req, res, 'queue_full');
    const waiter = {};
    const leave = () => { const i = queue.indexOf(waiter); if (i >= 0) queue.splice(i, 1); clearTimeout(waiter.timer); gauges(); };
    // the client-gone signal is the RESPONSE's 'close' — on current Node req 'close'
    // also fires merely because the request body has been fully read, which is not a disconnect, and once that has
    // happened it never fires again for a real one. A queued request has not been answered, so any res 'close' here
    // (writableEnded false) is a lost connection.
    waiter.admit = () => { res.off('close', onClientGone); hold(res); next(); };
    waiter.timer = setTimeout(() => { res.off('close', onClientGone); leave(); refuse(req, res, 'queue_timeout'); }, cfg.queueTimeoutMs);
    const onClientGone = () => { if (!res.writableEnded) leave(); };
    res.once('close', onClientGone);
    queue.push(waiter);
    gauges();
    return undefined;
  }

  return {
    route,
    config: cfg,
    middleware,
    saturated: () => cfg.maxQueue === 0 ? inFlight >= cfg.maxInFlight : queue.length >= cfg.maxQueue,
    stats: () => ({ route, inFlight, queued: queue.length, maxInFlight: cfg.maxInFlight, maxQueue: cfg.maxQueue, queueTimeoutMs: cfg.queueTimeoutMs, rejected: { ...rejected } }),
  };
}

// One limiter per route family per process — /ai/chat and /ai/chat/stream share a router and therefore a limiter.
const _instances = new Map();
function get(route) {
  if (!_instances.has(route)) _instances.set(route, createAdmission(route));
  return _instances.get(route);
}
function allStats() { return [..._instances.values()].map((a) => a.stats()); }
function anySaturated() { return [..._instances.values()].some((a) => a.saturated()); }

module.exports = { createAdmission, configFor, get, allStats, anySaturated, FAMILIES };
