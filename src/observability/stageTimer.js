'use strict';

/**
 * permanent per-request stage timer (replaces the auditor's require-hook,
 *).
 *
 * OFF by default. Enabled only by QODIQA_BENCH_STAGE_TIMING=true, read ONCE at
 * module load; bootValidator rule `bench.stage_timing` refuses it in production.
 * When off, every inline call site is guarded by the constant `ON` — no hrtime, no
 * record, no AsyncLocalStorage, no closure — and every wrapper returns the original
 * function object, so the timer itself allocates nothing per request. What the
 * tests assert is the structural half (src/observability/__tests__/stageTimer.test.js
 * ST-01/ST-02: wrappers are identity when off); the runtime cost of the remaining
 * boolean guards is measured, not asserted.
 *
 * Stage ids follow the audit's ordered stage table (audit/independent-2026-09-28/
 * sections/01-request-flow-and-crypto.md §A.2, stages 0–36 + 24a). Stages marked
 * `parent` are nested inside another stage and excluded from the stage sum, so
 * sum(stages) vs the server total leaves an honest residual.
 *
 * Usage at a call site:
 *   const t = ST.ON ? ST.start() : 0;
 *   ...work...
 *   if (ST.ON) ST.end('S18', t);
 *
 * Records (one per HTTP request, server total = first middleware → response
 * 'finish') go to a bounded ring buffer read by the bench-only, loopback-only
 * GET /__bench/stages endpoint (mounted only when ON; see src/app.js).
 */

const ON = process.env.QODIQA_BENCH_STAGE_TIMING === 'true';

const STAGES = Object.freeze({
  S00: { n: 0, name: 'trust_proxy_config', note: 'static app.set at boot; no per-request work' },
  S01: { n: 1, name: 'security_headers' },
  S02: { n: 2, name: 'csp_override' },
  S03: { n: 3, name: 'proxy_validation' },
  S04: { n: 4, name: 'cors' },
  S05: { n: 5, name: 'request_id' },
  S06: { n: 6, name: 'client_ip' },
  S07: { n: 7, name: 'tracing_root_span' },
  S08: { n: 8, name: 'request_drain' },
  S09: { n: 9, name: 'cache_control' },
  S10: { n: 10, name: 'json_body_parse' },
  S11: { n: 11, name: 'metrics_wrapper' },
  S11r: { n: 11.5, name: 'ip_rate_limit', note: 'per-client-IP limit before the route' },
  S11a: { n: 11.7, name: 'admission', note: 'admission control — in-flight limit + bounded queue' },
  S12: { n: 12, name: 'content_type_guard' },
  S13: { n: 13, name: 'idempotency_key_syntax' },
  S14: { n: 14, name: 'body_schema' },
  S15: { n: 15, name: 'artifact_decode' },
  S16: { n: 16, name: 'stream_idempotency_conflict' },
  S17: { n: 17, name: 'route_timeout_setup' },
  S18: { n: 18, name: 'artifact_verify_ed25519' },
  S19: { n: 19, name: 'tenant_org_active' },
  S20: { n: 20, name: 'request_binding' },
  S21: { n: 21, name: 'nonce_anomaly_redis' },
  S21r: { n: 21.3, name: 'identity_rate_limit', note: 'per-identity limit after signature verification' },
  S21s: { n: 21.6, name: 'identity_revocation_scope', note: 'identity revoked/disabled + provider scope' },
  S22: { n: 22, name: 'idempotency_reserve' },
  S23: { n: 23, name: 'tenant_policy_set' },
  S24: { n: 24, name: 'policy_engine' },
  S24a: { n: 24.1, name: 'consent', parent: 'S24' },
  S25: { n: 25, name: 'policy_drift' },
  S26: { n: 26, name: 'request_semantic' },
  S27: { n: 27, name: 'invariant_mint' },
  S28: { n: 28, name: 'invariant_assert' },
  S29: { n: 29, name: 'provider_selection' },
  S30: { n: 30, name: 'provider_call' },
  S31: { n: 31, name: 'late_completion_guard' },
  S32: { n: 32, name: 'output_semantic' },
  S33: { n: 33, name: 'audit_append' },
  // closure diagnostic: S33/S34 split.
  S33p: { n: 33.1, name: 'audit_pseudonym', parent: 'S33', note: 'subject pseudonym lookup before enqueue' },
  S33pw: { n: 33.11, name: 'audit_pseudonym_pool_wait', parent: 'S33p', note: 'PG pool connect() wait inside S33p' },
  S33f: { n: 33.2, name: 'audit_file_commit', parent: 'S33', note: 'enqueue -> own entry fsynced (group commit)' },
  S34: { n: 34, name: 'transparency' },
  S34pw: { n: 34.1, name: 'transparency_pool_wait', parent: 'S34', note: 'PG pool connect() wait' },
  S34w: { n: 34.2, name: 'transparency_head_lock_wait', parent: 'S34', note: 'transparency_log_head FOR UPDATE wait' },
  S34h: { n: 34.3, name: 'transparency_head_lock_hold', parent: 'S34', note: 'head lock acquired -> COMMIT done' },
  S35: { n: 35, name: 'idempotency_complete' },
  S36: { n: 36, name: 'response_write' },
});

const RING_SIZE = 20000;
let _als = null;
let _ring = null;
let _seq = 0;

if (ON) {
  const { AsyncLocalStorage } = require('async_hooks');
  _als = new AsyncLocalStorage();
  _ring = [];
}

/** Current high-resolution time in ms (enabled path only). */
function start() {
  return Number(process.hrtime.bigint()) / 1e6;
}

/** Add the time since `t0` to stage `id` of the current request (enabled path only). */
function end(id, t0) {
  const rec = _als.getStore();
  if (!rec) return;
  const ms = Number(process.hrtime.bigint()) / 1e6 - t0;
  rec.stages[id] = (rec.stages[id] || 0) + ms;
  rec.counts[id] = (rec.counts[id] || 0) + 1;
}

/** Add an explicitly measured duration to stage `id` of the current request (enabled path only). */
function add(id, ms) {
  const rec = _als.getStore();
  if (!rec) return;
  rec.stages[id] = (rec.stages[id] || 0) + ms;
  rec.counts[id] = (rec.counts[id] || 0) + 1;
}

/** Current accumulated ms of stage `id` for this request (enabled path only; 0 when none). */
function get(id) {
  const rec = _als.getStore();
  return rec && rec.stages[id] ? rec.stages[id] : 0;
}

/** Wrap an async function so each call is timed as stage `id`. Returns `fn` itself when OFF. */
function timeAsync(id, fn) {
  if (!ON) return fn;
  return async function stageTimedAsync(...args) {
    const t0 = start();
    try { return await fn.apply(this, args); } finally { end(id, t0); }
  };
}

/** Wrap a sync function so each call is timed as stage `id`. Returns `fn` itself when OFF. */
function timeSync(id, fn) {
  if (!ON) return fn;
  return function stageTimedSync(...args) {
    const t0 = start();
    try { return fn.apply(this, args); } finally { end(id, t0); }
  };
}

/** Mark a point in time relative to the request start (e.g. stream first byte). Enabled path only. */
function mark(name) {
  const rec = _als.getStore();
  if (!rec) return;
  if (rec.marks[name] === undefined) rec.marks[name] = Number(process.hrtime.bigint()) / 1e6 - rec.t0;
}

/** Attach a label to the current request record (decision, reason, stream flag, provider). Enabled path only. */
function label(key, value) {
  const rec = _als.getStore();
  if (rec) rec.labels[key] = value;
}

/**
 * First middleware: opens the request record and closes it on 'finish'
 * (server total), then stores it in the ring buffer. Only mounted when ON.
 */
function requestMiddleware(req, res, next) {
  const rec = {
    seq: 0, t0: Number(process.hrtime.bigint()) / 1e6, method: req.method, path: req.originalUrl.split('?')[0],
    stages: Object.create(null), counts: Object.create(null), marks: Object.create(null), labels: Object.create(null),
  };
  // S36 response_write = first res.json() call → 'finish'; also labels the decision/reason.
  const origJson = res.json;
  res.json = function stageTimedJson(body) {
    if (rec.jsonAt === undefined) {
      rec.jsonAt = Number(process.hrtime.bigint()) / 1e6;
      if (body && typeof body === 'object') { rec.labels.decision = body.decision ?? null; rec.labels.reason = body.reason ?? null; }
    }
    return origJson.apply(this, arguments);
  };
  res.once('finish', () => {
    const tEnd = Number(process.hrtime.bigint()) / 1e6;
    if (rec.jsonAt !== undefined) { rec.stages.S36 = tEnd - rec.jsonAt; rec.counts.S36 = 1; }
    rec.totalMs = tEnd - rec.t0;
    rec.status = res.statusCode;
    rec.requestId = req.requestId || null;
    rec.seq = ++_seq;
    _ring.push(rec);
    if (_ring.length > RING_SIZE) _ring.shift();
  });
  _als.run(rec, next);
}

/**
 * Wrap a middleware so its synchronous span (entry → next() or return) is
 * recorded as stage `id`. Returns the middleware unchanged when OFF.
 */
function wrapMiddleware(id, fn) {
  if (!ON) return fn;
  return function stageTimedMiddleware(req, res, next) {
    const t0 = start();
    let ended = false;
    const done = (...args) => { if (!ended) { ended = true; end(id, t0); } next(...args); };
    try {
      return fn(req, res, done);
    } finally {
      // a middleware that responded without calling next() (e.g. a 4xx) is still timed
      if (!ended && res.headersSent) { ended = true; end(id, t0); }
    }
  };
}

/** Express router for GET/POST /__bench/stages — loopback only. Mounted only when ON. */
function benchRouter() {
  const express = require('express');
  const r = express.Router();
  const loopbackOnly = (req, res, next) => {
    const a = req.socket && req.socket.remoteAddress;
    if (a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1') return next();
    return res.status(404).end();
  };
  r.get('/', loopbackOnly, (req, res) => {
    const since = Number(req.query.since) || 0;
    res.json({ stages: STAGES, records: _ring.filter((x) => x.seq > since), lastSeq: _seq });
  });
  r.post('/reset', loopbackOnly, (req, res) => { _ring.length = 0; res.json({ reset: true, lastSeq: _seq }); });
  return r;
}

module.exports = { ON, STAGES, start, end, add, get, mark, label, timeAsync, timeSync, requestMiddleware, wrapMiddleware, benchRouter };
