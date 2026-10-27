'use strict';

/**
 * Rate Limit Middleware —
 *
 * Sliding Window Counter with burst protection and hierarchical enforcement.
 * Completely replaces the Fixed Window middleware.
 *
 * HTTP Response Headers (RFC 6585 + draft-ietf-httpapi-ratelimit-headers-09):
 *   RateLimit-Limit     — configured maximum (most restrictive applicable limit)
 *   RateLimit-Remaining — requests remaining
 *   RateLimit-Reset     — Unix epoch when window resets
 *   Retry-After         — seconds until next allowed request (HTTP 429 only)
 *   X-RateLimit-*       — mirrors of the above for legacy clients
 *
 * Identity resolution (non-spoofable, in priority order):
 *   1. req.rbacUser.id   — authenticated operator (set by opsAuth after key validation)
 *   2. req.signingKeyId  — authenticated signing identity (set by signAuth —
 *                          see src/middleware/signAuth.js / TRUST-1). Checked
 *                          before tenantId so that multiple signing
 *                          identities scoped to the SAME tenant still get
 *                          independent rate-limit buckets — tenant alone is
 *                          too coarse to satisfy "independent per identity".
 *   3. req.tenantId      — authenticated tenant (set by tenant middleware)
 *   4. req.clientIp      — source IP (set by clientIp.js, XFF-aware)
 *   5. 'ip:unknown'      — fail-secure: unknown clients share one conservative bucket
 *
 * Modes:
 *   ON by default — whether or not REDIS_URL is set. The limiter connects
 *   through the same managed-Redis configuration as the nonce and auth-lockout
 *   stores (src/infra/redis/clientConfig.js, default redis://localhost:6379),
 * initialized unconditionally at startup like theirs. it was a
 *   silent no-op unless REDIS_URL or RL_ENABLED=true was set.
 *   RL_ENABLED=false is the ONLY off switch: explicit, reported in the boot
 *   report, refused in production (bootValidator), and used by the Jest setup
 *   for suites that do not exercise the limiter.
 *
 * Redis unavailable or eval() throws:
 *   failMode 'closed'  (auth, /sign, admin): HTTP 429
 *                       RATE_LIMIT_BACKEND_UNAVAILABLE, exactly as before.
 *   failMode 'degrade' (traffic: /ai/chat, public reads/verifications): the
 *                       SAME policy is enforced by a per-process in-memory
 *                       sliding window (never unlimited). Entering degraded
 *                       mode sets qodiqa_rate_limit_degraded{bucket}=1 and
 *                       raises a CRITICAL RATE_LIMIT_DEGRADED event + alert;
 *                       the first successful Redis evaluation clears it.
 */

const { emit }                          = require('../../../services/logger');
const { resolvePolicies, getPolicy }    = require('./policies');
const { evaluate }                      = require('./slidingWindow');
const storage                           = require('./storage');
const metrics                           = require('./metrics');
const promMetrics                       = require('../../observability/metrics');
// a throttled flood must not become one platform_audit_events
// row per request (every WARN is ingested there) — the deny-path log events are
// sampled per (surface, identity); the counters above still count every 429.
const { createEventSampler }            = require('../../observability/eventSampler');
const _denySampler = createEventSampler({ summaryEvent: 'RATE_LIMIT_EVENTS_SUPPRESSED' });

// ── Mode detection ────────────────────────────────────────────────────────────

function _isRlEnabled() {
  return process.env.RL_ENABLED !== 'false';
}

// ── Degraded-mode fallback (D3 → C) ───────────────────────────────────────────

const _fallbackStorage = new storage.MemoryStorage();
const _degraded = new Set();

function _enterDegraded(surface, why) {
  if (_degraded.has(surface)) return;
  _degraded.add(surface);
  try { promMetrics.rateLimitDegraded.set({ bucket: surface }, 1); } catch { /* fail-safe */ }
  emit('CRITICAL', 'RATE_LIMIT_DEGRADED', {
    surface, reason: why,
    message: 'Rate-limit backend unavailable — this bucket is enforced by a per-process in-memory limiter until Redis recovers',
  });
  try {
    require('../../alerting/engine/AlertEngine').createAlert({
      type: 'OPERATIONAL', subtype: 'RATE_LIMIT_DEGRADED', severity: 'CRITICAL',
      sourceEvent: 'RATE_LIMIT_DEGRADED', title: `Rate limiter degraded: ${surface}`,
      description: `Redis unavailable (${why}); the ${surface} bucket runs on the per-process fallback limiter.`,
      component: 'rateLimit', context: { surface, reason: why },
    }).catch(() => {});
  } catch { /* alerting must never affect the request */ }
}

function _leaveDegraded(surface) {
  if (!_degraded.has(surface)) return;
  _degraded.delete(surface);
  try { promMetrics.rateLimitDegraded.set({ bucket: surface }, 0); } catch { /* fail-safe */ }
  emit('INFO', 'RATE_LIMIT_DEGRADED_RECOVERED', { surface });
}

// ── Identity extraction ───────────────────────────────────────────────────────

function extractIdentity(req) {
  if (req.rbacUser?.id)                                     return `user:${req.rbacUser.id}`;
  if (typeof req.signingKeyId === 'string' && req.signingKeyId) return `signingkey:${req.signingKeyId}`;
  if (typeof req.tenantId === 'string' && req.tenantId)     return `tenant:${req.tenantId}`;
  if (req.clientIp)                                         return `ip:${req.clientIp}`;
  return 'ip:unknown';
}

// ── Response header helpers ───────────────────────────────────────────────────

function _setRateLimitHeaders(res, { limit, remaining, resetAt, retryAfter } = {}) {
  if (limit != null) {
    res.set('RateLimit-Limit',       String(limit));
    res.set('X-RateLimit-Limit',     String(limit));
  }
  if (remaining != null) {
    const r = String(Math.max(0, remaining));
    res.set('RateLimit-Remaining',   r);
    res.set('X-RateLimit-Remaining', r);
  }
  if (resetAt != null) {
    res.set('RateLimit-Reset',       String(resetAt));
    res.set('X-RateLimit-Reset',     String(resetAt));
  }
  if (retryAfter != null) {
    res.set('Retry-After', String(retryAfter));
  }
}

// ── Response envelope helper ──────────────────────────────────────────────────

// Mirrors the management/admin API envelope from src/api/response.js
// (`failure`/`buildFailureBody`) without depending on the API layer — Core
// must never import src/api (see .dependency-cruiser.js: no-core-to-api).
function _managementFailureBody(code, message, requestId, details) {
  return {
    status:    'error',
    timestamp: new Date().toISOString(),
    requestId: requestId ?? null,
    error:     { code, message, ...(details !== undefined ? { details } : {}) },
  };
}

// ── Middleware factory ────────────────────────────────────────────────────────

// This middleware gates both the core protocol surface (`sign`/`sign_auth` —
// QODIQA-PROTOCOL-SPEC.md §14.4) and the management/admin API surface
// (certification, certification_batch, transparency, portal, webhooks, and
// their `_admin` variants). Those two surfaces use different response
// envelopes, so callers select which one applies via `envelope`; the
// default preserves this middleware's pre-existing shape so `sign.js` (the
// only protocol-surface caller) needs no change.
//
// 'decision' and 'legacyFailure' exist solely to let routes
// migrated off middleware/publicRateLimit.js keep the exact response body
// their old `response:` callback produced — neither 'protocol' nor
// 'management' matches either legacy shape.
// Both are additive: they don't change 'protocol'/'management' behavior for
// any already-migrated consumer.
function _deny429(res, envelope, { code, message, surface, dimension, reason, retryAfterSeconds, reqId }) {
  if (envelope === 'management') {
    const details = { surface, dimension, reason, retryAfterSeconds };
    return res.status(429).json(
      _managementFailureBody(code, message, res.locals?.requestId, details),
    );
  }
  if (envelope === 'decision') {
    return res.status(429).json({ decision: 'BLOCK', reason: 'RATE_LIMITED', details: {}, requestId: reqId });
  }
  if (envelope === 'legacyFailure') {
    // Mirrors src/api/response.js's buildFailureBody('RATE_LIMITED', 'Too
    // many requests', requestId) shape exactly (no `details` key) — Core
    // must never import src/api (.dependency-cruiser.js: no-core-to-api),
    // so the shape is reproduced inline rather than requiring that module.
    return res.status(429).json({
      status:    'error',
      timestamp: new Date().toISOString(),
      requestId: reqId ?? null,
      error:     { code: 'RATE_LIMITED', message: 'Too many requests' },
    });
  }
  return res.status(429).json({ error: code, surface, dimension, reason, retryAfterSeconds, requestId: reqId });
}

/**
 * Create an Express rate limiting middleware for a named surface.
 *
 * @param {string} surface          One of the known rate limit surfaces
 * @param {{ _evalFn?: Function, envelope?: 'protocol'|'management'|'decision'|'legacyFailure', onBlocked?: Function }} [options]
 *   _evalFn: injectable eval(script, keys, args) for testing; bypasses Redis.
 *   envelope: which response envelope 429s use — see the comment above.
 *   onBlocked(req): optional side-effect callback invoked immediately before
 * any 429 is sent (limit exceeded or backend unavailable). lets
 *     migrated callers reproduce a legacy per-surface log event (e.g.
 *     HEALTH_PROBE_RATE_LIMITED, ADMIN_RATE_LIMITED — see server/startup.js)
 *     that this middleware's own generic RATE_LIMIT_EXCEEDED/
 *     RATE_LIMIT_REDIS_FAILURE events don't replace, since some of those
 *     event names are part of a documented operational contract
 *     (docs/deployment/kubernetes-probes.md).
 * @returns {Function} Express async middleware
 */
// ── Core decision (shared by the middleware and checkRateLimit) ─────────────

/**
 * Evaluate one request against a surface. Decision + metrics/events only; no
 * response is written. Returns
 *   { outcome: 'allow', headers }
 *   { outcome: 'deny', code: 'RATE_LIMIT_EXCEEDED' | 'RATE_LIMIT_BACKEND_UNAVAILABLE',
 *     message, dimension, reason, retryAfterSeconds, headers }
 */
async function _decide(surface, ctx, { _evalFn } = {}) {
  const t0 = Date.now();
  const { identity, tenantId = null, userId = null, signingKeyId = null, endpoint = null, reqId = null, path = null, method = null } = ctx;
  const nowSeconds = Math.floor(Date.now() / 1000);

  metrics.inc('rl_requests_total', { surface });
  promMetrics.rateLimitRequestsTotal.inc({ surface });

  const surfacePolicy = getPolicy(surface);
  const policyChain   = resolvePolicies(surface, { tenantId, userId, signingKeyId, endpoint });
  const prodStorage   = storage.getProductionStorage();
  const redisEval     = (script, keys, args) => prodStorage.eval(script, keys, args);
  const memoryEval    = (script, keys, args) => _fallbackStorage.eval(script, keys, args);
  const degradeOk     = !_evalFn && surfacePolicy.failMode === 'degrade';

  const backendUnavailable = (why) => {
    metrics.inc('rl_redis_failures_total', { surface });
    promMetrics.rateLimitRedisFailuresTotal.inc({ surface });
    emit('ERROR', 'RATE_LIMIT_REDIS_FAILURE', { surface, identity, requestId: reqId, path, method, error: why });
    const w = surfacePolicy.windowSeconds;
    return { outcome: 'deny', code: 'RATE_LIMIT_BACKEND_UNAVAILABLE', message: 'Rate limit backend is unavailable', dimension: null, reason: null, retryAfterSeconds: w, headers: { retryAfter: w } };
  };

  let evalFn = _evalFn;
  let usingFallback = false;
  if (!evalFn) {
    if (prodStorage.isReady()) evalFn = redisEval;
    else if (degradeOk) { _enterDegraded(surface, 'Redis not ready'); evalFn = memoryEval; usingFallback = true; }
    else return backendUnavailable('Redis not ready');
  }

  // If any applicable policy grants unlimited access, bypass all rate limiting.
  if (policyChain.some(({ policy }) => policy.unlimited)) {
    metrics.inc('rl_requests_allowed_total', { surface });
    promMetrics.rateLimitAllowedTotal.inc({ surface });
    return { outcome: 'allow', headers: {} };
  }

  const run = async (fn) => {
    let mostRestrictive = null; let mostRestrictivePolicy = null;
    let blocked = false; let blockedDimension = null; let blockedReason = null; let blockedRetryAfter = null; let disabledHeaders = null;
    for (const { dimension, policy } of policyChain) {
      if (policy.disabled) {
        blocked = true; blockedDimension = dimension; blockedReason = 'DISABLED'; blockedRetryAfter = 60;
        disabledHeaders = { limit: 0, remaining: 0, resetAt: nowSeconds + 60, retryAfter: 60 };
        break;
      }
      const baseKey = `${storage.KEY_PREFIX}${dimension}:${identity}`;
      const result  = await evaluate(fn, baseKey, nowSeconds, policy.windowSeconds, policy.maxRequests, policy.burstCapacity ?? 0, policy.burstWindowSeconds ?? 5);
      if (result.blockedBy === 'BURST') {
        metrics.inc('rl_burst_consumed_total', { surface, dimension });
        promMetrics.rateLimitBurstConsumedTotal.inc({ surface, dimension });
      }
      if (mostRestrictive === null || result.remaining < mostRestrictive.remaining) { mostRestrictive = result; mostRestrictivePolicy = policy; }
      metrics.set('rl_quota_utilization', Math.floor((result.count / policy.maxRequests) * 1000), { surface, dimension });
      promMetrics.rateLimitQuotaUtilization.set({ surface, dimension }, Math.floor((result.count / policy.maxRequests) * 1000));
      if (!result.allowed) { blocked = true; blockedDimension = dimension; blockedReason = result.blockedBy; break; }
    }
    return { mostRestrictive, mostRestrictivePolicy, blocked, blockedDimension, blockedReason, blockedRetryAfter, disabledHeaders };
  };

  let r;
  try {
    r = await run(evalFn);
    if (!usingFallback && !_evalFn) _leaveDegraded(surface);
  } catch (err) {
    if (degradeOk && !usingFallback) {
      _enterDegraded(surface, err.message);
      usingFallback = true;
      try { r = await run(memoryEval); } catch (e2) { return backendUnavailable(e2.message); }
    } else {
      return backendUnavailable(err.message);
    }
  }

  metrics.add('rl_latency_ms_total', Date.now() - t0, { surface });
  promMetrics.rateLimitLatencyMs.observe({ surface }, Date.now() - t0);

  const headers = r.disabledHeaders || (r.mostRestrictive ? {
    limit: r.mostRestrictivePolicy.maxRequests, remaining: r.mostRestrictive.remaining,
    resetAt: nowSeconds + r.mostRestrictive.resetIn, retryAfter: r.blocked ? r.mostRestrictive.resetIn : undefined,
  } : {});

  if (r.blocked) {
    metrics.inc('rl_limited_total', { surface, reason: r.blockedReason ?? 'UNKNOWN' });
    promMetrics.rateLimitLimitedTotal.inc({ surface, reason: r.blockedReason ?? 'UNKNOWN' });
    const count = r.mostRestrictive?.count ?? 0;
    const limit = r.mostRestrictivePolicy?.maxRequests ?? 1;
    const _s = _denySampler.sample(`${surface}|${identity}`);
    if (_s.log && count > limit * 2) {
      emit('WARN', 'RATE_LIMIT_SUSPICIOUS', { surface, identity, requestId: reqId, dimension: r.blockedDimension, reason: r.blockedReason, count, limit, path, method });
    }
    if (_s.log) emit('WARN', 'RATE_LIMIT_EXCEEDED', {
      surface, identity, requestId: reqId, path, method, dimension: r.blockedDimension, reason: r.blockedReason,
      limit: r.mostRestrictivePolicy?.maxRequests, count: r.mostRestrictive?.count, resetIn: r.mostRestrictive?.resetIn,
      deniedThisMinute: _s.countThisWindow, sampled: _s.countThisWindow > 10,
      ...(usingFallback ? { degraded: true } : {}),
    });
    const retryAfterSeconds = r.blockedRetryAfter ?? r.mostRestrictive?.resetIn ?? surfacePolicy.windowSeconds;
    return { outcome: 'deny', code: 'RATE_LIMIT_EXCEEDED', message: 'Rate limit exceeded', dimension: r.blockedDimension, reason: r.blockedReason, retryAfterSeconds, headers };
  }

  metrics.inc('rl_requests_allowed_total', { surface });
  promMetrics.rateLimitAllowedTotal.inc({ surface });
  return { outcome: 'allow', headers };
}

function createRateLimitMiddleware(surface, { _evalFn, envelope = 'protocol', onBlocked } = {}) {
  // Surface must be valid — validate at factory time, not per-request.
  getPolicy(surface);

  return async function rateLimitMiddleware(req, res, next) {
    if (!_isRlEnabled()) return next();
    const verdict = await _decide(surface, {
      identity:     extractIdentity(req),
      tenantId:     req.tenantId      ?? null,
      userId:       req.rbacUser?.id  ?? null,
      signingKeyId: req.signingKeyId  ?? null,
      endpoint:     req.rl_endpoint   ?? null,
      reqId:        req.requestId     ?? null,
      path:         req.path,
      method:       req.method,
    }, { _evalFn });
    _setRateLimitHeaders(res, verdict.headers);
    if (verdict.outcome === 'allow') return next();
    onBlocked?.(req);
    return _deny429(res, envelope, {
      code: verdict.code, message: verdict.message, surface, dimension: verdict.dimension,
      reason: verdict.reason, retryAfterSeconds: verdict.retryAfterSeconds, reqId: req.requestId ?? null,
    });
  };
}

/**
 * Imperative check for a surface, for a point in a handler where the identity
 * only becomes known after the request was accepted (ai_chat_identity,
 * checked after artifact signature verification). Same policies, storage,
 * tiers, metrics and events as the middleware.
 *
 * @returns {Promise<{ allowed: boolean, code?: string, retryAfterSeconds?: number, headers: object }>}
 */
async function checkRateLimit(surface, { identity, tenantId = null, signingKeyId = null, reqId = null, path = null, method = null }, { _evalFn } = {}) {
  getPolicy(surface);
  if (!_isRlEnabled()) return { allowed: true, headers: {} };
  const verdict = await _decide(surface, { identity, tenantId, signingKeyId, reqId, path, method }, { _evalFn });
  return { allowed: verdict.outcome === 'allow', code: verdict.code, retryAfterSeconds: verdict.retryAfterSeconds, headers: verdict.headers };
}

function _isDegraded(surface) { return _degraded.has(surface); }
function _resetDegradedForTest() { for (const x of [..._degraded]) _leaveDegraded(x); _fallbackStorage._reset(); _denySampler.reset(); }

module.exports = { createRateLimitMiddleware, checkRateLimit, extractIdentity, _isRlEnabled, _setRateLimitHeaders, _isDegraded, _resetDegradedForTest };
