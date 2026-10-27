'use strict';

/**
 * QODIQA Idempotency Gate — orchestration layer (API-2).
 *
 * The single entry point /ai/chat's enforcement pipeline calls once the
 * request is authenticated (post-validateBoundRequest — tenantId/
 * publicKeyId/callerId are known) but before policy evaluation or provider
 * execution. Translates the raw idempotencyStore primitives (reserve/
 * complete/release/get) into the five outcomes the route needs to act on.
 *
 * ── Scope decision: only a durably-completed SUCCESSFUL execution is ever
 *    replayed ─────────────────────────────────────────────────────────────
 *
 * gate() reserves atomically; the CALLER (aiChat.js) later invokes exactly
 * one of complete()/release() once the request's terminal outcome is known.
 * complete() is used ONLY for a successful EXECUTE — every other terminal
 * state (validation/policy/semantic BLOCK, provider error, timeout, audit/
 * transparency persistence failure) calls release() instead. Consequences:
 *
 *   • Provider invocation is guaranteed to happen at most once per
 *     (tenant, idempotencyKey) that ever reaches a successful outcome —
 *     concurrent duplicates serialize on the atomic reservation; a
 *     genuinely failed/blocked/timed-out attempt releases the reservation
 *     so a corrected retry gets a fully fresh, un-stale evaluation.
 *   • This is deliberately conservative: it never risks replaying a stale
 *     or incorrect decision (e.g. a policy BLOCK whose underlying consent/
 *     rate-limit state may have legitimately changed between attempts), at
 *     the cost of not short-circuiting the ok to redo the cheap steps for a
 *     request that is not going to result in provider execution.
 *   • It fully satisfies the finding's actual concern — duplicate
 *     PROVIDER execution, duplicate BILLING, duplicate SUCCESSFUL audit
 *     artifacts — because none of those things happen on a BLOCK/error
 *     path in the first place.
 *
 * See API-2-REMEDIATION-REPORT.md §4 (Design Rationale) for the full
 * write-up of this decision.
 *
 * ── Concurrency ────────────────────────────────────────────────────────────
 *
 * A second request racing the exact same (tenant, key, fingerprint) while
 * the first is still `pending` polls (bounded by IDEMPOTENCY_WAIT_TIMEOUT_MS,
 * IDEMPOTENCY_POLL_INTERVAL_MS) for the first to reach `completed`, and
 * replays it if it does. If the wait budget is exhausted while still
 * `pending`, the second request is rejected with IDEMPOTENCY_REQUEST_IN_PROGRESS
 * (409) rather than proceeding — it never executes concurrently with the
 * first. If the first attempt fails and releases (deleting the key) while
 * the second is polling, the second transparently re-attempts reservation
 * and — if it wins — proceeds normally as the new first attempt.
 */

const { computeFingerprint } = require('./fingerprint');
const { emit } = require('../../../services/logger');
const { monoNowMs } = require('../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

const IDEMPOTENCY_RETENTION_TTL_MS = (() => {
  const v = parseInt(process.env.IDEMPOTENCY_RETENTION_TTL_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 24 * 60 * 60 * 1000; // 24h
})();

const IDEMPOTENCY_WAIT_TIMEOUT_MS = (() => {
  const v = parseInt(process.env.IDEMPOTENCY_WAIT_TIMEOUT_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 10_000;
})();

const IDEMPOTENCY_POLL_INTERVAL_MS = (() => {
  const v = parseInt(process.env.IDEMPOTENCY_POLL_INTERVAL_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 200;
})();

function _sleep(ms) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (t.unref) t.unref();
  });
}

/**
 * @param {{
 *   idempotencyKey:   string,
 *   tenantId?:        string|null,
 *   organizationId?:  string|null,
 *   publicKeyId:      string,
 *   callerId?:        string|null,
 *   provider?:        string|null,
 *   requestHash:      string,
 *   reservationTtlMs: number,
 *   _store?:          object,   test injection — defaults to the production Redis store
 * }} params
 * @returns {Promise<
 *   { outcome: 'proceed',  ctx: object } |
 *   { outcome: 'replay',   record: object } |
 *   { outcome: 'conflict' | 'in_progress' | 'store_unavailable', reason: string, details?: object }
 * >}
 */
// the only value a client ever sees in IDEMPOTENCY_STORE_UNAVAILABLE details.error.
const IDEMPOTENCY_STORE_ERROR_DETAIL = 'IDEMPOTENCY_STORE_UNAVAILABLE';

async function gate({
  idempotencyKey, tenantId, organizationId, publicKeyId, callerId, provider, requestHash,
  reservationTtlMs, _store,
}) {
  // Lazy-load the production store only when no test store is injected —
  // mirrors src/validation/registerNonce.js's DI convention, so requiring
  // this module never triggers a Redis connection attempt in tests.
  const store = _store !== undefined ? _store : require('./idempotencyStore');

  let fingerprint;
  try {
    fingerprint = computeFingerprint({ tenantId, organizationId, publicKeyId, callerId, provider, requestHash });
  } catch (err) {
    // details reach the client in the BLOCK body — generic code out, raw error text to the server log only.
    emit('WARN', 'IDEMPOTENCY_STORE_UNAVAILABLE', { error: err.message, where: 'fingerprint' });
    return { outcome: 'store_unavailable', reason: 'IDEMPOTENCY_STORE_UNAVAILABLE', details: { error: IDEMPOTENCY_STORE_ERROR_DETAIL } };
  }

  const deadline = monoNowMs() + IDEMPOTENCY_WAIT_TIMEOUT_MS; // monotonic (same-process)

  // eslint-disable-next-line no-constant-condition
  while (true) {
    let reserveResult;
    try {
      reserveResult = await store.reserve(tenantId, idempotencyKey, fingerprint, reservationTtlMs);
    } catch (err) {
      emit('WARN', 'IDEMPOTENCY_STORE_UNAVAILABLE', { error: err.message });
      return { outcome: 'store_unavailable', reason: 'IDEMPOTENCY_STORE_UNAVAILABLE', details: { error: IDEMPOTENCY_STORE_ERROR_DETAIL } };
    }

    if (reserveResult.reserved) {
      return {
        outcome: 'proceed',
        ctx: { tenantId, idempotencyKey, fingerprint, retentionTtlMs: IDEMPOTENCY_RETENTION_TTL_MS, store },
      };
    }

    const existing = reserveResult.existing;

    // Key vanished between our failed SET NX and the follow-up GET (expired
    // TTL or a concurrent release) — retry reservation, bounded by deadline.
    if (!existing) {
      if (monoNowMs() >= deadline) { // monotonic (same-process)
        return { outcome: 'in_progress', reason: 'IDEMPOTENCY_REQUEST_IN_PROGRESS' };
      }
      await _sleep(IDEMPOTENCY_POLL_INTERVAL_MS);
      continue;
    }

    // Requirement: same key + different request body is rejected, not
    // silently treated as a retry and not silently treated as a new request.
    if (existing.fingerprint !== fingerprint) {
      emit('WARN', 'IDEMPOTENCY_KEY_CONFLICT', { tenantId: tenantId || null });
      return { outcome: 'conflict', reason: 'IDEMPOTENCY_KEY_CONFLICT' };
    }

    if (existing.status === 'completed') {
      emit('INFO', 'IDEMPOTENCY_REPLAY_SERVED', { tenantId: tenantId || null });
      return { outcome: 'replay', record: existing };
    }

    // status === 'pending' with a matching fingerprint — a genuine
    // concurrent duplicate of the SAME logical request. Wait for the
    // first attempt to finish rather than executing a second time.
    if (monoNowMs() >= deadline) { // monotonic (same-process)
      return { outcome: 'in_progress', reason: 'IDEMPOTENCY_REQUEST_IN_PROGRESS' };
    }
    await _sleep(IDEMPOTENCY_POLL_INTERVAL_MS);
  }
}

/**
 * Mark a held reservation as the canonical, durably-completed outcome.
 * Use ONLY for a successful EXECUTE — see module header for why every
 * other terminal state calls release() instead.
 *
 * @param {object|null} ctx        the `ctx` returned by gate()'s 'proceed' outcome
 * @param {{ httpStatus: number, body: object }} outcome
 */
async function complete(ctx, outcome) {
  if (!ctx) return;
  try {
    await ctx.store.complete(ctx.tenantId, ctx.idempotencyKey, {
      fingerprint: ctx.fingerprint,
      httpStatus:  outcome.httpStatus,
      body:        outcome.body,
    }, ctx.retentionTtlMs);
  } catch (err) {
    // Best-effort: the request itself already succeeded and was already
    // durably audited/transparency-logged by this point (aiChat.js only
    // calls complete() after both of those succeed) — a failure to persist
    // the idempotency pointer means a future retry may re-execute rather
    // than replay, which is the pre-existing (pre-remediation) behavior,
    // not a new regression. Logged loudly so operators can see the gap.
    emit('WARN', 'IDEMPOTENCY_COMPLETE_FAILED', { error: err.message });
  }
}

/**
 * Release a held reservation so a fresh retry can reserve it again.
 * Used for every non-EXECUTE terminal outcome.
 *
 * @param {object|null} ctx
 */
async function release(ctx) {
  if (!ctx) return;
  try {
    await ctx.store.release(ctx.tenantId, ctx.idempotencyKey);
  } catch (err) {
    // Worst case: the reservation lingers until its short reservationTtlMs
    // expires on its own (self-healing — see idempotencyStore.js header),
    // temporarily rejecting a retry as IDEMPOTENCY_REQUEST_IN_PROGRESS
    // rather than permanently — never a stuck/leaked key.
    emit('WARN', 'IDEMPOTENCY_RELEASE_FAILED', { error: err.message });
  }
}

module.exports = {
  gate,
  complete,
  release,
  IDEMPOTENCY_RETENTION_TTL_MS,
  IDEMPOTENCY_WAIT_TIMEOUT_MS,
  IDEMPOTENCY_POLL_INTERVAL_MS,
};
