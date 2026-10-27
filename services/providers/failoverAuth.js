'use strict';

/**
 * Provider failover authorization —.
 *
 * a retryable failure on the artifact's provider sent the call to the
 * configured PROVIDER_FAILOVER_<P> target with no consent or scope check, and
 * the evidence recorded only the provider the caller had asked for.
 *
 * Now the configured pair is still required (the routers only ever try the
 * configured target), AND the caller's per-request authorizer must approve the
 * target — consent for the caller and that provider, the signing identity's
 * permissions and provider scope (src/api/routes/aiChat.js builds it). No
 * authorizer (a caller that never supplied one) means no failover: fail closed.
 *
 * The routing outcome (requested vs executing provider, failover and why, or
 * the refusal) is reported through meta.onRouting so the caller can record it
 * in the audit entry's executionContext (a hash-schema input).
 */

const { emit } = require('../logger');

/** @returns {Promise<{ ok: true } | { ok: false, reason: string }>} */
async function authorizeFailover(meta, primary, target, cause, body) {
  if (!meta || typeof meta.authorizeFailover !== 'function') {
    return { ok: false, reason: 'FAILOVER_NOT_AUTHORIZED_NO_CHECK' };
  }
  try {
    // gate N-01: the model the router will really SEND to the target is the body's (the primary's, possibly replaced by routing) - the authoriser judges that one
    const r = await meta.authorizeFailover(target, { primary, cause: cause?.code ?? null, model: body && typeof body.model === 'string' ? body.model : null });
    return r && r.ok === true ? { ok: true } : { ok: false, reason: (r && r.reason) || 'FAILOVER_NOT_AUTHORIZED' };
  } catch (err) {
    emit('ERROR', 'PROVIDER_FAILOVER_AUTHORIZATION_ERROR', { primary, target, requestId: meta.requestId ?? null, error: err.message });
    return { ok: false, reason: 'FAILOVER_AUTHORIZATION_ERROR' };
  }
}

function reportRouting(meta, info) {
  if (meta && typeof meta.onRouting === 'function') {
    try { meta.onRouting(info); } catch { /* observability must never break a call */ }
  }
}

/** Refuse: log it, report it, and rethrow the PRIMARY failure (never a partial success). */
function refuse(meta, primary, target, cause, reason) {
  emit('WARN', 'PROVIDER_FAILOVER_REFUSED', {
    primaryProvider: primary, failoverProvider: target, failoverReason: cause?.code ?? null, refusal: reason,
    requestId: meta?.requestId ?? null,
    message: 'Failover target not authorized for this caller (consent / identity scope) — the primary failure is returned instead.',
  });
  reportRouting(meta, { requestedProvider: primary, executingProvider: null, failover: { from: primary, to: target, cause: cause?.code ?? null, refused: reason } });
  if (cause && typeof cause === 'object') cause.failoverRefused = { target, reason };
  return cause;
}

module.exports = { authorizeFailover, reportRouting, refuse };
