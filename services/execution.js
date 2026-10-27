'use strict';

/**
 * Provider execution layer.
 *
 * executeProviderCall() is the ONLY exported function in this module and the
 * ONLY path through which provider calls may be made.
 *
 * The invariant "no valid artifact → no execution" is enforced by
 * assertExecutionInvariant() on every call before any provider dispatch begins.
 * assertExecutionInvariant() throws synchronously and logs to stderr so
 * violations are visible even if an outer try/catch absorbs the throw.
 *
 * Provider dispatch is handled by routeProviderCall() in services/providers/router.js,
 * which selects the appropriate adapter, handles failover, and emits routing decisions.
 * All provider adapters return a normalized ProviderResponse object (normalize.js).
 *
 * Trace context:
 *   verifiedCtx carries the execution invariant fields (verified, requestHash,
 * policyHash, artifactId, issuedAt, signature — the latter two
 *   cryptographically bind this context to the pipeline run that produced
 *   it; see services/executionInvariantToken.js).  traceMeta carries the
 *   observability fields (policyHash) that accompany every provider
 *   telemetry record for end-to-end traceability.  Both are passed to the
 *   router as a single merged meta object.
 */

const { routeProviderCall }        = require('./providers/router');
const { resolveProvider }          = require('./providers');
// S28 invariant assert, timed only when the bench stage timer is on (else the original function).
const assertExecutionInvariant = require('../src/observability/stageTimer').timeSync('S28', require('./execution-guard').assertExecutionInvariant);

/**
 * Execute a provider call.
 *
 * The invariant is asserted as the very first operation — before provider
 * resolution, before any dispatch.  If the context is absent or invalid
 * the function throws UNVERIFIED_EXECUTION_ATTEMPT and emits a CRITICAL log
 * line to stderr.  No partial execution is possible.
 *
 * verifiedCtx must be the frozen object produced by the /ai/chat route
 * immediately after the enforcement pipeline (Steps 1–5) passes:
 *   { verified: true, requestHash: <64-char hex>, policyHash: <64-char hex>,
 *     artifactId: <uuid>, issuedAt: <number>, signature: <64-char hex> }
 * issuedAt/signature are minted by
 * services/executionInvariantToken.js's mintExecutionToken() and re-verified
 * by assertExecutionInvariant() below — a hand-built object of the right
 * shape is not sufficient on its own.
 *
 * traceMeta carries additional observability fields that are not part of the
 * execution invariant:
 *   { policyHash: <64-char hex | null> }
 *
 * @param {string} provider
 * @param {object} body
 * @param {{ verified: true, requestHash: string, policyHash: string, artifactId: string, issuedAt: number, signature: string }} verifiedCtx
 * @param {{ policyHash?: string | null }} [traceMeta]
 * @param {AbortSignal} [signal]     — cancellation: route-level timeout or client disconnect.
 *   Threaded through to the provider adapter so an outbound request in flight
 *   is aborted rather than left to run after the caller has given up on it.
 * @returns {Promise<object>}  Normalized ProviderResponse
 * @throws {Error} UNVERIFIED_EXECUTION_ATTEMPT — invariant violated
 * @throws {Error} PROVIDER_UNAVAILABLE          — provider name not registered
 * @throws {Error} PROVIDER_NOT_CONFIGURED       — provider registered but disabled
 * @throws {Error} PROVIDER_CANCELLED            — signal was already aborted before dispatch
 */
async function executeProviderCall(provider, body, verifiedCtx, traceMeta, signal) {
  // ── INVARIANT: must be the first statement, before any other logic ──────────
  assertExecutionInvariant(verifiedCtx, 'executeProviderCall');

  // Cancellation is checked immediately after the invariant — if the caller
  // already timed out, no provider work should begin at all, not even the
  // registry lookup below.
  if (signal?.aborted) {
    const err = new Error('PROVIDER_CANCELLED');
    err.code  = 'PROVIDER_CANCELLED';
    throw err;
  }

  // Quick existence check before routing — surfaces unknown provider names early
  // with a clear error distinct from PROVIDER_NOT_CONFIGURED.
  if (!resolveProvider(provider)) {
    const err = new Error('PROVIDER_UNAVAILABLE');
    err.code  = 'PROVIDER_UNAVAILABLE';
    throw err;
  }

  const meta = {
    requestId:   verifiedCtx.artifactId,
    requestHash: verifiedCtx.requestHash,
    policyHash:  traceMeta?.policyHash ?? null,
    // the caller's failover authorizer and routing reporter (see providers/failoverAuth.js).
    authorizeFailover: typeof traceMeta?.authorizeFailover === 'function' ? traceMeta.authorizeFailover : null,
    onRouting:         typeof traceMeta?.onRouting === 'function' ? traceMeta.onRouting : null,
    tenantId:    verifiedCtx.tenantId   ?? null,
  };

  return routeProviderCall(provider, body, meta, signal);
}

module.exports = { executeProviderCall };
