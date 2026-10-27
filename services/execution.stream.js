'use strict';

/**
 * Streaming provider execution layer.
 *
 * executeStreamingProviderCall() is the ONLY path through which streaming
 * provider calls may be made.  It mirrors the design of execution.js exactly:
 *
 *   • assertExecutionInvariant() is called as the very first operation —
 *     before provider resolution, before any dispatch.
 *   • On invariant violation: throws UNVERIFIED_EXECUTION_ATTEMPT and emits
 *     a CRITICAL log line to stderr.  No partial streaming is possible.
 *   • The caller's AbortSignal is threaded through to the provider so
 *     timeout and client-disconnect cancellation reach the network layer.
 *
 * verifiedCtx must be the frozen object produced by the /ai/chat route
 * immediately after all 5 enforcement steps pass:
 *   { verified: true, requestHash: <64-char hex>, policyHash: <64-char hex>,
 *     artifactId: <uuid>, tenantId: <string>, issuedAt: <number>, signature: <64-char hex> }
 * issuedAt/signature cryptographically bind this context — see
 * services/executionInvariantToken.js and services/execution-guard.js.
 */

const { routeStreamingProviderCall } = require('./providers/router.stream');
const { resolveProvider }            = require('./providers');
// S28 invariant assert, timed only when the bench stage timer is on (else the original function).
const assertExecutionInvariant = require('../src/observability/stageTimer').timeSync('S28', require('./execution-guard').assertExecutionInvariant);

/**
 * Execute a streaming provider call.
 *
 * @param {string}       provider
 * @param {object}       body          — { model, messages }
 * @param {{ verified: true, requestHash: string, policyHash: string, artifactId: string, tenantId: string, issuedAt: number, signature: string }} verifiedCtx
 * @param {{ policyHash?: string|null }} [traceMeta]
 * @param {AbortSignal}  [signal]      — cancellation: timeout or client disconnect
 * @yields {{ delta: string }}         — incremental text chunks
 * @throws {Error} UNVERIFIED_EXECUTION_ATTEMPT — invariant violated (synchronous)
 * @throws {Error} PROVIDER_UNAVAILABLE          — provider name not registered
 * @throws {Error} PROVIDER_NOT_CONFIGURED       — provider registered but disabled
 * @throws {Error} PROVIDER_*                    — provider call failed
 */
async function* executeStreamingProviderCall(provider, body, verifiedCtx, traceMeta, signal) {
  // ── INVARIANT: identical guard to non-streaming executeProviderCall ─────────
  assertExecutionInvariant(verifiedCtx, 'executeStreamingProviderCall');

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
    tenantId:    verifiedCtx.tenantId  ?? null,
  };

  yield* routeStreamingProviderCall(provider, body, meta, signal);
}

module.exports = { executeStreamingProviderCall };
