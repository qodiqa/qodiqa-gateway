'use strict';

/**
 * COMMIT audit entry: the closing record of a request that executed — what was ACTUALLY delivered.
 *
 * Lifecycle of one request: INTENT or STREAM_OPENED → DECISION → COMMIT. The DECISION says what the gateway decided and which output it
 * released; the COMMIT is written AFTER the response has left (or failed to), and states the exact number of output bytes delivered,
 * the hash of the delivered content and how the delivery ended (`completionStatus`). There is no STREAM_CLOSED type: COMMIT covers
 * both, and a stream that is stopped half-way, fails at the provider or loses its client commits the bytes that did reach the client.
 *
 *   RESPONSE_DELIVERED  COMPLETE                     the whole response was handed to the connection
 *   RESPONSE_FAILED     CLIENT_DISCONNECTED          the client went away (non-stream: before the response was flushed)
 *                       TIMEOUT / CANCELLED / ERROR  the stream timed out, was cancelled (shutdown, semantic block) or the provider failed
 *
 * `bytesDelivered` counts the UTF-8 bytes of the output text that outputHash covers (not SSE framing). A response that could not be
 * delivered at all commits EMPTY_OUTPUT_HASH and 0 bytes.
 *
 * The COMMIT only exists on audit schema v8 (QODIQA_AUDIT_SCHEMA_V8 stays off until a decision is made): with the flag off
 * nothing is written and the call only counts a `skipped`. It is written after the client was answered, so it never delays a response;
 * when the audit store refuses it, the exact record is queued durably and replayed, with the in-process
 * lifecycle reconciler as the fallback (CRITICAL AUDIT_COMMIT_FAILED meanwhile), never replaced by a different statement. A process that dies between the
 * DECISION and the COMMIT leaves a DECISION without COMMIT: the boot reconciler (lifecycleReconciler.reconcileCommitsAtBoot) writes a COMMIT with
 * completionStatus OUTCOME_UNKNOWN, reason RESPONSE_FAILED and 0 bytes (unknown, never claimed as delivered); the verifiers report a DECISION that
 * still has no COMMIT as ORPHAN_DECISION after the grace period.
 */

const entryBuilder = require('./entryBuilder');
const { emit } = require('../../../services/logger');
// Dependency inversion (rule no-circular): the recovery queue and the lifecycle reconciler replay a COMMIT through recordCommit; they get it injected at the end of this file.
const lifecycleReconciler = require('./lifecycleReconciler');
const persistenceRecovery = require('../persistenceRecovery');

const STATUS_BY_CAUSE = Object.freeze({
  COMPLETE: 'COMPLETE', CLIENT_DISCONNECTED: 'CLIENT_DISCONNECTED', TIMEOUT: 'TIMEOUT', CANCELLED: 'CANCELLED', ERROR: 'ERROR',
});

function _metrics() { try { return require('../../observability/metrics'); } catch { return null; } }
function _count(outcome) { const m = _metrics(); if (m && m.auditCommitsTotal) m.auditCommitsTotal.inc({ outcome }); }

/**
 * How a stream ended → completionStatus (the existing vocabulary of streamEnforcer: status completed|cancelled|blocked|error and the
 * terminationReason CLIENT_DISCONNECT | STREAM_TIMEOUT | SERVER_SHUTDOWN | provider code).
 */
function completionStatusForStream(status, terminationReason) {
  if (status === 'completed') return 'COMPLETE';
  if (status === 'error') return 'ERROR';
  if (terminationReason === 'CLIENT_DISCONNECT') return 'CLIENT_DISCONNECTED';
  if (terminationReason === 'STREAM_TIMEOUT') return 'TIMEOUT';
  return 'CANCELLED';
}

/** The facts of the request's artifact (issuedAt, protocolVersion) while still inside the request's async context. */
function captureFacts(requestId) {
  try {
    const f = require('./requestAuditContext').currentArtifactFacts();
    if (f && f.requestId && f.requestId === requestId) return { issuedAt: f.issuedAt ?? null, protocolVersion: f.protocolVersion ?? null };
  } catch { /* no request context */ }
  return { issuedAt: null, protocolVersion: null };
}

function _fields(c, { delivered, outputHash, bytesDelivered, completionStatus }) {
  if (!entryBuilder.COMPLETION_STATUSES.includes(completionStatus)) throw new Error(`invalid completionStatus ${completionStatus}`);
  return {
    artifactId: `${c.requestId}:commit`,
    entryType: 'COMMIT',
    decision: 'ALLOW',
    reason: delivered ? 'RESPONSE_DELIVERED' : 'RESPONSE_FAILED',
    signature: c.signature,
    tenantId: c.tenantId ?? undefined,
    organizationId: c.organizationId || undefined,
    requestId: c.requestId,
    outputHash,
    bytesDelivered,
    completionStatus,
    ...(c.issuedAt !== null && c.issuedAt !== undefined ? { issuedAt: c.issuedAt } : {}),
    ...(c.protocolVersion !== null && c.protocolVersion !== undefined ? { protocolVersion: c.protocolVersion } : {}),
  };
}

async function _queueDurably(c, outcome, err) {
  try {
    const { enqueueWithOutcome, OPERATION_TYPES } = persistenceRecovery;
    const { durable } = await enqueueWithOutcome(OPERATION_TYPES.AUDIT_COMMIT_WRITE, { c, outcome }, err);
    if (durable) emit('WARN', 'AUDIT_COMMIT_QUEUED', { requestId: c.requestId, durable, completionStatus: outcome.completionStatus, bytesDelivered: outcome.bytesDelivered,
      message: 'The COMMIT audit entry was refused by the audit store; it is queued durably and written by the recovery worker.' });
    return Boolean(durable);
  } catch { return false; }
}

/**
 * Write the COMMIT. Never throws.
 * @param {{ requestId: string, signature: string, tenantId?: string, organizationId?: string, issuedAt?: number|null, protocolVersion?: number|null }} c
 * @param {{ delivered: boolean, outputHash: string, bytesDelivered: number, completionStatus: string }} outcome
 * @param {{ _reconcile?: boolean }} [opts]
 * @returns {Promise<{ recorded: boolean, skipped?: boolean, duplicate?: boolean, failed?: boolean, auditEntryHash?: string|null }>}
 */
async function recordCommit(c, outcome, { _reconcile = false } = {}) {
  if (entryBuilder.currentSchemaVersion() < 8) { _count('skipped'); return { recorded: false, skipped: true }; }
  let fields;
  try { fields = _fields(c, outcome); } catch (err) {
    emit('CRITICAL', 'AUDIT_COMMIT_FAILED', { requestId: c.requestId, error: err.message, code: 'COMMIT_INVALID' });
    _count('failed');
    return { recorded: false, failed: true };
  }
  try {
    const audit = require('./audit-log');
    const entry = await audit.appendMandatory(fields, { stage: 'COMMIT', maxRetries: 3, retryDelayMs: 100 });
    _count('recorded');
    return { recorded: true, auditEntryHash: entry ? entry.hash : null };
  } catch (err) {
    if (typeof err.message === 'string' && err.message.startsWith('already_executed')) { _count('duplicate'); return { recorded: false, duplicate: true }; }
    emit('CRITICAL', 'AUDIT_COMMIT_FAILED', { requestId: c.requestId, error: err.message, code: err.code ?? null, completionStatus: outcome.completionStatus, bytesDelivered: outcome.bytesDelivered });
    _count('failed');
    if (!_reconcile) {
      // the exact record is queued DURABLY (recovery queue, or the file journal when PostgreSQL is down) so that a crash does not lose it; only when nothing
      // durable takes it does the in-process map of the lifecycle reconciler keep it (the boot reconciler then writes OUTCOME_UNKNOWN after a restart).
      const queued = await _queueDurably(c, outcome, err);
      if (queued) { _count('queued'); return { recorded: false, failed: true, queued: true }; }
      lifecycleReconciler.registerOpenLifecycle(`${c.requestId}:commit`, { kind: 'commit', retry: () => recordCommit(c, outcome, { _reconcile: true }) });
    }
    return { recorded: false, failed: true };
  }
}

/**
 * A tracker settles exactly once. `deliver()` / `fail()` return the recordCommit promise of the first call; later calls return the same one.
 * @param {{ requestId: string, signature: string, tenantId?: string, organizationId?: string }} ctx
 */
function createCommitTracker(ctx) {
  const c = { ...ctx, ...captureFacts(ctx.requestId) };
  let settled = null;
  const settle = (outcome) => { if (!settled) settled = recordCommit(c, outcome); return settled; };
  return {
    /** The response (or stream) reached the client: its text hash and size. */
    deliver({ outputHash, bytesDelivered }) { return settle({ delivered: true, outputHash, bytesDelivered, completionStatus: 'COMPLETE' }); },
    /** Delivery ended abnormally after `bytesDelivered` bytes (0 and EMPTY_OUTPUT_HASH when nothing reached the client). */
    fail(cause, { outputHash = entryBuilder.EMPTY_OUTPUT_HASH, bytesDelivered = 0 } = {}) {
      return settle({ delivered: false, outputHash, bytesDelivered, completionStatus: STATUS_BY_CAUSE[cause] || 'ERROR' });
    },
    /** A full outcome (streams): delivered or not, hash and bytes released, completionStatus. */
    commit(outcome) { return settle(outcome); },
    get settled() { return settled !== null; },
  };
}

/**
 * Non-stream: settle the tracker from the HTTP response itself. 'finish' = the whole response was handed to the connection;
 * 'close' without 'finish' = the client went away first.
 */
function watchResponse(res, tracker, { outputHash, bytesDelivered }) {
  // the request context records a client that left before the response was ended (see requestAuditContext)
  try { const f = require('./requestAuditContext').currentArtifactFacts(); if (f && f.clientGone === true) { tracker.fail('CLIENT_DISCONNECTED'); return; } } catch { /* no request context */ }
  if (!res || typeof res.once !== 'function') { tracker.deliver({ outputHash, bytesDelivered }); return; }
  // call this just BEFORE the response is written: a client that already went away never emits 'close' again (the request context's
  // clientGone flag above, or a destroyed response); everything after is settled by 'finish' / 'close'
  if (res.writableFinished === true) { tracker.deliver({ outputHash, bytesDelivered }); return; }
  if (res.destroyed === true) { tracker.fail('CLIENT_DISCONNECTED'); return; }
  res.once('finish', () => { tracker.deliver({ outputHash, bytesDelivered }); });
  res.once('close', () => { if (!tracker.settled) tracker.fail('CLIENT_DISCONNECTED'); });
}

/**
 * Stream: settle once the response has ended. `outcome` is what the enforcer knows (status, hash and bytes of the released text); the HTTP
 * response decides the last step: if the connection closed before the end was flushed, the COMMIT says CLIENT_DISCONNECTED / RESPONSE_FAILED with
 * the bytes that were handed to the connection.
 */
function watchStreamEnd(res, tracker, outcome) {
  const failedOutcome = { ...outcome, delivered: false, completionStatus: outcome.completionStatus === 'COMPLETE' ? 'CLIENT_DISCONNECTED' : outcome.completionStatus };
  if (!res || typeof res.once !== 'function') { tracker.commit(outcome); return; }
  if (res.writableFinished === true) { tracker.commit(outcome); return; }
  if (res.destroyed === true) { tracker.commit(failedOutcome); return; }
  res.once('finish', () => { tracker.commit(outcome); });
  res.once('close', () => { if (!tracker.settled) tracker.commit(failedOutcome); });
}

lifecycleReconciler.setCommitRecorder(recordCommit);
persistenceRecovery.setCommitWriter(recordCommit);

module.exports = { watchStreamEnd, recordCommit, createCommitTracker, watchResponse, completionStatusForStream, captureFacts };
