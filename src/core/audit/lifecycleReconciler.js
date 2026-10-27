'use strict';

/**
 * — audit lifecycles left open by a failed closing write.
 *
 * v7 writes an INTENT (and, when streaming, STREAM_OPENED) immediately before a provider call and a closing DECISION
 * after it. When the audit store fails BETWEEN the two, the provider has run but the closing DECISION is not in the
 * chain; the client was answered 503 AUDIT_PERSISTENCE_FAILED with no content (non-streaming) — and the chain keeps an
 * open INTENT forever. This module closes such lifecycles with what is TRUE:
 *
 *   runtime  the route registers the closing record it could not write; it is retried every RETRY_MS (bounded backoff
 *            is unnecessary: one cheap append per open lifecycle) until the store accepts it. Non-streaming: a BLOCK
 *            DECISION `PROVIDER_OUTCOME_UNRECORDED` (provider = the one dispatched, nothing delivered — the client got
 *            503 and no content). Streaming: content may already have been delivered, so the EXACT intended closing
 *            record is retried, never a substitute.
 *   boot     open lifecycles in the audit log's tail window were left by the PREVIOUS process (nothing of this process
 *            is in flight before it listens). Non-streaming → the same closing BLOCK. A lifecycle with STREAM_OPENED
 *            (delivery unknown) is reported (ERROR AUDIT_LIFECYCLE_UNRECONCILABLE) and left open — a false record is
 *            worse than an open one; the verifiers report it as ORPHAN_INTENT.
 *
 * A closing append that finds the decision already in the chain ("already_executed") counts as closed. Acceptance
 * criteria L-1..L-5:
 */

const RETRY_MS = (() => { const v = Number(process.env.QODIQA_AUDIT_LIFECYCLE_RETRY_MS); return Number.isInteger(v) && v >= 100 && v <= 600_000 ? v : 10_000; })();
const REASON = 'PROVIDER_OUTCOME_UNRECORDED';
// a streamed lifecycle (STREAM_OPENED) left open by a dead process is closed with what is TRUE — the
// stream was open when the process ended and how much content reached the client is UNKNOWN. This never claims 'nothing delivered'.
const STREAM_REASON = 'STREAM_OUTCOME_UNKNOWN';

const _pending = new Map();   // requestId → { kind, retry, since, attempts }
let _timer = null;
let _running = false;
let _blockWriter = null;      // aiChat's _writeAuditBlock (the one BLOCK writer: audit append + transparency leaf)
let _emitFn = null;           // the route module's logger emit (core must not depend on services/ — architecture rule)

function _emit(level, type, data) { try { if (_emitFn) _emitFn(level, type, data); } catch { /* best-effort */ } }

/** The route module hands over its BLOCK writer and its logger at load (used by retries and the boot reconciliation). */
function configure({ writeBlock, emit } = {}) {
  if (typeof writeBlock === 'function') _blockWriter = writeBlock;
  if (typeof emit === 'function') _emitFn = emit;
}
function setBlockWriter(fn) { configure({ writeBlock: fn }); }

/**
 * Register a lifecycle whose closing record could not be written. `retry()` must perform that write again and resolve
 * { recorded: boolean, duplicate?: boolean, auditEntryHash?: string }.
 */
// Dependency inversion (rule no-circular): commitEntry.js registers recordCommit here instead of this module requiring it.
let _commitRecorder = null;
function setCommitRecorder(fn) { _commitRecorder = fn; }

function registerOpenLifecycle(requestId, { kind, retry }) {
  if (typeof requestId !== 'string' || !requestId || typeof retry !== 'function' || _pending.has(requestId)) return false;
  _pending.set(requestId, { kind, retry, since: Date.now(), attempts: 0 });
  _emit('ERROR', 'AUDIT_LIFECYCLE_OPEN', { requestId, kind, pending: _pending.size,
    message: 'The closing audit record of a dispatched request could not be written; it is retried until the audit store accepts it.' });
  _ensureTimer();
  return true;
}

async function retryOpenLifecycles() {
  if (_running || _pending.size === 0) return { closed: 0, pending: _pending.size };
  _running = true;
  let closed = 0;
  try {
    for (const [requestId, it] of [..._pending]) {
      it.attempts++;
      let r;
      try { r = await it.retry(); } catch (err) { r = { recorded: false, error: err.message }; }
      if (r && (r.recorded || r.duplicate)) {
        _pending.delete(requestId); closed++;
        _emit('INFO', 'AUDIT_LIFECYCLE_RECONCILED', { requestId, kind: it.kind, attempts: it.attempts, openMs: Date.now() - it.since,
          duplicate: !!r.duplicate, auditEntryHash: r.auditEntryHash || null });
      }
    }
  } finally {
    _running = false;
    if (_pending.size === 0) _stopTimer();
  }
  return { closed, pending: _pending.size };
}

function _ensureTimer() {
  if (_timer) return;
  _timer = setInterval(() => { retryOpenLifecycles().catch(() => {}); }, RETRY_MS);
  if (_timer.unref) _timer.unref();
}
function _stopTimer() { if (_timer) { clearInterval(_timer); _timer = null; } }

/** The closing BLOCK for a non-streaming INTENT, from the INTENT's own (hash-protected) fields. */
function closingBlockFromIntent(intent, { stream = false } = {}) {
  return {
    artifactId:  intent.requestId,          // the DECISION's artifactId is the request id (R-9)
    requestId:   intent.requestId,
    inputHash:   intent.inputHash || null,
    signature:   intent.signature || null,
    requestHash: intent.requestHash || null,
    policyHash:  intent.policyHash || null,
    tenantId:    intent.tenantId || null,
    publicKeyId: intent.publicKeyId || null,
    callerContext: intent.callerContext || null,
    provider:    intent.provider || null,
    model:       intent.model || null,
    reason:      stream ? STREAM_REASON : REASON,
    stage:       stream ? 'STREAM_DELIVERY' : 'PROVIDER_EXECUTION',
    executingProvider: intent.executingProvider || null,
    closesLifecycle: true,
  };
}

/**
 * Boot: close the lifecycles the previous process left open (tail window). Call before the server listens.
 * @returns {Promise<{ open: number, closed: number, deferred: number, unreconcilable: number }>}
 */
async function reconcileAtBoot({ auditLog = require('./audit-log'), writeBlock = _blockWriter } = {}) {
  if (typeof auditLog.getOpenLifecyclesInWindow !== 'function') return { open: 0, closed: 0, deferred: 0, unreconcilable: 0, skipped: 'UNSUPPORTED' };
  const open = auditLog.getOpenLifecyclesInWindow();
  const out = { open: open.length, closed: 0, deferred: 0, unreconcilable: 0 };
  for (const o of open) {
    if (!o.intent) {
      out.unreconcilable++;
      _emit('ERROR', 'AUDIT_LIFECYCLE_UNRECONCILABLE', { requestId: o.requestId, streamOpened: !!o.streamOpened,
        message: 'An audit lifecycle has no INTENT record to close from; no closing record is fabricated. The verifiers report it as ORPHAN_INTENT.' });
      continue;
    }
    if (typeof writeBlock !== 'function') { out.deferred++; continue; }
    const args = closingBlockFromIntent(o.intent, { stream: !!o.streamOpened });
    const retry = () => writeBlock({ ...args, _reconcile: true });
    let r;
    try { r = await retry(); } catch (err) { r = { recorded: false, error: err.message }; }
    if (r && (r.recorded || r.duplicate)) {
      out.closed++;
      _emit('INFO', 'AUDIT_LIFECYCLE_RECONCILED', { requestId: o.requestId, kind: 'boot', attempts: 1, duplicate: !!r.duplicate, auditEntryHash: r.auditEntryHash || null });
    } else {
      out.deferred++;
      registerOpenLifecycle(o.requestId, { kind: 'boot', retry });
    }
  }
  if (out.open) _emit(out.unreconcilable ? 'WARN' : 'INFO', 'AUDIT_LIFECYCLE_BOOT_RECONCILIATION', out);
  return out;
}

/**
 * boot — a v8 ALLOW DECISION of the previous process whose provider executed but that has no COMMIT (the process died between the DECISION and the
 * COMMIT). What reached the client is UNKNOWN, so the COMMIT says exactly that: completionStatus OUTCOME_UNKNOWN, reason RESPONSE_FAILED, outputHash of the
 * empty text and 0 bytes (0 means "unknown" here, documented in AUDIT-V8-FREEZE section 4) — never "delivered". A request whose true COMMIT is waiting in the
 * durable queue or journal is left to that replay. Call before the server listens, after reconcileAtBoot().
 * @returns {Promise<{ open: number, written: number, queued: number, failed: number }>}
 */
async function reconcileCommitsAtBoot({ auditLog = require('./audit-log'), hasPending = (id) => require('../persistenceRecovery').hasPendingCommit(id), minAgeMs, nowMs = Date.now() } = {}) {
  // D-11: single node - nothing of this process is in flight before it listens, so every uncommitted DECISION is the previous process's (age 0). With
  // distributed ordering the window also holds the DECISIONs of PEER replicas that are still being served: only those older than the commit grace period count.
  if (minAgeMs !== undefined && !(Number.isFinite(minAgeMs) && minAgeMs >= 0)) throw new Error('reconcileCommitsAtBoot: minAgeMs must be a non-negative number');
  const age = Number.isFinite(minAgeMs) ? minAgeMs : (process.env.QODIQA_AUDIT_ORDERING_MODE === 'distributed' ? 10 * 60 * 1000 : 0);
  const out = { open: 0, written: 0, queued: 0, failed: 0 };
  const entryBuilder = require('./entryBuilder');
  if (entryBuilder.currentSchemaVersion() < 8 || typeof auditLog.getUncommittedDecisionsInWindow !== 'function') return { ...out, skipped: 'SCHEMA_V8_OFF' };
  const recordCommit = _commitRecorder;
  if (typeof recordCommit !== 'function') return { ...out, skipped: 'NO_COMMIT_RECORDER' };
  const open = auditLog.getUncommittedDecisionsInWindow();
  out.open = open.length;
  for (const d of open) {
    if (age > 0 && Number.isFinite(Date.parse(d.timestamp)) && Date.parse(d.timestamp) > nowMs - age) { out.young = (out.young || 0) + 1; continue; }
    let pending = false;
    try { pending = await hasPending(d.requestId); } catch { pending = false; }
    if (pending) { out.queued++; continue; }
    const ctx = { requestId: d.requestId, signature: d.signature, tenantId: d.tenantId ?? undefined, organizationId: d.organizationId || undefined,
      issuedAt: d.issuedAt ?? null, protocolVersion: d.protocolVersion ?? null };
    const r = await recordCommit(ctx, { delivered: false, outputHash: entryBuilder.EMPTY_OUTPUT_HASH, bytesDelivered: 0, completionStatus: 'OUTCOME_UNKNOWN' }, { _reconcile: true });
    if (r.recorded || r.duplicate) {
      out.written++;
      _emit('WARN', 'AUDIT_COMMIT_RECONCILED_AT_BOOT', { requestId: d.requestId, completionStatus: 'OUTCOME_UNKNOWN', duplicate: !!r.duplicate, auditEntryHash: r.auditEntryHash || null,
        message: 'A request that executed has no COMMIT (the previous process ended between its DECISION and its COMMIT); an OUTCOME_UNKNOWN COMMIT closes it. What the client received is not known.' });
    } else {
      out.failed++;
      registerOpenLifecycle(`${d.requestId}:commit`, { kind: 'commit-boot', retry: () => recordCommit(ctx, { delivered: false, outputHash: entryBuilder.EMPTY_OUTPUT_HASH, bytesDelivered: 0, completionStatus: 'OUTCOME_UNKNOWN' }, { _reconcile: true }) });
    }
  }
  if (out.open) _emit(out.failed ? 'ERROR' : 'WARN', 'AUDIT_COMMIT_BOOT_RECONCILIATION', out);
  return out;
}

function pendingCount() { return _pending.size; }
function _resetForTests() { _pending.clear(); _stopTimer(); _running = false; _blockWriter = null; _emitFn = null; }

module.exports = { setCommitRecorder, registerOpenLifecycle, retryOpenLifecycles, reconcileAtBoot, reconcileCommitsAtBoot, closingBlockFromIntent, configure, setBlockWriter, pendingCount,
  REASON, STREAM_REASON, RETRY_MS, _resetForTests };
