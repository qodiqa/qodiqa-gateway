'use strict';

/**
 * Log levels used across this service:
 *
 *   INFO     — Normal lifecycle events and expected enforcement decisions
 *              (startup, policy load, ALLOW/BLOCK decisions, audit writes).
 *
 *   WARN     — Abnormal but non-fatal states: Redis flapping, policy drift,
 *              incomplete audit lineage, replay traces, shutdown timeout.
 *              Investigate if sustained; no immediate action required.
 *
 *   ERROR    — A component failed in a recoverable way: store Redis errors,
 *              audit append failures, policy reload failures, shutdown
 *              disconnect failures, audit chain corruption or timeout.
 *              Page if sustained; check component health.
 *
 *   CRITICAL — A security invariant was violated. Treat as an active
 *              security incident and page immediately.
 *              Used for: EXECUTION_INVARIANT_VIOLATED, PROVIDER_SSRF_REJECTED.
 *
 *   FATAL    — Unrecoverable startup failure. Process will exit immediately.
 *
 * Stream routing: FATAL and CRITICAL go to stderr; all others go to stdout.
 *
 * Component 44.7 — Logging Security:
 *   Every emit() call passes `extra` through the centralized sanitization pipeline
 *   before the record is written to any sink (stream, eventBus, centralStore).
 *   Sensitive fields are replaced with [REDACTED]; PII, tokens, and cryptographic
 *   material in string values are replaced with typed placeholders.
 *   Every record is also classified as AUDIT, SECURITY, or OPERATIONAL.
 *
 * THROUGHPUT-12 — batched stdout flush (operational logging path only):
 *   This is the general-purpose OPERATIONAL/AUDIT-category structured logger
 *   (stdout/stderr JSON lines + dashboard SSE + best-effort central store).
 *   It is NOT the cryptographic, hash-chained compliance audit trail — that
 *   is src/core/audit/audit-log.js (WAL-backed, single-writer, optionally
 *   PostgreSQL-ordered), which this change does not touch in any way.
 *
 *   INFO/WARN/ERROR records go to stdout and are now batched: pushed to an
 *   in-memory FIFO buffer and flushed as one write() syscall per event-loop
 *   tick (see _scheduleFlush) instead of one syscall per record. This is
 *   safe for a non-cryptographic operational log because:
 *     - order is preserved exactly (single FIFO buffer, flushed in push order)
 *     - no entry is silently dropped: flush() drains synchronously on demand,
 *       and a process.on('exit', ...) safety net drains any remainder for
 *       every exit path (graceful shutdown or a raw process.exit() call),
 *       since 'exit' handlers run synchronously before the process
 *       terminates — exactly what a final drain needs.
 *     - the only un-survivable loss window is a hard kill/power loss, the
 *       same limitation any buffered logger has, and one that never applies
 *       to the separate audit chain, which remains fsynced-before-ack.
 *   CRITICAL/FATAL still go to stderr and are written immediately and
 *   synchronously, un-batched — they are rare, security-relevant events
 *   where operators want zero added latency, so there is nothing to gain
 *   (and something to lose) by batching them.
 */

const { EventEmitter } = require('events');
const { sanitize }     = require('./logSanitizer');
const { classify }     = require('./logClassifier');
const { currentContext: _tracingContext } = require('../src/observability/tracing/context');

// In-process event bus for dashboard SSE subscriptions.
// Dashboard SSE handler subscribes to 'log' events; each record is the same
// JSON object written to stdout/stderr. Emitted synchronously at emit() time
// (not deferred to the batched flush below) so dashboard updates stay real-time.
const eventBus = new EventEmitter();
eventBus.setMaxListeners(200);

// Central audit store (optional). Registered by server.js after pool init so
// that logger.js never imports centralStore.js and avoids circular dependencies:
//   server.js → centralStore.js → pgPool.js → logger.js
// Registration is one-time; safe to call before pgPool is ready (ingest() is
// gated on pgPool.isEnabled() internally).
let _centralStore = null;
function registerCentralStore(store) { _centralStore = store; }

// the query label centralStore.ingest() passes to pgPool.query(). Any
// event pool.js emits for that query (PG_QUERY_ERROR, PG_CIRCUIT_OPEN,
// PG_SLOW_QUERY) is the echo of an ingest attempt and is never forwarded back
// to centralStore — LOG-1's contract ("the operational signal survives, only
// the amplification is suppressed"). LOG-1's _ingestReentrant guard only covers
// the synchronous window; PG_QUERY_ERROR is emitted AFTER query()'s await, so
// without this the echo re-ingests itself. Once pool.end() has started, every
// re-ingest rejects synchronously ("Cannot use a pool after calling end"),
// turning the echo into an unbounded microtask loop that starves timers,
// setImmediate and I/O — graceful shutdown then hangs until SIGKILL and
// shutdown.js's SHUTDOWN_TIMEOUT safety net can never fire.
const AUDIT_STORE_INGEST_LABEL = 'audit_store_ingest';

// ── Batched stdout flush ──────────────────────────────────────────────────────
// See the THROUGHPUT-12 header comment above for the full rationale.

let _stdoutBuf       = [];
let _flushScheduled  = false;

function _flushStdoutSync() {
  if (_stdoutBuf.length === 0) return;
  const chunk = _stdoutBuf.join('');
  _stdoutBuf = [];
  process.stdout.write(chunk);
}

function _scheduleFlush() {
  if (_flushScheduled) return;
  _flushScheduled = true;
  const immediate = setImmediate(() => {
    _flushScheduled = false;
    _flushStdoutSync();
  });
  // Don't let a pending flush alone keep the event loop (and short-lived
  // scripts/test workers) alive — the process.on('exit', ...) safety net
  // above already guarantees this buffer is drained on any exit path, so an
  // unref'd immediate loses nothing: if the loop is otherwise busy, it still
  // fires in its normal turn; if the loop would otherwise be empty, exit
  // drains synchronously instead.
  if (typeof immediate.unref === 'function') immediate.unref();
}

// Safety net: drains any buffered lines on ANY process exit path, not just
// graceful shutdown — 'exit' listeners run synchronously before termination,
// which is exactly what a final drain needs (async work cannot be started
// here, but our writes are already synchronous).
// Guarded on `process` itself (not a module-local flag) so this stays a
// single listener even if this module is reloaded — e.g. under
// jest.resetModules() in tests that repeatedly re-require the codebase —
// which would otherwise silently accumulate one 'exit' listener per reload.
if (!/** @type {any} */ (process).__qodiqaLoggerExitHookInstalled) {
  process.on('exit', _flushStdoutSync);
  /** @type {any} */ (process).__qodiqaLoggerExitHookInstalled = true;
}

/**
 * Force any buffered stdout records to be written now.
 * Used by graceful shutdown (src/runtime/shutdown.js) and by tests that need
 * to observe a record immediately after emit(). No-op if nothing is buffered.
 * @returns {Promise<void>}
 */
function flush() {
  _flushStdoutSync();
  return Promise.resolve();
}

function emit(level, event, extra = {}) {
  const isSevere = (level === 'FATAL' || level === 'CRITICAL');
  const category = classify(level, event);
  // Sanitize extra before building the record — no sensitive data in any sink.
  let safe;
  try {
    const sanitized = sanitize(extra);
    safe = (sanitized !== null && typeof sanitized === 'object' && !Array.isArray(sanitized))
      ? sanitized
      : {};
  } catch {
    safe = {};
  }
  // canonical envelope field names (timestamp/eventType/severity) —
  // these match the names already used by the platform's canonical
  // correlation store (src/core/audit/centralStore.js's platform_audit_events
  // table: event_type/severity/occurred_at) and by the SIEM-shipping
  // normalizer (src/observability/logShipping/schema.js). Every record is
  // canonical from the moment it's created here — there is no longer a
  // separate rename/translation step at ship time. traceId/spanId are
  // populated automatically from the active OTel-style span (AsyncLocalStorage,
  // see src/observability/tracing/context.js) when tracing is enabled, so
  // every operational log line from a traced request can be joined to its
  // trace without every emit() call site threading it through by hand.
  // See SIEM-3-REMEDIATION-REPORT.md.
  const traceCtx = _tracingContext();
  // the envelope is authoritative. Caller fields used to be spread AFTER it, so a detail named
  // severity/eventType/timestamp/category (e.g. a webhook's own `eventType`) silently replaced the record's
  // own — a SIEM rule keyed on eventType/severity then missed or misfiled the event. A colliding caller value
  // is kept, under `shadowedFields`, instead of being dropped.
  // (traceId/spanId stay overridable by an explicit caller value — CE-06.)
  const envelope = {
    timestamp: new Date().toISOString(),
    severity:  level,
    eventType: event,
    category,
  };
  /** @type {Record<string, any>} */
  const record = {
    ...envelope,
    ...(traceCtx?.traceId ? { traceId: traceCtx.traceId } : {}),
    ...(traceCtx?.spanId  ? { spanId:  traceCtx.spanId }  : {}),
  };
  let shadowed = null;
  for (const k of Object.keys(safe)) {
    if (!Object.prototype.hasOwnProperty.call(envelope, k)) record[k] = safe[k];
    else if (safe[k] !== envelope[k]) (shadowed || (shadowed = {}))[k] = safe[k];
  }
  if (shadowed) record.shadowedFields = shadowed;
  const line   = JSON.stringify(record) + '\n';

  if (isSevere) {
    // CRITICAL/FATAL → stderr, immediate and synchronous (see header comment).
    process.stderr.write(line);
  } else {
    _stdoutBuf.push(line);
    _scheduleFlush();
  }

  // Non-blocking: dashboard subscribers receive the sanitized record.
  eventBus.emit('log', record);
  // Fire-and-forget to centralized platform audit store (no-op when PG disabled).
  // The echo of centralStore's own ingest query is not re-persisted.
  if (_centralStore && safe.label !== AUDIT_STORE_INGEST_LABEL) {
    _centralStore.ingest(level, event, record).catch(() => {});
  }
}

function log(level, requestId, artifactId, decision, reason) {
  emit(level, decision === 'ALLOW' ? 'GATEWAY_ALLOW' : 'GATEWAY_BLOCK', {
    component:    'GATEWAY',
    service:      'qodiqa',
    requestId:    requestId   || 'unknown',
    correlationId: requestId  || 'unknown',
    artifactId:   artifactId  || 'none',
    decision,
    reason,
  });
}

function allowed(requestId, artifactId, reason) {
  log('INFO', requestId, artifactId, 'ALLOW', reason);
}

function blocked(requestId, artifactId, reason) {
  log('WARN', requestId, artifactId, 'BLOCK', reason);
}

module.exports = { emit, allowed, blocked, eventBus, registerCentralStore, flush };
