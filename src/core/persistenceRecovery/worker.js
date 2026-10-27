'use strict';

/**
 * Persistence Recovery Worker — Component #13
 *
 * Background poller that drains the recovery queue.
 *
 * RETRY SCHEDULE (exponential backoff, seconds):
 *   attempt 1: +5 s
 *   attempt 2: +15 s
 *   attempt 3: +30 s
 *   attempt 4: +60 s
 *   attempt 5+: +300 s (5 min), then DLQ
 *
 * MAX_RETRIES: 5 — after the 5th failure the operation moves to DLQ.
 * a handler result whose error starts with "non-retryable:" (the
 * built-in handlers' label for a deterministic data/constraint failure,
 * classified by isPersistenceFailure) moves to the DLQ at once — retrying a
 * deterministic failure five times over ~7 minutes only delays the operator.
 *
 * MULTI-INSTANCE SAFETY:
 *   claimNext() uses an atomic `UPDATE ... FOR UPDATE SKIP LOCKED` against
 *   the persistence_recovery_queue PostgreSQL table (migration 032).  Only
 *   one worker claims each item.  If the worker crashes, the item re-appears
 *   after CLAIM_TIMEOUT_MS (30 s).
 *
 * HANDLER REGISTRY:
 *   Handlers are registered by operationType via registerHandler().
 *   Each handler receives the full operation object and must return
 *   { success: true } or { success: false, error: string }.
 */

const queue   = require('./queue');
const metrics = require('./metrics');
const { emit } = require('../../../services/logger');
const _defaultTaskRunner = require('../../runtime/backgroundTasks/BackgroundTaskRunner');

// ── Constants ─────────────────────────────────────────────────────────────────

const RETRY_DELAYS_MS = [5_000, 15_000, 30_000, 60_000, 300_000];
const MAX_RETRIES     = RETRY_DELAYS_MS.length;
const POLL_INTERVAL   = parseInt(process.env.PRQ_POLL_INTERVAL_MS || '2000', 10);
const SOURCE          = 'PERSISTENCE_RECOVERY_WORKER';

// ── Handler registry ──────────────────────────────────────────────────────────

const _handlers = new Map();

/**
 * Register a handler for an operation type.
 *
 * @param {string}   operationType  One of OPERATION_TYPES
 * @param {Function} handler        async fn(operation) → { success, error? }
 */
function registerHandler(operationType, handler) {
  _handlers.set(operationType, handler);
}

// ── Worker state ──────────────────────────────────────────────────────────────

let _timer   = null;
let _running = false;

// ── Process one claimed operation ─────────────────────────────────────────────

async function _processOne(operation) {
  const { operationId, operationType, retryCount } = operation;
  const handler = _handlers.get(operationType);

  if (!handler) {
    emit('ERROR', 'QUEUE_PROCESSING_FAILED', {
      source:        SOURCE,
      operationId,
      operationType,
      error:         `no handler registered for operationType: ${operationType}`,
    });
    metrics.inc('recovery_failed_total', { operationType });
    await queue.moveToDlq(operationId, `no handler: ${operationType}`, retryCount);
    metrics.inc('recovery_dlq_total', { operationType });
    return;
  }

  const startMs = Date.now();
  let result;

  try {
    result = await handler(operation);
  } catch (err) {
    result = { success: false, error: err.message };
  }

  const latencyMs = Date.now() - startMs;
  metrics.add('recovery_worker_latency_ms', latencyMs, { operationType });

  if (result.success) {
    await queue.markComplete(operationId);
    metrics.inc('recovery_processed_total', { operationType });
    emit('INFO', 'QUEUE_RECOVERED', {
      source:      SOURCE,
      operationId,
      operationType,
      latencyMs,
      retryCount,
    });
    return;
  }

  const errorMsg      = result.error ?? 'unknown error';
  const nextRetryCount = retryCount + 1;

  if (nextRetryCount > MAX_RETRIES || /^non-retryable:/.test(errorMsg)) {
    await queue.moveToDlq(operationId, errorMsg, nextRetryCount);
    metrics.inc('recovery_dlq_total', { operationType });
    emit('ERROR', 'QUEUE_DLQ', {
      source:        SOURCE,
      operationId,
      operationType,
      retryCount:    nextRetryCount,
      error:         errorMsg,
    });
  } else {
    const delayMs     = RETRY_DELAYS_MS[nextRetryCount - 1] ?? RETRY_DELAYS_MS[RETRY_DELAYS_MS.length - 1];
    const eligibleAt  = Date.now() + delayMs;
    await queue.markRetry(operationId, errorMsg, nextRetryCount, eligibleAt);
    metrics.inc('recovery_retry_total', { operationType });
    emit('WARN', 'QUEUE_RETRY', {
      source:        SOURCE,
      operationId,
      operationType,
      retryCount:    nextRetryCount,
      nextDelayMs:   delayMs,
      error:         errorMsg,
    });
  }
}

// ── Poll loop ─────────────────────────────────────────────────────────────────

// ER 2026-10-06: a background poller must never be what keeps a process alive (every other monitor here unrefs its
// timer). A running server stays alive through its HTTP listener; a leaked/unstopped worker no longer pins the process
// (the CI coverage job hung for hours on this). stop() still clears the timer explicitly.
function _unref(t) { if (t && typeof t.unref === 'function') t.unref(); return t; }

async function _poll({ _taskRunner = _defaultTaskRunner } = {}) {
  if (!_running) return;

  // Finding 3.6: runs through BackgroundTaskRunner (mandatory-persistence
  // retry infrastructure, classified 'critical' in taskRegistry.js — must
  // be loudly alerted on but must not crash the process). Rather than a
  // duplicated try/catch, this uses the runner's own { ok, error } outcome
  // to preserve the pre-existing domain-specific QUEUE_PROCESSING_FAILED
  // event and recovery_failed_total metric (BackgroundTaskRunner already
  // emits its own generic BACKGROUND_TASK_FAILED/metric on top of this).
  let op = null;
  const result = await _taskRunner.runTask('persistence-recovery-worker', async () => {
    op = await queue.claimNext();
    if (op) {
      emit('INFO', 'QUEUE_PROCESSING', {
        source:        SOURCE,
        operationId:   op.operationId,
        operationType: op.operationType,
        retryCount:    op.retryCount,
      });
      await _processOne(op);
    }
  });

  if (!result.ok) {
    emit('ERROR', 'QUEUE_PROCESSING_FAILED', { source: SOURCE, error: result.error.message });
    metrics.inc('recovery_failed_total', { operationType: 'UNKNOWN' });
  } else if (op && _running) {
    // drain more items without waiting if queue has work
    _timer = _unref(setTimeout(_poll, 0));
    return;
  }

  if (_running) {
    _timer = _unref(setTimeout(_poll, POLL_INTERVAL));
  }
}

/**
 * Start the background poll loop.
 */
function start() {
  if (_running) return;
  _running = true;
  emit('INFO', 'RECOVERY_WORKER_STARTED', { source: SOURCE, pollIntervalMs: POLL_INTERVAL });
  _timer = _unref(setTimeout(_poll, POLL_INTERVAL));
}

/**
 * Stop the background poll loop.
 */
function stop() {
  if (!_running) return;
  _running = false;
  if (_timer) {
    clearTimeout(_timer);
    _timer = null;
  }
  emit('INFO', 'RECOVERY_WORKER_STOPPED', { source: SOURCE });
}

function isRunning() {
  return _running;
}

module.exports = {
  registerHandler,
  start,
  stop,
  isRunning,
  _processOne,
  MAX_RETRIES,
  RETRY_DELAYS_MS,
};
