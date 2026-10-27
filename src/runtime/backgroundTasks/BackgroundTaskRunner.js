'use strict';

/**
 * BackgroundTaskRunner — Finding 3.6 remediation.
 *
 * The single reusable execution wrapper every background/async job in this
 * process must go through. It is the actual containment boundary: a
 * rejected Promise or thrown error from inside a wrapped task is caught
 * here and — for every criticality level except 'startup-critical' — never
 * allowed to escape as an unhandled rejection. That is what makes failure
 * of a background job stop being able to take down the whole enforcement
 * pipeline (see src/runtime/processHardening.js for the previous,
 * unconditional-exit global handler this replaces the blast radius of).
 *
 * Responsibilities (ticket item 5):
 *   - execute the task
 *   - catch synchronous exceptions AND async rejections
 *   - timeout protection
 *   - structured logging (services/logger.emit)
 *   - metrics (src/observability/metrics.js background_task_* family)
 *   - execution duration
 *   - bounded runner-level retries, only for tasks that declare
 *     retryPolicy: 'runner' in taskRegistry.js (most tasks already
 *     implement their own domain-specific retry/backoff internally —
 *     stacking a second, generic retry loop on top would double the
 *     effective attempt count and fight each subsystem's own backoff
 *     timing, so this is opt-in per task, not automatic).
 *
 * Every task passed to runTask() MUST have an entry in taskRegistry.js —
 * classification is not optional or inferred (ticket item 2: "Classification
 * must be explicit in code. No implicit assumptions."). Calling runTask()
 * with an unregistered name is a programming error, not a runtime failure
 * condition, and is rejected immediately.
 *
 * Failure handling by criticality (taskRegistry.js):
 *   - 'non-critical' / 'critical'  → never rethrows. Returns
 *     { ok: false, error }. Ongoing recurring background work is isolated;
 *     the owning scheduler decides whether/when to try again.
 *   - 'startup-critical'           → rethrows after logging/metrics, so a
 *     one-shot startup precondition (e.g. `await consentSubscriber.start()`
 *     in server.js) still fails fast exactly as before this remediation.
 */

const { emit: _defaultEmit } = require('../../../services/logger');
const _defaultMetrics        = require('../../observability/metrics');
const { getTaskDefinition }  = require('./taskRegistry');
const { runWithTask }        = require('./taskContext');

let _tracingContext = null;
try {
  // Optional — correlationId enrichment only. Never let a missing/broken
  // tracing module prevent background tasks from running.
  _tracingContext = require('../../observability/tracing/context');
} catch { /* tracing module not present in this build */ }

function _correlationId() {
  try {
    const ctx = _tracingContext && _tracingContext.currentContext();
    return ctx ? ctx.traceId : null;
  } catch {
    return null;
  }
}

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

class UnregisteredTaskError extends Error {
  constructor(taskName) {
    super(
      `BACKGROUND_TASK_UNCLASSIFIED: "${taskName}" has no taskRegistry.js entry. ` +
      'Every background task must be explicitly classified (criticality, ' +
      'subsystem, owner) before BackgroundTaskRunner will execute it.',
    );
    this.name = 'UnregisteredTaskError';
    this.taskName = taskName;
  }
}

/**
 * Race a promise against a timeout. Rejects with a tagged timeout error
 * (`err._isTimeout === true`) if the timeout fires first. The timer is
 * always cleared and always unref'd so it can never keep the process alive
 * or leak once the race settles.
 */
function _withTimeout(promise, timeoutMs) {
  if (!timeoutMs || timeoutMs <= 0) return promise;

  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      /** @type {any} */ const err = new Error(`Background task exceeded timeout of ${timeoutMs}ms`);
      err._isTimeout = true;
      reject(err);
    }, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
  });

  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timer));
}

/**
 * Execute `fn` (sync or async) under full failure isolation.
 *
 * @param {string}   taskName            Must match a taskRegistry.js key.
 * @param {Function} fn                  The task body. May be sync or async.
 * @param {object}   [opts]
 * @param {number}   [opts.timeoutMs]    Overrides the registry default (null = no timeout).
 * @param {number}   [opts.retries]      Extra attempts beyond the first. Only applied
 *                                       when the registry entry's retryPolicy is 'runner'.
 * @param {number}   [opts.retryDelayMs] Delay between runner-level retry attempts. Default 200ms.
 * @param {Function}   [opts._emit]      Injected logger (testing).
 * @param {object}     [opts._metrics]   Injected metrics registry (testing).
 * @returns {Promise<{ ok: boolean, result?: *, error?: Error }>}
 */
async function runTask(taskName, fn, opts = {}) {
  const def = getTaskDefinition(taskName);
  if (!def) throw new UnregisteredTaskError(taskName);

  const emit    = opts._emit    || _defaultEmit;
  const metrics = opts._metrics || _defaultMetrics;
  const timeoutMs    = opts.timeoutMs !== undefined ? opts.timeoutMs : def.timeoutMs;
  const retryDelayMs = opts.retryDelayMs !== undefined ? opts.retryDelayMs : 200;
  const extraRetries = def.retryPolicy === 'runner' ? Math.max(0, opts.retries || 0) : 0;
  const attemptsAllowed = extraRetries + 1;

  let lastError = null;

  for (let attempt = 1; attempt <= attemptsAllowed; attempt++) {
    const startedAt = Date.now();
    const ctx = {
      taskName,
      subsystem:   def.subsystem,
      owner:       def.owner,
      criticality: def.criticality,
      retryPolicy: def.retryPolicy,
      timeoutMs,
      frequency:   def.frequency,
      startedAt,
      attempt,
    };

    metrics.backgroundTasksStartedTotal.inc({ task: taskName });

    try {
      // eslint-disable-next-line no-await-in-loop
      const result = await runWithTask(ctx, () => _withTimeout(Promise.resolve().then(/** @type {any} */ (fn)), timeoutMs));

      const durationMs = Date.now() - startedAt;
      metrics.backgroundTasksCompletedTotal.inc({ task: taskName });
      metrics.backgroundTaskDurationSeconds.observe({ task: taskName }, durationMs / 1000);
      emit('INFO', 'BACKGROUND_TASK_COMPLETED', {
        task:            taskName,
        subsystem:       def.subsystem,
        owner:           def.owner,
        criticality:     def.criticality,
        executionTimeMs: durationMs,
        attempt,
        correlationId:   _correlationId(),
      });
      return { ok: true, result };

    } catch (err) {
      lastError = err;
      const durationMs = Date.now() - startedAt;
      const isTimeout   = !!(err && err._isTimeout);
      const reason       = isTimeout ? 'timeout' : 'rejected';
      const willRetry    = attempt < attemptsAllowed;

      metrics.backgroundTaskDurationSeconds.observe({ task: taskName }, durationMs / 1000);
      metrics.backgroundTasksFailedTotal.inc({ task: taskName, reason });
      if (isTimeout) metrics.backgroundTaskTimeoutsTotal.inc({ task: taskName });
      if (willRetry)  metrics.backgroundTaskRetriesTotal.inc({ task: taskName });

      emit(def.criticality === 'startup-critical' ? 'FATAL' : 'ERROR', 'BACKGROUND_TASK_FAILED', {
        task:            taskName,
        subsystem:       def.subsystem,
        owner:           def.owner,
        criticality:     def.criticality,
        executionTimeMs: durationMs,
        attempt,
        retryCount:      attempt - 1,
        willRetry,
        reason,
        error:           err instanceof Error ? err.message : String(err),
        stack:           err instanceof Error ? err.stack : undefined,
        correlationId:   _correlationId(),
      });

      if (willRetry) {
        // eslint-disable-next-line no-await-in-loop
        await _sleep(retryDelayMs);
        continue;
      }

      if (def.criticality === 'startup-critical') {
        throw err; // preserve today's fail-fast behavior for startup preconditions
      }

      return { ok: false, error: err };
    }
  }

  // Unreachable — the loop above always returns or throws — but keeps the
  // function's return type honest for static analysis.
  return { ok: false, error: lastError };
}

module.exports = { runTask, UnregisteredTaskError };
