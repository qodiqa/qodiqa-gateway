'use strict';

// AsyncLocalStorage-based active background-task context — mirrors the
// existing pattern in src/observability/tracing/context.js.
//
// BackgroundTaskRunner.runTask() runs every wrapped task inside
// runWithTask(), so any code executing on behalf of that task (including
// code several `await`s deep) can look up currentTask() without explicit
// parameter threading. This is what lets processHardening.js's global
// unhandledRejection/uncaughtException handlers distinguish "this error
// originated inside a classified background task" from "this error
// originated in the primary request path or unclassified code" — the
// defense-in-depth backstop for Finding 3.6 (see that file's header
// comment for why this matters even though BackgroundTaskRunner already
// catches everything inside the task body itself).

const { AsyncLocalStorage } = require('async_hooks');

const _storage = new AsyncLocalStorage();

/**
 * @returns {{ taskName: string, subsystem: string, owner: string,
 *   criticality: 'startup-critical'|'critical'|'non-critical',
 *   retryPolicy: string, timeoutMs: number|null, frequency: string,
 *   startedAt: number, attempt: number }|null}
 */
function currentTask() {
  return _storage.getStore() || null;
}

/**
 * Run fn (sync or async) inside a new task context. If fn returns a
 * Promise, the context is propagated through its resolution — code that
 * awaits deeper inside the task still observes currentTask() correctly.
 */
function runWithTask(ctx, fn) {
  return _storage.run(ctx, fn);
}

module.exports = { currentTask, runWithTask, _storage };
