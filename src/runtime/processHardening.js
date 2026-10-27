'use strict';

/**
 * Runtime Process Hardening —
 *
 * Applies security controls at the process level before any network traffic
 * is accepted.  All controls are applied in applyProcessHardening(), which
 * must be called as early as possible in the startup sequence.
 *
 * Controls applied:
 *
 *   1. Process title sanitisation
 *      Sets process.title to a safe value that contains no credentials,
 *      paths, or sensitive configuration.  The default title in Node.js is
 *      the full command line, which may include env var values on some
 *      platforms.
 *
 *   2. umask enforcement (0o027)
 *      Node.js inherits the parent process umask.  In many environments the
 *      default is 0o022 (world-readable files).  QODIQA stores sensitive
 *      data (key store, audit log, policy file) as local files.  A umask of
 *      0o027 ensures newly created files are mode 640 (owner rw, group r,
 *      world none) and directories are mode 750.
 *
 *   3. Unhandled exception / rejection handlers  (Finding 3.6 remediation)
 *      Node.js crashes with a full stack trace on unhandled rejections.
 *      In production this may leak internal paths, module names, or request
 *      data to stderr which could be forwarded to a log aggregator that is
 *      not under the operator's control.  The handlers here log a structured
 *      event and, for anything on the primary request path or a
 *      startup-critical precondition, exit(1) — crashing fast is intentional
 *      because the process is in an unknown state.  Never swallow those
 *      silently.
 *
 *      What changed under Finding 3.6 ("global crash-on-unhandled-rejection
 *      with no failure isolation"): every background job (scanners, webhook
 *      delivery, cache refresh, telemetry export, key rotation ticks, …) now
 *      runs through src/runtime/backgroundTasks/BackgroundTaskRunner.js,
 *      which is the actual containment boundary — it catches everything
 *      inside a wrapped task and never lets a non-startup-critical failure
 *      escape as a rejected promise in the first place.  This global handler
 *      is now defense-in-depth for the rare case something still escapes
 *      that boundary (e.g. a detached timer or unawaited promise created
 *      *inside* a task body, outliving the wrapper's try/catch): it consults
 *      the active BackgroundTaskRunner task context
 *      (src/runtime/backgroundTasks/taskContext.js) and only skips the
 *      exit when the escape is unambiguously attributable to a task
 *      classified as 'critical' or 'non-critical' (never 'startup-critical',
 *      and never when there is no active task context at all — i.e. the
 *      primary request path). An unhandled rejection should be exceptional
 *      now, not a normal execution path — see BACKGROUND_TASK_UNHANDLED_ESCAPE
 *      below, which is expected to fire at a rate of zero in steady state.
 *
 *   4. Single-instance assertion
 *      Re-asserts that the process is not running as a Node.js cluster worker.
 *      The audit chain assumes a single writer; a clustered child worker would
 *      create a split-brain audit log.  (Primary check is in multiInstanceGuard
 *      but we re-assert here at the runtime layer as defence-in-depth.)
 *
 *   5. NODE_ENV assertion
 *      Warns if NODE_ENV is not set (defaults to development behaviour which
 *      may disable security controls like HSTS and strict secret validation).
 */

const cluster = require('cluster');
const { currentTask } = require('./backgroundTasks/taskContext');
const { writeDiagnostic } = require('./rawStderrDiagnostic');

const SAFE_PROCESS_TITLE = 'qodiqa-gateway';

// Criticality levels (src/runtime/backgroundTasks/taskRegistry.js) that a
// global-handler escape is allowed to survive without exiting the process.
// 'startup-critical' is deliberately excluded — those are one-shot startup
// preconditions that must still fail fast.
const _SURVIVABLE_CRITICALITIES = new Set(['critical', 'non-critical']);

/**
 * Decide whether an unhandled rejection / uncaught exception escaping to
 * the global handler is attributable to an active BackgroundTaskRunner task
 * context, and if so, whether that task's criticality permits surviving it.
 *
 * Belt-and-suspenders only: in normal operation BackgroundTaskRunner itself
 * already prevents non-startup-critical task failures from ever reaching
 * here (see BackgroundTaskRunner.js). This exists for the residual case of
 * something created *inside* a task body (a detached timer, an unawaited
 * promise) that outlives the wrapper's own try/catch.
 *
 * @returns {{ survivable: boolean, task: object|null }}
 */
function _classifyEscape() {
  const task = currentTask();
  if (!task) return { survivable: false, task: null };
  return { survivable: _SURVIVABLE_CRITICALITIES.has(task.criticality), task };
}

/**
 * Applies all runtime process hardening controls.
 *
 * @param {Function} [emit] - Structured log emitter (emit(level, event, data)).
 *                            Optional — useful for testing without a real logger.
 * @param {object}   [opts]
 * @param {object}   [opts._metrics]  Injected metrics registry (testing).
 * @param {Function} [opts._exit]     Injected process.exit (testing).
 */
function applyProcessHardening(emit, opts = {}) {
  const log = emit || _defaultLog;
  const metrics = opts._metrics || require('../observability/metrics');
  const _exit = opts._exit || ((code) => { process.exitCode = code; process.exit(code); });

  // ── 1. Process title ────────────────────────────────────────────────────────
  try {
    process.title = SAFE_PROCESS_TITLE;
  } catch {
    // Some platforms (Alpine musl) do not allow setting process.title.
    // This is non-fatal — log and continue.
    log('WARN', 'PROCESS_TITLE_SET_FAILED', { title: SAFE_PROCESS_TITLE });
  }

  // ── 2. umask enforcement ────────────────────────────────────────────────────
  // 0o027: owner=rwx, group=rx, world=none → files 640, dirs 750.
  // Only apply if the current umask is more permissive than 0o027.
  let previousUmask;
  try {
    previousUmask = process.umask(0o027);
    if (previousUmask !== 0o027) {
      log('INFO', 'PROCESS_UMASK_SET', { previous: `0o${previousUmask.toString(8)}`, current: '0o027' });
    }
  } catch {
    // process.umask() is not available in Worker threads.
    log('WARN', 'PROCESS_UMASK_SET_FAILED', { note: 'Not available in this context' });
  }

  // ── 3. Unhandled rejection / exception handlers ─────────────────────────────
  // Only register if not already registered by another module.
  // See module header comment ("Finding 3.6 remediation") for the
  // criticality-aware rationale below.
  if (process.listenerCount('unhandledRejection') === 0) {
    process.on('unhandledRejection', (reason) => {
      const err = reason instanceof Error ? reason : new Error(String(reason));
      const { survivable, task } = _classifyEscape();

      if (survivable) {
        metrics.backgroundTasksFailedTotal.inc({ task: task.taskName, reason: 'escaped_isolation' });
        log('ERROR', 'BACKGROUND_TASK_UNHANDLED_ESCAPE', {
          task:        task.taskName,
          subsystem:   task.subsystem,
          owner:       task.owner,
          criticality: task.criticality,
          message:     err.message,
          stack:       err.stack,
          note:        'Unhandled rejection escaped BackgroundTaskRunner containment for a ' +
                       'non-startup-critical task — this should not happen; treat as a bug in ' +
                       'the task body (likely a detached timer or unawaited promise), not an ' +
                       'outage. Process is NOT exiting.',
        });
        return;
      }

      log('FATAL', 'UNHANDLED_REJECTION', {
        message: err.message,
        stack:   err.stack,
        task:    task ? task.taskName : null,
        note:    task
          ? 'Process exiting — unhandled rejection in a startup-critical task'
          : 'Process exiting — unhandled rejection indicates a coding error on the primary execution path',
      });
      _exit(1);
    });
  }

  if (process.listenerCount('uncaughtException') === 0) {
    process.on('uncaughtException', (err) => {
      const { survivable, task } = _classifyEscape();

      if (survivable) {
        metrics.backgroundTasksFailedTotal.inc({ task: task.taskName, reason: 'escaped_isolation' });
        log('ERROR', 'BACKGROUND_TASK_UNHANDLED_ESCAPE', {
          task:        task.taskName,
          subsystem:   task.subsystem,
          owner:       task.owner,
          criticality: task.criticality,
          message:     err.message,
          stack:       err.stack,
          note:        'Uncaught exception escaped BackgroundTaskRunner containment for a ' +
                       'non-startup-critical task — this should not happen; treat as a bug in ' +
                       'the task body. Process is NOT exiting.',
        });
        return;
      }

      log('FATAL', 'UNCAUGHT_EXCEPTION', {
        message: err.message,
        stack:   err.stack,
        task:    task ? task.taskName : null,
        note:    task
          ? 'Process exiting — uncaught exception in a startup-critical task'
          : 'Process exiting — uncaught exception leaves process in unknown state',
      });
      _exit(1);
    });
  }

  // ── 4. Cluster worker assertion ─────────────────────────────────────────────
  if (cluster.isWorker) {
    log('FATAL', 'PROCESS_CLUSTER_WORKER_DETECTED', {
      message:
        'QODIQA must not run as a Node.js cluster worker.  The hash-chained ' +
        'audit log assumes a single writer per process.  Running multiple ' +
        'cluster workers on the same audit log file creates a split-brain ' +
        'condition.  Use a process manager (PM2 fork mode, systemd) with a ' +
        'single worker per audit log file instead.',
    });
    process.exit(1);
  }

  // ── 5. NODE_ENV assertion ───────────────────────────────────────────────────
  const nodeEnv = process.env.NODE_ENV;
  if (!nodeEnv) {
    log('WARN', 'NODE_ENV_NOT_SET', {
      message:
        'NODE_ENV is not set.  QODIQA defaults to development mode which ' +
        'disables HSTS, relaxes secret validation, and may expose debug ' +
        'information.  Set NODE_ENV=production for production deployments.',
    });
  } else if (nodeEnv !== 'production' && nodeEnv !== 'test' && nodeEnv !== 'development') {
    log('WARN', 'NODE_ENV_UNRECOGNISED', { nodeEnv, known: ['production', 'development', 'test'] });
  }

  log('INFO', 'PROCESS_HARDENING_APPLIED', {
    title: SAFE_PROCESS_TITLE,
    umask: '0o027',
    nodeEnv: nodeEnv || '(not set)',
  });
}

// See src/runtime/rawStderrDiagnostic.js for the single shared
// implementation of this fail-safe write path.
function _defaultLog(level, event, data) {
  writeDiagnostic(level, event, data);
}

module.exports = { applyProcessHardening, SAFE_PROCESS_TITLE };
