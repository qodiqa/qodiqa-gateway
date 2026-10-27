'use strict';

/**
 * Live Audit Chain Verifier — Public API / Background Runner (CHAIN-2)
 *
 * Background periodic verifier for the PRODUCTION EXECUTION AUDIT CHAIN.
 * Runs three independent, unref'd, no-drift timers (so none of them can
 * keep the Node process alive on their own):
 *
 *   - INCREMENTAL  (QODIQA_AUDIT_VERIFIER_INCREMENTAL_INTERVAL, default 60s)
 *   - FULL         (QODIQA_AUDIT_VERIFIER_FULL_INTERVAL, default 4h)
 *   - PG_DIVERGENCE (QODIQA_AUDIT_VERIFIER_PG_DIVERGENCE_INTERVAL, default 15m;
 *                    a no-op unless single-node + PG dual-write mode)
 *
 * All three share one `_scanning` mutex so they never run concurrently with
 * each other (an incremental tick that fires mid-FULL-scan is skipped, not
 * queued) — mirrors src/core/transparency/scanner/index.js's `_scanning`
 * guard, and the same shape as every other background job in this codebase
 * (rootScheduler.js, key rotationScheduler.js).
 *
 * ── Usage ──────────────────────────────────────────────────────────────────
 *
 *   const runner = createVerifierRunner();
 *   await runner.start();
 *   // ... later, during graceful shutdown:
 *   runner.stop();
 *
 * ── Audit events emitted ───────────────────────────────────────────────────
 *
 *   AUDIT_CHAIN_VERIFIER_STARTED             INFO  — on start()
 *   AUDIT_CHAIN_VERIFIER_STOPPED             INFO  — on stop()
 *   AUDIT_CHAIN_VERIFIER_DISABLED            INFO  — QODIQA_AUDIT_VERIFIER_ENABLED != 'true'
 *   AUDIT_CHAIN_VERIFIER_ALREADY_RUNNING     WARN  — duplicate start() call
 *   AUDIT_CHAIN_VERIFIER_SKIPPED             INFO  — tick skipped (already scanning)
 *   AUDIT_CHAIN_VERIFIER_RETRY               WARN  — retrying after an engine failure
 *   AUDIT_CHAIN_VERIFIER_RUN_FAILED          ERROR — exhausted retries
 *   AUDIT_CHAIN_VERIFIER_SCAN_COMPLETED      INFO  — emitted by ChainVerifier.js
 *   AUDIT_CHAIN_CORRUPTED / AUDIT_CHAIN_STRUCTURAL_ANOMALY — per violation, by severity
 */

const { createChainVerifier } = require('./ChainVerifier');
const { createCompletionTracker } = require('./completionTracker');

// (VERIFIER-DESIGN.md §4, approved): per-mode run deadlines. In process the runner can only REPORT a
// timeout (the run cannot be cancelled; the mutex stays held until it really ends, so scans never overlap); in the
// verifier worker the host enforces it by terminating the worker (workerHost.js).
// S3: PG_INCREMENTAL = the 60 s file<->PG new-row layer; its first pass from the chain base may be long, so it
// shares PG_DIVERGENCE's deadline.
const DEFAULT_DEADLINES_MS = Object.freeze({ INCREMENTAL: 30_000, FULL: 3_600_000, PG_DIVERGENCE: 600_000, PG_INCREMENTAL: 600_000,
  MIRROR_CHECKPOINT_ADVANCE: 600_000 });   //
const { load: loadConfig }    = require('./verifierConfig');
const { emit: _defaultEmit }  = require('../../../../services/logger');
const _defaultMetrics          = require('../../../observability/metrics');
const { monoNowMs } = require('../../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

const SOURCE = 'AUDIT_CHAIN_VERIFIER';

function _sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function _unref(timer) {
  if (timer && typeof timer.unref === 'function') timer.unref();
  return timer;
}

/**
 * Create a Live Audit Chain Verifier runner instance.
 * All I/O dependencies are injectable for testing.
 *
 * @param {object}   [opts]
 * @param {object}   [opts.config]  — override config (default: verifierConfig.load())
 * @param {Function} [opts._emit]
 * @param {object}   [opts._metrics]
 * @param {...*}     opts.*         — forwarded to createChainVerifier() (e.g. _auditLog,
 *                                    _pgPool, _pgBackend, _mirrorCheck, _verifierState)
 * @returns {{ start, stop, isRunning, isScanning, verifyNow, getStatus }}
 */
function createVerifierRunner(opts = {}) {
  const {
    config: _configOverride,
    _emit    = _defaultEmit,
    _metrics = _defaultMetrics,
    _onRunStart = null,   // the verifier worker reports each run's start/end to its host
    _onRunEnd   = null,
    ..._verifierDeps
  } = opts;

  const config = _configOverride || loadConfig();
  const {
    enabled,
    incrementalIntervalMs,
    fullIntervalMs,
    pgDivergenceIntervalMs,
    maxRetries,
    retryDelayMs,
    startupScan,
  } = config;

  const _verifier = createChainVerifier({ config, _emit, _metrics, ..._verifierDeps });
  const _deadlines = { ...DEFAULT_DEADLINES_MS, ...(config.deadlinesMs || {}) };
  // (owner amendments 5, 7): escalation of non-completing runs + verifier lag. Off inside the worker (config.
  // trackCompletion === false): there the HOST tracks, so an escalation survives a worker restart.
  const _auditLogForLag = _verifierDeps._auditLog || (() => { try { return require('../audit-log'); } catch { return null; } })();
  const _tracker = config.trackCompletion === false ? null : createCompletionTracker({
    emit: _emit, metrics: _metrics, notCompletingAfter: config.notCompletingAfter || 3, lagWarnEntries: config.lagWarnEntries || 60_000,
    getAppendedCount: () => { try { return _auditLogForLag.getChainStats().modernLength; } catch { return null; } },
  });

  // Runs fn under the mode's deadline. Returns { result, timedOut }; on timeout the caller releases the mutex only
  // when the real run settles (runPromise).
  async function _withDeadline(mode, fn) {
    const deadline = _deadlines[mode];
    const runPromise = Promise.resolve().then(fn);
    if (!deadline) return { result: await runPromise, timedOut: false, runPromise };
    let timer = null;
    const timeout = new Promise((resolve) => { timer = _unref(setTimeout(() => resolve('__TIMEOUT__'), deadline)); });
    const winner = await Promise.race([runPromise, timeout]);
    clearTimeout(timer);
    if (winner === '__TIMEOUT__') return { result: null, timedOut: true, runPromise };
    return { result: winner, timedOut: false, runPromise };
  }

  function _recordOutcome(mode, result, timedOut) {
    const outcome = timedOut ? 'TIMEOUT' : (result && result.success !== false ? 'COMPLETE' : 'FAILED');
    if (_tracker) {
      if (!(result && result.skipped)) _tracker.record(mode, outcome, timedOut ? { deadlineMs: _deadlines[mode] } : {});
      if (mode === 'INCREMENTAL' && result && Number.isFinite(result.watermarkIndex)) _tracker.recordWatermark(result.watermarkIndex);
    }
    return outcome;
  }

  // ── Mutable state ──────────────────────────────────────────────────────────

  let _running   = false;
  let _scanning  = false;
  let _startedAt = null;
  let _totalRuns    = 0;
  let _totalSuccess = 0;
  let _totalFailed  = 0;

  let _incTicker  = null;
  let _fullTicker = null;
  let _pgTicker   = null;

  // ── Core execution (own-chain verify) ─────────────────────────────────────

  async function _executeWithRetry(mode, trigger) {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (!_running && trigger !== 'MANUAL') return null;

      if (attempt > 0) {
        _metrics.auditChainVerifierRetriesTotal?.inc({});
        _emit('WARN', 'AUDIT_CHAIN_VERIFIER_RETRY', { source: SOURCE, mode, trigger, attempt, maxRetries });
        await _sleep(retryDelayMs);
        if (!_running && trigger !== 'MANUAL') return null;
      }

      try {
        const result = await _verifier.verify({ mode, trigger });
        if (result && result.success === false && attempt < maxRetries) continue;
        return result;
      } catch (err) {
        if (attempt === maxRetries) {
          _emit('ERROR', 'AUDIT_CHAIN_VERIFIER_RUN_FAILED', { source: SOURCE, mode, trigger, error: err.message });
          return { success: false, mode, trigger, error: err.message };
        }
        // loop continues for retry
      }
    }
    return null;
  }

  async function _execute(mode, trigger) {
    if (_scanning) {
      _metrics.auditChainVerifierSkippedTotal?.inc({ reason: 'already_scanning' });
      _emit('INFO', 'AUDIT_CHAIN_VERIFIER_SKIPPED', { source: SOURCE, reason: 'SCAN_IN_PROGRESS', mode, trigger });
      return { skipped: true, reason: 'ALREADY_SCANNING' };
    }

    _scanning = true;
    _totalRuns++;
    if (_onRunStart) _onRunStart(mode, trigger, _deadlines[mode]);
    let release = true;
    try {
      const { result, timedOut, runPromise } = await _withDeadline(mode, () => _executeWithRetry(mode, trigger));
      const outcome = _recordOutcome(mode, result, timedOut);
      if (timedOut) {
        release = false;
        _totalFailed++;
        _emit('WARN', 'AUDIT_CHAIN_VERIFIER_RUN_TIMEOUT', { source: SOURCE, mode, trigger, deadlineMs: _deadlines[mode] });
        runPromise.catch(() => {}).finally(() => { _scanning = false; });
        const r = { success: false, mode, trigger, outcome: 'TIMEOUT' };
        if (_onRunEnd) _onRunEnd(mode, trigger, r, outcome);
        return r;
      }
      if (result && result.success !== false) _totalSuccess++;
      else _totalFailed++;
      if (_onRunEnd) _onRunEnd(mode, trigger, result, outcome);
      return result;
    } finally {
      if (release) _scanning = false;
    }
  }

  // S3: one mutex-guarded executor for the file<->PG modes. PG_DIVERGENCE scheduled = the layered 15-min run
  // (anchors + sweep slice); MANUAL = the full comparison (unchanged entry point); PG_INCREMENTAL = the 60 s layer.
  async function _executePgMode(mode, trigger, fn) {
    if (_scanning) {
      _metrics.auditChainVerifierSkippedTotal?.inc({ reason: 'already_scanning' });
      return { skipped: true, reason: 'ALREADY_SCANNING' };
    }
    _scanning = true;
    if (_onRunStart) _onRunStart(mode, trigger, _deadlines[mode]);
    let release = true;
    try {
      const { result, timedOut, runPromise } = await _withDeadline(mode, fn);
      const outcome = _recordOutcome(mode, result, timedOut);
      if (timedOut) {
        release = false;
        _emit('WARN', 'AUDIT_CHAIN_VERIFIER_RUN_TIMEOUT', { source: SOURCE, mode, trigger, deadlineMs: _deadlines[mode] });
        runPromise.catch(() => {}).finally(() => { _scanning = false; });
        const r = { success: false, trigger, outcome: 'TIMEOUT' };
        if (_onRunEnd) _onRunEnd(mode, trigger, r, outcome);
        return r;
      }
      if (_onRunEnd) _onRunEnd(mode, trigger, result, outcome);
      return result;
    } finally {
      if (release) _scanning = false;
    }
  }

  function _executePgDivergence(trigger) {
    const full = trigger === 'MANUAL' || config.divergenceMode === 'full' || typeof _verifier.verifyPgDivergenceRolling !== 'function';
    return _executePgMode('PG_DIVERGENCE', trigger, () => (full ? _verifier.verifyPgDivergence(trigger) : _verifier.verifyPgDivergenceRolling(trigger)));
  }

  function _executePgIncremental(trigger) {
    return _executePgMode('PG_INCREMENTAL', trigger, () => _verifier.verifyPgDivergenceIncremental(trigger));
  }

  // runtime mirror-checkpoint advancement, under the same mutex (never overlaps another verifier mode).
  function _executeAdvance(trigger) {
    if (typeof _verifier.advanceMirrorCheckpoint !== 'function') return Promise.resolve({ skipped: true, reason: 'UNSUPPORTED' });
    return _executePgMode('MIRROR_CHECKPOINT_ADVANCE', trigger, () => _verifier.advanceMirrorCheckpoint(trigger));
  }

  // The 15 min tick: the file<->PG divergence run, then the mirror-checkpoint advancement — sequential, same mutex.
  async function _pgTick(trigger) {
    const r = await _executePgDivergence(trigger);
    await _executeAdvance(trigger);
    return r;
  }

  // The 60 s tick: the file-mode incremental verify (unchanged), then the file<->PG new-row layer — sequential, under
  // the same mutex, so no verifier modes overlap.
  async function _incrementalTick(trigger) {
    const r = await _execute('INCREMENTAL', trigger);
    if (config.divergenceMode !== 'full' && typeof _verifier.verifyPgDivergenceIncremental === 'function') await _executePgIncremental(trigger);
    return r;
  }

  // ── No-drift ticker factory (one per timer; reschedules relative to when
  //    the tick SHOULD have fired, not when the previous run finished) ──────

  function _makeTicker(runFn, intervalMs) {
    let timer = null;

    async function tick() {
      if (!_running) return;
      const scheduledAt = monoNowMs(); // monotonic (same-process)
      try {
        await runFn();
      } finally {
        if (_running && intervalMs > 0) {
          const elapsed = monoNowMs() - scheduledAt; // monotonic (same-process)
          const delay   = Math.max(0, intervalMs - elapsed);
          timer = _unref(setTimeout(tick, delay));
        }
      }
    }

    return {
      start(initialDelayMs) {
        if (intervalMs > 0) timer = _unref(setTimeout(tick, initialDelayMs));
      },
      stop() {
        if (timer !== null) { clearTimeout(timer); timer = null; }
      },
    };
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  return {
    /**
     * Start the background runner. Idempotent — a second call emits a
     * warning and returns immediately.
     * @returns {Promise<object>} this (for chaining)
     */
    async start() {
      if (_running) {
        _emit('WARN', 'AUDIT_CHAIN_VERIFIER_ALREADY_RUNNING', { source: SOURCE });
        return this;
      }

      if (!enabled) {
        _emit('INFO', 'AUDIT_CHAIN_VERIFIER_DISABLED', {
          source:  SOURCE,
          message: 'QODIQA_AUDIT_VERIFIER_ENABLED is not "true". Verifier is inactive.',
        });
        return this;
      }

      _running   = true;
      _startedAt = new Date();
      _metrics.auditChainVerifierRunnerActive?.set({}, 1);

      _emit('INFO', 'AUDIT_CHAIN_VERIFIER_STARTED', {
        source: SOURCE,
        incrementalIntervalMs, fullIntervalMs, pgDivergenceIntervalMs,
        maxRetries, retryDelayMs, startupScan,
      });

      if (startupScan) {
        await _execute('INCREMENTAL', 'STARTUP');
      }

      _incTicker  = _makeTicker(() => _incrementalTick('SCHEDULED'), incrementalIntervalMs);
      _fullTicker = _makeTicker(() => _execute('FULL', 'SCHEDULED'), fullIntervalMs);
      _pgTicker   = _makeTicker(() => _pgTick('SCHEDULED'), pgDivergenceIntervalMs);

      _incTicker.start(incrementalIntervalMs);
      _fullTicker.start(fullIntervalMs);
      _pgTicker.start(pgDivergenceIntervalMs);

      return this;
    },

    /**
     * Stop the runner. Idempotent. Any in-progress scan completes; no new
     * timers are scheduled after this call.
     * @returns {object} this (for chaining)
     */
    stop() {
      if (!_running) return this;

      _running = false;
      _metrics.auditChainVerifierRunnerActive?.set({}, 0);

      _incTicker?.stop();
      _fullTicker?.stop();
      _pgTicker?.stop();

      _emit('INFO', 'AUDIT_CHAIN_VERIFIER_STOPPED', {
        source: SOURCE,
        totalRuns: _totalRuns, totalSuccess: _totalSuccess, totalFailed: _totalFailed,
        startedAt: _startedAt?.toISOString() ?? null,
      });

      return this;
    },

    /** @returns {boolean} */
    isRunning() { return _running; },

    /** @returns {boolean} */
    isScanning() { return _scanning; },

    /**
     * Trigger an immediate verification without waiting for the next timer
     * tick. Safe to call whether or not the background runner is started.
     * @param {'FULL'|'INCREMENTAL'} [mode]
     * @returns {Promise<object>} scan result
     */
    async verifyNow(mode) {
      return _execute(mode || 'INCREMENTAL', 'MANUAL');
    },

    /**
     * Layer 3: trigger an immediate PG_DIVERGENCE (file-vs-PG dual-write
     * cross-validation) check without waiting for the next scheduled tick
     * (default every 15 minutes — see verifierConfig.js). Before this, an
     * operator investigating a suspected mirror divergence mid-incident had
     * no way to force this specific check sooner; verifyNow() above only
     * ever routes to the file-only FULL/INCREMENTAL scans, which never
     * inspect PostgreSQL at all in single-node mode. Reuses the exact same
     * mutex-guarded _executePgDivergence() the scheduled ticker calls — same
     * serialization-with-other-scans guarantee, no shortcut around it.
     * Safe to call whether or not the background runner is started.
     * @returns {Promise<object>} scan result
     */
    async verifyPgDivergenceNow() {
      return _executePgDivergence('MANUAL');
    },

    /** run the mirror-checkpoint advancement now (same mutex as the scheduled run). */
    async advanceMirrorCheckpointNow() {
      return _executeAdvance('MANUAL');
    },

    /** @returns {object} status snapshot */
    getStatus() {
      return Object.freeze({
        running:  _running,
        scanning: _scanning,
        enabled,
        incrementalIntervalMs, fullIntervalMs, pgDivergenceIntervalMs,
        maxRetries, retryDelayMs, startupScan,
        startedAt:    _startedAt?.toISOString() ?? null,
        totalRuns:    _totalRuns,
        totalSuccess: _totalSuccess,
        totalFailed:  _totalFailed,
        lastResult:   _verifier.getLastResult(),
        completion:   _tracker ? _tracker.state() : null,
        deadlinesMs:  { ..._deadlines },
        host:         'in-process',
        repairAttempts:  0,
        repairSupported: false,
      });
    },
  };
}

// ── Default singleton accessor ────────────────────────────────────────────
//
// server.js creates/starts/stops exactly one runner for the life of the
// process (post-app.listen(), alongside the Gap Scanner / Key Rotation
// Scheduler — see server.js's startup wiring). The admin API routes
// (src/api/routes/audit.js's GET/POST /chain/verifier/*) need to reach that
// SAME running instance without server.js having to thread the reference
// through route-factory options — this mirrors
// services/artifact/rotationScheduler.js's getDefaultScheduler() pattern.
let _defaultInstance = null;

function getDefaultRunner() {
  // (VERIFIER-DESIGN.md): the verifier runs in a worker thread, off the request event loop, unless
  // QODIQA_AUDIT_VERIFIER_WORKER=false (then in process, as). Same public API either way.
  if (!_defaultInstance) {
    _defaultInstance = process.env.QODIQA_AUDIT_VERIFIER_WORKER === 'false'
      ? createVerifierRunner()
      : require('./workerHost').createWorkerRunner();
  }
  return _defaultInstance;
}

// Test-only: allows a fresh singleton per test file without a process restart.
function _resetDefaultRunner() {
  _defaultInstance = null;
}

module.exports = { createVerifierRunner, getDefaultRunner, _resetDefaultRunner };
