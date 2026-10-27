'use strict';

/**
 * QODIQA Transparency Root Scheduler — Component #33
 *
 * Automated background scheduler for periodic and event-driven generation of
 * Transparency Root digests.
 *
 * ── Triggering mechanisms ─────────────────────────────────────────────────────
 *
 * Time-based:  generate a root every N milliseconds (intervalMs > 0).
 * Entry-count: generate a root after N new log entries accumulate
 *              (entryThreshold > 0).
 *
 * Both mechanisms may be active simultaneously.  Whichever fires first
 * generates the next root.  The concurrency guard (_generating flag) ensures
 * that only one generation runs at a time even when both triggers fire close
 * together.
 *
 * ── Restart-safe state recovery ──────────────────────────────────────────────
 *
 * On start(), the scheduler queries the database to determine:
 *   • lastGeneratedAt — time of the most recent root (for initial time delay)
 *   • lastSeqTo       — seq_to of the most recent root (entry-count baseline)
 *
 * This ensures:
 *   • If the process was down for longer than intervalMs, a root is generated
 *     immediately on restart rather than waiting another full interval.
 *   • The entry-count baseline is correct even after restart.
 *
 * ── No-drift time scheduling ──────────────────────────────────────────────────
 *
 * Each time tick is scheduled relative to WHEN it should have fired, not when
 * it actually completed.  If execution takes T ms, the next tick is scheduled
 * at (scheduledTime + intervalMs), so the drift is bounded by execution latency
 * rather than accumulating over time.
 *
 * ── Concurrency safety ────────────────────────────────────────────────────────
 *
 * Within-process: the _generating flag prevents overlapping executions.
 *   - If the entry-count trigger fires while a time-triggered generation is
 *     running, the entry trigger is skipped with a SKIPPED audit event.
 *
 * Cross-process / Kubernetes replicas:
 *   - registrar.generateRoot() uses a PostgreSQL FOR UPDATE lock inside a
 *     REPEATABLE READ transaction.  The first caller wins; subsequent callers
 *     receive a "no new entries since last root" error, which this scheduler
 *     treats as a normal skip condition (INFO, not ERROR).
 *
 * ── Retry policy ─────────────────────────────────────────────────────────────
 *
 * On any non-skip failure, the scheduler retries up to maxRetries times with
 * retryDelayMs between each attempt.  After exhausting retries, the failure is
 * logged at ERROR level and the scheduler waits for the next scheduled trigger
 * rather than crashing.
 *
 * ── Audit events emitted ─────────────────────────────────────────────────────
 *
 *   TRANSPARENCY_ROOT_SCHEDULER_STARTED       INFO  — on start()
 *   TRANSPARENCY_ROOT_SCHEDULER_STOPPED       INFO  — on stop()
 *   TRANSPARENCY_ROOT_SCHEDULER_GENERATED     INFO  — successful root generation
 *   TRANSPARENCY_ROOT_SCHEDULER_SKIPPED       INFO  — no new entries, or busy
 *   TRANSPARENCY_ROOT_SCHEDULER_RETRY         WARN  — retrying after failure
 *   TRANSPARENCY_ROOT_SCHEDULER_FAILED        ERROR — all retries exhausted
 *   TRANSPARENCY_ROOT_SCHEDULER_STATE_LOAD_FAILED  WARN  — DB state query error on start
 *   TRANSPARENCY_ROOT_SCHEDULER_POLL_FAILED   WARN  — DB query error in entry poll
 *   TRANSPARENCY_ROOT_SCHEDULER_ALREADY_RUNNING    WARN  — duplicate start() call
 *
 * ── Prometheus metrics updated ────────────────────────────────────────────────
 *
 *   qodiqa_transparency_root_scheduler_runs_total        Counter  trigger label
 *   qodiqa_transparency_root_scheduler_generated_total   Counter  trigger label
 *   qodiqa_transparency_root_scheduler_skipped_total     Counter  trigger+reason labels
 *   qodiqa_transparency_root_scheduler_errors_total      Counter  trigger label
 *   qodiqa_transparency_root_scheduler_retries_total     Counter
 *   qodiqa_transparency_root_scheduler_duration_ms       Histogram trigger label
 *   qodiqa_transparency_root_scheduler_last_run_timestamp_seconds Gauge
 *   qodiqa_transparency_root_scheduler_active            Gauge    (1=running, 0=stopped)
 *
 * ── Configuration env vars ────────────────────────────────────────────────────
 *
 *   TRANSPARENCY_ROOT_INTERVAL_MS      Time-based interval in ms.  0 = disabled.
 *   TRANSPARENCY_ROOT_ENTRY_THRESHOLD  Entry count threshold.  0 = disabled.
 *   TRANSPARENCY_ROOT_INITIAL_DELAY_MS Initial delay before first time-based run
 *                                      when no previous root exists.  Default: 60 000.
 *   TRANSPARENCY_ROOT_POLL_INTERVAL_MS How often to check entry count.  Default: 30 000.
 *   TRANSPARENCY_ROOT_MAX_RETRIES      Max retry attempts on failure.  Default: 3.
 *   TRANSPARENCY_ROOT_RETRY_DELAY_MS   Delay between retries in ms.  Default: 5 000.
 */

const { emit: _defaultEmit } = require('../../../services/logger');
const _defaultMetrics        = require('../../observability/metrics');

const SOURCE = 'TRANSPARENCY_ROOT_SCHEDULER';

// ── Error classification ───────────────────────────────────────────────────────

const _SKIP_PATTERNS = [
  'no new entries since last root',
  'no transparency log entries exist',
  'no entries found in range',
];

function _isSkipError(err) {
  if (!(err instanceof Error)) return false;
  return _SKIP_PATTERNS.some(p => err.message.includes(p));
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function _envInt(key, fallback) {
  const raw = process.env[key];
  if (raw == null) return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function _unref(timer) {
  if (timer && typeof timer.unref === 'function') timer.unref();
  return timer;
}

// ── Scheduler factory ─────────────────────────────────────────────────────────

/**
 * Create and return a new Transparency Root Scheduler instance.
 *
 * All I/O dependencies are injectable for testing.
 *
 * @param {object}   [opts]
 * @param {number}   [opts.intervalMs]      Time interval in ms.  0 = disabled.
 * @param {number}   [opts.entryThreshold]  Entry count threshold.  0 = disabled.
 * @param {number}   [opts.initialDelayMs]  Initial delay (ms) before first time run when no prior root.
 * @param {number}   [opts.pollIntervalMs]  Entry-count poll interval in ms.
 * @param {number}   [opts.maxRetries]      Max retry attempts on generation failure.
 * @param {number}   [opts.retryDelayMs]    Delay between retries in ms.
 * @param {string}   [opts.generatedBy]     Value written to transparency_roots.generated_by.
 * @param {Function} [opts._generateRoot]   Injected for testing (default: registrar.generateRoot).
 * @param {Function} [opts._getLatestRoot]  Injected for testing (default: logStore.getLatestRoot).
 * @param {Function} [opts._getLatestEntry] Injected for testing (default: logStore.getLatestEntry).
 * @param {Function} [opts._emit]           Injected for testing (default: services/logger emit).
 * @param {object}   [opts._metrics]        Injected for testing (default: observability/metrics).
 * @returns {object} Scheduler instance with start(), stop(), isRunning(), getStatus().
 */
function createScheduler(opts = {}) {
  const {
    intervalMs     = _envInt('TRANSPARENCY_ROOT_INTERVAL_MS',    0),
    entryThreshold = _envInt('TRANSPARENCY_ROOT_ENTRY_THRESHOLD', 0),
    initialDelayMs = _envInt('TRANSPARENCY_ROOT_INITIAL_DELAY_MS', 60_000),
    pollIntervalMs = _envInt('TRANSPARENCY_ROOT_POLL_INTERVAL_MS', 30_000),
    maxRetries     = _envInt('TRANSPARENCY_ROOT_MAX_RETRIES',       3),
    retryDelayMs   = _envInt('TRANSPARENCY_ROOT_RETRY_DELAY_MS',    5_000),
    generatedBy    = 'scheduler',
    _generateRoot  = require('./registrar').generateRoot,
    _getLatestRoot = require('./logStore').getLatestRoot,
    _getLatestEntry = require('./logStore').getLatestEntry,
    _emit          = _defaultEmit,
    _metrics       = _defaultMetrics,
  } = opts;

  // ── Mutable state ───────────────────────────────────────────────────────────

  let _running            = false;
  let _generating         = false;
  let _timeTimer          = null;
  let _pollTimer          = null;
  let _nextTimeTriggerAt  = 0;    // Unix ms: when the next time tick should fire
  let _lastGeneratedAt    = null; // Date|null: derived from DB on start()
  let _lastSeqTo          = 0;    // Number: seq_to of last root, derived from DB
  let _startedAt          = null;
  let _totalRuns          = 0;
  let _totalGenerated     = 0;
  let _totalErrors        = 0;

  // ── DB state loader ─────────────────────────────────────────────────────────
  // Queries the live database to derive the correct scheduling baseline.
  // On failure, falls back to safe defaults (triggers run as if no prior root).

  async function _loadDbState() {
    try {
      const [latestRoot, latestEntry] = await Promise.all([
        _getLatestRoot(),
        _getLatestEntry(),
      ]);
      _lastSeqTo       = latestRoot  ? Number(latestRoot.seq_to)         : 0;
      _lastGeneratedAt = latestRoot  ? new Date(latestRoot.generated_at) : null;
      return { latestRoot, latestEntry };
    } catch (err) {
      _emit('WARN', 'TRANSPARENCY_ROOT_SCHEDULER_STATE_LOAD_FAILED', {
        source: SOURCE,
        error:  err.message,
      });
      _lastSeqTo       = 0;
      _lastGeneratedAt = null;
      return { latestRoot: null, latestEntry: null };
    }
  }

  // ── Core generation with retry ──────────────────────────────────────────────

  async function _generateWithRetry(trigger) {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) {
        _metrics.trSchedulerRetriesTotal.inc({});
        _emit('WARN', 'TRANSPARENCY_ROOT_SCHEDULER_RETRY', {
          source:     SOURCE,
          trigger,
          attempt,
          maxRetries,
        });
        await _sleep(retryDelayMs);
        if (!_running) return { generated: false, aborted: true };
      }

      try {
        const result = await _generateRoot({ generatedBy });

        _totalGenerated++;
        _metrics.trSchedulerGeneratedTotal.inc({ trigger });
        _emit('INFO', 'TRANSPARENCY_ROOT_SCHEDULER_GENERATED', {
          source:     SOURCE,
          trigger,
          rootId:     result.rootId,
          seqFrom:    result.seqFrom,
          seqTo:      result.seqTo,
          entryCount: result.entryCount,
          attempt,
          generatedBy,
        });
        return { generated: true };

      } catch (err) {
        if (_isSkipError(err)) {
          _metrics.trSchedulerSkippedTotal.inc({ trigger, reason: 'no_new_entries' });
          _emit('INFO', 'TRANSPARENCY_ROOT_SCHEDULER_SKIPPED', {
            source:  SOURCE,
            trigger,
            reason:  'NO_NEW_ENTRIES',
            detail:  err.message,
          });
          return { generated: false, skipped: true };
        }

        if (attempt === maxRetries) {
          _totalErrors++;
          _metrics.trSchedulerErrorsTotal.inc({ trigger });
          _emit('ERROR', 'TRANSPARENCY_ROOT_SCHEDULER_FAILED', {
            source:     SOURCE,
            trigger,
            attempt,
            maxRetries,
            error:      err.message,
          });
          return { generated: false, failed: true, error: err.message };
        }
        // Fall through to retry on next loop iteration
      }
    }
    return { generated: false };
  }

  // ── Main execution wrapper ──────────────────────────────────────────────────

  async function _executeGeneration(trigger) {
    if (_generating) {
      _metrics.trSchedulerSkippedTotal.inc({ trigger, reason: 'generating' });
      _emit('INFO', 'TRANSPARENCY_ROOT_SCHEDULER_SKIPPED', {
        source:  SOURCE,
        trigger,
        reason:  'GENERATING_IN_PROGRESS',
      });
      return;
    }

    _generating = true;
    _totalRuns++;
    _metrics.trSchedulerRunsTotal.inc({ trigger });
    const startMs = Date.now();

    try {
      await _generateWithRetry(trigger);
    } finally {
      _generating = false;
      const durationMs = Date.now() - startMs;
      _metrics.trSchedulerDurationMs.observe({ trigger }, durationMs);
      _metrics.trSchedulerLastRunTs.set({}, Math.floor(Date.now() / 1000));
    }
  }

  // ── Time-based trigger ──────────────────────────────────────────────────────

  async function _runTimeTick() {
    if (!_running) return;
    const scheduledAt = _nextTimeTriggerAt;

    try {
      await _executeGeneration('time');
    } finally {
      if (_running && intervalMs > 0) {
        _nextTimeTriggerAt = scheduledAt + intervalMs;
        const delay = Math.max(0, _nextTimeTriggerAt - Date.now());
        _timeTimer = _unref(setTimeout(_runTimeTick, delay));
      }
    }
  }

  // ── Entry-count polling ─────────────────────────────────────────────────────

  async function _pollEntryCount() {
    if (!_running || entryThreshold <= 0) return;

    try {
      const [latestRoot, latestEntry] = await Promise.all([
        _getLatestRoot(),
        _getLatestEntry(),
      ]);
      const currentSeqTo  = latestRoot  ? Number(latestRoot.seq_to) : 0;
      const latestEntryId = latestEntry ? Number(latestEntry.id)    : 0;
      const newEntries    = latestEntryId - currentSeqTo;

      if (newEntries >= entryThreshold) {
        await _executeGeneration('entry');
      }
    } catch (err) {
      _emit('WARN', 'TRANSPARENCY_ROOT_SCHEDULER_POLL_FAILED', {
        source: SOURCE,
        error:  err.message,
      });
    }

    if (_running && entryThreshold > 0) {
      _pollTimer = _unref(setTimeout(_pollEntryCount, pollIntervalMs));
    }
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  const scheduler = {

    /**
     * Start the scheduler.  Idempotent: calling start() while already running
     * emits a warning and returns without resetting state.
     *
     * Loads current DB state (latest root seq_to and generated_at) to derive
     * the correct initial timing delay and entry-count baseline.
     *
     * @returns {Promise<object>} this (for chaining)
     */
    async start() {
      if (_running) {
        _emit('WARN', 'TRANSPARENCY_ROOT_SCHEDULER_ALREADY_RUNNING', { source: SOURCE });
        return this;
      }

      _running   = true;
      _startedAt = new Date();
      _metrics.trSchedulerActive.set({}, 1);

      await _loadDbState();

      _emit('INFO', 'TRANSPARENCY_ROOT_SCHEDULER_STARTED', {
        source:          SOURCE,
        intervalMs,
        entryThreshold,
        pollIntervalMs,
        maxRetries,
        retryDelayMs,
        timeMode:        intervalMs     > 0,
        entryMode:       entryThreshold > 0,
        lastGeneratedAt: _lastGeneratedAt?.toISOString() ?? null,
        lastSeqTo:       _lastSeqTo,
        generatedBy,
      });

      // ── Time-based trigger ──────────────────────────────────────────────
      if (intervalMs > 0) {
        const now      = Date.now();
        const lastTime = _lastGeneratedAt ? _lastGeneratedAt.getTime() : 0;
        const elapsed  = now - lastTime;

        let delay;
        if (!_lastGeneratedAt) {
          // No previous root: use the configured initial delay.
          delay = initialDelayMs;
        } else if (elapsed >= intervalMs) {
          // Process was down for at least one full interval: run immediately.
          delay = 0;
        } else {
          // Normal case: wait for the remainder of the current interval.
          delay = intervalMs - elapsed;
        }

        _nextTimeTriggerAt = now + delay;
        _timeTimer = _unref(setTimeout(_runTimeTick, delay));
      }

      // ── Entry-count trigger ─────────────────────────────────────────────
      if (entryThreshold > 0) {
        _pollTimer = _unref(setTimeout(_pollEntryCount, pollIntervalMs));
      }

      return this;
    },

    /**
     * Stop the scheduler.  Idempotent.  Any in-progress generation completes
     * before the scheduler is fully idle; new timers will not be scheduled.
     *
     * @returns {object} this (for chaining)
     */
    stop() {
      if (!_running) return this;

      _running = false;
      _metrics.trSchedulerActive.set({}, 0);

      if (_timeTimer !== null) { clearTimeout(_timeTimer); _timeTimer = null; }
      if (_pollTimer !== null) { clearTimeout(_pollTimer); _pollTimer = null; }

      _emit('INFO', 'TRANSPARENCY_ROOT_SCHEDULER_STOPPED', {
        source:         SOURCE,
        totalRuns:      _totalRuns,
        totalGenerated: _totalGenerated,
        totalErrors:    _totalErrors,
        startedAt:      _startedAt?.toISOString() ?? null,
      });

      return this;
    },

    /** @returns {boolean} */
    isRunning() { return _running; },

    /**
     * Return a snapshot of current scheduler state.
     * @returns {object}
     */
    getStatus() {
      return Object.freeze({
        running:              _running,
        generating:           _generating,
        intervalMs,
        entryThreshold,
        pollIntervalMs,
        maxRetries,
        retryDelayMs,
        generatedBy,
        startedAt:            _startedAt?.toISOString()      ?? null,
        lastGeneratedAt:      _lastGeneratedAt?.toISOString() ?? null,
        lastSeqTo:            _lastSeqTo,
        nextTimeTriggerAt:    (intervalMs > 0 && _running)
          ? new Date(_nextTimeTriggerAt).toISOString()
          : null,
        totalRuns:            _totalRuns,
        totalGenerated:       _totalGenerated,
        totalErrors:          _totalErrors,
        timeMode:             intervalMs     > 0,
        entryMode:            entryThreshold > 0,
      });
    },
  };

  return scheduler;
}

module.exports = { createScheduler };
