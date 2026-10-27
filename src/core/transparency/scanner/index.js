'use strict';

/**
 * Transparency Gap Scanner — Public API — Component #34
 *
 * Background periodic scanner for the transparency log.  Periodically runs a
 * full or incremental integrity scan and dispatches all detected gaps through
 * the existing Transparency Gap Handling framework (Component #14).
 *
 * ── Usage ────────────────────────────────────────────────────────────────────
 *
 *   const scanner = createScanner();
 *   await scanner.start();
 *   // ... later, during graceful shutdown:
 *   scanner.stop();
 *
 * ── Configuration ─────────────────────────────────────────────────────────────
 *
 *   All configuration is read from environment variables by scannerConfig.load().
 *   See scannerConfig.js for the full list of env vars.
 *
 *   Key env vars:
 *     TRANSPARENCY_SCANNER_ENABLED=true   — must be set to activate
 *     TRANSPARENCY_SCANNER_INTERVAL=5m    — scan interval
 *     TRANSPARENCY_SCANNER_MODE=INCREMENTAL
 *
 * ── Audit events emitted ──────────────────────────────────────────────────────
 *
 *   TRANSPARENCY_SCANNER_STARTED         INFO  — on start()
 *   TRANSPARENCY_SCANNER_STOPPED         INFO  — on stop()
 *   TRANSPARENCY_SCANNER_SCAN_STARTED    INFO  — beginning of each scan
 *   TRANSPARENCY_SCANNER_SCAN_COMPLETED  INFO  — successful scan
 *   TRANSPARENCY_SCANNER_SCAN_FAILED     ERROR — scan failed after retries
 *   TRANSPARENCY_SCANNER_SCAN_RANGE      INFO  — start/end positions
 *   TRANSPARENCY_SCANNER_LOCK_NOT_ACQUIRED INFO — another instance holds the lock
 *   TRANSPARENCY_SCANNER_GAP_RECOVERED   INFO  — gap auto-resolved after detection
 *   TRANSPARENCY_SCANNER_GAP_UNRECOVERABLE WARN — gap detected, not auto-resolvable
 *   TRANSPARENCY_SCANNER_PG_DISABLED     WARN  — PG not enabled (no-op)
 *   TRANSPARENCY_SCANNER_ALREADY_RUNNING WARN  — duplicate start() call
 *   TRANSPARENCY_SCANNER_RETRY           WARN  — retrying after failure
 *   TRANSPARENCY_SCANNER_STATE_SAVE_FAILED WARN — state write error (non-fatal)
 */

const { createGapScanner }   = require('./GapScanner');
const { load: loadConfig }   = require('./scannerConfig');
const { emit: _defaultEmit } = require('../../../../services/logger');
const _defaultMetrics         = require('../../../observability/metrics');
const _defaultTaskRunner      = require('../../../runtime/backgroundTasks/BackgroundTaskRunner');
const { monoNowMs } = require('../../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

const SOURCE = 'TRANSPARENCY_GAP_SCANNER';

// ── Helpers ───────────────────────────────────────────────────────────────────

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function _unref(timer) {
  if (timer && typeof timer.unref === 'function') timer.unref();
  return timer;
}

// ── Scanner runner factory ────────────────────────────────────────────────────

/**
 * Create a Transparency Gap Scanner runner instance.
 *
 * All I/O dependencies are injectable for testing.
 *
 * @param {object}   [opts]
 * @param {object}   [opts.config]         — override config (default: loadConfig())
 * @param {object}   [opts._pgPool]        — injected for testing
 * @param {object}   [opts._gapFramework]  — injected for testing
 * @param {Function} [opts._emit]          — injected for testing
 * @param {object}   [opts._metrics]       — injected for testing
 * @param {object}   [opts._scannerState]  — injected for testing
 * @returns {{ start, stop, isRunning, getStatus, scanOnce }}
 */
function createScanner(opts = {}) {
  const {
    config:         _configOverride,
    _pgPool,
    _gapFramework,
    _emit          = _defaultEmit,
    _metrics       = _defaultMetrics,
    _scannerState,
    _taskRunner    = _defaultTaskRunner,
  } = opts;

  const config = _configOverride || loadConfig();

  const {
    enabled,
    intervalMs,
    mode,
    maxRetries,
    retryDelayMs,
    startupScan,
  } = config;

  // GapScanner instance (core logic, injectable)
  const _scanner = createGapScanner({
    config,
    ...((_pgPool       != null) ? { _pgPool }       : {}),
    ...((_gapFramework != null) ? { _gapFramework }  : {}),
    ...((_emit         != null) ? { _emit }          : {}),
    ...((_metrics      != null) ? { _metrics }       : {}),
    ...((_scannerState != null) ? { _scannerState }  : {}),
  });

  // ── Mutable state ───────────────────────────────────────────────────────────

  let _running      = false;
  let _scanning     = false;
  let _timer        = null;
  let _startedAt    = null;
  let _totalRuns    = 0;
  let _totalSuccess = 0;
  let _totalFailed  = 0;

  // ── Core execution ──────────────────────────────────────────────────────────

  async function _executeWithRetry() {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (!_running) return;

      if (attempt > 0) {
        _metrics.gapScannerRetriesTotal?.inc({});
        _emit('WARN', 'TRANSPARENCY_SCANNER_RETRY', {
          source:     SOURCE,
          attempt,
          maxRetries,
          retryDelayMs,
        });
        await _sleep(retryDelayMs);
        if (!_running) return;
      }

      try {
        const result = await _scanner.scan();
        if (!result.skipped) {
          if (result.success !== false) {
            _totalSuccess++;
          } else {
            // scan returned a failure result without throwing
            _totalFailed++;
            if (attempt < maxRetries) continue;
          }
        }
        return result;
      } catch (err) {
        if (attempt === maxRetries) {
          _totalFailed++;
          _metrics.gapScannerFailuresTotal?.inc({ mode });
          _emit('ERROR', 'TRANSPARENCY_SCANNER_SCAN_FAILED', {
            source:     SOURCE,
            attempt,
            maxRetries,
            error:      err.message,
          });
          return { success: false, error: err.message };
        }
        // Loop continues for retry
      }
    }
  }

  async function _execute() {
    if (_scanning) {
      _metrics.gapScannerSkippedTotal?.inc({ reason: 'already_scanning' });
      _emit('INFO', 'TRANSPARENCY_SCANNER_SKIPPED', {
        source: SOURCE,
        reason: 'SCAN_IN_PROGRESS',
      });
      return;
    }

    _scanning = true;
    _totalRuns++;
    _metrics.gapScannerActive?.set({}, 1);

    try {
      // Finding 3.6: runs through BackgroundTaskRunner so a thrown/rejected
      // error from _executeWithRetry() is contained and logged/metriced
      // instead of propagating out as an unhandled rejection when this is
      // invoked from the self-rescheduling _tick() loop below (bare
      // `setTimeout(_tick, …)` — nothing there awaits or catches). The
      // outer catch is additional defense-in-depth; runTask() itself does
      // not rethrow for this task's 'non-critical' classification.
      await _taskRunner.runTask('transparency-gap-scan', () => _executeWithRetry());
    } catch (err) {
      // Should be unreachable in practice — see comment above.
      _emit('ERROR', 'TRANSPARENCY_SCANNER_SCAN_ESCAPED', { source: SOURCE, error: err.message });
    } finally {
      _scanning = false;
      _metrics.gapScannerActive?.set({}, 0);
    }
  }

  // ── Timer management ────────────────────────────────────────────────────────

  async function _tick() {
    if (!_running) return;
    const scheduledAt = monoNowMs(); // monotonic (same-process)

    try {
      await _execute();
    } catch (err) {
      // Should be unreachable — _execute() no longer lets errors escape.
      // Defense-in-depth so the self-rescheduling loop never dies either way.
      _emit('ERROR', 'TRANSPARENCY_SCANNER_TICK_ESCAPED', { source: SOURCE, error: err.message });
    } finally {
      if (_running && intervalMs > 0) {
        const elapsed = monoNowMs() - scheduledAt; // monotonic (same-process)
        const delay   = Math.max(0, intervalMs - elapsed);
        _timer = _unref(setTimeout(_tick, delay));
      }
    }
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  return {
    /**
     * Start the scanner background runner.
     * Idempotent: a second call emits a warning and returns immediately.
     *
     * @returns {Promise<object>} this (for chaining)
     */
    async start() {
      if (_running) {
        _emit('WARN', 'TRANSPARENCY_SCANNER_ALREADY_RUNNING', { source: SOURCE });
        return this;
      }

      if (!enabled) {
        _emit('INFO', 'TRANSPARENCY_SCANNER_DISABLED', {
          source:  SOURCE,
          message: 'TRANSPARENCY_SCANNER_ENABLED is not "true". Scanner is inactive.',
        });
        return this;
      }

      _running   = true;
      _startedAt = new Date();
      _metrics.gapScannerRunnerActive?.set({}, 1);

      _emit('INFO', 'TRANSPARENCY_SCANNER_STARTED', {
        source:      SOURCE,
        intervalMs,
        mode,
        maxRetries,
        retryDelayMs,
        startupScan,
      });

      if (startupScan) {
        // Run immediately, then schedule
        await _execute();
      }

      if (_running && intervalMs > 0) {
        _timer = _unref(setTimeout(_tick, startupScan ? intervalMs : 0));
      }

      return this;
    },

    /**
     * Stop the scanner.  Idempotent.
     * Any in-progress scan completes; new timers will not be scheduled.
     *
     * @returns {object} this (for chaining)
     */
    stop() {
      if (!_running) return this;

      _running = false;
      _metrics.gapScannerRunnerActive?.set({}, 0);

      if (_timer !== null) {
        clearTimeout(_timer);
        _timer = null;
      }

      _emit('INFO', 'TRANSPARENCY_SCANNER_STOPPED', {
        source:       SOURCE,
        totalRuns:    _totalRuns,
        totalSuccess: _totalSuccess,
        totalFailed:  _totalFailed,
        startedAt:    _startedAt?.toISOString() ?? null,
      });

      return this;
    },

    /** @returns {boolean} */
    isRunning() { return _running; },

    /** @returns {boolean} */
    isScanning() { return _scanning; },

    /**
     * Trigger an immediate scan without waiting for the next timer tick.
     * Safe to call while the background runner is stopped or running.
     *
     * @param {string} [scanMode] — 'FULL' | 'INCREMENTAL' | undefined (use config)
     * @returns {Promise<object>} scan result
     */
    async scanOnce(scanMode) {
      return _scanner.scan(scanMode);
    },

    /** @returns {object} status snapshot */
    getStatus() {
      return Object.freeze({
        running:      _running,
        scanning:     _scanning,
        enabled,
        intervalMs,
        mode,
        maxRetries,
        retryDelayMs,
        startupScan,
        startedAt:    _startedAt?.toISOString() ?? null,
        totalRuns:    _totalRuns,
        totalSuccess: _totalSuccess,
        totalFailed:  _totalFailed,
        lastResult:   _scanner.getLastResult(),
      });
    },
  };
}

module.exports = { createScanner };
