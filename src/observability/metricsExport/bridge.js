'use strict';

// periodic metrics OTLP export bridge.
//
// Design invariants (deliberately stricter than the existing trace exporter
// in one respect — see the "at most one in-flight export" note below):
//   • Export is TIMER-DRIVEN, not queue-driven. Unlike spans (discrete
//     events, naturally batched), this registry's counters/gauges/
//     histograms are a continuously-mutating CURRENT STATE snapshot — the
//     correct model is "read the current state on an interval and push it",
//     not "buffer every mutation and drain a queue". Pushing on every
//     single .inc()/.observe() call would be enormous, pointless overhead.
//   • At most ONE export in flight at a time. If a tick fires while the
//     previous export is still awaiting the collector, that tick is
//     SKIPPED (counted, not queued) rather than starting a second
//     concurrent HTTP request. This bounds memory and outbound connections
//     under a slow/unresponsive collector — the registry itself is
//     untouched by a skipped tick, so the NEXT successful export simply
//     reports the latest (more complete) cumulative state; nothing is lost
//     the way a dropped event would be, because these are absolute
//     counters/gauges, not discrete occurrences.
//   • The timer is unref()'d — it can never keep the Node process alive on
//     its own, and never blocks graceful shutdown.
//   • Export failures are swallowed at this layer (network error, timeout,
//     4xx/5xx from the exporter) — never rethrown, never affect request
//     serving, matching this repository's own "metrics must never throw
//     into the response path" convention (metricsMiddleware.js) extended to
//     this asynchronous path too.
//   • shutdown() clears the timer and makes one final bounded export
//     attempt so the last export interval's data isn't silently lost on a
//     clean shutdown; it never throws and never hangs (bounded by the
//     exporter's own 15s HTTP timeout).

function createMetricsExportBridge(config, { exporter, getRegistrySnapshot }) {
  const _state = {
    exported:       0,
    failed:         0,
    skippedOverlap: 0,
    lastExport:     null,
    lastFailure:    null,
  };
  let _timer     = null;
  let _inFlight  = false;

  async function _tick() {
    if (_inFlight) {
      _state.skippedOverlap++;
      return;
    }
    _inFlight = true;
    try {
      await exporter.exportMetrics(getRegistrySnapshot());
      _state.exported++;
      _state.lastExport = new Date().toISOString();
    } catch {
      _state.failed++;
      _state.lastFailure = new Date().toISOString();
      // Failure isolation — never rethrow, matching the trace exporter's
      // own tracer.js _flush() convention.
    } finally {
      _inFlight = false;
    }
  }

  function start() {
    if (_timer) return; // idempotent
    _timer = setInterval(() => { _tick().catch(() => {}); }, config.exportIntervalMs);
    if (typeof _timer.unref === 'function') _timer.unref();
  }

  /** Clear the timer and make one final bounded export attempt. */
  async function shutdown() {
    if (_timer) {
      clearInterval(_timer);
      _timer = null;
    }
    await _tick();
  }

  function getHealth() {
    let status = 'unknown';
    if (_state.lastExport && !_state.lastFailure)      status = 'healthy';
    else if (!_state.lastExport && _state.lastFailure) status = 'degraded';
    else if (_state.lastExport && _state.lastFailure)
      status = _state.lastExport >= _state.lastFailure ? 'healthy' : 'degraded';

    return {
      component:   'otlp_metrics_export',
      status,
      exporter:    exporter.name,
      lastExport:  _state.lastExport,
      lastFailure: _state.lastFailure,
      inFlight:    _inFlight,
    };
  }

  function getStats() {
    return {
      exported_total:        _state.exported,
      failed_total:          _state.failed,
      skipped_overlap_total: _state.skippedOverlap,
    };
  }

  return { start, shutdown, getHealth, getStats };
}

module.exports = { createMetricsExportBridge };
