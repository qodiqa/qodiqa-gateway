'use strict';

/**
 * GC Profiler —
 *
 * Hooks into Node.js `perf_hooks.PerformanceObserver` to record V8 garbage
 * collection events: timing, type, and memory impact.
 *
 * Provides:
 *   startGcObserver()  — begin collecting GC events
 *   stopGcObserver()   — stop collecting and return the event log
 *   profileGc()        — run fn, collect GC events during execution, return report
 *   analyseGcPressure() — classify a GC log into Low/Medium/High pressure
 *
 * Design constraints:
 *   • Pure Node.js built-ins (perf_hooks).
 *   • PerformanceObserver may not observe GC in all Node.js builds; function
 *     degrades gracefully and returns { available: false } rather than throwing.
 *   • All returned objects are frozen plain objects (no class instances).
 */

const { PerformanceObserver, constants: perfConstants } = require('perf_hooks');

// ── GC type names (from Node.js perf_hooks PerformanceEntry.detail.kind) ─────

const GC_TYPE_NAMES = Object.freeze({
  1:  'Scavenge',       // minor GC (young generation)
  2:  'MarkSweepCompact', // major GC (full)
  4:  'IncrementalMarking',
  8:  'WeakCallbacks',
  15: 'All',            // flags combined
});

function _gcTypeName(kind) {
  return GC_TYPE_NAMES[kind] || `GC(${kind})`;
}

// ── Observer lifecycle ────────────────────────────────────────────────────────

/**
 * Start a GC PerformanceObserver.
 *
 * @returns {{ stop: Function, getEvents: Function } | { available: false }}
 */
function startGcObserver() {
  const events = [];
  let obs;

  try {
    obs = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        const detail = entry.detail || {};
        events.push(Object.freeze({
          type:       _gcTypeName(detail.kind),
          kind:       detail.kind,
          durationMs: entry.duration,
          startTime:  entry.startTime,
          flags:      detail.flags || 0,
        }));
      }
    });
    obs.observe({ type: 'gc', buffered: false });
  } catch {
    return Object.freeze({ available: false });
  }

  return Object.freeze({
    available: true,
    stop() {
      try { obs.disconnect(); } catch { /* ignore */ }
    },
    getEvents() {
      return [...events];
    },
  });
}

// ── High-level profiling ──────────────────────────────────────────────────────

/**
 * Run `fn` and collect all GC events that occur during its execution.
 *
 * @param {Function} fn
 * @param {object}   [options]
 * @param {number}   [options.warmupMs=50] — wait after starting observer before running fn
 * @returns {Promise<GcProfileResult>}
 */
async function profileGc(fn, options) {
  const opts     = options || {};
  const warmupMs = opts.warmupMs != null ? opts.warmupMs : 50;

  const observer = startGcObserver();
  if (!observer.available) {
    await fn();
    return Object.freeze({ available: false, events: [], summary: null });
  }

  // Small wait to let the observer settle before measuring
  if (warmupMs > 0) {
    await new Promise(r => setTimeout(r, warmupMs));
  }

  const t0 = process.hrtime.bigint();
  await fn();
  const durationMs = Number(process.hrtime.bigint() - t0) / 1_000_000;

  // Give the observer time to flush buffered events
  await new Promise(r => setImmediate(r));
  observer.stop();

  const events  = observer.getEvents();
  const summary = _summariseEvents(events, durationMs);

  return Object.freeze({ available: true, durationMs, events, summary });
}

/**
 * Profile `fn` under sustained load and analyse GC pressure.
 *
 * @param {string}   label
 * @param {Function} fn
 * @param {object}   [options]
 * @param {number}   [options.iterations=100]
 * @param {number}   [options.warmup=10]
 * @returns {Promise<GcPressureResult>}
 */
async function profileGcPressure(label, fn, options) {
  const opts       = options || {};
  const iterations = opts.iterations || 100;
  const warmup     = opts.warmup != null ? opts.warmup : 10;

  for (let i = 0; i < warmup; i++) {
    try { await fn(); } catch { /* ignore */ }
  }

  const observer = startGcObserver();
  if (!observer.available) {
    for (let i = 0; i < iterations; i++) {
      try { await fn(); } catch { /* ignore */ }
    }
    return Object.freeze({ label, available: false, events: [], pressure: 'Unknown', summary: null });
  }

  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    try { await fn(); } catch { /* ignore */ }
  }
  const durationMs = Number(process.hrtime.bigint() - t0) / 1_000_000;

  await new Promise(r => setImmediate(r));
  observer.stop();

  const events   = observer.getEvents();
  const summary  = _summariseEvents(events, durationMs);
  const pressure = analyseGcPressure(summary);

  return Object.freeze({ label, available: true, iterations, durationMs, events, summary, pressure });
}

// ── Analysis ──────────────────────────────────────────────────────────────────

function _summariseEvents(events, durationMs) {
  if (!events || events.length === 0) {
    return Object.freeze({
      count:          0,
      totalPauseMs:   0,
      meanPauseMs:    0,
      maxPauseMs:     0,
      pausePercent:   0,
      byType:         {},
    });
  }

  const totalPauseMs = events.reduce((s, e) => s + e.durationMs, 0);
  const maxPauseMs   = Math.max(...events.map(e => e.durationMs));
  const meanPauseMs  = totalPauseMs / events.length;
  const pausePercent = durationMs > 0 ? (totalPauseMs / durationMs) * 100 : 0;

  const byType = {};
  for (const ev of events) {
    if (!byType[ev.type]) byType[ev.type] = { count: 0, totalMs: 0, maxMs: 0 };
    byType[ev.type].count++;
    byType[ev.type].totalMs += ev.durationMs;
    if (ev.durationMs > byType[ev.type].maxMs) byType[ev.type].maxMs = ev.durationMs;
  }

  return Object.freeze({
    count:        events.length,
    totalPauseMs,
    meanPauseMs,
    maxPauseMs,
    pausePercent,
    byType,
  });
}

/**
 * Classify a GC summary into a pressure level.
 *
 * Thresholds (empirically calibrated for Node.js 18/22 on commodity hardware):
 *   Low    — total GC pause < 5% of runtime, maxPause < 10 ms
 *   Medium — total GC pause 5–20% of runtime, or maxPause 10–50 ms
 *   High   — total GC pause > 20% of runtime, or maxPause > 50 ms
 *
 * @param {{ pausePercent, maxPauseMs, count }} summary
 * @returns {'Low'|'Medium'|'High'|'None'}
 */
function analyseGcPressure(summary) {
  if (!summary || summary.count === 0) return 'None';
  if (summary.pausePercent > 20 || summary.maxPauseMs > 50) return 'High';
  if (summary.pausePercent > 5  || summary.maxPauseMs > 10) return 'Medium';
  return 'Low';
}

module.exports = {
  startGcObserver,
  profileGc,
  profileGcPressure,
  analyseGcPressure,
};
