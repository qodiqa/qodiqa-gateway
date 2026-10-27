'use strict';

/**
 * Memory Profiler —
 *
 * Provides three complementary memory analysis tools:
 *
 *   1. Heap snapshot capture (V8 heapsnapshot format via `v8.writeHeapSnapshot`
 *      or inspector-based capture for programmatic analysis).
 *
 *   2. Retained object tracking — tracks how much heap a code section
 *      allocates and retains after GC, using `process.memoryUsage()` deltas
 *      bracketed by explicit GC calls.
 *
 *   3. Bounded cache validation — given a cache-like object with a `size`
 *      property, asserts it never exceeds a configured maximum.
 *
 * Design constraints:
 *   • Pure Node.js built-ins (v8, inspector, process).
 *   • Heap snapshots require --expose-gc or are skipped gracefully.
 *   • All public functions return plain frozen objects — no streams.
 */

const v8 = require('v8');

// ── GC helper ─────────────────────────────────────────────────────────────────

function _gc() {
  if (typeof global.gc === 'function') { global.gc(); return true; }
  return false;
}

function _snapshot() {
  return process.memoryUsage();
}

function _delta(before, after) {
  return {
    heapUsed:     after.heapUsed     - before.heapUsed,
    heapTotal:    after.heapTotal    - before.heapTotal,
    rss:          after.rss          - before.rss,
    external:     after.external     - before.external,
    arrayBuffers: after.arrayBuffers - before.arrayBuffers,
  };
}

// ── Retained heap measurement ─────────────────────────────────────────────────

/**
 * Measure the net heap retained by `fn` after garbage collection.
 *
 * Runs `fn` once, forces GC before and after, and returns the heap delta.
 * Positive values mean `fn` retained allocations; negative values indicate
 * that GC reclaimed more than was allocated (prior run leaving objects).
 *
 * @param {Function} fn        — async or sync function to measure
 * @returns {Promise<RetainedHeapResult>}
 */
async function measureRetainedHeap(fn) {
  _gc();
  const before = _snapshot();
  _gc();

  await fn();

  _gc();
  const after = _snapshot();

  return Object.freeze({
    gcAvailable:  typeof global.gc === 'function',
    delta:        Object.freeze(_delta(before, after)),
    before:       Object.freeze(before),
    after:        Object.freeze(after),
  });
}

/**
 * Run `fn` N times and report heap growth per iteration.
 * Useful for detecting leaks: if heap grows linearly, there is a leak.
 *
 * @param {string}   label
 * @param {Function} fn
 * @param {object}   [options]
 * @param {number}   [options.iterations=10]
 * @param {number}   [options.warmup=3]
 * @returns {Promise<HeapGrowthResult>}
 */
async function measureHeapGrowth(label, fn, options) {
  const opts       = options || {};
  const iterations = opts.iterations || 10;
  const warmup     = opts.warmup != null ? opts.warmup : 3;

  for (let i = 0; i < warmup; i++) {
    try { await fn(); } catch { /* ignore */ }
  }

  const snapshots = [];
  for (let i = 0; i < iterations; i++) {
    _gc();
    const before = _snapshot();
    _gc();
    await fn();
    _gc();
    const after  = _snapshot();
    snapshots.push({ iteration: i + 1, heapUsed: after.heapUsed, delta: after.heapUsed - before.heapUsed });
  }

  const deltas    = snapshots.map(s => s.delta);
  const mean      = deltas.reduce((s, v) => s + v, 0) / deltas.length;
  const sorted    = [...deltas].sort((a, b) => a - b);
  const first     = snapshots[0].heapUsed;
  const last      = snapshots[snapshots.length - 1].heapUsed;
  const totalGrowth = last - first;

  // Simple leak detection: if mean delta is consistently positive and
  // total growth exceeds 1 MB across iterations, flag as potential leak.
  const likelyLeak = mean > 0 && totalGrowth > 1_048_576;

  return Object.freeze({
    label,
    iterations,
    gcAvailable: typeof global.gc === 'function',
    snapshots,
    delta: Object.freeze({
      mean,
      min:  sorted[0],
      max:  sorted[sorted.length - 1],
      p50:  sorted[Math.floor(sorted.length * 0.50)],
      p99:  sorted[Math.max(0, Math.ceil(sorted.length * 0.99) - 1)],
    }),
    totalGrowthBytes: totalGrowth,
    likelyLeak,
  });
}

// ── Heap snapshot ─────────────────────────────────────────────────────────────

/**
 * Write a V8 heap snapshot to the specified path.
 *
 * Returns the path written to, or null if heap snapshots are unavailable
 * (v8.writeHeapSnapshot throws in some environments).
 *
 * @param {string} [outputPath]  — if omitted, uses a temp path
 * @returns {{ path: string, sizeBytes: number } | null}
 */
function captureHeapSnapshot(outputPath) {
  const fs   = require('fs');
  const path = require('path');
  const os   = require('os');

  const dest = outputPath || path.join(os.tmpdir(), `qodiqa-heap-${Date.now()}.heapsnapshot`);
  const dir  = path.dirname(dest);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  try {
    const written = v8.writeHeapSnapshot(dest);
    const stat    = fs.statSync(written);
    return Object.freeze({ path: written, sizeBytes: stat.size });
  } catch {
    return null;
  }
}

// ── Bounded cache validation ──────────────────────────────────────────────────

/**
 * Assert that a cache-like object (with a numeric `size` property) never
 * grows beyond `maxSize` entries after running `fn` N times.
 *
 * Designed to validate that bounded caches (LRU, TTL-expiring maps) in the
 * enforcement pipeline don't leak entries over long operation windows.
 *
 * @param {string}                    label
 * @param {{ size: number }|Function} cache    — object with .size, or fn returning it
 * @param {Function}                  fn       — operation to execute per iteration
 * @param {object}                    options
 * @param {number}                    options.maxSize     — maximum allowed entries
 * @param {number}                    [options.iterations=1000]
 * @returns {Promise<BoundedCacheResult>}
 */
async function validateBoundedCache(label, cache, fn, options) {
  const opts       = options || {};
  const maxSize    = opts.maxSize;
  const iterations = opts.iterations || 1_000;

  if (typeof maxSize !== 'number') throw new TypeError('options.maxSize must be a number');

  const samples = [];
  for (let i = 0; i < iterations; i++) {
    await fn();
    if (i % Math.max(1, Math.floor(iterations / 20)) === 0) {
      const current = typeof cache === 'function' ? cache() : (cache.size || 0);
      samples.push({ iteration: i, size: current });
    }
  }

  const finalSize = typeof cache === 'function' ? cache() : (cache.size || 0);
  const maxObserved = Math.max(...samples.map(s => s.size), finalSize);
  const bounded     = maxObserved <= maxSize;

  return Object.freeze({
    label,
    iterations,
    maxSize,
    finalSize,
    maxObserved,
    bounded,
    samples,
  });
}

// ── V8 heap statistics ────────────────────────────────────────────────────────

/**
 * Return a snapshot of V8 heap statistics (v8.getHeapStatistics()).
 * Useful for comparing heap state before and after large operations.
 *
 * @returns {object}
 */
function getHeapStatistics() {
  return Object.freeze(v8.getHeapStatistics());
}

/**
 * Return V8 heap space statistics — per-space breakdown.
 *
 * @returns {object[]}
 */
function getHeapSpaceStatistics() {
  return v8.getHeapSpaceStatistics().map(s => Object.freeze({ ...s }));
}

module.exports = {
  measureRetainedHeap,
  measureHeapGrowth,
  captureHeapSnapshot,
  validateBoundedCache,
  getHeapStatistics,
  getHeapSpaceStatistics,
};
