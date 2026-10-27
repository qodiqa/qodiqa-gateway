'use strict';

/**
 * QODIQA Windowed Counter
 *
 * Maintains a sliding-window time series of event counts in memory.
 * Used by the AnomalyDetector to compute baselines and detect deviations
 * without requiring a database round-trip on the hot path.
 *
 * Data structure: circular buffer of (timestamp, count) buckets.
 * Window resolution: configurable bucket width (default 60s).
 * Maximum window: configurable (default 60 minutes = 60 buckets).
 */

class WindowedCounter {
  /**
   * @param {object} opts
   * @param {number} [opts.bucketMs]   — Bucket width in ms (default 60 000 = 1 min)
   * @param {number} [opts.windowMs]   — Total window in ms (default 3 600 000 = 1 hr)
   * @param {Function} [opts.clock]    — Returns current timestamp ms (injectable for tests)
   */
  constructor({ bucketMs = 60_000, windowMs = 3_600_000, clock = Date.now } = {}) {
    this._bucketMs  = bucketMs;
    this._windowMs  = windowMs;
    this._clock     = clock;
    this._maxBuckets = Math.ceil(windowMs / bucketMs) + 1;

    // Sparse map: bucketKey → count (where bucketKey = floor(ts / bucketMs))
    this._buckets   = new Map();
    this._totalEver = 0;
  }

  /**
   * Record N events occurring now.
   * @param {number} [n] — Default 1
   */
  increment(n = 1) {
    const key = this._currentBucketKey();
    this._buckets.set(key, (this._buckets.get(key) ?? 0) + n);
    this._totalEver += n;
    this._evict();
  }

  /**
   * Total count in the current window.
   */
  windowTotal() {
    const minKey = this._minBucketKey();
    let total = 0;
    for (const [k, v] of this._buckets) {
      if (k >= minKey) total += v;
    }
    return total;
  }

  /**
   * Per-minute rate across the current window (events / minute).
   */
  rate() {
    const windowMinutes = this._windowMs / 60_000;
    return this.windowTotal() / windowMinutes;
  }

  /**
   * Returns recent bucket values as an array (oldest → newest).
   * Useful for computing mean and std-dev.
   */
  bucketValues() {
    const minKey = this._minBucketKey();
    const entries = [];
    for (const [k, v] of this._buckets) {
      if (k >= minKey) entries.push({ key: k, value: v });
    }
    entries.sort((a, b) => a.key - b.key);
    return entries.map(e => e.value);
  }

  /**
   * Compute mean and standard deviation across current window buckets.
   */
  stats() {
    const values = this.bucketValues();
    if (!values.length) return { mean: 0, stddev: 0, min: 0, max: 0, count: 0 };

    const mean = values.reduce((s, v) => s + v, 0) / values.length;
    const variance = values.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / values.length;
    const stddev = Math.sqrt(variance);
    const min = Math.min(...values);
    const max = Math.max(...values);

    return { mean, stddev, min, max, count: values.length, windowTotal: this.windowTotal() };
  }

  /**
   * Check if the current rate deviates by more than N standard deviations from mean.
   * Returns { anomalous, deviation, zscore }.
   * @param {number} sigmaThreshold — Default 3.0 (3-sigma rule)
   */
  isAnomalous(sigmaThreshold = 3.0) {
    const { mean, stddev } = this.stats();
    const current = this._buckets.get(this._currentBucketKey()) ?? 0;

    if (stddev === 0 || mean === 0) {
      return { anomalous: false, zscore: 0, current, mean, stddev };
    }

    const zscore    = (current - mean) / stddev;
    const anomalous = zscore > sigmaThreshold;

    return { anomalous, zscore, current, mean, stddev, threshold: sigmaThreshold };
  }

  // ── Private ────────────────────────────────────────────────────────────────

  _currentBucketKey() {
    return Math.floor(this._clock() / this._bucketMs);
  }

  _minBucketKey() {
    return Math.floor((this._clock() - this._windowMs) / this._bucketMs);
  }

  _evict() {
    const minKey = this._minBucketKey();
    for (const k of this._buckets.keys()) {
      if (k < minKey) this._buckets.delete(k);
    }
  }
}

module.exports = { WindowedCounter };
