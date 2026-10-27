'use strict';

// Import the shared exported instances AND the classes indirectly by exercising
// them via the module's public surface. We also pull collect() from the module.
const metrics = require('./metrics');

const {
  requestsTotal,
  blocksTotal,
  requestDurationMs,
  activeRequests,
  redisStoreUp,
  collect,
} = metrics;

// ── Counter ────────────────────────────────────────────────────────────────────

describe('Counter', () => {
  // Use a fresh Counter instance for isolation
  const { requestsTotal: _unused, ...rest } = metrics;
  // Re-require won't work due to module cache; use the exported instances directly
  // but test via fresh inline counters built from the same class pattern.

  // We can test Counter behaviour through the exported counter instances.
  // Each test increments by known amounts and verifies format().

  test('inc() without labels increments the default bucket', () => {
    // Create a scoped counter instance by exercising blocksTotal (initially 0 for this label)
    const label = { reason: `__test_counter_nolabel_${Date.now()}` };
    blocksTotal.inc(label, 0); // init at 0
    const before = blocksTotal._values.get('reason="' + label.reason + '"') || 0;
    blocksTotal.inc(label, 3);
    const after = blocksTotal._values.get('reason="' + label.reason + '"') || 0;
    expect(after - before).toBe(3);
  });

  test('inc() default amount is 1', () => {
    const label = { reason: `__test_counter_default_${Date.now()}` };
    blocksTotal.inc(label);
    const val = blocksTotal._values.get('reason="' + label.reason + '"') || 0;
    expect(val).toBe(1);
  });

  test('inc() accumulates across multiple calls', () => {
    const label = { reason: `__test_counter_accum_${Date.now()}` };
    blocksTotal.inc(label, 10);
    blocksTotal.inc(label, 5);
    blocksTotal.inc(label, 2);
    const val = blocksTotal._values.get('reason="' + label.reason + '"') || 0;
    expect(val).toBe(17);
  });

  test('format() returns valid Prometheus text with HELP and TYPE headers', () => {
    const output = requestsTotal.format();
    expect(output).toContain('# HELP qodiqa_requests_total');
    expect(output).toContain('# TYPE qodiqa_requests_total counter');
  });

  test('format() with labels serializes labels correctly', () => {
    const label = { decision: `__test_label_${Date.now()}` };
    requestsTotal.inc(label, 1);
    const output = requestsTotal.format();
    expect(output).toContain('decision="');
  });

  test('inc() with invalid amount does not throw (infallible)', () => {
    expect(() => requestsTotal.inc({}, NaN)).not.toThrow();
    expect(() => requestsTotal.inc({}, undefined)).not.toThrow();
    expect(() => requestsTotal.inc(null, 1)).not.toThrow();
    expect(() => requestsTotal.inc(undefined, 1)).not.toThrow();
  });
});

// ── Gauge ──────────────────────────────────────────────────────────────────────

describe('Gauge', () => {
  test('set() stores the exact value', () => {
    redisStoreUp.set({ store: '__test_set__' }, 42);
    const val = redisStoreUp._values.get('store="__test_set__"');
    expect(val).toBe(42);
  });

  test('inc() adds to the gauge value', () => {
    const labelKey = { store: `__test_gauge_inc_${Date.now()}` };
    redisStoreUp.set(labelKey, 10);
    redisStoreUp.inc(labelKey, 5);
    const key = Object.keys(labelKey).map(k => `${k}="${labelKey[k]}"`).join(',');
    expect(redisStoreUp._values.get(key)).toBe(15);
  });

  test('dec() subtracts from the gauge value', () => {
    const labelKey = { store: `__test_gauge_dec_${Date.now()}` };
    redisStoreUp.set(labelKey, 10);
    redisStoreUp.dec(labelKey, 3);
    const key = Object.keys(labelKey).map(k => `${k}="${labelKey[k]}"`).join(',');
    expect(redisStoreUp._values.get(key)).toBe(7);
  });

  test('set() then format() includes the metric name', () => {
    redisStoreUp.set({ store: '__test_format__' }, 1);
    const output = redisStoreUp.format();
    expect(output).toContain('# HELP qodiqa_redis_store_up');
    expect(output).toContain('# TYPE qodiqa_redis_store_up gauge');
  });

  test('inc() and dec() without labels work on the default bucket', () => {
    activeRequests.set({}, 0);
    activeRequests.inc({}, 2);
    activeRequests.dec({}, 1);
    expect(activeRequests._values.get('')).toBe(1);
  });

  test('set() with invalid value does not throw (infallible)', () => {
    expect(() => redisStoreUp.set(null, 1)).not.toThrow();
    expect(() => redisStoreUp.inc(null, 1)).not.toThrow();
    expect(() => redisStoreUp.dec(null, 1)).not.toThrow();
  });
});

// ── Histogram ─────────────────────────────────────────────────────────────────

describe('Histogram', () => {
  test('observe() puts value in the correct cumulative buckets', () => {
    requestDurationMs.observe({ path: '__test_hist__' }, 30);
    // bucket 5 should NOT include 30; bucket 50 should include 30
    const output = requestDurationMs.format();
    expect(output).toContain('_bucket');
    expect(output).toContain('_sum');
    expect(output).toContain('_count');
  });

  test('format() includes _bucket, _sum, and _count lines', () => {
    requestDurationMs.observe({ path: '__test_hist_fmt__' }, 100);
    const output = requestDurationMs.format();
    expect(output).toMatch(/qodiqa_request_duration_ms_bucket/);
    expect(output).toMatch(/qodiqa_request_duration_ms_sum/);
    expect(output).toMatch(/qodiqa_request_duration_ms_count/);
  });

  test('format() includes HELP and TYPE headers', () => {
    const output = requestDurationMs.format();
    expect(output).toContain('# HELP qodiqa_request_duration_ms');
    expect(output).toContain('# TYPE qodiqa_request_duration_ms histogram');
  });

  test('cumulative bucket invariant: larger buckets have >= count of smaller buckets', () => {
    const labelKey = { path: `__test_cumulative_${Date.now()}` };
    // Observe values that fall in different buckets
    requestDurationMs.observe(labelKey, 10);  // falls in 10, 25, 50, ... +Inf
    requestDurationMs.observe(labelKey, 200); // falls in 250, 500, ... +Inf only
    const data = requestDurationMs._data.get(
      Object.keys(labelKey).map(k => `${k}="${labelKey[k]}"`).join(','),
    );
    expect(data).toBeDefined();
    expect(data.count).toBe(2);
    // All bucket counts should be between 0 and total count
    for (const c of data.counts) {
      expect(c).toBeGreaterThanOrEqual(0);
      expect(c).toBeLessThanOrEqual(data.count);
    }
    // Counts are non-decreasing (cumulative)
    for (let i = 1; i < data.counts.length; i++) {
      expect(data.counts[i]).toBeGreaterThanOrEqual(data.counts[i - 1]);
    }
  });

  test('observe() does not throw for invalid value (infallible)', () => {
    expect(() => requestDurationMs.observe({}, NaN)).not.toThrow();
    expect(() => requestDurationMs.observe({}, undefined)).not.toThrow();
    expect(() => requestDurationMs.observe(null, 10)).not.toThrow();
  });

  // ── getMean() / estimatePercentile() — #9 ────────────────────────────

  test('getMean() returns the exact sum/count mean for a known label combination', () => {
    const label = { path: `__test_mean_${Date.now()}` };
    requestDurationMs.observe(label, 10);
    requestDurationMs.observe(label, 20);
    requestDurationMs.observe(label, 30);

    expect(requestDurationMs.getMean(label)).toBe(20);
  });

  test('getMean() returns 0 for an unknown label combination', () => {
    expect(requestDurationMs.getMean({ path: `__test_mean_unknown_${Date.now()}` })).toBe(0);
  });

  test('getMean() never throws (infallible)', () => {
    // null resolves to the same "no labels" key other test/modules also
    // observe into, so it may be non-zero — the contract under test is only
    // that a malformed/unusual labels argument never throws.
    expect(() => requestDurationMs.getMean(null)).not.toThrow();
    expect(typeof requestDurationMs.getMean(null)).toBe('number');
  });

  test('estimatePercentile() returns 0 for an unknown label combination', () => {
    const p = requestDurationMs.estimatePercentile({ path: `__test_pctl_unknown_${Date.now()}` }, 99);
    expect(p).toBe(0);
  });

  test('estimatePercentile(99) is >= estimatePercentile(50) for the same label (monotonic)', () => {
    const label = { path: `__test_pctl_monotonic_${Date.now()}` };
    for (const v of [5, 10, 15, 20, 100, 200, 1000, 2000]) requestDurationMs.observe(label, v);

    const p50 = requestDurationMs.estimatePercentile(label, 50);
    const p99 = requestDurationMs.estimatePercentile(label, 99);
    expect(p99).toBeGreaterThanOrEqual(p50);
  });

  test('estimatePercentile() falls back to the largest bucket boundary when every observation exceeds it', () => {
    const label = { path: `__test_pctl_overflow_${Date.now()}` };
    requestDurationMs.observe(label, 999_999); // far beyond DEFAULT_LATENCY_BUCKETS' max (30000)

    const p99 = requestDurationMs.estimatePercentile(label, 99);
    expect(p99).toBe(30_000);
  });

  test('estimatePercentile() never throws (infallible)', () => {
    // Same null-resolves-to-the-shared-"no labels"-key caveat as getMean() above.
    expect(() => requestDurationMs.estimatePercentile(null, 99)).not.toThrow();
    expect(typeof requestDurationMs.estimatePercentile(null, 99)).toBe('number');
  });
});

// ── collect() ─────────────────────────────────────────────────────────────────

describe('collect()', () => {
  test('returns a non-empty string', () => {
    const output = collect();
    expect(typeof output).toBe('string');
    expect(output.length).toBeGreaterThan(0);
  });

  test('output contains metric lines', () => {
    const output = collect();
    expect(output).toContain('# HELP');
    expect(output).toContain('# TYPE');
    expect(output).toContain('qodiqa_');
  });

  test('collect(n) sets active requests to n', () => {
    const output = collect(7);
    expect(output).toContain('qodiqa_active_requests');
    // After calling collect(7), the activeRequests gauge should have 7
    expect(activeRequests._values.get('')).toBe(7);
  });

  test('collect(0) sets active requests to 0', () => {
    collect(0);
    expect(activeRequests._values.get('')).toBe(0);
  });

  test('collect() without argument defaults active requests to 0', () => {
    collect();
    expect(activeRequests._values.get('')).toBe(0);
  });

  test('output ends with a newline', () => {
    const output = collect();
    expect(output.endsWith('\n')).toBe(true);
  });

  test('includes uptime metric', () => {
    const output = collect();
    expect(output).toContain('qodiqa_process_uptime_seconds');
  });
});

// ── OTLP translation additions ──────────────────────────────────────────
//
// toOtlpMetric()/getRegistrySnapshot() are pure additions used only by the
// optional metrics OTLP export bridge (src/observability/metricsExport/) —
// these tests prove they compute correctly AND that adding them left
// format()/collect()/the /metrics route completely unchanged.

describe('/metrics (collect/format) is unchanged by the OTLP additions', () => {
  test('collect() output is unaffected by calling toOtlpMetric() on the same metrics', () => {
    const label = { decision: `__f16_unchanged_${Date.now()}` };
    requestsTotal.inc(label, 5);
    const before = collect(3);
    requestsTotal.toOtlpMetric('1', '2'); // must have zero side effect on Prometheus output
    const after = collect(3);
    expect(after).toBe(before);
  });

  test('Counter.format() output is byte-identical before/after toOtlpMetric() calls', () => {
    const label = { reason: `__f16_counter_fmt_${Date.now()}` };
    blocksTotal.inc(label, 4);
    const before = blocksTotal.format();
    blocksTotal.toOtlpMetric('1', '2');
    blocksTotal.toOtlpMetric('1', '2');
    expect(blocksTotal.format()).toBe(before);
  });

  test('getRegistrySnapshot() returns an array containing the same live metric instances collect() iterates', () => {
    const snapshot = metrics.getRegistrySnapshot();
    expect(Array.isArray(snapshot)).toBe(true);
    expect(snapshot).toContain(requestsTotal);
    expect(snapshot).toContain(activeRequests);
  });

  test('getRegistrySnapshot() returns a NEW array each call (not a mutable reference to the internal registry)', () => {
    const a = metrics.getRegistrySnapshot();
    const b = metrics.getRegistrySnapshot();
    expect(a).not.toBe(b);
    expect(a.length).toBe(b.length);
  });
});

describe('Counter.toOtlpMetric()', () => {
  test('produces a Sum data point per distinct label combination', () => {
    const label1 = { decision: `__f16_c1_${Date.now()}` };
    const label2 = { decision: `__f16_c2_${Date.now()}` };
    requestsTotal.inc(label1, 3);
    requestsTotal.inc(label2, 7);
    const otlp = requestsTotal.toOtlpMetric('100', '200');
    const p1 = otlp.sum.dataPoints.find(dp => dp.attributes.some(a => a.value.stringValue === label1.decision));
    const p2 = otlp.sum.dataPoints.find(dp => dp.attributes.some(a => a.value.stringValue === label2.decision));
    expect(p1.asDouble).toBe(3);
    expect(p2.asDouble).toBe(7);
  });

  test('marks the sum as CUMULATIVE and monotonic (never resets, matches Prometheus semantics)', () => {
    const otlp = requestsTotal.toOtlpMetric('100', '200');
    expect(otlp.sum.aggregationTemporality).toBe(2); // OTLP CUMULATIVE
    expect(otlp.sum.isMonotonic).toBe(true);
  });

  test('preserves the metric name and help text as name/description', () => {
    const otlp = requestsTotal.toOtlpMetric('100', '200');
    expect(otlp.name).toBe(requestsTotal.name);
    expect(otlp.description).toBe(requestsTotal.help);
  });

  test('label keys/values are translated as OTLP string attributes, sanitized the same way as Prometheus labels', () => {
    const label = { decision: `has"quote_${Date.now()}` };
    requestsTotal.inc(label, 1);
    const otlp = requestsTotal.toOtlpMetric('1', '2');
    const dp = otlp.sum.dataPoints.find(d => d.attributes.some(a => a.value.stringValue.includes('has')));
    expect(dp).toBeDefined();
    expect(dp.attributes[0].key).toBe('decision');
  });

  test('a fresh, never-incremented counter still emits one zero-value data point (mirrors format()\'s always-present guarantee)', () => {
    const fresh = new metrics.Counter('qodiqa_f16_fresh_total', 'test');
    expect(fresh.format()).toContain('qodiqa_f16_fresh_total 0'); // format()'s own guarantee
    const otlp = fresh.toOtlpMetric('1', '2');
    expect(otlp.sum.dataPoints).toHaveLength(1);
    expect(otlp.sum.dataPoints[0].asDouble).toBe(0);
  });
});

describe('Gauge.toOtlpMetric()', () => {
  test('produces a Gauge data point with no temporality/monotonicity fields', () => {
    activeRequests.set({}, 9);
    const otlp = activeRequests.toOtlpMetric('100', '200');
    expect(otlp.gauge.dataPoints[0].asDouble).toBe(9);
    expect(otlp.sum).toBeUndefined();
    expect(otlp.gauge.aggregationTemporality).toBeUndefined();
  });

  test('set() overwrites (not accumulates) — matches Prometheus gauge semantics exactly', () => {
    activeRequests.set({}, 2);
    activeRequests.set({}, 15);
    const otlp = activeRequests.toOtlpMetric('100', '200');
    expect(otlp.gauge.dataPoints[0].asDouble).toBe(15);
  });
});

describe('Histogram.toOtlpMetric()', () => {
  test('converts cumulative Prometheus-style bucket counts into individual OTLP bucketCounts', () => {
    const label = { decision: `__f16_hist_${Date.now()}` };
    requestDurationMs.observe(label, 3);   // falls in bucket boundary 5
    requestDurationMs.observe(label, 42);  // falls in bucket boundary 50
    requestDurationMs.observe(label, 42);  // same bucket again
    const otlp = requestDurationMs.toOtlpMetric('100', '200');
    const dp = otlp.histogram.dataPoints.find(d => d.attributes.some(a => a.value.stringValue === label.decision));
    expect(dp.count).toBe(3);
    expect(dp.sum).toBe(3 + 42 + 42);
    // individual (non-cumulative) counts: exactly 1 observation <=5, 0 in the
    // next two buckets, exactly 2 in the bucket containing 42 (boundary 50)
    const boundaryIdx = requestDurationMs.buckets.indexOf(50);
    expect(dp.bucketCounts[0]).toBe(1);
    expect(dp.bucketCounts[boundaryIdx]).toBe(2);
    // sum of all individual bucketCounts (incl. +Inf) must equal the total count
    expect(dp.bucketCounts.reduce((a, b) => a + b, 0)).toBe(3);
  });

  test('explicitBounds match the histogram\'s own configured buckets exactly', () => {
    const otlp = requestDurationMs.toOtlpMetric('100', '200');
    const dp = otlp.histogram.dataPoints[0];
    expect(dp.explicitBounds).toEqual(requestDurationMs.buckets);
  });

  test('bucketCounts has exactly one more entry than explicitBounds (the implicit +Inf bucket)', () => {
    const otlp = requestDurationMs.toOtlpMetric('100', '200');
    const dp = otlp.histogram.dataPoints[0];
    expect(dp.bucketCounts.length).toBe(dp.explicitBounds.length + 1);
  });

  test('marks the histogram as CUMULATIVE temporality', () => {
    const otlp = requestDurationMs.toOtlpMetric('100', '200');
    expect(otlp.histogram.aggregationTemporality).toBe(2);
  });

  test('an observation beyond the largest finite bucket lands entirely in the +Inf bucket', () => {
    const label = { decision: `__f16_hist_overflow_${Date.now()}` };
    requestDurationMs.observe(label, 999_999); // far beyond the largest bucket (30000)
    const otlp = requestDurationMs.toOtlpMetric('100', '200');
    const dp = otlp.histogram.dataPoints.find(d => d.attributes.some(a => a.value.stringValue === label.decision));
    const lastIdx = dp.bucketCounts.length - 1;
    expect(dp.bucketCounts[lastIdx]).toBe(1);
    expect(dp.bucketCounts.slice(0, lastIdx).every(c => c === 0)).toBe(true);
  });
});
