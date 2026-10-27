'use strict';

/**
 * Action 1 — metering reducer correctness.
 *
 * Exercises the canonical pure reducer (usageAggregation.js) against
 * evidence-shaped entries covering every entry class the audit chain
 * actually writes (see the reducer's header): non-streaming ALLOW,
 * output-semantic BLOCK with usage, streaming (tokenUsage null),
 * provider-error BLOCK (no tokenUsage key), pre-execution BLOCK — plus the
 * mandatory idempotency, determinism, range and numeric-safety proofs.
 */

const { isMeteredEntry, usageContribution, reduceUsage, toJsonSafeCount } =
  require('../usageAggregation');
const { resolveRange, MAX_RANGE_DAYS } = require('../usageMeteringService');

const T0 = Date.parse('2026-08-01T00:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const WIDE = { fromMs: T0 - 365 * DAY, toMs: T0 + 365 * DAY };

let _seq = 0;
/** Evidence-shaped entry factory (the fields the reducer reads + decoys). */
function entry({ id, at, tokenUsage, noTokenUsageKey = false, decision = 'ALLOW' } = {}) {
  const executionContext = noTokenUsageKey
    ? { stage: 'PROVIDER_EXECUTION', reason: 'PROVIDER_ERROR' }
    : { stage: 'PROVIDER_EXECUTION', tokenUsage: tokenUsage === undefined ? null : tokenUsage };
  return {
    artifactId: id ?? `art-${++_seq}`,
    decision,
    timestamp: new Date(at ?? T0).toISOString(),
    tenantId: 'acme',
    executionContext,
  };
}

describe('usageAggregation — metered-entry definition', () => {
  test('ALLOW with tokenUsage object is metered', () => {
    expect(isMeteredEntry(entry({ tokenUsage: { inputTokens: 1, outputTokens: 2, totalTokens: 3 } }))).toBe(true);
  });

  test('streaming-style entry (tokenUsage: null) is metered, contributes zero tokens', () => {
    const c = usageContribution(entry({ tokenUsage: null }));
    expect(c).not.toBeNull();
    expect(c.inputTokens).toBeNull();
    expect(c.outputTokens).toBeNull();
    expect(c.totalTokens).toBeNull();
  });

  test('output-semantic BLOCK with usage is metered (usage in evidence remains usage)', () => {
    const c = usageContribution(entry({ decision: 'BLOCK', tokenUsage: { inputTokens: 10, outputTokens: 5, totalTokens: 15 } }));
    expect(c.totalTokens).toBe(15);
  });

  test('provider-error / pre-execution entries (no tokenUsage key) are NOT metered', () => {
    expect(isMeteredEntry(entry({ noTokenUsageKey: true }))).toBe(false);
    expect(usageContribution(entry({ noTokenUsageKey: true }))).toBeNull();
    expect(isMeteredEntry({ artifactId: 'x', timestamp: new Date(T0).toISOString() })).toBe(false);
  });
});

describe('usageAggregation — token-field semantics', () => {
  test('recorded totalTokens wins; it is never reconstructed from components', () => {
    // deliberately inconsistent evidence: recorded total 100 != 1+2
    const c = usageContribution(entry({ tokenUsage: { inputTokens: 1, outputTokens: 2, totalTokens: 100 } }));
    expect(c.totalTokens).toBe(100);
  });

  test('missing total is derived deterministically from components (null counts 0)', () => {
    expect(usageContribution(entry({ tokenUsage: { inputTokens: 7, outputTokens: 3, totalTokens: null } })).totalTokens).toBe(10);
    expect(usageContribution(entry({ tokenUsage: { inputTokens: 7, outputTokens: null, totalTokens: null } })).totalTokens).toBe(7);
    expect(usageContribution(entry({ tokenUsage: { inputTokens: null, outputTokens: 4, totalTokens: null } })).totalTokens).toBe(4);
  });

  test('all-null tokenUsage yields null contributions (counted execution, zero tokens)', () => {
    const { totals } = reduceUsage([entry({ tokenUsage: { inputTokens: null, outputTokens: null, totalTokens: null } })], WIDE);
    expect(totals).toEqual({ executions: 1, inputTokens: 0, outputTokens: 0, totalTokens: 0 });
  });

  test('zero-token execution counts as an execution with 0 tokens', () => {
    const { totals } = reduceUsage([entry({ tokenUsage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 } })], WIDE);
    expect(totals).toEqual({ executions: 1, inputTokens: 0, outputTokens: 0, totalTokens: 0 });
  });

  test('non-numeric / negative token fields are treated as absent, never invented', () => {
    const c = usageContribution(entry({ tokenUsage: { inputTokens: 'NaN-ish', outputTokens: -5, totalTokens: undefined } }));
    expect(c.inputTokens).toBeNull();
    expect(c.outputTokens).toBeNull();
    expect(c.totalTokens).toBeNull();
  });
});

describe('usageAggregation — aggregation, time semantics, ranges', () => {
  test('multiple executions across days: totals + per-UTC-day series, ascending', () => {
    const entries = [
      entry({ at: T0 + 1 * DAY, tokenUsage: { inputTokens: 10, outputTokens: 1, totalTokens: 11 } }),
      entry({ at: T0 + 1 * DAY + 3600_000, tokenUsage: { inputTokens: 20, outputTokens: 2, totalTokens: 22 } }),
      entry({ at: T0 + 3 * DAY, tokenUsage: { inputTokens: 30, outputTokens: 3, totalTokens: 33 } }),
    ];
    const { totals, series } = reduceUsage(entries, WIDE);
    expect(totals).toEqual({ executions: 3, inputTokens: 60, outputTokens: 6, totalTokens: 66 });
    expect(series).toEqual([
      { day: '2026-08-02', executions: 2, inputTokens: 30, outputTokens: 3, totalTokens: 33 },
      { day: '2026-08-04', executions: 1, inputTokens: 30, outputTokens: 3, totalTokens: 33 },
    ]);
  });

  test('day bucketing is the UTC date of the entry timestamp (23:59Z vs 00:01Z)', () => {
    const { series } = reduceUsage([
      entry({ at: Date.parse('2026-08-01T23:59:00.000Z'), tokenUsage: { totalTokens: 1 } }),
      entry({ at: Date.parse('2026-08-02T00:01:00.000Z'), tokenUsage: { totalTokens: 2 } }),
    ], WIDE);
    expect(series.map((r) => r.day)).toEqual(['2026-08-01', '2026-08-02']);
  });

  test('half-open range [from, to): boundary entry at `to` excluded, at `from` included', () => {
    const a = entry({ at: T0, tokenUsage: { totalTokens: 1 } });
    const b = entry({ at: T0 + DAY, tokenUsage: { totalTokens: 2 } });
    const { totals } = reduceUsage([a, b], { fromMs: T0, toMs: T0 + DAY });
    expect(totals.executions).toBe(1);
    expect(totals.totalTokens).toBe(1);
  });

  test('adjacent ranges [a,b) and [b,c) partition entries with no overlap and no gap', () => {
    const entries = [0, 1, 2, 3].map((d) => entry({ at: T0 + d * DAY, tokenUsage: { totalTokens: 1 } }));
    const r1 = reduceUsage(entries, { fromMs: T0, toMs: T0 + 2 * DAY });
    const r2 = reduceUsage(entries, { fromMs: T0 + 2 * DAY, toMs: T0 + 4 * DAY });
    expect(r1.totals.executions + r2.totals.executions).toBe(4);
  });

  test('multi-tenant streams are never mixed: reducer input is already tenant-scoped, and per-tenant reductions are independent', () => {
    const acme  = [entry({ tokenUsage: { totalTokens: 5 } })];
    const globex = [entry({ tokenUsage: { totalTokens: 50 } })];
    expect(reduceUsage(acme, WIDE).totals.totalTokens).toBe(5);
    expect(reduceUsage(globex, WIDE).totals.totalTokens).toBe(50);
  });
});

describe('usageAggregation — idempotency (MANDATORY)', () => {
  test('the same logical execution (same artifactId) is counted exactly once', () => {
    const dup = entry({ id: 'art-dup', tokenUsage: { inputTokens: 5, outputTokens: 5, totalTokens: 10 } });
    const replayedRead = { ...dup }; // same evidence surfaced twice in one scan
    const { totals } = reduceUsage([dup, replayedRead, dup], WIDE);
    expect(totals).toEqual({ executions: 1, inputTokens: 5, outputTokens: 5, totalTokens: 10 });
  });

  test('re-running the aggregation over the same evidence yields byte-identical results', () => {
    const entries = [
      entry({ at: T0, tokenUsage: { inputTokens: 1, outputTokens: 2, totalTokens: 3 } }),
      entry({ at: T0 + DAY, tokenUsage: null }),
      entry({ noTokenUsageKey: true }),
    ];
    const first  = reduceUsage(entries, WIDE);
    const second = reduceUsage(entries, WIDE);
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
  });
});

describe('usageAggregation — numeric safety (large token counts)', () => {
  test('sums beyond Number.MAX_SAFE_INTEGER are emitted as exact decimal strings', () => {
    const big = Number.MAX_SAFE_INTEGER; // 9007199254740991 — a legal int in evidence
    const { totals } = reduceUsage([
      entry({ at: T0, tokenUsage: { inputTokens: big, outputTokens: 0, totalTokens: big } }),
      entry({ at: T0, tokenUsage: { inputTokens: big, outputTokens: 0, totalTokens: big } }),
      entry({ at: T0, tokenUsage: { inputTokens: 3, outputTokens: 0, totalTokens: 3 } }),
    ], WIDE);
    // 2 * MAX_SAFE + 3 = 18014398509481985 — NOT representable as a double
    expect(totals.totalTokens).toBe('18014398509481985');
    expect(totals.inputTokens).toBe('18014398509481985');
    expect(totals.executions).toBe(3);
  });

  test('toJsonSafeCount: exact number up to 2^53-1, exact string beyond', () => {
    expect(toJsonSafeCount(0n)).toBe(0);
    expect(toJsonSafeCount(BigInt(Number.MAX_SAFE_INTEGER))).toBe(Number.MAX_SAFE_INTEGER);
    expect(toJsonSafeCount(BigInt(Number.MAX_SAFE_INTEGER) + 1n)).toBe('9007199254740992');
  });
});

describe('usageMeteringService.resolveRange — validation', () => {
  const NOW = Date.parse('2026-09-01T12:00:00.000Z');

  test('defaults: to = now, from = to - 30 days', () => {
    const { fromMs, toMs } = resolveRange({}, NOW);
    expect(toMs).toBe(NOW);
    expect(fromMs).toBe(NOW - 30 * DAY);
  });

  test('explicit ISO range is honored verbatim', () => {
    const { fromMs, toMs } = resolveRange({ from: '2026-08-01T00:00:00Z', to: '2026-08-15T00:00:00Z' }, NOW);
    expect(new Date(fromMs).toISOString()).toBe('2026-08-01T00:00:00.000Z');
    expect(new Date(toMs).toISOString()).toBe('2026-08-15T00:00:00.000Z');
  });

  test.each([
    ['malformed from', { from: 'not-a-date' }],
    ['malformed to',   { to: '2026-13-99' }],
    ['from === to',    { from: '2026-08-01T00:00:00Z', to: '2026-08-01T00:00:00Z' }],
    ['from > to',      { from: '2026-08-02T00:00:00Z', to: '2026-08-01T00:00:00Z' }],
    ['excessive range', { from: `2020-01-01T00:00:00Z`, to: '2026-08-01T00:00:00Z' }],
  ])('rejects %s with USAGE_INVALID_RANGE', (_label, params) => {
    expect(() => resolveRange(params, NOW)).toThrow(expect.objectContaining({ code: 'USAGE_INVALID_RANGE' }));
  });

  test(`maximum accepted range is exactly ${MAX_RANGE_DAYS} days`, () => {
    const to = '2026-08-01T00:00:00Z';
    const okFrom  = new Date(Date.parse(to) - MAX_RANGE_DAYS * DAY).toISOString();
    const badFrom = new Date(Date.parse(to) - (MAX_RANGE_DAYS * DAY + 1)).toISOString();
    expect(() => resolveRange({ from: okFrom, to }, NOW)).not.toThrow();
    expect(() => resolveRange({ from: badFrom, to }, NOW)).toThrow(expect.objectContaining({ code: 'USAGE_INVALID_RANGE' }));
  });
});

describe('usageAggregation.mergePgDailyRows — distributed-path conversion', () => {
  const { mergePgDailyRows } = require('../usageAggregation');

  test('converts exact decimal-string rows and derives totals from per-day figures', () => {
    const merged = mergePgDailyRows([
      { day: '2026-08-10', executions: '2', inputTokens: '150', outputTokens: '15', totalTokens: '165' },
      { day: '2026-08-11', executions: '1', inputTokens: null, outputTokens: null, totalTokens: null },
    ]);
    expect(merged.totals).toEqual({ executions: 3, inputTokens: 150, outputTokens: 15, totalTokens: 165 });
    expect(merged.series[1]).toEqual({ day: '2026-08-11', executions: 1, inputTokens: 0, outputTokens: 0, totalTokens: 0 });
  });

  test('counts beyond 2^53-1 survive as exact decimal strings (bigint SUM safety)', () => {
    const merged = mergePgDailyRows([
      { day: '2026-08-10', executions: '1', inputTokens: '9007199254740991', outputTokens: '0', totalTokens: '9007199254740991' },
      { day: '2026-08-11', executions: '1', inputTokens: '9007199254740994', outputTokens: '0', totalTokens: '9007199254740994' },
    ]);
    expect(merged.totals.inputTokens).toBe('18014398509481985');
    expect(merged.series[1].inputTokens).toBe('9007199254740994');
    expect(merged.totals.executions).toBe(2);
  });

  test('agrees with reduceUsage on the same logical evidence', () => {
    const T = Date.parse('2026-08-10T12:00:00.000Z');
    const entries = [
      { artifactId: 'p1', timestamp: new Date(T).toISOString(), executionContext: { tokenUsage: { inputTokens: 10, outputTokens: 5, totalTokens: 15 } } },
      { artifactId: 'p2', timestamp: new Date(T + DAY).toISOString(), executionContext: { tokenUsage: null } },
    ];
    const reduced = reduceUsage(entries, { fromMs: T - DAY, toMs: T + 2 * DAY });
    const merged  = mergePgDailyRows([
      { day: '2026-08-10', executions: '1', inputTokens: '10', outputTokens: '5', totalTokens: '15' },
      { day: '2026-08-11', executions: '1', inputTokens: null, outputTokens: null, totalTokens: null },
    ]);
    expect(merged).toEqual(reduced);
  });
});
