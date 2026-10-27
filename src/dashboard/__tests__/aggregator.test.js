'use strict';

// the code under test reads the monotonic clock (src/infra/time/monotonicClock.js), which jest fake timers
// and Date.now spies do not move. Point it at Date.now so this suite keeps driving time the way it always has; the
// monotonic behaviour itself is pinned by src/infra/time/__tests__/monotonicSites.test.js.
jest.mock('../../infra/time/monotonicClock', () => ({ monoNowMs: () => Date.now(), wallFromMono: (m) => m || null }));

// 

// ── Aggregator unit tests ─────────────────────────────────────────────────────

// Temporarily stub audit-log before requiring aggregator
const STUB_CHAIN = [];

jest.mock('../../core/audit/audit-log', () => ({
  getAuditChain: () => STUB_CHAIN.slice(),
}));

const agg = require('../aggregator');

function makeEntry(overrides = {}) {
  return {
    artifactId: 'artifact-' + Math.random().toString(36).slice(2),
    timestamp:  new Date().toISOString(),
    decision:   'ALLOW',
    inputHash:  'a'.repeat(64),
    prevHash:   'GENESIS',
    hash:       'b'.repeat(64),
    signature:  'sig',
    policyHash: 'p'.repeat(64),
    requestHash:'r'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

beforeEach(() => {
  STUB_CHAIN.length = 0;
  agg.invalidate();
});

describe('aggregator.getOverview', () => {
  it('returns zeroes for empty chain', () => {
    const ov = agg.getOverview();
    expect(ov.totalRequests).toBe(0);
    expect(ov.allowedRequests).toBe(0);
    expect(ov.blockedRequests).toBe(0);
    expect(ov.replayAttempts).toBe(0);
    expect(ov.anomaliesDetected).toBe(0);
  });

  it('counts ALLOW and BLOCK entries', () => {
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'POLICY_DENIED' } }));
    agg.invalidate();
    const ov = agg.getOverview();
    expect(ov.totalRequests).toBe(3);
    expect(ov.allowedRequests).toBe(2);
    expect(ov.blockedRequests).toBe(1);
    expect(ov.byReason.POLICY_DENIED).toBe(1);
  });

  it('counts replay attempts', () => {
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'REPLAY_DETECTED', replayOf: 'abc' } }));
    agg.invalidate();
    const ov = agg.getOverview();
    expect(ov.replayAttempts).toBe(1);
    expect(ov.byReason.REPLAY_DETECTED).toBe(1);
  });

  it('counts anomaly detections', () => {
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'ANOMALY_DETECTED', anomalyType: 'SIGNATURE_BURST' } }));
    agg.invalidate();
    const ov = agg.getOverview();
    expect(ov.anomaliesDetected).toBe(1);
  });

  it('skips legacy entries', () => {
    STUB_CHAIN.push(makeEntry({ legacy: true }));
    agg.invalidate();
    const ov = agg.getOverview();
    expect(ov.totalRequests).toBe(0);
  });

  it('caches the result — second call does not re-scan', () => {
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    const r1 = agg.getOverview();
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));  // added without invalidate
    const r2 = agg.getOverview();
    expect(r1.totalRequests).toBe(r2.totalRequests);   // cache hit — same value
  });

  it('invalidate() clears cache', () => {
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    const r1 = agg.getOverview();
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    agg.invalidate();
    const r2 = agg.getOverview();
    expect(r2.totalRequests).toBe(r1.totalRequests + 1);
  });
});

describe('aggregator.getExecutions', () => {
  it('returns empty when chain is empty', () => {
    const r = agg.getExecutions();
    expect(r.entries).toHaveLength(0);
    expect(r.total).toBe(0);
  });

  it('paginates correctly', () => {
    for (let i = 0; i < 5; i++) STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    agg.invalidate();
    const r = agg.getExecutions({ page: 1, pageSize: 2 });
    expect(r.entries).toHaveLength(2);
    expect(r.total).toBe(5);
  });

  it('returns safe entry shape', () => {
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW', executionContext: { provider: 'anthropic', model: 'claude-3', stage: 'PROVIDER_EXECUTION' } }));
    agg.invalidate();
    const r = agg.getExecutions();
    const e = r.entries[0];
    expect(e).toHaveProperty('artifactId');
    expect(e).toHaveProperty('timestamp');
    expect(e).toHaveProperty('decision', 'ALLOW');
    expect(e).toHaveProperty('provider', 'anthropic');
    expect(e).toHaveProperty('model', 'claude-3');
  });
});

describe('aggregator.getBlocked', () => {
  it('includes byReason in response', () => {
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'RATE_LIMITED' } }));
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'RATE_LIMITED' } }));
    agg.invalidate();
    const r = agg.getBlocked();
    expect(r.byReason.RATE_LIMITED).toBe(2);
  });
});

describe('aggregator.getReplays', () => {
  it('returns only REPLAY_DETECTED entries', () => {
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'REPLAY_DETECTED' } }));
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'POLICY_DENIED'  } }));
    agg.invalidate();
    const r = agg.getReplays();
    expect(r.total).toBe(1);
    expect(r.entries[0].reason).toBe('REPLAY_DETECTED');
  });
});

describe('aggregator.getAnomalies', () => {
  it('returns only ANOMALY_DETECTED entries with byType breakdown', () => {
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'ANOMALY_DETECTED', anomalyType: 'RATE_BURST' } }));
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'ANOMALY_DETECTED', anomalyType: 'SIGNATURE_BURST' } }));
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'POLICY_DENIED' } }));
    agg.invalidate();
    const r = agg.getAnomalies();
    expect(r.total).toBe(2);
    expect(r.byType.RATE_BURST).toBe(1);
    expect(r.byType.SIGNATURE_BURST).toBe(1);
  });
});

describe('aggregator.getActivity', () => {
  it('returns series array', () => {
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW', timestamp: new Date().toISOString() }));
    agg.invalidate();
    const r = agg.getActivity({ windowMinutes: 60 });
    expect(r).toHaveProperty('series');
    expect(Array.isArray(r.series)).toBe(true);
    expect(r.windowMinutes).toBe(60);
  });

  it('excludes entries older than windowMinutes', () => {
    const old = new Date(Date.now() - 2 * 60 * 60_000).toISOString(); // 2 hours ago
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW', timestamp: old }));
    agg.invalidate();
    const r = agg.getActivity({ windowMinutes: 60 });
    expect(r.series).toHaveLength(0);
  });
});
