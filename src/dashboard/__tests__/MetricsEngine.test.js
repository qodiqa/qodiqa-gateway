'use strict';

const { MetricsEngine } = require('../metrics/MetricsEngine');

const RETENTION = { maxTimeBuckets: 10 };

function engine() { return new MetricsEngine(RETENTION); }

describe('MetricsEngine — counters', () => {
  it('starts at zero', () => {
    const e = engine();
    const ov = e.getOverview();
    expect(ov.totalRequests).toBe(0);
    expect(ov.allowedRequests).toBe(0);
    expect(ov.blockedRequests).toBe(0);
    expect(ov.replayAttempts).toBe(0);
    expect(ov.anomaliesDetected).toBe(0);
    expect(ov.byReason).toEqual({});
  });

  it('counts ALLOW', () => {
    const e = engine();
    e.record({ decision: 'ALLOW' });
    expect(e.getOverview().allowedRequests).toBe(1);
    expect(e.getOverview().totalRequests).toBe(1);
  });

  it('counts BLOCK', () => {
    const e = engine();
    e.record({ decision: 'BLOCK', reason: 'POLICY_DENIED' });
    const ov = e.getOverview();
    expect(ov.blockedRequests).toBe(1);
    expect(ov.byReason.POLICY_DENIED).toBe(1);
  });

  it('counts REPLAY_DETECTED', () => {
    const e = engine();
    e.record({ decision: 'BLOCK', reason: 'REPLAY_DETECTED' });
    expect(e.getOverview().replayAttempts).toBe(1);
  });

  it('counts ANOMALY_DETECTED with type', () => {
    const e = engine();
    e.record({ decision: 'BLOCK', reason: 'ANOMALY_DETECTED', anomalyType: 'RATE_BURST' });
    const ov = e.getOverview();
    expect(ov.anomaliesDetected).toBe(1);
    expect(e.getByAnomalyType().RATE_BURST).toBe(1);
  });

  it('ANOMALY_DETECTED defaults anomalyType to UNKNOWN', () => {
    const e = engine();
    e.record({ decision: 'BLOCK', reason: 'ANOMALY_DETECTED' });
    expect(e.getByAnomalyType().UNKNOWN).toBe(1);
  });

  it('accumulates multiple records', () => {
    const e = engine();
    for (let i = 0; i < 5; i++) e.record({ decision: 'ALLOW' });
    for (let i = 0; i < 3; i++) e.record({ decision: 'BLOCK', reason: 'RATE_LIMITED' });
    const ov = e.getOverview();
    expect(ov.totalRequests).toBe(8);
    expect(ov.allowedRequests).toBe(5);
    expect(ov.blockedRequests).toBe(3);
    expect(ov.byReason.RATE_LIMITED).toBe(3);
  });

  it('reset() zeroes all counters', () => {
    const e = engine();
    e.record({ decision: 'ALLOW' });
    e.record({ decision: 'BLOCK', reason: 'POLICY_DENIED' });
    e.reset();
    const ov = e.getOverview();
    expect(ov.totalRequests).toBe(0);
    expect(ov.byReason).toEqual({});
  });
});

describe('MetricsEngine — named counters', () => {
  it('getCounters returns correct named counters', () => {
    const e = engine();
    e.record({ decision: 'ALLOW' });
    e.record({ decision: 'ALLOW' });
    e.record({ decision: 'BLOCK', reason: 'REPLAY_DETECTED' });
    e.record({ decision: 'BLOCK', reason: 'ANOMALY_DETECTED' });
    const c = e.getCounters();
    expect(c.executions_total).toBe(2);
    expect(c.allowed_total).toBe(2);
    expect(c.blocked_total).toBe(2);
    expect(c.replay_total).toBe(1);
    expect(c.anomaly_total).toBe(1);
  });
});

describe('MetricsEngine — per-tenant', () => {
  it('tracks per-tenant counters', () => {
    const e = engine();
    e.record({ decision: 'ALLOW', tenantId: 'tenant-a' });
    e.record({ decision: 'ALLOW', tenantId: 'tenant-a' });
    e.record({ decision: 'BLOCK', reason: 'POLICY_DENIED', tenantId: 'tenant-b' });
    const byTenant = e.getByTenant();
    expect(byTenant['tenant-a'].allowed).toBe(2);
    expect(byTenant['tenant-b'].blocked).toBe(1);
    expect(byTenant['tenant-b'].allowed).toBe(0);
  });

  it('does not pollute global counters with tenant-specific entries', () => {
    const e = engine();
    e.record({ decision: 'ALLOW', tenantId: 'x' });
    expect(e.getOverview().allowedRequests).toBe(1);
  });

  it('getByTenant returns a safe copy', () => {
    const e = engine();
    e.record({ decision: 'ALLOW', tenantId: 't1' });
    const copy = e.getByTenant();
    copy['t1'].allowed = 999;
    expect(e.getByTenant()['t1'].allowed).toBe(1);
  });
});

describe('MetricsEngine — time buckets', () => {
  it('records activity in time buckets', () => {
    const e = engine();
    const ts = new Date().toISOString();
    e.record({ decision: 'ALLOW', timestamp: ts });
    e.record({ decision: 'BLOCK', reason: 'POLICY_DENIED', timestamp: ts });
    const buckets = e.getTimeBuckets(60);
    const total = buckets.reduce((s, b) => s + b.allowed + b.blocked, 0);
    expect(total).toBe(2);
  });

  it('excludes buckets outside the window', () => {
    const e = engine();
    const old = new Date(Date.now() - 2 * 60 * 60_000).toISOString();
    e.record({ decision: 'ALLOW', timestamp: old });
    const buckets = e.getTimeBuckets(60);
    expect(buckets).toHaveLength(0);
  });

  it('returns buckets sorted oldest-first', () => {
    const e = engine();
    const now = Date.now();
    e.record({ decision: 'ALLOW', timestamp: new Date(now - 2 * 60_000).toISOString() });
    e.record({ decision: 'ALLOW', timestamp: new Date(now - 1 * 60_000).toISOString() });
    e.record({ decision: 'ALLOW', timestamp: new Date(now).toISOString() });
    const buckets = e.getTimeBuckets(60);
    for (let i = 1; i < buckets.length; i++) {
      expect(buckets[i].minute >= buckets[i - 1].minute).toBe(true);
    }
  });

  it('prunes buckets beyond maxTimeBuckets', () => {
    const e = new MetricsEngine({ maxTimeBuckets: 3 });
    const base = Date.now();
    for (let i = 0; i < 6; i++) {
      e.record({ decision: 'ALLOW', timestamp: new Date(base - i * 60_000).toISOString() });
    }
    // After pruning, at most 3 buckets remain
    expect(e.getTimeBuckets(60 * 24)).toHaveLength(3);
  });

  it('getTimeBuckets returns copies — mutations do not affect engine state', () => {
    const e = engine();
    e.record({ decision: 'ALLOW', timestamp: new Date().toISOString() });
    const b = e.getTimeBuckets(60);
    if (b.length > 0) b[0].allowed = 999;
    const b2 = e.getTimeBuckets(60);
    if (b2.length > 0) expect(b2[0].allowed).toBe(1);
  });
});

describe('MetricsEngine — invalid input', () => {
  it('handles undefined decision gracefully', () => {
    const e = engine();
    expect(() => e.record({})).not.toThrow();
    // Neither ALLOW nor BLOCK — only total is incremented
    expect(e.getOverview().totalRequests).toBe(1);
    expect(e.getOverview().allowedRequests).toBe(0);
    expect(e.getOverview().blockedRequests).toBe(0);
  });

  it('handles null timestamp without throwing', () => {
    const e = engine();
    expect(() => e.record({ decision: 'ALLOW', timestamp: null })).not.toThrow();
  });

  it('handles invalid timestamp without throwing', () => {
    const e = engine();
    expect(() => e.record({ decision: 'ALLOW', timestamp: 'not-a-date' })).not.toThrow();
  });
});
