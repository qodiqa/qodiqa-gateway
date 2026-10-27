'use strict';

const { AggregationStore } = require('../store/AggregationStore');
const { LocalEventBus }    = require('../bus/LocalEventBus');
const { MetricsEngine }    = require('../metrics/MetricsEngine');

const RETENTION = {
  maxExecutions: 100, maxBlocked: 100, maxReplays: 100, maxAnomalies: 100, maxTimeBuckets: 60,
};

function makeStore() {
  const bus     = new LocalEventBus();
  const metrics = new MetricsEngine(RETENTION);
  const store   = new AggregationStore(bus, metrics, RETENTION);
  return { bus, metrics, store };
}

function makeEntry(overrides = {}) {
  return {
    artifactId:        'art-' + Math.random().toString(36).slice(2),
    timestamp:         new Date().toISOString(),
    decision:          'ALLOW',
    inputHash:         'a'.repeat(64),
    prevHash:          'GENESIS',
    hash:              'b'.repeat(64),
    signature:         'sig',
    policyHash:        'p'.repeat(64),
    requestHash:       'r'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

describe('AggregationStore — initialize()', () => {
  it('starts empty before initialize()', () => {
    const { store } = makeStore();
    expect(store.getExecutions()).toHaveLength(0);
  });

  it('processes ALLOW entries from chain', () => {
    const { store } = makeStore();
    store.initialize(() => [makeEntry({ decision: 'ALLOW' })]);
    expect(store.getExecutions()).toHaveLength(1);
    expect(store.getMetrics().getOverview().allowedRequests).toBe(1);
  });

  it('processes BLOCK entries from chain', () => {
    const { store } = makeStore();
    store.initialize(() => [makeEntry({ decision: 'BLOCK', executionContext: { reason: 'POLICY_DENIED' } })]);
    expect(store.getBlocked()).toHaveLength(1);
    expect(store.getMetrics().getOverview().blockedRequests).toBe(1);
  });

  it('skips legacy entries', () => {
    const { store } = makeStore();
    store.initialize(() => [makeEntry({ legacy: true })]);
    expect(store.getMetrics().getOverview().totalRequests).toBe(0);
  });

  it('processes REPLAY_DETECTED into replays buffer', () => {
    const { store } = makeStore();
    store.initialize(() => [makeEntry({ decision: 'BLOCK', executionContext: { reason: 'REPLAY_DETECTED' } })]);
    expect(store.getReplays()).toHaveLength(1);
    expect(store.getMetrics().getOverview().replayAttempts).toBe(1);
  });

  it('processes ANOMALY_DETECTED into anomalies buffer', () => {
    const { store } = makeStore();
    store.initialize(() => [makeEntry({ decision: 'BLOCK', executionContext: { reason: 'ANOMALY_DETECTED', anomalyType: 'RATE_BURST' } })]);
    expect(store.getAnomalies()).toHaveLength(1);
    expect(store.getMetrics().getOverview().anomaliesDetected).toBe(1);
  });
});

describe('AggregationStore — reinitialize()', () => {
  it('resets and re-processes chain', () => {
    const chain = [makeEntry({ decision: 'ALLOW' })];
    const { store } = makeStore();
    store.initialize(() => chain);
    chain.push(makeEntry({ decision: 'ALLOW' }));
    store.reinitialize();
    expect(store.getExecutions()).toHaveLength(2);
    expect(store.getMetrics().getOverview().allowedRequests).toBe(2);
  });

  it('reinitialize() is a no-op before initialize()', () => {
    const { store } = makeStore();
    expect(() => store.reinitialize()).not.toThrow();
    expect(store.getMetrics().getOverview().totalRequests).toBe(0);
  });
});

describe('AggregationStore — incremental updates via bus', () => {
  it('_onAllow updates counters and execution buffer', () => {
    const { bus, store } = makeStore();
    store.initialize(() => []);
    const record = { ts: new Date().toISOString(), event: 'AUDIT_EXECUTION_RECORDED', artifactId: 'x' };
    const entry  = makeEntry({ decision: 'ALLOW', artifactId: 'x' });
    bus.publish('audit.allow', { record, entry });
    expect(store.getExecutions()).toHaveLength(1);
    expect(store.getMetrics().getOverview().allowedRequests).toBe(1);
  });

  it('_onBlock updates counters and blocked buffer', () => {
    const { bus, store } = makeStore();
    store.initialize(() => []);
    const record = { ts: new Date().toISOString(), event: 'AUDIT_BLOCK_RECORDED', artifactId: 'y', reason: 'POLICY_DENIED' };
    const entry  = makeEntry({ decision: 'BLOCK', artifactId: 'y', executionContext: { reason: 'POLICY_DENIED' } });
    bus.publish('audit.block', { record, entry });
    expect(store.getBlocked()).toHaveLength(1);
    expect(store.getMetrics().getByReason().POLICY_DENIED).toBe(1);
  });

  it('_onBlock with REPLAY_DETECTED fills replays buffer', () => {
    const { bus, store } = makeStore();
    store.initialize(() => []);
    const entry = makeEntry({ decision: 'BLOCK', executionContext: { reason: 'REPLAY_DETECTED' } });
    bus.publish('audit.block', { record: { ts: new Date().toISOString(), reason: 'REPLAY_DETECTED' }, entry });
    expect(store.getReplays()).toHaveLength(1);
  });

  it('_onAllow falls back to record data when entry is null', () => {
    const { bus, store } = makeStore();
    store.initialize(() => []);
    bus.publish('audit.allow', { record: { ts: new Date().toISOString(), artifactId: 'z' }, entry: null });
    expect(store.getExecutions()).toHaveLength(1);
    expect(store.getMetrics().getOverview().allowedRequests).toBe(1);
  });

  it('_onBlock falls back to record reason when entry is null', () => {
    const { bus, store } = makeStore();
    store.initialize(() => []);
    bus.publish('audit.block', { record: { ts: new Date().toISOString(), reason: 'POLICY_DENIED' }, entry: null });
    expect(store.getMetrics().getByReason().POLICY_DENIED).toBe(1);
  });
});

describe('AggregationStore — retention bounds', () => {
  it('evicts oldest entry when buffer is full', () => {
    const retention = { ...RETENTION, maxExecutions: 3 };
    const bus     = new LocalEventBus();
    const metrics = new MetricsEngine(retention);
    const store   = new AggregationStore(bus, metrics, retention);

    const chain = [];
    for (let i = 0; i < 5; i++) chain.push(makeEntry({ decision: 'ALLOW', artifactId: `art-${i}` }));
    store.initialize(() => chain);

    const ids = store.getExecutions().map(e => e.artifactId);
    expect(ids).toHaveLength(3);
    expect(ids).not.toContain('art-0');  // oldest evicted
    expect(ids).not.toContain('art-1');  // oldest evicted
  });
});

describe('AggregationStore — tenant filtering', () => {
  it('filters executions by tenantId', () => {
    const { store } = makeStore();
    store.initialize(() => [
      makeEntry({ decision: 'ALLOW', tenantId: 'tenant-a' }),
      makeEntry({ decision: 'ALLOW', tenantId: 'tenant-b' }),
    ]);
    expect(store.getExecutions('tenant-a')).toHaveLength(1);
    expect(store.getExecutions('tenant-b')).toHaveLength(1);
    expect(store.getExecutions()).toHaveLength(2);
  });

  it('filters blocked by tenantId', () => {
    const { store } = makeStore();
    store.initialize(() => [
      makeEntry({ decision: 'BLOCK', tenantId: 'ta', executionContext: { reason: 'POLICY_DENIED' } }),
      makeEntry({ decision: 'BLOCK', tenantId: 'tb', executionContext: { reason: 'POLICY_DENIED' } }),
    ]);
    expect(store.getBlocked('ta')).toHaveLength(1);
    expect(store.getBlocked()).toHaveLength(2);
  });
});

describe('AggregationStore — safe entry shape', () => {
  it('exposes expected fields from ALLOW entry', () => {
    const { store } = makeStore();
    store.initialize(() => [makeEntry({
      decision: 'ALLOW',
      tenantId: 'tenant-x',
      executionContext: { provider: 'openai', model: 'gpt-4', stage: 'PROVIDER_EXECUTION' },
    })]);
    const e = store.getExecutions()[0];
    expect(e).toHaveProperty('artifactId');
    expect(e).toHaveProperty('timestamp');
    expect(e).toHaveProperty('decision', 'ALLOW');
    expect(e).toHaveProperty('tenantId', 'tenant-x');
    expect(e).toHaveProperty('provider', 'openai');
    expect(e).toHaveProperty('model', 'gpt-4');
    expect(e).toHaveProperty('reason', null);
  });

  it('maps UNAVAILABLE hash fields to null', () => {
    const { store } = makeStore();
    store.initialize(() => [makeEntry({ decision: 'ALLOW', requestHash: 'UNAVAILABLE', policyHash: 'UNAVAILABLE' })]);
    const e = store.getExecutions()[0];
    expect(e.requestHash).toBeNull();
    expect(e.policyHash).toBeNull();
  });
});
