'use strict';

const { AggregationStore }  = require('../store/AggregationStore');
const { InMemoryRepository } = require('../repository/InMemoryRepository');
const { LocalEventBus }      = require('../bus/LocalEventBus');
const { MetricsEngine }      = require('../metrics/MetricsEngine');

const RETENTION = {
  maxExecutions: 100, maxBlocked: 100, maxReplays: 100, maxAnomalies: 100, maxTimeBuckets: 60,
};

function makeRepo(chain = []) {
  const bus     = new LocalEventBus();
  const metrics = new MetricsEngine(RETENTION);
  const store   = new AggregationStore(bus, metrics, RETENTION);
  store.initialize(() => chain);
  return new InMemoryRepository(store);
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

describe('InMemoryRepository.getOverview()', () => {
  it('returns overview shape with all required fields', () => {
    const repo = makeRepo();
    const ov = repo.getOverview();
    expect(ov).toHaveProperty('totalRequests');
    expect(ov).toHaveProperty('allowedRequests');
    expect(ov).toHaveProperty('blockedRequests');
    expect(ov).toHaveProperty('replayAttempts');
    expect(ov).toHaveProperty('anomaliesDetected');
    expect(ov).toHaveProperty('byReason');
  });

  it('reflects chain contents in overview', () => {
    const repo = makeRepo([
      makeEntry({ decision: 'ALLOW' }),
      makeEntry({ decision: 'BLOCK', executionContext: { reason: 'POLICY_DENIED' } }),
    ]);
    const ov = repo.getOverview();
    expect(ov.totalRequests).toBe(2);
    expect(ov.allowedRequests).toBe(1);
    expect(ov.blockedRequests).toBe(1);
    expect(ov.byReason.POLICY_DENIED).toBe(1);
  });
});

describe('InMemoryRepository.getExecutions()', () => {
  it('returns pagination shape', () => {
    const repo = makeRepo([makeEntry({ decision: 'ALLOW' })]);
    const r = repo.getExecutions();
    expect(r).toHaveProperty('entries');
    expect(r).toHaveProperty('total', 1);
    expect(r).toHaveProperty('page', 1);
    expect(r).toHaveProperty('pageSize', 50);
  });

  it('returns newest entry first (descending order)', () => {
    const older = makeEntry({ decision: 'ALLOW', timestamp: new Date(Date.now() - 10_000).toISOString(), artifactId: 'older' });
    const newer = makeEntry({ decision: 'ALLOW', timestamp: new Date().toISOString(),                    artifactId: 'newer' });
    const repo  = makeRepo([older, newer]);
    const r = repo.getExecutions();
    expect(r.entries[0].artifactId).toBe('newer');
  });

  it('paginates correctly', () => {
    const chain = Array.from({ length: 7 }, () => makeEntry({ decision: 'ALLOW' }));
    const repo  = makeRepo(chain);
    const r = repo.getExecutions({ page: 2, pageSize: 3 });
    expect(r.entries).toHaveLength(3);
    expect(r.total).toBe(7);
    expect(r.page).toBe(2);
  });

  it('returns empty when no ALLOW entries', () => {
    const repo = makeRepo();
    expect(repo.getExecutions().entries).toHaveLength(0);
  });

  it('filters by tenantId', () => {
    const repo = makeRepo([
      makeEntry({ decision: 'ALLOW', tenantId: 'ta' }),
      makeEntry({ decision: 'ALLOW', tenantId: 'tb' }),
    ]);
    expect(repo.getExecutions({ tenantId: 'ta' }).total).toBe(1);
    expect(repo.getExecutions({ tenantId: 'tb' }).total).toBe(1);
    expect(repo.getExecutions().total).toBe(2);
  });
});

describe('InMemoryRepository.getBlocked()', () => {
  it('includes byReason in response', () => {
    const repo = makeRepo([
      makeEntry({ decision: 'BLOCK', executionContext: { reason: 'RATE_LIMITED' } }),
      makeEntry({ decision: 'BLOCK', executionContext: { reason: 'RATE_LIMITED' } }),
    ]);
    const r = repo.getBlocked();
    expect(r.byReason.RATE_LIMITED).toBe(2);
  });

  it('excludes ALLOW entries', () => {
    const repo = makeRepo([makeEntry({ decision: 'ALLOW' })]);
    expect(repo.getBlocked().total).toBe(0);
  });
});

describe('InMemoryRepository.getReplays()', () => {
  it('returns only REPLAY_DETECTED entries', () => {
    const repo = makeRepo([
      makeEntry({ decision: 'BLOCK', executionContext: { reason: 'REPLAY_DETECTED' } }),
      makeEntry({ decision: 'BLOCK', executionContext: { reason: 'POLICY_DENIED' } }),
    ]);
    expect(repo.getReplays().total).toBe(1);
    expect(repo.getReplays().entries[0].reason).toBe('REPLAY_DETECTED');
  });
});

describe('InMemoryRepository.getAnomalies()', () => {
  it('returns ANOMALY_DETECTED entries with byType', () => {
    const repo = makeRepo([
      makeEntry({ decision: 'BLOCK', executionContext: { reason: 'ANOMALY_DETECTED', anomalyType: 'SIGNATURE_BURST' } }),
      makeEntry({ decision: 'BLOCK', executionContext: { reason: 'ANOMALY_DETECTED', anomalyType: 'RATE_BURST' } }),
    ]);
    const r = repo.getAnomalies();
    expect(r.total).toBe(2);
    expect(r.byType).toHaveProperty('SIGNATURE_BURST', 1);
    expect(r.byType).toHaveProperty('RATE_BURST', 1);
  });
});

describe('InMemoryRepository.getActivity()', () => {
  it('returns series array and windowMinutes', () => {
    const repo = makeRepo([makeEntry({ decision: 'ALLOW', timestamp: new Date().toISOString() })]);
    const r = repo.getActivity({ windowMinutes: 60 });
    expect(r).toHaveProperty('series');
    expect(Array.isArray(r.series)).toBe(true);
    expect(r.windowMinutes).toBe(60);
  });

  it('excludes entries outside the window', () => {
    const old  = new Date(Date.now() - 2 * 60 * 60_000).toISOString();
    const repo = makeRepo([makeEntry({ decision: 'ALLOW', timestamp: old })]);
    const r = repo.getActivity({ windowMinutes: 60 });
    expect(r.series).toHaveLength(0);
  });
});

describe('InMemoryRepository.getAll()', () => {
  it('returns all executions without pagination', () => {
    const chain = Array.from({ length: 5 }, () => makeEntry({ decision: 'ALLOW' }));
    const repo  = makeRepo(chain);
    expect(repo.getAll('executions')).toHaveLength(5);
  });

  it('returns empty array for unknown category', () => {
    expect(makeRepo().getAll('nope')).toEqual([]);
  });
});

describe('InMemoryRepository.reinitialize()', () => {
  it('rebuilds state from updated chain', () => {
    const chain = [];
    const bus     = new LocalEventBus();
    const metrics = new MetricsEngine(RETENTION);
    const store   = new AggregationStore(bus, metrics, RETENTION);
    store.initialize(() => chain);
    const repo = new InMemoryRepository(store);

    expect(repo.getOverview().totalRequests).toBe(0);
    chain.push(makeEntry({ decision: 'ALLOW' }));
    repo.reinitialize();
    expect(repo.getOverview().totalRequests).toBe(1);
  });
});
