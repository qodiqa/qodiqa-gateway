'use strict';

const { loadRetentionConfig, DEFAULT_RETENTION } = require('../retention/RetentionConfig');

describe('DEFAULT_RETENTION', () => {
  it('exposes the expected default keys', () => {
    expect(DEFAULT_RETENTION).toHaveProperty('maxExecutions');
    expect(DEFAULT_RETENTION).toHaveProperty('maxBlocked');
    expect(DEFAULT_RETENTION).toHaveProperty('maxReplays');
    expect(DEFAULT_RETENTION).toHaveProperty('maxAnomalies');
    expect(DEFAULT_RETENTION).toHaveProperty('maxTimeBuckets');
  });

  it('is frozen', () => {
    expect(Object.isFrozen(DEFAULT_RETENTION)).toBe(true);
  });

  it('defaults are positive integers', () => {
    for (const val of Object.values(DEFAULT_RETENTION)) {
      expect(Number.isFinite(val) && val > 0).toBe(true);
    }
  });

  it('maxTimeBuckets default is 1440 (24h × 60min)', () => {
    expect(DEFAULT_RETENTION.maxTimeBuckets).toBe(1440);
  });
});

describe('loadRetentionConfig()', () => {
  const ORIG = { ...process.env };

  afterEach(() => {
    // Restore env vars after each test
    for (const k of ['DASHBOARD_MAX_EXECUTIONS', 'DASHBOARD_MAX_BLOCKED',
                      'DASHBOARD_MAX_REPLAYS',    'DASHBOARD_MAX_ANOMALIES',
                      'DASHBOARD_MAX_TIME_BUCKETS']) {
      if (ORIG[k] !== undefined) process.env[k] = ORIG[k];
      else delete process.env[k];
    }
  });

  it('returns frozen config', () => {
    expect(Object.isFrozen(loadRetentionConfig())).toBe(true);
  });

  it('uses defaults when no env vars are set', () => {
    delete process.env.DASHBOARD_MAX_EXECUTIONS;
    delete process.env.DASHBOARD_MAX_BLOCKED;
    const cfg = loadRetentionConfig();
    expect(cfg.maxExecutions).toBe(DEFAULT_RETENTION.maxExecutions);
    expect(cfg.maxBlocked).toBe(DEFAULT_RETENTION.maxBlocked);
  });

  it('respects DASHBOARD_MAX_EXECUTIONS override', () => {
    process.env.DASHBOARD_MAX_EXECUTIONS = '500';
    const cfg = loadRetentionConfig();
    expect(cfg.maxExecutions).toBe(500);
  });

  it('respects DASHBOARD_MAX_BLOCKED override', () => {
    process.env.DASHBOARD_MAX_BLOCKED = '250';
    expect(loadRetentionConfig().maxBlocked).toBe(250);
  });

  it('respects DASHBOARD_MAX_REPLAYS override', () => {
    process.env.DASHBOARD_MAX_REPLAYS = '100';
    expect(loadRetentionConfig().maxReplays).toBe(100);
  });

  it('respects DASHBOARD_MAX_ANOMALIES override', () => {
    process.env.DASHBOARD_MAX_ANOMALIES = '200';
    expect(loadRetentionConfig().maxAnomalies).toBe(200);
  });

  it('respects DASHBOARD_MAX_TIME_BUCKETS override', () => {
    process.env.DASHBOARD_MAX_TIME_BUCKETS = '720';
    expect(loadRetentionConfig().maxTimeBuckets).toBe(720);
  });

  it('falls back to default for non-numeric env var', () => {
    process.env.DASHBOARD_MAX_EXECUTIONS = 'not-a-number';
    expect(loadRetentionConfig().maxExecutions).toBe(DEFAULT_RETENTION.maxExecutions);
  });

  it('falls back to default for zero', () => {
    process.env.DASHBOARD_MAX_EXECUTIONS = '0';
    expect(loadRetentionConfig().maxExecutions).toBe(DEFAULT_RETENTION.maxExecutions);
  });

  it('falls back to default for negative value', () => {
    process.env.DASHBOARD_MAX_EXECUTIONS = '-1';
    expect(loadRetentionConfig().maxExecutions).toBe(DEFAULT_RETENTION.maxExecutions);
  });
});
