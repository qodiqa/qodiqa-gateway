'use strict';

const {
  SigningHealthMonitor,
  getHealthMonitor,
  resetAll,
  snapshotAll,
  STATE_HEALTHY,
  STATE_DEGRADED,
  STATE_UNAVAILABLE,
} = require('../healthMonitor');

const CONFIG = Object.freeze({
  cbFailureThreshold:      4,
  healthDegradedThreshold: 2,
  healthIntervalMs:        50,
});

afterEach(() => resetAll());

describe('SigningHealthMonitor — health model', () => {
  test('starts healthy', () => {
    const h = new SigningHealthMonitor('vault:transit:test', CONFIG);
    expect(h.state).toBe(STATE_HEALTHY);
  });

  test('becomes degraded after healthDegradedThreshold consecutive failures', () => {
    const h = new SigningHealthMonitor('vault:transit:test', CONFIG);
    h.recordFailure({ error: new Error('timeout') });
    expect(h.state).toBe(STATE_HEALTHY);
    h.recordFailure({ error: new Error('timeout') });
    expect(h.state).toBe(STATE_DEGRADED);
  });

  test('becomes unavailable after cbFailureThreshold consecutive failures', () => {
    const h = new SigningHealthMonitor('vault:transit:test', CONFIG);
    for (let i = 0; i < CONFIG.cbFailureThreshold; i++) h.recordFailure({ error: new Error('down') });
    expect(h.state).toBe(STATE_UNAVAILABLE);
  });

  test('a single success resets consecutiveFailures and recovers to healthy', () => {
    const h = new SigningHealthMonitor('vault:transit:test', CONFIG);
    for (let i = 0; i < CONFIG.cbFailureThreshold; i++) h.recordFailure({ error: new Error('down') });
    expect(h.state).toBe(STATE_UNAVAILABLE);

    h.recordSuccess(12);
    expect(h.state).toBe(STATE_HEALTHY);
    expect(h.consecutiveFailures).toBe(0);
  });

  test('tracks lastError and lastSuccessAt/lastFailureAt', () => {
    const h = new SigningHealthMonitor('vault:transit:test', CONFIG);
    h.recordFailure({ error: new Error('vault sealed') });
    expect(h.snapshot().lastError).toBe('vault sealed');
    expect(h.snapshot().lastFailureAt).toEqual(expect.any(String));

    h.recordSuccess(5);
    expect(h.snapshot().lastSuccessAt).toEqual(expect.any(String));
  });

  test('timeoutRate reflects the fraction of recent timed-out samples', () => {
    const h = new SigningHealthMonitor('vault:transit:test', CONFIG);
    h.recordFailure({ timedOut: true, error: new Error('timeout') });
    h.recordSuccess(10);
    expect(h.timeoutRate()).toBeCloseTo(0.5);
  });

  test('averageLatencyMs is computed only from successful samples', () => {
    const h = new SigningHealthMonitor('vault:transit:test', CONFIG);
    h.recordSuccess(10);
    h.recordSuccess(30);
    h.recordFailure({ error: new Error('x') });
    expect(h.averageLatencyMs()).toBe(20);
  });

  test('active probing invokes the probe function on the configured interval and stops cleanly', async () => {
    const h = new SigningHealthMonitor('vault:transit:test', CONFIG);
    let calls = 0;
    h.startActiveProbing(() => { calls++; return Promise.resolve(); });

    await new Promise((r) => setTimeout(r, CONFIG.healthIntervalMs * 3 + 20));
    expect(calls).toBeGreaterThanOrEqual(2);

    h.stopActiveProbing();
    const callsAtStop = calls;
    await new Promise((r) => setTimeout(r, CONFIG.healthIntervalMs * 2));
    expect(calls).toBe(callsAtStop); // no further ticks after stop
  });

  test('a rejecting probe function never produces an unhandled rejection', async () => {
    const unhandled = [];
    const handler = (err) => unhandled.push(err);
    process.on('unhandledRejection', handler);

    const h = new SigningHealthMonitor('vault:transit:test', CONFIG);
    h.startActiveProbing(() => Promise.reject(new Error('probe failed')));
    await new Promise((r) => setTimeout(r, CONFIG.healthIntervalMs + 20));
    h.stopActiveProbing();

    process.off('unhandledRejection', handler);
    expect(unhandled).toHaveLength(0);
  });
});

describe('SigningHealthMonitor registry', () => {
  test('getHealthMonitor returns the same instance per provider name', () => {
    const a = getHealthMonitor('aws:kms:test', CONFIG);
    const b = getHealthMonitor('aws:kms:test', CONFIG);
    expect(a).toBe(b);
  });

  test('snapshotAll reports every registered monitor', () => {
    getHealthMonitor('gcp:kms:test', CONFIG);
    expect(snapshotAll()).toHaveProperty('gcp:kms:test');
  });

  test('resetAll stops all active probes and clears the registry', () => {
    const h = getHealthMonitor('azure:kv:test', CONFIG);
    h.startActiveProbing(() => Promise.resolve());
    resetAll();
    expect(snapshotAll()).toEqual({});
  });
});
