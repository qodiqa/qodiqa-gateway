'use strict';

/**
 * haConfig.js coverage.
 *
 *   HC-01  Defaults to 'single' mode with no env vars set (backward compat)
 *   HC-02  Unknown REDIS_MODE falls back to 'single' with a validation error
 *   HC-03  Sentinel mode parses host:port list and master name correctly
 *   HC-04  Sentinel mode without hosts is invalid
 *   HC-05  Sentinel mode without master name is invalid
 *   HC-06  Cluster mode parses host:port list correctly
 *   HC-07  Cluster mode without hosts is invalid
 *   HC-08  Retry policy defaults match documented values
 *   HC-09  Retry policy env vars override defaults
 *   HC-10  Invalid numeric env vars fall back to defaults rather than NaN
 *   HC-11  REDIS_SENTINEL_USE_REPLICAS defaults to false; 'true' enables it
 */

const { resolveHaConfig } = require('../haConfig');

describe('haConfig', () => {
  test('HC-01 defaults to single mode with no env vars set', () => {
    const cfg = resolveHaConfig({});
    expect(cfg.mode).toBe('single');
    expect(cfg.valid).toBe(true);
    expect(cfg.validationErrors).toEqual([]);
  });

  test('HC-02 unknown REDIS_MODE falls back to single with a validation error', () => {
    const cfg = resolveHaConfig({ REDIS_MODE: 'bogus' });
    expect(cfg.mode).toBe('single');
    expect(cfg.valid).toBe(false);
    expect(cfg.validationErrors[0]).toMatch(/REDIS_MODE/);
  });

  test('HC-03 sentinel mode parses host:port list and master name correctly', () => {
    const cfg = resolveHaConfig({
      REDIS_MODE: 'sentinel',
      REDIS_SENTINEL_HOSTS: 'sentinel1:26379, sentinel2:26380,sentinel3:26381',
      REDIS_SENTINEL_MASTER_NAME: 'mymaster',
    });
    expect(cfg.mode).toBe('sentinel');
    expect(cfg.valid).toBe(true);
    expect(cfg.sentinel.masterName).toBe('mymaster');
    expect(cfg.sentinel.rootNodes).toEqual([
      { host: 'sentinel1', port: 26379 },
      { host: 'sentinel2', port: 26380 },
      { host: 'sentinel3', port: 26381 },
    ]);
  });

  test('HC-04 sentinel mode without hosts is invalid', () => {
    const cfg = resolveHaConfig({ REDIS_MODE: 'sentinel', REDIS_SENTINEL_MASTER_NAME: 'mymaster' });
    expect(cfg.valid).toBe(false);
    expect(cfg.validationErrors.some(e => /REDIS_SENTINEL_HOSTS/.test(e))).toBe(true);
  });

  test('HC-05 sentinel mode without master name is invalid', () => {
    const cfg = resolveHaConfig({ REDIS_MODE: 'sentinel', REDIS_SENTINEL_HOSTS: 'sentinel1:26379' });
    expect(cfg.valid).toBe(false);
    expect(cfg.validationErrors.some(e => /REDIS_SENTINEL_MASTER_NAME/.test(e))).toBe(true);
  });

  test('HC-06 cluster mode parses host:port list correctly', () => {
    const cfg = resolveHaConfig({ REDIS_MODE: 'cluster', REDIS_CLUSTER_HOSTS: 'node1:7000,node2:7001' });
    expect(cfg.mode).toBe('cluster');
    expect(cfg.valid).toBe(true);
    expect(cfg.cluster.rootNodes).toEqual([
      { host: 'node1', port: 7000 },
      { host: 'node2', port: 7001 },
    ]);
  });

  test('HC-07 cluster mode without hosts is invalid', () => {
    const cfg = resolveHaConfig({ REDIS_MODE: 'cluster' });
    expect(cfg.valid).toBe(false);
    expect(cfg.validationErrors.some(e => /REDIS_CLUSTER_HOSTS/.test(e))).toBe(true);
  });

  test('HC-08 retry policy defaults match documented values', () => {
    const cfg = resolveHaConfig({});
    expect(cfg.retry).toEqual({
      maxAttempts: 5,
      baseDelayMs: 100,
      maxDelayMs: 2_000,
      jitterRatio: 0.2,
      circuitBreakerCooldownMs: 30_000,
    });
  });

  test('HC-09 retry policy env vars override defaults', () => {
    const cfg = resolveHaConfig({
      REDIS_MAX_RECONNECT_ATTEMPTS: '10',
      REDIS_RECONNECT_BASE_DELAY_MS: '50',
      REDIS_RECONNECT_MAX_DELAY_MS: '5000',
      REDIS_RECONNECT_JITTER_RATIO: '0.5',
      REDIS_CIRCUIT_BREAKER_COOLDOWN_MS: '60000',
    });
    expect(cfg.retry).toEqual({
      maxAttempts: 10,
      baseDelayMs: 50,
      maxDelayMs: 5000,
      jitterRatio: 0.5,
      circuitBreakerCooldownMs: 60000,
    });
  });

  test('HC-10 invalid numeric env vars fall back to defaults rather than NaN', () => {
    const cfg = resolveHaConfig({
      REDIS_MAX_RECONNECT_ATTEMPTS: 'not-a-number',
      REDIS_RECONNECT_JITTER_RATIO: '5', // out of 0..1 range
    });
    expect(cfg.retry.maxAttempts).toBe(5);
    expect(cfg.retry.jitterRatio).toBe(0.2);
  });

  test('HC-11 REDIS_SENTINEL_USE_REPLICAS defaults to false; "true" enables it', () => {
    expect(resolveHaConfig({}).sentinel.useReplicas).toBe(false);
    expect(resolveHaConfig({ REDIS_SENTINEL_USE_REPLICAS: 'true' }).sentinel.useReplicas).toBe(true);
  });
});
