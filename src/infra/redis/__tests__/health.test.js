'use strict';

/**
 * health.js registry coverage.
 *
 *   H-01  register()/getAllHealth() round-trip
 *   H-02  unregister() removes a store from the report
 *   H-03  getOverallStatus() is 'healthy' when every store is HEALTHY
 *   H-04  getOverallStatus() is 'disconnected' if any store is DISCONNECTED (highest priority)
 *   H-05  getOverallStatus() is 'degraded' if any store is DEGRADED and none DISCONNECTED
 *   H-06  getOverallStatus() is 'recovering' if any store is RECOVERING and none DEGRADED/DISCONNECTED
 *   H-07  getOverallStatus() is 'healthy' with zero registered stores
 *   H-08  A getHealth() callback that throws is reported as UNKNOWN rather than crashing
 */

const healthRegistry = require('../health');

afterEach(() => {
  // Clean up between tests — this module is a shared, process-wide registry.
  for (const purpose of Object.keys(healthRegistry.getAllHealth())) {
    healthRegistry.unregister(purpose);
  }
});

describe('health registry', () => {
  test('H-01 register()/getAllHealth() round-trip', () => {
    healthRegistry.register('storeA', () => ({ state: 'HEALTHY', purpose: 'storeA' }));
    expect(healthRegistry.getAllHealth()).toEqual({ storeA: { state: 'HEALTHY', purpose: 'storeA' } });
  });

  test('H-02 unregister() removes a store from the report', () => {
    healthRegistry.register('storeB', () => ({ state: 'HEALTHY' }));
    healthRegistry.unregister('storeB');
    expect(healthRegistry.getAllHealth()).toEqual({});
  });

  test('H-03 getOverallStatus() is healthy when every store is HEALTHY', () => {
    healthRegistry.register('a', () => ({ state: 'HEALTHY' }));
    healthRegistry.register('b', () => ({ state: 'HEALTHY' }));
    expect(healthRegistry.getOverallStatus()).toBe('healthy');
  });

  test('H-04 getOverallStatus() is disconnected if any store is DISCONNECTED', () => {
    healthRegistry.register('a', () => ({ state: 'HEALTHY' }));
    healthRegistry.register('b', () => ({ state: 'DEGRADED' }));
    healthRegistry.register('c', () => ({ state: 'DISCONNECTED' }));
    expect(healthRegistry.getOverallStatus()).toBe('disconnected');
  });

  test('H-05 getOverallStatus() is degraded if any store is DEGRADED and none DISCONNECTED', () => {
    healthRegistry.register('a', () => ({ state: 'HEALTHY' }));
    healthRegistry.register('b', () => ({ state: 'DEGRADED' }));
    expect(healthRegistry.getOverallStatus()).toBe('degraded');
  });

  test('H-06 getOverallStatus() is recovering if any store is RECOVERING and none worse', () => {
    healthRegistry.register('a', () => ({ state: 'HEALTHY' }));
    healthRegistry.register('b', () => ({ state: 'RECOVERING' }));
    expect(healthRegistry.getOverallStatus()).toBe('recovering');
  });

  test('H-07 getOverallStatus() is healthy with zero registered stores', () => {
    expect(healthRegistry.getOverallStatus()).toBe('healthy');
  });

  test('H-08 a getHealth() callback that throws is reported as UNKNOWN rather than crashing', () => {
    healthRegistry.register('broken', () => { throw new Error('boom'); });
    const all = healthRegistry.getAllHealth();
    expect(all.broken.state).toBe('UNKNOWN');
    expect(all.broken.error).toBe('boom');
  });
});
