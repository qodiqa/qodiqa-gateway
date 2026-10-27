'use strict';

/**
 * GET /health/redis route coverage.
 *
 *   HR-01  Returns 200 with status 'healthy' when every store is HEALTHY
 *   HR-02  Returns 503 with status 'disconnected' when any store is DISCONNECTED
 *   HR-03  Returns 200 with status 'degraded' when a store is DEGRADED (still serving)
 *   HR-04  Response body includes the full per-store snapshot
 *   HR-05  Returns 200 healthy with zero registered stores (no Redis-backed features enabled)
 */

const request = require('supertest');
const express = require('express');
const healthRegistry = require('../../../infra/redis/health');

const healthRedisRouter = require('../healthRedis');

function buildApp() {
  const app = express();
  app.use('/health/redis', healthRedisRouter);
  return app;
}

afterEach(() => {
  for (const purpose of Object.keys(healthRegistry.getAllHealth())) {
    healthRegistry.unregister(purpose);
  }
});

describe('GET /health/redis', () => {
  test('HR-01 returns 200 with status healthy when every store is HEALTHY', async () => {
    healthRegistry.register('nonce', () => ({ state: 'HEALTHY', mode: 'single' }));
    const res = await request(buildApp()).get('/health/redis');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('healthy');
  });

  test('HR-02 returns 503 with status disconnected when any store is DISCONNECTED', async () => {
    healthRegistry.register('nonce', () => ({ state: 'HEALTHY' }));
    healthRegistry.register('anomaly', () => ({ state: 'DISCONNECTED' }));
    const res = await request(buildApp()).get('/health/redis');
    expect(res.status).toBe(503);
    expect(res.body.status).toBe('disconnected');
  });

  test('HR-03 returns 200 with status degraded when a store is DEGRADED', async () => {
    healthRegistry.register('nonce', () => ({ state: 'DEGRADED' }));
    const res = await request(buildApp()).get('/health/redis');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('degraded');
  });

  test('HR-04 response body includes the full per-store snapshot', async () => {
    healthRegistry.register('keyRotationLock', () => ({
      purpose: 'keyRotationLock', mode: 'sentinel', state: 'HEALTHY',
      master: { host: 'm1', port: 6379 }, failoverCount: 2,
    }));
    const res = await request(buildApp()).get('/health/redis');
    expect(res.body.stores.keyRotationLock).toEqual({
      purpose: 'keyRotationLock', mode: 'sentinel', state: 'HEALTHY',
      master: { host: 'm1', port: 6379 }, failoverCount: 2,
    });
  });

  test('HR-05 returns 200 healthy with zero registered stores', async () => {
    const res = await request(buildApp()).get('/health/redis');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'healthy', stores: {} });
  });
});
