'use strict';

const request          = require('supertest');
const express          = require('express');
const readinessState   = require('../../../runtime/readinessState');
const nonceStore       = require('../../../validation/nonceStore');
const anomalyStore     = require('../../../validation/anomalyStore');
const rateLimitStore   = require('../../../../services/policy/store');
const pgPool           = require('../../../infra/postgres/pool');
const consentSubscriber = require('../../../core/consent/revocation/RevocationSubscriber');
const consentCache      = require('../../../core/consent/ConsentCache');

jest.mock('../../../validation/nonceStore', () => ({ isReady: jest.fn() }));
jest.mock('../../../validation/anomalyStore', () => ({ isReady: jest.fn() }));
jest.mock('../../../../services/policy/store', () => ({ isReady: jest.fn() }));
jest.mock('../../../infra/postgres/pool', () => ({
  isEnabled:  jest.fn(),
  isHealthy:  jest.fn(),
  poolStats:  jest.fn(),
}));
jest.mock('../../../core/consent/revocation/RevocationSubscriber', () => ({ isReady: jest.fn() }));
jest.mock('../../../core/consent/ConsentCache', () => ({ isReady: jest.fn() }));

const diagnosticsRouter = require('../diagnostics');

function buildApp() {
  const app = express();
  app.use('/diagnostics', diagnosticsRouter);
  return app;
}

const HEALTHY_POOL_STATS = {
  enabled: true, healthy: true, size: 3, active: 1, idle: 2, waiting: 0,
  max: 10, saturated: false, acquireFailures: 0,
};

function setAllHealthy() {
  nonceStore.isReady.mockReturnValue(true);
  anomalyStore.isReady.mockReturnValue(true);
  rateLimitStore.isReady.mockReturnValue(true);
  pgPool.isEnabled.mockReturnValue(true);
  pgPool.isHealthy.mockReturnValue(true);
  pgPool.poolStats.mockReturnValue(HEALTHY_POOL_STATS);
  consentSubscriber.isReady.mockReturnValue(true);
  consentCache.isReady.mockReturnValue(true);
}

beforeEach(() => {
  setAllHealthy();
});

afterEach(() => {
  readinessState._reset();
  jest.clearAllMocks();
});

describe('GET /diagnostics', () => {
  it('returns HTTP 200 with executionIntegrity FULL when every required dependency is healthy', async () => {
    const res = await request(buildApp()).get('/diagnostics');
    expect(res.status).toBe(200);
    expect(res.body.executionIntegrity).toBe('FULL');
  });

  it('marks executionIntegrity DEGRADED when a required dependency is unhealthy', async () => {
    nonceStore.isReady.mockReturnValue(false);
    const res = await request(buildApp()).get('/diagnostics');
    expect(res.body.executionIntegrity).toBe('DEGRADED');
  });

  it('marks executionIntegrity DEGRADED when PostgreSQL is enabled but unhealthy', async () => {
    pgPool.isHealthy.mockReturnValue(false);
    const res = await request(buildApp()).get('/diagnostics');
    expect(res.body.executionIntegrity).toBe('DEGRADED');
    expect(res.body.components.postgres.ready).toBe(false);
  });

  it('marks executionIntegrity DEGRADED when the revocation subscriber is disconnected', async () => {
    consentSubscriber.isReady.mockReturnValue(false);
    const res = await request(buildApp()).get('/diagnostics');
    expect(res.body.executionIntegrity).toBe('DEGRADED');
    expect(res.body.components.consentSubscriber.ready).toBe(false);
  });

  // ConsentCache is optional/best-effort — its outage must not degrade
  // executionIntegrity, matching /ready's non-gating treatment.
  describe('ConsentCache', () => {
    it('stays FULL when only ConsentCache is unhealthy', async () => {
      consentCache.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/diagnostics');
      expect(res.body.executionIntegrity).toBe('FULL');
      expect(res.body.components.consentCache).toEqual({
        name:     'Consent Cache (Redis, best-effort)',
        ready:    false,
        required: false,
      });
    });

    it('reports required: false for consentCache and required: true for mandatory dependencies', async () => {
      const res = await request(buildApp()).get('/diagnostics');
      expect(res.body.components.consentCache.required).toBe(false);
      expect(res.body.components.nonceStore.required).toBe(true);
      expect(res.body.components.anomalyStore.required).toBe(true);
      expect(res.body.components.rateLimitStore.required).toBe(true);
      expect(res.body.components.postgres.required).toBe(true);
      expect(res.body.components.consentSubscriber.required).toBe(true);
    });
  });

  // PostgreSQL pool telemetry, including pgPool.waitingCount.
  describe('PostgreSQL pool telemetry', () => {
    it('exposes pool size/active/idle/waiting/max/saturated/acquireFailures', async () => {
      const res = await request(buildApp()).get('/diagnostics');
      expect(res.body.components.postgres.pool).toEqual(HEALTHY_POOL_STATS);
    });

    it('exposes waitingCount (as `waiting`) reflecting pool saturation', async () => {
      pgPool.poolStats.mockReturnValue({
        enabled: true, healthy: true, size: 10, active: 10, idle: 0,
        waiting: 4, max: 10, saturated: true, acquireFailures: 2,
      });
      const res = await request(buildApp()).get('/diagnostics');
      expect(res.body.components.postgres.pool.waiting).toBe(4);
      expect(res.body.components.postgres.pool.saturated).toBe(true);
      expect(res.body.components.postgres.pool.acquireFailures).toBe(2);
    });

    it('reports pool as disabled when PostgreSQL is not configured for this deployment', async () => {
      pgPool.isEnabled.mockReturnValue(false);
      pgPool.poolStats.mockReturnValue({ enabled: false });
      const res = await request(buildApp()).get('/diagnostics');
      expect(res.body.components.postgres.pool).toEqual({ enabled: false });
      expect(res.body.components.postgres.ready).toBe(true); // not enabled -> vacuously ready
    });
  });

  it('does not expose secrets or credentials anywhere in the payload', async () => {
    const res = await request(buildApp()).get('/diagnostics');
    const body = JSON.stringify(res.body).toLowerCase();
    for (const banned of ['password', 'secret', 'apikey', 'api_key', 'privatekey']) {
      expect(body).not.toContain(banned);
    }
  });
});
