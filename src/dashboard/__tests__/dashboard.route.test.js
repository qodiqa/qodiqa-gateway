'use strict';

/**
 * Integration tests for the /dashboard routes.
 *
 * The dashboard router itself is mount-agnostic — tests wire it directly into
 * a minimal Express app without the ops-auth middleware chain.
 */

const request = require('supertest');
const express = require('express');

// ── Stubs ─────────────────────────────────────────────────────────────────────

const STUB_CHAIN = [];

jest.mock('../../core/audit/audit-log', () => ({
  getAuditChain: () => STUB_CHAIN.slice(),
}));

jest.mock('../../validation/nonceStore', () => ({
  isReady: () => true,
}));

jest.mock('../../validation/anomalyStore', () => ({
  isReady: () => true,
}));

jest.mock('../../../services/policy/store', () => ({
  isReady: () => true,
}));

jest.mock('../../runtime/readinessState', () => ({
  isReady: () => true,
}));

// Suppress logger noise during tests
jest.mock('../../../services/logger', () => {
  const { EventEmitter } = require('events');
  const eventBus = new EventEmitter();
  return { emit: jest.fn(), allowed: jest.fn(), blocked: jest.fn(), eventBus };
});

const { invalidate } = require('../aggregator');
const dashboardRouter = require('../../api/routes/dashboard');

function buildApp() {
  const app = express();
  app.use('/dashboard', dashboardRouter);
  return app;
}

function makeEntry(overrides = {}) {
  return {
    artifactId: 'art-' + Math.random().toString(36).slice(2),
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
  invalidate();
});

// ── GET /dashboard/overview ───────────────────────────────────────────────────

describe('GET /dashboard/overview', () => {
  it('returns 200 with overview shape', async () => {
    const res = await request(buildApp()).get('/dashboard/overview');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('status', 'success');
    expect(res.body).toHaveProperty('timestamp');
    expect(res.body.data).toHaveProperty('totalRequests');
    expect(res.body.data).toHaveProperty('allowedRequests');
    expect(res.body.data).toHaveProperty('blockedRequests');
    expect(res.body.data).toHaveProperty('replayAttempts');
    expect(res.body.data).toHaveProperty('anomaliesDetected');
    expect(res.body.data).toHaveProperty('executionIntegrity');
    expect(res.body.data).toHaveProperty('uptime');
  });

  it('reflects chain entries in totals', async () => {
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'REPLAY_DETECTED' } }));
    invalidate();
    const res = await request(buildApp()).get('/dashboard/overview');
    expect(res.body.data.totalRequests).toBe(2);
    expect(res.body.data.allowedRequests).toBe(1);
    expect(res.body.data.blockedRequests).toBe(1);
    expect(res.body.data.replayAttempts).toBe(1);
  });
});

// ── GET /dashboard/executions ─────────────────────────────────────────────────

describe('GET /dashboard/executions', () => {
  it('returns 200 with entries and pagination fields', async () => {
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    invalidate();
    const res = await request(buildApp()).get('/dashboard/executions');
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('entries');
    expect(res.body.data).toHaveProperty('total');
    expect(res.body.data).toHaveProperty('page');
    expect(res.body.data).toHaveProperty('pageSize');
    expect(Array.isArray(res.body.data.entries)).toBe(true);
    expect(res.body.data.total).toBe(1);
  });

  it('respects page and pageSize query params', async () => {
    for (let i = 0; i < 5; i++) STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    invalidate();
    const res = await request(buildApp()).get('/dashboard/executions?page=2&pageSize=2');
    expect(res.status).toBe(200);
    expect(res.body.data.entries).toHaveLength(2);
    expect(res.body.data.page).toBe(2);
  });

  it('returns empty entries when no executions', async () => {
    const res = await request(buildApp()).get('/dashboard/executions');
    expect(res.body.data.entries).toHaveLength(0);
    expect(res.body.data.total).toBe(0);
  });

  it('caps pageSize at 200', async () => {
    for (let i = 0; i < 5; i++) STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    invalidate();
    const res = await request(buildApp()).get('/dashboard/executions?pageSize=9999');
    expect(res.status).toBe(200);
    expect(res.body.data.pageSize).toBeLessThanOrEqual(200);
  });
});

// ── GET /dashboard/blocked ────────────────────────────────────────────────────

describe('GET /dashboard/blocked', () => {
  it('returns 200 with byReason breakdown', async () => {
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'POLICY_DENIED' } }));
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'POLICY_DENIED' } }));
    invalidate();
    const res = await request(buildApp()).get('/dashboard/blocked');
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('byReason');
    expect(res.body.data.byReason.POLICY_DENIED).toBe(2);
    expect(res.body.data.total).toBe(2);
  });

  it('does not include ALLOW entries in blocked', async () => {
    STUB_CHAIN.push(makeEntry({ decision: 'ALLOW' }));
    invalidate();
    const res = await request(buildApp()).get('/dashboard/blocked');
    expect(res.body.data.total).toBe(0);
  });
});

// ── GET /dashboard/replays ────────────────────────────────────────────────────

describe('GET /dashboard/replays', () => {
  it('returns only REPLAY_DETECTED entries', async () => {
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'REPLAY_DETECTED', replayOf: 'abc' } }));
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'POLICY_DENIED' } }));
    invalidate();
    const res = await request(buildApp()).get('/dashboard/replays');
    expect(res.status).toBe(200);
    expect(res.body.data.total).toBe(1);
    expect(res.body.data.entries[0].reason).toBe('REPLAY_DETECTED');
  });
});

// ── GET /dashboard/anomalies ──────────────────────────────────────────────────

describe('GET /dashboard/anomalies', () => {
  it('returns ANOMALY_DETECTED entries with byType', async () => {
    STUB_CHAIN.push(makeEntry({ decision: 'BLOCK', executionContext: { reason: 'ANOMALY_DETECTED', anomalyType: 'RATE_BURST' } }));
    invalidate();
    const res = await request(buildApp()).get('/dashboard/anomalies');
    expect(res.status).toBe(200);
    expect(res.body.data.total).toBe(1);
    expect(res.body.data.byType).toHaveProperty('RATE_BURST', 1);
  });
});

// ── GET /dashboard/status ─────────────────────────────────────────────────────

describe('GET /dashboard/status', () => {
  it('returns 200 with component health', async () => {
    const res = await request(buildApp()).get('/dashboard/status');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('status', 'success');
    expect(res.body.data).toHaveProperty('service', 'qodiqa');
    expect(res.body.data).toHaveProperty('status');
    expect(res.body.data).toHaveProperty('executionIntegrity');
    expect(res.body.data).toHaveProperty('uptime');
    expect(res.body.data).toHaveProperty('components');
    expect(res.body.data.components).toHaveProperty('nonceStore');
    expect(res.body.data.components).toHaveProperty('anomalyStore');
    expect(res.body.data.components).toHaveProperty('rateLimitStore');
  });

  it('reflects store mock state as ready', async () => {
    const res = await request(buildApp()).get('/dashboard/status');
    expect(res.body.data.executionIntegrity).toBe('FULL');
    expect(res.body.data.components.nonceStore.ready).toBe(true);
    expect(res.body.data.components.anomalyStore.ready).toBe(true);
    expect(res.body.data.components.rateLimitStore.ready).toBe(true);
  });

  it('includes memoryMb field', async () => {
    const res = await request(buildApp()).get('/dashboard/status');
    expect(typeof res.body.data.memoryMb).toBe('number');
  });
});

// ── GET /dashboard/activity ───────────────────────────────────────────────────

describe('GET /dashboard/activity', () => {
  it('returns 200 with series array', async () => {
    const res = await request(buildApp()).get('/dashboard/activity');
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('series');
    expect(Array.isArray(res.body.data.series)).toBe(true);
    expect(res.body.data).toHaveProperty('windowMinutes');
  });

  it('respects windowMinutes param', async () => {
    const res = await request(buildApp()).get('/dashboard/activity?windowMinutes=30');
    expect(res.body.data.windowMinutes).toBe(30);
  });

  it('caps windowMinutes at 1440', async () => {
    const res = await request(buildApp()).get('/dashboard/activity?windowMinutes=99999');
    expect(res.body.data.windowMinutes).toBeLessThanOrEqual(1440);
  });
});

// ── GET /dashboard/stream ─────────────────────────────────────────────────────

describe('GET /dashboard/stream', () => {
  it('sets SSE headers', async () => {
    const app = buildApp();
    const res = await new Promise((resolve) => {
      const req = request(app).get('/dashboard/stream');
      req.buffer(false);
      req.on('response', (r) => { r.destroy(); resolve(r); });
      req.end();
    });
    expect(res.headers['content-type']).toMatch(/text\/event-stream/);
  });
});
