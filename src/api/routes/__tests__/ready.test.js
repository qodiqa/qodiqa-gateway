'use strict';

const request          = require('supertest');
const express          = require('express');
const readinessState   = require('../../../runtime/readinessState');
const readinessTracker = require('../../../runtime/readinessTracker');
const nonceStore       = require('../../../validation/nonceStore');
const anomalyStore     = require('../../../validation/anomalyStore');
const rateLimitStore   = require('../../../../services/policy/store');
const pgPool           = require('../../../infra/postgres/pool');
const consentSubscriber = require('../../../core/consent/revocation/RevocationSubscriber');
const consentCache      = require('../../../core/consent/ConsentCache');

jest.mock('../../../validation/nonceStore', () => ({ isReady: jest.fn() }));
jest.mock('../../../validation/anomalyStore', () => ({ isReady: jest.fn() }));
jest.mock('../../../../services/policy/store', () => ({ isReady: jest.fn() }));
jest.mock('../../../infra/postgres/pool', () => ({ isEnabled: jest.fn(), isHealthy: jest.fn() }));
jest.mock('../../../core/consent/revocation/RevocationSubscriber', () => ({ isReady: jest.fn() }));
jest.mock('../../../core/consent/ConsentCache', () => ({ isReady: jest.fn() }));

const readyRouter = require('../ready');

function buildApp() {
  const app = express();
  app.use('/ready', readyRouter);
  return app;
}

// Baseline: every dependency healthy, PostgreSQL not configured for this
// deployment (the common case — PostgreSQL is an optional backend; see
// src/infra/postgres/pool.js's isEnabled()).
function setAllStoresReady(value) {
  nonceStore.isReady.mockReturnValue(value);
  anomalyStore.isReady.mockReturnValue(value);
  rateLimitStore.isReady.mockReturnValue(value);
  pgPool.isEnabled.mockReturnValue(false);
  pgPool.isHealthy.mockReturnValue(value);
  consentSubscriber.isReady.mockReturnValue(value);
  consentCache.isReady.mockReturnValue(value);
}

beforeEach(() => {
  setAllStoresReady(true);
});

afterEach(() => {
  readinessState._reset();
  readinessTracker._reset();
  jest.clearAllMocks();
});

describe('GET /ready', () => {
  it('returns HTTP 503 when not ready (initial state)', async () => {
    const res = await request(buildApp()).get('/ready');
    expect(res.status).toBe(503);
  });

  it('returns { ready: false } when not ready', async () => {
    const res = await request(buildApp()).get('/ready');
    expect(res.body).toMatchObject({ ready: false });
  });

  it('returns HTTP 200 when ready and every store is ready', async () => {
    readinessState.setReady(true);
    const res = await request(buildApp()).get('/ready');
    expect(res.status).toBe(200);
  });

  it('returns { ready: true } when ready and every store is ready', async () => {
    readinessState.setReady(true);
    const res = await request(buildApp()).get('/ready');
    expect(res.body).toMatchObject({ ready: true });
  });

  it('returns 503 immediately after setReady(false)', async () => {
    readinessState.setReady(true);
    readinessState.setReady(false);
    const res = await request(buildApp()).get('/ready');
    expect(res.status).toBe(503);
  });

  it('reflects shutdown — returns 503 after readiness is cleared', async () => {
    readinessState.setReady(true);
    // Simulate the shutdown step: readiness cleared before drain
    readinessState.setReady(false);
    const res = await request(buildApp()).get('/ready');
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ ready: false });
  });

  // Regression coverage for the gap AT-008 (test/acceptance) found: startup
  // readiness alone must not be sufficient once a store disconnects mid-run.
  describe('live component health (post-startup degradation)', () => {
    it('returns 503 when nonceStore disconnects after a healthy startup', async () => {
      readinessState.setReady(true);
      nonceStore.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(503);
      expect(res.body).toMatchObject({ ready: false, components: { nonceStore: false } });
    });

    it('returns 503 when anomalyStore disconnects after a healthy startup', async () => {
      readinessState.setReady(true);
      anomalyStore.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(503);
      expect(res.body).toMatchObject({ ready: false, components: { anomalyStore: false } });
    });

    it('returns 503 when rateLimitStore disconnects after a healthy startup', async () => {
      readinessState.setReady(true);
      rateLimitStore.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(503);
      expect(res.body).toMatchObject({ ready: false, components: { rateLimitStore: false } });
    });

    it('recovers to 200/ready:true once the disconnected store reconnects', async () => {
      readinessState.setReady(true);
      nonceStore.isReady.mockReturnValue(false);
      const degraded = await request(buildApp()).get('/ready');
      expect(degraded.status).toBe(503);

      nonceStore.isReady.mockReturnValue(true);
      const recovered = await request(buildApp()).get('/ready');
      expect(recovered.status).toBe(200);
      expect(recovered.body).toMatchObject({ ready: true });
    });

    it('always reports the live per-component detail in the body, healthy or not', async () => {
      readinessState.setReady(true);
      setAllStoresReady(true);
      const res = await request(buildApp()).get('/ready');
      expect(res.body.components).toEqual({
        nonceStore:        true,
        anomalyStore:      true,
        rateLimitStore:    true,
        persistenceStore:  true,
        consentSubscriber: true,
        consentCache:      true,
        admission:         true, // not saturated
        auditBacklog:      true, // audit mirror backlog under its bound
        auditPersistence:  true, // mandatory audit appends not failing
        transparencyJournal: true, // the transparency evidence store is not past its unavailability bound
      });
    });
  });

  // (D-F5-1): readiness reflects the transparency evidence store — past its bound the instance leaves rotation.
  describe('transparency journal', () => {
    it('returns 503 with transparencyJournal:false once the unavailability window is older than its bound, and 200 again after recovery', async () => {
      readinessState.setReady(true);
      setAllStoresReady(true);
      const jh = require('../../../core/transparency/journalHealth');
      jh._reset();
      process.env.QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS = '1000';
      const realNow = Date.now;
      try {
        jh.noteFailure(new Error('journal volume gone'));
        expect((await request(buildApp()).get('/ready')).status).toBe(200);                 // inside the bound: still serving (BLOCKs, buffered leaves)
        Date.now = () => realNow() + 1500;
        const res = await request(buildApp()).get('/ready');
        expect(res.status).toBe(503);
        expect(res.body.components.transparencyJournal).toBe(false);
        jh.noteOk();
        Date.now = realNow;
        expect((await request(buildApp()).get('/ready')).status).toBe(200);
      } finally { Date.now = realNow; delete process.env.QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS; jh._reset(); }
    });
  });

  // readiness reflects saturation — a full admission queue pulls /ready to 503.
  describe('admission saturation', () => {
    it('returns 503 with admission:false while an admission queue is full, and 200 again once it drains', async () => {
      readinessState.setReady(true);
      setAllStoresReady(true);
      const admission = require('../../admission');
      const spy = jest.spyOn(admission, 'anySaturated').mockReturnValue(true);
      try {
        const res = await request(buildApp()).get('/ready');
        expect(res.status).toBe(503);
        expect(res.body).toMatchObject({ ready: false, components: { admission: false } });
        spy.mockReturnValue(false);
        const ok = await request(buildApp()).get('/ready');
        expect(ok.status).toBe(200);
        expect(ok.body.components.admission).toBe(true);
      } finally { spy.mockRestore(); }
    });
  });

  // 2026-10-06: an audit mirror backlog above its bound pulls /ready to 503 until it drains.
  describe('audit mirror backlog', () => {
    it('returns 503 with auditBacklog:false while mirror back-pressure is engaged, and 200 once released', async () => {
      readinessState.setReady(true);
      setAllStoresReady(true);
      const auditLog = require('../../../core/audit/audit-log');
      const spy = jest.spyOn(auditLog, 'mirrorBackpressureEngaged').mockReturnValue(true);
      try {
        const res = await request(buildApp()).get('/ready');
        expect(res.status).toBe(503);
        expect(res.body).toMatchObject({ ready: false, components: { auditBacklog: false } });
        spy.mockReturnValue(false);
        const ok = await request(buildApp()).get('/ready');
        expect(ok.status).toBe(200);
        expect(ok.body.components.auditBacklog).toBe(true);
      } finally { spy.mockRestore(); }
    });
  });

  // ConsentCache is optional/best-effort (see ready.js's classification
  // comment) — a cache miss/outage transparently falls through to PostgreSQL
  // with no fail-open path, so it must be visible but must never gate
  // readiness the way the REQUIRED_COMPONENTS do.
  describe('consent cache readiness', () => {
    it('reports consentCache health in the body without affecting HTTP status', async () => {
      readinessState.setReady(true);
      setAllStoresReady(true);
      consentCache.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ ready: true, components: { consentCache: false } });
    });

    it('does not flip overall readiness to false when only consentCache is down', async () => {
      readinessState.setReady(true);
      setAllStoresReady(true);
      consentCache.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.body.ready).toBe(true);
    });

    it('other required components still gate readiness when consentCache happens to be healthy', async () => {
      readinessState.setReady(true);
      setAllStoresReady(true);
      consentCache.isReady.mockReturnValue(true);
      nonceStore.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(503);
      expect(res.body.ready).toBe(false);
    });
  });

  // READY-50: PostgreSQL connectivity and the consent revocation subscriber
  // must gate readiness — a pod that can't durably audit or can't receive
  // revocations must not be reported Ready.
  describe('PostgreSQL readiness (READY-50)', () => {
    it('does not gate readiness when PostgreSQL is not configured for this deployment', async () => {
      readinessState.setReady(true);
      pgPool.isEnabled.mockReturnValue(false);
      pgPool.isHealthy.mockReturnValue(false); // irrelevant — not enabled
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(200);
      expect(res.body.components.persistenceStore).toBe(true);
    });

    it('returns 503 when PostgreSQL is enabled but unhealthy', async () => {
      readinessState.setReady(true);
      pgPool.isEnabled.mockReturnValue(true);
      pgPool.isHealthy.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(503);
      expect(res.body).toMatchObject({ ready: false, components: { persistenceStore: false } });
    });

    it('returns 200 when PostgreSQL is enabled and healthy', async () => {
      readinessState.setReady(true);
      pgPool.isEnabled.mockReturnValue(true);
      pgPool.isHealthy.mockReturnValue(true);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(200);
      expect(res.body.components.persistenceStore).toBe(true);
    });

    it('recovers to 200 once PostgreSQL reconnects', async () => {
      readinessState.setReady(true);
      pgPool.isEnabled.mockReturnValue(true);
      pgPool.isHealthy.mockReturnValue(false);
      const degraded = await request(buildApp()).get('/ready');
      expect(degraded.status).toBe(503);

      pgPool.isHealthy.mockReturnValue(true);
      const recovered = await request(buildApp()).get('/ready');
      expect(recovered.status).toBe(200);
      expect(recovered.body.components.persistenceStore).toBe(true);
    });

    it('does not query PostgreSQL — reads the cached health flag only', async () => {
      readinessState.setReady(true);
      pgPool.isEnabled.mockReturnValue(true);
      pgPool.isHealthy.mockReturnValue(true);
      await request(buildApp()).get('/ready');
      expect(pgPool.query).toBeUndefined(); // not even mocked/imported by ready.js
      expect(pgPool.isHealthy).toHaveBeenCalled();
    });
  });

  describe('consent revocation subscriber readiness (READY-50)', () => {
    it('returns 503 before the subscriber has ever connected (startup)', async () => {
      readinessState.setReady(true);
      consentSubscriber.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(503);
      expect(res.body).toMatchObject({ ready: false, components: { consentSubscriber: false } });
    });

    it('returns 503 when the subscriber disconnects after a healthy startup', async () => {
      readinessState.setReady(true);
      consentSubscriber.isReady.mockReturnValue(true);
      const healthy = await request(buildApp()).get('/ready');
      expect(healthy.status).toBe(200);

      consentSubscriber.isReady.mockReturnValue(false);
      const degraded = await request(buildApp()).get('/ready');
      expect(degraded.status).toBe(503);
      expect(degraded.body.components.consentSubscriber).toBe(false);
    });

    it('recovers to 200 once the subscriber reconnects and resubscribes', async () => {
      readinessState.setReady(true);
      consentSubscriber.isReady.mockReturnValue(false);
      const degraded = await request(buildApp()).get('/ready');
      expect(degraded.status).toBe(503);

      consentSubscriber.isReady.mockReturnValue(true);
      const recovered = await request(buildApp()).get('/ready');
      expect(recovered.status).toBe(200);
      expect(recovered.body.components.consentSubscriber).toBe(true);
    });

    it('is required regardless of PostgreSQL configuration', async () => {
      readinessState.setReady(true);
      pgPool.isEnabled.mockReturnValue(false);
      consentSubscriber.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(503);
    });
  });

  describe('combined dependency failures', () => {
    it('reports 503 when both PostgreSQL and the subscriber are down simultaneously', async () => {
      readinessState.setReady(true);
      pgPool.isEnabled.mockReturnValue(true);
      pgPool.isHealthy.mockReturnValue(false);
      consentSubscriber.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(503);
      expect(res.body.components).toMatchObject({ persistenceStore: false, consentSubscriber: false });
    });

    it('requires ALL dependencies healthy to report ready — not merely no dependency reporting unhealthy', async () => {
      readinessState.setReady(true);
      setAllStoresReady(true);
      pgPool.isEnabled.mockReturnValue(true);
      pgPool.isHealthy.mockReturnValue(true);
      const healthy = await request(buildApp()).get('/ready');
      expect(healthy.status).toBe(200);

      // Flip exactly one dependency off; everything else stays healthy.
      consentSubscriber.isReady.mockReturnValue(false);
      const res = await request(buildApp()).get('/ready');
      expect(res.status).toBe(503);
    });
  });

  describe('concurrent probes', () => {
    it('handles concurrent GET /ready requests consistently (no shared mutable request state)', async () => {
      readinessState.setReady(true);
      const app = buildApp();
      const results = await Promise.all(
        Array.from({ length: 10 }, () => request(app).get('/ready')),
      );
      for (const res of results) {
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ ready: true });
      }
    });

    it('handles a burst of probes spanning a dependency transition without corrupting per-request results', async () => {
      readinessState.setReady(true);
      const app = buildApp();

      const before = await Promise.all(Array.from({ length: 5 }, () => request(app).get('/ready')));
      for (const res of before) expect(res.status).toBe(200);

      consentSubscriber.isReady.mockReturnValue(false);

      const after = await Promise.all(Array.from({ length: 5 }, () => request(app).get('/ready')));
      for (const res of after) expect(res.status).toBe(503);
    });
  });
});
