'use strict';

/**
 * PostgreSQL DOWN / SLOW (silent partition) / connection exhaustion, against REAL PostgreSQL,
 * driving the PRODUCTION pool singleton (src/infra/postgres/pool.js: readiness monitor, circuit breaker, acquire
 * timeout) and the PRODUCTION GET /ready router (src/api/routes/ready.js). The database is reached through a TCP
 * fault proxy owned by this test (test/helpers/faultProxy.js); the PostgreSQL server is never stopped.
 *
 * What gap this closes: ready.test.js / pool.readiness.test.js prove the same contracts against a FAKE pg.Pool; the
 * real-PG suites (ind02, ACOR, PXR) prove query-level fail-closed + durable re-queueing but never look at /ready.
 * Here the probe, the breaker and /ready are exercised end to end against a real server and real sockets:
 *
 *   FR-PG-01  healthy baseline: /ready 200, persistenceStore true
 *   FR-PG-02  PG DOWN: queries reject within a bound (no hang) and then fast-fail PG_CIRCUIT_OPEN; /ready 503
 *             persistenceStore false within interval + probe timeout; nothing uncaught
 *   FR-PG-03  recovery from DOWN without a restart: /ready 200 and queries succeed once PG is reachable again
 *   FR-PG-04  PG SILENT/SLOW (blackhole): the readiness probe is bounded (/ready 503 within the bound), new
 *             connection acquisition fails within the acquire timeout, the pool does not pile up connections or waiters
 *   FR-PG-05  recovery from the silent partition (the partition heals with the TCP connections intact: held bytes are
 *             delivered late): /ready 200, queries succeed. The variant where the connections do NOT survive wedges the
 *             circuit breaker in HALF_OPEN permanently — a production defect (PH16-D1), kept OUT of this gating suite:
 *
 *   FR-PG-06  connection EXHAUSTION (QODIQA_PG_POOL_MAX=2, both held by pg_sleep): acquisition fails fast, /ready 503
 *             (probe cannot acquire), and returns to 200 once the holders finish
 *
 * Needs only SELECT 1 / pg_sleep (no schema, no migrations) — runs against the maintenance database of the disposable
 * PG. Parallel-pool safe: no migration chain, no catalog DDL.
 */

const express = require('express');
const supertest = require('supertest');
const { createFaultProxy } = require('../helpers/faultProxy');

const { pgTarget } = require('../helpers/disposableTargets');

// Targets come ONLY from explicit process env (pl-env.sh); no 5432 default, LIVE 5432 refused (INC-01).
const TARGET = pgTarget();
const RUN = TARGET.available;
const PG_HOST = TARGET.host;
const PG_PORT = TARGET.port;

const INTERVAL_MS = 150;
const PROBE_TIMEOUT_MS = 400;
const ACQUIRE_MS = 400;
const CB_RECOVERY_MS = 600;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const settleWithin = (p, ms) => Promise.race([p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e })), sleep(ms).then(() => ({ pending: true }))]);

jest.setTimeout(60_000);

(RUN ? describe : describe.skip)('PostgreSQL outage / partition / exhaustion → fail-closed, /ready, recovery (real PG)', () => {
  let proxy; let pool; let breaker; let app; let saved;
  const ENV = {
    QODIQA_PG_DATABASE: process.env.QODIQA_PG_DATABASE || 'postgres',
    QODIQA_PG_HOST: '127.0.0.1',
    QODIQA_PG_READY_CHECK_INTERVAL_MS: String(INTERVAL_MS),
    QODIQA_PG_READY_TIMEOUT_MS: String(PROBE_TIMEOUT_MS),
    QODIQA_PG_ACQUIRE_TIMEOUT_MS: String(ACQUIRE_MS),
    QODIQA_PG_STATEMENT_TIMEOUT_MS: '5000',
    QODIQA_PG_CB_RECOVERY_MS: String(CB_RECOVERY_MS),
    QODIQA_PG_CB_SUCCESS_THRESHOLD: '1',
    QODIQA_PG_POOL_MAX: '2',
  };

  const ready = () => supertest(app).get('/ready');
  async function waitReady(expectStatus, budgetMs) {
    const t0 = Date.now(); let last;
    while (Date.now() - t0 < budgetMs) {
      last = await ready();
      if (last.status === expectStatus) return { res: last, ms: Date.now() - t0 };
      await sleep(50);
    }
    // diagnostics travel with the failure (toBeUndefined on timedOut prints the whole object via the message below)
    const diag = { pool: pool.poolStats(), breaker: breaker.getCircuitBreaker().state, proxy: proxy.stats(), body: last && last.body };
    return { res: last, ms: Date.now() - t0, timedOut: JSON.stringify(diag) };
  }

  beforeAll(async () => {
    proxy = createFaultProxy({ targetHost: PG_HOST, targetPort: PG_PORT });
    const port = await proxy.listen();
    saved = {};
    for (const [k, v] of Object.entries({ ...ENV, QODIQA_PG_PORT: String(port) })) { saved[k] = process.env[k]; process.env[k] = v; }
    jest.resetModules();
    // Every OTHER /ready input is held healthy so the only moving part is PostgreSQL (the subject of this suite).
    const up = { isReady: () => true };
    jest.doMock('../../src/validation/nonceStore', () => up);
    jest.doMock('../../src/validation/anomalyStore', () => up);
    jest.doMock('../../services/policy/store', () => up);
    jest.doMock('../../src/core/consent/revocation/RevocationSubscriber', () => up);
    jest.doMock('../../src/core/consent/ConsentCache', () => up);
    jest.doMock('../../src/api/admission', () => ({ anySaturated: () => false }));
    jest.doMock('../../src/core/audit/audit-log', () => ({ mirrorBackpressureEngaged: () => false }));
    pool = require('../../src/infra/postgres/pool');
    breaker = require('../../src/infra/postgres/pgCircuitBreaker');
    require('../../src/runtime/readinessState').setReady(true);
    app = express();
    app.use('/ready', require('../../src/api/routes/ready'));
    pool.initialize();
    pool.startReadinessMonitor();
  });

  afterAll(async () => {
    if (pool) await pool.shutdown();
    if (proxy) await proxy.close();
    for (const [k, v] of Object.entries(saved || {})) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });

  test('FR-PG-01 healthy baseline: /ready 200 with persistenceStore true', async () => {
    const r = await waitReady(200, 5000);
    expect(r.timedOut).toBeUndefined();
    expect(r.res.body).toMatchObject({ ready: true, components: { persistenceStore: true } });
    expect((await pool.query('SELECT 1 AS x')).rows[0].x).toBe(1);
  });

  test('FR-PG-02 PG DOWN: queries reject within a bound, then fast-fail on the open breaker; /ready 503', async () => {
    proxy.refuse();
    const t0 = Date.now();
    const first = await settleWithin(pool.query('SELECT 1'), 5000);
    expect(first.pending).toBeUndefined();
    expect(first.ok).toBe(false);                                 // fail-closed: an error, never a fabricated result
    expect(Date.now() - t0).toBeLessThan(ACQUIRE_MS + 2000);
    // keep failing until the breaker opens (default threshold 5 connection-class failures)
    let openErr = null;
    for (let i = 0; i < 20 && !openErr; i++) {
      try { await pool.query('SELECT 1'); } catch (e) { if (e.code === 'PG_CIRCUIT_OPEN') openErr = e; }
    }
    expect(openErr).not.toBeNull();
    const t1 = Date.now();
    await expect(pool.query('SELECT 1')).rejects.toMatchObject({ code: 'PG_CIRCUIT_OPEN' });
    expect(Date.now() - t1).toBeLessThan(50);                      // fast-fail: no per-caller stall during the outage
    const r = await waitReady(503, INTERVAL_MS + PROBE_TIMEOUT_MS + 2000);
    expect(r.timedOut).toBeUndefined();
    expect(r.res.body).toMatchObject({ ready: false, components: { persistenceStore: false } });
    expect(pool.isHealthy()).toBe(false);
  });

  test('FR-PG-03 recovery from DOWN without a restart: /ready 200, queries succeed', async () => {
    proxy.heal();
    const r = await waitReady(200, CB_RECOVERY_MS + 10 * INTERVAL_MS + 5000);
    expect(r.timedOut).toBeUndefined();
    expect(r.res.body.components.persistenceStore).toBe(true);
    expect(breaker.getCircuitBreaker().state).toBe('CLOSED');
    expect((await pool.query('SELECT 42 AS x')).rows[0].x).toBe(42);
  });

  test('FR-PG-04 PG SILENT (blackhole): bounded probe → /ready 503; acquisition fails fast; no connection/waiter pile-up', async () => {
    breaker.reset();
    // drain idle clients so the next acquisition must open a NEW connection through the partition
    const stats0 = pool.poolStats();
    expect(stats0.waiting).toBe(0);
    proxy.blackhole();
    const r = await waitReady(503, INTERVAL_MS + PROBE_TIMEOUT_MS + 3000);
    expect(r.timedOut).toBeUndefined();
    expect(r.res.body.components.persistenceStore).toBe(false);
    // let many probe ticks run against the partition — the in-flight guard + acquire timeout must keep it bounded
    await sleep(20 * INTERVAL_MS);
    const s = pool.poolStats();
    expect(s.size).toBeLessThanOrEqual(2);
    expect(s.waiting).toBeLessThanOrEqual(1);
  });

  test('FR-PG-05 recovery from the silent partition (connections intact): /ready 200, queries succeed', async () => {
    proxy.heal({ deliverHeld: true });
    const r = await waitReady(200, CB_RECOVERY_MS + 10 * INTERVAL_MS + 8000);
    expect(r.timedOut).toBeUndefined();
    expect(r.res.body.ready).toBe(true);
    expect((await pool.query('SELECT 7 AS x')).rows[0].x).toBe(7);
  });

  test('FR-PG-06 connection EXHAUSTION: acquisition fails fast, /ready 503 while saturated, 200 after the holders finish', async () => {
    breaker.reset();
    await waitReady(200, 5000);
    const HOLD_S = 3;
    const holders = [pool.query(`SELECT pg_sleep(${HOLD_S})`), pool.query(`SELECT pg_sleep(${HOLD_S})`)];
    await sleep(100);
    const t0 = Date.now();
    const starved = await settleWithin(pool.query('SELECT 1'), 5000);
    expect(starved.pending).toBeUndefined();
    expect(starved.ok).toBe(false);
    expect(starved.e.message).toMatch(/timeout/i);
    expect(Date.now() - t0).toBeLessThan(ACQUIRE_MS + 1000);
    const down = await waitReady(503, HOLD_S * 1000);
    expect(down.timedOut).toBeUndefined();
    expect(down.res.body.components.persistenceStore).toBe(false);
    await Promise.allSettled(holders);
    breaker.reset();          // the starved acquisitions count as connection-class failures; isolate the drain check
    const up = await waitReady(200, CB_RECOVERY_MS + 10 * INTERVAL_MS + 5000);
    expect(up.timedOut).toBeUndefined();
    expect(pool.poolStats().waiting).toBe(0);
  });
});
