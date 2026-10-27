'use strict';

/**
 * regression — the echo of centralStore's own ingest query must never be
 * re-ingested, and pgPool.shutdown() must not starve the event loop.
 *
 * Real pool.js query() emits PG_QUERY_ERROR from its catch block, i.e. AFTER
 * `await _pool.query(...)` — outside LOG-1's synchronous _ingestReentrant
 * window (the LOG-1 suite's mock emits synchronously, so it never modelled
 * this). logger.emit() therefore forwarded that echo back into ingest(), which
 * failed again and echoed again. While PG is merely down the chain is paced by
 * I/O; once pool.end() has started, pg-pool rejects every query synchronously
 * ("Cannot use a pool after calling end on the pool"), so the chain is a pure
 * microtask loop: timers (shutdown.js's SHUTDOWN_TIMEOUT safety net),
 * setImmediate (the logger's own stdout flush) and I/O (pool.end() itself)
 * never run again, and graceful shutdown hangs until SIGKILL — reproduced on
 * the production Compose stack (exit 137 after the 60 s grace period).
 */

const path = require('path');
const { spawnSync } = require('child_process');

const POOL_PATH   = path.resolve(__dirname, '..', '..', '..', 'infra', 'postgres', 'pool');
const STORE_PATH  = path.resolve(__dirname, '..', 'centralStore.js');
const LOGGER_PATH = path.resolve(__dirname, '..', '..', '..', '..', 'services', 'logger');

describe('ingest echo is not re-persisted (async PG_QUERY_ERROR path)', () => {
  let logger;

  beforeEach(() => {
    jest.resetModules();
    logger = require(LOGGER_PATH);
  });

  afterEach(() => {
    jest.dontMock(POOL_PATH);
    jest.resetModules();
  });

  it('bounds the real async shape (emit AFTER the await) to one query attempt', async () => {
    let queryCallCount = 0;
    const CAP = 1000; // pre-fix the chain is unbounded; the cap keeps a failing run finite
    jest.doMock(POOL_PATH, () => ({
      isEnabled: jest.fn(() => true),
      query: jest.fn(async (sql, params, label) => {
        queryCallCount++;
        if (queryCallCount > CAP) return { rows: [], rowCount: 1 };
        await null; // pool.js: `await _pool.query(...)` — the failure surfaces after an await
        const err = new Error('Cannot use a pool after calling end on the pool');
        logger.emit('ERROR', 'PG_QUERY_ERROR', { label, error: err.message, code: null });
        throw err;
      }),
    }));
    const store = require(STORE_PATH);
    logger.registerCentralStore(store);
    const echoes = [];
    logger.eventBus.on('log', (r) => { if (r.label === 'audit_store_ingest') echoes.push(r.eventType); });

    logger.emit('INFO', 'PG_POOL_SHUTDOWN', {});
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    await store.flush(); // (step 5): the buffered row is written by the batched flush
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));

    expect(queryCallCount).toBe(1);
    // The operational signal survives on the non-PG sinks: exactly one echo.
    expect(echoes).toEqual(['PG_QUERY_ERROR']);
  });

  it('never forwards an audit_store_ingest-labelled event to centralStore; other events still are', () => {
    const ingested = [];
    logger.registerCentralStore({ ingest: async (level, event, record) => { ingested.push(`${event}:${record.label || ''}`); } });

    logger.emit('ERROR', 'PG_QUERY_ERROR', { label: 'audit_store_ingest', error: 'x' });
    logger.emit('WARN', 'PG_CIRCUIT_OPEN', { label: 'audit_store_ingest' });
    logger.emit('WARN', 'PG_SLOW_QUERY', { label: 'audit_store_ingest', ms: 2300 });
    logger.emit('ERROR', 'PG_QUERY_ERROR', { label: 'consent_store_get', error: 'y' });
    logger.emit('INFO', 'PG_POOL_SHUTDOWN', {});

    expect(ingested).toEqual(['PG_QUERY_ERROR:consent_store_get', 'PG_POOL_SHUTDOWN:']);
  });

  it('real logger + centralStore + pool.js + pg-pool: pgPool.shutdown() leaves the event loop live (timer fires)', () => {
    // Child process: a starved event loop would also starve Jest's own timeout.
    // PG points at an unreachable port — no database is touched. The ingest
    // started by PG_POOL_SHUTDOWN fails after pool.end() began, which is the
    // first post-end ERROR echo.
    const code = `
      Object.assign(process.env, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '1',
        QODIQA_PG_DATABASE: 'h127_unreachable', QODIQA_PG_USER: 'nobody', QODIQA_PG_PASSWORD: 'x' });
      const fs = require('fs');
      const logger = require(${JSON.stringify(LOGGER_PATH)});
      const store = require(${JSON.stringify(STORE_PATH)});
      const pool = require(${JSON.stringify(POOL_PATH)});
      let n = 0; const real = store.ingest;
      logger.registerCentralStore({ ingest: (...a) => { n++; return real(...a); } });
      pool.initialize();
      setTimeout(() => { fs.writeSync(2, 'H127_RESULT ' + JSON.stringify({ timerFired: true, ingestCalls: n }) + '\\n'); process.exit(0); }, 1500);
      pool.shutdown();
    `;
    const r = spawnSync(process.execPath, ['-e', code], { encoding: 'utf8', timeout: 15000, env: { ...process.env } });
    const m = /H127_RESULT (\{.*\})/.exec(r.stderr || '');

    expect(r.signal).toBeNull(); // pre-fix: killed by the 15 s timeout, the 1.5 s timer never fired
    expect(m).not.toBeNull();
    const result = JSON.parse(m[1]);
    expect(result.timerFired).toBe(true);
    expect(result.ingestCalls).toBeLessThanOrEqual(5); // PG_POOL_SHUTDOWN (+ PG_POOL_ERROR-class events), never a loop
  }, 30000);
});
