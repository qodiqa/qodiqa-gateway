'use strict';

/**
 * LOG-1 regression — centralStore.ingest() must never recursively re-enter
 * itself.
 *
 * pool.js's query() emits logger.emit('WARN', 'PG_CIRCUIT_OPEN', ...) — and
 * equally, on any real query failure, emit('ERROR', 'PG_QUERY_ERROR', ...) —
 * synchronously, before ever awaiting anything. logger.emit()'s last step is
 * a fire-and-forget call into centralStore.ingest(), which itself calls
 * pgPool.query() — so a query failure ingest() is trying to LOG about can, if
 * unguarded, synchronously re-trigger the exact same ingest() call on the
 * same native call stack: ingest() -> query() -> emit() -> ingest() -> ...,
 * unbounded, until it hits Node's own stack limit (empirically ~3,000 nested
 * calls in tens of milliseconds).
 * Live-witnessed producing both a sustained event flood (
 * 443,618 events/~31s) and outright process death via
 * processHardening.js's fail-fast unhandledRejection handler.
 *
 * These tests mock only pool.js (never a real database) but exercise the
 * REAL services/logger.js and REAL centralStore.js, with the mock's query()
 * reproducing pool.js's real synchronous emit-then-throw shape — so the
 * actual recursive trigger condition is genuinely exercised, not simulated
 * at a distance.
 */

const path = require('path');

const POOL_PATH   = path.resolve(__dirname, '..', '..', '..', 'infra', 'postgres', 'pool');
const STORE_PATH  = path.resolve(__dirname, '..', 'centralStore.js');
const LOGGER_PATH = path.resolve(__dirname, '..', '..', '..', '..', 'services', 'logger');

function circuitOpenError(label) {
  const err = new Error('PostgreSQL circuit breaker is OPEN — fast-failing without contacting the database');
  err.code = 'PG_CIRCUIT_OPEN';
  err.label = label;
  return err;
}

describe('centralStore.ingest() — LOG-1 re-entrancy guard', () => {
  let store, pool, logger;

  beforeEach(() => {
    jest.resetModules();
    logger = require(LOGGER_PATH);
  });

  afterEach(() => {
    jest.dontMock(POOL_PATH);
    jest.resetModules();
  });

  it('bounds a sustained-breaker-open trigger to exactly one pool.query() call, never recurses, never throws', async () => {
    let queryCallCount = 0;
    jest.doMock(POOL_PATH, () => ({
      isEnabled: jest.fn(() => true),
      query: jest.fn(async (sql, params, label) => {
        queryCallCount++;
        // Mirrors pool.js query()'s real breaker-open branch exactly:
        // emit() synchronously, then throw — before any await.
        logger.emit('WARN', 'PG_CIRCUIT_OPEN', { label });
        throw circuitOpenError(label);
      }),
    }));
    pool  = require(POOL_PATH);
    store = require(STORE_PATH);
    logger.registerCentralStore(store);

    const logged = [];
    logger.eventBus.on('log', (record) => logged.push(record));

    // Simulates a real caller (any pool.js query() invocation elsewhere in
    // the app) hitting the breaker-open branch — the actual LOG-1 trigger.
    expect(() => {
      logger.emit('WARN', 'PG_CIRCUIT_OPEN', { label: 'some_real_caller' });
    }).not.toThrow();

    // ingest() is fire-and-forget; let its microtask chain fully settle.
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    await store.flush(); // (step 5): the buffered row is written by the batched flush, under the same guard

    // Exactly one pool.query() attempt — centralStore's own ingest() call
    // for the original trigger. The re-entrant "echo" (ingest() invoked
    // again for the WARN that ingest()'s own query() call itself emits)
    // never reaches pool.query() at all — the guard suppresses it before
    // that point, not merely after. Pre-fix this call count is unbounded
    // (thousands) and the process crashes; this pins the fixed, bounded
    // count exactly.
    expect(queryCallCount).toBe(1);

    // The operational signal survives: both the original trigger WARN and
    // the one bounded echo from ingest()'s own failed attempt reach the
    // dashboard event stream (stdout is unconditional and untouched by this
    // guard either way) — nothing is silently dropped, only the recursive
    // amplification is suppressed.
    const circuitOpenLogs = logged.filter((r) => r.eventType === 'PG_CIRCUIT_OPEN');
    expect(circuitOpenLogs.length).toBe(2);
    expect(circuitOpenLogs[0].label).toBe('some_real_caller');
  });

  it('also bounds the adjacent PG_QUERY_ERROR-during-self-logging path (a real, non-breaker query failure)', async () => {
    let queryCallCount = 0;
    jest.doMock(POOL_PATH, () => ({
      isEnabled: jest.fn(() => true),
      query: jest.fn(async (sql, params, label) => {
        queryCallCount++;
        // Mirrors pool.js query()'s real catch-block branch: a genuine
        // (non-circuit-breaker) query failure also emits synchronously
        // before rethrowing.
        const err = new Error('relation "platform_audit_events" does not exist');
        logger.emit('ERROR', 'PG_QUERY_ERROR', { label, error: err.message, code: null });
        throw err;
      }),
    }));
    pool  = require(POOL_PATH);
    store = require(STORE_PATH);
    logger.registerCentralStore(store);

    expect(() => {
      logger.emit('ERROR', 'PG_QUERY_ERROR', { label: 'some_real_caller', error: 'boom', code: null });
    }).not.toThrow();

    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    await store.flush(); // (step 5)

    expect(queryCallCount).toBe(1);
  });

  it('does not suppress a second, independent, non-nested top-level ingest() — no regression to ordinary concurrent logging', async () => {
    const inserted = [];
    const insertedParams = [];
    jest.doMock(POOL_PATH, () => ({
      isEnabled: jest.fn(() => true),
      query: jest.fn(async (sql, params, label) => {
        inserted.push(label);
        insertedParams.push(params);
        return { rows: [], rowCount: 1 };
      }),
    }));
    pool  = require(POOL_PATH);
    store = require(STORE_PATH);
    logger.registerCentralStore(store);

    // Two ordinary, sequential (not nested/recursive) top-level events —
    // the guard is only ever held during the narrow synchronous window of
    // a single ingest() call's own pgPool.query() invocation, cleared
    // before that call's own await, so a second independent call must
    // proceed normally.
    logger.emit('INFO', 'GATEWAY_ALLOW', { requestId: 'r1' });
    logger.emit('INFO', 'GATEWAY_ALLOW', { requestId: 'r2' });

    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    await store.flush();

    // (step 5): both independent events are persisted — as two ROWS of one batched INSERT (was two INSERTs).
    // The property under test is unchanged: the second, non-nested event is not suppressed.
    expect(inserted).toEqual(['audit_store_ingest']);
    expect(insertedParams[0]).toHaveLength(2 * 19); // two rows, 19 bound parameters each
    const payloads = insertedParams[0].filter((v) => typeof v === 'string' && v.startsWith('{'));
    expect(payloads.some((j) => JSON.parse(j).requestId === 'r1')).toBe(true);
    expect(payloads.some((j) => JSON.parse(j).requestId === 'r2')).toBe(true);
  });
});
