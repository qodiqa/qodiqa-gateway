'use strict';

/**
 * (step 5) — platform_audit_events batched writer (src/core/audit/centralStore.js).
 *
 * BW-01 ingest() issues no query; flush() writes all buffered rows as ONE multi-row INSERT, 19 params per row,
 *          same per-row parameter order as the former single-row INSERT
 *   BW-02  the FLUSH_ROWS-th row triggers an immediate flush (no timer wait)
 *   BW-03  otherwise the rows are flushed by a timer after FLUSH_INTERVAL_MS
 *   BW-04  the buffer is bounded: past MAX_BUFFER_ROWS the oldest rows are dropped and ONE PLATFORM_EVENTS_DROPPED
 *          summary with the exact count is emitted
 */

const path = require('path');
const POOL_PATH   = path.resolve(__dirname, '..', '..', '..', 'infra', 'postgres', 'pool');
const STORE_PATH  = path.resolve(__dirname, '..', 'centralStore.js');
const LOGGER_PATH = path.resolve(__dirname, '..', '..', '..', '..', 'services', 'logger');

describe('platform_audit_events batched writer', () => {
  let store; let calls; let emitted;
  function load(queryImpl) {
    jest.resetModules();
    calls = []; emitted = [];
    jest.doMock(LOGGER_PATH, () => ({ emit: (level, type, payload) => emitted.push({ level, type, payload }) }));
    jest.doMock(POOL_PATH, () => ({ isEnabled: () => true, query: jest.fn((sql, params, label) => { calls.push({ sql, params, label }); return queryImpl ? queryImpl() : Promise.resolve({ rowCount: params.length / 19 }); }) }));
    store = require(STORE_PATH);
  }
  afterEach(() => { jest.useRealTimers(); jest.dontMock(POOL_PATH); jest.dontMock(LOGGER_PATH); jest.resetModules(); });

  test('BW-01 buffered, then one multi-row INSERT with the old per-row parameter order', async () => {
    load();
    await store.ingest('INFO', 'GATEWAY_ALLOW', { requestId: 'r1', decision: 'ALLOW' });
    await store.ingest('WARN', 'RBAC_DENY', { requestId: 'r2' });
    await store.ingest('ERROR', 'PG_POOL_ERROR', { error: 'x' });
    expect(calls).toHaveLength(0);
    await store.flush();
    expect(calls).toHaveLength(1);
    const { sql, params, label } = calls[0];
    expect(label).toBe('audit_store_ingest');
    expect(params).toHaveLength(3 * 19);
    expect((sql.match(/gen_random_uuid\(\)/g) || []).length).toBe(3);
    // row 2 = RBAC_DENY: [occurredAt, eventType, category, level, ...]
    expect(params.slice(19, 23).slice(1)).toEqual(['RBAC_DENY', 'SECURITY', 'WARN']);
    expect(params[1]).toBe('GATEWAY_ALLOW');
    expect(params[38 + 2]).toBe('INFRASTRUCTURE'); // row 3 starts at 2 × 19
    expect(store.batchStats()).toMatchObject({ rows: 3, flushes: 1, buffered: 0 });
  });

  test('BW-02 the FLUSH_ROWS-th row flushes immediately', async () => {
    load();
    const { flushRows } = store.batchStats();
    for (let i = 0; i < flushRows; i++) await store.ingest('INFO', 'GATEWAY_ALLOW', { i });
    await new Promise((r) => setImmediate(r));
    expect(calls).toHaveLength(1);
    expect(calls[0].params).toHaveLength(flushRows * 19);
  });

  test('BW-03 otherwise a timer flushes after FLUSH_INTERVAL_MS', async () => {
    jest.useFakeTimers();
    load();
    await store.ingest('INFO', 'GATEWAY_ALLOW', {});
    expect(calls).toHaveLength(0);
    await jest.advanceTimersByTimeAsync(store.batchStats().flushIntervalMs + 1);
    expect(calls).toHaveLength(1);
  });

  test('BW-04 bounded buffer: oldest rows dropped, one summary with the exact count', async () => {
    let release;
    load(() => new Promise((r) => { release = r; })); // PostgreSQL stalls: the first flush never returns
    const { flushRows, maxBufferRows } = store.batchStats();
    for (let i = 0; i < flushRows; i++) await store.ingest('INFO', 'E', { i }); // starts the stalled flush
    const extra = 7;
    for (let i = 0; i < maxBufferRows + extra; i++) await store.ingest('INFO', 'E', { i });
    expect(store.batchStats().buffered).toBe(maxBufferRows);
    expect(store.batchStats().droppedRows).toBe(extra);
    release({ rowCount: 0 });
    // let the stalled flush and the queued drain finish; every later INSERT resolves immediately
    for (let k = 0; k < 50 && store.batchStats().buffered > 0; k++) { if (release) { const r = release; release = null; r({ rowCount: 0 }); } await new Promise((r) => setImmediate(r)); }
    const drops = emitted.filter((e) => e.type === 'PLATFORM_EVENTS_DROPPED');
    expect(drops).toHaveLength(1);
    expect(drops[0].payload.count).toBe(extra);
  });
});
