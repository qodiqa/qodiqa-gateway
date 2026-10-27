'use strict';

/**
 * (step 5) — log-flood control (src/observability/aggregatedEmit.js).
 *
 *   AG-01  the first event per (eventType, key) per window is emitted in full; repeats are counted, not emitted
 *   AG-02  at the end of the window ONE LOG_EVENTS_AGGREGATED summary carries the exact suppressed count; the next
 *          occurrence starts a new window and is emitted in full again
 *   AG-03  different keys are independent (a second label is not hidden by the first)
 *   AG-04  a window with no repeats emits no summary
 *   AG-05  bounded state: beyond MAX_KEYS distinct keys, events pass through (never silently dropped)
 *   AG-06  a PG outage storm of 10,000 fast-failed queries on one label yields 1 event + 1 summary per window
 */

const { aggregatedEmit, WINDOW_MS, MAX_KEYS, _resetForTests } = require('../aggregatedEmit');

describe('aggregatedEmit', () => {
  let out; const emit = (level, type, payload) => out.push({ level, type, payload });
  beforeEach(() => { jest.useFakeTimers(); out = []; _resetForTests(); });
  afterEach(() => { _resetForTests(); jest.useRealTimers(); });

  test('AG-01 first in full, repeats counted', () => {
    expect(aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { label: 'q' }, 'q')).toBe(true);
    for (let i = 0; i < 5; i++) expect(aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { label: 'q' }, 'q')).toBe(false);
    expect(out).toEqual([{ level: 'WARN', type: 'PG_CIRCUIT_OPEN', payload: { label: 'q' } }]);
  });

  test('AG-02 one summary with the exact count; then a new window', () => {
    for (let i = 0; i < 6; i++) aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { label: 'q' }, 'q');
    jest.advanceTimersByTime(WINDOW_MS + 1);
    expect(out[1]).toEqual({ level: 'WARN', type: 'LOG_EVENTS_AGGREGATED', payload: { eventType: 'PG_CIRCUIT_OPEN', key: 'q', suppressed: 5, windowMs: WINDOW_MS } });
    aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { label: 'q' }, 'q');
    expect(out).toHaveLength(3);
    expect(out[2].type).toBe('PG_CIRCUIT_OPEN');
  });

  test('AG-03 keys are independent', () => {
    aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { label: 'a' }, 'a');
    aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { label: 'b' }, 'b');
    expect(out.map((e) => e.payload.label)).toEqual(['a', 'b']);
  });

  test('AG-04 no repeats, no summary', () => {
    aggregatedEmit(emit, 'ERROR', 'PG_POOL_ACQUIRE_FAILED', {}, 'X');
    jest.advanceTimersByTime(WINDOW_MS + 1);
    expect(out).toHaveLength(1);
  });

  test('AG-05 bounded state passes events through', () => {
    for (let i = 0; i < MAX_KEYS; i++) aggregatedEmit(emit, 'WARN', 'E', {}, `k${i}`);
    expect(aggregatedEmit(emit, 'WARN', 'E', { overflow: true }, 'extra')).toBe(true);
    expect(aggregatedEmit(emit, 'WARN', 'E', { overflow: true }, 'extra')).toBe(true);
    expect(out.filter((e) => e.payload.overflow)).toHaveLength(2);
  });

  test('AG-06 a 10,000-failure storm on one label: 1 event + 1 summary per window', () => {
    for (let i = 0; i < 10_000; i++) aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { label: 'consent_store_get' }, 'consent_store_get');
    jest.advanceTimersByTime(WINDOW_MS + 1);
    expect(out).toHaveLength(2);
    expect(out[1].payload.suppressed).toBe(9_999);
  });
});
