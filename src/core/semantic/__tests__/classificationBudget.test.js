'use strict';

/**
 * classification budget unit contract (../classificationBudget.js).
 *
 *   CB-02  take(): within the bucket → ok and debited; beyond → refused with Retry-After = seconds to refill
 *   CB-03  refill over time up to the burst, never above it
 *   CB-04  charge() never refuses and bounds the debt at −burst; a tenant in debt is refused until refilled
 *   CB-05  tenants are independent
 *   CB-06  a maximum-size prompt (32,768 chars = 94 windows) fits the default burst many times over
 */

const { windowsForLength, createBudget, BURST } = require('../classificationBudget');

describe('classification budget', () => {
  test('CB-01 window count', () => {
    expect([0, 1, 400].map(windowsForLength)).toEqual([1, 1, 1]);
    expect(windowsForLength(401)).toBe(2);
    expect(windowsForLength(750)).toBe(2);
    expect(windowsForLength(751)).toBe(3);
    expect(windowsForLength(32_768)).toBe(94);
  });

  test('CB-02 take within / beyond the bucket', () => {
    let t = 0; const b = createBudget({ refillPerSec: 10, burst: 20, now: () => t });
    expect(b.take('a', 15)).toMatchObject({ ok: true, remaining: 5 });
    const r = b.take('a', 9);
    expect(r).toMatchObject({ ok: false, retryAfterSeconds: 1 });
    expect(b.peek('a')).toBe(5); // a refusal debits nothing
  });

  test('CB-03 refill up to the burst', () => {
    let t = 0; const b = createBudget({ refillPerSec: 10, burst: 20, now: () => t });
    b.take('a', 20);
    t = 1000; expect(b.peek('a')).toBe(10);
    t = 10_000; expect(b.peek('a')).toBe(20);
  });

  test('CB-04 charge never refuses; debt bounded; a tenant in debt is refused until refilled', () => {
    let t = 0; const b = createBudget({ refillPerSec: 10, burst: 20, now: () => t });
    expect(b.charge('a', 1000)).toEqual({ remaining: -20 });
    expect(b.take('a', 1).ok).toBe(false);
    t = 4000; // +40 → 20
    expect(b.take('a', 1).ok).toBe(true);
  });

  test('CB-05 tenants are independent', () => {
    let t = 0; const b = createBudget({ refillPerSec: 1, burst: 3, now: () => t });
    b.take('a', 3);
    expect(b.take('a', 1).ok).toBe(false);
    expect(b.take('b', 3).ok).toBe(true);
  });

  test('CB-06 the default burst holds many maximum-size prompts', () => {
    expect(Math.floor(BURST / windowsForLength(32_768))).toBeGreaterThanOrEqual(200);
  });
});
