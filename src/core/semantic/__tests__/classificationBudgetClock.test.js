'use strict';

/**
 * the classification budget and clock steps.
 *   CB-01  a backward step of the budget's clock never drains the bucket (elapsed floored at 0)
 *   CB-02  the default clock is the monotonic clock: a wall-clock step (Date.now jumping back 120 s) changes nothing
 */

const { createBudget } = require('../classificationBudget');

describe('classification budget under clock steps', () => {
  test('CB-01 a backward step never drains the bucket', () => {
    let t = 1_000_000; const b = createBudget({ refillPerSec: 2000, burst: 20_000, now: () => t });
    expect(b.take('x', 10).ok).toBe(true);
    t -= 120_000;                                   // the clock steps back 120 s
    const r = b.take('x', 10);
    expect(r.ok).toBe(true);
    expect(r.remaining).toBe(20_000 - 20);          // was: 20,000 − 10 − 240,000 → refused for 120 s
  });

  test('CB-02 the default clock ignores wall-clock steps', () => {
    const b = createBudget({ refillPerSec: 2000, burst: 20_000 });
    expect(b.take('y', 10).ok).toBe(true);
    const real = Date.now;
    Date.now = () => real() - 120_000;
    try { expect(b.take('y', 10).ok).toBe(true); } finally { Date.now = real; }
  });
});
