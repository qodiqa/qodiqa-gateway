'use strict';

/**
 * reconnectStrategy.js coverage (bounded retry, exponential
 * backoff, jitter, circuit breaking).
 *
 *   RS-01  Delay grows exponentially with retries, bounded by maxDelayMs
 *   RS-02  Jitter perturbs the delay within ± jitterRatio of the exponential value
 *   RS-03  Zero jitterRatio produces the exact exponential value (deterministic)
 *   RS-04  Returns false once maxAttempts is reached (circuit opens)
 *   RS-05  onExhausted fires exactly once when the circuit opens
 *   RS-06  Circuit stays open (keeps returning false) during the cooldown window
 *   RS-07  Circuit resets and allows a fresh attempt cycle after cooldown elapses
 *   RS-08  onRetry fires on every non-exhausted attempt with the computed delay
 *   RS-09  Delay is never less than 1ms even with extreme negative jitter
 */

const { createBoundedReconnectStrategy, createInfiniteReconnectStrategy } = require('../reconnectStrategy');

describe('reconnectStrategy', () => {
  test('RS-01 delay grows exponentially, bounded by maxDelayMs', () => {
    const strategy = createBoundedReconnectStrategy({
      source: 'test', maxAttempts: 10, baseDelayMs: 100, maxDelayMs: 800, jitterRatio: 0,
    });
    expect(strategy(0)).toBe(100);
    expect(strategy(1)).toBe(200);
    expect(strategy(2)).toBe(400);
    expect(strategy(3)).toBe(800);
    expect(strategy(4)).toBe(800); // capped
  });

  test('RS-02 jitter perturbs the delay within ± jitterRatio of the exponential value', () => {
    // _random forced to 1 -> maximum positive jitter: exponential + jitterSpan
    const strategyMax = createBoundedReconnectStrategy({
      source: 'test', maxAttempts: 10, baseDelayMs: 100, maxDelayMs: 2000, jitterRatio: 0.2,
      _random: () => 1,
    });
    expect(strategyMax(0)).toBe(120); // 100 + 100*0.2

    // _random forced to 0 -> maximum negative jitter: exponential - jitterSpan
    const strategyMin = createBoundedReconnectStrategy({
      source: 'test', maxAttempts: 10, baseDelayMs: 100, maxDelayMs: 2000, jitterRatio: 0.2,
      _random: () => 0,
    });
    expect(strategyMin(0)).toBe(80); // 100 - 100*0.2
  });

  test('RS-03 zero jitterRatio produces the exact exponential value deterministically', () => {
    const strategy = createBoundedReconnectStrategy({
      source: 'test', maxAttempts: 10, baseDelayMs: 100, maxDelayMs: 2000, jitterRatio: 0, _random: () => Math.random(),
    });
    expect(strategy(1)).toBe(200);
    expect(strategy(1)).toBe(200); // stable regardless of _random
  });

  test('RS-04 returns false once maxAttempts is reached', () => {
    const strategy = createBoundedReconnectStrategy({ source: 'test', maxAttempts: 3, jitterRatio: 0 });
    expect(strategy(0)).not.toBe(false);
    expect(strategy(1)).not.toBe(false);
    expect(strategy(2)).not.toBe(false);
    expect(strategy(3)).toBe(false);
  });

  test('RS-05 onExhausted fires exactly once when the circuit opens', () => {
    const onExhausted = jest.fn();
    const strategy = createBoundedReconnectStrategy({ source: 'nonce', maxAttempts: 2, onExhausted });
    strategy(0);
    strategy(2); // exhausted
    expect(onExhausted).toHaveBeenCalledTimes(1);
    expect(onExhausted).toHaveBeenCalledWith({ source: 'nonce', retries: 2 });
  });

  test('RS-06 circuit stays open during the cooldown window', () => {
    let now = 1_000_000;
    const strategy = createBoundedReconnectStrategy({
      source: 'test', maxAttempts: 1, circuitBreakerCooldownMs: 30_000, _now: () => now,
    });
    expect(strategy(1)).toBe(false); // opens circuit at now=1_000_000
    now += 10_000; // still within cooldown
    expect(strategy(0)).toBe(false);
    now += 15_000; // 25s elapsed — still within 30s cooldown
    expect(strategy(0)).toBe(false);
  });

  test('RS-07 circuit resets and allows a fresh attempt cycle after cooldown elapses', () => {
    let now = 1_000_000;
    const strategy = createBoundedReconnectStrategy({
      source: 'test', maxAttempts: 1, baseDelayMs: 100, jitterRatio: 0, circuitBreakerCooldownMs: 30_000, _now: () => now,
    });
    expect(strategy(1)).toBe(false); // opens circuit
    now += 30_001; // cooldown elapsed
    expect(strategy(0)).toBe(100); // fresh cycle — first attempt succeeds again
  });

  test('RS-08 onRetry fires on every non-exhausted attempt with the computed delay', () => {
    const onRetry = jest.fn();
    const strategy = createBoundedReconnectStrategy({
      source: 'anomaly', maxAttempts: 5, baseDelayMs: 100, jitterRatio: 0, onRetry,
    });
    strategy(0);
    strategy(1);
    expect(onRetry).toHaveBeenCalledTimes(2);
    expect(onRetry).toHaveBeenNthCalledWith(1, { source: 'anomaly', retries: 0, delayMs: 100 });
    expect(onRetry).toHaveBeenNthCalledWith(2, { source: 'anomaly', retries: 1, delayMs: 200 });
  });

  test('RS-09 delay is never less than 1ms even with extreme negative jitter', () => {
    const strategy = createBoundedReconnectStrategy({
      source: 'test', maxAttempts: 10, baseDelayMs: 1, maxDelayMs: 1, jitterRatio: 1, _random: () => 0,
    });
    expect(strategy(0)).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// createInfiniteReconnectStrategy (single-instance stores: rate-limit,
// nonce, anomaly, idempotency). Unlike createBoundedReconnectStrategy above,
// this NEVER returns false — that's the whole point of the fix.
//
//   IRS-01  Never returns false, however high retries climbs
//   IRS-02 Matches the earlier curve for the first ~4 retries (jitterRatio 0)
//   IRS-03  Past the old 2000ms cap, delay keeps climbing to the higher maxDelayMs
//   IRS-04  Jitter is clamped — delay never exceeds maxDelayMs even at max positive jitter
//   IRS-05  pastOldThreshold is false below oldMaxReconnects, true at/above it
//   IRS-06  onRetry fires on every call, including past the old threshold
//   IRS-07  throws if opts.source is omitted
//   IRS-08  delay is never less than 1ms even with extreme negative jitter
// ═══════════════════════════════════════════════════════════════════════════

describe('createInfiniteReconnectStrategy', () => {
  test('IRS-01 never returns false, however high retries climbs', () => {
    const strategy = createInfiniteReconnectStrategy({ source: 'test', jitterRatio: 0 });
    for (const retries of [0, 1, 5, 20, 100, 10_000]) {
      expect(strategy(retries)).not.toBe(false);
      expect(typeof strategy(retries)).toBe('number');
    }
  });

  test('IRS-02 matches the earlier curve for the first ~4 retries', () => {
    // Pre-F5 stores all used: Math.min(100 * 2^retries, 2000)
    const strategy = createInfiniteReconnectStrategy({ source: 'test', baseDelayMs: 100, maxDelayMs: 30_000, jitterRatio: 0 });
    expect(strategy(0)).toBe(100);
    expect(strategy(1)).toBe(200);
    expect(strategy(2)).toBe(400);
    expect(strategy(3)).toBe(800);
    expect(strategy(4)).toBe(1600);
  });

  test('IRS-03 past the old 2000ms cap, delay keeps climbing to the higher maxDelayMs instead of flat-lining', () => {
    const strategy = createInfiniteReconnectStrategy({ source: 'test', baseDelayMs: 100, maxDelayMs: 30_000, jitterRatio: 0 });
    expect(strategy(5)).toBe(3200);   // old strategy would have already given up (false) here
    expect(strategy(8)).toBe(25_600);
    expect(strategy(9)).toBe(30_000); // capped at the new, higher ceiling
    expect(strategy(50)).toBe(30_000); // stays capped, never exceeds it
  });

  test('IRS-04 jitter is clamped — delay never exceeds maxDelayMs even at max positive jitter', () => {
    const strategy = createInfiniteReconnectStrategy({
      source: 'test', baseDelayMs: 100, maxDelayMs: 30_000, jitterRatio: 0.2, _random: () => 1,
    });
    // retries=9 -> exponential = 30_000 already; +20% jitter would be 36_000 unclamped
    expect(strategy(9)).toBe(30_000);
  });

  test('IRS-05 pastOldThreshold is false below oldMaxReconnects, true at/above it', () => {
    const onRetry = jest.fn();
    const strategy = createInfiniteReconnectStrategy({ source: 'test', oldMaxReconnects: 5, jitterRatio: 0, onRetry });
    strategy(4);
    strategy(5);
    expect(onRetry).toHaveBeenNthCalledWith(1, expect.objectContaining({ retries: 4, pastOldThreshold: false }));
    expect(onRetry).toHaveBeenNthCalledWith(2, expect.objectContaining({ retries: 5, pastOldThreshold: true }));
  });

  test('IRS-06 onRetry fires on every call, including well past the old threshold', () => {
    const onRetry = jest.fn();
    const strategy = createInfiniteReconnectStrategy({ source: 'nonce', oldMaxReconnects: 5, jitterRatio: 0, onRetry });
    [0, 1, 2, 3, 4, 5, 6, 50].forEach(r => strategy(r));
    expect(onRetry).toHaveBeenCalledTimes(8);
    expect(onRetry).toHaveBeenLastCalledWith({ source: 'nonce', retries: 50, delayMs: 30_000, pastOldThreshold: true });
  });

  test('IRS-07 throws if opts.source is omitted', () => {
    expect(() => createInfiniteReconnectStrategy({})).toThrow(/source is required/);
  });

  test('IRS-08 delay is never less than 1ms even with extreme negative jitter', () => {
    const strategy = createInfiniteReconnectStrategy({
      source: 'test', baseDelayMs: 1, maxDelayMs: 1, jitterRatio: 1, _random: () => 0,
    });
    expect(strategy(0)).toBeGreaterThanOrEqual(1);
  });
});
