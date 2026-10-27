'use strict';

/**
 * follow-up: monotonic stamps that a status / health object exposes (breaker `openedAt`, control-plane
 * `lastSyncOkAt`) are reported as their WALL-clock equivalent, never as the raw monotonic value.
 *
 *   WFM-01  null / 0 stay null
 *   WFM-02  with no wall step, the equivalent of "now" is Date.now()
 *   WFM-03  after a +120 s wall step, a stamp taken 50 ms earlier reports wall-now − 50 ms (it follows the wall clock),
 *           while the raw monotonic stamp would be ~120 s away from it
 */

const { monoNowMs, wallFromMono } = require('../monotonicClock');

describe('wallFromMono', () => {
  afterEach(() => jest.restoreAllMocks());

  test('WFM-01 null and 0 stay null', () => {
    expect(wallFromMono(null)).toBe(null);
    expect(wallFromMono(0)).toBe(null);
  });

  test('WFM-02 the equivalent of a fresh stamp is the current wall time', () => {
    const before = Date.now();
    const w = wallFromMono(monoNowMs());
    expect(w).toBeGreaterThanOrEqual(before - 2);
    expect(w).toBeLessThanOrEqual(Date.now() + 2);
  });

  test('WFM-03 after a +120 s wall step the exposed value follows the wall clock', async () => {
    const stamp = monoNowMs();
    await new Promise((r) => setTimeout(r, 50));
    const realNow = Date.now.bind(Date);
    // closure round 2026-10-12: the wall clock and the monotonic clock are NOT identical even before the step — their
    // offset (V8's periodic Date.now() re-sync, timeOrigin flooring, process uptime drift) is a few ms and was measured
    // at 6 ms in one gate run, failing the former fixed "<= 5" bound about 1 run in 5. The property under test is the
    // +120 s STEP, so it is asserted relative to the offset measured just before the step (same bound as the line above).
    const skew = realNow() - monoNowMs();
    jest.spyOn(Date, 'now').mockImplementation(() => realNow() + 120_000);
    const exposed = wallFromMono(stamp);
    const elapsed = monoNowMs() - stamp;
    expect(Math.abs(exposed - (Date.now() - elapsed))).toBeLessThanOrEqual(2);
    expect(Math.abs(exposed - stamp - 120_000 - skew)).toBeLessThanOrEqual(2); // the raw stamp is 120 s (+ the pre-step offset) behind
  });
});
