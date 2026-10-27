'use strict';

/**
 * 
 *   (a) a half-open probe that ends with an outcome the breaker does not count (404, auth, cancellation, a skip, an abandoned
 *       stream) must not strand the probe slot — every later request used to be refused without contacting the provider;
 *   (b) a malformed *_TIMEOUT_MS ("abc", "1e3", "0") must not become NaN / 1 ms in the adapters.
 */

jest.mock('../../../src/infra/time/monotonicClock', () => ({ monoNowMs: () => Date.now(), wallFromMono: (m) => m || null }));
jest.mock('../../logger', () => ({ emit: jest.fn() }));

const { getCircuitBreaker, resetAll, STATE_OPEN, STATE_HALF_OPEN, STATE_CLOSED } = require('../providerCircuitBreaker');
const { resolveTimeoutMs } = require('../timeout');

const CONFIG = Object.freeze({ cbFailureThreshold: 2, cbWindowMs: 10_000, cbRecoveryMs: 5_000, cbSuccessThreshold: 1 });

function openThenHalfOpen(cb) {
  cb.onFailure(); cb.onFailure();
  expect(cb.state).toBe(STATE_OPEN);
  jest.advanceTimersByTime(5_001);
}

describe('half-open probe slot', () => {
  beforeEach(() => { resetAll(); jest.useFakeTimers(); });
  afterEach(() => { jest.useRealTimers(); });

  test('HO-01 releaseProbe() after an uncounted probe outcome lets the NEXT request probe again', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    openThenHalfOpen(cb);
    const p1 = cb.acquire();
    expect(p1).toMatchObject({ allowed: true, probe: true });
    expect(cb.state).toBe(STATE_HALF_OPEN);
    expect(cb.acquire().allowed).toBe(false);          // concurrent callers are still refused while the probe is in flight
    cb.releaseProbe();                                  // the probe ended with e.g. a 404 that does not count
    expect(cb.acquire()).toMatchObject({ allowed: true, probe: true }); // before the fix: refused forever
    cb.onSuccess();
    expect(cb.state).toBe(STATE_CLOSED);
  });

  test('HO-02 a probe that never reports (lost) is treated as lost after cbRecoveryMs', () => {
    const cb = getCircuitBreaker('anthropic', CONFIG);
    openThenHalfOpen(cb);
    expect(cb.acquire().probe).toBe(true);
    jest.advanceTimersByTime(4_000);
    expect(cb.acquire().allowed).toBe(false);
    jest.advanceTimersByTime(1_500);
    expect(cb.acquire()).toMatchObject({ allowed: true, probe: true });
  });

  test('HO-03 releaseProbe() is a no-op when CLOSED/OPEN (cannot free another caller\'s slot)', () => {
    const cb = getCircuitBreaker('gemini', CONFIG);
    cb.releaseProbe();
    expect(cb.state).toBe(STATE_CLOSED);
    cb.onFailure(); cb.onFailure();
    cb.releaseProbe();
    expect(cb.state).toBe(STATE_OPEN);
    expect(cb.acquire().allowed).toBe(false);
  });

  test('HO-04 allowRequest() keeps its boolean contract', () => {
    const cb = getCircuitBreaker('mistral', CONFIG);
    expect(cb.allowRequest()).toBe(true);
  });
});

describe('resolveTimeoutMs', () => {
  const E = (v) => ({ X_TIMEOUT_MS: v });
  test('TO-01 plain positive integers are accepted', () => {
    expect(resolveTimeoutMs('X_TIMEOUT_MS', 30000, E('45000'))).toBe(45000);
    expect(resolveTimeoutMs('X_TIMEOUT_MS', 30000, E(' 1500 '))).toBe(1500);
  });
  test('TO-02 unset or empty falls back silently', () => {
    expect(resolveTimeoutMs('X_TIMEOUT_MS', 30000, {})).toBe(30000);
    expect(resolveTimeoutMs('X_TIMEOUT_MS', 30000, E(''))).toBe(30000);
  });
  test('TO-03 "abc", "1e3", "0", "-5", "12ms", "1.5" fall back to the default (were NaN or 1 ms)', () => {
    for (const bad of ['abc', '1e3', '0', '-5', '12ms', '1.5', 'NaN', '99999999999']) {
      expect(resolveTimeoutMs('X_TIMEOUT_MS', 30000, E(bad))).toBe(30000);
    }
  });
});
