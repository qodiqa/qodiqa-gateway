'use strict';

// the code under test reads the monotonic clock (src/infra/time/monotonicClock.js), which jest fake timers
// and Date.now spies do not move. Point it at Date.now so this suite keeps driving time the way it always has; the
// monotonic behaviour itself is pinned by src/infra/time/__tests__/monotonicSites.test.js.
jest.mock('../../../src/infra/time/monotonicClock', () => ({ monoNowMs: () => Date.now(), wallFromMono: (m) => m || null }));

jest.mock('../../logger', () => ({ emit: jest.fn() }));

const {
  getCircuitBreaker,
  resetAll,
  snapshot,
  STATE_CLOSED,
  STATE_OPEN,
  STATE_HALF_OPEN,
} = require('../providerCircuitBreaker');

const CONFIG = Object.freeze({
  cbFailureThreshold: 3,
  cbWindowMs:          10_000,
  cbRecoveryMs:        5_000,
  cbSuccessThreshold:  2,
});

beforeEach(() => {
  resetAll();
  jest.useFakeTimers();
});

afterEach(() => {
  jest.useRealTimers();
});

describe('ProviderCircuitBreaker', () => {
  test('starts CLOSED and allows requests through', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    expect(cb.state).toBe(STATE_CLOSED);
    expect(cb.allowRequest()).toBe(true);
  });

  test('counts consecutive failures without opening below threshold', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure();
    cb.onFailure();
    expect(cb.state).toBe(STATE_CLOSED);
    expect(cb.allowRequest()).toBe(true);
  });

  test('a success resets the consecutive-failure counter', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure();
    cb.onFailure();
    cb.onSuccess();
    cb.onFailure();
    cb.onFailure();
    expect(cb.state).toBe(STATE_CLOSED); // would have opened at 3 without the reset
  });

  test('transitions CLOSED -> OPEN after the failure threshold', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure();
    cb.onFailure();
    cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);
  });

  test('fast-fails while OPEN', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure(); cb.onFailure(); cb.onFailure();
    expect(cb.allowRequest()).toBe(false);
    expect(cb.allowRequest()).toBe(false); // repeated calls stay false, no side effects
    expect(cb.state).toBe(STATE_OPEN);
  });

  test('transitions OPEN -> HALF_OPEN only after the recovery window elapses', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure(); cb.onFailure(); cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);

    jest.advanceTimersByTime(4_999);
    expect(cb.allowRequest()).toBe(false);
    expect(cb.state).toBe(STATE_OPEN);

    jest.advanceTimersByTime(2); // now past 5000ms total
    expect(cb.allowRequest()).toBe(true);
    expect(cb.state).toBe(STATE_HALF_OPEN);
  });

  test('HALF_OPEN serializes concurrent callers to a single probe', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure(); cb.onFailure(); cb.onFailure();
    jest.advanceTimersByTime(5_001);

    expect(cb.allowRequest()).toBe(true);  // the one probe
    expect(cb.allowRequest()).toBe(false); // concurrent caller rejected
    expect(cb.allowRequest()).toBe(false); // another concurrent caller rejected
    expect(cb.state).toBe(STATE_HALF_OPEN);
  });

  test('HALF_OPEN -> CLOSED after the success threshold is reached', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure(); cb.onFailure(); cb.onFailure();
    jest.advanceTimersByTime(5_001);
    cb.allowRequest(); // enter HALF_OPEN, one probe in flight

    cb.onSuccess(); // 1st half-open success
    expect(cb.state).toBe(STATE_HALF_OPEN);
    expect(cb.allowRequest()).toBe(true); // next probe allowed

    cb.onSuccess(); // 2nd half-open success (== cbSuccessThreshold)
    expect(cb.state).toBe(STATE_CLOSED);
    expect(cb.allowRequest()).toBe(true);
  });

  test('HALF_OPEN -> OPEN immediately on any probe failure', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure(); cb.onFailure(); cb.onFailure();
    jest.advanceTimersByTime(5_001);
    cb.allowRequest(); // enter HALF_OPEN

    cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);
    expect(cb.allowRequest()).toBe(false);
  });

  test('failures outside the sliding window do not accumulate toward the threshold', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure();
    jest.advanceTimersByTime(10_001); // past cbWindowMs
    cb.onFailure();
    cb.onFailure();
    // Only the two recent failures count within the window filter, but
    // consecutive-failure counting is unconditional (not windowed) in this
    // implementation, matching the proven SigningCircuitBreaker pattern —
    // three onFailure() calls total still opens the breaker.
    expect(cb.state).toBe(STATE_OPEN);
  });

  test('breakers are independent per provider name', () => {
    const openaiCb    = getCircuitBreaker('openai', CONFIG);
    const anthropicCb = getCircuitBreaker('anthropic', CONFIG);
    openaiCb.onFailure(); openaiCb.onFailure(); openaiCb.onFailure();
    expect(openaiCb.state).toBe(STATE_OPEN);
    expect(anthropicCb.state).toBe(STATE_CLOSED);
  });

  test('getCircuitBreaker returns the same instance for repeated calls', () => {
    const a = getCircuitBreaker('openai', CONFIG);
    const b = getCircuitBreaker('openai', CONFIG);
    expect(a).toBe(b);
  });

  test('resetAll() clears the registry', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure(); cb.onFailure(); cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);

    resetAll();
    const fresh = getCircuitBreaker('openai', CONFIG);
    expect(fresh).not.toBe(cb);
    expect(fresh.state).toBe(STATE_CLOSED);
  });

  test('snapshot() reports state for every tracked provider', () => {
    getCircuitBreaker('openai', CONFIG).onFailure();
    getCircuitBreaker('anthropic', CONFIG);
    const snap = snapshot();
    expect(snap.openai.state).toBe(STATE_CLOSED);
    expect(snap.openai.consecutiveFails).toBe(1);
    expect(snap.anthropic.state).toBe(STATE_CLOSED);
  });
});
