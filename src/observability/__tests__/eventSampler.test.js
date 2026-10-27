'use strict';

/**
 * per-key event sampling, and its use on the limiter's deny
 * path: a throttled flood must not turn into one platform_audit_events row
 * (every WARN is ingested there) per request, while the counters still count
 * every 429.
 */

jest.mock('../../../services/logger', () => ({ emit: jest.fn(), eventBus: { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() } }));

const { emit } = require('../../../services/logger');
const { createEventSampler } = require('../eventSampler');

beforeEach(() => emit.mockClear());

describe('createEventSampler', () => {
  test('first 10 per key per window, then every 100th', () => {
    const s = createEventSampler({ summaryEvent: 'X_SUPPRESSED' });
    const logged = Array.from({ length: 250 }, () => s.sample('k').log).filter(Boolean).length;
    expect(logged).toBe(12);
    expect(s.sample('other').log).toBe(true);
  });

  test('suppressed volume is summarised once when the window rolls', () => {
    let t = 0; const s = createEventSampler({ summaryEvent: 'X_SUPPRESSED', now: () => t });
    for (let i = 0; i < 30; i++) s.sample('k');
    t = 61_000; s.sample('k');
    expect(emit).toHaveBeenCalledWith('WARN', 'X_SUPPRESSED', expect.objectContaining({ suppressed: 20 }));
    expect(s.sample('k').countThisWindow).toBe(2);
  });

  test('key tracking is bounded', () => {
    const s = createEventSampler({ summaryEvent: 'X', maxKeys: 5 });
    const r = Array.from({ length: 8 }, (_, i) => s.sample(`k${i}`).log);
    expect(r).toEqual([true, true, true, true, true, false, false, false]);
  });

  test('summaryEvent is required', () => {
    expect(() => createEventSampler({})).toThrow(TypeError);
  });
});

describe('limiter deny path (checkRateLimit)', () => {
  const rl = require('../../core/rateLimit');
  const metrics = require('../metrics');
  let saved;
  beforeEach(() => { saved = process.env.RL_ENABLED; process.env.RL_ENABLED = 'true'; rl._resetDegradedForTest(); });
  afterEach(() => { process.env.RL_ENABLED = saved; rl.loadConfig(); rl._resetDegradedForTest(); });

  test('200 throttled requests from one identity → ≤ 12 RATE_LIMIT_EXCEEDED events, every 429 counted', async () => {
    rl.loadConfig({ surfaces: { ai_chat_ip: { maxRequests: 1, windowSeconds: 60, failMode: 'degrade' } } });
    const limitedBefore = [...metrics.rateLimitLimitedTotal._values.values()].reduce((a, b) => a + b, 0);
    let denied = 0;
    for (let i = 0; i < 201; i++) if (!(await rl.checkRateLimit('ai_chat_ip', { identity: 'ip:198.51.100.1' })).allowed) denied++;
    expect(denied).toBe(200);
    expect(emit.mock.calls.filter((c) => c[1] === 'RATE_LIMIT_EXCEEDED').length).toBeLessThanOrEqual(12);
    const limitedAfter = [...metrics.rateLimitLimitedTotal._values.values()].reduce((a, b) => a + b, 0);
    expect(limitedAfter - limitedBefore).toBe(200);
  });
});
