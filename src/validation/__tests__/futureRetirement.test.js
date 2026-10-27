'use strict';

// key-file public metadata is unauthenticated: a writer of keys.json
// WITHOUT the KEK can add a 'deprecated' record (public key only) with a far-future retiredAt, and before this fix
// checkExecution() accepted artifacts signed by that key until retiredAt + 65 s, i.e. indefinitely.
// A genuine retirement is stamped at rotation time and is never in the verifier's future beyond the 5 s skew tolerance.

const { checkExecution, DEPRECATED_WINDOW_MS } = require('../keyLifecycle');
const { FUTURE_SKEW_MS } = require('../timeCheck');

const NOW = Date.parse('2026-10-09T12:00:00.000Z');
const iso = (ms) => new Date(ms).toISOString();

describe('deprecated key with a future retirement time', () => {
  test('DD025-01 injected deprecated key with retiredAt one year ahead → refused (pre-fix: valid)', () => {
    const t = { status: 'deprecated', activatedAt: iso(NOW - 86_400_000), deprecatedAt: iso(NOW + 365 * 86_400_000) };
    const r = checkExecution(t, NOW - 1_000, NOW);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('KEY_DEPRECATED');
    expect(r.details.issue).toBe('retirement time is in the future');
  });

  test('DD025-02 boundary: retiredAt up to the 5 s future-skew tolerance still honours the rotation window', () => {
    const t = { status: 'deprecated', deprecatedAt: iso(NOW + FUTURE_SKEW_MS) };
    expect(checkExecution(t, NOW - 1, NOW)).toEqual({ valid: true });
    expect(checkExecution({ status: 'deprecated', deprecatedAt: iso(NOW + FUTURE_SKEW_MS + 1) }, NOW - 1, NOW).details.issue).toBe('retirement time is in the future');
  });

  test('DD025-03 a genuine rotation (retiredAt <= now) is unchanged: valid inside the 65 s window, refused after', () => {
    const t = { status: 'deprecated', deprecatedAt: iso(NOW) };
    expect(checkExecution(t, NOW - 1, NOW + 1_000)).toEqual({ valid: true });
    expect(checkExecution(t, NOW - 1, NOW + DEPRECATED_WINDOW_MS).details.issue).toBe('deprecated-key window elapsed');
  });
});
