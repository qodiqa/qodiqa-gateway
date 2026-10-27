'use strict';

/** — write-capable scripts need an explicit, non-LIVE PostgreSQL target. */

const { assertExplicitNonLiveTarget, checkPgTarget } = require('../liveTargetGuard');

describe('liveTargetGuard', () => {
  test('LT-01 unset host/port is refused (no implicit localhost:5432)', () => {
    expect(() => assertExplicitNonLiveTarget('x.js', {})).toThrow(expect.objectContaining({ code: 'PG_TARGET_NOT_EXPLICIT' }));
    expect(() => assertExplicitNonLiveTarget('x.js', { QODIQA_PG_HOST: 'localhost' })).toThrow(expect.objectContaining({ code: 'PG_TARGET_NOT_EXPLICIT' }));
  });
  test('LT-02 the standard LIVE port is refused even when explicit', () => {
    expect(() => assertExplicitNonLiveTarget('x.js', { QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '5432' })).toThrow(expect.objectContaining({ code: 'PG_TARGET_IS_LIVE_PORT' }));
  });
  test('LT-03 an explicit non-LIVE port passes; CI and the inline allow flag pass', () => {
    expect(checkPgTarget({ QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '55710' }).ok).toBe(true);
    expect(checkPgTarget({ CI: 'true' }).ok).toBe(true);
    expect(checkPgTarget({ QODIQA_ALLOW_LIVE_TARGET: 'true', QODIQA_PG_HOST: 'h', QODIQA_PG_PORT: '5432' }).ok).toBe(true);
  });
  test('LT-04 the refusal message tells the operator how to proceed deliberately', () => {
    try { assertExplicitNonLiveTarget('seed.js', {}); } catch (e) { expect(e.message).toMatch(/QODIQA_ALLOW_LIVE_TARGET=true/); return; }
    throw new Error('expected a throw');
  });
});
