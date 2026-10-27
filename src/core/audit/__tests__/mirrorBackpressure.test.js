'use strict';

/**
 * 2026-10-06 — audit mirror backlog bound (src/core/audit/mirrorBackpressure.js, wired in audit-log.js).
 *
 *   MB-01  engages exactly at maxDepth, stays engaged until the backlog drains to half (hysteresis, no flapping)
 *   MB-02  env: QODIQA_AUDIT_MIRROR_MAX_DEPTH honoured; invalid/too-small values fall back to the 20,000 default
 *   MB-03  audit-log exports the probe admission and GET /ready read, idle (not engaged) at load
 */

const { createLatch, maxDepthFromEnv, DEFAULT_MAX_DEPTH } = require('../mirrorBackpressure');

describe('audit mirror back-pressure latch', () => {
  test('MB-01 hysteresis: engage at max, release only at half', () => {
    const l = createLatch(1000);
    expect(l.resumeDepth).toBe(500);
    expect(l.update(999)).toBeNull(); expect(l.engaged()).toBe(false);
    expect(l.update(1000)).toBe('engaged'); expect(l.engaged()).toBe(true);
    expect(l.update(1200)).toBeNull();
    expect(l.update(700)).toBeNull(); expect(l.engaged()).toBe(true); // below max but above resume: still engaged
    expect(l.update(999)).toBeNull();
    expect(l.update(500)).toBe('released'); expect(l.engaged()).toBe(false);
    expect(l.update(900)).toBeNull(); expect(l.engaged()).toBe(false);
  });

  test('MB-02 env parsing', () => {
    expect(DEFAULT_MAX_DEPTH).toBe(20_000);
    expect(maxDepthFromEnv({})).toBe(20_000);
    expect(maxDepthFromEnv({ QODIQA_AUDIT_MIRROR_MAX_DEPTH: '5000' })).toBe(5000);
    for (const bad of ['', 'abc', '99', '-1', '1.5', '0']) {
      expect(maxDepthFromEnv({ QODIQA_AUDIT_MIRROR_MAX_DEPTH: bad })).toBe(20_000);
    }
  });

  test('MB-03 audit-log exposes the probe and starts disengaged', () => {
    const auditLog = require('../audit-log');
    expect(auditLog.mirrorBackpressureEngaged()).toBe(false);
    expect(auditLog.mirrorBackpressureConfig()).toEqual({ maxDepth: 20_000, resumeDepth: 10_000 });
  });
});
