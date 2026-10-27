'use strict';

/** pre-auth rejects: counter always, sampled WARN log, bounded memory. */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { emit } = require('../../../../services/logger');
const metrics = require('../../../observability/metrics');
const pre = require('../preAuthRejects');

const warnCount = (type) => emit.mock.calls.filter((c) => c[1] === type).length;
function counterValue(labels) {
  const c = metrics.preAuthRejectsTotal;
  for (const [k, v] of c._values) {
    const l = c._labelsByKey.get(k) || {};
    if (l.reason === labels.reason && l.route === labels.route) return v;
  }
  return 0;
}

beforeEach(() => { emit.mockClear(); pre._resetForTest(); });

test('every reject increments qodiqa_preauth_rejects_total{reason,route}', async () => {
  const before = counterValue({ reason: 'MISSING_ARTIFACT', route: '/ai/chat' });
  for (let i = 0; i < 250; i++) pre.recordPreAuthReject({ route: '/ai/chat', reason: 'MISSING_ARTIFACT', clientIp: '198.51.100.7' });
  expect(counterValue({ reason: 'MISSING_ARTIFACT', route: '/ai/chat' })).toBe(before + 250);
});

test('logging is sampled: first 10 per (reason, IP) per minute, then every 100th', () => {
  for (let i = 0; i < 250; i++) pre.recordPreAuthReject({ route: '/ai/chat', reason: 'ARTIFACT_INVALID', clientIp: '198.51.100.8' });
  expect(warnCount('PREAUTH_REJECT')).toBe(pre.SAMPLE_FIRST + 2); // 1..10, 100, 200
});

test('distinct sources are sampled independently', () => {
  for (const ip of ['a', 'b', 'c']) for (let i = 0; i < 20; i++) pre.recordPreAuthReject({ reason: 'X', clientIp: ip });
  expect(warnCount('PREAUTH_REJECT')).toBe(30);
});

test('suppressed volume is summarised when the window rolls', () => {
  jest.useFakeTimers({ now: Date.parse('2026-09-28T00:00:00Z') });
  try {
    pre._resetForTest();
    for (let i = 0; i < 50; i++) pre.recordPreAuthReject({ reason: 'Y', clientIp: 'z' });
    jest.setSystemTime(Date.parse('2026-09-28T00:01:01Z'));
    pre.recordPreAuthReject({ reason: 'Y', clientIp: 'z' });
    const s = emit.mock.calls.find((c) => c[1] === 'PREAUTH_REJECTS_SUPPRESSED');
    expect(s[2]).toMatchObject({ suppressed: 40 });
  } finally { jest.useRealTimers(); }
});

test('source tracking is bounded (MAX_KEYS); overflow is counted, not stored', () => {
  for (let i = 0; i < pre.MAX_KEYS + 5; i++) pre.recordPreAuthReject({ reason: 'Z', clientIp: `ip${i}` });
  expect(warnCount('PREAUTH_REJECT')).toBe(pre.MAX_KEYS);
});

test('details are carried on the sampled event', () => {
  pre.recordPreAuthReject({ reason: 'INPUT_GUARD', clientIp: 'q', details: { unsupportedFields: ['temperature'] } });
  expect(emit.mock.calls[0][2]).toMatchObject({ reason: 'INPUT_GUARD', details: { unsupportedFields: ['temperature'] } });
});
