'use strict';

/**
 * Finding D — verifierConfig.js default FULL-scan interval.
 *
 * fullIntervalMs is the actual worst-case historical-tamper detection-
 * latency bound (INCREMENTAL only ever walks the tail delta — see this
 * module's header comment). Pins the new 4h default (lowered from 24h by
 *) as a permanent regression test, and confirms
 * QODIQA_AUDIT_VERIFIER_FULL_INTERVAL still overrides it in either
 * direction.
 */

describe('Finding D — verifierConfig fullIntervalMs default', () => {
  const ENV_KEYS = ['QODIQA_AUDIT_VERIFIER_FULL_INTERVAL'];
  let saved;

  beforeEach(() => {
    saved = {};
    for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
    jest.resetModules();
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  test('defaults to 4 hours (14_400_000ms) when QODIQA_AUDIT_VERIFIER_FULL_INTERVAL is unset', () => {
    const { load } = require('../verifierConfig');
    expect(load().fullIntervalMs).toBe(14_400_000);
  });

  test('QODIQA_AUDIT_VERIFIER_FULL_INTERVAL still overrides the default, e.g. back to the pre-WP-019 24h value', () => {
    process.env.QODIQA_AUDIT_VERIFIER_FULL_INTERVAL = '24h';
    const { load } = require('../verifierConfig');
    expect(load().fullIntervalMs).toBe(86_400_000);
  });

  test('QODIQA_AUDIT_VERIFIER_FULL_INTERVAL accepts a raw millisecond override tighter than the default', () => {
    process.env.QODIQA_AUDIT_VERIFIER_FULL_INTERVAL = '600000'; // 10 minutes
    const { load } = require('../verifierConfig');
    expect(load().fullIntervalMs).toBe(600_000);
  });
});
