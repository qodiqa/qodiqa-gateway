'use strict';

const { createSampler } = require('../sampler');

describe('createSampler', () => {
  it('rate 1.0 always returns true', () => {
    const s = createSampler(1.0);
    expect(s.shouldSample('00000000000000000000000000000000')).toBe(true);
    expect(s.shouldSample('ffffffffffffffffffffffffffffffff')).toBe(true);
  });

  it('rate 0.0 always returns false', () => {
    const s = createSampler(0.0);
    expect(s.shouldSample('00000000000000000000000000000000')).toBe(false);
    expect(s.shouldSample('ffffffffffffffffffffffffffffffff')).toBe(false);
  });

  it('rate defaults to 1.0 for undefined', () => {
    expect(createSampler(undefined).rate).toBe(1.0);
  });

  it('rate defaults to 1.0 for out-of-range values', () => {
    expect(createSampler(2.0).rate).toBe(1.0);
    expect(createSampler(-0.1).rate).toBe(1.0);
  });

  it('rate defaults to 1.0 for non-numeric input', () => {
    expect(createSampler('half').rate).toBe(1.0);
  });

  it('deterministic: same traceId always yields same decision', () => {
    const s = createSampler(0.5);
    const id = 'abcdef0123456789abcdef0123456789';
    const first  = s.shouldSample(id);
    const second = s.shouldSample(id);
    expect(first).toBe(second);
  });

  it('rate 0.5 — traceId starting 00000000 (value ~0) is sampled', () => {
    // parseInt('00000000', 16) = 0; 0 / 0xFFFFFFFF ≈ 0 < 0.5 → sampled
    const s = createSampler(0.5);
    expect(s.shouldSample('00000000' + '0'.repeat(24))).toBe(true);
  });

  it('rate 0.5 — traceId starting ffffffff (value ~1) is not sampled', () => {
    // parseInt('ffffffff', 16) = 4294967295; 4294967295 / 0xFFFFFFFF ≈ 1 ≥ 0.5 → not sampled
    const s = createSampler(0.5);
    expect(s.shouldSample('ffffffff' + '0'.repeat(24))).toBe(false);
  });

  it('rate 0.1 — traceId in bottom 10% is sampled', () => {
    // 0x19999999 / 0xFFFFFFFF ≈ 0.1 → just under threshold
    const s   = createSampler(0.1);
    const id  = '19999999' + '0'.repeat(24);
    const val = parseInt('19999999', 16) / 0xFFFFFFFF;
    expect(val).toBeLessThan(0.1);
    expect(s.shouldSample(id)).toBe(true);
  });

  it('returns false for null/empty traceId', () => {
    const s = createSampler(0.5);
    expect(s.shouldSample(null)).toBe(false);
    expect(s.shouldSample('')).toBe(false);
  });

  it('exposes rate property', () => {
    expect(createSampler(0.25).rate).toBe(0.25);
  });
});
