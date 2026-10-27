'use strict';

// the execution-invariant token is minted and verified on a process-local MONOTONIC clock, so a backward
// step of Date.now() (V8's 60 s re-sync on Windows, reproduced:) can no
// longer fail a legitimate token — while future-dated and expired tokens are still rejected with zero tolerance.

const crypto = require('crypto');

process.env.QODIQA_EXECUTION_INVARIANT_SECRET = process.env.QODIQA_EXECUTION_INVARIANT_SECRET || crypto.randomBytes(32).toString('hex');
const { mintExecutionToken, verifyExecutionToken, _monoNowMs, DEFAULT_TTL_MS } = require('../executionInvariantToken');
const { performance } = require('perf_hooks');

const requestHash = 'a'.repeat(64);
const policyHash  = 'b'.repeat(64);
const hmac = (issuedAt) => crypto.createHmac('sha256', Buffer.from(process.env.QODIQA_EXECUTION_INVARIANT_SECRET, 'hex'))
  .update(`QODIQA::EXECUTION_INVARIANT::V1|${requestHash}|${policyHash}|${issuedAt}`, 'utf8').digest('hex');

describe('execution token on a monotonic clock', () => {
  const realNow = Date.now;
  afterEach(() => { Date.now = realNow; jest.restoreAllMocks(); });

  test('MC-01 a backward Date.now() step between mint and verify does not fail a legitimate token', () => {
    let wall = realNow();
    Date.now = () => wall;                    // the wall clock, under test control
    const tok = mintExecutionToken({ requestHash, policyHash });
    wall -= 1;                                // the V8 re-sync step: Date.now() goes back 1 ms…
    expect(verifyExecutionToken({ requestHash, policyHash, ...tok })).toBe(true);
    wall -= 60_000;                           // …or a large backward system-time step: still irrelevant
    expect(verifyExecutionToken({ requestHash, policyHash, ...tok })).toBe(true);
  });

  test('MC-02 the pre-fix clock choice fails that same step (the regression this guards)', () => {
    // Same token, verified against a "now" 1 ms behind issuedAt — exactly what Date.now() produced at a re-sync.
    const tok = mintExecutionToken({ requestHash, policyHash });
    expect(verifyExecutionToken({ requestHash, policyHash, ...tok }, { _now: tok.issuedAt - 1 })).toBe(false);
  });

  test('MC-03 neither mint nor verify reads Date.now()', () => {
    const spy = jest.spyOn(Date, 'now');
    const tok = mintExecutionToken({ requestHash, policyHash });
    expect(verifyExecutionToken({ requestHash, policyHash, ...tok })).toBe(true);
    expect(spy).not.toHaveBeenCalled();
  });

  test('MC-04 zero tolerance kept: issuedAt 1 ms ahead of the monotonic clock is rejected even with a valid signature', () => {
    const issuedAt = _monoNowMs() + 1_000;    // correctly signed, but future-dated on the token's own clock
    expect(verifyExecutionToken({ requestHash, policyHash, issuedAt, signature: hmac(issuedAt) })).toBe(false);
    const now = 5_000_000;
    expect(verifyExecutionToken({ requestHash, policyHash, issuedAt: now + 1, signature: hmac(now + 1) }, { _now: now })).toBe(false);
    expect(verifyExecutionToken({ requestHash, policyHash, issuedAt: now, signature: hmac(now) }, { _now: now })).toBe(true);
  });

  test('MC-05 the max age is enforced on the same monotonic clock', () => {
    const issuedAt = _monoNowMs() - DEFAULT_TTL_MS - 1;
    expect(verifyExecutionToken({ requestHash, policyHash, issuedAt, signature: hmac(issuedAt) })).toBe(false);
    const fresh = _monoNowMs() - DEFAULT_TTL_MS + 5_000;
    expect(verifyExecutionToken({ requestHash, policyHash, issuedAt: fresh, signature: hmac(fresh) })).toBe(true);
  });

  test('MC-06 the clock never goes backwards and stays epoch-anchored', () => {
    let prev = _monoNowMs(); let backwards = 0;
    for (let i = 0; i < 200_000; i++) { const n = _monoNowMs(); if (n < prev) backwards++; prev = n; }
    expect(backwards).toBe(0);
    expect(Math.abs(_monoNowMs() - realNow())).toBeLessThan(60_000);
    expect(performance.timeOrigin).toBeGreaterThan(0);
  });
});
