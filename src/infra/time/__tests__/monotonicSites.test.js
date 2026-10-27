'use strict';

// same-process deadlines, windows, breakers, throttles and tick delays read
// the monotonic clock, so a wall-clock step — V8's 1 ms re-sync on Windows, or a large (120 s) system-time correction,
// the addendum's check — can no longer open/close a breaker early, fire a deadline early, keep a stale entry
// alive, or skip/stretch a scheduled tick.
//
// Method (precedent: middleware/__tests__/w10PublicRateLimitClock.test.js): the monotonic clock is a controllable
// `mono`, Date.now() a separately controllable `wall`. Each test moves the two apart by ±120 s and asserts the decision
// follows `mono`. Reverting any covered site to Date.now() makes its test fail (verified per site, see the table).

const BASE = 1_800_000_000_000;
const STEP = 120_000; // a large wall-clock step (the fault suite's clockskew row)

let mono; let wall;

beforeEach(() => {
  jest.resetModules();
  mono = BASE; wall = BASE;
  jest.doMock('../monotonicClock', () => ({ monoNowMs: () => mono, wallFromMono: (m) => (m ? Date.now() - (mono - m) : null) }));
  jest.spyOn(Date, 'now').mockImplementation(() => wall);
});

afterEach(() => {
  jest.restoreAllMocks();
  jest.dontMock('../monotonicClock');
});

// ── 1. circuit breakers ───────────────────────────────────────────────────────

describe('circuit breakers follow the monotonic clock', () => {
  const CFG = { cbFailureThreshold: 3, cbWindowMs: 60_000, cbRecoveryMs: 30_000, cbSuccessThreshold: 1 };

  function openThenStep(cb, recoveryMs, threshold) {
    for (let i = 0; i < threshold; i++) cb.onFailure();
    expect(cb.state).toBe('OPEN');
    wall += STEP; mono += 1_000;                   // wall jumps forward 120 s; 1 s really passed
    expect(cb.allowRequest()).toBe(false);         // must NOT half-open early
    expect(cb.state).toBe('OPEN');
    wall -= 2 * STEP; mono += recoveryMs;          // wall now 120 s BEHIND the open; the recovery window really passed
    expect(cb.allowRequest()).toBe(true);          // must NOT stay open 120 s too long
    expect(cb.state).toBe('HALF_OPEN');
  }

  test('MS-01 webhook breaker: a ±120 s wall step neither half-opens early nor delays recovery', () => {
    const { getCircuitBreaker } = require('../../../core/webhooks/webhookCircuitBreaker');
    openThenStep(getCircuitBreaker('ms01.example', CFG), CFG.cbRecoveryMs, CFG.cbFailureThreshold);
  });

  test('MS-02 signing-provider (key resilience) breaker: same', () => {
    const { getCircuitBreaker } = require('../../keys/resilience/circuitBreaker');
    openThenStep(getCircuitBreaker('ms02-provider', CFG), CFG.cbRecoveryMs, CFG.cbFailureThreshold);
  });

  test('MS-03 LLM provider breaker: same', () => {
    const { getCircuitBreaker } = require('../../../../services/providers/providerCircuitBreaker');
    openThenStep(getCircuitBreaker('ms03-provider', CFG), CFG.cbRecoveryMs, CFG.cbFailureThreshold);
  });

  test('MS-04 PostgreSQL breaker: same, and a forward step does not expire the half-open probe lease', () => {
    const pgcb = require('../../postgres/pgCircuitBreaker');
    pgcb.reset();
    const cb = pgcb.getCircuitBreaker();
    const { cbRecoveryMs, cbFailureThreshold } = cb._config;
    openThenStep(cb, cbRecoveryMs, cbFailureThreshold);   // the probe is now in flight (lease stamped)
    wall += 3 * STEP; mono += 1_000;                       // wall leaps forward; the probe has run 1 s
    expect(cb.allowRequest()).toBe(false);                 // a concurrent caller is refused…
    expect(cb.state).toBe('HALF_OPEN');                    // …and the lease has NOT expired early
    pgcb.reset();
  });

  test('MS-13 Redis reconnect cooldown (default clock): a ±120 s wall step neither ends nor stretches the cooldown', () => {
    const { createBoundedReconnectStrategy } = require('../../redis/reconnectStrategy');
    const strategy = createBoundedReconnectStrategy({ source: 'ms13', maxAttempts: 1, circuitBreakerCooldownMs: 30_000, jitterRatio: 0 });
    expect(strategy(1)).toBe(false);                       // exhausted → circuit opens
    wall += STEP; mono += 1_000;
    expect(strategy(0)).toBe(false);                       // still cooling down (Date.now(): cooldown "over")
    wall -= 2 * STEP; mono += 30_000;
    expect(typeof strategy(0)).toBe('number');             // cooldown really elapsed (Date.now(): -90 s, still open)
  });
});

// ── 2. deadlines / timeouts ───────────────────────────────────────────────────

describe('deadlines follow the monotonic clock', () => {
  test('MS-05 idempotency wait: a forward wall step does not end the wait for an in-flight duplicate early', async () => {
    process.env.IDEMPOTENCY_POLL_INTERVAL_MS = '1';
    try {
      const { gate } = require('../../../core/idempotency/idempotencyGate');
      let calls = 0;
      const store = {
        async reserve(_t, _k, fingerprint) {
          calls++;
          if (calls === 1) { wall += STEP; mono += 1; return { reserved: false, existing: { fingerprint, status: 'pending' } }; }
          return { reserved: true };                     // the first attempt released its reservation
        },
      };
      const r = await gate({ idempotencyKey: 'k1', tenantId: 't1', publicKeyId: 'pk1', requestHash: 'h1', reservationTtlMs: 30_000, _store: store });
      expect(r.outcome).toBe('proceed');                 // with Date.now() the 120 s jump passed the 10 s deadline → in_progress
      expect(calls).toBe(2);
    } finally {
      delete process.env.IDEMPOTENCY_POLL_INTERVAL_MS;
    }
  });

  test('MS-06 classifier budget: a forward wall step during classify() is not a timeout; a real overrun still is', () => {
    const { executeClassifiers } = require('../../../core/semantic/classifierExecution');
    const stepping = { id: 'stepping', classify: () => { wall += STEP; mono += 2; return null; } };
    const ok = executeClassifiers([stepping], {}, { classifierTimeoutMs: 50 });
    expect(ok.timedOut).toBe(0);
    expect(ok.succeeded).toBe(1);
    const slow = { id: 'slow', classify: () => { wall -= STEP; mono += 51; return null; } };
    const late = executeClassifiers([slow], {}, { classifierTimeoutMs: 50 });
    expect(late.timedOut).toBe(1);                       // with Date.now() the backward step hid the overrun
  });
});

// ── 3. staleness / throttles ──────────────────────────────────────────────────

describe('staleness bounds and throttles follow the monotonic clock', () => {
  test('MS-07 control-plane freshness: a forward wall step does not refuse a fresh snapshot; a real stall still does', async () => {
    const prev = process.env.QODIQA_CONTROL_PLANE_BACKEND;
    process.env.QODIQA_CONTROL_PLANE_BACKEND = 'pg';
    const cp = require('../../../core/controlPlane');
    try {
      await cp._resetForTest();
      cp._setPoolForTest({ async query() { return { rows: [{ horizon: '10', store: null }] }; } });
      await cp.start({ notifier: false });
      wall += STEP; mono += 1_000;
      expect(() => cp.assertFresh('tenant')).not.toThrow(); // with Date.now() the snapshot looked 120 s old → 503
      expect(cp.status().ageMs).toBe(1_000);
      wall -= 2 * STEP; mono += 5_000;                      // 6 s really passed without a pull; wall is behind
      let err = null; try { cp.assertFresh('tenant'); } catch (e) { err = e; }
      expect(err && err.code).toBe('CONTROL_PLANE_STALE');
    } finally {
      cp._setPoolForTest(null);
      await cp._resetForTest();
      if (prev === undefined) delete process.env.QODIQA_CONTROL_PLANE_BACKEND; else process.env.QODIQA_CONTROL_PLANE_BACKEND = prev;
    }
  });

  test('MS-08 verifier pacer: a forward wall step does not turn a short work slice into a 1 s pause', async () => {
    const pacer = require('../../../core/audit/verifierPacer');
    pacer.setDutyCycle(0.5);
    const delays = [];
    jest.spyOn(global, 'setTimeout').mockImplementation((fn, ms) => { delays.push(ms); fn(); return { unref() {} }; });
    wall += STEP; mono += 100;                             // 100 ms of work; the wall clock jumped 120 s
    await pacer.pace();
    expect(delays).toEqual([100]);                         // with Date.now(): min(1000, 120000) = 1000
    pacer.setDutyCycle(0);
  });
});

// ── 4. windows / caches / buckets ─────────────────────────────────────────────

describe('windows, caches and token buckets follow the monotonic clock', () => {
  // MS-09 (dashboard TTL cache) moved with to _quarantine/2026-10-27-audit-remediation

  test('MS-10 notification token bucket: a backward wall step does not withhold the next refill', () => {
    const BaseChannel = require('../../../alerting/notification/channels/BaseChannel');
    const Ctor = BaseChannel.BaseChannel || BaseChannel;
    const ch = new Ctor({ name: 'ms10', rateLimit: 1 });
    expect(ch._consumeToken()).toBe(true);
    expect(ch._consumeToken()).toBe(false);              // bucket empty
    wall -= STEP; mono += 60_000;                          // a full refill period really passed; wall stepped back
    expect(ch._consumeToken()).toBe(true);               // with Date.now() elapsed = -120 s → still empty
  });

  test('MS-11 provider health window: a forward wall step does not discard the samples that make a provider degraded', () => {
    const health = require('../../../../services/providers/providerHealth');
    health.resetAll();
    for (let i = 0; i < 5; i++) health.recordOutcome('ms11', { ok: false, timedOut: true, latencyMs: 1 });
    expect(health.isDegraded('ms11')).toBe(true);
    wall += STEP; mono += 1_000;
    health.recordOutcome('ms11', { ok: false, timedOut: true, latencyMs: 1 });
    expect(health.snapshot('ms11').samples).toBe(6);     // with Date.now() the 120 s jump pruned the first 5
    expect(health.isDegraded('ms11')).toBe(true);
    health.resetAll();
  });
});

// ── 5. self-rescheduling tick delays ──────────────────────────────────────────

describe('self-rescheduling tick delays follow the monotonic clock', () => {
  function captureTimers() {
    const timers = [];
    jest.spyOn(global, 'setTimeout').mockImplementation((fn, ms) => { timers.push({ fn, ms }); return { unref() {} }; });
    return timers;
  }

  test('MS-12 transparency gap scanner: a wall step during a scan neither skips nor stretches the next interval', async () => {
    const { createScanner } = require('../../../core/transparency/scanner');
    const emit = jest.fn();
    const taskRunner = { async runTask() { wall += STEP; mono += 10; } };   // the scan takes 10 ms; wall jumps 120 s
    const scanner = createScanner({
      config: { enabled: true, intervalMs: 60_000, mode: 'incremental', maxRetries: 1, retryDelayMs: 0, startupScan: false },
      _emit: emit, _metrics: {}, _taskRunner: taskRunner, _pgPool: {}, _gapFramework: {}, _scannerState: {},
    });
    const timers = captureTimers();
    await scanner.start();
    expect(timers.map((t) => t.ms)).toEqual([0]);
    await timers[0].fn();                                  // run the first tick
    expect(timers[1].ms).toBe(59_990);                     // with Date.now(): max(0, 60000 - 120010) = 0 → immediate rescan
    taskRunner.runTask = async () => { wall -= 2 * STEP; mono += 10; };
    await timers[1].fn();
    expect(timers[2].ms).toBe(59_990);                     // with Date.now(): 60000 + 239990 → a 5-minute gap
    await scanner.stop();
  });
});
