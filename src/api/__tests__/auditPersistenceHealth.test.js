'use strict';

/**
 * /ready reflects failing audit persistence (src/api/auditPersistenceHealth.js).
 *
 *   APH-01  a single AUDIT_PERSISTENCE_FAILED does not flip readiness (no flapping on one transient failure)
 *   APH-02  `threshold` CONSECUTIVE failures latch → isHealthy() false; a success in between resets the count
 *   APH-03  any successful mandatory append clears the latch
 *   APH-04  non-persistence errors (validation / replay — deterministic, caller-caused) are neither success nor failure
 *   APH-05  while latched, the writability probe is rate-limited; a passing probe releases the latch (no stuck state
 *           when an out-of-rotation instance receives no traffic); a failing probe keeps it
 *   APH-06  the real probe writes + fsyncs a sentinel in the given directory and fails on an unwritable one
 *   APH-07  GET /ready: 503 with components.auditPersistence:false while latched, 200 again after recovery
 *   APH-08  track() passes the append result / error through unchanged
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../validation/nonceStore', () => ({ isReady: () => true }));
jest.mock('../../validation/anomalyStore', () => ({ isReady: () => true }));
jest.mock('../../../services/policy/store', () => ({ isReady: () => true }));
jest.mock('../../infra/postgres/pool', () => ({ isEnabled: () => false, isHealthy: () => true }));
jest.mock('../../core/consent/revocation/RevocationSubscriber', () => ({ isReady: () => true }));
jest.mock('../../core/consent/ConsentCache', () => ({ isReady: () => true }));

const health = require('../auditPersistenceHealth');

const persistFail = () => Object.assign(new Error('AUDIT_PERSISTENCE_FAILED: ENOSPC: no space left on device'), { code: 'AUDIT_PERSISTENCE_FAILED' });
const neverProbe = () => { throw new Error('probe must not run'); };

beforeEach(() => health._resetForTests());

describe('latch rule', () => {
  test('APH-01 one failure never flips readiness', async () => {
    const append = health.track(async () => { throw persistFail(); });
    await expect(append({})).rejects.toMatchObject({ code: 'AUDIT_PERSISTENCE_FAILED' });
    expect(health.isHealthy({ probe: neverProbe })).toBe(true);
    expect(health.state()).toMatchObject({ latched: false, consecutiveFailures: 1 });
  });

  test('APH-02 threshold consecutive failures latch; an interleaved success resets the count', async () => {
    const T = health.FAILURE_THRESHOLD;
    expect(T).toBe(3); // documented default
    let fail = true;
    const append = health.track(async () => { if (fail) throw persistFail(); return { hash: 'h' }; });
    for (let i = 0; i < T - 1; i++) await append({}).catch(() => {});
    fail = false; await append({});
    fail = true;
    for (let i = 0; i < T - 1; i++) await append({}).catch(() => {});
    expect(health.isHealthy({ probe: neverProbe })).toBe(true);   // T-1 after the reset: still healthy
    await append({}).catch(() => {});
    expect(health.state().latched).toBe(true);
    expect(health.isHealthy({ now: Date.now(), probe: () => false })).toBe(false);
  });

  test('APH-03 a successful append clears the latch', async () => {
    for (let i = 0; i < health.FAILURE_THRESHOLD; i++) health.recordFailure();
    expect(health.state().latched).toBe(true);
    await health.track(async () => ({ hash: 'h' }))({});
    expect(health.state()).toMatchObject({ latched: false, consecutiveFailures: 0 });
    expect(health.isHealthy({ probe: neverProbe })).toBe(true);
  });

  test('APH-04 validation / replay errors do not count either way', async () => {
    for (let i = 0; i < health.FAILURE_THRESHOLD - 1; i++) health.recordFailure();
    const append = health.track(async () => { throw new Error('already_executed: duplicate'); });
    for (let i = 0; i < 5; i++) await append({}).catch(() => {});
    expect(health.state()).toMatchObject({ latched: false, consecutiveFailures: health.FAILURE_THRESHOLD - 1 });
  });

  test('APH-05 probe is rate-limited while latched; pass releases, fail keeps', () => {
    for (let i = 0; i < health.FAILURE_THRESHOLD; i++) health.recordFailure();
    const t0 = Date.now();
    const probe = jest.fn(() => false);
    expect(health.isHealthy({ now: t0 + 10, probe, intervalMs: 5000 })).toBe(false);
    expect(probe).not.toHaveBeenCalled();                      // inside the interval: no I/O
    expect(health.isHealthy({ now: t0 + 6000, probe, intervalMs: 5000 })).toBe(false);
    expect(probe).toHaveBeenCalledTimes(1);                    // failing probe: still latched
    expect(health.isHealthy({ now: t0 + 7000, probe, intervalMs: 5000 })).toBe(false);
    expect(probe).toHaveBeenCalledTimes(1);                    // rate-limited again
    const ok = jest.fn(() => true);
    expect(health.isHealthy({ now: t0 + 12000, probe: ok, intervalMs: 5000 })).toBe(true);
    expect(health.state().latched).toBe(false);
  });

  test('APH-06 the real probe writes + fsyncs a sentinel; an unwritable directory fails it', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dd020-'));
    try {
      for (let i = 0; i < health.FAILURE_THRESHOLD; i++) health.recordFailure();
      expect(health.isHealthy({ now: Date.now() + 60_000, probeDir: path.join(dir, 'does-not-exist') })).toBe(false);
      expect(health.isHealthy({ now: Date.now() + 120_000, probeDir: dir })).toBe(true);
      expect(fs.existsSync(path.join(dir, health.PROBE_FILE))).toBe(true);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); } // this test's own temp dir
  });

  test('APH-08 track() is transparent', async () => {
    const entry = { hash: 'x'.repeat(64) };
    const raw = jest.fn(async () => entry);
    await expect(health.track(raw)({ a: 1 }, { stage: 'ALLOW' })).resolves.toBe(entry);
    expect(raw).toHaveBeenCalledWith({ a: 1 }, { stage: 'ALLOW' });
    const err = persistFail();
    await expect(health.track(async () => { throw err; })({})).rejects.toBe(err);
  });
});

describe('GET /ready', () => {
  test('APH-07 503 + auditPersistence:false while latched, 200 after recovery', async () => {
    const request = require('supertest');
    const express = require('express');
    const readinessState = require('../../runtime/readinessState');
    const app = express(); app.use('/ready', require('../routes/ready'));
    readinessState.setReady(true);
    try {
      const ok = await request(app).get('/ready');
      expect(ok.status).toBe(200);
      expect(ok.body.components.auditPersistence).toBe(true);

      for (let i = 0; i < health.FAILURE_THRESHOLD; i++) health.recordFailure();
      const down = await request(app).get('/ready');
      expect(down.status).toBe(503);
      expect(down.body).toMatchObject({ ready: false, components: { auditPersistence: false } });

      health.recordSuccess();
      const back = await request(app).get('/ready');
      expect(back.status).toBe(200);
      expect(back.body.components.auditPersistence).toBe(true);
    } finally { readinessState._reset(); }
  });
});
