'use strict';

/**
 * a healthy org-assigned tenant is never rejected ORG_STATUS_STALE at the reconcile/freshness
 * boundary, and the freshness protection itself is unchanged.
 *
 * Real OrgStatusSubscriber + real organizationRegistry, wired as server.js wires them; only Redis is fake.
 * The fake store answers getAllStatuses() after a simulated Redis round trip (RTT), which is what opened the
 * window: the sweep refreshes syncedAt only when its read completes, so with sweep period == staleness bound
 * every tick left RTT (+ timer lateness) during which Date.now() - syncedAt > bound.
 *
 *   RB-01  sweep period is at most half the bound; the bound itself is still RECONCILE_INTERVAL_MS (5000)
 *   RB-02  healthy worker, RTT 40 ms: sampled every 5 ms across 4 bounds (4,000 checks) → zero STALE denials
 *   RB-03  healthy worker, RTT 2,000 ms (a slow but answering Redis): still zero STALE denials
 *   RB-04  protection kept: once Redis stops answering the sweep, the worker still denies ORG_STATUS_STALE
 *          as soon as the last confirmation is older than the bound — and not before
 *
 * step 8 — org-status grace for LATE sweeps only (subscription connected throughout, no failed sweep):
 *   RB-05  saturation: sweeps answer but land late (RTT 7,000 ms > the 5,000 ms bound) → zero STALE; the grace
 *          metric counts the allowed checks; pre-grace behaviour (GRACE 0) denies in the same scenario
 *   RB-06  the grace is itself bounded: a confirmation older than bound + grace is denied even while connected
 *   RB-07  a reconnect after the last confirmation removes the grace → strict bound until a sweep re-confirms
 *   RB-08  a failed sweep after the last confirmation removes the grace (RB-04 is the same case at RTT 40)
 */

jest.mock('redis', () => ({ createClient: jest.fn() }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
// these freshness tests simulate stalls/ageing with jest.setSystemTime, which moves Date only; the production
// org-status clock is monotonic (performance.now), so they read Date.now through it. test/orgStatusMonotonic covers the real clock.
jest.mock('./orgStatusClock', () => ({ now: () => Date.now() }));
jest.mock('../../../infra/redis/clientConfig', () => ({
  buildClientOptions: jest.fn().mockReturnValue({}),
  isAuthError:        jest.fn().mockReturnValue(false),
  isTlsError:         jest.fn().mockReturnValue(false),
}));

afterEach(() => { jest.dontMock('./OrgStatusStore'); jest.useRealTimers(); });

const clients = [];
function readyClient() {
  const EventEmitter = require('events');
  const emitter = new EventEmitter();
  const client = {
    disconnect:  jest.fn().mockResolvedValue(undefined),
    subscribe:   jest.fn().mockResolvedValue(undefined),
    unsubscribe: jest.fn().mockResolvedValue(undefined),
    ping:        jest.fn().mockResolvedValue('PONG'),
    on:         (ev, fn) => emitter.on(ev, fn),
    off:         (ev, fn) => emitter.off(ev, fn),
  };
  client.connect = jest.fn().mockImplementation(async () => { emitter.emit('ready'); });
  client._emit = (...a) => emitter.emit(...a);
  clients.push(client);
  return client;
}

// Boots the real pair with a fake Redis whose HGETALL takes rttMs. `state.answering=false` makes the
// store report Redis unavailable (getAllStatuses → null), exactly as OrgStatusStore does on error.
async function boot(rttMs, env = {}) {
  jest.resetModules();
  clients.length = 0;
  for (const k of Object.keys(env)) process.env[k] = env[k];
  jest.useFakeTimers({ now: 1_800_000_000_000 });
  const state = { answering: true, orgId: null, updatedAt: null };
  jest.doMock('./OrgStatusStore', () => ({
    getAllStatuses: jest.fn().mockImplementation(() => new Promise((resolve) => {
      if (state.hang) return; // never answers, never fails
      setTimeout(() => resolve(state.answering
        ? new Map([[state.orgId, { status: 'active', updatedAt: state.updatedAt }]])
        : null), rttMs);
    })),
    setStatus: jest.fn().mockResolvedValue(true),
    getStatus: jest.fn().mockResolvedValue(null),
  }));
  require('redis').createClient.mockImplementation(() => readyClient());
  const registry = require('../organizationRegistry');
  const subscriber = require('./OrgStatusSubscriber');
  for (const k of Object.keys(env)) delete process.env[k];
  registry._reset();
  registry.setOrgStatusSubscriber(subscriber);
  subscriber.setOrganizationRegistry(registry);
  const { organizationId } = registry.registerOrganization({ organizationName: 'healthy org' });
  registry.assignTenantToOrg('tenant-w8f1', organizationId);
  state.orgId = organizationId;
  state.updatedAt = Date.now();
  const started = subscriber.start();
  await jest.advanceTimersByTimeAsync(rttMs);
  await started;
  return { registry, subscriber, state };
}

// Steps the fake clock in stepMs increments for totalMs, checking the gate at every step.
async function sample(registry, totalMs, stepMs) {
  const reasons = {};
  let checks = 0;
  for (let t = 0; t < totalMs; t += stepMs) {
    await jest.advanceTimersByTimeAsync(stepMs);
    const r = registry.assertActiveOrganization('tenant-w8f1');
    const k = r.valid ? 'VALID' : r.reason;
    reasons[k] = (reasons[k] || 0) + 1;
    checks++;
  }
  return { reasons, checks };
}

describe('org-status reconcile/freshness boundary', () => {
  let active;
  afterEach(async () => { if (active) { await active.subscriber.stop().catch(() => {}); active = null; } });

  test('RB-01 sweep period ≤ bound/2; the bound itself is unchanged', () => {
    jest.resetModules();
    const s = require('./OrgStatusSubscriber');
    expect(s.MAX_PROPAGATION_WINDOW_MS).toBe(5000);
    expect(s.RECONCILE_INTERVAL_MS).toBe(5000);
    expect(s.SWEEP_PERIOD_MS).toBeGreaterThan(0);
    expect(s.SWEEP_PERIOD_MS * 2).toBeLessThanOrEqual(s.MAX_PROPAGATION_WINDOW_MS);
  });

  test('RB-02 healthy worker, 40 ms Redis RTT: zero STALE denials across 4 bounds (5 ms sampling)', async () => {
    active = await boot(40);
    const { reasons, checks } = await sample(active.registry, 4 * 5000, 5);
    expect(checks).toBe(4000);
    expect(reasons).toEqual({ VALID: 4000 });
  });

  test('RB-03 healthy worker, 2,000 ms Redis RTT: still zero STALE denials', async () => {
    active = await boot(2000);
    const { reasons } = await sample(active.registry, 4 * 5000, 10);
    expect(reasons).toEqual({ VALID: 2000 });
  });

  test('RB-04 protection kept: a worker that cannot re-confirm denies once its last confirmation exceeds the bound', async () => {
    active = await boot(40);
    // Healthy for a while, then Redis stops answering the sweep (the subscriber connection stays "ready").
    await sample(active.registry, 3000, 10);
    active.state.answering = false;
    // Every sweep from here on fails; the last successful confirmation is the latest completed read.
    const lastOk = Date.now();
    let firstStaleAt = null; let validAfterBound = 0;
    for (let t = 0; t < 12000; t += 10) {
      await jest.advanceTimersByTimeAsync(10);
      const r = active.registry.assertActiveOrganization('tenant-w8f1');
      if (!r.valid && firstStaleAt === null) { expect(r.reason).toBe('ORG_STATUS_STALE'); firstStaleAt = Date.now(); }
      if (firstStaleAt !== null && r.valid) validAfterBound++;
    }
    expect(firstStaleAt).not.toBeNull();
    // Denial starts no later than one bound after the last confirmation (never later than the pre-fix code).
    expect(firstStaleAt - lastOk).toBeLessThanOrEqual(5000 + 10);
    // …and once stale it stays denied while Redis is unanswering.
    expect(validAfterBound).toBe(0);
  });

  // An event-loop stall: wall time passes while no timer (no sweep, no sweep completion) can run — exactly what
  // CPU saturation does to the sweep's setInterval. The request is checked right after the stall, before the
  // overdue sweep has had its turn.
  const STALL_MS = 5100;
  const stall = () => jest.setSystemTime(Date.now() + STALL_MS);

  async function stalledChecks(registry, n) {
    const reasons = {};
    for (let i = 0; i < n; i++) {
      // Healthy running between stalls (varied phase), long enough for a sweep to complete — two stalls with no
      // confirmation between them would legitimately exceed bound + grace (that case is RB-06).
      await jest.advanceTimersByTimeAsync(2600 + (i * 173) % 2500);
      stall();
      const r = registry.assertActiveOrganization('tenant-w8f1');
      const k = r.valid ? 'VALID' : r.reason;
      reasons[k] = (reasons[k] || 0) + 1;
    }
    return reasons;
  }

  test('RB-05 saturation (5.1 s event-loop stalls): zero STALE with the grace; the pre-grace rule denies', async () => {
    active = await boot(40);
    const metrics = require('./OrgStatusMetrics');
    const inc = jest.spyOn(metrics.staleGraceAllowed, 'inc');
    expect(await stalledChecks(active.registry, 40)).toEqual({ VALID: 40 });
    expect(inc).toHaveBeenCalled();
    await active.subscriber.stop().catch(() => {});
    active = await boot(40, { QODIQA_ORG_STATUS_GRACE_MS: '0' });
    expect(active.subscriber.GRACE_MS).toBe(0);
    expect(await stalledChecks(active.registry, 40)).toEqual({ ORG_STATUS_STALE: 40 });
  });

  test('RB-06 the grace is bounded: older than bound + grace is denied even while connected', async () => {
    active = await boot(40);
    expect(active.subscriber.GRACE_MS).toBe(5000);
    await sample(active.registry, 1000, 10);
    // Sweeps stop COMPLETING (the answer never arrives) but never FAIL — the worst case for the grace.
    active.state.hang = true;
    const lastOk = Date.now();
    let firstStaleAt = null;
    for (let t = 0; t < 14000; t += 10) {
      await jest.advanceTimersByTimeAsync(10);
      const r = active.registry.assertActiveOrganization('tenant-w8f1');
      if (!r.valid && firstStaleAt === null) { expect(r.reason).toBe('ORG_STATUS_STALE'); firstStaleAt = Date.now(); }
    }
    expect(firstStaleAt).not.toBeNull();
    expect(firstStaleAt - lastOk).toBeGreaterThan(5000);
    expect(firstStaleAt - lastOk).toBeLessThanOrEqual(10000 + 10);
  });

  test('RB-07 a reconnect after the last confirmation restores the strict bound', async () => {
    active = await boot(40);
    await sample(active.registry, 3000, 10);
    const sub = clients[0];
    sub._emit('reconnecting');
    expect(active.subscriber.graceState().connectedSince).toBe(0);
    sub._emit('ready'); // pub/sub messages may have been missed while disconnected
    await jest.advanceTimersByTimeAsync(0); // the managed client verifies (ping) before announcing ready
    expect(active.subscriber.graceState().connectedSince).toBe(Date.now());
    stall();
    expect(active.registry.assertActiveOrganization('tenant-w8f1')).toMatchObject({ valid: false, reason: 'ORG_STATUS_STALE' });
    // Once the reconnect sweep re-confirms, the org is served again.
    await jest.advanceTimersByTimeAsync(100);
    expect(active.registry.assertActiveOrganization('tenant-w8f1').valid).toBe(true);
  });

  test('RB-08 a failed sweep after the last confirmation restores the strict bound', async () => {
    active = await boot(40);
    await sample(active.registry, 3000, 10);
    active.state.answering = false;
    await jest.advanceTimersByTimeAsync(2600); // at least one sweep fails
    expect(active.subscriber.graceState().lastSweepFailureAt).toBeGreaterThan(0);
    stall();
    expect(active.registry.assertActiveOrganization('tenant-w8f1')).toMatchObject({ valid: false, reason: 'ORG_STATUS_STALE' });
  });
});
