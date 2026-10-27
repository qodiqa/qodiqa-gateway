'use strict';

/**
 * (H2) — org-status freshness stamps use the MONOTONIC clock (status/orgStatusClock.js), not Date.now().
 *
 *   (a)  orgStatusClock.now() never decreases when Date.now() steps back (the V8 60 s re-sync step)
 *   (b)  the reproduced H2 scenario: the subscription connects, Date.now() steps back 1 ms, the org's status is
 * confirmed, then a sweep is late. With wall-clock stamps connectedSince > syncedAt withheld the grace and
 *            the healthy tenant got ORG_STATUS_STALE; with monotonic stamps the grace applies.
 *   (c)  the strict bound is unchanged: beyond window + grace the tenant is still denied ORG_STATUS_STALE, and a
 *            failed sweep after the last confirmation still removes the grace.
 */

jest.mock('../../../../../services/logger', () => ({ emit: jest.fn() }));

describe('monotonic org-status freshness', () => {
  let registry; let clock; let realNow; let offset;
  const WINDOW = 20; const GRACE = 200;

  beforeEach(() => {
    jest.resetModules();
    realNow = Date.now;
    offset = 0;
    Date.now = () => realNow() + offset;                // an advancing WALL clock that can be stepped; the monotonic clock is untouched
    clock = require('../orgStatusClock');
    registry = require('../../organizationRegistry');
    registry._reset();
  });
  afterEach(() => { Date.now = realNow; });

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  function subscriber(state, graceMs = GRACE) {
    return { isStarted: () => true, isReady: () => true, MAX_PROPAGATION_WINDOW_MS: WINDOW,
      graceState: () => ({ connectedSince: state.connectedSince, lastSweepFailureAt: state.lastSweepFailureAt, graceMs }) };
  }
  function setupOrg(sub) {
    registry.setOrgStatusSubscriber(sub);
    const { organizationId } = registry.registerOrganization({ organizationName: 'healthy org' });
    registry.assignTenantToOrg('tenant-w11-02', organizationId);
    return organizationId;
  }

  test('(a) now() never decreases when Date.now() steps back', () => {
    const a = clock.now();
    offset -= 1000;                                      // a large backward wall-clock step
    const b = clock.now();
    expect(b).toBeGreaterThanOrEqual(a);
  });

  test('(b) connect, 1 ms backward wall step, confirm, late sweep → the grace applies (no false ORG_STATUS_STALE)', async () => {
    // 2026-10-14 (final mission, flake root cause): with GRACE = 200 this test failed once in the 38-min in-band
    // coverage run — the 50 ms sleep overran by >= 170 ms (an event-loop stall), age > window + grace, a correct STALE.
    // Reproduced exactly by delaying that one timer 200 ms. The property under test is the H2 INVERSION (wall-clock stamps
    // make connectedSince > syncedAt after a backward step, which withholds the grace whatever its size), so this test
    // uses a 5 s grace: still discriminating (mutation-checked: wall-clock stamps → STALE), no longer timing-sensitive.
    // The bound itself (beyond window + grace → STALE) stays covered by (c) with the 200 ms grace.
    const state = { connectedSince: 0, lastSweepFailureAt: 0 };
    const orgId = setupOrg(subscriber(state, 5000));
    state.connectedSince = clock.now();                  // the subscription becomes ready
    offset -= 5;                                         // a backward Date.now() step (V8 re-sync is 1 ms; 5 ms makes the inversion certain)
    registry._applyRemoteStatus(orgId, 'active', realNow()); // the org's status is confirmed (syncedAt)
    await sleep(WINDOW + 30);                            // the next sweep is late: age > window, < window + grace
    expect(registry.assertActiveOrganization('tenant-w11-02')).toMatchObject({ valid: true });
  });

  test('(c) beyond window + grace, or after a failed sweep, the tenant is still denied ORG_STATUS_STALE', async () => {
    const state = { connectedSince: 0, lastSweepFailureAt: 0 };
    const orgId = setupOrg(subscriber(state));
    state.connectedSince = clock.now();
    registry._applyRemoteStatus(orgId, 'active', realNow());
    await sleep(WINDOW + 30);
    state.lastSweepFailureAt = clock.now();              // a sweep failed after the last confirmation → no grace
    expect(registry.assertActiveOrganization('tenant-w11-02')).toMatchObject({ valid: false, reason: 'ORG_STATUS_STALE' });
    state.lastSweepFailureAt = 0;
    await sleep(GRACE + 20);                             // beyond window + grace
    expect(registry.assertActiveOrganization('tenant-w11-02')).toMatchObject({ valid: false, reason: 'ORG_STATUS_STALE' });
  });
});
