'use strict';

/**
 * (H2, DATE-NOW-INVENTORY.md) — the clock for org-status FRESHNESS stamps, which are compared only with each other
 * inside one process: a status confirmation (`syncedAt`), the subscription's `connectedSince`, the last failed sweep
 * (`lastSweepFailureAt`) and the age `now - syncedAt`.
 *
 * On Windows V8 re-syncs Date.now() to the system time every 60 s and can step it back 1 ms
 *. A backward step between a reconnect / failed sweep and the next status
 * apply inverted their order: the grace was wrongly withheld and a late sweep denied a healthy tenant
 * ORG_STATUS_STALE (fail-closed, rare). monoNowMs() never decreases, so the order is the real order.
 *
 * NOT for `updatedAt`: a status change's stamp crosses processes (Redis) and stays on the wall clock with its own
 * ordering rule. Tests that simulate stalls with jest.setSystemTime mock this module to Date.now.
 */

const { monoNowMs } = require('../../../infra/time/monotonicClock');

function now() { return monoNowMs(); }

module.exports = { now };
