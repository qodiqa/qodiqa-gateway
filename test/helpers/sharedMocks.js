'use strict';

/**
 * Single authoritative source for the Redis-, PostgreSQL-, and Logger-shaped
 * test doubles used across the red-team / security test suites. Before
 * this module existed, test/redteam.test.js,
 * test/integration/redteam.integration.test.js, and test/authLockoutCredential.
 * security.test.js each hand-rolled their own copy of these stand-ins,
 * which is exactly the drift risk the finding calls out.
 *
 * Redis-family (nonce store, anomaly store): re-exported from
 * src/testing/stores.js — the pre-existing shared in-memory factory module
 * already consumed by 30+ other test files. This module does not
 * reimplement that logic; it is simply the one import surface the
 * red-team/security files use instead of redeclaring it locally.
 */

// Lazily required: src/testing/stores.js transitively pulls in
// src/infra/redis/managedClient.js, which itself requires services/logger.
// authLockoutCredential.security.test.js's jest.mock('../services/logger', ...)
// factory calls into this file for makeLoggerMock() — an eager top-level
// require here would re-enter that same services/logger mock resolution
// mid-construction (a circular require) and receive this module's own
// not-yet-populated exports. Lazy-requiring inside each redis-family
// factory sidesteps that entirely: makeLoggerMock() never touches this path.
function stores() { return require('../../src/testing/stores'); }

function makeNonceStore(...args) { return stores().makeNonceStore(...args); }
function makeOpenAnomalyStore(...args) { return stores().makeOpenAnomalyStore(...args); }
function makeCountingAnomalyStore(...args) { return stores().makeCountingAnomalyStore(...args); }
function makeDeadStore(...args) { return stores().makeDeadStore(...args); }
function makeIdempotencyStore(...args) { return stores().makeIdempotencyStore(...args); }

/**
 * In-memory PostgreSQL pool double: { isEnabled(), query() }, matching the
 * shape already hand-written ad hoc in test/audit-chain-hardening.test.js.
 * `query` is a bare jest.fn() — callers configure its behavior per test
 * (mockResolvedValueOnce / mockRejectedValue / mockImplementation).
 * `isEnabled` defaults to true so callers testing the common "PG available"
 * path don't need to configure it.
 */
function makePgPool({ enabled = true } = {}) {
  return {
    isEnabled: () => enabled,
    query: jest.fn(),
  };
}

/**
 * Logger double matching services/logger.js's real export surface
 * ({ emit, allowed, blocked, eventBus, registerCentralStore, flush }) —
 * only `emit` is mocked because it's the only method any current caller of
 * this double invokes. Usable directly inside a jest.mock() factory:
 *
 *   jest.mock('../services/logger', () => require('./helpers/sharedMocks').makeLoggerMock());
 *   const { emit } = require('../services/logger');
 */
function makeLoggerMock() {
  return { emit: jest.fn() };
}

module.exports = {
  makeNonceStore,
  makeOpenAnomalyStore,
  makeCountingAnomalyStore,
  makeDeadStore,
  makeIdempotencyStore,
  makePgPool,
  makeLoggerMock,
};
