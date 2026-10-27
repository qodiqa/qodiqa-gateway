'use strict';

/**
 * Distributed Rate Limiting —
 *
 * Algorithm: Sliding Window Counter with burst protection.
 * Replaces the Fixed Window Counter used in previous versions.
 *
 * Usage in route files:
 *   const { createRateLimitMiddleware } = require('../../core/rateLimit');
 *   router.use(createRateLimitMiddleware('portal'));
 *   router.use(createRateLimitMiddleware('portal', { _evalFn: testEval })); // tests
 *
 * Usage in server.js startup:
 *   const { initialize } = require('./src/core/rateLimit');
 *   await initialize();
 *
 * Usage in server.js shutdown:
 *   const { disconnect } = require('./src/core/rateLimit');
 *   await disconnect();
 *
 * Per-API-key quota configuration:
 *   const { loadConfig } = require('./src/core/rateLimit');
 *   loadConfig({
 *     users:       { 'user-uuid': { maxRequests: 1000, windowSeconds: 60 } },
 *     signingKeys: { 'key-id':    { maxRequests: 30,   windowSeconds: 60 } },
 *     tenants:     { 'tenant-id': { maxRequests: 5000, windowSeconds: 60 } },
 *   });
 */

const { createRateLimitMiddleware, checkRateLimit, extractIdentity, _isRlEnabled,
        _isDegraded, _resetDegradedForTest }                        = require('./middleware');
const { initialize, disconnect, isReady, KEY_PREFIX }              = require('./storage');
const { POLICIES, getPolicy, resolvePolicies,
        KNOWN_SURFACES, loadConfig, getConfig }                    = require('./policies');
const metrics                                                       = require('./metrics');

module.exports = {
  // Middleware factory — used by all route files
  createRateLimitMiddleware,
  // imperative check where the identity is known only after the request
  // was accepted (ai_chat_identity, after artifact signature verification)
  checkRateLimit,

  // Lifecycle — used by server.js
  initialize,
  disconnect,
  isReady,

  // Policy access — used by diagnostics / tests / runtime config
  POLICIES,
  getPolicy,
  resolvePolicies,
  KNOWN_SURFACES,
  loadConfig,
  getConfig,
  KEY_PREFIX,

  // Observability
  metrics,

  // Internals exported for testing
  extractIdentity,
  _isRlEnabled,
  _isDegraded,
  _resetDegradedForTest,
};
