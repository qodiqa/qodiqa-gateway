'use strict';

/**
 * Provider registry — backward-compatible shim.
 *
 * The routing and dispatch layer has moved to services/providers/router.js.
 * This module is retained for compatibility with execution.js which calls
 * resolveProvider() to check whether a named provider exists before dispatching.
 *
 * The authoritative list of providers is maintained in services/providers/router.js.
 * This module delegates to the router's registry inspection functions.
 *
 * Direct handler access is intentionally removed — all provider calls must flow
 * through routeProviderCall() in router.js which enforces the execution invariant
 * chain and handles failover with full audit coverage.
 */

const { listProviders, listEnabledProviders } = require('./providers/router');

/**
 * Return true if the named provider is registered (enabled or not).
 * Used by execution.js to detect completely unknown provider names
 * before the router is invoked.
 *
 * @param {string} name
 * @returns {boolean}
 */
function resolveProvider(name) {
  return listProviders().includes(name);
}

module.exports = { resolveProvider, listProviders, listEnabledProviders };
