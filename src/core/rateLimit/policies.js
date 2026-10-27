'use strict';

/**
 * Rate Limit Policy Registry —
 *
 * Hierarchical policy resolution — completely replaces the previous
 * single-surface flat policy registry.
 *
 * Resolution order (all applicable levels are checked; all must pass):
 *   1. Surface   — always applied; the baseline for this API surface
 *   2. Tenant    — applied when req.tenantId matches a configured tenant
 *   3. User      — applied when req.rbacUser.id matches a configured user (API key)
 *   4. SigningKey — applied when req.signingKeyId matches a configured signing key
 *   5. Endpoint  — applied when req.rl_endpoint matches a configured endpoint name
 *
 * The effective limit is the most restrictive applicable rule.
 * A single blocked level is sufficient to return HTTP 429.
 *
 * Backward-compatible: getPolicy(surface) returns the surface-level policy
 * with the same { maxRequests, windowSeconds } shape as the previous implementation.
 */

const { getConfig, loadConfig, KNOWN_SURFACES } = require('./config');

/**
 * Get the surface-level policy (backward-compatible).
 * @param {string} surface
 * @returns {{ maxRequests: number, windowSeconds: number, burstCapacity: number, ... }}
 * @throws if surface is unknown
 */
function getPolicy(surface) {
  const config = getConfig();
  const policy = config.surfaces[surface];
  if (!policy) {
    throw new Error(`Unknown rate limit surface: "${surface}". Known: ${[...KNOWN_SURFACES].join(', ')}`);
  }
  return policy;
}

/**
 * Resolve all applicable policy levels for a request.
 *
 * @param {string} surface
 * @param {{ tenantId?: string, userId?: string, signingKeyId?: string, endpoint?: string }} ctx
 * @returns {{ dimension: string, policy: object }[]}  ordered from broadest to most specific
 */
function resolvePolicies(surface, ctx = {}) {
  const config = getConfig();
  const chain  = [];

  const surfacePolicy = config.surfaces[surface];
  if (surfacePolicy) chain.push({ dimension: `surface:${surface}`, policy: surfacePolicy });

  if (ctx.tenantId) {
    const tp = config.tenants[ctx.tenantId];
    if (tp) chain.push({ dimension: `tenant:${ctx.tenantId}`, policy: tp });
  }

  if (ctx.userId) {
    const up = config.users[ctx.userId];
    if (up) chain.push({ dimension: `user:${ctx.userId}`, policy: up });
  }

  if (ctx.signingKeyId) {
    const sp = config.signingKeys[ctx.signingKeyId];
    if (sp) chain.push({ dimension: `signingkey:${ctx.signingKeyId}`, policy: sp });
  }

  if (ctx.endpoint) {
    const ep = config.endpoints[ctx.endpoint];
    if (ep) chain.push({ dimension: `endpoint:${ctx.endpoint}`, policy: ep });
  }

  return chain;
}

// POLICIES proxy: backward-compatible `POLICIES.portal` style access
const POLICIES = new Proxy({}, {
  get(_, surface)  { return getConfig().surfaces[surface] ?? undefined; },
  has(_, surface)  { return surface in getConfig().surfaces; },
  ownKeys()        { return Object.keys(getConfig().surfaces); },
  getOwnPropertyDescriptor(_, key) {
    const v = getConfig().surfaces[key];
    return v ? { configurable: true, enumerable: true, value: v } : undefined;
  },
});

module.exports = {
  getPolicy,
  resolvePolicies,
  POLICIES,
  KNOWN_SURFACES,
  loadConfig,
  getConfig,
};
