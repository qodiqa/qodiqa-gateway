'use strict';

/**
 * DATA_RESIDENCY policy rule: where a request's data may be processed. The provider a request goes to is a region; a tenant restricts the regions it allows.
 *
 * config:
 *   {
 *     residencyFormat:  1,
 *     tenantRegion:     'eu',                           the tenant's home region (informational, and the default of allowedRegions)
 *     allowedRegions:   ['eu', 'ch'],                   regions the tenant's data may reach (default [tenantRegion])
 *     providerRegions:  { openai: 'us', local: 'eu' }   where each provider processes (declared by the operator)
 *   }
 * The decision is made by the policy engine on every request, and again for a failover target (the same check runs for the target provider), so a failover can never move data
 * into a region the tenant forbids. FAIL CLOSED: a provider with no declared region is blocked (RESIDENCY_PROVIDER_REGION_UNKNOWN) - "unknown" is not "allowed".
 * Region ids are free labels chosen by the operator ('eu', 'eu-west-1', 'us'); QODIQA compares them as strings and does not know geography.
 */

const FORMAT = 1;
const REGION_RE = /^[a-z0-9][a-z0-9-]{0,23}$/;
const PROVIDER_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const ALLOWED = new Set(['residencyFormat', 'tenantRegion', 'allowedRegions', 'providerRegions']);

function validate(config) {
  for (const k of Object.keys(config)) if (!ALLOWED.has(k)) throw new Error(`unknown DATA_RESIDENCY config key: ${k}`);
  if (config.residencyFormat !== FORMAT) throw new Error(`config.residencyFormat must be ${FORMAT}`);
  if (typeof config.tenantRegion !== 'string' || !REGION_RE.test(config.tenantRegion)) throw new Error('config.tenantRegion must be a region id (lower-case letters, digits, dashes)');
  if (config.allowedRegions !== undefined && !(Array.isArray(config.allowedRegions) && config.allowedRegions.length > 0 && config.allowedRegions.length <= 32
    && config.allowedRegions.every((r) => typeof r === 'string' && REGION_RE.test(r)))) throw new Error('config.allowedRegions must be a non-empty array of region ids');
  const pr = config.providerRegions;
  if (pr === null || typeof pr !== 'object' || Array.isArray(pr) || Object.keys(pr).length === 0 || Object.keys(pr).length > 64) throw new Error('config.providerRegions must be an object { provider: region } with 1..64 entries');
  for (const [p, r] of Object.entries(pr)) {
    if (!PROVIDER_RE.test(p) || ['__proto__', 'constructor', 'prototype'].includes(p)) throw new Error(`invalid provider name: ${String(p).slice(0, 40)}`);
    if (typeof r !== 'string' || !REGION_RE.test(r)) throw new Error(`invalid region for provider ${p}`);
  }
}

function preprocess(config) {
  // derived under underscore keys so that policyHash ignores them
  return { ...config, _allowed: new Set(config.allowedRegions || [config.tenantRegion]), _providers: new Map(Object.entries(config.providerRegions)) };
}

function evaluate(context, config) {
  const provider = context && context.action;
  if (typeof provider !== 'string' || !provider) return { pass: false, reason: 'RESIDENCY_PROVIDER_UNKNOWN' };
  const region = config._providers.get(provider);
  if (!region) return { pass: false, reason: 'RESIDENCY_PROVIDER_REGION_UNKNOWN' };
  if (!config._allowed.has(region)) return { pass: false, reason: 'RESIDENCY_CROSS_REGION_BLOCKED' };
  return { pass: true };
}

module.exports = { validate, preprocess, evaluate, FORMAT };
