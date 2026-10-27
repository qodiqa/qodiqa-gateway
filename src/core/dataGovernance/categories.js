'use strict';

/**
 * The data inventory: every category of data QODIQA keeps, what it contains, where it lives, the bounds within which a tenant may set its retention, and whether an
 * enforcement engine exists for it today. The registry is the single list the DATA_RETENTION rule is validated against and the single place a reader finds "what do you keep".
 *
 * engine: 'audit-retention' enforced by src/core/ (platform_audit_events by event category; ENFORCEMENT events are never deleted automatically)
 *   engine: 'platform'          kept by the platform on its own schedule (backup / DR policy, hash chains that must stay verifiable); the tenant can READ the figure, not change it
 *
 * `minDays` / `maxDays` bound what a tenant may ask for (0 = indefinite, allowed only where `allowIndefinite`). A value outside the bounds is refused when the rule is validated.
 */

const CATEGORIES = Object.freeze({
  audit_security: { description: 'security events (authentication failures, key use, kill switch, policy changes)', contains: ['actor ids', 'client IPs', 'reasons'], store: 'platform_audit_events', engine: 'audit-retention', auditCategory: 'SECURITY', minDays: 365, maxDays: 3650, allowIndefinite: true, defaultDays: 730 },
  audit_access_control: { description: 'access-control events (role grants, MFA step-up, approvals of changes)', contains: ['user ids', 'client IPs'], store: 'platform_audit_events', engine: 'audit-retention', auditCategory: 'ACCESS_CONTROL', minDays: 365, maxDays: 3650, allowIndefinite: true, defaultDays: 730 },
  audit_operational: { description: 'operational events (startup, degradation, rate limiting)', contains: ['request ids', 'client IPs'], store: 'platform_audit_events', engine: 'audit-retention', auditCategory: 'OPERATIONAL', minDays: 30, maxDays: 730, allowIndefinite: false, defaultDays: 180 },
  audit_provider: { description: 'provider routing and failover events', contains: ['provider names', 'request ids'], store: 'platform_audit_events', engine: 'audit-retention', auditCategory: 'PROVIDER', minDays: 30, maxDays: 730, allowIndefinite: false, defaultDays: 180 },
  audit_enforcement_chain: { description: 'the enforcement hash chain (hashes and decisions; no prompt text)', contains: ['hashes', 'decisions', 'tenant ids'], store: 'audit chain', engine: 'platform', minDays: null, maxDays: null, allowIndefinite: true, defaultDays: 0, note: 'never deleted automatically: its value is that it stays verifiable' },
  agent_action_ledger: { description: 'agent action executions and approval requests (hashes and decisions; the arguments are held by an approval request while it is open)', contains: ['agent ids', 'action hashes', 'approver ids'], store: 'action_executions, approval_requests', engine: 'platform', minDays: null, maxDays: null, allowIndefinite: true, defaultDays: 0, note: 'part of the verifiable action chain; follows the backup and DR policy' },
  dlp_events: { description: 'DLP_TRANSFORM events (rule ids and the two text hashes; never the values)', contains: ['rule ids', 'hashes'], store: 'audit events and the log stream', engine: 'platform', minDays: null, maxDays: null, allowIndefinite: true, defaultDays: 0, note: 'carried by the audit categories above' },
});

const names = () => Object.keys(CATEGORIES);

/** @returns {string[]} problems; empty when the map { category: days } is acceptable */
function validateRetention(byCategory) {
  const out = [];
  for (const [cat, days] of Object.entries(byCategory)) {
    const c = Object.prototype.hasOwnProperty.call(CATEGORIES, cat) ? CATEGORIES[cat] : null;
    if (!c) { out.push(`unknown data category: ${String(cat).slice(0, 40)}`); continue; }
    if (c.engine === 'platform') { out.push(`category ${cat} is kept by the platform (${c.note}); a tenant cannot set its retention`); continue; }
    if (!Number.isInteger(days) || days < 0) { out.push(`category ${cat}: days must be a non-negative integer`); continue; }
    if (days === 0) { if (!c.allowIndefinite) out.push(`category ${cat} cannot be kept indefinitely`); continue; }
    if (days < c.minDays || days > c.maxDays) out.push(`category ${cat}: days must be between ${c.minDays} and ${c.maxDays}${c.allowIndefinite ? ' (or 0 = keep)' : ''}`);
  }
  return out;
}

/** The audit_retention_policies rows a DATA_RETENTION rule asks for, for one tenant. */
function retentionPlan(tenantId, byCategory) {
  const problems = validateRetention(byCategory);
  if (problems.length) throw new Error(problems[0]);
  return Object.entries(byCategory).filter(([cat]) => CATEGORIES[cat].engine === 'audit-retention').map(([cat, days]) => ({
    name: `tenant:${tenantId}:${cat}`, description: `data-retention rule: ${CATEGORIES[cat].description}`, eventCategory: CATEGORIES[cat].auditCategory, eventTypePattern: null, tenantId,
    severity: null, retainDays: days, complianceProfile: 'DATA_RETENTION_RULE',
  }));
}

/**
 * Apply the rule to the stores that have an engine. `upsertPolicy` is#upsertPolicy (injectable for tests). Categories kept by the platform cannot be in a
 * valid rule, so everything in the plan is applied.
 */
/** @param {any} tenantId @param {any} byCategory @param {{ upsertPolicy?: Function }} [opts] */
async function applyRetention(tenantId, byCategory, { upsertPolicy } = {}) {
  const up = upsertPolicy || require('../audit/retention').upsertPolicy;
  const plan = retentionPlan(tenantId, byCategory);
  for (const row of plan) await up(row);
  return { applied: plan.map((r) => ({ name: r.name, eventCategory: r.eventCategory, retainDays: r.retainDays })) };
}

/** The inventory as a plain list, for a report or an endpoint. */
function inventory() {
  return names().map((n) => ({ category: n, ...CATEGORIES[n] }));
}

module.exports = { CATEGORIES, names, validateRetention, retentionPlan, applyRetention, inventory };
