'use strict';

/**
 * Usage Metering Service — (Action 2's single aggregation source).
 *
 * The ONE canonical entry point every usage-metering surface consumes —
 * the tenant-portal JSON API and the CSV export both call
 * aggregateTenantUsage() here, so they can never disagree: there is exactly
 * one aggregation implementation behind both (evidence → audit-log.js
 * aggregateTenantUsage → this service → API/export adapters).
 *
 * This module adds NO metering semantics of its own — the normative
 * definition of "usage" lives in src/core/usage/usageAggregation.js (and
 * its SQL twin in pg-audit-backend.js). What lives here is the request-
 * facing contract:
 *
 *   RANGE RESOLUTION (deterministic, documented):
 *     - `to`   defaults to the moment of the call; `from` defaults to
 *       `to` minus 30 days. Defaults affect only WHICH WINDOW is requested —
 *       never how an entry inside it is bucketed (that is always the entry's
 *       own hash-protected UTC timestamp; see usageAggregation.js).
 *     - the range is half-open [from, to): an entry at exactly `to` is not
 *       included — so consecutive [a,b) [b,c) windows never overlap and
 *       never miss an entry.
 *     - malformed timestamps, from >= to, and ranges longer than
 *       MAX_RANGE_DAYS (400 days — one year of daily rows plus slack; a
 *       documented cost bound, not a business rule) are rejected with
 *       USAGE_INVALID_RANGE, carried on err.code for the route layer to map
 *       to a 400. Nothing is ever silently coerced.
 *
 *   TENANT SCOPE: tenantId here is ALWAYS the server-derived identity
 *   (req.tenantContext.tenantId from the validated portal session — see
 *   src/middleware/portalAuth.js). This service validates its shape
 *   (same pattern as src/infra/postgres/tenantContext.js) and passes it to
 *   the evidence layer, where it is enforced again (tenant index /
 *   tenant-scoped SQL under RLS). It is never read from client input.
 */

const auditLog = require('../audit/audit-log.js');

// Mirrors src/infra/postgres/tenantContext.js's TENANT_ID_RE (and
// tenantRegistry.js) — the canonical QODIQA tenant-id shape.
const TENANT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

const DEFAULT_RANGE_DAYS = 30;
const MAX_RANGE_DAYS     = 400;
const DAY_MS             = 24 * 60 * 60 * 1000;

function _invalidRange(message) {
  const err = new Error(`USAGE_INVALID_RANGE: ${message}`);
  err.code = 'USAGE_INVALID_RANGE';
  return err;
}

function _parseInstant(value, label) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') throw _invalidRange(`${label} must be an ISO-8601 timestamp string`);
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw _invalidRange(`${label} is not a valid ISO-8601 timestamp`);
  return ms;
}

/**
 * Resolve and validate a metering range. Exported for direct unit testing.
 * @returns {{fromMs: number, toMs: number}}
 */
function resolveRange({ from, to } = {}, nowMs = Date.now()) {
  const toMs   = _parseInstant(to, 'to')     ?? nowMs;
  const fromMs = _parseInstant(from, 'from') ?? (toMs - DEFAULT_RANGE_DAYS * DAY_MS);
  if (fromMs >= toMs) throw _invalidRange('from must be strictly before to');
  if (toMs - fromMs > MAX_RANGE_DAYS * DAY_MS) {
    throw _invalidRange(`range must not exceed ${MAX_RANGE_DAYS} days`);
  }
  return { fromMs, toMs };
}

/**
 * Aggregate a tenant's usage from execution evidence.
 *
 * @param {{tenantId: string, from?: string, to?: string}} params —
 *   tenantId is the SERVER-DERIVED tenant identity; from/to optional
 *   ISO-8601 instants (see range resolution above).
 * @returns {Promise<{tenantId: string, range: {from: string, to: string},
 *   totals: object, series: Array<object>}>}
 */
async function aggregateTenantUsage({ tenantId, from, to } = {}) {
  if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) {
    const err = new Error('USAGE_INVALID_TENANT: tenantId must be a valid QODIQA tenant id');
    err.code = 'USAGE_INVALID_TENANT';
    throw err;
  }
  const { fromMs, toMs } = resolveRange({ from, to });
  const { totals, series } = await auditLog.aggregateTenantUsage(tenantId, { fromMs, toMs });
  return {
    tenantId,
    range: { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString() },
    totals,
    series,
  };
}

module.exports = { aggregateTenantUsage, resolveRange, DEFAULT_RANGE_DAYS, MAX_RANGE_DAYS };
