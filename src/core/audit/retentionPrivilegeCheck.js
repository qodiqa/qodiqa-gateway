'use strict';

/**
 * Startup Retention Privilege Validation —
 *
 * ROOT CAUSE (see migration 027_platform_audit_events_retention_grants_fix.sql
 * and retention.js's module header): this check exists to prove, once at
 * boot, that the exact statement shapes retention.js's automated cleanup
 * cycle issues will actually succeed — before the process starts serving
 * traffic — so a misconfigured deployment fails loudly at startup instead of
 * "succeeding" with silently unenforced retention forever.
 *
 * UPDATE — role separation changed WHO must be verified:
 *   The automated cleanup cycle (stampRetentionDates()/expireEvents(), via
 *   retention.js's runRetentionCycle()) now runs through retentionPool.js,
 *   authenticated as the dedicated qodiqa_retention role (migration
 *   038_retention_dedicated_role.sql) — not qodiqa_app. This check now
 *   verifies qodiqa_retention's actual grants and RLS policies, not
 *   qodiqa_app's.
 *
 * WHY THIS IS A CATALOG CHECK, NOT A LIVE ROLLED-BACK FUNCTIONAL PROBE
 * (unlike the original design, which inserted, updated, and deleted a
 * synthetic row inside one transaction that was always rolled back):
 *   A live functional probe of qodiqa_retention's UPDATE/DELETE requires a
 *   real row for it to act on. qodiqa_retention has no INSERT grant on
 *   platform_audit_events (retention never inserts audit events — see
 *   migration 038's header), so it cannot create that row itself. Two
 *   alternatives were considered and rejected:
 *     1. Insert the row via pgPool (qodiqa_app, which still has INSERT) and
 *        have retentionPool act on it in a SEPARATE transaction/connection —
 *        rejected: PostgreSQL transaction isolation means an uncommitted
 *        insert on one connection is invisible to a different connection, so
 *        this would require actually COMMITTING the synthetic row before
 *        retentionPool could see it — violating the documented invariant
 *        that "the compliance audit table must never contain even a
 *        transient synthetic row" (preserved from the original design).
 *     2. Grant qodiqa_app membership in qodiqa_retention (or vice versa) so
 *        one connection could `SET LOCAL ROLE` between the two mid-
 *        transaction — rejected: this creates a new trust/inheritance
 *        relationship between the two roles that does not otherwise exist,
 * which is exactly the kind of privilege-escalation surface's
 *        security requirements ("no new trust assumptions, no privilege
 *        escalation") rule out.
 *   Given those two are foreclosed, this check instead verifies
 *   qodiqa_retention's grants and RLS policies via PostgreSQL's own system
 *   catalog — has_table_privilege() for the three base grants, and a direct
 *   pg_policies read for the two RLS policies migration 038 created. This is
 *   NOT the weaker "catalog check" the original design warned wasn't enough:
 *   that warning was about a policy whose USING clause has a real per-row
 *   condition that might silently filter every row for reasons a catalog
 *   check can't see. Here the policies (pae_retention_update/
 *   pae_retention_delete) are unconditional (`USING (true)`) by construction
 *   in migration 038 — there is no per-row condition to hide a silent-filter
 *   bug behind, so confirming the exact expected policy row exists (role,
 *   command, and a `true` qual) is equivalent in strength to a live probe
 *   for this specific, fixed-shape policy pair.
 *   The connectivity/SELECT portion of this check IS still a live round
 *   trip through retentionPool (has_table_privilege() and the pg_policies
 *   read are both real SELECT queries) — only the mutating (UPDATE/DELETE)
 *   half is catalog-based rather than functionally exercised.
 *
 * FAIL-CLOSED: any thrown error (retentionPool unreachable) or any missing
 * grant/policy is FATAL — logged with table, operation, database role, and
 * detail, then process.exit(1) before the HTTP server starts accepting
 * connections.
 *
 * SCOPE: no-op when PostgreSQL is disabled (QODIQA_PG_ENABLED != 'true') —
 * there is nothing to validate against file-based persistence.
 *
 * METRICS (src/observability/metrics.js):
 *   qodiqa_audit_retention_privilege_check_success_total,
 *   qodiqa_audit_retention_privilege_check_failure_total{operation},
 *   qodiqa_audit_retention_privilege_check_duration_seconds.
 */

const { emit } = require('../../../services/logger');
const { writeDiagnostic: _writeDiagnostic } = require('../../runtime/rawStderrDiagnostic');

// Exact set of grants/policies retention.js's automated cycle actually
// relies on — see migration 038_retention_dedicated_role.sql.
const _REQUIRED_TABLE_PRIVILEGES = [
  { table: 'platform_audit_events',   privilege: 'SELECT' },
  { table: 'platform_audit_events',   privilege: 'UPDATE' },
  { table: 'platform_audit_events',   privilege: 'DELETE' },
  { table: 'audit_retention_policies', privilege: 'SELECT' },
  { table: 'audit_retention_runs',     privilege: 'SELECT' },
  { table: 'audit_retention_runs',     privilege: 'INSERT' },
  // step 6 (migration 069): request_trails — personal data under OPERATIONAL retention; the cycle stamps and
  // deletes them, so a role that cannot is a silently unenforced retention of personal data.
  { table: 'request_trails',           privilege: 'SELECT' },
  { table: 'request_trails',           privilege: 'UPDATE' },
  { table: 'request_trails',           privilege: 'DELETE' },
];

// SELECT is required alongside UPDATE/DELETE: PostgreSQL RLS requires a row
// to be visible under an applicable SELECT policy before an UPDATE/DELETE
// policy's USING clause is even consulted — see migration 038's header for
// the empirical confirmation of this.
//
// arp_retention_select (migration 054) added here — the startup
// gate previously verified qodiqa_retention's base SELECT *grant* on
// audit_retention_policies (via _REQUIRED_TABLE_PRIVILEGES below) but never
// verified the RLS *policy* that grant actually needs to return any rows.
// That gap meant the gate could not have caught the exact defect
// found (zero applicable policy → every SELECT silently returns 0 rows,
// startup still reports PASSED) — and, going forward, could not catch a
// regression that accidentally drops this policy either. See
// D4.
const _REQUIRED_RLS_POLICIES = [
  { table: 'platform_audit_events', policy: 'pae_retention_select', cmd: 'SELECT' },
  { table: 'platform_audit_events', policy: 'pae_retention_update', cmd: 'UPDATE' },
  { table: 'platform_audit_events', policy: 'pae_retention_delete', cmd: 'DELETE' },
  { table: 'audit_retention_policies', policy: 'arp_retention_select', cmd: 'SELECT' },
  { table: 'request_trails', policy: 'rt_retention_select', cmd: 'SELECT' },
  { table: 'request_trails', policy: 'rt_retention_update', cmd: 'UPDATE' },
  { table: 'request_trails', policy: 'rt_retention_delete', cmd: 'DELETE' },
];

/**
 * Verifies qodiqa_retention actually holds every grant and RLS policy
 * retention.js's automated cleanup cycle requires. Must be called once at
 * startup, after retentionPool.initialize().
 *
 * All dependencies are injectable for testing.
 *
 * @param {object}   [opts]
 * @param {object}   [opts._retentionPool] retentionPool.js module (default: src/infra/postgres/retentionPool.js)
 * @param {object}   [opts._metrics]       observability/metrics.js module
 * @param {function} [opts._exit]          Exit function (default: process.exit)
 * @param {function} [opts._emit]          Logger emit function (default: services/logger emit)
 * @param {function} [opts._now]           Clock function returning ms since epoch (default: Date.now)
 * @returns {Promise<boolean>} true if startup may proceed (false only after
 *   this function has already called _exit(1)).
 */
async function verifyRetentionPrivileges({
  _retentionPool = require('../../infra/postgres/retentionPool'),
  _metrics       = require('../../observability/metrics'),
  _exit          = (code) => process.exit(code),
  _emit          = emit,
  _now           = () => Date.now(),
} = {}) {
  if (!_retentionPool.isEnabled()) {
    _emit('INFO', 'AUDIT_RETENTION_PRIVILEGE_CHECK_SKIPPED', {
      reason: 'QODIQA_PG_ENABLED is not "true" — no PostgreSQL retention target to verify privileges against.',
    });
    return true;
  }

  const role = process.env.QODIQA_PG_RETENTION_USER || 'qodiqa_retention';
  const startedAt = _now();

  try {
    const missingPrivileges = [];
    for (const { table, privilege } of _REQUIRED_TABLE_PRIVILEGES) {
      const res = await _retentionPool.query(
        `SELECT has_table_privilege(current_user, $1::regclass, $2) AS granted`,
        [table, privilege],
        'retention_privilege_probe',
      );
      if (res.rows[0]?.granted !== true) {
        missingPrivileges.push({ table, privilege });
      }
    }

    const missingPolicies = [];
    for (const { table, policy, cmd } of _REQUIRED_RLS_POLICIES) {
      const res = await _retentionPool.query(
        `SELECT 1
           FROM pg_policies
          WHERE schemaname = 'public'
            AND tablename  = $1
            AND policyname = $2
            AND cmd         = $3
            AND $4 = ANY(roles)
            AND qual        = 'true'`,
        [table, policy, cmd, role],
        'retention_rls_policy_probe',
      );
      if (res.rows.length === 0) {
        missingPolicies.push({ table, policy, cmd });
      }
    }

    if (missingPrivileges.length > 0 || missingPolicies.length > 0) {
      throw Object.assign(
        new Error('retention privilege check: qodiqa_retention is missing required grants or RLS policies'),
        { missingPrivileges, missingPolicies },
      );
    }

    _metrics.auditRetentionPrivilegeCheckSuccessTotal.inc({});
    _metrics.auditRetentionPrivilegeCheckDurationSeconds.observe({}, (_now() - startedAt) / 1000);
    _emit('INFO', 'AUDIT_RETENTION_PRIVILEGE_CHECK_PASSED', {
      role,
      verified: [
        ..._REQUIRED_TABLE_PRIVILEGES.map(p => `${p.table}:${p.privilege}`),
        ..._REQUIRED_RLS_POLICIES.map(p => `${p.table}:${p.policy}`),
      ],
    });
    return true;
  } catch (err) {
    _metrics.auditRetentionPrivilegeCheckFailureTotal.inc({
      operation: err.missingPrivileges?.[0]?.privilege ?? err.missingPolicies?.[0]?.cmd ?? 'UNKNOWN',
    });
    _metrics.auditRetentionPrivilegeCheckDurationSeconds.observe({}, (_now() - startedAt) / 1000);

    _writeDiagnostic('FATAL', 'AUDIT_RETENTION_PRIVILEGE_CHECK_FAILED', {
      reason: 'The dedicated retention database role is missing a grant or RLS policy required by the ' +
              'automated audit retention job. Retention would fail (missing base grant) or silently ' +
              'delete nothing while reporting success (missing/misconfigured RLS policy) if the process ' +
              'were allowed to start.',
      role,
      sqlstate:  err.code ?? null,
      pgMessage: err.message,
      missingPrivileges: err.missingPrivileges ?? [],
      missingPolicies:   err.missingPolicies ?? [],
      action: 'Apply migration 038_retention_dedicated_role.sql (run the migration runner: ' +
              'node src/infra/postgres/migrate.js), then restart. This check never grants privileges ' +
              'itself — it only verifies they are already in place.',
      ref: 'src/infra/postgres/migrations/038_retention_dedicated_role.sql',
    });
    _exit(1);
    return false;
  }
}

module.exports = { verifyRetentionPrivileges };
