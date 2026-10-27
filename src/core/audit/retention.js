'use strict';

/**
 * QODIQA Audit Retention Engine
 *
 * Enforces configurable retention policies on platform_audit_events.
 *
 * Design constraints:
 *   - ENFORCEMENT category events are NEVER subject to automated deletion.
 *   - Legal holds block deletion unconditionally, regardless of retain_until.
 *   - Deletions are batched (BATCH_SIZE rows) to avoid long table locks.
 *   - Every retention run is journaled in audit_retention_runs.
 *
 * ROLE SEPARATION: the automated cleanup cycle's own statements —
 * stampRetentionDates()'s UPDATE and expireEvents()'s DELETE, both issued by
 * runRetentionCycle() on a schedule with no human in the loop — run through
 * retentionPool (src/infra/postgres/retentionPool.js), authenticated as the
 * dedicated qodiqa_retention role (migration
 * 038_retention_dedicated_role.sql). That role holds only SELECT on
 * audit_retention_policies, SELECT/INSERT on audit_retention_runs, and
 * SELECT/UPDATE/DELETE on platform_audit_events — nothing else.
 *
 * The remaining functions below (listPolicies/upsertPolicy/placeLegalHold/
 * listLegalHolds/releaseLegalHold/listRuns) stay on the general-purpose
 * pgPool: they are human-triggered, RBAC-gated admin-API operations, not
 * part of the unattended DELETE cycle this role separation scopes.
 */

const pgPool        = require('../../infra/postgres/pool');
const retentionPool = require('../../infra/postgres/retentionPool');
const rolePools = require('../../infra/postgres/rolePools'); // operator retention views run as qodiqa_reporting
const { emit } = require('../../../services/logger');
const metrics = require('../../observability/metrics');

const BATCH_SIZE = 1000;

// ── Structured PG error classification ─────────────────────
//
// Distinguishes a missing base GRANT (Postgres throws "permission denied for
// table X", SQLSTATE 42501) from every other failure so operators get an
// actionable diagnostic — table, operation, database role, SQLSTATE, and the
// raw PostgreSQL error message — instead of a bare error.message. See
// retentionPrivilegeCheck.js for why an RLS-only gap does NOT throw here
// (it silently deletes/updates 0 rows instead); that class of failure is
// caught at startup, not at runtime, for exactly that reason.
function _classifyPgError(err, operation) {
  const isPermissionDenied = err?.code === '42501';
  return {
    table:      'platform_audit_events',
    operation,
    role:       process.env.QODIQA_PG_RETENTION_USER || 'qodiqa_retention',
    sqlstate:   err?.code ?? null,
    pgMessage:  err?.message ?? String(err),
    reason:     isPermissionDenied ? 'GRANT_MISSING' : 'UNKNOWN',
  };
}

// ── Policy management ─────────────────────────────────────────────────────────

/**
 * List all retention policies, ordered by id.
 */
async function listPolicies() {
  if (!pgPool.isEnabled()) return [];

  // (register-named): the GET /audit-store/retention/policies route
  // accepts no tenantId at all -- an ops-wide listing (Shape G) -- so a
  // plain query's arp_tenant_select restriction to platform-level rows only
  // hid every tenant-scoped retention policy from the ops console. Fixed via
  // the SECURITY DEFINER full-read bypass (migration 053). See
  // D1.
  const result = await rolePools.reporting.query(
    'SELECT * FROM qodiqa_audit_retention_policies_full_read() ORDER BY id ASC',
    [],
    'retention_list_policies',
  );
  return result.rows;
}

/**
 * Create or update a retention policy.
 * Use retain_days = 0 for indefinite retention.
 */
async function upsertPolicy({
  name,
  description,
  eventCategory,
  eventTypePattern,
  tenantId,
  severity,
  retainDays,
  complianceProfile,
}) {
  if (!name)                throw new Error('name is required');
  if (retainDays == null)   throw new Error('retainDays is required');
  if (!pgPool.isEnabled())  throw new Error('PostgreSQL not enabled');

  // (register-named): a plain query never set qodiqa.tenant_id, so a
  // tenant-scoped policy's INSERT failed arp_tenant_insert's WITH CHECK
  // (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant()) unconditionally.
  // Platform-level policies (tenantId null) are unaffected -- that predicate
  // already admits them under a plain query.
  const sql = `
    INSERT INTO audit_retention_policies
      (name, description, event_category, event_type_pattern, tenant_id,
       severity, retain_days, compliance_profile)
    VALUES
      ($1, $2, $3::audit_category, $4, $5, $6, $7, $8)
    ON CONFLICT (name) DO UPDATE SET
      description        = EXCLUDED.description,
      event_category     = EXCLUDED.event_category,
      event_type_pattern = EXCLUDED.event_type_pattern,
      tenant_id          = EXCLUDED.tenant_id,
      severity           = EXCLUDED.severity,
      retain_days        = EXCLUDED.retain_days,
      compliance_profile = EXCLUDED.compliance_profile,
      updated_at         = NOW()
    RETURNING *
  `;
  const params = [
    name,
    description      ?? null,
    eventCategory    ?? null,
    eventTypePattern ?? null,
    tenantId         ?? null,
    severity         ?? null,
    retainDays,
    complianceProfile ?? null,
  ];

  const result = tenantId
    ? await pgPool.withTenantTransaction(tenantId, (tx) => tx.query(sql, params))
    : await pgPool.query(sql, params, 'retention_upsert_policy');

  return result.rows[0];
}

// ── Retention stamping ────────────────────────────────────────────────────────

/**
 * Stamp retain_until on events that do not yet have a retention date.
 * Each policy with retain_days > 0 contributes a retain_until value.
 * The minimum (earliest expiry) wins when multiple policies match — the
 * most restrictive retention always takes effect.
 *
 * ENFORCEMENT category events are explicitly excluded from stamping.
 */
// step 6: request_trails fallback when no platform-wide OPERATIONAL policy with a period exists (never indefinite).
const TRAIL_FALLBACK_RETAIN_DAYS = 30;

async function stampRetentionDates() {
  if (!retentionPool.isEnabled()) return { stamped: 0 };

  const policies = await retentionPool.query(
    `SELECT id, event_category, event_type_pattern, tenant_id, severity, retain_days
     FROM audit_retention_policies
     WHERE retain_days > 0
     ORDER BY retain_days ASC`,
    [],
    'retention_load_policies',
  );

  let totalStamped = 0;

  for (const pol of policies.rows) {
    const clauses = [
      'retain_until IS NULL',
      "event_category != 'ENFORCEMENT'",
    ];
    const params = [];
    let p = 1;

    if (pol.event_category) {
      clauses.push(`event_category = $${p++}::audit_category`);
      params.push(pol.event_category);
    }
    if (pol.event_type_pattern) {
      clauses.push(`event_type LIKE $${p++}`);
      params.push(pol.event_type_pattern);
    }
    if (pol.tenant_id) {
      clauses.push(`tenant_id = $${p++}`);
      params.push(pol.tenant_id);
    }
    if (pol.severity) {
      clauses.push(`severity = $${p++}`);
      params.push(pol.severity);
    }

    const retainUntil = new Date();
    retainUntil.setDate(retainUntil.getDate() + pol.retain_days);
    params.push(retainUntil);

    const res = await retentionPool.query(
      `UPDATE platform_audit_events
       SET retain_until = $${p}
       WHERE ${clauses.join(' AND ')}`,
      params,
      'retention_stamp',
    );
    totalStamped += res.rowCount ?? 0;
  }

  // step 6 : request_trails hold personal data (caller IP, identity id) and take the retention of
  // NON-ENFORCEMENT OPERATIONAL events — the platform-wide OPERATIONAL policy's period, stamped the same way. Never
  // indefinite: with no such policy (or retain_days 0) the seeded 30-day operational default applies.
  const op = policies.rows.find((x) => x.event_category === 'OPERATIONAL' && !x.event_type_pattern && !x.tenant_id && !x.severity);
  const trailDays = op && op.retain_days > 0 ? op.retain_days : TRAIL_FALLBACK_RETAIN_DAYS;
  const trailUntil = new Date();
  trailUntil.setDate(trailUntil.getDate() + trailDays);
  const tr = await retentionPool.query('UPDATE request_trails SET retain_until = $1 WHERE retain_until IS NULL', [trailUntil], 'retention_stamp_trails');

  return { stamped: totalStamped, trailsStamped: tr.rowCount ?? 0, trailRetainDays: trailDays };
}

// ── Expiry ────────────────────────────────────────────────────────────────────

/**
 * Delete events whose retain_until has passed and that are not under legal hold.
 * ENFORCEMENT events are never deleted (double guard: no stamp + explicit WHERE).
 * Returns { expired, held, durationMs }.
 */
async function expireEvents() {
  if (!retentionPool.isEnabled()) return { expired: 0, held: 0, durationMs: 0 };

  const start = Date.now();
  let expired = 0;

  // Count how many would-be-expired events are blocked by legal hold
  const holdCnt = await retentionPool.query(`
    SELECT count(*) AS held
    FROM platform_audit_events
    WHERE retain_until < NOW()
      AND legal_hold = true
  `, [], 'retention_count_held');
  const held = Number(holdCnt.rows[0]?.held ?? 0);

  // Batch-delete eligible expired events
  let batchSize = BATCH_SIZE;
  while (batchSize === BATCH_SIZE) {
    const res = await retentionPool.query(`
      DELETE FROM platform_audit_events
      WHERE id IN (
        SELECT id
        FROM platform_audit_events
        WHERE retain_until < NOW()
          AND legal_hold = false
          AND event_category != 'ENFORCEMENT'
        ORDER BY occurred_at ASC
        LIMIT $1
        FOR UPDATE SKIP LOCKED
      )
    `, [BATCH_SIZE], 'retention_expire_batch');

    batchSize = res.rowCount ?? 0;
    expired  += batchSize;
  }

  // step 6: expired request_trails (OPERATIONAL retention, see stampRetentionDates), legal hold respected.
  let trailsExpired = 0;
  for (let n = BATCH_SIZE; n === BATCH_SIZE;) {
    const res = await retentionPool.query(`
      DELETE FROM request_trails
      WHERE id IN (SELECT id FROM request_trails WHERE retain_until < NOW() AND legal_hold = false
                   ORDER BY retain_until ASC LIMIT $1 FOR UPDATE SKIP LOCKED)`, [BATCH_SIZE], 'retention_expire_trails');
    n = res.rowCount ?? 0;
    trailsExpired += n;
  }

  const durationMs = Date.now() - start;

  await retentionPool.query(
    `INSERT INTO audit_retention_runs (events_expired, events_held, duration_ms, status)
     VALUES ($1, $2, $3, 'COMPLETE')`,
    [expired, held, durationMs],
    'retention_log_run',
  ).catch((err) => emit('WARN', 'AUDIT_RETENTION_RUN_RECORD_FAILED', { status: 'COMPLETE', error: err.message })); //

  return { expired, held, durationMs, trailsExpired };
}

// ── Legal holds ───────────────────────────────────────────────────────────────

/**
 * Place a legal hold preventing deletion of events matching the given scope.
 * At least one of { artifactId, tenantId, eventCategory } must be provided.
 */
async function placeLegalHold({ holdName, reason, artifactId, tenantId, eventCategory, heldBy }) {
  if (!holdName || typeof holdName !== 'string') throw new Error('holdName is required');
  if (!reason   || typeof reason   !== 'string') throw new Error('reason is required');
  if (!heldBy   || typeof heldBy   !== 'string') throw new Error('heldBy is required');
  if (!artifactId && !tenantId && !eventCategory) {
    throw new Error('At least one of artifactId, tenantId, or eventCategory is required');
  }
  if (!pgPool.isEnabled()) throw new Error('PostgreSQL not enabled');

  // (register-named, INSERT half only): a tenant-scoped hold's
  // INSERT failed alh_tenant_insert's WITH CHECK (tenant_id IS NULL OR
  // tenant_id = qodiqa_current_tenant()) under plain withTransaction(), which
  // never sets session tenant context. withTenantTransaction fixes it when
  // tenantId is supplied; the platform-level case (tenantId absent) is
  // unaffected -- that predicate already admits it.
  //
  // The UPDATE half below is a SEPARATE, NOT-fixed-by-this-change defect:
  // platform_audit_events has no UPDATE policy at all (only pae_tenant_select/
  // pae_system_insert exist), so under FORCE RLS this UPDATE silently affects
  // 0 rows for EVERY role regardless of tenant context, before and after this
  // fix. Adding a UPDATE policy is a schema change outside's minimal-
  // change discipline -- D4.
  const runHold = tenantId
    ? (fn) => pgPool.withTenantTransaction(tenantId, fn)
    : (fn) => pgPool.withTransaction(fn);

  const eventsHeld = await runHold(async (tx) => {
    await tx.query(
      `INSERT INTO audit_legal_holds
         (hold_name, reason, artifact_id, tenant_id, event_category, held_by)
       VALUES ($1, $2, $3, $4, $5::audit_category, $6)`,
      [holdName, reason, artifactId ?? null, tenantId ?? null, eventCategory ?? null, heldBy],
    );

    const clauses = [];
    const params  = [];
    let   p       = 1;

    if (artifactId)    { clauses.push(`artifact_id = $${p++}`);                    params.push(artifactId); }
    if (tenantId)      { clauses.push(`tenant_id = $${p++}`);                      params.push(tenantId); }
    if (eventCategory) { clauses.push(`event_category = $${p++}::audit_category`); params.push(eventCategory); }

    const res = await tx.query(
      `UPDATE platform_audit_events
       SET legal_hold = true
       WHERE (${clauses.join(' OR ')}) AND legal_hold = false`,
      params,
    );

    return res.rowCount ?? 0;
  });

  emit('INFO', 'AUDIT_LEGAL_HOLD_PLACED', {
    holdName, reason, artifactId, tenantId, eventCategory, heldBy, eventsHeld,
  });

  return { eventsHeld };
}

/**
 * List all active (unreleased) legal holds.
 */
async function listLegalHolds() {
  if (!pgPool.isEnabled()) return [];

  // (register-named): GET /audit-store/retention/holds accepts no
  // tenantId at all -- ops-wide listing (Shape G) -- see listPolicies()'s
  // comment above for the identical rationale.
  const result = await rolePools.reporting.query(
    `SELECT * FROM qodiqa_audit_legal_holds_full_read() WHERE released_at IS NULL ORDER BY held_at DESC`,
    [],
    'retention_list_holds',
  );
  return result.rows;
}

/**
 * Release a legal hold by name.  Does not un-mark events — those retain their
 * retain_until dates and will expire naturally in the next retention cycle.
 *
 * accepts an optional tenantId ('s own recorded open
 * item — "no route threads a tenantId to this function"). Without it, this
 * stays scoped to platform-level (tenant_id IS NULL) holds only, unchanged
 * from prior behavior — a tenant-scoped hold's release now actually works
 * when the caller supplies the tenant, matching placeLegalHold()'s own
 * already-established conditional pattern.
 */
async function releaseLegalHold(holdName, releasedBy, tenantId = null) {
  if (!holdName)            throw new Error('holdName is required');
  if (!pgPool.isEnabled())  throw new Error('PostgreSQL not enabled');

  const runRelease = tenantId
    ? (fn) => pgPool.withTenantTransaction(tenantId, fn)
    : (fn) => fn({ query: (sql, params) => pgPool.query(sql, params, 'retention_release_hold') });

  const res = await runRelease((tx) => tx.query(
    `UPDATE audit_legal_holds
     SET released_at = NOW(), released_by = $2
     WHERE hold_name = $1 AND released_at IS NULL
     RETURNING *`,
    [holdName, releasedBy],
  ));

  if (res.rows.length === 0) throw new Error(`No active hold named: ${holdName}`);

  const hold = res.rows[0];
  emit('INFO', 'AUDIT_LEGAL_HOLD_RELEASED', { holdName, releasedBy, holdId: hold.id, tenantId });
  return hold;
}

// ── Retention run history ─────────────────────────────────────────────────────

async function listRuns(limit = 50) {
  if (!pgPool.isEnabled()) return [];

  const result = await pgPool.query(
    `SELECT * FROM audit_retention_runs ORDER BY run_at DESC LIMIT $1`,
    [Math.min(limit, 200)],
    'retention_list_runs',
  );
  return result.rows;
}

// ── Full retention cycle ──────────────────────────────────────────────────────

/**
 * Run the complete retention cycle: stamp + expire.
 * Safe to call concurrently — SKIP LOCKED prevents double-deletion.
 */
async function runRetentionCycle() {
  emit('INFO', 'AUDIT_RETENTION_CYCLE_STARTED', {});
  const cycleStart = Date.now();

  let stampResult  = { stamped: 0 };
  let expireResult = { expired: 0, held: 0, durationMs: 0 };
  let error        = null;
  let errorDetail  = null;

  // Run independently (not Promise.all) so a failure in one stage is
  // attributed to the correct operation (UPDATE for stamping, DELETE for
  // expiry) rather than collapsing both into one undifferentiated rejection.
  const [stampSettled, expireSettled] = await Promise.allSettled([
    stampRetentionDates(),
    expireEvents(),
  ]);

  if (stampSettled.status === 'fulfilled') {
    stampResult = stampSettled.value;
  } else {
    error       = stampSettled.reason.message;
    errorDetail = _classifyPgError(stampSettled.reason, 'UPDATE');
  }

  if (expireSettled.status === 'fulfilled') {
    expireResult = expireSettled.value;
  } else {
    error       = error ?? expireSettled.reason.message;
    errorDetail = errorDetail ?? _classifyPgError(expireSettled.reason, 'DELETE');
  }

  const cycleTotalMs = Date.now() - cycleStart;
  const role = process.env.QODIQA_PG_RETENTION_USER || 'qodiqa_retention';

  if (error) {
    emit('ERROR', 'AUDIT_RETENTION_CYCLE_FAILED', { error, role, ...errorDetail });
    if (errorDetail?.reason === 'GRANT_MISSING') {
      metrics.auditRetentionPermissionFailuresTotal.inc({ operation: errorDetail.operation });
    }
    metrics.auditRetentionRunsTotal.inc({ status: 'FAILED' });
    metrics.auditRetentionLastFailureTimestamp.set({}, Math.floor(Date.now() / 1000));
    await retentionPool.query(
      `INSERT INTO audit_retention_runs (events_expired, events_held, duration_ms, status, error)
       VALUES ($1, $2, $3, 'FAILED', $4)`,
      [expireResult.expired, expireResult.held, cycleTotalMs, error],
      'retention_log_failure',
    ).catch((err) => emit('WARN', 'AUDIT_RETENTION_RUN_RECORD_FAILED', { status: 'FAILED', error: err.message })); //
  } else {
    emit('INFO', 'AUDIT_RETENTION_CYCLE_COMPLETE', {
      stamped:     stampResult.stamped,
      expired:     expireResult.expired,
      held:        expireResult.held,
      durationMs:  expireResult.durationMs,
      cycleTotalMs,
      role,
    });
    metrics.auditRetentionRunsTotal.inc({ status: 'COMPLETE' });
    metrics.auditRetentionEventsExpiredTotal.inc({}, expireResult.expired);
    metrics.auditRetentionEventsHeldTotal.inc({}, expireResult.held);
    metrics.auditRetentionLastSuccessTimestamp.set({}, Math.floor(Date.now() / 1000));
  }
  metrics.auditRetentionDurationMs.observe({}, cycleTotalMs);

  return {
    stamped:  stampResult.stamped,
    expired:  expireResult.expired,
    held:     expireResult.held,
    error,
  };
}

module.exports = {
  listPolicies,
  upsertPolicy,
  stampRetentionDates,
  expireEvents,
  placeLegalHold,
  listLegalHolds,
  releaseLegalHold,
  listRuns,
  runRetentionCycle,
};
