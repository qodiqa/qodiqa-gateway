'use strict';

/**
 * QODIQA Alert Store
 *
 * PostgreSQL-backed persistence for all alerting data.
 * Falls back to an in-memory ring buffer when PostgreSQL is disabled,
 * so the framework remains operational in development environments.
 *
 * All public methods are safe to call from the hot request path:
 * they never throw — failures are logged and swallowed internally.
 */

const crypto  = require('crypto');
const pgPool  = require('../../infra/postgres/pool');
const rolePools = require('../../infra/postgres/rolePools'); // operator /alerts reads (and escalation rehydrate) run as qodiqa_reporting
const { emit } = require('../../../services/logger');
const {
  SEVERITY, ALERT_STATUS, RETENTION, ALERT_TYPE,
} = require('../constants');

// ── In-memory fallback (ring buffer, capped at 10 000 entries) ─────────────────

const MAX_MEM_ALERTS = 10_000;
const _memAlerts     = [];       // newest-first push, oldest dropped when full
const _memIncidents  = new Map();

// this buffer NEVER DRAINS TO POSTGRESQL. Nothing in this module, or
// anywhere in src/alerting/, reconciles _memAlerts back into qodiqa_alerts: it
// is read by getAlert()/listAlerts()/getStats()/updateAlertStatus() in-process
// and is otherwise lost at shutdown. That is a reasonable degraded-mode buffer
// for the case it was written for (pgPool.isEnabled() === false), but it also
// silently absorbed the defect for as long as that defect existed:
// saveAlert()'s catch pushes here, so every alert whose INSERT failed with
// 42P10 looked successful to its caller — returned normally, counted by
// getStats(), listed by listAlerts() — while never reaching the database and
// vanishing at the next restart.
//
// Consequence, recorded rather than repaired: alerts raised before migration
// 047 shipped that landed only here are a KNOWN, UNRECOVERABLE LOSS. They
// cannot be reconstructed — there is no journal, and the events that produced
// them are not retained anywhere else. Nothing was corrupted; those alerts
// simply never existed in durable form.
//
// A drain/replay path (buffer on failure, reconcile on recovery) does not exist
// and is deliberately NOT added here: it is a separate durability design with
// its own ordering and duplicate-suppression questions, outside the approved
// fix, which was scoped to making the upsert work at all. See
//.
function _memPush(alert) {
  _memAlerts.unshift(alert);
  if (_memAlerts.length > MAX_MEM_ALERTS) _memAlerts.pop();
}

// ── Retention helper ──────────────────────────────────────────────────────────

function _retainUntil(severity) {
  const days = RETENTION[`${severity}_DAYS`] ?? RETENTION.MEDIUM_DAYS;
  const d    = new Date();
  d.setDate(d.getDate() + days);
  return d;
}

// ── Deduplication key ─────────────────────────────────────────────────────────

// the statuses migration 047's partial unique index
// (qodiqa_alerts_dedup_key_active_uq) is built over, and therefore the exact
// predicate saveAlert()'s ON CONFLICT must carry to infer it as an arbiter.
// Declared once here so the SQL below is generated from the same list a test
// asserts the shipped index against — the brittleness of partial-index
// inference was the one argument raised against this approach, so it is
// pinned mechanically rather than by convention.
//
// Deliberately the same three statuses migration 006's idx_alerts_status
// already treats as active. A row leaves this index when resolved, which frees
// its dedup_key so a recurrence opens a NEW alert rather than bumping a closed
// row's counter — the behavior a plain UNIQUE (dedup_key) would have lost.
const ACTIVE_ALERT_STATUSES = Object.freeze(['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING']);
const ACTIVE_STATUS_SQL_LIST = ACTIVE_ALERT_STATUSES.map(s => `'${s}'`).join(', ');

function buildDedupKey(alert) {
  const raw = [alert.type, alert.subtype, alert.tenantId ?? 'global',
               alert.sourceEvent ?? '', alert.publicKeyId ?? ''].join('|');
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 64);
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Persist a new alert.  Returns the saved alert (with generated id).
 *
 * @param {object} alert  — Validated alert from AlertEngine
 * @returns {Promise<object>}
 */
async function saveAlert(alert) {
  if (!pgPool.isEnabled()) {
    _memPush(alert);
    return alert;
  }

  try {
    const dedupKey    = buildDedupKey(alert);
    const retainUntil = _retainUntil(alert.severity);

    // a tenant-scoped alert MUST be written inside a tenant-context
    // transaction, for a reason that is not obvious from the INSERT itself.
    // Migration 018's qa_system_insert is `FOR INSERT TO qodiqa_app WITH CHECK
    // (true)` — deliberately permissive, with the comment "alert engine writes
    // without per-alert tenant context" — so the INSERT is never what RLS
    // refuses. The RETURNING clause is: it reads the new row back, which is
    // subject to the SELECT policy qa_tenant_select,
    // `USING (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())`.
    // A plain pgPool.query() never sets qodiqa.tenant_id, so for any alert
    // carrying a tenant_id that predicate is false and PostgreSQL raises 42501,
    // "new row violates row-level security policy". Proven by isolating the
    // clause against a live database as qodiqa_app: the identical tenant-scoped
    // INSERT succeeds without RETURNING (INSERT 0 1) and fails with it.
    //
    // This was invisible until's migration 047 fixed the arbiter — before
    // that, every insert died earlier with 42P10 and never reached RLS at all.
    // Same class as's ConsentStore fixes (findByKey/findById/list), and
    // it takes the same remedy: withTenantTransaction for the tenant-scoped
    // case, plain query for the platform-level (tenant_id IS NULL) case, which
    // qa_tenant_select admits unconditionally.
    // READ COMMITTED is pinned deliberately, not left to the default. Before
    // this fix a tenant-scoped alert went through a plain pgPool.query() —
    // autocommit, READ COMMITTED — so wrapping it in withTenantTransaction's
    // default REPEATABLE READ would newly expose this path to under RR,
    // PostgreSQL aborts a concurrent INSERT ... ON CONFLICT with SQLSTATE 40001
    // instead of waiting and re-evaluating. Measured, before pinning: 6
    // concurrent saves of one dedup_key landed only 2 rows' worth of
    // occurrences, the other 4 lost to "could not serialize access due to
    // concurrent update" and silently absorbed by _memPush. READ COMMITTED is
    // also simply the correct isolation for an upsert — the arbiter re-check is
    // exactly the behaviour RR removes. Fixing RLS must not cost concurrency on
    // a path that never had that problem.
    const runQuery = alert.tenantId
      ? (sql, params) => pgPool.withTenantTransaction(
          alert.tenantId, (tx) => tx.query(sql, params), { isolationLevel: 'READ COMMITTED' },
        )
      : (sql, params) => pgPool.query(sql, params, 'alert_save');

    const { rows } = await runQuery(`
      INSERT INTO qodiqa_alerts (
        id, alert_type, alert_subtype, severity, status, risk_score, confidence,
        title, description, tags, source_event, request_id, artifact_id, tenant_id,
        public_key_id, client_ip, actor_id, component, evidence, context,
        detected_at, next_escalation_at, retain_until, dedup_key, last_seen_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7,
        $8, $9, $10, $11, $12::uuid, $13, $14,
        $15, $16, $17, $18, $19::jsonb, $20::jsonb,
        $21, $22, $23, $24, $21
      )
      -- the WHERE is not a filter, it is the arbiter inference for
      -- migration 047's PARTIAL unique index
      -- qodiqa_alerts_dedup_key_active_uq. It must match that index's
      -- predicate EXACTLY or PostgreSQL cannot infer an arbiter and rejects
      -- the statement with 42P10 -- which is precisely the failure this fixes
      -- (the pre-existing idx_alerts_dedup_key is non-unique and
      -- multi-column, so it never qualified). ACTIVE_ALERT_STATUSES below is
      -- the single source of that predicate;
      -- __tests__/AlertStore.dedupKeyContract.test.js fails if this clause and
      -- the shipped index ever drift apart.
      ON CONFLICT (dedup_key) WHERE status IN (${ACTIVE_STATUS_SQL_LIST}) DO UPDATE
        SET deduplicated_count = qodiqa_alerts.deduplicated_count + 1,
            last_seen_at       = EXCLUDED.last_seen_at,
            risk_score         = GREATEST(qodiqa_alerts.risk_score, EXCLUDED.risk_score)
      RETURNING *
    `, [
      alert.id,
      alert.type,
      alert.subtype,
      alert.severity,
      alert.status,
      alert.riskScore,
      alert.confidence,
      alert.title,
      alert.description ?? '',
      alert.tags ?? [],
      alert.sourceEvent ?? null,
      alert.requestId   ?? null,
      alert.artifactId  ?? null,
      alert.tenantId    ?? null,
      alert.publicKeyId ?? null,
      alert.clientIp    ?? null,
      alert.actorId     ?? null,
      alert.component   ?? null,
      JSON.stringify(alert.evidence ?? {}),
      JSON.stringify(alert.context  ?? {}),
      alert.detectedAt instanceof Date ? alert.detectedAt : new Date(alert.detectedAt),
      alert.nextEscalationAt ?? null,
      retainUntil,
      dedupKey,
    ]);

    const saved = _rowToAlert(rows[0]);

    // Append creation history
    await _appendHistory(saved.id, 'CREATED', 'system', null, ALERT_STATUS.OPEN, {
      type: saved.type, subtype: saved.subtype, severity: saved.severity,
    });

    return saved;
  } catch (err) {
    emit('ERROR', 'ALERT_STORE_SAVE_FAILED', { error: err.message, alertId: alert.id });
    _memPush(alert);   // fallback to memory
    return alert;
  }
}

/**
 * Update alert status.  Validates allowed transitions.
 *
 * @param {string}  alertId
 * @param {string}  newStatus     — From ALERT_STATUS
 * @param {object}  [meta]        — { actor, note, resolvedBy, acknowledgedBy, tenantId }
 * meta.tenantId — required to act on a TENANT-SCOPED alert. Migration
 *   018's qa_tenant_update is
 *   `USING/WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())`,
 *   so without tenant context this UPDATE matches zero rows for such an alert
 *   (and its RETURNING would be refused by qa_tenant_select besides). Callers
 * holding only an id cannot know the tenant, which is the same shape
 *   hit on ConsentStore.findById() and solved the same way: an explicit,
 *   optional tenant argument. Platform-level alerts (tenant_id IS NULL) need
 *   nothing — both policies admit them unconditionally.
 * @returns {Promise<object|null>}
 */
async function updateAlertStatus(alertId, newStatus, meta = {}) {
  if (!pgPool.isEnabled()) {
    const a = _memAlerts.find(x => x.id === alertId);
    if (a) { a.status = newStatus; return a; }
    return null;
  }

  try {
    const extra = {};
    if (newStatus === ALERT_STATUS.ACKNOWLEDGED) {
      extra.acknowledged_at = new Date();
      extra.acknowledged_by = meta.actor ?? 'unknown';
    }
    if (newStatus === ALERT_STATUS.RESOLVED || newStatus === ALERT_STATUS.CLOSED) {
      extra.resolved_at     = new Date();
      extra.resolved_by     = meta.actor ?? 'unknown';
      extra.resolution_note = meta.note  ?? null;
    }

    const setClauses = ['status = $2'];
    const params     = [alertId, newStatus];
    let   pi         = 3;
    for (const [col, val] of Object.entries(extra)) {
      setClauses.push(`${col} = $${pi++}`);
      params.push(val);
    }

    const sql = `UPDATE qodiqa_alerts SET ${setClauses.join(', ')} WHERE id = $1 RETURNING *`;
    const { rows } = meta.tenantId
      ? await pgPool.withTenantTransaction(meta.tenantId, (tx) => tx.query(sql, params))
      : await pgPool.query(sql, params, 'alert_status_update');
    if (!rows.length) return null;

    const alert = _rowToAlert(rows[0]);
    await _appendHistory(alertId, 'STATUS_CHANGED', meta.actor ?? 'system', null, newStatus, extra);
    return alert;
  } catch (err) {
    emit('ERROR', 'ALERT_STORE_UPDATE_FAILED', { error: err.message, alertId });
    return null;
  }
}

/**
 * Record an escalation event.
 */
async function recordEscalation(alertId, { tenantId = null, fromLevel, toLevel, reason, notifiedRoles = [], detail = {} }) {
  if (!pgPool.isEnabled()) return;

  try {
    await pgPool.query(`
      INSERT INTO qodiqa_escalation_records (alert_id, from_level, to_level, trigger_reason, notified_roles, detail)
      VALUES ($1, $2, $3, $4, $5, $6::jsonb)
    `, [alertId, fromLevel, toLevel, reason, notifiedRoles, JSON.stringify(detail)], 'escalation_insert');

    // a second silent no-op beyond the register-named
    // incident-linking one -- qa_tenant_update's
    // USING/WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
    // made this UPDATE silently affect 0 rows for any tenant-scoped alert,
    // with no RETURNING to surface it. tenantId is now threaded from the one
    // live caller (EscalationService.js, which already has the full alert
    // object in scope). See D3.
    const runUpdate = tenantId
      ? (sql, params) => pgPool.withTenantTransaction(tenantId, (tx) => tx.query(sql, params))
      : (sql, params) => pgPool.query(sql, params, 'alert_escalation_update');

    await runUpdate(`
      UPDATE qodiqa_alerts
      SET escalation_level   = $2,
          last_escalated_at  = NOW()
      WHERE id = $1
    `, [alertId, toLevel]);

    await _appendHistory(alertId, 'ESCALATED', 'system', null, null,
      { fromLevel, toLevel, reason, notifiedRoles });
  } catch (err) {
    emit('ERROR', 'ALERT_STORE_ESCALATION_FAILED', { error: err.message, alertId });
  }
}

/**
 * Record a notification delivery attempt.
 */
async function recordNotification(alertId, { channel, recipient, status, responseCode, errorMessage, payloadHash }) {
  if (!pgPool.isEnabled()) return;

  try {
    await pgPool.query(`
      INSERT INTO qodiqa_notification_deliveries
        (alert_id, channel, recipient, status, attempt_count, attempted_at, sent_at, response_code, error_message, payload_hash)
      VALUES ($1, $2, $3, $4, 1, NOW(), $5, $6, $7, $8)
    `, [
      alertId, channel, recipient, status,
      status === 'SENT' ? new Date() : null,
      responseCode ?? null,
      errorMessage ?? null,
      payloadHash  ?? null,
    ], 'notification_insert');

    await _appendHistory(alertId, 'NOTIFICATION_SENT', channel, null, null,
      { channel, recipient, status });
  } catch (err) {
    emit('ERROR', 'ALERT_STORE_NOTIFICATION_FAILED', { error: err.message, alertId });
  }
}

/**
 * Fetch a single alert by ID.
 */
async function getAlert(alertId) {
  if (!pgPool.isEnabled()) {
    return _memAlerts.find(a => a.id === alertId) ?? null;
  }

  try {
    // qodiqa_alerts's own RLS (qa_tenant_select) restricts a plain
    // query with no session tenant context to platform-level rows only. This
    // is an RBAC-gated ops-only console (/alerts, opsAuth) with no
    // tenant-scoping middleware, so the fix is the SECURITY DEFINER
    // full-read bypass (migration 053), not withTenantTransaction. See
    // D1.
    const { rows } = await rolePools.reporting.query(
      'SELECT * FROM qodiqa_qodiqa_alerts_full_read() WHERE id = $1', [alertId], 'alert_get'
    );
    return rows.length ? _rowToAlert(rows[0]) : null;
  } catch (err) {
    emit('ERROR', 'ALERT_STORE_GET_FAILED', { error: err.message, alertId });
    return null;
  }
}

/**
 * List alerts with flexible filtering and pagination.
 *
 * @param {object} opts
 * @param {string}   [opts.status]
 * @param {string}   [opts.severity]
 * @param {string}   [opts.type]
 * @param {string}   [opts.tenantId]
 * @param {string}   [opts.requestId]
 * @param {string}   [opts.artifactId]
 * @param {string}   [opts.incidentId]
 * @param {Date}     [opts.from]
 * @param {Date}     [opts.to]
 * @param {number}   [opts.page]       — 1-based
 * @param {number}   [opts.pageSize]   — default 50, max 200
 * @param {string}   [opts.sort]       — 'detected_at_desc' | 'risk_score_desc' | 'severity_desc'
 * @returns {Promise<{ alerts: object[], total: number, page: number, pageSize: number }>}
 */
async function listAlerts(opts = {}) {
  if (!pgPool.isEnabled()) {
    return _memList(opts);
  }

  try {
    const where   = [];
    const params  = [];
    let   pi      = 1;

    const addFilter = (col, val) => { where.push(`${col} = $${pi++}`); params.push(val); };

    if (opts.status)     addFilter('status', opts.status);
    if (opts.severity)   addFilter('severity', opts.severity);
    if (opts.type)       addFilter('alert_type', opts.type);
    if (opts.tenantId)   addFilter('tenant_id', opts.tenantId);
    if (opts.incidentId) addFilter('incident_id', opts.incidentId);
    if (opts.requestId)  { where.push(`request_id = $${pi++}::uuid`); params.push(opts.requestId); }
    if (opts.artifactId) addFilter('artifact_id', opts.artifactId);
    if (opts.from)       { where.push(`detected_at >= $${pi++}`); params.push(opts.from); }
    if (opts.to)         { where.push(`detected_at <= $${pi++}`); params.push(opts.to); }

    const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';

    // Every branch ends in `, id DESC` — a unique tie-breaker so pagination
    // stays deterministic across pages even when the leading sort column(s)
    // have duplicate values (API-4 remediation).
    const SORT_MAP = {
      'detected_at_desc': 'detected_at DESC, id DESC',
      'risk_score_desc':  'risk_score DESC, detected_at DESC, id DESC',
      'severity_desc':    'severity DESC, detected_at DESC, id DESC',
    };
    const orderBy = SORT_MAP[opts.sort] ?? 'detected_at DESC, id DESC';

    const pageSize = Math.min(parseInt(opts.pageSize, 10) || 50, 200);
    const page     = Math.max(parseInt(opts.page, 10) || 1, 1);
    const offset   = (page - 1) * pageSize;

    // opts.tenantId was already an existing WHERE filter here, but
    // with no session tenant context ever set qa_tenant_select's RLS
    // predicate restricted every call -- filtered or not -- to platform-level
    // rows only, so a real tenantId filter ANDed with that restriction was
    // always the empty set. When a caller supplies one tenantId, scope the
    // read correctly via withTenantTransaction (Shape T). When no tenantId
    // is given (the ops "list everything" case, /alerts console, opsAuth),
    // use the SECURITY DEFINER full-read bypass (Shape G) so the existing
    // multi-filter WHERE clause runs against every tenant's rows instead of
    // only NULL-tenant ones. See D1.
    const listSql  = `SELECT * FROM %FROM% ${whereClause} ORDER BY ${orderBy} LIMIT $${pi} OFFSET $${pi + 1}`;
    const countSql = `SELECT COUNT(*) AS total FROM %FROM% ${whereClause}`;
    const listParams  = [...params, pageSize, offset];

    const [dataRes, countRes] = opts.tenantId
      ? await pgPool.withTenantTransaction(opts.tenantId, (tx) => Promise.all([
          tx.query(listSql.replace('%FROM%', 'qodiqa_alerts'), listParams),
          tx.query(countSql.replace('%FROM%', 'qodiqa_alerts'), params),
        ]))
      : await Promise.all([
          rolePools.reporting.query(listSql.replace('%FROM%', 'qodiqa_qodiqa_alerts_full_read()'), listParams, 'alert_list'),
          rolePools.reporting.query(countSql.replace('%FROM%', 'qodiqa_qodiqa_alerts_full_read()'), params, 'alert_count'),
        ]);

    return {
      alerts:   dataRes.rows.map(_rowToAlert),
      total:    parseInt(countRes.rows[0]?.total ?? 0, 10),
      page,
      pageSize,
    };
  } catch (err) {
    emit('ERROR', 'ALERT_STORE_LIST_FAILED', { error: err.message });
    return _memList(opts);
  }
}

/**
 * Aggregate statistics for dashboard and reporting.
 */
async function getStats(opts = {}) {
  if (!pgPool.isEnabled()) {
    return _memStats();
  }

  try {
    const from = opts.from ?? new Date(Date.now() - 24 * 3600_000);
    const to   = opts.to   ?? new Date();

    const { rows } = await rolePools.reporting.query(`
      SELECT
        COUNT(*)                                          AS total,
        COUNT(*) FILTER (WHERE status = 'OPEN')          AS open,
        COUNT(*) FILTER (WHERE status = 'ACKNOWLEDGED')  AS acknowledged,
        COUNT(*) FILTER (WHERE status = 'RESOLVED')      AS resolved,
        COUNT(*) FILTER (WHERE severity = 'CRITICAL')    AS critical,
        COUNT(*) FILTER (WHERE severity = 'HIGH')        AS high,
        COUNT(*) FILTER (WHERE severity = 'MEDIUM')      AS medium,
        COUNT(*) FILTER (WHERE severity = 'LOW')         AS low,
        COUNT(*) FILTER (WHERE severity = 'INFO')        AS info,
        COUNT(*) FILTER (WHERE alert_type = 'REPLAY_ATTACK')     AS replay_attacks,
        COUNT(*) FILTER (WHERE alert_type = 'SIGNATURE_FAILURE') AS signature_failures,
        COUNT(*) FILTER (WHERE alert_type = 'POLICY_FAILURE')    AS policy_failures,
        COUNT(*) FILTER (WHERE alert_type = 'ANOMALY')           AS anomalies,
        COUNT(*) FILTER (WHERE alert_type = 'OPERATIONAL')       AS operational,
        AVG(EXTRACT(EPOCH FROM (acknowledged_at - detected_at)) * 1000)
          FILTER (WHERE acknowledged_at IS NOT NULL)     AS mean_tta_ms,
        AVG(EXTRACT(EPOCH FROM (resolved_at - detected_at)) * 1000)
          FILTER (WHERE resolved_at IS NOT NULL)         AS mean_ttr_ms
      FROM qodiqa_qodiqa_alerts_full_read()
      WHERE detected_at BETWEEN $1 AND $2
    `, [from, to], 'alert_stats');

    const r = rows[0] ?? {};
    return {
      window:             { from: from.toISOString(), to: to.toISOString() },
      total:              +r.total              || 0,
      byStatus:           { open: +r.open || 0, acknowledged: +r.acknowledged || 0, resolved: +r.resolved || 0 },
      bySeverity:         { CRITICAL: +r.critical || 0, HIGH: +r.high || 0, MEDIUM: +r.medium || 0, LOW: +r.low || 0, INFO: +r.info || 0 },
      byType:             { REPLAY_ATTACK: +r.replay_attacks || 0, SIGNATURE_FAILURE: +r.signature_failures || 0, POLICY_FAILURE: +r.policy_failures || 0, ANOMALY: +r.anomalies || 0, OPERATIONAL: +r.operational || 0 },
      meanTimeToAckMs:    r.mean_tta_ms ? Math.round(+r.mean_tta_ms) : null,
      meanTimeToResolveMs: r.mean_ttr_ms ? Math.round(+r.mean_ttr_ms) : null,
    };
  } catch (err) {
    emit('ERROR', 'ALERT_STORE_STATS_FAILED', { error: err.message });
    return _memStats();
  }
}

/**
 * Fetch alert history (audit trail of state changes).
 */
async function getAlertHistory(alertId) {
  if (!pgPool.isEnabled()) return [];

  try {
    // same bypass as getAlert()'s comment above, applied to
    // qodiqa_alert_history's own FK-based RLS (qah_tenant_select).
    const { rows } = await rolePools.reporting.query(
      'SELECT * FROM qodiqa_qodiqa_alert_history_full_read() WHERE alert_id = $1 ORDER BY ts ASC',
      [alertId], 'alert_history'
    );
    return rows.map(r => ({
      id: r.id, alertId: r.alert_id, ts: r.ts, action: r.action,
      actor: r.actor, fromStatus: r.from_status, toStatus: r.to_status,
      detail: r.detail,
    }));
  } catch (err) {
    emit('ERROR', 'ALERT_STORE_HISTORY_FAILED', { error: err.message, alertId });
    return [];
  }
}

/**
 * Save or update a correlated incident.
 */
async function saveIncident(incident) {
  if (!pgPool.isEnabled()) {
    _memIncidents.set(incident.id, incident);
    return incident;
  }

  try {
    await pgPool.query(`
      INSERT INTO qodiqa_incidents (id, title, description, severity, status, alert_count, alert_types, tenant_id, correlation_key, opened_at, retain_until)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      ON CONFLICT (id) DO UPDATE
        SET alert_count = EXCLUDED.alert_count,
            alert_types = EXCLUDED.alert_types,
            severity    = EXCLUDED.severity
    `, [
      incident.id, incident.title, incident.description ?? '',
      incident.severity, incident.status, incident.alertCount,
      incident.alertTypes ?? [], incident.tenantId ?? null,
      incident.correlationKey,
      incident.openedAt instanceof Date ? incident.openedAt : new Date(incident.openedAt),
      _retainUntil(incident.severity),
    ], 'incident_save');

    // Link alerts to incident
    // (register-named): qa_tenant_update's RLS predicate made this
    // UPDATE silently affect 0 rows for any tenant-scoped alert -- the
    // .catch(() => {}) swallows nothing because RLS filtering 0 rows is not
    // an error. incident.tenantId is already on the incident object.
    if (incident.alertIds?.length) {
      const runLink = incident.tenantId
        ? (sql, params) => pgPool.withTenantTransaction(incident.tenantId, (tx) => tx.query(sql, params))
        : (sql, params) => pgPool.query(sql, params, 'alert_link_incident');
      for (const aid of incident.alertIds) {
        await runLink(
          'UPDATE qodiqa_alerts SET incident_id = $2 WHERE id = $1',
          [aid, incident.id],
        ).catch(() => {});
      }
    }

    return incident;
  } catch (err) {
    emit('ERROR', 'ALERT_STORE_INCIDENT_FAILED', { error: err.message });
    return incident;
  }
}

/**
 * Look up active suppression rules for an incoming alert.
 * Returns true if the alert should be suppressed.
 */
async function isSuppressed(alert) {
  if (!pgPool.isEnabled()) return false;

  try {
    // this is a per-alert business check (Shape T), not ops search
    // -- alert.tenantId is already available on the input. qodiqa_suppression_rules'
    // own RLS (qsr_tenant_select: tenant_id IS NULL OR tenant_id =
    // qodiqa_current_tenant()) silently restricted a tenant-scoped alert's
    // check to platform-level suppression rules only, with no session
    // context ever set -- a configured tenant-specific suppression rule was
    // never actually effective. withTenantTransaction makes the existing
    // WHERE clause's "tenant_id IS NULL OR tenant_id = $4" match RLS's own
    // admitted set exactly. See D1.
    const runQuery = alert.tenantId
      ? (sql, params) => pgPool.withTenantTransaction(alert.tenantId, (tx) => tx.query(sql, params))
      : (sql, params) => pgPool.query(sql, params, 'suppression_check');

    const { rows } = await runQuery(`
      SELECT id FROM qodiqa_suppression_rules
      WHERE enabled = TRUE
        AND (expires_at IS NULL OR expires_at > NOW())
        AND (alert_type    IS NULL OR alert_type    = $1)
        AND (alert_subtype IS NULL OR alert_subtype = $2)
        AND (severity      IS NULL OR severity      = $3)
        AND (tenant_id     IS NULL OR tenant_id     = $4)
      LIMIT 1
    `, [alert.type, alert.subtype, alert.severity, alert.tenantId ?? null]);

    if (rows.length) {
      const incrementQuery = alert.tenantId
        ? (sql, params) => pgPool.withTenantTransaction(alert.tenantId, (tx) => tx.query(sql, params))
        : (sql, params) => pgPool.query(sql, params, 'suppression_increment');
      await incrementQuery(
        'UPDATE qodiqa_suppression_rules SET suppressed_count = suppressed_count + 1 WHERE id = $1',
        [rows[0].id],
      ).catch(() => {});
    }

    return rows.length > 0;
  } catch (err) {
    emit('ERROR', 'ALERT_STORE_SUPPRESSION_CHECK_FAILED', { error: err.message });
    return false;   // fail-open on suppression (better to alert than miss)
  }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

async function _appendHistory(alertId, action, actor, fromStatus, toStatus, detail) {
  try {
    await pgPool.query(`
      INSERT INTO qodiqa_alert_history (alert_id, action, actor, from_status, to_status, detail)
      VALUES ($1, $2, $3, $4, $5, $6::jsonb)
    `, [alertId, action, actor, fromStatus, toStatus, JSON.stringify(detail)], 'history_insert');
  } catch (_) { /* history is supplemental; never propagate */ }
}

function _rowToAlert(row) {
  if (!row) return null;
  return {
    id:               row.id,
    type:             row.alert_type,
    subtype:          row.alert_subtype,
    severity:         row.severity,
    status:           row.status,
    riskScore:        row.risk_score,
    confidence:       row.confidence,
    title:            row.title,
    description:      row.description,
    tags:             row.tags ?? [],
    sourceEvent:      row.source_event,
    requestId:        row.request_id,
    artifactId:       row.artifact_id,
    tenantId:         row.tenant_id,
    publicKeyId:      row.public_key_id,
    clientIp:         row.client_ip,
    actorId:          row.actor_id,
    component:        row.component,
    evidence:         row.evidence ?? {},
    context:          row.context  ?? {},
    detectedAt:       row.detected_at,
    acknowledgedAt:   row.acknowledged_at,
    acknowledgedBy:   row.acknowledged_by,
    resolvedAt:       row.resolved_at,
    resolvedBy:       row.resolved_by,
    resolutionNote:   row.resolution_note,
    suppressedUntil:  row.suppressed_until,
    escalationLevel:  row.escalation_level,
    lastEscalatedAt:  row.last_escalated_at,
    nextEscalationAt: row.next_escalation_at,
    incidentId:       row.incident_id,
    retainUntil:      row.retain_until,
    dedupKey:         row.dedup_key,
    deduplicatedCount:row.deduplicated_count,
    lastSeenAt:       row.last_seen_at,
  };
}

// ── In-memory fallback implementations ───────────────────────────────────────

function _memList(opts = {}) {
  let results = [..._memAlerts];
  if (opts.status)   results = results.filter(a => a.status   === opts.status);
  if (opts.severity) results = results.filter(a => a.severity === opts.severity);
  if (opts.type)     results = results.filter(a => a.type     === opts.type);
  if (opts.tenantId) results = results.filter(a => a.tenantId === opts.tenantId);
  const pageSize = Math.min(parseInt(opts.pageSize, 10) || 50, 200);
  const page     = Math.max(parseInt(opts.page, 10) || 1, 1);
  const start    = (page - 1) * pageSize;
  return {
    alerts:   results.slice(start, start + pageSize),
    total:    results.length,
    page,
    pageSize,
  };
}

function _memStats() {
  const sevCount = {};
  const typeCount = {};
  for (const a of _memAlerts) {
    sevCount[a.severity]   = (sevCount[a.severity]   || 0) + 1;
    typeCount[a.type]      = (typeCount[a.type]       || 0) + 1;
  }
  return {
    total: _memAlerts.length,
    byStatus:   { open: _memAlerts.filter(a => a.status === 'OPEN').length },
    bySeverity: sevCount,
    byType:     typeCount,
    meanTimeToAckMs: null,
    meanTimeToResolveMs: null,
  };
}

module.exports = {
  saveAlert,
  updateAlertStatus,
  recordEscalation,
  recordNotification,
  getAlert,
  listAlerts,
  getStats,
  getAlertHistory,
  saveIncident,
  isSuppressed,
  buildDedupKey,
  // exported so the drift test asserts the shipped migration's index
  // predicate against the very list saveAlert()'s ON CONFLICT is built from,
  // rather than against a hand-copied literal that could silently diverge.
  ACTIVE_ALERT_STATUSES,
};
