'use strict';

/**
 * QODIQA Compliance Evidence Collector
 *
 * Aggregates and normalizes evidence from all QODIQA data sources for
 * a given assessment period.  Evidence is collected per-type, normalized
 * into a standard envelope, and returned for validation and scoring.
 *
 * Evidence types collected:
 *   enforcement_events    — ALLOW/BLOCK decisions from platform_audit_events
 *   policy_records        — Active and historical policies from policies table
 *   audit_events          — All audit events in the period
 *   security_events       — SECURITY category events
 *   lifecycle_events      — LIFECYCLE category events
 *   key_management_events — KEY_MANAGEMENT category events
 *   anomaly_events        — Anomaly detection events from audit store
 *   audit_chain_entries   — Records from audit_chain table
 *   signed_artifacts      — Signing records (artifact IDs with signatures)
 *   rbac_users            — User and role records
 *   signing_key_records   — Active signing keys from signing_keys table
 *   consent_events        — Consent-related enforcement events
 */

const pgPool = require('../../infra/postgres/pool');

const COLLECT_TIMEOUT_MS = 30_000;

// every collector below that accepts a tenantId already adds it as
// a plain `AND tenant_id = $N` WHERE clause, but issues the query through
// plain pgPool.query() -- which never sets session tenant context. Combined
// with platform_audit_events'/audit_chain's RLS (tenant_id IS NULL OR
// tenant_id = qodiqa_current_tenant()), a real (non-null) tenantId's WHERE
// filter ANDed with RLS's NULL-only visibility is ALWAYS the empty set --
// every tenant-scoped compliance report's evidence bundle was silently 100%
// empty for every one of these categories. This helper makes the existing
// WHERE-based filtering actually take effect by running the query inside
// withTenantTransaction when tenantId is supplied; the platform-wide case
// (tenantId null/omitted) is unaffected -- unchanged plain query, matching
// what that call already did. See D1.
function _collectorQuery(tenantId, sql, params, label) {
  return tenantId
    ? pgPool.withTenantTransaction(tenantId, (tx) => tx.query(sql, params))
    : pgPool.query(sql, params, label);
}

// ── Normalised evidence envelope ──────────────────────────────────────────────

// events a row set stands for (aggregate_count, default 1 — migration 068), and the same capped at the
// listing's LIMIT, which is exactly what rowCount of the capped listing reported when every row was one event.
function _events(rows) { return rows.reduce((s, r) => s + (Number(r.aggregate_count) || 1), 0); }
function _cappedEvents(rows, limit) { return Math.min(_events(rows), limit); }

function _ev(type, sourceTable, sourceId, occurredAt, summary, meta = {}) {
  return {
    evidenceType: type,
    sourceTable,
    sourceId:     String(sourceId),
    occurredAt:   occurredAt ? new Date(occurredAt).toISOString() : null,
    summary,
    valid:        true,
    integrityOk:  true,
    metadata:     meta,
  };
}

// ── Collectors ────────────────────────────────────────────────────────────────

async function _collectEnforcementEvents(periodStart, periodEnd, tenantId) {
  const params = [periodStart, periodEnd];
  let where = `occurred_at >= $1 AND occurred_at <= $2 AND event_category = 'ENFORCEMENT'`;
  if (tenantId) { where += ` AND tenant_id = $${params.length + 1}`; params.push(tenantId); }

  const res = await _collectorQuery(tenantId, `
    SELECT event_id, occurred_at, event_type, outcome, actor_id, artifact_id,
            policy_id, tenant_id, payload, aggregate_count
     FROM platform_audit_events
     WHERE ${where}
     ORDER BY occurred_at DESC
     LIMIT 1000`,
    params,
    'compliance_collect_enforcement',
  );

  // a row may stand for aggregate_count events (per-minute aggregate of a routine success type,
  // migration 068). Counting EVENTS keeps every figure what it was: min(events, LIMIT) is exactly the old capped
  // rowCount; BLOCK events are never aggregated.
  const total  = _cappedEvents(res.rows, 1000);
  const blocks = _events(res.rows.filter(r => r.outcome === 'BLOCK'));
  const allows = _events(res.rows.filter(r => r.outcome === 'ALLOW'));

  return {
    evidenceType: 'enforcement_events',
    count:        total,
    blockCount:   blocks,
    allowCount:   allows,
    items:        res.rows.map(r => _ev(
      'enforcement_events',
      'platform_audit_events',
      r.event_id,
      r.occurred_at,
      `${r.event_type} | outcome=${r.outcome ?? 'n/a'}`,
      { outcome: r.outcome, artifactId: r.artifact_id, policyId: r.policy_id },
    )),
  };
}

async function _collectPolicyRecords() {
  // this read the legacy `policies` table, which only a one-off migration script ever populated —
  // the running system keeps policies in the control-plane store (src/core/policy/store.js), so the evidence was stale/empty.
  const { listPolicies } = require('../policy/store');
  const { policies: rows } = listPolicies({ page: 1, pageSize: Number.MAX_SAFE_INTEGER, sortBy: 'priority', sortDir: 'asc' });

  const active    = rows.filter(r => r.enabled && r.status === 'ACTIVE').length;
  const withConsent = rows.filter(r => r.type === 'REQUIRE_CONSENT' && r.enabled).length;

  return {
    evidenceType:   'policy_records',
    count:          rows.length,
    activeCount:    active,
    consentPolicies: withConsent,
    items:          rows.map(r => _ev(
      'policy_records',
      'policies',
      r.id,
      r.updatedAt,
      `${r.name} | type=${r.type} | enabled=${r.enabled} | v${r.currentVersion}`,
      { type: r.type, enabled: r.enabled, status: r.status, version: r.currentVersion,
        validationStatus: r.validationStatus },
    )),
  };
}

async function _collectAuditEvents(periodStart, periodEnd, tenantId, category = null) {
  const params = [periodStart, periodEnd];
  let where = `occurred_at >= $1 AND occurred_at <= $2`;
  if (category) { where += ` AND event_category = $${params.length + 1}::audit_category`; params.push(category); }
  if (tenantId) { where += ` AND tenant_id = $${params.length + 1}`; params.push(tenantId); }

  // both queries run inside the SAME tenant transaction when
  // tenantId is present (one setLocal, consistent snapshot) rather than two
  // independent _collectorQuery() calls.
  const [countRes, sampleRes] = tenantId
    ? await pgPool.withTenantTransaction(tenantId, (tx) => Promise.all([
        tx.query(`SELECT COALESCE(SUM(aggregate_count), 0) AS total,
            SUM(CASE WHEN severity IN ('FATAL','CRITICAL','ERROR') THEN aggregate_count ELSE 0 END) AS error_count,
            MIN(occurred_at) AS first_event,
            MAX(occurred_at) AS last_event
     FROM platform_audit_events
     WHERE ${where}`, params),
        tx.query(`SELECT event_id, occurred_at, event_type, event_category, severity, outcome
     FROM platform_audit_events
     WHERE ${where}
     ORDER BY occurred_at DESC
     LIMIT 200`, params),
      ]))
    : await Promise.all([
        pgPool.query(`SELECT COALESCE(SUM(aggregate_count), 0) AS total,
            SUM(CASE WHEN severity IN ('FATAL','CRITICAL','ERROR') THEN aggregate_count ELSE 0 END) AS error_count,
            MIN(occurred_at) AS first_event,
            MAX(occurred_at) AS last_event
     FROM platform_audit_events
     WHERE ${where}`, params, 'compliance_collect_events_count'),
        pgPool.query(`SELECT event_id, occurred_at, event_type, event_category, severity, outcome
     FROM platform_audit_events
     WHERE ${where}
     ORDER BY occurred_at DESC
     LIMIT 200`, params, 'compliance_collect_events_sample'),
      ]);

  const row      = countRes.rows[0] ?? {};
  const total    = Number(row.total ?? 0);
  const errCount = Number(row.error_count ?? 0);

  const label = category ? `${category} events` : 'all audit events';
  const evType = category
    ? { SECURITY: 'security_events', LIFECYCLE: 'lifecycle_events',
        KEY_MANAGEMENT: 'key_management_events' }[category] ?? 'audit_events'
    : 'audit_events';

  return {
    evidenceType: evType,
    count:        total,
    errorCount:   errCount,
    firstEvent:   row.first_event,
    lastEvent:    row.last_event,
    items:        sampleRes.rows.map(r => _ev(
      evType,
      'platform_audit_events',
      r.event_id,
      r.occurred_at,
      `${r.event_type} | sev=${r.severity}`,
      { category: r.event_category, severity: r.severity, outcome: r.outcome },
    )),
  };
}

// after an operator retention prune (scripts/audit/prune.js) the audit chain — and the evidence
// bound to it — no longer holds entries up to the prune's signed checkpoint. A period that reaches back before that
// point is reported as TRUNCATED BY RETENTION (with the checkpoint that vouches for the removed prefix and the archive
// that holds it) instead of silently presenting the kept rows as the whole period. null = the period is fully kept.
async function _auditRetention(periodStart) {
  try {
    const r = await pgPool.query(
      `SELECT checkpoint_id, to_count, pruned_at, archive_location, base_record->>'headRecordedAt' AS through
         FROM audit_chain_prunes ORDER BY to_count DESC LIMIT 1`, [], 'compliance_audit_retention');
    const row = r && r.rows && r.rows[0];
    if (!row || !row.through) return null;
    const through = new Date(row.through);
    if (!(periodStart <= through)) return null;
    return { periodTruncated: true, prunedThrough: through.toISOString(), prunedEntries: Number(row.to_count),
      checkpointId: row.checkpoint_id, prunedAt: new Date(row.pruned_at).toISOString(), archiveLocation: row.archive_location || null };
  } catch (e) {
    if (e && e.code === '42P01') return null; // pre-071 schema: no prune can have run
    return { periodTruncated: null, error: `AUDIT_RETENTION_UNKNOWN: ${e.message}` };
  }
}

// (R-F3): audit_chain rows written since the mirror projection hold P(value) in their per-field columns
// (mirror_encoding = 1); decode the ones this collector reports. The tenant filter needs no change: tenant ids are
// /^[A-Za-z0-9_-]{1,64}$/ (tenantContext.js), on which P is the identity. `signature != ''` is likewise unchanged
// (P('') === '').
function _decodeCollectedRow(r) {
  const { encodingOf, decodeString, MIRROR_ENCODING_ESCAPED } = require('../../infra/postgres/mirrorProjection');
  const { mirror_encoding: enc, ...rest } = r;
  if (encodingOf(enc, `audit_chain row ${r.hash}`) !== MIRROR_ENCODING_ESCAPED) return rest;
  for (const c of ['artifact_id', 'decision', 'signature', 'tenant_id']) {
    if (typeof rest[c] === 'string') rest[c] = decodeString(rest[c], `audit_chain row ${r.hash}.${c}`);
  }
  return rest;
}

async function _collectAuditChainEntries(periodStart, periodEnd, tenantId) {
  const params = [periodStart, periodEnd];
  let where = `recorded_at >= $1 AND recorded_at <= $2`;
  if (tenantId) { where += ` AND tenant_id = $${params.length + 1}`; params.push(tenantId); }

  const res = await _collectorQuery(tenantId, `
    SELECT hash, prev_hash, artifact_id, decision, recorded_at,
            verification_result, signature, tenant_id, mirror_encoding
     FROM audit_chain
     WHERE ${where}
     ORDER BY seq DESC
     LIMIT 500`,
    params,
    'compliance_collect_chain',
  );

  // Verify forward hash linkage on the sample (hash / prev_hash are never projected); per-field values decoded
  const rows = res.rows.map(_decodeCollectedRow);
  let chainBroken = false;
  for (let i = 0; i < rows.length - 1; i++) {
    if (rows[i].prev_hash !== rows[i + 1].hash) {
      chainBroken = true;
      break;
    }
  }

  const verifiedCount = rows.filter(r => r.verification_result === true).length;
  const retention = await _auditRetention(periodStart);

  return {
    evidenceType:   'audit_chain_entries',
    count:          res.rowCount ?? 0,
    chainBroken,
    verifiedCount,
    ...(retention ? { retention } : {}),
    items:          rows.slice(0, 100).map(r => _ev(
      'audit_chain_entries',
      'audit_chain',
      r.hash,
      r.recorded_at,
      `artifact=${r.artifact_id} | decision=${r.decision} | verified=${r.verification_result}`,
      { decision: r.decision, verificationResult: r.verification_result },
    )),
  };
}

async function _collectSignedArtifacts(periodStart, periodEnd, tenantId) {
  const params = [periodStart, periodEnd];
  let where = `recorded_at >= $1 AND recorded_at <= $2 AND signature IS NOT NULL AND signature != ''`;
  if (tenantId) { where += ` AND tenant_id = $${params.length + 1}`; params.push(tenantId); }

  const res = await _collectorQuery(tenantId, `
    SELECT hash, artifact_id, decision, recorded_at, verification_result, mirror_encoding
     FROM audit_chain
     WHERE ${where}
     ORDER BY recorded_at DESC
     LIMIT 500`,
    params,
    'compliance_collect_signed',
  );

  const retention = await _auditRetention(periodStart);

  return {
    evidenceType: 'signed_artifacts',
    count:        res.rowCount ?? 0,
    ...(retention ? { retention } : {}),
    items:        res.rows.slice(0, 100).map(_decodeCollectedRow).map(r => _ev(
      'signed_artifacts',
      'audit_chain',
      r.hash,
      r.recorded_at,
      `artifact=${r.artifact_id} | decision=${r.decision}`,
      { decision: r.decision, verified: r.verification_result },
    )),
  };
}

async function _collectRbacUsers() {
  // same as above — the legacy `rbac_users` table is not what the running system reads; the RBAC store is.
  const { listUsers } = require('../rbac/store');
  const rows = listUsers().filter(u => u.enabled !== false)
    .sort((x, y) => String(x.role).localeCompare(String(y.role)) || String(x.username).localeCompare(String(y.username)));

  const roleSet = new Set(rows.map(r => r.role));

  return {
    evidenceType: 'rbac_users',
    count:        rows.length,
    roleCount:    roleSet.size,
    roles:        [...roleSet],
    hasAdmin:     roleSet.has('admin'),
    items:        rows.map(r => _ev(
      'rbac_users',
      'rbac_users',
      r.id,
      r.createdAt,
      `${r.username} | role=${r.role}`,
      { role: r.role },
    )),
  };
}

async function _collectSigningKeys(tenantId) {
  //'s hand-off, remediated here: no tenant context was ever set for
  // this query. sk_tenant_select (migration 052) is STRICT -- client_id =
  // qodiqa_current_tenant(), no NULL/platform-level case -- so a report with
  // no tenantId has no legitimate row set to bypass into (unlike
  // platform_audit_events/audit_chain, which have genuine platform-level
  // rows); this returns an explicit empty result rather than querying with
  // no context (FAIL CLOSED, not a bypass invented for a table that was
  // never designed to have one). A tenant-scoped report now genuinely sees
  // its own signing keys instead of silently zero. See
  // D6.
  if (!tenantId) {
    return {
      evidenceType: 'signing_key_records', count: 0, activeCount: 0, expiringCount: 0,
      algorithms: [], items: [],
    };
  }

  const res = await pgPool.withTenantTransaction(tenantId, (tx) => tx.query(
    `SELECT key_id, client_id, version, algorithm, status, created_at,
            rotation_deadline, expires_at
     FROM signing_keys
     ORDER BY client_id, version DESC`,
  ));

  const activeKeys = res.rows.filter(r => r.status === 'active');
  const now        = Date.now();
  const expiring   = activeKeys.filter(r => r.expires_at && new Date(r.expires_at) < new Date(now + 30 * 86_400_000));

  return {
    evidenceType:  'signing_key_records',
    count:         res.rowCount ?? 0,
    activeCount:   activeKeys.length,
    expiringCount: expiring.length,
    algorithms:    [...new Set(res.rows.map(r => r.algorithm))],
    items:         res.rows.map(r => _ev(
      'signing_key_records',
      'signing_keys',
      r.key_id,
      r.created_at,
      `${r.key_id} | status=${r.status} | algo=${r.algorithm}`,
      { status: r.status, algorithm: r.algorithm, expiresAt: r.expires_at },
    )),
  };
}

async function _collectConsentEvents(periodStart, periodEnd, tenantId) {
  const params = [periodStart, periodEnd];
  let where = `occurred_at >= $1 AND occurred_at <= $2
    AND (event_type LIKE '%CONSENT%' OR event_type LIKE '%GDPR%'
         OR (event_category = 'ENFORCEMENT' AND outcome = 'BLOCK'))`;
  if (tenantId) { where += ` AND tenant_id = $${params.length + 1}`; params.push(tenantId); }

  const res = await _collectorQuery(tenantId, `
    SELECT event_id, occurred_at, event_type, outcome, policy_id, tenant_id, aggregate_count
     FROM platform_audit_events
     WHERE ${where}
     ORDER BY occurred_at DESC
     LIMIT 500`,
    params,
    'compliance_collect_consent',
  );

  return {
    evidenceType: 'consent_events',
    count:        _cappedEvents(res.rows, 500), // events, not rows (see _events)
    items:        res.rows.map(r => _ev(
      'consent_events',
      'platform_audit_events',
      r.event_id,
      r.occurred_at,
      `${r.event_type} | outcome=${r.outcome ?? 'n/a'}`,
      { outcome: r.outcome, policyId: r.policy_id },
    )),
  };
}

async function _collectAnomalyEvents(periodStart, periodEnd, tenantId) {
  const params = [periodStart, periodEnd];
  let where = `occurred_at >= $1 AND occurred_at <= $2
    AND (event_type LIKE '%ANOMALY%' OR event_type LIKE '%RATE_LIMIT%'
         OR event_type LIKE '%REPLAY%' OR severity IN ('FATAL','CRITICAL'))`;
  if (tenantId) { where += ` AND tenant_id = $${params.length + 1}`; params.push(tenantId); }

  const res = await _collectorQuery(tenantId, `
    SELECT event_id, occurred_at, event_type, severity, payload, aggregate_count
     FROM platform_audit_events
     WHERE ${where}
     ORDER BY occurred_at DESC
     LIMIT 200`,
    params,
    'compliance_collect_anomaly',
  );

  return {
    evidenceType: 'anomaly_events',
    count:        _cappedEvents(res.rows, 200), // events, not rows (see _events)
    items:        res.rows.map(r => _ev(
      'anomaly_events',
      'platform_audit_events',
      r.event_id,
      r.occurred_at,
      `${r.event_type} | sev=${r.severity}`,
      { severity: r.severity },
    )),
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Collect all evidence for a compliance assessment.
 * Returns a structured evidence bundle keyed by evidence type.
 * Silently marks a type as unavailable if the DB is disabled.
 *
 * @param {{ periodStart: Date, periodEnd: Date, tenantId?: string }} opts
 * @returns {Promise<EvidenceBundle>}
 */
async function collectAll({ periodStart, periodEnd, tenantId = null } = {}) {
  if (!periodStart || !periodEnd) throw new Error('evidenceCollector: periodStart and periodEnd are required');

  const start = new Date(periodStart);
  const end   = new Date(periodEnd);
  if (isNaN(start.getTime()) || isNaN(end.getTime())) {
    throw new Error('evidenceCollector: periodStart and periodEnd must be valid dates');
  }
  if (start >= end) throw new Error('evidenceCollector: periodStart must be before periodEnd');

  const isDbEnabled = pgPool.isEnabled();

  if (!isDbEnabled) {
    return _offlineFallback(start, end);
  }

  const [
    enforcement,
    policies,
    allEvents,
    securityEvents,
    lifecycleEvents,
    keyMgmtEvents,
    chainEntries,
    signedArtifacts,
    rbacUsers,
    signingKeys,
    consentEvents,
    anomalyEvents,
  ] = await Promise.all([
    _collectEnforcementEvents(start, end, tenantId),
    _collectPolicyRecords(),
    _collectAuditEvents(start, end, tenantId),
    _collectAuditEvents(start, end, tenantId, 'SECURITY'),
    _collectAuditEvents(start, end, tenantId, 'LIFECYCLE'),
    _collectAuditEvents(start, end, tenantId, 'KEY_MANAGEMENT'),
    _collectAuditChainEntries(start, end, tenantId),
    _collectSignedArtifacts(start, end, tenantId),
    _collectRbacUsers(),
    _collectSigningKeys(tenantId),
    _collectConsentEvents(start, end, tenantId),
    _collectAnomalyEvents(start, end, tenantId),
  ]);

  return {
    periodStart:    start.toISOString(),
    periodEnd:      end.toISOString(),
    tenantId,
    collectedAt:    new Date().toISOString(),
    dbEnabled:      true,
    enforcement,
    policy_records: policies,
    audit_events:   allEvents,
    security_events:      securityEvents,
    lifecycle_events:     lifecycleEvents,
    key_management_events: keyMgmtEvents,
    audit_chain_entries:  chainEntries,
    signed_artifacts:     signedArtifacts,
    rbac_users:           rbacUsers,
    signing_key_records:  signingKeys,
    consent_events:       consentEvents,
    anomaly_events:       anomalyEvents,
  };
}

function _offlineFallback(start, end) {
  const empty = type => ({ evidenceType: type, count: 0, items: [], _offline: true });
  return {
    periodStart: start.toISOString(),
    periodEnd:   end.toISOString(),
    tenantId:    null,
    collectedAt: new Date().toISOString(),
    dbEnabled:   false,
    enforcement:           empty('enforcement_events'),
    policy_records:        empty('policy_records'),
    audit_events:          empty('audit_events'),
    security_events:       empty('security_events'),
    lifecycle_events:      empty('lifecycle_events'),
    key_management_events: empty('key_management_events'),
    audit_chain_entries:   empty('audit_chain_entries'),
    signed_artifacts:      empty('signed_artifacts'),
    rbac_users:            empty('rbac_users'),
    signing_key_records:   empty('signing_key_records'),
    consent_events:        empty('consent_events'),
    anomaly_events:        empty('anomaly_events'),
  };
}

/**
 * Collect evidence for a specific set of evidence types (used by individual control assessments).
 * @param {string[]} types
 * @param {{ periodStart, periodEnd, tenantId? }} opts
 */
async function collectForTypes(types, opts) {
  const bundle = await collectAll(opts);
  const result = {};
  for (const type of types) {
    const key = type === 'enforcement_events' ? 'enforcement' : type;
    result[type] = bundle[key] ?? bundle[type] ?? { evidenceType: type, count: 0, items: [] };
  }
  return result;
}

module.exports = { collectAll, collectForTypes };
