'use strict';

/**
 * QODIQA Centralized Platform Audit Event Store
 *
 * Transforms the operational log stream (services/logger.js emit()) into a
 * queryable, indexed, retention-managed audit store in PostgreSQL.
 *
 * WRITE PATH:  ingest(level, eventType, payload)
 *              Called fire-and-forget from logger.js after every emit().
 *              Never throws; never blocks the caller.
 *
 * READ PATH:   search(), correlate(), artifactTimeline(), actorActivity(),
 *              stats(), ingestionRate(), getEvent()
 *
 * All reads are no-ops (return empty / null) when PG is not enabled.
 * This preserves backwards compatibility with file-only deployments.
 */

const pgPool = require('../../infra/postgres/pool');
const rolePools = require('../../infra/postgres/rolePools'); // operator /audit-store reads run as qodiqa_reporting
const { randomUUID } = require('crypto');
const { monoNowMs } = require('../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

// ── Event classification ──────────────────────────────────────────────────────

// Exact-match overrides for events whose prefix would misclassify them
const _EXACT_CATEGORY = Object.freeze({
  GATEWAY_ALLOW:                'ENFORCEMENT',
  GATEWAY_BLOCK:                'ENFORCEMENT',
  AUDIT_BLOCK_RECORDED:         'ENFORCEMENT',
  AUDIT_EXECUTION_RECORDED:     'ENFORCEMENT',
  POLICY_RATE_LIMIT_EXCEEDED:   'ENFORCEMENT',
  POLICY_DRIFT_DETECTED:        'ENFORCEMENT',

  RBAC_DENY:                    'SECURITY',
  RBAC_PERMISSION_ENGINE_ERROR: 'SECURITY',
  RBAC_RESOLVE_UNKNOWN_ACTOR:   'SECURITY',
  RBAC_RESOLVE_DISABLED_USER:   'SECURITY',
  NONCE_V2_REPLAY_DETECTED:     'SECURITY',
  EXECUTION_INVARIANT_VIOLATED: 'SECURITY',
  KEY_PLAINTEXT_DETECTED:       'SECURITY',
  PROVIDER_SSRF_REJECTED:       'SECURITY',
  AUDIT_CHAIN_CORRUPTED:        'SECURITY',
  ANOMALY_THRESHOLD_EXCEEDED:   'SECURITY',
  OPS_AUTH_INVALID_TOKEN:       'SECURITY',
  OPS_ALLOWLIST_BLOCKED:        'SECURITY',
  OPS_AUTH_MISSING_CREDENTIALS: 'SECURITY',

  RBAC_ALLOW:                   'ACCESS_CONTROL',
  RBAC_RESOLVE_OK:              'ACCESS_CONTROL',
  RBAC_RESOLVE_NO_ACTOR:        'ACCESS_CONTROL',
  RBAC_USER_CREATED:            'ACCESS_CONTROL',
  RBAC_USER_UPDATED:            'ACCESS_CONTROL',
  RBAC_USER_DELETED:            'ACCESS_CONTROL',
  RBAC_BOOTSTRAP_ADMIN_CREATED: 'ACCESS_CONTROL',
  RBAC_BOOTSTRAP_UPGRADED:      'ACCESS_CONTROL',

  KEY_EXPIRED_STARTUP:          'KEY_MANAGEMENT',
  KEY_EXPIRING_SOON:            'KEY_MANAGEMENT',
  KEY_ROTATION_OVERDUE:         'KEY_MANAGEMENT',
  KEY_ROTATION_AUTO:            'KEY_MANAGEMENT',
  KEY_PROVISIONED:              'KEY_MANAGEMENT',
  KEY_STORE_VIOLATION:          'KEY_MANAGEMENT',
  TENANT_KEY_EXPIRED_ACTIVE:    'KEY_MANAGEMENT',
  TENANT_KEY_MISSING:           'KEY_MANAGEMENT',
  TENANT_KEY_PROVISIONING_FAILED: 'KEY_MANAGEMENT',
  TENANT_KEY_ROTATION_FAILED:   'KEY_MANAGEMENT',
  MULTIPLE_ACTIVE_KEYS_DETECTED:'KEY_MANAGEMENT',

  POLICY_CREATED:               'POLICY',
  POLICY_UPDATED:               'POLICY',
  POLICY_ENABLED:               'POLICY',
  POLICY_DISABLED:              'POLICY',
  POLICY_ROLLED_BACK:           'POLICY',
  POLICIES_LOADED:              'POLICY',
  POLICIES_RELOADED:            'POLICY',
  POLICY_LOAD_FAILED:           'POLICY',
  POLICY_RELOAD_FAILED:         'POLICY',

  // Component #20 — Policy Provenance
  PROVENANCE_VERSION_RECORDED:         'POLICY',
  PROVENANCE_RECORD_FAILED:            'POLICY',
  PROVENANCE_PREV_HASH_LOOKUP_FAILED:  'POLICY',
  PROVENANCE_CHAIN_INTEGRITY_FAILURE:  'SECURITY',
  PROVENANCE_INTEGRITY_RUN_PERSIST_FAILED: 'POLICY',
  PROVENANCE_ATTRIBUTION_REJECTED:     'SECURITY',
  PROVENANCE_REASON_REJECTED:          'POLICY',

  PROVIDER_EXECUTION_START:     'PROVIDER',
  PROVIDER_EXECUTION_COMPLETE:  'PROVIDER',
  PROVIDER_EXECUTION_FAILED:    'PROVIDER',
  PROVIDER_FAILOVER:            'PROVIDER',
  PROVIDER_FAILOVER_SUCCESS:    'PROVIDER',
  PROVIDER_ROUTING_DECISION:    'PROVIDER',

  AUDIT_CHAIN_VALIDATED:        'AUDIT_CHAIN',
  PG_AUDIT_PERSIST_FAILED:      'AUDIT_CHAIN',

  EVIDENCE_JSON_GENERATED:      'EVIDENCE',
  EVIDENCE_PDF_GENERATED:       'EVIDENCE',
  EVIDENCE_AUDIT_EXPORTED:      'EVIDENCE',
  EVIDENCE_VERIFY_GENERATED:    'EVIDENCE',
  EVIDENCE_GENERATE_FAILED:     'EVIDENCE',
  EVIDENCE_PDF_GENERATE_FAILED: 'EVIDENCE',

  // Component #21 — Evidence Chain
  EVIDENCE_CHAIN_RECORD_CREATED:          'EVIDENCE',
  EVIDENCE_CHAIN_PERSIST_FAILED:          'EVIDENCE',
  EVIDENCE_CHAIN_PREV_HASH_LOOKUP_FAILED: 'EVIDENCE',
  EVIDENCE_CHAIN_VERIFICATION_FAILED:     'SECURITY',
  EVIDENCE_CHAIN_CONTINUITY_FAILURE:      'SECURITY',
  EVIDENCE_CHAIN_API_ERROR:               'EVIDENCE',
  EVIDENCE_VERIFICATION_PERSIST_FAILED:   'EVIDENCE',

  // Component #23 — Public Verification Portal
  PORTAL_VERIFICATION_STARTED:               'EVIDENCE',
  PORTAL_VERIFICATION_COMPLETE:              'EVIDENCE',
  PORTAL_VERIFICATION_ERROR:                 'EVIDENCE',
  PORTAL_PERSIST_FAILED:                     'EVIDENCE',
  PORTAL_TRANSPARENCY_REGISTER_FAILED:       'EVIDENCE',
  PORTAL_API_ERROR:                          'EVIDENCE',

  // Component #24 — Attestation API
  ATTESTATION_STARTED:                       'EVIDENCE',
  ATTESTATION_COMPLETE:                      'EVIDENCE',
  ATTESTATION_ERROR:                         'EVIDENCE',
  ATTESTATION_PERSIST_FAILED:                'EVIDENCE',
  ATTESTATION_TRANSPARENCY_REGISTER_FAILED:  'EVIDENCE',
  ATTESTATION_EVIDENCE_VERIFY_STARTED:       'EVIDENCE',
  ATTESTATION_EVIDENCE_VERIFY_COMPLETE:      'EVIDENCE',
  ATTESTATION_CHAIN_VERIFY_STARTED:          'EVIDENCE',
  ATTESTATION_CHAIN_VERIFY_COMPLETE:         'EVIDENCE',
  ATTESTATION_EXPORT_REQUESTED:              'EVIDENCE',
  ATTESTATION_API_ERROR:                     'EVIDENCE',

  // Component #25 — Certification Runtime
  CERTIFICATION_STARTED:                         'EVIDENCE',
  CERTIFICATION_COMPLETE:                        'EVIDENCE',
  CERTIFICATION_PERSIST_FAILED:                  'EVIDENCE',
  CERTIFICATION_TRANSPARENCY_REGISTER_FAILED:    'EVIDENCE',
  CERTIFICATION_EXPORT_REQUESTED:                'EVIDENCE',
  CERTIFICATION_API_ERROR:                       'EVIDENCE',

  // Component #22 — Transparency Log
  TRANSPARENCY_ENTRY_REGISTERED:              'EVIDENCE',
  TRANSPARENCY_ENTRY_PERSIST_FAILED:          'EVIDENCE',
  TRANSPARENCY_PREV_HASH_LOOKUP_FAILED:       'EVIDENCE',
  TRANSPARENCY_ROOT_GENERATED:                'EVIDENCE',
  TRANSPARENCY_ROOT_PERSIST_FAILED:           'EVIDENCE',
  TRANSPARENCY_SIGNATURE_INVALID:             'SECURITY',
  TRANSPARENCY_INTEGRITY_VIOLATION:           'SECURITY',
  TRANSPARENCY_CHAIN_CONTINUITY_FAILURE:      'SECURITY',
  TRANSPARENCY_VERIFICATION_PERSIST_FAILED:   'EVIDENCE',
  TRANSPARENCY_REGISTER_FAILED:               'EVIDENCE',
  TRANSPARENCY_API_ERROR:                     'EVIDENCE',

  GATEWAY_START:                'LIFECYCLE',
  GATEWAY_RUNTIME_READY:        'LIFECYCLE',
  GATEWAY_RUNTIME_DEGRADED:     'LIFECYCLE',
  SHUTDOWN_COMPLETE:            'LIFECYCLE',
  SHUTDOWN_STARTED:             'LIFECYCLE',
});

// Prefix-based fallback category map (longest prefix first matters for iteration order)
const _PREFIX_CATEGORY = [
  ['NONCE_V2_',         'SECURITY'],
  ['ANOMALY_THRESHOLD', 'SECURITY'],
  ['ANOMALY_REPLAY',    'SECURITY'],
  ['ANOMALY_SIGNATURE', 'SECURITY'],
  ['ANOMALY_FUTURE',    'SECURITY'],
  ['ANOMALY_NONCE',     'SECURITY'],
  ['EXECUTION_INVARI',  'SECURITY'],
  ['NONCE_STORE_',      'INFRASTRUCTURE'],
  ['ANOMALY_STORE_',    'INFRASTRUCTURE'],
  ['RATE_LIMIT_STORE_', 'INFRASTRUCTURE'],
  ['REDIS_',            'INFRASTRUCTURE'],
  ['PG_',               'INFRASTRUCTURE'],
  ['RBAC_',             'ACCESS_CONTROL'],
  ['DSR_',              'ACCESS_CONTROL'],
  ['SIGNING_IDENTITY_ADMIN_', 'ACCESS_CONTROL'], // row 40: privilege changes on signing identities are access-control events
  ['KEY_ADMIN_',        'KEY_MANAGEMENT'],
  ['KEY_',              'KEY_MANAGEMENT'],
  ['TENANT_KEY_',       'KEY_MANAGEMENT'],
  ['TENANT_KEYS_',      'KEY_MANAGEMENT'],
  ['CHECKPOINT_KEY',    'KEY_MANAGEMENT'],   // step 6: audit-checkpoint key lifecycle (…_CREATED/_ROTATED/…, CHECKPOINT_KEYSTORE_LOADED is not matched)
  ['POLICY_',           'POLICY'],
  ['PROVENANCE_',       'POLICY'],
  ['PROVIDER_',         'PROVIDER'],
  ['TRANSPARENCY_',     'EVIDENCE'],
  ['PORTAL_',           'EVIDENCE'],
  ['ATTESTATION_',      'EVIDENCE'],
  ['CERTIFICATION_',    'EVIDENCE'],
  ['ANOMALY_',          'SECURITY'],
  ['AUDIT_VIEWER_',     'OPERATIONAL'],
  ['EVIDENCE_',         'EVIDENCE'],
  ['OPS_',              'OPERATIONAL'],
  ['AUDIT_',            'AUDIT_CHAIN'],
  ['GATEWAY_',          'LIFECYCLE'],
  ['STARTUP_',          'LIFECYCLE'],
  ['SHUTDOWN_',         'LIFECYCLE'],
  ['PROVIDERS_',        'LIFECYCLE'],
];

function _classify(eventType) {
  const exact = _EXACT_CATEGORY[eventType];
  if (exact) return exact;
  for (const [prefix, cat] of _PREFIX_CATEGORY) {
    if (eventType.startsWith(prefix)) return cat;
  }
  return 'OPERATIONAL';
}

// ── Component extraction ──────────────────────────────────────────────────────

const _COMPONENT_MAP = Object.freeze({
  GATEWAY:    'ENFORCEMENT_GATEWAY',
  AUDIT:      'AUDIT_SYSTEM',
  RBAC:       'RBAC_ENGINE',
  KEY:        'KEY_MANAGER',
  TENANT:     'TENANT_KEY_MANAGER',
  POLICY:     'POLICY_ENGINE',
  PROVENANCE: 'PROVENANCE_ENGINE',
  PROVIDER:   'PROVIDER_GATEWAY',
  ANOMALY:    'ANOMALY_DETECTOR',
  NONCE:      'NONCE_STORE',
  REDIS:      'REDIS',
  PG:         'POSTGRES',
  EVIDENCE:      'EVIDENCE_GENERATOR',
  TRANSPARENCY:  'TRANSPARENCY_LOG',
  PORTAL:        'VERIFICATION_PORTAL',
  ATTESTATION:     'ATTESTATION_API',
  CERTIFICATION:   'CERTIFICATION_RUNTIME',
  OPS:           'OPS_MIDDLEWARE',
  SHUTDOWN:   'RUNTIME',
  STARTUP:    'RUNTIME',
  EXECUTION:  'RUNTIME',
  METRICS:    'METRICS',
  CLOCK:      'RUNTIME',
});

function _component(eventType) {
  const prefix = eventType.split('_')[0];
  return _COMPONENT_MAP[prefix] || prefix || 'UNKNOWN';
}

// ── Outcome classification ────────────────────────────────────────────────────

function _outcome(eventType, payload) {
  if (payload?.decision === 'ALLOW') return 'ALLOW';
  if (payload?.decision === 'BLOCK') return 'BLOCK';
  const t = eventType.toLowerCase();
  if (t.includes('allow') || t.includes('granted') || t.includes('complete') ||
      t.includes('ready') || t.includes('_ok') || t.includes('validated') ||
      t.includes('success') || t.includes('initialized') || t.includes('provisioned')) return 'SUCCESS';
  if (t.includes('block') || t.includes('deny') || t.includes('denied') ||
      t.includes('failed') || t.includes('failure') || t.includes('rejected') ||
      t.includes('error') || t.includes('invalid') || t.includes('corrupted') ||
      t.includes('violated') || t.includes('fatal')) return 'FAILURE';
  if (t.includes('warn') || t.includes('degraded') || t.includes('expir') ||
      t.includes('missing') || t.includes('overdue') || t.includes('exceed')) return 'WARNING';
  return null;
}

// ── Correlation field extraction ──────────────────────────────────────────────

const _UUID_RE     = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const _TRACE_ID_RE = /^[0-9a-f]{32}$/i;
const _SPAN_ID_RE  = /^[0-9a-f]{16}$/i;

function _toUuid(v) {
  return typeof v === 'string' && _UUID_RE.test(v) ? v : null;
}

// W3C trace-id/span-id, populated automatically on every emit() call
// made from within a traced request (services/logger.js) when OTel-style
// tracing is enabled (src/observability/tracing/).
function _toTraceId(v) {
  return typeof v === 'string' && _TRACE_ID_RE.test(v) ? v : null;
}

function _toSpanId(v) {
  return typeof v === 'string' && _SPAN_ID_RE.test(v) ? v : null;
}

function _toStr(v, maxLen = 128) {
  if (typeof v !== 'string' || !v) return null;
  return v.slice(0, maxLen);
}

function _extractCorrelation(payload) {
  return {
    request_id:     _toUuid(payload?.requestId),
    correlation_id: _toUuid(payload?.correlationId),
    artifact_id:    _toStr(payload?.artifactId),
    actor_id:       _toStr(payload?.userId ?? payload?.actor),
    actor_username: _toStr(payload?.username),
    actor_role:     _toStr(payload?.role),
    policy_id:      _toStr(payload?.policyId),
    key_id:         _toStr(payload?.keyId),
    tenant_id:      _toStr(payload?.tenantId ?? payload?.source),
    trace_id:       _toTraceId(payload?.traceId),
    span_id:        _toSpanId(payload?.spanId),
  };
}

// ── Write path ────────────────────────────────────────────────────────────────

// the exact severity set platform_audit_events accepts — migration 003's
// platform_audit_events_severity_chk. Kept here, behind the store's own
// boundary, because what this table admits is a property of the store, not of
// logger.js: logger.js forwards EVERY emit() here fire-and-forget and has no
// business knowing the schema's severity vocabulary.
//
// Why a filter and not a widened constraint. logger.js:180 forwarded DEBUG
// events too, and every one of them failed the CHECK with SQLSTATE 23514 —
// "new row for relation \"platform_audit_events\" violates check constraint
// \"platform_audit_events_severity_chk\"". There is exactly one DEBUG emit site
// in the non-test codebase (ConsentVerifier.js's CONSENT_CACHE_HIT), and it
// sits on the hottest path in the system, so every cache-hit verification was
// spending a PostgreSQL round-trip on an INSERT that could never succeed —
// visible under load as PG_SLOW_QUERY on audit_store_ingest at 2.3s and as
// pool pressure that pushed a concurrent revoke to 2.1s end-to-end (
// Session 2).
//
// Admitting DEBUG instead was considered and declined: migration 003 defines
// this table as a compliance-grade store — retention policies, legal_hold,
// retain_until, RLS mirroring audit_chain with INSERT-only and no UPDATE/DELETE
// — and its five severities are the audit-relevant ones. Writing a per-cache-hit
// diagnostic row into a legal-hold-governed table is a compliance-surface and
// write-amplification cost taken to capture telemetry that belongs in metrics.
// If cache-hit telemetry is ever wanted it is a metrics/observability item, not
// an audit-store row.
//
// Dropping below the floor is silent by design: emitting a WARN per dropped
// event would reintroduce, on the same hot path, exactly the noise this removes.
// Nothing observable is lost — these rows never landed even once.
const INGESTIBLE_SEVERITIES = Object.freeze(new Set(['FATAL', 'CRITICAL', 'ERROR', 'WARN', 'INFO']));

// LOG-1: pool.js's query() emits a synchronous logger.emit('WARN',
// 'PG_CIRCUIT_OPEN', ...) — and equally, on any real query failure,
// emit('ERROR', 'PG_QUERY_ERROR', ...) — from INSIDE its own breaker-check/
// catch block, before ever awaiting anything. logger.emit() is itself a
// plain (non-async) function whose last step calls THIS ingest() function
// fire-and-forget. Since none of query()/ingest()/emit() hit an `await`
// before that nested call, calling pgPool.query() below can synchronously
// re-enter this exact function on the same native call stack: ingest() ->
// query() -> emit() -> ingest() -> query() -> emit() -> ... — unbounded
// until Node's own stack limit throws RangeError (empirically ~3,000 nested
// calls, tens of milliseconds, per trigger — see
//). Live-witnessed producing both a
// sustained event flood and outright process death via
// processHardening.js's fail-fast unhandledRejection handler.
//
// _ingestReentrant is a synchronous guard, not a general "ingest in
// flight" lock: it is set immediately before calling pgPool.query() and
// cleared immediately after that call returns (before this function's own
// `await`), so it is only ever true during the narrow synchronous window
// where a nested re-entrant call could occur. A second, independent,
// legitimately-concurrent top-level ingest() call arriving later (even one
// microtask tick later, e.g. two different requests logging at once) always
// sees it already cleared — no audit events are dropped under ordinary
// concurrent load, only the self-recursive cascade is broken. One bounded
// "echo" WARN/ERROR from ingest()'s own query() attempt still reaches
// stdout/the dashboard (logger.emit()'s non-PG sinks are never gated by
// this), it just isn't itself re-persisted — the operational signal survives,
// only the amplification is suppressed.
let _ingestReentrant = false;

/**
 * Ingest one log event into the centralized platform audit store.
 *
 * Called fire-and-forget from logger.js after every emit().
 * Must never throw; any database failure is silently absorbed so that
 * the operational logging path (stdout write) is never affected.
 *
 * Severities outside INGESTIBLE_SEVERITIES (i.e. DEBUG) are dropped before any
 * database work — see that constant's note.
 *
 * @param {string} level      — log level from emit()
 * @param {string} eventType  — event name from emit()
 * @param {object} payload    — full structured payload from emit()
 */
async function ingest(level, eventType, payload) {
  if (!pgPool.isEnabled()) return;
  if (!INGESTIBLE_SEVERITIES.has(level)) return;
  if (_ingestReentrant) return; // LOG-1: breaks the self-amplifying cascade — see comment above

  const category    = _classify(eventType);
  const component   = _component(eventType);
  const outcome     = _outcome(eventType, payload);
  const correlation = _extractCorrelation(payload);
  const occurredAt  = payload?.timestamp ? new Date(payload.timestamp) : new Date();

  // a routine success event is counted into its per-minute aggregate instead of written as a row.
  if (_isAggregated(eventType, level, outcome)) {
    _aggregate(occurredAt, eventType, category, level, component, outcome, correlation.tenant_id);
    if (correlation.request_id || correlation.artifact_id) _trailAdd(eventType, occurredAt, outcome, correlation, payload);
    return;
  }

  // (step 5): one row per event is still produced here, with exactly the parameters the single-row INSERT
  // bound — but it is BUFFERED and written by flush() as one multi-row INSERT, instead of one pool query per log
  // line. Measured before: 13.0 of the 28.4 PostgreSQL queries issued inside each /ai/chat request were this
  // INSERT, each taking a pool connection while the request's own evidence
  // writes needed one.
  _enqueue([
    occurredAt,
    eventType, category, level, component,
    correlation.request_id, correlation.correlation_id, correlation.artifact_id,
    correlation.actor_id, correlation.actor_username, correlation.actor_role,
    correlation.policy_id, correlation.key_id, correlation.tenant_id,
    correlation.trace_id, correlation.span_id,
    outcome, JSON.stringify(payload ?? {}),
    1,
  ]);
}

// ── step 6: per-minute aggregation of routine success events ────────────────
//
// Measured at ad8f2606: every /ai/chat request wrote 15.04 rows here — 16,810 of its
// 31,052 PostgreSQL bytes — one INFO success event per pipeline step (14 types; ANOMALY_STATE_INCREMENTED fires twice). Those types are no longer persisted
// row by row: each (clock minute of the event, event type, tenant, category, severity, component, outcome) becomes
// ONE row with aggregate_count = how many events it stands for (migration 068), occurred_at = the start of that
// minute and payload = { aggregated: true, count, windowStart, windowEnd, firstOccurredAt, lastOccurredAt }.
//
// Only a routine SUCCESS instance is aggregated: severity INFO and an outcome that is not BLOCK, FAILURE or WARNING
// (_outcome() reads payload.decision first, so a SIGN_DECISION that blocked stays a full row). Every WARN or higher
// event, every blocking/failing instance and every type not listed here is written exactly as before. Stdout keeps
// every line (logger.js is untouched). Every count over the table sums aggregate_count, so counts — per type,
// category, severity, outcome, tenant, minute — are unchanged; what a per-minute row cannot carry is the per-event
// correlation (request, trace, artifact, actor), so per-request timelines of these types come from stdout /
// SIEM and from the chain tables (one audit_chain / evidence / transparency row per request, unchanged).
//
// Rollback: QODIQA_AUDIT_STORE_AGGREGATE=false restores per-row persistence of these types.
const AGGREGATED_EVENT_TYPES = Object.freeze(new Set([
  'ANOMALY_STATE_INCREMENTED',
  'SIGN_AUTH_OK', 'SIGN_DECISION',
  'POLICY_HASH_BOUND', 'POLICY_EXECUTE',
  'PROVIDER_REQUEST_VALIDATED', 'PROVIDER_ROUTING_DECISION', 'PROVIDER_EXECUTION_START', 'PROVIDER_EXECUTION_COMPLETE',
  'AUDIT_EXECUTION_RECORDED', 'EVIDENCE_CHAIN_RECORD_CREATED',
  'TRANSPARENCY_ENTRY_CREATED', 'TRANSPARENCY_ENTRY_REGISTERED', 'TRANSPARENCY_ROOT_SIGNED',
]));
const _NOT_ROUTINE_OUTCOMES = new Set(['BLOCK', 'FAILURE', 'WARNING']);
const AGGREGATE_WINDOW_MS  = 60_000;
const AGGREGATE_SETTLE_MS  = 2_000;  // a minute is written once it closed this long ago (late events of it still count)
const AGGREGATE_TICK_MS    = 5_000;
const _agg = new Map();              // key → { minute, eventType, category, level, component, outcome, tenantId, count, first, last }
let _aggTimer = null;

function _aggregationEnabled() { return process.env.QODIQA_AUDIT_STORE_AGGREGATE !== 'false'; }

function _isAggregated(eventType, level, outcome) {
  return level === 'INFO' && AGGREGATED_EVENT_TYPES.has(eventType) && !_NOT_ROUTINE_OUTCOMES.has(outcome) && _aggregationEnabled();
}

function _aggregate(occurredAt, eventType, category, level, component, outcome, tenantId) {
  const t = occurredAt instanceof Date && !Number.isNaN(occurredAt.getTime()) ? occurredAt.getTime() : Date.now();
  const minute = Math.floor(t / AGGREGATE_WINDOW_MS) * AGGREGATE_WINDOW_MS;
  const key = `${minute}|${eventType}|${tenantId ?? ''}|${category}|${level}|${component}|${outcome ?? ''}`;
  const a = _agg.get(key);
  if (a) { a.count++; if (t < a.first) a.first = t; if (t > a.last) a.last = t; }
  else _agg.set(key, { minute, eventType, category, level, component, outcome, tenantId: tenantId ?? null, count: 1, first: t, last: t });
  if (!_aggTimer) {
    _aggTimer = setInterval(() => _drainAggregates(false), AGGREGATE_TICK_MS);
    if (_aggTimer.unref) _aggTimer.unref();
  }
}

// ── step 6 : one compact per-request trail row for the aggregated steps ─────────────────────
//
// The aggregate rows above carry no per-request identity, so correlate() / artifactTimeline() rebuild the per-request
// step list from request_trails (migration 069): for every aggregated event that carries a request or artifact id,
// ONE step { t: type, at: ISO time, r: request id, a: artifact id, tr/sp: trace/span id, o: outcome } plus the
// owner's allow-list — x: { latencyMs, evidenceId, transparencyId } when present, and the flags ip / id when the event
// carried the caller IP / identity id. The IP and identity values themselves are stored only in the row's caller_ip /
// actor_id COLUMNS (personal data: erasure target, OPERATIONAL retention), never in the step JSON; a step whose IP
// or identity differs from its trail's starts a new row, so a column never has to stand for two values. Steps are
// grouped per root (request id, else artifact id — one row per HTTP request) and written once the root saw no new step for TRAIL_IDLE_MS (or
// at flush()); a late step simply lands in a second row of the same root, and readers merge rows.
// Decision facts (decision, policy hash, provider, audit entry hash) are NOT kept here: readers take them from the
// audit chain.
const TRAIL_IDLE_MS = 5_000;
const TRAIL_ALLOWED_FIELDS = Object.freeze(['latencyMs', 'evidenceId', 'transparencyId']);
const MAX_OPEN_TRAILS = 20_000;
const _trails = new Map();   // root → { key, steps, requestIds, artifactIds, tenantId, actorId, callerIp, first, last, touched }
let _trailRows = [];         // closed trails waiting for the batched writer
let _trailStats = { rows: 0, steps: 0, splitRows: 0, droppedOpen: 0 };

function _trailAdd(eventType, occurredAt, outcome, correlation, payload) {
  const t = occurredAt instanceof Date && !Number.isNaN(occurredAt.getTime()) ? occurredAt.getTime() : Date.now();
  // Grouped per HTTP request: the request id first (SIGN_DECISION carries the artifact id of the chat it authorizes but
  // belongs to the /sign request), else the artifact id (evidence / transparency steps of a chat carry only that, and
  // on /ai/chat the artifact id IS the request id). Lookups use request_ids / artifact_ids, never the root.
  const root = correlation.request_id || correlation.artifact_id;
  const ip = typeof payload?.ip === 'string' && payload.ip ? payload.ip : null;
  const identity = typeof payload?.identityId === 'string' && payload.identityId ? payload.identityId : null;
  let tr = _trails.get(root);
  if (tr && ((ip && tr.callerIp && ip !== tr.callerIp) || (identity && tr.actorId && identity !== tr.actorId))) {
    _closeTrail(root); tr = null; _trailStats.splitRows++;
  }
  if (!tr) {
    if (_trails.size >= MAX_OPEN_TRAILS) { _closeTrail(_trails.keys().next().value); _trailStats.droppedOpen++; }
    tr = { key: root, steps: [], requestIds: new Set(), artifactIds: new Set(), tenantId: null, actorId: null, callerIp: null, first: t, last: t, touched: monoNowMs() }; // monotonic (same-process)
    _trails.set(root, tr);
  }
  const step = { t: eventType, at: new Date(t).toISOString(), r: correlation.request_id, a: correlation.artifact_id,
    tr: correlation.trace_id, sp: correlation.span_id, o: outcome ?? null };
  if (ip) { step.ip = 1; tr.callerIp = ip; }
  if (identity) { step.id = 1; tr.actorId = identity; }
  const x = {};
  for (const f of TRAIL_ALLOWED_FIELDS) if (payload && payload[f] !== undefined) x[f] = payload[f];
  if (Object.keys(x).length) step.x = x;
  tr.steps.push(step);
  if (correlation.request_id) tr.requestIds.add(correlation.request_id);
  if (correlation.artifact_id) tr.artifactIds.add(correlation.artifact_id);
  if (!tr.tenantId && correlation.tenant_id) tr.tenantId = correlation.tenant_id;
  if (t < tr.first) tr.first = t;
  if (t > tr.last) tr.last = t;
  tr.touched = monoNowMs(); // monotonic (same-process)
  _trailStats.steps++;
}

function _closeTrail(root) {
  const tr = _trails.get(root);
  if (!tr) return;
  _trails.delete(root);
  _trailRows.push([tr.key, [...tr.requestIds], [...tr.artifactIds], tr.tenantId, tr.actorId, tr.callerIp,
    JSON.stringify(tr.steps), new Date(tr.first), new Date(tr.last)]);
}

const TRAIL_COLS = 9;
function _trailInsertSql(rows) {
  const values = [];
  for (let r = 0; r < rows; r++) {
    const b = r * TRAIL_COLS;
    values.push(`($${b + 1}, $${b + 2}::uuid[], $${b + 3}::text[], $${b + 4}, $${b + 5}, $${b + 6}, $${b + 7}::jsonb, $${b + 8}, $${b + 9})`);
  }
  return `INSERT INTO request_trails (trail_key, request_ids, artifact_ids, tenant_id, actor_id, caller_ip, steps, first_occurred_at, last_occurred_at)
      VALUES ${values.join(',\n        ')}`;
}

/** Moves closed minutes (or, with all=true, every minute) from the aggregate map into the write buffer. */
function _drainAggregates(all) {
  const idleBefore = monoNowMs() - TRAIL_IDLE_MS; // monotonic (same-process)
  for (const [root, tr] of _trails) if (all || tr.touched <= idleBefore) _closeTrail(root);
  if (_trailRows.length && !_flushTimer && !all) {
    _flushTimer = setTimeout(() => { _flushTimer = null; flush(); }, FLUSH_INTERVAL_MS);
    if (_flushTimer.unref) _flushTimer.unref();
  }
  const cutoff = Date.now() - AGGREGATE_WINDOW_MS - AGGREGATE_SETTLE_MS;
  for (const [key, a] of _agg) {
    if (!all && a.minute > cutoff) continue;
    _agg.delete(key);
    _enqueue([
      new Date(a.minute),
      a.eventType, a.category, a.level, a.component,
      null, null, null,
      null, null, null,
      null, null, a.tenantId,
      null, null,
      a.outcome, JSON.stringify({ aggregated: true, count: a.count, windowStart: new Date(a.minute).toISOString(),
        windowEnd: new Date(a.minute + AGGREGATE_WINDOW_MS).toISOString(),
        firstOccurredAt: new Date(a.first).toISOString(), lastOccurredAt: new Date(a.last).toISOString() }),
      a.count,
    ]);
  }
  if (_agg.size === 0 && _trails.size === 0 && _aggTimer) { clearInterval(_aggTimer); _aggTimer = null; }
}

// ── (step 5): batched writer ───────────────────────────────────────────────
//
// Rows are flushed every FLUSH_INTERVAL_MS, or at once when FLUSH_ROWS have accumulated, as ONE multi-row INSERT
// (18 bound parameters per row; 500 rows = 9,000 parameters, well under PostgreSQL's 65,535). The buffer is
// bounded: past MAX_BUFFER_ROWS the OLDEST operational rows are dropped and counted, and one
// PLATFORM_EVENTS_DROPPED summary is emitted per flush that dropped anything — this store is the operational
// correlation index, not the evidence chain (audit_chain / transparency are written elsewhere, unchanged).
// A failed flush is swallowed exactly as a failed single-row ingest always was (the rows are lost, counted).
// The flush query carries the SAME label and the SAME LOG-1 re-entrancy guard the per-row query did, so a
// PostgreSQL failure's echo can neither recurse synchronously (LOG-1) nor be re-persisted asynchronously (:
// logger.js never forwards an audit_store_ingest-labelled event here). The pool's graceful shutdown flushes
// first (server/startup.js PG_POOL entry).
const FLUSH_INTERVAL_MS = 250;
const FLUSH_ROWS        = 500;
const MAX_BUFFER_ROWS   = 10_000;
const COLS_PER_ROW      = 19; // + aggregate_count (migration 068)
let _buffer = [];
let _flushTimer = null;
let _flushing = null;
let _dropped = 0;
let _batchStats = { rows: 0, flushes: 0, failedFlushes: 0, droppedRows: 0 };

function _enqueue(row) {
  if (_buffer.length >= MAX_BUFFER_ROWS) { _buffer.shift(); _dropped++; _batchStats.droppedRows++; }
  _buffer.push(row);
  if (_buffer.length >= FLUSH_ROWS) { flush(); return; }
  if (!_flushTimer) {
    _flushTimer = setTimeout(() => { _flushTimer = null; flush(); }, FLUSH_INTERVAL_MS);
    if (_flushTimer.unref) _flushTimer.unref();
  }
}

function _insertSql(rows) {
  const values = [];
  for (let r = 0; r < rows; r++) {
    const b = r * COLS_PER_ROW;
    values.push(`(gen_random_uuid(), '1.0', $${b + 1}, NOW(), $${b + 2}, $${b + 3}::audit_category, $${b + 4}, $${b + 5}, `
      + `$${b + 6}, $${b + 7}, $${b + 8}, $${b + 9}, $${b + 10}, $${b + 11}, $${b + 12}, $${b + 13}, $${b + 14}, `
      + `$${b + 15}, $${b + 16}, $${b + 17}, $${b + 18}, $${b + 19})`);
  }
  return `
      INSERT INTO platform_audit_events (
        event_id, schema_version,
        occurred_at, ingested_at,
        event_type, event_category, severity, component,
        request_id, correlation_id, artifact_id,
        actor_id, actor_username, actor_role,
        policy_id, key_id, tenant_id,
        trace_id, span_id,
        outcome, payload, aggregate_count
      ) VALUES ${values.join(',\n        ')}
    `;
}

/** Writes every buffered row (at most FLUSH_ROWS per INSERT). Never throws; resolves when done. */
async function flush() {
  _drainAggregates(true); // an explicit flush (graceful shutdown, tests) also writes the open minutes
  if (_flushTimer) { clearTimeout(_flushTimer); _flushTimer = null; }
  if (_flushing) { await _flushing; if (!_buffer.length && !_trailRows.length) return; }
  const run = (async () => {
    while (_buffer.length || _trailRows.length) {
      // closed per-request trails (request_trails), same LOG-1 guard and label as the event rows.
      if (_trailRows.length) {
        const trows = _trailRows.splice(0, FLUSH_ROWS);
        let tq;
        _ingestReentrant = true;
        try { tq = pgPool.query(_trailInsertSql(trows.length), trows.flat(), 'audit_store_ingest'); } catch (_e) { tq = null; } finally { _ingestReentrant = false; }
        try { await tq; _trailStats.rows += trows.length; } catch (_e) { _batchStats.failedFlushes++; }
        if (!_buffer.length) continue;
      }
      const rows = _buffer.splice(0, FLUSH_ROWS);
      const dropped = _dropped; _dropped = 0;
      let queryPromise;
      _ingestReentrant = true; // LOG-1: held only for the synchronous call, exactly as before
      try {
        queryPromise = pgPool.query(_insertSql(rows.length), rows.flat(), 'audit_store_ingest');
      } catch (_e) {
        queryPromise = null;
      } finally {
        _ingestReentrant = false;
      }
      _batchStats.flushes++;
      try { await queryPromise; _batchStats.rows += rows.length; } catch (_e) { _batchStats.failedFlushes++; }
      if (dropped) {
        try { require('../../../services/logger').emit('WARN', 'PLATFORM_EVENTS_DROPPED', { count: dropped, bufferMax: MAX_BUFFER_ROWS }); } catch { /* best-effort */ }
      }
    }
  })();
  _flushing = run;
  try { await run; } finally { if (_flushing === run) _flushing = null; }
}

function batchStats() { return { ..._batchStats, trails: { ..._trailStats, open: _trails.size, pending: _trailRows.length }, buffered: _buffer.length, flushIntervalMs: FLUSH_INTERVAL_MS, flushRows: FLUSH_ROWS, maxBufferRows: MAX_BUFFER_ROWS }; }

// ── Search ────────────────────────────────────────────────────────────────────

/**
 * Enterprise search across all platform audit events.
 * Returns { events, total, page, pageSize }.
 * Supports up to 500 results per page.
 */
async function search({
  artifactId,
  requestId,
  correlationId,
  traceId,
  actorId,
  actorUsername,
  keyId,
  policyId,
  tenantId,
  eventType,
  eventCategory,
  severity,
  outcome,
  component,
  startTime,
  endTime,
  page        = 1,
  pageSize    = 50,
  sortOrder   = 'desc',
} = {}) {
  if (!pgPool.isEnabled()) return { events: [], total: 0, page, pageSize };

  const clauses = [];
  const params  = [];
  let   p       = 1;

  const add = (clause, value) => {
    clauses.push(clause.replace('?', `$${p++}`));
    params.push(value);
  };

  if (artifactId)    add('artifact_id = ?',              artifactId);
  if (requestId)     add('request_id = ?::uuid',         requestId);
  if (correlationId) add('correlation_id = ?::uuid',     correlationId);
  if (traceId)       add('trace_id = ?',                 traceId);
  if (actorId)       add('actor_id = ?',                 actorId);
  if (actorUsername) add('actor_username ILIKE ?',       `%${actorUsername}%`);
  if (keyId)         add('key_id = ?',                   keyId);
  if (policyId)      add('policy_id = ?',                policyId);
  if (tenantId)      add('tenant_id = ?',                tenantId);
  if (eventType)     add('event_type = ?',               eventType);
  if (eventCategory) add('event_category = ?::audit_category', eventCategory);
  if (severity)      add('severity = ?',                 severity);
  if (outcome)       add('outcome = ?',                  outcome);
  if (component)     add('component = ?',                component);
  if (startTime)     add('occurred_at >= ?',             new Date(startTime));
  if (endTime)       add('occurred_at <= ?',             new Date(endTime));

  const where   = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
  const dir     = sortOrder === 'asc' ? 'ASC' : 'DESC';
  const pg      = Math.max(1, page);
  const ps      = Math.min(pageSize, 500);
  const offset  = (pg - 1) * ps;

  // platform_audit_events's own RLS (pae_tenant_select) restricts a
  // plain query with no session tenant context to platform-level rows only.
  // This is an RBAC-gated ops-only cross-tenant search console (/audit-store,
  // READ_AUDIT) with no tenant-scoping middleware -- tenantId above is one
  // optional filter among many, not the access boundary (RBAC already is,
  // unchanged here) -- so the fix is the SECURITY DEFINER full-read bypass
  // (migration 053), not withTenantTransaction. See D1.
  const dataQ = rolePools.reporting.query(`
    SELECT
      event_id, occurred_at, ingested_at,
      event_type, event_category, severity, component,
      request_id, correlation_id, artifact_id,
      actor_id, actor_username, actor_role,
      policy_id, key_id, tenant_id,
      trace_id, span_id,
      outcome, payload, legal_hold, retain_until
    FROM qodiqa_platform_audit_events_full_read()
    ${where}
    ORDER BY occurred_at ${dir}, id ${dir}
    LIMIT $${p++} OFFSET $${p++}
  `, [...params, ps, offset], 'audit_store_search');

  const cntQ = rolePools.reporting.query(
    `SELECT COALESCE(SUM(aggregate_count), 0) AS total FROM qodiqa_platform_audit_events_full_read() ${where}`,
    params,
    'audit_store_count',
  );

  const [dataResult, cntResult] = await Promise.all([dataQ, cntQ]);

  return {
    events:   dataResult.rows,
    total:    Number(cntResult.rows[0]?.total ?? 0),
    page:     pg,
    pageSize: ps,
  };
}

/**
 * Fetch a single event by its UUID event_id.
 */
async function getEvent(eventId) {
  if (!pgPool.isEnabled()) return null;

  // see search()'s comment above -- same bypass, same rationale.
  const result = await rolePools.reporting.query(
    'SELECT * FROM qodiqa_platform_audit_events_full_read() WHERE event_id = $1::uuid LIMIT 1',
    [eventId],
    'audit_store_get_event',
  );
  return result.rows[0] ?? null;
}

/**
 * Return all events sharing the same request_id, in chronological order.
 * Enables full reconstruction of what happened during a single HTTP request.
 */
async function correlate(requestId) {
  if (!pgPool.isEnabled()) return [];

  // see search()'s comment above -- same bypass, same rationale.
  const result = await rolePools.reporting.query(`
    SELECT
      event_id, occurred_at, event_type, event_category, severity, component,
      artifact_id, actor_id, actor_username, trace_id, span_id, outcome, payload
    FROM qodiqa_platform_audit_events_full_read()
    WHERE request_id = $1::uuid
    ORDER BY occurred_at ASC, id ASC
  `, [requestId], 'audit_store_correlate');

  // the aggregated routine steps of this request come back from its trail row(s), with
  // decision facts from the audit chain; rows persisted individually are returned exactly as before.
  const steps = await _trailSteps({ requestId }, (s) => s.r === requestId);
  const expanded = steps.map(({ s, trail, facts }) => ({
    event_id: null, occurred_at: new Date(s.at), event_type: s.t, event_category: _classify(s.t), severity: 'INFO',
    component: _component(s.t), artifact_id: s.a, actor_id: null, actor_username: null, trace_id: s.tr, span_id: s.sp,
    outcome: s.o, payload: _stepPayload(s, trail, facts),
  }));
  return _mergeByTime(result.rows, expanded);
}

// ── step 6 : rebuild aggregated steps from request_trails + the audit chain ─────────────────
//
// Returns the trail steps selected by `pick`, each with its trail row and — for AUDIT_EXECUTION_RECORDED — the
// decision facts of its artifact read from the audit chain (qodiqa_audit_chain_decisions, migration 069). A rebuilt
// row has event_id null and a reduced payload marked { fromTrail: true }: its ids, the allow-listed fields
// (latencyMs, evidenceId, transparencyId), the caller IP / identity id from the row's columns when that step carried
// them, and the chain's decision facts — never the other payload fields, which are in stdout/SIEM only.
async function _trailSteps({ requestId = null, artifactId = null }, pick) {
  const { rows: trails } = await rolePools.reporting.query(
    'SELECT * FROM qodiqa_request_trails_by_ids($1::uuid, $2)', [requestId, artifactId], 'audit_store_trails');
  const out = [];
  for (const trail of trails) for (const s of trail.steps || []) if (pick(s)) out.push({ s, trail, facts: null });
  const auditArtifacts = [...new Set(out.filter((o) => o.s.t === 'AUDIT_EXECUTION_RECORDED' && o.s.a).map((o) => o.s.a))];
  if (auditArtifacts.length) {
    const { rows } = await rolePools.reporting.query('SELECT * FROM qodiqa_audit_chain_decisions($1::text[])', [auditArtifacts], 'audit_store_chain_decisions');
    const byArtifact = new Map(rows.map((r) => [r.artifact_id, r]));
    for (const o of out) if (o.s.t === 'AUDIT_EXECUTION_RECORDED') o.facts = byArtifact.get(o.s.a) || null;
  }
  return out;
}

function _stepPayload(s, trail, facts) {
  const p = { fromTrail: true };
  if (s.r) p.requestId = s.r;
  if (s.a) p.artifactId = s.a;
  if (s.tr) p.traceId = s.tr;
  if (s.sp) p.spanId = s.sp;
  if (s.ip) p.ip = trail.caller_ip;            // null once erased
  if (s.id) p.identityId = trail.actor_id;     // pseudonym once erased
  if (s.x) Object.assign(p, s.x);
  if (facts) Object.assign(p, { decision: facts.decision, policyHash: facts.policy_hash, provider: facts.provider, auditEntryHash: facts.entry_hash });
  return p;
}

// Rows by occurred_at ascending; within one timestamp, individually persisted rows keep their id order and rebuilt
// steps keep their recorded order (the former id order across the two kinds within a millisecond is not recoverable).
function _mergeByTime(rows, expanded) {
  if (!expanded.length) return rows;
  const all = [...rows.map((r, i) => ({ r, k: 0, i })), ...expanded.map((r, i) => ({ r, k: 1, i }))];
  all.sort((x, y) => (new Date(x.r.occurred_at) - new Date(y.r.occurred_at)) || (x.k - y.k) || (x.i - y.i));
  return all.map((x) => x.r);
}

/**
 * Return all events sharing the same W3C trace_id, in chronological order.
 * the trace-based counterpart to correlate() — reconstructs a
 * request's full activity (including any audit chain append, surfaced via
 * the AUDIT_EXECUTION_RECORDED/AUDIT_BLOCK_RECORDED events' embedded
 * auditEntryHash/decision fields, see aiChat.js/streamEnforcer.js) using the
 * same trace_id an OTel/Datadog/Splunk/Sentry trace view already uses,
 * without any bespoke field mapping.
 *
 * routine success events (AGGREGATED_EVENT_TYPES, incl. the ALLOW-path AUDIT_EXECUTION_RECORDED) are
 * stored as per-minute aggregates without trace/request ids, so for an ALLOW request this returns its non-routine
 * events only; the full per-request trail of those types is in stdout/SIEM. BLOCK and failure events are unchanged.
 */
async function correlateByTrace(traceId) {
  if (!pgPool.isEnabled()) return [];

  // see search()'s comment above -- same bypass, same rationale.
  const result = await rolePools.reporting.query(`
    SELECT
      event_id, occurred_at, event_type, event_category, severity, component,
      artifact_id, request_id, actor_id, actor_username, span_id, outcome, payload
    FROM qodiqa_platform_audit_events_full_read()
    WHERE trace_id = $1
    ORDER BY occurred_at ASC, id ASC
  `, [traceId], 'audit_store_correlate_by_trace');

  return result.rows;
}

/**
 * Reconstruct the complete cross-subsystem timeline for an artifact.
 * Returns every event that references this artifactId in any field.
 */
async function artifactTimeline(artifactId) {
  if (!pgPool.isEnabled()) return [];

  // see search()'s comment above -- same bypass, same rationale.
  const result = await rolePools.reporting.query(`
    SELECT
      event_id, occurred_at, event_type, event_category, severity, component,
      request_id, correlation_id, actor_id, actor_username, outcome, payload
    FROM qodiqa_platform_audit_events_full_read()
    WHERE artifact_id = $1
    ORDER BY occurred_at ASC, id ASC
  `, [artifactId], 'audit_store_artifact_timeline');

  // see correlate().
  const steps = await _trailSteps({ artifactId }, (s) => s.a === artifactId);
  const expanded = steps.map(({ s, trail, facts }) => ({
    event_id: null, occurred_at: new Date(s.at), event_type: s.t, event_category: _classify(s.t), severity: 'INFO',
    component: _component(s.t), request_id: s.r, correlation_id: null, actor_id: null, actor_username: null,
    outcome: s.o, payload: _stepPayload(s, trail, facts),
  }));
  return _mergeByTime(result.rows, expanded);
}

/**
 * Fetch all events performed by a specific actor.
 * Supports time-range filtering and pagination for access reviews.
 */
async function actorActivity(actorId, { limit = 200, offset = 0, startTime, endTime } = {}) {
  if (!pgPool.isEnabled()) return [];

  const clauses = ['actor_id = $1'];
  const params  = [actorId];
  let   p       = 2;

  if (startTime) { clauses.push(`occurred_at >= $${p++}`); params.push(new Date(startTime)); }
  if (endTime)   { clauses.push(`occurred_at <= $${p++}`); params.push(new Date(endTime)); }

  // see search()'s comment above -- same bypass, same rationale.
  const result = await rolePools.reporting.query(`
    SELECT
      event_id, occurred_at, event_type, event_category, severity, component,
      artifact_id, request_id, tenant_id, outcome, payload
    FROM qodiqa_platform_audit_events_full_read()
    WHERE ${clauses.join(' AND ')}
    ORDER BY occurred_at DESC, id DESC
    LIMIT $${p++} OFFSET $${p++}
  `, [...params, Math.min(limit, 1000), offset], 'audit_store_actor_activity');

  return result.rows;
}

/**
 * Aggregate counts and storage statistics across all platform audit events.
 */
async function stats() {
  if (!pgPool.isEnabled()) return null;

  const result = await rolePools.reporting.query(`
    SELECT
      COALESCE(SUM(aggregate_count), 0)                                                      AS total,
      COALESCE(SUM(aggregate_count) FILTER (WHERE severity IN ('FATAL','CRITICAL','ERROR')), 0) AS error_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE severity = 'WARN'), 0)                    AS warn_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE event_category = 'ENFORCEMENT'), 0)       AS enforcement_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE event_category = 'SECURITY'), 0)          AS security_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE event_category = 'ACCESS_CONTROL'), 0)    AS access_control_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE event_category = 'KEY_MANAGEMENT'), 0)    AS key_management_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE event_category = 'POLICY'), 0)            AS policy_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE event_category = 'PROVIDER'), 0)          AS provider_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE outcome = 'BLOCK'), 0)                    AS blocked_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE outcome = 'FAILURE'), 0)                  AS failure_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE outcome = 'WARNING'), 0)                  AS warning_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE legal_hold = true), 0)                    AS held_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE retain_until IS NOT NULL
                         AND retain_until < NOW()), 0)                 AS expired_pending_count,
      min(occurred_at)                                             AS first_event,
      max(occurred_at)                                             AS last_event,
      pg_size_pretty(pg_total_relation_size('platform_audit_events')) AS table_size
    FROM qodiqa_platform_audit_events_full_read()
  `, [], 'audit_store_stats');

  const r = result.rows[0] ?? {};
  return {
    total:              Number(r.total               ?? 0),
    errorCount:         Number(r.error_count         ?? 0),
    warnCount:          Number(r.warn_count          ?? 0),
    enforcementCount:   Number(r.enforcement_count   ?? 0),
    securityCount:      Number(r.security_count      ?? 0),
    accessControlCount: Number(r.access_control_count ?? 0),
    keyManagementCount: Number(r.key_management_count ?? 0),
    policyCount:        Number(r.policy_count        ?? 0),
    providerCount:      Number(r.provider_count      ?? 0),
    blockedCount:       Number(r.blocked_count       ?? 0),
    failureCount:       Number(r.failure_count       ?? 0),
    warningCount:       Number(r.warning_count       ?? 0),
    heldCount:          Number(r.held_count          ?? 0),
    expiredPendingCount: Number(r.expired_pending_count ?? 0),
    firstEvent:         r.first_event ?? null,
    lastEvent:          r.last_event  ?? null,
    tableSize:          r.table_size  ?? null,
  };
}

/**
 * Per-minute ingestion rate over the last windowMinutes minutes.
 * Used for monitoring dashboards and alerting on rate anomalies.
 */
async function ingestionRate(windowMinutes = 60) {
  if (!pgPool.isEnabled()) return [];

  const result = await rolePools.reporting.query(`
    SELECT
      date_trunc('minute', occurred_at)                             AS bucket,
      COALESCE(SUM(aggregate_count), 0)                                                      AS event_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE event_category = 'SECURITY'), 0)          AS security_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE outcome IN ('BLOCK','FAILURE')), 0)        AS failure_count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE event_category = 'ENFORCEMENT'), 0)       AS enforcement_count
    FROM qodiqa_platform_audit_events_full_read()
    WHERE occurred_at >= NOW() - ($1::integer || ' minutes')::interval
    GROUP BY bucket
    ORDER BY bucket ASC
  `, [Math.min(windowMinutes, 1440)], 'audit_store_ingestion_rate');

  return result.rows;
}

/**
 * Top event types by volume over the last N hours.
 * Useful for anomaly detection and capacity planning.
 */
async function topEventTypes(hours = 24, limit = 20) {
  if (!pgPool.isEnabled()) return [];

  const result = await rolePools.reporting.query(`
    SELECT
      event_type,
      event_category,
      COALESCE(SUM(aggregate_count), 0) AS count,
      COALESCE(SUM(aggregate_count) FILTER (WHERE outcome IN ('BLOCK','FAILURE')), 0) AS failure_count
    FROM qodiqa_platform_audit_events_full_read()
    WHERE occurred_at >= NOW() - ($1::integer || ' hours')::interval
    GROUP BY event_type, event_category
    ORDER BY count DESC
    LIMIT $2
  `, [Math.min(hours, 168), Math.min(limit, 100)], 'audit_store_top_events');

  return result.rows;
}

module.exports = {
  ingest,
  classifyEventType: _classify, // exported for the privilege-change audit test
  flush,      // (step 5): batched writer
  batchStats, //
  // exported so the regression test asserts against the same set the
  // write path actually uses, rather than a copy that could drift away from it.
  INGESTIBLE_SEVERITIES,
  search,
  getEvent,
  correlate,
  correlateByTrace,
  artifactTimeline,
  actorActivity,
  stats,
  ingestionRate,
  topEventTypes,
};
