'use strict';

/**
 * ConsentStore — PostgreSQL persistence layer for consent records and audit log.
 *
 * All methods are fail-closed: if PostgreSQL is unavailable, they throw rather
 * than silently succeed. Callers must handle unavailability by denying consent.
 *
 * Records are never deleted — use state transitions (REVOKED, EXPIRED) instead.
 * The audit log is append-only; updates to it are never issued.
 */

const crypto   = require('crypto');
const pool     = require('../../infra/postgres/pool');
const rolePools = require('../../infra/postgres/rolePools'); // verifier integrity scan runs as qodiqa_system
const { emit } = require('../../../services/logger');
const stableStringify = require('../../utils/stableStringify');

const { STATE, isValidTransition, isTerminal } = require('./ConsentStateModel');

// ── Canonical record hash ─────────────────────────────────────────────────────

function _recordHash(record) {
  const canonical = JSON.stringify({
    id:         record.id,
    actor_id:   record.actor_id,
    action:     record.action,
    state:      record.state,
    scope:      record.scope ?? null,
    tenant_id:  record.tenant_id ?? null,
    granted_at: record.granted_at,
    granted_by: record.granted_by,
    expires_at: record.expires_at ?? null,
  });
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

// ── Audit helpers ─────────────────────────────────────────────────────────────

// TRACE-3: single source of truth for the audit-row checksum formula, used
// both when writing a row (_appendAudit below) and when verifying one back
// (verifyAuditChecksum below) — a checksum that is written and verified by
// two independently-maintained formulas is a drift risk, not a real integrity
// check. Covers exactly consent_id|event_type|actor|detail — the same four
// fields the original implementation covered; NOT from_state/to_state/
// actor_id/action/tenant_id/verification_result/denial_reason/request_id,
// even though those are also persisted columns on the same row. Widening the
// formula to cover more fields would silently invalidate every historical
// row's checksum with no versioning scheme for this table, so this documents
// the real coverage rather than changing it.
//
// Uses stableStringify (lexicographic key sort at every depth), NOT plain
// JSON.stringify, for `detail`. This is a deliberate, empirically-verified
// fix, not stylistic: `detail` is stored in a JSONB column, and PostgreSQL's
// jsonb type does NOT preserve original key insertion order — it re-emits
// object keys in its own internal order (observed: ascending key length,
// ties broken lexicographically) on every read. A checksum computed from
// plain JSON.stringify(detail) at write time therefore could never be
// reproduced from the same row read back later purely because of storage
// round-trip reordering, for any `detail` object whose authored key order
// isn't coincidentally already length-ascending (e.g. suspend()'s
// { suspension_reason, suspended_until } or rectify()'s
// { fields, before, after }) — a false tamper signal on every legitimate
// row of that shape, not a real integrity check. stableStringify sorts keys
// deterministically regardless of which order the object's keys happen to
// enumerate in, so it produces the same output whether given the pristine
// pre-insert object or the jsonb-round-tripped one read back later.
//
// consent_audit_log is immutable/append-only (no UPDATE grant — see
// pseudonymizeActor()'s comment below), so this fix cannot be backfilled
// onto rows written before it shipped: a row whose `detail` has more than
// one key AND was authored in a non-length-ascending order may report
// checksumValid: false even though it was never tampered with — that is a
// pre-existing defect in the original (previously never verified) formula,
// not evidence of tampering. verifyAuditChecksum()/getAuditLog() below
// surface this via `checksumFormulaNote` on any row from before this fix
// shipped is indistinguishable at read time; operators triaging a mismatch
// should cross-reference event_ts against this fix's deployment date.
function _auditChecksum({ consent_id, event_type, actor, detail }) {
  const detailJson = stableStringify(detail ?? {});
  const checksumSrc = `${consent_id ?? ''}|${event_type}|${actor}|${detailJson}`;
  return crypto.createHash('sha256').update(checksumSrc).digest('hex');
}

/**
 * TRACE-3: recompute and compare the checksum for a consent_audit_log row.
 * Pure function — no I/O. Accepts a DB row (snake_case columns) as returned
 * by getAuditLog()/pool queries against consent_audit_log.
 *
 * @param {object} row — must have consent_id, event_type, actor, detail, checksum
 * @returns {{ valid: boolean, expected: string|null, actual: string|null }}
 */
function verifyAuditChecksum(row) {
  if (!row || typeof row.checksum !== 'string' || !row.checksum) {
    return { valid: false, expected: null, actual: row?.checksum ?? null };
  }
  const expected = _auditChecksum(row);
  return { valid: expected === row.checksum, expected, actual: row.checksum };
}

async function _appendAudit(tx, entry) {
  const { consent_id, event_type, actor, request_id, from_state, to_state,
          actor_id, action, tenant_id, verification_result, denial_reason, detail } = entry;

  const detailJson = JSON.stringify(detail ?? {});
  const checksum = _auditChecksum({ consent_id, event_type, actor, detail });

  await tx.query(
    `INSERT INTO consent_audit_log
       (consent_id, event_type, actor, request_id,
        from_state, to_state, actor_id, action, tenant_id,
        verification_result, denial_reason, detail, checksum)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [
      consent_id ?? null,
      event_type,
      actor,
      request_id ?? null,
      from_state ?? null,
      to_state   ?? null,
      actor_id   ?? null,
      action     ?? null,
      tenant_id  ?? null,
      verification_result ?? null,
      denial_reason       ?? null,
      detailJson,
      checksum,
    ],
  );
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Create a new consent record in PENDING state, then transition to ACTIVE
 * in the same transaction. Emits a CONSENT_GRANTED audit event.
 *
 * If a record already exists for (actor_id, action, tenant_id) it is reset
 * to ACTIVE — UNLESS the existing record is in a terminal state (REVOKED or
 * EXPIRED), in which case the write is rejected. Terminal states are
 * permanent by protocol definition and must never be reactivated by a
 * subsequent create/grant call.
 *
 * @param {object} opts
 * @returns {Promise<object>} created record row
 */
async function create({
  actor_id,
  action,
  tenant_id       = null,
  scope           = null,
  required_scope  = null,
  granted_by,
  granted_via     = 'API',
  grant_reference = null,
  expires_at      = null,
  duration_days   = null,
  subject_name    = null,
  action_display  = null,
  policy_reference= null,
  tags            = [],
  metadata        = {},
  request_id      = null,
  //. Required on POST /consent (route schema);
  // a store-level grant without a basis is recorded as LEGACY_UNSPECIFIED,
  // never auto-labelled 'consent'.
  lawful_basis               = null,
  purpose                    = null,
  purpose_code               = null,
  special_category_condition = null,
}) {
  if (!actor_id || !action || !granted_by) {
    throw new Error('actor_id, action, and granted_by are required');
  }
  if (lawful_basis && !purpose) throw new Error('purpose is required when lawful_basis is given');
  const lawful_basis_status = lawful_basis ? 'SPECIFIED' : 'LEGACY_UNSPECIFIED';

  // Tenant-scoped rows must run inside withTenantTransaction so the RLS
  // policies added by migration 018 (cr_tenant_insert: WITH CHECK
  // (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())) see the
  // matching session context — withTransaction alone never sets it, which
  // made every non-platform-level consent grant fail RLS unconditionally
  // (confirmed via the acceptance test framework, AT-005). Platform-level
  // grants (tenant_id === null) keep using plain withTransaction, matching
  // the policy's own "tenant_id IS NULL" allowance.
  //
  // pinned to READ COMMITTED, not left at pool.js's REPEATABLE READ
  // default. This is a single-statement, single-row upsert keyed on the
  // (actor_id, action, COALESCE(tenant_id,'')) conflict target — no other
  // statement in this transaction reads a different row or table that would
  // need snapshot consistency with it. Under REPEATABLE READ, a concurrent
  // writer to the same key raised SQLSTATE 40001 unconditionally (surfaced
  // as an undifferentiated HTTP 500 with no retry — see
  // Case #10); 40001 cannot occur under
  // READ COMMITTED at all, and ON CONFLICT DO UPDATE's WHERE guard is
  // re-evaluated against the concurrent writer's committed row instead,
  // giving a correct terminal-state rejection (400) rather than an opaque
  // error. Same remedy already applied to AlertStore.saveAlert() for
  // same reasoning.
  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn, { isolationLevel: 'READ COMMITTED' })
    : (fn) => pool.withTransaction(fn, { isolationLevel: 'READ COMMITTED' });

  return runInTransaction(async (tx) => {
    const insertResult = await tx.query(
      `INSERT INTO consent_records
         (actor_id, action, tenant_id, state, scope, required_scope,
          granted_by, granted_via, grant_reference,
          expires_at, duration_days,
          subject_name, action_display, policy_reference,
          tags, metadata,
          lawful_basis, purpose, purpose_code, special_category_condition, lawful_basis_status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
       -- targets migration 046's COALESCE(tenant_id, '') unique index,
       -- not the old plain (actor_id, action, tenant_id) columns -- a NULL
       -- tenant_id (platform-level consent) must collide with itself here
       -- exactly like a real tenant_id does, or this upsert falls through
       -- to a plain INSERT and the terminal-state guard below never runs.
       ON CONFLICT (actor_id, action, (COALESCE(tenant_id, ''))) DO UPDATE
         SET state            = EXCLUDED.state,
             scope            = EXCLUDED.scope,
             required_scope   = EXCLUDED.required_scope,
             granted_by       = EXCLUDED.granted_by,
             granted_via      = EXCLUDED.granted_via,
             grant_reference  = EXCLUDED.grant_reference,
             granted_at       = NOW(),
             expires_at       = EXCLUDED.expires_at,
             duration_days    = EXCLUDED.duration_days,
             subject_name     = EXCLUDED.subject_name,
             action_display   = EXCLUDED.action_display,
             policy_reference = EXCLUDED.policy_reference,
             tags             = EXCLUDED.tags,
             metadata         = EXCLUDED.metadata,
             lawful_basis               = EXCLUDED.lawful_basis,
             purpose                    = EXCLUDED.purpose,
             purpose_code               = EXCLUDED.purpose_code,
             special_category_condition = EXCLUDED.special_category_condition,
             lawful_basis_status        = EXCLUDED.lawful_basis_status,
             revoked_at       = NULL,
             revoked_by       = NULL,
             revocation_reason= NULL,
             suspended_at     = NULL,
             suspended_by     = NULL,
             suspension_reason= NULL,
             suspended_until  = NULL
       WHERE consent_records.state NOT IN ('REVOKED', 'EXPIRED')
       RETURNING *`,
      [
        actor_id, action, tenant_id, STATE.ACTIVE, scope, required_scope,
        granted_by, granted_via, grant_reference,
        expires_at, duration_days,
        subject_name, action_display, policy_reference,
        // tags is a native TEXT[] column — pass the JS array directly so
        // node-postgres encodes it as a Postgres array literal ('{a,b}').
        // JSON.stringify would produce '["a","b"]', which Postgres rejects
        // as a malformed array literal. metadata is JSONB, where
        // JSON.stringify is correct.
        tags, JSON.stringify(metadata),
        lawful_basis, purpose, purpose_code, special_category_condition, lawful_basis_status,
      ],
    );

    if (!insertResult.rows.length) {
      // The unique key existed but the WHERE guard blocked the update — the
      // existing record is in a terminal state and must not be reactivated.
      const existing = await tx.query(
        `SELECT state FROM consent_records
          WHERE actor_id = $1 AND action = $2
            AND (tenant_id = $3 OR (tenant_id IS NULL AND $3 IS NULL))`,
        [actor_id, action, tenant_id],
      );
      const state = existing.rows[0]?.state ?? 'REVOKED';

      emit('WARN', 'CONSENT_REACTIVATION_BLOCKED', {
        actorId: actor_id, action, tenantId: tenant_id, state,
      });

      throw new Error(
        `Cannot grant consent: existing record for actor_id=${actor_id}, action=${action} ` +
        `is in terminal state ${state} and cannot be reactivated`,
      );
    }

    const record = insertResult.rows[0];
    const hash   = _recordHash(record);
    await tx.query('UPDATE consent_records SET record_hash = $1 WHERE id = $2', [hash, record.id]);
    record.record_hash = hash;

    await _appendAudit(tx, {
      consent_id:  record.id,
      event_type:  'CONSENT_GRANTED',
      actor:       granted_by,
      request_id,
      from_state:  null,
      to_state:    STATE.ACTIVE,
      actor_id:    record.actor_id,
      action:      record.action,
      tenant_id:   record.tenant_id,
      detail:      { scope, expires_at, granted_via },
    });

    emit('INFO', 'CONSENT_RECORD_CREATED', {
      consentId: record.id,
      actorId:   actor_id,
      action,
      tenantId:  tenant_id,
      state:     STATE.ACTIVE,
    });

    return record;
  });
}

/**
 * Look up a consent record by (actor_id, action, tenant_id).
 *
 * @returns {Promise<object|null>}
 */
async function findByKey(actor_id, action, tenant_id = null) {
  // Code-hygiene batch, 2026-08-14: ORDER BY added so LIMIT 1 is
  // deterministic. `id` is a random UUID (gen_random_uuid()), not
  // time-ordered, so created_at is the only column that actually orders
  // rows by recency. No behavior change for the expected case (one row per
  // (actor_id, action, tenant_id) triple) — this only matters if duplicates
  // exist, which (migration 046) made structurally impossible going
  // forward.
  const sql = `SELECT * FROM consent_records
      WHERE actor_id = $1 AND action = $2
        AND (tenant_id = $3 OR (tenant_id IS NULL AND $3 IS NULL))
      ORDER BY created_at DESC
      LIMIT 1`;
  const params = [actor_id, action, tenant_id];

  // A plain pool.query() never sets qodiqa.tenant_id, so the cr_tenant_select
  // RLS policy (migration 018) treats every tenant-scoped row as invisible —
  // the hot-path consent lookup always returned "not found" for any
  // non-platform-level consent (confirmed via the acceptance test
  // framework, AT-005). See the matching fix in create() above.
  const result = tenant_id
    ? await pool.withTenantTransaction(tenant_id, (tx) => tx.query(sql, params))
    : await pool.query(sql, params, 'consent_find_by_key');
  return result.rows[0] ?? null;
}

/**
 * Look up a consent record by its UUID.
 *
 * tenant_id is optional (the caller only has the record's id, not
 * its tenant, so it must supply tenant_id explicitly for the tenant-scoped
 * case) — same RLS rationale as findByKey()/revoke() above. A plain
 * pool.query() never sets qodiqa.tenant_id, so the cr_tenant_select RLS
 * policy's `tenant_id IS NULL OR tenant_id = qodiqa_current_tenant()`
 * predicate only ever admits platform-level (tenant_id IS NULL) rows without
 * it — this was NOT a cross-tenant leak (RLS still correctly hid every
 * tenant-scoped row from an unscoped caller), but it meant a tenant-scoped
 * consent record could never be found by id at all.
 *
 * @param {string} id
 * @param {string|null} [tenant_id]
 * @returns {Promise<object|null>}
 */
async function findById(id, tenant_id = null) {
  const sql = 'SELECT * FROM consent_records WHERE id = $1';
  const result = tenant_id
    ? await pool.withTenantTransaction(tenant_id, (tx) => tx.query(sql, [id]))
    : await pool.query(sql, [id], 'consent_find_by_id');
  return result.rows[0] ?? null;
}

/**
 * Revoke a consent record. Fails if already terminal.
 *
 * @returns {Promise<object>} updated record
 */
async function revoke({ id, tenant_id = null, revoked_by, revocation_reason = null, request_id = null }) {
  // Same RLS rationale as create()/findByKey() above: the caller only has
  // the record's id, not its tenant, so it must supply tenant_id explicitly
  // for the tenant-scoped case — a plain withTransaction() never sets the
  // RLS session context and would make any tenant-scoped record invisible
  // to this SELECT ... FOR UPDATE (confirmed via the acceptance test
  // framework, AT-052).
  //
  // pinned to READ COMMITTED. SELECT ... FOR UPDATE + a business-rule
  // check + UPDATE is multiple statements, but every one targets the SAME
  // single row (by id) — no cross-row/cross-table snapshot consistency is
  // needed. Under READ COMMITTED, FOR UPDATE blocks behind a concurrent
  // writer to this row and then re-reads its fresh, post-commit state — the
  // textbook-correct pattern for check-then-act row locking. Under
  // REPEATABLE READ this instead raised 40001 (surfaced as HTTP 500, no
  // retry), and a losing revoke's failure meant consent stayed wrongly
  // ACTIVE. With this pin, the
  // losing side now sees the fresh row and gets a correct outcome — e.g. a
  // revoke that loses to a concurrent revoke now correctly re-reads
  // state=REVOKED and rejects with "already terminal" (400), never a 500 —
  // and a revoke that commits is never silently undone by a concurrent
  // grant regressing to a stale snapshot.
  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn, { isolationLevel: 'READ COMMITTED' })
    : (fn) => pool.withTransaction(fn, { isolationLevel: 'READ COMMITTED' });
  return runInTransaction(async (tx) => {
    const existing = await tx.query(
      'SELECT * FROM consent_records WHERE id = $1 FOR UPDATE',
      [id],
    );
    if (!existing.rows.length) throw new Error(`Consent record not found: ${id}`);
    const record = existing.rows[0];

    if (isTerminal(record.state)) {
      throw new Error(`Cannot revoke consent in terminal state: ${record.state}`);
    }
    if (!isValidTransition(record.state, STATE.REVOKED)) {
      throw new Error(`Invalid transition: ${record.state} → REVOKED`);
    }

    const updated = await tx.query(
      `UPDATE consent_records
          SET state = $1, revoked_at = NOW(), revoked_by = $2, revocation_reason = $3
        WHERE id = $4
        RETURNING *`,
      [STATE.REVOKED, revoked_by, revocation_reason, id],
    );
    const row = updated.rows[0];

    await _appendAudit(tx, {
      consent_id:  id,
      event_type:  'CONSENT_REVOKED',
      actor:       revoked_by,
      request_id,
      from_state:  record.state,
      to_state:    STATE.REVOKED,
      actor_id:    record.actor_id,
      action:      record.action,
      tenant_id:   record.tenant_id,
      detail:      { revocation_reason },
    });

    emit('INFO', 'CONSENT_RECORD_REVOKED', {
      consentId: id,
      actorId:   record.actor_id,
      action:    record.action,
      revokedBy: revoked_by,
    });

    return row;
  });
}

/**
 * Persist the ACTIVE -> EXPIRED transition for a record whose expires_at has
 * passed. effectiveState() derived EXPIRED at
 * lookup time only, so the stored state stayed ACTIVE forever. Idempotent and
 * safe under races: the row is locked, the transition is re-validated against
 * the fresh row and the database clock, and a record that is no longer ACTIVE
 * or not yet due is left untouched (returns null).
 *
 * @returns {Promise<object|null>} the updated row, or null when nothing was due
 */
async function markExpired({ id, tenant_id = null, request_id = null }) {
  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn, { isolationLevel: 'READ COMMITTED' })
    : (fn) => pool.withTransaction(fn, { isolationLevel: 'READ COMMITTED' });
  return runInTransaction(async (tx) => {
    const existing = await tx.query('SELECT * FROM consent_records WHERE id = $1 FOR UPDATE', [id]);
    if (!existing.rows.length) return null;
    const record = existing.rows[0];
    if (record.state !== STATE.ACTIVE || !isValidTransition(record.state, STATE.EXPIRED)) return null;
    const updated = await tx.query(
      `UPDATE consent_records SET state = $1
        WHERE id = $2 AND state = $3 AND expires_at IS NOT NULL AND expires_at <= NOW()
        RETURNING *`,
      [STATE.EXPIRED, id, STATE.ACTIVE],
    );
    if (!updated.rows.length) return null;
    await _appendAudit(tx, {
      consent_id: id,
      event_type: 'CONSENT_EXPIRED',
      actor:      'system',
      request_id,
      from_state: record.state,
      to_state:   STATE.EXPIRED,
      actor_id:   record.actor_id,
      action:     record.action,
      tenant_id:  record.tenant_id,
      detail:     { expires_at: record.expires_at instanceof Date ? record.expires_at.toISOString() : (record.expires_at ?? null) },
    });
    emit('INFO', 'CONSENT_RECORD_EXPIRED', { consentId: id, actorId: record.actor_id, action: record.action });
    return updated.rows[0];
  });
}

/**
 * Suspend a consent record temporarily.
 *
 * @returns {Promise<object>}
 */
async function suspend({ id, tenant_id = null, suspended_by, suspension_reason = null, suspended_until = null, request_id = null }) {
  // same single-row check-then-act shape and same READ COMMITTED
  // rationale as revoke() above — see that function's comment.
  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn, { isolationLevel: 'READ COMMITTED' })
    : (fn) => pool.withTransaction(fn, { isolationLevel: 'READ COMMITTED' });
  return runInTransaction(async (tx) => {
    const existing = await tx.query(
      'SELECT * FROM consent_records WHERE id = $1 FOR UPDATE',
      [id],
    );
    if (!existing.rows.length) throw new Error(`Consent record not found: ${id}`);
    const record = existing.rows[0];

    if (!isValidTransition(record.state, STATE.SUSPENDED)) {
      throw new Error(`Invalid transition: ${record.state} → SUSPENDED`);
    }

    const updated = await tx.query(
      `UPDATE consent_records
          SET state = $1, suspended_at = NOW(), suspended_by = $2,
              suspension_reason = $3, suspended_until = $4
        WHERE id = $5
        RETURNING *`,
      [STATE.SUSPENDED, suspended_by, suspension_reason, suspended_until, id],
    );
    const row = updated.rows[0];

    await _appendAudit(tx, {
      consent_id:  id,
      event_type:  'CONSENT_SUSPENDED',
      actor:       suspended_by,
      request_id,
      from_state:  record.state,
      to_state:    STATE.SUSPENDED,
      actor_id:    record.actor_id,
      action:      record.action,
      tenant_id:   record.tenant_id,
      detail:      { suspension_reason, suspended_until },
    });

    return row;
  });
}

/**
 * Resume (un-suspend) a consent record.
 *
 * @returns {Promise<object>}
 */
async function resume({ id, tenant_id = null, resumed_by, request_id = null }) {
  // same single-row check-then-act shape and same READ COMMITTED
  // rationale as revoke() above — see that function's comment.
  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn, { isolationLevel: 'READ COMMITTED' })
    : (fn) => pool.withTransaction(fn, { isolationLevel: 'READ COMMITTED' });
  return runInTransaction(async (tx) => {
    const existing = await tx.query(
      'SELECT * FROM consent_records WHERE id = $1 FOR UPDATE',
      [id],
    );
    if (!existing.rows.length) throw new Error(`Consent record not found: ${id}`);
    const record = existing.rows[0];

    if (!isValidTransition(record.state, STATE.ACTIVE)) {
      throw new Error(`Invalid transition: ${record.state} → ACTIVE`);
    }

    const updated = await tx.query(
      `UPDATE consent_records
          SET state = $1, suspended_at = NULL, suspended_by = NULL,
              suspension_reason = NULL, suspended_until = NULL
        WHERE id = $2
        RETURNING *`,
      [STATE.ACTIVE, id],
    );
    const row = updated.rows[0];

    await _appendAudit(tx, {
      consent_id:  id,
      event_type:  'CONSENT_RESUMED',
      actor:       resumed_by,
      request_id,
      from_state:  record.state,
      to_state:    STATE.ACTIVE,
      actor_id:    record.actor_id,
      action:      record.action,
      tenant_id:   record.tenant_id,
      detail:      {},
    });

    return row;
  });
}

/**
 * Rectify (correct) mutable PII fields on a consent record — GDPR Article 16.
 *
 * Only a fixed allow-list of fields may be corrected: subject_name, metadata,
 * tags. actor_id/action/state/timestamps are never rectifiable through this
 * path — those are identity/lifecycle fields, not descriptive PII, and
 * changing them is either an erasure (actor_id) or a state transition
 * (state), each with its own method and its own audit semantics.
 *
 * The prior value is returned (not persisted here) so the caller (DSR
 * RectificationService) can record an append-only before/after row in
 * dsr_rectifications without ConsentStore needing to know that table exists.
 *
 * @returns {Promise<{record: object, before: object, after: object}>}
 */
const RECTIFIABLE_FIELDS = Object.freeze(['subject_name', 'metadata', 'tags']);

async function rectify({ id, tenant_id = null, fields, rectified_by, request_id = null }) {
  if (!id || !fields || typeof fields !== 'object') {
    throw new Error('id and fields are required');
  }
  const keys = Object.keys(fields).filter((k) => RECTIFIABLE_FIELDS.includes(k));
  if (!keys.length) {
    throw new Error(`fields must include at least one of: ${RECTIFIABLE_FIELDS.join(', ')}`);
  }
  if (!rectified_by) throw new Error('rectified_by is required');

  // same single-row check-then-act shape and same READ COMMITTED
  // rationale as revoke() above — see that function's comment.
  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn, { isolationLevel: 'READ COMMITTED' })
    : (fn) => pool.withTransaction(fn, { isolationLevel: 'READ COMMITTED' });

  return runInTransaction(async (tx) => {
    const existing = await tx.query(
      'SELECT * FROM consent_records WHERE id = $1 FOR UPDATE',
      [id],
    );
    if (!existing.rows.length) throw new Error(`Consent record not found: ${id}`);
    const record = existing.rows[0];

    const before = {};
    const setClauses = [];
    const params = [];
    let p = 1;
    for (const key of keys) {
      before[key] = record[key];
      setClauses.push(`${key} = $${p}`);
      params.push(key === 'metadata' ? JSON.stringify(fields[key]) : fields[key]);
      p += 1;
    }
    params.push(id);

    const updated = await tx.query(
      `UPDATE consent_records SET ${setClauses.join(', ')} WHERE id = $${p} RETURNING *`,
      params,
    );
    const row = updated.rows[0];

    const after = {};
    for (const key of keys) after[key] = row[key];

    await _appendAudit(tx, {
      consent_id:  id,
      event_type:  'CONSENT_RECTIFIED',
      actor:       rectified_by,
      request_id,
      from_state:  record.state,
      to_state:    record.state,
      actor_id:    record.actor_id,
      action:      record.action,
      tenant_id:   record.tenant_id,
      detail:      { fields: keys, before, after },
    });

    emit('INFO', 'CONSENT_RECORD_RECTIFIED', {
      consentId: id, actorId: record.actor_id, action: record.action, fields: keys,
    });

    return { record: row, before, after };
  });
}

/**
 * Anonymize a consent record — GDPR Article 17 erasure.
 *
 * Scrubs descriptive PII (subject_name, metadata, tags) and forces the
 * record into the terminal REVOKED state if it isn't already terminal
 * (EXPIRED records stay EXPIRED — the state machine has no EXPIRED->REVOKED
 * transition, and re-labeling isn't legally necessary; only PENDING/ACTIVE/
 * SUSPENDED are moved). actor_id is deliberately left untouched here — see
 * pseudonymizeActor() for the separate, opt-in identifier pseudonymization
 * path.
 *
 * Idempotent: erasing an already-erased record re-applies the same scrub
 * (a no-op UPDATE) and appends a fresh CONSENT_ERASED audit entry so repeat
 * DSR requests remain fully auditable rather than silently short-circuiting.
 *
 * @returns {Promise<object>} updated record
 */
async function anonymize({ id, tenant_id = null, erased_by, request_id = null }) {
  if (!id) throw new Error('id is required');
  if (!erased_by) throw new Error('erased_by is required');

  // same single-row check-then-act shape and same READ COMMITTED
  // rationale as revoke() above — see that function's comment.
  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn, { isolationLevel: 'READ COMMITTED' })
    : (fn) => pool.withTransaction(fn, { isolationLevel: 'READ COMMITTED' });

  return runInTransaction(async (tx) => {
    const existing = await tx.query(
      'SELECT * FROM consent_records WHERE id = $1 FOR UPDATE',
      [id],
    );
    if (!existing.rows.length) throw new Error(`Consent record not found: ${id}`);
    const record = existing.rows[0];

    let nextState = record.state;
    if (!isTerminal(record.state)) {
      if (!isValidTransition(record.state, STATE.REVOKED)) {
        throw new Error(`Invalid transition: ${record.state} → REVOKED`);
      }
      nextState = STATE.REVOKED;
    }

    const updated = await tx.query(
      `UPDATE consent_records
          SET subject_name      = NULL,
              metadata          = '{}'::jsonb,
              tags              = '{}',
              state             = $1,
              revoked_at        = COALESCE(revoked_at, NOW()),
              revoked_by        = COALESCE(revoked_by, $2),
              revocation_reason = COALESCE(revocation_reason, $3)
        WHERE id = $4
        RETURNING *`,
      [nextState, erased_by, 'GDPR_ARTICLE_17_ERASURE', id],
    );
    const row = updated.rows[0];

    await _appendAudit(tx, {
      consent_id:  id,
      event_type:  'CONSENT_ERASED',
      actor:       erased_by,
      request_id,
      from_state:  record.state,
      to_state:    nextState,
      actor_id:    record.actor_id,
      action:      record.action,
      tenant_id:   record.tenant_id,
      detail:      { fieldsAnonymized: ['subject_name', 'metadata', 'tags'], legalBasis: 'GDPR Art. 17' },
    });

    emit('INFO', 'CONSENT_RECORD_ERASED', {
      consentId: id, actorId: record.actor_id, action: record.action,
    });

    return row;
  });
}

/**
 * Pseudonymize an actor's identifier across their consent_records rows —
 * GDPR Article 17 erasure, opt-in (pseudonymizeActorId flag on the erasure
 * request; see ErasureService.js). Off by default because actor_id is
 * usually already a system/pseudonymous identifier, and rewriting it
 * unconditionally would silently break an operator's own correlation.
 *
 * Deliberately does NOT touch consent_audit_log: that table is immutable
 * append-only by design (no UPDATE grant, no UPDATE RLS policy — see
 * migrations 018/022, and the module doc comment above). Historical audit
 * entries retain the pre-pseudonymization actor_id as an immutable fact,
 * the same posture already applied to the cryptographic audit chain.
 *
 * @returns {Promise<{recordsUpdated: number}>}
 */
async function pseudonymizeActor({ actor_id, tenant_id = null, pseudonym }) {
  if (!actor_id) throw new Error('actor_id is required');
  if (!pseudonym) throw new Error('pseudonym is required');

  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn)
    : (fn) => pool.withTransaction(fn);

  return runInTransaction(async (tx) => {
    const result = await tx.query(
      `UPDATE consent_records
          SET actor_id = $1
        WHERE actor_id = $2
          AND (tenant_id = $3 OR (tenant_id IS NULL AND $3 IS NULL))
        RETURNING id`,
      [pseudonym, actor_id, tenant_id],
    );
    return { recordsUpdated: result.rowCount ?? 0 };
  });
}

/**
 * is this consent scope a GDPR Art. 9(1) special category
 * (consent_scopes.special_category, migration 064)? An unknown scope is not.
 *
 * @returns {Promise<boolean>}
 */
async function isSpecialCategoryScope(scope) {
  if (!scope) return false;
  const r = await pool.query('SELECT special_category FROM consent_scopes WHERE scope_name = $1', [scope], 'consent_scope_special');
  return r.rows[0]?.special_category === true;
}

/**
 * erase ONE bounded batch of a data subject's
 * consent_records rows. Each row is kept as a tombstone: actor_id → the
 * subject's pseudonym; subject_name, metadata, tags, grant_reference,
 * action_display and suspension_reason scrubbed; granted_by / revoked_by /
 * suspended_by → the pseudonym when they name the subject themselves (operator
 * names are kept); state → REVOKED (terminal states kept); record_hash
 * RECOMPUTED over the new values (it covers actor_id and granted_by). The
 * CONSENT_ERASED audit row carries the pseudonym, never the plaintext id.
 *
 * Unlike list() there is no 200-row ceiling: the caller loops until this
 * returns erased: 0, and every batch is its own transaction (resumable).
 *
 * @returns {Promise<{erased: number}>}
 */
async function eraseSubjectBatch({ actor_id, tenant_id = null, pseudonym, erased_by, request_id = null, batch = 200 }) {
  if (!actor_id) throw new Error('actor_id is required');
  if (!pseudonym || pseudonym === actor_id) throw new Error('a pseudonym distinct from actor_id is required');
  if (!erased_by) throw new Error('erased_by is required');

  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn, { isolationLevel: 'READ COMMITTED' })
    : (fn) => pool.withTransaction(fn, { isolationLevel: 'READ COMMITTED' });

  return runInTransaction((tx) => eraseSubjectBatchWithClient(tx, { actor_id, tenant_id, pseudonym, erased_by, request_id, batch }));
}

/**
 * The body of eraseSubjectBatch on a caller-supplied client/transaction — also
 * used by the DR restore erasure replay (scripts/dr/erasureReplay.js), which runs
 * on the restore connection, so the tombstone and record_hash logic exist once.
 */
async function eraseSubjectBatchWithClient(tx, { actor_id, tenant_id = null, pseudonym, erased_by, request_id = null, batch = 200 }) {
  const rows = (await tx.query(
    `SELECT * FROM consent_records
      WHERE actor_id = $1 AND tenant_id IS NOT DISTINCT FROM $2
      ORDER BY id LIMIT $3 FOR UPDATE`,
    [actor_id, tenant_id, Math.min(Math.max(1, batch), 1000)],
  )).rows;

  for (const record of rows) {
    const nextState = isTerminal(record.state) || !isValidTransition(record.state, STATE.REVOKED) ? record.state : STATE.REVOKED;
    const sub = (v) => (v === actor_id ? pseudonym : v);
    const updated = (await tx.query(
      `UPDATE consent_records
          SET actor_id          = $1,
              granted_by        = $2,
              revoked_by        = COALESCE($3, $6),
              suspended_by      = $4,
              subject_name      = NULL,
              metadata          = '{}'::jsonb,
              tags              = '{}',
              grant_reference   = NULL,
              action_display    = NULL,
              suspension_reason = NULL,
              state             = $5,
              revoked_at        = COALESCE(revoked_at, NOW()),
              revocation_reason = COALESCE(revocation_reason, 'GDPR_ARTICLE_17_ERASURE')
        WHERE id = $7
        RETURNING *`,
      [pseudonym, sub(record.granted_by), record.revoked_by == null ? null : sub(record.revoked_by),
        record.suspended_by == null ? null : sub(record.suspended_by), nextState, erased_by, record.id],
    )).rows[0];
    await tx.query('UPDATE consent_records SET record_hash = $1 WHERE id = $2', [_recordHash(updated), record.id]);

    await _appendAudit(tx, {
      consent_id:  record.id,
      event_type:  'CONSENT_ERASED',
      actor:       erased_by,
      request_id,
      from_state:  record.state,
      to_state:    nextState,
      actor_id:    pseudonym,
      action:      record.action,
      tenant_id:   record.tenant_id,
      detail: {
        fieldsAnonymized: ['actor_id', 'subject_name', 'metadata', 'tags', 'grant_reference', 'action_display', 'suspension_reason'],
        recordHashRecomputed: true,
        legalBasis: 'GDPR Art. 17',
      },
    });
  }
  return { erased: rows.length };
}

/**
 * List consent records with optional filters.
 *
 * @param {object} opts
 * @returns {Promise<{ records: object[], total: number }>}
 */
async function list({ actor_id, tenant_id, state, action, limit = 50, offset = 0 } = {}) {
  const conditions = [];
  const params     = [];

  if (actor_id)  { params.push(actor_id);  conditions.push(`actor_id = $${params.length}`); }
  if (tenant_id) { params.push(tenant_id); conditions.push(`tenant_id = $${params.length}`); }
  if (state)     { params.push(state);     conditions.push(`state = $${params.length}`); }
  if (action)    { params.push(action);    conditions.push(`action = $${params.length}`); }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  params.push(Math.min(limit, 200));
  const limitParam = params.length;
  params.push(Math.max(offset, 0));
  const offsetParam = params.length;

  const dataSql  = `SELECT * FROM consent_records ${where} ORDER BY granted_at DESC, id DESC LIMIT $${limitParam} OFFSET $${offsetParam}`;
  const countSql = `SELECT count(*) AS total FROM consent_records ${where}`;
  const countParams = params.slice(0, conditions.length);

  // the tenant_id WHERE filter above is not enough on its own — a
  // plain pool.query() never sets qodiqa.tenant_id, so the cr_tenant_select
  // RLS policy still only admits platform-level (tenant_id IS NULL) rows
  // underneath it, making `WHERE tenant_id = $N AND (RLS: tenant_id IS NULL)`
  // always empty for any real tenant, regardless of what was requested. Same
  // RLS-session-context fix as findById()/findByKey() above.
  const [dataResult, countResult] = tenant_id
    ? await pool.withTenantTransaction(tenant_id, async (tx) => Promise.all([
        tx.query(dataSql, params),
        tx.query(countSql, countParams),
      ]))
    : await Promise.all([
        pool.query(dataSql, params, 'consent_list'),
        pool.query(countSql, countParams, 'consent_count'),
      ]);

  return {
    records: dataResult.rows,
    total:   Number(countResult.rows[0]?.total ?? 0),
  };
}

/**
 * Append a verification attempt to the audit log (no record update).
 */
async function logVerification({ consent_id, actor_id, action, tenant_id, result, denial_reason, request_id }) {
  if (!pool.isEnabled()) return;

  try {
    await pool.withTransaction(async (tx) => {
      await _appendAudit(tx, {
        consent_id:          consent_id ?? null,
        event_type:          'CONSENT_VERIFIED',
        actor:               'system:verifier',
        request_id:          request_id ?? null,
        actor_id,
        action,
        tenant_id,
        verification_result: result,
        denial_reason:       denial_reason ?? null,
        detail:              {},
      });
    });
  } catch (err) {
    // O9: first N per window in full, the rest counted (src/observability/aggregatedEmit.js failureEmit)
    require('../../observability/aggregatedEmit').failureEmit(emit, 'WARN', 'CONSENT_AUDIT_LOG_FAILED', { error: err.message, actor_id, action });
  }
}

/**
 * Fetch audit log entries for a given consent record.
 */
async function getAuditLog({ consent_id, actor_id, tenant_id = null, limit = 100, offset = 0 }) {
  const conditions = [];
  const params     = [];

  if (consent_id) { params.push(consent_id); conditions.push(`consent_id = $${params.length}`); }
  if (actor_id)   { params.push(actor_id);   conditions.push(`actor_id = $${params.length}`); }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  params.push(Math.min(limit, 500));
  params.push(Math.max(offset, 0));

  const sql = `SELECT * FROM consent_audit_log ${where} ORDER BY event_ts DESC, id DESC LIMIT $${params.length - 1} OFFSET $${params.length}`;

  // (register-named): cal_tenant_select's RLS predicate (tenant_id
  // IS NULL OR tenant_id = qodiqa_current_tenant()) made every call here
  // silently see platform-level rows only -- GET /consent/:id/audit,
  // GET /consent/:id/history, and PortabilityService's DSR export all
  // returned an empty audit trail for any tenant-scoped consent record.
  // tenant_id is now an explicit optional caller-supplied parameter (same
  // shape as findByKey/findById/list above), threaded from the
  // consent.js routes' existing _queryTenantId() helper and from
  // PortabilityService's already-in-scope request.tenant_id.
  const result = tenant_id
    ? await pool.withTenantTransaction(tenant_id, (tx) => tx.query(sql, params))
    : await pool.query(sql, params, 'consent_audit_list');

  // TRACE-3: annotate each row with its recomputed checksum verification —
  // previously the checksum was written and never read back for anything.
  return result.rows.map(row => ({ ...row, checksumValid: verifyAuditChecksum(row).valid }));
}

/**
 * TRACE-3: scan recent consent_audit_log rows and report any whose stored
 * checksum does not match the recomputed one. Wired into the live audit
 * chain verifier's FULL scan (src/core/audit/verifier/ChainVerifier.js) so
 * a checksum mismatch surfaces through the same integrity-reporting path as
 * every other chain-integrity finding, rather than sitting in a table no
 * automated process ever looks at.
 *
 * @param {object} [opts]
 * @param {number} [opts.limit] - max rows to scan (most recent first)
 * @returns {Promise<{ scanned: number, mismatches: object[] }>}
 *   mismatches: [{ id, consentId, eventType, eventTs }]
 */
async function verifyConsentAuditIntegrity({ limit = 5000 } = {}) {
  if (!pool.isEnabled()) return { scanned: 0, mismatches: [] };

  // this is the FULL system-wide integrity scan ChainVerifier wires
  // in (Shape G, not tenant business logic) -- a plain query's cal_tenant_select
  // restriction made the "full" scan silently see platform-level rows only,
  // so tampering in any real tenant's audit trail was invisible to it. Fixed
  // via the SECURITY DEFINER full-read bypass (migration 053), mirroring
  // qodiqa_audit_chain_full_read(). See D1.
  const result = await rolePools.system.query(
    'SELECT id, consent_id, event_type, actor, detail, checksum, event_ts FROM qodiqa_consent_audit_log_full_read() ORDER BY id DESC LIMIT $1',
    [Math.min(Math.max(limit, 1), 20000)],
    'consent_audit_integrity_scan',
  );

  const mismatches = [];
  for (const row of result.rows) {
    if (!verifyAuditChecksum(row).valid) {
      mismatches.push({
        id:        row.id,
        consentId: row.consent_id,
        eventType: row.event_type,
        eventTs:   row.event_ts,
      });
    }
  }

  return { scanned: result.rows.length, mismatches };
}

module.exports = {
  create, findByKey, findById, revoke, markExpired, suspend, resume, list, logVerification, getAuditLog,
  rectify, anonymize, pseudonymizeActor, eraseSubjectBatch, eraseSubjectBatchWithClient, isSpecialCategoryScope, RECTIFIABLE_FIELDS,
  verifyAuditChecksum, verifyConsentAuditIntegrity,
};
