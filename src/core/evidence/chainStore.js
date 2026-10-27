'use strict';

/**
 * QODIQA Evidence Chain Store — Component #21
 *
 * PostgreSQL persistence layer for the immutable evidence chain ledger.
 *
 * WRITE PATH:  recordEvidenceFromAuditEntry(auditEntry, keyInfo, opts)
 *   Called fire-and-forget from pg-audit-backend.persistEntry() after every
 *   successful audit chain write.  Locks the evidence_chain_head pointer row
 *   (migration 042), resolves the previous evidence hash from it to build
 *   the chain link, INSERTs, then advances the pointer.  Never throws.  See
 *   the comment below for why this locks a dedicated pointer row rather
 *   than evidence_chain_records' own last row.
 *
 * READ PATH:   getByEvidenceId(), getByArtifactId(), searchEvidence(),
 *              getChain(), verifyEvidence(), verifyChainRange(),
 *              getVerifications(), aggregateStats()
 *
 * All reads return empty / null when PG is not enabled.
 *
 * Immutability contract:
 *   Only INSERT statements are issued against evidence_chain_records and
 *   evidence_chain_verifications.  No UPDATE or DELETE is ever executed.
 */

const pgPool  = require('../../infra/postgres/pool');
const rolePools = require('../../infra/postgres/rolePools'); // operator cross-tenant reads run as qodiqa_reporting
const chain   = require('./chain');
const evidenceBase = require('./evidenceBase'); // where the kept chain starts after a prune
const metrics = require('../../observability/metrics');
const { emit } = require('../../../services/logger');
const { setLocal } = require('../../infra/postgres/tenantContext');

// FINDING-EVIDENCE-CHAIN-RECORDS-PERMISSION (superseded — see below): the
// original fix for qodiqa_app's lack of UPDATE-class ACL on
// evidence_chain_records was a transaction-scoped advisory lock
// (pg_advisory_xact_lock) guarding a plain `SELECT ... ORDER BY id DESC
// LIMIT 1` chain-head read. That closed the ACL/42501 problem but not a
// separate, pre-existing race: FINDING-EVIDENCE-CHAIN-FORK-RACE-REPORT.md
// (deterministically reproduced, 3/3 forced-overlap runs) — blocking on a
// lock does not refresh a REPEATABLE READ transaction's snapshot unless the
// row it locked was itself UPDATEd by the blocking transaction, and the
// old approach locked nothing that was ever UPDATEd (evidence_chain_records
// is INSERT-only). Two concurrent writers could both read the same stale
// head and link to the same prevHash — a silent fork.
//
// migration 042's evidence_chain_head is the fix: a dedicated single-row
// pointer, `SELECT ... FOR UPDATE`-locked and UPDATEd atomically with every
// evidence_chain_records INSERT, in the same transaction. Because this
// transaction actually UPDATEs the row it locked, Postgres's EvalPlanQual
// re-fetch applies on unblock — the same mechanism migration 026 already
// uses for audit_chain_head (see distributedOrdering.js). qodiqa_app holds
// SELECT+UPDATE (no INSERT) on evidence_chain_head only — a new, separate,
// single-row table; evidence_chain_records' own ACL is untouched (still
// SELECT+INSERT only, no UPDATE, immutability contract intact).

// Local equivalent of pg-audit-backend.js's queryByArtifactId() — inlined
// rather than required from src/infra/postgres/pg-audit-backend.js so that
// Core never depends on Infrastructure (that reverse edge, paired with
// pg-audit-backend.js's own need to call into this module after a write, was
// the one real circular dependency in the codebase; see pg-audit-backend.js's
// header comment on persistEntry() for the other half).
//
// (evidence-verifier RLS, design decision STOP 1 = A): reads through
// migration 048's qodiqa_audit_chain_fetch_by_artifact_id() — the SECURITY
// DEFINER point lookup created for exactly this lookup (and already used
// by pg-audit-backend's queryByArtifactId()). A plain `FROM audit_chain` here
// is subject to ac_tenant_select and, under the non-BYPASSRLS qodiqa_app role
// with no tenant context, could not see any tenant-scoped row, so every
// genuine tenant-scoped evidence record verified INVALID. The bypass is only
// ever reached from verifyEvidence(), which accepts the returned row solely
// when its tenant matches the evidence record's (see there). RLS on
// audit_chain is unchanged.
async function _queryAuditEntryByArtifactId(artifactId) {
  if (!pgPool.isEnabled()) return null;
  // (R-F3/R-F4): projected rows (mirror_encoding 1) store P(artifactId) and P(...) in every per-field column; a
  // native row stores raw values. Look up by P(id) — identical to the raw id for every system-generated id — fall back
  // to the raw id for native rows only, and decode at this PG → entry boundary before verifyEvidence() uses the row.
  const { encodeString, decodeMirrorRow } = require('../../infra/postgres/mirrorProjection');
  const projected = typeof artifactId === 'string' ? encodeString(artifactId) : artifactId;
  let row = await _fetchAuditRowByStoredArtifactId(projected);
  if (row && row.mirrorEncoding !== 1 && projected !== artifactId) row = null;   // a native row whose raw id = P(other id)
  if (!row && projected !== artifactId) {
    row = await _fetchAuditRowByStoredArtifactId(artifactId);
    if (row && row.mirrorEncoding === 1) row = null;
  }
  if (!row) return null;
  row = decodeMirrorRow(row, `audit_chain row ${row.hash}`);
  return { ...row, consentProvenance: row.consentProvenance ?? null, policyDecision: row.policyDecision ?? null, callerContext: row.callerContext ?? null };
}

async function _fetchAuditRowByStoredArtifactId(storedArtifactId) {
  const result = await rolePools.reporting.query(`
    SELECT
      hash, prev_hash AS "prevHash", canonical,
      artifact_id AS "artifactId", decision,
      recorded_at::text AS timestamp,
      high_res_time AS "highResTime",
      input_hash AS "inputHash",
      signature, request_hash AS "requestHash",
      policy_hash AS "policyHash",
      verification_result AS "verificationResult",
      nonce, tenant_id AS "tenantId",
      execution_context AS "executionContext",
      public_key_id AS "publicKeyId",
      schema_version AS "schemaVersion",
      consent_provenance AS "consentProvenance",
      policy_decision AS "policyDecision",
      caller_context AS "callerContext",
      mirror_encoding AS "mirrorEncoding"
    FROM qodiqa_audit_chain_fetch_by_artifact_id($1)
  `, [storedArtifactId], 'audit_by_artifact');
  return result.rows[0] ?? null;
}

// ── Write path ────────────────────────────────────────────────────────────────

/**
 * Assemble and persist an evidence chain record from a completed audit entry.
 *
 * Designed to be called fire-and-forget (.catch(() => {})) so database failures
 * cannot affect the audit write path that triggered this call.
 *
 * @param {object}      auditEntry — frozen audit chain entry from audit-log.js
 * @param {object|null} keyInfo    — from keyManager (may be null if key unknown)
 * @param {object}      [opts]
 * @param {number|null} [opts.policyVersion] — from policy provenance lookup
 * @param {string}      [opts.policyId]      — defaults to 'POLICY_SET'
 */
async function recordEvidenceFromAuditEntry(auditEntry, keyInfo, opts) {
  if (!pgPool.isEnabled()) return;

  try {
    await _recordEvidenceFromAuditEntryOrThrow(auditEntry, keyInfo, opts);
  } catch (err) {
    metrics.evidenceChainPersistFailuresTotal.inc({});
    // O9: first N per window in full, the rest counted (src/observability/aggregatedEmit.js failureEmit)
    require('../../observability/aggregatedEmit').failureEmit(emit, 'ERROR', 'EVIDENCE_CHAIN_PERSIST_FAILED', {
      artifactId: auditEntry.artifactId,
      error:      err.message,
      code:       err.code ?? null,
    });
    // Absorbed — never propagated to this function's callers. Retryable
    // failures are durably queued by the caller (pg-audit-backend.js) via
    // the Persistence Recovery Queue instead of being dropped here.
  }
}

/**
 * Same write as recordEvidenceFromAuditEntry(), but throws instead of
 * absorbing the error. Used exclusively by the Persistence Recovery Queue's
 * EVIDENCE_CHAIN_SAVE retry handler (recoveryManager.js), which needs a real
 * exception to decide whether the retry succeeded.
 *
 * Not for direct use elsewhere — every other caller should keep using
 * recordEvidenceFromAuditEntry(), whose fire-and-forget contract this
 * preserves unchanged.
 */
async function _recordEvidenceFromAuditEntryOrThrow(auditEntry, keyInfo, opts) {
    // READ COMMITTED (not the pool's REPEATABLE READ default): a
    // transaction blocked on evidence_chain_head's row lock must
    // transparently re-fetch the fresh row once unblocked, not raise
    // 40001. Under REPEATABLE READ the same lock-then-see-a-newer-value
    // scenario is a serialization failure, not a silent success — correct
    // for most transactions, but this one specifically wants the fresh
    // pointer value, not an abort. Same choice distributedOrdering.js
    // already makes for audit_chain_head, same reason.
    await pgPool.withTransaction(async (tx) => {
      const headRes = await tx.query(
        `SELECT tail_hash FROM evidence_chain_head FOR UPDATE`,
      );
      const previousEvidenceHash = headRes.rows[0]?.tail_hash ?? null;

      const record = chain.buildEvidenceRecord(auditEntry, keyInfo, {
        previousEvidenceHash,
        policyVersion: opts?.policyVersion ?? null,
        policyId:      opts?.policyId      ?? 'POLICY_SET',
      });

      const insertedId = await _insertEvidenceRecordLocked(tx, record);

      // Only advance the pointer when a row was actually inserted —
      // ON CONFLICT DO NOTHING means a retried/duplicate artifact_id
      // inserted nothing, and the pointer must not move (or reference a
      // hash with no corresponding row) for a no-op.
      if (insertedId === undefined) return; // replay: evidence row already present
      if (insertedId !== null) {
        await tx.query(
          `UPDATE evidence_chain_head SET tail_hash = $1, tail_id = $2`,
          [record.evidenceHash, insertedId],
        );
      }

      metrics.evidenceChainRecordsTotal.inc({ decision: record.decision });

      emit('INFO', 'EVIDENCE_CHAIN_RECORD_CREATED', {
        evidenceId:   record.evidenceId,
        artifactId:   record.artifactId,
        decision:     record.decision,
        evidenceHash: record.evidenceHash,
      });
    }, { isolationLevel: 'READ COMMITTED' });
}

// phase 9: the per-record write shared by the single-record path above and the batched path below,
// so the two can never diverge. Caller holds evidence_chain_head FOR UPDATE inside a READ COMMITTED transaction.
// Returns undefined when the artifact already has its evidence row,
// the inserted id, or null when ON CONFLICT inserted nothing.
async function _insertEvidenceRecordLocked(tx, record) {
    // Same fix as registrar.js / pg-audit-backend.js — set AFTER the
    // chain-head lock above, immediately before the INSERT. Currently
    // masked by this table's extra unconditional ecr_select policy
    // (USING (true)), but relying on that redundant policy staying in
    // place would be fragile — fix the write path too.
    if (record.tenantId) {
      await setLocal(tx, record.tenantId);
    }

    // gap-free idempotent replay. Under the head lock
    // above, an artifact that already has its evidence row is a successful
    // replay (recovery retry, DLQ replay, duplicate call) and returns here:
    // no INSERT is attempted, so no BIGSERIAL id is consumed — a burnt id
    // would otherwise leave a gap that fails the NEXT record's
    // CHAIN_CONTINUITY (id = prior + 1). Concurrent duplicates serialize on
    // the head lock, and under READ COMMITTED this later statement sees the
    // row the first one committed. Read with this transaction's tenant
    // context (RLS unchanged: own-tenant or NULL-tenant rows); ON CONFLICT
    // below stays as the backstop for anything this check cannot see.
    const existing = await tx.query(
      'SELECT id FROM evidence_chain_records WHERE artifact_id = $1',
      [record.artifactId],
    );
    if (existing.rows.length > 0) return undefined;

    const insertRes = await tx.query(`
      INSERT INTO evidence_chain_records (
        evidence_id, artifact_id, artifact_hash,
        policy_id, policy_version, policy_hash,
        key_id, key_version, key_fingerprint,
        audit_record_id, audit_record_hash,
        previous_evidence_hash, evidence_hash,
        decision, tenant_id, created_at,
        schema_version, consent_provenance, policy_decision,
        caller_context
      ) VALUES (
        $1,  $2,  $3,
        $4,  $5,  $6,
        $7,  $8,  $9,
        $10, $11,
        $12, $13,
        $14, $15, $16,
        $17, $18, $19,
        $20
      )
      ON CONFLICT (artifact_id) DO NOTHING
      RETURNING id
    `, [
      record.evidenceId,
      record.artifactId,
      record.artifactHash,
      record.policyId,
      record.policyVersion   ?? null,
      record.policyHash,
      record.keyId           ?? null,
      record.keyVersion      ?? null,
      record.keyFingerprint  ?? null,
      record.auditRecordId,
      record.auditRecordHash,
      record.previousEvidenceHash ?? null,
      record.evidenceHash,
      record.decision,
      record.tenantId        ?? null,
      record.createdAt instanceof Date ? record.createdAt : new Date(record.createdAt),
      // TRACE-2: schema_version + the two provenance JSONB blobs.
      record.schemaVersion   ?? 1,
      record.consentProvenance != null ? JSON.stringify(record.consentProvenance) : null,
      record.policyDecision    != null ? JSON.stringify(record.policyDecision)    : null,
      // authenticated-caller snapshot JSONB blob.
      record.callerContext     != null ? JSON.stringify(record.callerContext)     : null,
    ]);

    return insertRes.rows[0] ? insertRes.rows[0].id : null;
}

/**
 * phase 9: batched evidence write for the single-node audit-mirror writer. One transaction, one
 * evidence_chain_head lock, records linked in order (each record's previous_evidence_hash = the record inserted just
 * before it in this transaction), the head pointer advanced once to the last inserted record — the same chain the
 * per-record path would build one transaction at a time, with one commit instead of one per record. Throws on any
 * error (the whole batch rolls back); the caller then falls back to the per-record path, which keeps the recovery-
 * queue semantics unchanged. Events and metrics are emitted only after the commit.
 *
 * @param {Array<{ auditEntry: object, keyInfo: object|null }>} items  in audit-chain order
 */
async function _recordEvidenceBatchOrThrow(items, opts) {
  const created = [];
  await pgPool.withTransaction(async (tx) => {
    const headRes = await tx.query(`SELECT tail_hash FROM evidence_chain_head FOR UPDATE`);
    let previousEvidenceHash = headRes.rows[0]?.tail_hash ?? null;
    let last = null;
    for (const { auditEntry, keyInfo } of items) {
      const record = chain.buildEvidenceRecord(auditEntry, keyInfo, {
        previousEvidenceHash,
        policyVersion: opts?.policyVersion ?? null,
        policyId:      opts?.policyId      ?? 'POLICY_SET',
      });
      const insertedId = await _insertEvidenceRecordLocked(tx, record);
      if (insertedId === undefined || insertedId === null) continue; // replay / no-op: the chain tail is unchanged
      previousEvidenceHash = record.evidenceHash;
      last = { hash: record.evidenceHash, id: insertedId };
      created.push(record);
    }
    if (last) await tx.query(`UPDATE evidence_chain_head SET tail_hash = $1, tail_id = $2`, [last.hash, last.id]);
  }, { isolationLevel: 'READ COMMITTED' });
  for (const record of created) {
    metrics.evidenceChainRecordsTotal.inc({ decision: record.decision });
    emit('INFO', 'EVIDENCE_CHAIN_RECORD_CREATED', {
      evidenceId:   record.evidenceId,
      artifactId:   record.artifactId,
      decision:     record.decision,
      evidenceHash: record.evidenceHash,
    });
  }
  return created.length;
}

// ── Read path ─────────────────────────────────────────────────────────────────

/**
 * Fetch a single evidence record by its UUID.
 *
 * @param {string} evidenceId — UUID
 * @returns {Promise<object|null>}
 */
async function getByEvidenceId(evidenceId) {
  if (!pgPool.isEnabled()) return null;

  // evidence_chain_records's own RLS (ecr_tenant_select) restricts a
  // plain query with no session tenant context to platform-level rows only.
  // This is an RBAC-gated ops-only forensic-investigation console
  // (/evidence-chain, READ_EVIDENCE_CHAIN) with no tenant-scoping middleware,
  // so the fix is the SECURITY DEFINER full-read bypass (migration 053), not
  // withTenantTransaction. See D1.
  const res = await rolePools.reporting.query(
    `SELECT * FROM qodiqa_evidence_chain_records_full_read() WHERE evidence_id = $1 LIMIT 1`,
    [evidenceId],
    'evidence_by_evidence_id',
  );
  return res.rows[0] ?? null;
}

/**
 * Fetch a single evidence record by the artifact it covers.
 * At most one record exists per artifact (UNIQUE constraint on artifact_id).
 *
 * @param {string} artifactId
 * @returns {Promise<object|null>}
 */
/**
 * the public-route variant of getByArtifactId(), for
 * anonymous artifact verification (POST /portal/verify, /v1/attestation/verify).
 * Runs as the app role through migration 061's qodiqa_evidence_public_lookup(),
 * which returns the record only when its tenant equals the tenant the artifact
 * claims (or the record is platform-level) — the database enforces what
 * portal.lookupEvidenceRecord() used to check in JavaScript after a
 * cross-tenant read.
 *
 * @param {string} artifactId
 * @param {string|null} claimedTenantId  the artifact's payload.tenantId
 */
async function getPublicByArtifactId(artifactId, claimedTenantId) {
  if (!pgPool.isEnabled()) return null;
  const res = await pgPool.query(
    'SELECT * FROM qodiqa_evidence_public_lookup($1, $2)',
    [artifactId, claimedTenantId ?? null],
    'evidence_public_by_artifact_id',
  );
  return res.rows[0] ?? null;
}

async function getByArtifactId(artifactId) {
  if (!pgPool.isEnabled()) return null;

  // see getByEvidenceId()'s comment above -- same bypass, same rationale.
  const res = await rolePools.reporting.query(
    `SELECT * FROM qodiqa_evidence_chain_records_full_read() WHERE artifact_id = $1 LIMIT 1`,
    [artifactId],
    'evidence_by_artifact_id',
  );
  return res.rows[0] ?? null;
}

/**
 * Paginated search across evidence records with full filtering.
 *
 * @param {object} [opts]
 * @param {string} [opts.artifactId]
 * @param {string} [opts.decision]       — 'ALLOW' or 'BLOCK'
 * @param {string} [opts.policyHash]
 * @param {string} [opts.keyId]
 * @param {string} [opts.auditRecordId]
 * @param {string} [opts.tenantId]
 * @param {string} [opts.startTime]      — ISO timestamp
 * @param {string} [opts.endTime]        — ISO timestamp
 * @param {number} [opts.page=1]
 * @param {number} [opts.pageSize=50]
 * @param {'asc'|'desc'} [opts.sortOrder='desc']
 * @returns {Promise<{ records: object[], total: number, page: number, pageSize: number }>}
 */
async function searchEvidence({
  artifactId,
  decision,
  policyHash,
  keyId,
  auditRecordId,
  tenantId,
  startTime,
  endTime,
  page      = 1,
  pageSize  = 50,
  sortOrder = 'desc',
} = {}) {
  if (!pgPool.isEnabled()) return { records: [], total: 0, page, pageSize };

  const clauses = [];
  const params  = [];
  let   p       = 1;

  const add = (clause, value) => {
    clauses.push(clause.replace('?', `$${p++}`));
    params.push(value);
  };

  if (artifactId)    add('artifact_id = ?',     artifactId);
  if (decision)      add('decision = ?',         decision.toUpperCase());
  if (policyHash)    add('policy_hash = ?',      policyHash);
  if (keyId)         add('key_id = ?',           keyId);
  if (auditRecordId) add('audit_record_id = ?',  auditRecordId);
  if (tenantId)      add('tenant_id = ?',        tenantId);
  if (startTime)     add('created_at >= ?',      new Date(startTime));
  if (endTime)       add('created_at <= ?',      new Date(endTime));

  const where  = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
  const dir    = sortOrder === 'asc' ? 'ASC' : 'DESC';
  const pg     = Math.max(1, page);
  const ps     = Math.min(Math.max(1, pageSize), 500);
  const offset = (pg - 1) * ps;

  const [dataRes, cntRes] = await Promise.all([
    rolePools.reporting.query(`
      SELECT
        id, evidence_id, artifact_id, artifact_hash, decision,
        policy_id, policy_version, policy_hash,
        key_id, key_version, key_fingerprint,
        audit_record_id, audit_record_hash,
        previous_evidence_hash, evidence_hash,
        created_at, tenant_id
      FROM qodiqa_evidence_chain_records_full_read()
      ${where}
      ORDER BY created_at ${dir}, id ${dir}
      LIMIT $${p++} OFFSET $${p++}
    `, [...params, ps, offset], 'evidence_search'),

    rolePools.reporting.query(
      `SELECT count(*) AS total FROM qodiqa_evidence_chain_records_full_read() ${where}`,
      params,
      'evidence_search_count',
    ),
  ]);

  return {
    records:  dataRes.rows,
    total:    Number(cntRes.rows[0]?.total ?? 0),
    page:     pg,
    pageSize: ps,
  };
}

/**
 * Fetch an ordered segment of the evidence chain for continuity inspection.
 * Records are returned in id ASC order, suitable for passing to
 * chain.validateChainContinuity().
 *
 * @param {object} [opts]
 * @param {number} [opts.startId]  — inclusive lower bound (id >=)
 * @param {number} [opts.endId]    — inclusive upper bound (id <=)
 * @param {number} [opts.limit=100] — max records to return (capped at 10000)
 * @returns {Promise<object[]>}
 */
async function getChain({ startId, endId, limit = 100 } = {}) {
  if (!pgPool.isEnabled()) return [];

  const clauses = [];
  const params  = [];
  let   p       = 1;

  if (startId != null) { clauses.push(`id >= $${p++}`); params.push(Number(startId)); }
  if (endId   != null) { clauses.push(`id <= $${p++}`); params.push(Number(endId)); }

  const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
  const cap   = Math.min(Math.max(1, limit), 10_000);

  // see getByEvidenceId()'s comment above -- same bypass, same rationale.
  // H129-B: schema_version and the TRACE-2 / fields are part of the
  // evidence hash for schema_version >= 2 (chain.canonicalFieldsFor); without
  // them validateChainContinuity() recomputed every record under the V1 field
  // set and reported every current record as tampered.
  const res = await rolePools.reporting.query(`
    SELECT
      id, evidence_id, artifact_id, artifact_hash, decision,
      policy_id, policy_version, policy_hash,
      key_id, key_version, key_fingerprint,
      audit_record_id, audit_record_hash,
      previous_evidence_hash, evidence_hash,
      created_at, tenant_id,
      schema_version, consent_provenance, policy_decision, caller_context
    FROM qodiqa_evidence_chain_records_full_read()
    ${where}
    ORDER BY id ASC
    LIMIT $${p}
  `, [...params, cap], 'evidence_chain_get');

  return res.rows;
}

// ── Verification ──────────────────────────────────────────────────────────────

/**
 * Run the 7-step verification for a single evidence record and persist the run.
 *
 * Looks up the audit entry from PG and the signing key from keyManager.
 * Skips steps where context is unavailable rather than failing.
 * The run result is persisted to evidence_chain_verifications (fire-and-forget).
 *
 * @param {string} evidenceId  — UUID of the evidence record to verify
 * @param {object} [opts]
 * @param {string} [opts.verifiedBy='system']
 * @returns {Promise<object>}  — verifyEvidenceRecord() result with durationMs
 */
async function verifyEvidence(evidenceId, { verifiedBy = 'system' } = {}) {
  if (!pgPool.isEnabled()) {
    return {
      result:        'ERROR',
      failedStep:    null,
      failureReason: 'PG not enabled',
      stepsPassed:   [],
      stepsFailed:   [],
      durationMs:    0,
    };
  }

  const start = Date.now();

  const evidenceRecord = await getByEvidenceId(evidenceId);
  if (!evidenceRecord) {
    return {
      result:        'ERROR',
      failedStep:    null,
      failureReason: `Evidence record not found: ${evidenceId}`,
      stepsPassed:   [],
      stepsFailed:   [],
      durationMs:    Date.now() - start,
    };
  }

  // Fetch the audit entry from PG for steps 1, 2, and 4.
  let auditEntry = null;
  try {
    auditEntry = await _queryAuditEntryByArtifactId(evidenceRecord.artifact_id);
  } catch { /* best-effort */ }

  // tenant-consistency check: the audit row read through the SECURITY
  // DEFINER lookup is accepted only if it belongs to the same tenant as the
  // evidence record being verified (NULL = platform-level on both sides).
  // Otherwise it is discarded — never compared, so none of its values reach
  // the verification result — and every audit-dependent step fails closed.
  let auditEntryRejectedReason = null;
  if (auditEntry && (auditEntry.tenantId ?? null) !== (evidenceRecord.tenant_id ?? null)) {
    auditEntry = null;
    auditEntryRejectedReason = 'audit record tenant does not match the evidence record tenant';
    emit('WARN', 'EVIDENCE_AUDIT_TENANT_MISMATCH', {
      evidenceId,
      artifactId: evidenceRecord.artifact_id,
    });
  }

  // Fetch live key info for step 3 (key fingerprint verification).
  let keyInfo = null;
  if (evidenceRecord.key_id) {
    try {
      const keyManager = require('../../../services/artifact/keyManager');
      keyInfo = await keyManager.getVerificationKey(evidenceRecord.key_id);
    } catch { /* best-effort */ }
  }

  // Fetch the prior record for steps 6 and 7 (chain link and continuity).
  let priorRecord = null;
  if (evidenceRecord.previous_evidence_hash) {
    try {
      // see getByEvidenceId()'s comment above -- same bypass, same rationale.
      const priorRes = await rolePools.reporting.query(
        `SELECT * FROM qodiqa_evidence_chain_records_full_read()
          WHERE evidence_hash = $1
          LIMIT 1`,
        [evidenceRecord.previous_evidence_hash],
        'evidence_prior_by_hash',
      );
      priorRecord = priorRes.rows[0] ?? null;
    } catch { /* best-effort */ }
  }

  // the first record KEPT after a retention prune links to the archived prefix — its prior
  // record is the prune base (evidenceBase.js), not a row. Anything else leaves the link steps as before (SKIP).
  if (!priorRecord && evidenceRecord.previous_evidence_hash) {
    try {
      const base = await evidenceBase.getEvidenceBase();
      if (base && !base.error && Number(evidenceRecord.id) > base.lastPrunedId
          && evidenceRecord.previous_evidence_hash === base.lastPrunedHash) {
        priorRecord = { id: base.lastPrunedId, evidence_hash: base.lastPrunedHash };
      }
    } catch { /* best-effort, like the prior-record lookup above */ }
  }

  const verResult = chain.verifyEvidenceRecord(evidenceRecord, {
    auditEntry,
    keyInfo,
    priorRecord,
    auditEntryRejectedReason,
  });

  const durationMs = Date.now() - start;

  if (verResult.result === 'INVALID') {
    metrics.evidenceChainVerificationFailuresTotal.inc({});
    emit('ERROR', 'EVIDENCE_CHAIN_VERIFICATION_FAILED', {
      evidenceId,
      artifactId:    evidenceRecord.artifact_id,
      failedStep:    verResult.failedStep,
      failureReason: verResult.failureReason,
    });
  }

  // Persist verification run (fire-and-forget).
  pgPool.query(`
    INSERT INTO evidence_chain_verifications (
      evidence_id, verification_result, failed_step, failure_reason,
      verified_by, steps_passed, steps_failed, duration_ms
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
  `, [
    evidenceRecord.evidence_id,
    verResult.result,
    verResult.failedStep    ?? null,
    verResult.failureReason ?? null,
    verifiedBy,
    JSON.stringify(verResult.stepsPassed),
    JSON.stringify(verResult.stepsFailed),
    durationMs,
  ], 'evidence_verification_insert').catch(err => {
    emit('WARN', 'EVIDENCE_VERIFICATION_PERSIST_FAILED', {
      evidenceId,
      error: err.message,
    });
  });

  return { ...verResult, durationMs };
}

// H132-D: range-request validation. Ids must be positive safe integers of type
// number (no booleans, numeric strings, fractions, negatives or out-of-range
// values — previously Number()-coerced or passed to PostgreSQL raw), both bounds
// are required, and startId <= endId.
const MAX_RANGE_VERIFY = 10_000;

function validateRangeRequest({ startId, endId, limit } = {}) {
  const isId = (v) => typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
  if (!isId(startId) || !isId(endId)) {
    return { ok: false, reason: 'startId and endId must both be positive integers' };
  }
  if (startId > endId) return { ok: false, reason: 'startId must not exceed endId' };
  if (limit !== undefined && limit !== null && (!isId(limit) || limit > MAX_RANGE_VERIFY)) {
    return { ok: false, reason: `limit must be an integer between 1 and ${MAX_RANGE_VERIFY}` };
  }
  return { ok: true, requestedCount: endId - startId + 1 };
}

// H132-D: result semantics (the invariant: valid === true ONLY for a complete,
// fully verified range — valid ⇒ complete ∧ checkedCount === retrievedCount):
//   requestedCount — endId - startId + 1 (null when the request is invalid)
//   retrievedCount — records the store returned for the span
//   complete       — the startId and endId records exist, nothing was truncated,
//                    and every id jump inside the span is hash-linked (an
//                    unused id — a sequence value consumed by a failed
//                    transaction — is not missing data; a deleted record is,
//                    because it breaks the hash link)
//   checkedCount   — records whose link and hash were verified by
//                    validateChainContinuity before it stopped
//   valid          — complete AND continuity held AND every record was checked
//                    AND (with a tenant context) every record belongs to it
//   warnings — additive ID_GAP observations; never a failure
// A span larger than the effective limit is not verified at all (valid false)
// instead of being silently truncated to the first `limit` records.
function _rangeResult(fields) {
  return {
    valid: false, complete: false, requestedCount: null, retrievedCount: 0,
    checkedCount: 0, failureId: null, failureDetail: null, warnings: [], ...fields,
  };
}

/**
 * Validate chain continuity over an ordered range of records.
 *
 * Fetches the specified segment, runs chain.validateChainContinuity(), and
 * emits an error event when the chain is broken.
 *
 * @param {object} [opts]
 * @param {number} [opts.startId]
 * @param {number} [opts.endId]
 * @param {number} [opts.limit=1000]
 * @param {string} [opts.verifiedBy='system']
 * @param {string|null} [opts.tenantId] — H132-D: when set, every record must belong to this tenant
 * @returns {Promise<{ valid: boolean, complete: boolean, requestedCount: number|null, retrievedCount: number, checkedCount: number, failureId: number|null, failureDetail: string|null }>}
 */
async function verifyChainRange({ startId, endId, limit = 1000, verifiedBy = 'system', tenantId = undefined } = {}) {
  const req = validateRangeRequest({ startId, endId, limit });
  if (!req.ok) {
    return _rangeResult({ failureDetail: `Invalid range request: ${req.reason}` });
  }
  const { requestedCount } = req;

  if (!pgPool.isEnabled()) {
    return _rangeResult({ requestedCount, failureDetail: 'PG not enabled — range not verified' });
  }

  const cap = Math.min(Math.max(1, limit), MAX_RANGE_VERIFY);
  if (requestedCount > cap) {
    return _rangeResult({
      requestedCount,
      failureDetail: `Range of ${requestedCount} records exceeds the verification limit of ${cap} — not verified`,
    });
  }

  // after a retention prune, records 1..lastPrunedId are archived and gone. A range that starts
  // inside that prefix cannot be verified here; a range starting at the first kept record links to the prune base; a
  // base whose signed checkpoint does not verify fails every range closed.
  let base = null;
  try { base = await evidenceBase.getEvidenceBase(); } catch (e) {
    return _rangeResult({ requestedCount, failureDetail: `Evidence retention base unreadable (${e.message}) — range not verified` });
  }
  if (base && base.error) return _rangeResult({ requestedCount, failureDetail: `${base.error} — range not verified` });
  if (base && startId <= base.lastPrunedId) {
    return _rangeResult({ requestedCount,
      failureDetail: `Range starts inside the pruned prefix: records up to id ${base.lastPrunedId} were archived and removed under signed checkpoint ${base.checkpointId} — verify them from the archive` });
  }

  const records   = await getChain({ startId, endId, limit: requestedCount });
  const continuity = chain.validateChainContinuity(records,
    base && records.length && records[0].previous_evidence_hash === base.lastPrunedHash ? { startHash: base.lastPrunedHash } : {});
  // an id jump counts as missing data only
  // when the hash link across it is broken; a hash-linked jump is an unused id.
  const unlinkedJump = records.some((r, i) => i > 0
    && Number(r.id) !== Number(records[i - 1].id) + 1
    && r.previous_evidence_hash !== records[i - 1].evidence_hash);
  const complete  = records.length > 0
    && Number(records[0].id) === startId
    && Number(records[records.length - 1].id) === endId
    && !unlinkedJump;
  const warnings = continuity.warnings || [];

  let result;
  if (!complete) {
    result = _rangeResult({
      requestedCount, retrievedCount: records.length, checkedCount: continuity.checkedCount, warnings,
      failureId: continuity.valid ? null : continuity.failureId,
      failureDetail: continuity.valid
        ? `Incomplete range: ${records.length} of ${requestedCount} requested records exist`
        : continuity.failureDetail,
    });
  } else if (tenantId !== undefined && records.some(r => (r.tenant_id ?? null) !== tenantId)) {
    const other = records.find(r => (r.tenant_id ?? null) !== tenantId);
    result = _rangeResult({
      complete: true, requestedCount, retrievedCount: records.length, checkedCount: continuity.checkedCount,
      failureId: Number(other.id), failureDetail: 'Range contains records of another tenant', warnings,
    });
  } else {
    let valid = continuity.valid && continuity.checkedCount === records.length;
    let failureId = continuity.failureId, failureDetail = continuity.failureDetail;
    // the kept chain must reach the evidence head the signed checkpoint vouches for — this is
    // what binds the (unsigned) prune base to the signature.
    if (valid && base && base.signedHead.id > base.lastPrunedId) {
      const sh = records.find(r => Number(r.id) === base.signedHead.id);
      if (sh && sh.evidence_hash !== base.signedHead.hash) {
        valid = false; failureId = base.signedHead.id;
        failureDetail = `Evidence record ${base.signedHead.id} does not match the signed checkpoint's evidence head (${base.checkpointId})`;
      }
    }
    // continuity covers only the hashed fields; the
    // stored decision is outside the evidence hash, so every record's decision is
    // checked against its bound audit record (chain.checkDecisionConsistency) —
    // the same audit lookup and tenant rule as verifyEvidence().
    if (valid) {
      for (const rec of records) {
        let audit = await _queryAuditEntryByArtifactId(rec.artifact_id);
        if (audit && (audit.tenantId ?? null) !== (rec.tenant_id ?? null)) audit = null;
        const dc = chain.checkDecisionConsistency(rec, audit);
        if (!dc.ok) {
          valid = false; failureId = Number(rec.id);
          failureDetail = `Decision not verified at id=${rec.id}: ${dc.reason}`;
          break;
        }
      }
    }
    result = _rangeResult({
      valid, complete: true, requestedCount, retrievedCount: records.length,
      checkedCount: continuity.checkedCount, failureId, failureDetail, warnings,
    });
  }

  if (!result.valid) {
    metrics.evidenceChainVerificationFailuresTotal.inc({});
    emit('ERROR', 'EVIDENCE_CHAIN_CONTINUITY_FAILURE', {
      failureId:     result.failureId,
      failureDetail: result.failureDetail,
      checkedCount:  result.checkedCount,
      verifiedBy,
    });
  }

  return result;
}

/**
 * Fetch the verification history for a single evidence record.
 *
 * @param {string} evidenceId — UUID
 * @param {object} [opts]
 * @param {number} [opts.limit=50]
 * @returns {Promise<object[]>}
 */
async function getVerifications(evidenceId, { limit = 50 } = {}) {
  if (!pgPool.isEnabled()) return [];

  const res = await pgPool.query(`
    SELECT
      id, evidence_id, verification_time, verification_result,
      failed_step, failure_reason, verified_by,
      steps_passed, steps_failed, duration_ms
    FROM evidence_chain_verifications
    WHERE evidence_id = $1
    ORDER BY verification_time DESC
    LIMIT $2
  `, [evidenceId, Math.min(limit, 500)], 'evidence_verifications_history');

  return res.rows;
}

// ── Stats ─────────────────────────────────────────────────────────────────────

/**
 * Aggregate stats across all evidence chain records and verifications.
 * Used for the monitoring dashboard.
 *
 * @returns {Promise<object|null>}
 */
async function aggregateStats() {
  if (!pgPool.isEnabled()) return null;

  // see getByEvidenceId()'s comment above -- same bypass, same
  // rationale for the chain-records half. evidence_chain_verifications is
  // unaffected (its own RLS is already USING(true), unconditionally global —
  //).
  const [chainRes, verifRes] = await Promise.all([
    rolePools.reporting.query(`
      SELECT
        count(*)                                              AS total_records,
        count(*) FILTER (WHERE decision = 'ALLOW')           AS allow_count,
        count(*) FILTER (WHERE decision = 'BLOCK')           AS block_count,
        count(DISTINCT key_id)   FILTER (WHERE key_id IS NOT NULL)      AS distinct_keys,
        count(DISTINCT policy_hash) FILTER (WHERE policy_hash != 'UNAVAILABLE') AS distinct_policy_hashes,
        min(created_at)                                      AS first_record,
        max(created_at)                                      AS last_record
      FROM qodiqa_evidence_chain_records_full_read()
    `, [], 'evidence_chain_stats'),

    pgPool.query(`
      SELECT
        count(*)                                                     AS total_verifications,
        count(*) FILTER (WHERE verification_result = 'VALID')        AS valid_count,
        count(*) FILTER (WHERE verification_result = 'INVALID')      AS invalid_count,
        count(*) FILTER (WHERE verification_result = 'PARTIAL')      AS partial_count,
        count(*) FILTER (WHERE verification_result = 'ERROR')        AS error_count
      FROM evidence_chain_verifications
    `, [], 'evidence_verification_stats'),
  ]);

  const c = chainRes.rows[0]  ?? {};
  const v = verifRes.rows[0]  ?? {};

  return {
    totalRecords:         Number(c.total_records          ?? 0),
    allowCount:           Number(c.allow_count            ?? 0),
    blockCount:           Number(c.block_count            ?? 0),
    distinctKeys:         Number(c.distinct_keys          ?? 0),
    distinctPolicyHashes: Number(c.distinct_policy_hashes ?? 0),
    firstRecord:          c.first_record ?? null,
    lastRecord:           c.last_record  ?? null,
    verifications: {
      total:   Number(v.total_verifications ?? 0),
      valid:   Number(v.valid_count         ?? 0),
      invalid: Number(v.invalid_count       ?? 0),
      partial: Number(v.partial_count       ?? 0),
      error:   Number(v.error_count         ?? 0),
    },
  };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  recordEvidenceFromAuditEntry,
  _recordEvidenceFromAuditEntryOrThrow,
  _recordEvidenceBatchOrThrow, // phase 9: batched single-node mirror path
  getByEvidenceId,
  getByArtifactId,
  getPublicByArtifactId,
  searchEvidence,
  getChain,
  verifyEvidence,
  verifyChainRange,
  validateRangeRequest,
  MAX_RANGE_VERIFY,
  getVerifications,
  aggregateStats,
};
