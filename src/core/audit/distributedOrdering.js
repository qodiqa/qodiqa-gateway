'use strict';

/**
 * PostgreSQL-Primary Audit Chain Ordering — SCAL-11 remediation
 * (QODIQA_AUDIT_ORDERING_MODE=distributed)
 *
 * Provides the ordering authority for audit-log.js's append() when running
 * with multiple replicas. Single-node mode never calls this module.
 *
 * Correctness model:
 *   audit_chain_head (migration 026) is a single mutable row holding the
 *   current chain tail. Every append locks that ONE row with
 *   `SELECT ... FOR UPDATE`, computes the new entry using the locked
 *   tail_hash as prevHash, INSERTs into audit_chain, then UPDATEs
 *   audit_chain_head — all inside one transaction. Concurrent replicas
 *   serialize on that row lock.
 *
 *   Isolation level is explicitly READ COMMITTED (not the pool's REPEATABLE
 *   READ default): under READ COMMITTED, a transaction that blocks on the
 *   head row's lock transparently re-fetches the fresh row once unblocked
 *   and proceeds — no retry loop needed. Under REPEATABLE READ (or
 *   SERIALIZABLE), the same scenario raises a 40001 serialization-failure
 *   error instead, because the row changed after the blocked transaction's
 *   snapshot was taken — that's the right behavior when you must not use
 *   stale data silently, but here we WANT the fresh value, not an abort, so
 *   READ COMMITTED is the deliberate, correct choice for this specific
 *   "lock and read a mutable pointer row" pattern.
 *
 * UNIQUE(prev_hash) (migration 026) is a second, independent backstop: even
 * if this locking discipline were somehow bypassed, the database refuses to
 * accept a forked chain rather than silently corrupting it.
 *
 * Dedup/replay: `idx_audit_chain_artifact_id` and `idx_audit_chain_nonce`
 * (both UNIQUE) make artifact/nonce reuse detection PG-authoritative and
 * correct across any number of replicas — a constraint violation here is
 * translated into the exact same error audit-log.js's single-node path
 * throws, so callers (appendMandatory's retry classification, aiChat.js,
 * etc.) don't need to know which ordering mode is active.
 */

const pgPool       = require('../../infra/postgres/pool');
const entryBuilder = require('./entryBuilder');
const { v8InsertValues } = require('../../infra/postgres/v8Columns');
const { projectEntryForMirror, MIRROR_ENCODING_ESCAPED } = require('../../infra/postgres/mirrorProjection'); //

const PG_UNIQUE_VIOLATION = '23505';

function _translateConstraintError(err) {
  if (err && err.code === PG_UNIQUE_VIOLATION) {
    const constraint = err.constraint || '';
    if (constraint.includes('artifact_id')) {
      const e = new Error('already_executed: artifactId already in audit log');
      e.cause = err;
      return e;
    }
    if (constraint.includes('nonce')) {
      const e = new Error('replay_detected: nonce already used');
      e.cause = err;
      return e;
    }
    if (constraint.includes('prev_hash')) {
      // Should be unreachable given the head-row lock — surfaces as a
      // retryable failure (no invalid_*/already_executed/replay_detected
      // prefix) so appendMandatory's bounded retry can recover from it.
      const e = new Error('AUDIT_CHAIN_CONCURRENT_CONFLICT: prev_hash collision despite head lock — retrying');
      e.cause = err;
      return e;
    }
  }
  return err;
}

/**
 * Appends one entry using PostgreSQL as the ordering authority.
 * Mirrors audit-log.js's append() contract: throws invalid_*,
 * already_executed, or replay_detected synchronously for deterministic
 * failures; any other thrown error is a candidate for appendMandatory's
 * bounded retry.
 *
 * @param {object} fields — same shape as audit-log.js append()
 * @returns {Promise<object>} the committed, frozen entry
 */
async function appendEntry(fields) {
  const normalized = entryBuilder.normalizeFields(fields);

  try {
    return await pgPool.withTransaction(async (tx) => {
      const headRes = await tx.query('SELECT tail_hash, tail_seq, tail_schema_version FROM audit_chain_head FOR UPDATE');
      if (headRes.rows.length === 0) {
        throw new Error(
          'AUDIT_CHAIN_HEAD_MISSING: audit_chain_head has no seed row — has migration 026 been applied?'
        );
      }

      const prevHash = headRes.rows[0].tail_hash;
      const prevSeq  = BigInt(headRes.rows[0].tail_seq); // BIGINT comes back as a string

      // the head carries the schema version of the entry it points at, read under the same row lock that orders
      // the append. A writer that would append a LOWER version (a v7 after a v8) is refused — SCHEMA_DOWNGRADE in every verifier —
      // whichever replica or process wrote the head; non-retryable (the invalid_ prefix), like the single-node writer's refusal.
      const headVersion = Number(headRes.rows[0].tail_schema_version);
      if (!Number.isSafeInteger(headVersion) || headVersion < 0) {
        throw new Error('AUDIT_CHAIN_HEAD_VERSION_INVALID: audit_chain_head.tail_schema_version is not a non-negative integer');
      }
      if (normalized.schemaVersion < headVersion) {
        const e = new Error('invalid_schema_downgrade: the chain head is schema v' + headVersion + ' and this writer would append v' + normalized.schemaVersion + ' (QODIQA_AUDIT_SCHEMA_V8 cannot be switched off once v8 entries exist)');
        e.code = 'AUDIT_SCHEMA_DOWNGRADE_REFUSED';
        throw e;
      }

      const entry = entryBuilder.buildEntry(normalized, prevHash);
      // (design §9/§11): per-field columns through the reversible projection P; canonical / hash / prev_hash verbatim
      const m = projectEntryForMirror(entry);

      await tx.query(`
        INSERT INTO audit_chain (
          hash, prev_hash, canonical,
          artifact_id, decision, recorded_at, high_res_time,
          input_hash, signature, request_hash, policy_hash,
          verification_result, nonce, tenant_id, execution_context,
          public_key_id, schema_version, consent_provenance, policy_decision,
          caller_context, provider, model,
          stage, reason, semantic, token_usage, response_id,
          entry_type, output_hash, request_id, organization_id, executing_provider,
          mirror_encoding,
          issued_at, protocol_version, agent_id, session_id, action_seq, action_hash, approval_ref, dlp, bytes_delivered, completion_status
        ) VALUES (
          $1,  $2,  $3,
          $4,  $5,  $6,  $7,
          $8,  $9,  $10, $11,
          $12, $13, $14, $15,
          $16, $17, $18, $19,
          $20, $21, $22,
          $23, $24, $25, $26, $27,
          $28, $29, $30, $31, $32,
          $33,
          $34, $35, $36, $37, $38, $39, $40, $41, $42, $43
        )
      `, [
        entry.hash, entry.prevHash, entry.canonical,
        m.artifactId, m.decision, new Date(entry.timestamp), m.highResTime,
        m.inputHash, m.signature, m.requestHash, m.policyHash,
        entry.verificationResult, m.nonce ?? null, m.tenantId ?? null,
        m.executionContext ? JSON.stringify(m.executionContext) : null,
        m.publicKeyId ?? null, entry.schemaVersion,
        // TRACE-2: this table is the ordering AUTHORITY in distributed mode —
        // must carry the same fields entryBuilder.js hashed into the entry,
        // see migration 033 and pg-audit-backend.js's matching INSERT.
        m.consentProvenance != null ? JSON.stringify(m.consentProvenance) : null,
        m.policyDecision    != null ? JSON.stringify(m.policyDecision)    : null,
        // same ordering-authority contract as above — see migration 034.
        m.callerContext     != null ? JSON.stringify(m.callerContext)     : null,
        // (migration 039) and (migration 057) added these
        // hash-protected fields to pg-audit-backend.js's INSERT but never here,
        // so every distributed-mode entry carrying them failed re-verification
        // on the next boot (fetchChainBatch/loadChainFromPg read them back as
        // NULL). Same round-trip contract as pg-audit-backend.js's INSERT.
        m.provider ?? null,
        m.model    ?? null,
        m.stage       ?? null,
        m.reason      ?? null,
        m.semantic    != null ? JSON.stringify(m.semantic)    : null,
        m.tokenUsage  != null ? JSON.stringify(m.tokenUsage)  : null,
        m.responseId  ?? null,
        // v7 (migration 075): same ordering-authority contract as pg-audit-backend.js's INSERT.
        m.entryType         ?? null,
        m.outputHash        ?? null,
        m.requestId         ?? null,
        m.organizationId    ?? null,
        m.executingProvider ?? null,
        // (R-F2): projected row marker — same contract as pg-audit-backend.js insertMirrorRow()
        MIRROR_ENCODING_ESCAPED,
        // audit v8 (migration 083): NULL for schema_version < 8
        ...v8InsertValues(m),
      ]);

      await tx.query(
        'UPDATE audit_chain_head SET tail_hash = $1, tail_seq = $2, tail_schema_version = $3',
        [entry.hash, (prevSeq + 1n).toString(), entry.schemaVersion]
      );

      return entry;
    }, { isolationLevel: 'READ COMMITTED' });
  } catch (err) {
    throw _translateConstraintError(err);
  }
}

module.exports = { appendEntry };
