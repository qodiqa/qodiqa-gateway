'use strict';

/**
 * PostgreSQL-backed Audit Chain Persistence
 *
 * Drop-in complement to audit-log.js's file backend.
 * When enabled (QODIQA_PG_ENABLED=true), every audit entry written to the
 * NDJSON file is ALSO written to PostgreSQL inside the same logical operation.
 *
 * The canonical chain state remains the in-memory array loaded from the NDJSON
 * file (for backwards compatibility and performance during chain verification).
 * PostgreSQL is the durable queryable store.
 *
 * SINGLE-INSTANCE CONSTRAINT (enforced by multiInstanceGuard.js at startup):
 *   The chain[] array in audit-log.js is process-local.  Two concurrent QODIQA
 *   processes would derive independent prevHash sequences, producing divergent
 *   chains with no shared ordering authority.  DO NOT run multiple enforcement
 * nodes until (PG-primary with serialized append) is implemented.
 *   See: docs/protocol/AUDIT-SCHEMA-V8.md
 *
 * Migration path:
 * dual-write (file + PG): this module ← CURRENT
 * PG primary: chain loaded from PG on startup, file is backup
 *     Requires: distributed ordering authority (PG advisory lock or sequence
 *     reservation), serialized append protocol, new startup chain hydration.
 * PG only: file deprecated
 *
 * PUBLIC INTERFACE (mirrors audit-log.js exports):
 *   persistEntry(entry)         — write to PG; non-blocking, best-effort
 *   setKeyInfoResolver(fn)      — inject the verification-key lookup used to
 *                                 enrich auto-generated evidence records.
 *                                 Infrastructure must not import Services
 *                                 (keyManager.js) directly — wired once by
 *                                 src/core/audit/audit-log.js at module load.
 *   loadChainFromPg()           — load all entries sorted by seq for startup
 *   getChainTail()              — true global last-inserted row (hash+seq),
 *                                 RLS-bypassed via migration 043; used by
 *                                 audit-log.js's single-node startup
 *                                 hydration (FINDING-AUDIT-CHAIN-TENANT-
 *                                 GENESIS-COLLISION)
 *   queryByArtifactId(id)       — lookup single entry
 *   queryByTenant(tenantId)     — tenant-scoped chain
 * aggregateUsageByTenantPg(tenantId, range) — per-day usage totals (SQL twin
 *                                 of src/core/usage/usageAggregation.js's reducer)
 */

const pgPool = require('./pool');
const rolePools = require('./rolePools'); // cross-tenant DEFINER reads run as qodiqa_system / qodiqa_reporting
const { emit } = require('../../../services/logger');
const { isPersistenceFailure } = require('../../core/persistenceRecovery/persistenceOperation');
const chainStore = require('../../core/evidence/chainStore');
const { setLocal } = require('./tenantContext');
const { orderByHashLinks } = require('../../utils/hashLinkOrder');
const { v8InsertValues } = require('./v8Columns');
const { projectEntryForMirror, decodeMirrorRow, encodeString: mirrorEncode, decodeString, encodingOf, MIRROR_ENCODING_ESCAPED } = require('./mirrorProjection'); //

// Verification-key resolver for evidence-record enrichment (fingerprint,
// version) — injected rather than required directly, because the concrete
// implementation (services/artifact/keyManager.js) lives in the Services
// layer and Infrastructure must never import Services. Wired once, at
// module load, by src/core/audit/audit-log.js (Core, the only caller of
// persistEntry() and a module already permitted to depend on both this
// module and keyManager). Defaults to a no-op resolver so persistEntry()
// degrades to keyInfo: null (identical to a failed lookup) if nothing wires
// a resolver in — e.g. in isolated unit tests of this module.
let _keyInfoResolver = async () => null;
function setKeyInfoResolver(fn) {
  _keyInfoResolver = fn;
}

// ── Write ─────────────────────────────────────────────────────────────────────

// ── guarded mirror INSERT — seq order = hash-chain order ─────────
//
// A mirror row is inserted only once its parent (prev_hash) is committed, or
// when it is the GENESIS entry. With UNIQUE(prev_hash) (migration 026) the
// chain is linear, so "every child after its parent" makes seq order equal to
// chain order for EVERY writer — the serialized live writer (audit-log.js),
// recovery-queue replays and backfill — under any concurrency or replay order.
// Check-then-insert in one transaction is race-free here: audit_chain is
// append-only, so a parent visible at the check is still there at the INSERT,
// and it committed (drawing its seq) before this INSERT draws its own. The
// checks go through migration 058's narrow SECURITY DEFINER function because
// audit_chain's SELECT is tenant-scoped by RLS and a parent may belong to
// another tenant. A missing parent throws AUDIT_MIRROR_PARENT_MISSING, which
// is retryable (persistenceOperation.js), so the row waits in the recovery
// queue instead of being committed out of order.
const AUDIT_MIRROR_PARENT_MISSING = 'AUDIT_MIRROR_PARENT_MISSING';

// _guardQuery: injectable for tests that simulate an earlier writer (default: the
// qodiqa_system pool). Production callers never pass it.
async function insertMirrorRow(tx, entry, { label, _guardQuery = (sql, params) => rolePools.system.query(sql, params, 'audit_mirror_guard') } = {}) {
  if (entry.tenantId) {
    await setLocal(tx, entry.tenantId);
  }
  // the cross-tenant existence check runs as qodiqa_system — the
  // app role no longer holds EXECUTE on qodiqa_audit_chain_hash_exists. The
  // ordering argument above is unchanged: audit_chain is append-only, so a
  // parent that is committed and visible to this read is still committed when
  // the INSERT below draws its seq.
  const guard = await _guardQuery(
    "SELECT ($1::text = 'GENESIS' OR qodiqa_audit_chain_hash_exists($1::text)) AS parent_ok, qodiqa_audit_chain_hash_exists($2::text) AS self_exists",
    [entry.prevHash, entry.hash],
  );
  const { parent_ok: parentOk, self_exists: selfExists } = guard.rows[0] || {};
  if (selfExists) return { inserted: false, alreadyPresent: true };
  if (!parentOk) {
    const err = new Error(`${AUDIT_MIRROR_PARENT_MISSING}: parent ${entry.prevHash} of ${entry.hash} is not in audit_chain yet`);
    err.code = AUDIT_MIRROR_PARENT_MISSING;
    throw err;
  }
  await _insertMirrorRowUnguarded(tx, entry, label);
  return { inserted: true, alreadyPresent: false };
}

// phase 9: the mirror INSERT itself, shared by the guarded single-row path and the batched path.
async function _insertMirrorRowUnguarded(tx, entry, label) {
  // (R-F2, design §9/§11): every per-field column is written through the reversible projection P;
  // canonical / hash / prev_hash stay verbatim (the hashed bytes are never projected).
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
    ON CONFLICT (hash) DO NOTHING
  `, [
    entry.hash,
    entry.prevHash,
    entry.canonical,
    m.artifactId,
    m.decision,
    new Date(entry.timestamp),
    m.highResTime,
    m.inputHash,
    m.signature,
    m.requestHash,
    m.policyHash,
    entry.verificationResult,
    m.nonce        ?? null,
    m.tenantId     ?? null,
    m.executionContext ? JSON.stringify(m.executionContext) : null,
    m.publicKeyId  ?? null,
    entry.schemaVersion ?? 1,
    // TRACE-2: must round-trip through PG unchanged so hydration/lookup
    // (loadChainFromPg, queryByArtifactId, fetchChainBatch below) and
    // distributed-mode reads reconstruct the same entry shape entryBuilder
    // built and hashed — see migration 033.
    m.consentProvenance != null ? JSON.stringify(m.consentProvenance) : null,
    m.policyDecision    != null ? JSON.stringify(m.policyDecision)    : null,
    // same round-trip contract as above — see migration 034.
    m.callerContext     != null ? JSON.stringify(m.callerContext)     : null,
    // same round-trip contract as above — see migration 039.
    m.provider ?? null,
    m.model    ?? null,
    // same round-trip contract as above — see migration 057.
    m.stage       ?? null,
    m.reason      ?? null,
    m.semantic    != null ? JSON.stringify(m.semantic)    : null,
    m.tokenUsage  != null ? JSON.stringify(m.tokenUsage)  : null,
    m.responseId  ?? null,
    // v7 (migration 075): same round-trip contract as above; NULL for schema_version < 7.
    m.entryType         ?? null,
    m.outputHash        ?? null,
    m.requestId         ?? null,
    m.organizationId    ?? null,
    m.executingProvider ?? null,
    // (R-F2): every row written after the change carries the projection marker
    MIRROR_ENCODING_ESCAPED,
    // audit v8 (migration 083): NULL for schema_version < 8
    ...v8InsertValues(m),
  ], ...(label ? [label] : []));
}

/**
 * Persist one audit chain entry to PostgreSQL.
 * Called from audit-log.js append() after the file write succeeds.
 * Non-blocking: PG write failure never fails the original append() — the
 * file-based chain is the authoritative MANDATORY store. However,
 * a retryable failure (connection drop, pool exhaustion, etc.) is durably
 * queued via the Persistence Recovery Queue rather than just logged and
 * dropped, so the PG copy and the evidence chain record it triggers are
 * eventually consistent instead of silently and permanently missing.
 *
 * @param {object} entry — frozen audit chain entry from audit-log.js
 */
async function persistEntry(entry) {
  if (!pgPool.isEnabled()) return;

  try {
    // FINDING-PG-TENANT-CONTEXT-WRITE-PATH: ON CONFLICT (even DO NOTHING)
    // requires evaluating the SELECT RLS policy against the conflict target,
    // same mechanism as registrar.js's RETURNING. This row carries
    // entry.tenantId; without matching qodiqa.tenant_id session context, a
    // non-null-tenant row fails that check and the INSERT errors as an RLS
    // violation. No chain-head lookup happens in this function (prevHash
    // comes from the caller's in-memory chain — see module header), so
    // there is no analogous global-visibility concern to preserve here.
    await pgPool.withTransaction((tx) => insertMirrorRow(tx, entry), { isolationLevel: 'READ COMMITTED' });
  } catch (e) {
    // O9: first N per window in full, the rest counted (src/observability/aggregatedEmit.js failureEmit)
    require('../../observability/aggregatedEmit').failureEmit(emit, 'ERROR', 'PG_AUDIT_PERSIST_FAILED', {
      artifactId: entry.artifactId,
      error:      e.message,
      code:       e.code ?? null,
    });
    if (isPersistenceFailure(e)) {
      const { enqueue, OPERATION_TYPES } = require('../../core/persistenceRecovery');
      const metrics = require('../../observability/metrics');
      metrics.auditPgRecoveryQueuedTotal.inc({ operationType: OPERATION_TYPES.AUDIT_CHAIN_PG_SAVE });
      // enqueue() is documented to never throw (recoveryManager.js), but this
      // dual-write must never disrupt the caller under any circumstance, so
      // guard defensively anyway rather than relying solely on that contract.
      await enqueue(OPERATION_TYPES.AUDIT_CHAIN_PG_SAVE, entry, e).catch(() => {});
    }
    // Non-retryable errors (constraint/data/auth issues) are logged above and
    // intentionally not queued — retrying a deterministic failure forever
    // would just occupy the DLQ with something that can never succeed.
  }

  await recordEvidenceForEntry(entry);
}

/**
 * phase 9: batched single-node mirror write. The live writer (audit-log.js) hands over up to
 * QODIQA_AUDIT_MIRROR_BATCH consecutive entries in chain order. One guard query (the first entry's parent is committed,
 * and which entries are already present), ONE transaction for all mirror INSERTs (each still parent-ordered: the
 * batch is a contiguous chain segment, inserted in order, so seq order = chain order exactly as before), then ONE
 * evidence-chain transaction for the batch. Measured on the disposable container this removes the per-entry commit
 * pair that capped the mirror at ~125 entries/s.
 *
 * Any failure — a non-contiguous batch, a missing parent, any SQL error — falls back to the unchanged per-entry
 * persistEntry() for every entry of the batch, so the recovery-queue / DLQ behaviour is exactly the per-entry one.
 * Never throws.
 *
 * @param {object[]} entries — frozen, committed audit chain entries, in chain order
 */
async function persistEntries(entries) {
  if (!pgPool.isEnabled() || !Array.isArray(entries) || entries.length === 0) return;
  // Tenant context is transaction-local and cannot be cleared once set (tenantContext.setLocal), so a transaction only
  // ever carries entries of ONE tenant (or none) — exactly the context each per-entry transaction had. A batch is
  // therefore written as consecutive same-tenant runs, in chain order.
  let run = [];
  for (const entry of entries) {
    if (run.length && (run[0].tenantId ?? null) !== (entry.tenantId ?? null)) { await _persistRun(run); run = []; }
    run.push(entry);
  }
  if (run.length) await _persistRun(run);
}

async function _persistRun(entries) {
  if (entries.length === 1) { await persistEntry(entries[0]); return; }
  const contiguous = entries.every((e, i) => i === 0 || e.prevHash === entries[i - 1].hash);
  let mirrored = false;
  if (contiguous) {
    try {
      const guard = await rolePools.system.query(
        "SELECT ($1::text = 'GENESIS' OR qodiqa_audit_chain_hash_exists($1::text)) AS parent_ok, " +
        'ARRAY(SELECT h FROM unnest($2::text[]) AS h WHERE qodiqa_audit_chain_hash_exists(h)) AS present',
        [entries[0].prevHash, entries.map((e) => e.hash)], 'audit_mirror_guard_batch');
      const { parent_ok: parentOk, present } = guard.rows[0] || {};
      if (parentOk) {
        const already = new Set(present || []);
        const tenantId = entries[0].tenantId;
        await pgPool.withTransaction(async (tx) => {
          if (tenantId) await setLocal(tx, tenantId);
          for (const entry of entries) {
            if (!already.has(entry.hash)) await _insertMirrorRowUnguarded(tx, entry);
          }
        }, { isolationLevel: 'READ COMMITTED' });
        mirrored = true;
      }
    } catch { /* fall back to the per-entry path below, which reports and queues each failure */ }
  }
  if (!mirrored) {
    for (const entry of entries) await persistEntry(entry);
    return;
  }
  await recordEvidenceForEntries(entries);
}

/** Batched evidence step; on any failure, the unchanged per-entry recordEvidenceForEntry() for each entry. */
async function recordEvidenceForEntries(entries) {
  try {
    const items = [];
    for (const entry of entries) {
      let keyInfo = null;
      const keyId = entry.publicKeyId ?? entry.executionContext?.publicKeyId ?? null;
      if (keyId) { try { keyInfo = await _keyInfoResolver(keyId); } catch { /* evidence without fingerprint, as per entry */ } }
      items.push({ auditEntry: entry, keyInfo });
    }
    await chainStore._recordEvidenceBatchOrThrow(items, null);
  } catch {
    for (const entry of entries) await recordEvidenceForEntry(entry);
  }
}

/**
 * Evidence-chain step for one committed audit entry (Component #21).
 * Called by persistEntry() in single-node mode, and — (owner
 * option A1) — by audit-log.js after a distributed-mode append has committed.
 * Always post-commit and best-effort: it never throws, never affects the
 * audit write that triggered it, and a retryable failure is durably queued as
 * EVIDENCE_CHAIN_SAVE (the idempotent writer is replayed by the recovery
 * worker). a non-retryable failure is queued too, instead of only
 * logged — the worker makes one replay attempt and, if that also fails
 * non-retryably, moves it straight to the DLQ (worker.js), where it is
 * visible (qodiqa_prq_dlq_depth + QUEUE_BACKLOG alert) and replayable once
 * the cause is fixed. No committed audit entry is left without either an
 * evidence row or a durable queue/DLQ record.
 *
 * @param {object} entry — frozen, committed audit chain entry
 */
async function recordEvidenceForEntry(entry) {
  if (!pgPool.isEnabled()) return;

  // Auto-generate evidence chain record (Component #21).
  //
  // Calls the throwing variant (_recordEvidenceFromAuditEntryOrThrow) directly
  // rather than the public recordEvidenceFromAuditEntry() — that function
  // intentionally swallows its own errors for its other fire-and-forget
  // callers, which would make a .catch() here dead code. This call site needs
  // the real exception so a retryable failure can be durably queued instead
  // of just logged and dropped.
  // Declared outside the try block so the catch below can include it in the
  // recovery-queue payload (a retry needs the same keyInfo the first attempt used).
  let keyInfo = null;
  try {
    // Key info lookup: best-effort, null if the key is not available.
    // Prefer the new hash-protected top-level field; fall back to the
    // legacy unprotected executionContext copy for pre-remediation entries.
    const keyId = entry.publicKeyId ?? entry.executionContext?.publicKeyId ?? null;
    if (keyId) {
      try {
        keyInfo = await _keyInfoResolver(keyId);
      } catch { /* key not available — evidence record will be created without fingerprint */ }
    }
    await chainStore._recordEvidenceFromAuditEntryOrThrow(entry, keyInfo, null);
  } catch (evErr) {
    const metrics = require('../../observability/metrics');
    metrics.evidenceChainPersistFailuresTotal.inc({});
    // O9: first N per window in full, the rest counted (src/observability/aggregatedEmit.js failureEmit)
    require('../../observability/aggregatedEmit').failureEmit(emit, 'ERROR', 'EVIDENCE_CHAIN_PERSIST_FAILED', {
      artifactId: entry.artifactId,
      error:      evErr.message,
      code:       evErr.code ?? null,
    });
    {
      const { enqueue, OPERATION_TYPES } = require('../../core/persistenceRecovery');
      metrics.auditPgRecoveryQueuedTotal.inc({ operationType: OPERATION_TYPES.EVIDENCE_CHAIN_SAVE });
      if (!isPersistenceFailure(evErr)) {
        emit('WARN', 'EVIDENCE_CHAIN_NON_RETRYABLE_QUEUED', {
          artifactId: entry.artifactId,
          error:      evErr.message,
          code:       evErr.code ?? null,
        });
      }
      await enqueue(OPERATION_TYPES.EVIDENCE_CHAIN_SAVE, { auditEntry: entry, keyInfo, opts: null }, evErr).catch(() => {
        /* enqueue() itself never throws (see recoveryManager.js) — defensive only */
      });
    }
    // evidence chain must never disrupt the audit write path this function
    // is called from — always resolve, never propagate.
  }
}

// ── Read ──────────────────────────────────────────────────────────────────────

/**
 * Load the entire audit chain from PostgreSQL, ordered by seq.
 * Used during+ startup to hydrate the in-memory chain.
 * Returns entries in the same shape as the NDJSON file (camelCase fields).
 */
async function loadChainFromPg() {
  if (!pgPool.isEnabled()) return [];

  // `timestamp` is deliberately NOT selected via `recorded_at::text`: a
  // TIMESTAMPTZ round-trips through Postgres's text cast in a different
  // format than the original ISO-8601
  // string that was actually hashed at write time (e.g.
  // "2026-07-17T12:34:56.789Z"). Reconstructing coreFields with that
  // reformatted value would no longer match the stored `canonical` string,
  // and audit-log.js's chain-walk would report every hydrated entry as
  // tampered. `timestamp` is derived from the stored `canonical` JSON below
  // instead — the exact string that produced `hash` — which round-trips
  // byte-for-byte regardless of how Postgres formats the column.
  const result = await rolePools.system.query(`
    SELECT
      hash, prev_hash AS "prevHash", canonical,
      artifact_id AS "artifactId", decision,
      high_res_time AS "highResTime",
      input_hash AS "inputHash",
      signature,
      request_hash AS "requestHash",
      policy_hash AS "policyHash",
      verification_result AS "verificationResult",
      nonce, tenant_id AS "tenantId",
      execution_context AS "executionContext",
      public_key_id AS "publicKeyId",
      schema_version AS "schemaVersion",
      consent_provenance AS "consentProvenance",
      policy_decision AS "policyDecision",
      caller_context AS "callerContext",
      provider, model,
      stage, reason, semantic,
      token_usage AS "tokenUsage",
      response_id AS "responseId",
      entry_type AS "entryType",
      output_hash AS "outputHash",
      request_id AS "requestId",
      organization_id AS "organizationId",
      executing_provider AS "executingProvider",
      issued_at AS "issuedAt", protocol_version AS "protocolVersion", agent_id AS "agentId", session_id AS "sessionId",
      action_seq AS "actionSeq", action_hash AS "actionHash", approval_ref AS "approvalRef", dlp,
      bytes_delivered AS "bytesDelivered", completion_status AS "completionStatus",
      mirror_encoding AS "mirrorEncoding"
    FROM qodiqa_audit_chain_full_read()
    ORDER BY seq ASC
  `, [], 'audit_load_chain');

  const mapped = result.rows.map(r0 => {
    // (R-F4): decode at the PostgreSQL → entry boundary, before any verification sees the row
    const r = decodeMirrorRow(r0, `audit_chain row ${r0.hash}`);
    let timestamp = null;
    try { timestamp = JSON.parse(r.canonical).timestamp ?? null; } catch { /* falls through to _validateChainEntry's invalid_field check */ }

    return {
      ...r,
      timestamp,
      executionContext: r.executionContext ?? undefined,
      tenantId:        r.tenantId         ?? undefined,
      nonce:           r.nonce            ?? undefined,
      // TRACE-2: unlike executionContext/tenantId/nonce above, these stay
      // `null` (not `undefined`) when absent — entryBuilder.buildEntry()
      // always sets them (possibly null) as own properties on every entry,
      // so hydrated entries must match that shape exactly.
      consentProvenance: r.consentProvenance ?? null,
      policyDecision:     r.policyDecision    ?? null,
      // same always-present-possibly-null contract as above.
      callerContext:      r.callerContext     ?? null,
      // same always-present-possibly-null contract as above.
      provider:           r.provider ?? null,
      model:              r.model    ?? null,
      // same always-present-possibly-null contract as above.
      stage:              r.stage       ?? null,
      reason:             r.reason      ?? null,
      semantic:           r.semantic    ?? null,
      tokenUsage:         r.tokenUsage  ?? null,
      responseId:         r.responseId  ?? null,
      // v7 (migration 075): same always-present-possibly-null contract — needed for schemaVersion 7 entries'
      // coreFieldsOf()/verifyCanonicalHash() and the lifecycle rules (entryType/requestId/executingProvider).
      entryType:          r.entryType         ?? null,
      outputHash:         r.outputHash        ?? null,
      requestId:          r.requestId         ?? null,
      organizationId:     r.organizationId    ?? null,
      executingProvider:  r.executingProvider ?? null,
    };
  });

  // return rows in HASH-LINK order, not seq order. A single-node
  // mirror written can carry seq inversions (a child committed
  // before its parent) on a chain whose hashes all verify; every consumer of
  // this function (distributed hydration, the verifier's full path, the DR
  // probe) walks the array positionally. All-or-nothing: if the rows do not
  // form one linear chain from GENESIS they are returned in seq order
  // unchanged, so a real break is still reported exactly as before.
  const linked = orderByHashLinks(mapped);
  if (linked.reordered > 0) {
    emit('WARN', 'AUDIT_CHAIN_SEQ_INVERSIONS_PRESENT', {
      rows: mapped.length, reordered: linked.reordered,
      action: 'Historical seq inversions in audit_chain (earlier single-node mirror). Reads follow hash links; re-sequence with scripts/audit-mirror-rebuild.js before switching to distributed mode.',
    });
  }
  return linked.rows;
}

/**
 * loadChainFromPg()'s rows, for the file-vs-PG divergence check, without materializing the
 * whole chain at once: the IDENTICAL query (same SECURITY DEFINER full-read function, same ORDER BY seq) streamed
 * through a server-side cursor inside ONE read-only REPEATABLE READ transaction, so the result is exactly the one
 * snapshot the single query would have seen — duplicate seqs included, which keyset paging on `seq >` would not
 * reproduce. Each page is reduced by `compact(row)` (the caller keeps only what it compares) and handed to
 * `onPage(compactRows)`, which may be async (it yields to the event loop between pages). The compacted rows are
 * then put in the same hash-link order loadChainFromPg() returns (orderByHashLinks uses only hash/prevHash), with
 * the same AUDIT_CHAIN_SEQ_INVERSIONS_PRESENT warning.
 *
 * @param {(row: object) => object} compact
 * @param {{ pageSize?: number, onPage?: (rows: object[]) => Promise<void>|void }} [opts]
 * @returns {Promise<object[]>} compacted rows in loadChainFromPg() order
 */
// M3: fromSeqExclusive / start — after a prune the comparison starts at the signed base record (rows with
// seq > its pgSeq, linked from its headHash); omitted, every row from GENESIS exactly as before.
function _seqFilter(fromSeqExclusive) {
  if (fromSeqExclusive === null || fromSeqExclusive === undefined) return '';
  if (!Number.isInteger(fromSeqExclusive) || fromSeqExclusive < 0) throw new TypeError('fromSeqExclusive must be a non-negative integer');
  return `WHERE seq > ${fromSeqExclusive}`;   // DECLARE takes no bind parameters; validated integer
}

// (R-F4, narrow S3 change): the compact readers carry exactly one per-field column, artifact_id; it is decoded
// here, at the PG → entry boundary, so ChainVerifier's divergence compare sees original values on both sides.
function _decodeCompactRow(row) {
  const { mirrorEncoding, ...rest } = row;
  if (encodingOf(mirrorEncoding, `audit_chain row ${row.hash}`) === MIRROR_ENCODING_ESCAPED && typeof rest.artifactId === 'string') {
    rest.artifactId = decodeString(rest.artifactId, `audit_chain row ${row.hash}.artifactId`);
  }
  return rest;
}

async function loadChainFromPgCompact(compact, { pageSize = 2000, onPage, fromSeqExclusive = null, start = 'GENESIS' } = {}) {
  if (!pgPool.isEnabled()) return [];
  const where = _seqFilter(fromSeqExclusive);
  const mapped = [];
  await rolePools.system.withReadOnlySnapshot(async (systemSnapshotTx) => {
    await systemSnapshotTx.query(`
      DECLARE w9_chain_compact NO SCROLL CURSOR FOR
      SELECT hash, prev_hash AS "prevHash", canonical, artifact_id AS "artifactId", mirror_encoding AS "mirrorEncoding"
      FROM qodiqa_audit_chain_full_read()
      ${where}
      ORDER BY seq ASC
    `);
    for (;;) {
      const r = await systemSnapshotTx.query(`FETCH ${Number(pageSize) | 0 || 2000} FROM w9_chain_compact`);
      if (r.rows.length === 0) break;
      const page = r.rows.map((row) => compact(_decodeCompactRow(row)));   // decode before the divergence compare
      for (const row of page) mapped.push(row);
      if (onPage) await onPage(page);
    }
  }, 'audit_load_chain_compact');

  const linked = orderByHashLinks(mapped, { start });
  if (linked.reordered > 0) {
    emit('WARN', 'AUDIT_CHAIN_SEQ_INVERSIONS_PRESENT', {
      rows: mapped.length, reordered: linked.reordered,
      action: 'Historical seq inversions in audit_chain (earlier single-node mirror). Reads follow hash links; re-sequence with scripts/audit-mirror-rebuild.js before switching to distributed mode.',
    });
  }
  return linked.rows;
}

/**
 * (VERIFIER-DESIGN.md, owner amendment 6) — the PG side of the bounded-memory divergence merge: the SAME query
 * and ONE read-only REPEATABLE READ snapshot as loadChainFromPgCompact(), but each compacted page (seq order) is
 * handed to `onPage(rows)` and NOT kept. onPage may be async and may return false to stop early.
 * @returns {Promise<number>} rows delivered
 */
async function forEachChainPageCompactInSnapshot(compact, { pageSize = 2000, onPage, fromSeqExclusive = null }) {
  if (!pgPool.isEnabled()) return 0;
  const where = _seqFilter(fromSeqExclusive);   // M3 (see loadChainFromPgCompact)
  let delivered = 0;
  await rolePools.system.withReadOnlySnapshot(async (systemSnapshotTx) => {
    await systemSnapshotTx.query(`
      DECLARE w10_chain_pages NO SCROLL CURSOR FOR
      SELECT hash, prev_hash AS "prevHash", canonical, artifact_id AS "artifactId", mirror_encoding AS "mirrorEncoding"
      FROM qodiqa_audit_chain_full_read()
      ${where}
      ORDER BY seq ASC
    `);
    for (;;) {
      const r = await systemSnapshotTx.query(`FETCH ${Number(pageSize) | 0 || 2000} FROM w10_chain_pages`);
      if (r.rows.length === 0) break;
      delivered += r.rows.length;
      if ((await onPage(r.rows.map((row) => compact(_decodeCompactRow(row))))) === false) break;   //
    }
  }, 'audit_chain_divergence_pages');
  return delivered;
}

/**
 * Look up a single audit chain entry by artifactId.
 * Returns null if not found.
 *
 * routed through qodiqa_audit_chain_fetch_by_artifact_id() (migration
 * 048), a SECURITY DEFINER function bypassing audit_chain's per-tenant RLS —
 * a plain query here would only ever see the calling session's own tenant
 * (or NULL-tenant) rows, the same defect class found live in
 * validateChainLinks(). This lookup is inherently global by design (an
 * artifactId is unique across the whole chain, not scoped to a tenant).
 */
async function queryByArtifactId(artifactId) {
  if (!pgPool.isEnabled()) return null;
  // rows written since the projection store P(artifactId); a native (legacy, mirror_encoding 0) row stores the
  // raw id. P is injective and the identity on printable ASCII without \ and ", so for every id the system generates
  // (UUIDs, their :intent / :stream_opened suffixes, sha256 hex) both forms are the same single lookup.
  const keys = typeof artifactId === 'string' ? [...new Set([mirrorEncode(artifactId), artifactId])] : [artifactId];
  for (const key of keys) {
    const row = await _queryByStoredArtifactId(key);
    if (row && (key === mirrorEncode(artifactId) ? row.mirrorEncoding === 1 || key === artifactId : row.mirrorEncoding !== 1)) {
      return _entryFromArtifactRow(decodeMirrorRow(row, `audit_chain row ${row.hash}`));
    }
  }
  return null;
}

async function _queryByStoredArtifactId(storedArtifactId) {
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
      provider, model,
      stage, reason, semantic,
      token_usage AS "tokenUsage",
      response_id AS "responseId",
      entry_type AS "entryType",
      output_hash AS "outputHash",
      request_id AS "requestId",
      organization_id AS "organizationId",
      executing_provider AS "executingProvider",
      issued_at AS "issuedAt", protocol_version AS "protocolVersion", agent_id AS "agentId", session_id AS "sessionId",
      action_seq AS "actionSeq", action_hash AS "actionHash", approval_ref AS "approvalRef", dlp,
      bytes_delivered AS "bytesDelivered", completion_status AS "completionStatus",
      mirror_encoding AS "mirrorEncoding"
    FROM qodiqa_audit_chain_fetch_by_artifact_id($1)
  `, [storedArtifactId], 'audit_by_artifact');
  return result.rows[0] ?? null;
}

function _entryFromArtifactRow(row) {
  // Normalize absence to null, matching entryBuilder.buildEntry()'s
  // shape — callers (chainStore.verifyEvidence, generator.js) read these as
  // always-present-possibly-null fields.
  return {
    ...row,
    consentProvenance: row.consentProvenance ?? null,
    policyDecision:    row.policyDecision    ?? null,
    callerContext:     row.callerContext     ?? null,
    provider:          row.provider          ?? null,
    model:             row.model             ?? null,
    stage:             row.stage             ?? null,
    reason:            row.reason            ?? null,
    semantic:          row.semantic          ?? null,
    tokenUsage:        row.tokenUsage        ?? null,
    responseId:        row.responseId        ?? null,
    entryType:         row.entryType         ?? null,
    outputHash:        row.outputHash        ?? null,
    requestId:         row.requestId         ?? null,
    organizationId:    row.organizationId    ?? null,
    executingProvider: row.executingProvider ?? null,
  };
}

/**
 * Fetch audit entries for a specific tenant, newest first.
 * Respects tenant isolation strictly.
 */
async function queryByTenant(tenantId, { limit = 1000, offset = 0 } = {}) {
  if (!pgPool.isEnabled()) return [];

  // (the register's own named example): a plain query never set
  // qodiqa.tenant_id, so ac_tenant_select's RLS predicate (tenant_id IS NULL
  // OR tenant_id = qodiqa_current_tenant()) silently restricted this to
  // platform-level rows only -- combined with the WHERE tenant_id = $1
  // filter (a real, non-null tenantId), the result was always empty.
  const sql = `
    SELECT
      hash, artifact_id AS "artifactId", decision,
      recorded_at AS timestamp,
      policy_hash AS "policyHash",
      verification_result AS "verificationResult",
      execution_context AS "executionContext",
      mirror_encoding AS "mirrorEncoding"
    FROM audit_chain
    WHERE tenant_id = $1
    ORDER BY seq DESC
    LIMIT $2 OFFSET $3
  `;
  // withTenantTransaction() validates tenantId against /^[A-Za-z0-9_-]{1,64}$/ (tenantContext.js) before the
  // query runs, so P(tenantId) === tenantId and the stored-value filter is exact for projected and native rows alike.
  const result = await pgPool.withTenantTransaction(
    tenantId, (tx) => tx.query(sql, [tenantId, limit, offset]),
  );

  return result.rows.map((r) => decodeMirrorRow(r, `audit_chain row ${r.hash}`));
}

/**
 * Action 1 (SQL twin) — per-tenant, per-UTC-day usage aggregation.
 *
 * States the SAME metering rules src/core/usage/usageAggregation.js states
 * in JS (see that module's header for the full normative definition):
 *   - metered = execution_context HAS the 'tokenUsage' key (jsonb `?`
 *     existence check — true even when the value is JSON null, matching
 *     isMeteredEntry()'s hasOwnProperty check exactly);
 *   - a component (`inputTokens`/`outputTokens`/`totalTokens`) is used only
 *     when present and >= 0, mirroring _tokenIntOrNull();
 *   - effective per-row total: the recorded totalTokens when present,
 *     otherwise the component sum when at least one component exists,
 *     otherwise NULL — reduceUsage()'s exact derivation rule;
 *   - day bucket: the UTC calendar date of recorded_at (a timestamptz, so
 *     already an absolute instant — AT TIME ZONE 'UTC' reads its UTC
 *     wall-clock date, matching new Date(ts).toISOString().slice(0,10));
 *   - artifactId idempotency needs no defensive dedup here (unlike the JS
 *     reducer's defensive Set) — migration 001's idx_audit_chain_artifact_id
 *     UNIQUE constraint already makes a duplicate artifact_id impossible at
 *     the PG level (see usageAggregation.js's header and UM-4 in
 *     test/integration/usageMeteringPg.integration.test.js).
 *
 * Returns rows shaped for mergePgDailyRows() (usageAggregation.js): one row
 * per UTC day with at least one metered execution, ascending by day, every
 * count as a string (node-pg's default BIGINT/NUMERIC representation) so no
 * value is ever silently rounded through a JS double — mirrored exactly by
 * test/integration/usageMeteringPg.integration.test.js's cross-check against the JS
 * reducer on identical fixture data.
 *
 * Tenant-scoped via pool.withTenantTransaction() — same RLS mechanism as
 * queryByTenant() above (ac_tenant_select), never a plain query.
 *
 * @param {string} tenantId
 * @param {{fromIso: string, toIso: string}} range — half-open [fromIso, toIso)
 * @returns {Promise<Array<{day: string, executions: string, inputTokens: string, outputTokens: string, totalTokens: string}>>}
 */
async function aggregateUsageByTenantPg(tenantId, { fromIso, toIso }) {
  if (!pgPool.isEnabled()) return [];

  const sql = `
    WITH metered AS (
      SELECT
        to_char(recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
        NULLIF(execution_context->'tokenUsage'->>'inputTokens',  '')::numeric AS input_raw,
        NULLIF(execution_context->'tokenUsage'->>'outputTokens', '')::numeric AS output_raw,
        NULLIF(execution_context->'tokenUsage'->>'totalTokens',  '')::numeric AS total_raw
      FROM audit_chain
      WHERE tenant_id = $1
        AND execution_context ? 'tokenUsage'
        AND recorded_at >= $2::timestamptz
        AND recorded_at <  $3::timestamptz
    ),
    normalized AS (
      SELECT
        day,
        CASE WHEN input_raw  IS NOT NULL AND input_raw  >= 0 THEN input_raw  ELSE NULL END AS input_tokens,
        CASE WHEN output_raw IS NOT NULL AND output_raw >= 0 THEN output_raw ELSE NULL END AS output_tokens,
        CASE WHEN total_raw  IS NOT NULL AND total_raw  >= 0 THEN total_raw  ELSE NULL END AS total_tokens_raw
      FROM metered
    ),
    effective AS (
      SELECT
        day, input_tokens, output_tokens,
        CASE
          WHEN total_tokens_raw IS NOT NULL THEN total_tokens_raw
          WHEN input_tokens IS NULL AND output_tokens IS NULL THEN NULL
          ELSE COALESCE(input_tokens, 0) + COALESCE(output_tokens, 0)
        END AS effective_total
      FROM normalized
    )
    SELECT
      day,
      COUNT(*)::text                          AS executions,
      COALESCE(SUM(input_tokens), 0)::text     AS "inputTokens",
      COALESCE(SUM(output_tokens), 0)::text    AS "outputTokens",
      COALESCE(SUM(effective_total), 0)::text  AS "totalTokens"
    FROM effective
    GROUP BY day
    ORDER BY day ASC
  `;
  const result = await pgPool.withTenantTransaction(
    tenantId, (tx) => tx.query(sql, [tenantId, fromIso, toIso]),
  );
  return result.rows;
}

/**
 * Get replay entries for a given original artifactId.
 * Equivalent to getReplayLineage() in audit-log.js but via SQL.
 *
 * routed through qodiqa_audit_chain_fetch_replay_lineage() (migration
 * 048) — same RLS rationale as queryByArtifactId() above. Replay detection
 * must see every entry referencing an artifactId regardless of which tenant
 * wrote it; a plain RLS-scoped query would silently miss tenant-scoped
 * replays.
 */
async function queryReplayLineage(artifactId) {
  if (!pgPool.isEnabled()) return [];

  const result = await rolePools.reporting.query(`
    SELECT
      hash, artifact_id AS "artifactId", decision,
      recorded_at AS timestamp,
      execution_context AS "executionContext",
      tenant_id AS "tenantId",
      mirror_encoding AS "mirrorEncoding"
    FROM qodiqa_audit_chain_fetch_replay_lineage($1)
  `, [mirrorEncode(artifactId)], 'audit_replay_lineage');
  // projected rows hold P(replayOf) inside execution_context; a native row holds the raw id. Both forms are
  // looked up (one query when they coincide, i.e. for every system-generated id) and each row is decoded by its marker.
  let rows = result.rows.filter((r) => r.mirrorEncoding === 1);
  if (mirrorEncode(artifactId) === artifactId) rows = result.rows;
  else {
    const native = await rolePools.reporting.query(`
      SELECT hash, artifact_id AS "artifactId", decision, recorded_at AS timestamp,
             execution_context AS "executionContext", tenant_id AS "tenantId", mirror_encoding AS "mirrorEncoding"
      FROM qodiqa_audit_chain_fetch_replay_lineage($1)
    `, [artifactId], 'audit_replay_lineage_native');
    rows = rows.concat(native.rows.filter((r) => r.mirrorEncoding !== 1));
  }
  return rows.map((r) => decodeMirrorRow(r, `audit_chain row ${r.hash}`));
}

/**
 * True global last-inserted row of audit_chain (hash + seq), regardless of
 * which tenant wrote it. Used only by audit-log.js's single-node startup
 * hydration (FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION) to determine the
 * correct prevHash for a fresh process instead of unconditionally assuming
 * 'GENESIS'. Deliberately NOT a plain `SELECT ... ORDER BY seq DESC LIMIT 1`
 * against audit_chain directly — that would only see tenant_id IS NULL rows
 * under ac_tenant_select's RLS policy (confirmed empirically: 0 rows
 * returned against a disposable DB that genuinely had 3 tenant-tagged
 * rows), silently reproducing the exact bug this function exists to close.
 * Routes through migration 043's qodiqa_audit_chain_last_row(), a narrow
 * SECURITY DEFINER function that bypasses RLS for this one read only.
 * Returns null if the table is empty (fresh install) or PG is disabled.
 */
async function getChainTail() {
  if (!pgPool.isEnabled()) return null;

  // the tail is defined by hash LINKS (the one row no other row
  // names as prev_hash — migration 058), not by max(seq): on a mirror that
  // still carries earlier seq inversions the max-seq row can be a mid-chain row,
  // and hydrating from it would fork the chain (UNIQUE(prev_hash) refusal).
  const result = await rolePools.system.query(
    'SELECT hash, seq FROM qodiqa_audit_chain_true_tail()',
    [],
    'audit_chain_tail',
  );
  const row = result.rows[0];
  if (!row || !row.hash) return null;
  return { hash: row.hash, seq: Number(row.seq) };
}

/**
 * Integrity validation: verify that every prev_hash link exists in the DB —
 * i.e. no orphan record whose prev_hash points to a hash that was never
 * written (deleted out from under it, or never existed). This is a
 * supplemental check — the cryptographic hash chain verification (in
 * audit-log.js verifyAuditChainDetailed) remains the authoritative check —
 * but it is real orphan-detection input to the live audit chain verifier's
 * FULL PG scan (src/core/audit/verifier/ChainVerifier.js), not merely
 * diagnostic decoration.
 *
 * both table references route through qodiqa_audit_chain_full_read()
 * (migration 044's existing SECURITY DEFINER function) instead of the raw
 * audit_chain table. A plain query here is RLS-scoped by ac_tenant_select
 * and, with no tenant context ever set for this deliberately global check,
 * silently sees only NULL-tenant rows — live-reproduced as a false
 * ORPHAN_RECORD (a genuinely-present tenant-scoped predecessor row was
 * invisible to the NOT EXISTS subquery). This is an unconditional full-table
 * check with no parameters to push down, so reusing the existing full-read
 * function is sufficient — no new SQL function needed (unlike the
 * genuinely-paginated functions below, see migration 048's header).
 */
async function validateChainLinks() {
  if (!pgPool.isEnabled()) return { valid: true, brokenLinks: 0 };

  const result = await rolePools.system.query(`
    SELECT count(*) AS broken
    FROM qodiqa_audit_chain_full_read() a
    WHERE a.prev_hash != 'GENESIS'
      AND NOT EXISTS (
        SELECT 1 FROM qodiqa_audit_chain_full_read() b WHERE b.hash = a.prev_hash
      )
  `, [], 'audit_chain_link_validation');

  const broken = Number(result.rows[0]?.broken ?? 0);
  return { valid: broken === 0, brokenLinks: broken };
}

/**
 * S3: the rows validateChainLinks() counts (prev_hash names no existing row), by seq, at most `limit`.
 * Same predicate, same full read; called by the (manual/fallback) full divergence verifier ONLY when
 * validateChainLinks() already reported broken links — to tell the recorded prune anchor from a real orphan.
 */
async function listChainLinkOrphans(limit = 100) {
  if (!pgPool.isEnabled()) return [];
  const result = await rolePools.system.query(`
    SELECT a.seq, a.hash
    FROM qodiqa_audit_chain_full_read() a
    WHERE a.prev_hash != 'GENESIS'
      AND NOT EXISTS (
        SELECT 1 FROM qodiqa_audit_chain_full_read() b WHERE b.hash = a.prev_hash
      )
    ORDER BY a.seq ASC
    LIMIT $1
  `, [limit], 'audit_chain_link_orphans');
  return result.rows.map((r) => ({ seq: Number(r.seq), hash: String(r.hash).trim() }));
}

/** S3: whether audit_chain_prunes records a prune at this signed checkpoint (app role: SELECT). */
async function isPruneRecorded(checkpointId) {
  if (!pgPool.isEnabled() || !checkpointId) return false;
  const r = await pgPool.query('SELECT 1 FROM audit_chain_prunes WHERE checkpoint_id = $1 LIMIT 1', [checkpointId], 'audit_chain_prune_recorded');
  return r.rowCount > 0;
}

/** S3: the divergence verifier's persisted position of one kind ('incremental' | 'sweep'), or null. */
async function loadVerificationProgress(kind) {
  if (!pgPool.isEnabled()) return null;
  const r = await pgPool.query('SELECT * FROM audit_chain_verification_progress WHERE kind = $1', [kind], 'audit_chain_verification_progress_load');
  const x = r.rows[0];
  return x ? { kind: x.kind, baseCheckpointId: x.base_checkpoint_id, pos: Number(x.pos), byteOffset: x.byte_offset === null ? null : Number(x.byte_offset),
    prevHash: x.prev_hash, pgSeq: Number(x.pg_seq), cycleStartedAt: x.cycle_started_at, cyclesCompleted: Number(x.cycles_completed),
    lastCycleMs: x.last_cycle_ms === null ? null : Number(x.last_cycle_ms) } : null;
}

/** S3: persist a VERIFIED position (callers hold the verifier advisory lock). Upsert, autocommit. */
async function saveVerificationProgress(kind, c, { cycleStartedAt, cyclesCompleted, lastCycleMs } = {}) {
  if (!pgPool.isEnabled()) return;
  await pgPool.query(`
    INSERT INTO audit_chain_verification_progress (kind, base_checkpoint_id, pos, byte_offset, prev_hash, pg_seq, cycle_started_at, cycles_completed, last_cycle_ms, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, 0), $9, now())
    ON CONFLICT (kind) DO UPDATE SET base_checkpoint_id = EXCLUDED.base_checkpoint_id, pos = EXCLUDED.pos, byte_offset = EXCLUDED.byte_offset,
      prev_hash = EXCLUDED.prev_hash, pg_seq = EXCLUDED.pg_seq,
      cycle_started_at = COALESCE(EXCLUDED.cycle_started_at, audit_chain_verification_progress.cycle_started_at),
      cycles_completed = COALESCE($8, audit_chain_verification_progress.cycles_completed),
      last_cycle_ms = COALESCE(EXCLUDED.last_cycle_ms, audit_chain_verification_progress.last_cycle_ms), updated_at = now()
  `, [kind, c.baseCheckpointId || null, c.pos, c.byteOffset, c.prevHash, c.pgSeq, cycleStartedAt || null, Number.isInteger(cyclesCompleted) ? cyclesCompleted : null,
    Number.isFinite(lastCycleMs) ? Math.round(lastCycleMs) : null], 'audit_chain_verification_progress_save');
}

// ── Live Audit Chain Verifier support (CHAIN-2) ──────────────────────────────
//
// The four functions below back src/core/audit/verifier/ChainVerifier.js's
// PG-authoritative and PG-batch verification paths. They are additive to
// this module's existing read surface and never called from the hot
// append/persistEntry path above.

/**
 * Paginated, seq-ordered batch fetch — used by the live audit chain verifier
 * for both incremental (fromSeq = last-verified watermark) and full
 * (fromSeq = 0, repeated with each batch's max seq) scans, so a FULL scan
 * never loads the entire table into memory at once. Returns entries in the
 * same shape as loadChainFromPg() plus the raw `seq` column, which the
 * verifier needs as its resumable cursor. As in loadChainFromPg(), timestamp
 * is reconstructed from `canonical` (the exact string that was hashed) - see
 * that function's comment for why.
 *
 * routed through qodiqa_audit_chain_fetch_batch() (migration 048), a
 * SECURITY DEFINER function bypassing RLS — a plain RLS-scoped query here
 * would only see the calling session's own tenant rows, meaning the
 * distributed-mode verifier's primary batched walk (the only real
 * verification path when PG is the ordering authority) could be silently
 * blind to most of the true chain. Deliberately its own dedicated function,
 * not a reuse of qodiqa_audit_chain_full_read() — that function's own
 * unconditional `ORDER BY seq ASC` with no LIMIT would force a full-table
 * materialization on every batch call, defeating the pagination this
 * function exists for (see this comment's own next paragraph).
 */
async function fetchChainBatch(fromSeq = 0, batchSize = 1000) {
  if (!pgPool.isEnabled()) return [];

  const result = await rolePools.system.query(`
    SELECT
      seq,
      hash, prev_hash AS "prevHash", canonical,
      artifact_id AS "artifactId", decision,
      high_res_time AS "highResTime",
      input_hash AS "inputHash",
      signature,
      request_hash AS "requestHash",
      policy_hash AS "policyHash",
      verification_result AS "verificationResult",
      nonce, tenant_id AS "tenantId",
      execution_context AS "executionContext",
      public_key_id AS "publicKeyId",
      schema_version AS "schemaVersion",
      consent_provenance AS "consentProvenance",
      policy_decision AS "policyDecision",
      caller_context AS "callerContext",
      provider, model,
      stage, reason, semantic,
      token_usage AS "tokenUsage",
      response_id AS "responseId",
      entry_type AS "entryType",
      output_hash AS "outputHash",
      request_id AS "requestId",
      organization_id AS "organizationId",
      executing_provider AS "executingProvider",
      issued_at AS "issuedAt", protocol_version AS "protocolVersion", agent_id AS "agentId", session_id AS "sessionId",
      action_seq AS "actionSeq", action_hash AS "actionHash", approval_ref AS "approvalRef", dlp,
      bytes_delivered AS "bytesDelivered", completion_status AS "completionStatus",
      mirror_encoding AS "mirrorEncoding"
    FROM qodiqa_audit_chain_fetch_batch($1, $2)
    ORDER BY seq ASC
  `, [fromSeq, batchSize], 'audit_verifier_fetch_batch');

  return result.rows.map(r0 => {
    const r = decodeMirrorRow(r0, `audit_chain row ${r0.hash}`);   // (R-F4)
    let timestamp = null;
    try { timestamp = JSON.parse(r.canonical).timestamp ?? null; } catch { /* falls through to caller's validation */ }
    return {
      ...r,
      seq: Number(r.seq),
      timestamp,
      executionContext: r.executionContext ?? undefined,
      tenantId:        r.tenantId         ?? undefined,
      nonce:           r.nonce            ?? undefined,
      // TRACE-2: coreFieldsOf()/verifyCanonicalHash() read these directly
      // off the entry for schemaVersion 3 — must be present (as null, not
      // undefined) exactly like buildEntry() left them, or a correctly
      // signed schemaVersion 3 entry would be mis-reported as tampered.
      consentProvenance: r.consentProvenance ?? null,
      policyDecision:     r.policyDecision    ?? null,
      // same always-present-possibly-null contract as above.
      callerContext:      r.callerContext     ?? null,
      // same always-present-possibly-null contract as above —
      // needed for schemaVersion 5 entries' coreFieldsOf()/verifyCanonicalHash().
      provider:           r.provider ?? null,
      model:              r.model    ?? null,
      // same always-present-possibly-null contract as above — needed
      // for schemaVersion 6 entries' coreFieldsOf()/verifyCanonicalHash().
      stage:              r.stage       ?? null,
      reason:             r.reason      ?? null,
      semantic:           r.semantic    ?? null,
      tokenUsage:         r.tokenUsage  ?? null,
      responseId:         r.responseId  ?? null,
      // v7 (migration 075): same always-present-possibly-null contract — needed for schemaVersion 7 entries'
      // coreFieldsOf()/verifyCanonicalHash() and the lifecycle rules (entryType/requestId/executingProvider).
      entryType:          r.entryType         ?? null,
      outputHash:         r.outputHash        ?? null,
      requestId:          r.requestId         ?? null,
      organizationId:     r.organizationId    ?? null,
      executingProvider:  r.executingProvider ?? null,
    };
  });
}

/**
 * Window-function gap detection over `seq`, bounded by fromSeq/batchSize so
 * it is safe to call incrementally as well as during a full scan.
 *
 * `audit_chain.seq` is BIGSERIAL with NO uniqueness constraint (see
 * migrations/001_initial_schema.sql), and PostgreSQL's nextval() is
 * non-transactional — a statement that acquires a sequence value and then
 * rolls back (e.g. a retried unique-constraint violation elsewhere in the
 * same transaction) permanently burns that value. A gap here is therefore
 * expected background noise, not tamper evidence by itself, and callers
 * classify it at MEDIUM severity rather than CRITICAL (see
 * src/core/audit/verifier/diagnostics.js).
 *
 * Includes one boundary row at-or-before fromSeq before computing LAG() —
 * without it, a gap that straddles the window's own starting edge (the
 * batch's first row's true predecessor lies outside `seq > fromSeq`) would
 * be invisible, since LAG() would see NULL for that row instead of its real
 * predecessor. This mirrors GapScanner._scanEntries()'s identical boundary-
 * row technique for the same class of off-by-one at a batch edge.
 *
 * routed through qodiqa_audit_chain_detect_sequence_gaps() (migration
 * 048) — same RLS/pagination rationale as fetchChainBatch() above. A plain
 * RLS-scoped query would see a gap-free-looking but incomplete slice of
 * `seq` values (tenant-scoped rows silently missing), which could either
 * mask a real gap or fabricate a false one depending on which rows RLS
 * happened to hide.
 */
async function detectSequenceAnomalies(fromSeq = 0, batchSize = 1000) {
  if (!pgPool.isEnabled()) return [];

  const result = await rolePools.system.query(`
    SELECT previous_seq AS "previousSeq", actual_seq AS "actualSeq"
    FROM qodiqa_audit_chain_detect_sequence_gaps($1, $2)
    ORDER BY actual_seq ASC
  `, [fromSeq, batchSize], 'audit_verifier_sequence_gaps');

  return result.rows.map(r => ({
    previousSeq: Number(r.previousSeq),
    actualSeq:   Number(r.actualSeq),
    expectedSeq: Number(r.previousSeq) + 1,
  }));
}

/**
 * Full-scan-only: true duplicate `seq` values. Unlike a sequence gap, a
 * duplicate can never arise from a routine rolled-back BIGSERIAL nextval() —
 * it requires an explicit non-default-sourced insert — so the verifier
 * always classifies this CRITICAL, never a benign artifact.
 *
 * routed through qodiqa_audit_chain_full_read() (migration 044) — an
 * unconditional full-table check, same rationale as validateChainLinks()
 * above.
 */
async function detectDuplicateSequences() {
  if (!pgPool.isEnabled()) return [];

  const result = await rolePools.system.query(`
    SELECT seq, count(*) AS "count"
    FROM qodiqa_audit_chain_full_read()
    GROUP BY seq
    HAVING count(*) > 1
    ORDER BY seq ASC
  `, [], 'audit_verifier_duplicate_sequences');

  return result.rows.map(r => ({ seq: Number(r.seq), count: Number(r.count) }));
}

/**
 * Count of rows whose prev_hash is the GENESIS sentinel. Exactly one is
 * expected for a healthy non-empty chain (the first record); zero means an
 * empty chain; more than one means an unexpected chain restart mid-history
 * (MULTIPLE_GENESIS).
 *
 * routed through qodiqa_audit_chain_full_read() (migration 044) — same
 * rationale as validateChainLinks()/detectDuplicateSequences() above.
 */
async function countGenesisRows() {
  if (!pgPool.isEnabled()) return 0;

  const result = await rolePools.system.query(`
    SELECT count(*) AS "count" FROM qodiqa_audit_chain_full_read() WHERE prev_hash = 'GENESIS'
  `, [], 'audit_verifier_genesis_count');

  return Number(result.rows[0]?.count ?? 0);
}

// ── audit_chain checkpoints (migration 059) ─────────────────────
// A checkpoint records "the PG mirror was verified consistent with the file
// chain up to chain_length entries, ending at hash (at seq)". The startup
// mirror check (mirrorConsistencyCheck.js) verifies only the suffix after the
// latest one, and falls back to the full check on any doubt. Unsigned until.

/** @returns {Promise<{chainLength:number, hash:string, seq:number}|null>} */
async function getLatestAuditCheckpoint() {
  if (!pgPool.isEnabled()) return null;
  const r = await pgPool.query(
    'SELECT chain_length, hash, seq FROM audit_chain_checkpoints ORDER BY chain_length DESC LIMIT 1',
    [], 'audit_checkpoint_latest');
  const row = r.rows[0];
  return row ? { chainLength: Number(row.chain_length), hash: String(row.hash).trim(), seq: Number(row.seq) } : null;
}

/** Record a verified position; idempotent per chain_length. */
async function insertAuditCheckpoint({ chainLength, hash, seq, createdBy }) {
  if (!pgPool.isEnabled()) return;
  await pgPool.query( // ordinary table insert (app role has INSERT); not a DEFINER read
    'INSERT INTO audit_chain_checkpoints (chain_length, hash, seq, created_by) VALUES ($1, $2, $3, $4) ON CONFLICT (chain_length) DO NOTHING',
    [chainLength, hash, seq, createdBy], 'audit_checkpoint_insert');
}

// ── signed audit-chain checkpoints (migration 070, append-only) ──────────────────────────────
function _signedCheckpointRow(r) {
  return r ? { payload: r.payload, payloadHash: String(r.payload_hash).trim(), signature: r.signature, createdBy: r.created_by } : null;
}

/** Persist one signed checkpoint (app role: INSERT only; the table refuses UPDATE/DELETE). */
async function insertSignedCheckpoint(signed, createdBy) {
  if (!pgPool.isEnabled()) return false;
  const p = signed.payload;
  await pgPool.query( // ordinary table insert (app role has INSERT); not a DEFINER read
    `INSERT INTO audit_signed_checkpoints (checkpoint_id, chain_length, head_hash, pg_seq, payload, payload_hash, signature,
       key_id, key_version, previous_checkpoint_hash, created_by)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11)`,
    [p.checkpointId, p.chainLength, p.headHash, p.pgSeq, JSON.stringify(p), signed.payloadHash, signed.signature,
      p.keyId, p.keyVersion, p.previousCheckpointHash, createdBy], 'audit_signed_checkpoint_insert');
  return true;
}

/** @returns {Promise<{payload, payloadHash, signature}|null>} the signed checkpoint with the largest chain_length */
async function getLatestSignedCheckpoint() {
  if (!pgPool.isEnabled()) return null;
  const r = await pgPool.query('SELECT payload, payload_hash, signature, created_by FROM audit_signed_checkpoints ORDER BY chain_length DESC LIMIT 1',
    [], 'audit_signed_checkpoint_latest');
  return _signedCheckpointRow(r.rows[0]);
}

/** Every signed checkpoint in chain order (verifiers walk the previousCheckpointHash chain). */
async function listSignedCheckpoints() {
  if (!pgPool.isEnabled()) return [];
  const r = await pgPool.query('SELECT payload, payload_hash, signature, created_by FROM audit_signed_checkpoints ORDER BY chain_length ASC',
    [], 'audit_signed_checkpoint_list');
  return r.rows.map(_signedCheckpointRow);
}

/**
 * the newest signed checkpoint with a confirmed pg_seq whose chain_length is in (afterLength, maxLength] — the
 * runtime mirror-checkpoint advancement target. A position only: the advancer re-verifies the whole range itself.
 */
async function findSignedCheckpointForAdvance(afterLength, maxLength) {
  if (!pgPool.isEnabled()) return null;
  const r = await pgPool.query(
    `SELECT payload, payload_hash, signature, created_by FROM audit_signed_checkpoints
      WHERE chain_length > $1 AND chain_length <= $2 AND pg_seq IS NOT NULL ORDER BY chain_length DESC LIMIT 1`,
    [afterLength, maxLength], 'audit_signed_checkpoint_advance_target');
  return _signedCheckpointRow(r.rows[0]);
}

/** audit_chain rows with seq <= the given seq, counted server-side (the range form of countChainRows()). */
async function countChainRowsThroughSeq(seq) {
  if (!pgPool.isEnabled()) return 0;
  const r = await rolePools.system.query('SELECT count(*)::bigint AS n FROM qodiqa_audit_chain_full_read() WHERE seq <= $1', [seq], 'audit_chain_count_through_seq');
  return Number(r.rows[0].n);
}

/** Total audit_chain rows, counted server-side (all tenants, via the migration 044 full read). */
async function countChainRows() {
  if (!pgPool.isEnabled()) return 0;
  const r = await rolePools.system.query('SELECT count(*)::bigint AS n FROM qodiqa_audit_chain_full_read()', [], 'audit_chain_count');
  return Number(r.rows[0].n);
}

/**
 * S2: the exact number of audit_chain rows as maintained by the migration 073 counter — one row read, O(1),
 * transactionally equal to count(*) (statement triggers on audit_chain). Returns null when the counter row is
 * missing (never substitutes another count). countChainRows() above stays the full exact count.
 */
async function mirrorRowCount() {
  if (!pgPool.isEnabled()) return 0;
  const r = await rolePools.system.query('SELECT qodiqa_audit_chain_mirror_count() AS n', [], 'audit_chain_mirror_count');
  const n = r.rows[0] ? r.rows[0].n : null;
  return n === null || n === undefined ? null : Number(n);
}

/**
 * S4: the authoritative counter cross-check (migration 073 qodiqa_audit_chain_mirror_count_check(): stored
 * counter, exact count(*), in_sync — one snapshot). O(n), no temp. Read-only: reports, never repairs. Used only by the
 * reconciler (src/core/audit/mirrorCountReconciler.js), at boot and on its 6 h schedule — never by the 60 s lag check.
 * `stored` is null when the counter row is missing.
 */
async function mirrorCountCheck() {
  const r = await rolePools.system.query('SELECT stored, exact, in_sync FROM qodiqa_audit_chain_mirror_count_check()', [], 'audit_chain_mirror_count_check');
  const row = r.rows[0] || {};
  return { stored: row.stored === null || row.stored === undefined ? null : Number(row.stored), exact: Number(row.exact), inSync: row.in_sync === true };
}

/**
 * Cheap, targeted lookup used only by the startup watermark-continuity gate
 * (src/core/audit/verifierStartupGate.js) — an O(1) indexed point lookup,
 * never a substitute for a real chain walk. Returns the hash stored at the
 * given seq, or null if no row has that exact seq (which the gate treats as
 * a truncation/deletion signal).
 *
 * routed through qodiqa_audit_chain_fetch_row_by_seq() (migration 048)
 * — this gate is FATAL (process.exit(1)) on a mismatch in distributed mode;
 * a plain RLS-scoped query could report a genuinely-present tenant-scoped
 * watermark row as missing, false-FATALing a healthy server's boot the same
 * way confirmed for mirrorConsistencyCheck.js's own startup gate.
 */
async function fetchRowBySeq(seq) {
  if (!pgPool.isEnabled()) return null;

  const result = await rolePools.system.query(
    `SELECT qodiqa_audit_chain_fetch_row_by_seq($1) AS hash`,
    [seq],
    'audit_verifier_fetch_row_by_seq'
  );
  return result.rows[0]?.hash ?? null;
}

/**
 * Current maximum seq in audit_chain, or null if the table is empty. Used
 * alongside fetchRowBySeq() by the startup continuity gate to detect
 * truncation without a full table scan.
 *
 * routed through qodiqa_audit_chain_max_seq() (migration 048) — same
 * FATAL-gate rationale as fetchRowBySeq() above. An RLS-undercounted max(seq)
 * could also mask real truncation (a shorter, RLS-filtered view still looks
 * internally consistent), not only false-positive one.
 */
async function getMaxSeq() {
  if (!pgPool.isEnabled()) return null;

  const result = await rolePools.system.query(
    `SELECT qodiqa_audit_chain_max_seq() AS "maxSeq"`,
    [],
    'audit_verifier_max_seq'
  );
  const maxSeq = result.rows[0]?.maxSeq;
  return maxSeq != null ? Number(maxSeq) : null;
}

module.exports = {
  persistEntries, // phase 9: batched single-node mirror writer
  getLatestAuditCheckpoint,
  insertAuditCheckpoint,
  insertSignedCheckpoint,     // M1/M2
  getLatestSignedCheckpoint,  //
  listSignedCheckpoints,      //
  findSignedCheckpointForAdvance, //
  countChainRowsThroughSeq,       //
  countChainRows,
  mirrorRowCount,      // S2
  mirrorCountCheck,    // S4
  insertMirrorRow,
  AUDIT_MIRROR_PARENT_MISSING,
  persistEntry,
  recordEvidenceForEntry,
  setKeyInfoResolver,
  loadChainFromPg,
  loadChainFromPgCompact,
  forEachChainPageCompactInSnapshot,
  getChainTail,
  queryByArtifactId,
  queryByTenant,
  aggregateUsageByTenantPg,
  queryReplayLineage,
  validateChainLinks,
  listChainLinkOrphans,        // S3
  isPruneRecorded,             // S3
  loadVerificationProgress,    // S3
  saveVerificationProgress,    // S3
  fetchChainBatch,
  detectSequenceAnomalies,
  detectDuplicateSequences,
  countGenesisRows,
  fetchRowBySeq,
  getMaxSeq,
};
