'use strict';

/**
 * QODIQA Transparency Log Registrar — Component #22
 *
 * Orchestrates the full registration lifecycle for a transparency log entry:
 *   1. Resolve previous entry hash from the store (chain link)
 *   2. Compute payload hash
 *   3. Compute entry hash (domain-separated SHA-256)
 *   4. Sign the entry hash with the active Ed25519 signing key
 *   5. Persist the signed entry via logStore.appendEntry()
 *
 * Also provides generateRoot() for periodic root digest generation:
 *   1. Determine the range of entries not yet covered by a root
 *   2. Collect all entry hashes in that range
 *   3. Compute the root hash
 *   4. Sign the root digest
 *   5. Persist via logStore.appendRoot()
 *
 * Fail-closed: any signing failure throws so the caller can handle it.
 * The caller (API route or fire-and-forget hook) decides on error handling.
 */

const { randomUUID }  = require('crypto');
const log             = require('./log');
const logStore        = require('./logStore');
const merkleCheckpoints = require('./merkleCheckpoints');
const pgPool          = require('../../infra/postgres/pool');
const metrics         = require('../../observability/metrics');
const { emit }        = require('../../../services/logger');
const gapHandler      = require('../transparencyGap');
const { setLocal, clearLocal } = require('../../infra/postgres/tenantContext');
const ST              = require('../../observability/stageTimer'); // closure diagnostic (bench only)

// ── Transparency signer (Component #30) ───────────────────────────────────────
//
// Lazy-loaded to avoid circular deps at module load time.
// All transparency signing now goes through the dedicated TransparencySigner,
// which uses the independent transparency key store — never the artifact key store.

let _transparencySigner = null;
function _getTransparencySigner() {
  if (!_transparencySigner) {
    _transparencySigner = require('./transparencySigner').getTransparencySigner();
  }
  return _transparencySigner;
}

/**
 * Legacy accessor — no longer used for signing.
 * Retained for backward compatibility with callers that import _signingClientId.
 */
function _signingClientId() {
  return process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT || process.env.QODIQA_CLIENT_ID || null;
}

/**
 * Sign a 32-byte hash buffer using the active transparency signing key.
 * Uses the independent transparency key store — never the artifact key store.
 * Fail-closed: throws on any signing failure.
 *
 * @param {Buffer} hashBuffer — 32-byte SHA-256 digest to sign
 * @returns {Promise<{ signature: string, keyId: string, keyVersion: number|null }>}
 */
async function _sign(hashBuffer) {
  const { signature, keyId, keyVersion } = await _getTransparencySigner().sign(hashBuffer);
  return { signature, keyId, keyVersion: keyVersion ?? null };
}

// ── Entry registration ────────────────────────────────────────────────────────

/**
 * Register a new transparency log entry.
 *
 * Fail-closed: throws if signing fails.
 * Returns the persisted row (with id) from the database.
 * Returns null when PG is not enabled (entry is still signed but not persisted).
 *
 * @param {object}      opts
 * @param {string}      opts.entryType         — 'ARTIFACT'|'EVIDENCE'|'VERIFICATION'|'POLICY'|'AUDIT'|'SYSTEM'
 * @param {string}      [opts.artifactId]
 * @param {string}      [opts.evidenceChainId] — UUID
 * @param {number}      [opts.verificationId]
 * @param {object}      [opts.payload={}]      — arbitrary JSON payload
 * @param {string}      [opts.registeredBy='system']
 * @param {string}      [opts.tenantId]
 * @returns {Promise<object>} { transparencyId, entryHash, signature, keyId, persisted: boolean, row: object|null }
 */
async function register(opts) {
  const {
    entryType,
    artifactId      = null,
    evidenceChainId = null,
    verificationId  = null,
    payload         = {},
    registeredBy    = 'system',
    tenantId        = null,
    // (D3): a caller that must be able to replay this registration from
    // the recovery queue pre-assigns the id, so the replay is idempotent.
    transparencyId: presetTransparencyId = null,
  } = opts || {};

  if (!entryType) throw new TypeError('register: entryType is required');

  // AUDIT_CHECKPOINT = the anchor leaf of a signed audit checkpoint (migration 070). Internal only —
  // the public register API's input schema (src/validation/schemas/transparency.schema.js) deliberately does NOT
  // accept it, so no caller can forge a checkpoint anchor.
  const VALID_TYPES = new Set(['ARTIFACT', 'EVIDENCE', 'VERIFICATION', 'POLICY', 'AUDIT', 'SYSTEM', 'AUDIT_CHECKPOINT']);
  if (!VALID_TYPES.has(entryType)) {
    throw new TypeError(`register: Unknown entryType "${entryType}"`);
  }

  if (presetTransparencyId !== null && (typeof presetTransparencyId !== 'string' || !/^[0-9a-f-]{36}$/i.test(presetTransparencyId))) {
    throw new TypeError('register: transparencyId must be a UUID string');
  }
  const transparencyId = presetTransparencyId || randomUUID();
  const payloadHash    = log.computePayloadHash(payload);
  const signerKeyId    = _getTransparencySigner().getActiveKeyInfo().keyId;

  // Build and sign the entry given a resolved previousEntryHash.
  const _assemble = async (previousEntryHash) => {
    const recordForHash = {
      transparencyId,
      entryType,
      artifactId:      artifactId      ?? null,
      evidenceChainId: evidenceChainId ?? null,
      verificationId:  verificationId  ?? null,
      payloadHash,
      previousEntryHash,
      signerKeyId,
    };
    const entryHash  = log.computeEntryHash(recordForHash);
    const hashBuffer = Buffer.from(entryHash, 'hex');
    const { signature, keyId, keyVersion } = await _sign(hashBuffer);
    const fullRecord = {
      ...recordForHash,
      entryHash,
      signature,
      signerKeyId:      keyId,
      signerKeyVersion: keyVersion,
      payload,
      registeredBy,
      tenantId,
      createdAt: new Date(),
    };
    return { fullRecord, entryHash, signature, keyId };
  };

  // ── Non-PG path: sign only, no persistence ──────────────────────────────────
  if (!pgPool.isEnabled()) {
    const { fullRecord, entryHash, signature, keyId } = await _assemble(null);
    emit('INFO', 'TRANSPARENCY_ENTRY_REGISTERED', {
      transparencyId, entryType, entryHash, signerKeyId: keyId, persisted: false,
    });
    return { transparencyId, entryHash, signature, keyId, persisted: false, row: null };
  }

  // ── PG path, group commit ──────
  if (GROUP_COMMIT) {
    return _enqueueGroupCommit({ _assemble, transparencyId, entryType, artifactId });
  }

  // ── PG path: transactional lock-INSERT-update to close the chain-link race ──
  // closure diagnostic (bench only, QODIQA_BENCH_STAGE_TIMING=true): S34pw pool wait, S34w head-lock wait,
  // S34h head-lock hold (acquired -> COMMIT done), and the in-flight count read by the bench sampler.
  const _b = ST.ON ? { lockAt: 0 } : null;
  if (_b) _benchTr.inflight++;
  try {
  return await pgPool.withTransaction(async (tx) => {
    // FINDING-EVIDENCE-CHAIN-FORK-RACE: chain-head serialization goes
    // through the dedicated transparency_log_head pointer row (migration
    // 042), not a FOR UPDATE lock on this table's own last row — locking a
    // row this transaction never itself UPDATEs (it only INSERTs a new
    // sibling row elsewhere) does not guarantee a blocked-then-unblocked
    // writer sees fresh data. See FINDING-EVIDENCE-CHAIN-FORK-RACE-REPORT.md.
    let previousEntryHash = null;
    try {
      const _w0 = _b ? ST.start() : 0;
      previousEntryHash = (await logStore.lockTransparencyLogHead(tx))?.tail_hash ?? null;
      if (_b) { _b.lockAt = ST.start(); ST.add('S34w', _b.lockAt - _w0); }
    } catch (err) {
      emit('WARN', 'TRANSPARENCY_PREV_HASH_LOOKUP_FAILED', { error: err.message });
      gapHandler.detectSequenceBreak({
        service:    'transparency',
        artifactId: artifactId ?? null,
        details:    { reason: 'previous_hash_lookup_failed', error: err.message },
      }).catch(() => {});
      // (D3): rethrow the ORIGINAL error. Continuing with
      // previousEntryHash=null could only ever (a) fork the chain, if the
      // transaction were still usable, or — what PostgreSQL actually does —
      // (b) fail the INSERT below with 25P02 "current transaction is
      // aborted", a class-25 NON-retryable code that masked a transient
      // failure (statement timeout, lost connection) and so defeated the
      // pending/recovery-queue classification in enforcementBridge.js.
      throw err;
    }

    const { fullRecord, entryHash, signature, keyId } = await _assemble(previousEntryHash);
    // FINDING-PG-TENANT-CONTEXT-WRITE-PATH: appendEntry's INSERT...RETURNING
    // also evaluates the SELECT RLS policy against the inserted row. This
    // row carries fullRecord.tenantId; without matching qodiqa.tenant_id
    // session context, a non-null-tenant row fails that visibility check
    // and the INSERT itself errors as an RLS violation. Set AFTER
    // lockTransparencyLogHead() above (deliberately) — scoping that lookup
    // instead would silently fork the global hash chain per tenant.
    // NULL-tenant rows already satisfy the policy's own (tenant_id IS NULL)
    // arm, so leave context unset rather than set it to an empty string.
    if (fullRecord.tenantId) {
      await setLocal(tx, fullRecord.tenantId);
    }
    const row = await logStore.appendEntry(fullRecord, { tx });

    if (row) {
      await tx.query(
        `UPDATE transparency_log_head SET tail_hash = $1, tail_id = $2`,
        [entryHash, row.id],
      );
    } else {
      gapHandler.detectPartialAppend({
        service:    'transparency',
        artifactId: artifactId ?? null,
        details:    { transparencyId, entryType, recentlyQueued: false },
      }).catch(() => {});
    }

    emit('INFO', 'TRANSPARENCY_ENTRY_REGISTERED', {
      transparencyId, entryType, entryHash, signerKeyId: keyId, persisted: !!row,
    });
    return { transparencyId, entryHash, signature, keyId, persisted: !!row, row };
  }, _b ? { isolationLevel: 'READ COMMITTED', onAcquireWait: (ms) => ST.add('S34pw', ms) } : { isolationLevel: 'READ COMMITTED' });
  } finally {
    if (_b) { _benchTr.inflight--; if (_b.lockAt) ST.add('S34h', ST.start() - _b.lockAt); }
  }
}

// closure diagnostic (bench only): registrations currently inside the PG path (waiting for a connection, waiting
// for the head lock, or holding it). Only maintained when QODIQA_BENCH_STAGE_TIMING=true.
const _benchTr = { inflight: 0 };
function _benchStats() { return { inflight: _benchTr.inflight }; }

// ── Transparency group commit ─────────────────────────
//
// QODIQA_TRANSPARENCY_GROUP_COMMIT=true (strict literal; anything else = OFF, the default) replaces "one transaction + one transparency_log_head lock + one WAL flush per leaf" with a per-process
// batcher in the style of the audit-file group commit: no timer — a registration that arrives while nothing is
// committing is committed at once (alone, with exactly the legacy statement sequence); registrations that arrive while
// a batch is committing queue and go, in arrival order, into the NEXT transaction (at most GC_MAX_BATCH leaves each).
//
// Per batch: BEGIN · lock head FOR UPDATE (once) · for each leaf: SAVEPOINT, sign over the running tail, set/clear the
// leaf's tenant context, INSERT, RELEASE · UPDATE head (once, to the last persisted leaf) · COMMIT.
//
// Guarantees (tests: registrarGroupCommit.test.js, test/integration/transparencyGroupCommit.integration.test.js):
//   - leaf content, previous-hash links, entry hashes and signatures are byte-identical to sequential appends of the
//     same input sequence (the hash/signature inputs never include the batch);
//   - each caller's promise settles only after its batch's COMMIT returned — never "persisted" before durability;
//   - lock or COMMIT failure (or any failure outside a leaf's savepoint) rejects EVERY caller of the batch with the
//     original error; PostgreSQL rolls the whole batch back, so nothing is partially visible;
//   - a failure confined to one leaf (its signing, its INSERT — e.g. 23505) rolls back only that leaf's savepoint and
//     rejects only that caller with its original error; the chain continues from the previous persisted leaf, exactly
//     as if that registration had failed alone in the legacy path;
//   - root generation / checkpoints take the same head lock and therefore run between batches, as they ran between
//     single appends; cross-process ordering is still decided by the head-row lock.
// Wait bound: a queued registration waits for at most the in-flight batch plus its own batch (each bounded by the PG
// statement timeout); there is no added linger, so latency at low load is unchanged.
const GROUP_COMMIT = process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT === 'true';
const GC_MAX_BATCH = (() => {
  const n = parseInt(process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT_MAX_BATCH || '', 10);
  return Number.isInteger(n) && n >= 1 && n <= 1024 ? n : 64;
})();
const _gc = { queue: [], flushing: false, batches: 0, entries: 0, maxBatch: 0, batchFailures: 0, leafFailures: 0, fastBatches: 0, fastFallbacks: 0 };

function groupCommitStats() {
  return {
    enabled: GROUP_COMMIT, maxBatchEntries: GC_MAX_BATCH, rollbackSwitch: 'QODIQA_TRANSPARENCY_GROUP_COMMIT (true = on)',
    queued: _gc.queue.length, flushing: _gc.flushing, batches: _gc.batches, entries: _gc.entries,
    maxBatch: _gc.maxBatch, batchFailures: _gc.batchFailures, leafFailures: _gc.leafFailures,
    fastBatches: _gc.fastBatches, fastFallbacks: _gc.fastFallbacks,
  };
}

function _enqueueGroupCommit(job) {
  return new Promise((resolve, reject) => {
    _gc.queue.push({ job, resolve, reject });
    if (ST.ON) _benchTr.inflight++;
    if (!_gc.flushing) _drainGroupCommit();
  });
}

async function _drainGroupCommit() {
  _gc.flushing = true;
  try {
    while (_gc.queue.length > 0) {
      const batch = _gc.queue.splice(0, GC_MAX_BATCH);
      await _commitBatch(batch); // settles every member; never throws
    }
  } finally {
    _gc.flushing = false;
  }
}

// Per-leaf path: one SAVEPOINT per leaf (none for a batch of one, which therefore issues exactly the legacy statement
// sequence and keeps legacy failure semantics — any error fails the whole transaction).
async function _perLeafBatch(tx, batch, tail) {
  const n = batch.length;
  const outcomes = new Array(n);
  let last = null;        // last persisted leaf → head update
  let tenantCtx = false;  // a tenant context may be set in this transaction
  for (let i = 0; i < n; i++) {
    const { job } = batch[i];
    const useSp = n > 1;
    if (useSp) await tx.query('SAVEPOINT qodiqa_tgc');
    try {
      const a = await job._assemble(tail);
      if (a.fullRecord.tenantId) {
        await setLocal(tx, a.fullRecord.tenantId);
        tenantCtx = true;
      } else if (tenantCtx) {
        // the previous leaf's transaction-local context must not apply to this NULL-tenant leaf
        await clearLocal(tx);
        tenantCtx = false;
      }
      const row = await logStore.appendEntry(a.fullRecord, { tx });
      if (useSp) await tx.query('RELEASE SAVEPOINT qodiqa_tgc');
      outcomes[i] = { a, row };
      if (row) { tail = a.entryHash; last = { hash: a.entryHash, id: row.id }; }
    } catch (err) {
      if (!useSp) throw err;
      // Leaf-confined failure: undo this leaf only. If the rollback itself fails the transaction is unusable → that
      // error fails the whole batch (outer catch), nothing is committed.
      await tx.query('ROLLBACK TO SAVEPOINT qodiqa_tgc');
      await tx.query('RELEASE SAVEPOINT qodiqa_tgc');
      tenantCtx = true; // context after rollback is whatever it was before the savepoint; clear defensively next
      outcomes[i] = { err };
    }
  }
  return { outcomes, last };
}

// Fast path: throws on any INSERT error or anomaly (caller rolls back to the batch savepoint and uses _perLeafBatch).
// A signing failure is leaf-confined here too: that leaf is skipped and the chain continues from the previous leaf,
// exactly as if its registration had failed alone.
async function _fastPathBatch(tx, batch, tail) {
  const n = batch.length;
  const outcomes = new Array(n);
  const items = [];
  let t = tail;
  for (let i = 0; i < n; i++) {
    try {
      const a = await batch[i].job._assemble(t);
      items.push({ i, a });
      t = a.entryHash;
    } catch (err) {
      outcomes[i] = { err };
    }
  }
  // Runs of consecutive leaves that share at most ONE non-NULL tenant: the INSERT ... RETURNING visibility check
  // (RLS tle_tenant_select: tenant_id IS NULL OR = current tenant) then holds for every row of the statement.
  const runs = [];
  for (const it of items) {
    const tenant = it.a.fullRecord.tenantId || null;
    const cur = runs[runs.length - 1];
    if (cur && (!tenant || !cur.tenant || cur.tenant === tenant)) { cur.items.push(it); if (tenant) cur.tenant = tenant; }
    else runs.push({ tenant, items: [it] });
  }
  let tenantCtx = false;
  let prevId = null;
  let last = null;
  for (const run of runs) {
    if (run.tenant) { await setLocal(tx, run.tenant); tenantCtx = true; }
    else if (tenantCtx) { await clearLocal(tx); tenantCtx = false; }
    const rows = await logStore.appendEntries(run.items.map((it) => it.a.fullRecord), { tx });
    const byHash = new Map(rows.map((r) => [r.entry_hash, r]));
    for (const it of run.items) {
      const row = byHash.get(it.a.entryHash);
      if (!row) throw new Error('group commit fast path: a leaf was not inserted (ON CONFLICT no-op)');
      const id = BigInt(row.id);
      if (prevId !== null && id <= prevId) throw new Error('group commit fast path: ids not increasing in arrival order');
      prevId = id;
      outcomes[it.i] = { a: it.a, row: { id: row.id, transparency_id: row.transparency_id, created_at: row.created_at } };
      last = { hash: it.a.entryHash, id: row.id };
    }
  }
  return { outcomes, last };
}

async function _commitBatch(batch) {
  const n = batch.length;
  const outcomes = new Array(n);
  const _b = ST.ON ? { lockAt: 0 } : null;
  let batchErr = null;
  try {
    await pgPool.withTransaction(async (tx) => {
      let tail = null;
      try {
        const _w0 = _b ? ST.start() : 0;
        tail = (await logStore.lockTransparencyLogHead(tx))?.tail_hash ?? null;
        if (_b) { _b.lockAt = ST.start(); ST.add('S34w', _b.lockAt - _w0); }
      } catch (err) {
        // Same signals as the legacy path, once per caller.
        for (const { job } of batch) {
          emit('WARN', 'TRANSPARENCY_PREV_HASH_LOOKUP_FAILED', { error: err.message });
          gapHandler.detectSequenceBreak({
            service: 'transparency', artifactId: job.artifactId ?? null,
            details: { reason: 'previous_hash_lookup_failed', error: err.message },
          }).catch(() => {});
        }
        throw err;
      }

      let res = null;
      if (n > 1) {
        // Fast path: sign the whole batch in order over the running tail, then ONE multi-row INSERT per tenant run,
        // under a batch savepoint. Any INSERT error or anomaly (an ON CONFLICT no-op — the chain computed after it
        // would be wrong — or ids not strictly increasing in arrival order) rolls the fast path back and the batch is
        // redone by the per-leaf savepoint path below, which has exactly the legacy per-leaf semantics.
        await tx.query('SAVEPOINT qodiqa_tgc_batch');
        try {
          res = await _fastPathBatch(tx, batch, tail);
          await tx.query('RELEASE SAVEPOINT qodiqa_tgc_batch');
          _gc.fastBatches++;
        } catch (err) {
          // If this rollback fails the transaction is unusable → whole batch fails (outer catch), nothing committed.
          await tx.query('ROLLBACK TO SAVEPOINT qodiqa_tgc_batch');
          await tx.query('RELEASE SAVEPOINT qodiqa_tgc_batch');
          _gc.fastFallbacks++;
          emit('WARN', 'TRANSPARENCY_GROUP_COMMIT_FAST_PATH_FALLBACK', { batch: n, error: err.message, code: err.code ?? null });
          res = null;
        }
      }
      if (!res) res = await _perLeafBatch(tx, batch, tail);
      res.outcomes.forEach((o, i) => { outcomes[i] = o; });
      const last = res.last;
      if (last) {
        await tx.query(`UPDATE transparency_log_head SET tail_hash = $1, tail_id = $2`, [last.hash, last.id]);
      }
    }, _b ? { isolationLevel: 'READ COMMITTED', onAcquireWait: (ms) => ST.add('S34pw', ms) } : { isolationLevel: 'READ COMMITTED' });
  } catch (err) {
    batchErr = err;
  } finally {
    if (_b && _b.lockAt) ST.add('S34h', ST.start() - _b.lockAt);
    if (ST.ON) _benchTr.inflight -= n;
  }

  _gc.batches++; _gc.entries += n; if (n > _gc.maxBatch) _gc.maxBatch = n;
  if (batchErr) {
    _gc.batchFailures++;
    for (const m of batch) m.reject(batchErr); // fail closed for every caller; the batch was rolled back as a whole
    return;
  }
  // Only now — after COMMIT returned — does any caller learn its outcome.
  for (let i = 0; i < n; i++) {
    const { job, resolve, reject } = batch[i];
    const o = outcomes[i];
    if (o.err) { _gc.leafFailures++; reject(o.err); continue; }
    const { a, row } = o;
    if (!row) {
      gapHandler.detectPartialAppend({
        service: 'transparency', artifactId: job.artifactId ?? null,
        details: { transparencyId: job.transparencyId, entryType: job.entryType, recentlyQueued: false },
      }).catch(() => {});
    }
    emit('INFO', 'TRANSPARENCY_ENTRY_REGISTERED', {
      transparencyId: job.transparencyId, entryType: job.entryType, entryHash: a.entryHash, signerKeyId: a.keyId, persisted: !!row,
    });
    resolve({ transparencyId: job.transparencyId, entryHash: a.entryHash, signature: a.signature, keyId: a.keyId, persisted: !!row, row });
  }
}

// ── Root generation ───────────────────────────────────────────────────────────

/**
 * Generate a transparency root covering all entries not yet included in a root.
 *
 * Determines the range by:
 *   - seqFrom: (latestRoot.seq_to + 1) or 1 if no roots exist
 *   - seqTo:   latestEntry.id
 *
 * Throws if there are no new entries to cover.
 * Throws if signing fails.
 *
 * @param {object} [opts]
 * @param {string} [opts.generatedBy='system']
 * @returns {Promise<object>} { rootId, seqFrom, seqTo, entryCount, rootHash, signature, row }
 */
async function generateRoot({ generatedBy = 'system' } = {}) {
  if (!pgPool.isEnabled()) {
    throw new Error('generateRoot: no transparency log entries exist');
  }

  return pgPool.withTransaction(async (tx) => {
    // FINDING-EVIDENCE-CHAIN-FORK-RACE: locks the dedicated pointer rows
    // (migration 042) rather than the ledgers' own last rows — see
    // register()'s comment above and FINDING-EVIDENCE-CHAIN-FORK-RACE-REPORT.md.
    // Locking both prevents concurrent generateRoot() calls from computing
    // overlapping ranges.
    const [rootsHead, entryHead] = await Promise.all([
      logStore.lockTransparencyRootsHead(tx),
      logStore.lockTransparencyLogHead(tx),
    ]);

    if (!entryHead?.tail_hash) {
      throw new Error('generateRoot: no transparency log entries exist');
    }

    // rootsHead.tail_hash is the tail root's root_hash; seq_to isn't
    // carried on the pointer row itself (root_hash is UNIQUE on
    // transparency_roots, migration 011), so it's resolved with one more
    // read inside this same locked transaction — safe, because no
    // concurrent writer can have advanced transparency_roots without first
    // holding transparency_roots_head's lock.
    const previousRootHash = rootsHead?.tail_hash ?? null;
    let seqFrom = 1;
    if (previousRootHash) {
      const priorRootRes = await tx.query(
        `SELECT seq_to FROM transparency_roots WHERE root_hash = $1`,
        [previousRootHash],
      );
      seqFrom = Number(priorRootRes.rows[0].seq_to) + 1;
    }
    const seqTo = Number(entryHead.tail_id);

    if (seqFrom > seqTo) {
      throw new Error(
        `generateRoot: no new entries since last root (seqTo=${seqFrom - 1}, latestEntry=${seqTo})`,
      );
    }

    // existence probe only — the new range is not loaded.
    const firstNew = await logStore.fetchEntriesFromId(seqFrom, 1, { tx });
    if (firstNew.length === 0 || Number(firstNew[0].id) > seqTo) {
      throw new Error(`generateRoot: no entries found in range [${seqFrom}, ${seqTo}]`);
    }

    // rootHash/entryCount MUST cover every entry from the beginning of the
    // log (id 1..seqTo), not just the entries newly added since the last
    // root (seqFrom..seqTo) — a transparency root's whole purpose is to
    // represent the state of the FULL log at this point, and RFC6962
    // consistency proofs (verifyConsistencyProof) only hold between two
    // roots whose trees are genuinely built over the same, growing leaf
    // sequence. Computing the tree from only the incremental range
    // produced a root that shared no leaves at all with any prior root
    // (confirmed via the acceptance test framework, AT-078) — every root
    // after the first was cryptographically unrelated to the ones before
    // it. seqFrom/seqTo themselves still record the incremental range this
    // generation call newly covered — only the hash/count inputs change.
    //
    // the same full-tree root, computed from Merkle block
    // checkpoints (merkleCheckpoints.js, migration 059) — stored hashes of
    // complete aligned blocks + the leaves of the final incomplete block —
    // instead of loading every entry from 1 on every generation. Blocks that
    // became complete since the last root are computed and stored here, inside
    // this same locked transaction. Byte-identical to log.computeRootHash over
    // the full list (property-tested in merkleBlocks.test.js).
    const tree            = await merkleCheckpoints.treeFor({ tx, seqTo });
    const entryCount      = tree.treeSize;
    const rootHash        = tree.root();

    const rootId      = randomUUID();
    const rootForSign = { rootId, seqFrom, seqTo, entryCount, rootHash, previousRootHash };
    const rootSignBuffer = log.computeRootSigningBuffer(rootForSign);
    const { signature, keyId, keyVersion } = await _sign(rootSignBuffer);

    const fullRootRecord = {
      ...rootForSign,
      signature,
      signerKeyId:      keyId,
      signerKeyVersion: keyVersion,
      generatedBy,
      generatedAt: new Date(),
    };

    const row = await logStore.appendRoot(fullRootRecord, { tx });

    // Only advance the pointer when a row was actually inserted — mirrors
    // chainStore.js's ON CONFLICT DO NOTHING handling: a duplicate
    // root_hash inserts nothing, and the pointer must not move for a no-op.
    if (row) {
      await tx.query(
        `UPDATE transparency_roots_head SET tail_hash = $1, tail_id = $2`,
        [rootHash, row.id],
      );
    }

    metrics.transparencyRootsTotal.inc({});
    emit('INFO', 'TRANSPARENCY_ROOT_GENERATED', {
      rootId, seqFrom, seqTo, entryCount, rootHash,
    });

    return { rootId, seqFrom, seqTo, entryCount, rootHash, previousRootHash, signature, keyId, persisted: !!row, row };
  }, { isolationLevel: 'READ COMMITTED' });
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  register,
  generateRoot,
  _signingClientId,
  _sign,
  _benchStats,
  groupCommitStats,
};
