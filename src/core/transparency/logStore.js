'use strict';

/**
 * QODIQA Transparency Log Store — Component #22
 *
 * PostgreSQL persistence layer for the transparency log.
 *
 * WRITE PATH:
 *   appendEntry(record)    — INSERT a signed entry (called from registrar.js)
 *   appendRoot(record)     — INSERT a signed root digest
 *   recordVerification(r)  — INSERT a verification run record
 *
 * CHAIN-HEAD LOCKING (migration 042, FINDING-EVIDENCE-CHAIN-FORK-RACE):
 *   lockTransparencyLogHead(tx), lockTransparencyRootsHead(tx) — lock and
 *   read the dedicated single-row pointer tables that serialize concurrent
 *   appenders. Callers (registrar.js) UPDATE the same row, in the same
 *   transaction, after a successful append.
 *
 * READ PATH:
 *   getByTransparencyId(), getByArtifactId(), getByEvidenceChainId(),
 *   listEntries(), getLatestEntry(), getEntriesInRange(),
 *   getRootById(), getLatestRoot(), listRoots(),
 *   getVerifications(), aggregateStats()
 *
 * All operations return empty / null when PG is not enabled.
 *
 * Immutability contract:
 *   Only INSERT statements are issued against transparency_log_entries,
 *   transparency_roots, and transparency_verifications — this has not
 *   changed. The chain-head locking functions above UPDATE a separate pair
 *   of one-row pointer tables (transparency_log_head, transparency_roots_head),
 *   never the ledger tables themselves.
 */

const pgPool  = require('../../infra/postgres/pool');
const rolePools = require('../../infra/postgres/rolePools'); // admin views as qodiqa_reporting, scheduler as qodiqa_system
const metrics = require('../../observability/metrics');
const { emit } = require('../../../services/logger');

// ── Entry write path ──────────────────────────────────────────────────────────

/**
 * Persist a signed transparency log entry.
 *
 * When `opts.tx` is provided the INSERT runs inside an existing transaction and
 * errors are rethrown (letting the caller roll back).  Without `opts.tx` any
 * DB error is logged and absorbed so the caller's operation is not disrupted.
 *
 * @param {object} record         — assembled by registrar.js
 * @param {object} [opts]
 * @param {object} [opts.tx]      — transactional client from pgPool.withTransaction
 * @returns {Promise<object|null>} inserted row (with id) or null on failure / non-insert
 */
async function appendEntry(record, { tx } = {}) {
  if (!tx && !pgPool.isEnabled()) return null;

  const INSERT_SQL = `
    INSERT INTO transparency_log_entries (
      transparency_id, entry_type,
      artifact_id, evidence_chain_id, verification_id,
      payload, payload_hash,
      previous_entry_hash, entry_hash,
      signer_key_id, signer_key_version, signature,
      registered_by, tenant_id, created_at
    ) VALUES (
      $1,  $2,
      $3,  $4,  $5,
      $6,  $7,
      $8,  $9,
      $10, $11, $12,
      $13, $14, $15
    )
    ON CONFLICT (entry_hash) DO NOTHING
    RETURNING id, transparency_id, created_at
  `;
  const INSERT_PARAMS = _entryInsertParams(record);

  try {
    const res = tx
      ? await tx.query(INSERT_SQL, INSERT_PARAMS)
      : await pgPool.query(INSERT_SQL, INSERT_PARAMS, 'transparency_entry_insert');

    const row = res.rows[0] ?? null;
    if (row) {
      metrics.transparencyEntriesTotal.inc({ entry_type: record.entryType });
      emit('INFO', 'TRANSPARENCY_ENTRY_CREATED', {
        transparencyId: record.transparencyId,
        entryType:      record.entryType,
        entryHash:      record.entryHash,
        artifactId:     record.artifactId ?? null,
      });
    }
    return row;
  } catch (err) {
    if (tx) throw err;
    metrics.transparencyPersistFailuresTotal.inc({});
    emit('ERROR', 'TRANSPARENCY_ENTRY_PERSIST_FAILED', {
      transparencyId: record.transparencyId,
      error:          err.message,
      code:           err.code ?? null,
    });
    return null;
  }
}

function _entryInsertParams(record) {
  return [
    record.transparencyId,
    record.entryType,
    record.artifactId        ?? null,
    record.evidenceChainId   ?? null,
    record.verificationId    ?? null,
    JSON.stringify(record.payload ?? {}),
    record.payloadHash,
    record.previousEntryHash ?? null,
    record.entryHash,
    record.signerKeyId,
    record.signerKeyVersion  ?? null,
    record.signature,
    record.registeredBy      || 'system',
    record.tenantId          ?? null,
    record.createdAt instanceof Date ? record.createdAt : new Date(record.createdAt ?? Date.now()),
  ];
}

/**
 * / R1 (transparency group commit): persist several already-chained, already-signed entries with ONE
 * multi-row INSERT inside the caller's transaction (which holds transparency_log_head). Same columns, same
 * ON CONFLICT (entry_hash) DO NOTHING, same per-row metrics/events as appendEntry(). Errors are always rethrown —
 * the caller decides (registrar.js falls back to its per-leaf savepoint path). Returned rows are NOT in any
 * guaranteed order; callers match them by entry_hash.
 *
 * @param {object[]} records
 * @param {object}   opts
 * @param {object}   opts.tx — REQUIRED transactional client
 * @returns {Promise<Array<{id, transparency_id, created_at, entry_hash}>>}
 */
async function appendEntries(records, { tx } = {}) {
  if (!tx) throw new TypeError('appendEntries: a transaction is required');
  const W = 15;
  const values = records.map((_, r) => '(' + Array.from({ length: W }, (__, c) => `$${r * W + c + 1}`).join(', ') + ')').join(', ');
  const res = await tx.query(`
    INSERT INTO transparency_log_entries (
      transparency_id, entry_type,
      artifact_id, evidence_chain_id, verification_id,
      payload, payload_hash,
      previous_entry_hash, entry_hash,
      signer_key_id, signer_key_version, signature,
      registered_by, tenant_id, created_at
    ) VALUES ${values}
    ON CONFLICT (entry_hash) DO NOTHING
    RETURNING id, transparency_id, created_at, entry_hash
  `, records.flatMap(_entryInsertParams));
  const byHash = new Map(records.map((r) => [r.entryHash, r]));
  for (const row of res.rows) {
    const record = byHash.get(row.entry_hash);
    if (!record) continue;
    metrics.transparencyEntriesTotal.inc({ entry_type: record.entryType });
    emit('INFO', 'TRANSPARENCY_ENTRY_CREATED', {
      transparencyId: record.transparencyId,
      entryType:      record.entryType,
      entryHash:      record.entryHash,
      artifactId:     record.artifactId ?? null,
    });
  }
  return res.rows;
}

// ── Root write path ───────────────────────────────────────────────────────────

/**
 * Persist a signed transparency root.
 *
 * When `opts.tx` is provided the INSERT runs inside an existing transaction and
 * errors are rethrown.  Without `opts.tx` errors are absorbed.
 *
 * @param {object} record    — assembled by registrar.js
 * @param {object} [opts]
 * @param {object} [opts.tx] — transactional client from pgPool.withTransaction
 * @returns {Promise<object|null>} inserted row (with id) or null on failure / non-insert
 */
async function appendRoot(record, { tx } = {}) {
  if (!tx && !pgPool.isEnabled()) return null;

  const INSERT_SQL = `
    INSERT INTO transparency_roots (
      root_id, seq_from, seq_to, entry_count,
      root_hash, previous_root_hash,
      signature, signer_key_id,
      generated_by, generated_at
    ) VALUES (
      $1, $2, $3, $4,
      $5, $6,
      $7, $8,
      $9, $10
    )
    ON CONFLICT (root_hash) DO NOTHING
    RETURNING id, root_id, generated_at
  `;
  const INSERT_PARAMS = [
    record.rootId,
    record.seqFrom,
    record.seqTo,
    record.entryCount,
    record.rootHash,
    record.previousRootHash ?? null,
    record.signature,
    record.signerKeyId,
    record.generatedBy || 'system',
    record.generatedAt instanceof Date ? record.generatedAt : new Date(),
  ];

  try {
    const res = tx
      ? await tx.query(INSERT_SQL, INSERT_PARAMS)
      : await pgPool.query(INSERT_SQL, INSERT_PARAMS, 'transparency_root_insert');

    const row = res.rows[0] ?? null;
    if (row) {
      metrics.transparencyRootsTotal.inc({});
      emit('INFO', 'TRANSPARENCY_ROOT_GENERATED', {
        rootId:      record.rootId,
        seqFrom:     record.seqFrom,
        seqTo:       record.seqTo,
        entryCount:  record.entryCount,
        rootHash:    record.rootHash,
      });
    }
    return row;
  } catch (err) {
    if (tx) throw err;
    metrics.transparencyPersistFailuresTotal.inc({});
    emit('ERROR', 'TRANSPARENCY_ROOT_PERSIST_FAILED', {
      rootId: record.rootId,
      error:  err.message,
      code:   err.code ?? null,
    });
    return null;
  }
}

// ── Verification write path ───────────────────────────────────────────────────

/**
 * Record a verification run (fire-and-forget).
 *
 * @param {object} record
 * @returns {Promise<void>}
 */
async function recordVerification(record) {
  if (!pgPool.isEnabled()) return;

  pgPool.query(`
    INSERT INTO transparency_verifications (
      transparency_id, verification_type, verification_result,
      checks_performed, failed_check, failure_reason,
      verified_by, duration_ms, verified_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
  `, [
    record.transparencyId  ?? null,
    record.verificationType,
    record.verificationResult,
    JSON.stringify(record.checksPerformed ?? []),
    record.failedCheck     ?? null,
    record.failureReason   ?? null,
    record.verifiedBy      || 'system',
    record.durationMs      ?? null,
    new Date(),
  ], 'transparency_verification_insert').catch(err => {
    emit('WARN', 'TRANSPARENCY_VERIFICATION_PERSIST_FAILED', {
      transparencyId: record.transparencyId,
      error:          err.message,
    });
  });
}

// ── Entry read path ───────────────────────────────────────────────────────────

/**
 * Fetch a single entry by its UUID.
 *
 * @param {string} transparencyId — UUID
 * @returns {Promise<object|null>}
 */
async function getByTransparencyId(transparencyId) {
  if (!pgPool.isEnabled()) return null;

  // routed through a SECURITY DEFINER function (migration 050) -- this
  // backs the public, unauthenticated transparency verification routes
  // (/entry/:id, /verify/:id, /proof/:id), which have no tenant identity at
  // all and must be able to find any entry regardless of tenant. See
  //.
  // public minimized lookup — verification fields only (no
  // tenant_id, registered_by, signer_key_version, payload); app role.
  const res = await pgPool.query(
    `SELECT * FROM qodiqa_transparency_public_entry($1)`,
    [transparencyId],
    'transparency_by_id',
  );
  return res.rows[0] ?? null;
}

/**
 * Fetch a single entry by its entry_hash (UNIQUE column).
 * Used to resolve the prior entry referenced by another entry's
 * previous_entry_hash for chain-link verification.
 *
 * @param {string} entryHash — 64-char hex SHA-256
 * @returns {Promise<object|null>}
 */
/**
 * the full row (including payload) for the public
 * /transparency/verify/:id integrity check, which must recompute the payload
 * hash. Read as qodiqa_system, never by the app role: the payload carries
 * tenantId/callerId and must not be readable cross-tenant through the
 * request-serving role. The route returns verdicts only — the payload never
 * leaves the server.
 */
async function getForVerification(transparencyId) {
  if (!pgPool.isEnabled()) return null;
  const res = await rolePools.system.query(
    'SELECT * FROM qodiqa_transparency_log_fetch_by_transparency_id($1)',
    [transparencyId],
    'transparency_verify_material',
  );
  return res.rows[0] ?? null;
}

async function getByEntryHash(entryHash) {
  if (!pgPool.isEnabled()) return null;

  // routed through a SECURITY DEFINER function (migration 050) -- this
  // backs the public /verify/:id route's chain-link check, which must find
  // the true prior entry regardless of tenant to correctly verify the hash
  // chain.
  // public minimized lookup (see getByTransparencyId).
  const res = await pgPool.query(
    `SELECT * FROM qodiqa_transparency_public_entry_by_hash($1)`,
    [entryHash],
    'transparency_by_entry_hash',
  );
  return res.rows[0] ?? null;
}

/**
 * Fetch entries linked to an artifact.
 *
 * @param {string} artifactId
 * @returns {Promise<object[]>}
 */
async function getByArtifactId(artifactId) {
  if (!pgPool.isEnabled()) return [];

  // routed through a SECURITY DEFINER function (migration 050) -- this
  // backs evidence-bundle generation's inclusion-proof lookup (proofLookup.js
  // -> generator.js), which must find the entry for a known artifact
  // regardless of tenant to prove public inclusion. See
  //.
  // operator evidence-bundle path — runs as qodiqa_reporting.
  const res = await rolePools.reporting.query(
    `SELECT * FROM qodiqa_transparency_log_fetch_by_artifact_id($1)`,
    [artifactId],
    'transparency_by_artifact',
  );
  return res.rows;
}

/**
 * Fetch entries linked to an evidence chain record.
 *
 * @param {string} evidenceChainId — UUID
 * @returns {Promise<object[]>}
 */
async function getByEvidenceChainId(evidenceChainId) {
  if (!pgPool.isEnabled()) return [];

  // the SECURITY DEFINER function this used to call
  // (qodiqa_transparency_log_fetch_by_evidence_chain_id, migration 050) had no
  // production caller and was dropped by migration 061 (definition preserved
  // in quarantine/w5/). This is now an ordinary, RLS-scoped read as the app
  // role: it returns only rows the session's tenant context may see. A future
  // caller that genuinely needs a cross-tenant lookup must add a reviewed,
  // role-granted function instead.
  const res = await pgPool.query(
    `SELECT * FROM transparency_log_entries WHERE evidence_chain_id = $1 ORDER BY id ASC`,
    [evidenceChainId],
    'transparency_by_evidence_chain',
  );
  return res.rows;
}

/**
 * Paginated list of transparency log entries.
 *
 * @param {object} [opts]
 * @param {string} [opts.entryType]
 * @param {string} [opts.artifactId]
 * @param {string} [opts.signerKeyId]
 * @param {string} [opts.tenantId]
 * @param {string} [opts.startTime]
 * @param {string} [opts.endTime]
 * @param {number} [opts.page=1]
 * @param {number} [opts.pageSize=50]
 * @param {'asc'|'desc'} [opts.sortOrder='desc']
 * @returns {Promise<{ entries: object[], total: number, page: number, pageSize: number }>}
 */
async function listEntries({
  entryType,
  artifactId,
  signerKeyId,
  tenantId,   // eslint-disable-line no-unused-vars -- accepted for API compatibility, never applied publicly
  startTime,
  endTime,
  page      = 1,
  pageSize  = 50,
  sortOrder = 'desc',
} = {}) {
  if (!pgPool.isEnabled()) return { entries: [], total: 0, page, pageSize };

  const pg     = Math.max(1, page);
  const ps     = Math.min(Math.max(1, pageSize), 500);
  const offset = (pg - 1) * ps;

  // backs the public, unauthenticated
  // /entries route. It runs as the app role through migration 061's
  // qodiqa_transparency_public_list(), which returns only the fields a
  // verifier needs (no tenant_id, registered_by, signer_key_version, payload)
  // and has no tenant filter at all — anyone could list or count a
  // tenant's entries with ?tenantId=. Operators get the full rows through the
  // admin routes (qodiqa_reporting).
  const res = await pgPool.query(
    'SELECT * FROM qodiqa_transparency_public_list($1, $2, $3, $4, $5, $6, $7, $8)',
    [entryType || null, artifactId || null, signerKeyId || null,
      startTime ? new Date(startTime) : null, endTime ? new Date(endTime) : null,
      ps, offset, sortOrder !== 'asc'],
    'transparency_public_list',
  );
  let total = res.rows.length ? Number(res.rows[0].total_count) : 0;
  if (!res.rows.length && offset > 0) {
    // A page past the end has no row to carry the window count; probe the first row for it.
    const probe = await pgPool.query(
      'SELECT total_count FROM qodiqa_transparency_public_list($1, $2, $3, $4, $5, 1, 0, true)',
      [entryType || null, artifactId || null, signerKeyId || null,
        startTime ? new Date(startTime) : null, endTime ? new Date(endTime) : null],
      'transparency_public_list_total',
    );
    total = probe.rows.length ? Number(probe.rows[0].total_count) : 0;
  }
  return {
    entries: res.rows.map(({ total_count, ...row }) => row), // eslint-disable-line no-unused-vars
    total,
    page:    pg,
    pageSize: ps,
  };
}

async function getLatestEntry() {
  if (!pgPool.isEnabled()) return null;

  // routed through a SECURITY DEFINER function (migration 050) -- this
  // backs rootScheduler.js's decision of when to trigger root generation,
  // which needs the TRUE latest id across the whole table; RLS-blindness
  // here could silently under-trigger root generation whenever recent
  // entries are tenant-owned.
  const res = await rolePools.system.query( // root scheduler + queue monitor (background)
    `SELECT * FROM qodiqa_transparency_log_latest_entry()`,
    [], 'transparency_latest_entry',
  );
  return res.rows[0] ?? null;
}

/**
 * Lock and read the transparency-log chain-head pointer row
 * (migration 042). Must be called inside a transaction; the caller is
 * responsible for UPDATEing this same row after a successful append, in
 * the same transaction, so EvalPlanQual re-fetch applies correctly to a
 * blocked-then-unblocked concurrent writer.
 *
 * @param {object} tx — transactional client from pgPool.withTransaction
 * @returns {Promise<{tail_hash: string|null, tail_id: string}>}
 */
async function lockTransparencyLogHead(tx) {
  const res = await tx.query('SELECT tail_hash, tail_id FROM transparency_log_head FOR UPDATE');
  return res.rows[0];
}

/**
 * Fetch all entries in an id range, ordered ASC.
 * Used during root generation to collect hashes.
 *
 * @param {number} seqFrom    — inclusive lower bound
 * @param {number} seqTo      — inclusive upper bound
 * @param {object} [opts]
 * @param {object} [opts.tx]  — transactional client from pgPool.withTransaction
 * @returns {Promise<object[]>}
 */
async function getEntriesInRange(seqFrom, seqTo, { tx } = {}) {
  // full rows for an entry range are an OPERATOR view only
  // (admin /transparency/admin/chain/validate), read as qodiqa_reporting.
  // Merkle construction (root generation, public proofs, consistency) needs
  // only (id, entry_hash) and uses getHashesInRange()/fetchEntriesFromId()
  // below, which the app role may call inside its own transaction.
  if (tx) throw new Error('getEntriesInRange: full-row range reads run on the reporting pool, not inside an app transaction — use getHashesInRange()');
  if (!pgPool.isEnabled()) return [];
  const res = await rolePools.reporting.query(
    'SELECT * FROM qodiqa_transparency_log_fetch_range_full($1, $2)',
    [Number(seqFrom), Number(seqTo)],
    'transparency_entries_in_range',
  );
  return res.rows;
}

/**
 * (id, entry_hash) for ids seqFrom..seqTo — hash-only, cross-tenant (migration
 * 049's qodiqa_transparency_log_fetch_hashes_in_range, executable by the app
 * role migration 061: entry hashes are public log data).
 */
async function getHashesInRange(seqFrom, seqTo, { tx } = {}) {
  if (!tx && !pgPool.isEnabled()) return [];
  const sql = 'SELECT id, entry_hash FROM qodiqa_transparency_log_fetch_hashes_in_range($1, $2)';
  const res = tx
    ? await tx.query(sql, [Number(seqFrom), Number(seqTo)])
    : await pgPool.query(sql, [Number(seqFrom), Number(seqTo)], 'transparency_hashes_in_range');
  return res.rows;
}

// ── Merkle block checkpoints ──────────────────────

/**
 * Up to `limit` (id, entry_hash) pairs with id >= fromId, id order. hash-only
 * (migration 061's qodiqa_transparency_public_hashes_from_id, app-executable,
 * capped at 4096 rows per call) — every caller (merkleCheckpoints.js,
 * registrar.js's existence probe) uses only these two fields.
 */
const HASH_PAGE_MAX = 4096;
async function fetchEntriesFromId(fromId, limit, { tx } = {}) {
  if (!tx && !pgPool.isEnabled()) return [];
  if (Number(limit) > HASH_PAGE_MAX) throw new Error(`fetchEntriesFromId: limit ${limit} exceeds ${HASH_PAGE_MAX}`);
  const sql = 'SELECT id, entry_hash FROM qodiqa_transparency_public_hashes_from_id($1, $2)';
  const res = tx
    ? await tx.query(sql, [Number(fromId), Number(limit)])
    : await pgPool.query(sql, [Number(fromId), Number(limit)], 'transparency_entries_from_id');
  return res.rows;
}

/** Stored block checkpoints for a block size, block_index order. */
async function getMerkleBlocks(blockSize, { tx } = {}) {
  if (!tx && !pgPool.isEnabled()) return [];
  const sql = 'SELECT block_index, first_id, last_id, subtree_hash FROM transparency_merkle_checkpoints WHERE block_size = $1 ORDER BY block_index ASC';
  const res = tx ? await tx.query(sql, [blockSize]) : await pgPool.query(sql, [blockSize], 'transparency_merkle_blocks');
  return res.rows.map((r) => ({ blockIndex: Number(r.block_index), firstId: Number(r.first_id), lastId: Number(r.last_id), subtreeHash: r.subtree_hash.trim() }));
}

/** Append one block checkpoint; idempotent (deterministic content). */
async function insertMerkleBlock({ blockSize, blockIndex, firstId, lastId, subtreeHash }, { tx } = {}) {
  const sql = 'INSERT INTO transparency_merkle_checkpoints (block_size, block_index, first_id, last_id, subtree_hash) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (block_size, block_index) DO NOTHING';
  const params = [blockSize, blockIndex, firstId, lastId, subtreeHash];
  if (tx) await tx.query(sql, params); else await pgPool.query(sql, params, 'transparency_merkle_block_insert');
}

// ── Root read path ────────────────────────────────────────────────────────────

/**
 * Fetch the most recently generated root. Plain, non-locking read — used by
 * callers that just want the current tail for observability (e.g.
 * rootScheduler.js), not for serializing concurrent root generators.
 *
 * Chain-head serialization for actual root generation goes through
 * lockTransparencyRootsHead() instead — see
 * FINDING-EVIDENCE-CHAIN-FORK-RACE-REPORT.md.
 *
 * @returns {Promise<object|null>}
 */
async function getLatestRoot() {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(
    `SELECT * FROM transparency_roots ORDER BY id DESC LIMIT 1`,
    [], 'transparency_latest_root',
  );
  return res.rows[0] ?? null;
}

/**
 * Lock and read the transparency-roots chain-head pointer row
 * (migration 042). Must be called inside a transaction; the caller is
 * responsible for UPDATEing this same row after a successful appendRoot(),
 * in the same transaction. tail_hash is the tail root's root_hash; to
 * resolve its seq_to (needed for the next root's seqFrom), look it up from
 * transparency_roots by root_hash (UNIQUE) inside the same locked
 * transaction — see registrar.js generateRoot().
 *
 * @param {object} tx — transactional client from pgPool.withTransaction
 * @returns {Promise<{tail_hash: string|null, tail_id: string}>}
 */
async function lockTransparencyRootsHead(tx) {
  const res = await tx.query('SELECT tail_hash, tail_id FROM transparency_roots_head FOR UPDATE');
  return res.rows[0];
}

/**
 * Fetch a root by its UUID.
 *
 * @param {string} rootId — UUID
 * @returns {Promise<object|null>}
 */
async function getRootById(rootId) {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(
    `SELECT * FROM transparency_roots WHERE root_id = $1 LIMIT 1`,
    [rootId],
    'transparency_root_by_id',
  );
  return res.rows[0] ?? null;
}

/**
 * Find the root that covers a given entry id.
 * Returns the smallest root whose seqTo >= entryId AND seqFrom <= entryId.
 *
 * @param {number} entryId
 * @returns {Promise<object|null>}
 */
async function getRootCoveringEntry(entryId) {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(`
    SELECT * FROM transparency_roots
    WHERE seq_from <= $1 AND seq_to >= $1
    ORDER BY id ASC
    LIMIT 1
  `, [Number(entryId)], 'transparency_root_covering_entry');

  return res.rows[0] ?? null;
}

/**
 * Paginated list of roots, newest first.
 *
 * @param {object} [opts]
 * @param {number} [opts.page=1]
 * @param {number} [opts.pageSize=20]
 * @returns {Promise<{ roots: object[], total: number, page: number, pageSize: number }>}
 */
async function listRoots({ page = 1, pageSize = 20 } = {}) {
  if (!pgPool.isEnabled()) return { roots: [], total: 0, page, pageSize };

  const pg     = Math.max(1, page);
  const ps     = Math.min(Math.max(1, pageSize), 200);
  const offset = (pg - 1) * ps;

  const [dataRes, cntRes] = await Promise.all([
    pgPool.query(`
      SELECT
        id, root_id, seq_from, seq_to, entry_count,
        root_hash, previous_root_hash,
        signer_key_id, generated_by, generated_at
      FROM transparency_roots
      ORDER BY id DESC
      LIMIT $1 OFFSET $2
    `, [ps, offset], 'transparency_roots_list'),

    pgPool.query(
      `SELECT count(*) AS total FROM transparency_roots`,
      [],
      'transparency_roots_count',
    ),
  ]);

  return {
    roots:    dataRes.rows,
    total:    Number(cntRes.rows[0]?.total ?? 0),
    page:     pg,
    pageSize: ps,
  };
}

// ── Verification read path ────────────────────────────────────────────────────

/**
 * Fetch verification history for a transparency entry.
 *
 * @param {string} transparencyId — UUID
 * @param {object} [opts]
 * @param {number} [opts.limit=50]
 * @returns {Promise<object[]>}
 */
async function getVerifications(transparencyId, { limit = 50 } = {}) {
  if (!pgPool.isEnabled()) return [];

  const cap = Math.min(limit, 500);
  const res = await pgPool.query(`
    SELECT
      id, transparency_id, verification_type, verification_result,
      checks_performed, failed_check, failure_reason,
      verified_by, duration_ms, verified_at
    FROM transparency_verifications
    WHERE transparency_id = $1
    ORDER BY verified_at DESC
    LIMIT ${cap}
  `, [transparencyId], 'transparency_verifications_history');

  return res.rows;
}

// ── Aggregate stats ───────────────────────────────────────────────────────────

/**
 * Aggregate statistics across all transparency log records.
 * Used for the monitoring dashboard.
 *
 * @returns {Promise<object|null>}
 */
async function aggregateStats() {
  if (!pgPool.isEnabled()) return null;

  // entries portion routed through the same generic SECURITY DEFINER
  // bypass listEntries() uses (migration 050) -- an unconditional full-table
  // aggregate, admin /admin/stats dashboard, meant to reflect true
  // platform-wide totals.
  const [entryRes, rootRes, verifRes] = await Promise.all([
    rolePools.reporting.query(` /* admin /admin/stats, qodiqa_reporting */
      SELECT
        count(*)                                               AS total_entries,
        count(*) FILTER (WHERE entry_type = 'ARTIFACT')       AS artifact_count,
        count(*) FILTER (WHERE entry_type = 'EVIDENCE')       AS evidence_count,
        count(*) FILTER (WHERE entry_type = 'VERIFICATION')   AS verification_count,
        count(*) FILTER (WHERE entry_type = 'POLICY')         AS policy_count,
        count(*) FILTER (WHERE entry_type = 'AUDIT')          AS audit_count,
        count(*) FILTER (WHERE entry_type = 'SYSTEM')         AS system_count,
        count(DISTINCT signer_key_id)                         AS distinct_signers,
        min(created_at)                                       AS first_entry,
        max(created_at)                                       AS last_entry
      FROM qodiqa_transparency_log_read_all()
    `, [], 'transparency_entry_stats'),

    pgPool.query(`
      SELECT
        count(*)          AS total_roots,
        min(generated_at) AS first_root,
        max(generated_at) AS last_root
      FROM transparency_roots
    `, [], 'transparency_root_stats'),

    pgPool.query(`
      SELECT
        count(*)                                                        AS total_verifications,
        count(*) FILTER (WHERE verification_result = 'VALID')           AS valid_count,
        count(*) FILTER (WHERE verification_result = 'INVALID')         AS invalid_count,
        count(*) FILTER (WHERE verification_result = 'PARTIAL')         AS partial_count,
        count(*) FILTER (WHERE verification_result = 'ERROR')           AS error_count
      FROM transparency_verifications
    `, [], 'transparency_verification_stats'),
  ]);

  const e = entryRes.rows[0] ?? {};
  const r = rootRes.rows[0]  ?? {};
  const v = verifRes.rows[0] ?? {};

  return {
    entries: {
      total:             Number(e.total_entries       ?? 0),
      byType: {
        ARTIFACT:        Number(e.artifact_count      ?? 0),
        EVIDENCE:        Number(e.evidence_count      ?? 0),
        VERIFICATION:    Number(e.verification_count  ?? 0),
        POLICY:          Number(e.policy_count        ?? 0),
        AUDIT:           Number(e.audit_count         ?? 0),
        SYSTEM:          Number(e.system_count        ?? 0),
      },
      distinctSigners:   Number(e.distinct_signers    ?? 0),
      firstEntry:        e.first_entry ?? null,
      lastEntry:         e.last_entry  ?? null,
    },
    roots: {
      total:             Number(r.total_roots ?? 0),
      firstRoot:         r.first_root ?? null,
      lastRoot:          r.last_root  ?? null,
    },
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
  appendEntries, // / R1 group commit (registrar.js)
  // Write path
  appendEntry,
  appendRoot,
  recordVerification,
  // Chain-head locking (migration 042)
  lockTransparencyLogHead,
  lockTransparencyRootsHead,
  // Entry reads
  getByTransparencyId,
  getForVerification,
  getByEntryHash,
  getByArtifactId,
  getByEvidenceChainId,
  listEntries,
  getLatestEntry,
  getEntriesInRange,
  getHashesInRange,
  fetchEntriesFromId,
  // Merkle block checkpoints
  getMerkleBlocks,
  insertMerkleBlock,
  // Root reads
  getLatestRoot,
  getRootById,
  getRootCoveringEntry,
  listRoots,
  // Verification reads
  getVerifications,
  // Stats
  aggregateStats,
};
