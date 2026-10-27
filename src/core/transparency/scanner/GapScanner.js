'use strict';

/**
 * Transparency Gap Scanner — Core Engine — Component #34
 *
 * Performs full and incremental scans of the transparency log in PostgreSQL,
 * detecting integrity violations and routing them through the existing
 * Transparency Gap Handling framework (Component #14).
 *
 * ── What is checked ───────────────────────────────────────────────────────────
 *
 * Entry-level checks (per batch):
 *   • Sequence continuity  — ID gaps between consecutive entries
 *   • Hash chain link      — entry[n].previous_entry_hash === entry[n-1].entry_hash
 *   • Entry hash integrity — recomputed entry_hash must match stored value
 *   • Genesis entry        — first entry must have previous_entry_hash = NULL
 *
 * Root-level checks (per root, when verifyRoots=true):
 *   • Root chain link      — root[n].previous_root_hash === root[n-1].root_hash
 *   • Root hash integrity  — recomputed root_hash must match stored value
 *   • Root authenticity    — ST23-03: the root's Ed25519 signature verifies under
 *                            its signer key from the transparency key store, and
 *                            that key's status is active or deprecated (the
 *                            transparency-key lifecycle rule: well-known.js
 * VERIFIABLE, generator.js). Hash consistency
 *                            alone does not make a root valid: anyone able to
 *                            rewrite the stored entries and roots consistently
 *                            passes the integrity checks, but cannot sign. A
 *                            missing, invalid, unknown, revoked or unverifiable
 *                            signature is reported as a CHECKPOINT_DIVERGENCE gap
 *                            whose details.check is 'ROOT_SIGNATURE', distinct
 *                            from the integrity contexts above. An unknown key
 *                            triggers ONE reload of the transparency key store per
 * scan and one
 *                            re-check; it is never accepted. Entry signatures are
 *                            not checked here (roots only).
 *
 * ── Distributed lock ─────────────────────────────────────────────────────────
 *
 * Uses PostgreSQL transaction-level advisory lock (pg_try_advisory_xact_lock)
 * acquired at the start of the scan transaction.  Auto-releases on commit,
 * rollback, or connection loss — safe for Kubernetes / Docker replica sets.
 * Only one scanner may own a scan window at a time across all replicas.
 *
 * ── Scan modes ────────────────────────────────────────────────────────────────
 *
 * FULL:        Scan every entry from id=1.  Resets resume position.
 * INCREMENTAL: Resume from last_scanned_id (state persisted in gap_scanner_state).
 *              Uses a one-entry overlap at the boundary to verify chain continuity.
 *
 * ── Failure handling ─────────────────────────────────────────────────────────
 *
 * Partial scan: if the scan is interrupted, state is NOT written.
 * The next scan resumes from the last persisted position, not from the
 * interrupted point.  This prevents state corruption on process crash.
 *
 * State is only written AFTER the scan transaction commits successfully.
 *
 * ── Gap routing ──────────────────────────────────────────────────────────────
 *
 * All detected issues are dispatched through gapFramework.handleGap()
 * (Component #14), which handles classification, alerting, policy enforcement,
 * and the in-memory recovery store.  The scanner never duplicates that logic.
 */

const { computeEntryHash, computeRootHash } = require('../log');
const scannerState = require('./scannerState');
const { emit: _defaultEmit } = require('../../../../services/logger');
const _defaultMetrics         = require('../../../observability/metrics');
const _defaultPgPool          = require('../../../infra/postgres/pool');
// the three cross-tenant reads run as qodiqa_system; the app role
// keeps only the advisory lock and scanner state in its own transaction.
const _defaultDefinerQuery     = (sql, params) => require('../../../infra/postgres/rolePools').system.query(sql, params, 'gap_scanner_definer_read');
const _defaultGapFramework    = require('../../transparencyGap');

// ST23-03: root authenticity — the shared transparency signature-trust check (key policy active|deprecated,
// transparency key store by default, loaded lazily).
const { checkSignatureTrust } = require('../signatureTrust');

const SOURCE = 'TRANSPARENCY_GAP_SCANNER';
const LOCK_KEY = 'qodiqa_gap_scanner';

// ── Helpers ───────────────────────────────────────────────────────────────────

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Map snake_case DB row to camelCase for computeEntryHash. */
function _toCanonical(row) {
  return {
    transparencyId:   row.transparency_id,
    entryType:        row.entry_type,
    artifactId:       row.artifact_id   ?? null,
    evidenceChainId:  row.evidence_chain_id ?? null,
    verificationId:   row.verification_id   ?? null,
    payloadHash:      row.payload_hash,
    previousEntryHash: row.previous_entry_hash ?? null,
    signerKeyId:      row.signer_key_id,
  };
}

// ── Scanner factory ───────────────────────────────────────────────────────────

/**
 * Create a GapScanner instance with fully injectable dependencies.
 *
 * @param {object}   [opts]
 * @param {object}   [opts.config]          — scannerConfig.load() result
 * @param {object}   [opts._pgPool]         — injected for testing
 * @param {object}   [opts._gapFramework]   — injected for testing
 * @param {Function} [opts._emit]           — injected for testing
 * @param {object}   [opts._metrics]        — injected for testing
 * @param {object}   [opts._scannerState]   — injected for testing
 * @param {Function} [opts._definerQuery]   — (sql, params) => result; cross-tenant reads (default: qodiqa_system pool)
 * @returns {{ scan, getLastResult }}
 */
function createGapScanner({
  config = {},
  _pgPool        = _defaultPgPool,
  _gapFramework  = _defaultGapFramework,
  _emit          = _defaultEmit,
  _metrics       = _defaultMetrics,
  _scannerState  = scannerState,
  _definerQuery  = _defaultDefinerQuery,
  _transparencyKeys = null,
} = {}) {
  const {
    mode             = 'INCREMENTAL',
    maxBatchSize     = 1000,
    verifyEntryHashes = true,
    verifyRoots      = true,
  } = config;

  let _lastResult = null;

  // ── Entry batch query ───────────────────────────────────────────────────────
  ///RLS-1: routed through a SECURITY DEFINER function (migration 049) --
  // GapScanner runs under the plain, non-tenant withTransaction() below
  // (deliberately: this is a global, cross-tenant integrity sweep, not a
  // per-tenant operation), so a plain SELECT here would be subject to
  // transparency_log_entries' own tle_tenant_select RLS policy and only see
  // tenant_id IS NULL rows -- blind to every real tenant's entries. See
  // migration 049's header.

  async function _fetchBatch(tx, fromId, batchSize) {
    const res = await _definerQuery(
      'SELECT * FROM qodiqa_transparency_log_fetch_batch($1, $2)',
      [fromId, batchSize],
    );
    return res.rows;
  }

  // ── Root batch query ────────────────────────────────────────────────────────

  async function _fetchRootBatch(tx, fromId, batchSize) {
    const sql = `
      SELECT id, root_id, seq_from, seq_to, entry_count,
             root_hash, previous_root_hash, signer_key_id, signature, generated_at
      FROM transparency_roots
      WHERE id >= $1
      ORDER BY id ASC
      LIMIT $2
    `;
    const res = await tx.query(sql, [fromId, batchSize]);
    return res.rows;
  }

  // ── Entry hash lookup for root verification ─────────────────────────────────
  ///RLS-1: routed through a SECURITY DEFINER function (migration 049) --
  // an RLS-undercounted result here previously produced false
  // CHECKPOINT_DIVERGENCE gaps whenever a root's range included any
  // tenant-owned entry. See _fetchBatch()'s comment above.

  async function _fetchEntryHashesInRange(tx, seqFrom, seqTo) {
    const res = await _definerQuery(
      'SELECT * FROM qodiqa_transparency_log_fetch_hashes_in_range($1, $2)',
      [Number(seqFrom), Number(seqTo)],
    );
    return res.rows;
  }

  // ── Root authenticity (ST23-03) ─────────────────────────────────────────────
  // Returns null when the root's signature verifies under a verifiable transparency key, otherwise the gap details
  // ({ check: 'ROOT_SIGNATURE', context, ... }). Never throws and never returns null for a root it could not verify.
  // keyCtx.reloadAttempted bounds the unknown-key reload to ONE per scan pass.

  function _verifyRootAuthenticity(root, keyCtx) {
    // D-c: keyCtx enables ONE fail-closed transparency-store reload per scan pass for an unknown key (a stale replica
    // may not yet hold a key rotated in elsewhere), then one re-check. The checks themselves: signatureTrust.js.
    const r = checkSignatureTrust('root', root, {
      keys: _transparencyKeys,
      keyCtx,
      onReload: ({ keyId, reloaded, error }) => _emit('INFO', 'TRANSPARENCY_SCANNER_KEY_RELOAD', {
        source: SOURCE, keyId, rootId: root.root_id, reloaded, error,
      }),
    });
    if (r.ok) return null;
    return {
      check: 'ROOT_SIGNATURE', rootId: root.root_id, signerKeyId: root.signer_key_id ?? null, context: r.context,
      ...(r.keyStatus !== undefined ? { keyStatus: r.keyStatus } : {}),
      ...(r.reason !== undefined ? { reason: r.reason } : {}),
    };
  }

  // ── Gap dispatch ────────────────────────────────────────────────────────────
  // Returns true if the gap was auto-resolved.

  async function _reportGap(gapType, context, stats) {
    stats.gapsDetected++;
    _metrics.gapScannerGapsDetectedTotal?.inc({ gap_type: gapType });

    try {
      const { gap } = await _gapFramework.handleGap(gapType, context);

      const resolved = _gapFramework.autoResolveGap(gap.gapId);
      if (resolved) {
        stats.gapsRecovered++;
        _metrics.gapScannerGapsRecoveredTotal?.inc({});
        _emit('INFO', 'TRANSPARENCY_SCANNER_GAP_RECOVERED', {
          source:  SOURCE,
          gapId:   gap.gapId,
          gapType,
          service: context.service,
        });
      } else {
        stats.gapsUnrecoverable++;
        _metrics.gapScannerGapsUnrecoverableTotal?.inc({});
        _emit('WARN', 'TRANSPARENCY_SCANNER_GAP_UNRECOVERABLE', {
          source:  SOURCE,
          gapId:   gap.gapId,
          gapType,
          service: context.service,
        });
      }
    } catch (err) {
      // GapError thrown in FAIL_CLOSED mode — rethrow to abort the scan
      throw err;
    }
  }

  // ── Entry scan ──────────────────────────────────────────────────────────────

  async function _scanEntries(tx, startId, stats) {
    let currentId   = startId;
    let prevHash    = null;  // entry_hash of last processed entry
    let prevId      = null;  // id of last processed entry
    let lastScanned = null;

    // For incremental scan, load the boundary entry to enable chain verification.
    ///RLS-1: routed through a SECURITY DEFINER function (migration 049) --
    // see _fetchBatch()'s comment above.
    if (startId > 1) {
      const boundaryRes = await _definerQuery(
        'SELECT * FROM qodiqa_transparency_log_fetch_boundary($1)',
        [startId]
      );
      if (boundaryRes.rows.length > 0) {
        prevHash = boundaryRes.rows[0].entry_hash;
        prevId   = Number(boundaryRes.rows[0].id);
      }
    }

    while (true) {
      const batch = await _fetchBatch(tx, currentId, maxBatchSize);
      if (batch.length === 0) break;

      for (const row of batch) {
        const entryId = Number(row.id);
        stats.entriesChecked++;

        // ── Sequence continuity ───────────────────────────────────────────
        if (prevId !== null && entryId !== prevId + 1) {
          await _reportGap('SEQUENCE_BREAK', {
            service:   SOURCE,
            artifactId: null,
            details: {
              expectedId:  prevId + 1,
              actualId:    entryId,
              gap:         entryId - prevId - 1,
              context:     'entry_id_gap',
            },
          }, stats);
        }

        // ── Entry hash integrity ──────────────────────────────────────────
        if (verifyEntryHashes) {
          const expected = computeEntryHash(_toCanonical(row));
          if (expected !== row.entry_hash) {
            await _reportGap('HASH_CHAIN_BREAK', {
              service:   SOURCE,
              artifactId: row.artifact_id ?? null,
              details: {
                entryId,
                transparencyId:    row.transparency_id,
                storedHash:        row.entry_hash,
                computedHash:      expected,
                context:           'entry_hash_mismatch',
              },
            }, stats);
          }
        }

        // ── Hash chain link ───────────────────────────────────────────────
        if (prevHash !== null) {
          if (row.previous_entry_hash !== prevHash) {
            await _reportGap('HASH_CHAIN_BREAK', {
              service:   SOURCE,
              artifactId: row.artifact_id ?? null,
              details: {
                entryId,
                transparencyId:    row.transparency_id,
                expectedPrevHash:  prevHash,
                actualPrevHash:    row.previous_entry_hash,
                context:           'prev_hash_mismatch',
              },
            }, stats);
          }
        } else if (startId === 1 && prevId === null) {
          // Genesis entry: must have NULL previous_entry_hash
          if (row.previous_entry_hash !== null) {
            await _reportGap('HASH_CHAIN_BREAK', {
              service:   SOURCE,
              artifactId: row.artifact_id ?? null,
              details: {
                entryId,
                transparencyId: row.transparency_id,
                context:        'genesis_has_prev_hash',
                prevHash:       row.previous_entry_hash,
              },
            }, stats);
          }
        }

        prevHash    = row.entry_hash;
        prevId      = entryId;
        lastScanned = entryId;
      }

      if (batch.length < maxBatchSize) break; // last batch
      currentId = Number(batch[batch.length - 1].id) + 1;
    }

    return lastScanned;
  }

  // ── Root scan ───────────────────────────────────────────────────────────────

  async function _scanRoots(tx, startRootId, stats) {
    let currentRootId     = startRootId;
    let prevRootHash      = null;
    let prevRootId        = null;
    let lastCompletedRoot = null;
    const keyCtx          = { reloadAttempted: false }; // ST23-03: at most one key-store reload per scan pass

    // Load boundary root for chain verification on incremental scan.
    if (startRootId > 1) {
      const boundaryRes = await tx.query(
        `SELECT id, root_hash FROM transparency_roots WHERE id < $1 ORDER BY id DESC LIMIT 1`,
        [startRootId]
      );
      if (boundaryRes.rows.length > 0) {
        prevRootHash = boundaryRes.rows[0].root_hash;
        prevRootId   = Number(boundaryRes.rows[0].id);
      }
    }

    while (true) {
      const batch = await _fetchRootBatch(tx, currentRootId, maxBatchSize);
      if (batch.length === 0) break;

      for (const root of batch) {
        const rootId = Number(root.id);

        // ── Root chain link ───────────────────────────────────────────────
        if (prevRootHash !== null) {
          if (root.previous_root_hash !== prevRootHash) {
            await _reportGap('CHECKPOINT_DIVERGENCE', {
              service:   SOURCE,
              details: {
                rootId:            root.root_id,
                storedPrevHash:    root.previous_root_hash,
                expectedPrevHash:  prevRootHash,
                context:           'root_chain_break',
              },
            }, stats);
          }
        } else if (startRootId === 1 && prevRootId === null) {
          if (root.previous_root_hash !== null) {
            await _reportGap('CHECKPOINT_DIVERGENCE', {
              service:   SOURCE,
              details: {
                rootId:     root.root_id,
                context:    'genesis_root_has_prev_hash',
                prevHash:   root.previous_root_hash,
              },
            }, stats);
          }
        }

        // ── Root hash integrity ───────────────────────────────────────────
        //
        // Over 1..seq_to, NOT seq_from..seq_to. registrar.generateRoot()
        // computes both entry_count and root_hash over the FULL log from id 1
        // to seq_to (see its own comment there, and AT-078): a transparency
        // root represents the state of the whole log at that point, and
        // RFC6962 consistency proofs only hold between roots built over the
        // same growing leaf sequence. seq_from/seq_to record only which range
        // that generation call newly covered.
        //
        // This scanner was never updated to match, so for any root after the
        // first it fetched the incremental range and then reported a spurious
        // CHECKPOINT_DIVERGENCE 'root_entry_count_mismatch' (390 rows vs an
        // entry_count of 1020 in the case that surfaced this). Invisible while
        // seq_from === 1, and invisible entirely until root generation ran on
        // real data at all. Found live, 2026-09-14; the identical
        // stale assumption in proofLookup.getInclusionProofForEntry() is fixed
        // in the same change.
        const entryRows = await _fetchEntryHashesInRange(tx, 1, root.seq_to);
        if (entryRows.length !== Number(root.entry_count)) {
          await _reportGap('CHECKPOINT_DIVERGENCE', {
            service:   SOURCE,
            details: {
              rootId:         root.root_id,
              seqFrom:        Number(root.seq_from),
              seqTo:          Number(root.seq_to),
              expectedCount:  Number(root.entry_count),
              actualCount:    entryRows.length,
              context:        'root_entry_count_mismatch',
            },
          }, stats);
        } else if (entryRows.length > 0) {
          const entryHashes  = entryRows.map(r => r.entry_hash);
          const computedHash = computeRootHash(entryHashes);
          if (computedHash !== root.root_hash) {
            await _reportGap('CHECKPOINT_DIVERGENCE', {
              service:   SOURCE,
              details: {
                rootId:       root.root_id,
                storedHash:   root.root_hash,
                computedHash,
                context:      'root_hash_mismatch',
              },
            }, stats);
          }
        }

        // ── Root authenticity (ST23-03) ───────────────────────────────────
        // Checked for every root, independently of the integrity checks above: a hash-consistent root is still a
        // gap if it is not signed under a verifiable transparency key.
        const authFailure = _verifyRootAuthenticity(root, keyCtx);
        if (authFailure) {
          await _reportGap('CHECKPOINT_DIVERGENCE', { service: SOURCE, details: authFailure }, stats);
        }

        prevRootHash      = root.root_hash;
        prevRootId        = rootId;
        lastCompletedRoot = rootId;
      }

      if (batch.length < maxBatchSize) break;
      currentRootId = Number(batch[batch.length - 1].id) + 1;
    }

    return lastCompletedRoot;
  }

  // ── Core scan execution ─────────────────────────────────────────────────────

  /**
   * Execute a single scan pass (full or incremental).
   *
   * Acquires the PostgreSQL transaction-level advisory lock first.
   * If the lock cannot be acquired (another scanner is running), returns
   * { skipped: true }.
   *
   * @param {string} [overrideMode] — 'FULL' | 'INCREMENTAL' | undefined (use config)
   * @returns {Promise<object>} scan result
   */
  async function scan(overrideMode) {
    if (!_pgPool.isEnabled()) {
      _emit('WARN', 'TRANSPARENCY_SCANNER_PG_DISABLED', {
        source:  SOURCE,
        message: 'PostgreSQL is not enabled; gap scanner is a no-op.',
      });
      return { skipped: true, reason: 'PG_DISABLED' };
    }

    const scanMode = (overrideMode || mode).toUpperCase();
    const startMs  = Date.now();

    _metrics.gapScannerRunsTotal?.inc({ mode: scanMode });
    _emit('INFO', 'TRANSPARENCY_SCANNER_SCAN_STARTED', {
      source:   SOURCE,
      scanMode,
    });

    const stats = {
      gapsDetected:      0,
      gapsRecovered:     0,
      gapsUnrecoverable: 0,
      entriesChecked:    0,
    };

    let scanResult;

    try {
      scanResult = await _pgPool.withTransaction(async (tx) => {
        // ── Acquire distributed lock ────────────────────────────────────
        const lockRes = await tx.query(
          'SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint) AS acquired',
          [LOCK_KEY]
        );

        if (!lockRes.rows[0].acquired) {
          _metrics.gapScannerSkippedTotal?.inc({ reason: 'lock_not_acquired' });
          _emit('INFO', 'TRANSPARENCY_SCANNER_LOCK_NOT_ACQUIRED', {
            source: SOURCE,
            reason: 'Another scanner instance holds the lock.',
          });
          return { skipped: true, reason: 'LOCK_NOT_ACQUIRED' };
        }

        // ── Load persisted state ────────────────────────────────────────
        const state = await _scannerState.load(tx);

        const startEntryId = (scanMode === 'FULL')
          ? 1
          : (state?.last_scanned_id ? Number(state.last_scanned_id) + 1 : 1);

        const startRootId = (scanMode === 'FULL')
          ? 1
          : (state?.last_completed_root_id ? Number(state.last_completed_root_id) + 1 : 1);

        _emit('INFO', 'TRANSPARENCY_SCANNER_SCAN_RANGE', {
          source:       SOURCE,
          scanMode,
          startEntryId,
          startRootId,
        });

        // ── Scan entries ────────────────────────────────────────────────
        const lastScannedId = await _scanEntries(tx, startEntryId, stats);

        // ── Scan roots ──────────────────────────────────────────────────
        let lastCompletedRootId = state?.last_completed_root_id ?? null;
        if (verifyRoots) {
          lastCompletedRootId = await _scanRoots(tx, startRootId, stats);
        }

        return {
          skipped:            false,
          scanMode,
          lastScannedId:      lastScannedId      ?? (state?.last_scanned_id ?? null),
          lastCompletedRootId: lastCompletedRootId ?? (state?.last_completed_root_id ?? null),
          ...stats,
        };
      }, { isolationLevel: 'REPEATABLE READ' });

    } catch (err) {
      const durationMs = Date.now() - startMs;
      _metrics.gapScannerFailuresTotal?.inc({ mode: scanMode });
      _metrics.gapScannerActive?.set({}, 0);
      _emit('ERROR', 'TRANSPARENCY_SCANNER_SCAN_FAILED', {
        source:    SOURCE,
        scanMode,
        durationMs,
        error:     err.message,
      });
      _lastResult = { success: false, scanMode, durationMs, error: err.message, ...stats };
      return _lastResult;
    }

    const durationMs = Date.now() - startMs;

    if (scanResult.skipped) {
      _lastResult = { ...scanResult, durationMs };
      return _lastResult;
    }

    // ── Update metrics ──────────────────────────────────────────────────────
    _metrics.gapScannerSuccessTotal?.inc({ mode: scanMode });
    _metrics.gapScannerLastSuccessTs?.set({}, Math.floor(Date.now() / 1000));
    _metrics.gapScannerDurationMs?.observe({ mode: scanMode }, durationMs);
    _metrics.gapScannerEntriesCheckedTotal?.inc({}, stats.entriesChecked);

    // ── Persist state ───────────────────────────────────────────────────────
    try {
      await _scannerState.save({
        lastScannedId:          scanResult.lastScannedId,
        lastCompletedRootId:    scanResult.lastCompletedRootId,
        lastScanMode:           scanMode,
        lastScanAt:             new Date(),
        lastScanDurationMs:     durationMs,
        lastScanGapsDetected:   stats.gapsDetected,
        lastScanEntriesChecked: stats.entriesChecked,
        lastFullScanAt:         scanMode === 'FULL' ? new Date() : null,
      });
    } catch (stateErr) {
      _emit('WARN', 'TRANSPARENCY_SCANNER_STATE_SAVE_FAILED', {
        source: SOURCE,
        error:  stateErr.message,
      });
    }

    _emit('INFO', 'TRANSPARENCY_SCANNER_SCAN_COMPLETED', {
      source:             SOURCE,
      scanMode,
      durationMs,
      lastScannedId:      scanResult.lastScannedId,
      lastCompletedRootId: scanResult.lastCompletedRootId,
      gapsDetected:       stats.gapsDetected,
      gapsRecovered:      stats.gapsRecovered,
      gapsUnrecoverable:  stats.gapsUnrecoverable,
      entriesChecked:     stats.entriesChecked,
    });

    _lastResult = {
      success:             true,
      scanMode,
      durationMs,
      lastScannedId:       scanResult.lastScannedId,
      lastCompletedRootId: scanResult.lastCompletedRootId,
      ...stats,
    };
    return _lastResult;
  }

  return {
    scan,
    getLastResult: () => _lastResult,
  };
}

module.exports = { createGapScanner };
