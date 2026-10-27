'use strict';

/**
 * Live Audit Chain Verifier — Core Engine (CHAIN-2)
 *
 * Verifies the PRODUCTION EXECUTION AUDIT CHAIN — audit.log / audit_chain,
 * the real enforcement record — as opposed to the separate RFC6962
 * transparency log GapScanner (src/core/transparency/scanner/) already
 * covers. See docs/protocol/AUDIT-SCHEMA-V8.md "Decision Update:
 * Live Audit Chain Integrity Verifier (CHAIN-2)" for the full disambiguation
 * between the four detectors that now exist for this chain (this module,
 * mirrorConsistencyCheck.js, pgLagMonitor.js, and the on-demand
 * GET /audit/chain/integrity endpoint).
 *
 * Reuses, rather than reimplements, the chain-walking primitives already in
 * audit-log.js (_walkChain via verifyAuditChainDetailed /
 * verifyFullChainFromDisk / getModernChainSlice) and
 * mirrorConsistencyCheck.js (crossValidateRecords) — this module's job is
 * orchestration, watermarking, and classification, not hash-chain math.
 *
 * ── Three verification surfaces ───────────────────────────────────────────
 *
 *  1. File mode (single-node, QODIQA_AUDIT_ORDERING_MODE != 'distributed'):
 *     - INCREMENTAL: walk only the modern-chain slice appended since the
 *       persisted watermark (O(delta)).
 *     - FULL: re-read and re-validate audit.log directly from disk,
 *       independent of the in-memory chain — the only way to catch tampering
 *       that happened to the file after the process's one-time startup load.
 *  2. PG-authoritative mode (QODIQA_AUDIT_ORDERING_MODE=distributed):
 *     batched, paginated seq-ordered walk of audit_chain, guarded by a
 *     PostgreSQL transaction-level advisory lock so only one replica scans a
 *     window at a time (same convention as GapScanner). FULL scans add
 *     table-wide duplicate-seq, genesis-count, and orphan-link checks.
 *  3. PG dual-write divergence (single-node with QODIQA_PG_ENABLED=true):
 *     periodic re-run of the same file-vs-PG positional cross-validation
 *     mirrorConsistencyCheck.js performs once at startup — closing the
 *     "only checked once, at boot" gap for this specific comparison.
 * S3: layered — a 60 s incremental layer (new rows, from a
 *     persisted, re-validated position), a 15-minute run of signed-
 *     checkpoint anchors + one 20,000-row rolling sweep slice, and the full
 *     O(n) comparison kept for MANUAL runs and as the fallback verdict
 *     (QODIQA_AUDIT_DIVERGENCE_MODE=full restores the previous schedule).
 *
 * ── Never repairs ─────────────────────────────────────────────────────────
 *
 * This module only diagnoses. It never rewrites the file, never overwrites
 * PostgreSQL, never advances a watermark past a detected violation (so the
 * next scan keeps re-detecting and re-alerting on it until an operator
 * resolves it out of band) — matching the same philosophy
 * mirrorConsistencyCheck.js and audit-log.js's own startup checks already
 * establish for this chain.
 */

const { createStreamingLinker } = require('../../../utils/hashLinkOrder');
const _defaultEmit        = require('../../../../services/logger').emit;
const { monoNowMs } = require('../../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows
const _defaultMetrics     = require('../../../observability/metrics');
const _defaultAuditLog    = require('../audit-log');
const _defaultPgPool      = require('../../../infra/postgres/pool');
const _defaultPgBackend   = require('../../../infra/postgres/pg-audit-backend');
const _defaultMirrorCheck = require('../mirrorConsistencyCheck');
const _defaultVerifierState = require('./verifierState');
const _defaultConsentStore = require('../../consent/ConsentStore');
const diagnostics = require('./diagnostics');
const crypto = require('crypto');

// the PG-divergence check compares only these four fields — crossValidateRecords() reads
// hash, prevHash, artifactId, and canonical (equality only). `canonical` is held as its SHA-256 digest: equal
// strings ⇔ equal digests (barring a SHA-256 collision), and a non-string value is kept as-is, so every
// comparison outcome is unchanged. ~200 bytes per entry instead of the whole parsed entry is what bounds memory.
// M3: the chain start as audit-log reports it (a facade without getChainStart = never pruned).
function _chainStartOf(auditLog) {
  return typeof auditLog.getChainStart === 'function' ? auditLog.getChainStart() : null;
}

function _compactForDivergence(e) {
  if (!e) return e;
  const c = e.canonical;
  return {
    hash: e.hash, prevHash: e.prevHash, artifactId: e.artifactId,
    canonical: typeof c === 'string' ? `sha256:${crypto.createHash('sha256').update(c).digest('hex')}` : c,
  };
}
const DIVERGENCE_FILE_PAGE = 1000;
// measured heap cost of the full comparison's compact records, both sides together.
const FULL_COMPARE_BYTES_PER_ENTRY = 1636;
// the incremental scan's catch-up bound per tick (approved default).
const MAX_INCREMENTAL_ENTRIES = 20_000;
// the in-flight-tail recheck (see _verifyPgDivergence). A tail longer than this is a stalled mirror, not an
// in-flight write, and alerts without a recheck.
const TAIL_RECHECK_MAX = 1000;
const TAIL_RECHECK_WAIT_MS = (() => { const v = parseInt(process.env.QODIQA_AUDIT_VERIFIER_TAIL_RECHECK_MS, 10); return Number.isFinite(v) && v >= 0 ? v : 10_000; })();
const _yieldNow = () => require('../verifierPacer').pace(); // setImmediate, or duty-cycled inside the verifier worker

const SOURCE   = 'AUDIT_CHAIN_VERIFIER';
const LOCK_KEY = 'qodiqa_audit_chain_verifier';

function createChainVerifier({
  config          = {},
  _auditLog       = _defaultAuditLog,
  _pgPool         = _defaultPgPool,
  _pgBackend      = _defaultPgBackend,
  _mirrorCheck    = _defaultMirrorCheck,
  _verifierState  = _defaultVerifierState,
  _consentStore   = _defaultConsentStore,
  _emit           = _defaultEmit,
  _metrics        = _defaultMetrics,
  _checkpointVerify = (cp) => require('../checkpoint/checkpoint').verifyCheckpoint(cp),   // S3: anchor layer
} = {}) {
  const { batchSize = 1000 } = config;
  const _chainStart = () => _chainStartOf(_auditLog);   // M3

  let _lastResult = null;

  function _violation(reason, extra = {}) {
    return { reason, severity: diagnostics.severityOf(reason), ...extra };
  }

  function _reportViolations(violations, trigger) {
    for (const v of violations) {
      const event = diagnostics.alertEventFor(v.reason);
      _metrics.auditChainVerifierViolationsTotal?.inc({ reason: v.reason, severity: v.severity });
      _emit(v.severity === diagnostics.SEVERITY.CRITICAL ? 'CRITICAL' : 'WARN', event, {
        source: SOURCE,
        trigger,
        ...v,
      });
    }
  }

  // ── File mode: INCREMENTAL ────────────────────────────────────────────────

  async function _verifyFileModeIncremental() {
    const violations = [];
    const state = await _verifierState.loadFileState();

    let fromIndex = 0;
    let fromHash  = 'GENESIS';
    if (state && Number.isInteger(state.lastVerifiedIndex)) {
      fromIndex = state.lastVerifiedIndex;
      fromHash  = state.lastVerifiedHash || 'GENESIS';
    }
    // M3: after a prune the file starts at the signed base record (verified by audit-log at load): a verifier with
    // no watermark, or one inside the archived prefix, continues from the base.
    const start = _chainStart();
    if (start && start.startCount > 0 && fromIndex < start.startCount) {
      fromIndex = start.startCount;
      fromHash  = start.startHash;
    }

    const chainLength = _auditLog.getChainStats().modernLength;
    if (fromIndex > chainLength) {
      // The durable record is now SHORTER than what a prior run of this
      // verifier already confirmed — truncation. Do not advance the
      // watermark; keep re-reporting until an operator investigates.
      violations.push(_violation(diagnostics.VIOLATION_REASON.TRUNCATION, {
        expectedAtLeast: fromIndex,
        actual: chainLength,
      }));
      return { entriesChecked: 0, violations, newWatermark: null };
    }

    // (VERIFIER-DESIGN.md §4): catch-up is bounded — at most maxIncrementalEntries per tick (default 20,000),
    // read page by page; the watermark advances by what was verified and the next ticks continue. The verifier-lag
    // metric (runner) makes a growing backlog visible instead of hiding it behind the cap.
    const cap = Number.isInteger(config.maxIncrementalEntries) && config.maxIncrementalEntries > 0 ? config.maxIncrementalEntries : MAX_INCREMENTAL_ENTRIES;
    let slice;
    if (typeof _auditLog.getModernChainPage === 'function') {
      slice = [];
      let cursor = { m: fromIndex };
      while (cursor && slice.length < cap) {
        const page = await _auditLog.getModernChainPage({ cursor, limit: Math.min(DIVERGENCE_FILE_PAGE * 5, cap - slice.length) });
        for (const e of page.entries) slice.push(e);
        cursor = page.nextCursor;
        await _yieldNow();
      }
    } else {
      slice = (await _auditLog.getModernChainSlice(fromIndex)).slice(0, cap);
    }
    if (slice.length === 0) {
      return { entriesChecked: 0, violations, newWatermark: { index: fromIndex, hash: fromHash }, caughtUp: true };
    }

    // Chunked/non-blocking — this runs on a background
    // timer concurrently with live request handling, so a large delta must
    // not monopolize the event loop for its own duration.
    const walk = await _auditLog.verifyAuditChainDetailedChunked(slice, fromHash);

    if (!walk.valid) {
      violations.push(_violation(diagnostics.mapAuditLogReason(walk.reason), {
        offendingIndex:       fromIndex + (walk.offendingIndex ?? walk.entriesVerified),
        offendingArtifactId:  walk.offendingArtifactId ?? null,
        expectedPrevHash:     walk.expectedPrevHash,
        actualPrevHash:       walk.actualPrevHash,
        expectedHash:         walk.expectedHash,
        actualHash:           walk.actualHash,
        previousValidIndex:   fromIndex + walk.entriesVerified - 1,
      }));
      return {
        entriesChecked: walk.entriesVerified,
        violations,
        // Advance the watermark only up to the last confirmed-good entry —
        // never past the violation.
        newWatermark: walk.entriesVerified > 0
          ? { index: fromIndex + walk.entriesVerified, hash: walk.tail }
          : { index: fromIndex, hash: fromHash },
      };
    }

    return {
      entriesChecked: slice.length,
      violations,
      newWatermark: { index: fromIndex + slice.length, hash: walk.tail ?? fromHash },
      caughtUp: fromIndex + slice.length >= chainLength,
    };
  }

  // ── File mode: FULL ───────────────────────────────────────────────────────

  async function _verifyFileModeFull() {
    const violations = [];
    // Chunked/non-blocking — the scheduled FULL scan
    // (default every 24h) walks the ENTIRE on-disk chain; on a large chain
    // that walk alone could previously stall every concurrent request for
    // its whole duration.
    const result = await _auditLog.verifyFullChainFromDiskChunked();

    if (!result.applicable) {
      return { entriesChecked: 0, violations, newWatermark: null, skipped: true, reason: 'DISTRIBUTED_MODE_NO_FILE' };
    }

    if (result.parseError) {
      violations.push(_violation(diagnostics.VIOLATION_REASON.MALFORMED_RECORD, { parseError: result.parseError }));
      return { entriesChecked: 0, violations, newWatermark: null };
    }

    if (!result.checksumOk) {
      violations.push(_violation(diagnostics.VIOLATION_REASON.TRUNCATION, {
        diskEntriesCount: result.diskEntriesCount,
      }));
    }

    if (result.walkResult && !result.walkResult.valid) {
      violations.push(_violation(diagnostics.mapAuditLogReason(result.walkResult.reason), {
        offendingIndex:      result.walkResult.offendingIndex ?? null,
        offendingArtifactId: result.walkResult.offendingArtifactId ?? null,
        expectedPrevHash:    result.walkResult.expectedPrevHash,
        actualPrevHash:      result.walkResult.actualPrevHash,
        expectedHash:        result.walkResult.expectedHash,
        actualHash:          result.walkResult.actualHash,
      }));
    }

    if (result.memoryVsDiskDivergence) {
      violations.push(_violation(diagnostics.VIOLATION_REASON.FILE_MEMORY_DIVERGENCE, {
        diskEntriesCount: result.diskEntriesCount,
      }));
    }

    diagnostics.checkArchiveBoundary(); // documented no-op extension point

    // entriesVerified (not diskEntriesCount) is the count of MODERN entries
    // the walk actually confirmed — the same index space
    // getModernChainSlice() uses. Using the raw disk line count here instead
    // would silently desync the FULL and INCREMENTAL watermarks whenever any
    // legacy (pre-hash-chain) entries are present in the file.
    const walkOk = result.walkResult && result.walkResult.valid;
    const newWatermark = walkOk
      ? { index: result.walkResult.entriesVerified, hash: result.walkResult.tail ?? 'GENESIS' }
      : null; // don't advance past a detected violation

    return {
      entriesChecked: result.walkResult ? result.walkResult.entriesVerified : 0,
      violations,
      newWatermark,
    };
  }

  // ── PG-authoritative (distributed) mode ───────────────────────────────────

  async function _verifyPgAuthoritative(mode) {
    if (!_pgPool.isEnabled()) return { skipped: true, reason: 'PG_DISABLED' };

    return _pgPool.withTransaction(async (tx) => {
      const lockRes = await tx.query(
        'SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint) AS acquired',
        [LOCK_KEY]
      );
      if (!lockRes.rows[0].acquired) {
        return { skipped: true, reason: 'LOCK_NOT_ACQUIRED' };
      }

      const state = await _verifierState.loadPgState(tx);
      const startSeq  = mode === 'FULL' ? 0 : Number(state?.last_verified_seq ?? 0);
      const startHash = mode === 'FULL' ? 'GENESIS' : (state?.last_verified_hash || 'GENESIS');

      const violations = [];
      let entriesChecked = 0;
      let lastGoodSeq  = startSeq;
      let lastGoodHash = startHash;
      let stoppedEarly = false;
      // rows are FETCHED in seq order (paginated, indexed) but WALKED
      // in hash-link order. A earlier single-node mirror can carry seq inversions
      // (child committed before its parent) on a chain whose hashes all verify;
      // a positional walk reported those as PREV_HASH_MISMATCH. The streaming
      // linker holds a row until its parent has been walked, so every row is
      // still hash- and link-verified, and anything left unlinked at the end is
      // reported as ORPHAN_RECORD — a real break is never hidden.
      const linker = createStreamingLinker(startHash);
      let fetchSeq = startSeq;

      while (true) {
        const fetched = await _pgBackend.fetchChainBatch(fetchSeq, batchSize);
        if (fetched.length === 0) break;

        let batch;
        try {
          batch = linker.push(fetched);
        } catch (linkErr) {
          violations.push(_violation(diagnostics.VIOLATION_REASON.PREV_HASH_MISMATCH, {
            detail: linkErr.message, code: linkErr.code ?? null, previousValidSeq: lastGoodSeq,
          }));
          stoppedEarly = true;
          break;
        }

        const walk = batch.length > 0
          ? _auditLog.verifyAuditChainDetailed(batch, lastGoodHash)
          : { valid: true, entriesVerified: 0, tail: lastGoodHash };
        entriesChecked += walk.entriesVerified;

        if (!walk.valid) {
          const offendingRow = batch[walk.offendingIndex ?? walk.entriesVerified];
          violations.push(_violation(diagnostics.mapAuditLogReason(walk.reason), {
            offendingSeq:        offendingRow ? offendingRow.seq : null,
            offendingArtifactId: walk.offendingArtifactId ?? null,
            expectedPrevHash:    walk.expectedPrevHash,
            actualPrevHash:      walk.actualPrevHash,
            expectedHash:        walk.expectedHash,
            actualHash:          walk.actualHash,
            previousValidSeq:    lastGoodSeq,
          }));
          stoppedEarly = true;
          break;
        }

        // Bounded, incremental-safe sequence-gap check for this batch's range.
        const gaps = await _pgBackend.detectSequenceAnomalies(fetchSeq, batchSize);
        for (const g of gaps) violations.push(_violation(diagnostics.VIOLATION_REASON.SEQUENCE_GAP, g));

        fetchSeq = fetched[fetched.length - 1].seq;
        if (batch.length > 0) lastGoodHash = walk.tail;
        // The watermark seq may only advance past rows that are ALL linked.
        if (linker.pending().length === 0) lastGoodSeq = fetchSeq;

        if (fetched.length < batchSize) break;
      }

      if (!stoppedEarly && linker.pending().length > 0) {
        const pending = linker.pending();
        violations.push(_violation(diagnostics.VIOLATION_REASON.ORPHAN_RECORD, {
          unlinkedRows: pending.length,
          firstUnlinkedSeq: pending.reduce((m, r) => (m === null || r.seq < m ? r.seq : m), null),
          expectedPrevHash: linker.cursor(),
          previousValidSeq: lastGoodSeq,
        }));
        stoppedEarly = true;
      }

      // Table-wide structural checks — expensive relative to a single batch,
      // so only run during FULL scans, never on every incremental tick.
      if (mode === 'FULL') {
        const dupes = await _pgBackend.detectDuplicateSequences();
        for (const d of dupes) violations.push(_violation(diagnostics.VIOLATION_REASON.DUPLICATE_SEQUENCE, d));

        const genesisCount = await _pgBackend.countGenesisRows();
        if (genesisCount > 1) {
          violations.push(_violation(diagnostics.VIOLATION_REASON.MULTIPLE_GENESIS, { genesisCount }));
        } else if (genesisCount === 0 && lastGoodSeq > startSeq) {
          violations.push(_violation(diagnostics.VIOLATION_REASON.INVALID_GENESIS, { genesisCount }));
        }

        const linkCheck = await _pgBackend.validateChainLinks();
        if (!linkCheck.valid) {
          violations.push(_violation(diagnostics.VIOLATION_REASON.ORPHAN_RECORD, { brokenLinks: linkCheck.brokenLinks }));
        }
      }

      if (!stoppedEarly && linker.inversions() > 0) {
        _emit('WARN', 'AUDIT_CHAIN_SEQ_INVERSIONS_PRESENT', {
          source: SOURCE, mode, inversions: linker.inversions(), entriesChecked,
          action: 'Chain verified by hash links; historical seq inversions present (earlier single-node mirror). Re-sequence with scripts/audit-mirror-rebuild.js.',
        });
      }

      return {
        skipped: false,
        entriesChecked,
        violations,
        // a walk that had to link around seq inversions does not
        // persist a watermark — with inversions the row at max(seq) need not be
        // the chain tail, and verifierStartupGate checks exactly that pair. The
        // next run rescans instead; after scripts/audit-mirror-rebuild.js (and
        // for every mirror written) there are no inversions and the
        // watermark advances exactly as before.
        newWatermark: (stoppedEarly || linker.inversions() > 0) ? null : { seq: lastGoodSeq, hash: lastGoodHash },
      };
    }, { isolationLevel: 'REPEATABLE READ' });
  }

  // ── PG dual-write divergence (single-node + PG mirror) ────────────────────

  // Deliberately a full O(n) positional comparison on every call, not an
  // incremental one: file-array-index and PG-seq only stay 1:1-comparable
  // up to the last position both stores are CONFIRMED to agree on, which is
  // exactly the thing this check exists to (re-)establish — a naive
  // "resume from the last watermark" slice would silently trust the very
  // assumption a real divergence (a skipped or out-of-order PG dual-write)
  // would violate. Kept safe by running relatively infrequently
  // (QODIQA_AUDIT_VERIFIER_PG_DIVERGENCE_INTERVAL, default 15 minutes) —
  // see docs/operations/audit-chain-integrity-verification.md for the
  // scaling note on very large dual-write deployments.
  // ── (VERIFIER-DESIGN.md, owner amendment 6): bounded-memory divergence merge ───────────────────────────────
  // Both sides are read in pages, in chain order — the file through getModernChainPage()'s cursor, PG through ONE
  // read-only snapshot cursor (the same query as the full path) put in hash-link order by the streaming linker —
  // and compared position by position (hash, prevHash, canonical digest). Only O(page) is held.
  // The result is ACCEPTED only when every position agrees and nothing is left over on the PG side; in exactly that
  // case the full comparison (crossValidateRecords) would also find no mismatch. A file tail beyond the PG snapshot
  // is the normal in-flight dual-write and gets the same drain + lookup recheck. ANY disagreement returns
  // { decided: false } and the caller runs the unchanged full comparison, which produces the exact verdict.
  async function _streamingDivergence(base = null) {
    const linker = createStreamingLinker(base ? base.startHash : 'GENESIS');   // M3
    const fileBuf = [];
    const file = { cursor: null, pos: 0, ended: false };
    const fill = async () => {
      const page = await _auditLog.getModernChainPage({ cursor: file.cursor || (file.pos ? { m: file.pos } : null), limit: DIVERGENCE_FILE_PAGE });
      for (const e of page.entries) fileBuf.push(_compactForDivergence(e));
      file.pos = page.startPos + page.entries.length;
      file.cursor = page.nextCursor;
      file.ended = !page.nextCursor;
      return page.entries.length;
    };
    let pos = 0; let pgRowsSeen = 0; let lastCommon = null; let reason = null;
    await _pgBackend.forEachChainPageCompactInSnapshot(_compactForDivergence, {
      pageSize: 2000,
      fromSeqExclusive: base ? base.pgSeq : null,   // M3: rows after the signed base record only
      onPage: async (rows) => {
        pgRowsSeen += rows.length;
        let ordered;
        try { ordered = linker.push(rows); } catch (e) { reason = e.code || 'LINKER_ERROR'; return false; }
        for (const p of ordered) {
          if (fileBuf.length === 0 && (await fill()) === 0) { reason = 'PG_AHEAD_OF_FILE'; return false; }
          const fe = fileBuf.shift();
          if (fe.hash !== p.hash || fe.prevHash !== p.prevHash || fe.canonical !== p.canonical) { reason = 'POSITIONAL_MISMATCH'; return false; }
          lastCommon = { sequence: pos, hash: fe.hash };
          if (++pos % 2048 === 0) await _yieldNow();
        }
        return true;
      },
    });
    if (reason) return { decided: false, reason, comparedBeforeFallback: pos };
    if (linker.pending().length) return { decided: false, reason: 'PG_UNLINKED_ROWS', comparedBeforeFallback: pos };
    while (!file.ended && fileBuf.length <= TAIL_RECHECK_MAX) await fill();
    if (fileBuf.length > TAIL_RECHECK_MAX) return { decided: false, reason: 'LONG_FILE_TAIL', comparedBeforeFallback: pos };
    const tail = fileBuf.splice(0);
    if (tail.length > 0) {
      if (typeof _pgBackend.queryByArtifactId !== 'function') return { decided: false, reason: 'TAIL_NO_LOOKUP', comparedBeforeFallback: pos };
      const t0 = Date.now();
      if (typeof _auditLog.drainMirrorWriter === 'function') {
        await Promise.race([Promise.resolve(_auditLog.drainMirrorWriter()).catch(() => {}), new Promise((res) => setTimeout(res, TAIL_RECHECK_WAIT_MS).unref?.())]);
      }
      for (const e of tail) {
        const row = typeof e.artifactId === 'string' ? await _pgBackend.queryByArtifactId(e.artifactId).catch(() => null) : null;
        const p = row ? _compactForDivergence(row) : null;
        if (!p || p.hash !== e.hash || p.prevHash !== e.prevHash || p.canonical !== e.canonical) return { decided: false, reason: 'TAIL_UNRESOLVED', comparedBeforeFallback: pos };
        lastCommon = { sequence: pos, hash: e.hash };
        pos++;
      }
      _emit('INFO', 'AUDIT_CHAIN_VERIFIER_TAIL_RECHECKED', { source: 'AUDIT_CHAIN_VERIFIER', tailLength: tail.length, foundOnRecheck: tail.length, waitedMs: Date.now() - t0, resolved: true, stillMismatched: null, streamed: true });
    }
    return { decided: true, crossValidation: { recordsChecked: pos, fileChainLength: pos, pgChainLength: pgRowsSeen + tail.length, firstMismatch: null, lastCommonRecord: lastCommon, divergencePoint: null } };
  }

  // Owner amendment 6 fallback: the full comparison holds both sides in memory (measured 1,636 bytes per entry for
  // both sides together). Warn before it can hit the worker's memory limit.
  function _projectFullCompareMemory() {
    const limitMb = Number(config.memoryLimitMb) || 0;
    if (!limitMb || typeof _auditLog.getChainStats !== 'function') return;
    const entries = _auditLog.getChainStats().modernLength || 0;
    const projectedMb = Math.round((entries * FULL_COMPARE_BYTES_PER_ENTRY) / 1048576);
    if (projectedMb >= 0.7 * limitMb) {
      _emit('WARN', 'AUDIT_CHAIN_VERIFIER_MEMORY_PROJECTION', { source: SOURCE, entries, projectedMb, limitMb, percentOfLimit: Math.round((100 * projectedMb) / limitMb),
        message: 'The full divergence comparison (the fallback of the bounded-memory merge) would use >= 70% of the verifier worker memory limit.' });
    }
  }

  async function _verifyPgDivergence() {
    if (_auditLog.ORDERING_MODE === 'distributed') return { skipped: true, reason: 'DISTRIBUTED_MODE' };
    if (!_pgPool.isEnabled())                       return { skipped: true, reason: 'PG_DISABLED' };

    const violations = [];
    let crossValidation = null;
    // M3: after a prune both sides are compared from the signed base record — PG rows with seq > its pgSeq, linked
    // from its headHash. A base without a PG seq cannot be aligned with the mirror: skipped, said loudly.
    const start = _chainStart();
    let base = null;
    if (start && start.startCount > 0) {
      const pgSeq = start.checkpoint && start.checkpoint.payload ? start.checkpoint.payload.pgSeq : null;
      if (!Number.isInteger(pgSeq)) {
        _emit('WARN', 'AUDIT_CHAIN_VERIFIER_DIVERGENCE_SKIPPED', { source: SOURCE, reason: 'REBASED_WITHOUT_PG_SEQ',
          message: 'The signed base record carries no PG seq: the file and the PG mirror cannot be aligned after the prune.' });
        return { skipped: true, reason: 'REBASED_WITHOUT_PG_SEQ' };
      }
      base = { startHash: start.startHash, pgSeq };
    }
    if (config.streamingDivergence !== false && typeof _auditLog.getModernChainPage === 'function'
        && typeof _pgBackend.forEachChainPageCompactInSnapshot === 'function') {
      const st = await _streamingDivergence(base);
      if (st.decided) crossValidation = st.crossValidation;
      else _emit('INFO', 'AUDIT_CHAIN_VERIFIER_DIVERGENCE_FULL_COMPARE', { source: SOURCE, reason: st.reason, comparedBeforeFallback: st.comparedBeforeFallback });
    }
    if (!crossValidation) { // the full comparison — the reference, and the fallback of the merge above
    _projectFullCompareMemory();
    // the same full O(n) comparison as before — the same file entries (getModernChain()'s
    // walk), the same PG rows in the same order (loadChainFromPg()'s query and hash-link ordering, one snapshot),
    // the same algorithm — but streamed: each page is reduced to the four compared fields and the event loop is
    // yielded between pages and every 2,048 comparisons. Before, the whole chain was materialized twice and
    // compared synchronously; at 75,000 entries that blocked the event loop for up to 1.2 s per run and stalled
    // live traffic. Injected facades without the paged functions
    // (tests) take the original calls; the compaction is applied to both sides either way.
    const fileEntries = [];
    if (typeof _auditLog.forEachModernChainPage === 'function') {
      await _auditLog.forEachModernChainPage(async (page) => {
        for (const e of page) fileEntries.push(_compactForDivergence(e));
        await _yieldNow();
      }, { limit: DIVERGENCE_FILE_PAGE });
    } else {
      for (const e of await _auditLog.getModernChain()) fileEntries.push(_compactForDivergence(e));
    }
    const pgRows = typeof _pgBackend.loadChainFromPgCompact === 'function'
      ? await _pgBackend.loadChainFromPgCompact(_compactForDivergence, { onPage: _yieldNow, ...(base ? { fromSeqExclusive: base.pgSeq, start: base.startHash } : {}) })
      : (await _pgBackend.loadChainFromPg()).map(_compactForDivergence);
    const compare = (f, p) => (typeof _mirrorCheck.crossValidateRecordsAsync === 'function'
      ? _mirrorCheck.crossValidateRecordsAsync(f, p)
      : _mirrorCheck.crossValidateRecords(f, p));
    crossValidation = await compare(fileEntries, pgRows);

    // — recheck before alerting. The file chain is read before the PG
    // chain, so an entry appended just before the file read can still have its PG dual-write in flight when PG is
    // read: a false CRITICAL AUDIT_CHAIN_CORRUPTED (PG_MIRROR_MISSING_IN_PG) at exactly the chain tail, seen under
    // load. Only when the first mismatch is
    // MISSING_IN_PG AND every file entry from there to the end is absent from the PG snapshot (a contiguous tail,
    // at most TAIL_RECHECK_MAX entries): wait for the mirror writer to drain (bounded), fetch those entries from PG
    // by artifact id, append them to the PG side in chain order, and run the SAME comparison again. A tail that
    // has meanwhile been written correctly compares clean; one still missing, or written differently, is reported
    // exactly as before. A gap in the middle of the chain, a longer missing tail (a stalled mirror), or a backend
    // without the lookup is never rechecked — it alerts immediately, as before.
    if (crossValidation.firstMismatch && crossValidation.firstMismatch.reason === 'MISSING_IN_PG'
        && typeof _pgBackend.queryByArtifactId === 'function') {
      const from = crossValidation.firstMismatch.sequence;
      const pgHashes = new Set(pgRows.map((r) => r && r.hash));
      const tail = fileEntries.slice(from);
      if (tail.length > 0 && tail.length <= TAIL_RECHECK_MAX && tail.every((e) => !pgHashes.has(e.hash))) {
        const t0 = Date.now();
        if (typeof _auditLog.drainMirrorWriter === 'function') {
          await Promise.race([Promise.resolve(_auditLog.drainMirrorWriter()).catch(() => {}), new Promise((r) => setTimeout(r, TAIL_RECHECK_WAIT_MS).unref?.())]);
        }
        const fetched = [];
        for (const e of tail) {
          const row = typeof e.artifactId === 'string' ? await _pgBackend.queryByArtifactId(e.artifactId).catch(() => null) : null;
          if (row) fetched.push(_compactForDivergence(row));
        }
        const recheck = await compare(fileEntries, pgRows.concat(fetched));
        _emit('INFO', 'AUDIT_CHAIN_VERIFIER_TAIL_RECHECKED', {
          source: 'AUDIT_CHAIN_VERIFIER', tailLength: tail.length, foundOnRecheck: fetched.length, waitedMs: Date.now() - t0,
          resolved: recheck.firstMismatch === null, stillMismatched: recheck.firstMismatch ? recheck.firstMismatch.reason : null,
        });
        crossValidation = recheck;
      }
    }
    } // end of the full comparison

    if (crossValidation.firstMismatch) {
      violations.push(_violation(diagnostics.mapMirrorReason(crossValidation.firstMismatch.reason), {
        sequence:         crossValidation.firstMismatch.sequence,
        fileHash:         crossValidation.firstMismatch.fileHash,
        pgHash:           crossValidation.firstMismatch.pgHash,
        expectedPrevHash: crossValidation.firstMismatch.expectedPrevHash,
        actualPrevHash:   crossValidation.firstMismatch.actualPrevHash,
        lastCommonRecord: crossValidation.lastCommonRecord,
      }));
    }

    // CHAIN-5: validateChainLinks() is a generic, cheap, indexed table-wide
    // orphan-link check against audit_chain — it doesn't depend on which
    // ordering mode is active. The distributed-mode FULL scan
    // (_verifyPgAuthoritative above) already calls it; single-node +
    // PG-dual-write deployments (this function's only callers) previously
    // never did, leaving the PG mirror's referential integrity completely
    // unchecked in the most common deployment shape. Reuses this function's
    // own existing schedule (QODIQA_AUDIT_VERIFIER_PG_DIVERGENCE_INTERVAL) —
    // no new timer, no second validation framework.
    const linkCheck = await _pgBackend.validateChainLinks();
    if (!linkCheck.valid) {
      // S3 — pre-existing defect corrected: after a legitimate M3/M4 prune the kept
      // signed anchor row's parent is gone by design, and this check reported ORPHAN_RECORD on every run. Exactly that
      // one row is excused, and only when the prune is recorded; every other missing parent is still an orphan.
      const brokenLinks = linkCheck.brokenLinks - ((await _excusedPruneAnchor(linkCheck.brokenLinks)) ? 1 : 0);
      if (brokenLinks > 0) violations.push(_violation(diagnostics.VIOLATION_REASON.ORPHAN_RECORD, { brokenLinks }));
    }

    return {
      skipped: false,
      entriesChecked: crossValidation.recordsChecked,
      violations,
      lastCommonSeq: crossValidation.lastCommonRecord?.sequence ?? null,
    };
  }

  // ── Consent audit checksum scan (TRACE-3) ─────────────────────────────────
  //
  // Postgres-only data, independent of which audit-chain ordering mode is
  // active (distributed vs single-node) — run once from the FULL scan branch
  // regardless of orderingMode, rather than duplicating this call into both
  // _verifyPgAuthoritative and _verifyFileModeFull. Never runs on an
  // INCREMENTAL tick — consent_audit_log has no resumable watermark of its
  // own here, and a full-table scan of it on every 60s incremental tick
  // would be wasteful; it shares the FULL scan's own interval instead (see
  // verifierConfig.js's fullIntervalMs).
  async function _verifyConsentAudit() {
    if (!_pgPool.isEnabled()) return [];
    try {
      const { mismatches } = await _consentStore.verifyConsentAuditIntegrity({});
      return mismatches.map(m => _violation(diagnostics.VIOLATION_REASON.CONSENT_CHECKSUM_MISMATCH, {
        consentAuditRowId: m.id,
        consentId:         m.consentId,
        eventType:         m.eventType,
        eventTs:           m.eventTs,
      }));
    } catch (err) {
      _emit('ERROR', 'AUDIT_CHAIN_VERIFIER_CONSENT_SCAN_FAILED', { source: SOURCE, error: err.message });
      return [];
    }
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * @param {object} opts
   * @param {'FULL'|'INCREMENTAL'} [opts.mode]
   * @param {'STARTUP'|'SCHEDULED'|'MANUAL'} [opts.trigger]
   */
  async function verify({ mode = 'INCREMENTAL', trigger = 'MANUAL' } = {}) {
    const startedAt = Date.now();
    const orderingMode = _auditLog.ORDERING_MODE === 'distributed' ? 'distributed' : 'single-node';

    _metrics.auditChainVerifierRunsTotal?.inc({ mode, trigger });
    _metrics.auditChainVerifierActive?.set({}, 1);

    let outcome;
    try {
      if (orderingMode === 'distributed') {
        outcome = await _verifyPgAuthoritative(mode);
      } else {
        outcome = mode === 'FULL' ? await _verifyFileModeFull() : await _verifyFileModeIncremental();
      }
      if (mode === 'FULL' && !outcome.skipped) {
        const consentViolations = await _verifyConsentAudit();
        if (consentViolations.length) outcome.violations.push(...consentViolations);
      }
    } catch (err) {
      _metrics.auditChainVerifierActive?.set({}, 0);
      _metrics.auditChainVerifierFailureTotal?.inc({ mode, reason: 'ENGINE_ERROR' });
      _emit('ERROR', 'AUDIT_CHAIN_VERIFIER_SCAN_FAILED', { source: SOURCE, mode, trigger, error: err.message });
      _lastResult = { success: false, mode, trigger, error: err.message, durationMs: Date.now() - startedAt };
      return _lastResult;
    }

    const durationMs = Date.now() - startedAt;
    _metrics.auditChainVerifierActive?.set({}, 0);
    _metrics.auditChainVerifierDurationSeconds?.observe({ mode }, durationMs / 1000);

    if (outcome.skipped) {
      _metrics.auditChainVerifierSkippedTotal?.inc({ reason: outcome.reason });
      _lastResult = { success: true, skipped: true, reason: outcome.reason, mode, trigger, durationMs, repairAttempts: 0, repairSupported: false };
      return _lastResult;
    }

    // Persist the new watermark (best-effort — see verifierState.js's
    // comment on why a failed watermark write is never treated as fatal).
    if (outcome.newWatermark) {
      if (orderingMode === 'distributed') {
        await _verifierState.savePgState({
          lastVerifiedSeq:  outcome.newWatermark.seq,
          lastVerifiedHash: outcome.newWatermark.hash,
          lastScanMode:     mode,
          lastScanTrigger:  trigger,
          lastScanAt:       new Date(),
          lastFullScanAt:   mode === 'FULL' ? new Date() : null,
          lastScanDurationMs: durationMs,
          lastScanViolationsDetected: outcome.violations.length,
          lastScanEntriesChecked:     outcome.entriesChecked,
        }).catch((err) => _emit('WARN', 'AUDIT_CHAIN_VERIFIER_STATE_SAVE_FAILED', { store: 'pg', mode, trigger, error: err.message })); //
      } else {
        await _verifierState.saveFileState({
          lastVerifiedIndex: outcome.newWatermark.index,
          lastVerifiedHash:  outcome.newWatermark.hash,
          lastScanMode:      mode,
          lastScanTrigger:   trigger,
          lastScanAt:        new Date().toISOString(),
          lastFullScanAt:    mode === 'FULL' ? new Date().toISOString() : undefined,
          lastScanDurationMs: durationMs,
          lastScanViolationsDetected: outcome.violations.length,
          lastScanEntriesChecked:     outcome.entriesChecked,
        }).catch((err) => _emit('WARN', 'AUDIT_CHAIN_VERIFIER_STATE_SAVE_FAILED', { store: 'file', mode, trigger, error: err.message })); //
      }
    }

    _metrics.auditChainVerifierEntriesCheckedTotal?.inc({}, outcome.entriesChecked || 0);
    _metrics.auditChainVerifierWatermarkPosition?.set({}, outcome.newWatermark
      ? (outcome.newWatermark.index ?? outcome.newWatermark.seq ?? 0)
      : 0);

    if (outcome.violations.length > 0) {
      _reportViolations(outcome.violations, trigger);
      _metrics.auditChainVerifierFailureTotal?.inc({ mode, reason: 'VIOLATIONS_DETECTED' });
      _metrics.auditChainVerifierLastViolationTimestamp?.set({}, Math.floor(Date.now() / 1000));
    } else {
      _metrics.auditChainVerifierSuccessTotal?.inc({ mode });
      _metrics.auditChainVerifierLastSuccessTimestamp?.set({}, Math.floor(Date.now() / 1000));
    }

    _emit('INFO', 'AUDIT_CHAIN_VERIFIER_SCAN_COMPLETED', {
      source: SOURCE, mode, trigger, durationMs,
      entriesChecked:     outcome.entriesChecked,
      violationsDetected: outcome.violations.length,
    });

    _lastResult = {
      success: true,
      mode, trigger, durationMs,
      entriesChecked: outcome.entriesChecked,
      violations:     outcome.violations,
      // for the runner's verifier-lag metric and its not-completing escalation
      watermarkIndex: outcome.newWatermark ? (outcome.newWatermark.index ?? null) : null,
      caughtUp:       outcome.caughtUp !== false,
      repairAttempts: 0,
      repairSupported: false,
    };
    return _lastResult;
  }

  // ── S3: prune-aware orphan rule (shared by the full and the layered verifier) ─────────────────────────────
  // The ONE missing parent that is not an orphan: the recorded signed prune anchor — chain rebased onto a signed base
  // whose checkpoint has an integer pgSeq, audit_chain_prunes records that checkpoint, and the orphan row IS that
  // checkpoint's row (seq = pgSeq, hash = headHash). Returns true only when all three hold.
  async function _excusedPruneAnchor(brokenLinks) {
    const start = _chainStart();
    const p = start && start.startCount > 0 && start.checkpoint && start.checkpoint.payload ? start.checkpoint.payload : null;
    if (!p || !Number.isInteger(p.pgSeq) || typeof _pgBackend.listChainLinkOrphans !== 'function' || typeof _pgBackend.isPruneRecorded !== 'function') return false;
    const orphans = await _pgBackend.listChainLinkOrphans(Math.max(1, brokenLinks));
    const anchor = orphans.find((o) => o.seq === p.pgSeq && o.hash === p.headHash);
    if (!anchor || !(await _pgBackend.isPruneRecorded(p.checkpointId))) return false;
    _emit('INFO', 'AUDIT_CHAIN_VERIFIER_PRUNE_ANCHOR_EXCUSED', { source: SOURCE, checkpointId: p.checkpointId, seq: p.pgSeq, headHash: p.headHash });
    return true;
  }

  // ── S3: layered divergence verifier ───────────────────────────
  //
  //   PG_INCREMENTAL (60 s)  verifyPgDivergenceIncremental(): compare the file and audit_chain from the persisted
  //                          'incremental' position to the end of what both hold; persist at verified page boundaries.
  //                          No saved position (first run, after a prune, after a reset): ONE streamed pass from the
  //                          chain base, persisted every PERSIST_EVERY_ROWS (partial-progress recovery).
  //   PG_DIVERGENCE (15 min) verifyPgDivergenceRolling(): every signed checkpoint re-checked (signature + its PG row),
  //                          then one sweep slice of SWEEP_SLICE_ROWS over the verified prefix [base, incremental].
  //   MANUAL / fallback      verifyPgDivergence(): the full comparison above, unchanged except the prune-aware fix.
  //
  // Same comparison rule as the full path, position by position: hash, prevHash, sha256(canonical) (the compact form),
  // PG rows in hash-link order. Any disagreement, unlinked PG row, anchor mismatch or invalid saved position hands the
  // VERDICT to the full verifier, so reported violations are the full verifier's own. Positions are written only after
  // their range verified, and only by the holder of the existing verifier advisory lock.
  const SWEEP_SLICE_ROWS = Number.isInteger(config.sweepSliceRows) && config.sweepSliceRows > 0 ? config.sweepSliceRows : 20_000;   // approved
  const PERSIST_EVERY_ROWS = Number.isInteger(config.persistEveryRows) && config.persistEveryRows > 0 ? config.persistEveryRows : 20_000;
  const DIVERGENCE_PG_PAGE = 2000;
  const FALLBACK_MIN_INTERVAL_MS = Number.isFinite(config.pgDivergenceIntervalMs) && config.pgDivergenceIntervalMs >= 0 ? config.pgDivergenceIntervalMs : 900_000;
  let _lastFallbackAt = -Infinity;
  let _incompleteSince = null;

  function _layeredApplicable() {
    if (_auditLog.ORDERING_MODE === 'distributed') return 'DISTRIBUTED_MODE';
    if (!_pgPool.isEnabled()) return 'PG_DISABLED';
    if (config.divergenceMode === 'full') return 'DIVERGENCE_MODE_FULL';
    if (typeof _auditLog.getModernChainPage !== 'function' || typeof _pgBackend.fetchChainBatch !== 'function'
      || typeof _pgBackend.loadVerificationProgress !== 'function') return 'LAYERED_UNSUPPORTED';
    return null;
  }

  function _baseCursor() {
    const start = _chainStart();
    if (start && start.startCount > 0) {
      const p = start.checkpoint && start.checkpoint.payload ? start.checkpoint.payload : null;
      if (!p || !Number.isInteger(p.pgSeq)) return { skip: 'REBASED_WITHOUT_PG_SEQ' };
      return { pos: start.startCount, byteOffset: null, prevHash: start.startHash, pgSeq: p.pgSeq, baseCheckpointId: p.checkpointId || null };
    }
    return { pos: 0, byteOffset: null, prevHash: 'GENESIS', pgSeq: 0, baseCheckpointId: null };
  }
  const _isBase = (c, base) => c.pos === base.pos && c.byteOffset === null && c.prevHash === base.prevHash && c.pgSeq === base.pgSeq;

  function _readFile(c, limit) {
    const cursor = c.byteOffset !== null ? { m: c.pos, o: c.byteOffset } : { m: c.pos };
    return _auditLog.getModernChainPage({ cursor, limit, durable: true });
  }

  // null = valid; otherwise the reason it cannot be trusted. Never repairs.
  async function _validateCursor(c, base) {
    if ((c.baseCheckpointId || null) !== (base.baseCheckpointId || null)) return 'BASE_CHANGED';
    if (_isBase(c, base)) return null;
    if (c.pos < base.pos) return 'BEFORE_BASE';
    if (c.byteOffset === null) return 'NO_BYTE_OFFSET';
    const stats = _auditLog.getChainStats();
    if (c.pos > stats.modernLength) return 'BEYOND_FILE';
    if (c.pos < stats.modernLength) {
      const page = await _readFile(c, 1);
      const e = page.entries[0];
      if (!e || e.prevHash !== c.prevHash || page.startPos !== c.pos) return 'FILE_POSITION_MISMATCH';
    } else if (stats.tailHash !== c.prevHash) {
      return 'FILE_TAIL_MISMATCH';
    }
    if (c.pgSeq > 0) {
      const h = await _pgBackend.fetchRowBySeq(c.pgSeq);
      if (!h || String(h).trim() !== c.prevHash) return 'PG_POSITION_MISMATCH';
    }
    return null;
  }

  // Compares from cursor c. maxRows/stopPos bound the file side (Infinity = to the end).
  //   OK         everything up to the bound / the end of both sides compared equal
  //   INCOMPLETE benign: PG behind the file (in-flight mirror tail), or PG ahead of this file view, or PG rows still
  //              waiting for a parent when stopped at a bound
  //   DISAGREE   a position differs, a fork, or a PG row that can never link
  // `boundary` = the last verified page boundary (a cursor with a byte offset) — the only positions ever persisted.
  async function _compareFrom(c, { maxRows = Infinity, stopPos = Infinity, onBoundary = null } = {}) {
    const linker = createStreamingLinker(c.prevHash);
    const pgQueue = [];
    let pgFrom = c.pgSeq; let pgDone = false; let rowsRead = 0;
    const pullPg = async () => {
      const rows = await _pgBackend.fetchChainBatch(pgFrom, DIVERGENCE_PG_PAGE);
      rowsRead += rows.length;
      if (rows.length < DIVERGENCE_PG_PAGE) pgDone = true;
      if (rows.length === 0) return;
      pgFrom = Number(rows[rows.length - 1].seq);
      const ordered = linker.push(rows.map((r) => ({ ..._compactForDivergence(r), seq: Number(r.seq) })));
      for (const o of ordered) pgQueue.push(o);
    };
    let cur = { ...c }; let compared = 0; let boundary = null; let lastPgSeq = c.pgSeq;
    const result = (status, reason, extra = {}) => ({ status, reason, compared, boundary, rowsRead, end: cur, ...extra });
    try {
      for (;;) {
        if (compared >= maxRows || cur.pos >= stopPos) {
          return linker.pending().length ? result('INCOMPLETE', 'PG_PENDING_AT_BOUND') : result('OK', 'BOUND');
        }
        const want = Math.min(DIVERGENCE_FILE_PAGE, maxRows - compared, stopPos - cur.pos);
        const page = await _readFile(cur, want);
        const entries = page.entries;
        if (entries.length === 0) break;
        for (let i = 0; i < entries.length; i++) {
          while (pgQueue.length === 0 && !pgDone) await pullPg();
          if (pgQueue.length === 0) {
            // PG is exhausted. Rows still waiting for a parent can never link (a deleted or re-pointed row): a real
            // disagreement. Otherwise PG simply has not caught up with the file yet (in-flight mirror tail).
            if (linker.pending().length) return result('DISAGREE', 'PG_UNLINKED_ROWS', { at: cur.pos + i, unlinked: linker.pending().length });
            return result('INCOMPLETE', 'PG_BEHIND_FILE', { at: cur.pos + i });
          }
          const fe = _compactForDivergence(entries[i]); const p = pgQueue.shift();
          if (fe.hash !== p.hash || fe.prevHash !== p.prevHash || fe.canonical !== p.canonical) {
            return result('DISAGREE', 'POSITIONAL_MISMATCH', { at: cur.pos + i, fileHash: fe.hash, pgHash: p.hash });
          }
          lastPgSeq = p.seq; compared++;
        }
        const last = entries[entries.length - 1];
        const nextO = page.nextCursor && Number.isInteger(page.nextCursor.o) ? page.nextCursor.o : null;
        cur = { pos: cur.pos + entries.length, byteOffset: nextO, prevHash: last.hash, pgSeq: lastPgSeq, baseCheckpointId: c.baseCheckpointId || null };
        if (nextO !== null) { boundary = { ...cur }; if (onBoundary) await onBoundary(boundary, compared); }
        if (!page.nextCursor) break;
        await _yieldNow();
      }
      // The file ends here. Anything left on the PG side?
      if (pgQueue.length === 0 && !pgDone) await pullPg();
      if (pgQueue.length > 0) return result('INCOMPLETE', 'PG_AHEAD_OF_FILE');
      while (!pgDone) await pullPg();
      if (linker.pending().length) return result('DISAGREE', 'PG_UNLINKED_ROWS', { unlinked: linker.pending().length });
      return result('OK', 'END');
    } catch (e) {
      if (e && (e.code === 'HASH_LINK_FORK' || e.code === 'HASH_LINK_PENDING_OVERFLOW')) return result('DISAGREE', e.code);
      throw e;
    }
  }

  // The full verifier as the verdict, at most once per pgDivergenceIntervalMs (today's cadence for a violation state).
  async function _fallbackToFull(trigger, why, detail = {}) {
    const now = monoNowMs(); // monotonic (same-process)
    const rateLimited = now - _lastFallbackAt < FALLBACK_MIN_INTERVAL_MS;
    _emit('WARN', 'AUDIT_CHAIN_VERIFIER_DIVERGENCE_FALLBACK', { source: SOURCE, trigger, reason: why, rateLimited, ...detail });
    if (rateLimited) return { ran: false, rateLimited: true };
    _lastFallbackAt = now;
    const full = await verifyPgDivergence(trigger);
    return { ran: true, result: full };
  }

  // Runs fn while holding the existing verifier advisory lock (transaction-scoped, on its own connection). Progress
  // writes are autocommit on other connections, so each verified boundary is durable at once; the lock only guarantees
  // that no other process advances the same state meanwhile.
  async function _withProgressLock(fn) {
    return _pgPool.withTransaction(async (tx) => {
      const r = await tx.query('SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint) AS acquired', [LOCK_KEY]);
      if (!r.rows[0].acquired) return { skipped: true, reason: 'LOCK_NOT_ACQUIRED' };
      return fn();
    }, { isolationLevel: 'READ COMMITTED' });
  }

  async function _loadValidated(kind, base, trigger) {
    const saved = await _pgBackend.loadVerificationProgress(kind);
    if (!saved) return { cursor: { ...base }, fresh: true, saved: null };
    const bad = await _validateCursor(saved, base);
    if (!bad) return { cursor: saved, fresh: false, saved };
    _emit('WARN', 'AUDIT_CHAIN_VERIFICATION_PROGRESS_RESET', { source: SOURCE, kind, trigger, reason: bad, savedPos: saved.pos, basePos: base.pos,
      message: 'The saved verification position could not be validated against the file and audit_chain; it is discarded (reset to the chain base), never repaired.' });
    await _pgBackend.saveVerificationProgress(kind, base, kind === 'sweep' ? { cycleStartedAt: new Date(), cyclesCompleted: saved.cyclesCompleted || 0 } : {});
    return { cursor: { ...base }, fresh: true, reset: bad, saved };
  }

  /** PG_INCREMENTAL (60 s): new rows since the persisted position. */
  async function verifyPgDivergenceIncremental(trigger = 'SCHEDULED') {
    const na = _layeredApplicable();
    if (na) return { success: true, skipped: true, reason: na, trigger };
    const base = _baseCursor();
    if (base.skip) {
      _emit('WARN', 'AUDIT_CHAIN_VERIFIER_DIVERGENCE_SKIPPED', { source: SOURCE, reason: base.skip,
        message: 'The signed base record carries no PG seq: the file and the PG mirror cannot be aligned after the prune.' });
      return { success: true, skipped: true, reason: base.skip, trigger };
    }
    const startedAt = Date.now();
    const out = await _withProgressLock(async () => {
      const { cursor, reset } = await _loadValidated('incremental', base, trigger);
      if (reset) {
        await _pgBackend.saveVerificationProgress('sweep', base, { cycleStartedAt: new Date() });
        const fb = await _fallbackToFull(trigger, 'INVALID_SAVED_POSITION', { savedPositionReason: reset });
        return { status: 'RESET', reset, fallback: fb, compared: 0 };
      }
      let lastPersistedCompared = 0;
      const r = await _compareFrom(cursor, {
        onBoundary: async (b, compared) => {
          if (compared - lastPersistedCompared >= PERSIST_EVERY_ROWS) { await _pgBackend.saveVerificationProgress('incremental', b); lastPersistedCompared = compared; }
        },
      });
      if (r.boundary) await _pgBackend.saveVerificationProgress('incremental', r.boundary);   // write-after-verify
      if (r.status === 'DISAGREE') {
        _incompleteSince = null;
        return { ...r, fallback: await _fallbackToFull(trigger, r.reason, { at: r.at ?? null }) };
      }
      if (r.status === 'INCOMPLETE' && !r.boundary) {
        _incompleteSince = _incompleteSince ?? monoNowMs(); // monotonic (same-process)
        if (monoNowMs() - _incompleteSince > FALLBACK_MIN_INTERVAL_MS) return { ...r, fallback: await _fallbackToFull(trigger, `STALLED_${r.reason}`) };
      } else {
        _incompleteSince = null;
      }
      return r;
    });
    if (out.skipped) return { success: true, skipped: true, reason: out.reason, trigger };
    const position = await _pgBackend.loadVerificationProgress('incremental');
    return { success: true, trigger, mode: 'PG_INCREMENTAL', status: out.status, reason: out.reason, entriesChecked: out.compared, pgRowsRead: out.rowsRead ?? 0,
      position: position ? position.pos : null, durationMs: Date.now() - startedAt,
      violations: out.fallback && out.fallback.ran ? (out.fallback.result.violations || []) : [], fallback: out.fallback || null };
  }

  // Every signed checkpoint at or after the base: signature verifies, and its PG row carries headHash. File-side anchors
  // are not read here (outside the in-memory window that is an O(n) file scan); the incremental layer, the sweep and
  // the 4-hourly FULL file scan cover the file.
  async function _checkAnchors(base) {
    const cps = typeof _pgBackend.listSignedCheckpoints === 'function' ? await _pgBackend.listSignedCheckpoints() : [];
    const mismatches = []; const unverifiable = []; let checked = 0;
    for (const cp of cps) {
      const p = cp && cp.payload;
      if (!p || !Number.isInteger(p.pgSeq) || p.pgSeq < base.pgSeq) continue;
      checked++;
      const sig = _checkpointVerify(cp);
      // A signature that verifies FALSE is a mismatch. One that cannot be checked here (the key is not in this process's
      // checkpoint key store) is reported, not treated as a chain disagreement: the full comparison does not check
      // checkpoint signatures either (the boot check is the fail-closed authority), so falling back would only bring back
      // the periodic O(n) scan. The PG row is still checked.
      if (!sig.ok && /^CHECKPOINT_(KEY_UNAVAILABLE|VERIFY_ERROR)/.test(String(sig.reason))) unverifiable.push({ checkpointId: p.checkpointId, reason: sig.reason });
      else if (!sig.ok) { mismatches.push({ checkpointId: p.checkpointId, reason: sig.reason }); continue; }
      const h = await _pgBackend.fetchRowBySeq(p.pgSeq);
      if (!h || String(h).trim() !== p.headHash) mismatches.push({ checkpointId: p.checkpointId, reason: 'PG_ROW_HASH_MISMATCH', pgSeq: p.pgSeq });
    }
    return { checked, mismatches, unverifiable };
  }

  /** PG_DIVERGENCE (15 min): anchors + one sweep slice. divergenceMode 'full' = the previous full comparison. */
  async function verifyPgDivergenceRolling(trigger = 'SCHEDULED') {
    if (config.divergenceMode === 'full') return verifyPgDivergence(trigger);
    const na = _layeredApplicable();
    if (na) return { success: true, skipped: true, reason: na, trigger };
    const base = _baseCursor();
    if (base.skip) return { success: true, skipped: true, reason: base.skip, trigger };
    const startedAt = Date.now();
    const out = await _withProgressLock(async () => {
      const anchors = await _checkAnchors(base);
      if (anchors.unverifiable.length) {
        _emit('WARN', 'AUDIT_CHAIN_VERIFIER_ANCHOR_UNVERIFIABLE', { source: SOURCE, trigger, unverifiable: anchors.unverifiable.slice(0, 20), checked: anchors.checked,
          message: 'Signed checkpoint signatures could not be verified here (key not in this process); their PG rows were still checked.' });
      }
      if (anchors.mismatches.length) {
        _emit('WARN', 'AUDIT_CHAIN_VERIFIER_ANCHOR_MISMATCH', { source: SOURCE, trigger, mismatches: anchors.mismatches.slice(0, 20), checked: anchors.checked });
        return { anchors, fallback: await _fallbackToFull(trigger, 'ANCHOR_MISMATCH') };
      }
      const inc = await _pgBackend.loadVerificationProgress('incremental');
      if (!inc || (await _validateCursor(inc, base))) return { anchors, sweep: { status: 'NO_VERIFIED_PREFIX' } };
      const { cursor: s0, reset, saved } = await _loadValidated('sweep', base, trigger);
      if (reset) return { anchors, sweep: { status: 'RESET', reset }, fallback: await _fallbackToFull(trigger, 'INVALID_SAVED_POSITION', { kind: 'sweep', savedPositionReason: reset }) };
      const cyclesCompleted = saved ? saved.cyclesCompleted || 0 : 0;
      const cycleStartedAt = _isBase(s0, base) || !saved ? new Date() : saved.cycleStartedAt;
      if (s0.pos >= inc.pos) return { anchors, sweep: { status: 'NOTHING_TO_SWEEP' } };
      const r = await _compareFrom(s0, { maxRows: SWEEP_SLICE_ROWS, stopPos: inc.pos,
        onBoundary: async (b) => { await _pgBackend.saveVerificationProgress('sweep', b, { cycleStartedAt, cyclesCompleted }); } });
      // Inside the verified prefix PG must hold every row: anything but a clean slice (or rows merely waiting at the
      // slice bound) is a disagreement.
      if (r.status === 'DISAGREE' || (r.status === 'INCOMPLETE' && r.reason !== 'PG_PENDING_AT_BOUND')) {
        return { anchors, sweep: r, fallback: await _fallbackToFull(trigger, `SWEEP_${r.reason}`, { at: r.at ?? null }) };
      }
      if (r.boundary && r.boundary.pos >= inc.pos) {
        const cycleMs = cycleStartedAt ? Date.now() - new Date(cycleStartedAt).getTime() : null;
        await _pgBackend.saveVerificationProgress('sweep', base, { cycleStartedAt: new Date(), cyclesCompleted: cyclesCompleted + 1, lastCycleMs: cycleMs });
        _emit('INFO', 'AUDIT_CHAIN_SWEEP_COMPLETED', { source: SOURCE, trigger, rows: inc.pos - base.pos, cycleMs, cyclesCompleted: cyclesCompleted + 1 });
        return { anchors, sweep: { ...r, cycleCompleted: true } };
      }
      return { anchors, sweep: r };
    });
    if (out.skipped) return { success: true, skipped: true, reason: out.reason, trigger };
    const violations = out.fallback && out.fallback.ran ? (out.fallback.result.violations || []) : [];
    const result = { success: true, trigger, mode: 'PG_DIVERGENCE', layered: true, durationMs: Date.now() - startedAt,
      anchorsChecked: out.anchors.checked, anchorMismatches: out.anchors.mismatches.length,
      sweep: out.sweep ? { status: out.sweep.status, reason: out.sweep.reason, rows: out.sweep.compared ?? 0, cycleCompleted: !!out.sweep.cycleCompleted } : null,
      entriesChecked: out.sweep ? out.sweep.compared ?? 0 : 0, violations, fallback: out.fallback || null };
    _emit('INFO', 'AUDIT_CHAIN_VERIFIER_PG_DIVERGENCE_CHECK_COMPLETED', { source: SOURCE, trigger, layered: true, durationMs: result.durationMs,
      entriesChecked: result.entriesChecked, anchorsChecked: result.anchorsChecked, violationsDetected: violations.length });
    return result;
  }

  // advance the startup mirror checkpoint to the newest signed checkpoint after re-running the
  // boot fast path's checks over that range (mirrorConsistencyCheck.advanceMirrorCheckpoint — invariants I-1..I-10 in
  //). Diagnoses and records only.
  async function advanceMirrorCheckpoint(trigger = 'SCHEDULED') {
    if (typeof _mirrorCheck.advanceMirrorCheckpoint !== 'function') return { success: true, skipped: true, reason: 'UNSUPPORTED', trigger };
    try {
      return await _mirrorCheck.advanceMirrorCheckpoint({ _pgPool, _pgAuditBackend: _pgBackend, _auditLog, _emit, _checkpointVerify, trigger });
    } catch (err) {
      _emit('ERROR', 'AUDIT_MIRROR_CHECKPOINT_ADVANCE_FAILED', { source: SOURCE, trigger, error: err.message,
        message: 'The run failed before writing anything; the latest mirror checkpoint is unchanged.' });
      return { success: false, trigger, error: err.message };
    }
  }

  /** @param {'STARTUP'|'SCHEDULED'|'MANUAL'} [trigger] */
  async function verifyPgDivergence(trigger = 'SCHEDULED') {
    const startedAt = Date.now();
    let outcome;
    try {
      outcome = await _verifyPgDivergence();
    } catch (err) {
      _emit('ERROR', 'AUDIT_CHAIN_VERIFIER_PG_DIVERGENCE_CHECK_FAILED', { source: SOURCE, trigger, error: err.message });
      return { success: false, trigger, error: err.message };
    }

    if (outcome.skipped) {
      return { success: true, skipped: true, reason: outcome.reason, trigger };
    }

    const durationMs = Date.now() - startedAt;
    if (outcome.violations.length > 0) _reportViolations(outcome.violations, trigger);

    _emit('INFO', 'AUDIT_CHAIN_VERIFIER_PG_DIVERGENCE_CHECK_COMPLETED', {
      source: SOURCE, trigger, durationMs,
      entriesChecked:     outcome.entriesChecked,
      violationsDetected: outcome.violations.length,
    });

    return {
      success: true, trigger, durationMs,
      entriesChecked: outcome.entriesChecked,
      violations:     outcome.violations,
    };
  }

  return {
    verify,
    verifyPgDivergence,                // full comparison: MANUAL and the layered verifier's fallback
    verifyPgDivergenceIncremental,     // S3: 60 s new-row layer
    verifyPgDivergenceRolling,         // S3: 15 min anchors + sweep slice
    advanceMirrorCheckpoint,           // runtime mirror-checkpoint advancement (after the 15 min run)
    getLastResult: () => _lastResult,
  };
}

module.exports = { createChainVerifier, _compactForDivergence };
