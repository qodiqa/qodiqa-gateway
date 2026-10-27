'use strict';

/**
 * Live Audit Chain Verifier — Startup Watermark-Continuity Gate (CHAIN-2)
 *
 * ROOT CAUSE: mirrorConsistencyCheck.js's startup gate
 * compares the file chain against the PostgreSQL mirror at a single point in
 * time — but it has no memory of anything from a PREVIOUS process run. A
 * coordinated rollback of BOTH the file and its PG mirror to an older,
 * mutually-consistent backup would pass that check (the two stores still
 * agree with each other) and pass audit-log.js's own load-time hash-chain
 * walk (the restored history is still internally a valid chain) — yet it is
 * a real, and plausible, tampering scenario. This gate closes that gap by
 * comparing the current durable state against a watermark this SAME
 * deployment already confirmed durable in a past run (persisted by the live
 * verifier — src/core/audit/verifier/verifierState.js).
 *
 * PERFORMANCE — NO REDUNDANT FULL WALK:
 *   By the time this gate runs, audit-log.js's own startup load
 *   (loadFromDisk()'s IIFE, or hydrateFromPgIfDistributed()) has ALREADY
 *   performed a full O(n) hash-chain walk of the entire durable chain and
 *   would have refused to boot on any internal inconsistency. This gate does
 *   not repeat that work. It only asks: does the entry this deployment
 *   previously confirmed at a specific position still have the same hash at
 *   that position? That is a single O(1) lookup (an array index in file
 *   mode; an indexed point SELECT in PG mode — see
 *   pg-audit-backend.js's fetchRowBySeq()/getMaxSeq()), not a scan.
 *
 * FAIL-CLOSED / NO AUTO-REPAIR — same posture as mirrorConsistencyCheck.js:
 *   Any divergence is FATAL by default (process exits non-zero before
 *   accepting a single request). QODIQA_AUDIT_VERIFIER_RECOVERY_MODE=true
 *   (naming mirrors QODIQA_AUDIT_MIRROR_RECOVERY_MODE) downgrades this to a
 *   WARN and lets startup proceed in a supervised, degraded state — it never
 *   reconciles, repairs, or picks a "right" copy automatically.
 *
 * NO PRIOR WATERMARK is not an anomaly (first-ever run of this verifier, or
 * a brand-new deployment) — the gate seeds the watermark from the current,
 * already-trusted state (this deployment's own load-time walk) so the live
 * verifier's first background tick starts from "now", not from genesis.
 */

const { emit: _defaultEmit }        = require('../../../services/logger');
const { writeDiagnostic: _writeDiagnostic } = require('../../runtime/rawStderrDiagnostic');
const _defaultAuditLog              = require('./audit-log');
const _defaultPgPool                = require('../../infra/postgres/pool');
const _defaultPgBackend             = require('../../infra/postgres/pg-audit-backend');
const _defaultVerifierState         = require('./verifier/verifierState');
const _defaultMetrics               = require('../../observability/metrics');

// Bypasses the shared logger for FATAL/WARN diagnostics — same rationale as
// mirrorConsistencyCheck.js's _writeDiagnostic: the shared logger's central
// store sink is PG-backed, and a PG-reachability problem is exactly one of
// the failure modes this gate exists to catch in distributed mode. See
// src/runtime/rawStderrDiagnostic.js for the single shared
// implementation of this fail-safe write path.

async function _handleDivergence({ recoveryMode, _exit, _metrics, _env, _emit, reason, detail }) {
  const diagnostics = {
    reason: 'A prior run of this deployment already confirmed the audit chain durable up to a specific ' +
            'position; the durable record loaded at this startup no longer agrees with that confirmed position.',
    violationType: reason,
    ...detail,
    action: 'Do not restart until this is resolved by an operator. Possible causes: audit.log (or, in ' +
            'distributed mode, audit_chain) was restored from an older backup, truncated, or replaced — ' +
            'including a coordinated rollback of both the file and its PostgreSQL mirror together, which ' +
            'mirrorConsistencyCheck.js\'s file-vs-PG comparison alone cannot detect. This check never repairs ' +
            'or reconciles automatically.',
    ref: 'docs/protocol/AUDIT-SCHEMA-V8.md',
  };

  _metrics.auditChainVerifierFailureTotal?.inc({ mode: 'STARTUP', reason: 'CONTINUITY_VIOLATION' });

  if (recoveryMode) {
    _writeDiagnostic('WARN', 'AUDIT_CHAIN_VERIFIER_RECOVERY_MODE_ENGAGED', {
      ...diagnostics,
      recoveryModeEngaged: true,
      action: 'QODIQA_AUDIT_VERIFIER_RECOVERY_MODE=true — startup is proceeding DESPITE the divergence above. ' +
              'No automatic reconciliation, overwrite, or repair has occurred. ' + diagnostics.action,
    });

    // QODIQA_AUDIT_VERIFIER_FULL_ON_WATERMARK_MISMATCH (default true): once
    // an operator has explicitly opted into booting in a known-degraded
    // state, immediately run a full from-disk/from-PG scan so complete
    // forensics (every violation, not just the first one this O(1) gate
    // found) are available right away rather than waiting for the next
    // scheduled FULL tick (default interval: 24h). This never blocks
    // startup on failure — a forensics-scan error is logged and swallowed,
    // never escalated to FATAL, since the process is already proceeding in
    // a supervised degraded state by the operator's own choice.
    if (_env.QODIQA_AUDIT_VERIFIER_FULL_ON_WATERMARK_MISMATCH !== 'false') {
      try {
        const { createChainVerifier } = require('./verifier/ChainVerifier');
        const verifier = createChainVerifier();
        await verifier.verify({ mode: 'FULL', trigger: 'STARTUP' });
      } catch (err) {
        _emit('ERROR', 'AUDIT_CHAIN_VERIFIER_RECOVERY_FORENSICS_SCAN_FAILED', { error: err.message });
      }
    }

    return true;
  }

  _writeDiagnostic('FATAL', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_VIOLATION', diagnostics);
  _exit(1);
  return false;
}

/**
 * Must be called once at startup, after the existing mirror-consistency gate
 * and (in distributed mode) after hydrateFromPgIfDistributed(). All
 * dependencies are injectable for testing.
 *
 * @returns {Promise<boolean>} true if startup may proceed (false only after
 *   this function has already called _exit(1)) — same contract as
 *   verifyMirrorConsistency().
 */
async function verifyChainVerifierContinuity({
  _env           = process.env,
  _auditLog      = _defaultAuditLog,
  _pgPool        = _defaultPgPool,
  _pgBackend     = _defaultPgBackend,
  _verifierState = _defaultVerifierState,
  _metrics       = _defaultMetrics,
  _exit          = (code) => process.exit(code),
  _emit          = _defaultEmit,
} = {}) {
  const orderingMode = _env.QODIQA_AUDIT_ORDERING_MODE === 'distributed' ? 'distributed' : 'single-node';
  const recoveryMode = _env.QODIQA_AUDIT_VERIFIER_RECOVERY_MODE === 'true';

  const stats = _auditLog.getChainStats();
  const currentLength = stats.modernLength;

  // ── Distributed / PG-authoritative mode ─────────────────────────────────
  if (orderingMode === 'distributed') {
    if (!_pgPool.isEnabled()) {
      // Unreachable in a correctly configured deployment (multiInstanceGuard
      // already requires PG for distributed mode) — treat as a skip rather
      // than fail, since there is nothing this gate can check.
      _emit('INFO', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_CHECK_SKIPPED', { reason: 'PG_DISABLED' });
      return true;
    }

    let watermark;
    try {
      watermark = await _verifierState.loadPgState();
    } catch (err) {
      _writeDiagnostic('FATAL', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_CHECK_FAILED', {
        reason: 'Could not load the audit chain verifier watermark from PostgreSQL.',
        error:  err.message,
        action: 'Verify QODIQA_PG_* connectivity and that migration 031 has been applied, then restart.',
        ref:    'docs/protocol/AUDIT-SCHEMA-V8.md',
      });
      _exit(1);
      return false;
    }

    // a FAILED continuity query used to read as "no rows" (null) — misreported as TRUNCATION /
    // WATERMARK_RECORD_MISSING, and accepted outright in the genesis case. A query failure is now its own fail-closed
    // outcome, exactly like a failed watermark load above: the continuity of the chain could not be checked.
    const _queryFailed = (what, err) => {
      _writeDiagnostic('FATAL', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_CHECK_FAILED', {
        reason: `Could not ${what} from PostgreSQL, so audit-chain continuity could not be checked.`,
        error:  err && err.message,
        action: 'Verify QODIQA_PG_* connectivity, then restart.',
        ref:    'docs/protocol/AUDIT-SCHEMA-V8.md',
      });
      _exit(1);
      return false;
    };

    if (!watermark || watermark.last_verified_seq == null) {
      let maxSeq;
      try { maxSeq = await _pgBackend.getMaxSeq(); } catch (err) { return _queryFailed('read the audit_chain tail position', err); }
      await _verifierState.savePgState({
        lastVerifiedSeq:  maxSeq,
        lastVerifiedHash: stats.tailHash === 'GENESIS' ? null : stats.tailHash,
        lastScanMode:     'NONE',
        lastScanTrigger:  'STARTUP',
        lastScanAt:       new Date(),
      }).catch((err) => _emit('WARN', 'AUDIT_CHAIN_VERIFIER_STATE_SAVE_FAILED', { stage: 'STARTUP_SEED', error: err.message }));
      _emit('INFO', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_SEEDED', { orderingMode, currentLength, seededSeq: maxSeq });
      return true;
    }

    const watermarkSeq  = Number(watermark.last_verified_seq);
    const watermarkHash = watermark.last_verified_hash;

    let currentMaxSeq;
    try { currentMaxSeq = await _pgBackend.getMaxSeq(); } catch (err) { return _queryFailed('read the audit_chain tail position', err); }

    // getMaxSeq() returns null for a genuinely empty audit_chain table
    // (SQL MAX() over zero rows), which is indistinguishable by value from a
    // query failure — the pre-existing .catch(() => null) above already
    // accepts that ambiguity for the general case. Without this guard, a
    // deployment whose chain was still empty when the live background
    // verifier last confirmed the watermark (watermarkSeq 0, GENESIS) would
    // hit this exact null on every later boot, because an empty table's max
    // is ALWAYS null, not 0 — permanently FATAL-ing on a chain that was
    // never actually touched, let alone truncated. Reproduced directly: a
    // fresh distributed-mode deployment, confirmed healthy and left running
    // long enough for one scheduled verifier tick, then restarted before any
    // audit-worthy event was ever logged, refused to boot again with this
    // exact FATAL. Only the genesis-to-genesis case is treated as
    // consistent; any watermark that ever recorded a real entry
    // (watermarkSeq > 0) still fails closed exactly as before on a null
    // currentMaxSeq — that remains the real truncation signature this gate
    // exists to catch.
    // The genesis case has no anchor row to fetch (seq 0 predates the first
    // real entry), so it must short-circuit here with VERIFIED rather than
    // just skipping the truncation check below and falling through into the
    // anchor-hash-fetch logic, which would then itself (correctly, for any
    // OTHER watermark) treat the missing row as WATERMARK_RECORD_MISSING.
    // H-40: the genesis watermark is consistent with ANY chain the load-time walk accepted, not only an
    // empty one. A scan of the still-empty chain persists (0, GENESIS) (ChainVerifier: startSeq 0, no rows walked);
    // if legitimate entries are then appended and the process restarts before a later scan advances the watermark,
    // currentMaxSeq >= 1 skipped the shortcut above and the anchor fetch below looked up seq 0 — a row that never
    // exists (audit_chain starts at seq 1) — refusing a complete, consistent chain as WATERMARK_RECORD_MISSING.
    // Reproduced deterministically on real PostgreSQL (H-40 evidence, 6/6). Accepting it adds no trust: a genesis
    // watermark confirms no position, so there is nothing to have been truncated or replaced, and
    // hydrateFromPgIfDistributed() has already validated every audit_chain row linked from GENESIS before this gate
    // runs (boot is refused on any break). Still fail-closed: a failed getMaxSeq() never reaches here (ACV-24), and a
    // seq-0 watermark with any hash other than the literal 'GENESIS' falls through to WATERMARK_RECORD_MISSING below.
    if (watermarkSeq === 0 && watermarkHash === 'GENESIS') {
      _emit('INFO', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_VERIFIED', { orderingMode, watermarkSeq, currentMaxSeq, note: currentMaxSeq === null ? 'genesis' : 'genesis watermark; entries appended since' });
      return true;
    }

    if (currentMaxSeq == null || currentMaxSeq < watermarkSeq) {
      return _handleDivergence({
        recoveryMode, _exit, _metrics, _env, _emit,
        reason: 'TRUNCATION',
        detail: { watermarkSeq, currentMaxSeq },
      });
    }

    let anchorHash;
    try { anchorHash = await _pgBackend.fetchRowBySeq(watermarkSeq); } catch (err) { return _queryFailed(`read audit_chain row ${watermarkSeq}`, err); }
    if (anchorHash == null) {
      return _handleDivergence({
        recoveryMode, _exit, _metrics, _env, _emit,
        reason: 'WATERMARK_RECORD_MISSING',
        detail: { watermarkSeq },
      });
    }
    if (anchorHash !== watermarkHash) {
      return _handleDivergence({
        recoveryMode, _exit, _metrics, _env, _emit,
        reason: 'HASH_DIVERGENCE',
        detail: { watermarkSeq, expectedHash: watermarkHash, actualHash: anchorHash },
      });
    }

    _emit('INFO', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_VERIFIED', { orderingMode, watermarkSeq, currentMaxSeq });
    return true;
  }

  // ── Single-node mode (file, with or without a PG dual-write mirror) ────
  let watermark;
  try {
    watermark = await _verifierState.loadFileState();
  } catch {
    watermark = null;
  }

  if (!watermark || !Number.isInteger(watermark.lastVerifiedIndex) || watermark.lastVerifiedIndex === 0) {
    await _verifierState.saveFileState({
      lastVerifiedIndex: currentLength,
      lastVerifiedHash:  stats.tailHash,
      lastScanMode:      'NONE',
      lastScanTrigger:   'STARTUP',
      lastScanAt:        new Date().toISOString(),
    });
    _emit('INFO', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_SEEDED', { orderingMode, currentLength });
    return true;
  }

  const watermarkIndex = watermark.lastVerifiedIndex;
  const watermarkHash  = watermark.lastVerifiedHash;

  if (currentLength < watermarkIndex) {
    return _handleDivergence({
      recoveryMode, _exit, _metrics, _env, _emit,
      reason: 'TRUNCATION',
      detail: { watermarkIndex, currentLength },
    });
  }

  // M3: a watermark inside an archived prefix. audit-log.js verified the signed base record at load (fail closed);
  // it vouches for the chain up to startCount — a later point than the watermark — so continuity holds. A watermark
  // exactly at the base must still be the base's head.
  const start = typeof _auditLog.getChainStart === 'function' ? _auditLog.getChainStart() : null;
  if (start && start.startCount > 0 && watermarkIndex <= start.startCount) {
    if (watermarkIndex === start.startCount && watermarkHash !== start.startHash) {
      return _handleDivergence({
        recoveryMode, _exit, _metrics, _env, _emit,
        reason: 'HASH_DIVERGENCE',
        detail: { watermarkIndex, expectedHash: watermarkHash, actualHash: start.startHash, note: 'signed base record head' },
      });
    }
    _emit('INFO', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_VERIFIED', { orderingMode, watermarkIndex, currentLength, note: 'watermark covered by the signed base record', baseCount: start.startCount });
    return true;
  }

  // single-entry fetch — avoids materializing a slice from the
  // watermark to the head just to read its first element.
  const anchorEntry = await _auditLog.getModernEntryAt(watermarkIndex - 1);
  if (!anchorEntry || anchorEntry.hash !== watermarkHash) {
    return _handleDivergence({
      recoveryMode, _exit, _metrics, _env, _emit,
      reason: 'HASH_DIVERGENCE',
      detail: {
        watermarkIndex,
        expectedHash: watermarkHash,
        actualHash:   anchorEntry ? anchorEntry.hash : null,
      },
    });
  }

  _emit('INFO', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_VERIFIED', { orderingMode, watermarkIndex, currentLength });
  return true;
}

module.exports = { verifyChainVerifierContinuity };
