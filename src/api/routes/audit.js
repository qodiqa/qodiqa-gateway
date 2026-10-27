'use strict';

const { Router } = require('express');
const {
  getArtifactById,
  verifyAuditChainDetailedChunked,
  getReplayLineage,
  validateChainIntegrityFromDurableStoreChunked,
  verifyChecksumAnchorIsolation,
} = require('../../core/audit/audit-log.js');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { emit } = require('../../../services/logger');
const { getDefaultRunner: _getVerifierRunner } = require('../../core/audit/verifier');
const { success, failure } = require('../response');
// present the hash-protected value of fields later schema versions promoted out of the
// unhashed executionContext (stage/reason v6, provider v5) — see entryBuilder.protectedField().
const { protectedField: pf } = require('../../core/audit/entryBuilder');
const { raceTimeout } = require('../../utils/raceTimeout');

// UUID v4 canonical form — must match the requestId format produced by
// src/validation/requestId.js (crypto.randomUUID(), always lowercase).
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Configurable timeout for the chain integrity walk.  Walking the full chain can
// be expensive on large audit logs; the timeout ensures the endpoint never blocks
// indefinitely under adversarial conditions.
const AUDIT_TIMEOUT_MS = (() => {
  const v = parseInt(process.env.AUDIT_TIMEOUT_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 10_000;
})();

// Rate limit: forensic audit endpoints must be protected against bulk enumeration.
// A tighter limit than public key endpoints since audit data is more sensitive.
const auditRateLimit = createRateLimitMiddleware('audit', { envelope: 'legacyFailure' });

// Tighter than auditRateLimit: POST /chain/verifier/verify can trigger an
// expensive FULL scan (a fresh from-disk / paginated PG rescan), so it gets
// its own, much stricter limit to prevent an operator or script from
// repeatedly triggering full rescans.
const verifierManualRateLimit = createRateLimitMiddleware('audit_verifier_manual', { envelope: 'legacyFailure' });

const VERIFIER_MANUAL_TIMEOUT_MS = (() => {
  const v = parseInt(process.env.QODIQA_AUDIT_VERIFIER_MANUAL_TIMEOUT_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 30_000;
})();

// ── Lineage completeness assessment ──────────────────────────────────────────

function _assessLineage(entry) {
  const missing = [];

  if (entry.decision === 'ALLOW') {
    if (!entry.requestHash || entry.requestHash === 'UNAVAILABLE') missing.push('requestHash');
    if (!entry.policyHash  || entry.policyHash  === 'UNAVAILABLE') missing.push('policyHash');
    if (!entry.signature   || entry.signature   === 'UNAVAILABLE') missing.push('signature');
    if (!entry.inputHash   || entry.inputHash   === 'UNAVAILABLE') missing.push('inputHash');
    if (entry.verificationResult !== true)                         missing.push('verificationResult');
    if (!pf(entry, 'provider'))                                    missing.push('provider');
    if (!pf(entry, 'stage'))                                       missing.push('stage');
  } else {
    if (!pf(entry, 'stage'))                                       missing.push('stage');
    if (!pf(entry, 'reason'))                                      missing.push('reason');
    if (entry.verificationResult !== false)                        missing.push('verificationResult');
  }

  return { complete: missing.length === 0, missing };
}

// ── Derive structured policy outcome from an audit entry ─────────────────────

function _derivePolicyOutcome(entry) {
  if (!entry) return 'UNKNOWN';
  if (entry.decision === 'ALLOW') return 'ALLOWED';
  const stage  = pf(entry, 'stage');
  const reason = pf(entry, 'reason');
  if (stage === 'POLICY_ENFORCEMENT')                        return 'BLOCKED';
  if (stage === 'POLICY_CHECK')                              return 'BLOCKED';
  if (reason === 'POLICY_BLOCKED' || reason === 'NO_POLICIES_LOADED') return 'BLOCKED';
  if (stage === 'VALIDATION' || stage === 'ARTIFACT_DECODE' || stage === 'INPUT_GUARD') {
    return 'NOT_REACHED';
  }
  return 'UNKNOWN';
}

// ── Build the canonical audit response object ─────────────────────────────────

function _buildResponse(artifactId, entry, replayEntries, chainDetail, lineageState) {
  const hasExecution    = entry !== null;
  const hasVerification = hasExecution && typeof entry.verificationResult === 'boolean';
  const hasReplayTrace  = replayEntries.length > 0;
  const hasProviderOutcome = hasExecution && typeof pf(entry, 'provider') === 'string';

  const execution = hasExecution ? {
    found:              true,
    decision:           entry.decision,
    stage:              pf(entry, 'stage'),
    reason:             pf(entry, 'reason'),
    provider:           pf(entry, 'provider'),
    timestamp:          entry.timestamp,
    verificationResult: entry.verificationResult ?? null,
  } : {
    found:              false,
    decision:           null,
    stage:              null,
    reason:             null,
    provider:           null,
    timestamp:          null,
    verificationResult: null,
  };

  const _available = (v) => (v && v !== 'UNAVAILABLE') ? v : null;

  const verification = {
    outcome:     !hasExecution              ? 'UNKNOWN'
                : entry.verificationResult  ? 'VERIFIED'
                :                            'UNVERIFIED',
    requestHash: _available(entry?.requestHash),
    policyHash:  _available(entry?.policyHash),
    signature:   _available(entry?.signature),
    inputHash:   _available(entry?.inputHash),
  };

  const policy = {
    outcome:    _derivePolicyOutcome(entry),
    policyHash: _available(entry?.policyHash),
    reason:     pf(entry, 'reason'),
  };

  const consentBlocked = (
    entry?.decision === 'BLOCK' &&
    pf(entry, 'stage') === 'POLICY_ENFORCEMENT'
  );
  const consent = {
    outcome: !hasExecution         ? 'UNKNOWN'
            : entry.decision === 'ALLOW' ? 'GRANTED'
            : consentBlocked             ? 'DENIED'
            :                             'NOT_EVALUATED',
  };

  const replayAttempts = replayEntries.map(r => ({
    replayAuditId:          r.artifactId,
    timestamp:              r.timestamp,
    requestHash:            _available(r.requestHash),
    reason:                 pf(r, 'reason') ?? 'REPLAY_DETECTED',
    nonceState:             'CONSUMED',
    firstSeenTimestamp:     entry?.timestamp ?? null,
    replayAttemptTimestamp: r.timestamp,
  }));

  const replay = {
    replayDetected: hasReplayTrace,
    replayBlocked:  hasReplayTrace,
    replayAttempts: replayEntries.length,
    attempts:       replayAttempts,
  };

  const chainIntegrity = {
    valid:             chainDetail.valid,
    reason:            chainDetail.reason,
    entriesVerified:   chainDetail.entriesVerified,
    tamperingDetected: chainDetail.tamperingDetected,
  };

  const lineageCompleteness = {
    hasExecution,
    hasVerification,
    hasReplayTrace,
    hasProviderOutcome,
    complete: lineageState === 'COMPLETE',
  };

  return {
    artifactId,
    tenantId: entry?.tenantId ?? null,
    lineageState,
    execution,
    verification,
    policy,
    consent,
    replay,
    chainIntegrity,
    lineageCompleteness,
    resolvedAt: new Date().toISOString(),
  };
}

// ── Router ────────────────────────────────────────────────────────────────────

const router = Router();

// GET /audit/chain/integrity
// Full chain integrity walk, re-read fresh from the durable store (disk in
// single-node mode, PostgreSQL in distributed mode) on every call —
// Finding E: this previously walked only the in-memory chain[] array, which
// cannot detect audit.log/audit_chain being modified directly on disk/in the
// database while this process keeps running. Protected by rate limit and
// timeout to prevent DoS via repeated expensive chain walks.
router.get('/chain/integrity', auditRateLimit, async (req, res) => {
  const reqId = req.requestId ?? null;
  let report;
  try {
    report = await raceTimeout(validateChainIntegrityFromDurableStoreChunked(), AUDIT_TIMEOUT_MS, () => new Error('AUDIT_TIMEOUT')); //
  } catch (err) {
    const isTimeout = err?.message === 'AUDIT_TIMEOUT';
    emit('ERROR', isTimeout ? 'AUDIT_CHAIN_TIMEOUT' : 'AUDIT_CHAIN_ERROR', {
      requestId: reqId,
    });
    return failure(res, isTimeout ? 'AUDIT_TIMEOUT' : 'INTERNAL_ERROR', 'Audit chain integrity check failed', 503);
  }

  const event = report.chainValid ? 'AUDIT_CHAIN_VALIDATED' : 'AUDIT_CHAIN_CORRUPTED';
  emit(report.chainValid ? 'INFO' : 'ERROR', event, {
    chainLength:       report.chainLength,
    modernLength:      report.modernLength,
    failureCount:      report.integrityFailures.length,
    corruptedCount:    report.corruptedEntries.length,
    replaysDetected:   report.replayCorrelationState.replaysDetected,
    tamperingDetected: report.tamperingDetected,
  });

  // #2: additive isolated-anchor cross-check, independent of the file
  // walk above — never allowed to fail or slow down this endpoint's existing
  // contract, so it's best-effort and defaults to a no-op-shaped result.
  let checksumAnchor = { applicable: false, reason: 'CHECK_FAILED', valid: null };
  try {
    checksumAnchor = await verifyChecksumAnchorIsolation();
  } catch { /* additive field only — never fail the response over this */ }
  if (checksumAnchor.applicable && !checksumAnchor.valid) {
    emit('ERROR', 'AUDIT_CHECKSUM_ANCHOR_MISMATCH', {
      requestId: reqId, reason: checksumAnchor.reason,
    });
  }

  return success(res, { ...report, checksumAnchor });
});

// GET /audit/chain/verifier/status
//
// Live Audit Chain Integrity Verifier (CHAIN-2) — cheap status read, no live
// computation: returns the background runner's current snapshot (running
// state, config, last scan result, cumulative counters). Never exposes
// audit chain contents — only verifier status/metadata (reasons, positions,
// counts), matching the "never expose confidential audit contents
// unnecessarily" requirement.
router.get('/chain/verifier/status', auditRateLimit, (req, res) => {
  const reqId = req.requestId ?? null;
  const status = _getVerifierRunner().getStatus();

  return success(res, status);
});

// POST /audit/chain/verifier/verify
//
// Triggers an on-demand verification run — FULL (fresh from-disk / paginated
// PG rescan), INCREMENTAL (default), or PG_DIVERGENCE (Layer 3: the
// file-vs-PG dual-write cross-validation, otherwise only run on its own
// 15-minute scheduled interval — see verifierConfig.js. FULL/INCREMENTAL
// never inspect PostgreSQL at all in single-node mode; PG_DIVERGENCE is the
// only mode that does, so an operator investigating a suspected mirror
// divergence mid-incident is no longer limited to waiting for the next
// scheduled tick). Rate-limited more tightly than the other audit endpoints
// and timeout-guarded independently (a FULL scan can legitimately take
// longer than the in-memory-only GET /chain/integrity walk). Never repairs —
// the response always reports repairAttempts: 0, repairSupported: false
// (see runner.getStatus() / ChainVerifier.js).
router.post('/chain/verifier/verify', verifierManualRateLimit, async (req, res) => {
  const reqId = req.requestId ?? null;
  const rawMode = typeof req.body?.mode === 'string' ? req.body.mode.toUpperCase() : 'INCREMENTAL';
  const mode = rawMode === 'FULL' ? 'FULL' : rawMode === 'PG_DIVERGENCE' ? 'PG_DIVERGENCE' : 'INCREMENTAL';

  let result;
  try {
    result = await raceTimeout( //
      mode === 'PG_DIVERGENCE'
        ? _getVerifierRunner().verifyPgDivergenceNow()
        : _getVerifierRunner().verifyNow(mode),
      VERIFIER_MANUAL_TIMEOUT_MS, () => new Error('AUDIT_VERIFIER_TIMEOUT'));
  } catch (err) {
    const isTimeout = err?.message === 'AUDIT_VERIFIER_TIMEOUT';
    emit('ERROR', isTimeout ? 'AUDIT_CHAIN_VERIFIER_MANUAL_TIMEOUT' : 'AUDIT_CHAIN_VERIFIER_MANUAL_ERROR', {
      requestId: reqId,
      mode,
    });
    return failure(res, isTimeout ? 'AUDIT_TIMEOUT' : 'INTERNAL_ERROR', 'Audit chain verifier run failed', 503);
  }

  return success(res, result);
});

// GET /audit/:artifactId
router.get('/:artifactId', auditRateLimit, async (req, res) => {
  const reqId      = req.requestId ?? null;
  const artifactId = String(req.params.artifactId || '');

  if (!UUID_V4_RE.test(artifactId)) {
    return failure(res, 'INVALID_ARTIFACT_ID', 'Invalid artifactId', 400);
  }

  // AUTHZ-1: getArtifactById()'s tenant-isolation parameter is threaded
  // through by construction now, even though this route has no per-request
  // authenticated tenant of its own to enforce (it is a global ops/admin
  // tool — RBAC users are not tenant-scoped in this codebase, see
  // src/middleware/rbac.js). An optional ?tenantId= lets a caller who
  // already knows which tenant they're investigating scope their own
  // lookup; omitted, behavior is unchanged (visible across all tenants, as
  // intended for this admin surface).
  const tenantId = typeof req.query.tenantId === 'string' ? req.query.tenantId.trim() || null : null;

  // O(n) integrity walk — required for cryptographic verification. Chunked
  // so a large chain can't stall concurrent request
  // handling for the duration of a single lookup.
  // O(1) artifact and replay lookups replace the prior O(n) array scans.
  const chainDetail   = await verifyAuditChainDetailedChunked();
  const execEntry     = await getArtifactById(artifactId, tenantId);   // O(1) in-window; durable fallback out of window
  const replayEntries = await getReplayLineage(artifactId, tenantId);   // (NF-9): same tenant scope as the artifact

  if (!chainDetail.valid) {
    emit('ERROR', 'AUDIT_CHAIN_CORRUPTED', {
      artifactId,
      reason:            chainDetail.reason,
      tamperingDetected: chainDetail.tamperingDetected,
      entriesVerified:   chainDetail.entriesVerified,
    });
  }

  if (!execEntry && replayEntries.length === 0) {
    emit('INFO', 'AUDIT_LOOKUP_NOT_FOUND', { artifactId });
    return failure(res, 'NOT_FOUND', 'Artifact not found', 404, { artifactId, lineageState: 'NOT_FOUND' });
  }

  if (!execEntry && replayEntries.length > 0) {
    emit('WARN', 'AUDIT_REPLAY_TRACE_DETECTED', {
      artifactId,
      replayCount:   replayEntries.length,
      note: 'original execution record absent',
    });
    emit('WARN', 'AUDIT_LINEAGE_INCOMPLETE', {
      artifactId,
      missing: ['executionRecord'],
    });
    const response = _buildResponse(artifactId, null, replayEntries, chainDetail, 'INCOMPLETE');
    return success(res, response);
  }

  const lineageAssessment = _assessLineage(execEntry);

  if (replayEntries.length > 0) {
    emit('INFO', 'AUDIT_REPLAY_TRACE_DETECTED', {
      artifactId,
      replayCount: replayEntries.length,
      decision:    execEntry.decision,
    });
  }

  if (!lineageAssessment.complete) {
    emit('WARN', 'AUDIT_LINEAGE_INCOMPLETE', {
      artifactId,
      decision: execEntry.decision,
      missing:  lineageAssessment.missing,
    });
  }

  const lineageState = lineageAssessment.complete ? 'COMPLETE' : 'INCOMPLETE';
  const response     = _buildResponse(artifactId, execEntry, replayEntries, chainDetail, lineageState);

  emit('INFO', 'AUDIT_LOOKUP_SUCCESS', {
    artifactId,
    decision:         execEntry.decision,
    lineageState,
    replayCount:      replayEntries.length,
    chainIntegrity:   chainDetail.valid,
    verificationResult: execEntry.verificationResult,
  });

  return success(res, response);
});

// Reject all other methods on audit routes.
router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

module.exports = router;
