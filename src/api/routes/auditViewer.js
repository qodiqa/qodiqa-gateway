'use strict';

const PDFDocument  = require('pdfkit');
const { Router }   = require('express');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { emit }     = require('../../../services/logger');
const { sanitizeCsvCell } = require('../../utils/csvSanitize');
const {
  getAuditChain,
  getModernChain,
  verifyAuditChainDetailed,
  getReplayLineage,
  validateChainIntegrity,
  getArtifactById,
  getArtifactNeighbors,
  getRequestHashEntries,
  getChainStats,
} = require('../../core/audit/audit-log.js');
const {
  listPublicKeys,
  getVerificationKey,
} = require('../../../services/artifact/keyManager');
const {
  computePolicyHash,
  policyHashesEqual,
} = require('../../../services/policyHash');
const {
  createInvestigation,
  getInvestigation,
  listInvestigations,
  appendInvestigationEvent,
} = require('../../core/investigation/store');
const { success, failure } = require('../response');
const {
  parsePagination, parseSortOrder, buildPaginationMeta, withPaginationMeta,
} = require('../../utils/pagination');

const MAX_EXPORT      = 10_000;
const MAX_PAGE_SIZE     = 500;
const DEFAULT_PAGE_SIZE = 50;
const UUID_V4_RE      = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const INV_ID_RE       = /^INV-[0-9A-F]{16}$/;

// ── Rate limiter ──────────────────────────────────────────────────────────────

const _rl = createRateLimitMiddleware('audit_viewer', { envelope: 'legacyFailure' });

// ── Shared helpers ────────────────────────────────────────────────────────────

function _str(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.trim().slice(0, max ?? 256);
  return s || null;
}

function _avail(v) {
  return (v && v !== 'UNAVAILABLE') ? v : null;
}

// AUTHZ-1: getArtifactById()'s tenant-isolation parameter is threaded
// through by construction now, even though these routes have no
// per-request authenticated tenant of their own to enforce (this is a
// global ops/admin surface — RBAC users are not tenant-scoped in this
// codebase, see src/middleware/rbac.js). An optional ?tenantId= lets a
// caller who already knows which tenant they're investigating scope their
// own lookup; omitted, behavior is unchanged (visible across all tenants).
function _tenantIdFilter(req) {
  return _str(req.query.tenantId, 128);
}

function _parseFilters(q) {
  return {
    artifactId:         _str(q.artifactId,         36),
    decision:           _str(q.decision,            10),
    stage:              _str(q.stage,               64),
    startDate:          _str(q.startDate,           30),
    endDate:            _str(q.endDate,             30),
    verificationStatus: _str(q.verificationStatus,  20),
    signatureStatus:    _str(q.signatureStatus,     20),
    replayOnly:         q.replayOnly  === 'true',
    failedOnly:         q.failedOnly  === 'true',
  };
}

function _deriveSignatureStatus(entry) {
  if (!entry) return 'UNKNOWN';
  if (!entry.signature || entry.signature === 'UNAVAILABLE') return 'MISSING';
  if (entry.verificationResult === true)  return 'VALID';

  const reason = entry.executionContext?.reason;
  if (reason === 'EXPIRED')           return 'EXPIRED';
  if (reason === 'KEY_NOT_FOUND')     return 'REVOKED';
  if (reason === 'INVALID_SIGNATURE') return 'INVALID';
  if (reason === 'TIME_SKEW_EXCEEDED') return 'EXPIRED';

  return entry.verificationResult === false ? 'INVALID' : 'UNKNOWN';
}

function _matches(e, f) {
  if (f.artifactId && !e.artifactId.includes(f.artifactId))     return false;
  if (f.decision   && e.decision !== f.decision)                 return false;
  if (f.stage      && e.executionContext?.stage !== f.stage)     return false;
  if (f.startDate  && e.timestamp < f.startDate)                 return false;
  if (f.endDate    && e.timestamp > f.endDate)                   return false;
  if (f.replayOnly && !e.executionContext?.replayOf)             return false;
  if (f.failedOnly && e.decision === 'ALLOW' && e.verificationResult !== false) return false;

  if (f.verificationStatus) {
    if (f.verificationStatus === 'VERIFIED'   && e.verificationResult !== true)  return false;
    if (f.verificationStatus === 'UNVERIFIED' && e.verificationResult === true)  return false;
  }

  if (f.signatureStatus) {
    const ss = _deriveSignatureStatus(e);
    if (ss !== f.signatureStatus) return false;
  }

  return true;
}

function _toRow(e) {
  return {
    artifactId:         e.artifactId,
    timestamp:          e.timestamp,
    decision:           e.decision,
    verificationResult: e.verificationResult ?? null,
    signatureStatus:    _deriveSignatureStatus(e),
    stage:              e.executionContext?.stage    ?? null,
    reason:             e.executionContext?.reason   ?? null,
    provider:           e.executionContext?.provider ?? null,
    replayOf:           e.executionContext?.replayOf ?? null,
    policyHash:         _avail(e.policyHash),
    requestHash:        _avail(e.requestHash),
    inputHash:          _avail(e.inputHash),
    hash:               e.hash ?? null,
  };
}

// ── Router factory ────────────────────────────────────────────────────────────

function createAuditViewerRouter({ _getPolicies } = {}) {
  const router = Router();

  // ── chain-summary ──────────────────────────────────────────────────────────
  // GET /audit-viewer/chain-summary
  router.get('/chain-summary', _rl, async (req, res) => {
    const reqId  = req.requestId ?? null;

    // O(1) stats from index counters — no full chain scan required.
    const stats  = getChainStats();
    const detail = verifyAuditChainDetailed();

    // byReason/byStage require one O(n) pass over modern entries only.
    const modern   = await getModernChain();
    const byReason = {};
    const byStage  = {};
    for (const e of modern) {
      const r = e.executionContext?.reason ?? 'UNKNOWN';
      const s = e.executionContext?.stage  ?? 'UNKNOWN';
      byReason[r] = (byReason[r] || 0) + 1;
      byStage[s]  = (byStage[s]  || 0) + 1;
    }

    success(res, {
      chainLength:       stats.chainLength,
      modernLength:      stats.modernLength,
      chainValid:        detail.valid,
      tamperingDetected: detail.tamperingDetected,
      validationReason:  detail.reason,
      allows:            stats.allowCount,   // O(1)
      blocks:            stats.blockCount,   // O(1)
      replays:           stats.replayCount,  // O(1)
      byReason,
      byStage,
      firstTimestamp: modern[0]?.timestamp ?? null,
      lastTimestamp:  modern[modern.length - 1]?.timestamp ?? null,
    });
  });

  // ── search ─────────────────────────────────────────────────────────────────
  // GET /audit-viewer/search
  router.get('/search', _rl, async (req, res) => {
    const reqId    = req.requestId ?? null;
    const f        = _parseFilters(req.query);
    // Canonical page/pageSize (+ legacy limit/offset aliases) via the shared
    // utility (src/utils/pagination.js — API-4 remediation). Cap raised from
    // this endpoint's previous 200 to the fleet-standard 500 (additive —
    // every request that worked before still works identically).
    const { page, pageSize } = parsePagination(req.query, { defaultPageSize: DEFAULT_PAGE_SIZE, maxPageSize: MAX_PAGE_SIZE });
    // `sort` is this endpoint's legacy direction toggle; `sortOrder` is now
    // also accepted as the canonical name (both map to the same parser).
    const sortDir  = parseSortOrder(req.query);

    if (f.decision && !['ALLOW', 'BLOCK'].includes(f.decision)) {
      return failure(res, 'INVALID_FILTER', 'Invalid decision filter', 400, { field: 'decision' });
    }

    const filtered = (await getModernChain()).filter(e => _matches(e, f));
    filtered.sort((a, b) => sortDir === 'asc'
      ? a.timestamp.localeCompare(b.timestamp)
      : b.timestamp.localeCompare(a.timestamp)
    );

    const total   = filtered.length;
    const start   = (page - 1) * pageSize;
    const results = filtered.slice(start, start + pageSize).map(_toRow);

    emit('INFO', 'AUDIT_VIEWER_SEARCH', { total, page, pageSize, requestId: reqId });

    success(res, {
      total, page, pageSize, sortDir, results,
      ...buildPaginationMeta({ page, pageSize, totalItems: total }),
      sortOrder: sortDir,
    });
  });

  // ── timeline ───────────────────────────────────────────────────────────────
  // GET /audit-viewer/timeline
  router.get('/timeline', _rl, async (req, res) => {
    const reqId     = req.requestId ?? null;
    // Cap raised from this endpoint's previous 200 to the fleet-standard 500
    // (additive — every request that worked before still works identically).
    const { page, pageSize } = parsePagination(req.query, { defaultPageSize: DEFAULT_PAGE_SIZE, maxPageSize: MAX_PAGE_SIZE });
    const startDate = _str(req.query.startDate, 30);
    const endDate   = _str(req.query.endDate,   30);

    const EVENT_TYPES = new Set([
      'ARTIFACT_ALLOWED', 'POLICY_BLOCKED', 'VALIDATION_FAILED',
      'REPLAY_DETECTED', 'ARTIFACT_BLOCKED', 'SIGNATURE_VERIFIED',
      'SIGNATURE_FAILED', 'CONSENT_DENIED', 'ANOMALY_DETECTED',
    ]);
    const typeFilter = _str(req.query.eventType, 40);
    if (typeFilter && !EVENT_TYPES.has(typeFilter)) {
      return failure(res, 'INVALID_FILTER', 'Invalid event type filter', 400, { field: 'eventType', valid: [...EVENT_TYPES] });
    }

    const events = (await getModernChain())
      .filter(e => {
        if (startDate && e.timestamp < startDate) return false;
        if (endDate   && e.timestamp > endDate)   return false;
        return true;
      })
      .map(e => {
        let eventType;
        if (e.executionContext?.replayOf) {
          eventType = 'REPLAY_DETECTED';
        } else if (e.decision === 'ALLOW') {
          eventType = e.verificationResult ? 'ARTIFACT_ALLOWED' : 'ARTIFACT_ALLOWED';
        } else {
          const s = e.executionContext?.stage ?? '';
          const r = e.executionContext?.reason ?? '';
          if (s === 'POLICY_ENFORCEMENT' || s === 'POLICY_CHECK')              eventType = 'POLICY_BLOCKED';
          else if (s === 'VALIDATION' || s === 'ARTIFACT_DECODE')              eventType = 'VALIDATION_FAILED';
          else if (r === 'INVALID_SIGNATURE')                                   eventType = 'SIGNATURE_FAILED';
          else if (r === 'CONSENT_DENIED' || r === 'REQUIRE_CONSENT_FAILED')  eventType = 'CONSENT_DENIED';
          else                                                                  eventType = 'ARTIFACT_BLOCKED';
        }

        return {
          timestamp:     e.timestamp,
          eventType,
          artifactId:    e.artifactId,
          decision:      e.decision,
          stage:         e.executionContext?.stage    ?? null,
          reason:        e.executionContext?.reason   ?? null,
          provider:      e.executionContext?.provider ?? null,
          replayOf:      e.executionContext?.replayOf ?? null,
          verificationResult: e.verificationResult ?? null,
          signatureStatus:    _deriveSignatureStatus(e),
          chainHash:     e.hash ?? null,
        };
      })
      .filter(ev => !typeFilter || ev.eventType === typeFilter)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp));

    const total   = events.length;
    const start   = (page - 1) * pageSize;
    const results = events.slice(start, start + pageSize);

    success(res, {
      total, page, pageSize, events: results,
      ...buildPaginationMeta({ page, pageSize, totalItems: total }),
    });
  });

  // ── export ─────────────────────────────────────────────────────────────────
  // GET /audit-viewer/export
  router.get('/export', _rl, async (req, res) => {
    const reqId  = req.requestId ?? null;
    const format = _str(req.query.format, 10) ?? 'json';

    if (!['json', 'csv', 'pdf'].includes(format)) {
      return failure(res, 'INVALID_FORMAT', 'Invalid export format', 400, { supported: ['json', 'csv', 'pdf'] });
    }

    const f       = _parseFilters(req.query);
    const records = (await getModernChain())
      .filter(e => _matches(e, f))
      .slice(0, MAX_EXPORT)
      .map(_toRow);

    emit('INFO', 'AUDIT_VIEWER_EXPORT', { format, count: records.length, requestId: reqId });

    if (format === 'csv') {
      const cols = [
        'artifactId', 'timestamp', 'decision', 'verificationResult', 'signatureStatus',
        'stage', 'reason', 'provider', 'replayOf', 'policyHash', 'requestHash', 'inputHash', 'hash',
      ];
      // INJ-7: sanitizeCsvCell() neutralizes leading =/+/-/@ (spreadsheet
      // formula injection) in addition to the standard quote-escaping this
      // route already applied.
      const rows = records.map(r =>
        cols.map(c => sanitizeCsvCell(r[c])).join(',')
      );
      res.set('Content-Type', 'text/csv; charset=utf-8');
      res.set('Content-Disposition', 'attachment; filename="qodiqa-audit-export.csv"');
      return res.send([cols.join(','), ...rows].join('\r\n'));
    }

    if (format === 'pdf') {
      const now = new Date().toISOString();
      res.set('Content-Type', 'application/pdf');
      res.set('Content-Disposition', 'attachment; filename="qodiqa-audit-report.pdf"');
      return _streamPdfReport(records, f, { exportedAt: now, requestId: reqId, count: records.length }, res);
    }

    res.set('Content-Type', 'application/json; charset=utf-8');
    res.set('Content-Disposition', 'attachment; filename="qodiqa-audit-export.json"');
    success(res, {
      exportedAt:     new Date().toISOString(),
      filters:        f,
      count:          records.length,
      maxExportLimit: MAX_EXPORT,
      records,
    });
  });

  // ── artifact inspection ────────────────────────────────────────────────────
  // GET /audit-viewer/artifact/:artifactId
  router.get('/artifact/:artifactId', _rl, async (req, res) => {
    const reqId      = req.requestId ?? null;
    const artifactId = String(req.params.artifactId || '');

    if (!UUID_V4_RE.test(artifactId)) {
      return failure(res, 'INVALID_ARTIFACT_ID', 'Invalid artifactId', 400);
    }

    // O(1) lookups via indexes — no full chain scan required.
    const entry       = await getArtifactById(artifactId, _tenantIdFilter(req));
    const replays     = await getReplayLineage(artifactId, _tenantIdFilter(req)); // (NF-9)
    const chainDetail = verifyAuditChainDetailed();    // O(n) — inherent for integrity

    if (!entry && replays.length === 0) {
      return failure(res, 'NOT_FOUND', 'Artifact not found', 404, { artifactId });
    }

    const sigStatus   = _deriveSignatureStatus(entry);
    const neighbors   = entry ? await getArtifactNeighbors(artifactId) : null;
    const position    = neighbors?.position ?? -1;
    const modernChain = await getModernChain();
    const prevEntry   = neighbors?.prev ?? null;
    const nextEntry   = neighbors?.next ?? null;

    let policyMatchesCurrent = null;
    if (entry && _avail(entry.policyHash) && typeof _getPolicies === 'function') {
      try {
        const currentHash = computePolicyHash(_getPolicies());
        policyMatchesCurrent = policyHashesEqual(entry.policyHash, currentHash);
      } catch {
        policyMatchesCurrent = null;
      }
    }

    const consentBlocked = entry?.decision === 'BLOCK' &&
      entry?.executionContext?.stage === 'POLICY_ENFORCEMENT';

    const data = {
      artifactId,
      timestamp:    entry?.timestamp ?? null,
      decision:     entry?.decision  ?? null,
      lineageState: !entry ? (replays.length > 0 ? 'INCOMPLETE' : 'NOT_FOUND') : 'COMPLETE',

      execution: entry ? {
        found:              true,
        decision:           entry.decision,
        stage:              entry.executionContext?.stage    ?? null,
        reason:             entry.executionContext?.reason   ?? null,
        provider:           entry.executionContext?.provider ?? null,
        replayOf:           entry.executionContext?.replayOf ?? null,
        timestamp:          entry.timestamp,
        verificationResult: entry.verificationResult ?? null,
      } : { found: false, decision: null, stage: null, reason: null, provider: null, replayOf: null, timestamp: null, verificationResult: null },

      signature: {
        value:     entry ? _avail(entry.signature) : null,
        status:    sigStatus,
        algorithm: 'Ed25519',
        verifiedAt: entry?.timestamp ?? null,
        failureReason: sigStatus !== 'VALID'
          ? (entry?.executionContext?.reason ?? null)
          : null,
      },

      hashes: {
        artifact:  entry?.hash        ?? null,
        input:     _avail(entry?.inputHash),
        policy:    _avail(entry?.policyHash),
        request:   _avail(entry?.requestHash),
        chainPrev: entry?.prevHash    ?? null,
      },

      policy: {
        hash:              _avail(entry?.policyHash),
        outcome:           !entry ? 'UNKNOWN'
                           : entry.decision === 'ALLOW' ? 'ALLOWED'
                           : (entry.executionContext?.stage === 'POLICY_ENFORCEMENT' || entry.executionContext?.stage === 'POLICY_CHECK')
                             ? 'BLOCKED' : 'NOT_REACHED',
        matchesCurrent:    policyMatchesCurrent,
        reason:            entry?.executionContext?.reason ?? null,
      },

      verification: {
        outcome:     !entry               ? 'UNKNOWN'
                     : entry.verificationResult ? 'VERIFIED'
                     :                           'UNVERIFIED',
        requestHash: _avail(entry?.requestHash),
        policyHash:  _avail(entry?.policyHash),
        inputHash:   _avail(entry?.inputHash),
      },

      consent: {
        outcome: !entry ? 'UNKNOWN'
                 : entry.decision === 'ALLOW' ? 'GRANTED'
                 : consentBlocked             ? 'DENIED'
                 :                             'NOT_EVALUATED',
      },

      replay: {
        replayDetected: replays.length > 0,
        replayBlocked:  replays.length > 0,
        replayCount:    replays.length,
        attempts: replays.map(r => ({
          replayArtifactId:       r.artifactId,
          timestamp:              r.timestamp,
          requestHash:            _avail(r.requestHash),
          reason:                 r.executionContext?.reason   ?? 'REPLAY_DETECTED',
          stage:                  r.executionContext?.stage    ?? null,
          firstSeenTimestamp:     entry?.timestamp ?? null,
          replayAttemptTimestamp: r.timestamp,
        })),
      },

      chain: {
        position:        position,
        valid:           chainDetail.valid,
        tamperingDetected: chainDetail.tamperingDetected,
        entriesVerified: chainDetail.entriesVerified,
        reason:          chainDetail.reason,
        prevArtifactId:  prevEntry?.artifactId ?? null,
        nextArtifactId:  nextEntry?.artifactId ?? null,
      },

      auditReferences: {
        chainPosition: position,
        chainLength:   modernChain.length,
        prevEntryHash: entry?.prevHash ?? null,
        entryHash:     entry?.hash     ?? null,
        prevArtifactId: prevEntry?.artifactId ?? null,
        nextArtifactId: nextEntry?.artifactId ?? null,
        replayArtifactIds: replays.map(r => r.artifactId),
      },

      raw: entry ? {
        artifactId:         entry.artifactId,
        timestamp:          entry.timestamp,
        decision:           entry.decision,
        inputHash:          entry.inputHash,
        signature:          entry.signature,
        policyHash:         entry.policyHash,
        requestHash:        entry.requestHash,
        verificationResult: entry.verificationResult,
        hash:               entry.hash,
        prevHash:           entry.prevHash,
        executionContext:   entry.executionContext ?? null,
        tenantId:           entry.tenantId ?? null,
      } : null,

      resolvedAt: new Date().toISOString(),
    };

    emit('INFO', 'AUDIT_VIEWER_ARTIFACT_INSPECT', { artifactId, decision: entry?.decision ?? null, requestId: reqId });

    success(res, data);
  });

  // ── signature validation ───────────────────────────────────────────────────
  // GET /audit-viewer/signature/:artifactId
  router.get('/signature/:artifactId', _rl, async (req, res) => {
    const reqId      = req.requestId ?? null;
    const artifactId = String(req.params.artifactId || '');

    if (!UUID_V4_RE.test(artifactId)) {
      return failure(res, 'INVALID_ARTIFACT_ID', 'Invalid artifactId', 400);
    }

    const entry = await getArtifactById(artifactId, _tenantIdFilter(req));

    if (!entry) {
      return failure(res, 'NOT_FOUND', 'Artifact not found', 404, { artifactId });
    }

    const sigStatus = _deriveSignatureStatus(entry);
    let allKeys = [];
    try { allKeys = listPublicKeys(); } catch {}

    const data = {
      artifactId,
      signature: {
        value:        _avail(entry.signature),
        status:       sigStatus,
        algorithm:    'Ed25519',
        encoding:     'hex',
        verifiedAt:   entry.timestamp,
      },
      validation: {
        result:         entry.verificationResult ?? null,
        outcome:        entry.verificationResult === true ? 'VALID' : 'INVALID',
        failureReason:  sigStatus !== 'VALID' ? (entry.executionContext?.reason ?? null) : null,
        failureStage:   sigStatus !== 'VALID' ? (entry.executionContext?.stage  ?? null) : null,
        recordedAt:     entry.timestamp,
      },
      signingContext: {
        decision:          entry.decision,
        stage:             entry.executionContext?.stage    ?? null,
        reason:            entry.executionContext?.reason   ?? null,
        policyHash:        _avail(entry.policyHash),
        requestHash:       _avail(entry.requestHash),
        inputHash:         _avail(entry.inputHash),
      },
      keys: allKeys.map(k => ({
        keyId:        k.keyId,
        clientId:     k.clientId,
        status:       k.status,
        algorithm:    k.algorithm ?? 'Ed25519',
        createdAt:    k.createdAt ?? null,
        fingerprint:  k.publicKeyB64 ? k.publicKeyB64.slice(0, 32) + '…' : null,
      })),
      stateExplanation: _explainSignatureStatus(sigStatus, entry),
      resolvedAt: new Date().toISOString(),
    };

    emit('INFO', 'AUDIT_VIEWER_SIGNATURE_LOOKUP', { artifactId, sigStatus, requestId: reqId });

    success(res, data);
  });

  // ── replay analysis ────────────────────────────────────────────────────────
  // GET /audit-viewer/replay/:artifactId
  router.get('/replay/:artifactId', _rl, async (req, res) => {
    const reqId      = req.requestId ?? null;
    const artifactId = String(req.params.artifactId || '');

    if (!UUID_V4_RE.test(artifactId)) {
      return failure(res, 'INVALID_ARTIFACT_ID', 'Invalid artifactId', 400);
    }

    // O(1) lookups — no full chain scan.
    const entry         = await getArtifactById(artifactId, _tenantIdFilter(req));
    const replayEntries = await getReplayLineage(artifactId, _tenantIdFilter(req)); // (NF-9)

    if (!entry && replayEntries.length === 0) {
      return failure(res, 'NOT_FOUND', 'Artifact not found', 404, { artifactId });
    }

    let status;
    if (replayEntries.length === 0) {
      status = 'NO_REPLAY';
    } else if (replayEntries.every(r => r.executionContext?.reason?.includes('REPLAY'))) {
      status = 'CONFIRMED_REPLAY';
    } else {
      status = 'SUSPECTED_REPLAY';
    }

    const firstSeen = entry?.timestamp ?? null;
    const lastSeen  = replayEntries.length > 0
      ? replayEntries.reduce((max, r) => r.timestamp > max ? r.timestamp : max, replayEntries[0].timestamp)
      : null;

    const timeline = [];
    if (entry) {
      timeline.push({
        event:     'ORIGINAL_EXECUTION',
        timestamp: entry.timestamp,
        artifactId,
        decision:  entry.decision,
        requestHash: _avail(entry.requestHash),
        nonce:     entry.nonce ?? null,
      });
    }
    for (const r of [...replayEntries].sort((a, b) => a.timestamp.localeCompare(b.timestamp))) {
      timeline.push({
        event:     'REPLAY_ATTEMPT',
        timestamp: r.timestamp,
        artifactId: r.artifactId,
        decision:  r.decision,
        requestHash: _avail(r.requestHash),
        reason:    r.executionContext?.reason   ?? null,
        stage:     r.executionContext?.stage    ?? null,
      });
    }

    // O(1) related-request lookup via _requestHashIdx — replaces O(n) chain scan.
    const relatedRequests = _avail(entry?.requestHash)
      ? (await getRequestHashEntries(entry.requestHash))
          .filter(e => e.artifactId !== artifactId)
          .map(e => ({
            artifactId:  e.artifactId,
            timestamp:   e.timestamp,
            decision:    e.decision,
            requestHash: _avail(e.requestHash),
          }))
      : [];

    // ── Forensic analysis ─────────────────────────────────────────────────────
    let windowMs      = null;
    let replayFreqPerHour = null;
    let clusterPattern = 'NO_REPLAY';

    if (replayEntries.length > 0 && firstSeen && lastSeen) {
      windowMs = new Date(lastSeen).getTime() - new Date(firstSeen).getTime();
      if (windowMs > 0) {
        replayFreqPerHour = Math.round((replayEntries.length / (windowMs / 3_600_000)) * 100) / 100;
      }

      // Cluster analysis: compute inter-attempt gaps
      const sorted = [...replayEntries].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
      const gaps = [];
      for (let i = 1; i < sorted.length; i++) {
        gaps.push(new Date(sorted[i].timestamp).getTime() - new Date(sorted[i - 1].timestamp).getTime());
      }
      const avgGapMs = gaps.length > 0 ? gaps.reduce((s, g) => s + g, 0) / gaps.length : 0;
      const burstGaps = gaps.filter(g => g < 5_000).length;

      if (replayEntries.length === 1) {
        clusterPattern = 'SINGLE_REPLAY';
      } else if (burstGaps >= Math.ceil(gaps.length * 0.7)) {
        clusterPattern = 'BURST_REPLAY';      // >70% of gaps < 5s → rapid burst
      } else if (windowMs > 3_600_000) {
        clusterPattern = 'SUSTAINED_REPLAY';  // replays spread across >1h
      } else {
        clusterPattern = 'DISTRIBUTED_REPLAY';
      }
    }

    const data = {
      artifactId,
      status,
      nonce:              entry?.nonce ?? null,
      requestFingerprint: _avail(entry?.requestHash),
      firstSeen,
      lastSeen,
      replayCount:    replayEntries.length,
      detectionSource: replayEntries.length > 0 ? 'NONCE_STORE' : null,
      forensics: {
        windowMs,
        windowHuman:       windowMs !== null ? _fmtDuration(windowMs) : null,
        replayFreqPerHour,
        clusterPattern,
        avgInterAttemptMs: replayEntries.length > 1 && windowMs !== null
          ? Math.round(windowMs / (replayEntries.length - 1))
          : null,
        riskLevel: replayEntries.length === 0 ? 'NONE'
          : clusterPattern === 'BURST_REPLAY'     ? 'CRITICAL'
          : clusterPattern === 'SUSTAINED_REPLAY' ? 'HIGH'
          : clusterPattern === 'DISTRIBUTED_REPLAY' ? 'MEDIUM'
          : 'LOW',
      },
      attempts: replayEntries.map(r => ({
        replayArtifactId:   r.artifactId,
        timestamp:          r.timestamp,
        requestHash:        _avail(r.requestHash),
        reason:             r.executionContext?.reason   ?? null,
        stage:              r.executionContext?.stage    ?? null,
        chainHash:          r.hash ?? null,
      })),
      detectionTimeline: timeline,
      relatedRequests,
      evidence: {
        originalDecision:   entry?.decision ?? null,
        originalTimestamp:  firstSeen,
        nonceConsumedAt:    firstSeen,
        subsequentBlocked:  replayEntries.length,
      },
      resolvedAt: new Date().toISOString(),
    };

    emit('INFO', 'AUDIT_VIEWER_REPLAY_LOOKUP', { artifactId, status, replayCount: replayEntries.length, requestId: reqId });

    success(res, data);
  });

  // ── lineage tracking ───────────────────────────────────────────────────────
  // GET /audit-viewer/lineage/:artifactId
  router.get('/lineage/:artifactId', _rl, async (req, res) => {
    const reqId      = req.requestId ?? null;
    const artifactId = String(req.params.artifactId || '');

    if (!UUID_V4_RE.test(artifactId)) {
      return failure(res, 'INVALID_ARTIFACT_ID', 'Invalid artifactId', 400);
    }

    // O(1) lookups via indexes.
    const entry   = await getArtifactById(artifactId, _tenantIdFilter(req));
    const replays = await getReplayLineage(artifactId, _tenantIdFilter(req)); // (NF-9)

    if (!entry && replays.length === 0) {
      return failure(res, 'NOT_FOUND', 'Artifact not found', 404, { artifactId });
    }

    let allKeys = [];
    try { allKeys = listPublicKeys(); } catch {}

    let policyMatchesCurrent = null;
    if (entry && _avail(entry.policyHash) && typeof _getPolicies === 'function') {
      try {
        const currentHash = computePolicyHash(_getPolicies());
        policyMatchesCurrent = policyHashesEqual(entry.policyHash, currentHash);
      } catch {}
    }

    const artifactNode = {
      id:     'artifact',
      type:   'ARTIFACT',
      label:  'Artifact',
      status: entry ? 'FOUND' : (replays.length > 0 ? 'PARTIAL' : 'NOT_FOUND'),
      data: {
        artifactId,
        timestamp:  entry?.timestamp ?? null,
        decision:   entry?.decision  ?? null,
        verificationResult: entry?.verificationResult ?? null,
        inputHash:  _avail(entry?.inputHash),
        requestHash: _avail(entry?.requestHash),
      },
    };

    const policyNode = {
      id:     'policy',
      type:   'POLICY',
      label:  'Policy',
      status: _avail(entry?.policyHash) ? (policyMatchesCurrent === true ? 'CURRENT' : policyMatchesCurrent === false ? 'CHANGED' : 'LINKED') : 'MISSING',
      data: {
        policyHash:     _avail(entry?.policyHash),
        matchesCurrent: policyMatchesCurrent,
        outcome:        !entry ? 'UNKNOWN'
                        : entry.decision === 'ALLOW' ? 'ALLOWED'
                        : (entry.executionContext?.stage === 'POLICY_ENFORCEMENT') ? 'BLOCKED'
                        : 'NOT_REACHED',
      },
    };

    const keyNode = {
      id:     'signing-key',
      type:   'KEY',
      label:  'Signing Key',
      status: allKeys.length > 0 ? 'AVAILABLE' : 'UNKNOWN',
      data: {
        algorithm:   'Ed25519',
        knownKeys:   allKeys.length,
        keys: allKeys.map(k => ({
          keyId:     k.keyId,
          clientId:  k.clientId,
          status:    k.status,
          createdAt: k.createdAt ?? null,
        })),
      },
    };

    const auditNode = {
      id:     'audit-record',
      type:   'AUDIT',
      label:  'Audit Record',
      status: entry ? 'PRESENT' : (replays.length > 0 ? 'PARTIAL' : 'MISSING'),
      data: {
        chainHash:  entry?.hash     ?? null,
        prevHash:   entry?.prevHash ?? null,
        timestamp:  entry?.timestamp ?? null,
        replayCount: replays.length,
      },
    };

    const verificationNode = {
      id:     'verification',
      type:   'VERIFICATION',
      label:  'Verification Result',
      status: !entry ? 'UNKNOWN'
              : entry.verificationResult ? 'VERIFIED'
              : 'FAILED',
      data: {
        verificationResult: entry?.verificationResult ?? null,
        signatureStatus:    _deriveSignatureStatus(entry),
        stage:              entry?.executionContext?.stage  ?? null,
        reason:             entry?.executionContext?.reason ?? null,
        verifiedAt:         entry?.timestamp ?? null,
      },
    };

    const nodes = [artifactNode, policyNode, keyNode, auditNode, verificationNode];

    const edgeStatus = (fromStatus, toStatus) => {
      if (fromStatus === 'MISSING' || toStatus === 'MISSING' || fromStatus === 'NOT_FOUND') return 'MISSING';
      if (fromStatus === 'FAILED'  || toStatus === 'FAILED')  return 'FAILED';
      return 'LINKED';
    };

    const edges = [
      {
        from:   'artifact',
        to:     'policy',
        type:   'ENFORCED_BY',
        label:  'Enforced By',
        status: edgeStatus(artifactNode.status, policyNode.status),
        metadata: { policyHash: _avail(entry?.policyHash) },
      },
      {
        from:   'artifact',
        to:     'signing-key',
        type:   'SIGNED_WITH',
        label:  'Signed With',
        status: edgeStatus(artifactNode.status, keyNode.status),
        metadata: { algorithm: 'Ed25519' },
      },
      {
        from:   'artifact',
        to:     'audit-record',
        type:   'RECORDED_IN',
        label:  'Recorded In',
        status: edgeStatus(artifactNode.status, auditNode.status),
        metadata: { chainHash: entry?.hash ?? null },
      },
      {
        from:   'audit-record',
        to:     'verification',
        type:   'PRODUCED',
        label:  'Produced',
        status: edgeStatus(auditNode.status, verificationNode.status),
        metadata: { verificationResult: entry?.verificationResult ?? null },
      },
    ];

    const lifecycle = [];
    if (entry) {
      lifecycle.push({ step: 1, event: 'ARTIFACT_RECEIVED',    timestamp: entry.timestamp,  description: 'Artifact submitted for enforcement' });
      lifecycle.push({ step: 2, event: 'SIGNATURE_EVALUATED',  timestamp: entry.timestamp,  description: entry.verificationResult ? 'Signature verified successfully' : 'Signature verification failed' });
      lifecycle.push({ step: 3, event: 'POLICY_EVALUATED',     timestamp: entry.timestamp,  description: `Policy decision: ${entry.decision}` });
      lifecycle.push({ step: 4, event: 'AUDIT_RECORDED',       timestamp: entry.timestamp,  description: 'Enforcement result written to immutable audit chain' });
      lifecycle.push({ step: 5, event: 'RESULT_FINALIZED',     timestamp: entry.timestamp,  description: `Final outcome: ${entry.decision}${entry.executionContext?.provider ? ` via ${entry.executionContext.provider}` : ''}` });
    }
    for (const r of [...replays].sort((a, b) => a.timestamp.localeCompare(b.timestamp))) {
      lifecycle.push({ step: lifecycle.length + 1, event: 'REPLAY_DETECTED', timestamp: r.timestamp, description: `Replay attempt blocked (${r.executionContext?.reason ?? 'REPLAY_DETECTED'})` });
    }

    const data = {
      artifactId,
      nodes,
      edges,
      lifecycle,
      summary: {
        totalNodes:  nodes.length,
        linkedNodes: nodes.filter(n => !['MISSING', 'NOT_FOUND', 'UNKNOWN'].includes(n.status)).length,
        failedLinks: edges.filter(e => e.status !== 'LINKED').length,
        completeLineage: nodes.every(n => !['MISSING', 'NOT_FOUND'].includes(n.status)),
      },
      resolvedAt: new Date().toISOString(),
    };

    emit('INFO', 'AUDIT_VIEWER_LINEAGE_LOOKUP', { artifactId, requestId: reqId });

    success(res, data);
  });

  // ── chain verification ─────────────────────────────────────────────────────
  // GET /audit-viewer/chain/:artifactId
  router.get('/chain/:artifactId', _rl, async (req, res) => {
    const reqId      = req.requestId ?? null;
    const artifactId = String(req.params.artifactId || '');

    if (!UUID_V4_RE.test(artifactId)) {
      return failure(res, 'INVALID_ARTIFACT_ID', 'Invalid artifactId', 400);
    }

    // O(1) lookups — no full chain scan for artifact retrieval.
    const entry       = await getArtifactById(artifactId, _tenantIdFilter(req));
    const neighbors   = entry ? await getArtifactNeighbors(artifactId) : null;
    const position    = neighbors?.position ?? -1;
    const chainDetail = verifyAuditChainDetailed();    // O(n) — required for integrity
    const modern      = await getModernChain();

    if (!entry) {
      return failure(res, 'NOT_FOUND', 'Artifact not found', 404, { artifactId });
    }

    let policyMatchesCurrent = null;
    let currentPolicyHash    = null;
    if (_avail(entry.policyHash) && typeof _getPolicies === 'function') {
      try {
        currentPolicyHash    = computePolicyHash(_getPolicies());
        policyMatchesCurrent = policyHashesEqual(entry.policyHash, currentPolicyHash);
      } catch {}
    }

    let allKeys = [];
    try { allKeys = listPublicKeys(); } catch {}

    const failures  = [];
    const findings  = [];

    // Link 1: Artifact record present
    const artifactLink = { label: 'Artifact Record', status: 'PRESENT', verified: true, details: { artifactId, timestamp: entry.timestamp } };

    // Link 2: Policy linkage
    const policyLinked  = !!_avail(entry.policyHash);
    const policyChanged = policyMatchesCurrent === false;
    if (!policyLinked) {
      failures.push({ link: 'Policy', reason: 'No policy hash recorded', severity: 'WARN' });
    }
    if (policyChanged) {
      findings.push({ link: 'Policy', finding: 'Policy set has changed since this artifact was processed', severity: 'INFO' });
    }
    const policyLink = {
      label:          'Policy Linkage',
      status:         policyLinked ? (policyChanged ? 'CHANGED' : 'LINKED') : 'MISSING',
      verified:       policyLinked,
      details:        { policyHash: _avail(entry.policyHash), matchesCurrent: policyMatchesCurrent },
    };

    // Link 3: Key linkage
    const keyAvailable = allKeys.length > 0;
    if (!keyAvailable) {
      findings.push({ link: 'Key', finding: 'No public keys available for key linkage', severity: 'WARN' });
    }
    const keyLink = {
      label:    'Signing Key',
      status:   keyAvailable ? 'AVAILABLE' : 'UNKNOWN',
      verified: keyAvailable,
      details:  {
        algorithm:  'Ed25519',
        knownKeys:  allKeys.length,
        keyStatuses: allKeys.map(k => ({ keyId: k.keyId, status: k.status })),
      },
    };

    // Link 4: Audit log linkage + hash integrity
    const chainIntegrityUpToPosition = chainDetail.entriesVerified > position;
    const hashValidAtPosition = chainIntegrityUpToPosition;
    if (!hashValidAtPosition && !chainDetail.valid) {
      failures.push({ link: 'Audit Log', reason: `Chain integrity failure: ${chainDetail.reason}`, severity: 'CRITICAL' });
    }
    const auditLink = {
      label:       'Audit Log Record',
      status:      'PRESENT',
      verified:    hashValidAtPosition,
      details: {
        entryHash:    entry.hash,
        prevHash:     entry.prevHash,
        position,
        chainLength:  modern.length,
        hashValid:    hashValidAtPosition,
        chainValid:   chainDetail.valid,
        tamperingDetected: chainDetail.tamperingDetected,
      },
    };

    // Link 5: Verification result
    const verificationVerified = typeof entry.verificationResult === 'boolean';
    if (!verificationVerified) {
      failures.push({ link: 'Verification', reason: 'Verification result absent from record', severity: 'WARN' });
    }
    const verificationLink = {
      label:    'Verification Result',
      status:   !verificationVerified ? 'MISSING'
                : entry.verificationResult ? 'VERIFIED' : 'FAILED',
      verified: verificationVerified,
      details: {
        verificationResult: entry.verificationResult ?? null,
        signatureStatus:    _deriveSignatureStatus(entry),
        decision:           entry.decision,
        stage:              entry.executionContext?.stage  ?? null,
        reason:             entry.executionContext?.reason ?? null,
      },
    };

    const links = [artifactLink, policyLink, keyLink, auditLink, verificationLink];
    const allVerified    = links.every(l => l.verified);
    const anyFailed      = failures.some(f => f.severity === 'CRITICAL');

    let overallStatus;
    if (allVerified && failures.length === 0) overallStatus = 'FULLY_VERIFIED';
    else if (anyFailed)                        overallStatus = 'FAILED';
    else                                       overallStatus = 'PARTIALLY_VERIFIED';

    // Integrity score 0–100
    let integrityScore = 100;
    if (chainDetail.tamperingDetected)    integrityScore -= 50;
    for (const f of failures) {
      if (f.severity === 'CRITICAL') integrityScore -= 20;
      else if (f.severity === 'WARN') integrityScore -= 10;
    }
    for (const fi of findings) {
      if (fi.severity === 'WARN') integrityScore -= 5;
      else if (fi.severity === 'INFO') integrityScore -= 2;
    }
    if (!chainDetail.valid) integrityScore = Math.min(integrityScore, 30);
    integrityScore = Math.max(0, Math.min(100, integrityScore));

    const integritySeverity =
      integrityScore >= 90 ? 'OK'
      : integrityScore >= 70 ? 'WARN'
      : integrityScore >= 40 ? 'HIGH'
      : 'CRITICAL';

    const data = {
      artifactId,
      status:   overallStatus,
      links,
      failures,
      findings,
      integrity: {
        chainValid:        chainDetail.valid,
        entriesVerified:   chainDetail.entriesVerified,
        tamperingDetected: chainDetail.tamperingDetected,
        validationReason:  chainDetail.reason,
        position,
        entryHash:         entry.hash,
        prevHash:          entry.prevHash,
        integrityScore,
        integritySeverity,
      },
      verifiedAt: new Date().toISOString(),
    };

    emit('INFO', 'AUDIT_VIEWER_CHAIN_VERIFY', { artifactId, status: overallStatus, requestId: reqId });

    success(res, data);
  });

  // ── investigation — list ───────────────────────────────────────────────────
  // GET /audit-viewer/investigation
  router.get('/investigation', _rl, (req, res) => {
    const reqId    = req.requestId ?? null;
    const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 20, maxPageSize: 100 });

    const result = listInvestigations({ page, pageSize });

    success(res, withPaginationMeta(result));
  });

  // ── investigation — create ─────────────────────────────────────────────────
  // POST /audit-viewer/investigation
  router.post('/investigation', _rl, (req, res) => {
    const reqId = req.requestId ?? null;
    const body  = req.body;

    if (!body || typeof body !== 'object') {
      return failure(res, 'INVALID_BODY', 'Invalid request body', 400);
    }

    let inv;
    try {
      inv = createInvestigation({
        title:        body.title,
        investigator: body.investigator,
        notes:        body.notes,
        artifactIds:  body.artifactIds,
      });
    } catch (err) {
      if (err.message === 'INVESTIGATION_LIMIT_EXCEEDED') {
        return failure(res, 'INVESTIGATION_LIMIT_EXCEEDED', 'Investigation limit exceeded', 429);
      }
      throw err;
    }

    recordInvestigationEvent(inv.id, 'INVESTIGATION_CREATED', { artifactCount: inv.artifactIds.length, requestId: reqId });

    success(res, inv, 201);
  });

  // ── investigation — get ────────────────────────────────────────────────────
  // GET /audit-viewer/investigation/:id
  router.get('/investigation/:id', _rl, async (req, res) => {
    const reqId = req.requestId ?? null;
    const id    = String(req.params.id || '');

    if (!INV_ID_RE.test(id)) {
      return failure(res, 'INVALID_INVESTIGATION_ID', 'Invalid investigation id', 400);
    }

    const inv = getInvestigation(id);
    if (!inv) {
      return failure(res, 'NOT_FOUND', 'Investigation not found', 404, { id });
    }

    // O(1) per artifact — indexed lookups replace O(n) chain.find() calls.
    const _tid = _tenantIdFilter(req);
    const artifacts = await Promise.all(inv.artifactIds.map(async (aid) => {
      const entry   = await getArtifactById(aid, _tid);
      const replays = await getReplayLineage(aid, _tid); // (NF-9)
      return {
        artifactId:         aid,
        found:              !!entry,
        decision:           entry?.decision                        ?? null,
        timestamp:          entry?.timestamp                       ?? null,
        verificationResult: entry?.verificationResult              ?? null,
        signatureStatus:    _deriveSignatureStatus(entry),
        replayCount:        replays.length,
        stage:              entry?.executionContext?.stage         ?? null,
        reason:             entry?.executionContext?.reason        ?? null,
      };
    }));

    const summary = {
      totalArtifacts:  artifacts.length,
      found:           artifacts.filter(a => a.found).length,
      allowed:         artifacts.filter(a => a.decision === 'ALLOW').length,
      blocked:         artifacts.filter(a => a.decision === 'BLOCK').length,
      replaysDetected: artifacts.filter(a => a.replayCount > 0).length,
      verificationFailures: artifacts.filter(a => a.verificationResult === false).length,
    };

    const accessedAt = new Date().toISOString();
    recordInvestigationEvent(id, 'INVESTIGATION_OPENED', { requestId: reqId, accessedAt });
    emit('INFO', 'AUDIT_VIEWER_INVESTIGATION_LOOKUP', { investigationId: id, requestId: reqId });

    success(res, {
      ...inv,
      artifacts,
      summary,
      enrichedAt: accessedAt,
    });
  });

  // ── 405 catch-all ──────────────────────────────────────────────────────────
  router.use((req, res) =>
    failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405)
  );

  return router;
}

// ── Investigation auditability ────────────────────────────────────────────────

function recordInvestigationEvent(investigationId, event, meta = {}) {
  try {
    appendInvestigationEvent(investigationId, {
      event,
      timestamp: new Date().toISOString(),
      ...meta,
    });
  } catch {
    // audit event recording is best-effort; never block the request
  }
  emit('INFO', event, { investigationId, ...meta });
}

// ── Duration formatter ────────────────────────────────────────────────────────

function _fmtDuration(ms) {
  if (ms < 1_000)          return `${ms}ms`;
  if (ms < 60_000)         return `${(ms / 1_000).toFixed(1)}s`;
  if (ms < 3_600_000)      return `${Math.floor(ms / 60_000)}m ${Math.floor((ms % 60_000) / 1_000)}s`;
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);
  return `${h}h ${m}m`;
}

// ── PDF Report generator (pdfkit — real binary PDF) ───────────────────────────

function _streamPdfReport(records, filters, meta, res) {
  const MARGIN  = 40;
  const PAGE_W  = 841.89;  // A4 landscape width  (pts)
  const PAGE_H  = 595.28;  // A4 landscape height (pts)
  const COL_W   = [200, 110, 55, 55, 70, 80, 110, (PAGE_W - 2 * MARGIN) - 680];
  const HEADERS = ['Artifact ID', 'Timestamp', 'Decision', 'Verified', 'Sig Status', 'Stage', 'Reason', 'Provider'];
  const FIELDS  = ['artifactId', 'timestamp', 'decision', 'verificationResult', 'signatureStatus', 'stage', 'reason', 'provider'];

  const doc = new PDFDocument({ size: 'A4', layout: 'landscape', margin: MARGIN, autoFirstPage: true, info: {
    Title:    'QODIQA Audit Evidence Report',
    Author:   'QODIQA Audit Viewer',
    Subject:  'Forensic audit chain export',
    Keywords: 'audit, forensic, QODIQA',
    Creator:  'QODIQA Audit Viewer v1',
  }});

  doc.pipe(res);

  const DARK   = '#1a1a2e';
  const ALLOW  = '#166534';
  const BLOCK  = '#991b1b';
  const GRAY   = '#f5f5f5';
  const BORDER = '#cccccc';

  let y = MARGIN;

  // ── Cover header ────────────────────────────────────────────────────────────
  doc.rect(MARGIN, y, PAGE_W - 2 * MARGIN, 60).fill(DARK);
  doc.fillColor('#ffffff').fontSize(18).font('Helvetica-Bold')
     .text('QODIQA Audit Evidence Report', MARGIN + 14, y + 10, { width: PAGE_W - 2 * MARGIN - 28 });
  doc.fontSize(9).font('Helvetica')
     .text(`Generated: ${meta.exportedAt}  |  Records: ${meta.count}  |  Max export: ${MAX_EXPORT.toLocaleString()}`, MARGIN + 14, y + 36, { width: PAGE_W - 2 * MARGIN - 28 });
  y += 72;

  // ── Integrity notice ─────────────────────────────────────────────────────────
  doc.rect(MARGIN, y, PAGE_W - 2 * MARGIN, 30).fillAndStroke('#f0fdf4', '#86efac');
  doc.fillColor('#166534').fontSize(8).font('Helvetica-Bold')
     .text('INTEGRITY NOTICE', MARGIN + 8, y + 5);
  doc.fillColor('#111111').font('Helvetica')
     .text('Read-only export of an immutable cryptographic audit chain. Verify forensic authenticity via GET /audit/chain/integrity.', MARGIN + 8, y + 16, { width: PAGE_W - 2 * MARGIN - 16 });
  y += 40;

  // ── Meta section ─────────────────────────────────────────────────────────────
  const halfW = (PAGE_W - 2 * MARGIN - 10) / 2;

  doc.rect(MARGIN, y, halfW, 64).fillAndStroke('#ffffff', BORDER);
  doc.fillColor('#777777').fontSize(7).font('Helvetica-Bold').text('EXPORT METADATA', MARGIN + 8, y + 6);
  doc.fillColor('#111111').fontSize(8).font('Helvetica')
     .text(`Exported At: ${meta.exportedAt}`, MARGIN + 8, y + 18)
     .text(`Record Count: ${meta.count}`, MARGIN + 8, y + 30)
     .text(`Request ID: ${meta.requestId ?? 'N/A'}`, MARGIN + 8, y + 42);

  const filterEntries = Object.entries(filters).filter(([, v]) => v !== null && v !== false && v !== '');
  doc.rect(MARGIN + halfW + 10, y, halfW, 64).fillAndStroke('#ffffff', BORDER);
  doc.fillColor('#777777').fontSize(7).font('Helvetica-Bold').text('APPLIED FILTERS', MARGIN + halfW + 18, y + 6);
  if (filterEntries.length === 0) {
    doc.fillColor('#888888').fontSize(8).font('Helvetica').text('None', MARGIN + halfW + 18, y + 18);
  } else {
    filterEntries.slice(0, 4).forEach(([k, v], i) => {
      doc.fillColor('#111111').fontSize(8).font('Helvetica')
         .text(`${k}: ${String(v)}`, MARGIN + halfW + 18, y + 18 + i * 11, { width: halfW - 20, ellipsis: true });
    });
  }
  y += 76;

  // ── Table header ─────────────────────────────────────────────────────────────
  function drawTableHeader() {
    doc.rect(MARGIN, y, PAGE_W - 2 * MARGIN, 22).fill(DARK);
    let x = MARGIN;
    HEADERS.forEach((h, i) => {
      doc.fillColor('#ffffff').fontSize(7).font('Helvetica-Bold')
         .text(h.toUpperCase(), x + 4, y + 7, { width: COL_W[i] - 8, ellipsis: true });
      x += COL_W[i];
    });
    y += 22;
  }

  drawTableHeader();

  // ── Table rows ───────────────────────────────────────────────────────────────
  const ROW_H = 18;
  records.forEach((r, idx) => {
    if (y + ROW_H > PAGE_H - MARGIN - 30) {
      doc.addPage({ size: 'A4', layout: 'landscape', margin: MARGIN });
      y = MARGIN;
      drawTableHeader();
    }
    if (idx % 2 === 1) {
      doc.rect(MARGIN, y, PAGE_W - 2 * MARGIN, ROW_H).fill(GRAY);
    }
    doc.rect(MARGIN, y, PAGE_W - 2 * MARGIN, ROW_H).stroke(BORDER);

    let x = MARGIN;
    FIELDS.forEach((field, fi) => {
      let val = r[field] ?? '';
      if (val === null || val === undefined) val = '';
      val = String(val);

      let color = '#111111';
      if (field === 'decision') color = val === 'ALLOW' ? ALLOW : BLOCK;

      doc.fillColor(color).fontSize(7).font(field === 'decision' ? 'Helvetica-Bold' : 'Helvetica')
         .text(val, x + 4, y + 5, { width: COL_W[fi] - 8, ellipsis: true });
      x += COL_W[fi];
    });
    y += ROW_H;
  });

  if (records.length === 0) {
    doc.rect(MARGIN, y, PAGE_W - 2 * MARGIN, 30).fill(GRAY);
    doc.fillColor('#888888').fontSize(9).font('Helvetica')
       .text('No records match the selected filters.', MARGIN, y + 10, { width: PAGE_W - 2 * MARGIN, align: 'center' });
    y += 30;
  }

  // ── Footer on every page ─────────────────────────────────────────────────────
  const pages = doc.bufferedPageRange();
  for (let p = 0; p < pages.count; p++) {
    doc.switchToPage(pages.start + p);
    const footerY = PAGE_H - MARGIN + 4;
    doc.moveTo(MARGIN, footerY - 4).lineTo(PAGE_W - MARGIN, footerY - 4).stroke(BORDER);
    doc.fillColor('#777777').fontSize(7).font('Helvetica')
       .text(
         `QODIQA Audit Viewer  |  Confidential — For authorized review only  |  Page ${p + 1} of ${pages.count}`,
         MARGIN, footerY, { width: PAGE_W - 2 * MARGIN, align: 'center' }
       );
  }

  doc.end();
}

// ── Signature status explanation ──────────────────────────────────────────────

function _explainSignatureStatus(status, entry) {
  const explanations = {
    VALID:   'The artifact signature was verified against a known public key at the time of enforcement. The cryptographic proof is valid.',
    INVALID: 'The Ed25519 signature did not verify against any known public key. The artifact may have been tampered with or signed with an unknown key.',
    EXPIRED: 'The artifact was submitted after its declared expiry time or was rejected due to clock skew exceeding the permitted threshold.',
    REVOKED: 'The signing key referenced by this artifact could not be found or has been revoked. Enforcement was blocked.',
    MISSING: 'No signature was recorded for this artifact. The artifact may have been blocked before reaching signature verification.',
    UNKNOWN: 'The signature status could not be determined from the available audit record.',
  };
  const base = explanations[status] ?? explanations.UNKNOWN;
  if (status !== 'VALID' && entry?.executionContext?.reason) {
    return `${base} (Enforcement reason: ${entry.executionContext.reason})`;
  }
  return base;
}

module.exports = createAuditViewerRouter;
