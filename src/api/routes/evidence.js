'use strict';

/**
 * Evidence Package Generator — API Router
 *
 * Mounts under /evidence with ops middleware applied by server.js.
 * Factory accepts { _getPolicies } so the router can pass current policy state
 * into the generator without coupling to file I/O.
 *
 * Endpoints:
 *   GET /evidence/package/:artifactId        — full JSON evidence package
 *   GET /evidence/package/:artifactId/json   — alias for JSON package
 *   GET /evidence/package/:artifactId/pdf    — PDF evidence report
 *   GET /evidence/package/:artifactId/audit  — audit chain export (full)
 *   GET /evidence/package/:artifactId/verify — cryptographic verification output
 *   GET /evidence/package/:artifactId/bundle — self-contained offline evidence
 * bundle: evidence package + Merkle transparency inclusion
 *     proof, sealed together — verifiable with zero network/DB/server access
 *     via tools/verify/verify.bundle.external.js.
 */

const PDFDocument = require('pdfkit');
const { Router }  = require('express');
const { emit }    = require('../../../services/logger');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { success, failure, internalError } = require('../response');
const { safeAttachmentHeader } = require('../../utils/contentDisposition');
const { API_CSP } = require('../../infra/security/csp');
const {
  generateEvidencePackage,
  exportAuditChain,
  streamAuditChainExport,
  generateVerificationOutput,
  generateEvidenceBundle,
  SCHEMA_VERSION,
  GENERATOR_VERSION,
} = require('../../core/evidence/generator');

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ── PDF rendering ─────────────────────────────────────────────────────────────

const PDF_COLORS = {
  header:     '#1a1a2e',
  accent:     '#4fc3f7',
  allow:      '#4caf50',
  block:      '#f44336',
  warn:       '#ff9800',
  text:       '#212121',
  muted:      '#757575',
  border:     '#e0e0e0',
  bg:         '#fafafa',
  sectionBg:  '#f5f5f5',
};

function _statusColor(status) {
  if (!status) return PDF_COLORS.muted;
  const s = String(status).toUpperCase();
  if (['VALID', 'VERIFIED', 'ALLOW', 'EXECUTE', 'MATCH', 'CLEAN'].includes(s)) return PDF_COLORS.allow;
  if (['INVALID', 'BLOCK', 'COMPROMISED', 'MISMATCH', 'REPLAYS_DETECTED'].includes(s)) return PDF_COLORS.block;
  if (['UNKNOWN', 'PARTIAL', 'UNAVAILABLE', 'REPLAYED'].includes(s)) return PDF_COLORS.warn;
  return PDF_COLORS.text;
}

function _streamEvidencePdf(pkg, res) {
  const doc = new PDFDocument({
    size:        'A4',
    layout:      'portrait',
    margin:      40,
    bufferPages: true,
    info: {
      Title:    `QODIQA Evidence Report — ${pkg.artifactId}`,
      Author:   'QODIQA Evidence Package Generator',
      Subject:  `Forensic evidence package for artifact ${pkg.artifactId}`,
      Creator:  `QODIQA/${GENERATOR_VERSION}`,
    },
  });

  res.setHeader('Content-Type', 'application/pdf');
  // INJ-8: defense-in-depth — sanitize even the already-UUID-validated
  // artifactId before header interpolation, matching every other export site.
  res.setHeader('Content-Disposition', safeAttachmentHeader(`evidence-${pkg.artifactId}.pdf`));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  doc.pipe(res);

  const W     = doc.page.width  - 80;  // usable width (margins 40 each side)
  const LEFT  = 40;
  let   y     = 40;

  // ── Cover header ────────────────────────────────────────────────────────────
  doc.rect(0, 0, doc.page.width, 90).fill(PDF_COLORS.header);
  doc.fontSize(22).fillColor('#ffffff').font('Helvetica-Bold')
     .text('QODIQA Evidence Report', LEFT, 18, { width: W });
  doc.fontSize(10).fillColor(PDF_COLORS.accent).font('Helvetica')
     .text(`Forensic Artifact Evidence Package  •  ${SCHEMA_VERSION}`, LEFT, 46, { width: W });
  doc.fontSize(9).fillColor('#b0bec5')
     .text(`Generated: ${pkg.generatedAt}   •   Generator v${GENERATOR_VERSION}`, LEFT, 64, { width: W });
  y = 108;

  // ── Artifact ID banner ───────────────────────────────────────────────────────
  doc.rect(LEFT, y, W, 32).fill(PDF_COLORS.sectionBg).stroke(PDF_COLORS.border);
  doc.fontSize(9).fillColor(PDF_COLORS.muted).font('Helvetica-Bold')
     .text('ARTIFACT ID', LEFT + 10, y + 6);
  doc.fontSize(11).fillColor(PDF_COLORS.text).font('Helvetica')
     .text(pkg.artifactId, LEFT + 10, y + 17);
  y += 46;

  function _sectionHeading(title) {
    y += 12;
    doc.rect(LEFT, y, W, 22).fill(PDF_COLORS.header);
    doc.fontSize(10).fillColor('#ffffff').font('Helvetica-Bold')
       .text(title, LEFT + 8, y + 6);
    y += 30;
  }

  // Renders a label/value row. Cryptographic material (hashes, signatures,
  // public keys, canonical payloads) is NEVER truncated here — the
  // row height is measured from the actual (possibly multi-line) text so a
  // long full value never gets clipped by a fixed single-line height.
  function _kvRow(label, value, valueColor) {
    if (y > doc.page.height - 80) { doc.addPage(); y = 40; }
    const col  = W / 2;
    const text = String(value ?? 'N/A');
    doc.fontSize(8).fillColor(PDF_COLORS.muted).font('Helvetica-Bold')
       .text(label, LEFT, y, { width: col - 10 });
    doc.fontSize(9).fillColor(valueColor || PDF_COLORS.text).font('Helvetica');
    const textHeight = doc.heightOfString(text, { width: col });
    doc.text(text, LEFT + col, y - (doc.currentLineHeight() * 0.5), { width: col });
    y += Math.max(16, textHeight + 4);
  }

  // ── Executive Summary ────────────────────────────────────────────────────────
  _sectionHeading('EXECUTIVE SUMMARY');
  const art  = pkg.sections.artifact;
  const ver  = pkg.sections.verification;
  const aud  = pkg.sections.audit;

  const summaryStatus = !pkg.found ? 'NOT FOUND'
    : art.decision === 'ALLOW'    ? 'ALLOWED'
    : 'BLOCKED';

  doc.rect(LEFT, y, W, 56).fill(PDF_COLORS.bg).stroke(PDF_COLORS.border);
  doc.fontSize(28).font('Helvetica-Bold')
     .fillColor(_statusColor(summaryStatus))
     .text(summaryStatus, LEFT + 16, y + 10);
  doc.fontSize(9).fillColor(PDF_COLORS.muted).font('Helvetica')
     .text(`Verification: ${ver.outcome}   Chain: ${aud.chainIntegrity.valid ? 'VALID' : 'INVALID'}   Replays: ${aud.replayAnalysis.replayCount}`, LEFT + 16, y + 40);
  y += 68;

  // ── Artifact Details ─────────────────────────────────────────────────────────
  _sectionHeading('ARTIFACT DETAILS');
  if (art) {
    _kvRow('Decision',        art.decision,  _statusColor(art.decision));
    _kvRow('Timestamp',       art.timestamp  ? new Date(art.timestamp).toISOString() : 'N/A');
    _kvRow('Nonce',           art.nonce      ?? 'None');
    _kvRow('Tenant',          art.tenantId   ?? 'Default');
    _kvRow('Input Hash',      art.inputHash);
    _kvRow('Request Hash',    art.requestHash);
    _kvRow('Policy Hash',     art.policyHash);
    _kvRow('Chain Hash',      art.chainHash);
    _kvRow('Prev Hash',       art.prevHash);
    _kvRow('Canonical Payload', art.canonical);
    if (art.executionContext) {
      _kvRow('Stage',    art.executionContext.stage    ?? 'N/A');
      _kvRow('Reason',   art.executionContext.reason   ?? 'N/A');
      _kvRow('Provider', art.executionContext.provider ?? 'N/A');
    }
  } else {
    doc.fontSize(10).fillColor(PDF_COLORS.warn).text('Artifact not found in audit chain.', LEFT, y);
    y += 20;
  }

  // ── Verification ─────────────────────────────────────────────────────────────
  _sectionHeading('CRYPTOGRAPHIC VERIFICATION');
  _kvRow('Outcome',       ver.outcome,       _statusColor(ver.outcome));
  _kvRow('Signature',     ver.signature ?? 'N/A');
  _kvRow('Signature Algorithm', ver.signatureAlgorithm ?? 'Ed25519');
  _kvRow('Signing Key',   ver.publicKeyId    ?? 'N/A');
  _kvRow('Key Status',    ver.keyCurrentStatus, _statusColor(ver.keyCurrentStatus));
  _kvRow('Algorithm',     'Ed25519');
  _kvRow('Note',          ver.verificationNote);

  // ── Policy ───────────────────────────────────────────────────────────────────
  const pol = pkg.sections.policy;
  _sectionHeading('POLICY STATE');
  _kvRow('Hash At Execution',   pol.policyHashAtExecution);
  _kvRow('Current Policy Hash', pol.currentPolicyHash);
  _kvRow('Hash Integrity',      pol.hashIntegrity, _statusColor(pol.hashIntegrity));
  _kvRow('Policy Count',        pol.policyCount ?? 'N/A');

  // ── Key Metadata ─────────────────────────────────────────────────────────────
  const key = pkg.sections.key;
  _sectionHeading('KEY METADATA');
  _kvRow('Public Key ID',    key.publicKeyId   ?? 'N/A');
  _kvRow('Key Status',       key.keyStatus,       _statusColor(key.keyStatus));
  _kvRow('Algorithm',        key.algorithm);
  _kvRow('Client ID',        key.clientId      ?? 'N/A');
  _kvRow('Key Version',      key.keyVersion    ?? 'N/A');
  _kvRow('Created At',       key.createdAt     ?? 'N/A');
  // Full, untruncated public key — required for offline verification.
  _kvRow('Public Key',       key.publicKey ?? 'N/A');
  _kvRow('Public Key Encoding', key.publicKeyEncoding ?? 'N/A');
  _kvRow('Keys In Store',    key.totalKeysInStore);
  _kvRow('Active Keys',      key.activeKeys);

  // ── Audit Chain ──────────────────────────────────────────────────────────────
  _sectionHeading('AUDIT CHAIN INTEGRITY');
  const ci = aud.chainIntegrity;
  _kvRow('Chain Valid',          ci.valid ? 'YES' : 'NO',  _statusColor(ci.valid ? 'VALID' : 'INVALID'));
  _kvRow('Tampering Detected',   ci.tamperingDetected ? 'YES' : 'NO', ci.tamperingDetected ? PDF_COLORS.block : PDF_COLORS.allow);
  _kvRow('Entries Verified',     ci.entriesVerified);
  _kvRow('Failure Reason',       ci.reason ?? 'None');
  _kvRow('Artifact Position',    aud.artifactPosition.found ? `Index ${aud.artifactPosition.index} of ${aud.artifactPosition.totalInChain}` : 'Not found');

  // ── Replay Analysis ──────────────────────────────────────────────────────────
  _sectionHeading('REPLAY ANALYSIS');
  const rp = aud.replayAnalysis;
  _kvRow('Replay Count',   rp.replayCount,      rp.replayCount > 0 ? PDF_COLORS.block : PDF_COLORS.allow);
  _kvRow('Risk Level',     rp.replayRiskLevel,  _statusColor(rp.replayRiskLevel));
  _kvRow('Window',         rp.replayWindowHuman);
  _kvRow('First Replay',   rp.firstReplayAt  ? new Date(rp.firstReplayAt).toISOString()  : 'N/A');
  _kvRow('Last Replay',    rp.lastReplayAt   ? new Date(rp.lastReplayAt).toISOString()   : 'N/A');

  // ── Package Integrity ────────────────────────────────────────────────────────
  _sectionHeading('PACKAGE INTEGRITY');
  _kvRow('Package Hash',  pkg.integrity.packageHash);
  _kvRow('Hash Algorithm', pkg.integrity.algorithm);
  // Full package-level Ed25519 seal — signs this entire evidence
  // bundle so a third party can verify authenticity offline, without
  // trusting a running QODIQA instance.
  _kvRow('Package Signature',   pkg.integrity.signature ?? 'UNAVAILABLE');
  _kvRow('Signing Key ID',      pkg.integrity.keyId ?? 'N/A');
  _kvRow('Signing Public Key',  pkg.integrity.publicKey ?? 'N/A');
  _kvRow('Signing Algorithm',   pkg.integrity.signingAlgorithm ?? 'N/A');
  _kvRow('Signed At',           pkg.integrity.signedAt ?? 'N/A');
  _kvRow('Schema',        pkg.schema);
  _kvRow('Generator',     `v${pkg.version}`);

  // ── Footer on each page ──────────────────────────────────────────────────────
  const range     = doc.bufferedPageRange();
  const pageCount = range.count;
  for (let i = range.start; i < range.start + pageCount; i++) {
    doc.switchToPage(i);
    const pageH = doc.page.height;
    doc.rect(0, pageH - 28, doc.page.width, 28).fill(PDF_COLORS.header);
    doc.fontSize(7).fillColor('#b0bec5').font('Helvetica')
       .text(
         `QODIQA Forensic Evidence Package  •  Artifact: ${pkg.artifactId}  •  Page ${i - range.start + 1}/${pageCount}`,
         LEFT, pageH - 18, { width: W, align: 'center' }
       );
  }

  doc.flushPages();
  doc.end();
}

// ── Router factory ─────────────────────────────────────────────────────────────

function createEvidenceRouter({ _getPolicies } = {}) {
  const router = Router();
  const _rl    = createRateLimitMiddleware('evidence', { envelope: 'legacyFailure' });

  function _policies() {
    if (typeof _getPolicies === 'function') {
      try { return _getPolicies(); } catch (_) {}
    }
    return [];
  }

  function _validId(id) { return UUID_V4_RE.test(id); }

  // Thin adapters over the canonical envelope (src/api/response.js) that keep
  // this file's existing (req, status) call-site ergonomics — the actual
  // envelope shape is built in exactly one place, response.js.
  function _ok(res, req, data) {
    return success(res, data);
  }

  function _err(res, req, status, code, detail) {
    emit('WARN', `EVIDENCE_${code}`, { requestId: req.requestId, detail });
    return failure(res, code, detail, status);
  }

  // FAIL CLOSED — an audit history that cannot be read is an explicit 503, never a
  // package / verification / export built on a partial or empty history. The response carries no internal error text.
  function _failClosed(res, req, e, artifactId) {
    if (!e || e.code !== 'AUDIT_HISTORY_UNAVAILABLE') return false;
    emit('ERROR', 'EVIDENCE_HISTORY_UNAVAILABLE', { requestId: req.requestId ?? null, artifactId, read: e.read || null,
      error: e.cause && e.cause.message ? e.cause.message : e.message });
    failure(res, 'AUDIT_HISTORY_UNAVAILABLE', 'The audit history could not be read; no evidence was produced. Retry later or contact the operator.', 503);
    return true;
  }

  // AUTHZ-1: optional tenant scope for getArtifactById() — see that
  // function's own doc for why this is opt-in on an admin surface with no
  // per-request authenticated tenant of its own.
  function _tenantIdFilter(req) {
    return typeof req.query.tenantId === 'string' ? req.query.tenantId.trim() || null : null;
  }

  // ── GET /evidence/package/:artifactId  (full JSON package) ──────────────────
  // ── GET /evidence/package/:artifactId/json (alias) ──────────────────────────
  async function _handleJsonPackage(req, res) {
    const artifactId = String(req.params.artifactId || '');
    if (!_validId(artifactId)) return _err(res, req, 400, 'INVALID_ARTIFACT_ID');

    let result;
    try {
      result = await generateEvidencePackage(artifactId, _policies(), req.rbacUser ?? null, _tenantIdFilter(req));
    } catch (e) {
      if (_failClosed(res, req, e, artifactId)) return;
      return internalError(res, req, e, { label: 'EVIDENCE_GENERATE_FAILED', code: 'GENERATE_FAILED', extra: { artifactId } });
    }

    if (!result.found) {
      return _err(res, req, 404, 'ARTIFACT_NOT_FOUND', `No audit record found for artifact ${artifactId}`);
    }

    emit('INFO', 'EVIDENCE_JSON_GENERATED', { artifactId, requestId: req.requestId });
    _ok(res, req, result.package);
  }

  router.get('/package/:artifactId',      _rl, _handleJsonPackage);
  router.get('/package/:artifactId/json', _rl, _handleJsonPackage);

  // ── GET /evidence/package/:artifactId/pdf ────────────────────────────────────
  router.get('/package/:artifactId/pdf', _rl, async (req, res) => {
    const artifactId = String(req.params.artifactId || '');
    if (!_validId(artifactId)) return _err(res, req, 400, 'INVALID_ARTIFACT_ID');

    let result;
    try {
      result = await generateEvidencePackage(artifactId, _policies(), req.rbacUser ?? null, _tenantIdFilter(req));
    } catch (e) {
      if (_failClosed(res, req, e, artifactId)) return;
      return internalError(res, req, e, { label: 'EVIDENCE_PDF_GENERATE_FAILED', code: 'GENERATE_FAILED', extra: { artifactId } });
    }

    if (!result.found) {
      return _err(res, req, 404, 'ARTIFACT_NOT_FOUND', `No audit record found for artifact ${artifactId}`);
    }

    emit('INFO', 'EVIDENCE_PDF_GENERATED', { artifactId, requestId: req.requestId });

    try {
      _streamEvidencePdf(result.package, res);
    } catch (e) {
      if (res.headersSent) {
        emit('ERROR', 'EVIDENCE_PDF_STREAM_FAILED', { artifactId, error: e.message, requestId: req.requestId ?? null });
      } else {
        internalError(res, req, e, { label: 'EVIDENCE_PDF_STREAM_FAILED', code: 'PDF_STREAM_FAILED', extra: { artifactId } });
      }
    }
  });

  // ── GET /evidence/package/:artifactId/audit ──────────────────────────────────
  router.get('/package/:artifactId/audit', _rl, async (req, res) => {
    const artifactId = String(req.params.artifactId || '');
    if (!_validId(artifactId)) return _err(res, req, 400, 'INVALID_ARTIFACT_ID');

    const filtered = req.query.filtered !== 'false';  // default: filtered view

    // the unfiltered export is the whole history — streamed, never materialised.
    if (!filtered) return _streamUnfilteredExport(req, res, artifactId);

    let result;
    try {
      result = await exportAuditChain(artifactId, filtered);
    } catch (e) {
      if (_failClosed(res, req, e, artifactId)) return;
      return internalError(res, req, e, { label: 'EVIDENCE_AUDIT_EXPORT_FAILED', code: 'EXPORT_FAILED', extra: { artifactId } });
    }

    if (result.meta.exportedCount === 0 && filtered) {
      return _err(res, req, 404, 'ARTIFACT_NOT_FOUND', `No audit entries found for artifact ${artifactId}`);
    }

    emit('INFO', 'EVIDENCE_AUDIT_EXPORTED', { artifactId, filtered, count: result.meta.exportedCount, requestId: req.requestId });
    _ok(res, req, result);
  });

  // GET /evidence/package/:id/audit?filtered=false, streamed with backpressure. The body is exactly what
  // success(res, { entries, meta }) serialises — {"status","timestamp","requestId","data":{"entries":[...],"meta":{...}}}
  // — with meta written last, after the walk, as before. Headers res.json() would set are set here (JSON content type;
  // the API CSP the S02 middleware adds through its res.json hook). A failure after the first byte destroys the
  // connection: the client gets a truncated, invalid JSON body, never a well-formed one presenting a partial chain.
  async function _streamUnfilteredExport(req, res, artifactId) {
    const head = JSON.stringify({ status: 'success', timestamp: new Date().toISOString(), requestId: res.locals?.requestId ?? null });
    let started = false;
    const write = (chunk) => new Promise((resolve, reject) => {
      if (res.destroyed) { reject(new Error('client disconnected')); return; }
      if (!started) {
        started = true;
        res.status(200);
        res.set('Content-Type', 'application/json; charset=utf-8');
        res.set('Content-Security-Policy', API_CSP);
        res.write(`${head.slice(0, -1)},"data":{"entries":[`);
      }
      if (res.write(chunk)) { resolve(); return; }
      const onDrain = () => { res.off('close', onClose); resolve(); };
      const onClose = () => { res.off('drain', onDrain); reject(new Error('client disconnected')); };
      res.once('drain', onDrain); res.once('close', onClose);
    });
    try {
      const meta = await streamAuditChainExport(artifactId, write);
      await write('');
      res.end(`],"meta":${JSON.stringify(meta)}}}`);
      emit('INFO', 'EVIDENCE_AUDIT_EXPORTED', { artifactId, filtered: false, count: meta.exportedCount, requestId: req.requestId, streamed: true });
    } catch (e) {
      if (!started) {
        if (_failClosed(res, req, e, artifactId)) return;
        return internalError(res, req, e, { label: 'EVIDENCE_AUDIT_EXPORT_FAILED', code: 'EXPORT_FAILED', extra: { artifactId } });
      }
      emit('ERROR', 'EVIDENCE_AUDIT_EXPORT_STREAM_FAILED', { artifactId, error: e.message, requestId: req.requestId ?? null });
      res.destroy(e);
    }
  }

  // ── GET /evidence/package/:artifactId/verify ─────────────────────────────────
  router.get('/package/:artifactId/verify', _rl, async (req, res) => {
    const artifactId = String(req.params.artifactId || '');
    if (!_validId(artifactId)) return _err(res, req, 400, 'INVALID_ARTIFACT_ID');

    let output;
    try {
      output = await generateVerificationOutput(artifactId, _policies(), _tenantIdFilter(req));
    } catch (e) {
      if (_failClosed(res, req, e, artifactId)) return;
      return internalError(res, req, e, { label: 'EVIDENCE_VERIFY_FAILED', code: 'VERIFY_FAILED', extra: { artifactId } });
    }

    if (!output.found) {
      return _err(res, req, 404, 'ARTIFACT_NOT_FOUND', `No audit record found for artifact ${artifactId}`);
    }

    emit('INFO', 'EVIDENCE_VERIFY_GENERATED', { artifactId, overallStatus: output.overallStatus, requestId: req.requestId });
    _ok(res, req, output);
  });

  // ── GET /evidence/package/:artifactId/bundle ─────────────────────────────────
  router.get('/package/:artifactId/bundle', _rl, async (req, res) => {
    const artifactId = String(req.params.artifactId || '');
    if (!_validId(artifactId)) return _err(res, req, 400, 'INVALID_ARTIFACT_ID');

    let result;
    try {
      result = await generateEvidenceBundle(artifactId, _policies(), req.rbacUser ?? null, _tenantIdFilter(req));
    } catch (e) {
      if (_failClosed(res, req, e, artifactId)) return;
      return internalError(res, req, e, { label: 'EVIDENCE_BUNDLE_GENERATE_FAILED', code: 'GENERATE_FAILED', extra: { artifactId } });
    }

    if (!result.found) {
      return _err(res, req, 404, 'ARTIFACT_NOT_FOUND', `No audit record found for artifact ${artifactId}`);
    }

    emit('INFO', 'EVIDENCE_BUNDLE_GENERATED', {
      artifactId, requestId: req.requestId,
      transparencyAvailable: result.bundle.transparency.available,
    });
    _ok(res, req, result.bundle);
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => _err(res, req, 405, 'METHOD_NOT_ALLOWED', 'Method not allowed'));

  return router;
}

module.exports = createEvidenceRouter;
