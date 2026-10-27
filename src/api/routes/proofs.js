'use strict';

/**
 * Downloadable proof of one request.
 *
 *   GET /v1/proofs/:requestId?tenantId=<tenant>     READ_AUDIT_PROOFS (auditor, compliance, admin)
 *
 * Assembles `qodiqa-proof/1` (docs/protocol/VECTORS-FORMAT.md section 3) from the audit chain, the transparency log, the checkpoints, the receipt store and
 * the external anchors (src/core/audit/proofAssembler.js). The gateway does not store the signed artifact: the caller adds it when verifying
 * (`node scripts/audit-repro/verify/qodiqa-proof-verify.js --proof proof.json --artifact artifact.json [--anchors-repo <dir>]`).
 *
 * Chain path: the contiguous path between the request and its checkpoint contains OTHER tenants' raw entries, so it is served only with
 * `?fullChain=true` and the platform-wide permission READ_AUDIT_PROOFS_FULL_CHAIN (admin); otherwise it is withheld (`parts.chainPathWithheld`) and the
 * proof is partial (CHAIN_NOT_ANCHORED).
 *
 * Tenant isolation: operator credentials are not tenant-scoped in this codebase, so the isolation boundary is the explicit `tenantId`: the request is looked
 * up WITH it, and a request of another tenant answers exactly like an unknown one (404 NOT_FOUND). Reading a proof needs no MFA step-up; every read is logged
 * (PROOF_ACCESSED with the operator) and counted.
 */

const { Router } = require('express');
const { success, failure } = require('../response');
const { emit } = require('../../../services/logger');
const { permissionGuard } = require('./permissionGuard');
const { resolveOperatorActor } = require('../../core/audit/actorAttribution');
const { assembleProof } = require('../../core/audit/proofAssembler');

const REQUEST_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TENANT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function _count(outcome) {
  try { require('../../observability/metrics').proofRequestsTotal.inc({ outcome }); }
  catch (err) { try { emit('WARN', 'PROOF_METRIC_FAILED', { outcome, error: err && err.message }); } catch { /* logging is fail-safe */ } }
}

function createProofsRouter({ requirePermission, assemble = assembleProof } = {}) {
  const router = Router();
  const _canRead = permissionGuard(requirePermission, 'READ_AUDIT_PROOFS', 'proofs');
  const _canReadFull = permissionGuard(requirePermission, 'READ_AUDIT_PROOFS_FULL_CHAIN', 'proofs');

  // ?fullChain=true needs the platform-wide permission (it serves other tenants' raw entries between the request and its checkpoint)
  const _fullGate = (req, res, next) => (req.query.fullChain === 'true' ? _canReadFull(req, res, next) : next());

  router.get('/:requestId', _canRead, _fullGate, async (req, res) => {
    const requestId = String(req.params.requestId).toLowerCase();   // D-13: UUIDs are case-insensitive; stored ids are lower case
    const tenantId = typeof req.query.tenantId === 'string' ? req.query.tenantId : '';
    if (!REQUEST_ID_RE.test(requestId)) { _count('invalid'); return failure(res, 'INVALID_REQUEST_ID', 'requestId must be the UUID of the request', 400); }
    if (!TENANT_ID_RE.test(tenantId)) { _count('invalid'); return failure(res, 'TENANT_ID_REQUIRED', 'tenantId is required: the proof of a request is only served for the tenant that owns it', 400); }
    const actor = resolveOperatorActor(req);
    try {
      const out = await assemble({ tenantId, requestId, allowForeignEntries: req.query.fullChain === 'true' });
      if (!out.ok) {
        _count('not_found');
        emit('INFO', 'PROOF_ACCESSED', { requestId, tenantId, actor, outcome: 'not_found' });
        return failure(res, 'NOT_FOUND', 'No proof is available for this request.', 404);
      }
      _count('served');
      emit('INFO', 'PROOF_ACCESSED', { requestId, tenantId, actor, outcome: 'served', parts: out.parts });
      res.set('Cache-Control', 'no-store');
      return success(res, out.proof);
    } catch (err) {
      _count('error');
      emit('ERROR', 'PROOF_ASSEMBLY_FAILED', { requestId, tenantId, actor, error: err && err.message });
      return failure(res, 'PROOF_UNAVAILABLE', 'The proof could not be assembled.', 503);
    }
  });

  return router;
}

module.exports = { createProofsRouter, REQUEST_ID_RE };
