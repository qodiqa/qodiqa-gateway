'use strict';

/**
 * Human approval of agent actions - /v1/approvals.
 *
 *   GET  /?tenantId=&status=&agentId=       the requests (expiry applied)                                READ_APPROVALS
 *   GET  /:approvalId?tenantId=             one request WITH the action it is about (tool and arguments)  READ_APPROVALS
 *   POST /:approvalId/decision              { tenantId, decision: "APPROVE" | "DENY", reason?, ttlSeconds?, notBefore? }       DECIDE_APPROVALS
 *
 * The approver is never the requester: not the signing identity that asked, not the user the agent acts for, not an operator that user provisioned
 * (src/core/approvals/approvalStore.js, src/core/policy/governance/independence.js). A decision is signed by the gateway (QODIQA::APPROVAL::V1) and bound to the actionHash
 * the approver saw. The requester's side - looking at a request and withdrawing it - is on the signing-identity API: GET / POST /v1/actions/approvals/{id}[/cancel].
 */

const { Router } = require('express');
const store = require('../../core/approvals/approvalStore');
const { success, failure } = require('../response');
const { permissionGuard } = require('./permissionGuard');

function _handle(res, fn) {
  return Promise.resolve().then(fn).catch((err) => {
    if (err && err.name === 'ApprovalError') return failure(res, err.code, err.message, err.status || 400);
    return failure(res, 'APPROVAL_STORE_UNAVAILABLE', 'The approval store could not process the request.', 503);
  });
}
const tenantOf = (req) => (typeof (req.body && req.body.tenantId) === 'string' ? req.body.tenantId : (typeof req.query.tenantId === 'string' ? req.query.tenantId : ''));

function createApprovalsRouter({ requirePermission, approvals = store } = {}) {
  const router = Router();
  const canDecide = permissionGuard(requirePermission, 'DECIDE_APPROVALS', 'approvals');
  const canRead = permissionGuard(requirePermission, 'READ_APPROVALS', 'approvals');

  router.get('/', canRead, (req, res) => _handle(res, async () => success(res, { approvals: await approvals.list(tenantOf(req), { status: req.query.status || undefined, agentId: req.query.agentId || undefined }) })));
  router.get('/:approvalId', canRead, (req, res) => _handle(res, async () => {
    const a = await approvals.get(tenantOf(req), req.params.approvalId);
    return a ? success(res, a) : failure(res, 'NOT_FOUND', 'No such approval request.', 404);
  }));
  router.post('/:approvalId/decision', canDecide, (req, res) => _handle(res, async () => {
    const b = req.body || {};
    if (typeof b !== 'object' || Array.isArray(b) || Object.keys(b).some((k) => !['tenantId', 'decision', 'reason', 'ttlSeconds', 'notBefore'].includes(k))) return failure(res, 'INVALID_REQUEST', 'Unknown member in the decision.', 400);
    const u = req.rbacUser || {};
    const a = await approvals.decide(tenantOf(req), req.params.approvalId, { decision: b.decision, reason: b.reason, ttlSeconds: b.ttlSeconds, notBefore: b.notBefore }, { id: u.id, username: u.username });
    return success(res, a);
  }));
  return router;
}

module.exports = { createApprovalsRouter };
