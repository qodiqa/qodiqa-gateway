'use strict';

/**
 * /v1/delegations - delegation of authority between agents. Authenticated like /sign (a tenant signing identity); every statement runs under the identity's
 * tenant, so another tenant's delegation is indistinguishable from an unknown one.
 *
 *   POST /                   issue a delegation (root grant, or a narrower child of a delegation the issuer holds). The ISSUANCE IS AN AUTHORISED ACTION of the
 * issuer's session: class `delegate`, a live session, counted against the session's action and cost budgets (it takes no place in
 *                            the session's chain of artifacts: nothing executes for a delegation), traced by a DELEGATION_ISSUED entry (audit schema v8).
 *   POST /verify             check a chain: { chain: [envelopes root first] } offline (signatures, links, attenuation, depth, cycle) plus the live state of its leaf
 *                            when the gateway knows it, or { delegationId } for a stored one
 *   GET  /:delegationId      the stored delegation with its chain of tokens
 *   POST /:delegationId/revoke   revoke it and everything below it { reason, revokeAgents? } - the executions running under it are aborted
 */

const crypto = require('crypto');
const { Router } = require('express');
const enforceContentType = require('../../../middleware/enforceContentType');
const { emit } = require('../../../services/logger');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { createSignAuthMiddleware } = require('../../middleware/signAuth');
const { createAuthLockout } = require('../../core/authLockout');
const signingIdentityStore = require('../../core/signing/signingIdentityStore');
const { isSigningPermitted } = require('../../core/signing/signingPermissions');
const { resolveServerEnvironment } = require('../../core/signing/serverEnvironment');
const agents = require('../../core/agents/agentStore');
const { verifyAgentCaller } = require('../../core/agents/agentAuth');
const store = require('../../core/delegation/delegationStore');
const tok = require('../../core/delegation/delegationToken');

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ISSUE_KEYS = new Set(['issuerAgentId', 'issuerSessionId', 'parentId', 'subjectAgentId', 'classes', 'tools', 'maxActions', 'ttlSeconds', 'maxDepth', 'requestId', 'proof']);

function _intEnv(name, dflt) { const v = parseInt(process.env[name], 10); return Number.isFinite(v) && v > 0 ? v : dflt; }
const _lockoutConfig = () => ({
  authLockoutEnabled: process.env.QODIQA_SIGN_AUTH_LOCKOUT_ENABLED !== 'false', authLockoutMaxFailures: _intEnv('QODIQA_SIGN_AUTH_FAILURE_MAX', 10),
  authLockoutFailureWindowMs: _intEnv('QODIQA_SIGN_AUTH_FAILURE_WINDOW_MS', 60_000), authLockoutDurationMs: _intEnv('QODIQA_SIGN_AUTH_LOCKOUT_MS', 300_000),
  authLockoutBackoffMinMs: 0, authLockoutBackoffMaxMs: 0, authLockoutCredentialHashBytes: 16,
});
const STATUS = { AGENT_PROOF_REQUIRED: 401, AGENT_PROOF_INVALID: 401, ACTION_BUDGET_EXHAUSTED: 429, COST_BUDGET_EXHAUSTED: 429, ACTION_CHAIN_MISMATCH: 409, ACTION_ORDER_VIOLATION: 409, ACTION_REPLAY: 409 };

function createDelegationsRouter({ _authLockout, delegationApi = store, agentApi = agents } = {}) {
  const router = Router();
  const lockout = _authLockout || createAuthLockout(_lockoutConfig(), { namespace: 'sign' });
  router.use(createRateLimitMiddleware('sign_auth'));
  router.use(createSignAuthMiddleware({ store: signingIdentityStore, isSigningPermitted, authLockout: lockout }));
  router.use(createRateLimitMiddleware('sign'));

  const ctxOf = (req, res) => {
    const reqId = req.requestId ?? null; const identity = req.signingIdentity; const tenantId = identity.tenantId;
    const deny = (status, reason, extra = {}) => {
      emit('WARN', 'DELEGATION_DECISION', { requestId: reqId, decision: 'BLOCK', reason, identityId: identity.id, tenantId, ...extra });
      return res.status(status).json({ decision: 'BLOCK', reason, details: {}, requestId: reqId });
    };
    return { reqId, identity, tenantId, deny };
  };
  const mapErr = (err, c) => {
    if (err && (err.name === 'DelegationStoreError' || err.name === 'AgentError' || err.name === 'DelegationError')) return c.deny(err.status || 403, err.code);
    emit('ERROR', 'DELEGATION_FAILED', { requestId: c.reqId, tenantId: c.tenantId, error: err && err.message });
    return c.deny(503, 'DELEGATION_UNAVAILABLE');
  };

  router.post('/', enforceContentType, async (req, res) => {
    const c = ctxOf(req, res);
    const { tenantId } = c;
    if (c.identity.environment !== resolveServerEnvironment()) return c.deny(403, 'SCOPE_ENVIRONMENT_MISMATCH');
    const b = req.body;
    if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).some((k) => !ISSUE_KEYS.has(k))) return c.deny(400, 'INVALID_REQUEST');
    if (b.requestId !== undefined && !(typeof b.requestId === 'string' && UUID_V4.test(b.requestId))) return c.deny(400, 'INVALID_REQUEST');
    if (b.proof !== undefined && typeof b.proof !== 'string') return c.deny(400, 'INVALID_REQUEST');
    const requestId = b.requestId || crypto.randomUUID();
    try {
      // who is delegating: the issuer agent in a live session (proof of possession when it has a key), with the right to delegate at all
      const caller = await verifyAgentCaller({ tenantId, agentId: b.issuerAgentId, sessionId: b.issuerSessionId, requestId, proof: b.proof });
      if (!caller.ok) return c.deny(STATUS[caller.reason] || 403, caller.reason);
      if (!caller.allowedActionClasses.includes('delegate')) return c.deny(403, 'ACTION_CLASS_NOT_ALLOWED', { needs: 'delegate' });
      // the issuance is an authorised action of the issuer's session: its class, its live session and its budgets are checked and charged. It takes NO place in the
      // session's action chain (seq / prevActionHash): that chain is the chain of artifacts, and nothing executes for a delegation
      const charged = await agentApi.chargeAction(tenantId, b.issuerSessionId, { actionClass: 'delegate' });
      if (!charged.ok) return c.deny(STATUS[charged.reason] || 403, charged.reason);
      const issued = await delegationApi.issue(tenantId, { issuerAgentId: b.issuerAgentId, subjectAgentId: b.subjectAgentId, parentId: b.parentId, classes: b.classes, tools: b.tools, maxActions: b.maxActions,
        ttlSeconds: b.ttlSeconds, maxDepth: b.maxDepth }, `identity:${c.identity.id}`);
      emit('INFO', 'DELEGATION_DECISION', { requestId: c.reqId, decision: 'ALLOW', reason: 'DELEGATION_ISSUED', identityId: c.identity.id, tenantId, delegationId: issued.delegation.delegationId, depth: issued.delegation.depth,
        rootAgentId: issued.delegation.rootAgentId, issuerAgentId: b.issuerAgentId, subjectAgentId: b.subjectAgentId, chainHash: issued.chainHash, issuerSessionId: b.issuerSessionId, sessionActionsUsed: charged.session.actionsUsed, actsFor: caller.actsFor });
      return res.status(201).json({ delegationId: issued.delegation.delegationId, delegation: issued.delegation, token: issued.token, chainHash: issued.chainHash, requestId: c.reqId });
    } catch (err) { return mapErr(err, c); }
  });

  router.post('/verify', enforceContentType, async (req, res) => {
    const c = ctxOf(req, res);
    const b = req.body;
    if (!b || typeof b !== 'object' || Array.isArray(b) || (b.chain === undefined) === (b.delegationId === undefined) || Object.keys(b).some((k) => !['chain', 'delegationId'].includes(k))) return c.deny(400, 'INVALID_REQUEST');
    try {
      if (b.delegationId !== undefined) {
        const live = await delegationApi.verifyLive(c.tenantId, b.delegationId);
        if (!live.ok) return res.status(200).json({ valid: false, reason: live.reason, ...(live.detail ? { detail: live.detail } : {}), requestId: c.reqId });
        return res.status(200).json({ valid: true, state: 'ACTIVE', ..._facts(live), requestId: c.reqId });
      }
      const v = tok.verifyChain(b.chain, { resolveKey: require('../../validation/resolveKey').resolveKey });
      if (!v.ok) return res.status(200).json({ valid: false, reason: v.reason, ...(v.detail ? { detail: v.detail } : {}), ...(v.index !== undefined ? { index: v.index } : {}), requestId: c.reqId });
      if (v.tenantId !== c.tenantId) return res.status(200).json({ valid: false, reason: 'DELEGATION_INVALID', detail: 'tenant', requestId: c.reqId });
      const stored = await delegationApi.get(c.tenantId, v.delegationId);
      const state = !stored ? 'UNKNOWN' : (stored.status === 'active' ? 'ACTIVE' : 'REVOKED');
      if (state === 'REVOKED') return res.status(200).json({ valid: false, reason: 'DELEGATION_REVOKED', requestId: c.reqId });
      return res.status(200).json({ valid: true, state, ..._facts(v), requestId: c.reqId });
    } catch (err) { return mapErr(err, c); }
  });

  router.get('/:delegationId', async (req, res) => {
    const c = ctxOf(req, res);
    try {
      const d = await delegationApi.get(c.tenantId, req.params.delegationId);
      if (!d || !(await delegationApi.isControlledBy(c.tenantId, req.params.delegationId, `identity:${c.identity.id}`))) return c.deny(404, 'NOT_FOUND'); // A1-01: not another identity's delegation
      const live = await delegationApi.verifyLive(c.tenantId, req.params.delegationId).catch(() => ({ ok: false }));
      return res.status(200).json({ delegation: d, chain: live.ok ? live.chain : undefined, valid: live.ok === true, ...(live.ok ? {} : { reason: live.reason }), requestId: c.reqId });
    } catch (err) { return mapErr(err, c); }
  });

  router.post('/:delegationId/revoke', enforceContentType, async (req, res) => {
    const c = ctxOf(req, res);
    const b = req.body || {};
    if (typeof b !== 'object' || Array.isArray(b) || Object.keys(b).some((k) => !['reason', 'revokeAgents'].includes(k)) || typeof b.reason !== 'string' || !b.reason.trim() || b.reason.length > 256
      || (b.revokeAgents !== undefined && typeof b.revokeAgents !== 'boolean')) return c.deny(400, 'INVALID_REQUEST');
    try {
      if (!(await delegationApi.isControlledBy(c.tenantId, req.params.delegationId, `identity:${c.identity.id}`))) return c.deny(404, 'NOT_FOUND'); // A1-01
      const r = await delegationApi.revoke(c.tenantId, req.params.delegationId, { reason: b.reason.trim(), actor: `identity:${c.identity.id}`, revokeAgents: b.revokeAgents === true });
      return res.status(200).json({ ...r, requestId: c.reqId });
    } catch (err) { return mapErr(err, c); }
  });

  router.use((req, res) => res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null }));
  return router;
}

const _facts = (v) => ({ delegationId: v.delegationId, depth: v.depth, maxDepth: v.maxDepth, chainHash: v.chainHash, rootAgentId: v.rootAgentId, issuerAgentId: v.issuerAgentId, subjectAgentId: v.subjectAgentId,
  classes: v.classes, tools: v.tools, maxActions: v.maxActions, expiresAt: new Date(v.expiry).toISOString() });

module.exports = { createDelegationsRouter };
