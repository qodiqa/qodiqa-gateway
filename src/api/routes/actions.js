'use strict';

/**
 * POST /v1/actions/authorize - the per-action authorisation of an agent.
 *
 * The caller is the tenant's signing identity (Bearer sk_..., exactly as for /sign: src/middleware/signAuth.js, per-identity scope, environment, rate limits,
 * auth-failure lockout). It asks for permission to run ONE action for one agent session:
 *
 *   { agentId, sessionId, tool: { server, name }, args, parentRequestHash?, requestId?, proof? }
 *
 * and gets back an action artifact (src/core/actions/actionArtifact.js, Ed25519, lifetime <= 60 s, domain QODIQA::ACTION_ARTIFACT::V1) that binds
 * actionHash = SHA-256("QODIQA::ACTION::V2" || JCS-P1({v, tenantId, agentId, sessionId, seq, tool{server, name, schemaHash}, args, parentRequestHash, prevActionHash})).
 *
 * What this endpoint decides (each is a refusal with its own reason, none is a default-allow):
 *   * the agent and the session are live and belong to the identity's tenant; an agent with a registered key proves possession for THIS requestId
 *   * the tool is in the tenant's registry with an ACTIVE version (not pending review, not disabled); a tool-schema hash the caller names must be the active one
 *   * the arguments satisfy the registered schema (strictly: an argument the schema does not name is refused)
 *   * the action class is one the agent may use, the session has action and cost budget left; seq / prevActionHash are assigned by the gateway, never by the caller
 * * a tool that requires approval is refused until the approval flow exists - nothing a caller sends turns that check off
 *
 * The artifact authorises; it executes nothing. The executor (src/core/actions/executor.js) recomputes the hash from what it is about to run.
 */

const crypto = require('crypto');
const { Router } = require('express');
const enforceContentType = require('../../../middleware/enforceContentType');
const keyManager = require('../../../services/artifact/keyManager');
const { emit } = require('../../../services/logger');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { createSignAuthMiddleware } = require('../../middleware/signAuth');
const { createAuthLockout } = require('../../core/authLockout');
const signingIdentityStore = require('../../core/signing/signingIdentityStore');
const { isSigningPermitted } = require('../../core/signing/signingPermissions');
const { resolveServerEnvironment } = require('../../core/signing/serverEnvironment');
const agents = require('../../core/agents/agentStore');
const { verifyAgentCaller } = require('../../core/agents/agentAuth');
const registry = require('../../core/actions/toolRegistry');
const plans = require('../../core/actions/planStore');
const delegationStore = require('../../core/delegation/delegationStore');
const toolPolicy = require('../../core/mcp/toolPolicy');
const approvalStore = require('../../core/approvals/approvalStore');
const { computeActionHash, ActionHashError } = require('../../core/actions/actionHash');
const dlpStage = require('../../core/dlp/dlpService');
const { buildActionPayload, signActionArtifact, signActionArtifactNative, MAX_ACTION_TTL_MS } = require('../../core/actions/actionArtifact');

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BODY_KEYS = new Set(['agentId', 'sessionId', 'tool', 'args', 'parentRequestHash', 'requestId', 'proof', 'ttl', 'planId', 'delegationId', 'approvalId']);
const PLAN_BODY_KEYS = new Set(['agentId', 'sessionId', 'steps', 'ttlSeconds', 'requestId', 'proof']);
const DEFAULT_TTL_MS = 30_000;
const MIN_TTL_MS = 1_000;

function _intEnv(name, dflt) { const v = parseInt(process.env[name], 10); return Number.isFinite(v) && v > 0 ? v : dflt; }
const _lockoutConfig = () => ({
  authLockoutEnabled: process.env.QODIQA_SIGN_AUTH_LOCKOUT_ENABLED !== 'false', authLockoutMaxFailures: _intEnv('QODIQA_SIGN_AUTH_FAILURE_MAX', 10),
  authLockoutFailureWindowMs: _intEnv('QODIQA_SIGN_AUTH_FAILURE_WINDOW_MS', 60_000), authLockoutDurationMs: _intEnv('QODIQA_SIGN_AUTH_LOCKOUT_MS', 300_000),
  authLockoutBackoffMinMs: 0, authLockoutBackoffMaxMs: 0, authLockoutCredentialHashBytes: 16,
});

const STATUS_BY_REASON = {
  AGENT_SESSION_UNKNOWN: 403, AGENT_SESSION_ENDED: 403, AGENT_SESSION_EXPIRED: 403, AGENT_NOT_ACTIVE: 403, AGENT_PROOF_REQUIRED: 401, AGENT_PROOF_INVALID: 401,
  TOOL_NOT_REGISTERED: 403, TOOL_PENDING_REVIEW: 403, TOOL_DISABLED: 403, TOOL_SCHEMA_CHANGED: 409,
  ACTION_PLAN_REQUIRED: 403, ACTION_PLAN_UNKNOWN: 403, ACTION_PLAN_EXPIRED: 403, ACTION_NOT_IN_PLAN: 403, ACTION_PLAN_STEP_EXHAUSTED: 429,
  DELEGATION_INVALID: 403, DELEGATION_REVOKED: 403, DELEGATION_DEPTH_EXCEEDED: 403, DELEGATION_CYCLE: 403, DELEGATION_ATTENUATION_VIOLATION: 403, ACTION_NOT_IN_DELEGATION: 403,
  ACTION_POLICY_REQUIRED: 403, ACTION_POLICY_DENIED: 403, ACTION_TOOL_LIMIT: 429,
  SESSION_AWAITING_APPROVAL: 409, APPROVAL_PENDING: 202, APPROVAL_DENIED: 403, APPROVAL_EXPIRED: 403, APPROVAL_CANCELLED: 403, APPROVAL_INVALID: 403, APPROVAL_ALREADY_USED: 409,
  ACTION_CLASS_NOT_ALLOWED: 403, ACTION_APPROVAL_REQUIRED: 403, ACTION_BUDGET_EXHAUSTED: 429, COST_BUDGET_EXHAUSTED: 429, ACTION_CHAIN_MISMATCH: 409,
};

function createActionsRouter({ _authLockout, getPolicies, registryApi = registry, agentApi = agents, planApi = plans, delegationApi = delegationStore, approvalApi = approvalStore } = {}) {
  // caller-chosen requestIds already used for an authorisation: a second artifact with the same id could never run and would wedge the session behind it
const ISSUED_REQUEST_IDS = new Map();
const router = Router();
  const lockout = _authLockout || createAuthLockout(_lockoutConfig(), { namespace: 'sign' });
  // admission control for the agent action surface, before authentication and any work (src/api/admission.js)
  router.use(require('../admission').get('actions').middleware);
  router.use(createRateLimitMiddleware('sign_auth'));
  router.use(createSignAuthMiddleware({ store: signingIdentityStore, isSigningPermitted, authLockout: lockout }));
  router.use(createRateLimitMiddleware('sign'));

  router.post('/authorize', enforceContentType, async (req, res) => {
    const reqId = req.requestId ?? null;
    const identity = req.signingIdentity;
    const deny = (status, reason, extra = {}) => {
      emit('WARN', 'ACTION_AUTHORIZE_DECISION', { requestId: reqId, decision: 'BLOCK', reason, identityId: identity.id, tenantId: identity.tenantId, ...extra });
      return res.status(status).json({ decision: 'BLOCK', reason, details: {}, requestId: reqId });
    };
    if (identity.environment !== resolveServerEnvironment()) return deny(403, 'SCOPE_ENVIRONMENT_MISMATCH');
    const b = req.body;
    if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).some((k) => !BODY_KEYS.has(k))) return deny(400, 'INVALID_REQUEST');
    const t = b.tool;
    if (!t || typeof t !== 'object' || Array.isArray(t) || Object.keys(t).sort().join(',') !== 'name,server' || typeof t.server !== 'string' || typeof t.name !== 'string') return deny(400, 'ACTION_INVALID_TOOL');
    if (!b.args || typeof b.args !== 'object' || Array.isArray(b.args)) return deny(400, 'ACTION_INVALID_ARGS');
    if (b.parentRequestHash !== undefined && b.parentRequestHash !== null && !/^[0-9a-f]{64}$/.test(String(b.parentRequestHash))) return deny(400, 'ACTION_INVALID_PARENT');
    if (b.requestId !== undefined && !(typeof b.requestId === 'string' && UUID_V4.test(b.requestId))) return deny(400, 'INVALID_REQUEST');
    if (b.proof !== undefined && typeof b.proof !== 'string') return deny(400, 'INVALID_REQUEST');
    if (b.planId !== undefined && !(typeof b.planId === 'string' && UUID_V4.test(b.planId))) return deny(400, 'INVALID_REQUEST');
    if (b.delegationId !== undefined && !(typeof b.delegationId === 'string' && UUID_V4.test(b.delegationId))) return deny(400, 'INVALID_REQUEST');
    if (b.approvalId !== undefined && !(typeof b.approvalId === 'string' && UUID_V4.test(b.approvalId))) return deny(400, 'INVALID_REQUEST');
    let ttl = DEFAULT_TTL_MS;
    if (b.ttl !== undefined) { if (!Number.isInteger(b.ttl) || b.ttl < MIN_TTL_MS) return deny(400, 'INVALID_REQUEST'); ttl = Math.min(b.ttl, MAX_ACTION_TTL_MS); }
    const tenantId = identity.tenantId;
    const requestId = b.requestId || crypto.randomUUID();
    if (b.requestId) {
      const nowMs = Date.now();
      for (const [k, exp] of ISSUED_REQUEST_IDS) if (exp <= nowMs) ISSUED_REQUEST_IDS.delete(k);
      const key = `${tenantId}:${requestId}`;
      if (ISSUED_REQUEST_IDS.has(key)) return deny(409, 'REQUEST_ID_REUSED');
    }
    let planInfo = null;
    let delegationInfo = null;

    try {
      // 1. who is calling: the (tenant, agent, session) triple is live right now, and an agent with a registered key proves possession for this requestId
      const caller = await verifyAgentCaller({ tenantId, agentId: b.agentId, sessionId: b.sessionId, requestId, proof: b.proof });
      if (!caller.ok) return deny(STATUS_BY_REASON[caller.reason] || 403, caller.reason);
      // 2. the tool: registered, active, its CURRENT schema; arguments by that schema
      const reg = await registryApi.get(tenantId, t.server, t.name);
      if (!reg) return deny(403, 'TOOL_NOT_REGISTERED');
      if (!reg.active) return deny(403, reg.versions.some((v) => v.status === 'pending_review') ? 'TOOL_PENDING_REVIEW' : 'TOOL_DISABLED');
      const tool = reg.active;
      const valid = registryApi.validateArgs(tool, b.args);
      if (!valid.ok) return deny(400, 'ACTION_ARGS_INVALID', { path: valid.path, code: valid.code });
      if (b.approvalId !== undefined && !tool.requiresApproval) return deny(400, 'INVALID_REQUEST', { detail: 'this tool needs no approval' });
      // the tool's own constraints on what its arguments may touch: default deny for file / database / external_api / command
      const pol = toolPolicy.check(tool, b.args);
      if (!pol.ok) return deny(403, pol.code, { detail: pol.detail });
      if (!caller.allowedActionClasses.includes(tool.actionClass)) return deny(403, 'ACTION_CLASS_NOT_ALLOWED');
      // ABAC rules of tool scope (the tenant's policy set): who may authorise which tool, by class, server, reversibility - checked before anything is reserved
      {
        const abac = require('../../../services/policy/evaluators/abac');
        const { sanitizeSupplied } = require('../../../services/policy/abac/attributes');
        const set = dlpStage.policiesFor(tenantId, getPolicies);
        const verdict = abac.evaluateTool(set, { userId: identity.id, callerId: identity.id, tenantId, action: null, ip: req.clientIp || null, timestamp: Math.floor(Date.now() / 1000),
          attributes: sanitizeSupplied({ 'tool.server': t.server, 'tool.name': t.name, 'tool.class': tool.actionClass, 'tool.reversible': tool.reversible === true, 'agent.id': b.agentId }) });
        if (!verdict.pass) return deny(403, verdict.reason, { policyId: verdict.policyId });
      }
      // DLP on the arguments: checked BEFORE a chain position is reserved or an artifact exists, so a refused call leaves the session where it was. DETECT / BLOCK only.
      {
        const dlpArgs = dlpStage.applyToToolArgs(b.args, dlpStage.policiesFor(tenantId, getPolicies));
        await dlpStage.recordEvents(dlpArgs.events, { requestId, tenantId });
        if (dlpArgs.blocked) return deny(403, dlpArgs.reason, { dlp: { direction: 'tool_input', rules: [...new Set(dlpArgs.events.flatMap((e) => e.rules))] } });
      }
      // 2a. delegated authority: the chain must be valid and unrevoked NOW, the agent must be its delegate, and the action must lie within what the chain still allows
      let liveDelegation = null;
      if (b.delegationId !== undefined) {
        liveDelegation = await delegationApi.verifyLive(tenantId, b.delegationId, { agentId: b.agentId });
        if (!liveDelegation.ok) return deny(STATUS_BY_REASON[liveDelegation.reason] || 403, liveDelegation.reason, { delegationId: b.delegationId, detail: liveDelegation.detail });
        if (!liveDelegation.classes.includes(tool.actionClass)) return deny(403, 'ACTION_CLASS_NOT_ALLOWED', { delegationId: b.delegationId });
        if (liveDelegation.tools && !liveDelegation.tools.some((x) => x.server === t.server && x.name === t.name)) return deny(403, 'ACTION_NOT_IN_DELEGATION', { delegationId: b.delegationId });
        delegationInfo = { delegationId: b.delegationId, chainHash: liveDelegation.chainHash, depth: liveDelegation.depth, rootAgentId: liveDelegation.rootAgentId };
      }
      // 2c. human approval: a tool that requires it gets a REQUEST first (202), and an artifact only with the approval that answers it
      let approval = null;
      let requestOnly = false;
      if (tool.requiresApproval) {
        if (b.approvalId === undefined) requestOnly = true;
        else {
          approval = await approvalApi.get(tenantId, b.approvalId);
          if (!approval || approval.agentId !== b.agentId || approval.sessionId !== b.sessionId || approval.tool.server !== t.server || approval.tool.name !== t.name) return deny(403, 'APPROVAL_INVALID');
          // the approval is for exactly this action: the hash recomputed from what is being asked now, at the position the request reserved
          let again;
          try {
            again = computeActionHash({ tenantId, agentId: b.agentId, sessionId: b.sessionId, seq: approval.seq, tool: { server: t.server, name: t.name, schemaHash: tool.schemaHash }, args: b.args,
              parentRequestHash: b.parentRequestHash ?? null, prevActionHash: approval.prevActionHash });
          } catch { return deny(403, 'APPROVAL_INVALID'); }
          if (again !== approval.actionHash) return deny(403, 'APPROVAL_INVALID', { detail: 'not this action' });
          if (approval.status === 'PENDING') return res.status(202).json({ status: 'pending', timestamp: new Date().toISOString(), requestId: reqId, data: { approvalId: approval.approvalId, actionHash: approval.actionHash, expiresAt: approval.expiresAt } });
          if (approval.status !== 'APPROVED') return deny(STATUS_BY_REASON[`APPROVAL_${approval.status}`] || 403, `APPROVAL_${approval.status}`, { approvalId: approval.approvalId });
        }
      }
      // while an approval request of this session is open the session authorises nothing else: the position it reserved must stay the last one so that it can be given back
      if (!approval && await approvalApi.hasOpen(tenantId, b.sessionId)) return deny(409, 'SESSION_AWAITING_APPROVAL');
      // 2b. the plan: while the session has an active plan every action must be a step of it, and the step must have calls left. Only CHECKED here; the step is
      //     charged after the chain position is reserved, so a request that is refused later never uses up the plan or a delegation.
      const planIdUsed = approval ? (approval.planId || b.planId) : b.planId;
      const active = await planApi.activePlan(tenantId, b.sessionId);
      if (planIdUsed !== undefined || active) {
        if (planIdUsed === undefined || planIdUsed === null) return deny(403, 'ACTION_PLAN_REQUIRED');
        const step = await planApi.peekStep(tenantId, planIdUsed, { sessionId: b.sessionId, agentId: b.agentId, server: t.server, name: t.name });
        if (!step.ok) return deny(STATUS_BY_REASON[step.reason] || 403, step.reason);
        planInfo = { planId: planIdUsed, planHash: step.planHash, step: step.stepIndex, used: step.used, maxCalls: step.maxCalls };
      }
      // 3. position in the session chain; seq / prevActionHash are the gateway's, assigned atomically (a concurrent authorisation moves the chain: re-read and retry)
      let reserved = null; let actionHash = null; let prevActionHash = null; let seq = null;
      if (approval) { reserved = { ok: true, seq: approval.seq }; actionHash = approval.actionHash; prevActionHash = approval.prevActionHash; seq = approval.seq; }   // the request reserved it
      for (let attempt = 0; attempt < 8 && !reserved; attempt++) {
        const s = await agentApi.getSession(tenantId, b.sessionId);
        if (!s) return deny(403, 'AGENT_SESSION_UNKNOWN');
        seq = s.nextSeq; prevActionHash = s.lastActionHash;
        actionHash = computeActionHash({ tenantId, agentId: b.agentId, sessionId: b.sessionId, seq, tool: { server: t.server, name: t.name, schemaHash: tool.schemaHash }, args: b.args,
          parentRequestHash: b.parentRequestHash ?? null, prevActionHash });
        const r = await agentApi.reserveAction(tenantId, b.sessionId, { actionClass: tool.actionClass, actionHash, prevActionHash });
        if (r.ok) { if (r.seq !== seq) return deny(409, 'ACTION_CHAIN_MISMATCH'); reserved = r; } else if (r.reason !== 'ACTION_CHAIN_MISMATCH') return deny(STATUS_BY_REASON[r.reason] || 403, r.reason);
      }
      if (!reserved) return deny(409, 'ACTION_CHAIN_MISMATCH');
      if (!requestOnly) {
        // 3b. charge what this artifact uses - plan step, delegation budget, the approval - and give the chain position back if one of them is refused (an approved action keeps
        //     the position its request reserved: that one is closed by the approval itself)
        const giveBack = async () => { if (!approval) { try { await agentApi.releaseReservation(tenantId, b.sessionId, { seq, prevActionHash, actionHash }); } catch { /* the position stays; the session budget already counted it */ } } };
        if (planInfo) {
          const step = await planApi.consumeStep(tenantId, planInfo.planId, { sessionId: b.sessionId, agentId: b.agentId, server: t.server, name: t.name });
          if (!step.ok) { await giveBack(); return deny(STATUS_BY_REASON[step.reason] || 403, step.reason); }
          planInfo = { planId: planInfo.planId, planHash: step.planHash, step: step.stepIndex, used: step.used, maxCalls: step.maxCalls };
        }
        if (liveDelegation) {
          const used = await delegationApi.useDelegation(tenantId, liveDelegation, { requestId, agentId: b.agentId, sessionId: b.sessionId });
          if (!used.ok) { await giveBack(); return deny(STATUS_BY_REASON[used.reason] || 429, used.reason, { delegationId: b.delegationId }); }
        }
        if (approval) {
          // spend the approval: once, for this artifact
          const spent = await approvalApi.issue(tenantId, approval.approvalId, { agentId: b.agentId, sessionId: b.sessionId, actionHash: approval.actionHash }, { requestId });
          if (!spent.ok) return deny(STATUS_BY_REASON[spent.reason] || 403, spent.reason, { approvalId: approval.approvalId, ...(spent.detail ? { detail: spent.detail } : {}) });
        }
      }
      if (requestOnly) {
        const a = await approvalApi.request(tenantId, { sessionId: b.sessionId, agentId: b.agentId, seq, actionHash, prevActionHash, server: t.server, tool: t.name, schemaHash: tool.schemaHash, actionClass: tool.actionClass,
          args: b.args, parentRequestHash: b.parentRequestHash ?? null, planId: planInfo ? planInfo.planId : null, delegationId: b.delegationId || null, requesterId: `identity:${identity.id}`, requesterUserId: caller.actsFor || null });
        return res.status(202).json({ status: 'pending', timestamp: new Date().toISOString(), requestId: reqId, data: { approvalId: a.approvalId, actionHash, seq, expiresAt: a.expiresAt } });
      }
      // 4. sign
      const key = keyManager.getSigningKey(tenantId);
      const now = Date.now();
      const fields = { payload: buildActionPayload({ requestId, tenantId, agentId: b.agentId, sessionId: b.sessionId, seq, actionHash, ...(approval ? { approvalRef: approval.approvalId } : {}) }), timestamp: now, expiry: now + ttl, publicKeyId: key.keyId };
      const artifact = key.nativeSigning ? await signActionArtifactNative(fields, keyManager.nativeSign) : signActionArtifact(fields, key.privDer);
      emit('INFO', 'ACTION_AUTHORIZE_DECISION', { requestId: reqId, decision: 'ALLOW', reason: 'ACTION_AUTHORIZED', identityId: identity.id, tenantId, agentId: b.agentId, sessionId: b.sessionId, seq,
        actionHash, tool: `${t.server}/${t.name}`, toolVersion: tool.version, actsFor: caller.actsFor, artifactId: requestId, ...(planInfo ? { planId: planInfo.planId, planHash: planInfo.planHash, planStep: planInfo.step } : {}), ...(delegationInfo ? { delegation: delegationInfo } : {}), ...(approval ? { approvalId: approval.approvalId, approverId: approval.approverId } : {}) });
      if (b.requestId) ISSUED_REQUEST_IDS.set(`${tenantId}:${requestId}`, Date.now() + MAX_ACTION_TTL_MS + 10_000);   // only an ISSUED artifact uses the id up (a 202 or a refusal does not)
      return res.status(200).json({
        artifactId: requestId, artifact,
        action: { actionHash, seq, prevActionHash, tool: { server: t.server, name: t.name, schemaHash: tool.schemaHash, version: tool.version }, parentRequestHash: b.parentRequestHash ?? null },
        meta: { keyId: key.keyId, expiresAt: now + ttl, tenantId, agentId: b.agentId, sessionId: b.sessionId, actionClass: tool.actionClass, reversible: tool.reversible, ...(planInfo ? { plan: planInfo } : {}), ...(delegationInfo ? { delegation: delegationInfo } : {}), ...(approval ? { approvalId: approval.approvalId, approverId: approval.approverId } : {}) },
        requestId: reqId,
      });
    } catch (err) {
      if (err instanceof ActionHashError) return deny(400, err.code);
      if (err && err.code === '23505') return deny(409, 'REQUEST_ID_REUSED');
      if (err && (err.name === 'AgentError' || err.name === 'ToolError' || err.name === 'ApprovalError')) return deny(err.status || 400, err.code);
      emit('ERROR', 'ACTION_AUTHORIZE_FAILED', { requestId: reqId, tenantId, error: err && err.message });
      return res.status(503).json({ decision: 'BLOCK', reason: 'ACTION_AUTHORIZATION_UNAVAILABLE', details: {}, requestId: reqId });
    }
  });

  // The requester's side of an approval: look at it, withdraw it. Only the identity that asked sees or cancels it.
  const requesterView = (a) => ({ approvalId: a.approvalId, status: a.status, actionHash: a.actionHash, seq: a.seq, tool: a.tool, agentId: a.agentId, sessionId: a.sessionId, requestedAt: a.requestedAt, expiresAt: a.expiresAt,
    approverId: a.approverId, decidedAt: a.decidedAt, decisionReason: a.decisionReason, notBefore: a.notBefore, approvalExpiresAt: a.approvalExpiresAt, usedAt: a.usedAt, cancelledAt: a.cancelledAt });
  router.get('/approvals/:approvalId', async (req, res) => {
    const identity = req.signingIdentity; const reqId = req.requestId ?? null;
    try {
      const a = await approvalApi.get(identity.tenantId, req.params.approvalId);
      if (!a || a.requesterId !== `identity:${identity.id}`) return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND', details: {}, requestId: reqId });
      return res.status(200).json({ status: 'success', timestamp: new Date().toISOString(), requestId: reqId, data: requesterView(a) });
    } catch (err) {
      if (err && err.name === 'ApprovalError') return res.status(err.status || 400).json({ decision: 'BLOCK', reason: err.code, details: {}, requestId: reqId });
      return res.status(503).json({ decision: 'BLOCK', reason: 'ACTION_AUTHORIZATION_UNAVAILABLE', details: {}, requestId: reqId });
    }
  });
  router.post('/approvals/:approvalId/cancel', enforceContentType, async (req, res) => {
    const identity = req.signingIdentity; const reqId = req.requestId ?? null;
    const body = req.body || {};
    if (typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some((k) => k !== 'reason') || (body.reason !== undefined && !(typeof body.reason === 'string' && body.reason.length <= 500))) return res.status(400).json({ decision: 'BLOCK', reason: 'INVALID_REQUEST', details: {}, requestId: reqId });
    try {
      const cur = await approvalApi.get(identity.tenantId, req.params.approvalId);
      if (!cur || cur.requesterId !== `identity:${identity.id}`) return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND', details: {}, requestId: reqId });
      const a = await approvalApi.cancel(identity.tenantId, req.params.approvalId, { by: `identity:${identity.id}`, reason: body.reason });
      return res.status(200).json({ status: 'success', timestamp: new Date().toISOString(), requestId: reqId, data: requesterView(a) });
    } catch (err) {
      if (err && err.name === 'ApprovalError') return res.status(err.status || 400).json({ decision: 'BLOCK', reason: err.code, details: {}, requestId: reqId });
      return res.status(503).json({ decision: 'BLOCK', reason: 'ACTION_AUTHORIZATION_UNAVAILABLE', details: {}, requestId: reqId });
    }
  });

  // The execution plan of a session: authorised once, then every action is authorised individually against it.
  router.post('/plans', enforceContentType, async (req, res) => {
    const reqId = req.requestId ?? null;
    const identity = req.signingIdentity;
    const tenantId = identity.tenantId;
    const deny = (status, reason, extra = {}) => {
      emit('WARN', 'ACTION_PLAN_DECISION', { requestId: reqId, decision: 'BLOCK', reason, identityId: identity.id, tenantId, ...extra });
      return res.status(status).json({ decision: 'BLOCK', reason, details: {}, requestId: reqId });
    };
    if (identity.environment !== resolveServerEnvironment()) return deny(403, 'SCOPE_ENVIRONMENT_MISMATCH');
    const b = req.body;
    if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).some((k) => !PLAN_BODY_KEYS.has(k))) return deny(400, 'INVALID_REQUEST');
    if (b.requestId !== undefined && !(typeof b.requestId === 'string' && UUID_V4.test(b.requestId))) return deny(400, 'INVALID_REQUEST');
    if (b.proof !== undefined && typeof b.proof !== 'string') return deny(400, 'INVALID_REQUEST');
    try {
      const caller = await verifyAgentCaller({ tenantId, agentId: b.agentId, sessionId: b.sessionId, requestId: b.requestId, proof: b.proof });
      if (!caller.ok) return deny(STATUS_BY_REASON[caller.reason] || 403, caller.reason);
      // every step must be a registered, active tool the agent may use and that needs no approval (what cannot run cannot be planned)
      const list = Array.isArray(b.steps) ? b.steps : null;
      if (!list) return deny(400, 'INVALID_PLAN');
      for (const st of list) {
        if (!st || typeof st.server !== 'string' || typeof st.name !== 'string') return deny(400, 'INVALID_PLAN');
        const reg = await registryApi.get(tenantId, st.server, st.name);
        if (!reg) return deny(403, 'TOOL_NOT_REGISTERED', { tool: `${st.server}/${st.name}` });
        if (!reg.active) return deny(403, reg.versions.some((v) => v.status === 'pending_review') ? 'TOOL_PENDING_REVIEW' : 'TOOL_DISABLED', { tool: `${st.server}/${st.name}` });
        if (reg.active.requiresApproval) return deny(403, 'ACTION_APPROVAL_REQUIRED', { tool: `${st.server}/${st.name}` });
        if (!caller.allowedActionClasses.includes(reg.active.actionClass)) return deny(403, 'ACTION_CLASS_NOT_ALLOWED', { tool: `${st.server}/${st.name}` });
      }
      const plan = await planApi.createPlan(tenantId, { sessionId: b.sessionId, agentId: b.agentId, steps: list, ttlSeconds: b.ttlSeconds }, `identity:${identity.id}`);
      return res.status(201).json({ planId: plan.planId, plan, requestId: reqId });
    } catch (err) {
      if (err && (err.name === 'PlanError' || err.name === 'AgentError' || err.name === 'ToolError')) return deny(err.status || 400, err.code);
      emit('ERROR', 'ACTION_PLAN_FAILED', { requestId: reqId, tenantId, error: err && err.message });
      return res.status(503).json({ decision: 'BLOCK', reason: 'ACTION_AUTHORIZATION_UNAVAILABLE', details: {}, requestId: reqId });
    }
  });

  router.use((req, res) => res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null }));
  return router;
}

module.exports = { createActionsRouter };
