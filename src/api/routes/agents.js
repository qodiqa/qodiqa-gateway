'use strict';

/**
 * Agent identities and sessions API.
 *
 *   /v1/agents      (control plane: operator MFA step-up on every change)
 *     POST   /                       create an agent (the agentId is issued by the gateway: a UUID v4)   MANAGE_AGENTS
 *     GET    /?tenantId=&status=     list                                   READ_AGENTS
 *     GET    /:agentId?tenantId=     one agent                              READ_AGENTS
 *     PATCH  /:agentId               change limits / suspend / revoke       MANAGE_AGENTS   (revoked is absorbing; suspend / revoke end its active sessions)
 *
 * Sessions are in src/api/routes/agentSessions.js.
 *
 * Operator credentials are not tenant-scoped in this codebase, so every call names its tenant (body or query) and every statement runs under that tenant's
 * row-level security. Another tenant's agent or session is indistinguishable from an unknown one (404).
 */

const { Router } = require('express');
const store = require('../../core/agents/agentStore');
const { resolveOperatorActor } = require('../../core/audit/actorAttribution');
const { success, failure } = require('../response');
const { permissionGuard } = require('./permissionGuard');

function _handle(res, fn) {
  return Promise.resolve().then(fn).catch((err) => {
    if (err && err.name === 'AgentError') return failure(res, err.code, err.message, err.status);
    return failure(res, 'AGENT_STORE_UNAVAILABLE', 'The agent store could not process the request.', 503);
  });
}
const tenantOf = (req) => (typeof (req.body && req.body.tenantId) === 'string' ? req.body.tenantId : (typeof req.query.tenantId === 'string' ? req.query.tenantId : ''));
const notFound = (res, what) => failure(res, 'NOT_FOUND', `No such ${what}.`, 404);

function createAgentsRouter({ requirePermission, agents = store } = {}) {
  const router = Router();
  const canManage = permissionGuard(requirePermission, 'MANAGE_AGENTS', 'agents');
  const canRead = permissionGuard(requirePermission, 'READ_AGENTS', 'agents');

  router.post('/', canManage, (req, res) => _handle(res, async () => success(res, await agents.createAgent(tenantOf(req), req.body, resolveOperatorActor(req)), 201)));
  router.get('/', canRead, (req, res) => _handle(res, async () => success(res, { agents: await agents.listAgents(tenantOf(req), { status: req.query.status || undefined }) })));
  router.get('/:agentId', canRead, (req, res) => _handle(res, async () => {
    const a = await agents.getAgent(tenantOf(req), req.params.agentId);
    return a ? success(res, a) : notFound(res, 'agent');
  }));
  router.patch('/:agentId', canManage, (req, res) => _handle(res, async () => success(res, await agents.updateAgent(tenantOf(req), req.params.agentId, req.body, resolveOperatorActor(req)))));
  return router;
}

module.exports = { createAgentsRouter };
