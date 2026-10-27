'use strict';

/**
 * Agent sessions API - the runtime half of src/api/routes/agents.js (kept in its own file so that each mount prefix has exactly its own routes).
 *
 *     POST   /v1/sessions                          start a session       MANAGE_AGENT_SESSIONS   effective limits = min(requested, agent, platform caps)
 *     GET    /v1/sessions?tenantId=&agentId=&status=                      READ_AGENTS
 *     GET    /v1/sessions/:sessionId?tenantId=     one session (expiry applied)   READ_AGENTS
 *     POST   /v1/sessions/:sessionId/end           end it                MANAGE_AGENT_SESSIONS
 *     POST   /v1/sessions/:sessionId/kill          force-stop it (CRITICAL event, aborts what runs in this process)   MANAGE_AGENT_SESSIONS
 *
 * Admin plane like every state change: operator authentication, RBAC and the operator MFA step-up. A tenant-facing
 * runtime credential that opens sessions without an operator arrives with the identity work and the action API.
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

function createSessionsRouter({ requirePermission, agents = store } = {}) {
  const router = Router();
  const canManage = permissionGuard(requirePermission, 'MANAGE_AGENT_SESSIONS', 'sessions');
  const canRead = permissionGuard(requirePermission, 'READ_AGENTS', 'sessions');

  router.post('/', canManage, (req, res) => _handle(res, async () => {
    const b = req.body || {};
    return success(res, await agents.startSession(tenantOf(req), b.agentId, b, resolveOperatorActor(req)), 201);
  }));
  router.get('/', canRead, (req, res) => _handle(res, async () => success(res, { sessions: await agents.listSessions(tenantOf(req), { agentId: req.query.agentId || undefined, status: req.query.status || undefined }) })));
  router.get('/:sessionId', canRead, (req, res) => _handle(res, async () => {
    const s = await agents.getSession(tenantOf(req), req.params.sessionId);
    return s ? success(res, s) : notFound(res, 'session');
  }));
  router.post('/:sessionId/end', canManage, (req, res) => _handle(res, async () => success(res, await agents.endSession(tenantOf(req), req.params.sessionId, req.body && req.body.reason, resolveOperatorActor(req)))));
  router.post('/:sessionId/kill', canManage, (req, res) => _handle(res, async () => success(res, await agents.killSession(tenantOf(req), req.params.sessionId, req.body && req.body.reason, resolveOperatorActor(req)))));
  return router;
}

module.exports = { createSessionsRouter };
