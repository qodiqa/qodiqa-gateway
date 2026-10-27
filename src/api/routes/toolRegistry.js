'use strict';

/**
 * Tool registry API - the allowlist of tools an agent action may name.
 *
 * /v1/tool-registry
 *     POST   /                       register a tool version (a changed definition is a NEW version in pending_review)   MANAGE_TOOLS
 *     GET    /?tenantId=&status=     list every version                       READ_TOOLS
 *     GET    /entry?tenantId=&server=&name=    one tool with its versions     READ_TOOLS
 *     POST   /approve                activate a pending version (the registrant of a CHANGED definition cannot approve it)   MANAGE_TOOLS
 *     POST   /disable                disable the active version               MANAGE_TOOLS
 *     POST   /policy                 change the per-tool policy / requiresApproval of the active version   MANAGE_TOOLS
 *
 * Tool names may contain "/", so a tool is addressed by (server, name) in the query or body, never in the path. Every call names its tenant; every
 * statement runs under that tenant's row-level security.
 */

const { Router } = require('express');
const store = require('../../core/actions/toolRegistry');
const { resolveOperatorActor } = require('../../core/audit/actorAttribution');
const { success, failure } = require('../response');
const { permissionGuard } = require('./permissionGuard');

function _handle(res, fn) {
  return Promise.resolve().then(fn).catch((err) => {
    if (err && (err.name === 'ToolError' || err.name === 'SchemaError' || err.name === 'ActionHashError')) return failure(res, err.code, err.message, err.status || 400);
    return failure(res, 'TOOL_REGISTRY_UNAVAILABLE', 'The tool registry could not process the request.', 503);
  });
}
const tenantOf = (req) => (typeof (req.body && req.body.tenantId) === 'string' ? req.body.tenantId : (typeof req.query.tenantId === 'string' ? req.query.tenantId : ''));
const str = (v) => (typeof v === 'string' ? v : '');

function createToolRegistryRouter({ requirePermission, registry = store } = {}) {
  const router = Router();
  const canManage = permissionGuard(requirePermission, 'MANAGE_TOOLS', 'tool-registry');
  const canRead = permissionGuard(requirePermission, 'READ_TOOLS', 'tool-registry');

  router.post('/', canManage, (req, res) => _handle(res, async () => {
    const b = req.body || {};
    const r = await registry.register(tenantOf(req), { server: b.server, name: b.name, schema: b.schema, actionClass: b.actionClass, reversible: b.reversible,
      requiresApproval: b.requiresApproval, policy: b.policy, description: b.description }, resolveOperatorActor(req));
    return success(res, r, 201);
  }));
  router.get('/', canRead, (req, res) => _handle(res, async () => success(res, { tools: await registry.list(tenantOf(req), { status: req.query.status || undefined }) })));
  router.get('/entry', canRead, (req, res) => _handle(res, async () => {
    const t = await registry.get(tenantOf(req), str(req.query.server), str(req.query.name));
    return t ? success(res, t) : failure(res, 'NOT_FOUND', 'No such tool.', 404);
  }));
  router.post('/approve', canManage, (req, res) => _handle(res, async () => {
    const b = req.body || {};
    return success(res, await registry.approve(tenantOf(req), str(b.server), str(b.name), b.version, resolveOperatorActor(req)));
  }));
  router.post('/disable', canManage, (req, res) => _handle(res, async () => {
    const b = req.body || {};
    return success(res, await registry.disable(tenantOf(req), str(b.server), str(b.name), resolveOperatorActor(req)));
  }));
  router.post('/policy', canManage, (req, res) => _handle(res, async () => {
    const b = req.body || {};
    return success(res, await registry.updatePolicy(tenantOf(req), str(b.server), str(b.name), { policy: b.policy, requiresApproval: b.requiresApproval }, resolveOperatorActor(req)));
  }));
  return router;
}

module.exports = { createToolRegistryRouter };
