'use strict';

/**
 * MCP servers API - /v1/mcp/servers.
 *
 *   POST   /                                  register a server { tenantId, serverId, url, identity?, description? }        MANAGE_MCP_SERVERS
 *   GET    /?tenantId=&status=                list                                                                            READ_MCP_SERVERS
 *   GET    /:serverId?tenantId=               one server                                                                      READ_MCP_SERVERS
 *   POST   /:serverId/disable                 { tenantId, reason }  stops calls through it (running ones are aborted)         MANAGE_MCP_SERVERS
 *   POST   /:serverId/enable                  { tenantId }                                                                    MANAGE_MCP_SERVERS
 *   POST   /:serverId/identity                { tenantId, identity } rotate the pinned key (the URL never changes)            MANAGE_MCP_SERVERS
 *   POST   /:serverId/tools/refresh           { tenantId } ask the server for its tools and register what it offers in the tool registry (NEW / MODIFIED tools are
 *                                             pending_review - an operator approves them; nothing the server announces is callable by announcing it)
 *
 * The URL goes through the SSRF policy of the model providers (https, no credentials, not an IP literal, not a private destination); an https server must be
 * registered with its pinned identity. QODIQA_MCP_ALLOW_LOCAL=true (never in production) admits http and loopback / private destinations for the operator's own tests.
 */

const { Router } = require('express');
const mcpRegistry = require('../../core/mcp/mcpRegistry');
const mcpClient = require('../../core/mcp/mcpClient');
const toolRegistry = require('../../core/actions/toolRegistry');
const { resolveOperatorActor } = require('../../core/audit/actorAttribution');
const { success, failure } = require('../response');
const { permissionGuard } = require('./permissionGuard');

function _handle(res, fn) {
  return Promise.resolve().then(fn).catch((err) => {
    if (err && (err.name === 'McpRegistryError' || err.name === 'McpUrlError' || err.name === 'ToolError')) return failure(res, err.code, err.message, err.status || 400);
    return failure(res, 'MCP_REGISTRY_UNAVAILABLE', 'The MCP server registry could not process the request.', 503);
  });
}
const tenantOf = (req) => (typeof (req.body && req.body.tenantId) === 'string' ? req.body.tenantId : (typeof req.query.tenantId === 'string' ? req.query.tenantId : ''));

/** What a discovered MCP tool becomes in the tool registry: a PROPOSAL (pending_review), classified conservatively from hints the server itself supplies. */
function proposalOf(serverId, tool) {
  const ann = (tool && tool.annotations && typeof tool.annotations === 'object') ? tool.annotations : {};
  const readOnly = ann.readOnlyHint === true;
  const schema = tool.inputSchema && typeof tool.inputSchema === 'object' && !Array.isArray(tool.inputSchema) ? { ...tool.inputSchema } : { type: 'object' };
  delete schema.$schema; delete schema.$id;
  return { server: serverId, name: tool.name, schema, actionClass: readOnly ? 'read' : 'external_api', reversible: readOnly, description: typeof tool.description === 'string' ? tool.description : undefined };
}

function createMcpServersRouter({ requirePermission, registry = mcpRegistry, client = mcpClient, tools = toolRegistry } = {}) {
  const router = Router();
  const canManage = permissionGuard(requirePermission, 'MANAGE_MCP_SERVERS', 'mcp-servers');
  const canRead = permissionGuard(requirePermission, 'READ_MCP_SERVERS', 'mcp-servers');

  router.post('/', canManage, (req, res) => _handle(res, async () => {
    const b = req.body || {};
    return success(res, await registry.register(tenantOf(req), { serverId: b.serverId, url: b.url, identity: b.identity, description: b.description }, resolveOperatorActor(req)), 201);
  }));
  router.get('/', canRead, (req, res) => _handle(res, async () => success(res, { servers: await registry.list(tenantOf(req), { status: req.query.status || undefined }) })));
  router.get('/:serverId', canRead, (req, res) => _handle(res, async () => {
    const s = await registry.get(tenantOf(req), req.params.serverId);
    return s ? success(res, s) : failure(res, 'NOT_FOUND', 'No such MCP server.', 404);
  }));
  router.post('/:serverId/disable', canManage, (req, res) => _handle(res, async () => success(res, await registry.disable(tenantOf(req), req.params.serverId, { reason: req.body && req.body.reason, actor: resolveOperatorActor(req) }))));
  router.post('/:serverId/enable', canManage, (req, res) => _handle(res, async () => success(res, await registry.enable(tenantOf(req), req.params.serverId, { actor: resolveOperatorActor(req) }))));
  router.post('/:serverId/identity', canManage, (req, res) => _handle(res, async () => success(res, await registry.rotateIdentity(tenantOf(req), req.params.serverId, req.body && req.body.identity, resolveOperatorActor(req)))));
  router.post('/:serverId/tools/refresh', canManage, (req, res) => _handle(res, async () => {
    const tenantId = tenantOf(req); const serverId = req.params.serverId;
    const srv = await registry.resolve(tenantId, serverId);
    if (!srv.ok) return failure(res, srv.reason, `The MCP server cannot be called (${srv.reason}).`, srv.reason === 'MCP_SERVER_UNKNOWN' ? 404 : 409);
    let listed;
    try { listed = await client.listTools(srv.server, { timeoutMs: 15_000 }); } catch (err) {
      await registry.recordRefresh(tenantId, serverId, { error: `${err.code || 'MCP_ERROR'}: ${err.message}` });
      return failure(res, 'MCP_REFRESH_FAILED', `The MCP server could not be asked for its tools (${err.code || 'MCP_ERROR'}).`, 502);
    }
    const summary = { NEW: [], MODIFIED: [], UNCHANGED: [], SKIPPED: [] };
    for (const t of listed) {
      if (!t || typeof t.name !== 'string') { summary.SKIPPED.push({ name: null, reason: 'NO_NAME' }); continue; }
      try {
        const r = await tools.observe(tenantId, proposalOf(serverId, t), resolveOperatorActor(req));
        summary[r.change].push({ name: t.name, ...(r.tool ? { version: r.tool.version, status: r.tool.status, schemaHash: r.tool.schemaHash } : {}) });
      } catch (e) { summary.SKIPPED.push({ name: t.name, reason: (e && e.code) || 'REJECTED' }); }
    }
    await registry.recordRefresh(tenantId, serverId, { tools: listed.length });
    return success(res, { serverId, discovered: listed.length, ...summary });
  }));
  return router;
}

module.exports = { createMcpServersRouter, proposalOf };
