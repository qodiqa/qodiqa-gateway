'use strict';

/**
 * POST /v1/tools/call - the tool gateway: runs ONE authorised action against a REGISTERED MCP server over HTTP and returns the screened result.
 *
 *   { artifact, tool: { server, name }, args, parentRequestHash? }      authenticated like /sign (a tenant signing identity)
 *
 * What happens, in this order, and what stops it:
 *   1. the artifact is an action artifact of THIS tenant                        ACTION_TENANT_MISMATCH / WRONG_ARTIFACT_KIND / ACTION_SIGNATURE_INVALID / expired
 *   2. the MCP server is registered, active, its URL still acceptable, its configuration intact      MCP_SERVER_UNKNOWN / _DISABLED / MCP_URL_* / MCP_SERVER_CONFIG_TAMPERED
 *   3. the executor (src/core/actions/executor.js): agent and session live, ORDER, actionHash recomputed from THIS call (ACTION_MISMATCH), arguments valid for the registered
 * schema, tool policy, delegation chain still valid, the artifact consumed once (ACTION_REPLAY), ACTION_INTENT written
 *   4. the call - HTTP(S) to the server, pinned identity, SSRF-guarded connection, no redirects, bounded time and size; abortable: killing the session, disabling the tool or
 *      the server, revoking the delegation (this replica at once, the others within about a second: src/core/mcp/revocationWatch.js)
 *   5. the result is screened (src/core/mcp/resultScreen.js: encodings revealed, instruction conflict, semantic policy) and returned as UNTRUSTED data with its provenance
 *   6. ACTION_COMMIT is written; the response carries a receipt (the ledger record of the call, bound to the hash of what was delivered)
 *
 * There is no stdio transport and nothing here starts a process or runs a local command.
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
const executor = require('../../core/actions/executor');
const mcpRegistry = require('../../core/mcp/mcpRegistry');
const mcpClient = require('../../core/mcp/mcpClient');
const resultScreen = require('../../core/mcp/resultScreen');
const dlpStage = require('../../core/dlp/dlpService');
const revocationWatch = require('../../core/mcp/revocationWatch');
const killRegistry = require('../../core/agents/killRegistry');
const { canonicalJcsP1 } = require('../../validation/jcsP1');
const { outputHashOf } = require('../../core/audit/entryBuilder');

const BODY_KEYS = new Set(['artifact', 'tool', 'args', 'parentRequestHash']);
function _intEnv(name, dflt) { const v = parseInt(process.env[name], 10); return Number.isFinite(v) && v > 0 ? v : dflt; }
const _lockoutConfig = () => ({
  authLockoutEnabled: process.env.QODIQA_SIGN_AUTH_LOCKOUT_ENABLED !== 'false', authLockoutMaxFailures: _intEnv('QODIQA_SIGN_AUTH_FAILURE_MAX', 10),
  authLockoutFailureWindowMs: _intEnv('QODIQA_SIGN_AUTH_FAILURE_WINDOW_MS', 60_000), authLockoutDurationMs: _intEnv('QODIQA_SIGN_AUTH_LOCKOUT_MS', 300_000),
  authLockoutBackoffMinMs: 0, authLockoutBackoffMaxMs: 0, authLockoutCredentialHashBytes: 16,
});

const STATUS = {
  ACTION_ARTIFACT_INVALID: 400, WRONG_ARTIFACT_KIND: 400, ACTION_SIGNATURE_INVALID: 401, ACTION_TENANT_MISMATCH: 403, ACTION_MISMATCH: 409, ACTION_REPLAY: 409, ACTION_ORDER_VIOLATION: 409,
  TOOL_SCHEMA_CHANGED: 409, ACTION_ARGS_INVALID: 400, ACTION_INVALID_TOOL: 400, ACTION_INVALID: 400, ACTION_TOOL_LIMIT: 429, AUDIT_UNAVAILABLE: 503, MCP_SERVER_CONFIG_TAMPERED: 409,
};

function createToolsRouter({ _authLockout, getPolicies, executorApi = executor, mcpApi = mcpRegistry, clientApi = mcpClient, screenDeps = {}, watchIntervalMs } = {}) {
  const router = Router();
  const lockout = _authLockout || createAuthLockout(_lockoutConfig(), { namespace: 'sign' });
  // the tool gateway holds a slot for the whole upstream call, so it has its own admission family (src/api/admission.js)
  router.use(require('../admission').get('tools').middleware);
  router.use(createRateLimitMiddleware('sign_auth'));
  router.use(createSignAuthMiddleware({ store: signingIdentityStore, isSigningPermitted, authLockout: lockout }));
  router.use(createRateLimitMiddleware('sign'));

  router.post('/call', enforceContentType, async (req, res) => {
    const reqId = req.requestId ?? null; const identity = req.signingIdentity; const tenantId = identity.tenantId;
    const deny = (status, reason, extra = {}) => {
      emit('WARN', 'TOOL_CALL_DECISION', { requestId: reqId, decision: 'BLOCK', reason, identityId: identity.id, tenantId, ...extra });
      return res.status(status).json({ decision: 'BLOCK', reason, details: {}, requestId: reqId });
    };
    if (identity.environment !== resolveServerEnvironment()) return deny(403, 'SCOPE_ENVIRONMENT_MISMATCH');
    const b = req.body;
    if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).some((k) => !BODY_KEYS.has(k))) return deny(400, 'INVALID_REQUEST');
    const t = b.tool;
    if (!t || typeof t !== 'object' || Array.isArray(t) || Object.keys(t).sort().join(',') !== 'name,server' || typeof t.server !== 'string' || typeof t.name !== 'string') return deny(400, 'ACTION_INVALID_TOOL');
    if (!b.args || typeof b.args !== 'object' || Array.isArray(b.args)) return deny(400, 'ACTION_INVALID_ARGS');
    if (b.parentRequestHash !== undefined && b.parentRequestHash !== null && !/^[0-9a-f]{64}$/.test(String(b.parentRequestHash))) return deny(400, 'ACTION_INVALID_PARENT');
    if (!b.artifact || typeof b.artifact !== 'object' || !b.artifact.payload || b.artifact.payload.tenantId !== tenantId) return deny(403, b.artifact && b.artifact.payload ? 'ACTION_TENANT_MISMATCH' : 'ACTION_ARTIFACT_INVALID');

    let execution = null; let stopWatch = null; let unregister = null;
    try {
      // 2. the destination
      const srv = await mcpApi.resolve(tenantId, t.server);
      if (!srv.ok) return deny(STATUS[srv.reason] || 403, srv.reason, { server: t.server });
      // 3. the authorisation, re-derived from this very call; consumes the artifact
      const begun = await executorApi.beginExecution({ artifact: b.artifact, tool: t, args: b.args, parentRequestHash: b.parentRequestHash ?? null });
      if (!begun.ok) return deny(STATUS[begun.reason] || 403, begun.reason, begun.detail ? { detail: begun.detail } : {});
      execution = begun.execution;
      const closeFailed = async (outputHash) => { try { await executorApi.completeExecution(execution, { ok: false, outputHash }); } catch { /* never masks the answer */ } };

      // 4. the call, abortable from every direction
      const controller = new AbortController();
      const labels = [`mcp:${t.server}`, `tool:${t.server}/${t.name}`, ...(execution.delegation ? execution.delegation.chainIds.map((id) => `delegation:${id}`) : [])];
      unregister = killRegistry.register(tenantId, execution.sessionId, controller, 'tool-call', labels);
      stopWatch = revocationWatch.watch({ tenantId, serverId: t.server, tool: t.name, schemaHash: execution.schemaHash, delegationId: execution.delegation ? execution.delegation.delegationId : null,
        agentId: execution.agentId, sessionId: execution.sessionId, controller, ...(watchIntervalMs ? { intervalMs: watchIntervalMs } : {}) });
      const startedAt = new Date();
      let raw;
      try {
        raw = await clientApi.callTool(srv.server, t.name, b.args, { signal: controller.signal, timeoutMs: _intEnv('QODIQA_TOOL_CALL_TIMEOUT_MS', 30_000), maxResponseBytes: _intEnv('QODIQA_TOOL_MAX_RESPONSE_BYTES', 1_048_576) });
      } catch (err) {
        await closeFailed();
        const cause = err && err.cause && err.cause.code ? err.cause.code : null;
        if (err && err.code === 'MCP_ABORTED') return deny(409, cause || 'TOOL_CALL_ABORTED', { requestId: execution.requestId });
        emit('WARN', 'TOOL_CALL_FAILED', { requestId: reqId, tenantId, server: t.server, tool: t.name, code: err && err.code, message: err && err.message });
        const status = err && (err.code === 'MCP_TIMEOUT') ? 504 : 502;
        return res.status(status).json({ decision: 'ERROR', reason: 'TOOL_CALL_FAILED', details: { code: (err && err.code) || 'MCP_ERROR', ...(err && err.rpcCode !== undefined ? { rpcCode: err.rpcCode } : {}) }, requestId: reqId, actionRequestId: execution.requestId });
      }

      // 5. what comes back is untrusted
      const reg = begun.tool;
      // DLP on the result: before it is screened, hashed or delivered. A blocked result is withheld exactly like a screening BLOCK.
      const dlpRes = dlpStage.applyToToolResult(raw, dlpStage.policiesFor(tenantId, getPolicies));
      await dlpStage.recordEvents(dlpRes.events, { requestId: execution.requestId, tenantId });
      const screened = dlpRes.blocked
        ? { decision: 'BLOCK', reason: dlpRes.reason, provenance: { screening: { findings: [...new Set(dlpRes.events.flatMap((e) => e.rules))].map((rule) => ({ rule })) }, withheld: true, contentHash: null }, content: [], delimited: null, deliveredText: '' }
        : await resultScreen.screenResult(dlpRes.raw, { tenantId, requestId: execution.requestId, serverId: t.server, tool: t.name, toolVersion: reg.version, actionHash: execution.actionHash, policy: reg.policy }, screenDeps);
      const finishedAt = new Date();
      const outputHash = outputHashOf(screened.deliveredText);
      const ok = screened.decision === 'ALLOW' && raw.isError !== true;
      const closed = await executorApi.completeExecution(execution, { ok, outputHash });
      const receipt = {
        v: 1, requestId: execution.requestId, actionHash: execution.actionHash, seq: execution.seq, agentId: execution.agentId, sessionId: execution.sessionId, tenantId,
        tool: { server: t.server, name: t.name, schemaHash: execution.schemaHash, version: reg.version }, serverConfigHash: srv.server.configHash,
        status: screened.decision === 'BLOCK' ? 'RESULT_BLOCKED' : (raw.isError === true ? 'TOOL_ERROR' : 'COMPLETED'), outputHash, startedAt: startedAt.toISOString(), finishedAt: finishedAt.toISOString(),
        ...(execution.delegation ? { delegation: { delegationId: execution.delegation.delegationId, chainHash: execution.delegation.chainHash, depth: execution.delegation.depth, rootAgentId: execution.delegation.rootAgentId } } : {}),
      };
      receipt.receiptHash = crypto.createHash('sha256').update(canonicalJcsP1({ ...receipt }), 'utf8').digest('hex');
      emit(screened.decision === 'BLOCK' ? 'WARN' : 'INFO', 'TOOL_CALL_DECISION', { requestId: reqId, decision: screened.decision === 'BLOCK' ? 'BLOCK' : 'EXECUTE', reason: screened.reason || 'TOOL_CALL_COMPLETED', tenantId,
        server: t.server, tool: t.name, actionRequestId: execution.requestId, actionHash: execution.actionHash, seq: execution.seq, findings: screened.provenance.screening.findings.map((f) => `${f.rule}:${f.variant || ''}`) });
      if (screened.decision === 'BLOCK') {
        return res.status(200).json({ decision: 'BLOCK', reason: screened.reason, details: { findings: screened.provenance.screening.findings, withheld: screened.provenance.withheld }, receipt, requestId: reqId });
      }
      return res.status(200).json({
        decision: 'EXECUTE', result: { isError: raw.isError === true, content: screened.content, provenance: screened.provenance, delimited: screened.delimited }, receipt, ...(closed && closed.audit ? { audit: closed.audit } : {}), requestId: reqId,
      });
    } catch (err) {
      if (execution) { try { await executorApi.completeExecution(execution, { ok: false }); } catch { /* ignore */ } }
      emit('ERROR', 'TOOL_CALL_ERROR', { requestId: reqId, tenantId, error: err && err.message });
      return res.status(503).json({ decision: 'BLOCK', reason: 'TOOL_GATEWAY_UNAVAILABLE', details: {}, requestId: reqId });
    } finally {
      if (stopWatch) stopWatch();
      if (unregister) unregister();
    }
  });

  router.use((req, res) => res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null }));
  return router;
}

module.exports = { createToolsRouter };
