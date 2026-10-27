'use strict';

/**
 * Watches ONE in-flight tool call for revocation. A revocation made on this process aborts the call at once through the kill registry (labels
 * `tool:<server>/<name>`, `mcp:<server>`, `delegation:<id>`, and the session). A revocation made on ANOTHER replica reaches the shared store, not this process's memory;
 * this watcher re-reads the store every `intervalMs` (default 1 s) while the call is in flight and aborts it when anything the call stands on is gone:
 *
 *   the MCP server is disabled / its configuration changed      -> MCP_SERVER_DISABLED (or MCP_SERVER_*)
 *   the tool is no longer the active version it was called as   -> TOOL_REVOKED
 *   the delegation chain it ran under is revoked or expired     -> DELEGATION_REVOKED
 *   the agent or the session is no longer live                  -> AGENT_SESSION_*
 *
 * So a compromised tool stops being called on the next request on any replica, and a call already running stops within about `intervalMs` (plus the store's own latency)
 * - inside the 5 s the plan sets. A check that itself fails (store unavailable) does NOT abort: the call is bounded by its own timeout and the kill switch; failing the
 * watch closed would turn a store hiccup into an outage of every running tool call.
 */

const mcpRegistry = require('./mcpRegistry');
const toolRegistry = require('../actions/toolRegistry');
const agents = require('../agents/agentStore');
const delegations = require('../delegation/delegationStore');

const DEFAULT_INTERVAL_MS = 1000;

function watch({ tenantId, serverId, tool, schemaHash, delegationId, agentId, sessionId, controller, intervalMs = DEFAULT_INTERVAL_MS, onAbort }) {
  let stopped = false; let busy = false;
  const abort = (code, message) => {
    if (stopped || controller.signal.aborted) return;
    const err = new Error(message || code); err.code = code;
    if (onAbort) onAbort(code);
    controller.abort(err);
  };
  const tick = async () => {
    if (stopped || busy) return;
    busy = true;
    try {
      const s = await mcpRegistry.resolve(tenantId, serverId);
      if (!s.ok) return abort(s.reason === 'MCP_SERVER_DISABLED' ? 'MCP_SERVER_DISABLED' : s.reason, `the MCP server is no longer callable (${s.reason})`);
      const t = await toolRegistry.resolveForAction(tenantId, serverId, tool, schemaHash);
      if (!t.ok) return abort('TOOL_REVOKED', `the tool is no longer callable (${t.reason})`);
      const live = await agents.checkSession(tenantId, agentId, sessionId);
      if (!live.ok) return abort(live.reason, `the session is no longer live (${live.reason})`);
      if (delegationId) {
        const d = await delegations.verifyLive(tenantId, delegationId, { agentId });
        if (!d.ok) return abort(d.reason, `the delegation is no longer valid (${d.reason})`);
      }
    } catch { /* a failing check never aborts the call: see the header */ } finally { busy = false; }
  };
  const timer = setInterval(tick, intervalMs);
  if (timer.unref) timer.unref();
  return () => { stopped = true; clearInterval(timer); };
}

module.exports = { DEFAULT_INTERVAL_MS, watch };
