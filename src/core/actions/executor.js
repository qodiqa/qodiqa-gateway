'use strict';

/**
 * The execution side of an action artifact. Whoever is about to RUN an action (the tool gateway, or a customer's own executor via
 * the same module) calls beginExecution() with the artifact and the action it is about to perform; the action runs only when this returns ok.
 *
 *   1. the artifact itself verifies (kind "action", signature in the action domain, tenant = key owner, time window, key lifecycle)   -> verifyActionArtifact
 *   2. the agent and the session are live RIGHT NOW (suspension / kill / expiry / revocation take effect at the next action)
 *   3. ORDER: seq n executes only after seq n-1 has been consumed (ACTION_ORDER_VIOLATION); prevActionHash is read from that ledger row
 *   4. the executor RECOMPUTES actionHash from what it is about to do (tenant, agent, session, seq, tool + the ACTIVE schemaHash, args, parentRequestHash,
 *      prevActionHash) and compares it in constant time with the artifact's: one changed byte of the arguments, the tool or the parent is ACTION_MISMATCH;
 *      when the recomputation fails but an EARLIER version of the same tool reproduces the artifact's hash, the reason is TOOL_SCHEMA_CHANGED (TOCTOU);
 *   5. the arguments pass the registered schema again (the registry decides, not the caller)
 *   6. CONSUME: one ledger row per artifact (action_executions): the same requestId or the same (session, seq) twice is ACTION_REPLAY - atomically, across replicas
 *   7. audit: ACTION_INTENT is written after the consumption and BEFORE the action runs; if it cannot be written the action does not run (fail closed);
 *      completeExecution() writes ACTION_COMMIT with the outcome. Schema v8 only (QODIQA_AUDIT_SCHEMA_V8 stays off until a decision is made): with it off
 *      the ledger row is still the durable INTENT / COMMIT record and the call only reports `audit: 'skipped'`.
 *
 * Deliberate limits: the audit entry is written right after the ledger transaction, not inside it (the audit chain has its own transaction and head
 * lock); a crash between the two leaves a ledger row without INTENT, which the reconciler (reconcileOpen) closes as `unknown`. An artifact that was authorised and
 * never executed blocks the session at that seq (omission is an ORDER violation by design): the agent starts a new session.
 */

const pgPool = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');
const agents = require('../agents/agentStore');
const registry = require('./toolRegistry');
const { verifyActionArtifact } = require('./actionArtifact');
const { computeActionHash, hashesEqual, ActionHashError } = require('./actionHash');
const delegations = require('../delegation/delegationStore');
const toolPolicy = require('../mcp/toolPolicy');
const approvals = require('../approvals/approvalStore');

const usePg = () => pgPool.isEnabled();
const _mem = new Map();                                    // `${tenant}|${session}|${seq}` -> row
const _memReq = new Map();                                 // `${tenant}|${requestId}` -> key

const rowOut = (r) => (r ? { tenantId: r.tenant_id, sessionId: r.session_id, seq: Number(r.seq), requestId: r.request_id, agentId: r.agent_id, actionHash: String(r.action_hash).trim(),
  server: r.server_id, tool: r.tool_name, approvalRef: r.approval_ref || null, status: r.status, outputHash: r.output_hash ? String(r.output_hash).trim() : null,
  startedAt: new Date(r.started_at).toISOString(), finishedAt: r.finished_at ? new Date(r.finished_at).toISOString() : null } : null);

async function _lookupPrev(tenantId, sessionId, seq) {
  if (seq === 1) return { ok: true, prevActionHash: null };
  if (!usePg()) { const r = _mem.get(`${tenantId}|${sessionId}|${seq - 1}`); return r ? { ok: true, prevActionHash: r.action_hash } : { ok: false }; }
  const r = await pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT action_hash FROM action_executions WHERE tenant_id=$1 AND session_id=$2 AND seq=$3', [tenantId, sessionId, seq - 1])).rows[0]);
  return r ? { ok: true, prevActionHash: String(r.action_hash).trim() } : { ok: false };
}

async function _retry(fn) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) { if (!(e && e.code === '40001') || i >= 12) throw e; await new Promise((r) => setTimeout(r, 2 + Math.floor(Math.random() * 10 * (i + 1)))); }
  }
}

/** Atomically consume the artifact: @returns {Promise<{ ok: true } | { ok: false, reason: 'ACTION_REPLAY' | 'ACTION_ORDER_VIOLATION' }>} */
async function consume(c, { maxCalls = null } = {}) {
  if (!usePg()) {
    const key = `${c.tenantId}|${c.sessionId}|${c.seq}`;
    if (_mem.has(key) || _memReq.has(`${c.tenantId}|${c.requestId}`)) return { ok: false, reason: 'ACTION_REPLAY' };
    if (c.seq > 1 && !_mem.has(`${c.tenantId}|${c.sessionId}|${c.seq - 1}`)) return { ok: false, reason: 'ACTION_ORDER_VIOLATION' };
    if (maxCalls !== null && [..._mem.values()].filter((r) => r.tenant_id === c.tenantId && r.session_id === c.sessionId && r.server_id === c.server && r.tool_name === c.tool).length >= maxCalls) return { ok: false, reason: 'ACTION_TOOL_LIMIT' };
    _mem.set(key, { tenant_id: c.tenantId, session_id: c.sessionId, seq: c.seq, request_id: c.requestId, agent_id: c.agentId, action_hash: c.actionHash, server_id: c.server, tool_name: c.tool,
      approval_ref: c.approvalRef || null, status: 'intent', output_hash: null, started_at: new Date(), finished_at: null });
    _memReq.set(`${c.tenantId}|${c.requestId}`, key);
    return { ok: true };
  }
  try {
    return await _retry(() => pgPool.withTenantTransaction(c.tenantId, async (tx) => {
      const dup = await tx.query('SELECT 1 FROM action_executions WHERE tenant_id=$1 AND (request_id=$2 OR (session_id=$3 AND seq=$4))', [c.tenantId, c.requestId, c.sessionId, c.seq]);
      if (dup.rows.length) return { ok: false, reason: 'ACTION_REPLAY' };
      if (c.seq > 1) {
        const prev = await tx.query('SELECT 1 FROM action_executions WHERE tenant_id=$1 AND session_id=$2 AND seq=$3', [c.tenantId, c.sessionId, c.seq - 1]);
        if (!prev.rows.length) return { ok: false, reason: 'ACTION_ORDER_VIOLATION' };
      }
      if (maxCalls !== null) {
        // the per-tool limit of the session: serialised per (session, tool) so that concurrent consumers cannot both take the last place
        await tx.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`${c.tenantId}|${c.sessionId}|${c.server}|${c.tool}`]);
        const n = await tx.query('SELECT count(*)::int AS n FROM action_executions WHERE tenant_id=$1 AND session_id=$2 AND server_id=$3 AND tool_name=$4', [c.tenantId, c.sessionId, c.server, c.tool]);
        if (n.rows[0].n >= maxCalls) return { ok: false, reason: 'ACTION_TOOL_LIMIT' };
      }
      await tx.query(`INSERT INTO action_executions (tenant_id, session_id, seq, request_id, agent_id, action_hash, server_id, tool_name, approval_ref)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [c.tenantId, c.sessionId, c.seq, c.requestId, c.agentId, c.actionHash, c.server, c.tool, c.approvalRef || null]);
      return { ok: true };
    }));
  } catch (e) {
    if (e && e.code === '23505') return { ok: false, reason: 'ACTION_REPLAY' };           // the concurrent twin won the insert
    throw e;
  }
}

async function _finish(tenantId, sessionId, seq, status, outputHash) {
  if (!usePg()) { const r = _mem.get(`${tenantId}|${sessionId}|${seq}`); if (r && r.status === 'intent') { r.status = status; r.output_hash = outputHash || null; r.finished_at = new Date(); return true; } return false; }
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query(
    "UPDATE action_executions SET status=$4, output_hash=$5, finished_at=now() WHERE tenant_id=$1 AND session_id=$2 AND seq=$3 AND status='intent'", [tenantId, sessionId, seq, status, outputHash || null])).rowCount === 1);
}

function _auditOn() { try { return require('../audit/entryBuilder').currentSchemaVersion() >= 8; } catch { return false; } }

async function _writeAudit(fields, stage) {
  const audit = require('../audit/audit-log');
  return audit.appendMandatory(fields, { stage, maxRetries: 3, retryDelayMs: 100 });
}

const _delegationCtx = (x) => (x.delegation ? { delegation: { delegationId: x.delegation.delegationId, chainHash: x.delegation.chainHash, depth: x.delegation.depth, rootAgentId: x.delegation.rootAgentId } } : {});

function _intentFields(x) {
  return { artifactId: `${x.requestId}:action_intent`, entryType: 'ACTION_INTENT', decision: 'ALLOW', reason: 'ACTION_AUTHORIZED', signature: x.signature, tenantId: x.tenantId, requestId: x.requestId,
    agentId: x.agentId, sessionId: x.sessionId, actionSeq: x.seq, actionHash: x.actionHash, ...(x.approvalRef ? { approvalRef: x.approvalRef } : {}), issuedAt: x.issuedAt, protocolVersion: 2,
    executionContext: { action: { tool: { server: x.server, name: x.tool, schemaHash: x.schemaHash }, parentRequestHash: x.parentRequestHash, prevActionHash: x.prevActionHash }, ..._delegationCtx(x) } };
}

/**
 * @param {{ artifact: object, tool: { server: string, name: string }, args: object, parentRequestHash?: string|null, now?: number, resolveKey?: Function }} input
 * @returns {Promise<{ ok: true, execution: object, tool: object, audit: 'written'|'skipped' } | { ok: false, reason: string, detail?: string }>}
 */
async function beginExecution(input) {
  const { artifact, tool, args } = input || {};
  const parentRequestHash = input && input.parentRequestHash !== undefined ? input.parentRequestHash : null;
  const no = (reason, detail) => ({ ok: false, reason, ...(detail ? { detail } : {}) });
  if (!tool || typeof tool !== 'object' || typeof tool.server !== 'string' || typeof tool.name !== 'string') return no('ACTION_INVALID_TOOL');
  const v = verifyActionArtifact(artifact, { now: input.now ?? Date.now(), ...(input.resolveKey ? { resolveKey: input.resolveKey } : {}) });
  if (!v.ok) return no(v.reason);
  const live = await agents.checkSession(v.tenantId, v.agentId, v.sessionId);
  if (!live.ok) return no(live.reason);
  const reg = await registry.get(v.tenantId, tool.server, tool.name);
  if (!reg) return no('TOOL_NOT_REGISTERED');
  if (!reg.active) return no(reg.versions.some((x) => x.status === 'pending_review') ? 'TOOL_PENDING_REVIEW' : 'TOOL_DISABLED');
  const prev = await _lookupPrev(v.tenantId, v.sessionId, v.seq);
  if (!prev.ok) return no('ACTION_ORDER_VIOLATION');
  const h = (schemaHash) => computeActionHash({ tenantId: v.tenantId, agentId: v.agentId, sessionId: v.sessionId, seq: v.seq, tool: { server: tool.server, name: tool.name, schemaHash },
    args, parentRequestHash, prevActionHash: prev.prevActionHash });
  let now;
  try { now = h(reg.active.schemaHash); } catch (e) { if (e instanceof ActionHashError) return no('ACTION_INVALID', e.code); throw e; }
  if (!hashesEqual(now, v.actionHash)) {
    for (const old of reg.versions) {
      if (old.schemaHash === reg.active.schemaHash) continue;
      try { if (hashesEqual(h(old.schemaHash), v.actionHash)) return no('TOOL_SCHEMA_CHANGED'); } catch { /* not computable for that version */ }
    }
    return no('ACTION_MISMATCH');
  }
  const valid = registry.validateArgs(reg.active, args);
  if (!valid.ok) return no('ACTION_ARGS_INVALID', `${valid.code} ${valid.path}`);
  const approvalRef = artifact.payload.qodiqa.approvalRef || null;
  if (reg.active.requiresApproval && !approvalRef) return no('ACTION_APPROVAL_REQUIRED');
  if (approvalRef) {
    // the approval named by the artifact is still in force (not cancelled, not expired unspent), was spent by THIS artifact, names THIS action, and its signed statement holds
    const av = await approvals.verifyForExecution(v.tenantId, approvalRef, { actionHash: v.actionHash, agentId: v.agentId, sessionId: v.sessionId, requestId: v.requestId, ...(input.resolveKey ? { resolveKey: input.resolveKey } : {}) });
    if (!av.ok) return no(av.reason, av.detail);
  }
  const pol = toolPolicy.check(reg.active, args);                                                    // the policy may have changed since the artifact was issued
  if (!pol.ok) return no(pol.code, pol.detail);
  const c = { tenantId: v.tenantId, sessionId: v.sessionId, seq: v.seq, requestId: v.requestId, agentId: v.agentId, actionHash: v.actionHash, server: tool.server, tool: tool.name, approvalRef };
  // the delegation chain the request was authorised under: revoked or expired since authorisation => the action does not run
  let delegation = null;
  const du = await delegations.getUse(v.tenantId, v.requestId);
  if (du) {
    const live = await delegations.verifyLive(v.tenantId, du.delegationId, { agentId: v.agentId });
    if (!live.ok) return no(live.reason, live.detail);
    delegation = { delegationId: du.delegationId, chainHash: live.chainHash, depth: live.depth, rootAgentId: live.rootAgentId, chainIds: live.chain.map((e) => e.payload.delegationId) };
  }
  const used = await consume(c, { maxCalls: Number.isInteger(reg.active.policy && reg.active.policy.maxCallsPerSession) ? reg.active.policy.maxCallsPerSession : null });
  if (!used.ok) return no(used.reason);
  const execution = { ...c, delegation, signature: artifact.signature, issuedAt: artifact.timestamp, schemaHash: reg.active.schemaHash, parentRequestHash, prevActionHash: prev.prevActionHash };
  let auditState = 'skipped';
  if (_auditOn()) {
    try { await _writeAudit(_intentFields(execution), 'ACTION_DISPATCH'); auditState = 'written'; } catch (err) {
      await _finish(c.tenantId, c.sessionId, c.seq, 'failed', null).catch(() => {});
      emit('CRITICAL', 'ACTION_INTENT_AUDIT_FAILED', { requestId: c.requestId, tenantId: c.tenantId, sessionId: c.sessionId, seq: c.seq, error: err.message, message: 'The ACTION_INTENT entry could not be written; the action was not run.' });
      return no('AUDIT_UNAVAILABLE');
    }
  }
  return { ok: true, execution, tool: reg.active, audit: auditState };
}

/** Close an execution. Never throws. @param {{ ok: boolean, outputHash?: string }} outcome */
async function completeExecution(execution, { ok, outputHash } = {}) {
  const status = ok ? 'completed' : 'failed';
  let closed = false;
  try { closed = await _finish(execution.tenantId, execution.sessionId, execution.seq, status, outputHash); } catch (err) {
    emit('CRITICAL', 'ACTION_LEDGER_UPDATE_FAILED', { requestId: execution.requestId, error: err.message });
  }
  if (!_auditOn()) return { closed, audit: 'skipped' };
  try {
    const { outputHashOf } = require('../audit/entryBuilder');
    await _writeAudit({ artifactId: `${execution.requestId}:action_commit`, entryType: 'ACTION_COMMIT', decision: 'ALLOW', reason: ok ? 'ACTION_COMPLETED' : 'ACTION_FAILED', signature: execution.signature,
      tenantId: execution.tenantId, requestId: execution.requestId, agentId: execution.agentId, sessionId: execution.sessionId, actionSeq: execution.seq, actionHash: execution.actionHash,
      ...(execution.approvalRef ? { approvalRef: execution.approvalRef } : {}), outputHash: outputHash || outputHashOf(''), completionStatus: ok ? 'COMPLETE' : 'ERROR',
      issuedAt: execution.issuedAt, protocolVersion: 2,
      executionContext: { action: { tool: { server: execution.server, name: execution.tool, schemaHash: execution.schemaHash }, parentRequestHash: execution.parentRequestHash, prevActionHash: execution.prevActionHash }, ..._delegationCtx(execution) } }, 'ACTION_COMMIT');
    return { closed, audit: 'written' };
  } catch (err) {
    emit('CRITICAL', 'ACTION_COMMIT_AUDIT_FAILED', { requestId: execution.requestId, tenantId: execution.tenantId, error: err.message });
    return { closed, audit: 'failed' };
  }
}

/**
 * Record an action the GATEWAY itself performs in the session chain (e.g. issuing a delegation): it takes its place in the ledger, in order, exactly once.
 * @returns {Promise<{ ok: true, finish: (ok:boolean, outputHash?:string)=>Promise<boolean> } | { ok: false, reason: string }>}
 */
async function recordInternal(c) {
  const used = await consume({ approvalRef: null, ...c });
  if (!used.ok) return used;
  return { ok: true, finish: (ok, outputHash) => _finish(c.tenantId, c.sessionId, c.seq, ok ? 'completed' : 'failed', outputHash) };
}

/** Close ledger rows left in `intent` longer than olderThanMs as `unknown` (the process died while the action ran). @returns {Promise<number>} rows closed */
async function reconcileOpen(tenantId, { olderThanMs = 15 * 60_000 } = {}) {
  if (!usePg()) { let n = 0; for (const r of _mem.values()) if (r.tenant_id === tenantId && r.status === 'intent' && Date.now() - r.started_at.getTime() > olderThanMs) { r.status = 'unknown'; r.finished_at = new Date(); n += 1; } return n; }
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query(
    "UPDATE action_executions SET status='unknown', finished_at=now() WHERE tenant_id=$1 AND status='intent' AND started_at < now() - ($2::bigint * interval '1 millisecond')", [tenantId, olderThanMs])).rowCount);
}

async function getExecution(tenantId, sessionId, seq) {
  if (!usePg()) return rowOut(_mem.get(`${tenantId}|${sessionId}|${seq}`) || null);
  return rowOut(await pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT * FROM action_executions WHERE tenant_id=$1 AND session_id=$2 AND seq=$3', [tenantId, sessionId, seq])).rows[0]));
}

function _resetForTests() { _mem.clear(); _memReq.clear(); }

// the approval store closes the ledger of a decision that will never run through this module (cancelled / expired / not releasable); it gets the recorder injected
approvals.setLedgerRecorder(recordInternal);

module.exports = { beginExecution, completeExecution, reconcileOpen, getExecution, consume, recordInternal, _resetForTests };
