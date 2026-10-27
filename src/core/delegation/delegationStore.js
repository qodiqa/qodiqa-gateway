'use strict';

/**
 * Delegation store: issue, verify (offline chain + live state), use, revoke (cascade).
 *
 *   issue(tenant, request, actor)          sign and store a delegation (attenuation, depth and cycle are checked BEFORE signing; the result is re-verified)
 *   verifyLive(tenant, delegationId, o)    the chain of the delegation, root first: signatures and rules (delegationToken.verifyChain) AND state - no link revoked,
 *                                          every agent of the chain still active (DELEGATION_REVOKED otherwise)
 *   useDelegation(tenant, id, ctx)         count one action against the max_actions of EVERY link that has one, atomically, and record the trace (delegation_uses)
 *   revoke(tenant, id, o)                  revoke the delegation and every descendant; abort the executions running under any of them; optionally revoke the delegates
 *   revokeForAgent(tenant, agentId, ...)   an agent that is suspended / revoked takes every delegation it issued or holds with it
 *   getUse(tenant, requestId)              the chain an authorised action request ran under
 *
 * Storage: PostgreSQL (migration 104, RLS forced by tenant) or process memory without PostgreSQL. A token's content is fixed at insert; only state moves.
 */

const crypto = require('crypto');
const pgPool = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');
const agents = require('../agents/agentStore');
const killRegistry = require('../agents/killRegistry');
const tok = require('./delegationToken');

const TENANT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DEFAULT_MAX_DEPTH = 3;
const MIN_TTL_S = 1;
const MAX_TTL_S = 24 * 3600;
const DEFAULT_TTL_S = 3600;

class StoreError extends Error { constructor(code, message, status = 400) { super(message); this.name = 'DelegationStoreError'; this.code = code; this.status = status; } }

const usePg = () => pgPool.isEnabled();
const _mem = new Map();                                            // `${tenant}|${delegationId}` -> row
const _uses = new Map();                                           // `${tenant}|${requestId}` -> use

const out = (r) => (r ? { tenantId: r.tenant_id, delegationId: r.delegation_id, parentId: r.parent_id || null, rootAgentId: r.root_agent_id, issuerAgentId: r.issuer_agent_id,
  subjectAgentId: r.subject_agent_id, depth: r.depth, maxDepth: r.max_depth, classes: r.classes, tools: r.tools || null, maxActions: r.max_actions ?? null, actionsUsed: r.actions_used,
  status: r.status, tokenDigest: String(r.token_digest).trim(), issuedAt: new Date(r.issued_at).toISOString(), expiresAt: new Date(r.expires_at).toISOString(), createdBy: r.created_by,
  revokedAt: r.revoked_at ? new Date(r.revoked_at).toISOString() : null, revokedReason: r.revoked_reason || null, revokedBy: r.revoked_by || null, token: r.token } : null);

function _tenant(t) { if (typeof t !== 'string' || !TENANT_RE.test(t)) throw new StoreError('INVALID_TENANT', 'tenantId'); }
function _uuid(v, what) { if (typeof v !== 'string' || !UUID_V4.test(v)) throw new StoreError(`INVALID_${what}`, `${what} must be a UUID v4`); return v; }
async function _retry(fn) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) { if (!(e && e.code === '40001') || i >= 12) throw e; await new Promise((r) => setTimeout(r, 2 + Math.floor(Math.random() * 10 * (i + 1)))); }
  }
}

// ── reads ────────────────────────────────────────────────────────────────────────────────────────────────
/** Rows of the chain of a delegation, root first; null when the delegation or an ancestor is unknown. */
async function _chainRows(tenantId, delegationId) {
  if (!usePg()) {
    const rows = []; let cur = _mem.get(`${tenantId}|${delegationId}`);
    while (cur) { rows.unshift(cur); cur = cur.parent_id ? _mem.get(`${tenantId}|${cur.parent_id}`) : null; if (rows.length > tok.MAX_DEPTH_CAP + 1) return null; }
    return rows.length && !rows[0].parent_id ? rows : null;
  }
  const r = await pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query(
    `WITH RECURSIVE c AS (SELECT * FROM agent_delegations WHERE tenant_id=$1 AND delegation_id=$2
       UNION ALL SELECT d.* FROM agent_delegations d JOIN c ON d.tenant_id=c.tenant_id AND d.delegation_id=c.parent_id) SELECT * FROM c ORDER BY depth`, [tenantId, delegationId])).rows);
  return r.length && !r[0].parent_id ? r : null;
}

async function get(tenantId, delegationId) {
  _tenant(tenantId);
  if (typeof delegationId !== 'string' || !UUID_V4.test(delegationId)) return null;
  if (!usePg()) return out(_mem.get(`${tenantId}|${delegationId}`) || null);
  return out(await pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT * FROM agent_delegations WHERE tenant_id=$1 AND delegation_id=$2', [tenantId, delegationId])).rows[0]));
}

async function list(tenantId, { agentId, status } = {}) {
  _tenant(tenantId);
  if (!usePg()) return [..._mem.values()].filter((r) => r.tenant_id === tenantId && (!agentId || r.issuer_agent_id === agentId || r.subject_agent_id === agentId) && (!status || r.status === status))
    .sort((a, b) => a.issued_at - b.issued_at).map(out);
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query(
    'SELECT * FROM agent_delegations WHERE tenant_id=$1 AND ($2::text IS NULL OR issuer_agent_id=$2 OR subject_agent_id=$2) AND ($3::text IS NULL OR status=$3) ORDER BY issued_at, id', [tenantId, agentId || null, status || null])).rows.map(out));
}

function _defaultResolveKey(id) { return require('../../validation/resolveKey').resolveKey(id); }

function _keyCheckFor(resolveKey) {
  return ({ publicKeyId, timestamp, now }) => {
    try {
      const key = resolveKey(publicKeyId);
      const timeline = require('../signing/keyStatusTimeline').effective(publicKeyId, key.timeline || { status: key.status });
      const lc = require('../../validation/keyLifecycle').checkExecution(timeline, timestamp, now);
      return lc.valid ? null : lc.reason;
    } catch (e) { return e && e.name === 'ControlPlaneError' ? e.code : 'KEY_UNAVAILABLE'; }
  };
}

/**
 * Offline chain verification of stored rows plus live state.
 * @returns {Promise<{ ok: true, ...chainFacts, rows: object[], chain: object[] } | { ok: false, reason: string, detail?: string }>}
 */
async function verifyLive(tenantId, delegationId, { now = Date.now(), agentId, resolveKey = _defaultResolveKey } = {}) {
  _tenant(tenantId);
  if (typeof delegationId !== 'string' || !UUID_V4.test(delegationId)) return { ok: false, reason: 'DELEGATION_INVALID', detail: 'delegationId' };
  const rows = await _chainRows(tenantId, delegationId);
  if (!rows) return { ok: false, reason: 'DELEGATION_INVALID', detail: 'unknown delegation' };
  const bad = rows.find((r) => r.status !== 'active');
  if (bad) return { ok: false, reason: 'DELEGATION_REVOKED', detail: bad.delegation_id };
  const chain = rows.map((r) => r.token);
  const v = tok.verifyChain(chain, { now, resolveKey, keyCheck: _keyCheckFor(resolveKey) });
  if (!v.ok) return v;
  if (v.tenantId !== tenantId) return { ok: false, reason: 'DELEGATION_INVALID', detail: 'tenant' };
  if (agentId !== undefined && v.subjectAgentId !== agentId) return { ok: false, reason: 'DELEGATION_INVALID', detail: 'not the delegate' };
  // every agent of the chain must still be active: a suspended or revoked agent has no authority to pass on or to hold
  const ids = [...new Set([v.rootAgentId, ...chain.map((e) => e.payload.subjectAgentId)])];
  for (const id of ids) {
    const a = await agents.getAgent(tenantId, id);
    if (!a || a.status !== 'active') return { ok: false, reason: 'DELEGATION_REVOKED', detail: `agent ${a ? a.status : 'unknown'}` };
  }
  return { ...v, rows: rows.map(out), chain };
}

// ── issue ────────────────────────────────────────────────────────────────────────────────────────────────
function _requestShape(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) throw new StoreError('INVALID_REQUEST', 'request');
  _uuid(r.issuerAgentId, 'ISSUER'); _uuid(r.subjectAgentId, 'SUBJECT');
  if (r.parentId !== undefined && r.parentId !== null) _uuid(r.parentId, 'PARENT');
  if (!Array.isArray(r.classes) || !r.classes.length || !r.classes.every((c) => tok.ACTION_CLASSES.includes(c))) throw new StoreError('INVALID_CLASSES', `classes is a non-empty subset of ${tok.ACTION_CLASSES.join(', ')}`);
  if (r.tools !== undefined && r.tools !== null) {
    if (!Array.isArray(r.tools) || !r.tools.length || r.tools.length > 100 || r.tools.some((t) => !t || typeof t !== 'object' || typeof t.server !== 'string' || typeof t.name !== 'string' || Object.keys(t).length !== 2)) throw new StoreError('INVALID_TOOLS', 'tools is a list of { server, name }');
  }
  if (r.maxActions !== undefined && r.maxActions !== null && !(Number.isInteger(r.maxActions) && r.maxActions >= 1 && r.maxActions <= tok.MAX_ACTIONS_CAP)) throw new StoreError('INVALID_MAX_ACTIONS', `maxActions is 1..${tok.MAX_ACTIONS_CAP}`);
  const ttl = r.ttlSeconds === undefined ? DEFAULT_TTL_S : r.ttlSeconds;
  if (!Number.isInteger(ttl) || ttl < MIN_TTL_S || ttl > MAX_TTL_S) throw new StoreError('INVALID_TTL', `ttlSeconds is ${MIN_TTL_S}..${MAX_TTL_S}`);
  if (r.maxDepth !== undefined && !(Number.isInteger(r.maxDepth) && r.maxDepth >= 1 && r.maxDepth <= tok.MAX_DEPTH_CAP)) throw new StoreError('INVALID_MAX_DEPTH', `maxDepth is 1..${tok.MAX_DEPTH_CAP}`);
  return ttl;
}

const refuse = (code, detail, status = 403) => new StoreError(code, detail ? `${code}: ${detail}` : code, status);

/**
 * @param {object} req { issuerAgentId, subjectAgentId, parentId?, classes, tools?, maxActions?, ttlSeconds?, maxDepth? (root grants only) }
 * @returns {Promise<{ delegation: object, token: object, chainHash: string }>}
 */
async function issue(tenantId, req, actor, { now = Date.now(), resolveKey = _defaultResolveKey } = {}) {
  _tenant(tenantId);
  const ttl = _requestShape(req);
  const root = req.parentId === undefined || req.parentId === null;
  if (!root && req.maxDepth !== undefined) throw new StoreError('INVALID_MAX_DEPTH', 'maxDepth is fixed by the root grant');
  const issuer = await agents.getAgent(tenantId, req.issuerAgentId);
  const subject = await agents.getAgent(tenantId, req.subjectAgentId);
  if (!issuer || issuer.status !== 'active') throw refuse('DELEGATION_INVALID', 'issuer agent is not active');
  if (!subject || subject.status !== 'active') throw refuse('DELEGATION_INVALID', 'delegate agent is not active');
  if (req.issuerAgentId === req.subjectAgentId) throw refuse('DELEGATION_CYCLE', 'an agent cannot delegate to itself');

  let parentChain = [];
  let parentEnv = null;
  let expiry = now + ttl * 1000;
  if (root) {
    // a root grant gives away part of the issuer's OWN authority: it cannot exceed the issuer's identity (no escalation from nothing)
    if (!req.classes.every((c) => issuer.allowedActionClasses.includes(c))) throw refuse('DELEGATION_ATTENUATION_VIOLATION', 'classes beyond the issuer agent\'s own');
  } else {
    const live = await verifyLive(tenantId, req.parentId, { now, resolveKey });
    if (!live.ok) throw refuse(live.reason, live.detail);
    if (live.subjectAgentId !== req.issuerAgentId) throw refuse('DELEGATION_INVALID', 'the issuer is not the delegate of the parent');
    parentChain = live.chain; parentEnv = parentChain[parentChain.length - 1];
    if (parentEnv.payload.depth >= parentEnv.payload.maxDepth) throw refuse('DELEGATION_DEPTH_EXCEEDED', `the chain is at its maximum depth (${parentEnv.payload.maxDepth})`);
    const everyone = [live.rootAgentId, ...parentChain.map((e) => e.payload.subjectAgentId)];
    if (everyone.includes(req.subjectAgentId)) throw refuse('DELEGATION_CYCLE', 'the delegate is already in the chain');
    // the child can never hold more than the issuer actually holds
    // no lifetime asked for: the child lives as long as the parent at most (an explicit lifetime beyond the parent's is a violation, never silently shortened)
    if (req.ttlSeconds === undefined) expiry = Math.min(expiry, parentEnv.expiry);
    if (expiry <= now) throw refuse('DELEGATION_INVALID', 'the parent has expired');
    const wide = tok.attenuationProblem(parentEnv.payload, { classes: [...new Set(req.classes)].sort(), tools: tok.normaliseTools(req.tools), maxActions: req.maxActions ?? null }, parentEnv.expiry, expiry);
    if (wide) throw refuse('DELEGATION_ATTENUATION_VIOLATION', wide);
  }
  const delegationId = crypto.randomUUID();
  const payload = tok.buildPayload({ delegationId, tenantId, parent: parentEnv, issuerAgentId: req.issuerAgentId, subjectAgentId: req.subjectAgentId, classes: req.classes, tools: req.tools,
    maxActions: req.maxActions ?? null, maxDepth: root ? (req.maxDepth ?? DEFAULT_MAX_DEPTH) : undefined });
  const key = require('../../../services/artifact/keyManager').getSigningKey(tenantId);
  const fields = { payload, timestamp: now, expiry, publicKeyId: key.keyId };
  const token = key.nativeSigning ? await tok.signDelegationNative(fields, require('../../../services/artifact/keyManager').nativeSign) : tok.signDelegation(fields, key.privDer);
  // the invariant, checked on what was actually signed (a defect in the checks above would otherwise ship a token no verifier accepts - or worse, one they accept)
  const check = tok.verifyChain([...parentChain, token], { now, resolveKey });
  if (!check.ok) throw new StoreError('DELEGATION_SELF_CHECK_FAILED', `${check.reason}: ${check.detail || ''}`, 500);
  const row = { tenant_id: tenantId, delegation_id: delegationId, parent_id: payload.parentId, root_agent_id: payload.rootAgentId, issuer_agent_id: payload.issuerAgentId, subject_agent_id: payload.subjectAgentId,
    depth: payload.depth, max_depth: payload.maxDepth, classes: payload.classes, tools: payload.tools, max_actions: payload.maxActions, actions_used: 0, status: 'active', token,
    token_digest: check.chainHash, issued_at: new Date(now), expires_at: new Date(token.expiry), created_by: String(actor || 'unknown').slice(0, 256), created_at: new Date(), revoked_at: null,
    revoked_reason: null, revoked_by: null };
  if (!usePg()) {
    if (payload.parentId && _mem.get(`${tenantId}|${payload.parentId}`).status !== 'active') throw refuse('DELEGATION_REVOKED', payload.parentId);
    _mem.set(`${tenantId}|${delegationId}`, row);
  } else {
    await _retry(() => pgPool.withTenantTransaction(tenantId, async (tx) => {
      if (payload.parentId) {
        const p = await tx.query('SELECT status FROM agent_delegations WHERE tenant_id=$1 AND delegation_id=$2 FOR SHARE', [tenantId, payload.parentId]);
        if (!p.rows.length || p.rows[0].status !== 'active') throw refuse('DELEGATION_REVOKED', payload.parentId);
      }
      await tx.query(`INSERT INTO agent_delegations (tenant_id, delegation_id, parent_id, root_agent_id, issuer_agent_id, subject_agent_id, depth, max_depth, classes, tools, max_actions, token, token_digest, issued_at, expires_at, created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12::jsonb,$13,$14,$15,$16)`, [tenantId, delegationId, payload.parentId, payload.rootAgentId, payload.issuerAgentId, payload.subjectAgentId, payload.depth,
        payload.maxDepth, payload.classes, payload.tools === null ? null : JSON.stringify(payload.tools), payload.maxActions, JSON.stringify(token), check.chainHash, row.issued_at, row.expires_at, row.created_by]);
    }));
  }
  emit('INFO', 'DELEGATION_ISSUED', { tenantId, delegationId, parentId: payload.parentId, rootAgentId: payload.rootAgentId, issuerAgentId: payload.issuerAgentId, subjectAgentId: payload.subjectAgentId,
    depth: payload.depth, chainHash: check.chainHash, classes: payload.classes, actor: row.created_by });
  await _audit('DELEGATION_ISSUED', { delegationId, chainHash: check.chainHash, depth: payload.depth, rootAgentId: payload.rootAgentId, parentId: payload.parentId, tenantId });
  return { delegation: out(row), token, chainHash: check.chainHash };
}

// ── use ──────────────────────────────────────────────────────────────────────────────────────────────────
/** Count one action against every limited link of the chain and record the trace; @returns {{ ok: true } | { ok: false, reason: 'ACTION_BUDGET_EXHAUSTED' }} */
async function useDelegation(tenantId, live, { requestId, agentId, sessionId }) {
  const rows = live.rows; const limited = rows.filter((r) => r.maxActions !== null);
  const trace = { requestId, delegationId: live.delegationId, chainHash: live.chainHash, depth: live.depth, rootAgentId: live.rootAgentId, agentId, sessionId };
  if (!usePg()) {
    const mem = rows.map((r) => _mem.get(`${tenantId}|${r.delegationId}`));
    if (mem.some((r) => r.max_actions !== null && r.actions_used >= r.max_actions)) return { ok: false, reason: 'ACTION_BUDGET_EXHAUSTED' };
    for (const r of mem) if (r.max_actions !== null) r.actions_used += 1;
    _uses.set(`${tenantId}|${requestId}`, { ...trace, usedAt: new Date() });
    return { ok: true };
  }
  const ids = limited.map((r) => r.delegationId);
  try {
    await _retry(() => pgPool.withTenantTransaction(tenantId, async (tx) => {
      if (ids.length) {
        const u = await tx.query('UPDATE agent_delegations SET actions_used = actions_used + 1 WHERE tenant_id=$1 AND delegation_id = ANY($2::uuid[]) AND status=\'active\' AND actions_used < max_actions RETURNING delegation_id', [tenantId, ids]);
        if (u.rowCount !== ids.length) throw Object.assign(new Error('exhausted'), { exhausted: true });          // rolls the whole transaction back: no link is charged for a refusal
      }
      await tx.query('INSERT INTO delegation_uses (tenant_id, request_id, delegation_id, chain_hash, depth, root_agent_id, agent_id, session_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [tenantId, requestId, live.delegationId, live.chainHash, live.depth, live.rootAgentId, agentId, sessionId]);
    }));
    return { ok: true };
  } catch (e) { if (e && e.exhausted) return { ok: false, reason: 'ACTION_BUDGET_EXHAUSTED' }; throw e; }
}

async function getUse(tenantId, requestId) {
  if (typeof requestId !== 'string' || !UUID_V4.test(requestId)) return null;
  if (!usePg()) return _uses.get(`${tenantId}|${requestId}`) || null;
  const r = await pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT * FROM delegation_uses WHERE tenant_id=$1 AND request_id=$2', [tenantId, requestId])).rows[0]);
  return r ? { requestId: r.request_id, delegationId: r.delegation_id, chainHash: String(r.chain_hash).trim(), depth: r.depth, rootAgentId: r.root_agent_id, agentId: r.agent_id, sessionId: r.session_id, usedAt: r.used_at } : null;
}

// ── revoke ───────────────────────────────────────────────────────────────────────────────────────────────
async function _descendantsRevoke(tenantId, delegationId, reason, actor) {
  const by = String(actor || 'unknown').slice(0, 256); const why = String(reason || '').slice(0, 256) || null;
  if (!usePg()) {
    const out_ = []; const walk = (id) => {
      const r = _mem.get(`${tenantId}|${id}`);
      if (r && r.status === 'active') { r.status = 'revoked'; r.revoked_at = new Date(); r.revoked_reason = why; r.revoked_by = by; out_.push(r); }
      for (const c of _mem.values()) if (c.tenant_id === tenantId && c.parent_id === id) walk(c.delegation_id);
    };
    walk(delegationId);
    return out_;
  }
  return _retry(() => pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query(
    `WITH RECURSIVE t AS (SELECT delegation_id FROM agent_delegations WHERE tenant_id=$1 AND delegation_id=$2
       UNION ALL SELECT d.delegation_id FROM agent_delegations d JOIN t ON d.parent_id=t.delegation_id WHERE d.tenant_id=$1)
     UPDATE agent_delegations SET status='revoked', revoked_at=now(), revoked_reason=$3, revoked_by=$4
      WHERE tenant_id=$1 AND status='active' AND delegation_id IN (SELECT delegation_id FROM t) RETURNING *`, [tenantId, delegationId, why, by])).rows));
}

/**
 * Revoke a delegation and every delegation below it. The executions running under any of them are aborted at once (this process; other replicas stop at the
 * next action: verifyLive is checked on every authorisation and on every execution). `revokeAgents` also revokes the delegates of the whole subtree.
 * @returns {Promise<{ revoked: string[], abortedExecutions: number, agentsRevoked: string[] }>}
 */
async function revoke(tenantId, delegationId, { reason, actor, revokeAgents = false } = {}) {
  _tenant(tenantId);
  _uuid(delegationId, 'DELEGATION');
  const d = await get(tenantId, delegationId);
  if (!d) throw new StoreError('NOT_FOUND', 'no such delegation', 404);
  const rows = await _descendantsRevoke(tenantId, delegationId, reason, actor);
  let aborted = 0;
  for (const r of rows) aborted += killRegistry.abortLabel(tenantId, `delegation:${r.delegation_id}`, `DELEGATION_REVOKED: ${reason || ''}`);
  const agentsRevoked = [];
  if (revokeAgents) {
    const subtree = rows.length ? rows : [];
    const ids = [...new Set(subtree.map((r) => r.subject_agent_id))].filter((a) => a !== d.rootAgentId);
    for (const a of ids) {
      try { await agents.updateAgent(tenantId, a, { status: 'revoked' }, actor); agentsRevoked.push(a); } catch (e) { if (!(e && e.code === 'AGENT_REVOKED')) emit('ERROR', 'DELEGATION_AGENT_REVOKE_FAILED', { tenantId, agentId: a, error: e && e.message }); }
    }
  }
  for (const r of rows) {
    emit('WARN', 'DELEGATION_REVOKED', { tenantId, delegationId: r.delegation_id, rootAgentId: r.root_agent_id, depth: r.depth, reason: reason || null, actor: String(actor || 'unknown'), cascadeRoot: delegationId });
    await _audit('DELEGATION_REVOKED', { delegationId: r.delegation_id, chainHash: String(r.token_digest).trim(), depth: r.depth, rootAgentId: r.root_agent_id, parentId: r.parent_id || null, tenantId });
  }
  return { revoked: rows.map((r) => r.delegation_id), abortedExecutions: aborted, agentsRevoked };
}

/**
 * Re-audit A1-01: who may read or revoke a delegation. The identity that issued it, or one that issued any delegation ABOVE it in its chain (the root owner controls
 * everything below), may; another identity of the same tenant may not. Operators with their own permissions use the operator routes, not this check.
 */
async function isControlledBy(tenantId, delegationId, actor) {
  _tenant(tenantId);
  const me = String(actor || '');
  let cur = await get(tenantId, delegationId);
  for (let hops = 0; cur && hops < 10; hops++) {
    if (cur.createdBy === me) return true;
    cur = cur.parentId ? await get(tenantId, cur.parentId) : null;
  }
  return false;
}

/** An agent that is suspended or revoked takes its delegations with it: those it issued, those it holds, and everything below them. */
async function revokeForAgent(tenantId, agentId, reason, actor) {
  const all = await list(tenantId, { agentId, status: 'active' });
  const revoked = [];
  for (const d of all) { const r = await revoke(tenantId, d.delegationId, { reason, actor }); revoked.push(...r.revoked); }
  return [...new Set(revoked)];
}

// ── audit (schema v8 only) ───────────────────────────────────────────────────────────────────────────────
async function _audit(type, c) {
  const eb = require('../audit/entryBuilder');
  if (eb.currentSchemaVersion() < 8) return { recorded: false, reason: 'AUDIT_SCHEMA_V8_DISABLED' };
  try {
    const entry = await require('../audit/audit-log').appendMandatory({
      artifactId: `${c.delegationId}:${type === 'DELEGATION_ISSUED' ? 'delegation_issued' : 'delegation_revoked'}`, entryType: type, decision: 'ALLOW', reason: type, tenantId: c.tenantId,
      executionContext: { delegation: { chainHash: c.chainHash, depth: c.depth, rootAgentId: c.rootAgentId, parentId: c.parentId } },
    }, { stage: 'DELEGATION', maxRetries: 3, retryDelayMs: 100 });
    return { recorded: true, entryHash: entry ? entry.hash : null };
  } catch (err) {
    emit('CRITICAL', 'DELEGATION_AUDIT_FAILED', { type, delegationId: c.delegationId, error: err.message, code: err.code ?? null });
    return { recorded: false, reason: 'AUDIT_APPEND_FAILED' };
  }
}

function _resetForTests() { _mem.clear(); _uses.clear(); }

// an agent that is suspended or revoked takes its delegations with it; registered here so that the agent store does not need to require this module
agents.onAgentInactive(revokeForAgent);

module.exports = { StoreError, DEFAULT_MAX_DEPTH, issue, get, list, verifyLive, useDelegation, getUse, revoke, revokeForAgent, isControlledBy, _resetForTests };
