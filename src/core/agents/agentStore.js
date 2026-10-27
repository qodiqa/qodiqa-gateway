'use strict';

/**
 * Agent identities and sessions.
 *
 *   agent    a named, tenant-owned, revocable identity that acts on behalf of a user (owner_user_id) or of the tenant. It carries the LIMITS of its autonomy:
 * the classes of action it may be authorised for, the maximum number of actions and the maximum duration of one session, a cost budget.
 *   session  one bounded run of an agent: expires (TTL), has a hard cap of actions (max_actions) and of cost, a per-session action sequence (next_seq,
 * last_action_hash - the chain builds on), and can be ended or force-stopped.
 *
 * Effective session limits are ALWAYS the lower of what the caller asks for and what the agent allows (and the platform hard caps below): a session cannot
 * be given more autonomy than its agent has. A revoked or suspended agent has no usable session: checkSession() refuses it on every request and
 * revoking / suspending an agent ends its active sessions at once. Privilege separation: the agent acts with ITS limits, never with the user's own rights;
 * the user it acts for is recorded (owner_user_id) and travels in the evidence, it is not an authority.
 *
 * Identifiers: agentId and sessionId are gateway-issued UUID v4 (docs/protocol/PROTOCOL-V2.md section 5.1); the human name is displayName.
 *
 * Storage: PostgreSQL (migration 100, RLS forced by tenant, every statement inside withTenantTransaction) or, without PostgreSQL, process memory.
 */

const crypto = require('crypto');
const pgPool = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');

const ACTION_CLASSES = Object.freeze(['read', 'write', 'file', 'database', 'external_api', 'command', 'communication', 'financial', 'delegate']);
const AGENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;   // gateway-issued UUID v4 (V2-FREEZE 5.1)
const TENANT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SESSION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HARD_MAX_SESSION_SECONDS = 24 * 3600;
const DEFAULT_SESSION_SECONDS = 3600;
const HARD_MAX_ACTIONS = 100_000;
const DEFAULT_MAX_ACTIONS = 100;
const STATUSES = Object.freeze(['active', 'suspended', 'revoked']);

class AgentError extends Error {
  constructor(code, message, status = 400) { super(message); this.name = 'AgentError'; this.code = code; this.status = status; }
}

const _agents = new Map();      // `${tenant}\u0000${agent}` -> record
const _sessions = new Map();    // `${tenant}\u0000${session}` -> record
const usePg = () => pgPool.isEnabled();
const akey = (t, a) => `${t}\u0000${a}`;

function _tenant(t) { if (typeof t !== 'string' || !TENANT_ID_RE.test(t)) throw new AgentError('INVALID_TENANT_ID', 'tenantId must be 1-64 characters of A-Z a-z 0-9 _ -'); return t; }
function _agentId(a) { if (typeof a !== 'string' || !AGENT_ID_RE.test(a)) throw new AgentError('INVALID_AGENT_ID', 'agentId must be a UUID v4 issued by the gateway'); return a; }
function _sessionId(s) { if (typeof s !== 'string' || !SESSION_ID_RE.test(s)) throw new AgentError('INVALID_SESSION_ID', 'sessionId must be a UUID'); return s.toLowerCase(); }
function _int(v, name, { min = 0, max = Number.MAX_SAFE_INTEGER, nullable = true } = {}) {
  if (v === undefined || v === null) { if (nullable) return null; throw new AgentError('INVALID_LIMIT', `${name} is required`); }
  if (!Number.isInteger(v) || v < min || v > max) throw new AgentError('INVALID_LIMIT', `${name} must be an integer ${min}..${max}`);
  return v;
}
function _classes(list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.some((c) => !ACTION_CLASSES.includes(c)) || new Set(list).size !== list.length) throw new AgentError('INVALID_ACTION_CLASSES', `allowedActionClasses must be a list of distinct values among ${ACTION_CLASSES.join(', ')}`);
  return [...list].sort();
}
function _publicKey(k) {
  if (k === undefined || k === null) return null;
  let ok = false;
  try { const der = Buffer.from(k, 'base64'); ok = typeof k === 'string' && der.toString('base64') === k && crypto.createPublicKey({ key: der, format: 'der', type: 'spki' }).asymmetricKeyType === 'ed25519'; } catch { ok = false; }
  if (!ok) throw new AgentError('INVALID_PUBLIC_KEY', 'publicKey must be an Ed25519 public key (SPKI DER, canonical base64)');
  return k;
}

const agentOut = (r) => (r ? {
  tenantId: r.tenant_id, agentId: r.agent_id, displayName: r.display_name, status: r.status, ownerUserId: r.owner_user_id ?? null, publicKey: r.public_key ?? null,
  allowedActionClasses: [...(r.allowed_action_classes || [])], maxActionsPerSession: r.max_actions_per_session ?? null, maxSessionSeconds: r.max_session_seconds ?? null,
  costBudgetMicros: r.cost_budget_micros === null || r.cost_budget_micros === undefined ? null : Number(r.cost_budget_micros),
  createdBy: r.created_by, createdAt: new Date(r.created_at).toISOString(), updatedAt: new Date(r.updated_at).toISOString(), revokedAt: r.revoked_at ? new Date(r.revoked_at).toISOString() : null,
} : null);
const sessionOut = (r) => (r ? {
  tenantId: r.tenant_id, sessionId: r.session_id, agentId: r.agent_id, status: r.status, startedAt: new Date(r.started_at).toISOString(), expiresAt: new Date(r.expires_at).toISOString(),
  endedAt: r.ended_at ? new Date(r.ended_at).toISOString() : null, endedReason: r.ended_reason ?? null, maxActions: Number(r.max_actions), actionsUsed: Number(r.actions_used),
  costBudgetMicros: r.cost_budget_micros === null || r.cost_budget_micros === undefined ? null : Number(r.cost_budget_micros), costUsedMicros: Number(r.cost_used_micros),
  nextSeq: Number(r.next_seq), lastActionHash: r.last_action_hash ?? null, createdBy: r.created_by,
} : null);

// ── agents ───────────────────────────────────────────────────────────────────────────────────────────────
async function createAgent(tenantId, spec, actor) {
  _tenant(tenantId); const s = spec || {};
  if (s.agentId !== undefined) throw new AgentError('AGENT_ID_IS_ISSUED', 'the agentId is issued by the gateway (a UUID v4); do not send one', 400);
  const row = {
    tenant_id: tenantId, agent_id: crypto.randomUUID(),
    display_name: (typeof s.displayName === 'string' && s.displayName.trim() && s.displayName.length <= 200) ? s.displayName.trim() : (() => { throw new AgentError('INVALID_DISPLAY_NAME', 'displayName is required (1-200 characters)'); })(),
    status: 'active', owner_user_id: s.ownerUserId === undefined || s.ownerUserId === null ? null : (typeof s.ownerUserId === 'string' && s.ownerUserId.length > 0 && s.ownerUserId.length <= 128 ? s.ownerUserId : (() => { throw new AgentError('INVALID_OWNER', 'ownerUserId must be 1-128 characters'); })()),
    public_key: _publicKey(s.publicKey), allowed_action_classes: _classes(s.allowedActionClasses),
    max_actions_per_session: _int(s.maxActionsPerSession, 'maxActionsPerSession', { max: HARD_MAX_ACTIONS }), max_session_seconds: _int(s.maxSessionSeconds, 'maxSessionSeconds', { min: 1, max: HARD_MAX_SESSION_SECONDS }),
    cost_budget_micros: _int(s.costBudgetMicros, 'costBudgetMicros'), created_by: String(actor || 'unknown').slice(0, 256),
  };
  const now = new Date();
  if (!usePg()) {
    const rec = { ...row, created_at: now, updated_at: now, revoked_at: null }; _agents.set(akey(tenantId, row.agent_id), rec); return agentOut(rec);
  }
  {
    return await pgPool.withTenantTransaction(tenantId, async (tx) => {
      const r = await tx.query(`INSERT INTO agent_identities (tenant_id, agent_id, display_name, status, owner_user_id, public_key, allowed_action_classes, max_actions_per_session, max_session_seconds, cost_budget_micros, created_by)
        VALUES ($1,$2,$3,'active',$4,$5,$6,$7,$8,$9,$10) RETURNING *`, [row.tenant_id, row.agent_id, row.display_name, row.owner_user_id, row.public_key, row.allowed_action_classes, row.max_actions_per_session, row.max_session_seconds, row.cost_budget_micros, row.created_by]);
      return agentOut(r.rows[0]);
    });
  }
}

async function getAgent(tenantId, agentId) {
  _tenant(tenantId); _agentId(agentId);
  if (!usePg()) return agentOut(_agents.get(akey(tenantId, agentId)));
  return pgPool.withTenantTransaction(tenantId, async (tx) => agentOut((await tx.query('SELECT * FROM agent_identities WHERE tenant_id = $1 AND agent_id = $2', [tenantId, agentId])).rows[0]));
}

async function listAgents(tenantId, { status, limit = 100 } = {}) {
  _tenant(tenantId);
  if (status !== undefined && !STATUSES.includes(status)) throw new AgentError('INVALID_STATUS', `status must be one of ${STATUSES.join(', ')}`);
  const lim = Math.min(Math.max(Number.isInteger(limit) ? limit : 100, 1), 500);
  if (!usePg()) return [..._agents.values()].filter((r) => r.tenant_id === tenantId && (!status || r.status === status)).sort((a, b) => (a.agent_id < b.agent_id ? -1 : 1)).slice(0, lim).map(agentOut);
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT * FROM agent_identities WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2) ORDER BY agent_id LIMIT $3', [tenantId, status || null, lim])).rows.map(agentOut));
}

/** Revoked is absorbing. Suspending or revoking ends the agent's active sessions at once. */
async function updateAgent(tenantId, agentId, patch, actor) {
  _tenant(tenantId); _agentId(agentId);
  const cur = await getAgent(tenantId, agentId);
  if (!cur) throw new AgentError('AGENT_NOT_FOUND', 'no such agent', 404);
  const p = patch || {};
  if (cur.status === 'revoked') throw new AgentError('AGENT_REVOKED', 'a revoked agent cannot be changed', 409);
  const next = {
    display_name: p.displayName !== undefined ? ((typeof p.displayName === 'string' && p.displayName.trim() && p.displayName.length <= 200) ? p.displayName.trim() : (() => { throw new AgentError('INVALID_DISPLAY_NAME', 'displayName must be 1-200 characters'); })()) : cur.displayName,
    status: p.status !== undefined ? (STATUSES.includes(p.status) ? p.status : (() => { throw new AgentError('INVALID_STATUS', `status must be one of ${STATUSES.join(', ')}`); })()) : cur.status,
    owner_user_id: p.ownerUserId !== undefined ? p.ownerUserId : cur.ownerUserId,
    public_key: p.publicKey !== undefined ? _publicKey(p.publicKey) : cur.publicKey,
    allowed_action_classes: p.allowedActionClasses !== undefined ? _classes(p.allowedActionClasses) : cur.allowedActionClasses,
    max_actions_per_session: p.maxActionsPerSession !== undefined ? _int(p.maxActionsPerSession, 'maxActionsPerSession', { max: HARD_MAX_ACTIONS }) : cur.maxActionsPerSession,
    max_session_seconds: p.maxSessionSeconds !== undefined ? _int(p.maxSessionSeconds, 'maxSessionSeconds', { min: 1, max: HARD_MAX_SESSION_SECONDS }) : cur.maxSessionSeconds,
    cost_budget_micros: p.costBudgetMicros !== undefined ? _int(p.costBudgetMicros, 'costBudgetMicros') : cur.costBudgetMicros,
  };
  const now = new Date(); const revokedAt = next.status === 'revoked' ? now : null;
  let out;
  if (!usePg()) {
    const rec = _agents.get(akey(tenantId, agentId)); Object.assign(rec, next, { updated_at: now, revoked_at: revokedAt }); out = agentOut(rec);
  } else {
    out = await pgPool.withTenantTransaction(tenantId, async (tx) => agentOut((await tx.query(`UPDATE agent_identities SET display_name=$3, status=$4, owner_user_id=$5, public_key=$6, allowed_action_classes=$7, max_actions_per_session=$8,
        max_session_seconds=$9, cost_budget_micros=$10, updated_at=now(), revoked_at=$11 WHERE tenant_id=$1 AND agent_id=$2 RETURNING *`,
      [tenantId, agentId, next.display_name, next.status, next.owner_user_id, next.public_key, next.allowed_action_classes, next.max_actions_per_session, next.max_session_seconds, next.cost_budget_micros, revokedAt])).rows[0]));
  }
  if (next.status !== 'active') {
    await killAgentSessions(tenantId, agentId, `AGENT_${next.status.toUpperCase()}`, actor);
    // an agent that is suspended or revoked takes the delegations it issued or holds with it; every use re-checks the agents of the chain anyway
    for (const hook of _inactiveHooks) {
      try { await hook(tenantId, agentId, `AGENT_${next.status.toUpperCase()}`, actor); } catch (e) { emit('ERROR', 'AGENT_DELEGATION_REVOKE_FAILED', { tenantId, agentId, error: e && e.message }); }
    }
  }
  emit('INFO', 'AGENT_UPDATED', { tenantId, agentId, status: out.status, actor: String(actor || 'unknown') });
  return out;
}

// ── sessions ─────────────────────────────────────────────────────────────────────────────────────────────
/** Effective limits = min(requested, agent's, platform caps). */
async function startSession(tenantId, agentId, req, actor) {
  _tenant(tenantId); _agentId(agentId);
  const agent = await getAgent(tenantId, agentId);
  if (!agent) throw new AgentError('AGENT_NOT_FOUND', 'no such agent', 404);
  if (agent.status !== 'active') throw new AgentError('AGENT_NOT_ACTIVE', `the agent is ${agent.status}`, 409);
  const r = req || {};
  const ttl = Math.min(_int(r.ttlSeconds, 'ttlSeconds', { min: 1, max: HARD_MAX_SESSION_SECONDS }) ?? DEFAULT_SESSION_SECONDS, agent.maxSessionSeconds ?? HARD_MAX_SESSION_SECONDS);
  const maxActions = Math.min(_int(r.maxActions, 'maxActions', { max: HARD_MAX_ACTIONS }) ?? DEFAULT_MAX_ACTIONS, agent.maxActionsPerSession ?? HARD_MAX_ACTIONS);
  const reqCost = _int(r.costBudgetMicros, 'costBudgetMicros');
  const cost = reqCost === null ? agent.costBudgetMicros : (agent.costBudgetMicros === null ? reqCost : Math.min(reqCost, agent.costBudgetMicros));
  const sessionId = crypto.randomUUID(); const now = new Date(); const expires = new Date(now.getTime() + ttl * 1000);
  const row = { tenant_id: tenantId, session_id: sessionId, agent_id: agentId, status: 'active', started_at: now, expires_at: expires, ended_at: null, ended_reason: null, max_actions: maxActions, actions_used: 0,
    cost_budget_micros: cost, cost_used_micros: 0, next_seq: 1, last_action_hash: null, created_by: String(actor || 'unknown').slice(0, 256) };
  if (!usePg()) { _sessions.set(akey(tenantId, sessionId), { ...row, updated_at: now }); return sessionOut(row); }
  return pgPool.withTenantTransaction(tenantId, async (tx) => sessionOut((await tx.query(`INSERT INTO agent_sessions (tenant_id, session_id, agent_id, started_at, expires_at, max_actions, cost_budget_micros, created_by)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`, [tenantId, sessionId, agentId, now, expires, maxActions, cost, row.created_by])).rows[0]));
}

async function _expireDue(tenantId, sessionId) {
  if (!usePg()) {
    const r = _sessions.get(akey(tenantId, sessionId));
    if (r && r.status === 'active' && r.expires_at.getTime() <= Date.now()) Object.assign(r, { status: 'expired', ended_at: new Date(), ended_reason: 'TTL', updated_at: new Date() });
    return;
  }
  await _retry(() => pgPool.withTenantTransaction(tenantId, async (tx) => {
    await tx.query(`UPDATE agent_sessions SET status='expired', ended_at=now(), ended_reason='TTL', updated_at=now() WHERE tenant_id=$1 AND session_id=$2 AND status='active' AND expires_at <= now()`, [tenantId, sessionId]);
  }));
}

async function getSession(tenantId, sessionId) {
  _tenant(tenantId); const sid = _sessionId(sessionId);
  await _expireDue(tenantId, sid);
  if (!usePg()) return sessionOut(_sessions.get(akey(tenantId, sid)));
  return pgPool.withTenantTransaction(tenantId, async (tx) => sessionOut((await tx.query('SELECT * FROM agent_sessions WHERE tenant_id=$1 AND session_id=$2', [tenantId, sid])).rows[0]));
}

async function listSessions(tenantId, { agentId, status, limit = 100 } = {}) {
  _tenant(tenantId);
  if (agentId !== undefined) _agentId(agentId);
  if (status !== undefined && !['active', 'ended', 'expired', 'killed'].includes(status)) throw new AgentError('INVALID_STATUS', 'status must be active, ended, expired or killed');
  const lim = Math.min(Math.max(Number.isInteger(limit) ? limit : 100, 1), 500);
  if (!usePg()) return [..._sessions.values()].filter((r) => r.tenant_id === tenantId && (!agentId || r.agent_id === agentId) && (!status || r.status === status)).sort((a, b) => b.started_at - a.started_at).slice(0, lim).map(sessionOut);
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT * FROM agent_sessions WHERE tenant_id=$1 AND ($2::text IS NULL OR agent_id=$2) AND ($3::text IS NULL OR status=$3) ORDER BY started_at DESC LIMIT $4', [tenantId, agentId || null, status || null, lim])).rows.map(sessionOut));
}

async function _close(tenantId, sessionId, status, reason) {
  const sid = _sessionId(sessionId);
  if (!usePg()) {
    const r = _sessions.get(akey(tenantId, sid)); if (!r) return null;
    if (r.status === 'active') Object.assign(r, { status, ended_at: new Date(), ended_reason: reason, updated_at: new Date() });
    return sessionOut(r);
  }
  return _retry(() => pgPool.withTenantTransaction(tenantId, async (tx) => {
    await tx.query(`UPDATE agent_sessions SET status=$3, ended_at=now(), ended_reason=$4, updated_at=now() WHERE tenant_id=$1 AND session_id=$2 AND status='active'`, [tenantId, sid, status, reason]);
    return sessionOut((await tx.query('SELECT * FROM agent_sessions WHERE tenant_id=$1 AND session_id=$2', [tenantId, sid])).rows[0]);
  }));
}
const _reason = (r, d) => (typeof r === 'string' && r.trim() ? r.trim().slice(0, 500) : d);

async function endSession(tenantId, sessionId, reason, actor) {
  _tenant(tenantId);
  const out = await _close(tenantId, sessionId, 'ended', _reason(reason, 'ENDED_BY_CALLER'));
  if (!out) throw new AgentError('SESSION_NOT_FOUND', 'no such session', 404);
  emit('INFO', 'AGENT_SESSION_ENDED', { tenantId, sessionId: out.sessionId, agentId: out.agentId, actor: String(actor || 'unknown'), status: out.status });
  return out;
}

/** force-stop. The status is `killed`; every later checkSession()/reserveAction() refuses it; the cancellation of work in flight is propagated by killRegistry. */
async function killSession(tenantId, sessionId, reason, actor) {
  _tenant(tenantId);
  const out = await _close(tenantId, sessionId, 'killed', _reason(reason, 'KILLED_BY_OPERATOR'));
  if (!out) throw new AgentError('SESSION_NOT_FOUND', 'no such session', 404);
  require('./killRegistry').abort(tenantId, out.sessionId, _reason(reason, 'KILLED_BY_OPERATOR'));
  emit('CRITICAL', 'AGENT_SESSION_KILLED', { tenantId, sessionId: out.sessionId, agentId: out.agentId, actor: String(actor || 'unknown'), reason: _reason(reason, 'KILLED_BY_OPERATOR') });
  return out;
}

async function killAgentSessions(tenantId, agentId, reason, actor) {
  const active = await listSessions(tenantId, { agentId, status: 'active', limit: 500 });
  for (const s of active) await killSession(tenantId, s.sessionId, reason, actor);
  return active.length;
}

/**
 * is this (tenant, agent, session) triple allowed to act RIGHT NOW? Checked on every request that names an agent session.
 * @returns {Promise<{ ok: true, agent: object, session: object } | { ok: false, reason: string }>}
 */
async function checkSession(tenantId, agentId, sessionId) {
  try { _tenant(tenantId); _agentId(agentId); _sessionId(sessionId); } catch { return { ok: false, reason: 'AGENT_SESSION_INVALID' }; }
  const session = await getSession(tenantId, sessionId);
  if (!session || session.agentId !== agentId) return { ok: false, reason: 'AGENT_SESSION_UNKNOWN' };      // another tenant's / another agent's session looks identical to an unknown one
  if (session.status === 'expired') return { ok: false, reason: 'AGENT_SESSION_EXPIRED' };
  if (session.status !== 'active') return { ok: false, reason: 'AGENT_SESSION_ENDED' };
  const agent = await getAgent(tenantId, agentId);
  if (!agent || agent.status !== 'active') return { ok: false, reason: 'AGENT_NOT_ACTIVE' };
  return { ok: true, agent, session };
}

/**
 * Atomically take one action from the session budget (and `costMicros` from the cost budget) and advance the action sequence. Refuses an action class the agent
 * is not allowed and a session that is not active / is exhausted. `prevActionHash` of the caller must equal last_action_hash when given (chain).
 * @returns {Promise<{ ok: true, seq: number, session: object } | { ok: false, reason: string }>}
 */
async function reserveAction(tenantId, sessionId, { actionClass, costMicros = 0, actionHash = null, prevActionHash } = {}) {
  _tenant(tenantId); const sid = _sessionId(sessionId);
  if (!ACTION_CLASSES.includes(actionClass)) return { ok: false, reason: 'ACTION_CLASS_INVALID' };
  if (!Number.isInteger(costMicros) || costMicros < 0) return { ok: false, reason: 'COST_INVALID' };
  if (actionHash !== null && !/^[0-9a-f]{64}$/.test(String(actionHash))) return { ok: false, reason: 'ACTION_HASH_INVALID' };
  const s0 = await getSession(tenantId, sid);
  if (!s0) return { ok: false, reason: 'AGENT_SESSION_UNKNOWN' };
  const c = await checkSession(tenantId, s0.agentId, sid);
  if (!c.ok) return c;
  if (!c.agent.allowedActionClasses.includes(actionClass)) return { ok: false, reason: 'ACTION_CLASS_NOT_ALLOWED' };
  if (prevActionHash !== undefined && prevActionHash !== s0.lastActionHash) return { ok: false, reason: 'ACTION_CHAIN_MISMATCH' };
  if (!usePg()) {
    const r = _sessions.get(akey(tenantId, sid));
    if (r.actions_used >= r.max_actions) return { ok: false, reason: 'ACTION_BUDGET_EXHAUSTED' };
    if (r.cost_budget_micros !== null && r.cost_used_micros + costMicros > r.cost_budget_micros) return { ok: false, reason: 'COST_BUDGET_EXHAUSTED' };
    if (prevActionHash !== undefined && prevActionHash !== r.last_action_hash) return { ok: false, reason: 'ACTION_CHAIN_MISMATCH' };
    const seq = r.next_seq; r.actions_used += 1; r.cost_used_micros += costMicros; r.next_seq += 1; if (actionHash) r.last_action_hash = actionHash; r.updated_at = new Date();
    return { ok: true, seq, session: sessionOut(r) };
  }
  return _retry(() => pgPool.withTenantTransaction(tenantId, async (tx) => {
    const r = await tx.query(`UPDATE agent_sessions SET actions_used = actions_used + 1, cost_used_micros = cost_used_micros + $3, next_seq = next_seq + 1,
        last_action_hash = COALESCE($4, last_action_hash), updated_at = now()
      WHERE tenant_id=$1 AND session_id=$2 AND status='active' AND expires_at > now() AND actions_used < max_actions
        AND (cost_budget_micros IS NULL OR cost_used_micros + $3 <= cost_budget_micros)
        AND ($5::boolean IS FALSE OR last_action_hash IS NOT DISTINCT FROM $6)
      RETURNING *, next_seq - 1 AS taken_seq`, [tenantId, sid, costMicros, actionHash, prevActionHash !== undefined, prevActionHash === undefined ? null : prevActionHash]);
    if (r.rows.length) return { ok: true, seq: Number(r.rows[0].taken_seq), session: sessionOut(r.rows[0]) };
    const now = sessionOut((await tx.query('SELECT * FROM agent_sessions WHERE tenant_id=$1 AND session_id=$2', [tenantId, sid])).rows[0]);
    if (!now || now.status !== 'active') return { ok: false, reason: 'AGENT_SESSION_ENDED' };
    if (now.actionsUsed >= now.maxActions) return { ok: false, reason: 'ACTION_BUDGET_EXHAUSTED' };
    if (now.costBudgetMicros !== null && now.costUsedMicros + costMicros > now.costBudgetMicros) return { ok: false, reason: 'COST_BUDGET_EXHAUSTED' };
    if (prevActionHash !== undefined && prevActionHash !== now.lastActionHash) return { ok: false, reason: 'ACTION_CHAIN_MISMATCH' };
    return { ok: false, reason: 'AGENT_SESSION_EXPIRED' };
  }));
}

/**
 * Count one action against the session's budgets WITHOUT taking a place in the session chain (no seq, no hash): for actions the gateway performs itself that are
 * not artifact-driven. Same checks as reserveAction: live session, allowed class, action and cost budget.
 * @returns {Promise<{ ok: true, session: object } | { ok: false, reason: string }>}
 */
async function chargeAction(tenantId, sessionId, { actionClass, costMicros = 0 } = {}) {
  _tenant(tenantId); const sid = _sessionId(sessionId);
  if (!ACTION_CLASSES.includes(actionClass)) return { ok: false, reason: 'ACTION_CLASS_INVALID' };
  if (!Number.isInteger(costMicros) || costMicros < 0) return { ok: false, reason: 'COST_INVALID' };
  const s0 = await getSession(tenantId, sid);
  if (!s0) return { ok: false, reason: 'AGENT_SESSION_UNKNOWN' };
  const c = await checkSession(tenantId, s0.agentId, sid);
  if (!c.ok) return c;
  if (!c.agent.allowedActionClasses.includes(actionClass)) return { ok: false, reason: 'ACTION_CLASS_NOT_ALLOWED' };
  if (!usePg()) {
    const r = _sessions.get(akey(tenantId, sid));
    if (r.actions_used >= r.max_actions) return { ok: false, reason: 'ACTION_BUDGET_EXHAUSTED' };
    if (r.cost_budget_micros !== null && r.cost_used_micros + costMicros > r.cost_budget_micros) return { ok: false, reason: 'COST_BUDGET_EXHAUSTED' };
    r.actions_used += 1; r.cost_used_micros += costMicros; r.updated_at = new Date();
    return { ok: true, session: sessionOut(r) };
  }
  return _retry(() => pgPool.withTenantTransaction(tenantId, async (tx) => {
    const r = await tx.query(`UPDATE agent_sessions SET actions_used = actions_used + 1, cost_used_micros = cost_used_micros + $3, updated_at = now()
      WHERE tenant_id=$1 AND session_id=$2 AND status='active' AND expires_at > now() AND actions_used < max_actions AND (cost_budget_micros IS NULL OR cost_used_micros + $3 <= cost_budget_micros) RETURNING *`, [tenantId, sid, costMicros]);
    if (r.rows.length) return { ok: true, session: sessionOut(r.rows[0]) };
    const now = sessionOut((await tx.query('SELECT * FROM agent_sessions WHERE tenant_id=$1 AND session_id=$2', [tenantId, sid])).rows[0]);
    if (!now || now.status !== 'active') return { ok: false, reason: 'AGENT_SESSION_ENDED' };
    if (now.actionsUsed >= now.maxActions) return { ok: false, reason: 'ACTION_BUDGET_EXHAUSTED' };
    if (now.costBudgetMicros !== null && now.costUsedMicros + costMicros > now.costBudgetMicros) return { ok: false, reason: 'COST_BUDGET_EXHAUSTED' };
    return { ok: false, reason: 'AGENT_SESSION_EXPIRED' };
  }));
}

/**
 * Give back the LAST reservation of the session chain (reserveAction): the position, the hash and the count - used when a reserved action will never be authorised
 * (an approval that ended unapproved). Only possible while nothing was reserved after it; otherwise it refuses and the caller must close the gap another way.
 * @returns {Promise<boolean>} true when released
 */
async function releaseReservation(tenantId, sessionId, { seq, prevActionHash, actionHash }) {
  _tenant(tenantId); const sid = _sessionId(sessionId);
  if (!usePg()) {
    const r = _sessions.get(akey(tenantId, sid));
    if (!r || r.next_seq !== seq + 1 || (r.last_action_hash || null) !== (actionHash || null) || r.actions_used < 1) return false;
    r.next_seq = seq; r.last_action_hash = prevActionHash || null; r.actions_used -= 1; r.updated_at = new Date();
    return true;
  }
  return _retry(() => pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query(`UPDATE agent_sessions SET next_seq = $3, last_action_hash = $4, actions_used = actions_used - 1, updated_at = now()
    WHERE tenant_id=$1 AND session_id=$2 AND next_seq = $3 + 1 AND last_action_hash IS NOT DISTINCT FROM $5 AND actions_used > 0`, [tenantId, sid, seq, prevActionHash || null, actionHash || null])).rowCount === 1));
}

// concurrent updates of one session row under the pool's transaction isolation raise a serialization failure (40001): retry, never fail the caller for it
async function _retry(fn) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) { if (!(e && e.code === '40001') || i >= 12) throw e; await new Promise((r) => setTimeout(r, 2 + Math.floor(Math.random() * 10 * (i + 1)))); }
  }
}

function _resetForTests() { _agents.clear(); _sessions.clear(); try { require('./killRegistry')._reset(); } catch { /* none */ } }

// Dependency inversion (rule no-circular): code that must react when an agent stops being active (the delegation store revokes the delegations the agent issued or
// holds) registers a hook here instead of this module requiring it.
const _inactiveHooks = [];
function onAgentInactive(hook) { if (typeof hook === 'function' && !_inactiveHooks.includes(hook)) _inactiveHooks.push(hook); }

module.exports = { onAgentInactive, AgentError, ACTION_CLASSES, STATUSES, HARD_MAX_SESSION_SECONDS, HARD_MAX_ACTIONS, createAgent, getAgent, listAgents, updateAgent, startSession, getSession, listSessions, endSession, killSession,
  killAgentSessions, checkSession, reserveAction, chargeAction, releaseReservation, _resetForTests };
