'use strict';

/**
 * Execution plans: the plan of an agent session is authorised ONCE; each action is then authorised individually against it.
 *
 *   createPlan(tenant, { sessionId, agentId, steps: [{ server, name, maxCalls }], ttlSeconds? }, actor)   steps are checked against the registry by the caller
 *   activePlan(tenant, sessionId)                                         the session's newest active, unexpired plan, or null
 *   consumeStep(tenant, planId, { sessionId, agentId, server, name })     { ok, stepIndex, used, maxCalls } | { ok: false, reason }
 *   closePlan(tenant, planId, actor)
 *
 * While a session has an active plan an action outside it is refused (ACTION_NOT_IN_PLAN) - a tool the agent was talked into using after the plan was
 * authorised (prompt injection) is not callable. The counters move through ONE statement that checks the bound, so concurrent authorisations cannot exceed
 * maxCalls. planHash = SHA-256("QODIQA::ACTION_PLAN::V1" || JCS-P1(steps)) identifies exactly what was authorised.
 * Storage: PostgreSQL (migration 103, RLS forced by tenant) or process memory without PostgreSQL.
 */

const crypto = require('crypto');
const pgPool = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');
const { canonicalJcsP1 } = require('../../validation/jcsP1');

const PLAN_DOMAIN = 'QODIQA::ACTION_PLAN::V1';
const MAX_STEPS = 50;
const MAX_CALLS = 10_000;
const MAX_PLAN_SECONDS = 24 * 3600;
const DEFAULT_PLAN_SECONDS = 3600;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TENANT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SERVER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TOOL_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;

class PlanError extends Error { constructor(code, message, status = 400) { super(message); this.name = 'PlanError'; this.code = code; this.status = status; } }

const usePg = () => pgPool.isEnabled();
const _mem = new Map();                                   // `${tenant}|${planId}` -> row

const out = (r) => (r ? { tenantId: r.tenant_id, planId: r.plan_id, sessionId: r.session_id, agentId: r.agent_id, steps: r.steps, used: r.used, planHash: String(r.plan_hash).trim(), status: r.status,
  createdBy: r.created_by, createdAt: new Date(r.created_at).toISOString(), expiresAt: new Date(r.expires_at).toISOString(), closedAt: r.closed_at ? new Date(r.closed_at).toISOString() : null } : null);

function _steps(steps) {
  if (!Array.isArray(steps) || steps.length < 1 || steps.length > MAX_STEPS) throw new PlanError('INVALID_PLAN', `a plan has 1..${MAX_STEPS} steps`);
  const seen = new Set();
  return steps.map((s) => {
    if (!s || typeof s !== 'object' || Array.isArray(s) || Object.keys(s).some((k) => !['server', 'name', 'maxCalls'].includes(k))) throw new PlanError('INVALID_PLAN', 'a step is exactly { server, name, maxCalls }');
    if (typeof s.server !== 'string' || !SERVER_RE.test(s.server) || typeof s.name !== 'string' || !TOOL_RE.test(s.name)) throw new PlanError('INVALID_PLAN', 'step server / name');
    if (!Number.isInteger(s.maxCalls) || s.maxCalls < 1 || s.maxCalls > MAX_CALLS) throw new PlanError('INVALID_PLAN', `step maxCalls is 1..${MAX_CALLS}`);
    const k = `${s.server}\u0000${s.name}`;
    if (seen.has(k)) throw new PlanError('INVALID_PLAN', 'a tool appears once in a plan');
    seen.add(k);
    return { server: s.server, name: s.name, maxCalls: s.maxCalls };
  });
}

function planHashOf(steps) { return crypto.createHash('sha256').update(PLAN_DOMAIN, 'utf8').update(canonicalJcsP1(steps.map((s) => ({ ...s })).sort((a, b) => (a.server + a.name < b.server + b.name ? -1 : 1))), 'utf8').digest('hex'); }

async function createPlan(tenantId, { sessionId, agentId, steps, ttlSeconds }, actor) {
  if (typeof tenantId !== 'string' || !TENANT_RE.test(tenantId)) throw new PlanError('INVALID_TENANT', 'tenantId');
  if (typeof sessionId !== 'string' || !UUID_V4.test(sessionId)) throw new PlanError('INVALID_SESSION', 'sessionId');
  if (typeof agentId !== 'string' || !UUID_V4.test(agentId)) throw new PlanError('INVALID_AGENT', 'agentId');
  const st = _steps(steps);
  const ttl = ttlSeconds === undefined ? DEFAULT_PLAN_SECONDS : ttlSeconds;
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > MAX_PLAN_SECONDS) throw new PlanError('INVALID_PLAN', `ttlSeconds is 1..${MAX_PLAN_SECONDS}`);
  const planId = crypto.randomUUID();
  const planHash = planHashOf(st);
  const createdBy = String(actor || 'unknown').slice(0, 256);
  const expiresAt = new Date(Date.now() + ttl * 1000);
  const used = st.map(() => 0);
  let row;
  if (!usePg()) {
    // at most one active plan per session: a new plan closes the previous one
    for (const r of _mem.values()) if (r.tenant_id === tenantId && r.session_id === sessionId && r.status === 'active') { r.status = 'closed'; r.closed_at = new Date(); }
    row = { tenant_id: tenantId, plan_id: planId, session_id: sessionId, agent_id: agentId, steps: st, used, plan_hash: planHash, status: 'active', created_by: createdBy, created_at: new Date(), expires_at: expiresAt, closed_at: null };
    _mem.set(`${tenantId}|${planId}`, row);
  } else {
    row = await _retry(() => pgPool.withTenantTransaction(tenantId, async (tx) => {
      await tx.query("UPDATE action_plans SET status='closed', closed_at=now() WHERE tenant_id=$1 AND session_id=$2 AND status='active'", [tenantId, sessionId]);
      return (await tx.query(`INSERT INTO action_plans (tenant_id, plan_id, session_id, agent_id, steps, used, plan_hash, created_by, expires_at)
        VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9) RETURNING *`, [tenantId, planId, sessionId, agentId, JSON.stringify(st), JSON.stringify(used), planHash, createdBy, expiresAt])).rows[0];
    }));
  }
  emit('INFO', 'ACTION_PLAN_AUTHORIZED', { tenantId, planId, sessionId, agentId, planHash, steps: st.length, actor: createdBy });
  return out(row);
}

async function getPlan(tenantId, planId) {
  if (typeof planId !== 'string' || !UUID_V4.test(planId)) return null;
  if (!usePg()) return out(_mem.get(`${tenantId}|${planId}`) || null);
  return out(await pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT * FROM action_plans WHERE tenant_id=$1 AND plan_id=$2', [tenantId, planId])).rows[0]));
}

async function activePlan(tenantId, sessionId) {
  if (typeof sessionId !== 'string' || !UUID_V4.test(sessionId)) return null;
  if (!usePg()) {
    const rows = [..._mem.values()].filter((r) => r.tenant_id === tenantId && r.session_id === sessionId && r.status === 'active' && r.expires_at > new Date());
    return out(rows.sort((a, b) => b.created_at - a.created_at)[0] || null);
  }
  return out(await pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query(
    "SELECT * FROM action_plans WHERE tenant_id=$1 AND session_id=$2 AND status='active' AND expires_at > now() ORDER BY created_at DESC LIMIT 1", [tenantId, sessionId])).rows[0]));
}

/** Consume one call of the step (server, name) of the plan, atomically within its bound. */
async function consumeStep(tenantId, planId, { sessionId, agentId, server, name }) {
  const plan = await getPlan(tenantId, planId);
  if (!plan || plan.sessionId !== sessionId || plan.agentId !== agentId) return { ok: false, reason: 'ACTION_PLAN_UNKNOWN' };       // another session's plan is indistinguishable from none
  if (plan.status !== 'active' || new Date(plan.expiresAt) <= new Date()) return { ok: false, reason: 'ACTION_PLAN_EXPIRED' };
  const idx = plan.steps.findIndex((s) => s.server === server && s.name === name);
  if (idx < 0) return { ok: false, reason: 'ACTION_NOT_IN_PLAN' };
  const max = plan.steps[idx].maxCalls;
  if (!usePg()) {
    const r = _mem.get(`${tenantId}|${planId}`);
    if (r.used[idx] >= max) return { ok: false, reason: 'ACTION_PLAN_STEP_EXHAUSTED' };
    r.used[idx] += 1;
    return { ok: true, stepIndex: idx, used: r.used[idx], maxCalls: max, planHash: plan.planHash };
  }
  const row = await _retry(() => pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query(
    `UPDATE action_plans SET used = jsonb_set(used, ARRAY[$3::text], to_jsonb((used->>$3::int)::int + 1))
      WHERE tenant_id=$1 AND plan_id=$2 AND status='active' AND expires_at > now() AND (used->>$3::int)::int < $4 RETURNING used`, [tenantId, planId, idx, max])).rows[0]));
  if (!row) return { ok: false, reason: 'ACTION_PLAN_STEP_EXHAUSTED' };
  return { ok: true, stepIndex: idx, used: Number(row.used[idx]), maxCalls: max, planHash: plan.planHash };
}

/** The same checks as consumeStep, without charging the step (a request that may never be authorised must not use up the plan). */
async function peekStep(tenantId, planId, { sessionId, agentId, server, name }) {
  const plan = await getPlan(tenantId, planId);
  if (!plan || plan.sessionId !== sessionId || plan.agentId !== agentId) return { ok: false, reason: 'ACTION_PLAN_UNKNOWN' };
  if (plan.status !== 'active' || new Date(plan.expiresAt) <= new Date()) return { ok: false, reason: 'ACTION_PLAN_EXPIRED' };
  const idx = plan.steps.findIndex((s) => s.server === server && s.name === name);
  if (idx < 0) return { ok: false, reason: 'ACTION_NOT_IN_PLAN' };
  if (plan.used[idx] >= plan.steps[idx].maxCalls) return { ok: false, reason: 'ACTION_PLAN_STEP_EXHAUSTED' };
  return { ok: true, stepIndex: idx, planHash: plan.planHash };
}

async function closePlan(tenantId, planId, actor) {
  const plan = await getPlan(tenantId, planId);
  if (!plan) throw new PlanError('NOT_FOUND', 'no such plan', 404);
  if (plan.status === 'closed') return plan;
  if (!usePg()) { const r = _mem.get(`${tenantId}|${planId}`); r.status = 'closed'; r.closed_at = new Date(); } else {
    await pgPool.withTenantTransaction(tenantId, async (tx) => tx.query("UPDATE action_plans SET status='closed', closed_at=now() WHERE tenant_id=$1 AND plan_id=$2 AND status='active'", [tenantId, planId]));
  }
  emit('INFO', 'ACTION_PLAN_CLOSED', { tenantId, planId, actor: String(actor || 'unknown') });
  return getPlan(tenantId, planId);
}

// concurrent updates of one plan row under the pool's transaction isolation raise a serialization failure (40001): retry, never fail the caller for it
async function _retry(fn) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) { if (!(e && e.code === '40001') || i >= 12) throw e; await new Promise((r) => setTimeout(r, 2 + Math.floor(Math.random() * 10 * (i + 1)))); }
  }
}

function _resetForTests() { _mem.clear(); }

module.exports = { PLAN_DOMAIN, MAX_STEPS, PlanError, planHashOf, createPlan, getPlan, activePlan, consumeStep, peekStep, closePlan, _resetForTests };
