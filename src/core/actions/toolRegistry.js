'use strict';

/**
 * Tool registry: the allowlist of tools an agent action may name, with VERSIONED argument schemas.
 *
 *   register(tenant, spec)     an operator registers a tool. First registration = version 1, ACTIVE (the operator approves it by registering it).
 * A later registration with a different schema / class / reversibility = a NEW version in pending_review; the active
 *                              version keeps serving until an operator approves the new one.
 * observe(tenant, spec) a tool DISCOVERED: unknown -> v1 pending_review (NEW), different -> next version
 *                              pending_review (MODIFIED), identical -> UNCHANGED. Nothing discovered is callable until approved.
 *   approve / disable / updatePolicy
 *   resolveForAction(tenant, server, name, schemaHash)   the check the authoriser and the executor make: TOOL_NOT_REGISTERED / TOOL_DISABLED /
 *                              TOOL_PENDING_REVIEW / TOOL_SCHEMA_CHANGED, else the active version
 *   validateArgs(tool, args)   the registered schema decides (src/core/actions/schemaSubset.js); an argument the schema does not name is refused
 *
 * schemaHash = SHA-256("QODIQA::TOOL_SCHEMA::V1" || JCS-P1(schema)) - actionHash.computeSchemaHash. A changed schema is a different tool.
 * Storage: PostgreSQL (migration 101, RLS forced by tenant) or process memory without PostgreSQL.
 */

const pgPool = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');
const { computeSchemaHash, ActionHashError } = require('./actionHash');
const { assertSupported, validate, SchemaError } = require('./schemaSubset');
const { ACTION_CLASSES } = require('../agents/agentStore');
const { assertValidConstraints } = require('../mcp/toolPolicy');
const killRegistry = require('../agents/killRegistry');

const TENANT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SERVER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TOOL_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const POLICY_KEYS = new Set(['maxCallsPerSession', 'constraints']);

class ToolError extends Error { constructor(code, message, status = 400) { super(message); this.name = 'ToolError'; this.code = code; this.status = status; } }

const _mem = [];                                  // rows
let _memId = 0;
const usePg = () => pgPool.isEnabled();

function _ids(tenantId, server, name) {
  if (typeof tenantId !== 'string' || !TENANT_RE.test(tenantId)) throw new ToolError('INVALID_TENANT_ID', 'tenantId must be 1-64 characters of A-Z a-z 0-9 _ -');
  if (typeof server !== 'string' || !SERVER_RE.test(server)) throw new ToolError('INVALID_SERVER_ID', 'server must start with a letter or digit and use only A-Z a-z 0-9 . _ : -');
  if (typeof name !== 'string' || !TOOL_RE.test(name)) throw new ToolError('INVALID_TOOL_NAME', 'name must start with a letter or digit and use only A-Z a-z 0-9 . _ : / -');
}
function _policy(p) {
  if (p === undefined) return {};
  if (p === null || typeof p !== 'object' || Array.isArray(p)) throw new ToolError('INVALID_POLICY', 'policy must be an object');
  for (const k of Object.keys(p)) if (!POLICY_KEYS.has(k)) throw new ToolError('INVALID_POLICY', `unknown policy key ${k}`);
  if (p.maxCallsPerSession !== undefined && !(Number.isInteger(p.maxCallsPerSession) && p.maxCallsPerSession >= 1 && p.maxCallsPerSession <= 100_000)) throw new ToolError('INVALID_POLICY', 'maxCallsPerSession must be an integer 1..100000');
  const out_ = { ...p };
  if (p.constraints !== undefined) out_.constraints = assertValidConstraints(p.constraints);
  return out_;
}
function _spec(s) {
  const x = s || {};
  if (!ACTION_CLASSES.includes(x.actionClass)) throw new ToolError('INVALID_ACTION_CLASS', `actionClass must be one of ${ACTION_CLASSES.join(', ')}`);
  if (typeof x.reversible !== 'boolean') throw new ToolError('INVALID_REVERSIBLE', 'reversible must be stated (true or false)');
  let hash;
  try { assertSupported(x.schema); hash = computeSchemaHash(x.schema); } catch (e) {
    if (e instanceof SchemaError || e instanceof ActionHashError) throw new ToolError(e.code, e.message);
    throw e;
  }
  return { schema: JSON.parse(JSON.stringify(x.schema)), schemaHash: hash, actionClass: x.actionClass, reversible: x.reversible,
    requiresApproval: x.requiresApproval === undefined ? !x.reversible : x.requiresApproval === true, policy: _policy(x.policy),
    description: typeof x.description === 'string' ? x.description.slice(0, 1000) : null };
}

const out = (r) => (r ? {
  tenantId: r.tenant_id, server: r.server_id, name: r.tool_name, version: r.version, status: r.status, schema: r.schema, schemaHash: String(r.schema_hash).trim(),
  actionClass: r.action_class, reversible: r.reversible, requiresApproval: r.requires_approval, policy: r.policy || {}, description: r.description ?? null,
  createdBy: r.created_by, createdAt: new Date(r.created_at).toISOString(), approvedBy: r.approved_by ?? null, approvedAt: r.approved_at ? new Date(r.approved_at).toISOString() : null,
} : null);

async function _versions(tenantId, server, name) {
  if (!usePg()) return _mem.filter((r) => r.tenant_id === tenantId && r.server_id === server && r.tool_name === name).sort((a, b) => a.version - b.version);
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT * FROM tool_registry WHERE tenant_id=$1 AND server_id=$2 AND tool_name=$3 ORDER BY version', [tenantId, server, name])).rows);
}

async function _insert(tenantId, server, name, version, status, sp, actor) {
  const now = new Date();
  const row = { tenant_id: tenantId, server_id: server, tool_name: name, version, status, schema: sp.schema, schema_hash: sp.schemaHash, action_class: sp.actionClass, reversible: sp.reversible,
    requires_approval: sp.requiresApproval, policy: sp.policy, description: sp.description, created_by: String(actor || 'unknown').slice(0, 256), created_at: now, updated_at: now,
    approved_by: status === 'active' ? String(actor || 'unknown').slice(0, 256) : null, approved_at: status === 'active' ? now : null };
  if (!usePg()) { const r = { id: ++_memId, ...row }; _mem.push(r); return r; }
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query(`INSERT INTO tool_registry (tenant_id, server_id, tool_name, version, status, schema, schema_hash, action_class, reversible,
      requires_approval, policy, description, created_by, approved_by, approved_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,
    [tenantId, server, name, version, status, JSON.stringify(sp.schema), sp.schemaHash, sp.actionClass, sp.reversible, sp.requiresApproval, JSON.stringify(sp.policy), sp.description, row.created_by, row.approved_by, row.approved_at])).rows[0]);
}

const sameDefinition = (r, sp) => String(r.schema_hash).trim() === sp.schemaHash && r.action_class === sp.actionClass && r.reversible === sp.reversible;

/** Operator registration. @returns {Promise<{ change: 'NEW'|'MODIFIED', tool: object }>} */
async function register(tenantId, spec, actor) {
  _ids(tenantId, spec && spec.server, spec && spec.name);
  const sp = _spec(spec);
  const vs = await _versions(tenantId, spec.server, spec.name);
  const live = vs.filter((r) => r.status === 'active' || r.status === 'pending_review');
  if (live.some((r) => sameDefinition(r, sp))) throw new ToolError('TOOL_UNCHANGED', 'this exact definition (schema, class, reversibility) is already registered', 409);
  const version = (vs.length ? vs[vs.length - 1].version : 0) + 1;
  const hasActive = vs.some((r) => r.status === 'active');
  const row = await _insert(tenantId, spec.server, spec.name, version, hasActive ? 'pending_review' : 'active', sp, actor);
  emit('INFO', 'TOOL_REGISTERED', { tenantId, server: spec.server, name: spec.name, version, status: row.status, schemaHash: sp.schemaHash, actor: String(actor || 'unknown') });
  return { change: version === 1 ? 'NEW' : 'MODIFIED', tool: out(row) };
}

/** A tool discovered at a server: never callable until approved. @returns {Promise<{ change: 'NEW'|'MODIFIED'|'UNCHANGED', tool: object|null }>} */
async function observe(tenantId, spec, actor = 'discovery') {
  _ids(tenantId, spec && spec.server, spec && spec.name);
  const sp = _spec(spec);
  const vs = await _versions(tenantId, spec.server, spec.name);
  if (vs.some((r) => (r.status === 'active' || r.status === 'pending_review') && sameDefinition(r, sp))) return { change: 'UNCHANGED', tool: null };
  const version = (vs.length ? vs[vs.length - 1].version : 0) + 1;
  const row = await _insert(tenantId, spec.server, spec.name, version, 'pending_review', sp, actor);
  emit('WARN', vs.length ? 'TOOL_SCHEMA_CHANGE_DETECTED' : 'TOOL_DISCOVERED', { tenantId, server: spec.server, name: spec.name, version, schemaHash: sp.schemaHash });
  return { change: vs.length ? 'MODIFIED' : 'NEW', tool: out(row) };
}

async function _setStatus(tenantId, row, status, patch = {}) {
  const now = new Date();
  if (!usePg()) { Object.assign(row, { status, updated_at: now }, patch); return row; }
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query(`UPDATE tool_registry SET status=$3, updated_at=now(), approved_by=COALESCE($4, approved_by), approved_at=CASE WHEN $4::text IS NULL THEN approved_at ELSE now() END
    WHERE tenant_id=$1 AND id=$2 RETURNING *`, [tenantId, row.id, status, patch.approved_by || null])).rows[0]);
}

// A4-03: QODIQA_TOOL_SELF_APPROVAL=true lets one operator register and approve a changed tool version (four-eyes off). Like QODIQA_MCP_ALLOW_LOCAL it is
// a development convenience and is ignored in production, whatever the flag says.
function _selfApprovalAllowed(env = process.env) {
  if (env.QODIQA_TOOL_SELF_APPROVAL !== 'true') return false;
  return !(env.NODE_ENV === 'production' || env.QODIQA_ENVIRONMENT === 'production');
}

/** Approve a pending version: it becomes the single active one; the previous active version is superseded. */
async function approve(tenantId, server, name, version, actor) {
  _ids(tenantId, server, name);
  const vs = await _versions(tenantId, server, name);
  const target = vs.find((r) => r.version === version);
  if (!target) throw new ToolError('TOOL_VERSION_NOT_FOUND', 'no such tool version', 404);
  if (target.status === 'active') return out(target);
  if (target.status === 'superseded') throw new ToolError('TOOL_VERSION_SUPERSEDED', 'a superseded version cannot be re-activated; register it again', 409);
  const who = String(actor || 'unknown').slice(0, 256);
  if (target.created_by === who && target.status === 'pending_review' && who !== 'unknown' && !_selfApprovalAllowed() && vs.some((r) => r.status === 'active')) {
    throw new ToolError('TOOL_SELF_APPROVAL', 'a changed tool version must be approved by someone other than the operator who registered it', 409);
  }
  const previous = vs.filter((x) => x.status === 'active');
  for (const r of previous) await _setStatus(tenantId, r, 'superseded');
  const row = await _setStatus(tenantId, target, 'active', { approved_by: who, approved_at: new Date() });
  // calls running as the superseded version stop here (other replicas: their watchers, src/core/mcp/revocationWatch.js)
  const aborted = previous.length ? killRegistry.abortLabel(tenantId, `tool:${server}/${name}`, 'TOOL_VERSION_SUPERSEDED') : 0;
  emit('INFO', 'TOOL_VERSION_APPROVED', { tenantId, server, name, version, actor: who, abortedExecutions: aborted });
  return out(row);
}

async function disable(tenantId, server, name, actor) {
  _ids(tenantId, server, name);
  const vs = await _versions(tenantId, server, name);
  const active = vs.filter((r) => r.status === 'active');
  if (!active.length) throw new ToolError('TOOL_NOT_ACTIVE', 'the tool has no active version', 409);
  for (const r of active) await _setStatus(tenantId, r, 'disabled');
  // a compromised tool is stopped NOW: calls running through it are aborted on this process at once, on other replicas by their revocation watchers (<= ~1 s)
  const aborted = killRegistry.abortLabel(tenantId, `tool:${server}/${name}`, 'TOOL_REVOKED');
  emit('WARN', 'TOOL_DISABLED', { tenantId, server, name, actor: String(actor || 'unknown'), abortedExecutions: aborted });
  return { disabled: active.length, abortedExecutions: aborted };
}

async function updatePolicy(tenantId, server, name, patch, actor) {
  _ids(tenantId, server, name);
  const vs = await _versions(tenantId, server, name);
  const a = vs.find((r) => r.status === 'active');
  if (!a) throw new ToolError('TOOL_NOT_ACTIVE', 'the tool has no active version', 409);
  const policy = _policy(patch && patch.policy !== undefined ? patch.policy : a.policy);
  const requiresApproval = patch && patch.requiresApproval !== undefined ? patch.requiresApproval === true : a.requires_approval;
  if (!usePg()) { Object.assign(a, { policy, requires_approval: requiresApproval, updated_at: new Date() }); return out(a); }
  return out(await pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('UPDATE tool_registry SET policy=$3, requires_approval=$4, updated_at=now() WHERE tenant_id=$1 AND id=$2 RETURNING *', [tenantId, a.id, JSON.stringify(policy), requiresApproval])).rows[0]));
}

async function get(tenantId, server, name) {
  _ids(tenantId, server, name);
  const vs = await _versions(tenantId, server, name);
  if (!vs.length) return null;
  return { server, name, active: out(vs.find((r) => r.status === 'active') || null), versions: vs.map(out) };
}

async function list(tenantId, { status } = {}) {
  _ids(tenantId, 'x', 'x');
  if (!usePg()) return _mem.filter((r) => r.tenant_id === tenantId && (!status || r.status === status)).sort((a, b) => (a.server_id + a.tool_name + a.version).localeCompare(b.server_id + b.tool_name + b.version)).map(out);
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT * FROM tool_registry WHERE tenant_id=$1 AND ($2::text IS NULL OR status=$2) ORDER BY server_id, tool_name, version', [tenantId, status || null])).rows.map(out));
}

/**
 * The check made at authorisation AND at execution.
 * @returns {Promise<{ ok: true, tool: object } | { ok: false, reason: string }>}
 */
async function resolveForAction(tenantId, server, name, schemaHash) {
  try { _ids(tenantId, server, name); } catch { return { ok: false, reason: 'TOOL_NOT_REGISTERED' }; }
  const vs = await _versions(tenantId, server, name);
  if (!vs.length) return { ok: false, reason: 'TOOL_NOT_REGISTERED' };
  const active = vs.find((r) => r.status === 'active');
  if (!active) return { ok: false, reason: vs.some((r) => r.status === 'pending_review') ? 'TOOL_PENDING_REVIEW' : 'TOOL_DISABLED' };
  if (String(active.schema_hash).trim() !== schemaHash) return { ok: false, reason: 'TOOL_SCHEMA_CHANGED' };           // TOCTOU: the action names a schema that is no longer the active one
  return { ok: true, tool: out(active) };
}

/** @returns {{ ok: true } | { ok: false, path: string, code: string, message: string }} */
function validateArgs(tool, args) { return validate(tool.schema, args); }

function _resetForTests() { _mem.length = 0; _memId = 0; }

module.exports = { ToolError, POLICY_KEYS, register, observe, approve, disable, updatePolicy, get, list, resolveForAction, validateArgs, _resetForTests };
