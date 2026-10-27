'use strict';

/**
 * Approval requests: human approval bound to ONE action.
 *
 *   request(tenant, action, opts)          open a request for an action whose tool requires approval (the action's position in the session chain is already reserved)
 *   get / list                             expiry is applied on read
 *   decide(tenant, id, decision, approver) APPROVE | DENY by an operator: never the requester, never the agent's owner, after MFA step-up (the route is mounted behind it);
 *                                          the gateway signs the statement (approvalToken.js)
 *   cancel(tenant, id, by)                 the requester withdraws it - from PENDING, and from APPROVED up to the moment the action runs
 *   issue(tenant, id, expected)            ONE use: the approval is spent when the action artifact that carries it is issued
 *   verifyForExecution(tenant, ref, ...)   the executor's check: the approval is still APPROVED, was spent by THIS artifact, names THIS action, and its signature holds
 *   expireDue(tenant)                      PENDING past its deadline, APPROVED never spent past its window
 *
 * STATES  PENDING -> APPROVED | DENIED | EXPIRED | CANCELLED.  APPROVED -> CANCELLED | EXPIRED (never spent). Nothing leaves DENIED / EXPIRED / CANCELLED.
 * The position the action holds in its session chain stays reserved while the request is open (and the session authorises nothing else meanwhile: hasOpen); when the request
 * ends WITHOUT the action being authorised (denied, expired, cancelled) the position is given back, so the chain of artifacts stays contiguous (see _release).
 * Every transition is announced: a structured event, a webhook (approval.*), a notification through the configured alert channels (for new requests) and - under audit
 * schema v8 - the chain entries APPROVAL_REQUESTED / APPROVAL_DECIDED / APPROVAL_EXPIRED (AUDIT-V8-FREEZE section 3).
 */

const crypto = require('crypto');
const pgPool = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');
const tok = require('./approvalToken');

const TENANT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const STATUSES = Object.freeze(['PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED']);
const POLICY_RULE = 'tool:requiresApproval';

function _int(name, dflt, max) { const v = parseInt(process.env[name], 10); return Number.isFinite(v) && v > 0 ? Math.min(v, max) : dflt; }
const pendingSeconds = () => _int('QODIQA_APPROVAL_TTL_SECONDS', 600, 3600);                  // how long a request may wait for a decision
const validSeconds = () => _int('QODIQA_APPROVAL_VALID_SECONDS', 600, 3600);                  // how long a granted approval can be spent (default and cap)

class ApprovalError extends Error { constructor(code, message, status = 400) { super(message || code); this.name = 'ApprovalError'; this.code = code; this.status = status; } }

const usePg = () => pgPool.isEnabled();
const _mem = new Map();
const iso = (d) => (d ? new Date(d).toISOString() : null);

// the arguments of a request may hold sensitive data (a file path, a recipient, a query) and are not part of any hash chain (the action hash binds them, it does not store them),
// so they are sealed in the row. The AAD binds the ciphertext to its tenant and approval id.
const fieldEnc = require('../../infra/crypto/fieldEncryption');
const argsCtx = (tenantId, approvalId) => ({ purpose: 'approval_requests.args', aad: `${tenantId}|${approvalId}` });
/** The arguments of a row, or null + the reason when they cannot be opened (the key was rotated, or the value was moved / altered): one unreadable row must not break a listing. */
function openArgs(r) {
  try { return { args: fieldEnc.openObject(r.args, argsCtx(r.tenant_id, r.approval_id)) }; } catch (e) {
    if (e && typeof e.code === 'string' && e.code.startsWith('FIELD_')) { emit('WARN', 'APPROVAL_ARGS_UNREADABLE', { tenantId: r.tenant_id, approvalId: r.approval_id, code: e.code }); return { args: null, argsUnreadable: e.code }; }
    throw e;
  }
}

const out = (r) => (r ? {
  tenantId: r.tenant_id, approvalId: r.approval_id, status: r.status, sessionId: r.session_id, agentId: r.agent_id, seq: Number(r.seq), actionHash: String(r.action_hash).trim(),
  prevActionHash: r.prev_action_hash ? String(r.prev_action_hash).trim() : null, tool: { server: r.server_id, name: r.tool_name, schemaHash: String(r.schema_hash).trim() }, actionClass: r.action_class,
  ...openArgs(r), parentRequestHash: r.parent_request_hash ? String(r.parent_request_hash).trim() : null, planId: r.plan_id || null, delegationId: r.delegation_id || null,
  requesterId: r.requester_id, requesterUserId: r.requester_user_id || null, policyRuleId: r.policy_rule_id, requestedAt: iso(r.requested_at), expiresAt: iso(r.expires_at),
  approverId: r.approver_id || null, decidedAt: iso(r.decided_at), decisionReason: r.decision_reason || null, notBefore: iso(r.not_before), approvalExpiresAt: iso(r.approval_expires_at),
  decisionToken: r.decision_token || null, mfa: r.mfa || null, usedAt: iso(r.used_at), usedRequestId: r.used_request_id || null, cancelledBy: r.cancelled_by || null, cancelledAt: iso(r.cancelled_at), expiredAt: iso(r.expired_at),
} : null);

function _tenant(t) { if (typeof t !== 'string' || !TENANT_RE.test(t)) throw new ApprovalError('INVALID_TENANT', 'tenantId'); }
function _id(id) { if (typeof id !== 'string' || !UUID_V4.test(id)) throw new ApprovalError('INVALID_APPROVAL_ID', 'approvalId must be a UUID v4', 404); return id; }
async function _retry(fn) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) { if (!(e && e.code === '40001') || i >= 12) throw e; await new Promise((r) => setTimeout(r, 2 + Math.floor(Math.random() * 10 * (i + 1)))); }
  }
}
const _pg = (tenantId, fn) => _retry(() => pgPool.withTenantTransaction(tenantId, fn));

async function _row(tenantId, approvalId) {
  if (!usePg()) return _mem.get(`${tenantId}|${approvalId}`) || null;
  return _pg(tenantId, async (tx) => (await tx.query('SELECT * FROM approval_requests WHERE tenant_id=$1 AND approval_id=$2', [tenantId, approvalId])).rows[0] || null);
}

// ── announcements ────────────────────────────────────────────────────────────────────────────────────────
async function _audit(type, a, extra = {}) {
  const eb = require('../audit/entryBuilder');
  if (eb.currentSchemaVersion() < 8) return { recorded: false, reason: 'AUDIT_SCHEMA_V8_DISABLED' };
  const base = { artifactId: `${a.approvalId}:${type.toLowerCase()}`, entryType: type, tenantId: a.tenantId, approvalRef: a.approvalId, actionHash: a.actionHash };
  const spec = {
    APPROVAL_REQUESTED: { ...base, decision: 'BLOCK', reason: 'APPROVAL_REQUIRED', executionContext: { approval: { requesterId: a.requesterId, policyRuleId: a.policyRuleId } } },
    APPROVAL_DECIDED: { ...base, decision: extra.approved ? 'ALLOW' : 'BLOCK', reason: extra.approved ? 'APPROVED' : 'DENIED',
      executionContext: { approval: { requesterId: a.requesterId, approverId: a.approverId, decision: extra.approved ? 'APPROVED' : 'DENIED', notBefore: a.notBefore, expiresAt: a.approvalExpiresAt, mfa: a.mfa } } },
    APPROVAL_EXPIRED: { ...base, decision: 'BLOCK', reason: 'APPROVAL_EXPIRED', executionContext: { approval: { requesterId: a.requesterId } } },
  }[type];
  try {
    const entry = await require('../audit/audit-log').appendMandatory(spec, { stage: 'APPROVAL', maxRetries: 3, retryDelayMs: 100 });
    return { recorded: true, entryHash: entry ? entry.hash : null };
  } catch (err) {
    emit('CRITICAL', 'APPROVAL_AUDIT_FAILED', { type, approvalId: a.approvalId, error: err.message, code: err.code ?? null });
    return { recorded: false, reason: 'AUDIT_APPEND_FAILED' };
  }
}

function _webhook(eventType, a) {
  try {
    const dispatcher = require('../webhooks/webhookDispatcher');
    dispatcher.dispatchEvent(eventType, dispatcher.buildApprovalPayload(eventType, a));
  } catch (err) { emit('WARN', 'WEBHOOK_DISPATCH_FAILED', { eventType, approvalId: a.approvalId, error: err.message }); }
}

async function _notify(a) {
  if (process.env.QODIQA_APPROVAL_NOTIFY === 'false') return;
  try {
    const svc = require('../../alerting/notification/NotificationService');
    await svc.notify({ id: `approval-${a.approvalId}`, type: 'GOVERNANCE', subtype: 'APPROVAL_REQUESTED', severity: 'HIGH', riskScore: 50, tenantId: a.tenantId, requestId: a.approvalId,
      title: `Approval needed: ${a.tool.server}/${a.tool.name}`,
      description: `An agent action is waiting for a human decision. Action ${a.actionHash.slice(0, 16)}..., class ${a.actionClass}, requested by ${a.requesterId}; it expires at ${a.expiresAt}. Review it in the operator console (Approvals) or with GET /v1/approvals/${a.approvalId}.`,
      detectedAt: a.requestedAt, status: 'OPEN' });
  } catch (err) { emit('WARN', 'APPROVAL_NOTIFY_FAILED', { approvalId: a.approvalId, error: err && err.message }); }
}

/**
 * The action never ran and never will. While a request is open the session authorises nothing else (hasOpen), so its reserved place is still the LAST one and is simply
 * GIVEN BACK: the session's chain of artifacts stays contiguous, which is what the audit verifiers require of ACTION_INTENT sequence numbers. If the chain moved on
 * anyway (a concurrent authorisation slipped in between the check and the reservation) the place is closed in the execution ledger as a failed action, so the session
 * still continues in order - and the gap is reported (APPROVAL_POSITION_NOT_RELEASABLE): a later ACTION_INTENT will then skip that number.
 */
async function _release(a) {
  if (a.usedAt) return 'spent';                                       // the artifact exists: its place is its own (the session waits for it, see TOOL_GATEWAY.md)
  try {
    if (await require('../agents/agentStore').releaseReservation(a.tenantId, a.sessionId, { seq: a.seq, prevActionHash: a.prevActionHash, actionHash: a.actionHash })) return 'released';
  } catch (err) { emit('ERROR', 'APPROVAL_RELEASE_FAILED', { approvalId: a.approvalId, error: err.message }); }
  emit('WARN', 'APPROVAL_POSITION_NOT_RELEASABLE', { tenantId: a.tenantId, approvalId: a.approvalId, sessionId: a.sessionId, seq: a.seq, message: 'The chain of the session moved on after this position was reserved; it is closed as a failed action and the sequence will skip it.' });
  return _closeLedger(a);
}

// Dependency inversion (rule no-circular): the executor registers the function that writes the internal ledger record instead of this module requiring it.
let _ledgerRecorder = null;
function setLedgerRecorder(fn) { _ledgerRecorder = fn; }

async function _closeLedger(a) {
  try {
    if (!_ledgerRecorder) throw new Error('no ledger recorder registered (the action executor registers one when it is loaded)');
    const rec = await _ledgerRecorder({ tenantId: a.tenantId, sessionId: a.sessionId, seq: a.seq, requestId: a.approvalId, agentId: a.agentId, actionHash: a.actionHash, server: a.tool.server, tool: a.tool.name });
    if (rec.ok) await rec.finish(false);
    return rec.ok ? 'closed' : rec.reason;
  } catch (err) { emit('ERROR', 'APPROVAL_LEDGER_CLOSE_FAILED', { approvalId: a.approvalId, error: err.message }); return 'error'; }
}

// ── request ──────────────────────────────────────────────────────────────────────────────────────────────
async function request(tenantId, c, { now = Date.now() } = {}) {
  _tenant(tenantId);
  const approvalId = crypto.randomUUID();
  const expires = new Date(now + pendingSeconds() * 1000);
  const row = { tenant_id: tenantId, approval_id: approvalId, session_id: c.sessionId, agent_id: c.agentId, seq: c.seq, action_hash: c.actionHash, prev_action_hash: c.prevActionHash || null, server_id: c.server, tool_name: c.tool,
    schema_hash: c.schemaHash, action_class: c.actionClass, args: fieldEnc.sealObject(c.args, argsCtx(tenantId, approvalId), { emit }), parent_request_hash: c.parentRequestHash || null, plan_id: c.planId || null, delegation_id: c.delegationId || null, requester_id: String(c.requesterId).slice(0, 256),
    requester_user_id: c.requesterUserId ? String(c.requesterUserId).slice(0, 256) : null, policy_rule_id: c.policyRuleId || POLICY_RULE, status: 'PENDING', requested_at: new Date(now), expires_at: expires,
    approver_id: null, decided_at: null, decision_reason: null, not_before: null, approval_expires_at: null, decision_token: null, mfa: null, used_at: null, used_request_id: null, cancelled_by: null, cancelled_at: null, expired_at: null };
  if (!usePg()) {
    if ([..._mem.values()].some((r) => r.tenant_id === tenantId && r.session_id === c.sessionId && r.seq === c.seq && (r.status === 'PENDING' || r.status === 'APPROVED'))) throw new ApprovalError('APPROVAL_EXISTS', 'this position already has a live approval request', 409);
    _mem.set(`${tenantId}|${approvalId}`, row);
  } else {
    try {
      await _pg(tenantId, async (tx) => tx.query(`INSERT INTO approval_requests (tenant_id, approval_id, session_id, agent_id, seq, action_hash, prev_action_hash, server_id, tool_name, schema_hash, action_class, args, parent_request_hash,
        plan_id, delegation_id, requester_id, requester_user_id, policy_rule_id, requested_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18,$19,$20)`,
      [tenantId, approvalId, c.sessionId, c.agentId, c.seq, c.actionHash, row.prev_action_hash, c.server, c.tool, c.schemaHash, c.actionClass, JSON.stringify(row.args), row.parent_request_hash, row.plan_id, row.delegation_id,
        row.requester_id, row.requester_user_id, row.policy_rule_id, row.requested_at, expires]));
    } catch (e) { if (e && e.code === '23505') throw new ApprovalError('APPROVAL_EXISTS', 'this position already has a live approval request', 409); throw e; }
  }
  const a = out(await _row(tenantId, approvalId));
  emit('WARN', 'APPROVAL_REQUESTED', { tenantId, approvalId, actionHash: a.actionHash, tool: `${a.tool.server}/${a.tool.name}`, agentId: a.agentId, sessionId: a.sessionId, seq: a.seq, requesterId: a.requesterId, expiresAt: a.expiresAt });
  await _audit('APPROVAL_REQUESTED', a);
  _webhook('approval.requested', a);
  await _notify(a);
  return a;
}

// ── expiry ───────────────────────────────────────────────────────────────────────────────────────────────
async function expireDue(tenantId, { now = Date.now() } = {}) {
  _tenant(tenantId);
  let rows;
  if (!usePg()) {
    rows = [];
    for (const r of _mem.values()) {
      if (r.tenant_id !== tenantId) continue;
      if ((r.status === 'PENDING' && r.expires_at.getTime() <= now) || (r.status === 'APPROVED' && !r.used_at && r.approval_expires_at.getTime() <= now)) { r.status = 'EXPIRED'; r.expired_at = new Date(now); rows.push(r); }
    }
  } else {
    rows = await _pg(tenantId, async (tx) => (await tx.query(`UPDATE approval_requests SET status='EXPIRED', expired_at=$2 WHERE tenant_id=$1 AND ((status='PENDING' AND expires_at <= $2)
      OR (status='APPROVED' AND used_at IS NULL AND approval_expires_at <= $2)) RETURNING *`, [tenantId, new Date(now)])).rows);
  }
  for (const r of rows) {
    const a = out(r);
    emit('WARN', 'APPROVAL_EXPIRED', { tenantId, approvalId: a.approvalId, actionHash: a.actionHash, tool: `${a.tool.server}/${a.tool.name}` });
    await _audit('APPROVAL_EXPIRED', a);
    _webhook('approval.expired', a);
    await _release(a);
  }
  return rows.length;
}

/** Is there an approval request of this session that is still open (waiting, or granted and not yet spent)? While there is, the session authorises nothing else. */
async function hasOpen(tenantId, sessionId, { now = Date.now() } = {}) {
  _tenant(tenantId);
  await expireDue(tenantId, { now });
  if (!usePg()) return [..._mem.values()].some((r) => r.tenant_id === tenantId && r.session_id === sessionId && (r.status === 'PENDING' || (r.status === 'APPROVED' && !r.used_at)));
  return _pg(tenantId, async (tx) => (await tx.query("SELECT 1 FROM approval_requests WHERE tenant_id=$1 AND session_id=$2 AND (status='PENDING' OR (status='APPROVED' AND used_at IS NULL)) LIMIT 1", [tenantId, sessionId])).rows.length > 0);
}

async function get(tenantId, approvalId, { now } = {}) {
  _tenant(tenantId); _id(approvalId);
  await expireDue(tenantId, { now });
  return out(await _row(tenantId, approvalId));
}

async function list(tenantId, { status, agentId, limit = 200 } = {}) {
  _tenant(tenantId);
  if (status !== undefined && !STATUSES.includes(status)) throw new ApprovalError('INVALID_STATUS', `status is one of ${STATUSES.join(', ')}`);
  await expireDue(tenantId);
  const lim = Math.min(Math.max(1, Number(limit) || 200), 500);
  if (!usePg()) return [..._mem.values()].filter((r) => r.tenant_id === tenantId && (!status || r.status === status) && (!agentId || r.agent_id === agentId)).sort((a, b) => a.requested_at - b.requested_at).slice(0, lim).map(out);
  return _pg(tenantId, async (tx) => (await tx.query('SELECT * FROM approval_requests WHERE tenant_id=$1 AND ($2::text IS NULL OR status=$2) AND ($3::text IS NULL OR agent_id=$3) ORDER BY requested_at, id LIMIT $4', [tenantId, status || null, agentId || null, lim])).rows.map(out));
}

// ── decide ───────────────────────────────────────────────────────────────────────────────────────────────
function _independence(a, approver) {
  // compared case-insensitively: the RBAC store treats usernames so (src/core/rbac/store.js), and 'Alice' must not approve what 'alice' asked
  const ids = new Set([approver.id, approver.username].filter(Boolean).map((x) => String(x).toLowerCase()));
  if (!ids.size) throw new ApprovalError('APPROVER_REQUIRED', 'an authenticated approver is required', 401);
  if (ids.has(String(a.requesterId).toLowerCase()) || (a.requesterUserId && ids.has(String(a.requesterUserId).toLowerCase()))) throw new ApprovalError('APPROVAL_NOT_INDEPENDENT', 'the approver is the requester, or the user the agent acts for', 403);
  if (a.requesterUserId) {
    // the same lineage rule as every other maker-checker stage: not provisioned by the author (src/core/policy/governance/independence.js)
    try { require('../policy/governance/independence').assertIndependentOfAuthor({ author_id: a.requesterUserId, author_username: a.requesterUserId }, { id: approver.id }, 'APPROVAL'); } catch (e) {
      throw new ApprovalError('APPROVAL_NOT_INDEPENDENT', e && e.message ? String(e.message).slice(0, 200) : 'the approver is not independent of the requester', 403);
    }
  }
}

/**
 * @param {{ decision: 'APPROVE'|'DENY', reason?: string, ttlSeconds?: number, notBefore?: string|number }} d
 * @param {{ id: string, username?: string }} approver
 */
async function decide(tenantId, approvalId, d, approver, { now = Date.now() } = {}) {
  _tenant(tenantId); _id(approvalId);
  if (!d || (d.decision !== 'APPROVE' && d.decision !== 'DENY')) throw new ApprovalError('INVALID_DECISION', 'decision is APPROVE or DENY');
  if (d.reason !== undefined && !(typeof d.reason === 'string' && d.reason.length <= 500)) throw new ApprovalError('INVALID_REASON', 'reason is at most 500 characters');
  if (d.decision === 'DENY' && !(typeof d.reason === 'string' && d.reason.trim())) throw new ApprovalError('REASON_REQUIRED', 'a reason is required to deny');
  await expireDue(tenantId, { now });
  const cur = out(await _row(tenantId, approvalId));
  if (!cur) throw new ApprovalError('NOT_FOUND', 'no such approval request', 404);
  _independence(cur, approver);
  if (cur.argsUnreadable) throw new ApprovalError('APPROVAL_ARGS_UNREADABLE', 'the arguments of this request cannot be read, so it cannot be approved: the approver must see exactly what is approved', 409);
  if (cur.status === 'EXPIRED') throw new ApprovalError('APPROVAL_EXPIRED', 'the request has expired', 409);
  if (cur.status !== 'PENDING') throw new ApprovalError('APPROVAL_NOT_PENDING', `the request is ${cur.status}`, 409);
  const approved = d.decision === 'APPROVE';
  const ttl = d.ttlSeconds === undefined ? validSeconds() : d.ttlSeconds;
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > _int('QODIQA_APPROVAL_VALID_MAX_SECONDS', 3600, 86_400)) throw new ApprovalError('INVALID_TTL', 'ttlSeconds is 1..3600');
  let notBefore = now;
  if (d.notBefore !== undefined) {
    notBefore = typeof d.notBefore === 'number' ? d.notBefore : Date.parse(d.notBefore);
    if (!Number.isSafeInteger(notBefore) || notBefore < now - 1000 || notBefore > Date.parse(cur.expiresAt)) throw new ApprovalError('INVALID_NOT_BEFORE', 'notBefore is between now and the end of the request window');
    notBefore = Math.max(notBefore, now);
  }
  const expiresAt = notBefore + ttl * 1000;
  const keyManager = require('../../../services/artifact/keyManager');
  const key = keyManager.getSigningKey(tenantId);
  const payload = { v: 1, kind: 'approval', approvalId, tenantId, actionHash: cur.actionHash, agentId: cur.agentId, sessionId: cur.sessionId, seq: cur.seq, requesterId: cur.requesterId, approverId: String(approver.id),
    decision: approved ? 'APPROVED' : 'DENIED', notBefore, expiresAt, mfa: 'step-up', policyRuleId: cur.policyRuleId };
  const fields = { payload, timestamp: now, expiry: expiresAt, publicKeyId: key.keyId };
  const token = key.nativeSigning ? await tok.signApprovalNative(fields, keyManager.nativeSign) : tok.signApproval(fields, key.privDer);
  const status = approved ? 'APPROVED' : 'DENIED';
  let updated;
  if (!usePg()) {
    const r = _mem.get(`${tenantId}|${approvalId}`);
    if (r.status !== 'PENDING') throw new ApprovalError('APPROVAL_NOT_PENDING', `the request is ${r.status}`, 409);
    Object.assign(r, { status, approver_id: String(approver.id), decided_at: new Date(now), decision_reason: d.reason ? d.reason.trim() : null, not_before: approved ? new Date(notBefore) : null, approval_expires_at: approved ? new Date(expiresAt) : null, decision_token: token, mfa: 'step-up' });
    updated = r;
  } else {
    updated = await _pg(tenantId, async (tx) => (await tx.query(`UPDATE approval_requests SET status=$3, approver_id=$4, decided_at=$5, decision_reason=$6, not_before=$7, approval_expires_at=$8, decision_token=$9::jsonb, mfa='step-up'
      WHERE tenant_id=$1 AND approval_id=$2 AND status='PENDING' AND expires_at > $5 RETURNING *`, [tenantId, approvalId, status, String(approver.id), new Date(now), d.reason ? d.reason.trim() : null,
      approved ? new Date(notBefore) : null, approved ? new Date(expiresAt) : null, JSON.stringify(token)])).rows[0]);
    if (!updated) throw new ApprovalError('APPROVAL_NOT_PENDING', 'the request is no longer pending', 409);
  }
  const a = out(updated);
  emit(approved ? 'WARN' : 'INFO', 'APPROVAL_DECIDED', { tenantId, approvalId, decision: status, approverId: a.approverId, requesterId: a.requesterId, actionHash: a.actionHash, tool: `${a.tool.server}/${a.tool.name}` });
  await _audit('APPROVAL_DECIDED', a, { approved });
  _webhook('approval.decided', a);
  if (!approved) await _release(a);
  return a;
}

// ── cancel ───────────────────────────────────────────────────────────────────────────────────────────────
async function cancel(tenantId, approvalId, { by, reason } = {}, { now = Date.now() } = {}) {
  _tenant(tenantId); _id(approvalId);
  await expireDue(tenantId, { now });
  const cur = await _row(tenantId, approvalId);
  if (!cur) throw new ApprovalError('NOT_FOUND', 'no such approval request', 404);
  if (cur.status !== 'PENDING' && cur.status !== 'APPROVED') throw new ApprovalError('APPROVAL_NOT_CANCELLABLE', `the request is ${cur.status}`, 409);
  let updated;
  if (!usePg()) {
    cur.status = 'CANCELLED'; cur.cancelled_by = String(by || 'unknown').slice(0, 256); cur.cancelled_at = new Date(now); updated = cur;
  } else {
    updated = await _pg(tenantId, async (tx) => (await tx.query("UPDATE approval_requests SET status='CANCELLED', cancelled_by=$3, cancelled_at=$4 WHERE tenant_id=$1 AND approval_id=$2 AND status IN ('PENDING','APPROVED') RETURNING *",
      [tenantId, approvalId, String(by || 'unknown').slice(0, 256), new Date(now)])).rows[0]);
    if (!updated) throw new ApprovalError('APPROVAL_NOT_CANCELLABLE', 'the request can no longer be cancelled', 409);
  }
  const a = out(updated);
  emit('WARN', 'APPROVAL_CANCELLED', { tenantId, approvalId, by: a.cancelledBy, reason: reason ? String(reason).slice(0, 200) : null, wasApproved: Boolean(a.approverId) });
  _webhook('approval.cancelled', a);
  await _release(a);
  return a;
}

// ── use ──────────────────────────────────────────────────────────────────────────────────────────────────
/** Spend the approval for the artifact `requestId`. @returns {{ ok: true, approval } | { ok: false, reason: string, status?: string }} */
async function issue(tenantId, approvalId, expected, { now = Date.now(), requestId, resolveKey } = {}) {
  _tenant(tenantId);
  if (typeof approvalId !== 'string' || !UUID_V4.test(approvalId)) return { ok: false, reason: 'APPROVAL_INVALID' };
  await expireDue(tenantId, { now });
  const cur = out(await _row(tenantId, approvalId));
  if (!cur) return { ok: false, reason: 'APPROVAL_INVALID' };
  if (cur.agentId !== expected.agentId || cur.sessionId !== expected.sessionId || cur.actionHash !== expected.actionHash) return { ok: false, reason: 'APPROVAL_INVALID', detail: 'not this action' };
  if (cur.status === 'PENDING') return { ok: false, reason: 'APPROVAL_PENDING', status: 'PENDING', approval: cur };
  if (cur.status === 'DENIED') return { ok: false, reason: 'APPROVAL_DENIED', status: 'DENIED' };
  if (cur.status === 'EXPIRED') return { ok: false, reason: 'APPROVAL_EXPIRED', status: 'EXPIRED' };
  if (cur.status === 'CANCELLED') return { ok: false, reason: 'APPROVAL_CANCELLED', status: 'CANCELLED' };
  if (cur.usedAt) return { ok: false, reason: 'APPROVAL_ALREADY_USED', status: 'APPROVED' };
  // the signed statement must hold for exactly this action, now
  const v = tok.verifyApproval(cur.decisionToken, { now, resolveKey: _rk(resolveKey), keyCheck: _keyCheckFor(_rk(resolveKey)), expect: { actionHash: expected.actionHash, tenantId, agentId: expected.agentId, sessionId: expected.sessionId, seq: cur.seq, approvalId } });
  if (!v.ok) return { ok: false, reason: v.reason, detail: v.detail };
  let updated;
  if (!usePg()) {
    const r = _mem.get(`${tenantId}|${approvalId}`);
    if (r.used_at) return { ok: false, reason: 'APPROVAL_ALREADY_USED' };
    r.used_at = new Date(now); r.used_request_id = requestId; updated = r;
  } else {
    updated = await _pg(tenantId, async (tx) => (await tx.query(`UPDATE approval_requests SET used_at=$3, used_request_id=$4 WHERE tenant_id=$1 AND approval_id=$2 AND status='APPROVED' AND used_at IS NULL
      AND not_before <= $3 AND approval_expires_at > $3 RETURNING *`, [tenantId, approvalId, new Date(now), requestId])).rows[0]);
    if (!updated) return { ok: false, reason: 'APPROVAL_ALREADY_USED' };
  }
  emit('INFO', 'APPROVAL_USED', { tenantId, approvalId, requestId, actionHash: cur.actionHash });
  return { ok: true, approval: out(updated) };
}

// A2-01: the signed approval statement is checked against the signing key's lifecycle like delegations and action artifacts are, so a statement
// signed by a key that has since been revoked or archived stops being usable (it used to stay valid for its whole window).
function _rk(resolveKey) { return resolveKey || require('../../validation/resolveKey').resolveKey; }
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

/** The executor's check: still approved (not cancelled / expired unspent), spent by THIS artifact, naming THIS action, signature intact. */
async function verifyForExecution(tenantId, approvalRef, { actionHash, agentId, sessionId, requestId, resolveKey } = {}) {
  _tenant(tenantId);
  if (typeof approvalRef !== 'string' || !UUID_V4.test(approvalRef)) return { ok: false, reason: 'APPROVAL_INVALID', detail: 'approvalRef' };
  const a = out(await _row(tenantId, approvalRef));
  if (!a) return { ok: false, reason: 'APPROVAL_INVALID', detail: 'unknown approval' };
  if (a.status === 'CANCELLED') return { ok: false, reason: 'APPROVAL_CANCELLED' };
  if (a.status === 'EXPIRED') return { ok: false, reason: 'APPROVAL_EXPIRED' };
  if (a.status !== 'APPROVED') return { ok: false, reason: 'APPROVAL_INVALID', detail: a.status };
  if (a.usedRequestId !== requestId) return { ok: false, reason: 'APPROVAL_INVALID', detail: 'spent by another artifact' };
  const usedAt = Date.parse(a.usedAt);
  const v = tok.verifyApproval(a.decisionToken, { now: usedAt, resolveKey: _rk(resolveKey), keyCheck: _keyCheckFor(_rk(resolveKey)), expect: { actionHash, tenantId, agentId, sessionId, seq: a.seq, approvalId: approvalRef } });
  if (!v.ok) return { ok: false, reason: v.reason, detail: v.detail };
  return { ok: true, approval: a };
}

function _resetForTests() { _mem.clear(); }

module.exports = { setLedgerRecorder, STATUSES, POLICY_RULE, ApprovalError, pendingSeconds, validSeconds, request, get, list, hasOpen, decide, cancel, issue, verifyForExecution, expireDue, _resetForTests, _peekRowForTests: (tenantId, approvalId) => _mem.get(`${tenantId}|${approvalId}`) || null };
