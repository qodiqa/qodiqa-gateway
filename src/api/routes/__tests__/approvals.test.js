'use strict';

/**
 * human approval bound to one action, over the memory stores, with the real signing identity, key manager, executor and verifiers.
 *
 *   AP-01  the whole path: request (202) -> operator decision -> artifact with approvalRef -> execution; the approval is signed, bound to actionHash, spent once
 *   AP-02  the refusals the plan names: a wrong actionHash, expired, the same human asks and approves, replay - and denied, cancelled before and after use, tampered statement
 *   AP-03  the chain survives: a request that ends without the action leaves no hole in the session
 *   AP-04  /v1/approvals: permissions, validation, independence, double decision, the requester's own view
 *   AP-05  announcements: audit entries (schema v8) of the frozen shape, webhooks without arguments, notification
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const express = require('express');
const request = require('supertest');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

const T = 'default';
let apiKey; let otherKey; let app; let mods; let asked;
const SEND = { type: 'object', required: ['to', 'text'], properties: { to: { type: 'string' }, text: { type: 'string' } }, additionalProperties: false };
const H = (c) => c.repeat(64);

function boot({ allow = true } = {}) {
  jest.resetModules();
  jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
  process.env.QODIQA_CLIENT_ID = T;
  mods = { agents: require('../../../core/agents/agentStore'), registry: require('../../../core/actions/toolRegistry'), executor: require('../../../core/actions/executor'), approvals: require('../../../core/approvals/approvalStore'),
    tok: require('../../../core/approvals/approvalToken'), plans: require('../../../core/actions/planStore'), resolveKey: require('../../../validation/resolveKey').resolveKey };
  const { createActionsRouter } = require('../actions'); const { createApprovalsRouter } = require('../approvals');
  asked = [];
  const requirePermission = (p) => (req, res, next) => { asked.push(p); return allow ? next() : res.status(403).json({ status: 'failure', error: { code: 'FORBIDDEN' } }); };
  app = express();
  app.use(express.json());
  app.use((req, res, next) => { const u = req.headers['x-user'] || 'bob'; req.rbacUser = { id: u, username: u }; next(); });
  app.use('/v1/actions', createActionsRouter());
  app.use('/v1/approvals', createApprovalsRouter({ requirePermission }));
  ({ apiKey } = provisionTestSigningIdentity({ tenantId: T }));
  ({ apiKey: otherKey } = provisionTestSigningIdentity({ tenantId: 'other' }));
}

const bearer = (k = apiKey) => ({ Authorization: `Bearer ${k}` });
const authorize = (who, args, extra = {}, key = apiKey, name = 'notify') => request(app).post('/v1/actions/authorize').set(bearer(key)).send({ agentId: who.agentId, sessionId: who.sessionId, tool: { server: 'srv', name }, args, ...extra });
const decide = (id, body, user = 'bob') => request(app).post(`/v1/approvals/${id}/decision`).set('x-user', user).send({ tenantId: T, ...body });
async function agent(opts = {}) {
  const a = await mods.agents.createAgent(T, { displayName: 'Bot', allowedActionClasses: ['read', 'communication'], ...opts }, 'op');
  return { agentId: a.agentId, sessionId: (await mods.agents.startSession(T, a.agentId, {}, 'op')).sessionId };
}
const MAIL = { to: 'ceo@example.com', text: 'Wire approved.' };
const exec = (art, args = MAIL) => mods.executor.beginExecution({ artifact: art, tool: { server: 'srv', name: 'notify' }, args });

beforeEach(async () => {
  boot();
  mods.agents._resetForTests(); mods.registry._resetForTests(); mods.executor._resetForTests(); mods.approvals._resetForTests(); mods.plans._resetForTests();
  await mods.registry.register(T, { server: 'srv', name: 'notify', schema: SEND, actionClass: 'communication', reversible: false }, 'alice');       // irreversible => requires approval
  await mods.registry.register(T, { server: 'srv', name: 'peek', schema: SEND, actionClass: 'read', reversible: true }, 'alice');
});
afterEach(() => { delete process.env.QODIQA_APPROVAL_TTL_SECONDS; });

describe('approval flow', () => {
  test('AP-01 request, decision, artifact, execution; signed, bound, spent once', async () => {
    const w = await agent();
    const r = await authorize(w, MAIL);
    expect(r.status).toBe(202);
    expect(r.body).toMatchObject({ status: 'pending', requestId: null, data: { approvalId: expect.any(String), actionHash: expect.stringMatching(/^[0-9a-f]{64}$/), seq: 1 } });
    const id = r.body.data.approvalId;
    expect(r.body.artifact).toBeUndefined();                                                                           // no artifact without an approval
    // while pending: still 202, the requester sees its status, the operator sees the action and its arguments
    expect((await authorize(w, MAIL, { approvalId: id })).status).toBe(202);
    const mine = await request(app).get(`/v1/actions/approvals/${id}`).set(bearer());
    expect(mine.body.data).toMatchObject({ approvalId: id, status: 'PENDING', actionHash: r.body.data.actionHash, seq: 1 });
    expect(mine.body.data.args).toBeUndefined();
    const op = await request(app).get(`/v1/approvals/${id}?tenantId=${T}`);
    expect(op.body.data).toMatchObject({ status: 'PENDING', args: MAIL, tool: { server: 'srv', name: 'notify' }, requesterId: expect.stringMatching(/^identity:/) });
    expect((await request(app).get(`/v1/approvals?tenantId=${T}&status=PENDING`)).body.data.approvals.map((a) => a.approvalId)).toEqual([id]);
    // the operator decides: signed statement, bound to the actionHash
    const d = await decide(id, { decision: 'APPROVE', reason: 'verified by phone', ttlSeconds: 300 });
    expect(d.status).toBe(200);
    expect(d.body.data).toMatchObject({ status: 'APPROVED', approverId: 'bob', mfa: 'step-up', decisionReason: 'verified by phone' });
    const token = d.body.data.decisionToken;
    expect(token.payload).toMatchObject({ v: 1, kind: 'approval', approvalId: id, actionHash: r.body.data.actionHash, agentId: w.agentId, sessionId: w.sessionId, seq: 1, approverId: 'bob', decision: 'APPROVED', mfa: 'step-up', tenantId: T });
    expect(token.payload.expiresAt - token.payload.notBefore).toBe(300_000);
    expect(mods.tok.verifyApproval(token, { resolveKey: mods.resolveKey, expect: { actionHash: r.body.data.actionHash, tenantId: T } })).toMatchObject({ ok: true });
    // the artifact: carries approvalRef, the position the request reserved, the same hash
    const a = await authorize(w, MAIL, { approvalId: id });
    expect(a.status).toBe(200);
    expect(a.body.action).toMatchObject({ seq: 1, actionHash: r.body.data.actionHash, prevActionHash: null });
    expect(a.body.artifact.payload.qodiqa).toMatchObject({ kind: 'action', seq: 1, actionHash: r.body.data.actionHash, approvalRef: id });
    expect(a.body.meta).toMatchObject({ approvalId: id, approverId: 'bob' });
    // spent once
    const again = await authorize(w, MAIL, { approvalId: id });
    expect(again.status).toBe(409); expect(again.body.reason).toBe('APPROVAL_ALREADY_USED');
    // the executor re-checks the approval and runs the action
    const begun = await exec(a.body.artifact);
    expect(begun).toMatchObject({ ok: true, execution: { seq: 1, approvalRef: id } });
    expect(await mods.executor.getExecution(T, w.sessionId, 1)).toMatchObject({ status: 'intent', approvalRef: id });
    // the session carries on in order
    const next = await authorize(w, { to: 'a@b.c', text: 'ok' }, {}, apiKey, 'peek');
    expect(next.body.action).toMatchObject({ seq: 2, prevActionHash: r.body.data.actionHash });
  });

  test('AP-02 refusals', async () => {
    const w = await agent();
    const r = await authorize(w, MAIL); const id = r.body.data.approvalId;
    // approval for a DIFFERENT action: a changed argument, another tool, another agent / session
    await decide(id, { decision: 'APPROVE' });
    expect((await authorize(w, { ...MAIL, text: 'Wire 10x.' }, { approvalId: id })).body.reason).toBe('APPROVAL_INVALID');
    const other = await agent();
    expect((await authorize(other, MAIL, { approvalId: id })).body.reason).toBe('APPROVAL_INVALID');
    expect((await authorize(w, MAIL, { approvalId: id }, apiKey, 'peek')).status).toBe(400);                              // a tool that needs no approval takes none
    expect((await authorize(w, MAIL, { approvalId: crypto.randomUUID() })).body.reason).toBe('APPROVAL_INVALID');
    expect((await authorize(w, MAIL, { approvalId: 'nope' })).body.reason).toBe('INVALID_REQUEST');
    // the requester can only look at its own requests
    expect((await request(app).get(`/v1/actions/approvals/${id}`).set(bearer(otherKey))).status).toBe(404);
    expect((await request(app).post(`/v1/actions/approvals/${id}/cancel`).set(bearer(otherKey)).send({})).status).toBe(404);
    // the right call still works (none of the above spent it)
    const ok = await authorize(w, MAIL, { approvalId: id });
    expect(ok.status).toBe(200);

    // the same human asks and approves: the agent acts for 'alice'; alice cannot approve her own agent's request
    const mine = await agent({ ownerUserId: 'alice' });
    const q = await authorize(mine, MAIL); const qid = q.body.data.approvalId;
    const self = await decide(qid, { decision: 'APPROVE' }, 'alice');
    expect(self.status).toBe(403); expect(self.body.error.code).toBe('APPROVAL_NOT_INDEPENDENT');
    expect((await decide(qid, { decision: 'DENY', reason: 'mine' }, 'alice')).body.error.code).toBe('APPROVAL_NOT_INDEPENDENT');
    expect((await decide(qid, { decision: 'APPROVE' }, 'Alice')).body.error.code).toBe('APPROVAL_NOT_INDEPENDENT');          // case-insensitive
    expect((await mods.approvals.get(T, qid)).status).toBe('PENDING');
    expect((await decide(qid, { decision: 'APPROVE' }, 'carol')).status).toBe(200);                                       // someone else can
    // ... and the requesting identity is not an approver either
    const idReq = await authorize(await agent(), MAIL);
    const identityId = (await mods.approvals.get(T, idReq.body.data.approvalId)).requesterId;
    expect((await decide(idReq.body.data.approvalId, { decision: 'APPROVE' }, identityId)).body.error.code).toBe('APPROVAL_NOT_INDEPENDENT');

    // replay: a spent approval, a copy of the artifact
    const w2 = await agent();
    const r2 = await authorize(w2, MAIL); await decide(r2.body.data.approvalId, { decision: 'APPROVE' });
    const a2 = await authorize(w2, MAIL, { approvalId: r2.body.data.approvalId });
    expect((await exec(a2.body.artifact)).ok).toBe(true);
    expect((await exec(a2.body.artifact))).toEqual({ ok: false, reason: 'ACTION_REPLAY' });
    expect((await authorize(w2, MAIL, { approvalId: r2.body.data.approvalId })).body.reason).toBe('APPROVAL_ALREADY_USED');
  });

  test('AP-02d (re-audit A2-01) an approval signed by a key that has since been revoked is refused', async () => {
    const w = await agent();
    const r = await authorize(w, MAIL); const id = r.body.data.approvalId;
    expect((await decide(id, { decision: 'APPROVE' })).status).toBe(200);
    const rk = require('../../../validation/resolveKey');
    const real = rk.resolveKey;
    const spy = jest.spyOn(rk, 'resolveKey').mockImplementation((keyId) => ({ ...real(keyId), status: 'revoked', timeline: undefined }));
    try {
      const refused = await authorize(w, MAIL, { approvalId: id });
      expect(refused.status).toBeGreaterThanOrEqual(400);
      expect(refused.body.artifact).toBeUndefined();
    } finally { spy.mockRestore(); }
    // the same approval is usable again once the key is trusted again (nothing was spent by the refusal)
    expect((await authorize(w, MAIL, { approvalId: id })).status).toBe(200);
  });

  test('AP-02b expiry: unanswered requests, unspent approvals', async () => {
    process.env.QODIQA_APPROVAL_TTL_SECONDS = '1';
    const w = await agent();
    const r = await authorize(w, MAIL); const id = r.body.data.approvalId;
    await new Promise((res) => setTimeout(res, 1150));
    expect((await decide(id, { decision: 'APPROVE' })).body.error.code).toBe('APPROVAL_EXPIRED');
    expect((await mods.approvals.get(T, id)).status).toBe('EXPIRED');
    expect((await authorize(w, MAIL, { approvalId: id })).body.reason).toBe('APPROVAL_EXPIRED');
    delete process.env.QODIQA_APPROVAL_TTL_SECONDS;
    // granted but not spent in time
    const r2 = await authorize(w, { ...MAIL, text: 'second' }); const id2 = r2.body.data.approvalId;
    expect((await decide(id2, { decision: 'APPROVE', ttlSeconds: 1 })).status).toBe(200);
    await new Promise((res) => setTimeout(res, 1150));
    expect((await authorize(w, { ...MAIL, text: 'second' }, { approvalId: id2 })).body.reason).toBe('APPROVAL_EXPIRED');
    // an approval that is "not yet valid"
    const r3 = await authorize(w, { ...MAIL, text: 'third' }); const id3 = r3.body.data.approvalId;
    const later = new Date(Date.now() + 5000).toISOString();
    expect((await decide(id3, { decision: 'APPROVE', notBefore: later })).status).toBe(200);
    const early = await authorize(w, { ...MAIL, text: 'third' }, { approvalId: id3 });
    expect(early.status).toBe(403); expect(early.body.reason).toBe('APPROVAL_INVALID');
  });

  test('AP-02c cancelled before and after the artifact exists; a tampered statement', async () => {
    const w = await agent();
    const r = await authorize(w, MAIL); const id = r.body.data.approvalId;
    await decide(id, { decision: 'APPROVE' });
    const c = await request(app).post(`/v1/actions/approvals/${id}/cancel`).set(bearer()).send({ reason: 'changed my mind' });
    expect(c.status).toBe(200); expect(c.body.data.status).toBe('CANCELLED');
    expect((await authorize(w, MAIL, { approvalId: id })).body.reason).toBe('APPROVAL_CANCELLED');
    expect((await request(app).post(`/v1/actions/approvals/${id}/cancel`).set(bearer()).send({})).body.reason).toBe('APPROVAL_NOT_CANCELLABLE');
    expect((await request(app).post(`/v1/actions/approvals/${id}/cancel`).set(bearer()).send({ surprise: 1 })).status).toBe(400);
    // cancelled AFTER the artifact was issued: the execution does not run
    const r2 = await authorize(w, { ...MAIL, text: 'b' }); const id2 = r2.body.data.approvalId;
    await decide(id2, { decision: 'APPROVE' });
    const a2 = await authorize(w, { ...MAIL, text: 'b' }, { approvalId: id2 });
    expect(a2.status).toBe(200);
    await request(app).post(`/v1/actions/approvals/${id2}/cancel`).set(bearer()).send({});
    expect(await mods.agents.getSession(T, w.sessionId)).toMatchObject({ nextSeq: 2, lastActionHash: a2.body.action.actionHash });   // the artifact's place is its own: not given back
    expect(await exec(a2.body.artifact, { ...MAIL, text: 'b' })).toMatchObject({ ok: false });
    expect(['APPROVAL_CANCELLED', 'ACTION_REPLAY']).toContain((await exec(a2.body.artifact, { ...MAIL, text: 'b' })).reason);
    // a statement altered in the store no longer verifies: the artifact is not issued
    const r3 = await authorize(w, { ...MAIL, text: 'c' }); const id3 = r3.body.data.approvalId;
    await decide(id3, { decision: 'APPROVE' });
    const rec = await mods.approvals.get(T, id3);
    rec.decisionToken.payload.approverId = 'mallory';                                                                    // the memory store hands out the stored object
    const t = await authorize(w, { ...MAIL, text: 'c' }, { approvalId: id3 });
    expect(t.status).toBe(403); expect(t.body.reason).toBe('APPROVAL_INVALID');
  });

  test('AP-03 a request that ends without the action leaves no hole in the session chain', async () => {
    const w = await agent();
    const one = await authorize(w, MAIL); const oid = one.body.data.approvalId;
    // while the request is open the session authorises nothing else (its place must stay the last one)
    const blocked = await authorize(w, { to: 'x@y.z', text: 'hi' }, {}, apiKey, 'peek');
    expect(blocked.status).toBe(409); expect(blocked.body.reason).toBe('SESSION_AWAITING_APPROVAL');
    expect((await authorize(w, { ...MAIL, text: 'second request' })).body.reason).toBe('SESSION_AWAITING_APPROVAL');
    expect(await mods.approvals.hasOpen(T, w.sessionId)).toBe(true);
    expect(await mods.agents.getSession(T, w.sessionId)).toMatchObject({ nextSeq: 2, actionsUsed: 1, lastActionHash: one.body.data.actionHash });
    await decide(oid, { decision: 'DENY', reason: 'no' });
    expect((await authorize(w, MAIL, { approvalId: oid })).body.reason).toBe('APPROVAL_DENIED');
    // the place was given back: position, hash chain and count are as if the request had never been made
    expect(await mods.agents.getSession(T, w.sessionId)).toMatchObject({ nextSeq: 1, actionsUsed: 0, lastActionHash: null });
    expect(await mods.executor.getExecution(T, w.sessionId, 1)).toBeNull();
    expect(await mods.approvals.hasOpen(T, w.sessionId)).toBe(false);
    const next = await authorize(w, { to: 'x@y.z', text: 'hi' }, {}, apiKey, 'peek');
    expect(next.body.action).toMatchObject({ seq: 1, prevActionHash: null });                                           // contiguous: no ACTION_INTENT number is skipped
    expect((await mods.executor.beginExecution({ artifact: next.body.artifact, tool: { server: 'srv', name: 'peek' }, args: { to: 'x@y.z', text: 'hi' } })).ok).toBe(true);
    // cancelled before the artifact exists: given back too
    const two = await authorize(w, MAIL);
    expect(two.body.data.seq).toBe(2);
    await request(app).post(`/v1/actions/approvals/${two.body.data.approvalId}/cancel`).set(bearer()).send({});
    expect(await mods.agents.getSession(T, w.sessionId)).toMatchObject({ nextSeq: 2, actionsUsed: 1 });
    // granted and never spent: given back when the grant lapses
    const three = await authorize(w, MAIL);
    await decide(three.body.data.approvalId, { decision: 'APPROVE', ttlSeconds: 1 });
    await new Promise((res) => setTimeout(res, 1150));
    expect(await mods.approvals.expireDue(T)).toBe(1);
    expect(await mods.agents.getSession(T, w.sessionId)).toMatchObject({ nextSeq: 2, actionsUsed: 1 });
    // an unanswered request is given back when it expires
    process.env.QODIQA_APPROVAL_TTL_SECONDS = '1';
    const four = await authorize(w, MAIL);
    expect(four.body.data.seq).toBe(2);
    await new Promise((res) => setTimeout(res, 1150));
    expect(await mods.approvals.expireDue(T)).toBe(1);
    expect(await mods.agents.getSession(T, w.sessionId)).toMatchObject({ nextSeq: 2, actionsUsed: 1 });
    delete process.env.QODIQA_APPROVAL_TTL_SECONDS;
  });

  test('AP-03b if the chain moved on anyway the place is closed as a failed action and the gap is reported', async () => {
    const { emit } = require('../../../../services/logger');
    const w = await agent();
    const one = await authorize(w, MAIL);                                                                                // seq 1 reserved by the request
    await mods.agents.reserveAction(T, w.sessionId, { actionClass: 'read', actionHash: H('9'), prevActionHash: one.body.data.actionHash });   // a concurrent authorisation slipped in: seq 2
    await decide(one.body.data.approvalId, { decision: 'DENY', reason: 'no' });
    expect(await mods.executor.getExecution(T, w.sessionId, 1)).toMatchObject({ status: 'failed', tool: 'notify' });      // closed in the ledger so the session still continues in order
    expect(emit.mock.calls.some((c) => c[1] === 'APPROVAL_POSITION_NOT_RELEASABLE')).toBe(true);
  });
});

describe('/v1/approvals', () => {
  test('AP-04 permissions, validation, double decision', async () => {
    const w = await agent();
    const r = await authorize(w, MAIL); const id = r.body.data.approvalId;
    expect((await request(app).get(`/v1/approvals?tenantId=${T}`)).status).toBe(200);
    expect(asked).toContain('READ_APPROVALS');
    for (const [body, code] of [[{ decision: 'MAYBE' }, 'INVALID_DECISION'], [{ decision: 'DENY' }, 'REASON_REQUIRED'], [{ decision: 'APPROVE', ttlSeconds: 0 }, 'INVALID_TTL'], [{ decision: 'APPROVE', ttlSeconds: 99999 }, 'INVALID_TTL'],
      [{ decision: 'APPROVE', notBefore: 'yesterday' }, 'INVALID_NOT_BEFORE'], [{ decision: 'APPROVE', reason: 'x'.repeat(501) }, 'INVALID_REASON'], [{ decision: 'APPROVE', surprise: 1 }, 'INVALID_REQUEST']])
      expect([JSON.stringify(body), (await decide(id, body)).body.error.code]).toEqual([JSON.stringify(body), code]);
    expect(asked).toContain('DECIDE_APPROVALS');
    expect((await decide(crypto.randomUUID(), { decision: 'APPROVE' })).body.error.code).toBe('NOT_FOUND');
    expect((await decide('not-a-uuid', { decision: 'APPROVE' })).status).toBe(404);
    expect((await request(app).get(`/v1/approvals?tenantId=${T}&status=WEIRD`)).body.error.code).toBe('INVALID_STATUS');
    expect((await decide(id, { decision: 'APPROVE' })).status).toBe(200);
    const twice = await decide(id, { decision: 'DENY', reason: 'second thoughts' });
    expect(twice.status).toBe(409); expect(twice.body.error.code).toBe('APPROVAL_NOT_PENDING');
    // another tenant sees nothing
    expect((await request(app).get(`/v1/approvals/${id}?tenantId=other`)).status).toBe(404);
    expect((await request(app).get('/v1/approvals?tenantId=other')).body.data.approvals).toEqual([]);
    // without the permission nothing happens
    boot({ allow: false });
    expect((await request(app).post(`/v1/approvals/${id}/decision`).send({ tenantId: T, decision: 'APPROVE' })).status).toBe(403);
  });

  test('AP-05 announcements: audit entries of the frozen shape, webhooks without arguments', async () => {
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true';
    try {
      const calls = []; const events = [];
      jest.doMock('../../../core/audit/audit-log', () => ({ appendMandatory: async (f, o) => { calls.push({ f, o }); return { hash: 'h' }; } }));
      const dispatcher = require('../../../core/webhooks/webhookDispatcher');
      jest.spyOn(dispatcher, 'dispatchEvent').mockImplementation((t, p) => { events.push([t, p]); });
      const w = await agent();
      const r = await authorize(w, MAIL); const id = r.body.data.approvalId;
      await decide(id, { decision: 'APPROVE' });
      const r2 = await authorize(await agent(), { ...MAIL, text: 'two' });
      await decide(r2.body.data.approvalId, { decision: 'DENY', reason: 'no' });
      process.env.QODIQA_APPROVAL_TTL_SECONDS = '1';
      await authorize(await agent(), { ...MAIL, text: 'three' });
      await new Promise((res) => setTimeout(res, 1150));
      await mods.approvals.expireDue(T);
      expect(calls.map((c) => [c.f.entryType, c.f.decision, c.f.reason, c.o.stage])).toEqual([
        ['APPROVAL_REQUESTED', 'BLOCK', 'APPROVAL_REQUIRED', 'APPROVAL'], ['APPROVAL_DECIDED', 'ALLOW', 'APPROVED', 'APPROVAL'], ['APPROVAL_REQUESTED', 'BLOCK', 'APPROVAL_REQUIRED', 'APPROVAL'],
        ['APPROVAL_DECIDED', 'BLOCK', 'DENIED', 'APPROVAL'], ['APPROVAL_REQUESTED', 'BLOCK', 'APPROVAL_REQUIRED', 'APPROVAL'], ['APPROVAL_EXPIRED', 'BLOCK', 'APPROVAL_EXPIRED', 'APPROVAL']]);
      const eb = require('../../../core/audit/entryBuilder');
      for (const c of calls) {
        const entry = JSON.parse(JSON.stringify(eb.buildEntry(eb.normalizeFields(c.f), 'GENESIS')));
        expect(eb.v8ShapeViolation(entry)).toBeFalsy();
      }
      expect(calls[0].f).toMatchObject({ approvalRef: id, actionHash: r.body.data.actionHash, artifactId: `${id}:approval_requested`, executionContext: { approval: { requesterId: expect.stringMatching(/^identity:/), policyRuleId: 'tool:requiresApproval' } } });
      expect(calls[1].f.executionContext.approval).toMatchObject({ approverId: 'bob', decision: 'APPROVED', mfa: 'step-up', notBefore: expect.any(String), expiresAt: expect.any(String) });
      expect(events.map((e) => e[0])).toEqual(['approval.requested', 'approval.decided', 'approval.requested', 'approval.decided', 'approval.requested', 'approval.expired']);
      for (const [, p] of events) { expect(JSON.stringify(p)).not.toContain('Wire approved'); expect(p).toMatchObject({ tenantId: T, tool: 'srv/notify', actionClass: 'communication' }); expect(p.args).toBeUndefined(); }
    } finally { delete process.env.QODIQA_AUDIT_SCHEMA_V8; delete process.env.QODIQA_APPROVAL_TTL_SECONDS; }
  });

  test('AP-06 the approval statement: offline verification', () => {
    const tok = require('../../../core/approvals/approvalToken');
    const kp = crypto.generateKeyPairSync('ed25519');
    const priv = kp.privateKey.export({ format: 'der', type: 'pkcs8' }); const pub = kp.publicKey.export({ format: 'der', type: 'spki' });
    const resolveKey = (id) => (id === 't1:key_v1' ? { found: true, pubDer: pub, clientId: 't1' } : { found: false });
    const NOW = 1_800_000_000_000;
    const A = crypto.randomUUID(); const S = crypto.randomUUID(); const I = crypto.randomUUID();
    const payload = (o = {}) => ({ v: 1, kind: 'approval', approvalId: I, tenantId: 't1', actionHash: H('a'), agentId: A, sessionId: S, seq: 3, requesterId: 'identity:x', approverId: 'bob', decision: 'APPROVED', notBefore: NOW, expiresAt: NOW + 600_000, mfa: 'step-up', policyRuleId: 'tool:requiresApproval', ...o });
    const env = (o = {}, f = {}) => tok.signApproval({ payload: payload(o), timestamp: NOW, expiry: payload(o).expiresAt, publicKeyId: 't1:key_v1', ...f }, priv);
    const v = (e, x = {}) => tok.verifyApproval(e, { now: NOW + 1000, resolveKey, ...x });
    expect(v(env())).toMatchObject({ ok: true });
    expect(v(env(), { expect: { actionHash: H('a'), seq: 3, tenantId: 't1', agentId: A, sessionId: S, approvalId: I } }).ok).toBe(true);
    expect(v(env(), { expect: { actionHash: H('b') } })).toMatchObject({ ok: false, reason: 'APPROVAL_INVALID', detail: 'not for this actionHash' });
    expect(v(env(), { expect: { agentId: crypto.randomUUID() } }).detail).toBe('not for this agentId');
    expect(v(env(), { now: NOW + 600_000 })).toEqual({ ok: false, reason: 'APPROVAL_EXPIRED' });
    expect(v(env(), { now: NOW - 1 })).toMatchObject({ ok: false, reason: 'APPROVAL_INVALID' });
    expect(v(env({ decision: 'DENIED' }))).toMatchObject({ ok: false, reason: 'APPROVAL_INVALID', detail: 'denied' });
    expect(() => env({ approverId: 'identity:x' })).toThrow(/the approver is the requester/);
    const e = env(); const mut = (f) => { const c = JSON.parse(JSON.stringify(e)); f(c); return c; };
    for (const f of [(c) => { c.payload.actionHash = H('b'); }, (c) => { c.payload.approverId = 'eve'; }, (c) => { c.payload.expiresAt += 1; c.expiry += 1; }, (c) => { c.timestamp += 1; }, (c) => { c.publicKeyId = 't2:key_v1'; }])
      expect(v(mut(f)).reason).toBe('APPROVAL_INVALID');
    expect(v(mut((c) => { c.extra = 1; }))).toMatchObject({ ok: false, detail: 'envelope members' });
    const other = crypto.generateKeyPairSync('ed25519');
    expect(v(tok.signApproval({ payload: payload(), timestamp: NOW, expiry: NOW + 600_000, publicKeyId: 't1:key_v1' }, other.privateKey.export({ format: 'der', type: 'pkcs8' })))).toMatchObject({ ok: false, detail: 'signature' });
    expect(v(env(), { resolveKey: () => ({ found: true, pubDer: pub, clientId: 't2' }) })).toMatchObject({ ok: false, detail: 'tenant' });
  });
});
