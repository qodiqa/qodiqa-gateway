'use strict';

/**
 * delegation between agents, over the memory stores, with the real signing identity, key manager and verifiers.
 *
 *   DL-01  a root grant and a chain of children; verification of the chain offline and of the stored delegation
 *   DL-02  refusals: right to delegate, escalation (root and child), depth, cycle, issuer is not the delegate, unknown / revoked parent, bad bodies
 *   DL-03  acting under a delegation: class, tool, shared action limit, wrong delegate
 *   DL-04  revocation in the middle of a chain; cascade; running executions aborted; agents of the chain revoked; a revoked / suspended agent takes its delegations
 * DL-05 issuing a delegation is an authorised action: it is charged against the session's action budget
 *   DL-06  traceability: the chain an action ran under is recorded and reaches the audit entries; a chain revoked after authorisation stops the execution
 *   DL-07  tenant isolation
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const express = require('express');
const request = require('supertest');

const T = 'default';
let apiKey; let otherKey; let app; let store; let registry; let executor; let del; let actionsMod; let killRegistry; let tok;
const READ = { server: 'srv', name: 'files/read', schema: { type: 'object', required: ['path'], properties: { path: { type: 'string' } } }, actionClass: 'read', reversible: true };
const WRITE = { ...READ, name: 'files/write', actionClass: 'write' };

function boot() {
  jest.resetModules();
  jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
  process.env.QODIQA_CLIENT_ID = T;
  store = require('../../../core/agents/agentStore');
  registry = require('../../../core/actions/toolRegistry');
  executor = require('../../../core/actions/executor');
  del = require('../../../core/delegation/delegationStore');
  tok = require('../../../core/delegation/delegationToken');
  killRegistry = require('../../../core/agents/killRegistry');
  actionsMod = require('../actions');
  const { createDelegationsRouter } = require('../delegations');
  app = express();
  app.use(express.json());
  app.use('/v1/actions', actionsMod.createActionsRouter());
  app.use('/v1/delegations', createDelegationsRouter());
  const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
  ({ apiKey } = provisionTestSigningIdentity({ tenantId: T }));
  ({ apiKey: otherKey } = provisionTestSigningIdentity({ tenantId: 'other' }));
}

const post = (url, body, key = apiKey) => request(app).post(url).set('Authorization', `Bearer ${key}`).send(body);
const get = (url, key = apiKey) => request(app).get(url).set('Authorization', `Bearer ${key}`);
async function agent(classes = ['read', 'write', 'delegate'], name = 'Bot') {
  const a = await store.createAgent(T, { displayName: name, allowedActionClasses: classes }, 'op');
  const s = await store.startSession(T, a.agentId, {}, 'op');
  return { agentId: a.agentId, sessionId: s.sessionId };
}
const grant = (from, to, over = {}, key = apiKey) => post('/v1/delegations', { issuerAgentId: from.agentId, issuerSessionId: from.sessionId, subjectAgentId: to.agentId, classes: ['read', 'write'], ...over }, key);
const act = (who, delegationId, name = 'files/read', args = { path: '/p' }) => post('/v1/actions/authorize', { agentId: who.agentId, sessionId: who.sessionId, tool: { server: 'srv', name }, args, ...(delegationId ? { delegationId } : {}) });

beforeEach(async () => {
  boot();
  store._resetForTests(); registry._resetForTests(); executor._resetForTests(); del._resetForTests();
  await registry.register(T, READ, 'alice'); await registry.register(T, WRITE, 'alice');
});

describe('delegation', () => {
  test('DL-01 root grant, child, chain verification', async () => {
    const A = await agent(); const B = await agent(); const C = await agent(['read']);
    const g1 = await grant(A, B, { classes: ['read', 'write', 'delegate'], maxDepth: 3, maxActions: 10, ttlSeconds: 3600 });
    expect(g1.status).toBe(201);
    expect(g1.body.delegation).toMatchObject({ depth: 1, maxDepth: 3, rootAgentId: A.agentId, issuerAgentId: A.agentId, subjectAgentId: B.agentId, parentId: null, status: 'active', classes: ['delegate', 'read', 'write'] });
    const g2 = await grant(B, C, { parentId: g1.body.delegationId, classes: ['read'], tools: [{ server: 'srv', name: 'files/read' }], maxActions: 4, ttlSeconds: 600 });
    expect(g2.status).toBe(201);
    expect(g2.body.delegation).toMatchObject({ depth: 2, maxDepth: 3, rootAgentId: A.agentId, parentId: g1.body.delegationId });
    expect(g2.body.token.payload.parentDigest).toBe(tok.digestHex(g1.body.token));
    // offline chain, stored delegation
    const v = await post('/v1/delegations/verify', { chain: [g1.body.token, g2.body.token] });
    expect(v.body).toMatchObject({ valid: true, state: 'ACTIVE', depth: 2, rootAgentId: A.agentId, subjectAgentId: C.agentId, chainHash: g2.body.chainHash, classes: ['read'], maxActions: 4 });
    expect((await post('/v1/delegations/verify', { delegationId: g2.body.delegationId })).body).toMatchObject({ valid: true, chainHash: g2.body.chainHash });
    expect((await post('/v1/delegations/verify', { chain: [g2.body.token] })).body).toMatchObject({ valid: false, reason: 'DELEGATION_INVALID' });
    expect((await post('/v1/delegations/verify', { chain: [g1.body.token], delegationId: g1.body.delegationId })).status).toBe(400);
    const got = await get(`/v1/delegations/${g2.body.delegationId}`);
    expect(got.body).toMatchObject({ valid: true, delegation: { delegationId: g2.body.delegationId } }); expect(got.body.chain).toHaveLength(2);
  });

  test('DL-02 refusals', async () => {
    const A = await agent(); const B = await agent(); const C = await agent(); const D = await agent(['read']); const noDel = await agent(['read', 'write']);
    const reason = (r) => r.body.reason;
    expect(reason(await grant(noDel, B))).toBe('ACTION_CLASS_NOT_ALLOWED');                                           // no right to delegate at all
    expect(reason(await grant(A, B, { classes: ['read', 'financial'] }))).toBe('DELEGATION_ATTENUATION_VIOLATION');    // root grants only the issuer's OWN classes
    expect(reason(await grant(D, B, { classes: ['read'] }))).toBe('ACTION_CLASS_NOT_ALLOWED');
    expect(reason(await grant(A, A))).toBe('DELEGATION_CYCLE');
    expect(reason(await grant(A, B, { classes: [] }))).toBe('INVALID_CLASSES');
    expect(reason(await grant(A, B, { classes: ['read'], maxDepth: 9 }))).toBe('INVALID_MAX_DEPTH');
    expect(reason(await grant(A, B, { classes: ['read'], ttlSeconds: 0 }))).toBe('INVALID_TTL');
    expect(reason(await post('/v1/delegations', { issuerAgentId: A.agentId, issuerSessionId: A.sessionId, subjectAgentId: B.agentId, classes: ['read'], surprise: 1 }))).toBe('INVALID_REQUEST');
    expect(reason(await grant(A, { agentId: crypto.randomUUID() }, { classes: ['read'] }))).toBe('DELEGATION_INVALID');
    expect((await post('/v1/delegations', {}, 'sk_nope')).status).toBe(401);
    const g1 = await grant(A, B, { classes: ['read', 'write', 'delegate'], maxDepth: 2, maxActions: 5, ttlSeconds: 1000 });
    const pid = g1.body.delegationId;
    expect(reason(await grant(C, D, { parentId: pid, classes: ['read'] }))).toBe('DELEGATION_INVALID');                // C is not the delegate of the parent
    expect(reason(await grant(B, C, { parentId: crypto.randomUUID(), classes: ['read'] }))).toBe('DELEGATION_INVALID');
    expect(reason(await grant(B, C, { parentId: pid, classes: ['read', 'file'] }))).toBe('DELEGATION_ATTENUATION_VIOLATION');
    expect(reason(await grant(B, C, { parentId: pid, classes: ['read'], maxActions: 6 }))).toBe('DELEGATION_ATTENUATION_VIOLATION');
    expect(reason(await grant(B, C, { parentId: pid, classes: ['read'], ttlSeconds: 2000 }))).toBe('DELEGATION_ATTENUATION_VIOLATION');
    expect(reason(await grant(B, A, { parentId: pid, classes: ['read'] }))).toBe('DELEGATION_CYCLE');                  // back to the root agent
    expect(reason(await grant(B, C, { parentId: pid, classes: ['read'], maxDepth: 5 }))).toBe('INVALID_MAX_DEPTH');     // a child cannot raise the depth
    const g2 = await grant(B, C, { parentId: pid, classes: ['read', 'delegate'], maxActions: 5, ttlSeconds: 500 });
    expect(g2.status).toBe(201);
    expect(reason(await grant(C, D, { parentId: g2.body.delegationId, classes: ['read'] }))).toBe('DELEGATION_DEPTH_EXCEEDED');   // maxDepth 2 reached
    // a revoked parent cannot be extended
    await post(`/v1/delegations/${pid}/revoke`, { reason: 'test' });
    expect(reason(await grant(B, D, { parentId: pid, classes: ['read'] }))).toBe('DELEGATION_REVOKED');
  });

  test('DL-03 acting under a delegation', async () => {
    const A = await agent(); const B = await agent(['read', 'write', 'delegate']); const C = await agent(['read', 'write']);
    const g1 = await grant(A, B, { classes: ['read', 'write', 'delegate'], maxActions: 4 });
    const g2 = await grant(B, C, { parentId: g1.body.delegationId, classes: ['read'], tools: [{ server: 'srv', name: 'files/read' }], maxActions: 3 });
    const leaf = g2.body.delegationId;
    expect((await act(C, leaf)).status).toBe(200);
    expect((await act(C, leaf, 'files/write')).body.reason).toBe('ACTION_CLASS_NOT_ALLOWED');                          // write is not in the delegation
    await registry.register(T, { ...READ, name: 'files/list' }, 'alice');
    expect((await act(C, leaf, 'files/list')).body.reason).toBe('ACTION_NOT_IN_DELEGATION');                           // read, but not a listed tool
    expect((await act(B, leaf)).body.reason).toBe('DELEGATION_INVALID');                                               // B is not the delegate of the leaf
    expect((await act(A, leaf)).body.reason).toBe('DELEGATION_INVALID');
    expect((await act(C, crypto.randomUUID())).body.reason).toBe('DELEGATION_INVALID');
    expect((await act(C, leaf)).status).toBe(200); expect((await act(C, leaf)).status).toBe(200);
    const over = await act(C, leaf);
    expect(over.status).toBe(429); expect(over.body.reason).toBe('ACTION_BUDGET_EXHAUSTED');                           // the leaf's own limit (3)
    expect((await del.get(T, leaf)).actionsUsed).toBe(3);                                                              // the refusal is not charged
    // the PARENT's limit bounds everything below it: g1 allows 4 in total, 3 are spent below -> one more anywhere, then none
    const g3 = await grant(B, C, { parentId: g1.body.delegationId, classes: ['read'], maxActions: 4 });
    expect((await act(C, g3.body.delegationId)).status).toBe(200);
    expect((await act(C, g3.body.delegationId)).body.reason).toBe('ACTION_BUDGET_EXHAUSTED');
    // without a delegation the agent still has its own identity's rights
    expect((await act(C)).status).toBe(200);
  });

  test('DL-03b a refusal that comes AFTER the delegation check does not use up the delegation', async () => {
    const A = await agent(); const C = await agent(['read']);
    const a = await store.createAgent(T, { displayName: 'tiny', allowedActionClasses: ['read'], maxActionsPerSession: 1 }, 'op');
    const s = await store.startSession(T, a.agentId, { maxActions: 1 }, 'op');
    const D = { agentId: a.agentId, sessionId: s.sessionId };
    const g = await grant(A, D, { classes: ['read'], maxActions: 3 });
    expect((await act(D, g.body.delegationId)).status).toBe(200);                                                      // the session's only action
    for (let i = 0; i < 3; i++) expect((await act(D, g.body.delegationId)).body.reason).toBe('ACTION_BUDGET_EXHAUSTED');   // refused by the SESSION budget
    expect((await del.get(T, g.body.delegationId)).actionsUsed).toBe(1);                                                // ... and not charged to the delegation
    void C;
  });

  test('DL-03c a caller-chosen requestId is single-use once an artifact was issued', async () => {
    const A = await agent();
    const rid = crypto.randomUUID();
    const body = { agentId: A.agentId, sessionId: A.sessionId, tool: { server: 'srv', name: 'files/read' }, args: { path: '/p' }, requestId: rid };
    expect((await post('/v1/actions/authorize', body)).status).toBe(200);
    const again = await post('/v1/actions/authorize', body);
    expect(again.status).toBe(409); expect(again.body.reason).toBe('REQUEST_ID_REUSED');
    expect((await post('/v1/actions/authorize', { ...body, requestId: crypto.randomUUID() })).status).toBe(200);        // the session is not wedged
  });

  test('DL-04 revocation in the middle of a chain, cascade, abort, agents', async () => {
    const A = await agent(); const B = await agent(); const C = await agent(['read', 'delegate']); const D = await agent(['read']);
    const g1 = await grant(A, B, { classes: ['read', 'write', 'delegate'], maxDepth: 4 });
    const g2 = await grant(B, C, { parentId: g1.body.delegationId, classes: ['read', 'delegate'] });
    const g3 = await grant(C, D, { parentId: g2.body.delegationId, classes: ['read'] });
    const ids = [g1, g2, g3].map((g) => g.body.delegationId);
    expect((await act(D, ids[2])).status).toBe(200);
    // an execution running under the leaf is aborted when the middle link is revoked
    const ctl = new AbortController();
    killRegistry.register(T, D.sessionId, ctl, 'run', [`delegation:${ids[2]}`]);
    expect((await post(`/v1/delegations/${ids[1]}/revoke`, { reason: 'compromised' })).body).toMatchObject({ revoked: [ids[1], ids[2]], abortedExecutions: 1, agentsRevoked: [] });
    expect(ctl.signal.aborted).toBe(true);
    expect((await act(D, ids[2])).body.reason).toBe('DELEGATION_REVOKED');                                              // below the revoked link
    expect((await act(C, ids[1])).body.reason).toBe('DELEGATION_REVOKED');
    expect((await grant(C, D, { parentId: ids[1], classes: ['read'] })).body.reason).toBe('DELEGATION_REVOKED');
    expect((await post('/v1/delegations/verify', { delegationId: ids[2] })).body).toMatchObject({ valid: false, reason: 'DELEGATION_REVOKED' });
    expect((await post('/v1/delegations/verify', { chain: [g1.body.token, g2.body.token, g3.body.token] })).body).toMatchObject({ valid: false, reason: 'DELEGATION_REVOKED' });
    // above the revoked link nothing changed
    expect((await get(`/v1/delegations/${ids[0]}`)).body.delegation.status).toBe('active');
    expect((await act(B, ids[0])).status).toBe(200);
    // revoking again is a no-op; a reason is required
    expect((await post(`/v1/delegations/${ids[1]}/revoke`, { reason: 'again' })).body.revoked).toEqual([]);
    expect((await post(`/v1/delegations/${ids[1]}/revoke`, {})).status).toBe(400);
    expect((await post(`/v1/delegations/${crypto.randomUUID()}/revoke`, { reason: 'x' })).status).toBe(404);
    // revoking the whole chain: the delegates are revoked too (not the root agent), and their sessions end
    const r = await post(`/v1/delegations/${ids[0]}/revoke`, { reason: 'end of task', revokeAgents: true });
    expect(r.body.revoked).toEqual([ids[0]]);                                                                           // the others were already revoked
    expect(r.body.agentsRevoked).toEqual([B.agentId]);                                                                  // only the subjects of what THIS call revoked
    expect((await store.getAgent(T, B.agentId)).status).toBe('revoked');
    expect((await store.getSession(T, B.sessionId)).status).toBe('killed');
    expect((await store.getAgent(T, A.agentId)).status).toBe('active');
  });

  test('DL-04b a suspended or revoked agent takes its delegations with it', async () => {
    const A = await agent(); const B = await agent(); const C = await agent(['read', 'delegate']); const D = await agent(['read']);
    const g1 = await grant(A, B, { classes: ['read', 'write', 'delegate'] });
    const g2 = await grant(B, C, { parentId: g1.body.delegationId, classes: ['read', 'delegate'] });
    const g3 = await grant(C, D, { parentId: g2.body.delegationId, classes: ['read'] });
    await store.updateAgent(T, C.agentId, { status: 'suspended' }, 'op');
    expect((await del.get(T, g2.body.delegationId)).status).toBe('revoked');                                            // held by C
    expect((await del.get(T, g3.body.delegationId)).status).toBe('revoked');                                            // issued by C
    expect((await del.get(T, g1.body.delegationId)).status).toBe('active');
    expect((await act(D, g3.body.delegationId)).body.reason).toBe('DELEGATION_REVOKED');
  });

  test('DL-05 issuing a delegation is an authorised action of the issuer session: class, live session, budget - and no place in the chain of artifacts', async () => {
    const A = await agent(); const B = await agent();
    const g = await grant(A, B, { classes: ['read'] });
    expect(g.status).toBe(201);
    expect(g.body.action).toBeUndefined();
    expect(await store.getSession(T, A.sessionId)).toMatchObject({ nextSeq: 1, actionsUsed: 1, lastActionHash: null });                 // charged, but no seq taken, no hash chained
    expect(await executor.getExecution(T, A.sessionId, 1)).toBeNull();
    // the chain of artifacts is untouched: the next authorised action is seq 1 and can be executed at once
    const a = await act(A, undefined);
    expect(a.body.action).toMatchObject({ seq: 1, prevActionHash: null });
    expect((await executor.beginExecution({ artifact: a.body.artifact, tool: { server: 'srv', name: 'files/read' }, args: { path: '/p' } })).ok).toBe(true);
    // the session budget counts it, and the class and the live session are checked
    const tiny = await store.createAgent(T, { displayName: 'Tiny', allowedActionClasses: ['read', 'delegate'], maxActionsPerSession: 1 }, 'op');
    const ts = await store.startSession(T, tiny.agentId, {}, 'op');
    const T1 = { agentId: tiny.agentId, sessionId: ts.sessionId };
    expect((await grant(T1, B, { classes: ['read'] })).status).toBe(201);
    expect((await grant(T1, A, { classes: ['read'] })).body.reason).toBe('ACTION_BUDGET_EXHAUSTED');
    const noDel = await agent(['read']);
    expect((await grant(noDel, B, { classes: ['read'] })).body.reason).toBe('ACTION_CLASS_NOT_ALLOWED');
    await store.killSession(T, A.sessionId, 'stop', 'op');
    expect((await grant(A, B, { classes: ['read'] })).body.reason).toBe('AGENT_SESSION_ENDED');
    // a refused issuance still spent the attempt (it is not free to probe)
    const C = await agent(['read', 'delegate']);
    expect((await grant(C, B, { classes: ['read', 'financial'] })).body.reason).toBe('DELEGATION_ATTENUATION_VIOLATION');
    expect((await store.getSession(T, C.sessionId)).actionsUsed).toBe(1);
  });

  test('DL-06 traceability and revocation between authorisation and execution', async () => {
    const A = await agent(); const B = await agent(['read', 'write', 'delegate']); const C = await agent(['read']);
    const g1 = await grant(A, B, { classes: ['read', 'write', 'delegate'] });
    const g2 = await grant(B, C, { parentId: g1.body.delegationId, classes: ['read'] });
    const a = await act(C, g2.body.delegationId);
    expect(a.body.meta.delegation).toMatchObject({ delegationId: g2.body.delegationId, chainHash: g2.body.chainHash, depth: 2, rootAgentId: A.agentId });
    expect(await del.getUse(T, a.body.artifactId)).toMatchObject({ delegationId: g2.body.delegationId, chainHash: g2.body.chainHash, depth: 2, rootAgentId: A.agentId, agentId: C.agentId, sessionId: C.sessionId });
    // executed: the execution carries the chain; under schema v8 the entries do too
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true';
    try {
      const calls = [];
      jest.doMock('../../../core/audit/audit-log', () => ({ appendMandatory: async (f, o) => { calls.push({ f, o }); return { hash: 'h' }; } }));
      const begun = await executor.beginExecution({ artifact: a.body.artifact, tool: { server: 'srv', name: 'files/read' }, args: { path: '/p' } });
      expect(begun).toMatchObject({ ok: true, audit: 'written', execution: { delegation: { delegationId: g2.body.delegationId, depth: 2, rootAgentId: A.agentId, chainIds: [g1.body.delegationId, g2.body.delegationId] } } });
      await executor.completeExecution(begun.execution, { ok: true });
      expect(calls.map((c) => c.f.entryType)).toEqual(['ACTION_INTENT', 'ACTION_COMMIT']);
      const eb = require('../../../core/audit/entryBuilder');
      for (const c of calls) {
        expect(c.f.executionContext.delegation).toEqual({ delegationId: g2.body.delegationId, chainHash: g2.body.chainHash, depth: 2, rootAgentId: A.agentId });
        const entry = JSON.parse(JSON.stringify(eb.buildEntry(eb.normalizeFields(c.f), 'GENESIS')));
        expect(eb.v8ShapeViolation(entry)).toBeFalsy();                                                                // the frozen entry shape accepts the delegation facts
        expect(entry.executionContext.delegation.chainHash).toBe(g2.body.chainHash);
      }
    } finally { delete process.env.QODIQA_AUDIT_SCHEMA_V8; }
    // authorised, then the chain is revoked: the execution does not run and consumes nothing
    const b = await act(C, g2.body.delegationId);
    await post(`/v1/delegations/${g1.body.delegationId}/revoke`, { reason: 'stop' });
    expect(await executor.beginExecution({ artifact: b.body.artifact, tool: { server: 'srv', name: 'files/read' }, args: { path: '/p' } })).toEqual({ ok: false, reason: 'DELEGATION_REVOKED', detail: g1.body.delegationId });
    expect(await executor.getExecution(T, C.sessionId, 2)).toBeNull();
  });

  test('DL-07 tenant isolation', async () => {
    const A = await agent(); const B = await agent();
    const g = await grant(A, B, { classes: ['read'] });
    expect((await get(`/v1/delegations/${g.body.delegationId}`, otherKey)).status).toBe(404);
    expect((await post(`/v1/delegations/${g.body.delegationId}/revoke`, { reason: 'x' }, otherKey)).status).toBe(404);
    expect((await post('/v1/delegations/verify', { delegationId: g.body.delegationId }, otherKey)).body).toMatchObject({ valid: false, reason: 'DELEGATION_INVALID' });
    expect((await post('/v1/delegations/verify', { chain: [g.body.token] }, otherKey)).body).toMatchObject({ valid: false, reason: 'DELEGATION_INVALID', detail: 'tenant' });
    expect((await grant(A, B, { classes: ['read'] }, otherKey)).body.reason).toBe('AGENT_SESSION_UNKNOWN');
    expect((await get(`/v1/delegations/${g.body.delegationId}`)).body.delegation.status).toBe('active');
  });

  test('DL-07b (re-audit A1-01) another signing identity of the SAME tenant cannot read or revoke a delegation it did not issue', async () => {
    const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
    const { apiKey: sameTenantOther } = provisionTestSigningIdentity({ tenantId: T });
    const A = await agent(); const B = await agent();
    const g = await grant(A, B, { classes: ['read'] });
    expect((await get(`/v1/delegations/${g.body.delegationId}`, sameTenantOther)).status).toBe(404);
    expect((await post(`/v1/delegations/${g.body.delegationId}/revoke`, { reason: 'x', revokeAgents: true }, sameTenantOther)).status).toBe(404);
    expect((await get(`/v1/delegations/${g.body.delegationId}`)).body.delegation.status).toBe('active');
    expect((await post(`/v1/delegations/${g.body.delegationId}/revoke`, { reason: 'owner revokes' })).status).toBe(200);
  });
});
