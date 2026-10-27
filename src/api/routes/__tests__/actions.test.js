'use strict';

/**
 * POST /v1/actions/authorize and the executor, over the memory stores, with the real signing identity, key manager and verifier.
 *
 *   AZ-01  happy path: the artifact verifies, actionHash is the recomputable one, seq / prevActionHash form the session chain
 *   AZ-02  refusals carry their reason: body, tool (unknown / pending / disabled), arguments, class, approval, session, agent proof
 *   AZ-03  budget; concurrent authorisations of one session get distinct, gap-free seqs and a consistent chain
 * EX-01 the seven security tests (1 modified argument, 2 replay, 3 reorder / omission, 4 confused deputy, 5 unlisted tool, 7 TOCTOU on schemaHash)
 * the execution plan: authorised once, every action authorised individually against it
 *   EX-02  the session is checked again at execution (kill), the ledger closes, the audit entries are written under schema v8 and skipped without it
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const express = require('express');
const request = require('supertest');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

const T = 'default';
let apiKey; let app; let store; let registry; let executor; let actionHash; let artifactMod; let authMod; let plans;

function boot() {
  jest.resetModules();
  jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
  process.env.QODIQA_CLIENT_ID = T;
  store = require('../../../core/agents/agentStore');
  registry = require('../../../core/actions/toolRegistry');
  executor = require('../../../core/actions/executor');
  actionHash = require('../../../core/actions/actionHash');
  artifactMod = require('../../../core/actions/actionArtifact');
  authMod = require('../../../core/agents/agentAuth');
  plans = require('../../../core/actions/planStore');
  const { createActionsRouter } = require('../actions');
  app = express();
  app.use(express.json());
  app.use('/v1/actions', createActionsRouter());
  ({ apiKey } = require('../../../../test/helpers/signingIdentity').provisionTestSigningIdentity({ tenantId: T }));
}

const READ = { server: 'srv', name: 'files/read', schema: { type: 'object', required: ['path'], properties: { path: { type: 'string', maxLength: 64 }, limit: { type: 'integer', minimum: 1 } } }, actionClass: 'read', reversible: true };
const post = (body, key = apiKey) => request(app).post('/v1/actions/authorize').set('Authorization', `Bearer ${key}`).send(body);
const ask = (agentId, sessionId, args = { path: '/tmp/a' }, extra = {}) => post({ agentId, sessionId, tool: { server: 'srv', name: 'files/read' }, args, ...extra });
const H = (c) => c.repeat(64);

async function world({ classes = ['read'], max = 50, key } = {}) {
  const agent = await store.createAgent(T, { displayName: 'Bot', allowedActionClasses: classes, maxActionsPerSession: max, ...(key ? { publicKey: key } : {}) }, 'op');
  const session = await store.startSession(T, agent.agentId, {}, 'op');
  return { agentId: agent.agentId, sessionId: session.sessionId };
}

beforeEach(async () => {
  boot();
  store._resetForTests(); registry._resetForTests(); executor._resetForTests(); plans._resetForTests();
  await registry.register(T, READ, 'alice');
});

describe('authorize', () => {
  test('AZ-01 happy path and the session chain', async () => {
    const { agentId, sessionId } = await world();
    const r1 = await ask(agentId, sessionId, { path: '/tmp/a', limit: 3 });
    expect(r1.status).toBe(200);
    const a1 = r1.body.artifact;
    const v1 = artifactMod.verifyActionArtifact(a1);
    expect(v1).toMatchObject({ ok: true, tenantId: T, agentId, sessionId, seq: 1 });
    const schemaHash = actionHash.computeSchemaHash(READ.schema);
    expect(r1.body.action).toMatchObject({ seq: 1, prevActionHash: null, tool: { server: 'srv', name: 'files/read', schemaHash } });
    expect(v1.actionHash).toBe(actionHash.computeActionHash({ tenantId: T, agentId, sessionId, seq: 1, tool: { server: 'srv', name: 'files/read', schemaHash }, args: { path: '/tmp/a', limit: 3 }, parentRequestHash: null, prevActionHash: null }));
    expect(a1.expiry - a1.timestamp).toBe(30_000);
    const r2 = await ask(agentId, sessionId, { path: '/tmp/b' }, { parentRequestHash: H('c'), ttl: 5000 });
    expect(r2.body.action).toMatchObject({ seq: 2, prevActionHash: r1.body.action.actionHash, parentRequestHash: H('c') });
    expect(r2.body.artifact.expiry - r2.body.artifact.timestamp).toBe(5000);
    expect((await ask(agentId, sessionId, { path: '/x' }, { ttl: 999_999 })).body.artifact.expiry - Date.now()).toBeLessThanOrEqual(60_000);
    expect(await store.getSession(T, sessionId)).toMatchObject({ nextSeq: 4, actionsUsed: 3 });
  });

  test('AZ-02 refusals', async () => {
    const { agentId, sessionId } = await world();
    const reason = (r) => r.body.reason;
    expect((await request(app).post('/v1/actions/authorize').send({})).status).toBe(401);
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv', name: 'files/read' }, args: {}, approvalRef: 'x' }))).toBe('INVALID_REQUEST');          // no caller-supplied approval
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv', name: 'files/read' }, args: {}, seq: 1 }))).toBe('INVALID_REQUEST');                  // seq is the gateway's
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv' }, args: {} }))).toBe('ACTION_INVALID_TOOL');
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv', name: 'files/read' }, args: [] }))).toBe('ACTION_INVALID_ARGS');
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv', name: 'files/read' }, args: {}, parentRequestHash: 'zz' }))).toBe('ACTION_INVALID_PARENT');
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv', name: 'files/read' }, args: {}, requestId: 'nope' }))).toBe('INVALID_REQUEST');
    // arguments by the registered schema
    const bad = await ask(agentId, sessionId, { path: '/a', sneaky: 1 });
    expect(bad.status).toBe(400); expect(bad.body).toMatchObject({ reason: 'ACTION_ARGS_INVALID', decision: 'BLOCK' });
    expect(reason(await ask(agentId, sessionId, {}))).toBe('ACTION_ARGS_INVALID');
    expect(reason(await ask(agentId, sessionId, { path: 5 }))).toBe('ACTION_ARGS_INVALID');
    // nothing was reserved by the refusals
    expect(await store.getSession(T, sessionId)).toMatchObject({ nextSeq: 1, actionsUsed: 0 });
    // tool states
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv', name: 'unlisted' }, args: {} }))).toBe('TOOL_NOT_REGISTERED');
    await registry.observe(T, { ...READ, name: 'fresh' });
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv', name: 'fresh' }, args: { path: '/a' } }))).toBe('TOOL_PENDING_REVIEW');
    await registry.approve(T, 'srv', 'fresh', 1, 'bob'); await registry.disable(T, 'srv', 'fresh', 'bob');
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv', name: 'fresh' }, args: { path: '/a' } }))).toBe('TOOL_DISABLED');
    // class not allowed / approval required
    await registry.register(T, { ...READ, name: 'wipe', actionClass: 'file', reversible: false }, 'alice');
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv', name: 'wipe' }, args: { path: '/a' } }))).toBe('ACTION_POLICY_REQUIRED');                  // class file: default-deny without a constraint
    await registry.register(T, { ...READ, name: 'notify', actionClass: 'read', reversible: false }, 'alice');
    const pend = await post({ agentId, sessionId, tool: { server: 'srv', name: 'notify' }, args: { path: '/a' } });
    expect(pend.status).toBe(202); expect(pend.body).toMatchObject({ status: 'pending', data: { approvalId: expect.any(String) } });                  // irreversible: a request for approval, not an artifact
    expect((await post({ agentId, sessionId, tool: { server: 'srv', name: 'files/read' }, args: { path: '/b' } })).body.reason).toBe('SESSION_AWAITING_APPROVAL');
    await registry.register(T, { ...READ, name: 'writer', actionClass: 'write' }, 'alice');
    expect(reason(await post({ agentId, sessionId, tool: { server: 'srv', name: 'writer' }, args: { path: '/a' } }))).toBe('ACTION_CLASS_NOT_ALLOWED');
    // sessions: unknown, another agent's, ended, killed
    expect(reason(await ask(agentId, crypto.randomUUID()))).toBe('AGENT_SESSION_UNKNOWN');
    const other = await world();
    expect(reason(await ask(agentId, other.sessionId))).toBe('AGENT_SESSION_UNKNOWN');
    await store.endSession(T, other.sessionId, 'done', 'op');
    expect(reason(await ask(other.agentId, other.sessionId))).toBe('AGENT_SESSION_ENDED');
    await store.killSession(T, sessionId, 'stop', 'op');
    expect(reason(await ask(agentId, sessionId))).toBe('AGENT_SESSION_ENDED');
  });

  test('AZ-02b an agent with a registered key must prove possession for THIS request', async () => {
    const kp = crypto.generateKeyPairSync('ed25519');
    const { agentId, sessionId } = await world({ key: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') });
    expect((await ask(agentId, sessionId)).body.reason).toBe('AGENT_PROOF_REQUIRED');
    const requestId = crypto.randomUUID();
    const proof = authMod.signProof({ tenantId: T, agentId, sessionId, requestId }, kp.privateKey);
    expect((await ask(agentId, sessionId, { path: '/a' }, { requestId, proof })).status).toBe(200);
    const other = crypto.randomUUID();
    expect((await ask(agentId, sessionId, { path: '/a' }, { requestId: other, proof })).body.reason).toBe('AGENT_PROOF_INVALID');                    // proof of another request
    const stranger = crypto.generateKeyPairSync('ed25519');
    expect((await ask(agentId, sessionId, { path: '/a' }, { requestId: other, proof: authMod.signProof({ tenantId: T, agentId, sessionId, requestId: other }, stranger.privateKey) })).body.reason).toBe('AGENT_PROOF_INVALID');
  });

  test('AZ-03 budget and concurrent authorisations', async () => {
    const limited = await world({ max: 2 });
    expect((await ask(limited.agentId, limited.sessionId)).status).toBe(200);
    expect((await ask(limited.agentId, limited.sessionId)).status).toBe(200);
    const over = await ask(limited.agentId, limited.sessionId);
    expect(over.status).toBe(429); expect(over.body.reason).toBe('ACTION_BUDGET_EXHAUSTED');
    const { agentId, sessionId } = await world();
    const res = await Promise.all(Array.from({ length: 6 }, (_, i) => ask(agentId, sessionId, { path: `/p${i}` })));
    const ok = res.filter((r) => r.status === 200).map((r) => r.body.action);
    expect(ok).toHaveLength(6);
    const bySeq = [...ok].sort((a, b) => a.seq - b.seq);
    expect(bySeq.map((a) => a.seq)).toEqual([1, 2, 3, 4, 5, 6]);
    bySeq.forEach((a, i) => expect(a.prevActionHash).toBe(i === 0 ? null : bySeq[i - 1].actionHash));
  });
});

describe('execution plans', () => {
  const plan = (body, key = apiKey) => request(app).post('/v1/actions/plans').set('Authorization', `Bearer ${key}`).send(body);
  const step = (name, maxCalls) => ({ server: 'srv', name, maxCalls });
  const askPlan = (w, planId, name = 'files/read', args = { path: '/p' }) => post({ agentId: w.agentId, sessionId: w.sessionId, tool: { server: 'srv', name }, args, ...(planId ? { planId } : {}) });

  test('a plan is authorised once; each action is authorised against it', async () => {
    await registry.register(T, { ...READ, name: 'twin' }, 'alice');
    await registry.register(T, { ...READ, name: 'wipe', actionClass: 'file', reversible: false }, 'alice');
    const w = await world({ classes: ['read'] });
    // refusals when creating
    expect((await plan({ ...w, steps: [] })).body.reason).toBe('INVALID_PLAN');
    expect((await plan({ ...w, steps: [step('files/read', 0)] })).body.reason).toBe('INVALID_PLAN');
    expect((await plan({ ...w, steps: [step('files/read', 1), step('files/read', 2)] })).body.reason).toBe('INVALID_PLAN');
    expect((await plan({ ...w, steps: [step('ghost', 1)] })).body.reason).toBe('TOOL_NOT_REGISTERED');
    expect((await plan({ ...w, steps: [step('wipe', 1)] })).body.reason).toBe('ACTION_APPROVAL_REQUIRED');
    expect((await plan({ ...w, sessionId: crypto.randomUUID(), steps: [step('files/read', 1)] })).body.reason).toBe('AGENT_SESSION_UNKNOWN');
    expect((await plan({ ...w, steps: [step('files/read', 1)], extra: 1 })).body.reason).toBe('INVALID_REQUEST');
    expect((await request(app).post('/v1/actions/plans').send({})).status).toBe(401);
    // no plan: actions work as before
    expect((await askPlan(w)).status).toBe(200);
    // authorise the plan once
    const created = await plan({ ...w, steps: [step('files/read', 2)] });
    expect(created.status).toBe(201);
    expect(created.body.plan).toMatchObject({ status: 'active', steps: [{ server: 'srv', name: 'files/read', maxCalls: 2 }], used: [0], sessionId: w.sessionId });
    expect(created.body.plan.planHash).toMatch(/^[0-9a-f]{64}$/);
    const planId = created.body.planId;
    // from now on an action needs the plan, and must be a step of it
    expect((await askPlan(w)).body.reason).toBe('ACTION_PLAN_REQUIRED');
    expect((await askPlan(w, planId, 'twin')).body.reason).toBe('ACTION_NOT_IN_PLAN');
    expect((await askPlan(w, crypto.randomUUID())).body.reason).toBe('ACTION_PLAN_UNKNOWN');
    const one = await askPlan(w, planId);
    expect(one.status).toBe(200); expect(one.body.meta.plan).toMatchObject({ planId, step: 0, used: 1, maxCalls: 2 });
    expect((await askPlan(w, planId, 'files/read', { path: '/q' })).status).toBe(200);
    const over = await askPlan(w, planId);
    expect(over.status).toBe(429); expect(over.body.reason).toBe('ACTION_PLAN_STEP_EXHAUSTED');
    // another session cannot use this session's plan
    const other = await world();
    expect((await askPlan(other, planId)).body.reason).toBe('ACTION_PLAN_UNKNOWN');
    // a new plan replaces the old one; the old id is expired; closing it frees the session
    const second = await plan({ ...w, steps: [step('files/read', 1), step('twin', 1)] });
    expect((await askPlan(w, planId)).body.reason).toBe('ACTION_PLAN_EXPIRED');
    expect((await askPlan(w, second.body.planId, 'twin')).status).toBe(200);
    await plans.closePlan(T, second.body.planId, 'op');
    expect((await askPlan(w)).status).toBe(200);
    expect(await plans.getPlan(T, second.body.planId)).toMatchObject({ status: 'closed', used: [0, 1] });
  });

  test('the plan hash identifies the authorised steps, whatever their order', () => {
    const a = plans.planHashOf([{ server: 's', name: 'a', maxCalls: 1 }, { server: 's', name: 'b', maxCalls: 2 }]);
    expect(plans.planHashOf([{ server: 's', name: 'b', maxCalls: 2 }, { server: 's', name: 'a', maxCalls: 1 }])).toBe(a);
    expect(plans.planHashOf([{ server: 's', name: 'a', maxCalls: 1 }, { server: 's', name: 'b', maxCalls: 3 }])).not.toBe(a);
  });
});

describe('the executor', () => {
  const run = async (resp, over = {}) => executor.beginExecution({ artifact: resp.body.artifact, tool: { server: 'srv', name: 'files/read' }, args: resp.body.args || over.args, ...over });
  async function twoActions() {
    const w = await world();
    const a1 = await ask(w.agentId, w.sessionId, { path: '/one' }); const a2 = await ask(w.agentId, w.sessionId, { path: '/two' });
    return { ...w, a1, a2 };
  }

  test('EX-01.1 a changed argument is ACTION_MISMATCH (and nothing is consumed)', async () => {
    const { a1 } = await twoActions();
    for (const args of [{ path: '/one2' }, { path: '/one', limit: 1 }, {}, { path: '/ONE' }]) expect(await run(a1, { args })).toMatchObject({ ok: false, reason: expect.stringMatching(/^(ACTION_MISMATCH|ACTION_ARGS_INVALID)$/) });
    expect(await run(a1, { args: { path: '/one2' } })).toMatchObject({ ok: false, reason: 'ACTION_MISMATCH' });
    expect(await run(a1, { args: { path: '/one' } })).toMatchObject({ ok: true });                                                      // the honest call still works: the bad ones consumed nothing
    expect(await run(a1, { args: { path: '/one' }, parentRequestHash: H('d') })).toMatchObject({ ok: false });
  });

  test('EX-01.2 replay', async () => {
    const { a1 } = await twoActions();
    const first = await run(a1, { args: { path: '/one' } });
    expect(first.ok).toBe(true);
    expect(await run(a1, { args: { path: '/one' } })).toEqual({ ok: false, reason: 'ACTION_REPLAY' });
    // concurrent double submission: exactly one wins
    const w = await world();
    const r = await ask(w.agentId, w.sessionId, { path: '/c' });
    const outs = await Promise.all(Array.from({ length: 5 }, () => run(r, { args: { path: '/c' } })));
    expect(outs.filter((o) => o.ok)).toHaveLength(1);
    expect(outs.filter((o) => !o.ok).every((o) => o.reason === 'ACTION_REPLAY')).toBe(true);
  });

  test('EX-01.3 reordering and omission', async () => {
    const { a1, a2, agentId, sessionId } = await twoActions();
    expect(await run(a2, { args: { path: '/two' } })).toEqual({ ok: false, reason: 'ACTION_ORDER_VIOLATION' });                       // 2 before 1
    expect((await run(a1, { args: { path: '/one' } })).ok).toBe(true);
    expect((await run(a2, { args: { path: '/two' } })).ok).toBe(true);                                                               // now in order
    const a3 = await ask(agentId, sessionId, { path: '/3' }); const a4 = await ask(agentId, sessionId, { path: '/4' });
    expect(await run(a4, { args: { path: '/4' } })).toEqual({ ok: false, reason: 'ACTION_ORDER_VIOLATION' });                        // 3 omitted
    expect((await run(a3, { args: { path: '/3' } })).ok).toBe(true);
    expect((await run(a4, { args: { path: '/4' } })).ok).toBe(true);
  });

  test('EX-01.4 confused deputy: across sessions, agents and tenants', async () => {
    const A = await world(); const B = await world();
    const a = await ask(A.agentId, A.sessionId, { path: '/x' }); const b = await ask(B.agentId, B.sessionId, { path: '/x' });
    expect(a.body.action.actionHash).not.toBe(b.body.action.actionHash);                                                             // same call, different session = different hash
    // A's artifact relabelled for B's session / agent: the signature no longer matches
    const relabel = (art, patch) => ({ ...art, payload: { ...art.payload, qodiqa: { ...art.payload.qodiqa, ...patch } } });
    expect(await executor.beginExecution({ artifact: relabel(a.body.artifact, { sessionId: B.sessionId }), tool: { server: 'srv', name: 'files/read' }, args: { path: '/x' } })).toEqual({ ok: false, reason: 'ACTION_SIGNATURE_INVALID' });
    expect(await executor.beginExecution({ artifact: relabel(a.body.artifact, { agentId: B.agentId }), tool: { server: 'srv', name: 'files/read' }, args: { path: '/x' } })).toEqual({ ok: false, reason: 'ACTION_SIGNATURE_INVALID' });
    // tenant: a key of another tenant cannot vouch for this tenant's artifact
    const wrongOwner = (id) => { const k = require('../../../validation/resolveKey').resolveKey(id); return { ...k, clientId: 'other-tenant' }; };
    expect(await executor.beginExecution({ artifact: a.body.artifact, tool: { server: 'srv', name: 'files/read' }, args: { path: '/x' }, resolveKey: wrongOwner })).toEqual({ ok: false, reason: 'ACTION_TENANT_MISMATCH' });
    // an ORDINARY artifact is the wrong kind, an action artifact is not an ordinary one
    const { signArtifact } = require('../../../validation/signArtifact');
    const keyManager = require('../../../../services/artifact/keyManager'); const key = keyManager.getSigningKey(T);
    const ordinary = signArtifact({ payload: { requestId: crypto.randomUUID(), requestHash: H('1'), policyHash: H('2'), tenantId: T }, timestamp: Date.now(), expiry: Date.now() + 30_000, publicKeyId: key.keyId }, key.privDer);
    expect(await executor.beginExecution({ artifact: ordinary, tool: { server: 'srv', name: 'files/read' }, args: {} })).toEqual({ ok: false, reason: 'WRONG_ARTIFACT_KIND' });
    expect((await executor.beginExecution({ artifact: a.body.artifact, tool: { server: 'srv', name: 'files/read' }, args: { path: '/x' } })).ok).toBe(true);
  });

  test('EX-01.5 a tool that is not listed, or another listed tool, cannot run under the artifact', async () => {
    const { a1 } = await twoActions();
    expect(await executor.beginExecution({ artifact: a1.body.artifact, tool: { server: 'srv', name: 'ghost' }, args: { path: '/one' } })).toEqual({ ok: false, reason: 'TOOL_NOT_REGISTERED' });
    await registry.register(T, { ...READ, name: 'twin' }, 'alice');                                                                   // same schema, same args, a different tool
    expect(await executor.beginExecution({ artifact: a1.body.artifact, tool: { server: 'srv', name: 'twin' }, args: { path: '/one' } })).toEqual({ ok: false, reason: 'ACTION_MISMATCH' });
    await registry.disable(T, 'srv', 'files/read', 'bob');
    expect(await run(a1, { args: { path: '/one' } })).toEqual({ ok: false, reason: 'TOOL_DISABLED' });
  });

  test('EX-01.7 TOCTOU: the schema changed between authorisation and execution', async () => {
    const { a1 } = await twoActions();
    const changed = { ...READ, schema: { ...READ.schema, properties: { ...READ.schema.properties, mode: { type: 'string' } } } };
    await registry.register(T, changed, 'alice');
    expect(await run(a1, { args: { path: '/one' } })).toMatchObject({ ok: true });                                                    // v1 is still active: pending v2 changes nothing
    const w = await world();
    const b = await ask(w.agentId, w.sessionId, { path: '/b' });
    await registry.approve(T, 'srv', 'files/read', 2, 'bob');
    expect(await executor.beginExecution({ artifact: b.body.artifact, tool: { server: 'srv', name: 'files/read' }, args: { path: '/b' } })).toEqual({ ok: false, reason: 'TOOL_SCHEMA_CHANGED' });
    // authorising again names the new schema
    const b2 = await ask(w.agentId, w.sessionId, { path: '/b', mode: 'x' });
    expect(b2.status).toBe(200);
    expect(b2.body.action.tool.schemaHash).toBe(actionHash.computeSchemaHash(changed.schema));
  });

  test('EX-02 liveness at execution, expiry, ledger closing and audit', async () => {
    const w = await world();
    const a = await ask(w.agentId, w.sessionId, { path: '/k' }, { ttl: 1000 });
    const later = Date.now() + 5000;
    expect(await executor.beginExecution({ artifact: a.body.artifact, tool: { server: 'srv', name: 'files/read' }, args: { path: '/k' }, now: later })).toMatchObject({ ok: false });   // expired
    await store.killSession(T, w.sessionId, 'stop', 'op');
    expect(await run(a, { args: { path: '/k' } })).toEqual({ ok: false, reason: 'AGENT_SESSION_ENDED' });

    const w2 = await world();
    const b = await ask(w2.agentId, w2.sessionId, { path: '/ok' });
    const begun = await run(b, { args: { path: '/ok' } });
    expect(begun).toMatchObject({ ok: true, audit: 'skipped', execution: { seq: 1, requestId: b.body.artifactId } });
    expect(await executor.getExecution(T, w2.sessionId, 1)).toMatchObject({ status: 'intent', finishedAt: null });
    expect(await executor.completeExecution(begun.execution, { ok: true, outputHash: H('9') })).toEqual({ closed: true, audit: 'skipped' });
    expect(await executor.getExecution(T, w2.sessionId, 1)).toMatchObject({ status: 'completed', outputHash: H('9') });
    expect((await executor.completeExecution(begun.execution, { ok: false })).closed).toBe(false);                                   // settles once
  });

  test('EX-03 under schema v8 ACTION_INTENT then ACTION_COMMIT are appended; an INTENT that cannot be written stops the action', async () => {
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true';
    try {
      const calls = [];
      let auditImpl = async (fields, opts) => { calls.push({ fields, opts }); return { hash: 'h' }; };
      jest.doMock('../../../core/audit/audit-log', () => ({ appendMandatory: (f, o) => auditImpl(f, o) }));
      const w = await world();
      const a = await ask(w.agentId, w.sessionId, { path: '/v8' });
      const begun = await run(a, { args: { path: '/v8' } });
      expect(begun).toMatchObject({ ok: true, audit: 'written' });
      await executor.completeExecution(begun.execution, { ok: true });
      expect(calls.map((c) => [c.fields.entryType, c.fields.reason, c.opts.stage])).toEqual([['ACTION_INTENT', 'ACTION_AUTHORIZED', 'ACTION_DISPATCH'], ['ACTION_COMMIT', 'ACTION_COMPLETED', 'ACTION_COMMIT']]);
      const eb = require('../../../core/audit/entryBuilder');
      for (const c of calls) expect(() => eb.normalizeFields({ ...c.fields, inputHash: undefined })).not.toThrow();
      const intent = calls[0].fields;
      expect(intent).toMatchObject({ agentId: w.agentId, sessionId: w.sessionId, actionSeq: 1, actionHash: a.body.action.actionHash, executionContext: { action: { prevActionHash: null } } });
      auditImpl = async () => { throw new Error('audit store down'); };
      const w3 = await world();
      const c = await ask(w3.agentId, w3.sessionId, { path: '/v8b' });
      expect(await run(c, { args: { path: '/v8b' } })).toEqual({ ok: false, reason: 'AUDIT_UNAVAILABLE' });
      expect(await executor.getExecution(T, w3.sessionId, 1)).toMatchObject({ status: 'failed' });
    } finally { delete process.env.QODIQA_AUDIT_SCHEMA_V8; }
  });
});
