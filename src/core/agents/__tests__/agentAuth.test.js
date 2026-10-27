'use strict';

/**
 * who is calling, and what the agent may do.
 *
 *   AA-01  a live (tenant, agent, session) passes; every other state is refused with its reason, on every call (no caching)
 *   AA-02  an agent with a registered key must prove possession for THIS request: missing / wrong key / another request / another session / malformed
 *   AA-03  privilege separation: the effective rights are the agent's own classes, never the owner's; an agent is not an RBAC principal
 * AA-04 autonomy limits: classes outside the agent's list are refused whatever the session allows; narrowing the agent takes effect on the next request
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const store = require('../agentStore');
const { verifyAgentCaller, signProof, proofDigest } = require('../agentAuth');

const T = 'tenant-a';
const kp = () => { const k = crypto.generateKeyPairSync('ed25519'); return { priv: k.privateKey, pub: k.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') }; };
const rid = () => crypto.randomUUID();
beforeEach(() => store._resetForTests());

describe('agent caller verification', () => {
  test('AA-01 every request is checked against the stores', async () => {
    const a = await store.createAgent(T, { displayName: 'A', ownerUserId: 'u-7', allowedActionClasses: ['read'] }, 'op');
    const s = await store.startSession(T, a.agentId, {}, 'op');
    const caller = { tenantId: T, agentId: a.agentId, sessionId: s.sessionId };
    const ok = await verifyAgentCaller(caller);
    expect(ok).toMatchObject({ ok: true, actsFor: 'u-7', allowedActionClasses: ['read'] });
    await store.updateAgent(T, a.agentId, { status: 'suspended' }, 'op');                           // the very next request sees it
    expect(await verifyAgentCaller(caller)).toEqual({ ok: false, reason: 'AGENT_SESSION_ENDED' });
    expect(await verifyAgentCaller({ ...caller, tenantId: 'tenant-b' })).toEqual({ ok: false, reason: 'AGENT_SESSION_UNKNOWN' });
    expect(await verifyAgentCaller({ ...caller, agentId: rid() })).toEqual({ ok: false, reason: 'AGENT_SESSION_UNKNOWN' });
    expect(await verifyAgentCaller({})).toEqual({ ok: false, reason: 'AGENT_SESSION_INVALID' });
  });

  test('AA-02 an agent with a key must prove possession for this very request', async () => {
    const k = kp(); const other = kp();
    const a = await store.createAgent(T, { displayName: 'Keyed', publicKey: k.pub, allowedActionClasses: ['read'] }, 'op');
    const s = await store.startSession(T, a.agentId, {}, 'op');
    const ctx = { tenantId: T, agentId: a.agentId, sessionId: s.sessionId, requestId: rid() };
    expect(await verifyAgentCaller(ctx)).toEqual({ ok: false, reason: 'AGENT_PROOF_REQUIRED' });                            // a leaked session id alone is not enough
    expect(await verifyAgentCaller({ ...ctx, proof: signProof(ctx, k.priv) })).toMatchObject({ ok: true });
    expect(await verifyAgentCaller({ ...ctx, proof: signProof(ctx, other.priv) })).toEqual({ ok: false, reason: 'AGENT_PROOF_INVALID' });     // another key
    expect(await verifyAgentCaller({ ...ctx, requestId: rid(), proof: signProof(ctx, k.priv) })).toEqual({ ok: false, reason: 'AGENT_PROOF_INVALID' });   // replayed for another request
    const s2 = await store.startSession(T, a.agentId, {}, 'op');
    expect(await verifyAgentCaller({ ...ctx, sessionId: s2.sessionId, proof: signProof(ctx, k.priv) })).toEqual({ ok: false, reason: 'AGENT_PROOF_INVALID' });  // another session
    expect(await verifyAgentCaller({ ...ctx, proof: `${signProof(ctx, k.priv)}AA` })).toEqual({ ok: false, reason: 'AGENT_PROOF_INVALID' });         // non-canonical
    expect(await verifyAgentCaller({ ...ctx, requestId: 'not-a-uuid', proof: signProof(ctx, k.priv) })).toEqual({ ok: false, reason: 'AGENT_PROOF_INVALID' });
    expect(proofDigest(ctx)).toHaveLength(32);
  });

  test('AA-03 an agent has its own rights, never the user\'s, and is not an RBAC principal', async () => {
    const a = await store.createAgent(T, { displayName: 'Delegate', ownerUserId: 'admin-user', allowedActionClasses: ['read'] }, 'op');
    const s = await store.startSession(T, a.agentId, {}, 'op');
    const v = await verifyAgentCaller({ tenantId: T, agentId: a.agentId, sessionId: s.sessionId });
    expect(v.actsFor).toBe('admin-user');                                                                                // recorded as the user it acts for ...
    expect(v.allowedActionClasses).toEqual(['read']);                                                                    // ... but the rights are the agent's own
    expect(await store.reserveAction(T, s.sessionId, { actionClass: 'financial' })).toEqual({ ok: false, reason: 'ACTION_CLASS_NOT_ALLOWED' });
    const { ROLES, PERMISSIONS } = require('../../rbac/roles');
    expect(Object.values(ROLES)).not.toContain('agent');
    for (const roles of Object.values(PERMISSIONS)) expect(roles).not.toContain('agent');
  });

  test('AA-04 autonomy limits are re-read on every request', async () => {
    const a = await store.createAgent(T, { displayName: 'Narrowing', allowedActionClasses: ['read', 'write', 'file'] }, 'op');
    const s = await store.startSession(T, a.agentId, {}, 'op');
    expect(await store.reserveAction(T, s.sessionId, { actionClass: 'file' })).toMatchObject({ ok: true });
    await store.updateAgent(T, a.agentId, { allowedActionClasses: ['read'] }, 'op');
    expect(await store.reserveAction(T, s.sessionId, { actionClass: 'file' })).toEqual({ ok: false, reason: 'ACTION_CLASS_NOT_ALLOWED' });
    expect(await store.reserveAction(T, s.sessionId, { actionClass: 'read' })).toMatchObject({ ok: true });
    expect(await store.reserveAction(T, s.sessionId, { actionClass: 'delegate' })).toEqual({ ok: false, reason: 'ACTION_CLASS_NOT_ALLOWED' });
    expect(await store.reserveAction(T, s.sessionId, { actionClass: 'rm' })).toEqual({ ok: false, reason: 'ACTION_CLASS_INVALID' });
  });
});
