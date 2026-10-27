'use strict';

/**
 * delegation tokens and chains (src/core/delegation/delegationToken.js).
 *
 *   DT-01  a valid chain verifies (root -> leaf), the leaf digest is the chainHash, facts are the leaf's
 *   DT-02  forgery: a tampered payload / member, a foreign key, another tenant, a spliced or reordered chain, a missing link
 *   DT-03  attenuation: classes, tools (unrestricted child of a restricted parent), maxActions, expiry - each is DELEGATION_ATTENUATION_VIOLATION
 *   DT-04  depth: maxDepth is fixed by the root; one link too deep is DELEGATION_DEPTH_EXCEEDED
 *   DT-05  cycle: an agent twice in the chain, a self-delegation
 *   DT-06  time: expired, from the future, issued before its parent
 *   DT-07  the first failure in the documented order is the one reported
 */

const crypto = require('crypto');
const tok = require('../delegationToken');

const T = 'tenant-a';
const kp = crypto.generateKeyPairSync('ed25519');
const priv = kp.privateKey.export({ format: 'der', type: 'pkcs8' });
const pub = kp.publicKey.export({ format: 'der', type: 'spki' });
const other = crypto.generateKeyPairSync('ed25519');
const otherPriv = other.privateKey.export({ format: 'der', type: 'pkcs8' });
const KID = `${T}:key_v1`;
const NOW = 1_800_000_000_000;
const uuid = () => crypto.randomUUID();
const A = [uuid(), uuid(), uuid(), uuid(), uuid()];                    // agents
const resolveKey = (id) => (id === KID ? { found: true, pubDer: pub, clientId: T } : (id === 'tenant-b:key_v1' ? { found: true, pubDer: pub, clientId: 'tenant-b' } : { found: false }));
const verify = (chain, o = {}) => tok.verifyChain(chain, { now: NOW, resolveKey, ...o });

/** Build a link. `parent` = the parent envelope or null; `from`/`to` = indexes into A. */
function link(parent, from, to, over = {}) {
  const { ttl = 3600, classes = ['read', 'write'], tools = null, maxActions = null, maxDepth = 3, key = priv, kid = KID, ts = NOW, tenantId = T, rawPayload } = over;
  const payload = rawPayload || tok.buildPayload({ delegationId: uuid(), tenantId, parent, issuerAgentId: A[from], subjectAgentId: A[to], classes, tools, maxActions, maxDepth });
  return tok.signDelegation({ payload, timestamp: ts, expiry: ts + ttl * 1000, publicKeyId: kid }, key);
}
const root = (o) => link(null, 0, 1, o);
const clone = (x) => JSON.parse(JSON.stringify(x));

describe('delegation tokens', () => {
  test('DT-01 a valid chain', () => {
    const r0 = root({ classes: ['read', 'write', 'file'], tools: [{ server: 's', name: 'b' }, { server: 's', name: 'a' }], maxActions: 10 });
    const r1 = link(r0, 1, 2, { classes: ['read', 'write'], tools: [{ server: 's', name: 'a' }], maxActions: 5, ttl: 1800 });
    const r2 = link(r1, 2, 3, { classes: ['read'], tools: [{ server: 's', name: 'a' }], maxActions: 5, ttl: 600 });
    const v = verify([r0, r1, r2]);
    expect(v).toMatchObject({ ok: true, depth: 3, maxDepth: 3, rootAgentId: A[0], issuerAgentId: A[2], subjectAgentId: A[3], tenantId: T, classes: ['read'], tools: [{ server: 's', name: 'a' }], maxActions: 5 });
    expect(v.chainHash).toBe(tok.digestHex(r2));
    expect(v.chainHash).toMatch(/^[0-9a-f]{64}$/);
    expect(r0.payload.tools.map((t) => t.name)).toEqual(['a', 'b']);                                                   // sorted on build
    expect(verify([r0]).ok).toBe(true);
    // the chain hash covers the whole chain: another path to the same leaf content gives another hash
    const r1b = link(r0, 1, 2, { classes: ['read', 'write'], tools: [{ server: 's', name: 'a' }], maxActions: 5, ttl: 1800 });
    expect(verify([r0, r1b]).chainHash).not.toBe(verify([r0, r1]).chainHash);
  });

  test('DT-02 forgery', () => {
    const r0 = root(); const r1 = link(r0, 1, 2);
    const mut = (e, f) => { const c = clone(e); f(c); return c; };
    for (const f of [(c) => { c.payload.classes = ['read', 'write', 'financial']; }, (c) => { c.payload.subjectAgentId = A[4]; }, (c) => { c.expiry += 1000; }, (c) => { c.timestamp -= 1; }, (c) => { c.publicKeyId = 'tenant-b:key_v1'; }])
      expect(verify([r0, mut(r1, f)])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', index: 1 });
    expect(verify([mut(r0, (c) => { c.payload.maxDepth = 8; }), r1])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', index: 0 });
    expect(verify([r0, mut(r1, (c) => { c.extra = 1; })])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'envelope members' });
    expect(verify([r0, mut(r1, (c) => { c.payload.extra = 1; })])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'payload members' });
    expect(verify([r0, mut(r1, (c) => { c.signature = c.signature.slice(0, -2) + 'AA'; })]).ok).toBe(false);
    // a link signed by a key that is not the tenant's
    expect(verify([r0, link(r0, 1, 2, { key: otherPriv })])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'signature' });
    // another tenant's key vouching: a (valid) signature by tenant-b's key over a tenant-a payload
    expect(verify([r0, link(r0, 1, 2, { kid: 'tenant-b:key_v1' })])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'tenant' });
    // splice: a link whose parent is another chain's root
    const r0b = root(); const foreign = link(r0b, 1, 2);
    expect(verify([r0, foreign])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'link to parent' });
    // the same parent id but a different parent (digest mismatch): re-issue a parent with the same delegationId and different content
    const r0twin = tok.signDelegation({ payload: { ...r0.payload, classes: ['read'] }, timestamp: NOW, expiry: NOW + 3600_000, publicKeyId: KID }, priv);
    expect(verify([r0twin, r1])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'link to parent' });
    // missing link / reordered / duplicated / empty
    const r2 = link(r1, 2, 3);
    expect(verify([r0, r2])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID' });
    expect(verify([r1, r0])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID' });
    expect(verify([r0, r1, r1])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID' });
    expect(verify([r1, r2])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'root link' });             // a chain must start at a root grant
    expect(verify([])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID' });
    expect(verify('x')).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID' });
    // a child whose tenantId differs from the root's, signed by the same key (tenant of the key = tenant of the root)
    const evil = link(r0, 1, 2); const evilPayload = { ...evil.payload, tenantId: 'tenant-b' };
    expect(verify([r0, tok.signDelegation({ payload: evilPayload, timestamp: NOW, expiry: NOW + 1000, publicKeyId: KID }, priv)])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID' });
    // key unknown
    expect(verify([r0], { resolveKey: () => ({ found: false }) })).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'signature' });
  });

  test('DT-03 attenuation', () => {
    const r0 = root({ classes: ['read', 'write'], tools: [{ server: 's', name: 'a' }], maxActions: 5, ttl: 3600 });
    const bad = (over) => verify([r0, link(r0, 1, 2, { classes: ['read'], tools: [{ server: 's', name: 'a' }], maxActions: 5, ttl: 600, ...over })]);
    expect(bad({})).toMatchObject({ ok: true });
    expect(bad({ classes: ['read', 'file'] })).toMatchObject({ ok: false, reason: 'DELEGATION_ATTENUATION_VIOLATION', detail: 'classes' });
    expect(bad({ classes: ['financial'] })).toMatchObject({ reason: 'DELEGATION_ATTENUATION_VIOLATION' });
    expect(bad({ tools: [{ server: 's', name: 'z' }] })).toMatchObject({ reason: 'DELEGATION_ATTENUATION_VIOLATION', detail: 'tools' });
    expect(bad({ tools: [{ server: 's', name: 'a' }, { server: 's', name: 'z' }] })).toMatchObject({ reason: 'DELEGATION_ATTENUATION_VIOLATION', detail: 'tools' });
    expect(bad({ tools: null })).toMatchObject({ reason: 'DELEGATION_ATTENUATION_VIOLATION', detail: 'tools' });          // unrestricted child of a restricted parent
    expect(bad({ maxActions: 6 })).toMatchObject({ reason: 'DELEGATION_ATTENUATION_VIOLATION', detail: 'maxActions' });
    expect(bad({ maxActions: null })).toMatchObject({ reason: 'DELEGATION_ATTENUATION_VIOLATION', detail: 'maxActions' });
    expect(bad({ ttl: 3601 })).toMatchObject({ reason: 'DELEGATION_ATTENUATION_VIOLATION', detail: 'expiry' });
    // an unrestricted parent imposes nothing on tools / maxActions; equal rights are allowed (a subset, not a proper subset)
    const open = root({ classes: ['read', 'write'] });
    expect(verify([open, link(open, 1, 2, { classes: ['read', 'write'], tools: [{ server: 's', name: 'q' }], maxActions: 9 })]).ok).toBe(true);
    // the issuer-side helper agrees
    expect(tok.attenuationProblem(r0.payload, { classes: ['read'], tools: [{ server: 's', name: 'a' }], maxActions: 5 }, r0.expiry, r0.expiry)).toBeNull();
    expect(tok.attenuationProblem(r0.payload, { classes: ['file'], tools: [{ server: 's', name: 'a' }], maxActions: 5 }, r0.expiry, r0.expiry)).toBe('classes');
  });

  test('DT-04 depth', () => {
    const r0 = root({ maxDepth: 2 }); const r1 = link(r0, 1, 2);
    expect(verify([r0, r1]).ok).toBe(true);
    const r2 = link(r1, 2, 3);                                                                         // depth 3 > maxDepth 2 (built with the inherited maxDepth)
    expect(verify([r0, r1, r2])).toMatchObject({ ok: false, reason: 'DELEGATION_DEPTH_EXCEEDED', index: 2 });
    // a child cannot raise maxDepth
    const raised = tok.signDelegation({ payload: { ...r1.payload, maxDepth: 5 }, timestamp: NOW, expiry: r1.expiry, publicKeyId: KID }, priv);
    expect(verify([r0, raised])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'link to parent' });
    expect(() => root({ maxDepth: 9 })).toThrow(/DELEGATION_INVALID/);
    expect(() => root({ maxDepth: 0 })).toThrow(/DELEGATION_INVALID/);
    // a chain longer than the platform cap
    expect(verify(Array.from({ length: 9 }, () => r0))).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'chain length' });
  });

  test('DT-05 cycle', () => {
    const r0 = root({ maxDepth: 5 }); const r1 = link(r0, 1, 2); const r2 = link(r1, 2, 3);
    expect(verify([r0, r1, r2]).ok).toBe(true);
    const back = link(r2, 3, 1, { maxDepth: 5 });                                                      // A0 -> A1 -> A2 -> A3 -> A1
    expect(verify([r0, r1, r2, back])).toMatchObject({ ok: false, reason: 'DELEGATION_CYCLE', index: 3 });
    const toRoot = link(r1, 2, 0);                                                                     // back to the root agent
    expect(verify([r0, r1, toRoot])).toMatchObject({ ok: false, reason: 'DELEGATION_CYCLE', index: 2 });
    const self = tok.signDelegation({ payload: { ...r0.payload, subjectAgentId: A[0] }, timestamp: NOW, expiry: r0.expiry, publicKeyId: KID }, priv);
    expect(verify([self])).toMatchObject({ ok: false, reason: 'DELEGATION_CYCLE' });
  });

  test('DT-06 time', () => {
    const r0 = root({ ttl: 60 });
    expect(verify([r0], { now: NOW + 59_000 }).ok).toBe(true);
    expect(verify([r0], { now: NOW + 60_000 })).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'expired' });
    expect(verify([root({ ts: NOW + 10 * 60_000 })])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'issued in the future' });
    const r1 = link(r0, 1, 2, { ts: NOW - 5000, ttl: 30 });
    expect(verify([r0, r1])).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'issued before its parent' });
    expect(verify([r0], { keyCheck: () => 'KEY_REVOKED' })).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID', detail: 'KEY_REVOKED' });
    expect(() => tok.signDelegation({ payload: r0.payload, timestamp: NOW, expiry: NOW, publicKeyId: KID }, priv)).toThrow(/timestamp < expiry/);
  });

  test('DT-07 the first failure in the documented order is reported', () => {
    // link 1 is both too deep AND a cycle AND widens classes: depth comes first, then cycle, then attenuation
    const r0 = root({ maxDepth: 1, classes: ['read'] });
    const both = tok.signDelegation({ payload: { ...tok.buildPayload({ delegationId: uuid(), tenantId: T, parent: null, issuerAgentId: A[1], subjectAgentId: A[0], classes: ['read'], tools: null, maxActions: null, maxDepth: 1 }),
      parentId: r0.payload.delegationId, parentDigest: tok.digestHex(r0), rootAgentId: A[0], depth: 2, classes: ['read', 'write'] }, timestamp: NOW, expiry: NOW + 1000, publicKeyId: KID }, priv);
    expect(verify([r0, both])).toMatchObject({ ok: false, reason: 'DELEGATION_DEPTH_EXCEEDED' });
    const r0b = root({ maxDepth: 3, classes: ['read'] });
    const cyc = tok.signDelegation({ payload: { ...tok.buildPayload({ delegationId: uuid(), tenantId: T, parent: null, issuerAgentId: A[1], subjectAgentId: A[0], classes: ['read'], tools: null, maxActions: null, maxDepth: 3 }),
      parentId: r0b.payload.delegationId, parentDigest: tok.digestHex(r0b), rootAgentId: A[0], depth: 2, classes: ['read', 'write'] }, timestamp: NOW, expiry: NOW + 1000, publicKeyId: KID }, priv);
    expect(verify([r0b, cyc])).toMatchObject({ ok: false, reason: 'DELEGATION_CYCLE' });
  });
});
