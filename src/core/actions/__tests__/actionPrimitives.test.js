'use strict';

/**
 * primitives: actionHash, the action artifact, the argument schema subset, the tool registry (process-memory store; PostgreSQL in
 * test/integration/toolRegistry.integration.test.js).
 *
 *   AH-01  actionHash: domain-separated JCS-P1 hash; every field matters; key order does not; invalid documents get a precise code
 *   AH-02  the chain rule: prevActionHash is null exactly when seq is 1; args are canonicalised (NFC, decimals, no duplicate semantics)
 *   AA-01  the action artifact: sign / verify round trip with an injected key; ordinary artifacts are the WRONG kind and do not verify (domain separation)
 *   AA-02  tampering: payload, seq, actionHash, expiry, key id, tenant mismatch, lifetime above 60 s
 *   SS-01  the schema subset: accepted keywords, refused keywords, strict additionalProperties, nesting limits
 *   TR-01  tool registry lifecycle: first registration active; changed definition = pending version; approve supersedes; self-approval refused; observe NEW/MODIFIED/UNCHANGED
 *   TR-02  resolveForAction: not registered / pending review / disabled / schema changed (TOCTOU) / ok; argument validation by the registered schema
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const { computeActionHash, computeSchemaHash, buildActionDocument, ActionHashError, hashesEqual, ACTION_DOMAIN } = require('../actionHash');
const aa = require('../actionArtifact');
const ss = require('../schemaSubset');
const registry = require('../toolRegistry');

const H = (c) => c.repeat(64);
const A = crypto.randomUUID(); const S = crypto.randomUUID();
const base = (over = {}) => ({ tenantId: 't1', agentId: A, sessionId: S, seq: 1, tool: { server: 'srv', name: 'files/read', schemaHash: H('e') }, args: { path: '/tmp/a.txt', limit: 10 }, parentRequestHash: H('f'), prevActionHash: null, ...over });

describe('actionHash', () => {
  test('AH-01 domain-separated, every field matters, key order does not', () => {
    const h = computeActionHash(base());
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    const doc = buildActionDocument(base());
    const manual = crypto.createHash('sha256').update(ACTION_DOMAIN).update(JSON.stringify(doc, Object.keys(doc).sort()).length ? require('../../../validation/jcsP1').canonicalJcsP1(doc) : '').digest('hex');
    expect(h).toBe(manual);
    expect(computeActionHash(base({ args: { limit: 10, path: '/tmp/a.txt' } }))).toBe(h);                       // key order
    const variants = [base({ tenantId: 't2' }), base({ agentId: crypto.randomUUID() }), base({ sessionId: crypto.randomUUID() }), base({ seq: 2, prevActionHash: H('1') }),
      base({ tool: { server: 'srv2', name: 'files/read', schemaHash: H('e') } }), base({ tool: { server: 'srv', name: 'files/write', schemaHash: H('e') } }),
      base({ tool: { server: 'srv', name: 'files/read', schemaHash: H('d') } }), base({ args: { path: '/tmp/b.txt', limit: 10 } }), base({ args: { path: '/tmp/a.txt', limit: 11 } }),
      base({ parentRequestHash: H('0') }), base({ parentRequestHash: null })];
    expect(new Set([h, ...variants.map(computeActionHash)]).size).toBe(variants.length + 1);
    expect(computeActionHash(base({ args: { path: '/tmp/a.txt', limit: 10.5 } }))).not.toBe(h);                // decimals are allowed under JCS-P1 and distinct
    expect(hashesEqual(h, h)).toBe(true); expect(hashesEqual(h, H('0'))).toBe(false); expect(hashesEqual(h, 'short')).toBe(false);
    const bad = [
      [base({ tenantId: 'a b' }), 'ACTION_INVALID_TENANT'], [base({ agentId: 'x' }), 'ACTION_INVALID_AGENT'], [base({ sessionId: crypto.randomUUID().toUpperCase() }), 'ACTION_INVALID_SESSION'],
      [base({ seq: 0 }), 'ACTION_INVALID_SEQ'], [base({ seq: 1.5 }), 'ACTION_INVALID_SEQ'], [base({ tool: { server: 'srv', name: 'n' } }), 'ACTION_INVALID_TOOL'],
      [base({ tool: { server: 'srv', name: 'n', schemaHash: 'zz', extra: 1 } }), 'ACTION_INVALID_TOOL'], [base({ args: [] }), 'ACTION_INVALID_ARGS'], [base({ args: 'x' }), 'ACTION_INVALID_ARGS'],
      [base({ parentRequestHash: 'abc' }), 'ACTION_INVALID_PARENT'], [base({ prevActionHash: 'abc' }), 'ACTION_INVALID_PREV'],
    ];
    for (const [p, code] of bad) expect(() => computeActionHash(p)).toThrow(expect.objectContaining({ code }));
  });

  test('AH-02 the chain rule and canonicalisation of the arguments', () => {
    expect(() => computeActionHash(base({ seq: 2, prevActionHash: null }))).toThrow(expect.objectContaining({ code: 'ACTION_INVALID_PREV' }));
    expect(() => computeActionHash(base({ seq: 1, prevActionHash: H('1') }))).toThrow(expect.objectContaining({ code: 'ACTION_INVALID_PREV' }));
    expect(() => computeActionHash(base({ args: { s: 'é' } }))).toThrow(expect.objectContaining({ code: 'ACTION_ARGS_NOT_CANONICALIZABLE' }));            // not NFC
    expect(() => computeActionHash(base({ args: { n: 1e400 } }))).toThrow(ActionHashError);                                                                  // not finite
    expect(() => computeActionHash(base({ args: { n: 2 ** 60 } }))).toThrow(expect.objectContaining({ code: 'ACTION_ARGS_NOT_CANONICALIZABLE' }));           // beyond the safe range
    const deep = {}; let cur = deep; for (let i = 0; i < 80; i++) { cur.a = {}; cur = cur.a; }
    expect(() => computeActionHash(base({ args: deep }))).toThrow(expect.objectContaining({ code: 'ACTION_ARGS_NOT_CANONICALIZABLE' }));
    expect(() => computeActionHash(base({ args: { big: 'x'.repeat(300_000) } }))).toThrow(expect.objectContaining({ code: 'ACTION_ARGS_NOT_CANONICALIZABLE' }));
    expect(computeSchemaHash({ type: 'object' })).toMatch(/^[0-9a-f]{64}$/);
    expect(computeSchemaHash({ type: 'object', properties: { a: { type: 'string' } } })).not.toBe(computeSchemaHash({ type: 'object', properties: { a: { type: 'number' } } }));
    expect(() => computeSchemaHash([])).toThrow(expect.objectContaining({ code: 'SCHEMA_INVALID' }));
  });
});

describe('action artifact', () => {
  const kp = crypto.generateKeyPairSync('ed25519');
  const priv = kp.privateKey.export({ format: 'der', type: 'pkcs8' }); const pub = kp.publicKey.export({ format: 'der', type: 'spki' });
  const KID = 't1:key_v1';
  const now = Date.now();
  const resolver = (over = {}) => (id) => (id === KID ? { found: true, pubDer: pub, clientId: 't1', status: 'active', ...over } : { found: false });
  const payload = (over = {}) => aa.buildActionPayload({ requestId: crypto.randomUUID(), tenantId: 't1', agentId: A, sessionId: S, seq: 1, actionHash: H('a'), ...over });
  const issue = (over = {}) => aa.signActionArtifact({ payload: payload(), timestamp: now, expiry: now + 30_000, publicKeyId: KID, ...over }, priv);
  const ver = (art, o = {}) => aa.verifyActionArtifact(art, { now, resolveKey: resolver(), ...o });

  test('AA-01 round trip; an ordinary artifact is the wrong kind; domains are separated', () => {
    const art = issue();
    expect(ver(art)).toMatchObject({ ok: true, tenantId: 't1', agentId: A, sessionId: S, seq: 1, actionHash: H('a') });
    // an ORDINARY artifact (no qodiqa block, signed in the ordinary domain) is the wrong kind
    const { signArtifact } = require('../../../validation/signArtifact');
    const ordinary = signArtifact({ payload: { requestId: crypto.randomUUID(), requestHash: H('1'), policyHash: H('2'), tenantId: 't1' }, timestamp: now, expiry: now + 30_000, publicKeyId: KID }, priv);
    expect(ver(ordinary)).toEqual({ ok: false, reason: 'WRONG_ARTIFACT_KIND' });
    const v2req = signArtifact({ payload: { requestId: crypto.randomUUID(), tenantId: 't1', qodiqa: { v: 2, kind: 'request', bind: { headers: [] } } }, timestamp: now, expiry: now + 30_000, publicKeyId: KID }, priv);
    expect(ver(v2req)).toEqual({ ok: false, reason: 'WRONG_ARTIFACT_KIND' });
    // an action payload signed in the ORDINARY domain does not verify as an action artifact, and an action artifact is not an ordinary artifact
    const crossed = signArtifact({ payload: payload(), timestamp: now, expiry: now + 30_000, publicKeyId: KID }, priv);
    expect(ver(crossed)).toEqual({ ok: false, reason: 'ACTION_SIGNATURE_INVALID' });
    const { verify } = require('../../../infra/crypto/ed25519'); const { envelopeHash } = require('../../../validation/canonicalize');
    expect(verify(envelopeHash({ expiry: art.expiry, payload: art.payload, publicKeyId: art.publicKeyId, timestamp: art.timestamp }), art.signature, pub)).toBe(false);
  });

  test('AA-02 tampering and limits', () => {
    const art = issue(); const m = (f) => { const c = JSON.parse(JSON.stringify(art)); f(c); return c; };
    expect(ver(m((c) => { c.payload.qodiqa.seq = 2; }))).toEqual({ ok: false, reason: 'ACTION_SIGNATURE_INVALID' });
    expect(ver(m((c) => { c.payload.qodiqa.actionHash = H('b'); }))).toEqual({ ok: false, reason: 'ACTION_SIGNATURE_INVALID' });
    expect(ver(m((c) => { c.payload.qodiqa.agentId = crypto.randomUUID(); }))).toEqual({ ok: false, reason: 'ACTION_SIGNATURE_INVALID' });
    expect(ver(m((c) => { c.expiry += 1; }))).toEqual({ ok: false, reason: 'ACTION_SIGNATURE_INVALID' });
    expect(ver(m((c) => { c.publicKeyId = 't2:key_v1'; }))).toEqual({ ok: false, reason: 'ACTION_SIGNATURE_INVALID' });
    expect(ver(m((c) => { c.extra = 1; }))).toEqual({ ok: false, reason: 'ACTION_ARTIFACT_INVALID' });
    expect(ver(m((c) => { c.payload.qodiqa.extra = 1; }))).toEqual({ ok: false, reason: 'ACTION_ARTIFACT_INVALID' });
    expect(ver(m((c) => { c.signature = c.signature.replace(/=+$/, ''); }))).toEqual({ ok: false, reason: 'ACTION_ARTIFACT_INVALID' });
    expect(ver(art, { resolveKey: resolver({ clientId: 't2' }) })).toEqual({ ok: false, reason: 'ACTION_TENANT_MISMATCH' });                         // tenant A's key speaking for tenant B
    expect(ver(art, { resolveKey: () => ({ found: false }) })).toEqual({ ok: false, reason: 'ACTION_SIGNATURE_INVALID' });
    expect(ver(art, { now: now + 31_000 }).ok).toBe(false);                                                                                           // expired (reason from timeCheck)
    expect(ver(art, { now: now - 60_000 }).ok).toBe(false);                                                                                           // from the future
    expect(() => issue({ expiry: now + 61_000 })).toThrow(/at most/);
    expect(() => aa.buildActionPayload({ requestId: 'x', tenantId: 't1', agentId: A, sessionId: S, seq: 1, actionHash: H('a') })).toThrow(/requestId/);
  });
});

describe('schema subset', () => {
  test('SS-01 accepted, refused and strict', () => {
    const schema = { type: 'object', required: ['path'], properties: { path: { type: 'string', minLength: 1, maxLength: 20 }, limit: { type: 'integer', minimum: 1, maximum: 100 }, mode: { enum: ['r', 'w'] },
      tags: { type: 'array', items: { type: 'string' }, maxItems: 2, uniqueItems: true }, opt: { anyOf: [{ type: 'null' }, { type: 'string' }] } } };
    expect(() => ss.assertSupported(schema)).not.toThrow();
    const v = (x) => ss.validate(schema, x);
    expect(v({ path: 'a', limit: 5, mode: 'r', tags: ['x'], opt: null })).toEqual({ ok: true });
    expect(v({})).toMatchObject({ ok: false, code: 'REQUIRED', path: '/path' });
    expect(v({ path: 'a', extra: 1 })).toMatchObject({ ok: false, code: 'ADDITIONAL_PROPERTY', path: '/extra' });                       // strict by default
    expect(v({ path: '' })).toMatchObject({ code: 'MIN_LENGTH' }); expect(v({ path: 'x'.repeat(21) })).toMatchObject({ code: 'MAX_LENGTH' });
    expect(v({ path: 'a', limit: 1.5 })).toMatchObject({ code: 'TYPE' }); expect(v({ path: 'a', limit: 0 })).toMatchObject({ code: 'MINIMUM' }); expect(v({ path: 'a', mode: 'x' })).toMatchObject({ code: 'ENUM' });
    expect(v({ path: 'a', tags: ['a', 'a'] })).toMatchObject({ code: 'UNIQUE_ITEMS' }); expect(v({ path: 'a', tags: [1] })).toMatchObject({ code: 'TYPE', path: '/tags/0' });
    expect(v({ path: 'a', opt: 5 })).toMatchObject({ code: 'ANY_OF' });
    expect(v('str')).toMatchObject({ code: 'TYPE' });
    expect(ss.validate({ type: 'object', additionalProperties: true }, { anything: 1 })).toEqual({ ok: true });
    for (const bad of [{ pattern: '.*' }, { $ref: '#/x' }, { format: 'email' }, { oneOf: [] }, { allOf: [] }, { not: {} }, { patternProperties: {} }, { properties: { a: { pattern: 'x' } } }])
      expect(() => ss.assertSupported({ type: 'object', ...bad })).toThrow(expect.objectContaining({ code: 'SCHEMA_UNSUPPORTED_KEYWORD' }));
    expect(() => ss.assertSupported({ type: 'weird' })).toThrow(expect.objectContaining({ code: 'SCHEMA_INVALID' }));
    let deep = { type: 'string' }; for (let i = 0; i < 20; i++) deep = { type: 'array', items: deep };
    expect(() => ss.assertSupported(deep)).toThrow(expect.objectContaining({ code: 'SCHEMA_TOO_DEEP' }));
    expect(() => ss.assertSupported({ type: 'object', properties: JSON.parse('{"__proto__":{"type":"string"}}') })).toThrow();
  });
});

describe('tool registry', () => {
  const T = 't1';
  const spec = (over = {}) => ({ server: 'srv', name: 'files/read', schema: { type: 'object', required: ['path'], properties: { path: { type: 'string' } } }, actionClass: 'read', reversible: true, ...over });
  beforeEach(() => registry._resetForTests());

  test('TR-01 lifecycle: first active, change pending, approve supersedes, self-approval refused, observe', async () => {
    const r1 = await registry.register(T, spec(), 'alice');
    expect(r1).toMatchObject({ change: 'NEW', tool: { version: 1, status: 'active', requiresApproval: false, schemaHash: computeSchemaHash(spec().schema) } });
    await expect(registry.register(T, spec(), 'alice')).rejects.toMatchObject({ code: 'TOOL_UNCHANGED', status: 409 });
    const changed = spec({ schema: { type: 'object', required: ['path'], properties: { path: { type: 'string' }, mode: { type: 'string' } } } });
    const r2 = await registry.register(T, changed, 'alice');
    expect(r2).toMatchObject({ change: 'MODIFIED', tool: { version: 2, status: 'pending_review' } });
    expect((await registry.get(T, 'srv', 'files/read')).active.version).toBe(1);                       // v1 keeps serving
    await expect(registry.approve(T, 'srv', 'files/read', 2, 'alice')).rejects.toMatchObject({ code: 'TOOL_SELF_APPROVAL' });
    expect((await registry.approve(T, 'srv', 'files/read', 2, 'bob')).status).toBe('active');
    const g = await registry.get(T, 'srv', 'files/read');
    expect(g.versions.map((v) => [v.version, v.status])).toEqual([[1, 'superseded'], [2, 'active']]);
    await expect(registry.approve(T, 'srv', 'files/read', 1, 'bob')).rejects.toMatchObject({ code: 'TOOL_VERSION_SUPERSEDED' });
    // an irreversible tool requires approval by default; the policy is validated
    expect((await registry.register(T, spec({ name: 'files/delete', reversible: false, actionClass: 'file' }), 'alice')).tool.requiresApproval).toBe(true);
    await expect(registry.register(T, spec({ name: 'x1', policy: { surprise: 1 } }), 'alice')).rejects.toMatchObject({ code: 'INVALID_POLICY' });
    expect((await registry.updatePolicy(T, 'srv', 'files/read', { policy: { maxCallsPerSession: 3 } }, 'bob')).policy).toEqual({ maxCallsPerSession: 3 });
    // discovery
    const d1 = await registry.observe(T, spec({ name: 'search' })); expect(d1).toMatchObject({ change: 'NEW', tool: { version: 1, status: 'pending_review' } });
    expect(await registry.observe(T, spec({ name: 'search' }))).toEqual({ change: 'UNCHANGED', tool: null });
    const d2 = await registry.observe(T, spec({ name: 'search', schema: { type: 'object', properties: {} } })); expect(d2).toMatchObject({ change: 'MODIFIED', tool: { version: 2 } });
    // validation of what is registered
    await expect(registry.register(T, spec({ name: 'bad', schema: { type: 'object', pattern: 'x' } }), 'a')).rejects.toMatchObject({ code: 'SCHEMA_UNSUPPORTED_KEYWORD' });
    await expect(registry.register(T, spec({ name: 'bad', actionClass: 'fly' }), 'a')).rejects.toMatchObject({ code: 'INVALID_ACTION_CLASS' });
    await expect(registry.register(T, spec({ name: 'bad', reversible: undefined }), 'a')).rejects.toMatchObject({ code: 'INVALID_REVERSIBLE' });
    await expect(registry.register(T, spec({ server: 'bad server' }), 'a')).rejects.toMatchObject({ code: 'INVALID_SERVER_ID' });
  });

  test('TR-02 resolveForAction and argument validation', async () => {
    const h = computeSchemaHash(spec().schema);
    expect(await registry.resolveForAction(T, 'srv', 'files/read', h)).toEqual({ ok: false, reason: 'TOOL_NOT_REGISTERED' });
    await registry.observe(T, spec());
    expect(await registry.resolveForAction(T, 'srv', 'files/read', h)).toEqual({ ok: false, reason: 'TOOL_PENDING_REVIEW' });
    await registry.approve(T, 'srv', 'files/read', 1, 'bob');
    const ok = await registry.resolveForAction(T, 'srv', 'files/read', h);
    expect(ok).toMatchObject({ ok: true, tool: { actionClass: 'read' } });
    expect(await registry.resolveForAction(T, 'srv', 'files/read', H('9'))).toEqual({ ok: false, reason: 'TOOL_SCHEMA_CHANGED' });          // TOCTOU: the action names an old / other schema
    expect(await registry.resolveForAction('t2', 'srv', 'files/read', h)).toEqual({ ok: false, reason: 'TOOL_NOT_REGISTERED' });             // another tenant's registry
    expect(await registry.resolveForAction(T, 'srv', 'unlisted', h)).toEqual({ ok: false, reason: 'TOOL_NOT_REGISTERED' });
    expect(registry.validateArgs(ok.tool, { path: '/a' })).toEqual({ ok: true });
    expect(registry.validateArgs(ok.tool, { path: '/a', sneak: 1 })).toMatchObject({ ok: false, code: 'ADDITIONAL_PROPERTY' });
    await registry.disable(T, 'srv', 'files/read', 'bob');
    expect(await registry.resolveForAction(T, 'srv', 'files/read', h)).toEqual({ ok: false, reason: 'TOOL_DISABLED' });
    await expect(registry.disable(T, 'srv', 'files/read', 'bob')).rejects.toMatchObject({ code: 'TOOL_NOT_ACTIVE' });
  });
});
