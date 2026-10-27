#!/usr/bin/env node
'use strict';

/**
 * Generates the delegation-chain vectors (docs/protocol/vectors/delegation.json, DELEG-nnn) from the PRODUCTION implementation
 * (src/core/delegation/delegationToken.js, specification docs/protocol/DELEGATION.md).
 *
 * Every chain is signed with PUBLISHED test seeds (below - never a real key) and fixed identifiers/timestamps, so the file is byte-for-byte reproducible
 * (Ed25519 signatures are deterministic). Each case carries the whole chain and the verification time; the expected verdict is {ok:true, facts} or
 * {ok:false, reason, index}. Two independent verifiers (verify-delegation-vectors.js, verify_delegation_vectors.py - no QODIQA import, own JCS-P1, own rules,
 * the Python one with its own Ed25519) re-derive every verdict. A disagreement is a defect in the specification, the implementation or a verifier - never settled
 * by editing a vector.
 *
 *   node scripts/protocol/gen-delegation-vectors.js            write the file
 *   node scripts/protocol/gen-delegation-vectors.js --check    regenerate in memory and compare with the committed file (exit 1 on any difference)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tok = require('../../src/core/delegation/delegationToken');

const FILE = path.join(__dirname, '..', '..', 'docs', 'protocol', 'vectors', 'delegation.json');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const seedOf = (label) => crypto.createHash('sha256').update(`QODIQA published delegation test seed: ${label}`, 'utf8').digest();
const privOf = (seed) => Buffer.concat([PKCS8_PREFIX, seed]);
const pubOf = (seed) => crypto.createPublicKey({ key: privOf(seed), format: 'der', type: 'pkcs8' }).export({ format: 'der', type: 'spki' });

const KEYS = [
  { publicKeyId: 'tenant-a:key_v1', clientId: 'tenant-a', seed: seedOf('tenant-a') },
  { publicKeyId: 'tenant-b:key_v1', clientId: 'tenant-b', seed: seedOf('tenant-b') },
];
const STRANGER = privOf(seedOf('stranger'));
const KA = KEYS[0]; const KB = KEYS[1];
const NOW = 1_800_000_000_000;
const H = 3_600_000;

// fixed UUID v4s: agents a0..a9, delegation ids d0..
const uid = (kind, n) => `${(kind.charCodeAt(0).toString(16) + '0000000').slice(0, 8)}-0000-4000-8000-${String(n).padStart(12, '0')}`;
const agent = (n) => uid('a', n);
let counter = 0;
const nextId = () => uid('d', ++counter);

function link(parent, from, to, over = {}) {
  const { classes = ['read', 'write'], tools = null, maxActions = null, maxDepth = 3, key = KA, signWith, ts = NOW - H, ttl = 4 * H, tenantId = key.clientId, payloadPatch, envelopePatch } = over;
  let payload = tok.buildPayload({ delegationId: nextId(), tenantId, parent, issuerAgentId: agent(from), subjectAgentId: agent(to), classes, tools, maxActions, maxDepth });
  if (payloadPatch) payload = { ...payload, ...payloadPatch };
  const priv = privOf(signWith ? signWith.seed : key.seed);
  return tok.signDelegation({ payload, timestamp: ts, expiry: ts + ttl, publicKeyId: key.publicKeyId, ...(envelopePatch || {}) }, priv);
}
const clone = (x) => JSON.parse(JSON.stringify(x));
const mut = (e, f) => { const c = clone(e); f(c); return c; };

function build() {
  counter = 0;
  const cases = [];
  const add = (description, chain, now = NOW) => {
    const v = tok.verifyChain(clone(chain), { now, resolveKey: (id) => { const k = KEYS.find((x) => x.publicKeyId === id); return k ? { found: true, pubDer: pubOf(k.seed), clientId: k.clientId } : { found: false }; } });
    const expected = v.ok ? { ok: true, depth: v.depth, maxDepth: v.maxDepth, chainHash: v.chainHash, rootAgentId: v.rootAgentId, issuerAgentId: v.issuerAgentId, subjectAgentId: v.subjectAgentId, tenantId: v.tenantId,
      delegationId: v.delegationId, classes: v.classes, tools: v.tools, maxActions: v.maxActions, expiry: v.expiry } : { ok: false, reason: v.reason, ...(v.index !== undefined ? { index: v.index } : {}) };
    cases.push({ id: `DELEG-${String(cases.length + 1).padStart(3, '0')}`, description, input: { chain: clone(chain), now }, expected });
  };

  const r0 = link(null, 0, 1, { classes: ['read', 'write', 'delegate'], maxDepth: 4 });
  const r1 = link(r0, 1, 2, { classes: ['read', 'write'] });
  const r2 = link(r1, 2, 3, { classes: ['read'] });
  // valid chains
  add('a root grant alone', [r0]);
  add('two links', [r0, r1]);
  add('three links, rights narrowing at every link', [r0, r1, r2]);
  const lim0 = link(null, 0, 1, { classes: ['read', 'write'], tools: [{ server: 's', name: 'b' }, { server: 's', name: 'a' }], maxActions: 10 });
  const lim1 = link(lim0, 1, 2, { classes: ['read'], tools: [{ server: 's', name: 'a' }], maxActions: 5, ttl: 2 * H });
  add('tools and an action limit narrowed by the child', [lim0, lim1]);
  const eq1 = link(lim0, 1, 2, { classes: ['read', 'write'], tools: [{ server: 's', name: 'a' }, { server: 's', name: 'b' }], maxActions: 10, ttl: 4 * H });
  add('a child holding exactly the rights of its parent (a subset, not a proper subset)', [lim0, eq1]);
  const open1 = link(r0, 1, 2, { classes: ['read'], tools: [{ server: 'x', name: 'y' }], maxActions: 7 });
  add('a child of an unrestricted parent may add tool and action limits', [r0, open1]);
  let chain8 = [link(null, 0, 1, { classes: ['read'], maxDepth: 8 })];
  for (let i = 1; i < 8; i++) chain8.push(link(chain8[i - 1], i, i + 1, { classes: ['read'] }));
  add('a chain of the maximum depth (8)', chain8);
  add('the same chain is valid just before its expiry', [r0], r0.expiry - 1);

  // forgery
  add('payload tampered after signing: classes widened', [r0, mut(r1, (c) => { c.payload.classes = ['read', 'write', 'financial']; })]);
  add('payload tampered after signing: another delegate', [r0, mut(r1, (c) => { c.payload.subjectAgentId = agent(9); })]);
  add('expiry extended after signing', [r0, mut(r1, (c) => { c.expiry += 1000; })]);
  add('timestamp changed after signing', [r0, mut(r1, (c) => { c.timestamp -= 1; })]);
  add('signature altered', [r0, mut(r1, (c) => { c.signature = `${c.signature.slice(0, 10)}${c.signature[10] === 'A' ? 'B' : 'A'}${c.signature.slice(11)}`; })]);
  add('signature with non-canonical encoding (no padding)', [r0, mut(r1, (c) => { c.signature = c.signature.replace(/=+$/, ''); })]);
  add('signed by a key that is not the tenant key', [r0, link(r0, 1, 2, { signWith: { seed: seedOf('stranger') } })]);
  add('envelope with an extra member', [r0, mut(r1, (c) => { c.note = 'x'; })]);
  add('payload with an extra member', [r0, mut(r1, (c) => { c.payload.note = 'x'; })]);
  add('the root tampered: maxDepth raised', [mut(r0, (c) => { c.payload.maxDepth = 8; }), r1]);
  add('a key id nobody knows', [mut(r0, (c) => { c.publicKeyId = 'tenant-z:key_v1'; })]);
  const bLink = link(r0, 1, 2, { key: KB });
  add('a link signed by another tenant\'s key (tenant mismatch with the root)', [r0, bLink]);
  const bRoot = link(null, 0, 1, { key: KB });
  add('a root of another tenant, children of the first tenant', [bRoot, r1]);
  const foreign = link(link(null, 0, 1, { classes: ['read', 'write', 'delegate'], maxDepth: 4 }), 1, 2);
  add('a link spliced in from another chain', [r0, foreign]);
  const r0twin = tok.signDelegation({ payload: { ...r0.payload, classes: ['read'] }, timestamp: r0.timestamp, expiry: r0.expiry, publicKeyId: KA.publicKeyId }, privOf(KA.seed));
  add('same delegation id, different content: the parent digest no longer matches', [r0twin, r1]);
  add('a link missing from the middle', [r0, r2]);
  add('links in the wrong order', [r1, r0]);
  add('a link repeated', [r0, r1, r1]);
  add('a chain that does not start at a root grant', [r1, r2]);
  add('an empty chain', []);
  add('a chain longer than the platform cap', Array.from({ length: 9 }, () => r0));

  // depth
  const d0 = link(null, 0, 1, { maxDepth: 2 });
  const d1 = link(d0, 1, 2);
  const d2 = link(d1, 2, 3);
  add('one link deeper than the maxDepth fixed by the root', [d0, d1, d2]);
  add('a child that raises maxDepth', [d0, tok.signDelegation({ payload: { ...d1.payload, maxDepth: 5 }, timestamp: d1.timestamp, expiry: d1.expiry, publicKeyId: KA.publicKeyId }, privOf(KA.seed))]);

  // cycle
  const c0 = link(null, 0, 1, { maxDepth: 5 });
  const c1 = link(c0, 1, 2);
  const c2 = link(c1, 2, 3);
  add('a delegation back to the root agent', [c0, c1, link(c1, 2, 0)]);
  add('a delegation back to an agent in the middle of the chain', [c0, c1, c2, link(c2, 3, 1)]);
  add('an agent delegating to itself', [tok.signDelegation({ payload: { ...c0.payload, subjectAgentId: agent(0) }, timestamp: c0.timestamp, expiry: c0.expiry, publicKeyId: KA.publicKeyId }, privOf(KA.seed))]);

  // attenuation
  const p0 = link(null, 0, 1, { classes: ['read', 'write'], tools: [{ server: 's', name: 'a' }], maxActions: 5, ttl: 2 * H });
  const child = (over) => link(p0, 1, 2, { classes: ['read'], tools: [{ server: 's', name: 'a' }], maxActions: 5, ttl: H, ...over });
  add('a child with a class its parent does not have', [p0, child({ classes: ['read', 'file'] })]);
  add('a child with a tool its parent does not list', [p0, child({ tools: [{ server: 's', name: 'z' }] })]);
  add('a child with one extra tool beside the listed one', [p0, child({ tools: [{ server: 's', name: 'a' }, { server: 's', name: 'z' }] })]);
  add('an unrestricted child of a parent that lists tools', [p0, child({ tools: null })]);
  add('a child with a larger action limit', [p0, child({ maxActions: 6 })]);
  add('an unlimited child of a parent with an action limit', [p0, child({ maxActions: null })]);
  add('a child that outlives its parent', [p0, child({ ttl: 3 * H })]);

  // time
  add('expired at the moment of verification', [r0], r0.expiry);
  add('the second link expired while its parent is still valid', [r0, link(r0, 1, 2, { ts: r0.timestamp, ttl: H / 2 })], NOW);
  add('issued far in the future', [link(null, 0, 1, { ts: NOW + H })]);
  const early = link(r0, 1, 2, { ts: r0.timestamp - 1000, ttl: H });
  add('a link issued before its parent', [r0, early]);

  // order of checks
  const o0 = link(null, 0, 1, { maxDepth: 1, classes: ['read'] });
  add('too deep, a cycle and wider rights at once: depth is reported first', [o0, tok.signDelegation({ payload: { ...tok.buildPayload({ delegationId: nextId(), tenantId: 'tenant-a', parent: null, issuerAgentId: agent(1), subjectAgentId: agent(0), classes: ['read', 'write'], tools: null, maxActions: null, maxDepth: 1 }),
    parentId: o0.payload.delegationId, parentDigest: tok.digestHex(o0), rootAgentId: agent(0), depth: 2 }, timestamp: NOW - H, expiry: NOW + H, publicKeyId: KA.publicKeyId }, privOf(KA.seed))]);
  const o1 = link(null, 0, 1, { maxDepth: 3, classes: ['read'] });
  add('a cycle and wider rights at once: the cycle is reported first', [o1, tok.signDelegation({ payload: { ...tok.buildPayload({ delegationId: nextId(), tenantId: 'tenant-a', parent: null, issuerAgentId: agent(1), subjectAgentId: agent(0), classes: ['read', 'write'], tools: null, maxActions: null, maxDepth: 3 }),
    parentId: o1.payload.delegationId, parentDigest: tok.digestHex(o1), rootAgentId: agent(0), depth: 2 }, timestamp: NOW - H, expiry: NOW + H, publicKeyId: KA.publicKeyId }, privOf(KA.seed))]);
  add('wider rights and an expired link at once: attenuation is reported before time', [p0, child({ classes: ['read', 'file'], ts: NOW - 5 * H, ttl: H })]);

  const v = {
    format: 'qodiqa-vectors/1', family: 'delegation', spec: 'docs/protocol/DELEGATION.md', specVersion: 'v2-freeze-1', generatedBy: 'scripts/protocol/gen-delegation-vectors.js',
    domain: tok.DELEGATION_DOMAIN,
    keys: KEYS.map((k) => ({ publicKeyId: k.publicKeyId, clientId: k.clientId, publicKeySpkiB64: pubOf(k.seed).toString('base64'), seedNote: 'published test seed: SHA-256("QODIQA published delegation test seed: <clientId>")' })),
    stranger: 'a key outside the registry signs the "not the tenant key" case',
    cases,
  };
  v.counts = { cases: cases.length, valid: cases.filter((c) => c.expected.ok).length, refused: cases.filter((c) => !c.expected.ok).length,
    byReason: cases.reduce((a, c) => { if (!c.expected.ok) a[c.expected.reason] = (a[c.expected.reason] || 0) + 1; return a; }, {}) };
  return v;
}

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
if (require.main === module) {
  const text = `${JSON.stringify(build(), null, 2)}\n`;
  if (process.argv.includes('--check')) {
    const have = fs.existsSync(FILE) ? fs.readFileSync(FILE, 'utf8') : '';
    const ok = have === text;
    process.stdout.write(`${JSON.stringify({ ok, file: 'docs/protocol/vectors/delegation.json', generatedSha256: sha(text), committedSha256: sha(have) })}\n`);
    if (!ok) { process.stderr.write('[delegation-vectors] DRIFT: run `npm run protocol:vectors` and review the diff\n'); process.exit(1); }
  } else {
    fs.writeFileSync(FILE, text);
    process.stdout.write(`${JSON.stringify({ wrote: path.relative(process.cwd(), FILE), counts: build().counts })}\n`);
  }
}

module.exports = { build, KEYS, STRANGER };
