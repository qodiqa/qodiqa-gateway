#!/usr/bin/env node
'use strict';

/**
 * INDEPENDENT verifier for docs/protocol/vectors/qodiqa-protocol-vectors.json.
 *
 * Imports NOTHING from src/ or services/: only node:crypto and the independent canonicalizer
 * (scripts/audit-repro/verify/canonical.js, itself dependency-free). Every hash, signature and verdict in the vector
 * file is re-derived here from the rules in docs/protocol/QODIQA-PROTOCOL.md — including an independent
 * re-implementation of the artifact verification procedure (§4) — and compared with what production produced.
 * A mismatch means the implementation and the specification disagree.
 *
 *   node scripts/protocol/verify-vectors.js [vectors.json]     exit 1 on any mismatch
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { canonicalize } = require('../audit-repro/verify/canonical');

const FILE = process.argv[2] || path.join(__dirname, '..', '..', 'docs', 'protocol', 'vectors', 'qodiqa-protocol-vectors.json');
const V = JSON.parse(fs.readFileSync(FILE, 'utf8'));
const results = []; const fail = [];
const rec = (section, name, ok, detail) => { results.push({ section, name, ok }); if (!ok) fail.push({ section, name, detail }); };
const sha256hex = (...parts) => { const h = crypto.createHash('sha256'); for (const p of parts) h.update(Buffer.from(p, 'utf8')); return h.digest('hex'); };
const domainHash = (tag, canonical) => sha256hex(tag, canonical);   // SHA-256(utf8(tag) || utf8(canonical)), no separator

// ── §1 canonicalization ──
for (const v of V.canonicalization.valid) { const c = canonicalize(v.input); rec('canonicalization', v.name, c === v.canonical, { independent: c, production: v.canonical }); }
{ // undefined → null
  const c = canonicalize({ a: undefined, b: [1, undefined] }); rec('canonicalization', 'undefined → null', c === V.canonicalization.undefinedHandling.canonical, { independent: c });
}
const build = (k) => {
  switch (k.kind) {
    case 'number': return { x: k.value === 'NaN' ? NaN : Infinity };
    case 'forbiddenKey': return k.key === '__proto__' ? JSON.parse('{"__proto__":{"a":1}}') : { [k.key]: 1 };
    case 'type': return k.value === 'function' ? { f() {} } : { d: new Date(0) };
    case 'circular': { const o = {}; o.self = o; return o; }
    case 'depth': { let o = 1; for (let i = 0; i < k.depth; i++) o = { a: o }; return o; }
    default: throw new Error(`unknown construct ${k.kind}`);
  }
};
for (const e of V.canonicalization.errors) {
  let threw = false; try { canonicalize(build(e.construct)); } catch { threw = true; }
  rec('canonicalization.errors', e.name, threw === (e.error !== null), { productionError: e.error, independentThrew: threw });
}

// ── §3 domain tags ──
for (const t of V.domainTags.tags) {
  const d = domainHash(t.tag, V.domainTags.sampleCanonical);
  rec('domainTags', t.tag, d === t.digestHex && (t.productionDigestHex === undefined || t.productionDigestHex === d), { independent: d });
}

// ── §2 artifact envelope + signature ──
const SIGNER = crypto.createPublicKey({ key: Buffer.from(V.testKeys.signerPublicKeySpkiB64, 'base64'), format: 'der', type: 'spki' });
const envelopeCanonical = (a) => canonicalize({ expiry: a.expiry, payload: a.payload, publicKeyId: a.publicKeyId, timestamp: a.timestamp });
const ARTIFACT_TAG = 'QODIQA::ARTIFACT::V1';
for (const a of V.artifacts) {
  const c = envelopeCanonical(a.artifact); const h = domainHash(ARTIFACT_TAG, c);
  const sigOk = crypto.verify(null, Buffer.from(h, 'hex'), SIGNER, Buffer.from(a.artifact.signature, 'base64'));
  rec('artifacts', a.name, c === a.envelopeCanonical && h === a.envelopeHashHex && sigOk, { canonicalOk: c === a.envelopeCanonical, hashOk: h === a.envelopeHashHex, sigOk });
}

// ── §4 artifact verification — an independent implementation of the decision procedure ──
const KEYS = new Map(V.verification.keys.map((k) => [k.publicKeyId, { pub: crypto.createPublicKey({ key: Buffer.from(k.publicKeySpkiB64, 'base64'), format: 'der', type: 'spki' }), t: k.timeline }]));
const L = V.verification.limits;
const isPlain = (x) => x !== null && typeof x === 'object' && !Array.isArray(x) && Object.getPrototypeOf(x) === Object.prototype;
const FIELDS = ['expiry', 'payload', 'publicKeyId', 'signature', 'timestamp'];
function decide(a, now) {
  const B = (reason) => ({ decision: 'BLOCK', reason });
  if (!isPlain(a)) return B('INVALID_ARTIFACT');
  if (Object.keys(a).some((k) => !FIELDS.includes(k)) || FIELDS.some((k) => !(k in a))) return B('INVALID_ARTIFACT');
  if (!isPlain(a.payload)) return B('INVALID_ARTIFACT');
  for (const f of ['timestamp', 'expiry']) if (typeof a[f] !== 'number' || !Number.isSafeInteger(a[f]) || a[f] <= 0) return B('INVALID_ARTIFACT');   // positive safe integers
  if (typeof a.signature !== 'string') return B('INVALID_ARTIFACT');
  if (!/^[A-Za-z0-9+/]{86}==$/.test(a.signature) || Buffer.from(a.signature, 'base64').toString('base64') !== a.signature) return B('INVALID_SIGNATURE');
  if (typeof a.publicKeyId !== 'string' || !a.publicKeyId.trim()) return B('INVALID_ARTIFACT');
  const key = KEYS.get(a.publicKeyId);   // unknown key → the same outcome as a bad signature
  const h = Buffer.from(domainHash(ARTIFACT_TAG, envelopeCanonical(a)), 'hex');
  if (!key || !crypto.verify(null, h, key.pub, Buffer.from(a.signature, 'base64'))) return B('INVALID_SIGNATURE');
  if (a.timestamp >= a.expiry) return B('INVALID_ARTIFACT');   // timestamp < expiry, after the signature
  if (a.timestamp > now + L.futureSkewMs) return B('FUTURE_TIMESTAMP');
  if (now >= a.expiry) return B('EXPIRED');
  if (now - a.timestamp > L.maxArtifactAgeMs) return B('TIME_SKEW_EXCEEDED');
  const t = key.t || {}; const ms = (s) => (s ? Date.parse(s) : null);
  if (t.status === 'revoked') return B('KEY_REVOKED');
  if (t.status === 'archived') return B('KEY_ARCHIVED');
  if (t.status === 'deprecated') {
    const dep = ms(t.deprecatedAt);
    if (dep === null || a.timestamp >= dep || now >= dep + L.deprecatedWindowMs) return B('KEY_DEPRECATED');
    return { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED' };
  }
  if (t.status === 'active') {
    const act = ms(t.activatedAt);
    if (act !== null && a.timestamp < act - L.futureSkewMs) return B('KEY_NOT_YET_ACTIVE');
    return { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED' };
  }
  return B('KEY_STATUS_UNKNOWN');
}
for (const c of V.verification.cases) {
  const d = decide(c.artifact, V.verification.nowMs);
  rec('verification', c.name, d.decision === c.expected.decision && d.reason === c.expected.reason, { independent: d, production: c.expected });
}

// ── §5 request binding ──
const REQUEST_TAG = 'QODIQA::REQUEST::V1';
for (const r of V.requestBinding.hashes) {
  const c = canonicalize({ body: r.request.body, method: r.request.method.toUpperCase(), path: r.request.path });
  rec('requestBinding.hash', r.name, c === r.canonical && domainHash(REQUEST_TAG, c) === r.requestHashHex, { independent: domainHash(REQUEST_TAG, c) });
}
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
for (const b of V.requestBinding.binding) {
  const p = b.artifactPayload;
  const bound = UUID_V4.test(p.requestId || '') && /^[0-9a-f]{64}$/.test(p.requestHash || '')
    && domainHash(REQUEST_TAG, canonicalize({ body: b.request.body, method: b.request.method.toUpperCase(), path: b.request.path })) === p.requestHash;
  rec('requestBinding.binding', b.name, bound === b.expected.bound, { independent: bound });
}

// ── §6 policy hash ──
const strip = (v) => (Array.isArray(v) ? v.map(strip) : (v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).filter(([k]) => !k.startsWith('_') || k === '__proto__').map(([k, x]) => [k, strip(x)])) : v));
for (const c of V.policyHash.cases) rec('policyHash', c.name, domainHash('QODIQA::POLICY::V1', canonicalize(strip(c.policies))) === c.policyHashHex, {});

const summary = { file: path.relative(process.cwd(), FILE).split(path.sep).join('/'), checks: results.length, failed: fail.length,
  bySection: results.reduce((a, r) => { a[r.section] = (a[r.section] || 0) + 1; return a; }, {}), failures: fail };
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
process.exit(fail.length ? 1 : 0);
