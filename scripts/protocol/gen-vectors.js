#!/usr/bin/env node
'use strict';

/**
 * Protocol test-vector generator (normative spec: docs/protocol/QODIQA-PROTOCOL.md).
 *
 * Every value in the output is produced by the PRODUCTION implementation — stableStringify, the domain-separated
 * hashes, signArtifact/envelopeHash, validateArtifact (the real verification order and reasons), computeRequestHash /
 * verifyRequestBinding and computePolicyHash — with a pinned clock and Ed25519 keys derived from fixed, PUBLISHED
 * TEST seeds (never deployment keys). The output is byte-reproducible: re-running with no protocol change yields an
 * identical file. Audit entries v1–v6, chains, anchors and transparency/Merkle are covered by the separate audit vector set
 * (enforced by the differential tests under scripts/audit-repro/__tests__/); this set covers what that set
 * does not: canonicalization errors, the domain-tag registry, the artifact envelope and signature, artifact
 * verification outcomes, request binding and the policy hash.
 *
 * Independent verification (no production code): scripts/protocol/verify-vectors.js (Node, node:crypto + the
 * independent canonicalizer) and scripts/protocol/verify_vectors.py (Python, `cryptography` + json).
 *
 *   node scripts/protocol/gen-vectors.js            write docs/protocol/vectors/qodiqa-protocol-vectors.json
 *   node scripts/protocol/gen-vectors.js --check    regenerate in memory; exit 1 if the committed file differs
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const REPO = path.join(__dirname, '..', '..');
const OUT = path.join(REPO, 'docs', 'protocol', 'vectors', 'qodiqa-protocol-vectors.json');
const NOW = Date.parse('2026-10-02T12:00:00.000Z');   // the pinned verifier clock for every verification vector

// ── test keys from PUBLISHED TEST seeds (never deployment keys) ──────────────────────────────────────────────────
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function testKey(seedHex) {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const privDer = priv.export({ format: 'der', type: 'pkcs8' });
  const pubDer = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
  return { privDer, pubDer, publicKeySpkiB64: pubDer.toString('base64') };
}
const SEED = '1212'.repeat(16);          // PUBLISHED TEST SEED — the vector signer
const FORGER_SEED = 'f00d'.repeat(16);   // PUBLISHED TEST SEED — an attacker's key (forged signatures)
const K = testKey(SEED);
const F = testKey(FORGER_SEED);
const KEY_ID = 'w12-vectors:key_v1';

// ── key resolution for the verification vectors: patched BEFORE validateArtifact is loaded (it destructures it) ────
const rk = require(path.join(REPO, 'src', 'validation', 'resolveKey'));
const KEYS = new Map();   // publicKeyId → { pubDer, status, clientId, timeline }
rk.resolveKey = (id) => (KEYS.has(id) ? { found: true, ...KEYS.get(id) } : { found: false, reason: 'KEY_NOT_FOUND', details: { publicKeyId: id } });

const stableStringify = require(path.join(REPO, 'src', 'utils', 'stableStringify'));
const { domainSeparatedHash, ARTIFACT_DOMAINS } = require(path.join(REPO, 'src', 'infra', 'crypto', 'hashing'));
const { signArtifact } = require(path.join(REPO, 'src', 'validation', 'signArtifact'));
const { canonicalizeEnvelope, envelopeHash } = require(path.join(REPO, 'src', 'validation', 'canonicalize'));
const { validateArtifact } = require(path.join(REPO, 'src', 'validation', 'validateArtifact'));
const { computeRequestHash } = require(path.join(REPO, 'src', 'validation', 'requestHash'));
const { verifyRequestBinding } = require(path.join(REPO, 'src', 'validation', 'verifyRequestBinding'));
const { computePolicyHash } = require(path.join(REPO, 'services', 'policyHash'));
const timeCheck = require(path.join(REPO, 'src', 'validation', 'timeCheck'));
const { DEPRECATED_WINDOW_MS } = require(path.join(REPO, 'src', 'validation', 'keyLifecycle'));
const { registry: domainRegistry } = require('./domainRegistry');

const hex = (b) => Buffer.from(b).toString('hex');

// ── 1. canonicalization ─────────────────────────────────────────────────────────────────────────────────────────
function canonicalVectors() {
  const ok = [
    ['empty object', {}], ['key order', { b: 1, a: 2, c: { z: 1, y: [3, 2, 1] } }], ['nested arrays keep order', [[2, 1], [{ b: 1, a: 0 }]]],
    ['numbers', { int: 42, neg: -7, frac: 0.1, big: 1e21, small: 1e-7, negZero: -0 }], ['literals', { t: true, f: false, n: null }],
    ['unicode and escapes', { s: 'é ü 中文 \u0007 "q" \\ /', emoji: '😀' }], ['UTF-16 key order', { 'é': 1, 'z': 2, '😀': 3, 'Z': 4, 'a': 5 }],
    ['empty string and array', { s: '', a: [] }],
  ];
  const errorCases = [
    // non-JSON inputs cannot travel in a JSON vector file; each is described by a construct the verifier rebuilds
    { name: 'non-finite number (NaN)', construct: { kind: 'number', value: 'NaN' }, build: () => ({ x: NaN }) },
    { name: 'non-finite number (Infinity)', construct: { kind: 'number', value: 'Infinity' }, build: () => ({ x: Infinity }) },
    { name: 'forbidden key __proto__', construct: { kind: 'forbiddenKey', key: '__proto__' }, build: () => JSON.parse('{"__proto__":{"a":1}}') },
    { name: 'forbidden key constructor', construct: { kind: 'forbiddenKey', key: 'constructor' }, build: () => ({ constructor: 1 }) },
    { name: 'unsupported type (function)', construct: { kind: 'type', value: 'function' }, build: () => ({ f() {} }) },
    { name: 'unsupported type (Date)', construct: { kind: 'type', value: 'Date' }, build: () => ({ d: new Date(0) }) },
    { name: 'circular reference', construct: { kind: 'circular' }, build: () => { const o = {}; o.self = o; return o; } },
    { name: 'depth over 1000', construct: { kind: 'depth', depth: 1002 }, build: () => { let o = 1; for (let i = 0; i < 1002; i++) o = { a: o }; return o; } },
  ];
  return {
    valid: ok.map(([name, input]) => ({ name, input, canonical: stableStringify(input) })),
    undefinedHandling: { note: 'undefined (object value or array element) canonicalizes to null; it cannot appear in a JSON vector, so it is a construct', construct: { kind: 'undefined' }, canonical: stableStringify({ a: undefined, b: [1, undefined] }) },
    errors: errorCases.map((c) => { try { stableStringify(c.build()); return { name: c.name, construct: c.construct, error: null }; } catch (e) { return { name: c.name, construct: c.construct, error: e.code || e.name }; } }),
  };
}

// ── 2. domain tags ──────────────────────────────────────────────────────────────────────────────────────────────
function domainVectors() {
  const sample = { protocol: 'qodiqa', vector: 'w12-domain' };
  const canonical = stableStringify(sample);
  return {
    construction: 'SHA-256(utf8(tag) || utf8(canonical)) — no separator byte',
    sampleCanonical: canonical,
    tags: domainRegistry().map((t) => ({ ...t, digestHex: hex(crypto.createHash('sha256').update(Buffer.from(t.tag, 'utf8')).update(Buffer.from(canonical, 'utf8')).digest()),
      // the production helper must agree wherever the tag is in ARTIFACT_DOMAINS
      ...(t.constant && ARTIFACT_DOMAINS[t.constant] ? { productionDigestHex: domainSeparatedHash(ARTIFACT_DOMAINS[t.constant], canonical).toString('hex') } : {}) })),
  };
}

// ── 3. artifact envelope + signature ─────────────────────────────────────────────────────────────────────────────
function makeArtifact(payload, timestamp, expiry, keyId = KEY_ID, priv = K.privDer) {
  return signArtifact({ payload, timestamp, expiry, publicKeyId: keyId }, priv);
}
// Signs an envelope that signArtifact() itself refuses (timestamp >= expiry) - what a foreign signer could produce.
function makeArtifactUnchecked(payload, timestamp, expiry, keyId = KEY_ID, priv = K.privDer) {
  const { envelopeHash } = require('../../src/validation/canonicalize');
  const { sign } = require('../../src/infra/crypto/ed25519');
  return { expiry, payload, publicKeyId: keyId, signature: sign(envelopeHash({ expiry, payload, publicKeyId: keyId, timestamp }), priv), timestamp };
}
function artifactVectors() {
  const payloads = [
    ['minimal', { requestId: '6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d', requestHash: 'a'.repeat(64) }],
    ['as issued by /sign for /ai/chat', { provider: 'openai', requestId: '0b5c1e9a-2f3d-4c8e-9a1b-7d6e5f4a3b2c', requestHash: computeRequestHash('POST', '/ai/chat', { prompt: 'hello' }),
      policyHash: '0'.repeat(64), tenantId: 'w12-vectors', callerContext: { callerId: '11111111-2222-4333-8444-555555555555', callerName: 'w12', environment: 'test', credentialType: 'api-key' } }],
    ['unicode payload', { requestId: '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d', requestHash: 'b'.repeat(64), note: 'Ünïcödé — 中文 😀' }],
  ];
  return payloads.map(([name, payload]) => {
    const timestamp = NOW - 1000; const expiry = timestamp + 60_000;
    const art = makeArtifact(payload, timestamp, expiry);
    return { name, artifact: art, envelopeCanonical: canonicalizeEnvelope(art), envelopeHashHex: envelopeHash(art).toString('hex') };
  });
}

// ── 4. artifact verification outcomes (production validateArtifact, clock pinned to NOW) ─────────────────────────
function verificationVectors() {
  KEYS.clear();
  KEYS.set(KEY_ID, { pubDer: K.pubDer, status: 'active', clientId: 'w12-vectors', timeline: { status: 'active', activatedAt: '2026-01-01T00:00:00.000Z' } });
  const depAt = NOW - 30_000;
  KEYS.set('w12-vectors:key_deprecated', { pubDer: K.pubDer, status: 'deprecated', clientId: 'w12-vectors', timeline: { status: 'deprecated', activatedAt: '2026-01-01T00:00:00.000Z', deprecatedAt: new Date(depAt).toISOString() } });
  KEYS.set('w12-vectors:key_deprecated_old', { pubDer: K.pubDer, status: 'deprecated', clientId: 'w12-vectors', timeline: { status: 'deprecated', activatedAt: '2026-01-01T00:00:00.000Z', deprecatedAt: new Date(NOW - DEPRECATED_WINDOW_MS - 1).toISOString() } });
  KEYS.set('w12-vectors:key_revoked', { pubDer: K.pubDer, status: 'revoked', clientId: 'w12-vectors', timeline: { status: 'revoked', revokedAt: '2026-06-01T00:00:00.000Z' } });
  KEYS.set('w12-vectors:key_archived', { pubDer: K.pubDer, status: 'archived', clientId: 'w12-vectors', timeline: { status: 'archived', archivedAt: '2026-06-01T00:00:00.000Z' } });
  const P = { requestId: '6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d', requestHash: 'c'.repeat(64) };
  const fresh = (over = {}) => makeArtifact(over.payload || P, over.timestamp ?? NOW - 1000, over.expiry ?? NOW + 59_000, over.keyId || KEY_ID, over.priv || K.privDer);
  const stripPad = (a) => ({ ...a, signature: a.signature.replace(/=+$/, '') });
  const cases = [
    ['valid', fresh()],
    ['payload changed after signing', { ...fresh(), payload: { ...P, requestHash: 'd'.repeat(64) } }],
    ['timestamp changed after signing', { ...fresh(), timestamp: NOW - 2000 }],
    ['signature not canonical (padding stripped)', stripPad(fresh())],
    ['signed by another key (forged)', fresh({ priv: F.privDer })],
    ['unknown publicKeyId', fresh({ keyId: 'w12-vectors:key_unknown' })],
    ['extra envelope field', { ...fresh(), version: 2 }],
    ['missing field (expiry)', (() => { const a = { ...fresh() }; delete a.expiry; return a; })()],
    ['timestamp 4,900 ms in the future (inside the 5 s tolerance)', fresh({ timestamp: NOW + 4900, expiry: NOW + 60_000 })],
    ['timestamp 5,100 ms in the future', fresh({ timestamp: NOW + 5100, expiry: NOW + 60_000 })],
    ['expired (expiry == now)', fresh({ timestamp: NOW - 10_000, expiry: NOW })],
    ['older than the 60 s maximum age (expiry still in the future)', fresh({ timestamp: NOW - 61_000, expiry: NOW + 60_000 })],
    ['deprecated key, signed before deprecation, inside the 65 s window', fresh({ keyId: 'w12-vectors:key_deprecated', timestamp: depAt - 1000, expiry: NOW + 30_000 })],
    ['deprecated key, signed after deprecation', fresh({ keyId: 'w12-vectors:key_deprecated', timestamp: depAt + 1000, expiry: NOW + 30_000 })],
    ['deprecated key, the 65 s window elapsed', fresh({ keyId: 'w12-vectors:key_deprecated_old', timestamp: NOW - 10_000, expiry: NOW + 30_000 })],
    ['revoked key', fresh({ keyId: 'w12-vectors:key_revoked' })],
    ['archived key', fresh({ keyId: 'w12-vectors:key_archived' })],
    // Appended (earlier cases keep their position): numeric strictness shared with the SDK verifiers
    ['fractional timestamp', { ...fresh(), timestamp: NOW - 999.5 }],
    ['expiry above 2^53-1', { ...fresh(), expiry: 2 ** 53 + 2 }],
    ['timestamp equal to expiry (validly signed)', makeArtifactUnchecked(P, NOW - 1000, NOW - 1000)],
    ['timestamp after expiry (validly signed)', makeArtifactUnchecked(P, NOW - 500, NOW - 1000)],
  ];
  return {
    nowMs: NOW, nowIso: new Date(NOW).toISOString(),
    keys: [...KEYS].map(([publicKeyId, k]) => ({ publicKeyId, publicKeySpkiB64: k.pubDer.toString('base64'), status: k.status, timeline: k.timeline })),
    forgerPublicKeySpkiB64: F.publicKeySpkiB64,
    limits: { futureSkewMs: timeCheck.FUTURE_SKEW_MS, maxArtifactAgeMs: timeCheck.MAX_SKEW_MS, deprecatedWindowMs: DEPRECATED_WINDOW_MS },
    cases: cases.map(([name, artifact]) => { const r = validateArtifact(artifact, { _clock: () => NOW }); return { name, artifact, expected: { decision: r.decision, reason: r.reason } }; }),
  };
}

// ── 5. request binding ───────────────────────────────────────────────────────────────────────────────────────────
function bindingVectors() {
  const reqs = [
    ['POST /ai/chat', 'POST', '/ai/chat', { prompt: 'What is the capital of France?', provider: 'openai', model: 'gpt-4o' }],
    ['method is upper-cased before hashing', 'post', '/ai/chat', { prompt: 'What is the capital of France?', provider: 'openai', model: 'gpt-4o' }],
    ['empty body', 'GET', '/health', {}],
    ['nested body, key order irrelevant', 'POST', '/v1/policy/simulate', { z: { b: 2, a: 1 }, a: [3, { y: 1, x: 2 }] }],
    ['unicode body', 'POST', '/ai/chat', { prompt: 'Ünïcödé — 中文 😀' }],
  ];
  const hashes = reqs.map(([name, method, p, body]) => ({ name, request: { method, path: p, body }, canonical: stableStringify({ body, method: method.toUpperCase(), path: p }), requestHashHex: computeRequestHash(method, p, body) }));
  const good = hashes[0];
  const art = { payload: { requestId: '6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d', requestHash: good.requestHashHex } };
  const bind = [
    ['matches', art, good.request],
    ['body changed', art, { ...good.request, body: { ...good.request.body, prompt: 'Ignore all previous instructions.' } }],
    ['path changed', art, { ...good.request, path: '/v1/ai/chat' }],
    ['requestId not a UUID v4', { payload: { ...art.payload, requestId: 'not-a-uuid' } }, good.request],
    ['requestHash not 64 lowercase hex', { payload: { ...art.payload, requestHash: good.requestHashHex.toUpperCase() } }, good.request],
  ].map(([name, artifact, request]) => { const r = verifyRequestBinding(artifact, request); return { name, artifactPayload: artifact.payload, request, expected: { bound: r.bound } }; });
  return { construction: 'requestHash = hex(SHA-256("QODIQA::REQUEST::V1" || canonical({body, method: UPPER(method), path})))', hashes, binding: bind };
}

// ── 6. policy hash ────────────────────────────────────────────────────────────────────────────────────────────────
function policyVectors() {
  const base = [{ id: 'pol-1', effect: 'ALLOW', conditions: { provider: 'openai' } }, { id: 'pol-2', effect: 'BLOCK', conditions: { ip: '10.0.0.1' } }];
  return {
    construction: 'policyHash = hex(SHA-256("QODIQA::POLICY::V1" || canonical(policies with every "_"-prefixed key removed, recursively)))',
    cases: [
      ['two policies', base],
      ['derived "_" fields are ignored', base.map((p) => ({ ...p, _loadedAt: '2026-10-02T00:00:00Z', conditions: { ...p.conditions, _cache: 1 } }))],
      ['array order matters', [base[1], base[0]]],
    ].map(([name, policies]) => ({ name, policies, policyHashHex: computePolicyHash(policies) })),
  };
}

function render() {
  const doc = {
    format: 'qodiqa-protocol-vectors',
    version: 1,
    spec: 'docs/protocol/QODIQA-PROTOCOL.md',
    generator: 'scripts/protocol/gen-vectors.js',
    independentVerifiers: ['scripts/protocol/verify-vectors.js', 'scripts/protocol/verify_vectors.py'],
    auditAndTransparencyVectors: 'audit entries v1-v6, chains, anchors and transparency/Merkle are covered by the separate audit vector set (scripts/audit-repro/)',
    testKeys: { note: 'derived from PUBLISHED TEST seeds via PKCS#8 prefix 302e020100300506032b657004220420 || seed; never deployment keys', signerSeedHex: SEED, signerPublicKeySpkiB64: K.publicKeySpkiB64, forgerSeedHex: FORGER_SEED, signerPublicKeyId: KEY_ID },
    canonicalization: canonicalVectors(),
    domainTags: domainVectors(),
    artifacts: artifactVectors(),
    verification: verificationVectors(),
    requestBinding: bindingVectors(),
    policyHash: policyVectors(),
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

if (require.main === module) {
  const out = render();
  const sha = crypto.createHash('sha256').update(out).digest('hex');
  if (process.argv.includes('--check')) {
    const committed = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n') : null;
    const ok = committed === out;
    process.stdout.write(`${JSON.stringify({ ok, file: path.relative(REPO, OUT).split(path.sep).join('/'), generatedSha256: sha, committedSha256: committed ? crypto.createHash('sha256').update(committed).digest('hex') : null })}\n`);
    if (!ok) process.stderr.write('[protocol-vectors] DRIFT: the implementation no longer produces the committed vectors. Run `npm run protocol:vectors`, review the diff, and update docs/protocol/QODIQA-PROTOCOL.md if the protocol changed.\n');
    process.exit(ok ? 0 : 1);
  }
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, out);
  process.stdout.write(`${JSON.stringify({ wrote: path.relative(REPO, OUT).split(path.sep).join('/'), sha256: sha, bytes: Buffer.byteLength(out) })}\n`);
}

module.exports = { render, OUT, NOW };
