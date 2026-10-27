'use strict';

/**
 * QODIQA Evidence Bundle — Standalone Offline Verifier
 *
 * Verifies a QODIQA::EVIDENCE_BUNDLE::V1 bundle (as downloaded from
 * GET /evidence/package/:artifactId/bundle) using the data inside the bundle
 * plus TRUST ANCHORS you supply (the QODIQA instance's published seal and
 * transparency key sets). No network calls, no database, no QODIQA source imports —
 * this file has zero dependencies beyond Node's built-in `crypto` module, so
 * it can be copied out of this repository and run standalone by any
 * external auditor, regulator, customer, or forensic investigator, with no
 * running QODIQA instance, no transparency service, and no external APIs.
 *
 * A bundle combines two previously-separate things this repo's other
 * standalone verifiers each cover on their own:
 *
 *   1. An evidence package (tools/verify/verify.evidence.external.js's job) — proving the
 *      recorded decision itself is authentic and unaltered: packageHash
 *      self-consistency, an Ed25519 seal signature, and the underlying
 *      audit-chain entry's protected hash.
 *   2. A Merkle inclusion proof (previously only checkable via a live
 *      GET /transparency/proof/:id call, or by importing
 *      src/core/transparency/merkle.js) — proving the decision was actually
 *      entered into QODIQA's published, tamper-evident RFC6962 transparency
 *      log, not merely recorded in a package that could in principle be
 *      generated without ever publishing it anywhere externally checkable.
 *
 * Neither proof on its own establishes that they belong together — an
 * attacker who could get one validly-signed evidence package and one
 * validly-signed (but unrelated) inclusion proof could otherwise splice them
 * into a single bundle and have both individual checks pass. This is why
 * generateEvidenceBundle() (src/core/evidence/generator.js) adds one more
 * Ed25519 seal over the combined { evidencePackage, transparency } content —
 * check 4 below — binding the two together as one attested unit.
 *
 * Usage:
 *   node tools/verify/verify.bundle.external.js --keys qodiqa-keys.json \
 *        --transparency-keys qodiqa-transparency-keys.json <evidence-bundle.json>
 *   (--pin <spki-sha256-hex> may replace --keys.) The key sets come from
 *   GET /.well-known/qodiqa/keys and GET /.well-known/qodiqa/transparency-keys, obtained over a
 *   channel you trust — never from the bundle. Exit 0 = valid, 1 = not valid, 2 = input error.
 */

const crypto = require('crypto');
const fs     = require('fs');

// ── Canonical serialization (mirrors src/utils/stableStringify.js) ───────────

// this standalone copy is CONFORMANT with the server's canonicalizer
// (src/utils/stableStringify.js, docs/protocol/QODIQA-PROTOCOL.md §3): JSON string escaping (control characters,
// lone surrogates), JS number formatting, keys sorted by UTF-16 code units, undefined → null, and the same refusals
// (non-finite number, unsupported type, forbidden key). It stays dependency-free so this file can be copied out and run
// alone; test/externalVerifierCanonicalConformance.test.js holds every copy to the server output.
const _FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function _encodeString(str) {
  return JSON.stringify(str);
}

function stableStringify(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('NON_FINITE_NUMBER');
    return JSON.stringify(value);
  }
  if (typeof value === 'string')  return _encodeString(value);
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  if (typeof value === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== null && proto !== Object.prototype) throw new Error('UNSUPPORTED_TYPE');
    const keys = Object.keys(value);
    for (const k of keys) if (_FORBIDDEN_KEYS.has(k)) throw new Error('FORBIDDEN_KEY');
    return '{' + keys.sort()
      .map(k => _encodeString(k) + ':' + stableStringify(value[k]))
      .join(',') + '}';
  }
  throw new Error('UNSUPPORTED_TYPE');
}

// ── Hashing (mirrors src/infra/crypto/hashing.js) ─────────────────────────────

function domainSeparatedHash(domain, canonical) {
  return crypto.createHash('sha256').update(domain, 'utf8').update(canonical, 'utf8').digest();
}

function canonicalHash(obj) {
  return crypto.createHash('sha256').update(stableStringify(obj), 'utf8').digest('hex');
}

const EVIDENCE_DOMAIN = 'QODIQA::EVIDENCE::V1';
const AUDIT_DOMAIN     = 'QODIQA::AUDIT::V1';
const BUNDLE_DOMAIN    = 'QODIQA::EVIDENCE_BUNDLE::V1';

// ── Ed25519 verification (mirrors src/infra/crypto/ed25519.js) ───────────────

function verifyEd25519(hashBuffer, signatureBase64, publicKeyBase64) {
  try {
    const sigBuf = Buffer.from(signatureBase64, 'base64');
    if (sigBuf.length !== 64) return false;
    const pubDer = Buffer.from(publicKeyBase64, 'base64');
    const pubKey = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
    return crypto.verify(null, hashBuffer, pubKey, sigBuf);
  } catch {
    return false;
  }
}

// ── RFC6962 Merkle verification (mirrors src/core/transparency/merkle.js) ────
//
// Pure, self-contained reimplementation of just the two primitives an
// offline inclusion-proof verifier needs (leafHash/nodeHash + path
// reconstruction) — NOT the full merkle.js (tree construction, consistency
// proofs, etc. are irrelevant to verifying a single already-generated proof
// and would just be more surface a standalone auditor has to trust/audit).

const _MERKLE_LEAF_PREFIX = Buffer.from([0x00]);
const _MERKLE_NODE_PREFIX = Buffer.from([0x01]);

function _merkleLeafHash(entryHashHex) {
  return crypto.createHash('sha256')
    .update(_MERKLE_LEAF_PREFIX)
    .update(Buffer.from(entryHashHex, 'hex'))
    .digest();
}

function _merkleNodeHash(leftBuf, rightBuf) {
  return crypto.createHash('sha256')
    .update(_MERKLE_NODE_PREFIX)
    .update(leftBuf)
    .update(rightBuf)
    .digest();
}

// the RFC6962 side sequence (deepest first) of leaf `leafIndex` in a `treeSize`-leaf tree — a
// path is accepted only if it has exactly these sides, which binds the proof to its claimed position (the same
// decomposition src/core/transparency/merkle.js inclusionPath() walks). null for an invalid (index, size) pair.
function expectedPathSides(leafIndex, treeSize) {
  if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize) || leafIndex < 0 || leafIndex >= treeSize) return null;
  const sides = []; let size = treeSize; let idx = leafIndex;
  while (size > 1) {
    let k = 1; while (k * 2 < size) k *= 2;   // largest power of two < size
    if (idx < k) { sides.push('right'); size = k; } else { sides.push('left'); idx -= k; size -= k; }
  }
  return sides.reverse();
}

// Rebuilds the Merkle root from a leaf's entry hash and its O(log n) sibling
// path, then compares against the expected root — same algorithm as
// merkle.js's verifyInclusionPath(), position-bound.
function verifyMerkleInclusionPath(entryHashHex, path, expectedRootHex, leafIndex, treeSize) {
  if (!entryHashHex || !Array.isArray(path) || !expectedRootHex) return false;
  const sides = expectedPathSides(leafIndex, treeSize);
  if (!sides || path.length !== sides.length || path.some((st, i) => !st || st.side !== sides[i])) return false;

  let current = _merkleLeafHash(entryHashHex);
  for (const { hash, side } of path) {
    const sibBuf = Buffer.from(hash, 'hex');
    current = side === 'right'
      ? _merkleNodeHash(current, sibBuf)
      : _merkleNodeHash(sibBuf, current);
  }
  return current.toString('hex') === expectedRootHex;
}

// ── Evidence package content reconstruction (mirrors generator.js) ───────────

function packageContent(pkg) {
  const content = {
    artifactId:   pkg.artifactId,
    generatedAt:  pkg.generatedAt,
    artifact:     pkg.sections.artifact,
    policy:       pkg.sections.policy,
    key:          pkg.sections.key,
    verification: pkg.sections.verification,
    audit:        pkg.sections.audit,
  };
  if (pkg.sections.consent !== undefined) content.consent = pkg.sections.consent;
  if (pkg.sections.caller  !== undefined) content.caller  = pkg.sections.caller;
  return content;
}

// ── Bundle content reconstruction (mirrors generator.js's _bundleContent) ────

function bundleContent(bundle) {
  return {
    schema:          bundle.schema,
    generatedAt:     bundle.generatedAt,
    artifactId:      bundle.artifactId,
    evidencePackage: bundle.evidencePackage,
    transparency:    bundle.transparency,
  };
}

// ──: trust anchors ─────────────────────
//
// every seal in a bundle was verified with the public key the BUNDLE ITSELF carried,
// and the transparency "inclusion proof" was a Merkle path checked against a root taken from the
// same untrusted proof, with no signature check at all: a bundle fabricated with
// no QODIQA key verified "valid". Authenticity now requires trust anchors obtained out of band:
//   --keys <file>               GET /.well-known/qodiqa/keys              (evidence + bundle seals)
//   --pin  <hex>                SHA-256 of a trusted seal key's SPKI DER
//   --transparency-keys <file>  GET /.well-known/qodiqa/transparency-keys (entry + root signatures)
// Without them `valid` is false; internal consistency is still reported, labelled as such.
// Inlined (same code as tools/verify/verify.evidence.external.js) because this file is designed to run alone.

function spkiFingerprint(publicKeyB64) {
  return crypto.createHash('sha256').update(Buffer.from(String(publicKeyB64 || ''), 'base64')).digest('hex');
}

function buildTrustSet({ keys = [], pins = [] } = {}) {
  const list = Array.isArray(keys) ? keys : (keys && Array.isArray(keys.keys) ? keys.keys : []);
  return {
    keys: list.filter((k) => k && typeof k.publicKey === 'string')
      .map((k) => ({ keyId: k.keyId ?? null, publicKey: k.publicKey, status: k.status ?? 'active', fingerprint: spkiFingerprint(k.publicKey) })),
    pins: new Set((pins || []).map((p) => String(p).toLowerCase().replace(/[^0-9a-f]/g, '')).filter((p) => p.length === 64)),
  };
}

const REVOKED_STATUSES = new Set(['revoked', 'compromised']);

function resolveTrustedKey(trust, keyId, embeddedPublicKey) {
  if (!trust || (trust.keys.length === 0 && trust.pins.size === 0)) {
    return { ok: false, reason: 'TRUST_ANCHOR_REQUIRED: supply --keys <published key set> or --pin <spki-sha256>; keys embedded in the bundle cannot authenticate it' };
  }
  const embeddedFp = embeddedPublicKey ? spkiFingerprint(embeddedPublicKey) : null;
  let match = null;
  if (keyId) match = trust.keys.find((k) => k.keyId === keyId) || null;
  if (!match && embeddedFp) match = trust.keys.find((k) => k.fingerprint === embeddedFp) || null;
  if (match) {
    if (embeddedFp && embeddedFp !== match.fingerprint) return { ok: false, reason: `KEY_MISMATCH: names key ${keyId} but embeds different key material` };
    if (REVOKED_STATUSES.has(String(match.status).toLowerCase())) return { ok: false, reason: `KEY_REVOKED: trusted key ${match.keyId} has status ${match.status}` };
    return { ok: true, publicKey: match.publicKey, anchor: 'keys', keyId: match.keyId, fingerprint: match.fingerprint };
  }
  if (embeddedFp && trust.pins.has(embeddedFp)) return { ok: true, publicKey: embeddedPublicKey, anchor: 'pin', keyId: keyId ?? null, fingerprint: embeddedFp };
  return { ok: false, reason: `UNTRUSTED_KEY: ${keyId ? `key ${keyId} / ` : ''}fingerprint ${embeddedFp || '(none)'} is not in the trust set` };
}

// ── Transparency entry / root hashing (mirrors scripts/audit-repro/verify/transparency.js) ──
const TRANSPARENCY_ENTRY_DOMAIN = 'QODIQA::TRANSPARENCY::V1';
const TRANSPARENCY_ROOT_DOMAIN  = 'QODIQA::TRANSPARENCY_ROOT::V1';
const ENTRY_FIELDS = ['transparencyId', 'entryType', 'artifactId', 'evidenceChainId', 'verificationId', 'payloadHash', 'previousEntryHash', 'signerKeyId'];
const ROOT_FIELDS  = ['rootId', 'seqFrom', 'seqTo', 'entryCount', 'rootHash', 'previousRootHash'];

function transparencyEntryHash(entry) {
  const o = {}; for (const f of ENTRY_FIELDS) o[f] = entry[f] ?? null;
  return domainSeparatedHash(TRANSPARENCY_ENTRY_DOMAIN, stableStringify(o)).toString('hex');
}
function transparencyRootDigest(root) {
  const num = (v) => (v === undefined || v === null ? null : Number(v));
  const o = {
    rootId: root.rootId ?? null, seqFrom: num(root.seqFrom), seqTo: num(root.seqTo), entryCount: root.entryCount ?? null,
    rootHash: root.rootHash ?? null, previousRootHash: root.previousRootHash ?? null,
  };
  return domainSeparatedHash(TRANSPARENCY_ROOT_DOMAIN, stableStringify(o));
}

/** Verify a proofVersion-2 inclusion proof against TRUSTED transparency keys and bind it to artifactId. */
function verifyTransparencyProof(proof, artifactId, transparencyTrust) {
  const reasons = [];
  if (!proof || !proof.entry || !proof.root || !proof.proof) return { valid: false, reasons: ['TRANSPARENCY_PROOF_MALFORMED'] };
  const { entry, root } = proof; const p = proof.proof;
  const leafIndex = Number(p.leafIndex); const treeSize = Number(p.treeSize);
  if (!(Number.isInteger(leafIndex) && Number.isInteger(treeSize) && leafIndex >= 0 && leafIndex < treeSize)) reasons.push('TRANSPARENCY_LEAF_INDEX_OUT_OF_RANGE');
  if (root.entryCount !== undefined && root.entryCount !== null && Number(root.entryCount) !== treeSize) reasons.push('TRANSPARENCY_TREE_SIZE_MISMATCH: proof.treeSize differs from the signed root entryCount');
  const maxDepth = treeSize > 1 ? Math.ceil(Math.log2(treeSize)) : 0;
  if (!Array.isArray(p.merklePath) || p.merklePath.length > maxDepth) reasons.push('TRANSPARENCY_PATH_LENGTH_INVALID');
  if (transparencyEntryHash(entry) !== entry.entryHash) reasons.push('TRANSPARENCY_ENTRY_HASH_MISMATCH: entryHash does not cover the entry fields');
  if (!verifyMerkleInclusionPath(entry.entryHash, p.merklePath, root.rootHash, leafIndex, treeSize)) reasons.push('TRANSPARENCY_MERKLE_PATH_INVALID');
  if (p.merkleRoot !== undefined && p.merkleRoot !== root.rootHash) reasons.push('TRANSPARENCY_ROOT_HASH_MISMATCH');
  // Binding: the leaf must be registered for THIS artifact (a DECISION leaf under the request id, lifecycle leaves suffixed).
  const ea = String(entry.artifactId ?? '');
  if (!(ea === artifactId || ea.startsWith(`${artifactId}:`))) reasons.push(`TRANSPARENCY_ENTRY_NOT_BOUND: leaf artifactId ${ea || '(none)'} does not name artifact ${artifactId}`);
  // Signatures — only with trusted transparency keys; the proof carries no key material of its own.
  const ek = resolveTrustedKey(transparencyTrust, entry.signerKeyId, null);
  if (!ek.ok) reasons.push(`TRANSPARENCY_ENTRY_KEY: ${ek.reason}`);
  else if (!verifyEd25519(Buffer.from(String(entry.entryHash), 'hex'), entry.signature, ek.publicKey)) reasons.push('TRANSPARENCY_ENTRY_SIGNATURE_INVALID');
  const rk = resolveTrustedKey(transparencyTrust, root.signerKeyId, null);
  if (!rk.ok) reasons.push(`TRANSPARENCY_ROOT_KEY: ${rk.reason}`);
  else if (!verifyEd25519(transparencyRootDigest(root), root.signature, rk.publicKey)) reasons.push('TRANSPARENCY_ROOT_SIGNATURE_INVALID');
  return { valid: reasons.length === 0, reasons };
}

// ── Nested evidence-package verification (mirrors tools/verify/verify.evidence.external.js) ─

function verifyEvidencePackage(pkg, opts = {}) {
  const trust = opts.trust || buildTrustSet({ keys: opts.trustedKeys, pins: opts.pins });
  const result = { packageHashValid: false, signatureValid: null, selfConsistentSignature: null, chainHashValid: null, trust: null, valid: false, reasons: [] };

  if (!pkg || typeof pkg !== 'object' || !pkg.sections || !pkg.integrity) {
    result.reasons.push('MALFORMED_PACKAGE: missing sections or integrity block');
    return result;
  }

  const content      = packageContent(pkg);
  const computedHash = canonicalHash(content);
  result.packageHashValid = computedHash === pkg.integrity.packageHash;
  if (!result.packageHashValid) {
    result.reasons.push(`PACKAGE_HASH_MISMATCH: expected ${pkg.integrity.packageHash}, computed ${computedHash}`);
  }

  const { signature, publicKey, domain, keyId } = pkg.integrity;
  if (domain !== undefined && domain !== null && domain !== EVIDENCE_DOMAIN) {
    result.signatureValid = false;
    result.reasons.push(`DOMAIN_MISMATCH: package declares ${domain}, evidence seals use ${EVIDENCE_DOMAIN}`);
  } else if (signature && publicKey) {
    const hashBuf = domainSeparatedHash(EVIDENCE_DOMAIN, stableStringify(content));
    result.selfConsistentSignature = verifyEd25519(hashBuf, signature, publicKey);
    const tk = resolveTrustedKey(trust, keyId, publicKey);
    result.trust = tk.ok ? { anchor: tk.anchor, keyId: tk.keyId, fingerprint: tk.fingerprint } : { anchor: null, error: tk.reason };
    if (!tk.ok) { result.signatureValid = false; result.reasons.push(tk.reason); }
    else {
      result.signatureValid = verifyEd25519(hashBuf, signature, tk.publicKey);
      if (!result.signatureValid) result.reasons.push('SIGNATURE_INVALID');
    }
  } else {
    result.reasons.push('SIGNATURE_UNAVAILABLE: package was not sealed at generation time');
  }

  const art = pkg.sections.artifact;
  if (art && art.chainHashDomain !== undefined && art.chainHashDomain !== null && !/^QODIQA::AUDIT::V\d+$/.test(art.chainHashDomain)) {
    result.chainHashValid = false;
    result.reasons.push(`CHAIN_DOMAIN_INVALID: ${art.chainHashDomain} is not an audit-chain domain`);
  } else if (art && art.canonical && art.chainHash) {
    const computedChainHash = domainSeparatedHash(art.chainHashDomain || AUDIT_DOMAIN, art.canonical).toString('hex');
    result.chainHashValid = computedChainHash === art.chainHash;
    if (!result.chainHashValid) {
      result.reasons.push(`CHAIN_HASH_MISMATCH: expected ${art.chainHash}, computed ${computedChainHash}`);
    }
  }

  result.valid = result.packageHashValid && result.signatureValid === true && result.chainHashValid !== false;
  return result;
}

// ── Main bundle verification logic ────────────────────────────────────────────

/**
 * @param {object} bundle
 * @param {{ trust?: object, transparencyTrust?: object, trustedKeys?, pins?, transparencyKeys? }} [opts]
 *   trust: seal trust set (evidence + bundle seals). transparencyTrust: transparency key set.
 *   Both REQUIRED for valid:true (transparencyTrust only when the bundle carries a proof).
 */
function verifyEvidenceBundle(bundle, opts = {}) {
  const trust = opts.trust || buildTrustSet({ keys: opts.trustedKeys, pins: opts.pins });
  const transparencyTrust = opts.transparencyTrust || buildTrustSet({ keys: opts.transparencyKeys });
  const result = {
    bundleHashValid:        false,
    bundleSignatureValid:   null,
    selfConsistentBundleSignature: null,
    packageValid:           false,
    transparencyProofValid: null,
    trust:                  null,
    valid:                  false,
    reasons:                [],
  };

  if (!bundle || typeof bundle !== 'object' || !bundle.evidencePackage || !bundle.integrity) {
    result.reasons.push('MALFORMED_BUNDLE: missing evidencePackage or integrity block');
    return result;
  }

  // 1. Bundle envelope hash — recompute SHA-256 of the canonical envelope content.
  const content            = bundleContent(bundle);
  const computedBundleHash = canonicalHash(content);
  result.bundleHashValid = computedBundleHash === bundle.integrity.bundleHash;
  if (!result.bundleHashValid) {
    result.reasons.push(`BUNDLE_HASH_MISMATCH: expected ${bundle.integrity.bundleHash}, computed ${computedBundleHash}`);
  }

  // 2. Bundle envelope Ed25519 seal — binds package + transparency proof as one unit; trusted key only.
  const { signature, publicKey, domain, keyId } = bundle.integrity;
  if (domain !== undefined && domain !== null && domain !== BUNDLE_DOMAIN) {
    result.bundleSignatureValid = false;
    result.reasons.push(`DOMAIN_MISMATCH: bundle declares ${domain}, bundle seals use ${BUNDLE_DOMAIN}`);
  } else if (signature && publicKey) {
    const hashBuf = domainSeparatedHash(BUNDLE_DOMAIN, stableStringify(content));
    result.selfConsistentBundleSignature = verifyEd25519(hashBuf, signature, publicKey);
    const tk = resolveTrustedKey(trust, keyId, publicKey);
    result.trust = tk.ok ? { anchor: tk.anchor, keyId: tk.keyId, fingerprint: tk.fingerprint } : { anchor: null, error: tk.reason };
    if (!tk.ok) { result.bundleSignatureValid = false; result.reasons.push(tk.reason); }
    else {
      result.bundleSignatureValid = verifyEd25519(hashBuf, signature, tk.publicKey);
      if (!result.bundleSignatureValid) result.reasons.push('BUNDLE_SIGNATURE_INVALID');
    }
  } else {
    result.reasons.push('BUNDLE_SIGNATURE_UNAVAILABLE: bundle was not sealed at generation time');
  }

  // 3. Nested evidence package — same trust set; must name the same artifact as the bundle.
  const packageResult = verifyEvidencePackage(bundle.evidencePackage, { trust });
  result.packageValid = packageResult.valid;
  if (!packageResult.valid) {
    result.reasons.push('EVIDENCE_PACKAGE_INVALID', ...packageResult.reasons.map(r => `  package: ${r}`));
  }
  if (bundle.evidencePackage && bundle.evidencePackage.artifactId !== bundle.artifactId) {
    result.packageValid = false;
    result.reasons.push('ARTIFACT_ID_MISMATCH: bundle and nested package name different artifacts');
  }

  // 4. Transparency inclusion — signed entry + signed root, bound to this artifact.
  if (bundle.transparency && bundle.transparency.available) {
    const t = verifyTransparencyProof(bundle.transparency.inclusionProof, bundle.artifactId, transparencyTrust);
    result.transparencyProofValid = t.valid;
    result.reasons.push(...t.reasons);
  }

  result.valid = result.bundleHashValid
    && result.bundleSignatureValid === true
    && result.packageValid
    && result.transparencyProofValid !== false;

  return result;
}

// ── CLI entry point ───────────────────────────────────────────────────────────

function _readStdin() {
  return fs.readFileSync(0, 'utf8');
}

/** `[--keys <file>]... [--pin <hex>]... [--transparency-keys <file>]... [bundle-file]` */
function parseCliArgs(argv) {
  const keys = []; const pins = []; const tkeys = []; let filePath = null;
  const load = (f) => { const k = JSON.parse(fs.readFileSync(f, 'utf8')); return Array.isArray(k) ? k : (k.keys || []); };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--keys') keys.push(...load(argv[++i]));
    else if (argv[i] === '--pin') pins.push(argv[++i]);
    else if (argv[i] === '--transparency-keys') tkeys.push(...load(argv[++i]));
    else if (!filePath) filePath = argv[i];
  }
  return { filePath, trust: buildTrustSet({ keys, pins }), transparencyTrust: buildTrustSet({ keys: tkeys }) };
}

if (require.main === module) {
  let filePath; let trust; let transparencyTrust;
  try {
    ({ filePath, trust, transparencyTrust } = parseCliArgs(process.argv.slice(2)));
  } catch (err) {
    process.stderr.write(`Error reading trust anchors: ${err.message}\n`);
    process.exit(2);
  }

  let raw;
  try {
    raw = filePath ? fs.readFileSync(filePath, 'utf8') : _readStdin();
  } catch (err) {
    process.stderr.write(`Error reading input: ${err.message}\n`);
    process.exit(2);
  }

  let bundle;
  try {
    const parsed = JSON.parse(raw);
    // Accept both the raw bundle and the standard API envelope
    // ({ status, data: <bundle> }) returned by GET /evidence/package/:id/bundle.
    bundle = parsed && parsed.data && parsed.data.schema ? parsed.data : parsed;
  } catch {
    process.stderr.write('Error: input is not valid JSON\n');
    process.exit(1);
  }

  const result = verifyEvidenceBundle(bundle, { trust, transparencyTrust });
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exit(result.valid ? 0 : 1);
}

module.exports = {
  verifyEvidenceBundle, verifyEvidencePackage, verifyMerkleInclusionPath, verifyTransparencyProof,
  stableStringify, canonicalHash, domainSeparatedHash, verifyEd25519,
  packageContent, bundleContent,
  buildTrustSet, resolveTrustedKey, spkiFingerprint, parseCliArgs, transparencyEntryHash, transparencyRootDigest,
  EVIDENCE_DOMAIN, BUNDLE_DOMAIN,
};
