'use strict';

/**
 * QODIQA Evidence Package — Standalone Offline Verifier
 *
 * Verifies a QODIQA::EVIDENCE::V1 evidence package (as downloaded from
 * GET /evidence/package/:artifactId/json) using the data inside the package
 * plus a TRUST ANCHOR you supply (the QODIQA instance's published key set or a
 * pinned key fingerprint). No network calls, no database, no QODIQA source imports —
 * this file has zero dependencies beyond Node's built-in `crypto` module, so
 * it can be copied out of this repository and run standalone by any
 * external auditor, regulator, customer, or forensic investigator.
 *
 * It performs three independent checks:
 *
 *   1. packageHash   — SHA-256 self-consistency of the package content.
 *   2. seal signature — Ed25519 signature over the same content, verified with a
 * TRUSTED key you supply. Only
 *                       then does it prove the package was issued by the QODIQA
 *                       instance holding that key; the key embedded in the
 *                       package is never trusted on its own.
 *   3. chain hash     — SHA-256 domain-separated hash of the underlying
 *                       audit-chain entry's canonical fields, proving the
 *                       recorded decision has not been altered since it was
 *                       appended to the chain.
 *
 * TRACE-2: when the package includes a `consent` section (schemaVersion 3+
 * packages), that section — plus the matched-rule fields on `policy` — is
 * part of the same signed content checks 1-3 already cover, so a tampered
 * consentId/policy rule is caught the same way a tampered decision would be.
 * The output additionally includes a `provenance` summary (consentId,
 * version, revocation status, matched rule id/version) for human review.
 *
 * same treatment for the `caller` section (schemaVersion 4+
 * packages) — the authenticated caller identity (callerId/callerName/
 * environment/credentialType) that requested the signature at /sign time,
 * distinct from the `key` section's publicKeyId (which only proves which
 * shared tenant key produced the artifact). This is what lets an OFFLINE
 * verifier — no server call required — determine not just which key signed,
 * but which specific authenticated caller requested that signature.
 *
 * Usage:
 *   node tools/verify/verify.evidence.external.js --keys qodiqa-keys.json <evidence-package.json>
 *   node tools/verify/verify.evidence.external.js --pin <spki-sha256-hex> <evidence-package.json>
 *   cat evidence-package.json | node tools/verify/verify.evidence.external.js --keys qodiqa-keys.json
 * qodiqa-keys.json = GET /.well-known/qodiqa/keys, obtained over a channel you trust
 * (not from the party handing you the package). Exit 0 = valid, 1 = not valid, 2 = input error.
 */

const crypto = require('crypto');
const fs     = require('fs');

// ── Canonical serialization (mirrors src/utils/stableStringify.js) ───────────
// Same contract for the plain-JSON shapes an evidence package actually
// contains: keys sorted lexicographically at every depth, array order
// preserved, no whitespace.

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

// ──: trust anchors ─────────────────────
//
// the seal was verified with the public key the PACKAGE ITSELF carried, so a
// package anyone fabricated and signed with their own key verified "valid" — a self-signature
// proves nothing about who issued it. Authenticity now requires a TRUST ANCHOR obtained out of
// band, never from the package:
//   --keys <file>   the QODIQA instance's published key set (GET /.well-known/qodiqa/keys,
//                   saved from a channel you trust; {keys:[{keyId, publicKey, status}]} or an array)
//   --pin  <hex>    the SHA-256 of a trusted key's SPKI DER (the key's fingerprint)
// Without either, `valid` is false (TRUST_ANCHOR_REQUIRED) — the package's internal consistency is
// still reported (selfConsistent*), clearly labelled as NOT an authenticity check.
// Inlined (not a shared module) because this verifier is designed to be copied out and run alone.

function spkiFingerprint(publicKeyB64) {
  return crypto.createHash('sha256').update(Buffer.from(String(publicKeyB64 || ''), 'base64')).digest('hex');
}

/** Normalise a trust set: { keys:[{keyId, publicKey, status, fingerprint}], pins:Set<hex> }. */
function buildTrustSet({ keys = [], pins = [] } = {}) {
  const list = Array.isArray(keys) ? keys : (keys && Array.isArray(keys.keys) ? keys.keys : []);
  return {
    keys: list.filter((k) => k && typeof k.publicKey === 'string')
      .map((k) => ({ keyId: k.keyId ?? null, publicKey: k.publicKey, status: k.status ?? 'active', fingerprint: spkiFingerprint(k.publicKey) })),
    pins: new Set((pins || []).map((p) => String(p).toLowerCase().replace(/[^0-9a-f]/g, '')).filter((p) => p.length === 64)),
  };
}

const REVOKED_STATUSES = new Set(['revoked', 'compromised']);

/**
 * Decide which public key (if any) may verify a seal. Never trusts the embedded key on its own.
 * @returns {{ ok: boolean, publicKey?: string, reason?: string, anchor?: string, keyId?: string|null, fingerprint?: string }}
 */
function resolveTrustedKey(trust, keyId, embeddedPublicKey) {
  if (!trust || (trust.keys.length === 0 && trust.pins.size === 0)) {
    return { ok: false, reason: 'TRUST_ANCHOR_REQUIRED: supply --keys <published key set> or --pin <spki-sha256>; the key embedded in the package cannot authenticate it' };
  }
  const embeddedFp = embeddedPublicKey ? spkiFingerprint(embeddedPublicKey) : null;
  let match = null;
  if (keyId) match = trust.keys.find((k) => k.keyId === keyId) || null;
  if (!match && embeddedFp) match = trust.keys.find((k) => k.fingerprint === embeddedFp) || null;
  if (match) {
    if (embeddedFp && embeddedFp !== match.fingerprint) {
      return { ok: false, reason: `KEY_MISMATCH: the package names key ${keyId} but embeds different key material` };
    }
    if (REVOKED_STATUSES.has(String(match.status).toLowerCase())) {
      return { ok: false, reason: `KEY_REVOKED: trusted key ${match.keyId} has status ${match.status}` };
    }
    return { ok: true, publicKey: match.publicKey, anchor: 'keys', keyId: match.keyId, fingerprint: match.fingerprint };
  }
  if (embeddedFp && trust.pins.has(embeddedFp)) {
    return { ok: true, publicKey: embeddedPublicKey, anchor: 'pin', keyId: keyId ?? null, fingerprint: embeddedFp };
  }
  return { ok: false, reason: `UNTRUSTED_KEY: ${keyId ? `key ${keyId} / ` : ''}fingerprint ${embeddedFp || '(none)'} is not in the trust set` };
}

// ── Package content reconstruction (mirrors generator.js _packageContent) ───

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
  // TRACE-2: mirrors src/core/evidence/generator.js's _packageContent() —
  // only add the key when present, so a package generated before this field
  // existed (no `consent` section at all) still recomputes to the exact
  // content it was originally signed over.
  if (pkg.sections.consent !== undefined) content.consent = pkg.sections.consent;
  // same "only add when present" contract as `consent` above.
  if (pkg.sections.caller  !== undefined) content.caller  = pkg.sections.caller;
  return content;
}

// TRACE-2: pulls a human-readable provenance summary out of an already-parsed
// package for the CLI output below — purely descriptive, not a verification
// step (the actual proof is the signature/hash checks above, which already
// cover this data since it's part of `content`).
function summarizeProvenance(pkg) {
  const consent = pkg?.sections?.consent;
  const policy  = pkg?.sections?.policy;
  const caller  = pkg?.sections?.caller;
  return {
    consent: consent && consent.available ? {
      consentId:         consent.consentId,
      consentVersion:    consent.consentVersion,
      subject:           consent.subject,
      scope:             consent.scope,
      revocationStatus:  consent.revocationStatus,
      expiresAt:         consent.expiresAt,
    } : { available: false, note: consent?.note ?? 'No consent section in this package' },
    policyRule: {
      matchedRuleId:      policy?.matchedRuleId      ?? null,
      matchedRuleVersion: policy?.matchedRuleVersion ?? null,
      // TRACE-4: independently-recomputable hash of the deciding rule's
      // canonical content — see services/policyHash.js computeRuleHash.
      matchedRuleHash:    policy?.matchedRuleHash    ?? null,
      engineVersion:      policy?.engineVersion      ?? null,
      evaluatedAt:        policy?.evaluatedAt         ?? null,
    },
    // WHICH authenticated caller requested this signature — the
    // core deliverable of this remediation. attribution states plainly,
    // in technically verifiable terms, the strength of non-repudiation
    // this specific decision carries — see NONREP-1-REMEDIATION-REPORT.md.
    caller: caller && caller.available ? {
      callerId:       caller.callerId,
      callerName:     caller.callerName,
      environment:    caller.environment,
      credentialType: caller.credentialType,
      attribution:    'CALLER_BOUND — non-repudiation proves which authenticated caller requested this signature',
    } : {
      available:   false,
      note:        caller?.note ?? 'No caller section in this package',
      attribution: 'KEY_ONLY — non-repudiation proves only which signing key produced this artifact, not which caller requested it',
    },
  };
}

// ── Main verification logic ───────────────────────────────────────────────────

/**
 * @param {object} pkg
 * @param {{ trust?: object, trustedKeys?: object|object[], pins?: string[] }} [opts]
 *   trust = buildTrustSet(...) result, or pass trustedKeys / pins directly. REQUIRED for valid:true.
 */
function verifyEvidencePackage(pkg, opts = {}) {
  const trust = opts.trust || buildTrustSet({ keys: opts.trustedKeys, pins: opts.pins });
  const result = {
    packageHashValid: false,
    signatureValid:   null,
    selfConsistentSignature: null,
    chainHashValid:   null,
    trust:            null,
    valid:            false,
    reasons:          [],
  };

  if (!pkg || typeof pkg !== 'object' || !pkg.sections || !pkg.integrity) {
    result.reasons.push('MALFORMED_PACKAGE: missing sections or integrity block');
    return result;
  }

  // 1. packageHash — recompute SHA-256 of the canonical content.
  const content      = packageContent(pkg);
  const computedHash = canonicalHash(content);
  result.packageHashValid = computedHash === pkg.integrity.packageHash;
  if (!result.packageHashValid) {
    result.reasons.push(`PACKAGE_HASH_MISMATCH: expected ${pkg.integrity.packageHash}, computed ${computedHash}`);
  }

  // 2. Ed25519 seal signature — proves QODIQA authenticity ONLY against a trusted key.
  //    The domain is fixed by this verifier: a package declaring another domain is
  //    rejected, never verified under the domain it chose for itself.
  const { signature, publicKey, domain, keyId } = pkg.integrity;
  if (domain !== undefined && domain !== null && domain !== EVIDENCE_DOMAIN) {
    result.signatureValid = false;
    result.reasons.push(`DOMAIN_MISMATCH: package declares ${domain}, evidence seals use ${EVIDENCE_DOMAIN}`);
  } else if (signature && publicKey) {
    const canonical = stableStringify(content);
    const hashBuf    = domainSeparatedHash(EVIDENCE_DOMAIN, canonical);
    result.selfConsistentSignature = verifyEd25519(hashBuf, signature, publicKey); // informational only
    const tk = resolveTrustedKey(trust, keyId, publicKey);
    result.trust = tk.ok ? { anchor: tk.anchor, keyId: tk.keyId, fingerprint: tk.fingerprint } : { anchor: null, error: tk.reason };
    if (!tk.ok) {
      result.signatureValid = false;
      result.reasons.push(tk.reason);
    } else {
      result.signatureValid = verifyEd25519(hashBuf, signature, tk.publicKey);
      if (!result.signatureValid) result.reasons.push('SIGNATURE_INVALID');
    }
  } else {
    result.reasons.push('SIGNATURE_UNAVAILABLE: package was not sealed at generation time');
  }

  // 3. Audit-chain entry hash — proves the underlying decision record is
  //    unmodified since it was appended to the chain. Only audit-chain domains are accepted.
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
  // TRACE-2: descriptive only — this data was already covered by the
  // packageHash/signature checks above (it's part of `content`), so it does
  // not affect `valid`. Included so a human reviewer, or another program,
  // can answer "which consent, which rule, why" from this output alone.
  result.provenance = summarizeProvenance(pkg);
  return result;
}

// ── CLI entry point ───────────────────────────────────────────────────────────

function _readStdin() {
  return fs.readFileSync(0, 'utf8');
}

/** Parse `[--keys <file>]... [--pin <hex>]... [package-file]`. Exported for tests. */
function parseCliArgs(argv) {
  const keys = []; const pins = []; let filePath = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--keys') { const k = JSON.parse(fs.readFileSync(argv[++i], 'utf8')); keys.push(...(Array.isArray(k) ? k : (k.keys || []))); }
    else if (argv[i] === '--pin') pins.push(argv[++i]);
    else if (!filePath) filePath = argv[i];
  }
  return { filePath, trust: buildTrustSet({ keys, pins }) };
}

if (require.main === module) {
  let filePath; let trust;
  try {
    ({ filePath, trust } = parseCliArgs(process.argv.slice(2)));
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

  let pkg;
  try {
    const parsed = JSON.parse(raw);
    // Accept both the raw evidence package and the standard API envelope
    // ({ status, data: <package> }) returned by GET /evidence/package/:id/json.
    pkg = parsed && parsed.data && parsed.data.schema ? parsed.data : parsed;
  } catch {
    process.stderr.write('Error: input is not valid JSON\n');
    process.exit(1);
  }

  const result = verifyEvidencePackage(pkg, { trust });
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exit(result.valid ? 0 : 1);
}

module.exports = {
  verifyEvidencePackage, stableStringify, canonicalHash, domainSeparatedHash, verifyEd25519,
  packageContent, summarizeProvenance,
  buildTrustSet, resolveTrustedKey, spkiFingerprint, parseCliArgs, EVIDENCE_DOMAIN,
};
