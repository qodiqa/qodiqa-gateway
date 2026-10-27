'use strict';

/**
 * Evidence Package Generator
 *
 * Assembles forensic-grade evidence packages from audit chain, key store,
 * policy state, and cryptographic verification for a given artifactId.
 *
 * No private key material is ever exposed.  Any unresolvable verification
 * step is reported as UNKNOWN rather than ERROR, preserving the fail-safe
 * contract.
 */

const crypto  = require('crypto');
const { canonicalHash } = require('../../../services/utils/evidencePackage');
// the chain is walked page by page (forEachChainEntry + createChainWalker) instead of being
// materialised with getAuditChain() per request — one authorised admin request on a large log used to exhaust the heap.
// Design / invariants E-1..E-6:
const auditLog = require('../audit/audit-log.js');
// history reads go through the module object (as the chain walk does), so every read's failure path is testable.
const getArtifactById  = (...args) => auditLog.getArtifactById(...args);
const getReplayLineage = (...args) => auditLog.getReplayLineage(...args);
const {
  listPublicKeys,
  getVerificationKey,
  getSigningKey,
} = require('../../../services/artifact/keyManager');
const { validateArtifact } = require('../../validation/validateArtifact');
const { computePolicyHash } = require('../../../services/policyHash');
const stableStringify = require('../../utils/stableStringify');
const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../infra/crypto/hashing');
const { sign, verify } = require('../../infra/crypto/ed25519');
const proofLookup = require('../transparency/proofLookup');
// version-aware read of promoted fields — the hashed value whenever the entry's schema
// version hashes the field (even null), the legacy executionContext copy only for older entries.
// `entry.x ?? entry.executionContext?.x` fell back to the unprotected copy whenever the hashed value
// was legitimately null, so a rewritten executionContext changed the sealed package unnoticed.
const { protectedField: pf } = require('../audit/entryBuilder');

// ── Constants ─────────────────────────────────────────────────────────────────

const GENERATOR_VERSION = '1.2.0'; // adds the `caller` section (authenticated caller attribution)
const SCHEMA_VERSION    = 'QODIQA::EVIDENCE::V1';
const BUNDLE_SCHEMA_VERSION = 'QODIQA::EVIDENCE_BUNDLE::V1'; //

// ── Helpers ───────────────────────────────────────────────────────────────────

function _now() { return new Date().toISOString(); }

function _safe(fn, fallback = null) {
  try { return fn(); } catch (_) { return fallback; }
}

function _fmtMs(ms) {
  if (!Number.isFinite(ms) || ms < 0) return 'N/A';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
  if (ms < 3600000) return `${(ms / 60000).toFixed(2)}m`;
  return `${(ms / 3600000).toFixed(2)}h`;
}

// ── Section builders ──────────────────────────────────────────────────────────

function _buildArtifactSection(entry) {
  if (!entry) return null;
  return {
    artifactId:      entry.artifactId,
    decision:        entry.decision,
    timestamp:       entry.timestamp,
    inputHash:       entry.inputHash    ?? 'UNAVAILABLE',
    requestHash:     entry.requestHash  ?? 'UNAVAILABLE',
    policyHash:      entry.policyHash   ?? 'UNAVAILABLE',
    // Full, untruncated signature — a partial signature cannot be
    // base64/hex-decoded to the correct byte length and silently breaks
    // Ed25519 verification for any external auditor.
    signature:       entry.signature    ?? 'UNAVAILABLE',
    nonce:           entry.nonce        ?? null,
    tenantId:        entry.tenantId     ?? null,
    highResTime:     entry.highResTime  ?? null,
    executionContext: entry.executionContext ?? null,
    chainHash:       entry.hash         ?? null,
    prevHash:        entry.prevHash     ?? null,
    // Canonical serialization of the hash-protected core fields —
    // required for a third party to independently recompute chainHash
    // offline: SHA-256(chainHashDomain || canonical) must equal chainHash.
    // Omitting this field makes chainHash unverifiable — a hash with
    // nothing to recompute it from is not evidence, just an assertion.
    canonical:       entry.canonical    ?? null,
    chainHashDomain: entry.canonical ? ARTIFACT_DOMAINS.AUDIT : null,
    // prefer the hash-protected top-level field (schemaVersion 5);
    // fall back to the legacy, unprotected executionContext copy for
    // entries written before this fix — same fallback pattern
    // _buildKeySection() already established for publicKeyId.
    provider: pf(entry, 'provider'),
    model:    pf(entry, 'model'),
  };
}

function _buildPolicySection(entry, policies) {
  const policyHash = entry?.policyHash ?? null;
  let computedHash = null;
  let hashMatch    = 'UNKNOWN';

  if (Array.isArray(policies) && policies.length > 0) {
    computedHash = _safe(() => computePolicyHash(policies), null);
    if (computedHash && policyHash && policyHash !== 'UNAVAILABLE') {
      hashMatch = computedHash === policyHash ? 'MATCH' : 'MISMATCH';
    }
  }

  // TRACE-2: rule-level decision provenance, read straight off the immutable
  // audit entry (entry.policyDecision — schemaVersion 3+ only). Naturally
  // absent/null for older entries, since the field simply doesn't exist on
  // them — no compatibility shim needed, this is a direct read.
  const decision = entry?.policyDecision ?? null;

  return {
    policyHashAtExecution: policyHash,
    currentPolicyHash:     computedHash,
    hashIntegrity:         hashMatch,
    policyCount:           Array.isArray(policies) ? policies.length : null,
    // Which specific rule authorized/denied execution, and why — offline
    // verifiable without a live policy store lookup.
    matchedRuleId:      decision?.policyId      ?? null,
    matchedRuleVersion: decision?.policyVersion ?? null,
    // TRACE-4: deterministic hash of the deciding rule's own canonical
    // content — an auditor with a copy of the rule definition can
    // independently recompute this (services/policyHash.js computeRuleHash)
    // and confirm it matches, without a live policy store lookup. null on
    // ALLOW (no single rule decides) or for entries predating TRACE-4.
    matchedRuleHash:    decision?.policyRuleHash ?? null,
    engineVersion:      decision?.engineVersion ?? null,
    evaluatedAt:        decision?.evaluatedAt   ?? null,
    evaluationPath:     decision?.evaluationPath ?? [],
  };
}

// TRACE-2: consent-record provenance that authorized (or, on a
// CONSENT_-reason BLOCK, was checked and denied for) this decision.
// Distinguishes "no consent policy applied" from "entry predates
// TRACE-2 (schemaVersion < 3)" so an auditor never confuses the two.
function _buildConsentSection(entry) {
  if (!entry) {
    return { available: false, note: 'Artifact not found in audit chain' };
  }
  if ((entry.schemaVersion ?? 1) < 3) {
    return { available: false, note: 'Audit entry predates consent provenance capture (schemaVersion < 3)' };
  }
  if (!entry.consentProvenance) {
    return { available: false, note: 'No consent policy applied to this request' };
  }
  return { available: true, ...entry.consentProvenance };
}

// authenticated-caller provenance — the identity that requested
// the signature at /sign time, distinct from _buildKeySection's publicKeyId
// (which only proves which shared tenant key produced the artifact).
// Distinguishes "entry predates schemaVersion 4" (this capability didn't
// exist yet) from "artifact was signed before the remediation shipped"
// (capability existed, but this specific artifact carries no caller
// binding — key-attribution only) so an auditor never confuses the two.
function _buildCallerSection(entry) {
  if (!entry) {
    return { available: false, note: 'Artifact not found in audit chain' };
  }
  if ((entry.schemaVersion ?? 1) < 4) {
    return { available: false, note: 'Audit entry predates caller-attribution capture (schemaVersion < 4) — non-repudiation for this decision is key-attribution only, see docs/security/key-management.md' };
  }
  if (!entry.callerContext) {
    return { available: false, note: 'Artifact was signed before the remediation shipped — non-repudiation for this decision is key-attribution only (proves which signing key produced it, not which authenticated caller requested it)' };
  }
  return { available: true, ...entry.callerContext };
}

function _buildKeySection(entry) {
  // Prefer the hash-protected top-level field; fall
  // back to the legacy, unprotected executionContext copy for entries
  // written before this fix.
  const publicKeyId = pf(entry, 'publicKeyId');
  let allKeys = [];
  _safe(() => { allKeys = listPublicKeys(); });

  const keyRecord = publicKeyId
    ? allKeys.find(k => k.keyId === publicKeyId) ?? null
    : null;

  return {
    publicKeyId:      publicKeyId,
    keyStatus:        keyRecord?.status ?? 'UNKNOWN',
    algorithm:        keyRecord?.algorithm ?? 'Ed25519',
    clientId:         keyRecord?.clientId  ?? null,
    keyVersion:       keyRecord?.version   ?? null,
    createdAt:        keyRecord?.createdAt ?? null,
    // Never expose private key material. Public key material, in contrast,
    // MUST be exported in full: a truncated public key cannot be
    // loaded by crypto.createPublicKey() and silently breaks independent
    // Ed25519 verification. publicKeyEncoding documents how to decode it.
    publicKey:         keyRecord?.publicKeyB64 ?? null,
    publicKeyEncoding: keyRecord?.publicKeyB64 ? 'base64-der-spki' : null,
    totalKeysInStore: allKeys.length,
    activeKeys:       allKeys.filter(k => k.status === 'active').length,
  };
}

function _buildVerificationSection(entry) {
  if (!entry) {
    return {
      outcome:          'UNKNOWN',
      reason:           'NO_ENTRY',
      signatureValid:   null,
      chainPosition:    null,
      verificationNote: 'Artifact not found in audit chain',
    };
  }

  // Reconstruct the artifact envelope from the chain entry to re-run validateArtifact.
  // The chain entry does not store the original payload, so we can only verify
  // the chain record's signature field against the stored hashes.
  const verificationResult = entry.verificationResult;
  const sigField           = entry.signature ?? 'UNAVAILABLE';
  const isUnavailable      = sigField === 'UNAVAILABLE';

  let outcome;
  if (isUnavailable) {
    outcome = 'UNAVAILABLE';
  } else if (verificationResult === true) {
    outcome = 'VALID';
  } else if (verificationResult === false) {
    outcome = 'INVALID';
  } else {
    outcome = 'UNKNOWN';
  }

  // Try to get current key status for the key used at signing time.
  // Prefer the hash-protected top-level field; fall back to the legacy
  // unprotected executionContext copy for pre-remediation entries.
  const publicKeyId = pf(entry, 'publicKeyId');
  let keyCurrentStatus = 'UNKNOWN';
  let publicKey        = null;
  if (publicKeyId) {
    _safe(() => {
      const k = getVerificationKey(publicKeyId);
      keyCurrentStatus = k?.status ?? 'UNKNOWN';
      if (k?.pubDer) publicKey = k.pubDer.toString('base64');
    });
  }

  return {
    outcome,
    // Full, untruncated signature and public key — required for
    // independent offline verification. Any preview/display formatting
    // belongs only in the UI, never in exported evidence.
    signature:            sigField === 'UNAVAILABLE' ? 'UNAVAILABLE' : sigField,
    signatureAlgorithm:   'Ed25519',
    signatureValid:       verificationResult ?? null,
    publicKeyId,
    publicKey,
    publicKeyEncoding:    publicKey ? 'base64-der-spki' : null,
    keyCurrentStatus,
    decisionAtExecution:  entry.decision,
    stage:                pf(entry, 'stage'),
    reason:               pf(entry, 'reason'),
    verificationNote:     _verificationNote(outcome, entry),
  };
}

function _verificationNote(outcome, entry) {
  switch (outcome) {
    case 'VALID':       return 'Ed25519 signature verified successfully at execution time';
    case 'INVALID':     return 'Signature verification failed at execution time';
    case 'UNAVAILABLE': return 'Signature field not present (early-stage BLOCK before signing)';
    default:            return 'Verification result not recorded';
  }
}

// FAIL CLOSED. A history read that fails is an explicit error, never a result —
// previously a failed walk produced "0 entries, chain valid", a failed artifact lookup "not found" and a failed replay
// lookup "CLEAN". Callers (the evidence routes) map it to HTTP 503 AUDIT_HISTORY_UNAVAILABLE. A chain that is READ but
// does not verify is not this error: it is reported as the verification result (valid:false / COMPROMISED).
class AuditHistoryUnavailableError extends Error {
  constructor(read, cause) {
    super(`AUDIT_HISTORY_UNAVAILABLE: the audit history could not be read (${read})`);
    this.code = 'AUDIT_HISTORY_UNAVAILABLE';
    this.read = read;
    this.cause = cause;
  }
}
async function _readOrFail(read, fn) {
  try { return await fn(); } catch (err) { throw new AuditHistoryUnavailableError(read, err); }
}

// ONE streaming pass over the chain — the snapshot getAuditChain() returned (same entries, same order: E-1/E-2)
// fed to the walker verifyAuditChainDetailed(chain) uses (same checks, same default GENESIS start: E-3), plus whatever
// per-entry facts the caller needs (`onEntry(entry, index)`). Memory O(page + the walker's duplicate set). A failed read
// throws AuditHistoryUnavailableError. `afterPage` is awaited between pages (streaming export).
async function _walkChainOnce(onEntry = null, { afterPage = null } = {}) {
  const walker = auditLog.createChainWalker();
  let count = 0;
  await _readOrFail('chain walk', () => auditLog.forEachChainEntry((e) => {
    walker.push(e);
    if (onEntry) onEntry(e, count);
    count++;
  }, { pageSize: 1000, afterPage }));
  return { integrity: walker.result(), count };
}

function _buildAuditSection(entry, replayEntries, walk) {
  // `walk` = { integrity, count, artifactIndex } from _walkChainOnce — the same values the previous
  // verifyAuditChainDetailed(chain) / chain.findIndex(...) / chain.length produced.
  const integrity = walk.integrity;
  const chainPos = walk.artifactIndex;

  // Replay analysis
  const replayCount = replayEntries.length;
  const timestamps  = replayEntries
    .map(r => r.timestamp)
    .filter(t => typeof t === 'number')
    .sort((a, b) => a - b);

  let replayWindowMs  = null;
  let replayRiskLevel = 'NONE';
  if (timestamps.length >= 2) {
    replayWindowMs = timestamps[timestamps.length - 1] - timestamps[0];
  }
  if (replayCount >= 10) replayRiskLevel = 'CRITICAL';
  else if (replayCount >= 5) replayRiskLevel = 'HIGH';
  else if (replayCount >= 2) replayRiskLevel = 'MEDIUM';
  else if (replayCount >= 1) replayRiskLevel = 'LOW';

  return {
    chainIntegrity: {
      valid:             integrity.valid,
      entriesVerified:   integrity.entriesVerified,
      tamperingDetected: integrity.tamperingDetected,
      reason:            integrity.reason ?? null,
      head:              integrity.head   ?? null,
      tail:              integrity.tail   ?? null,
    },
    artifactPosition: {
      index:       chainPos >= 0 ? chainPos : null,
      totalInChain: walk.count,
      found:        chainPos >= 0,
    },
    replayAnalysis: {
      replayCount,
      replayRiskLevel,
      replayWindowMs,
      replayWindowHuman: replayWindowMs !== null ? _fmtMs(replayWindowMs) : 'N/A',
      firstReplayAt: timestamps[0] ?? null,
      lastReplayAt:  timestamps[timestamps.length - 1] ?? null,
    },
  };
}

// ── Package integrity seal ────────────────────────────────────────────────────

function _clientId() {
  return process.env.QODIQA_CLIENT_ID || 'default';
}

function _packageContent(pkg) {
  const content = {
    artifactId:   pkg.artifactId,
    generatedAt:  pkg.generatedAt,
    artifact:     pkg.sections.artifact,
    policy:       pkg.sections.policy,
    key:          pkg.sections.key,
    verification: pkg.sections.verification,
    audit:        pkg.sections.audit,
  };
  // TRACE-2: only add the key when the section is actually present — mirrors
  // how `requestor`/`integrity` are already deliberately excluded above.
  // This keeps _packageContent() a strict superset of its pre-TRACE-2 shape:
  // a package object that never had a `consent` section (e.g. one built by
  // code that predates this change) recomputes to the exact same signed
  // content it always did, so its original signature/hash still verify.
  if (pkg.sections.consent !== undefined) content.consent = pkg.sections.consent;
  // same "only add when present" contract as `consent` above —
  // preserves pre-NONREP-1 packages' signature/hash recomputation exactly.
  if (pkg.sections.caller  !== undefined) content.caller  = pkg.sections.caller;
  return content;
}

function _sealPackage(pkg) {
  return canonicalHash(_packageContent(pkg));
}

// Ed25519-signs the whole package content with QODIQA's active signing key
// the SHA-256 packageHash above only proves internal
// self-consistency (anyone can recompute a bare hash) — it is not proof
// that QODIQA actually issued this bundle. Signing the domain-separated
// hash of the same content, and exporting the full signature + full public
// key + keyId + algorithm, lets any third party verify the bundle's
// authenticity and tamper-evidence entirely offline, without trusting a
// running QODIQA instance.
//
// Best-effort: a signing failure (no active key, or a native-signing
// provider — Vault/HSM — that only supports async signing) degrades to
// signature: null with a `sealError` reason rather than throwing. Evidence
// viewing must not break because sealing is unavailable — see this file's
// header comment on the fail-safe (UNKNOWN, not ERROR) contract.
function _signPackage(pkg) {
  const canonical = stableStringify(_packageContent(pkg));
  const hashBuf   = domainSeparatedHash(ARTIFACT_DOMAINS.EVIDENCE, canonical);

  try {
    const signingKey = getSigningKey(_clientId());
    if (!signingKey.privDer) {
      return {
        signature: null, keyId: signingKey.keyId ?? null, publicKey: null,
        signingAlgorithm: 'Ed25519', domain: ARTIFACT_DOMAINS.EVIDENCE, signedAt: null,
        sealError: 'SIGNING_UNAVAILABLE_NATIVE_PROVIDER',
      };
    }
    return {
      signature:        sign(hashBuf, signingKey.privDer),
      keyId:            signingKey.keyId,
      publicKey:        signingKey.pubDer.toString('base64'),
      signingAlgorithm: 'Ed25519',
      domain:           ARTIFACT_DOMAINS.EVIDENCE,
      signedAt:         _now(),
      sealError:        null,
    };
  } catch (err) {
    return {
      signature: null, keyId: null, publicKey: null, signingAlgorithm: 'Ed25519',
      domain: ARTIFACT_DOMAINS.EVIDENCE, signedAt: null, sealError: err.message,
    };
  }
}

/**
 *the seal key is resolved from THIS instance's key store by
 * the package's keyId — the trust anchor — never taken from the package itself. A package sealed
 * with any key the store does not hold (or holds as revoked), or embedding key material that differs
 * from the stored key, does not verify. The standalone verifiers apply the same rule with an
 * out-of-band key set (tools/verify/verify.evidence.external.js --keys / --pin).
 */
function _trustedSealKey(keyId, embeddedPublicKeyB64) {
  if (!keyId) return { ok: false, reason: 'UNTRUSTED_KEY: the package names no keyId' };
  let stored;
  try { stored = getVerificationKey(keyId); } catch (err) { return { ok: false, reason: `UNTRUSTED_KEY: ${err.message}` }; }
  const pubDer = stored && (stored.pubDer || stored);
  if (!Buffer.isBuffer(pubDer)) return { ok: false, reason: `UNTRUSTED_KEY: no verification key for ${keyId}` };
  if (embeddedPublicKeyB64 && Buffer.from(String(embeddedPublicKeyB64), 'base64').compare(pubDer) !== 0) {
    return { ok: false, reason: `KEY_MISMATCH: the package names ${keyId} but embeds different key material` };
  }
  return { ok: true, pubDer };
}

/**
 * Independently verify a generated evidence package — no database. The seal is
 * verified against this instance's key store by keyId, never against the
 * key embedded in the package; the domain tag is fixed, not taken from the package.
 *
 * @param {object} pkg  — a package as returned by generateEvidencePackage()
 * @returns {{ valid: boolean, packageHashValid: boolean, signatureValid: boolean|null,
 *             chainHashValid: boolean|null, reasons: string[] }}
 */
function verifyEvidencePackage(pkg) {
  const reasons = [];

  if (!pkg || typeof pkg !== 'object' || !pkg.sections || !pkg.integrity) {
    return { valid: false, packageHashValid: false, signatureValid: null, chainHashValid: null, reasons: ['MALFORMED_PACKAGE'] };
  }

  // 1. Package hash — proves internal self-consistency.
  const content       = _packageContent(pkg);
  const computedHash  = canonicalHash(content);
  const packageHashValid = computedHash === pkg.integrity.packageHash;
  if (!packageHashValid) reasons.push('PACKAGE_HASH_MISMATCH');

  // 2. Ed25519 signature — proves QODIQA authenticity + tamper-evidence.
  let signatureValid = null;
  const { signature, publicKey, domain, keyId } = pkg.integrity;
  if (domain && domain !== ARTIFACT_DOMAINS.EVIDENCE) {
    signatureValid = false;
    reasons.push(`DOMAIN_MISMATCH: ${domain}`);
  } else if (signature && publicKey) {
    const tk = _trustedSealKey(keyId, publicKey);
    if (!tk.ok) {
      signatureValid = false;
      reasons.push(tk.reason);
    } else {
      try {
        const canonical = stableStringify(content);
        const hashBuf    = domainSeparatedHash(ARTIFACT_DOMAINS.EVIDENCE, canonical);
        signatureValid   = verify(hashBuf, signature, tk.pubDer);
      } catch (err) {
        signatureValid = false;
        reasons.push('SIGNATURE_VERIFY_ERROR: ' + err.message);
      }
      if (!signatureValid) reasons.push('SIGNATURE_INVALID');
    }
  } else {
    reasons.push('SIGNATURE_UNAVAILABLE');
  }

  // 3. Audit-chain entry hash — proves the underlying decision record
  //    (including its copy of the artifact's own signature) has not been
  //    altered since it was appended to the chain.
  let chainHashValid = null;
  const art = pkg.sections.artifact;
  if (art?.canonical && art?.chainHash) {
    try {
      const computedChainHash = domainSeparatedHash(art.chainHashDomain || ARTIFACT_DOMAINS.AUDIT, art.canonical).toString('hex');
      chainHashValid = computedChainHash === art.chainHash;
    } catch (err) {
      chainHashValid = false;
      reasons.push('CHAIN_HASH_VERIFY_ERROR: ' + err.message);
    }
    if (!chainHashValid) reasons.push('CHAIN_HASH_MISMATCH');
  }

  return {
    valid: packageHashValid && signatureValid === true && chainHashValid !== false,
    packageHashValid,
    signatureValid,
    chainHashValid,
    reasons,
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Generate a complete evidence package for the given artifactId.
 *
 * @param {string}   artifactId   — UUID v4 of the artifact
 * @param {object[]} policies     — Current in-memory policy array (for hash comparison)
 * @param {object}  [requestor]   — RBAC user making the request { id, username, role }
 * @param {string|null} [tenantId] — AUTHZ-1: optional tenant scope for the lookup; see
 *   getArtifactById()'s own doc for why this is opt-in on an admin surface with no
 *   per-request authenticated tenant of its own.
 * @returns {{ found: boolean, package: object|null, missing: string[] }}
 */
async function generateEvidencePackage(artifactId, policies, requestor, tenantId = null) {
  // the audit lookups are async (window fast path + durable fallback).
  const walk          = await _walkWithArtifactIndex(artifactId);
  const entry         = await _readOrFail('artifact lookup', () => getArtifactById(artifactId, tenantId));   //
  const replayEntries = await _readOrFail('replay lineage', () => getReplayLineage(artifactId));           //

  const found = !!entry;
  const missing = [];

  if (!found) missing.push('artifact_not_in_chain');

  // Requestor section for evidentiary integrity (Req 7)
  const requestorSection = requestor ? {
    userId:              requestor.id       ?? null,
    username:            requestor.username ?? null,
    role:                requestor.role     ?? null,
    authorizationResult: 'AUTHORIZED',
    generatedAt:         _now(),
  } : {
    userId:              null,
    username:            null,
    role:                null,
    authorizationResult: 'UNKNOWN',
    generatedAt:         _now(),
  };

  const pkg = {
    schema:      SCHEMA_VERSION,
    version:     GENERATOR_VERSION,
    artifactId,
    generatedAt: requestorSection.generatedAt,
    found,
    sections: {
      artifact:     _buildArtifactSection(entry),
      policy:       _buildPolicySection(entry, policies),
      key:          _buildKeySection(entry),
      verification: _buildVerificationSection(entry),
      audit:        _buildAuditSection(entry, replayEntries, { ...walk, artifactIndex: entry?.artifactId ? walk.indexOf(entry.artifactId) : -1 }),
      consent:      _buildConsentSection(entry),
      caller:       _buildCallerSection(entry),
      requestor:    requestorSection,
    },
    integrity: null,  // filled in below
    missing,
  };

  const seal = _signPackage(pkg);
  pkg.integrity = {
    packageHash:      _sealPackage(pkg),
    algorithm:        'SHA-256',
    // Full package-level Ed25519 seal — see _signPackage() above.
    signature:        seal.signature,
    publicKey:        seal.publicKey,
    keyId:            seal.keyId,
    signingAlgorithm: seal.signingAlgorithm,
    domain:           seal.domain,
    signedAt:         seal.signedAt,
    sealError:        seal.sealError,
  };

  return { found, package: pkg, missing };
}

/**
 * Export the full or filtered audit chain for an artifact.
 *
 * @param {string}  artifactId  — UUID v4 of the artifact
 * @param {boolean} [filtered]  — If true, only export entries related to this artifact
 * @returns {{ entries: object[], meta: object }}
 */
async function exportAuditChain(artifactId, filtered) {
  // one streaming pass. Filtered: only the matching entries are kept (O(page + matches)). Unfiltered: every
  // entry is collected — this function's contract returns them all; the HTTP route streams the unfiltered export
  // instead (streamAuditChainExport) so it never holds the history.
  const entries = [];
  const match = (e) => e.artifactId === artifactId || e.executionContext?.replayOf === artifactId;
  const walk = await _walkChainOnce((e) => { if (!filtered || match(e)) entries.push(e); });
  return { entries, meta: _exportMeta(artifactId, filtered, walk, entries.length) };
}

function _exportMeta(artifactId, filtered, walk, exportedCount) {
  return {
    artifactId,
    filtered:     !!filtered,
    totalChain:   walk.count,
    exportedCount,
    exportedAt:   _now(),
    chainIntegrity: {
      valid:             walk.integrity.valid,
      tamperingDetected: walk.integrity.tamperingDetected,
      entriesVerified:   walk.integrity.entriesVerified,
    },
  };
}

/**
 * the UNFILTERED export, streamed. `write(chunk)` receives the JSON text of `entries` (comma-separated, page by
 * page) and is awaited between pages for backpressure; resolves with the same `meta` exportAuditChain() returns, built
 * after the walk (counts and integrity verdict of the very sequence that was written). A read failure mid-walk rejects
 * (the caller aborts the response — never a well-formed body with a partial chain; E-5).
 *
 * @param {string} artifactId
 * @param {(chunk: string) => Promise<void>|void} write
 * @returns {Promise<object>} meta
 */
async function streamAuditChainExport(artifactId, write) {
  let buf = []; let first = true;
  const walk = await _walkChainOnce((e) => { buf.push(JSON.stringify(e)); }, {
    afterPage: async () => {
      if (buf.length === 0) return;
      const chunk = (first ? '' : ',') + buf.join(',');
      first = false; buf = [];
      await write(chunk);
    },
  });
  return _exportMeta(artifactId, false, walk, walk.count);
}

// the walk plus the artifact's first index — chain.findIndex(e => e.artifactId === id) on the same sequence.
async function _walkWithArtifactIndex(artifactId) {
  let first = -1;
  const walk = await _walkChainOnce((e, i) => { if (first < 0 && artifactId && e.artifactId === artifactId) first = i; });
  return { ...walk, indexOf: (id) => (id === artifactId ? first : -1) };
}

/**
 * Generate a cryptographic verification output for an artifact.
 *
 * @param {string}   artifactId — UUID v4
 * @param {object[]} policies   — Current policy array
 * @param {string|null} [tenantId] — AUTHZ-1: see generateEvidencePackage()'s doc.
 * @returns {object} Machine-readable verification document
 */
async function generateVerificationOutput(artifactId, policies, tenantId = null) {
  const walk  = await _walkChainOnce();   //
  const entry = await _readOrFail('artifact lookup', () => getArtifactById(artifactId, tenantId));   //

  const chainVerification = walk.integrity;

  // Policy hash comparison
  let policyVerification = { status: 'UNKNOWN', note: 'Policy array not provided' };
  if (Array.isArray(policies) && policies.length > 0 && entry?.policyHash) {
    const currentHash = _safe(() => computePolicyHash(policies), null);
    if (currentHash) {
      const match = currentHash === entry.policyHash;
      policyVerification = {
        status:              match ? 'MATCH' : 'MISMATCH',
        hashAtExecution:     entry.policyHash,
        hashCurrent:         currentHash,
        note:                match
          ? 'Policy set is identical to the set active at execution time'
          : 'Policy set has changed since execution time',
      };
    }
  }

  // Signature verification status from chain record
  let signatureVerification;
  if (!entry) {
    signatureVerification = { status: 'UNKNOWN', note: 'Artifact not found in chain' };
  } else if (entry.signature === 'UNAVAILABLE') {
    signatureVerification = { status: 'UNAVAILABLE', note: 'Signature not recorded (early-stage BLOCK)' };
  } else {
    const verifyKeyId = pf(entry, 'publicKeyId');
    let fullPublicKey = null;
    if (verifyKeyId) {
      _safe(() => {
        const k = getVerificationKey(verifyKeyId);
        if (k?.pubDer) fullPublicKey = k.pubDer.toString('base64');
      });
    }
    signatureVerification = {
      status:       entry.verificationResult === true ? 'VALID' : (entry.verificationResult === false ? 'INVALID' : 'UNKNOWN'),
      publicKeyId:  verifyKeyId,
      // Full, untruncated signature and public key — required for
      // independent offline verification.
      signature:    entry.signature,
      publicKey:    fullPublicKey,
      algorithm:    'Ed25519',
      note:         entry.verificationResult === true
        ? 'Signature was valid at execution time'
        : 'Signature was invalid or result not recorded',
    };
  }

  // Replay status
  const replayEntries = await _readOrFail('replay lineage', () => getReplayLineage(artifactId));   //
  const replayVerification = {
    status:       replayEntries.length > 0 ? 'REPLAYS_DETECTED' : 'CLEAN',
    replayCount:  replayEntries.length,
    note:         replayEntries.length > 0
      ? `${replayEntries.length} replay attempt(s) detected`
      : 'No replay attempts detected',
  };

  return {
    schema:      SCHEMA_VERSION,
    version:     GENERATOR_VERSION,
    artifactId,
    generatedAt: _now(),
    found:       !!entry,
    verifications: {
      chain:     {
        status:            chainVerification.valid ? 'VALID' : 'INVALID',
        valid:             chainVerification.valid,
        tamperingDetected: chainVerification.tamperingDetected,
        entriesVerified:   chainVerification.entriesVerified,
        note:              chainVerification.reason ?? (chainVerification.valid ? 'Chain integrity verified' : 'Chain integrity failure'),
      },
      signature:  signatureVerification,
      policy:     policyVerification,
      replay:     replayVerification,
    },
    overallStatus: _computeOverallStatus(entry, chainVerification, signatureVerification, replayVerification),
  };
}

function _computeOverallStatus(entry, chain, sig, replay) {
  if (!entry)                                return 'UNKNOWN';
  if (!chain.valid)                          return 'COMPROMISED';
  if (chain.tamperingDetected)               return 'COMPROMISED';
  if (sig.status === 'INVALID')              return 'INVALID';
  if (replay.status === 'REPLAYS_DETECTED')  return 'REPLAYED';
  if (sig.status === 'VALID' && chain.valid) return 'VERIFIED';
  if (sig.status === 'UNAVAILABLE')         return 'PARTIAL';
  return 'UNKNOWN';
}

// ── Self-contained offline evidence bundle ─────────────────────────
//
// The evidence package generated above is already independently verifiable
// offline (full signature, full public key, canonical hash
// input). What it does NOT carry is proof that the underlying decision was
// ever entered into the tamper-evident RFC6962 transparency log — that proof
// (a Merkle inclusion path) lives in a completely separate subsystem
// (src/core/transparency/) with its own storage and its own offline
// verification primitives (merkle.js), never previously combined with an
// evidence package into one exportable artifact. generateEvidenceBundle()
// closes that gap: it wraps a full evidence package together with the
// artifact's Merkle inclusion proof (via the shared proofLookup helper —
// see proofLookup.js's header comment for why this is extracted rather than
// reimplemented) inside one more Ed25519-sealed envelope, so a third party
// can verify BOTH — the decision's own signature chain AND its inclusion in
// the published transparency log — from a single downloaded JSON file, with
// zero network access, zero database access, and no running QODIQA
// instance. See tools/verify/verify.bundle.external.js for the standalone offline
// verifier this bundle format is designed for.

function _bundleContent(bundle) {
  return {
    schema:         bundle.schema,
    generatedAt:    bundle.generatedAt,
    artifactId:     bundle.artifactId,
    evidencePackage: bundle.evidencePackage,
    transparency:    bundle.transparency,
  };
}

// Ed25519-signs the bundle ENVELOPE (evidencePackage + transparency proof
// together), distinct from _signPackage()'s seal over the evidence package
// alone. Without this, an attacker could take a validly-signed evidence
// package for artifact A and splice in a validly-signed inclusion proof for
// unrelated artifact B — each half would still verify individually, since
// nothing binds them together. This seal is that binding. Same best-effort
// degrade-to-null contract as _signPackage() — see its comment for why.
function _signBundle(content) {
  const canonical = stableStringify(content);
  const hashBuf   = domainSeparatedHash(ARTIFACT_DOMAINS.BUNDLE, canonical);

  try {
    const signingKey = getSigningKey(_clientId());
    if (!signingKey.privDer) {
      return {
        signature: null, keyId: signingKey.keyId ?? null, publicKey: null,
        signingAlgorithm: 'Ed25519', domain: ARTIFACT_DOMAINS.BUNDLE, signedAt: null,
        sealError: 'SIGNING_UNAVAILABLE_NATIVE_PROVIDER',
      };
    }
    return {
      signature:        sign(hashBuf, signingKey.privDer),
      keyId:            signingKey.keyId,
      publicKey:        signingKey.pubDer.toString('base64'),
      signingAlgorithm: 'Ed25519',
      domain:           ARTIFACT_DOMAINS.BUNDLE,
      signedAt:         _now(),
      sealError:        null,
    };
  } catch (err) {
    return {
      signature: null, keyId: null, publicKey: null, signingAlgorithm: 'Ed25519',
      domain: ARTIFACT_DOMAINS.BUNDLE, signedAt: null, sealError: err.message,
    };
  }
}

/**
 * Generate a self-contained, offline-verifiable evidence bundle for the
 * given artifactId — evidence package + Merkle transparency inclusion proof,
 * sealed together with one more Ed25519 signature over the combined content.
 *
 * @param {string}   artifactId
 * @param {object[]} policies
 * @param {object}  [requestor]
 * @param {string|null} [tenantId]
 * @returns {Promise<{ found: boolean, bundle: object|null, missing: string[] }>}
 */
async function generateEvidenceBundle(artifactId, policies, requestor, tenantId = null) {
  const { found, package: evidencePackage, missing } = await generateEvidencePackage(artifactId, policies, requestor, tenantId);

  if (!found) {
    return { found: false, bundle: null, missing };
  }

  const { proof: inclusionProof, message: transparencyNote } =
    await _safeAsync(() => proofLookup.getInclusionProofForArtifact(artifactId),
      { proof: null, message: 'Transparency proof lookup failed' });

  const bundle = {
    schema:      BUNDLE_SCHEMA_VERSION,
    generatedAt: _now(),
    artifactId,
    evidencePackage,
    transparency: inclusionProof
      ? { available: true, inclusionProof }
      : { available: false, note: transparencyNote ?? 'No transparency inclusion proof available' },
    integrity: null, // filled in below
  };

  const seal = _signBundle(_bundleContent(bundle));
  bundle.integrity = {
    bundleHash:       canonicalHash(_bundleContent(bundle)),
    algorithm:        'SHA-256',
    signature:        seal.signature,
    publicKey:        seal.publicKey,
    keyId:            seal.keyId,
    signingAlgorithm: seal.signingAlgorithm,
    domain:           seal.domain,
    signedAt:         seal.signedAt,
    sealError:        seal.sealError,
  };

  return { found: true, bundle, missing };
}

async function _safeAsync(fn, fallback) {
  try { return await fn(); } catch (_) { return fallback; }
}

// the transparency key statuses this instance publishes as verifiable at
// GET /.well-known/qodiqa/transparency-keys (well-known.js VERIFIABLE) — the server-side trust set.
const _TRANSPARENCY_VERIFIABLE_STATUSES = new Set(['active', 'deprecated']);

/**
 * resolve a transparency signer key from THIS instance's transparency key store (public key only), by the
 * keyId the proof names. The proof carries no key material, so the store is the sole trust anchor — the same rule
 * tools/verify/verify.bundle.external.js applies with --transparency-keys.
 */
function _trustedTransparencyKey(keyId) {
  if (!keyId) return { ok: false, reason: 'UNTRUSTED_KEY: the proof names no signerKeyId' };
  const tks = require('../transparency/transparencyKeyStore');
  let status;
  let rec;
  try {
    status = tks.getKeyStatus(keyId);
    rec    = tks.getPublicKey(keyId);
  } catch (err) {
    return { ok: false, reason: `UNTRUSTED_KEY: ${err.message}` };
  }
  if (!_TRANSPARENCY_VERIFIABLE_STATUSES.has(status)) {
    return { ok: false, reason: `UNTRUSTED_KEY: transparency key ${keyId} has status ${status ?? '(unknown)'}` };
  }
  const pubDer = rec && (rec.pubDer || rec);
  if (!Buffer.isBuffer(pubDer)) return { ok: false, reason: `UNTRUSTED_KEY: no transparency key for ${keyId}` };
  return { ok: true, pubDer };
}

/**
 * the trust half of transparency-proof verification (mirrors tools/verify/verify.bundle.external.js
 * verifyTransparencyProof): entryHash covers the entry fields, the leaf is bound to this artifact, and the entry and
 * root signatures verify under trusted transparency keys. Returns the failure reasons ([] = all passed).
 */
function _verifyTransparencyProofTrust(log, proof, artifactId) {
  const reasons = [];
  if (!proof || !proof.entry || !proof.root) return ['TRANSPARENCY_PROOF_MALFORMED'];
  const { entry, root } = proof;

  if (log.computeEntryHash(entry) !== entry.entryHash) {
    reasons.push('TRANSPARENCY_ENTRY_HASH_MISMATCH: entryHash does not cover the entry fields');
  }
  // Binding: the leaf must be registered for THIS artifact (DECISION leaf under the id, lifecycle leaves suffixed).
  const ea = String(entry.artifactId ?? '');
  if (typeof artifactId !== 'string' || !artifactId || !(ea === artifactId || ea.startsWith(`${artifactId}:`))) {
    reasons.push(`TRANSPARENCY_ENTRY_NOT_BOUND: leaf artifactId ${ea || '(none)'} does not name artifact ${artifactId}`);
  }
  const ek = _trustedTransparencyKey(entry.signerKeyId);
  if (!ek.ok) reasons.push(`TRANSPARENCY_ENTRY_KEY: ${ek.reason}`);
  else if (!log.verifyEntrySignature(entry, ek.pubDer)) reasons.push('TRANSPARENCY_ENTRY_SIGNATURE_INVALID');
  const rk = _trustedTransparencyKey(root.signerKeyId);
  if (!rk.ok) reasons.push(`TRANSPARENCY_ROOT_KEY: ${rk.reason}`);
  else if (!log.verifyRootSignature(root, rk.pubDer)) reasons.push('TRANSPARENCY_ROOT_SIGNATURE_INVALID');
  return reasons;
}

/**
 * Independently verify a generated evidence bundle — pure function except
 * for the nested evidence-package/transparency-proof checks, which are
 * themselves pure. No I/O, no database, no key store lookups: mirrors
 * exactly what an external, offline third-party verifier
 * (tools/verify/verify.bundle.external.js) must do.
 *
 * @param {object} bundle — as returned by generateEvidenceBundle()
 * @returns {{ valid: boolean, bundleHashValid: boolean, bundleSignatureValid: boolean|null,
 *             packageValid: boolean, transparencyProofValid: boolean|null, reasons: string[] }}
 */
function verifyEvidenceBundle(bundle) {
  const reasons = [];

  if (!bundle || typeof bundle !== 'object' || !bundle.evidencePackage || !bundle.integrity) {
    return {
      valid: false, bundleHashValid: false, bundleSignatureValid: null,
      packageValid: false, transparencyProofValid: null, reasons: ['MALFORMED_BUNDLE'],
    };
  }

  // 1. Bundle envelope hash.
  const content            = _bundleContent(bundle);
  const computedBundleHash = canonicalHash(content);
  const bundleHashValid    = computedBundleHash === bundle.integrity.bundleHash;
  if (!bundleHashValid) reasons.push('BUNDLE_HASH_MISMATCH');

  // 2. Bundle envelope Ed25519 signature — binds evidencePackage and
  //    transparency together so neither can be swapped independently.
  let bundleSignatureValid = null;
  const { signature, publicKey, domain, keyId } = bundle.integrity;
  if (domain && domain !== ARTIFACT_DOMAINS.BUNDLE) {
    bundleSignatureValid = false;
    reasons.push(`DOMAIN_MISMATCH: ${domain}`);
  } else if (signature && publicKey) {
    const tk = _trustedSealKey(keyId, publicKey);  // trusted key store, never the embedded key
    if (!tk.ok) {
      bundleSignatureValid = false;
      reasons.push(tk.reason);
    } else {
      try {
        const canonical  = stableStringify(content);
        const hashBuf    = domainSeparatedHash(ARTIFACT_DOMAINS.BUNDLE, canonical);
        bundleSignatureValid = verify(hashBuf, signature, tk.pubDer);
      } catch (err) {
        bundleSignatureValid = false;
        reasons.push('BUNDLE_SIGNATURE_VERIFY_ERROR: ' + err.message);
      }
      if (!bundleSignatureValid) reasons.push('BUNDLE_SIGNATURE_INVALID');
    }
  } else {
    reasons.push('BUNDLE_SIGNATURE_UNAVAILABLE');
  }

  // 3. Nested evidence package — its own full self-contained verification.
  const packageResult = verifyEvidencePackage(bundle.evidencePackage);
  if (!packageResult.valid) reasons.push('EVIDENCE_PACKAGE_INVALID', ...packageResult.reasons);

  // 4. Transparency inclusion proof, if present — structure (log.verifyInclusionProof) AND, the same
  //    trust checks the standalone tools/verify/verify.bundle.external.js applies: entry hash, entry + root Ed25519 signatures
  //    against this instance's TRUSTED transparency keys, and the leaf ↔ artifact binding.
  let transparencyProofValid = null;
  if (bundle.transparency?.available) {
    const log = require('../transparency/log');
    try {
      const proof       = bundle.transparency.inclusionProof;
      const proofResult = log.verifyInclusionProof(proof);
      if (!proofResult.valid) reasons.push('TRANSPARENCY_PROOF_INVALID: ' + (proofResult.failureReason ?? 'unknown'));
      const trustReasons = _verifyTransparencyProofTrust(log, proof, bundle.artifactId);
      reasons.push(...trustReasons);
      transparencyProofValid = proofResult.valid && trustReasons.length === 0;
    } catch (err) {
      transparencyProofValid = false;
      reasons.push('TRANSPARENCY_PROOF_VERIFY_ERROR: ' + err.message);
    }
  }

  return {
    valid: bundleHashValid && bundleSignatureValid === true && packageResult.valid && transparencyProofValid !== false,
    bundleHashValid,
    bundleSignatureValid,
    packageValid: packageResult.valid,
    transparencyProofValid,
    reasons,
  };
}

module.exports = {
  generateEvidencePackage,
  exportAuditChain,
  streamAuditChainExport,   //
  AuditHistoryUnavailableError,   //
  generateVerificationOutput,
  verifyEvidencePackage,
  generateEvidenceBundle,
  verifyEvidenceBundle,
  SCHEMA_VERSION,
  GENERATOR_VERSION,
  BUNDLE_SCHEMA_VERSION,
};
