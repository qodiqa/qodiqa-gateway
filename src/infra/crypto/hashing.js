'use strict';

const crypto        = require('crypto');
const stableStringify = require('../../utils/stableStringify');

// Single canonical serialization authority — delegates to stableStringify.
// No local copy; all callers share the same deterministic implementation.
const sortedJSON = stableStringify;

function computeHash({ prompt, consent, purpose, timestamp, decision, ai_output }) {
  const canonical = sortedJSON({ ai_output, consent, decision, prompt, purpose, timestamp });
  return domainSeparatedHash(ARTIFACT_DOMAINS.CANONICAL, canonical).toString('hex');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function sha256Raw(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function generateArtifactId(hash, timestamp) {
  return sha256Hex(`${hash}|${timestamp}`).slice(0, 32);
}

function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

function generateUUID() {
  return crypto.randomUUID();
}

function timingSafeCompare(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// Canonical domain identifiers — one per artifact class.
// Never share domains across classes; cross-protocol reuse must be impossible.
const ARTIFACT_DOMAINS = Object.freeze({
  CANONICAL:   'QODIQA::CANONICAL::V1',
  ARTIFACT:    'QODIQA::ARTIFACT::V1',    // full-envelope domain — covers payload+timestamp+expiry+publicKeyId
  REQUEST:     'QODIQA::REQUEST::V1',     // request-binding domain — covers method+path+body
  REQUEST_V2:  'QODIQA::REQUEST::V2',     // protocol V2 request binding (docs/protocol/PROTOCOL-V2.md section 3) — covers v+method+path+query+headers+body under JCS-P1
  POLICY:      'QODIQA::POLICY::V1',      // policy hash domain — covers canonical policy set at signing time
  CERTIFICATE: 'QODIQA::CERTIFICATE::V1', // certificate artifact domain — covers canonical certificate payload
  EVIDENCE:    'QODIQA::EVIDENCE::V1',    // evidence chain hash domain — covers canonical evidence fields
  AUDIT:       'QODIQA::AUDIT::V1',       // audit record hash domain — covers full serialised audit entry
  POLICY_GOVERNANCE: 'QODIQA::POLICY_GOVERNANCE::V1', // maker-checker workflow domain — change-request payloads and approval_events entries. Distinct from POLICY (whole-live-set signing fingerprint).
  CONSENT:     'QODIQA::CONSENT::V1',      // TRACE-2 — consent provenance reference hash, used by the transparency log leaf (src/core/transparency/enforcementBridge.js) to bind a leaf to a full ConsentProvenance object without embedding it wholesale.
  IDEMPOTENCY: 'QODIQA::IDEMPOTENCY::V1',  // API-2 — idempotency request fingerprint domain, covers the immutable, execution-affecting fields of an /ai/chat request (see src/core/idempotency/fingerprint.js). Never shares a domain with ARTIFACT/REQUEST so a fingerprint can never collide with or be mistaken for an envelope/binding hash.
  EXECUTION_INVARIANT: 'QODIQA::EXECUTION_INVARIANT::V1', // HMAC message domain for the execution-invariant token (services/executionInvariantToken.js), binding requestHash+policyHash+issuedAt. Never shares a domain with any other class so an execution-invariant signature can never be confused with or replayed as any other artifact's hash/signature.
  OUTPUT:      'QODIQA::OUTPUT::V1',      // audit schema v7 (R-5/R-5a) — `outputHash` of the exact output content bytes delivered to the client. Distinct from every other class so an output hash is never confusable with an artifact/content/audit hash.
  RECEIPT:     'QODIQA::RECEIPT::V1',     // signed receipt (docs/protocol/PROTOCOL-V2.md section 6): Ed25519 over SHA-256(domain || JCS-P1(receipt without signature)), signed with a TRANSPARENCY key. Distinct from every other class so a receipt signature is never confusable with a leaf, root or artifact signature.
  BUNDLE:      'QODIQA::EVIDENCE_BUNDLE::V1', // self-contained offline evidence bundle envelope domain (src/core/evidence/generator.js generateEvidenceBundle()). Covers { evidencePackage, transparency } together, so the envelope itself — not just the evidence package inside it — is tamper-evident (e.g. against splicing in a transparency/Merkle proof from a different artifact). Distinct from EVIDENCE, which seals the evidence package alone.
});

// Generic domain-separated hash: SHA-256(domain || canonical).
// Prevents cross-protocol signature reuse between artifact classes.
// Returns a raw Buffer (32 bytes) — callers convert to hex as needed.
function domainSeparatedHash(domain, canonical) {
  if (typeof domain    !== 'string' || !domain)    throw new TypeError('domainSeparatedHash: domain must be a non-empty string');
  if (typeof canonical !== 'string' && !Buffer.isBuffer(canonical)) throw new TypeError('domainSeparatedHash: canonical must be a string or Buffer');
  return crypto.createHash('sha256')
    .update(domain,    'utf8')
    .update(canonical, 'utf8')
    .digest();
}

module.exports = { sortedJSON, computeHash, sha256Hex, sha256Raw, domainSeparatedHash, ARTIFACT_DOMAINS, generateArtifactId, generateNonce, generateUUID, timingSafeCompare };
