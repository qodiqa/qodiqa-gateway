'use strict';

const crypto          = require('crypto');
const { domainSeparatedHash } = require('../src/infra/crypto/hashing');
const stableStringify = require('./utils/stableStringify');

// Domain constant — must match ARTIFACT_DOMAINS.POLICY in src/infra/crypto/hashing.js.
// Changing this string invalidates all existing policyHash values.
const POLICY_DOMAIN = 'QODIQA::POLICY::V1';

// Policy evaluators (see services/policy/evaluators/*.js) preprocess raw
// config into a runtime-optimized form — e.g. blockIp.js's preprocess()
// adds `_blocklistSet: new Set(config.blocklist)` for O(1) lookups, and
// timeWindow.js's preprocess() adds `_windows: [...{days: new Set(...)}]`.
// These derived fields are underscore-prefixed by established convention
// (the same convention reportIntegrity.js uses for its own excluded
// `signature`/`signedAt`/`_hash` fields) and are NOT part of the canonical
// policy definition — they are caches computed FROM the canonical fields,
// which remain present alongside them.
//
// computePolicyHash is called both on freshly-loaded policies (loader.js,
// pre-preprocessing) and on the live in-memory policy set used for
// enforcement (services/policy/evaluatePolicyDecision.js, post-preprocessing). Stripping
// derived fields before hashing makes the digest depend only on the actual
// policy content in both cases — so it actually changes when policy content
// (e.g. a blocklist) changes, which is the entire point of a forensic
// content fingerprint. Without this, a Set instance has no defined
// canonical representation (see src/utils/stableStringify.js) and — before
// this fix existed — silently produced the same hash for any two
// blocklists, defeating the fingerprint's purpose.
function _stripDerivedFields(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(_stripDerivedFields);
  // Null-prototype accumulator: a "__proto__"-keyed value assigned onto a
  // normal {} silently invokes the inherited setter instead of creating an
  // own property, which would strip the key here before stableStringify's
  // own forbidden-key check ever sees it. Object.create(null) preserves it
  // so that check still fires downstream (defense in depth — loader.js
  // already rejects poison keys upstream, but this function is exported
  // and may be called directly by other callers).
  const out = Object.create(null);
  for (const k of Object.keys(value)) {
    // "__proto__" also starts with "_" but is a forbidden key (spec §6.1),
    // not a derived/cache field — it must NOT be swallowed here, or
    // stableStringify's own forbidden-key rejection would never see it.
    if (k !== '__proto__' && k.startsWith('_')) continue;
    out[k] = _stripDerivedFields(value[k]);
  }
  return out;
}

/**
 * Compute the canonical policy hash for an informational audit commitment.
 *
 * Formula: SHA-256("QODIQA::POLICY::V1" || stableStringify(policies))
 *
 * Domain separation prevents policy hashes from colliding with request hashes
 * or artifact envelope hashes (which use different domain prefixes).
 *
 * policyHash is INFORMATIONAL ONLY — it is a forensic record of what policy
 * set was active at signing time.  The runtime NEVER compares
 * artifact.payload.policyHash against current live policies.  Enforcement
 * always uses the current live policy set regardless of the embedded hash.
 *
 * stableStringify sorts object keys recursively, so key-ordering differences
 * in individual policy objects never affect the digest. Underscore-prefixed
 * derived/cache fields (see _stripDerivedFields above) are excluded so the
 * hash reflects only the canonical policy definition, whether policies is
 * the raw loaded form or the preprocessed live-enforcement form.
 *
 * Throws on any invalid input — fail-closed everywhere.
 *
 * @param {ReadonlyArray} policies — non-empty array of policy objects
 * @returns {string}              — 64-char lowercase hex SHA-256 digest
 */
function computePolicyHash(policies) {
  if (!Array.isArray(policies) || policies.length === 0) {
    throw new Error('computePolicyHash: policies must be a non-empty array');
  }
  const canonical = stableStringify(_stripDerivedFields(policies));
  return domainSeparatedHash(POLICY_DOMAIN, canonical).toString('hex');
}

/**
 * Constant-time equality check for two policy hash hex strings.
 *
 * FOR AUDIT/FORENSIC USE ONLY — not part of the enforcement path.
 * Use to detect whether the policy set changed between signing and execution
 * (i.e., compare artifact.payload.policyHash against computePolicyHash(currentPolicies)).
 *
 * Returns false for any non-string or non-64-char input rather than throwing,
 * so callers can treat a malformed hash as "not equal" without crashing.
 *
 * @param {string} a — 64-char hex SHA-256 digest
 * @param {string} b — 64-char hex SHA-256 digest
 * @returns {boolean}
 */
function policyHashesEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== 64 || b.length !== 64) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

// Domain for the per-rule companion hash (TRACE-4). A distinct domain from
// POLICY_DOMAIN above — this hashes a single rule's content, not the whole
// policy set, and domain separation prevents a rule hash from ever colliding
// with (or being confused for) a whole-set policyHash.
const POLICY_RULE_DOMAIN = 'QODIQA::POLICY::RULE::V1';

/**
 * Compute a deterministic hash for a SINGLE policy rule — the companion to
 * computePolicyHash() above (TRACE-4 remediation).
 *
 * policyHash identifies only the whole ACTIVE POLICY SET (by design — see
 * its own doc comment; that formula must not change, or every historical
 * artifact's policyHash becomes incomparable with no versioning path). It
 * does not, by itself, let an auditor independently verify WHICH specific
 * rule produced a decision — only the engine's own policyId string claims
 * that, unverifiable without a live policy store lookup.
 *
 * computeRuleHash(policy) closes that gap: same canonicalization primitives
 * as computePolicyHash (_stripDerivedFields, stableStringify,
 * domainSeparatedHash), applied to exactly the one rule object that decided
 * — reused, not reimplemented. Combined with the policyId/policyVersion the
 * engine already records, an independent auditor can recompute this hash
 * from a copy of the rule's canonical definition and confirm it matches
 * what's embedded in the audit-chain-protected `policyDecision` object
 * (schemaVersion 3+, entryBuilder.js), without needing a live policy store.
 *
 * @param {object} policy — a single policy/rule object (as loaded by
 *   policyLoader.loadPolicies(), pre- or post-preprocessing)
 * @returns {string} 64-char lowercase hex SHA-256 digest
 */
function computeRuleHash(policy) {
  if (!policy || typeof policy !== 'object') {
    throw new Error('computeRuleHash: policy must be an object');
  }
  const canonical = stableStringify(_stripDerivedFields(policy));
  return domainSeparatedHash(POLICY_RULE_DOMAIN, canonical).toString('hex');
}

module.exports = { computePolicyHash, policyHashesEqual, computeRuleHash, POLICY_RULE_DOMAIN };
