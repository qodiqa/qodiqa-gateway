'use strict';

/**
 * Audit Chain Entry Builder — shared between the single-node path
 * (audit-log.js, prevHash from process-local _tailHash) and the distributed
 * path (distributedOrdering.js, prevHash from the PG-locked audit_chain_head
 * row). Extracted so both paths validate/shape entries identically — field
 * validation is a security-relevant surface (decision/signature/hash
 * presence checks), and having two independently-maintained copies would be
 * a drift risk between the two ordering modes.
 *
 * See QODIQA-PROTOCOL-SPEC.md §11.3 for the field/hash spec this implements.
 */

const { sortedJSON, domainSeparatedHash, ARTIFACT_DOMAINS, sha256Hex } = require('../../infra/crypto/hashing.js');
const { currentArtifactFacts } = require('./requestAuditContext');

// The 9 fields hashed into a legacy (schemaVersion 1) entry's chain hash.
const CORE_HASH_FIELDS_V1 = Object.freeze([
  'artifactId', 'decision', 'inputHash', 'policyHash',
  'prevHash', 'requestHash', 'signature', 'timestamp', 'verificationResult',
]);

// schemaVersion 2: adds `publicKeyId` and
// `schemaVersion` itself into the protected hash set.
const CORE_HASH_FIELDS_V2 = Object.freeze([
  ...CORE_HASH_FIELDS_V1, 'publicKeyId', 'schemaVersion',
]);

// schemaVersion 3 (TRACE-2 remediation): adds `consentProvenance` and
// `policyDecision` into the protected hash set — the immutable consent
// record snapshot and policy-rule decision (matched rule id/version,
// engine version, ordered evaluation path) that authorized this decision.
// Both are full objects (or null when not applicable), not pre-hashed
// scalars: sortedJSON()/stableStringify() already canonicalizes nested
// objects/arrays deterministically, so no new hashing primitive is needed.
const CORE_HASH_FIELDS_V3 = Object.freeze([
  ...CORE_HASH_FIELDS_V2, 'consentProvenance', 'policyDecision',
]);

// schemaVersion 4: adds `callerContext` — the
// authenticated caller identity (callerId/callerName/environment/
// credentialType) that /sign bound into the artifact's payload, read
// straight off the signature-verified artifact and threaded here by
// aiChat.js. Deliberately a TOP-LEVEL, always-present (possibly null) field
// independent of consent: consentProvenance is only populated when a
// requireConsent policy is configured for the route, but caller attribution
// must be durable for every decision regardless of which policies apply —
// see QODIQA-PROTOCOL-SPEC.md §11.3 and NONREP-1-REMEDIATION-REPORT.md.
// null means either "this decision predates schemaVersion 4" or "the
// artifact was signed before the remediation shipped" — the
// evidence generator's caller section (_buildCallerSection) is responsible
// for distinguishing the two for an auditor; entryBuilder itself does not.
const CORE_HASH_FIELDS_V4 = Object.freeze([
  ...CORE_HASH_FIELDS_V3, 'callerContext',
]);

// schemaVersion 5: adds `provider` and `model` — the AI
// provider/model identity that actually executed (or would have executed)
// this request. Previously these lived only inside `executionContext`, which
// is NOT hash-protected (see the comment in normalizeFields() below) —
// meaning an attacker who could rewrite audit.log/audit_chain in place could
// silently change which provider/model a historical decision was attributed
// to without invalidating chainHash. Provider/model are exactly the kind of
// execution-changing metadata that must be protected: which model executed a
// request materially affects the request's risk/compliance posture. There is
// no separate provider-id/model-id concept anywhere in this codebase
// (services/providers/*) — the provider name (e.g. "anthropic") and model
// string (e.g. "claude-3-opus-20240229") already ARE the identifiers, so no
// new field shape is invented here.
const CORE_HASH_FIELDS_V5 = Object.freeze([
  ...CORE_HASH_FIELDS_V4, 'provider', 'model',
]);

// schemaVersion 6: adds `stage`,
// `reason`, `semantic`, `tokenUsage`, `responseId` — the residual fields of
// `executionContext` (see the comment in normalizeFields() below)
// with real evidentiary weight, promoted individually out of that opaque,
// unhashed blob following V5's own precedent for provider/model rather than
// hashing the whole blob. Closes the gap
// AUDIT-SCHEMA-2026-09-10.md documented: an attacker with in-place write
// access to audit.log/audit_chain could previously alter the *stated reason*
// for a BLOCK, the recorded semantic classification, token-usage figures, or
// the linked provider response id, without invalidating the chain hash.
// `replayOf` and `completionStatus` were considered but NOT promoted — the
// owner's approved option named exactly these 5 fields (see's decision
// brief); replay detection itself is already enforced at write time via a
// separate mechanism (the nonce/dedup check), not the historical record.
const CORE_HASH_FIELDS_V6 = Object.freeze([
  ...CORE_HASH_FIELDS_V5, 'stage', 'reason', 'semantic', 'tokenUsage', 'responseId',
]);

// schemaVersion 7:
// adds `entryType` (DECISION | INTENT | STREAM_OPENED, R-4), `outputHash` (domain-separated SHA-256 of the exact
// output content bytes delivered to the client, R-5/R-5a/R-5b), the previously unhashed `tenantId`, `requestId`,
// `organizationId` and the WHOLE `executionContext`, and `executingProvider` — the effective provider
// after routing/failover (R-7; `provider` keeps its v5 meaning: the REQUESTED provider). Same domain
// (QODIQA::AUDIT::V1, R-3), same canonicalization; every V7 field is always present (possibly null).
const CORE_HASH_FIELDS_V7 = Object.freeze([
  ...CORE_HASH_FIELDS_V6, 'entryType', 'outputHash', 'tenantId', 'requestId', 'organizationId', 'executionContext', 'executingProvider',
]);

// schemaVersion 8: ten new always-present (possibly null) hashed fields that every
// planned wave needs, so the hash contract is opened once: the artifact's issuance time and protocol version, the
// agent/action/approval identity, the DLP transformation, the delivered byte count and completion status.
const V8_NEW_FIELDS = Object.freeze([
  'issuedAt', 'protocolVersion', 'agentId', 'sessionId', 'actionSeq', 'actionHash', 'approvalRef', 'dlp', 'bytesDelivered', 'completionStatus',
]);
const CORE_HASH_FIELDS_V8 = Object.freeze([...CORE_HASH_FIELDS_V7, ...V8_NEW_FIELDS]);

// The schema version the WRITER stamps. 7 until the owner enables QODIQA_AUDIT_SCHEMA_V8 (default off; one-directional,
// AUDIT-V8-FREEZE 1.5). Read at call time so a test or an operator restart picks the value up without a module reload.
const CURRENT_SCHEMA_VERSION = 7;
function currentSchemaVersion() {
  return process.env.QODIQA_AUDIT_SCHEMA_V8 === 'true' ? 8 : CURRENT_SCHEMA_VERSION;
}

const VALID_DECISIONS = new Set(['ALLOW', 'BLOCK']);

// R-4: exactly these three; no others without a future versioned decision.
const ENTRY_TYPES = Object.freeze(['DECISION', 'INTENT', 'STREAM_OPENED']);
// v8 adds the closing and system entry types of AUDIT-V8-FREEZE section 3.
const ENTRY_TYPES_V8 = Object.freeze([
  ...ENTRY_TYPES, 'COMMIT', 'ACTION_INTENT', 'ACTION_COMMIT', 'APPROVAL_REQUESTED', 'APPROVAL_DECIDED', 'APPROVAL_EXPIRED',
  'KILL_SWITCH', 'DLP_TRANSFORM', 'DELEGATION_ISSUED', 'DELEGATION_REVOKED',
]);
const COMPLETION_STATUSES = Object.freeze(['COMPLETE', 'CANCELLED', 'ERROR', 'TIMEOUT', 'CLIENT_DISCONNECTED', 'OUTCOME_UNKNOWN']);
const DLP_ACTIONS = Object.freeze(['DETECT', 'REDACT', 'BLOCK', 'MASK']);
// AUDIT-V8-FREEZE section 3, one row per NEW type: the fixed values that are not free. `allowed` lists the new (v8)
// fields the type may carry non-null, `required` those it must; `ctx` is the frozen executionContext key (null = the
// entry carries no executionContext); `system` entries have signature SYSTEM and verificationResult false.
const V8_TYPE_RULES = Object.freeze({
  COMMIT: { stage: 'COMMIT', outcomes: { ALLOW: ['RESPONSE_DELIVERED', 'RESPONSE_FAILED'] }, suffix: ':commit', output: true, system: false,
    allowed: ['issuedAt', 'protocolVersion', 'bytesDelivered', 'completionStatus'], required: ['bytesDelivered', 'completionStatus'], ctx: null },
  ACTION_INTENT: { stage: 'ACTION_DISPATCH', outcomes: { ALLOW: ['ACTION_AUTHORIZED'] }, suffix: ':action_intent', output: false, system: false,
    allowed: ['issuedAt', 'protocolVersion', 'agentId', 'sessionId', 'actionSeq', 'actionHash', 'approvalRef'], required: ['agentId', 'sessionId', 'actionSeq', 'actionHash'], ctx: 'action' },
  ACTION_COMMIT: { stage: 'ACTION_COMMIT', outcomes: { ALLOW: ['ACTION_COMPLETED', 'ACTION_FAILED'] }, suffix: ':action_commit', output: true, system: false,
    allowed: ['issuedAt', 'protocolVersion', 'agentId', 'sessionId', 'actionSeq', 'actionHash', 'approvalRef', 'completionStatus'], required: ['agentId', 'sessionId', 'actionSeq', 'actionHash', 'completionStatus'], ctx: 'action' },
  APPROVAL_REQUESTED: { stage: 'APPROVAL', outcomes: { BLOCK: ['APPROVAL_REQUIRED'] }, suffix: ':approval_requested', output: false, system: true,
    allowed: ['approvalRef', 'actionHash'], required: ['approvalRef', 'actionHash'], ctx: 'approval' },
  APPROVAL_DECIDED: { stage: 'APPROVAL', outcomes: { ALLOW: ['APPROVED'], BLOCK: ['DENIED'] }, suffix: ':approval_decided', output: false, system: true,
    allowed: ['approvalRef', 'actionHash'], required: ['approvalRef', 'actionHash'], ctx: 'approval' },
  APPROVAL_EXPIRED: { stage: 'APPROVAL', outcomes: { BLOCK: ['APPROVAL_EXPIRED'] }, suffix: ':approval_expired', output: false, system: true,
    allowed: ['approvalRef', 'actionHash'], required: ['approvalRef', 'actionHash'], ctx: 'approval' },
  KILL_SWITCH: { stage: 'KILL_SWITCH', outcomes: { BLOCK: ['KILL_SWITCH_ON'], ALLOW: ['KILL_SWITCH_OFF'] }, suffix: ':kill_switch', output: false, system: true,
    allowed: [], required: [], ctx: 'killSwitch' },
  DLP_TRANSFORM: { stage: 'DLP', outcomes: { ALLOW: ['DLP_DETECT', 'DLP_REDACT', 'DLP_MASK'], BLOCK: ['DLP_BLOCK'] }, suffixRe: /:dlp_(in|out)_[0-9]+$/, output: false, system: true,
    allowed: ['dlp'], required: ['dlp'], ctx: null },
  DELEGATION_ISSUED: { stage: 'DELEGATION', outcomes: { ALLOW: ['DELEGATION_ISSUED'] }, suffix: ':delegation_issued', output: false, system: true,
    allowed: [], required: [], ctx: 'delegation' },
  DELEGATION_REVOKED: { stage: 'DELEGATION', outcomes: { ALLOW: ['DELEGATION_REVOKED'] }, suffix: ':delegation_revoked', output: false, system: true,
    allowed: [], required: [], ctx: 'delegation' },
});
// The v8 fields the three pre-existing types may carry (everything else on them must be null).
const V8_LEGACY_TYPE_ALLOWED = Object.freeze({
  DECISION: ['issuedAt', 'protocolVersion', 'completionStatus'],
  INTENT: ['issuedAt', 'protocolVersion'],
  STREAM_OPENED: ['issuedAt', 'protocolVersion'],
});
// R-8 / R-8a: the fixed values of the two lifecycle entry types (SCHEMA-V7-DESIGN.md §4/§5).
const LIFECYCLE_FIXED = Object.freeze({
  INTENT:        Object.freeze({ decision: 'ALLOW', stage: 'PROVIDER_DISPATCH' }),
  STREAM_OPENED: Object.freeze({ decision: 'ALLOW', stage: 'STREAM_OPENED' }),
});
// R-9: deterministic artifact-id suffixes (artifactId is unique per chain: SCHEMA-V6 §6, PG idx_audit_chain_artifact_id,
// evidence_chain_records UNIQUE(artifact_id)); traceable to the originating artifact and, via the hashed requestId, to
// its DECISION entry.
const LIFECYCLE_ARTIFACT_SUFFIX = Object.freeze({ INTENT: ':intent', STREAM_OPENED: ':stream_opened' });
const HEX64 = /^[0-9a-f]{64}$/;

/** R-5/R-5a: outputHash = hex SHA-256( UTF8("QODIQA::OUTPUT::V1") ‖ UTF8(delivered output content) ). */
function outputHashOf(deliveredContent) {
  if (typeof deliveredContent !== 'string') throw new TypeError('outputHashOf: delivered content must be a string');
  return domainSeparatedHash(ARTIFACT_DOMAINS.OUTPUT, deliveredContent).toString('hex');
}
// R-5/R-5b: nothing delivered → the hash of the EMPTY byte sequence (never null on a v7 DECISION).
const EMPTY_OUTPUT_HASH = outputHashOf('');

// R-5 for streamed output: the SAME value as outputHashOf(chunk1 + chunk2 + …) over the chunks released to the client,
// in delivery order, computed incrementally so the delivered text is never retained. Equality with the one-shot form
// holds for every JS string: a trailing high surrogate is carried into the next chunk, so a surrogate pair split
// across two released chunks is UTF-8-encoded as the pair the client reassembles, never as two U+FFFD halves.
function createOutputHasher() {
  const h = require('crypto').createHash('sha256').update(ARTIFACT_DOMAINS.OUTPUT, 'utf8');
  let carry = '';
  let digest = null;
  let bytes = 0;   // UTF-8 bytes hashed so far (COMMIT bytesDelivered)
  return {
    update(chunk) {
      if (digest !== null) throw new Error('createOutputHasher: update() after digest()');
      if (typeof chunk !== 'string') throw new TypeError('createOutputHasher: chunk must be a string');
      let s = carry + chunk;
      carry = '';
      const last = s.length ? s.charCodeAt(s.length - 1) : 0;
      if (last >= 0xD800 && last <= 0xDBFF) { carry = s.slice(-1); s = s.slice(0, -1); }
      if (s) { h.update(s, 'utf8'); bytes += Buffer.byteLength(s, 'utf8'); }
    },
    digest() {
      if (digest === null) {
        if (carry) { h.update(carry, 'utf8'); bytes += Buffer.byteLength(carry, 'utf8'); }
        digest = h.digest('hex');
      }
      return digest;
    },
    /** UTF-8 bytes of everything hashed (exact once digest() was called). */
    bytes() { return bytes; },
  };
}

function lifecycleArtifactId(artifactId, entryType) {
  const suffix = LIFECYCLE_ARTIFACT_SUFFIX[entryType];
  if (!suffix) throw new Error(`lifecycleArtifactId: no suffix for entryType ${entryType}`);
  return `${artifactId}${suffix}`;
}

/**
 * v7 per-entry shape rules (SCHEMA-V7-DESIGN.md §8, R-4/R-5/R-8/R-8a). Returns null when the entry is not v7 or is
 * well-shaped, else the violation detail code. Field VALUES are already bound by the hash; this checks that the
 * hashed values obey the v7 contract.
 */
function v7ShapeViolation(entry) {
  if (!entry || entry.schemaVersion !== 7) return null;
  const t = entry.entryType;
  if (!ENTRY_TYPES.includes(t)) return 'INVALID_ENTRY_TYPE';
  if (t === 'DECISION') {
    if (typeof entry.outputHash !== 'string' || !HEX64.test(entry.outputHash)) return 'INVALID_OUTPUT_HASH';
    return null;
  }
  const fixed = LIFECYCLE_FIXED[t];
  if (entry.outputHash !== null && entry.outputHash !== undefined) return 'INVALID_ENTRY_SHAPE';
  if (entry.decision !== fixed.decision || entry.stage !== fixed.stage) return 'INVALID_ENTRY_SHAPE';
  return null;
}

const _isInt = (v, min) => typeof v === 'number' && Number.isSafeInteger(v) && v >= min;
const _isStr = (v) => typeof v === 'string' && v.length > 0;
const _isNullish = (v) => v === null || v === undefined;
const V8_FIELD_OK = Object.freeze({
  issuedAt: (v) => _isInt(v, 0),
  protocolVersion: (v) => _isInt(v, 1),
  agentId: _isStr, sessionId: _isStr, approvalRef: _isStr,
  actionSeq: (v) => _isInt(v, 1),
  actionHash: (v) => typeof v === 'string' && HEX64.test(v),
  bytesDelivered: (v) => _isInt(v, 0),
  completionStatus: (v) => COMPLETION_STATUSES.includes(v),
  dlp: (v) => !!v && typeof v === 'object' && !Array.isArray(v)
    && Array.isArray(v.rules) && v.rules.every(_isStr) && DLP_ACTIONS.includes(v.action)
    && typeof v.inputHashBefore === 'string' && HEX64.test(v.inputHashBefore)
    && typeof v.inputHashAfter === 'string' && HEX64.test(v.inputHashAfter),
});
const V8_NULL_ON_NEW_TYPES = Object.freeze([
  'publicKeyId', 'provider', 'model', 'executingProvider', 'semantic', 'tokenUsage', 'responseId', 'consentProvenance', 'policyDecision', 'callerContext',
]);

/**
 * v8 per-entry shape rules (AUDIT-V8-FREEZE section 3). Returns null when the entry is not v8 or is well-shaped, else the
 * violation detail code. Same role as v7ShapeViolation: the VALUES are bound by the hash, this checks that they obey
 * the contract. The independent verifier restates these rules (scripts/audit-repro/verify/auditContract.js).
 */
function v8ShapeViolation(entry) {
  if (!entry || entry.schemaVersion !== 8) return null;
  const t = entry.entryType;
  if (!ENTRY_TYPES_V8.includes(t)) return 'INVALID_ENTRY_TYPE';
  const legacy = V8_LEGACY_TYPE_ALLOWED[t];
  const rule = V8_TYPE_RULES[t];
  const allowed = legacy || rule.allowed;
  for (const f of V8_NEW_FIELDS) {
    const v = entry[f];
    if (_isNullish(v)) continue;
    if (!allowed.includes(f)) return 'INVALID_ENTRY_SHAPE';
    if (!V8_FIELD_OK[f](v)) return 'INVALID_V8_FIELD';
  }
  if (legacy) {
    if (t === 'DECISION') {
      if (typeof entry.outputHash !== 'string' || !HEX64.test(entry.outputHash)) return 'INVALID_OUTPUT_HASH';
      return null;
    }
    const fixed = LIFECYCLE_FIXED[t];
    if (!_isNullish(entry.outputHash)) return 'INVALID_ENTRY_SHAPE';
    return (entry.decision === fixed.decision && entry.stage === fixed.stage) ? null : 'INVALID_ENTRY_SHAPE';
  }
  for (const f of rule.required) if (_isNullish(entry[f])) return 'INVALID_V8_FIELD';
  const reasons = rule.outcomes[entry.decision];
  if (!reasons || !reasons.includes(entry.reason) || entry.stage !== rule.stage) return 'INVALID_ENTRY_SHAPE';
  if (t === 'DLP_TRANSFORM' && entry.reason !== `DLP_${entry.dlp.action}`) return 'INVALID_ENTRY_SHAPE';
  if (t === 'DLP_TRANSFORM' ? !(typeof entry.artifactId === 'string' && rule.suffixRe.test(entry.artifactId))
    : !(typeof entry.artifactId === 'string' && entry.artifactId.endsWith(rule.suffix) && entry.artifactId.length > rule.suffix.length)) return 'INVALID_ENTRY_SHAPE';
  if (rule.output ? !(typeof entry.outputHash === 'string' && HEX64.test(entry.outputHash)) : !_isNullish(entry.outputHash)) return 'INVALID_OUTPUT_HASH';
  if (entry.verificationResult !== !rule.system) return 'INVALID_ENTRY_SHAPE';
  if (rule.system && entry.signature !== 'SYSTEM') return 'INVALID_ENTRY_SHAPE';
  if (entry.inputHash !== 'UNAVAILABLE' || entry.requestHash !== 'UNAVAILABLE' || entry.policyHash !== 'UNAVAILABLE') return 'INVALID_ENTRY_SHAPE';
  for (const f of V8_NULL_ON_NEW_TYPES) if (!_isNullish(entry[f])) return 'INVALID_ENTRY_SHAPE';
  const ctx = entry.executionContext;
  if (rule.ctx === null) { if (!_isNullish(ctx)) return 'INVALID_ENTRY_SHAPE'; }
  else if (!ctx || typeof ctx !== 'object' || Array.isArray(ctx) || !ctx[rule.ctx] || typeof ctx[rule.ctx] !== 'object') return 'INVALID_ENTRY_SHAPE';
  return null;
}

/** Shape violation of any version that has one (v7 or v8); null for everything else. */
function shapeViolationOf(entry) {
  if (!entry) return null;
  return entry.schemaVersion === 8 ? v8ShapeViolation(entry) : v7ShapeViolation(entry);
}

/** The entry type a verifier/statistic should assume: v7+ state it; every pre-v7 entry is a DECISION. */
function entryTypeOf(entry) {
  return entry && (entry.schemaVersion === 7 || entry.schemaVersion === 8) ? entry.entryType : 'DECISION';
}

// R-6: the whole executionContext is hashed from v7 on. It must be a plain JSON value that survives the file-log
// (JSON.stringify) and PG (JSONB) round trips unchanged — JSON.stringify DROPS undefined members while the canonical
// form encodes them as null, so the stored copy is normalized ONCE through the canonical serializer: undefined → null
// (the documented canonical rule, SCHEMA-V6 §3), every other value unchanged. Non-plain values (Date, Error, class
// instances, functions, NaN/Infinity, cycles, forbidden keys) are REFUSED (the append fails closed) — never silently
// stringified.
function _normalizeExecutionContextV7(ctx) {
  if (ctx === undefined || ctx === null) return null;
  let canonical;
  try { canonical = sortedJSON(ctx); } catch (err) {
    const e = new Error(`invalid_executionContext: ${err && err.code ? err.code : err.message}`);
    e.code = 'INVALID_EXECUTION_CONTEXT';
    throw e;
  }
  return JSON.parse(canonical);
}

// the schema versions this build can
// verify. Absent/null is a schemaVersion-1 entry (V1 has no schemaVersion field; the PG column
// defaults to 1). Anything else — 7+, the string "6", 0, 1.5, true — used to fall through
// hashFieldsFor() to the V1 set and verify as v1, i.e. an unknown version was silently accepted
// as a different one (with the claimed version not even inside the hash). It is now refused.
const SUPPORTED_SCHEMA_VERSIONS = Object.freeze([1, 2, 3, 4, 5, 6, 7, 8]);

function isSupportedSchemaVersion(entry) {
  const v = entry ? entry.schemaVersion : undefined;
  return v === undefined || v === null || SUPPORTED_SCHEMA_VERSIONS.includes(v);
}

function hashFieldsFor(entry) {
  if (entry && entry.schemaVersion === 8) return CORE_HASH_FIELDS_V8;
  if (entry && entry.schemaVersion === 7) return CORE_HASH_FIELDS_V7;
  if (entry && entry.schemaVersion === 6) return CORE_HASH_FIELDS_V6;
  if (entry && entry.schemaVersion === 5) return CORE_HASH_FIELDS_V5;
  if (entry && entry.schemaVersion === 4) return CORE_HASH_FIELDS_V4;
  if (entry && entry.schemaVersion === 3) return CORE_HASH_FIELDS_V3;
  if (entry && entry.schemaVersion === 2) return CORE_HASH_FIELDS_V2;
  return CORE_HASH_FIELDS_V1;
}

// the value a consumer should PRESENT for a field that a later schema version promoted
// out of the unhashed executionContext (publicKeyId v2, provider/model v5, stage/reason v6): the
// hash-protected top-level value whenever this entry's version hashes the field — even when it is
// null — and the legacy executionContext copy only for older entries. `a ?? ctx.a` is not enough:
// a legitimately-null hashed value would fall back to the unprotected copy, so rewriting
// executionContext (outside the hash) would change what the consumer shows without breaking the chain.
function protectedField(entry, field) {
  if (!entry) return null;
  if (hashFieldsFor(entry).includes(field)) return entry[field] ?? null;
  const ctx = entry.executionContext;
  return ctx && typeof ctx === 'object' ? (ctx[field] ?? null) : null;
}

function coreFieldsOf(entry) {
  const out = {};
  for (const key of hashFieldsFor(entry)) out[key] = entry[key];
  return out;
}

function verifyCanonicalHash(entry) {
  // v7: a v7 entry whose hashed values break the v7 contract (entryType, outputHash, the fixed INTENT /
  // STREAM_OPENED values) is not intact, whatever its hash (walks report the detail via v7IntegrityDetail).
  return _sealIntact(entry) && !shapeViolationOf(entry);
}

/**
 * v7: the detail a walk reports for a failed entry — the v7 shape violation ONLY when the entry is otherwise
 * intact (hash and canonical reproduce, i.e. a self-consistently sealed but ill-shaped v7 entry). A canonical / hash
 * mismatch is reported without a shape detail, in the same order the independent verifier checks
 * (scripts/audit-repro/verify/auditContract.js checkEntryHash: canonical first, then shape).
 */
function v7IntegrityDetail(entry) {
  return _sealIntact(entry) ? shapeViolationOf(entry) : null;
}

function _sealIntact(entry) {
  if (!isSupportedSchemaVersion(entry)) return false;
  if (typeof entry.canonical !== 'string') return false;
  if (domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, entry.canonical).toString('hex') !== entry.hash) return false;
  // (vector K-M-forbidden-key): a stored hashed field that cannot be canonicalized (e.g. a
  // "__proto__" key injected into a hashed object) cannot equal the entry's canonical string.
  // This predicate used to THROW, which the disk scan reported as a generic parse error and the
  // in-memory walker's catch-all as AUDIT_CHAIN_BROKEN with no index — a tampered entry must be
  // reported as tampered, at its position.
  try {
    return sortedJSON(coreFieldsOf(entry)) === entry.canonical;
  } catch (err) {
    if (err && err.name === 'CanonicalizationError') return false;
    throw err;
  }
}

// Recomputes the hash a valid entry's `canonical` string would produce,
// without asserting anything about `entry.hash` — used by diagnostics that
// need to report "expected X, got Y" for a hash mismatch.
function expectedHashFor(entry) {
  return domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, entry.canonical).toString('hex');
}

/**
 * Validates and defaults the raw fields passed to append()/appendDistributed().
 * Does NOT resolve prevHash or compute the hash — that's the ordering-mode-
 * specific step (see buildEntry below). Does NOT perform dedup/replay checks
 * (nonce/artifactId uniqueness) — those are storage-specific: an in-memory
 * Set for single-node, a PG UNIQUE constraint for distributed.
 *
 * @throws {Error} invalid_decision | invalid_inputHash | invalid_signature |
 *                 invalid_requestHash | invalid_policyHash
 */
// / F6-N2. The audit_chain mirror stores per-field values
// through the reversible projection (src/infra/postgres/mirrorProjection.js), but two downstream stores keep RAW
// values: evidence_chain_records (per-field TEXT / JSONB columns) and the persistence-recovery queue (the whole entry
// as a JSONB payload). PostgreSQL cannot represent U+0000 (TEXT and JSONB) or an unpaired UTF-16 surrogate (JSONB;
// TEXT alters it). An entry carrying either would commit to the file log and the mirror yet fail its evidence record
// and then its recovery enqueue — a partial lifecycle. So an append is refused BEFORE anything is persisted when any
// string value or object key, at any depth, of any field it would carry contains U+0000 or a lone surrogate.
//   - fail-closed, deterministic: Error 'invalid_unrepresentable_text: <field path>' (non-retryable invalid_ prefix),
//     code AUDIT_UNREPRESENTABLE_TEXT, and the path of the first offending value (never the value itself);
//   - no raw fallback, no replacement, no normalization: the value is not altered, the append is refused;
//   - ordinary Unicode is accepted: non-ASCII text, controls other than U+0000, and correctly PAIRED surrogates (emoji).
// Applied whatever the deployment mode, so the content an audit chain can hold does not depend on whether PostgreSQL is
// enabled. The file log and canonical hashing are unchanged (nothing that passes this check is treated differently).
const UNREPRESENTABLE_RE = /\u0000|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
function _unrepresentablePath(v, p, seen) {
  if (typeof v === 'string') return UNREPRESENTABLE_RE.test(v) ? p : null;
  if (v === null || typeof v !== 'object') return null;
  if (seen.has(v)) return null;                 // cycles are refused elsewhere (executionContext canonicalization)
  seen.add(v);
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) { const r = _unrepresentablePath(v[i], `${p}[${i}]`, seen); if (r) return r; }
    return null;
  }
  for (const k of Object.keys(v)) {
    if (UNREPRESENTABLE_RE.test(k)) return `${p}.<key>`;
    const r = _unrepresentablePath(v[k], `${p}.${k}`, seen); if (r) return r;
  }
  return null;
}
/** The first field path holding U+0000 / a lone surrogate, or null (exported for the provider-response guard). */
function unrepresentableTextPath(fields) {
  if (!fields || typeof fields !== 'object') return null;
  const seen = new Set();
  for (const k of Object.keys(fields)) { const r = _unrepresentablePath(fields[k], k, seen); if (r) return r; }
  return null;
}
function unrepresentableTextError(path) {
  const e = new Error(`invalid_unrepresentable_text: ${path} contains U+0000 or an unpaired UTF-16 surrogate, which the evidence-chain / recovery stores cannot represent`);
  e.code = 'AUDIT_UNREPRESENTABLE_TEXT';
  e.field = path;
  return e;
}

function normalizeFields(fields) {
  // F6-N2: refuse before any normalization or persistence (see above)
  const bad = unrepresentableTextPath(fields);
  if (bad) throw unrepresentableTextError(bad);
  return _normalizeFields(fields);
}

function _normalizeFields({ artifactId, inputHash, decision, signature, nonce, executionContext, requestHash, policyHash, verificationResult, tenantId, organizationId, publicKeyId, consentProvenance, policyDecision, callerContext, requestId, traceId, provider, model, stage, reason, semantic, tokenUsage, responseId, entryType, outputHash, executingProvider,
  issuedAt, protocolVersion, agentId, sessionId, actionSeq, actionHash, approvalRef, dlp, bytesDelivered, completionStatus }) {
  if (!VALID_DECISIONS.has(decision)) throw new Error('invalid_decision');

  // ── v8 (AUDIT-V8-FREEZE): only a writer whose flag is on may state a v8 field or one of the new entry types ──
  const schemaVersion = currentSchemaVersion();
  const v8Fields = { issuedAt, protocolVersion, agentId, sessionId, actionSeq, actionHash, approvalRef, dlp, bytesDelivered, completionStatus };
  if (schemaVersion < 8) {
    if (V8_NEW_FIELDS.some((f) => !_isNullish(v8Fields[f]))) throw new Error('invalid_v8_field: audit schema v8 is not enabled (QODIQA_AUDIT_SCHEMA_V8)');
    if (!_isNullish(entryType) && !ENTRY_TYPES.includes(entryType) && ENTRY_TYPES_V8.includes(entryType)) {
      throw new Error('invalid_entryType: ' + entryType + ' requires audit schema v8 (QODIQA_AUDIT_SCHEMA_V8)');
    }
  } else {
    // an entry of the request that consumed an artifact states when that artifact was issued and its protocol version
    // (bound once by the enforcement pipeline, see requestAuditContext.js); only for the types that may carry them.
    const facts = currentArtifactFacts();
    const type = _isNullish(entryType) ? 'DECISION' : entryType;
    const may = V8_LEGACY_TYPE_ALLOWED[type] || (V8_TYPE_RULES[type] ? V8_TYPE_RULES[type].allowed : []);
    if (facts && facts.requestId && requestId === facts.requestId && may.includes('issuedAt')) {
      if (_isNullish(v8Fields.issuedAt)) v8Fields.issuedAt = facts.issuedAt;
      if (_isNullish(v8Fields.protocolVersion)) v8Fields.protocolVersion = facts.protocolVersion;
    }
  }
  if (schemaVersion === 8 && !_isNullish(entryType) && V8_TYPE_RULES[entryType]) {
    return _normalizeV8SystemType({ artifactId, inputHash, decision, signature, nonce, executionContext, verificationResult, tenantId, organizationId, requestId, traceId, stage, reason, entryType, outputHash, v8Fields });
  }

  // ── v7 (SCHEMA-V7-DESIGN.md §2–§5): entry type, output hash, executing provider ──
  const resolvedEntryType = entryType === undefined || entryType === null ? 'DECISION' : entryType;
  if (!ENTRY_TYPES.includes(resolvedEntryType)) throw new Error('invalid_entryType');
  let resolvedOutputHash;
  if (resolvedEntryType === 'DECISION') {
    if (outputHash === undefined || outputHash === null) {
      // R-5/R-5b: a BLOCK delivered nothing → the empty-bytes hash. An ALLOW must state what it delivered — a
      // forgotten outputHash on an ALLOW is refused rather than silently recorded as "empty".
      if (decision !== 'BLOCK') throw new Error('invalid_outputHash: an ALLOW decision must state the delivered output hash');
      resolvedOutputHash = EMPTY_OUTPUT_HASH;
    } else if (typeof outputHash !== 'string' || !HEX64.test(outputHash)) {
      throw new Error('invalid_outputHash');
    } else {
      resolvedOutputHash = outputHash;
    }
  } else {
    // R-8/R-8a: INTENT / STREAM_OPENED are written before delivery — fixed decision/stage, no output hash.
    const fixed = LIFECYCLE_FIXED[resolvedEntryType];
    if (outputHash !== undefined && outputHash !== null) throw new Error('invalid_outputHash: lifecycle entries carry no output hash');
    if (decision !== fixed.decision) throw new Error('invalid_decision: lifecycle entries record decision ALLOW');
    if (stage !== fixed.stage) throw new Error(`invalid_stage: ${resolvedEntryType} records stage ${fixed.stage}`);
    resolvedOutputHash = null;
  }
  const resolvedExecutingProvider = (typeof executingProvider === 'string' && executingProvider) ? executingProvider : null;
  const resolvedExecutionContext = _normalizeExecutionContextV7(executionContext);

  const isBlock = decision === 'BLOCK';
  if (typeof inputHash   !== 'string' || !inputHash)   { if (!isBlock) throw new Error('invalid_inputHash');   inputHash   = 'UNAVAILABLE'; }
  if (typeof signature   !== 'string' || !signature)   { if (!isBlock) throw new Error('invalid_signature');   signature   = 'UNAVAILABLE'; }
  if (typeof requestHash !== 'string' || !requestHash) { if (!isBlock) throw new Error('invalid_requestHash'); requestHash = 'UNAVAILABLE'; }
  if (typeof policyHash  !== 'string' || !policyHash)  { if (!isBlock) throw new Error('invalid_policyHash');  policyHash  = 'UNAVAILABLE'; }

  // Durable key attribution: null when no signature-
  // verified key is available yet — never a placeholder string.
  const resolvedPublicKeyId = (typeof publicKeyId === 'string' && publicKeyId) ? publicKeyId : null;

  const resolvedId = (typeof artifactId === 'string' && artifactId)
    ? artifactId
    : sha256Hex(inputHash);

  return {
    resolvedId, inputHash, decision, signature, requestHash, policyHash,
    resolvedPublicKeyId,
    verificationResult: verificationResult === true,
    nonce:           (typeof nonce === 'string' && nonce.length > 0) ? nonce : null,
    tenantId:         (typeof tenantId       === 'string' && tenantId)       ? tenantId       : null,
    organizationId:   (typeof organizationId === 'string' && organizationId) ? organizationId : null,
    // correlation identifiers shared with the operational log stream
    // (services/logger.js) and the canonical correlation store
    // (src/core/audit/centralStore.js's platform_audit_events). Deliberately
    // NOT hash-protected (not in CORE_HASH_FIELDS_V*) — these are the same
    // kind of durable-but-non-evidentiary metadata as tenantId/organizationId
    // above, added purely so a SOC analyst can join an audit chain entry to
    // the operational events from the same request without bespoke mapping.
    // See SIEM-3-REMEDIATION-REPORT.md.
    // (true for schema < 7 only — from v7, requestId and tenantId ARE in CORE_HASH_FIELDS_V7.)
    requestId:        (typeof requestId === 'string' && requestId) ? requestId : null,
    traceId:          (typeof traceId   === 'string' && traceId)   ? traceId   : null,
    // v7 (R-6): hashed; normalized once (see _normalizeExecutionContextV7).
    executionContext: resolvedExecutionContext,
    // v7 (R-4/R-5/R-7): hashed.
    entryType:          resolvedEntryType,
    outputHash:         resolvedOutputHash,
    executingProvider:  resolvedExecutingProvider,
    // TRACE-2: immutable consent + policy-rule provenance. Always present
    // (possibly null) on every entry built from this point forward — see
    // buildEntry() below, which promotes both into the hash-protected core.
    consentProvenance: consentProvenance ?? null,
    policyDecision:     policyDecision    ?? null,
    // immutable authenticated-caller snapshot. Always present
    // (possibly null) from this point forward — see buildEntry() below.
    callerContext:      callerContext     ?? null,
    // hash-protected provider/model identity. Always present
    // (possibly null — e.g. an early-stage BLOCK before a provider was
    // chosen) from this point forward — see buildEntry() below.
    provider:           (typeof provider === 'string' && provider) ? provider : null,
    model:              (typeof model    === 'string' && model)    ? model    : null,
    // (schemaVersion 6): hash-protected residual executionContext
    // fields with real evidentiary weight. Always present (possibly null)
    // from this point forward — see buildEntry() below. `stage`/`reason`
    // are the decision's own "what happened, why" (reason is null for
    // ALLOW entries and for BLOCKs where no rule-specific reason applies);
    // `semantic`/`tokenUsage` are objects (or null), canonicalized
    // deterministically the same way consentProvenance/policyDecision
    // already are; `responseId` links back to the actual provider response
    // this decision was based on.
    stage:              (typeof stage      === 'string' && stage)      ? stage      : null,
    reason:             (typeof reason     === 'string' && reason)     ? reason     : null,
    semantic:           semantic    ?? null,
    tokenUsage:         tokenUsage  ?? null,
    responseId:         (typeof responseId === 'string' && responseId) ? responseId : null,
    schemaVersion,
    ...(schemaVersion === 8 ? _resolveV8Fields(v8Fields) : {}),
  };
}

// The ten v8 fields as stored in an entry: each is always present, null when not stated. Value validity is the shape
// check's job (v8ShapeViolation, run again by every verifier); the writer refuses a malformed value up front.
function _resolveV8Fields(v) {
  const out = {};
  for (const f of V8_NEW_FIELDS) {
    const x = v[f];
    if (_isNullish(x)) { out[f] = null; continue; }
    if (!V8_FIELD_OK[f](x)) throw new Error('invalid_v8_field: ' + f);
    out[f] = x;
  }
  return out;
}

// v8 entries of the NEW types (COMMIT, ACTION_*, APPROVAL_*, KILL_SWITCH, DLP_TRANSFORM, DELEGATION_*): the fixed values of
// AUDIT-V8-FREEZE section 3 are applied here and the finished shape is checked with the same function the verifiers use,
// so a writer cannot produce an entry its own verifier would refuse. inputHash / requestHash / policyHash are
// "UNAVAILABLE" (the existing convention for a hash that does not apply), the other defaulted fields are null.
function _normalizeV8SystemType(f) {
  const rule = V8_TYPE_RULES[f.entryType];
  const reasons = rule.outcomes[f.decision];
  if (!reasons) throw new Error('invalid_decision: ' + f.entryType + ' cannot record decision ' + f.decision);
  const resolved = _resolveV8Fields(f.v8Fields);
  const artifactId = typeof f.artifactId === 'string' && f.artifactId ? f.artifactId : null;
  if (!artifactId) throw new Error('invalid_artifactId: ' + f.entryType + ' needs its deterministic artifactId');
  const out = {
    resolvedId: artifactId, inputHash: 'UNAVAILABLE', decision: f.decision,
    signature: rule.system ? 'SYSTEM' : (typeof f.signature === 'string' && f.signature ? f.signature : null),
    requestHash: 'UNAVAILABLE', policyHash: 'UNAVAILABLE', resolvedPublicKeyId: null,
    verificationResult: !rule.system,
    nonce: (typeof f.nonce === 'string' && f.nonce.length > 0) ? f.nonce : null,
    tenantId: (typeof f.tenantId === 'string' && f.tenantId) ? f.tenantId : null,
    organizationId: (typeof f.organizationId === 'string' && f.organizationId) ? f.organizationId : null,
    requestId: (typeof f.requestId === 'string' && f.requestId) ? f.requestId : null,
    traceId: (typeof f.traceId === 'string' && f.traceId) ? f.traceId : null,
    executionContext: _normalizeExecutionContextV7(f.executionContext),
    entryType: f.entryType,
    outputHash: _isNullish(f.outputHash) ? null : f.outputHash,
    executingProvider: null, consentProvenance: null, policyDecision: null, callerContext: null, provider: null, model: null,
    stage: rule.stage, reason: typeof f.reason === 'string' && f.reason ? f.reason : null,
    semantic: null, tokenUsage: null, responseId: null,
    schemaVersion: 8, ...resolved,
  };
  if (!out.signature) throw new Error('invalid_signature: ' + f.entryType + ' is artifact-driven and needs the artifact signature');
  const bad = v8ShapeViolation({ ...out, artifactId: out.resolvedId });
  if (bad) throw new Error('invalid_entry_shape: ' + f.entryType + ' (' + bad + ')');
  return out;
}

/**
 * Builds the frozen, hash-computed entry given normalized fields and the
 * prevHash to chain off (resolved by the caller under whatever ordering
 * authority is in effect).
 *
 * @param {object} normalized — output of normalizeFields()
 * @param {string} prevHash
 * @returns {object} frozen entry, same shape as today's audit-log.js entries
 */
function buildEntry(normalized, prevHash) {
  const timestamp    = new Date().toISOString();
  const highResTime  = process.hrtime.bigint().toString();

  const coreFields = {
    artifactId:  normalized.resolvedId,
    decision:    normalized.decision,
    inputHash:   normalized.inputHash,
    policyHash:  normalized.policyHash,
    prevHash,
    publicKeyId: normalized.resolvedPublicKeyId,
    requestHash: normalized.requestHash,
    schemaVersion: normalized.schemaVersion,
    signature:   normalized.signature,
    timestamp,
    verificationResult: normalized.verificationResult,
    // TRACE-2: hash-protected on schemaVersion 3 (see CORE_HASH_FIELDS_V3) —
    // present-but-null when no consent policy/rule decision applies (e.g. a
    // VALIDATION-stage BLOCK that never reached policy evaluation).
    consentProvenance: normalized.consentProvenance,
    policyDecision:     normalized.policyDecision,
    // hash-protected on schemaVersion 4 (CORE_HASH_FIELDS_V4) —
    // present-but-null when the artifact predates the remediation (see
    // module header comment above and NONREP-1-REMEDIATION-REPORT.md).
    callerContext:      normalized.callerContext,
    // hash-protected on schemaVersion 5 (CORE_HASH_FIELDS_V5).
    provider:           normalized.provider,
    model:              normalized.model,
    // hash-protected on schemaVersion 6 (CORE_HASH_FIELDS_V6) —
    // present-but-null wherever not applicable (see normalizeFields() above).
    stage:              normalized.stage,
    reason:             normalized.reason,
    semantic:           normalized.semantic,
    tokenUsage:         normalized.tokenUsage,
    responseId:         normalized.responseId,
    // schemaVersion 7 (CORE_HASH_FIELDS_V7): always present, possibly null — previously the unhashed
    // tenantId / requestId / organizationId / executionContext, now inside the hash.
    entryType:          normalized.entryType,
    outputHash:         normalized.outputHash,
    tenantId:           normalized.tenantId,
    requestId:          normalized.requestId,
    organizationId:     normalized.organizationId,
    executionContext:   normalized.executionContext,
    executingProvider:  normalized.executingProvider,
  };
  if (normalized.schemaVersion === 8) {
    // v8 (AUDIT-V8-FREEZE section 2): ten more always-present, possibly null, hashed fields.
    for (const f of V8_NEW_FIELDS) coreFields[f] = normalized[f] ?? null;
  }
  const canonical = sortedJSON(coreFields);
  const hash      = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, canonical).toString('hex');

  return Object.freeze({
    ...coreFields,
    highResTime,
    // Still unhashed (SCHEMA-V6 §2.2): operational correlation only.
    ...(normalized.nonce          ? { nonce: normalized.nonce }                   : {}),
    ...(normalized.traceId        ? { traceId: normalized.traceId }               : {}),
    canonical,
    hash,
  });
}

module.exports = {
  CORE_HASH_FIELDS_V1,
  CORE_HASH_FIELDS_V2,
  CORE_HASH_FIELDS_V3,
  CORE_HASH_FIELDS_V4,
  CORE_HASH_FIELDS_V5,
  CORE_HASH_FIELDS_V6,
  CORE_HASH_FIELDS_V7,
  CORE_HASH_FIELDS_V8,
  V8_NEW_FIELDS,
  CURRENT_SCHEMA_VERSION,
  currentSchemaVersion,
  SUPPORTED_SCHEMA_VERSIONS,
  VALID_DECISIONS,
  ENTRY_TYPES,
  ENTRY_TYPES_V8,
  COMPLETION_STATUSES,
  V8_TYPE_RULES,
  LIFECYCLE_FIXED,
  LIFECYCLE_ARTIFACT_SUFFIX,
  EMPTY_OUTPUT_HASH,
  createOutputHasher,
  v7IntegrityDetail,
  unrepresentableTextPath,     // / F6-N2
  unrepresentableTextError,
  outputHashOf,
  lifecycleArtifactId,
  v7ShapeViolation,
  v8ShapeViolation,
  shapeViolationOf,
  entryTypeOf,
  isSupportedSchemaVersion,
  hashFieldsFor,
  protectedField,
  coreFieldsOf,
  verifyCanonicalHash,
  expectedHashFor,
  normalizeFields,
  buildEntry,
};
