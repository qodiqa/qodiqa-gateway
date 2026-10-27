'use strict';

/**
 * QODIQA Immutable Evidence Chain Engine — Component #21
 *
 * Pure-logic module: no I/O, no side effects.  All functions are synchronous
 * and deterministic.  Database persistence is handled by chainStore.js.
 * Key/audit lookups for live verification are handled by the caller.
 *
 * Responsibilities:
 *   • Canonical JSON serialisation for deterministic hashing
 *   • Evidence record hash computation
 *   • Audit record hash computation (seals the full audit entry)
 *   • Signing key fingerprint computation
 *   • Evidence record assembly from an audit chain entry
 *   • 7-step verification engine
 *   • Chain continuity validation
 *   • Report data assembly and CSV export
 */

const { createHash, randomUUID }         = require('crypto');
const stableStringify                     = require('../../utils/stableStringify');
const { sanitizeCsvCell }                 = require('../../utils/csvSanitize');
const { domainSeparatedHash,
        ARTIFACT_DOMAINS }                = require('../../infra/crypto/hashing');

function _sha256(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

// ── Evidence hash computation ─────────────────────────────────────────────────

/**
 * The canonical fields used to compute the evidence hash (schema_version 1 —
 * legacy, pre-TRACE-2). Changing any of these fields would produce a
 * different hash, revealing any tampering with the evidence record.
 * Exported unchanged as `CANONICAL_FIELDS` for backward compatibility.
 */
const CANONICAL_FIELDS_V1 = [
  'evidenceId',
  'artifactId',
  'artifactHash',
  'policyId',
  'policyHash',
  'keyId',
  'keyFingerprint',
  'auditRecordId',
  'auditRecordHash',
  'previousEvidenceHash',
];

// schema_version 2 (TRACE-2 remediation): adds the immutable consent-record
// and policy-rule decision provenance that authorized this record's
// underlying decision. Appended, not inserted, so existing V1 records'
// canonical field order (and therefore hash) is completely unaffected.
const CANONICAL_FIELDS_V2 = [
  ...CANONICAL_FIELDS_V1,
  'consentProvenance',
  'policyDecision',
];

// schema_version 3: adds the immutable authenticated-
// caller snapshot (callerId/callerName/environment/credentialType) that
// authored the underlying signed artifact — see entryBuilder.js's parallel
// CORE_HASH_FIELDS_V4 addition, which this mirrors for the evidence chain's
// independent hash surface.
const CANONICAL_FIELDS_V3 = [
  ...CANONICAL_FIELDS_V2,
  'callerContext',
];

// schema_version 4:
// auditRecordHash is computed over the PERSISTED audit-record representation
// (see persistedAuditRecordOf() below) instead of the full in-memory entry,
// and schemaVersion itself joins the hashed set so a v4 record cannot be
// relabelled to a legacy version (or vice versa) without failing
// EVIDENCE_HASH. No other evidence field changes.
const CANONICAL_FIELDS_V4 = [
  ...CANONICAL_FIELDS_V3,
  'schemaVersion',
];

const CANONICAL_FIELDS = CANONICAL_FIELDS_V1;

const EVIDENCE_SCHEMA_V1      = 1;
const EVIDENCE_SCHEMA_V2      = 2;
const EVIDENCE_SCHEMA_V3      = 3;
const EVIDENCE_SCHEMA_V4      = 4;
const EVIDENCE_SCHEMA_CURRENT = EVIDENCE_SCHEMA_V4;

function _evidenceSchemaVersionOf(record) {
  return record?.schemaVersion ?? record?.schema_version ?? EVIDENCE_SCHEMA_V1;
}

// Accepts either a camelCase in-memory record (schemaVersion) or a snake_case
// DB row (schema_version) — both shapes flow through this module (chainStore.js
// passes raw pg rows into verifyEvidenceRecord/validateChainContinuity).
function canonicalFieldsFor(record) {
  const version = _evidenceSchemaVersionOf(record);
  if (version >= EVIDENCE_SCHEMA_V4) return CANONICAL_FIELDS_V4;
  if (version >= EVIDENCE_SCHEMA_V3) return CANONICAL_FIELDS_V3;
  return version >= EVIDENCE_SCHEMA_V2 ? CANONICAL_FIELDS_V2 : CANONICAL_FIELDS_V1;
}

/**
 * Compute the evidence hash for a record.
 * Only the schema-appropriate canonical fields are included — non-canonical
 * metadata fields (createdAt, decision, tenantId) are excluded so the hash
 * represents the cryptographic links, not operational metadata.
 *
 * @param {object} record — must contain all fields for its schema version
 * @returns {string} 64-char hex SHA-256
 */
function computeEvidenceHash(record) {
  const fields    = canonicalFieldsFor(record);
  const canonical = {};
  for (const f of fields) {
    // schemaVersion (V4+) resolves from either record shape, like the dispatch
    // above — verification passes snake_case schema_version.
    canonical[f] = f === 'schemaVersion' ? _evidenceSchemaVersionOf(record) : (record[f] ?? null);
  }
  return domainSeparatedHash(ARTIFACT_DOMAINS.EVIDENCE, stableStringify(canonical)).toString('hex');
}

/**
 * Compute the audit record hash from a complete audit chain entry.
 * SHA-256 of the full serialised entry (including all fields: hash, prevHash,
 * canonical, executionContext, etc.).  Detects modification of ANY field.
 *
 * @param {object} auditEntry — frozen audit chain entry from audit-log.js
 * @returns {string} 64-char hex SHA-256
 */
function computeAuditRecordHash(auditEntry) {
  return domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, stableStringify(auditEntry)).toString('hex');
}

// ── Persisted audit-record contract (evidence schema_version >= 4) ───────────
//
// The legacy auditRecordHash above (evidence schema_version 1-3) covers the
// full IN-MEMORY entry, which includes fields audit_chain never persisted for
// pre-v7 entries (requestId, traceId, organizationId), so it cannot be
// recomputed from the database for most entries. (audit schema
// v7 hashes requestId/organizationId into the entry's own canonical, so for a
// v7 entry they are recoverable from it; traceId is still never persisted.)
// The v4 contract covers exactly what audit_chain persists for the entry, in
// the form it is persisted:
//
//   format           — constant tag, so no legacy entry object can ever hash equal
//   hash             — audit_chain.hash (the entry's own canonical hash)
//   canonical        — audit_chain.canonical, verbatim: the hash-protected core
//                      fields for the entry's own schemaVersion (1-6), including
//                      the fields — everything persistEntry()'s
//                      denormalized columns are copies of
//   highResTime      — audit_chain.high_res_time
//   tenantId         — audit_chain.tenant_id    (persisted as `?? null`)
//   nonce            — audit_chain.nonce        (persisted as `?? null`)
//   executionContext — audit_chain.execution_context (persisted as JSON when
//                      truthy, else NULL; JSON round-trip mirrors that)
//
// Never fabricated: a field audit_chain does not store is simply not covered.
const PERSISTED_AUDIT_RECORD_FORMAT = 'qodiqa.audit_chain.persisted.v1';

/**
 * Project an audit entry onto its persisted representation. Accepts both the
 * in-memory entry (write side) and chainStore's audit_chain projection (read
 * side) — both expose these camelCase keys.
 *
 * @param {object} entry
 * @returns {object}
 */
function persistedAuditRecordOf(entry) {
  const ctx = entry.executionContext;
  return {
    format:           PERSISTED_AUDIT_RECORD_FORMAT,
    hash:             entry.hash,
    canonical:        entry.canonical,
    highResTime:      entry.highResTime == null ? null : String(entry.highResTime),
    tenantId:         entry.tenantId ?? null,
    nonce:            entry.nonce    ?? null,
    executionContext: ctx ? JSON.parse(JSON.stringify(ctx)) : null,
  };
}

/**
 * auditRecordHash for evidence schema_version >= 4.
 * @param {object} entry — in-memory entry or audit_chain projection
 * @returns {string} 64-char hex
 */
function computePersistedAuditRecordHash(entry) {
  return domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, stableStringify(persistedAuditRecordOf(entry))).toString('hex');
}

/**
 * Best-effort rebuild of the in-memory entry a LEGACY (schema_version < 4)
 * auditRecordHash was computed over, from persisted data only: the verbatim
 * canonical core fields plus the persisted envelope, with the same
 * conditional keys entryBuilder.buildEntry() uses. Nothing is ever fabricated:
 * a pre-v7 entry that carried requestId / organizationId (unhashed then), or
 * any entry that carried traceId, cannot be rebuilt; a v7 entry's requestId /
 * organizationId come back from its own canonical. Returns null when canonical
 * is unusable.
 */
function _legacyAuditEntryFromPersisted(entry) {
  if (typeof entry.canonical !== 'string') return null;
  let core;
  try { core = JSON.parse(entry.canonical); } catch { return null; }
  if (!core || typeof core !== 'object' || Array.isArray(core)) return null;
  return {
    ...core,
    highResTime: entry.highResTime,
    ...(entry.tenantId         ? { tenantId: entry.tenantId }                 : {}),
    ...(entry.nonce            ? { nonce: entry.nonce }                       : {}),
    ...(entry.executionContext ? { executionContext: entry.executionContext } : {}),
    canonical: entry.canonical,
    hash:      entry.hash,
  };
}

/**
 * Compute the key fingerprint per QODIQA-PROTOCOL-SPEC.md §12.3:
 *   keyFingerprint = LowercaseHex(SHA-256(UTF8(publicKeyB64)))
 * This hashes the UTF-8 bytes of the Base64 STRING itself — NOT the bytes it
 * decodes to. Decoding first would produce a different (non-conformant) value.
 *
 * @param {string} publicKeyB64 — Standard Base64 of SPKI DER public key bytes
 * @returns {string|null} 64-char hex SHA-256, or null if input is invalid
 */
function computeKeyFingerprint(publicKeyB64) {
  if (typeof publicKeyB64 !== 'string' || !publicKeyB64) return null;
  return createHash('sha256').update(publicKeyB64, 'utf8').digest('hex');
}

// ── Evidence record assembly ──────────────────────────────────────────────────

/**
 * Assemble a complete, ready-to-persist evidence chain record from an audit entry.
 *
 * @param {object} auditEntry         — frozen audit chain entry
 * @param {object|null} keyInfo       — from keyManager.listPublicKeys() / getVerificationKey()
 * @param {object} [opts]
 * @param {string|null} [opts.previousEvidenceHash] — hash of the most recent prior record
 * @param {number|null} [opts.policyVersion]        — fallback when auditEntry has no policyDecision
 * @param {string}      [opts.policyId]             — fallback when auditEntry has no policyDecision;
 *                                                     defaults to 'POLICY_SET' (whole-set, no matched rule)
 * @returns {object} complete evidence record ready for DB insertion
 */
function buildEvidenceRecord(auditEntry, keyInfo, opts) {
  const {
    previousEvidenceHash = null,
    policyVersion         = null,
    policyId              = 'POLICY_SET',
  } = opts || {};

  const evidenceId        = randomUUID();
  const artifactId        = auditEntry.artifactId;
  const artifactHash      = auditEntry.inputHash    ?? 'UNAVAILABLE';
  const policyHash        = auditEntry.policyHash   ?? 'UNAVAILABLE';
  // Prefer the hash-protected top-level field; fall
  // back to the legacy, unprotected executionContext copy for audit entries
  // written before this fix (schemaVersion 1, no top-level publicKeyId).
  const keyId             = auditEntry.publicKeyId ?? auditEntry.executionContext?.publicKeyId ?? null;
  const keyVersion        = keyInfo?.version        ?? null;
  const keyFingerprint    = keyInfo?.publicKeyB64
    ? computeKeyFingerprint(keyInfo.publicKeyB64)
    : null;
  const auditRecordId     = auditEntry.hash;
  // schema_version 4: over the persisted representation (see persistedAuditRecordOf).
  const auditRecordHash   = computePersistedAuditRecordHash(auditEntry);

  // TRACE-2: consentProvenance/policyDecision are copied straight off the
  // (already-hashed, already-in-hand) audit entry — no lookup. Old audit
  // entries (schemaVersion < 3) simply don't have these fields, so both
  // default to null, matching schema_version 1 evidence records exactly.
  // policyId/policyVersion prefer the matched-rule identity from
  // policyDecision over the legacy 'POLICY_SET' whole-set placeholder — this
  // is the second half of TRACE-2 (which rule decided, not just which set).
  const consentProvenance = auditEntry.consentProvenance ?? null;
  const policyDecision    = auditEntry.policyDecision    ?? null;
  const resolvedPolicyId      = policyDecision?.policyId      ?? policyId;
  const resolvedPolicyVersion = policyDecision?.policyVersion ?? policyVersion;
  // authenticated-caller snapshot, copied straight off the audit
  // entry — null for entries that predate schemaVersion 4 (entryBuilder.js)
  // or the artifact itself predates the remediation.
  const callerContext     = auditEntry.callerContext     ?? null;

  const record = {
    evidenceId,
    artifactId,
    artifactHash,
    policyId:      resolvedPolicyId,
    policyVersion: resolvedPolicyVersion,
    policyHash,
    keyId,
    keyVersion,
    keyFingerprint,
    auditRecordId,
    auditRecordHash,
    previousEvidenceHash: previousEvidenceHash || null,
    evidenceHash: null,   // computed below
    decision:    auditEntry.decision,
    tenantId:    auditEntry.tenantId ?? null,
    createdAt:   new Date(auditEntry.timestamp),
    schemaVersion: EVIDENCE_SCHEMA_CURRENT,
    consentProvenance,
    policyDecision,
    callerContext,
  };

  record.evidenceHash = computeEvidenceHash(record);
  return record;
}

// ── 7-step verification engine ────────────────────────────────────────────────

const VERIFICATION_STEPS = Object.freeze([
  'ARTIFACT_HASH',
  'POLICY_HASH',
  'KEY_FINGERPRINT',
  'AUDIT_RECORD_HASH',
  'EVIDENCE_HASH',
  'CHAIN_LINK',
  'CHAIN_CONTINUITY',
  'CONSENT_PROVENANCE_CONSISTENCY',
  'POLICY_DECISION_CONSISTENCY',
  'CALLER_CONTEXT_CONSISTENCY',
  'DECISION_CONSISTENCY',
]);

// the evidence record's `decision` is
// operational metadata outside the evidence hash (see computeEvidenceHash), so
// it is never trusted on its own. The authoritative decision is the one inside
// the audit entry's `canonical` — the audit hash is
// domainSeparatedHash(AUDIT, canonical) for every audit schema version, and that
// hash is this evidence record's audit_record_id, which the evidence hash covers
// for every evidence schema version (CANONICAL_FIELDS_V1). So a canonical that
// hashes to audit_record_id is bound to this record, and its decision is the
// genuine one. Anything else — no audit entry, a canonical that is not the bound
// one, no ALLOW/BLOCK inside it, or any difference from the stored value — fails.
const AUTHORITATIVE_DECISIONS = new Set(['ALLOW', 'BLOCK']);

/**
 * @param {object}      evidenceRecord — DB row (snake_case)
 * @param {object|null} auditEntry     — audit_chain projection (canonical, hash, ...)
 * @returns {{ ok: boolean, reason: string|null }}
 */
function checkDecisionConsistency(evidenceRecord, auditEntry) {
  if (!auditEntry) return { ok: false, reason: 'Audit entry not found — cannot verify the decision' };
  const canonical = auditEntry.canonical;
  if (typeof canonical !== 'string'
      || domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, canonical).toString('hex') !== evidenceRecord.audit_record_id) {
    return { ok: false, reason: 'The audit record is not the one bound to this evidence record — cannot verify the decision' };
  }
  let authoritative = null;
  try { authoritative = JSON.parse(canonical)?.decision ?? null; } catch { authoritative = null; }
  if (!AUTHORITATIVE_DECISIONS.has(authoritative)) {
    return { ok: false, reason: 'The bound audit record carries no valid decision — cannot verify the decision' };
  }
  if (evidenceRecord.decision !== authoritative) {
    return { ok: false, reason: 'Stored decision does not match the decision in the hash-protected audit record — the decision may have been altered' };
  }
  return { ok: true, reason: null };
}

/**
 * Run the 10-step evidence chain verification for a single record (TRACE-2
 * added steps 8-9, added step 10, both appended not inserted, so
 * existing step-index/name assertions are unaffected).
 *
 * Steps:
 *  1. ARTIFACT_HASH       — stored artifactHash matches auditEntry.inputHash
 *  2. POLICY_HASH         — stored policyHash matches auditEntry.policyHash
 *  3. KEY_FINGERPRINT     — stored fingerprint matches freshly computed fingerprint from keyInfo
 *  4. AUDIT_RECORD_HASH   — stored auditRecordHash matches the audit record, per the
 *                           evidence schema_version: >= 4 the persisted-record
 *                           contract (persistedAuditRecordOf), < 4 the legacy
 *                           full-in-memory-entry contract (see step 4 below)
 *  5. EVIDENCE_HASH       — stored evidenceHash matches recomputed hash of evidence fields
 *  6. CHAIN_LINK          — stored previousEvidenceHash matches prior record's evidenceHash
 *  7. CHAIN_CONTINUITY    — record ids are sequential (no gaps)
 *  8. CONSENT_PROVENANCE_CONSISTENCY — stored consent_provenance matches auditEntry.consentProvenance
 *  9. POLICY_DECISION_CONSISTENCY    — stored policy_decision matches auditEntry.policyDecision
 * 10. CALLER_CONTEXT_CONSISTENCY — stored caller_context matches auditEntry.callerContext
 * 11. DECISION_CONSISTENCY           — stored decision matches the decision in the audit entry's
 * canonical bound to audit_record_id
 *
 * Steps 3, 6, 7 are SKIPPED (not failed) when the required context is unavailable:
 *   - Step 3: skipped when keyInfo is null (key may have been rotated/revoked)
 *   - Step 6: skipped when priorRecord is null (first record in chain)
 *   - Step 7: skipped when priorRecord is null
 * Steps 8, 9, 10 are SKIPPED (not failed) when auditEntry is unavailable, or
 * when the record's schema_version predates the field in question (< 2 for
 * 8-9, < 3 for 10) and legitimately has nothing to check — a tamper to any of
 * these fields is already caught by step 5 (EVIDENCE_HASH) regardless, since
 * all three are part of the hashed canonical set; steps 8-10 exist only to
 * give a more specific diagnostic than a bare hash mismatch.
 *
 * @param {object} evidenceRecord  — the DB row to verify
 * @param {object} context
 * @param {object|null} context.auditEntry    — from audit chain lookup
 * @param {object|null} context.keyInfo       — from keyManager (may be null if key unknown)
 * @param {object|null} context.priorRecord   — previous evidence_chain_record (may be null)
 * @returns {{ result: string, steps: object[], failedStep: string|null, failureReason: string|null }}
 */
function verifyEvidenceRecord(evidenceRecord, context) {
  const { auditEntry = null, keyInfo = null, priorRecord = null, auditEntryRejectedReason = null } = context || {};
  // Wording for every audit-dependent step when auditEntry is null: "not
  // found" by default, or the caller's explicit rejection reason (chainStore
  // rejects an audit row whose tenant differs from the evidence record's).
  const auditUnavailable = auditEntryRejectedReason
    ? `Audit entry rejected: ${auditEntryRejectedReason}`
    : 'Audit entry not found';
  const steps       = [];
  const warnings    = []; // additive, non-failing observations (ID_GAP)
  let   firstFail   = null;

  function pass(name)        { steps.push({ step: name, result: 'PASS' }); }
  function fail(name, reason) {
    steps.push({ step: name, result: 'FAIL', reason });
    if (!firstFail) firstFail = { step: name, reason };
  }
  function skip(name, reason) { steps.push({ step: name, result: 'SKIP', reason }); }

  // ── Step 1: ARTIFACT_HASH ──────────────────────────────────────────────────
  if (!auditEntry) {
    fail('ARTIFACT_HASH', auditEntryRejectedReason
      ? `${auditUnavailable} — cannot verify artifact hash`
      : 'Audit entry not found in chain — cannot verify artifact hash');
  } else {
    const expected = auditEntry.inputHash ?? 'UNAVAILABLE';
    if (evidenceRecord.artifact_hash === expected) {
      pass('ARTIFACT_HASH');
    } else {
      fail('ARTIFACT_HASH',
        `Stored artifact_hash ${evidenceRecord.artifact_hash} does not match audit entry inputHash ${expected}`
      );
    }
  }

  // ── Step 2: POLICY_HASH ────────────────────────────────────────────────────
  if (!auditEntry) {
    fail('POLICY_HASH', `${auditUnavailable} — cannot verify policy hash`);
  } else {
    const expected = auditEntry.policyHash ?? 'UNAVAILABLE';
    if (evidenceRecord.policy_hash === expected) {
      pass('POLICY_HASH');
    } else {
      fail('POLICY_HASH',
        `Stored policy_hash ${evidenceRecord.policy_hash} does not match audit entry policyHash ${expected}`
      );
    }
  }

  // ── Step 3: KEY_FINGERPRINT ────────────────────────────────────────────────
  if (!keyInfo) {
    skip('KEY_FINGERPRINT', 'Key info not available — key may have been rotated or revoked');
  } else if (!evidenceRecord.key_fingerprint) {
    skip('KEY_FINGERPRINT', 'No key fingerprint stored — artifact may have been blocked before signing');
  } else {
    const computedFp = computeKeyFingerprint(keyInfo.publicKeyB64);
    if (!computedFp) {
      skip('KEY_FINGERPRINT', 'Cannot compute fingerprint from stored key material');
    } else if (evidenceRecord.key_fingerprint === computedFp) {
      pass('KEY_FINGERPRINT');
    } else {
      fail('KEY_FINGERPRINT',
        `Key fingerprint mismatch: stored ${evidenceRecord.key_fingerprint}, computed ${computedFp} — possible key substitution`
      );
    }
  }

  // ── Step 4: AUDIT_RECORD_HASH ──────────────────────────────────────────────
  // Dispatches on the evidence record's own schema_version (hash-bound for v4+):
  //   >= 4  persisted-representation contract (computePersistedAuditRecordHash)
  //   <  4  legacy full-in-memory-entry contract — recomputed from the entry as
  //         read and from the faithful persisted rebuild; never with fabricated
  //         requestId/traceId/organizationId, so a genuine legacy record whose
  //         entry carried any of them stays FAIL (fail-closed), with a reason
  //         that says so rather than asserting tampering.
  if (!auditEntry) {
    fail('AUDIT_RECORD_HASH', `${auditUnavailable} — cannot verify audit record hash`);
  } else if (_evidenceSchemaVersionOf(evidenceRecord) >= EVIDENCE_SCHEMA_V4) {
    if (evidenceRecord.audit_record_hash === computePersistedAuditRecordHash(auditEntry)) {
      pass('AUDIT_RECORD_HASH');
    } else {
      fail('AUDIT_RECORD_HASH',
        'Audit record hash mismatch (persisted-record contract, evidence schema_version >= 4) — the persisted audit record or the evidence record has been modified'
      );
    }
  } else {
    const legacyRebuild = _legacyAuditEntryFromPersisted(auditEntry);
    const candidates = [auditEntry, ...(legacyRebuild ? [legacyRebuild] : [])];
    if (candidates.some(c => computeAuditRecordHash(c) === evidenceRecord.audit_record_hash)) {
      pass('AUDIT_RECORD_HASH');
    } else {
      fail('AUDIT_RECORD_HASH',
        'Audit record hash mismatch (legacy contract, evidence schema_version < 4) — the legacy hash covers in-memory entry fields audit_chain does not persist (requestId/traceId/organizationId), so a genuine record whose entry carried them cannot be recomputed; the audit record may also have been modified'
      );
    }
  }

  // ── Step 5: EVIDENCE_HASH ──────────────────────────────────────────────────
  // Recompute the evidence hash from the stored fields and compare.
  // schema_version (and, for schema_version >= 2, consent_provenance /
  // policy_decision — TRACE-2) must be included so computeEvidenceHash()
  // dispatches to the same canonical field set the record was originally
  // hashed under.
  const recomputed = computeEvidenceHash({
    evidenceId:          evidenceRecord.evidence_id,
    artifactId:          evidenceRecord.artifact_id,
    artifactHash:        evidenceRecord.artifact_hash,
    policyId:            evidenceRecord.policy_id,
    policyHash:          evidenceRecord.policy_hash,
    keyId:               evidenceRecord.key_id,
    keyFingerprint:      evidenceRecord.key_fingerprint,
    auditRecordId:       evidenceRecord.audit_record_id,
    auditRecordHash:     evidenceRecord.audit_record_hash,
    previousEvidenceHash: evidenceRecord.previous_evidence_hash,
    schema_version:      evidenceRecord.schema_version,
    consentProvenance:   evidenceRecord.consent_provenance ?? null,
    policyDecision:      evidenceRecord.policy_decision    ?? null,
    callerContext:       evidenceRecord.caller_context     ?? null,
  });
  if (evidenceRecord.evidence_hash === recomputed) {
    pass('EVIDENCE_HASH');
  } else {
    fail('EVIDENCE_HASH',
      `Evidence hash mismatch: stored ${evidenceRecord.evidence_hash}, recomputed ${recomputed} — evidence record has been tampered`
    );
  }

  // ── Step 6: CHAIN_LINK ─────────────────────────────────────────────────────
  if (!priorRecord && !evidenceRecord.previous_evidence_hash) {
    pass('CHAIN_LINK');   // first record, no prior expected
  } else if (!priorRecord && evidenceRecord.previous_evidence_hash) {
    skip('CHAIN_LINK', 'Prior record context not provided — cannot verify chain link');
  } else if (priorRecord && !evidenceRecord.previous_evidence_hash) {
    fail('CHAIN_LINK',
      `Record has previous_evidence_hash=null but a prior record exists with evidence_hash ${priorRecord.evidence_hash}`
    );
  } else {
    const priorHash = priorRecord.evidence_hash ?? priorRecord.evidenceHash;
    if (evidenceRecord.previous_evidence_hash === priorHash) {
      pass('CHAIN_LINK');
    } else {
      fail('CHAIN_LINK',
        `Chain link broken: stored previous_evidence_hash ${evidenceRecord.previous_evidence_hash} does not match prior record evidence_hash ${priorHash}`
      );
    }
  }

  // ── Step 7: CHAIN_CONTINUITY ───────────────────────────────────────────────
  if (!priorRecord) {
    skip('CHAIN_CONTINUITY', 'Prior record not provided — cannot verify sequential ordering');
  } else {
    const currentId = Number(evidenceRecord.id);
    const priorId   = Number(priorRecord.id);
    // id adjacency is no longer an
    // attestation invariant — the cryptographic hash link is. A forward id gap
    // whose hash link holds (a sequence value consumed by a transaction that
    // failed after its INSERT; ids are non-transactional) passes, with an
    // additive ID_GAP warning. A gap without the hash link, or a non-increasing
    // id, still fails.
    const hashLinked = evidenceRecord.previous_evidence_hash != null
      && evidenceRecord.previous_evidence_hash === (priorRecord.evidence_hash ?? priorRecord.evidenceHash);
    if (Number.isFinite(currentId) && Number.isFinite(priorId) && currentId === priorId + 1) {
      pass('CHAIN_CONTINUITY');
    } else if (!Number.isFinite(currentId) || !Number.isFinite(priorId)) {
      skip('CHAIN_CONTINUITY', 'Record IDs not numeric — cannot verify sequential ordering');
    } else if (currentId > priorId + 1 && hashLinked) {
      pass('CHAIN_CONTINUITY');
      warnings.push({
        code: 'ID_GAP', step: 'CHAIN_CONTINUITY', priorId, id: currentId, missingIds: currentId - priorId - 1,
        reason: `Non-contiguous IDs: prior=${priorId}, current=${currentId} — the hash link is intact; ${currentId - priorId - 1} unused id(s) (not a continuity failure)`,
      });
    } else {
      fail('CHAIN_CONTINUITY',
        `Non-sequential IDs: prior=${priorId}, current=${currentId} — gap of ${currentId - priorId - 1} records detected`
      );
    }
  }

  // ── Step 8: CONSENT_PROVENANCE_CONSISTENCY (TRACE-2) ──────────────────────
  // A tamper here is already caught by EVIDENCE_HASH (step 5), since
  // consent_provenance is part of the hashed canonical set for schema_version
  // >= 2 — this step exists purely to give a specific diagnostic instead of a
  // bare hash mismatch.
  if (!auditEntry) {
    skip('CONSENT_PROVENANCE_CONSISTENCY', `${auditUnavailable} — cannot verify consent provenance`);
  } else if ((evidenceRecord.schema_version ?? 1) < EVIDENCE_SCHEMA_V2) {
    skip('CONSENT_PROVENANCE_CONSISTENCY', 'Record predates TRACE-2 (schema_version < 2) — no consent provenance to check');
  } else {
    const expected = auditEntry.consentProvenance ?? null;
    const stored   = evidenceRecord.consent_provenance ?? null;
    if (stableStringify(stored) === stableStringify(expected)) {
      pass('CONSENT_PROVENANCE_CONSISTENCY');
    } else {
      fail('CONSENT_PROVENANCE_CONSISTENCY',
        'Stored consent_provenance does not match the audit entry it was derived from — provenance may have been altered'
      );
    }
  }

  // ── Step 9: POLICY_DECISION_CONSISTENCY (TRACE-2) ──────────────────────────
  if (!auditEntry) {
    skip('POLICY_DECISION_CONSISTENCY', `${auditUnavailable} — cannot verify policy decision`);
  } else if ((evidenceRecord.schema_version ?? 1) < EVIDENCE_SCHEMA_V2) {
    skip('POLICY_DECISION_CONSISTENCY', 'Record predates TRACE-2 (schema_version < 2) — no policy decision to check');
  } else {
    const expected = auditEntry.policyDecision ?? null;
    const stored   = evidenceRecord.policy_decision ?? null;
    if (stableStringify(stored) === stableStringify(expected)) {
      pass('POLICY_DECISION_CONSISTENCY');
    } else {
      fail('POLICY_DECISION_CONSISTENCY',
        'Stored policy_decision does not match the audit entry it was derived from — provenance may have been altered'
      );
    }
  }

  // ── Step 10: CALLER_CONTEXT_CONSISTENCY ────────────────────────
  // Same "already caught by EVIDENCE_HASH, exists for a specific diagnostic"
  // reasoning as steps 8-9 — callerContext is part of the hashed canonical
  // set for schema_version >= 3.
  if (!auditEntry) {
    skip('CALLER_CONTEXT_CONSISTENCY', `${auditUnavailable} — cannot verify caller context`);
  } else if ((evidenceRecord.schema_version ?? 1) < EVIDENCE_SCHEMA_V3) {
    skip('CALLER_CONTEXT_CONSISTENCY', 'Record predates schema version 3 — no caller context to check');
  } else {
    const expected = auditEntry.callerContext ?? null;
    const stored   = evidenceRecord.caller_context ?? null;
    if (stableStringify(stored) === stableStringify(expected)) {
      pass('CALLER_CONTEXT_CONSISTENCY');
    } else {
      fail('CALLER_CONTEXT_CONSISTENCY',
        'Stored caller_context does not match the audit entry it was derived from — caller attribution may have been altered'
      );
    }
  }

  // ── Step 11: DECISION_CONSISTENCY ───────────────────────────────────
  // Unlike steps 8-10 this is the ONLY protection of its field (decision is not
  // in the evidence hash), so it never SKIPs: an unavailable or rejected audit
  // entry fails it, like steps 1, 2 and 4.
  if (!auditEntry) {
    fail('DECISION_CONSISTENCY', `${auditUnavailable} — cannot verify the decision`);
  } else {
    const dc = checkDecisionConsistency(evidenceRecord, auditEntry);
    if (dc.ok) pass('DECISION_CONSISTENCY');
    else fail('DECISION_CONSISTENCY', dc.reason);
  }

  const passCount = steps.filter(s => s.result === 'PASS').length;
  const failCount = steps.filter(s => s.result === 'FAIL').length;

  let result;
  if (failCount === 0 && passCount > 0)   result = 'VALID';
  else if (failCount > 0)                  result = 'INVALID';
  else                                     result = 'PARTIAL';

  return {
    result,
    stepsPassed: steps.filter(s => s.result === 'PASS').map(s => s.step),
    stepsFailed: steps.filter(s => s.result !== 'PASS').map(s => ({ step: s.step, result: s.result, reason: s.reason ?? null })),
    failedStep:    firstFail?.step    ?? null,
    failureReason: firstFail?.reason  ?? null,
    steps,
    warnings,
  };
}

// ── Chain continuity validation ───────────────────────────────────────────────

/**
 * Validate continuity over an ordered array of evidence chain records.
 * Records must be ordered by id ASC.
 *
 * Checks:
 *  - Each record's previous_evidence_hash matches the prior record's evidence_hash
 *  - Each record's evidence_hash is correct (recomputed from fields)
 *  - IDs strictly increase
 *
 * the hash link — not id adjacency — is the
 * continuity invariant. An id jump across an intact hash link (a sequence value
 * consumed by a transaction that failed after its INSERT) is reported in
 * `warnings` as ID_GAP and does not fail; a deleted record still breaks the hash
 * link ("Chain break"), and a non-increasing id still fails.
 *
 * @param {object[]} records — ordered ASC by id
 * @returns {{ valid: boolean, checkedCount: number, failureId: number|null, failureDetail: string|null, warnings: object[] }}
 */
function validateChainContinuity(records, { startHash } = {}) {
  // startHash — when the first record is the first KEPT record after a retention prune, it must
  // link to the last pruned record's hash (evidenceBase.js) instead of null. Omitted = unchanged genesis rule.
  const warnings = [];
  if (!Array.isArray(records) || records.length === 0) {
    return { valid: true, checkedCount: 0, failureId: null, failureDetail: null, warnings };
  }

  let prevEvidenceHash = null;
  let prevId           = null;
  let checkedCount     = 0;
  const fail = (failureId, failureDetail) => ({ valid: false, checkedCount, failureId, failureDetail, warnings });

  for (const rec of records) {
    const currentId   = Number(rec.id);
    const storedPrev  = rec.previous_evidence_hash ?? null;
    const storedHash  = rec.evidence_hash;
    const idsNumeric  = prevId !== null && Number.isFinite(prevId) && Number.isFinite(currentId);

    // Ordering check: ids must strictly increase.
    if (idsNumeric && currentId <= prevId) {
      return fail(currentId, `Non-increasing ID: ${currentId} follows ${prevId}`);
    }

    // Chain link check (the continuity invariant)
    if (checkedCount === 0) {
      if (startHash !== undefined) {
        if (storedPrev !== startHash) {
          return fail(currentId, `First kept record does not link to the pruned prefix: expected prev_hash=${startHash}, stored=${storedPrev}`);
        }
      } else if (storedPrev !== null) {
        return fail(currentId, `First record has non-null previous_evidence_hash: ${storedPrev}`);
      }
    } else if (storedPrev !== prevEvidenceHash) {
      return fail(currentId, `Chain break at id=${currentId}: expected prev_hash=${prevEvidenceHash}, stored=${storedPrev}`);
    }

    // Hash-linked id jump: observable, not a failure.
    if (idsNumeric && currentId !== prevId + 1) {
      warnings.push({ code: 'ID_GAP', afterId: prevId, id: currentId, missingIds: currentId - prevId - 1 });
    }

    // Evidence hash integrity — schema_version (and, for >= 2,
    // consent_provenance/policy_decision — TRACE-2) must be included so the
    // recompute dispatches to the field set each record was actually hashed
    // under (see computeEvidenceHash / canonicalFieldsFor).
    const recomputed = computeEvidenceHash({
      evidenceId:          rec.evidence_id,
      artifactId:          rec.artifact_id,
      artifactHash:        rec.artifact_hash,
      policyId:            rec.policy_id,
      policyHash:          rec.policy_hash,
      keyId:               rec.key_id,
      keyFingerprint:      rec.key_fingerprint,
      auditRecordId:       rec.audit_record_id,
      auditRecordHash:     rec.audit_record_hash,
      previousEvidenceHash: rec.previous_evidence_hash,
      schema_version:      rec.schema_version,
      consentProvenance:   rec.consent_provenance ?? null,
      policyDecision:      rec.policy_decision    ?? null,
      callerContext:       rec.caller_context     ?? null,
    });

    if (storedHash !== recomputed) {
      return fail(currentId, `Evidence hash mismatch at id=${currentId}: stored=${storedHash}, recomputed=${recomputed}`);
    }

    prevEvidenceHash = storedHash;
    prevId           = currentId;
    checkedCount++;
  }

  return { valid: true, checkedCount, failureId: null, failureDetail: null, warnings };
}

// ── Reporting ─────────────────────────────────────────────────────────────────

/**
 * Assemble a structured evidence report from an evidence record and optional
 * verification context.
 *
 * @param {object}  evidenceRecord
 * @param {object}  [verificationResult]  — from verifyEvidenceRecord()
 * @param {object}  [opts]
 * @param {string}  [opts.requestedBy]
 * @returns {object}
 */
function assembleEvidenceReport(evidenceRecord, verificationResult, opts) {
  const { requestedBy = 'system' } = opts || {};

  return {
    reportType:    'EVIDENCE_CHAIN_RECORD',
    generatedAt:   new Date().toISOString(),
    requestedBy,
    evidence: {
      evidenceId:           evidenceRecord.evidence_id,
      artifactId:           evidenceRecord.artifact_id,
      artifactHash:         evidenceRecord.artifact_hash,
      decision:             evidenceRecord.decision,
      createdAt:            evidenceRecord.created_at,
    },
    policyLink: {
      policyId:      evidenceRecord.policy_id,
      policyVersion: evidenceRecord.policy_version,
      policyHash:    evidenceRecord.policy_hash,
    },
    keyLink: {
      keyId:         evidenceRecord.key_id,
      keyVersion:    evidenceRecord.key_version,
      keyFingerprint: evidenceRecord.key_fingerprint,
    },
    auditLink: {
      auditRecordId:   evidenceRecord.audit_record_id,
      auditRecordHash: evidenceRecord.audit_record_hash,
    },
    chainLink: {
      evidenceHash:          evidenceRecord.evidence_hash,
      previousEvidenceHash:  evidenceRecord.previous_evidence_hash,
    },
    verification: verificationResult ?? null,
  };
}

/**
 * Convert an array of evidence records to CSV format.
 *
 * @param {object[]} records
 * @returns {string}
 */
function evidenceRecordsToCSV(records) {
  const headers = [
    'id', 'evidence_id', 'artifact_id', 'artifact_hash', 'decision',
    'policy_id', 'policy_version', 'policy_hash',
    'key_id', 'key_version', 'key_fingerprint',
    'audit_record_id', 'audit_record_hash',
    'previous_evidence_hash', 'evidence_hash',
    'created_at', 'tenant_id',
  ];

  // INJ-7: centralized sanitizer — neutralizes leading =/+/-/@ (spreadsheet
  // formula injection) in addition to standard quote-escaping.
  const escape = sanitizeCsvCell;

  const rows = records.map(r => [
    r.id, r.evidence_id, r.artifact_id, r.artifact_hash, r.decision,
    r.policy_id, r.policy_version ?? '', r.policy_hash,
    r.key_id ?? '', r.key_version ?? '', r.key_fingerprint ?? '',
    r.audit_record_id, r.audit_record_hash,
    r.previous_evidence_hash ?? '', r.evidence_hash,
    r.created_at, r.tenant_id ?? '',
  ].map(escape).join(','));

  return [headers.join(','), ...rows].join('\n');
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  computeEvidenceHash,
  computeAuditRecordHash,
  computePersistedAuditRecordHash,
  persistedAuditRecordOf,
  PERSISTED_AUDIT_RECORD_FORMAT,
  computeKeyFingerprint,
  buildEvidenceRecord,
  verifyEvidenceRecord,
  checkDecisionConsistency,
  validateChainContinuity,
  assembleEvidenceReport,
  evidenceRecordsToCSV,
  canonicalFieldsFor,
  CANONICAL_FIELDS,
  CANONICAL_FIELDS_V1,
  CANONICAL_FIELDS_V2,
  CANONICAL_FIELDS_V3,
  CANONICAL_FIELDS_V4,
  EVIDENCE_SCHEMA_V1,
  EVIDENCE_SCHEMA_V2,
  EVIDENCE_SCHEMA_V3,
  EVIDENCE_SCHEMA_V4,
  EVIDENCE_SCHEMA_CURRENT,
  VERIFICATION_STEPS,
};
