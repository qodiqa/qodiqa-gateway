'use strict';

/**
 * DECISION_CONSISTENCY.
 *
 * evidence_chain_records.decision is outside the evidence hash, so a
 * changed ALLOW/BLOCK verified VALID. Step 11 compares it with the decision inside
 * the audit entry's canonical, accepted only when that canonical hashes to the
 * record's audit_record_id (itself covered by the evidence hash). Real entries come
 * from the real entryBuilder; rows mirror what chainStore passes the verifier.
 */

const {
  buildEvidenceRecord,
  verifyEvidenceRecord,
  checkDecisionConsistency,
  computeAuditRecordHash,
  computeEvidenceHash,
  VERIFICATION_STEPS,
} = require('../chain');
const { buildEntry, normalizeFields, EMPTY_OUTPUT_HASH } = require('../../audit/entryBuilder');

const HEX = (c) => c.repeat(64);

function makeEntry(decision = 'ALLOW', extra = {}) {
  return buildEntry(normalizeFields({
    artifactId: `art-h133-${decision}`, inputHash: HEX('a'), decision, signature: 'sig-b64',
    outputHash: EMPTY_OUTPUT_HASH,   // v7 (R-5): a synthetic decision that delivered nothing
    nonce: 'nonce-1', executionContext: { route: '/ai/chat', latencyMs: 3 },
    requestHash: HEX('r'), policyHash: HEX('p'), verificationResult: true, tenantId: 'tenant-a',
    publicKeyId: 'tenant-a:key_v1', provider: 'local', model: 'm',
    ...extra,
  }), 'GENESIS');
}

// chainStore's audit_chain projection for a row persistEntry() wrote from `entry`.
function asPersistedRow(entry) {
  return {
    hash: entry.hash, prevHash: entry.prevHash, canonical: entry.canonical,
    artifactId: entry.artifactId, decision: entry.decision,
    timestamp: '2026-09-26 09:00:00.000+00', highResTime: String(entry.highResTime),
    inputHash: entry.inputHash, signature: entry.signature, requestHash: entry.requestHash,
    policyHash: entry.policyHash, verificationResult: entry.verificationResult,
    nonce: entry.nonce ?? null, tenantId: entry.tenantId ?? null,
    executionContext: entry.executionContext ? JSON.parse(JSON.stringify(entry.executionContext)) : null,
    publicKeyId: entry.publicKeyId ?? null, schemaVersion: entry.schemaVersion ?? 1,
    consentProvenance: entry.consentProvenance ?? null, policyDecision: entry.policyDecision ?? null,
    callerContext: entry.callerContext ?? null,
  };
}

// evidence_chain_records row, as verifyEvidenceRecord() receives it.
function asEvidenceRow(rec) {
  return {
    id: 1, evidence_id: rec.evidenceId, artifact_id: rec.artifactId, artifact_hash: rec.artifactHash,
    decision: rec.decision, policy_id: rec.policyId, policy_hash: rec.policyHash, key_id: rec.keyId,
    key_fingerprint: rec.keyFingerprint, audit_record_id: rec.auditRecordId, audit_record_hash: rec.auditRecordHash,
    previous_evidence_hash: rec.previousEvidenceHash, evidence_hash: rec.evidenceHash,
    tenant_id: rec.tenantId, schema_version: rec.schemaVersion,
    consent_provenance: rec.consentProvenance, policy_decision: rec.policyDecision, caller_context: rec.callerContext,
  };
}

function genuine(decision = 'ALLOW', extra = {}) {
  const entry = makeEntry(decision, extra);
  return { entry, row: asEvidenceRow(buildEvidenceRecord(entry, null)), audit: asPersistedRow(entry) };
}

function legacy(decision = 'ALLOW', extra = {}) {
  const entry = makeEntry(decision, extra);
  const rec = { ...buildEvidenceRecord(entry, null), schemaVersion: 3, auditRecordHash: computeAuditRecordHash(entry) };
  rec.evidenceHash = computeEvidenceHash(rec);
  return { entry, row: asEvidenceRow(rec), audit: asPersistedRow(entry) };
}

const step = (v, name) => v.steps.find(s => s.step === name);

describe('DECISION_CONSISTENCY — step list', () => {
  test('DC-01 appended as step 11; the existing ten steps keep their order', () => {
    expect(VERIFICATION_STEPS).toHaveLength(11);
    expect(VERIFICATION_STEPS[10]).toBe('DECISION_CONSISTENCY');
    expect(VERIFICATION_STEPS.slice(0, 10)).toEqual([
      'ARTIFACT_HASH', 'POLICY_HASH', 'KEY_FINGERPRINT', 'AUDIT_RECORD_HASH', 'EVIDENCE_HASH',
      'CHAIN_LINK', 'CHAIN_CONTINUITY', 'CONSENT_PROVENANCE_CONSISTENCY', 'POLICY_DECISION_CONSISTENCY',
      'CALLER_CONTEXT_CONSISTENCY',
    ]);
    const { row, audit } = genuine();
    expect(verifyEvidenceRecord(row, { auditEntry: audit }).steps.map(s => s.step)).toEqual([...VERIFICATION_STEPS]);
  });
});

describe('DECISION_CONSISTENCY — positive controls', () => {
  test.each(['ALLOW', 'BLOCK'])('DC-02 a genuine %s record (schema_version 4) is VALID; the step PASSES', (d) => {
    const { row, audit } = genuine(d);
    const v = verifyEvidenceRecord(row, { auditEntry: audit });
    expect(v.result).toBe('VALID');
    expect(step(v, 'DECISION_CONSISTENCY').result).toBe('PASS');
  });

  test('DC-03 a genuine legacy (schema_version 3) record is VALID; the step PASSES', () => {
    const { row, audit } = legacy('BLOCK');
    const v = verifyEvidenceRecord(row, { auditEntry: audit });
    expect(v.result).toBe('VALID');
    expect(step(v, 'DECISION_CONSISTENCY').result).toBe('PASS');
  });

  test('DC-04 the decision binding does not depend on the legacy auditRecordHash rebuild (entry carried traceId, never persisted)', () => {
    // v7: requestId is a hashed core field now (recoverable from canonical); traceId is still never persisted.
    const { row, audit } = legacy('ALLOW', { traceId: 'trace-h133' });
    const v = verifyEvidenceRecord(row, { auditEntry: audit });
    expect(step(v, 'AUDIT_RECORD_HASH').result).toBe('FAIL'); // pre-existing fail-closed legacy case
    expect(step(v, 'DECISION_CONSISTENCY').result).toBe('PASS');
  });
});

describe('DECISION_CONSISTENCY — altered decisions fail', () => {
  test.each([
    ['ALLOW replaced with BLOCK', 'ALLOW', 'BLOCK'],
    ['BLOCK replaced with ALLOW (fabricated ALLOW)', 'BLOCK', 'ALLOW'],
  ])('DC-05 %s → INVALID at DECISION_CONSISTENCY; every hash step still PASSES (decision is outside the hash)', (_n, orig, forged) => {
    const { row, audit } = genuine(orig);
    const v = verifyEvidenceRecord({ ...row, decision: forged }, { auditEntry: audit });
    expect(v.result).toBe('INVALID');
    expect(v.failedStep).toBe('DECISION_CONSISTENCY');
    expect(v.failureReason).toMatch(/does not match the decision in the hash-protected audit record/);
    for (const s of ['ARTIFACT_HASH', 'POLICY_HASH', 'AUDIT_RECORD_HASH', 'EVIDENCE_HASH']) expect(step(v, s).result).toBe('PASS');
  });

  test.each([
    ['NOT_ATTESTED'], ['ATTESTED'], ['allow'], ['ALLOW '], [''], [null], [undefined], [1], [{ decision: 'ALLOW' }],
  ])('DC-06 fabricated / malformed / missing stored decision %p → INVALID at DECISION_CONSISTENCY', (forged) => {
    const { row, audit } = genuine('ALLOW');
    const v = verifyEvidenceRecord({ ...row, decision: forged }, { auditEntry: audit });
    expect(v.result).toBe('INVALID');
    expect(v.failedStep).toBe('DECISION_CONSISTENCY');
  });

  test('DC-07 a decision replayed from another record (other tenant, other decision) fails', () => {
    const a = genuine('ALLOW');
    const b = genuine('BLOCK', { tenantId: 'tenant-b', publicKeyId: 'tenant-b:key_v1' });
    const v = verifyEvidenceRecord({ ...a.row, decision: b.row.decision }, { auditEntry: a.audit });
    expect(v.failedStep).toBe('DECISION_CONSISTENCY');
  });

  test('DC-08 re-hashed: recomputing the evidence hash after the change leaves it identical, and the change still fails', () => {
    const { row, audit } = genuine('ALLOW');
    const reh = computeEvidenceHash({
      evidenceId: row.evidence_id, artifactId: row.artifact_id, artifactHash: row.artifact_hash, policyId: row.policy_id,
      policyHash: row.policy_hash, keyId: row.key_id, keyFingerprint: row.key_fingerprint, auditRecordId: row.audit_record_id,
      auditRecordHash: row.audit_record_hash, previousEvidenceHash: row.previous_evidence_hash, schema_version: row.schema_version,
      consentProvenance: row.consent_provenance, policyDecision: row.policy_decision, callerContext: row.caller_context, decision: 'BLOCK',
    });
    expect(reh).toBe(row.evidence_hash);
    const v = verifyEvidenceRecord({ ...row, decision: 'BLOCK', evidence_hash: reh }, { auditEntry: audit });
    expect(v.failedStep).toBe('DECISION_CONSISTENCY');
  });

  test('DC-09 re-bound to the audit_chain.decision column: the denormalized column is never the authority', () => {
    const { row, audit } = genuine('ALLOW');
    const v = verifyEvidenceRecord({ ...row, decision: 'BLOCK' }, { auditEntry: { ...audit, decision: 'BLOCK' } });
    expect(v.failedStep).toBe('DECISION_CONSISTENCY');
    // and a genuine record is not failed by a changed column alone
    const g = verifyEvidenceRecord(row, { auditEntry: { ...audit, decision: 'BLOCK' } });
    expect(step(g, 'DECISION_CONSISTENCY').result).toBe('PASS');
  });

  test('DC-10 re-bound into canonical without rehash: the canonical is no longer the bound one — both AUDIT_RECORD_HASH and the step fail', () => {
    const { row, audit } = genuine('ALLOW');
    const forgedAudit = { ...audit, decision: 'BLOCK', canonical: audit.canonical.replace('"decision":"ALLOW"', '"decision":"BLOCK"') };
    const v = verifyEvidenceRecord({ ...row, decision: 'BLOCK' }, { auditEntry: forgedAudit });
    expect(v.result).toBe('INVALID');
    expect(step(v, 'AUDIT_RECORD_HASH').result).toBe('FAIL');
    expect(step(v, 'DECISION_CONSISTENCY').result).toBe('FAIL');
    expect(step(v, 'DECISION_CONSISTENCY').reason).toMatch(/not the one bound to this evidence record/);
  });
});

describe('DECISION_CONSISTENCY — fail closed, never SKIP', () => {
  test('DC-11 no audit entry → FAIL (not SKIP)', () => {
    const { row } = genuine();
    const v = verifyEvidenceRecord(row, { auditEntry: null });
    expect(step(v, 'DECISION_CONSISTENCY')).toEqual(expect.objectContaining({ result: 'FAIL' }));
    expect(v.result).toBe('INVALID');
  });

  test('DC-12 audit entry rejected by the caller (tenant mismatch) → FAIL with that reason', () => {
    const { row } = genuine();
    const v = verifyEvidenceRecord(row, { auditEntry: null, auditEntryRejectedReason: 'audit record tenant does not match the evidence record tenant' });
    expect(step(v, 'DECISION_CONSISTENCY').result).toBe('FAIL');
    expect(step(v, 'DECISION_CONSISTENCY').reason).toMatch(/tenant does not match/);
  });

  test('DC-13 the audit entry of ANOTHER record (its own canonical and hash intact) is not accepted as the authority', () => {
    const a = genuine('ALLOW');
    const b = genuine('BLOCK', { artifactId: 'art-other' });
    const r = checkDecisionConsistency({ ...a.row, decision: 'BLOCK' }, b.audit);
    expect(r).toEqual({ ok: false, reason: expect.stringMatching(/not the one bound/) });
  });

  test.each([
    ['non-string canonical', (au) => ({ ...au, canonical: JSON.parse(au.canonical) })],
    ['missing canonical', (au) => ({ ...au, canonical: undefined })],
  ])('DC-14 %s → not bound → fails', (_n, mut) => {
    const { row, audit } = genuine();
    expect(checkDecisionConsistency(row, mut(audit)).ok).toBe(false);
  });

  test.each([
    ['unparseable canonical', 'not-json'],
    ['canonical without a decision', JSON.stringify({ artifactId: 'x' })],
    ['canonical with a non-enum decision', JSON.stringify({ decision: 'ATTESTED' })],
  ])('DC-15 %s that IS bound to the record → no valid authoritative decision → fails', (_n, canonical) => {
    const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../../infra/crypto/hashing');
    const { row, audit } = genuine();
    const boundId = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, canonical).toString('hex');
    const r = checkDecisionConsistency({ ...row, audit_record_id: boundId }, { ...audit, canonical });
    expect(r).toEqual({ ok: false, reason: expect.stringMatching(/carries no valid decision/) });
  });

  test('DC-16 checkDecisionConsistency on a genuine pair', () => {
    const { row, audit } = genuine('BLOCK');
    expect(checkDecisionConsistency(row, audit)).toEqual({ ok: true, reason: null });
  });
});
