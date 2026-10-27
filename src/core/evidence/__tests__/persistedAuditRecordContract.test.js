'use strict';

/**
 * (evidence-verifier RLS) — AUDIT_RECORD_HASH contract, design decision
 * STOP 2 = C.
 *
 * Evidence schema_version 4 hashes the audit record's PERSISTED representation
 * (persistedAuditRecordOf: format tag, hash, canonical, highResTime, tenantId,
 * nonce, executionContext). schema_version 1-3 keep the legacy contract (the
 * full in-memory entry), verified from the entry as read or a faithful rebuild
 * from persisted data — never with fabricated requestId/traceId/organizationId.
 * Real entries come from the real entryBuilder; the "row" side mirrors exactly
 * what pg-audit-backend.persistEntry() stores and chainStore's projection reads.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const {
  buildEvidenceRecord,
  verifyEvidenceRecord,
  computeAuditRecordHash,
  computePersistedAuditRecordHash,
  persistedAuditRecordOf,
  PERSISTED_AUDIT_RECORD_FORMAT,
  canonicalFieldsFor,
  computeEvidenceHash,
  CANONICAL_FIELDS_V3,
  CANONICAL_FIELDS_V4,
  EVIDENCE_SCHEMA_V4,
  EVIDENCE_SCHEMA_CURRENT,
} = require('../chain');
const { buildEntry, normalizeFields } = require('../../audit/entryBuilder');

const HEX = (c) => c.repeat(64);

function makeEntry(extra = {}) {
  return buildEntry(normalizeFields({
    artifactId: 'art-h127-1', inputHash: HEX('a'), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig-b64',
    nonce: 'nonce-1', executionContext: { route: '/ai/chat', latencyMs: 12, nested: { b: 2, a: 1 } },
    requestHash: HEX('r'), policyHash: HEX('p'), verificationResult: true, tenantId: 'tenant-a',
    publicKeyId: 'tenant-a:key_v1', provider: 'local', model: 'llama3.2:1b',
    ...extra,
  }), 'GENESIS');
}

// What chainStore's projection returns for a row persistEntry() wrote from `entry`.
function asPersistedRow(entry) {
  return {
    hash: entry.hash, prevHash: entry.prevHash, canonical: entry.canonical,
    artifactId: entry.artifactId, decision: entry.decision,
    timestamp: '2026-09-24 15:07:30.561+00',            // recorded_at::text — not the ISO string
    highResTime: String(entry.highResTime),
    inputHash: entry.inputHash, signature: entry.signature, requestHash: entry.requestHash,
    policyHash: entry.policyHash, verificationResult: entry.verificationResult,
    nonce: entry.nonce ?? null, tenantId: entry.tenantId ?? null,
    executionContext: entry.executionContext ? JSON.parse(JSON.stringify(entry.executionContext)) : null,
    publicKeyId: entry.publicKeyId ?? null, schemaVersion: entry.schemaVersion ?? 1,
    consentProvenance: entry.consentProvenance ?? null, policyDecision: entry.policyDecision ?? null,
    callerContext: entry.callerContext ?? null,
  };
}

// DB-row shape of an evidence record, as verifyEvidenceRecord() receives it.
// `decision` (a NOT NULL column) was missing from this double; step 11
// (DECISION_CONSISTENCY) reads it, and a row without it correctly fails closed.
function asEvidenceRow(rec) {
  return {
    id: 1, evidence_id: rec.evidenceId, artifact_id: rec.artifactId, artifact_hash: rec.artifactHash, decision: rec.decision,
    policy_id: rec.policyId, policy_hash: rec.policyHash, key_id: rec.keyId, key_fingerprint: rec.keyFingerprint,
    audit_record_id: rec.auditRecordId, audit_record_hash: rec.auditRecordHash,
    previous_evidence_hash: rec.previousEvidenceHash, evidence_hash: rec.evidenceHash,
    tenant_id: rec.tenantId, schema_version: rec.schemaVersion,
    consent_provenance: rec.consentProvenance, policy_decision: rec.policyDecision, caller_context: rec.callerContext,
  };
}

const step = (v, name) => v.steps.find(s => s.step === name);

describe('persisted audit-record contract (evidence schema_version 4)', () => {
  test('PAR-01 current evidence schema is 4; V4 = V3 + schemaVersion; dispatch by version', () => {
    expect(EVIDENCE_SCHEMA_CURRENT).toBe(EVIDENCE_SCHEMA_V4);
    expect(CANONICAL_FIELDS_V4).toEqual([...CANONICAL_FIELDS_V3, 'schemaVersion']);
    expect(canonicalFieldsFor({ schema_version: 4 })).toBe(CANONICAL_FIELDS_V4);
    expect(canonicalFieldsFor({ schema_version: 3 })).toBe(CANONICAL_FIELDS_V3);
  });

  test('PAR-02 the persisted representation covers exactly the documented persisted fields — never traceId; requestId/organizationId only inside the hashed v7 canonical', () => {
    const entry = makeEntry({ requestId: 'req-1', traceId: 'trace-1', organizationId: 'org-1' });
    const rep = persistedAuditRecordOf(entry);
    expect(Object.keys(rep).sort()).toEqual(['canonical', 'executionContext', 'format', 'hash', 'highResTime', 'nonce', 'tenantId']);
    expect(rep.format).toBe(PERSISTED_AUDIT_RECORD_FORMAT);
    expect(JSON.stringify(rep)).not.toMatch(/trace-1/);
    // audit schema v7: requestId/organizationId are hash-protected core fields of the audit entry itself, so they
    // reach the persisted representation only as part of the verbatim canonical (bound by audit_chain.hash) — never as
    // a separate, unbound envelope key.
    expect(JSON.parse(rep.canonical)).toMatchObject({ schemaVersion: 7, requestId: 'req-1', organizationId: 'org-1' });
  });

  test('PAR-03 write side (in-memory entry) and read side (persisted row) hash identically, with and without optional envelope fields', () => {
    for (const extra of [{}, { requestId: 'req-1', traceId: 't-1' }, { tenantId: undefined, nonce: undefined, executionContext: undefined }]) {
      const entry = makeEntry(extra);
      expect(computePersistedAuditRecordHash(asPersistedRow(entry))).toBe(computePersistedAuditRecordHash(entry));
    }
  });

  test('PAR-04 a genuine v4 record verifies VALID from the persisted row even though the entry carried requestId/traceId', () => {
    const entry = makeEntry({ requestId: 'req-1', traceId: 't-1' });
    const rec = buildEvidenceRecord(entry, null);
    expect(rec.schemaVersion).toBe(4);
    const v = verifyEvidenceRecord(asEvidenceRow(rec), { auditEntry: asPersistedRow(entry) });
    expect(v.result).toBe('VALID');
    expect(step(v, 'AUDIT_RECORD_HASH').result).toBe('PASS');
    expect(step(v, 'EVIDENCE_HASH').result).toBe('PASS');
  });

  test.each([
    ['canonical', (r) => ({ ...r, canonical: r.canonical.replace('"ALLOW"', '"BLOCK"') })],
    ['hash', (r) => ({ ...r, hash: HEX('0') })],
    ['tenantId', (r) => ({ ...r, tenantId: 'tenant-b' })],
    ['nonce', (r) => ({ ...r, nonce: 'nonce-2' })],
    ['highResTime', (r) => ({ ...r, highResTime: '1' })],
    ['executionContext', (r) => ({ ...r, executionContext: { ...r.executionContext, route: '/sign' } })],
  ])('PAR-05 v4: tampering the persisted %s fails AUDIT_RECORD_HASH', (_name, tamper) => {
    const entry = makeEntry();
    const rec = buildEvidenceRecord(entry, null);
    const v = verifyEvidenceRecord(asEvidenceRow(rec), { auditEntry: tamper(asPersistedRow(entry)) });
    expect(step(v, 'AUDIT_RECORD_HASH').result).toBe('FAIL');
    expect(v.result).toBe('INVALID');
  });

  test('PAR-06 the version marker is hash-bound: relabelling v4 -> 3 or a v3 record -> 4 fails', () => {
    const entry = makeEntry();
    const row = asEvidenceRow(buildEvidenceRecord(entry, null));
    const down = verifyEvidenceRecord({ ...row, schema_version: 3 }, { auditEntry: asPersistedRow(entry) });
    expect(step(down, 'EVIDENCE_HASH').result).toBe('FAIL');
    expect(step(down, 'AUDIT_RECORD_HASH').result).toBe('FAIL');

    const legacyRec = { ...buildEvidenceRecord(entry, null), schemaVersion: 3, auditRecordHash: computeAuditRecordHash(entry) };
    legacyRec.evidenceHash = computeEvidenceHash(legacyRec);
    const up = verifyEvidenceRecord({ ...asEvidenceRow(legacyRec), schema_version: 4 }, { auditEntry: asPersistedRow(entry) });
    expect(step(up, 'EVIDENCE_HASH').result).toBe('FAIL');
  });
});

describe('legacy contract (evidence schema_version < 4)', () => {
  function legacyRow(entry) {
    const rec = { ...buildEvidenceRecord(entry, null), schemaVersion: 3, auditRecordHash: computeAuditRecordHash(entry) };
    rec.evidenceHash = computeEvidenceHash(rec);
    return asEvidenceRow(rec);
  }

  test('LEG-01 a legacy record whose entry carried no non-persisted fields is rebuilt faithfully and PASSES', () => {
    const entry = makeEntry();
    const v = verifyEvidenceRecord(legacyRow(entry), { auditEntry: asPersistedRow(entry) });
    expect(step(v, 'AUDIT_RECORD_HASH').result).toBe('PASS');
    expect(v.result).toBe('VALID');
  });

  test('LEG-02 a legacy record whose entry carried traceId (never persisted) cannot be recomputed without fabrication — FAIL, and the reason says why', () => {
    // v7: requestId/organizationId are now hashed core fields (inside the persisted canonical), so the never-
    // persisted field that exercises this fail-closed path is traceId (LEG-02b covers the v7 requestId case).
    const entry = makeEntry({ traceId: 'trace-h127-1' });
    const v = verifyEvidenceRecord(legacyRow(entry), { auditEntry: asPersistedRow(entry) });
    const s = step(v, 'AUDIT_RECORD_HASH');
    expect(s.result).toBe('FAIL');
    expect(s.reason).toMatch(/legacy contract.*requestId\/traceId\/organizationId/);
    expect(v.result).toBe('INVALID');
  });

  test('LEG-02b v7: a legacy record whose v7 entry carried requestId is rebuilt from the hashed canonical — PASS, nothing fabricated', () => {
    const entry = makeEntry({ requestId: 'art-h127-1' });
    expect(JSON.parse(entry.canonical).requestId).toBe('art-h127-1');
    const v = verifyEvidenceRecord(legacyRow(entry), { auditEntry: asPersistedRow(entry) });
    expect(step(v, 'AUDIT_RECORD_HASH').result).toBe('PASS');
  });

  test('LEG-03 a tampered legacy audit record still FAILS', () => {
    const entry = makeEntry();
    const row = asPersistedRow(entry);
    const v = verifyEvidenceRecord(legacyRow(entry), { auditEntry: { ...row, canonical: row.canonical.replace('"ALLOW"', '"BLOCK"') } });
    expect(step(v, 'AUDIT_RECORD_HASH').result).toBe('FAIL');
  });
});

describe('unavailable / rejected audit entry (fail-closed)', () => {
  test('UNV-01 no audit entry: steps 1, 2, 4 FAIL with the unchanged "not found" wording', () => {
    const rec = buildEvidenceRecord(makeEntry(), null);
    const v = verifyEvidenceRecord(asEvidenceRow(rec), {});
    expect(v.result).toBe('INVALID');
    expect(step(v, 'ARTIFACT_HASH').reason).toBe('Audit entry not found in chain — cannot verify artifact hash');
    expect(step(v, 'AUDIT_RECORD_HASH').result).toBe('FAIL');
  });

  test('UNV-02 a rejected audit entry fails the same steps and says it was rejected, not missing', () => {
    const rec = buildEvidenceRecord(makeEntry(), null);
    const v = verifyEvidenceRecord(asEvidenceRow(rec), { auditEntryRejectedReason: 'audit record tenant does not match the evidence record tenant' });
    expect(v.result).toBe('INVALID');
    for (const n of ['ARTIFACT_HASH', 'POLICY_HASH', 'AUDIT_RECORD_HASH']) {
      expect(step(v, n).result).toBe('FAIL');
      expect(step(v, n).reason).toMatch(/^Audit entry rejected: audit record tenant does not match/);
    }
  });
});
