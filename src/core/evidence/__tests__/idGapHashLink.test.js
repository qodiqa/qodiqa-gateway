'use strict';

/**
 * continuity is the cryptographic hash link, not id
 * adjacency. A forward id gap across an intact hash link (a sequence value consumed by a
 * transaction that failed after its INSERT) is an additive ID_GAP warning, never a failure;
 * a broken hash link, an edited record, a deletion or a non-increasing id still fails.
 * Real entries from the real entryBuilder; rows in the shape chainStore passes the verifier.
 *
 *   IG-01  contiguous per-record: CHAIN_CONTINUITY PASS, no warnings
 *   IG-02  forward gap + intact hash link: VALID, CHAIN_CONTINUITY PASS, one ID_GAP warning
 *   IG-03  forward gap + broken hash link: INVALID (CHAIN_LINK and CHAIN_CONTINUITY fail)
 *   IG-04  non-increasing id: CHAIN_CONTINUITY FAIL
 *   IG-05  range: contiguous chain valid, warnings []
 *   IG-06  range: hash-linked gap → valid, ID_GAP warning with the missing count
 *   IG-07  range: deleted middle record → "Chain break" (hash link), not a warning
 *   IG-08  range: an edited record → "Evidence hash mismatch"; a reorder → "Non-increasing ID"
 * IG-09 range: first-record genesis rule unchanged
 * IG-10 DECISION_CONSISTENCY is unaffected by the gap handling
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const { buildEvidenceRecord, verifyEvidenceRecord, validateChainContinuity } = require('../chain');
const { buildEntry, normalizeFields } = require('../../audit/entryBuilder');

const HEX = (c) => c.repeat(64);
function chainOf(n) {
  const rows = []; let prevAudit = 'GENESIS'; let prevEv = null;
  for (let i = 1; i <= n; i++) {
    const entry = buildEntry(normalizeFields({
      artifactId: `ig-${i}`, inputHash: HEX('a'), decision: i % 3 ? 'ALLOW' : 'BLOCK', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig', nonce: `n-ig-${i}`,
      requestHash: HEX('b'), policyHash: HEX('c'), verificationResult: true, tenantId: 'tenant-a', publicKeyId: 'tenant-a:key_v1',
    }), prevAudit);
    prevAudit = entry.hash;
    const rec = buildEvidenceRecord(entry, null, { previousEvidenceHash: prevEv });
    prevEv = rec.evidenceHash;
    rows.push({
      entry,
      row: {
        id: i, evidence_id: rec.evidenceId, artifact_id: rec.artifactId, artifact_hash: rec.artifactHash, decision: rec.decision,
        policy_id: rec.policyId, policy_hash: rec.policyHash, key_id: rec.keyId, key_fingerprint: rec.keyFingerprint,
        audit_record_id: rec.auditRecordId, audit_record_hash: rec.auditRecordHash, previous_evidence_hash: rec.previousEvidenceHash,
        evidence_hash: rec.evidenceHash, tenant_id: rec.tenantId, schema_version: rec.schemaVersion,
        consent_provenance: rec.consentProvenance, policy_decision: rec.policyDecision, caller_context: rec.callerContext,
      },
    });
  }
  return rows;
}
const persisted = (e) => ({
  hash: e.hash, canonical: e.canonical, highResTime: String(e.highResTime), tenantId: e.tenantId ?? null, nonce: e.nonce ?? null,
  executionContext: e.executionContext ? JSON.parse(JSON.stringify(e.executionContext)) : null,
  inputHash: e.inputHash, policyHash: e.policyHash, consentProvenance: e.consentProvenance ?? null,
  policyDecision: e.policyDecision ?? null, callerContext: e.callerContext ?? null,
});
const step = (v, name) => v.steps.find(s => s.step === name);
// renumber ids from position `from` onward by +k — the rows' hashes are untouched (ids are not hashed)
const withGap = (rows, from, k) => rows.map((r, i) => (i >= from ? { ...r.row, id: r.row.id + k } : r.row));

describe('per-record CHAIN_CONTINUITY (verifyEvidenceRecord step 7)', () => {
  const c = chainOf(3);

  test('IG-01 contiguous: PASS, VALID, no warnings', () => {
    const v = verifyEvidenceRecord(c[1].row, { auditEntry: persisted(c[1].entry), priorRecord: c[0].row });
    expect(v.result).toBe('VALID');
    expect(step(v, 'CHAIN_CONTINUITY').result).toBe('PASS');
    expect(v.warnings).toEqual([]);
  });

  test('IG-02 forward gap with the hash link intact: VALID, PASS, one additive ID_GAP warning', () => {
    const rec = { ...c[1].row, id: 5 };
    const v = verifyEvidenceRecord(rec, { auditEntry: persisted(c[1].entry), priorRecord: c[0].row });
    expect(v.result).toBe('VALID');
    expect(step(v, 'CHAIN_LINK').result).toBe('PASS');
    expect(step(v, 'CHAIN_CONTINUITY').result).toBe('PASS');
    expect(v.warnings).toEqual([expect.objectContaining({ code: 'ID_GAP', step: 'CHAIN_CONTINUITY', priorId: 1, id: 5, missingIds: 3 })]);
    expect(v.stepsFailed.filter(s => s.result === 'FAIL')).toEqual([]);
  });

  test('IG-03 forward gap with a broken hash link: INVALID — the gap is not excused', () => {
    const rec = { ...c[2].row, id: 5 }; // record 3 presented against record 1: its previous hash is record 2's
    const v = verifyEvidenceRecord(rec, { auditEntry: persisted(c[2].entry), priorRecord: c[0].row });
    expect(v.result).toBe('INVALID');
    expect(step(v, 'CHAIN_LINK').result).toBe('FAIL');
    expect(step(v, 'CHAIN_CONTINUITY').result).toBe('FAIL');
    expect(v.warnings).toEqual([]);
  });

  test('IG-04 non-increasing id: CHAIN_CONTINUITY FAIL', () => {
    const v = verifyEvidenceRecord({ ...c[1].row, id: 1 }, { auditEntry: persisted(c[1].entry), priorRecord: c[0].row });
    expect(step(v, 'CHAIN_CONTINUITY').result).toBe('FAIL');
    expect(v.result).toBe('INVALID');
  });

  test('IG-10 DECISION_CONSISTENCY is unaffected: a changed decision still fails across a gap', () => {
    const v = verifyEvidenceRecord({ ...c[1].row, id: 5, decision: c[1].row.decision === 'ALLOW' ? 'BLOCK' : 'ALLOW' },
      { auditEntry: persisted(c[1].entry), priorRecord: c[0].row });
    expect(v.result).toBe('INVALID');
    expect(v.failedStep).toBe('DECISION_CONSISTENCY');
  });
});

describe('range continuity (validateChainContinuity)', () => {
  const c = chainOf(6);

  test('IG-05 contiguous chain: valid, warnings []', () => {
    expect(validateChainContinuity(c.map(r => r.row))).toEqual({ valid: true, checkedCount: 6, failureId: null, failureDetail: null, warnings: [] });
  });

  test('IG-06 hash-linked gaps: valid, one ID_GAP warning per jump with the unused-id count', () => {
    const rows = withGap(c, 2, 1).map((r, i) => (i >= 4 ? { ...r, id: r.id + 2 } : r)); // ids 1,2,4,5,8,9
    const res = validateChainContinuity(rows);
    expect(res).toEqual(expect.objectContaining({ valid: true, checkedCount: 6, failureId: null }));
    expect(res.warnings).toEqual([
      { code: 'ID_GAP', afterId: 2, id: 4, missingIds: 1 },
      { code: 'ID_GAP', afterId: 5, id: 8, missingIds: 2 },
    ]);
  });

  test('IG-07 a deleted middle record breaks the hash link: "Chain break", not a warning', () => {
    const rows = c.map(r => r.row).filter(r => r.id !== 3);
    const res = validateChainContinuity(rows);
    expect(res.valid).toBe(false);
    expect(res.failureId).toBe(4);
    expect(res.failureDetail).toMatch(/^Chain break at id=4/);
  });

  test('IG-08 an edited record fails its evidence hash; a reorder fails the ordering check', () => {
    const edited = c.map(r => r.row); edited[3] = { ...edited[3], policy_hash: HEX('d') };
    expect(validateChainContinuity(edited)).toEqual(expect.objectContaining({ valid: false, failureId: 4, failureDetail: expect.stringMatching(/^Evidence hash mismatch at id=4/) }));
    // swapping two records: record 4 now follows record 2, so the hash link breaks first
    const reordered = c.map(r => r.row); [reordered[2], reordered[3]] = [reordered[3], reordered[2]];
    expect(validateChainContinuity(reordered)).toEqual(expect.objectContaining({ valid: false, failureId: 4, failureDetail: expect.stringMatching(/^Chain break at id=4/) }));
    // an id that does not increase fails the ordering check even where the hash link holds
    const repeated = c.map(r => r.row); repeated[2] = { ...repeated[2], id: 2 };
    expect(validateChainContinuity(repeated)).toEqual(expect.objectContaining({ valid: false, failureId: 2, failureDetail: expect.stringMatching(/^Non-increasing ID: 2 follows 2/) }));
  });

  test('IG-09 the genesis rule is unchanged: a range starting mid-chain still fails on its first record', () => {
    const res = validateChainContinuity(c.slice(2).map(r => r.row));
    expect(res.valid).toBe(false);
    expect(res.failureDetail).toMatch(/^First record has non-null previous_evidence_hash/);
  });
});
