'use strict';

/**
 * — the evidence chain after a retention prune, without PostgreSQL:
 *   EB-01  validateChainContinuity: a kept range linking to the prune base verifies; the same range with the first
 *          link altered, or without the base, fails; omitting startHash keeps the genesis rule
 *   EB-02  evidenceBase._validate: a base whose checkpoint verifies and whose signed head matches is accepted; a bad
 *          signature, a head that is not the signed one, and an out-of-range lastPrunedId fail CLOSED ({error})
 *   EB-03  a base carried forward by a later prune verifies against the checkpoint it carries
 *   EB-04  getEvidenceBase: no row → null; a pre-071 schema (42P01) → null; other errors propagate
 */

const chain = require('../chain');
const { _validate, getEvidenceBase } = require('../evidenceBase');

function record(id, prev) {
  const r = { id, evidence_id: `00000000-0000-4000-8000-${String(id).padStart(12, '0')}`, artifact_id: `a-${id}`, artifact_hash: 'a'.repeat(64),
    policy_id: 'p', policy_hash: 'b'.repeat(64), key_id: 'k', key_fingerprint: 'c'.repeat(64), audit_record_id: `a-${id}`,
    audit_record_hash: 'd'.repeat(64), previous_evidence_hash: prev, schema_version: 1 };
  r.evidence_hash = chain.computeEvidenceHash({ evidenceId: r.evidence_id, artifactId: r.artifact_id, artifactHash: r.artifact_hash, policyId: r.policy_id,
    policyHash: r.policy_hash, keyId: r.key_id, keyFingerprint: r.key_fingerprint, auditRecordId: r.audit_record_id, auditRecordHash: r.audit_record_hash,
    previousEvidenceHash: prev, schema_version: 1, consentProvenance: null, policyDecision: null, callerContext: null });
  return r;
}
function chainFrom(prevHash, fromId, n) {
  const out = []; let prev = prevHash;
  for (let i = 0; i < n; i++) { const r = record(fromId + i, prev); out.push(r); prev = r.evidence_hash; }
  return out;
}

describe('evidence chain after a retention prune', () => {
  const full = chainFrom(null, 1, 8);
  const E = 4; const base = full[E - 1].evidence_hash;
  const kept = full.slice(E);

  test('EB-01 continuity from the prune base', () => {
    expect(chain.validateChainContinuity(full)).toMatchObject({ valid: true, checkedCount: 8 });
    expect(chain.validateChainContinuity(kept, { startHash: base })).toMatchObject({ valid: true, checkedCount: 4 });
    expect(chain.validateChainContinuity(kept)).toMatchObject({ valid: false, failureId: 5 });           // genesis rule without the base
    const altered = kept.map((r) => ({ ...r }));
    altered[0].previous_evidence_hash = 'f'.repeat(64);
    expect(chain.validateChainContinuity(altered, { startHash: base }).valid).toBe(false);
    const gap = [kept[0], ...kept.slice(2)];                                                               // a deleted kept record
    expect(chain.validateChainContinuity(gap, { startHash: base }).valid).toBe(false);
  });

  const cp = (evidenceHead) => ({ payload: { checkpointId: 'cp-1', evidenceHead } });
  const ok = () => ({ ok: true });

  test('EB-02 base validation fails closed', () => {
    const signedHead = { id: 6, hash: full[5].evidence_hash };
    const rec = { checkpoint: cp(signedHead), evidence: { lastPrunedId: E, lastPrunedHash: base, signedHead } };
    expect(_validate(rec, ok)).toEqual({ lastPrunedId: E, lastPrunedHash: base, signedHead, checkpointId: 'cp-1' });
    expect(_validate(rec, () => ({ ok: false, reason: 'CHECKPOINT_SIGNATURE_INVALID' })).error).toMatch(/EVIDENCE_BASE_CHECKPOINT_INVALID/);
    expect(_validate({ ...rec, evidence: { ...rec.evidence, signedHead: { id: 6, hash: 'e'.repeat(64) } } }, ok).error).toMatch(/EVIDENCE_BASE_MISMATCH/);
    expect(_validate({ ...rec, evidence: { ...rec.evidence, lastPrunedId: 7 } }, ok).error).toMatch(/EVIDENCE_BASE_MALFORMED/);
    expect(_validate({ checkpoint: cp(signedHead), evidence: { lastPrunedId: 6, lastPrunedHash: base, signedHead } }, ok).error).toMatch(/EVIDENCE_BASE_MISMATCH/);
    expect(_validate({ checkpoint: cp(signedHead), evidence: null }, ok)).toBeNull();
  });

  test('EB-03 a base carried forward verifies against the checkpoint it carries', () => {
    const oldHead = { id: 6, hash: full[5].evidence_hash };
    const rec = { checkpoint: cp({ id: 8, hash: full[7].evidence_hash }), evidence: { lastPrunedId: E, lastPrunedHash: base, signedHead: oldHead, checkpoint: cp(oldHead) } };
    expect(_validate(rec, ok)).toMatchObject({ lastPrunedId: E, signedHead: oldHead });
    expect(_validate({ ...rec, evidence: { ...rec.evidence, checkpoint: undefined } }, ok).error).toMatch(/EVIDENCE_BASE_MISMATCH/);
  });

  test('EB-04 reading the base', async () => {
    expect(await getEvidenceBase({ query: async () => ({ rows: [] }) })).toBeNull();
    expect(await getEvidenceBase({ query: async () => { const e = new Error('relation "audit_chain_prunes" does not exist'); e.code = '42P01'; throw e; } })).toBeNull();
    await expect(getEvidenceBase({ query: async () => { throw new Error('connection refused'); } })).rejects.toThrow('connection refused');
  });
});
