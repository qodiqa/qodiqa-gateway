'use strict';

/**
 * audit schema v7 — R-14 fail-closed pseudonymization, with the REAL src/core/dsr/subjectPseudonym.js (no mock).
 * Unit runs have no PostgreSQL (jest.setup forces QODIQA_PG_ENABLED=false), which is exactly the condition R-14 rules
 * on: an append that carries consentProvenance.subject or callerContext.callerId must be REFUSED — no raw-identity
 * entry, no v6 downgrade — while an append with no identity to pseudonymize needs no database at all.
 *
 *   PF-01  callerContext.callerId without PostgreSQL → rejected, code SUBJECT_PSEUDONYM_UNAVAILABLE, nothing written
 *   PF-02  consentProvenance.subject without PostgreSQL → rejected the same way
 *   PF-03  appendMandatory treats it as non-retryable (one attempt, no retry budget burned) and surfaces it unchanged
 *   PF-04  no identity → the append succeeds without PostgreSQL (the pre-step is skipped, not weakened)
 */

jest.mock('../../../infra/postgres/pg-audit-backend', () => ({ persistEntry: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const fs = require('fs');
const os = require('os');
const path = require('path');
const { EMPTY_OUTPUT_HASH } = require('../entryBuilder');

const dirs = [];
afterAll(() => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });   // this suite's own temp dirs
function freshAudit() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w7pf-')); dirs.push(dir);
  const saved = process.env.QODIQA_AUDIT_LOG;
  process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit.log');
  let audit; let pool;
  try { jest.isolateModules(() => { audit = require('../audit-log'); pool = require('../../../infra/postgres/pool'); }); }
  finally { if (saved === undefined) delete process.env.QODIQA_AUDIT_LOG; else process.env.QODIQA_AUDIT_LOG = saved; }
  return { audit, pool, log: path.join(dir, 'audit.log') };
}
const fields = (over = {}) => ({ artifactId: 'pf-' + Math.random().toString(16).slice(2), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: EMPTY_OUTPUT_HASH, signature: 's', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64), verificationResult: true, tenantId: 't1', ...over });

describe('R-14 — pseudonymization is fail-closed without PostgreSQL', () => {
  test('PF-01 callerContext.callerId → refused, nothing written', async () => {
    const { audit, pool, log } = freshAudit();
    expect(pool.isEnabled()).toBe(false);
    await expect(audit.append(fields({ callerContext: { callerId: 'identity-x' } })))
      .rejects.toMatchObject({ code: 'SUBJECT_PSEUDONYM_UNAVAILABLE', message: expect.stringMatching(/^subject_pseudonym_unavailable: /) });
    expect(audit.getChainStats().modernLength).toBe(0);
    expect(fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '').not.toContain('identity-x');
  });

  test('PF-02 consentProvenance.subject → refused the same way', async () => {
    const { audit } = freshAudit();
    await expect(audit.append(fields({ consentProvenance: { consentId: 'c', subject: 'subject-y' } })))
      .rejects.toMatchObject({ code: 'SUBJECT_PSEUDONYM_UNAVAILABLE' });
    expect(audit.getChainStats().modernLength).toBe(0);
  });

  test('PF-03 appendMandatory: non-retryable — surfaced on the first attempt', async () => {
    const { audit } = freshAudit();
    const metrics = require('../../../observability/metrics');
    const spy = jest.spyOn(metrics.auditAppendRetriesTotal, 'inc');
    try {
      await expect(audit.appendMandatory(fields({ callerContext: { callerId: 'identity-z' } }), { stage: 'INTENT', maxRetries: 3, retryDelayMs: 1 }))
        .rejects.toMatchObject({ code: 'SUBJECT_PSEUDONYM_UNAVAILABLE' });
      expect(spy).not.toHaveBeenCalled();
    } finally { spy.mockRestore(); }
  });

  test('PF-04 no identity → the append needs no database and succeeds as v7', async () => {
    const { audit } = freshAudit();
    const e = await audit.append(fields({ callerContext: null, consentProvenance: null }));
    expect(e.schemaVersion).toBe(7);
    expect(audit.getChainStats().modernLength).toBe(1);
  });
});
