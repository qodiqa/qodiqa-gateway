'use strict';

/**
 * / F6-N2 — the audit-entry write boundary.
 *
 * U+0000 / a lone high or low surrogate in any string value or object key, at any depth, of any field an entry
 *          carries (hashed or not: reason, executionContext, nested arrays, keys, traceId, nonce) → refused:
 *          'invalid_unrepresentable_text: <path>', code AUDIT_UNREPRESENTABLE_TEXT, .field = the path; the message never
 *          echoes the value
 * ordinary Unicode is NOT refused: accented / Romanian / CJK, emoji (correctly PAIRED surrogates), TAB, LF, CR,
 *          DEL, other C0 controls, U+2028 — the restriction is only U+0000 and unpaired surrogates
 * audit-log append() on the real file log: refused, NOTHING written (file bytes and chain length unchanged), and
 *          refused BEFORE the subject-pseudonym step (no key lookup / creation)
 * appendMandatory(): non-retryable (invalid_ prefix) — surfaced on the first attempt, no retry budget burned
 */

jest.mock('../../../infra/postgres/pg-audit-backend', () => ({ persistEntry: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));

const fs = require('fs');
const os = require('os');
const path = require('path');
const eb = require('../entryBuilder');

const base = (o = {}) => ({ artifactId: 'rf-' + Math.random().toString(16).slice(2), decision: 'BLOCK', inputHash: 'a'.repeat(64), signature: 's', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64), verificationResult: false, ...o });
function refusal(fields) { try { eb.normalizeFields(fields); return null; } catch (e) { return e; } }

describe('F6-N2 — write-time refusal of text the downstream raw stores cannot represent', () => {
  test('U+0000 / lone surrogates anywhere → deterministic refusal naming the path, never the value', () => {
    const cases = [
      [{ reason: 'a\u0000b' }, 'reason'],
      [{ reason: 'x\ud800' }, 'reason'],
      [{ reason: '\udc00y' }, 'reason'],
      [{ executionContext: { a: { b: ['ok', 'z\u0000'] } } }, 'executionContext.a.b[1]'],
      [{ semantic: { ['k\ud83d']: 1 } }, 'semantic.<key>'],
      [{ callerContext: { callerId: 'ap1:' + 'a'.repeat(64), callerName: 'n\u0000' } }, 'callerContext.callerName'],
      [{ consentProvenance: { consentId: 'c', subject: 's\udfff' } }, 'consentProvenance.subject'],
      [{ traceId: 't\u0000' }, 'traceId'],
      [{ nonce: 'n\ud800' }, 'nonce'],
      [{ artifactId: 'id\u0000' }, 'artifactId'],
    ];
    for (const [over, p] of cases) {
      const e = refusal(base(over));
      expect({ p, code: e && e.code, field: e && e.field, prefix: e && e.message.startsWith('invalid_unrepresentable_text: '), echoes: e && /[\u0000\ud800-\udfff]/.test(e.message) })
        .toEqual({ p, code: 'AUDIT_UNREPRESENTABLE_TEXT', field: p, prefix: true, echoes: false });
    }
  });

  test('ordinary Unicode, paired surrogates and other controls are accepted', () => {
    for (const s of ['éàü', 'Ștefan își ţară', '漢字かな한국어', '😀👩‍👩‍👧🇷🇴', 'a\tb\nc\rd', 'del\u007f', 'c0\u0001\u001f', 'ls ', '"q" \\ b']) {
      expect({ s, refused: refusal(base({ reason: s, executionContext: { [s]: [s] } })) }).toEqual({ s, refused: null });
    }
  });

  test('append() on the real file log: refused before anything is written, before the pseudonym step', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f6n2-'));
    const saved = process.env.QODIQA_AUDIT_LOG;
    process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit.log');
    let audit; let sp;
    try { jest.isolateModules(() => { audit = require('../audit-log'); sp = require('../../dsr/subjectPseudonym'); }); }
    finally { if (saved === undefined) delete process.env.QODIQA_AUDIT_LOG; else process.env.QODIQA_AUDIT_LOG = saved; }
    try {
      await audit.append(base({ reason: 'ok' }));                                   // one good entry first
      const bytes = fs.statSync(path.join(dir, 'audit.log')).size;
      const len = audit.getChainStats().modernLength;
      sp.pseudonymFor.mockClear();
      await expect(audit.append(base({ callerContext: { callerId: 'raw-subject', callerName: 'x\u0000' } })))
        .rejects.toMatchObject({ code: 'AUDIT_UNREPRESENTABLE_TEXT', field: 'callerContext.callerName' });
      expect(sp.pseudonymFor).not.toHaveBeenCalled();
      expect(audit.getChainStats().modernLength).toBe(len);
      expect(fs.statSync(path.join(dir, 'audit.log')).size).toBe(bytes);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }   // this test's own temp dir
  });

  test('appendMandatory: non-retryable, surfaced on the first attempt', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f6n2-'));
    const saved = process.env.QODIQA_AUDIT_LOG;
    process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit.log');
    let audit;
    try { jest.isolateModules(() => { audit = require('../audit-log'); }); } finally { if (saved === undefined) delete process.env.QODIQA_AUDIT_LOG; else process.env.QODIQA_AUDIT_LOG = saved; }
    const metrics = require('../../../observability/metrics');
    const spy = jest.spyOn(metrics.auditAppendRetriesTotal, 'inc');
    try {
      await expect(audit.appendMandatory(base({ reason: '\ud800' }), { stage: 'INTENT', maxRetries: 3, retryDelayMs: 1 })).rejects.toMatchObject({ code: 'AUDIT_UNREPRESENTABLE_TEXT' });
      expect(spy).not.toHaveBeenCalled();
    } finally { spy.mockRestore(); fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
