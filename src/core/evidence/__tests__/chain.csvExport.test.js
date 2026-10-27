'use strict';

/**
 * INJ-7 remediation — evidenceRecordsToCSV formula-injection protection.
 */

const { evidenceRecordsToCSV } = require('../chain');

describe('chain.evidenceRecordsToCSV — INJ-7 formula injection protection', () => {
  test('a decision field starting with "=" is neutralized with a leading quote', () => {
    const csv = evidenceRecordsToCSV([{
      id: 1, evidence_id: 'e1', artifact_id: 'a1', artifact_hash: 'h1',
      decision: '=cmd|\'/C calc\'!A0', policy_id: 'p1', policy_hash: 'ph1',
      audit_record_id: 'ar1', audit_record_hash: 'arh1', evidence_hash: 'eh1',
      created_at: '2024-01-01T00:00:00Z',
    }]);
    const dataRow = csv.split('\n')[1];
    expect(dataRow).toContain('"\'=cmd');
  });

  test('an ordinary decision value is unaffected beyond standard quoting', () => {
    const csv = evidenceRecordsToCSV([{
      id: 1, evidence_id: 'e1', artifact_id: 'a1', artifact_hash: 'h1',
      decision: 'ALLOW', policy_id: 'p1', policy_hash: 'ph1',
      audit_record_id: 'ar1', audit_record_hash: 'arh1', evidence_hash: 'eh1',
      created_at: '2024-01-01T00:00:00Z',
    }]);
    expect(csv).toContain('ALLOW');
  });
});
