'use strict';

/**
 * the approval-statement vectors (docs/protocol/vectors/approval.json, APPROVAL-nnn).
 *
 *   PV-01  the committed file is exactly what the production implementation produces now
 *   PV-02  coverage: the cases the plan names (wrong actionHash, expired, same person approves and asks, tampering) and every other way the statement can be wrong
 *   PV-03  the independent Node verifier (no src/ imports) re-derives every verdict
 *   PV-04  the independent Python verifier (own JCS-P1 and Ed25519) re-derives every verdict (skipped only when no python is installed)
 *   PV-05  negative control: a changed verdict is rejected by both verifiers
 *   PV-06  neither verifier imports production code
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..', '..');
const FILE = path.join(REPO, 'docs', 'protocol', 'vectors', 'approval.json');
const v = JSON.parse(fs.readFileSync(FILE, 'utf8'));
const python = (() => { for (const exe of ['python', 'python3']) { const r = spawnSync(exe, ['-c', 'print(1)'], { encoding: 'utf8' }); if (r.status === 0) return exe; } return null; })();

describe('approval vectors', () => {
  test('PV-01 the committed file is what the generator produces', () => {
    expect(spawnSync(process.execPath, ['scripts/protocol/gen-approval-vectors.js', '--check'], { cwd: REPO, encoding: 'utf8' }).status).toBe(0);
  });

  test('PV-02 coverage', () => {
    expect(v.cases.length).toBeGreaterThanOrEqual(30);
    expect(new Set(v.cases.map((c) => c.id)).size).toBe(v.cases.length);
    const text = v.cases.map((c) => c.description).join('\n');
    for (const needle of ['another actionHash', 'expired', 'approver equals requester', 'altered after signing', 'not the tenant key', 'another tenant', 'denied', 'not yet valid', 'extra member', 'decided in the future']) expect(text).toContain(needle);
    const details = new Set(v.cases.filter((c) => c.expected.detail).map((c) => c.expected.detail));
    for (const d of ['shape', 'signature', 'tenant', 'denied', 'the approver is the requester', 'not for this actionHash', 'not for this sessionId', 'not yet valid', 'decided in the future']) expect(details.has(d)).toBe(true);
    expect(v.cases.some((c) => c.expected.reason === 'APPROVAL_EXPIRED')).toBe(true);
    expect(v.cases.filter((c) => c.expected.ok).length).toBeGreaterThanOrEqual(5);
    expect(JSON.stringify(v)).not.toMatch(/PRIVATE KEY|privateKey|"seed"/);
  });

  test('PV-03 the independent Node verifier agrees on every case', () => {
    const r = spawnSync(process.execPath, ['scripts/protocol/verify-approval-vectors.js'], { cwd: REPO, encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toMatchObject({ checks: v.cases.length, failed: 0 });
  });

  (python ? test : test.skip)('PV-04 the independent Python verifier agrees on every case', () => {
    const r = spawnSync(python, ['-I', 'scripts/protocol/verify_approval_vectors.py'], { cwd: REPO, encoding: 'utf8', timeout: 200_000 });
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toMatchObject({ checks: v.cases.length, failed: 0 });
  });

  test('PV-05 negative control', () => {
    const bad = JSON.parse(JSON.stringify(v));
    bad.cases[0].expected.digest = '0'.repeat(64);
    const refused = bad.cases.findIndex((c) => !c.expected.ok);
    bad.cases[refused].expected.reason = 'APPROVAL_EXPIRED';
    const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-appr-')), 'bad.json');
    fs.writeFileSync(f, JSON.stringify(bad));
    const n = spawnSync(process.execPath, ['scripts/protocol/verify-approval-vectors.js', f], { cwd: REPO, encoding: 'utf8' });
    expect(n.status).toBe(1); expect(JSON.parse(n.stdout).failed).toBe(2);
    if (python) {
      const p = spawnSync(python, ['-I', 'scripts/protocol/verify_approval_vectors.py', f], { cwd: REPO, encoding: 'utf8', timeout: 200_000 });
      expect(p.status).toBe(1); expect(JSON.parse(p.stdout).failed).toBe(2);
    }
  });

  test('PV-06 neither verifier imports production code', () => {
    for (const f of ['scripts/protocol/verify-approval-vectors.js', 'scripts/protocol/verify_approval_vectors.py']) {
      const src = fs.readFileSync(path.join(REPO, f), 'utf8');
      expect(src).not.toMatch(/require\(['"][^'"]*\/(src|services)\//);
      expect(src).not.toMatch(/^\s*(from|import)\s+(src|services)\b/m);
    }
  });
});
