'use strict';

/**
 * the delegation-chain vectors (docs/protocol/vectors/delegation.json, DELEG-nnn).
 *
 *   DV-01  the committed file is exactly what the production implementation produces now
 *   DV-02  coverage: >= 30 cases, every reason of V2-FREEZE 7.5 that a chain can reach, every attack of the plan (forged chain, attenuation, cycle, depth, splice)
 *   DV-03  the independent Node verifier (no src/ imports) re-derives every verdict
 *   DV-04  the independent Python verifier (own JCS-P1 and Ed25519) re-derives every verdict (skipped only when no python is installed)
 *   DV-05  negative control: a vector whose verdict is changed is rejected by both verifiers
 *   DV-06  neither verifier imports production code
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..', '..');
const FILE = path.join(REPO, 'docs', 'protocol', 'vectors', 'delegation.json');
const v = JSON.parse(fs.readFileSync(FILE, 'utf8'));
const python = (() => { for (const exe of ['python', 'python3']) { const r = spawnSync(exe, ['-c', 'print(1)'], { encoding: 'utf8' }); if (r.status === 0) return exe; } return null; })();
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-deleg-'));

describe('delegation vectors', () => {
  test('DV-01 the committed file is what the generator produces', () => {
    expect(spawnSync(process.execPath, ['scripts/protocol/gen-delegation-vectors.js', '--check'], { cwd: REPO, encoding: 'utf8' }).status).toBe(0);
  });

  test('DV-02 coverage', () => {
    expect(v.cases.length).toBeGreaterThanOrEqual(30);
    expect(new Set(v.cases.map((c) => c.id)).size).toBe(v.cases.length);
    const reasons = new Set(v.cases.filter((c) => !c.expected.ok).map((c) => c.expected.reason));
    for (const r of ['DELEGATION_INVALID', 'DELEGATION_ATTENUATION_VIOLATION', 'DELEGATION_DEPTH_EXCEEDED', 'DELEGATION_CYCLE']) expect(reasons.has(r)).toBe(true);
    const text = v.cases.map((c) => c.description).join('\n');
    for (const needle of ['tampered', 'spliced', 'missing', 'wrong order', 'repeated', 'back to the root agent', 'itself', 'larger action limit', 'outlives', 'maxDepth', 'expired', 'first']) expect(text).toContain(needle);
    expect(v.cases.filter((c) => c.expected.ok).length).toBeGreaterThanOrEqual(6);
    expect(v.cases.some((c) => c.input.chain.length === 8 && c.expected.ok)).toBe(true);
    // the published seeds are not secrets and no private key is in the file
    expect(JSON.stringify(v)).not.toMatch(/PRIVATE KEY|privateKey|"seed"/);
  });

  test('DV-03 the independent Node verifier agrees on every case', () => {
    const r = spawnSync(process.execPath, ['scripts/protocol/verify-delegation-vectors.js'], { cwd: REPO, encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toMatchObject({ checks: v.cases.length, failed: 0 });
  });

  (python ? test : test.skip)('DV-04 the independent Python verifier agrees on every case', () => {
    const r = spawnSync(python, ['-I', 'scripts/protocol/verify_delegation_vectors.py'], { cwd: REPO, encoding: 'utf8', timeout: 200_000 });
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toMatchObject({ checks: v.cases.length, failed: 0 });
  });

  test('DV-05 negative control: a changed verdict is rejected by both verifiers', () => {
    const bad = JSON.parse(JSON.stringify(v));
    bad.cases[0].expected.depth += 1;                                                        // a valid case with a wrong fact
    const refused = bad.cases.findIndex((c) => !c.expected.ok);
    bad.cases[refused].expected.reason = 'DELEGATION_CYCLE';                                 // a refusal with the wrong reason
    const f = path.join(tmp(), 'bad.json');
    fs.writeFileSync(f, JSON.stringify(bad));
    const n = spawnSync(process.execPath, ['scripts/protocol/verify-delegation-vectors.js', f], { cwd: REPO, encoding: 'utf8' });
    expect(n.status).toBe(1);
    expect(JSON.parse(n.stdout).failed).toBe(2);
    if (python) {
      const p = spawnSync(python, ['-I', 'scripts/protocol/verify_delegation_vectors.py', f], { cwd: REPO, encoding: 'utf8', timeout: 200_000 });
      expect(p.status).toBe(1);
      expect(JSON.parse(p.stdout).failed).toBe(2);
    }
  });

  test('DV-06 neither verifier imports production code', () => {
    for (const f of ['scripts/protocol/verify-delegation-vectors.js', 'scripts/protocol/verify_delegation_vectors.py']) {
      const src = fs.readFileSync(path.join(REPO, f), 'utf8');
      expect(src).not.toMatch(/require\(['"][^'"]*\/(src|services)\//);
      expect(src).not.toMatch(/^\s*(from|import)\s+(src|services)/m);
    }
  });
});
