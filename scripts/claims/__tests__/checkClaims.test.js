'use strict';

/**
 * the claims checker. Positive: the real registry passes. Negative (each on a throw-away repository tree): a forbidden phrase, a PROVEN
 * claim without test/run evidence, deleted evidence, a stale generated page, a missing caveat, a reference to a retracted claim.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { checkClaims, render } = require('../check-claims');

function writeRegistry(root, registry) {
  const reg = { forbiddenGlobal: [], publicFiles: ['README.md', 'claims/CLAIMS.generated.md'], ...registry };
  fs.mkdirSync(path.join(root, 'claims'), { recursive: true });
  fs.writeFileSync(path.join(root, 'claims', 'claims.json'), JSON.stringify(reg));
  fs.writeFileSync(path.join(root, 'claims', 'CLAIMS.generated.md'), render(reg));
}

function tree(registry, files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-claims-'));
  writeRegistry(root, registry);
  fs.writeFileSync(path.join(root, 'README.md'), '# Readme\n');
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src', 'a.js'), 'const x = "marker";\n');
  fs.writeFileSync(path.join(root, 'src', 'a.test.js'), 'test("marker", () => {});\n');
  for (const [f, c] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true });
    fs.writeFileSync(path.join(root, f), c);
  }
  return root;
}

const good = (over = {}) => ({
  id: 'C-001', claim: 'It works.', scope: 'README', status: 'PROVEN', caveat: null, matrix: [],
  evidence: [{ type: 'code', path: 'src/a.js', regex: 'marker' }, { type: 'test', path: 'src/a.test.js', regex: 'marker' }], ...over,
});

describe('claims registry', () => {
  test('F3-CL-00 the real registry passes', () => {
    const r = checkClaims();
    expect(r.errors).toEqual([]);
    expect(r.count).toBeGreaterThanOrEqual(10);
  });

  test('F3-CL-01 a clean synthetic registry passes', () => {
    expect(checkClaims({ root: tree({ claims: [good()] }) }).errors).toEqual([]);
  });

  test('F3-CL-02 a forbidden phrase in a public file fails; the same phrase with a negation passes', () => {
    const reg = { claims: [good({ id: 'C-002', status: 'NOT-DELIVERED', caveat: 'Not delivered.', forbiddenIfNot: ['SOC 2 compliant'], evidence: [] })] };
    const root = tree(reg, { 'README.md': 'QODIQA is SOC 2 compliant.\n' });
    expect(checkClaims({ root }).errors.join('\n')).toMatch(/forbidden phrase "SOC 2 compliant"/);
    fs.writeFileSync(path.join(root, 'README.md'), 'QODIQA is not SOC 2 compliant.\n');
    expect(checkClaims({ root }).errors).toEqual([]);
  });

  test('F3-CL-03 a global forbidden phrase fails', () => {
    const root = tree({ claims: [good()], forbiddenGlobal: ['production-ready'] }, { 'README.md': 'Fully production-ready.\n' });
    expect(checkClaims({ root }).errors.join('\n')).toMatch(/production-ready/);
  });

  test('F3-CL-04 PROVEN without a test or run evidence fails; without code evidence fails', () => {
    const noTest = tree({ claims: [good({ evidence: [{ type: 'code', path: 'src/a.js', regex: 'marker' }] })] });
    expect(checkClaims({ root: noTest }).errors.join('\n')).toMatch(/needs a test, run or cmd evidence/);
    const noCode = tree({ claims: [good({ evidence: [{ type: 'test', path: 'src/a.test.js', regex: 'marker' }] })] });
    expect(checkClaims({ root: noCode }).errors.join('\n')).toMatch(/needs at least one code evidence/);
  });

  test('F3-CL-05 evidence that disappears or no longer matches fails', () => {
    const root = tree({ claims: [good()] });
    fs.unlinkSync(path.join(root, 'src', 'a.js'));
    expect(checkClaims({ root }).errors.join('\n')).toMatch(/evidence path missing: src\/a.js/);
    const root2 = tree({ claims: [good({ evidence: [{ type: 'code', path: 'src/a.js', regex: 'does-not-occur' }, { type: 'test', path: 'src/a.test.js', regex: 'marker' }] })] });
    expect(checkClaims({ root: root2 }).errors.join('\n')).toMatch(/does not match/);
  });

  test('F3-CL-06 a stale generated page fails', () => {
    const root = tree({ claims: [good()] });
    fs.appendFileSync(path.join(root, 'claims', 'CLAIMS.generated.md'), 'hand edit\n');
    expect(checkClaims({ root }).errors.join('\n')).toMatch(/CLAIMS.generated.md is stale/);
  });

  test('F3-CL-07 a claim reference needs its caveat in the same paragraph; an unknown or retracted claim cannot be referenced', () => {
    const reg = { claims: [good({ status: 'PROVEN-CAVEAT', caveat: 'Only on one machine.' }), good({ id: 'C-009', status: 'RETRACTED', caveat: 'Retracted.', evidence: [] })] };
    const root = tree(reg, { 'README.md': 'Fast. claim:C-001\n' });
    expect(checkClaims({ root }).errors.join('\n')).toMatch(/requires its caveat/);
    fs.writeFileSync(path.join(root, 'README.md'), 'Fast. claim:C-001 Only on one machine.\n');
    expect(checkClaims({ root }).errors).toEqual([]);
    fs.writeFileSync(path.join(root, 'README.md'), 'Old figure. claim:C-009\n');
    expect(checkClaims({ root }).errors.join('\n')).toMatch(/cannot be asserted/);
    fs.writeFileSync(path.join(root, 'README.md'), 'Mystery. claim:C-777\n');
    expect(checkClaims({ root }).errors.join('\n')).toMatch(/unknown claim C-777/);
  });

  test('F3-CL-08 a caveat-requiring status without a caveat fails; duplicate ids and unknown statuses fail', () => {
    const root = tree({ claims: [good({ status: 'SIMULATED', caveat: null }), good({ status: 'MAYBE' })] });
    const e = checkClaims({ root }).errors.join('\n');
    expect(e).toMatch(/requires a caveat/);
    expect(e).toMatch(/duplicate id/);
    expect(e).toMatch(/unknown status MAYBE/);
  });
});
