'use strict';

/**
 * doc-drift-check.js when the base commit is missing (history replaced by a force push, a shallow checkout, a first push):
 *   DDM-01 an unknown GITHUB_BEFORE does not fail the check; the cross-file comparison is skipped and the markers are checked
 *   DDM-02 the marker check still runs over every mapped document in that case (a missing marker fails)
 *   DDM-03 an unknown --base behaves the same
 *   DDM-04 a base that exists is still compared
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');

const SCRIPTS = path.join(__dirname, '..');
const MISSING = 'a'.repeat(40);

let dir; let head; let parent; let docs;

const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
function run(extraEnv = {}, args = []) {
  const env = { ...process.env, ...extraEnv };
  for (const k of Object.keys(env)) if (k.startsWith('GITHUB_') && !(k in extraEnv)) delete env[k];
  return spawnSync(process.execPath, [path.join(dir, 'scripts', 'doc-drift-check.js'), ...args], { cwd: dir, env, encoding: 'utf8' });
}

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-drift-'));
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  for (const f of ['doc-drift-check.js', 'doc-drift-map.js']) fs.copyFileSync(path.join(SCRIPTS, f), path.join(dir, 'scripts', f));
  docs = [...new Set(require(path.join(dir, 'scripts', 'doc-drift-map.js')).map((m) => m.docFile))];
  const writeDocs = (stamp) => {
    for (const d of docs) { fs.mkdirSync(path.dirname(path.join(dir, d)), { recursive: true }); fs.writeFileSync(path.join(dir, d), `# ${d}\n\nLast verified: 2026-01-01\n${stamp}\n`); }
  };
  git('init', '-q', '-b', 'main');
  git('config', 'user.email', 't@example.invalid'); git('config', 'user.name', 't'); git('config', 'core.autocrlf', 'false');
  writeDocs('one'); git('add', '-A'); git('commit', '-q', '-m', 'one');
  parent = git('rev-parse', 'HEAD');
  writeDocs('two'); git('add', '-A'); git('commit', '-q', '-m', 'two');
  head = git('rev-parse', 'HEAD');
});
afterAll(() => { fs.rmSync(dir, { recursive: true, force: true }); });

describe('doc-drift-check with a missing base commit', () => {
  test('DDM-01 an unknown pre-push SHA falls back to the marker check and passes', () => {
    const r = run({ GITHUB_BEFORE: MISSING, GITHUB_SHA: head });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/is not available in this checkout/);
    expect(r.stdout).toMatch(/PASS: no documentation drift detected/);
    expect(r.stdout).not.toMatch(/comparing /);
  });

  test('DDM-02 the fallback still checks every mapped document: a missing marker fails', () => {
    const victim = docs[0];
    const full = path.join(dir, victim);
    const original = fs.readFileSync(full, 'utf8');
    try {
      fs.writeFileSync(full, '# no marker here\n');
      const r = run({ GITHUB_BEFORE: MISSING, GITHUB_SHA: head });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain(victim);
      expect(r.stderr).toMatch(/missing a "Last verified/);
    } finally { fs.writeFileSync(full, original); }
  });

  test('DDM-03 an unknown --base behaves the same', () => {
    const r = run({}, ['--base', MISSING, '--head', head]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/is not available in this checkout/);
  });

  test('DDM-04 a base that exists is still compared', () => {
    const r = run({ GITHUB_BEFORE: parent, GITHUB_SHA: head });
    expect(r.stdout).toMatch(/comparing /);
    expect(r.stdout).not.toMatch(/is not available/);
  });
});
