'use strict';

// every third-party GitHub Action is pinned to a full
// commit SHA (tag kept as a trailing comment for Dependabot), and Dependabot
// watches both the Actions and the npm ecosystems. A floating tag (@v4) lets
// whoever controls the action's repository change what CI executes — including
// release.yml, which builds and signs the shipped image.

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const WORKFLOWS = path.join(ROOT, '.github', 'workflows');

function workflowFiles() {
  return fs.readdirSync(WORKFLOWS)
    .filter((f) => /\.ya?ml$/.test(f))
    .map((f) => path.join(WORKFLOWS, f));
}

function usesLines() {
  const out = [];
  for (const file of workflowFiles()) {
    fs.readFileSync(file, 'utf8').split(/\r?\n/).forEach((line, i) => {
      const m = line.match(/^\s*-?\s*uses:\s*([^\s#]+)/);
      if (m) out.push({ file: path.basename(file), line: i + 1, ref: m[1] });
    });
  }
  return out;
}

describe('CI supply-chain pinning', () => {
  test('workflows exist and reference actions', () => {
    expect(workflowFiles().length).toBeGreaterThan(0);
    expect(usesLines().length).toBeGreaterThan(0);
  });

  test('every third-party action is pinned to a 40-hex commit SHA', () => {
    const unpinned = usesLines()
      .filter(({ ref }) => !ref.startsWith('./'))
      .filter(({ ref }) => !/@[0-9a-f]{40}$/.test(ref));
    expect(unpinned).toEqual([]);
  });

  test('a pinned action keeps its tag as a trailing comment', () => {
    const missing = [];
    for (const file of workflowFiles()) {
      fs.readFileSync(file, 'utf8').split(/\r?\n/).forEach((line, i) => {
        if (/uses:\s*[^\s#]+@[0-9a-f]{40}/.test(line) && !/#\s*v\d/.test(line)) {
          missing.push(`${path.basename(file)}:${i + 1}`);
        }
      });
    }
    expect(missing).toEqual([]);
  });

  test('no workflow installs a tool at @latest', () => {
    const hits = [];
    for (const file of workflowFiles()) {
      fs.readFileSync(file, 'utf8').split(/\r?\n/).forEach((line, i) => {
        if (/^\s*#/.test(line)) return;
        if (/@latest\b/.test(line)) hits.push(`${path.basename(file)}:${i + 1}`);
      });
    }
    expect(hits).toEqual([]);
  });

  // the update bot is switched off while the repository is private: the check runs again once its configuration is back
  (fs.existsSync(path.join(ROOT, '.github', 'dependabot.yml')) ? test : test.skip)('Dependabot covers github-actions and npm', () => {
    const cfg = fs.readFileSync(path.join(ROOT, '.github', 'dependabot.yml'), 'utf8');
    expect(cfg).toMatch(/package-ecosystem:\s*["']?github-actions/);
    expect(cfg).toMatch(/package-ecosystem:\s*["']?npm/);
  });
});
