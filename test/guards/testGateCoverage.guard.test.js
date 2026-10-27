'use strict';

/**
 * Test-gate discovery coverage guard.
 *
 * Closes the discovery-gap CLASS, not just the specific orphans found
 * during the audit: a test file
 * dropped under a directory neither test:unit's nor test:component's
 * discovery pattern covers currently runs only if invoked manually — never
 * in either baseline gate, which means a real regression it should catch
 * can ship silently. This test fails loudly, listing every offending file
 * by name, instead of letting that happen again unnoticed.
 *
 * Reads test:unit's real, current --testPathPatterns value directly out of
 * package.json rather than a hardcoded copy, so this guard cannot itself
 * drift from the shipped gate config.
 */

const fs   = require('fs');
const path = require('path');

const REPO_ROOT = path.join(__dirname, '..', '..');

// Directories Jest never discovers tests in at all (jest.config.js's own
// testPathIgnorePatterns, mirrored here so this walk matches Jest's real
// universe — not a third, independently-drifting copy of the exclusion
// logic, just the directory names themselves, which change far less often
// than a regex would).
const IGNORED_DIR_NAMES = new Set(['node_modules', 'sdk', 'coverage', '.git', '_quarantine', '.stryker-tmp']);

// Files deliberately excluded from BOTH baseline gates, with the reason —
///§3 for the full audit.
// Keep this list minimal and named-with-reason; it is not a place to quietly
// dump future orphans found by this very guard.
const DELIBERATE_EXCLUSIONS = {
};

function getUnitPattern() {
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
  const script = pkg.scripts['test:unit'];
  const m = script.match(/--testPathPatterns="([^"]+)"/);
  if (!m) {
    throw new Error(
      'Could not extract --testPathPatterns from package.json\'s test:unit script — ' +
      'its format changed; update this guard\'s parsing to match.',
    );
  }
  return new RegExp(m[1]);
}

function walkTestFiles(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (IGNORED_DIR_NAMES.has(entry.name) || entry.name.startsWith('.stryker-tmp')) continue; // ECS: any Stryker tempDirName (matches jest.config.js)
    if (entry.name === 'worktrees' && path.basename(dir) === '.claude') continue; // 2026-10-09: agent worktrees are full checkouts (matches jest.config.js)
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkTestFiles(full, out);
      continue;
    }
    if (/\.(test|spec)\.js$/.test(entry.name)) {
      out.push(path.relative(REPO_ROOT, full).split(path.sep).join('/'));
    }
  }
}

describe('test-gate discovery coverage (Item 4 guard)', () => {
  test('every *.test.js/*.spec.js file is covered by test:unit, test:component, or an explicit exclusion', () => {
    const unitPattern = getUnitPattern();
    const files = [];
    walkTestFiles(REPO_ROOT, files);
    expect(files.length).toBeGreaterThan(400); // sanity: the walk itself found something real

    const orphaned = files.filter((f) => {
      if (unitPattern.test(f)) return false;          // covered by test:unit
      if (f.startsWith('test/')) return false;         // covered by test:component
      if (Object.prototype.hasOwnProperty.call(DELIBERATE_EXCLUSIONS, f)) return false;
      return true;
    });

    if (orphaned.length > 0) {
      throw new Error(
        `${orphaned.length} test file(s) are collected by NEITHER test:unit NOR test:component, ` +
        `and are not in this guard's DELIBERATE_EXCLUSIONS allowlist:\n` +
        orphaned.map((f) => `  - ${f}`).join('\n') +
        `\n\nEither widen test:unit's/test:component's discovery pattern to include them, or add ` +
        `them to DELIBERATE_EXCLUSIONS above with a concrete reason ` +
        `(with the gate-safety checks ` +
        `a new exclusion should get before being accepted).`,
      );
    }
  });

  test('every DELIBERATE_EXCLUSIONS entry still exists on disk (no stale, silently-permissive entries)', () => {
    for (const rel of Object.keys(DELIBERATE_EXCLUSIONS)) {
      expect(fs.existsSync(path.join(REPO_ROOT, rel))).toBe(true);
    }
  });
});
