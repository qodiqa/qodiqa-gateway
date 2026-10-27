'use strict';

/**
 * public/js/console.js — Studio model-input hint architecture.
 *
 * built the canonical server-side configurable default-model mechanism
 * (services/providers/config.js's resolveDefaultModel() and the
 * PROVIDER_DEFAULT_MODEL_<NAME> env var family). During's repository
 * search, console.js's Studio tool turned out to have a second, independent
 * `PROVIDER_DEFAULT_MODEL` constant — a purely client-side pre-fill hint for
 * the #studio-model input, never read by any server code.'s decision
 * (documented in the register and in a comment block directly at the
 * constant's definition) was to keep it deliberately independent — the
 * alternative (a new unauthenticated config-exposure endpoint just to
 * eliminate one harmless hint) was judged disproportionate — but rename it
 * away from its original name (which too closely echoed the real
 * PROVIDER_DEFAULT_MODEL_<NAME> mechanism) to STUDIO_MODEL_HINTS, and add an
 * explicit disambiguating comment.
 *
 * This suite proves that decision holds by static inspection of
 * public/js/console.js's source text — the same technique already
 * established by for verifying this
 * same file's content without a browser/jsdom harness.
 */

const fs   = require('fs');
const path = require('path');

const CONSOLE_JS_PATH   = path.join(__dirname, '../../public/js/console.js');
const CONSOLE_HTML_PATH = path.join(__dirname, '../../public/console.html');
const consoleJs   = fs.readFileSync(CONSOLE_JS_PATH, 'utf8');
const consoleHtml = fs.readFileSync(CONSOLE_HTML_PATH, 'utf8');

describe('console.js Studio model hint', () => {
  test('the renamed constant STUDIO_MODEL_HINTS exists', () => {
    expect(consoleJs).toMatch(/const\s+STUDIO_MODEL_HINTS\s*=\s*\{/);
  });

  test('the old, misleading name is gone — no bare PROVIDER_DEFAULT_MODEL constant remains', () => {
    // Matches only a `const PROVIDER_DEFAULT_MODEL =` declaration (the
    // client-side object this item renamed) — not any occurrence of the
    // unrelated server-side PROVIDER_DEFAULT_MODEL_<NAME> env var family
    // text, which this file never references at all (confirmed by the
    // "never referenced by any server file" test below covering the real
    // mechanism, and this file has no reason to mention env var names).
    expect(consoleJs).not.toMatch(/const\s+PROVIDER_DEFAULT_MODEL\s*=/);
  });

  test('the comment block at the definition explicitly disclaims server authority', () => {
    // Every phrase Option B's contract requires the comment to state,
    // verified present verbatim (not paraphrased) so a future edit cannot
    // silently drop one while keeping others.
    expect(consoleJs).toContain('CLIENT-SIDE COSMETIC PRE-FILL ONLY');
    expect(consoleJs).toContain('is NOT, the server\'s');
    expect(consoleJs).toContain('resolveDefaultModel()');
    expect(consoleJs).toContain('may differ from "qwen2.5:7b"');
    expect(consoleJs).toContain('always freely editable and');
    expect(consoleJs).toContain('clearable');
    expect(consoleJs).toContain('intentionally NOT reunified with the server value');
  });

  test('the hint never forces a value into the request — an empty field omits `model` entirely', () => {
    // Same line runStudio() has always used: the server's own
    // resolveDefaultModel() applies exactly as it would for any other
    // client whenever this field is left blank.
    expect(consoleJs).toMatch(/const\s+requestBody\s*=\s*model\s*\?\s*\{\s*prompt,\s*model\s*\}\s*:\s*\{\s*prompt\s*\}/);
  });

  test('the #studio-model input element is a plain, freely-editable text input', () => {
    // Defined in public/console.html, not console.js. Extract just the one
    // <input id="studio-model" ...> tag and assert it carries neither
    // readonly nor disabled — the pre-fill logic in console.js only ever
    // sets `.value`, it never locks the field.
    const tagMatch = consoleHtml.match(/<input[^>]*\bid="studio-model"[^>]*>/);
    expect(tagMatch).not.toBeNull();
    const tag = tagMatch[0];
    expect(tag).not.toMatch(/\breadonly\b/i);
    expect(tag).not.toMatch(/\bdisabled\b/i);
    expect(tag).toMatch(/type="text"/);
  });

  test('the real console.js is well-formed JavaScript (sanity check the edit did not break syntax)', () => {
    expect(() => new Function(consoleJs.replace(/^#!.*/, ''))).not.toThrow();
  });
});

// ── STUDIO_MODEL_HINTS server-side-reference check ─────────────────────
//
// The check below necessarily mentions "STUDIO_MODEL_HINTS" as its own test
// subject, so a plain `git grep -l STUDIO_MODEL_HINTS -- scripts` always
// matches THIS FILE too, once it is git-tracked ('s own root cause: the
// original version of this test passed only while this file was still
// untracked — `git grep` searches tracked files by default — and started
// failing, self-referentially, the moment's commit tracked it).
//
// Fix: search the SAME scope as before (nothing narrowed — every intended
// server-side location is still scanned) and filter out only this exact
// file's own repo-relative path from the result, computed from `__filename`
// rather than hardcoded, so a future rename of this file can't silently
// reintroduce the bug by making the filter target stale.
//
// _filterSelfMatch is exercised directly (not just through the real git
// invocation) so a negative control is possible without mutating git state:
// it proves the filter removes ONLY the exact self-path, never a genuine
// second match — i.e. a real future reference to STUDIO_MODEL_HINTS in
// server-side code would still fail this test.

function _filterSelfMatch(rawGitGrepOutput, selfPath) {
  return rawGitGrepOutput
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && line !== selfPath);
}

function _findServerSideReferences(repoRoot, term, selfPath) {
  const { execFileSync } = require('child_process');
  let raw = '';
  try {
    raw = execFileSync(
      'git',
      ['grep', '-l', term, '--', 'src', 'services', 'scripts', 'middleware'],
      { cwd: repoRoot, encoding: 'utf8' },
    );
  } catch (err) {
    // git grep exits 1 when there are no matches — that is the passing case.
    if (err.status !== 1) throw err;
    raw = '';
  }
  return _filterSelfMatch(raw, selfPath);
}

describe('STUDIO_MODEL_HINTS server-side-reference check', () => {
  const REPO_ROOT = path.join(__dirname, '../..');
  // Repo-relative, forward-slash path — matches git grep's own output format
  // on every platform (including Windows/Git Bash, where path.sep is '\\').
  const SELF_PATH = path.relative(REPO_ROOT, __filename).split(path.sep).join('/');

  test('the computed self-path is genuinely this file (sanity check the exclusion target is correct)', () => {
    expect(SELF_PATH).toBe('scripts/__tests__/consoleStudioModelHint.test.js');
  });

  test('STUDIO_MODEL_HINTS is never referenced by any server-side source file', () => {
    const refs = _findServerSideReferences(REPO_ROOT, 'STUDIO_MODEL_HINTS', SELF_PATH);
    expect(refs).toEqual([]);
  });

  test('negative control: a genuine additional match survives the self-match filter, not silently swallowed', () => {
    // Simulates exactly what real `git grep` output would look like if a
    // server-side file actually referenced STUDIO_MODEL_HINTS — proves the
    // fix only ever ignores this exact file, so a real future violation
    // would still fail the test above.
    const raw = `${SELF_PATH}\nsrc/api/routes/aiChat.js\n`;
    expect(_filterSelfMatch(raw, SELF_PATH)).toEqual(['src/api/routes/aiChat.js']);
  });

  test('when this file is the only match (the real, expected state), the filtered result is empty', () => {
    const raw = `${SELF_PATH}\n`;
    expect(_filterSelfMatch(raw, SELF_PATH)).toEqual([]);
  });

  test('an empty git-grep result (no matches at all) passes through unchanged', () => {
    expect(_filterSelfMatch('', SELF_PATH)).toEqual([]);
  });

  test('a match at a different path is never mistaken for the self-match', () => {
    const raw = 'scripts/__tests__/someOtherFile.test.js\n';
    expect(_filterSelfMatch(raw, SELF_PATH)).toEqual(['scripts/__tests__/someOtherFile.test.js']);
  });
});
