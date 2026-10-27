'use strict';

/**
 * permanent CI guard against the duplicated frontend infrastructure
 * (esc/attrJs/badge/paginate/createClickDispatcher) reappearing across the
 * four admin UIs (public/js/dashboard.js, console.js, audit-viewer.js,
 * policy-management.js) after this consolidation. Runs as a normal Jest test
 * file, so it's picked up automatically by the existing `integration` job's
 * `testPathPatterns="test/"` in .github/workflows/test.yml — no separate
 * workflow or CI wiring needed.
 *
 * Two independent failure modes are guarded against:
 *   1. A page re-declaring one of these helpers locally instead of using
 *      the shared public/js/common/ implementation (AC-1/AC-2).
 *   2. A page's HTML dropping the <script src="/js/common/..."> tag(s) it
 *      depends on, silently breaking that page in the browser even though
 *      its own .js file still parses fine in isolation.
 */

const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');
const JS_DIR = path.join(PUBLIC_DIR, 'js');

// 4 -> 6, adding tenant-login.js/tenant-portal.js — the
// tenant self-service portal's two pages. Both follow the SAME shared-
// helper convention this guard exists to protect (esc() only, via
// public/js/common/esc.js — no local re-declaration, same as console.js).
// approvals.js - the operator page for human approval of agent actions (textContent only; it uses none of the shared helpers).
const PAGE_JS_FILES = ['dashboard.js', 'console.js', 'audit-viewer.js', 'policy-management.js', 'tenant-login.js', 'tenant-portal.js', 'approvals.js'];

// Which shared common/*.js scripts each page's HTML must reference. Mirrors
// what each page's .js file actually destructures off window.QodiqaCommon —
// see the "shared infrastructure" comment at the top of each file.
const PAGE_HTML_DEPENDENCIES = {
  'dashboard.html':          ['/js/common/esc.js', '/js/common/pagination.js', '/js/common/actions.js'],
  'audit-viewer.html':       ['/js/common/esc.js', '/js/common/pagination.js', '/js/common/badges.js', '/js/common/actions.js'],
  'policy-management.html':  ['/js/common/esc.js', '/js/common/pagination.js', '/js/common/badges.js', '/js/common/actions.js'],
  'console.html':            ['/js/common/esc.js'],
  // tenant-login.html loads esc.js but its own tenant-login.js does
  // not currently call esc() (it only uses textContent) — still loaded for
  // forward-compatibility and consistency with every other page here, so
  // it is listed as a page dependency (script tag presence), not asserted
  // as an actual esc() call site the way the other pages' guard above does.
  'tenant-login.html':       ['/js/common/esc.js'],
  'tenant-portal.html':      ['/js/common/esc.js'],
};

// Symbols that must be declared in exactly one place: public/js/common/.
// The regexes intentionally match a `function NAME(` declaration only (not
// a call site like `esc(x)` or a destructure like `window.QodiqaCommon.esc`),
// so re-adding a local re-implementation is what trips this guard.
const GUARDED_DECLARATIONS = [
  { name: 'esc', pattern: /function\s+esc\s*\(/ },
  { name: 'attrJs', pattern: /function\s+attrJs\s*\(/ },
  { name: 'paginate', pattern: /function\s+paginate\s*\(/ },
  { name: 'badge', pattern: /function\s+badge\s*\(/ },
  { name: 'createClickDispatcher', pattern: /function\s+createClickDispatcher\s*\(/ },
];

function readPageJs(fileName) {
  return fs.readFileSync(path.join(JS_DIR, fileName), 'utf8');
}

function readPublicHtml(fileName) {
  return fs.readFileSync(path.join(PUBLIC_DIR, fileName), 'utf8');
}

describe('permanent guard: no duplicated shared-helper declarations', () => {
  test.each(PAGE_JS_FILES)('public/js/%s declares none of the shared helpers locally', (fileName) => {
    const src = readPageJs(fileName);
    const offenders = GUARDED_DECLARATIONS.filter((d) => d.pattern.test(src)).map((d) => d.name);
    expect(offenders).toEqual([]);
  });

  test('exactly one implementation of each shared helper exists, in public/js/common/', () => {
    // readdirSync on public/js is non-recursive, so it lists only the four
    // page files — public/js/common/*.js (where these declarations legitimately
    // live) is a subdirectory and is correctly excluded from this scan.
    const topLevelJsFiles = fs.readdirSync(JS_DIR).filter((f) => f.endsWith('.js'));
    expect(topLevelJsFiles.sort()).toEqual([...PAGE_JS_FILES].sort());

    GUARDED_DECLARATIONS.forEach(({ name, pattern }) => {
      const declaringFiles = topLevelJsFiles.filter((f) => pattern.test(readPageJs(f)));
      expect(declaringFiles).toEqual([]);
    });
  });

  test('public/js/common exports every guarded helper exactly once', () => {
    const common = require('../../public/js/common');
    GUARDED_DECLARATIONS.forEach(({ name }) => {
      expect(typeof common[name]).toBe('function');
    });
  });
});

describe('permanent guard: every admin page still loads the shared scripts it depends on', () => {
  test.each(Object.entries(PAGE_HTML_DEPENDENCIES))('%s references its required common script(s)', (fileName, deps) => {
    const html = readPublicHtml(fileName);
    deps.forEach((dep) => {
      expect(html).toContain(`src="${dep}"`);
    });
  });

  test.each(Object.entries(PAGE_HTML_DEPENDENCIES))('%s loads common scripts before its own page script', (fileName, deps) => {
    const html = readPublicHtml(fileName);
    const ownScript = `/js/${fileName.replace(/\.html$/, '.js')}`;
    const ownScriptIndex = html.indexOf(`src="${ownScript}"`);
    expect(ownScriptIndex).toBeGreaterThan(-1);
    deps.forEach((dep) => {
      const depIndex = html.indexOf(`src="${dep}"`);
      expect(depIndex).toBeGreaterThan(-1);
      expect(depIndex).toBeLessThan(ownScriptIndex);
    });
  });
});
