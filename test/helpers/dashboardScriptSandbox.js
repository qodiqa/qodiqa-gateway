'use strict';

/**
 * Executes the REAL script of a public/*.html dashboard page inside a Node
 * `vm` context, so XSS-regression tests call the production rendering code
 * verbatim — not a reimplementation of it — and fail the instant that code
 * stops escaping something it used to escape.
 *
 * (CSP unsafe-inline removal) moved every dashboard's script out of an
 * inline <script> block into an external public/js/<name>.js file, referenced
 * via <script src="/js/<name>.js" defer>. These helpers load that external
 * file directly — the HTML file itself carries no script content anymore.
 *
 * Only usable for dashboard files whose functions are declared at the
 * top level of the script (audit-viewer.html, dashboard.html,
 * policy-management.html). console.html wraps its entire script in a single
 * IIFE, so nothing is reachable off the sandbox context for that file —
 * use extractFunctionSource() (below) for it instead.
 *
 * No external DOM/browser-testing dependency is introduced: the "DOM" here
 * is a minimal auto-vivifying stub, just enough surface for these dashboard
 * scripts' top-level init() calls (document.getElementById, fetch,
 * EventSource, navigator.clipboard) to run without throwing.
 */

const fs   = require('fs');
const path = require('path');
const vm   = require('vm');

const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');
const SCRIPT_DIR = path.join(PUBLIC_DIR, 'js');

/** Extracts a top-level `function NAME(...) { ... }` declaration's exact
 * source text via brace-depth counting (not a full JS parser — sufficient
 * because none of the targeted functions hide braces inside string/regex
 * literals in a way that would unbalance a plain depth count). */
function extractFunctionSource(source, name) {
  const marker = `function ${name}(`;
  const start  = source.indexOf(marker);
  if (start === -1) throw new Error(`extractFunctionSource: "${name}" not found`);
  const braceStart = source.indexOf('{', start);
  let depth = 0;
  let i     = braceStart;
  for (; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}') {
      depth--;
      if (depth === 0) { i++; break; }
    }
  }
  return source.slice(start, i);
}

/** Evaluates one or more extracted function sources together (so a function
 * that calls a sibling helper, e.g. attrJs() calling esc(), has it in
 * scope) and returns the last-named function. */
function evalFunctions(html, names) {
  const sources = names.map(n => extractFunctionSource(html, n)).join('\n\n');
  const factory = new Function(`'use strict';\n${sources}\nreturn { ${names.join(', ')} };`);
  return factory();
}

function readHtml(fileName) {
  return fs.readFileSync(path.join(PUBLIC_DIR, fileName), 'utf8');
}

/** Reads the external public/js/<name>.js file that fileName's (e.g.
 * 'audit-viewer.html') <script src="…" defer> tag points at. */
function readScript(fileName) {
  const scriptName = fileName.replace(/\.html$/, '.js');
  return fs.readFileSync(path.join(SCRIPT_DIR, scriptName), 'utf8');
}

/**
 * dashboard pages now load their shared public/js/common/*.js
 * infrastructure via one or more <script src="/js/common/…"> tags before
 * their own <script src="/js/<name>.js">. Rather than hardcoding which
 * common files each page depends on (liable to drift out of sync), this
 * reads the page's own HTML and returns every local /js/... script src in
 * document order — the exact same order a real browser would execute them
 * in, common files first, the page's own script last.
 */
function readLocalScriptSources(fileName) {
  const html = readHtml(fileName);
  const srcs = [...html.matchAll(/<script\s+src="(\/js\/[^"]+)"/g)].map((m) => m[1]);
  return srcs.map((src) => fs.readFileSync(path.join(PUBLIC_DIR, src), 'utf8'));
}

// ── Auto-vivifying fake DOM element ─────────────────────────────────────────
//
// Reading an unset property returns undefined/a no-op function; writing a
// property just stores it — so `el.innerHTML = x` followed by reading
// `el.innerHTML` round-trips exactly, which is all these tests need.

function makeFakeElement() {
  const store = {};
  return new Proxy(store, {
    get(target, prop) {
      if (prop in target) return target[prop];
      switch (prop) {
        // Real <input> elements default .value to '' and .checked to false —
        // not undefined — so code that unconditionally calls .value.trim()
        // (as several of these dashboards' filter-reading helpers do) works
        // against a freshly-created stub exactly as it would in a browser.
        case 'value':         return '';
        case 'checked':       return false;
        case 'classList':    return { add() {}, remove() {}, toggle() {}, contains() { return false; } };
        case 'style':        return new Proxy({}, { get: () => '', set: () => true });
        case 'dataset':      return {};
        case 'addEventListener': case 'removeEventListener':
        case 'appendChild':  case 'removeChild': case 'remove':
        case 'focus':        case 'select':      case 'click':
        case 'scrollIntoView': case 'setAttribute': case 'removeAttribute':
          return () => {};
        case 'getAttribute': return () => null;
        case 'querySelector':     return () => makeFakeElement();
        case 'querySelectorAll':  return () => [];
        default: return undefined;
      }
    },
    set(target, prop, value) { target[prop] = value; return true; },
  });
}

class EventSourceStub {
  constructor(url) { this.url = url; this.onopen = null; this.onerror = null; this._listeners = {}; }
  addEventListener(type, cb) { (this._listeners[type] ||= []).push(cb); }
  close() {}
}

/**
 * Loads and executes fileName's inline script in a fresh vm context.
 *
 * @param {string} fileName          e.g. 'audit-viewer.html'
 * @param {object} [opts]
 * @param {Function} [opts.fetchImpl]  (path) => Promise<{ok, status, statusText, json}>
 *   Defaults to an always-ok empty-object response so init()'s background
 *   loads resolve harmlessly instead of rejecting.
 * @returns {{ ctx: object, getElement: (id: string) => any }}
 *   ctx        — the vm context; every top-level function/const of the real
 *                script is a property on it (ctx.esc, ctx.openInvestigationDetail, …)
 *   getElement — fetches the same fake element instance document.getElementById(id)
 *                returned inside the sandbox, so tests can read back .innerHTML etc.
 */
function loadDashboardScript(fileName, opts = {}) {
  // run every local script this page's HTML loads, in document
  // order — the shared public/js/common/*.js files first, then the page's
  // own script — mirroring real <script src> execution order exactly, so
  // e.g. `const esc = window.QodiqaCommon.esc` inside the page's own script
  // resolves against the real, already-loaded shared implementation.
  const scripts = readLocalScriptSources(fileName);

  const elements = new Map();
  function getElementById(id) {
    if (!elements.has(id)) elements.set(id, makeFakeElement());
    return elements.get(id);
  }

  const defaultFetch = async () => ({
    ok: true, status: 200, statusText: 'OK',
    json: async () => ({ data: {} }),
  });
  const fetchImpl = opts.fetchImpl || defaultFetch;

  const documentStub = {
    getElementById,
    createElement:     () => makeFakeElement(),
    querySelector:      () => makeFakeElement(),
    querySelectorAll:   () => [],
    addEventListener:   () => {},
    body:               makeFakeElement(),
  };

  const sandbox = {
    document:  documentStub,
    navigator: { clipboard: { writeText: () => Promise.resolve() } },
    fetch:     (...args) => fetchImpl(...args),
    EventSource: EventSourceStub,
    URLSearchParams,
    encodeURIComponent, decodeURIComponent,
    console,
    setTimeout: () => 0, clearTimeout: () => {},
    setInterval: () => 0, clearInterval: () => {},
    Promise, JSON, Math, Date, Array, Object, String, Number, RegExp, Error, Map, Set,
    alert: () => {}, confirm: () => true,
  };
  sandbox.window   = sandbox;
  sandbox.self     = sandbox;
  sandbox.location = { href: 'https://sandbox.invalid/', search: '', pathname: '/' };

  const ctx = vm.createContext(sandbox);
  scripts.forEach((src, i) => {
    vm.runInContext(src, ctx, { filename: i === scripts.length - 1 ? fileName : `common-script-${i}` });
  });

  return { ctx, getElement: getElementById };
}

module.exports = { loadDashboardScript, extractFunctionSource, evalFunctions, readHtml, readScript, readLocalScriptSources };
