#!/usr/bin/env node
'use strict';

/**
 * SDK ↔ OpenAPI contract check (static; part of the CI drift job).
 *
 * Extracts every HTTP call the two maintained SDKs make — method, path template, and whether the call sends the
 * operator (ops) credential — directly from their source, and checks each one against the committed contract
 * (docs/api/openapi.json):
 *   SC-1  the (method, path) is a documented operation;
 *   SC-2  a call to an operation whose documented security requires BearerAuth sends the ops credential, and a call
 *         that sends the ops credential targets an operation that documents BearerAuth (no silent auth drift);
 *   SC-3  the JavaScript and Python SDKs call the same set of operations (parity), apart from the reviewed
 *         SDK_PARITY_EXCEPTIONS list;
 * SC-4 every query parameter the operation documents as REQUIRED is sent by the calling method
 *         (its name appears in the method's query object — JS `query: { … name … }`, Python `"name"` in params). The
 *         per-id webhook calls of both SDKs never sent the required `tenantId`, so every one of them was a guaranteed
 *         400 against a real gateway while this check passed.
 * Operations no SDK calls are reported (coverage), never failed.
 *
 * Extraction is source-level by design: the SDKs are thin wrappers whose every request is one line of the form
 *   JS:  this.http.<get|post|put|patch|delete>(<'path' | `path`>, …)    (auth: this.auth.getAuthHeader() in the same method)
 * this.http.stream({ method: 'POST', path: '/ai/chat', … })
 *   PY:  self._http.<get|post|…>(<"path" | f"path">, …)                 (auth: self._auth.get_auth_header() in the same def)
 *        self._http.stream("POST", "/ai/chat", …)
 * and an unparseable call site is itself a failure (the check can never silently skip a call).
 *
 *   node scripts/contract/sdk-openapi-check.js [--json <out>]      exit 1 on any SC-1/SC-2/SC-3 violation
 */

const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');
const CONTRACT = path.join(REPO, 'docs', 'api', 'openapi.json');
const METHODS = ['get', 'post', 'put', 'patch', 'delete'];

// Reviewed parity differences between the two SDKs (method path → reason). Additions are a review decision.
const SDK_PARITY_EXCEPTIONS = {
  'get /v1/attestation/{attestationId}/export': 'JS-only attestation.export(); not in the Python SDK',
};

// the generated operation layer builds its calls from the descriptor table, not from one-line source call sites. It is held to the contract by a stronger check:
// scripts/sdk/generate-operations.js --check (the tables equal what the contract generates) and the operations tests (every operation of the contract is called and its verb, URL and credential asserted).
const GENERATED_LAYER = new Set(['operations.ts', '_operations.py']);

function walk(dir, ext, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!['node_modules', 'dist', '__pycache__', 'tests', '_verification', 'verification'].includes(e.name)) walk(p, ext, out); }
    else if (e.name.endsWith(ext) && !GENERATED_LAYER.has(e.name)) out.push(p);
  }
  return out;
}

/** Split a source file into method/def bodies so auth can be attributed to the call's own function. */
function blocks(src, lang) {
  const lines = src.split(/\r?\n/);
  const out = []; let cur = null;
  const start = lang === 'js' ? /^\s{2}(?:async\s+)?(?:\*\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(/ : /^\s{4}(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/;
  lines.forEach((l, i) => {
    const m = l.match(start);
    if (m && !/^\s*(if|for|while|switch|return|catch)\b/.test(l.trim())) { if (cur) out.push(cur); cur = { name: m[1], line: i + 1, text: '' }; }
    if (cur) cur.text += `${l}\n`;
  });
  if (cur) out.push(cur);
  return out;
}

function toTemplate(raw, lang) {
  let p = raw;
  if (lang === 'js') p = p.replace(/\$\{\s*encodeURIComponent\(\s*([A-Za-z0-9_.]+)\s*\)\s*\}/g, '{$1}').replace(/\$\{\s*([A-Za-z0-9_.]+)\s*\}/g, '{$1}');
  else p = p.replace(/\{\s*_seg\(\s*([A-Za-z0-9_]+)\s*\)\s*\}/g, '{$1}').replace(/\{\s*([A-Za-z0-9_]+)\s*\}/g, '{$1}');
  return p.split('?')[0];
}

function extract(lang) {
  // QODIQA_SDK_ROOT (tests / negative controls only): check an alternative checkout of sdk/ instead of the working tree
  const sdkRoot = process.env.QODIQA_SDK_ROOT || path.join(REPO, 'sdk');
  const root = lang === 'js' ? path.join(sdkRoot, 'javascript', 'src') : path.join(sdkRoot, 'python', 'qodiqa');
  const files = walk(root, lang === 'js' ? '.ts' : '.py');
  const calls = []; const unparsed = [];
  const callRe = lang === 'js'
    ? /this\.http\.(get|post|put|patch|delete)\s*(?:<[\s\S]*?>)?\s*\(\s*(['`])([^'`]*)\2/g
    : /self\._http\.(get|post|put|patch|delete)\s*\(\s*f?"([^"]*)"/g;
  const streamRe = lang === 'js'
    ? /this\.http\.stream\s*\(\s*\{\s*method:\s*'(GET|POST|PUT|PATCH|DELETE)',\s*path:\s*(['`])([^'`]*)\2/g
    : /self\._http\.stream\s*\(\s*"(GET|POST|PUT|PATCH|DELETE)",\s*f?"([^"]*)"/g;
  const anyCall = lang === 'js' ? /this\.http\.(get|post|put|patch|delete|stream)\b/g : /self\._http\.(get|post|put|patch|delete|stream)\b/g;
  for (const f of files) {
    const src = fs.readFileSync(f, 'utf8');
    for (const b of blocks(src, lang)) {
      const found = [...b.text.matchAll(callRe), ...[...b.text.matchAll(streamRe)].map((m) => [m[0], m[1].toLowerCase(), ...m.slice(2)])];
      const total = (b.text.match(anyCall) || []).length;
      if (found.length !== total) unparsed.push(`${path.relative(REPO, f)}:${b.line} ${b.name}: ${total - found.length} call(s) not in the canonical form`);
      const auth = lang === 'js' ? /this\.auth\.getAuthHeader\(\)/.test(b.text) : /self\._auth\.get_auth_header\(\)/.test(b.text);
      for (const m of found) {
        const method = m[1]; const raw = lang === 'js' ? m[3] : m[2];
        calls.push({ lang, file: path.relative(REPO, f).split(path.sep).join('/'), fn: b.name, method, path: toTemplate(raw, lang), opsAuth: auth, body: b.text });
      }
    }
  }
  return { calls, unparsed };
}

function matchOp(doc, method, tpl) {
  // match by shape: every {x} in either template matches one segment
  const norm = (p) => p.replace(/\{[^}]+\}/g, '{}');
  for (const [p, item] of Object.entries(doc.paths)) if (item[method] && norm(p) === norm(tpl)) return { path: p, op: item[method] };
  return null;
}

/** Names of the query parameters an operation documents as required ($ref parameters resolved). */
function requiredQuery(doc, op) {
  return (op.parameters || []).map((x) => (x.$ref ? doc.components.parameters[x.$ref.split('/').pop()] : x))
    .filter((x) => x && x.in === 'query' && x.required === true).map((x) => x.name);
}

function run() {
  const doc = JSON.parse(fs.readFileSync(CONTRACT, 'utf8'));
  const js = extract('js'); const py = extract('python');
  const violations = [...js.unparsed.map((u) => `UNPARSED (js) ${u}`), ...py.unparsed.map((u) => `UNPARSED (python) ${u}`)];
  const opsCalled = { js: new Set(), python: new Set() };
  for (const c of [...js.calls, ...py.calls]) {
    const hit = matchOp(doc, c.method, c.path);
    const where = `${c.lang} ${c.file} ${c.fn}()`;
    if (!hit) { violations.push(`SC-1 ${where}: ${c.method.toUpperCase()} ${c.path} is not a documented operation`); continue; }
    c.operation = `${c.method} ${hit.path}`;
    opsCalled[c.lang].add(c.operation);
    const sec = hit.op.security === undefined ? doc.security : hit.op.security;
    // API-11: an ops operation now lists the ops credential's two accepted carriers (BearerAuth, OpsTokenHeader) as
    // alternatives; either is the SAME credential, so a requirement made only of those still REQUIRES it, and an
    // anonymous alternative ({}) makes it optional (the health probes).
    const isOps = (s) => { const k = Object.keys(s); return k.length > 0 && k.every((n) => n === 'BearerAuth' || n === 'OpsTokenHeader'); };
    const needsBearer = Array.isArray(sec) && sec.length > 0 && sec.every(isOps);
    const allowsBearer = Array.isArray(sec) && sec.some((s) => Object.prototype.hasOwnProperty.call(s, 'BearerAuth'));
    if (needsBearer && !c.opsAuth) violations.push(`SC-2 ${where}: ${c.operation} requires BearerAuth but the SDK sends no ops credential`);
    if (c.opsAuth && !allowsBearer) violations.push(`SC-2 ${where}: sends the ops credential but ${c.operation} documents no BearerAuth`);
    for (const name of requiredQuery(doc, hit.op)) {
      const sent = c.lang === 'js' ? new RegExp(`query[\\s\\S]*?\\b${name}\\b`).test(c.body) : new RegExp(`["']${name}["']`).test(c.body);
      if (!sent) violations.push(`SC-4 ${where}: ${c.operation} requires the query parameter "${name}" but the SDK method never sends it`);
    }
  }
  const onlyJs = [...opsCalled.js].filter((o) => !opsCalled.python.has(o));
  const onlyPy = [...opsCalled.python].filter((o) => !opsCalled.js.has(o));
  for (const o of [...onlyJs, ...onlyPy]) if (!SDK_PARITY_EXCEPTIONS[o]) violations.push(`SC-3 parity: ${o} is called by ${onlyJs.includes(o) ? 'JavaScript' : 'Python'} only`);
  for (const o of Object.keys(SDK_PARITY_EXCEPTIONS)) if (!onlyJs.includes(o) && !onlyPy.includes(o)) violations.push(`SC-3 stale parity exception: ${o} (no longer a one-sided call)`);
  const allOps = Object.entries(doc.paths).flatMap(([p, item]) => METHODS.filter((m) => item[m]).map((m) => `${m} ${p}`));
  const covered = new Set([...opsCalled.js, ...opsCalled.python]);
  return { ok: violations.length === 0, violations, counts: { jsCalls: js.calls.length, pyCalls: py.calls.length, jsOperations: opsCalled.js.size, pyOperations: opsCalled.python.size, contractOperations: allOps.length },
    parityExceptions: SDK_PARITY_EXCEPTIONS, uncoveredOperations: allOps.filter((o) => !covered.has(o)).length, calls: [...js.calls, ...py.calls].map(({ body, ...c }) => c) };
}

if (require.main === module) {
  const r = run();
  const i = process.argv.indexOf('--json');
  if (i > 0) { fs.mkdirSync(path.dirname(path.resolve(process.argv[i + 1])), { recursive: true }); fs.writeFileSync(process.argv[i + 1], JSON.stringify(r, null, 1)); }
  process.stdout.write(`${JSON.stringify({ ok: r.ok, counts: r.counts, uncoveredOperations: r.uncoveredOperations, violations: r.violations }, null, 2)}\n`);
  process.exit(r.ok ? 0 : 1);
}
module.exports = { run, extract, SDK_PARITY_EXCEPTIONS };
