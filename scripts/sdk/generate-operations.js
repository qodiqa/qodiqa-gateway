#!/usr/bin/env node
'use strict';

/**
 * generates the operation-complete clients of the TypeScript and Python SDKs from docs/api/openapi.json (the contract), so that every documented operation is callable and
 * the SDKs cannot drift from it:
 *
 *   sdk/javascript/src/generated/operations.ts   descriptor table + typed `OperationMethods` interface (client.operations.<operationId>(...))
 *   sdk/python/qodiqa/_operations_data.py        descriptor table (client.operations.<operation_id>(...), snake_case; dynamic dispatch in qodiqa/_operations.py)
 *   sdk/go/operations.json, sdk/java/src/main/resources/dev/qodiqa/sdk/operations.json   the same descriptors as JSON (embedded / loaded by the Go and Java SDKs)
 *
 *   node scripts/sdk/generate-operations.js          write
 *   node scripts/sdk/generate-operations.js --check  exit 1 when a generated file differs from what the contract produces (npm run sdk:check)
 *
 * A descriptor says how to call the operation: method, path template, path/query/header parameter names, request body kind, response kind and which credential it takes (`ops` = operator
 * key, `sign` = signing key, `none`, `optional` = operator key when present). Request and response bodies are NOT typed per operation in this version (the hand-written resources
 * type the main flows); the generated layer guarantees coverage, correct URLs/verbs/credentials and required-parameter checks.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const REPO = path.join(__dirname, '..', '..');
const SPEC = path.join(REPO, 'docs', 'api', 'openapi.json');
const TS_OUT = path.join(REPO, 'sdk', 'javascript', 'src', 'generated', 'operations.ts');
const PY_OUT = path.join(REPO, 'sdk', 'python', 'qodiqa', '_operations_data.py');
const GO_OUT = path.join(REPO, 'sdk', 'go', 'operations.json');
const JAVA_OUT = path.join(REPO, 'sdk', 'java', 'src', 'main', 'resources', 'dev', 'qodiqa', 'sdk', 'operations.json');
const HTTP = ['get', 'post', 'put', 'patch', 'delete'];
// shared protocol vectors, copied byte-for-byte so that the Go and Java modules test themselves without the rest of the repository
const VECTOR_SOURCES = [['docs/protocol/vectors/qodiqa-protocol-vectors.json', 'qodiqa-protocol-vectors.json'], ['test-vectors/artifact-v1.json', 'artifact-v1.json']];
const VECTOR_DIRS = [path.join(REPO, 'sdk', 'go', 'testdata'), path.join(REPO, 'sdk', 'java', 'src', 'test', 'resources', 'vectors')];

const snake = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').replace(/[^A-Za-z0-9]+/g, '_').toLowerCase();

function authOf(op, specSecurity) {
  const sec = op.security !== undefined ? op.security : specSecurity;
  if (!sec || sec.length === 0) return 'none';
  const names = new Set(); let anon = false;
  for (const s of sec) { const k = Object.keys(s); if (k.length === 0) anon = true; for (const n of k) names.add(n); }
  if (names.has('SigningApiKey')) return 'sign';
  if (anon) return 'optional';
  return 'ops';
}

function kindOfResponse(op) {
  const ok = Object.entries(op.responses || {}).find(([c]) => /^2/.test(c));
  if (!ok) return 'json';
  const content = ok[1].content ? Object.keys(ok[1].content) : [];
  if (content.length === 0) return ok[0] === '204' ? 'none' : 'json';
  if (content.includes('application/json')) return 'json';
  if (content.includes('text/event-stream')) return 'sse';
  if (content.every((c) => /^text\/|yaml|xml|csv/.test(c))) return 'text';
  return 'binary';
}

function collect(spec) {
  const out = [];
  for (const [p, item] of Object.entries(spec.paths)) {
    for (const m of HTTP) {
      const op = item[m]; if (!op) continue;
      if (!op.operationId) throw new Error(`${m.toUpperCase()} ${p} has no operationId`);
      const resolve = (x) => (x && x.$ref ? x.$ref.split('/').slice(1).reduce((o, k) => o[k], spec) : x);
      const params = [...(item.parameters || []), ...(op.parameters || [])].map(resolve);
      const byIn = (loc) => params.filter((x) => x.in === loc);
      const pathParams = [...p.matchAll(/\{([^}]+)\}/g)].map((x) => x[1]);
      for (const n of pathParams) if (!byIn('path').some((x) => x.name === n)) throw new Error(`${op.operationId}: path parameter ${n} is not declared`);
      let body = 'none'; let bodyRequired = false;
      if (op.requestBody) {
        const rb = resolve(op.requestBody); const ct = Object.keys(rb.content || {})[0] || 'application/json';
        body = ct === 'application/json' ? 'json' : /x-www-form-urlencoded/.test(ct) ? 'form' : 'raw';
        bodyRequired = rb.required === true;
      }
      out.push({
        id: op.operationId, method: m.toUpperCase(), path: p, auth: authOf(op, spec.security),
        pathParams, query: byIn('query').map((x) => x.name).sort(), requiredQuery: byIn('query').filter((x) => x.required).map((x) => x.name).sort(),
        headers: byIn('header').map((x) => x.name).sort(), body, bodyRequired, response: kindOfResponse(op),
        summary: String(op.summary || '').replace(/\s+/g, ' ').slice(0, 160),
      });
    }
  }
  out.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const ids = new Set(); const sn = new Set();
  for (const o of out) { if (ids.has(o.id)) throw new Error(`duplicate operationId ${o.id}`); ids.add(o.id); const s = snake(o.id); if (sn.has(s)) throw new Error(`python name collision for ${o.id} (${s})`); sn.add(s); }
  return out;
}

const q = (s) => JSON.stringify(s);

function genTs(ops, hash) {
  const lines = [];
  lines.push('// GENERATED by scripts/sdk/generate-operations.js from docs/api/openapi.json - do not edit (npm run sdk:generate; npm run sdk:check fails on drift).');
  lines.push(`// contract sha256: ${hash}`);
  lines.push('');
  lines.push("export type OperationAuth = 'ops' | 'sign' | 'none' | 'optional';");
  lines.push("export type OperationBody = 'json' | 'form' | 'raw' | 'none';");
  lines.push("export type OperationResponse = 'json' | 'sse' | 'text' | 'binary' | 'none';");
  lines.push('');
  lines.push('export interface OperationDescriptor {');
  lines.push('  readonly id: string; readonly method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE"; readonly path: string; readonly auth: OperationAuth;');
  lines.push('  readonly pathParams: readonly string[]; readonly query: readonly string[]; readonly requiredQuery: readonly string[]; readonly headers: readonly string[];');
  lines.push('  readonly body: OperationBody; readonly bodyRequired: boolean; readonly response: OperationResponse; readonly summary: string;');
  lines.push('}');
  lines.push('');
  lines.push('export interface OperationArgs {');
  lines.push('  path?: Record<string, string | number>;');
  lines.push('  query?: Record<string, string | number | boolean | undefined>;');
  lines.push('  headers?: Record<string, string>;');
  lines.push('  body?: unknown;');
  lines.push('  timeout?: number;');
  lines.push('  signal?: AbortSignal;');
  lines.push('}');
  lines.push('');
  lines.push('export const OPERATIONS: Readonly<Record<string, OperationDescriptor>> = Object.freeze({');
  for (const o of ops) lines.push(`  ${q(o.id)}: ${JSON.stringify(o)},`);
  lines.push('});');
  lines.push('');
  lines.push('/** One method per documented operation: `client.operations.<operationId>(args)`; `path` is required exactly when the template has parameters. */');
  lines.push('export interface OperationMethods {');
  for (const o of ops) {
    const pathT = o.pathParams.length ? `path: { ${o.pathParams.map((n) => `${q(n)}: string | number`).join('; ')} }` : 'path?: never';
    const needArgs = o.pathParams.length > 0 || o.requiredQuery.length > 0 || o.bodyRequired;
    const queryT = o.query.length ? `query${o.requiredQuery.length ? '' : '?'}: { ${o.query.map((n) => `${q(n)}${o.requiredQuery.includes(n) ? '' : '?'}: string | number | boolean`).join('; ')} }` : 'query?: never';
    const bodyT = o.body === 'none' ? 'body?: never' : `body${o.bodyRequired ? '' : '?'}: unknown`;
    const hdrT = o.headers.length ? `headers?: { ${o.headers.map((n) => `${q(n)}?: string`).join('; ')} }` : 'headers?: Record<string, string>';
    const ret = o.response === 'sse' ? 'AsyncGenerator<unknown>' : 'Promise<unknown>';
    lines.push(`  /** ${o.method} ${o.path} - ${o.summary.replace(/\*\//g, '* /')} (credential: ${o.auth}) */`);
    lines.push(`  ${o.id}(args${needArgs ? '' : '?'}: { ${[pathT, queryT, bodyT, hdrT, 'timeout?: number', 'signal?: AbortSignal'].join('; ')} }): ${ret};`);
  }
  lines.push('}');
  lines.push('');
  return lines.join('\n');
}

function genPy(ops, hash) {
  const lines = [];
  lines.push('# GENERATED by scripts/sdk/generate-operations.js from docs/api/openapi.json - do not edit (npm run sdk:generate; npm run sdk:check fails on drift).');
  lines.push(`# contract sha256: ${hash}`);
  lines.push('"""Descriptor table of every documented operation (name -> how to call it). See qodiqa/_operations.py."""');
  lines.push('');
  lines.push('from __future__ import annotations');
  lines.push('');
  lines.push('from typing import Any, Dict, Tuple');
  lines.push('');
  lines.push('OPERATIONS: Dict[str, Dict[str, Any]] = {');
  for (const o of ops) {
    lines.push(`    ${q(snake(o.id))}: {`);
    lines.push(`        "id": ${q(o.id)}, "method": ${q(o.method)}, "path": ${q(o.path)}, "auth": ${q(o.auth)},`);
    lines.push(`        "path_params": ${pyTuple(o.pathParams)}, "query": ${pyTuple(o.query)}, "required_query": ${pyTuple(o.requiredQuery)}, "headers": ${pyTuple(o.headers)},`);
    lines.push(`        "body": ${q(o.body)}, "body_required": ${o.bodyRequired ? 'True' : 'False'}, "response": ${q(o.response)}, "summary": ${q(o.summary)},`);
    lines.push('    },');
  }
  lines.push('}');
  lines.push('');
  lines.push('OPERATION_NAMES: Tuple[str, ...] = tuple(sorted(OPERATIONS))');
  lines.push('');
  return lines.join('\n');
}
function genJson(ops, hash) { return `${JSON.stringify({ about: 'GENERATED by scripts/sdk/generate-operations.js from docs/api/openapi.json - do not edit', contractSha256: hash, operations: ops }, null, 1)}
`; }
const pyTuple = (a) => (a.length === 0 ? '()' : a.length === 1 ? `(${q(a[0])},)` : `(${a.map(q).join(', ')})`);

function main() {
  const raw = fs.readFileSync(SPEC, 'utf8');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const spec = JSON.parse(raw);
  const ops = collect(spec);
  const files = [[TS_OUT, genTs(ops, hash)], [PY_OUT, genPy(ops, hash)], [GO_OUT, genJson(ops, hash)], [JAVA_OUT, genJson(ops, hash)]];
  for (const [src, name] of VECTOR_SOURCES) for (const dir of VECTOR_DIRS) files.push([path.join(dir, name), fs.readFileSync(path.join(REPO, src), 'utf8')]);
  const check = process.argv.includes('--check');
  let drift = 0;
  for (const [file, content] of files) {
    const rel = path.relative(REPO, file);
    if (check) {
      const cur = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n') : null;
      if (cur !== content.replace(/\r\n/g, '\n')) { console.error(`DRIFT: ${rel} differs from what docs/api/openapi.json generates (run npm run sdk:generate)`); drift += 1; }
    } else { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, content); console.log(`wrote ${rel}`); }
  }
  console.log(JSON.stringify({ operations: ops.length, byAuth: ops.reduce((a, o) => ((a[o.auth] = (a[o.auth] || 0) + 1), a), {}), byResponse: ops.reduce((a, o) => ((a[o.response] = (a[o.response] || 0) + 1), a), {}) }));
  if (drift) process.exit(1);
}

if (require.main === module) main();
module.exports = { collect, snake, authOf, kindOfResponse, genTs, genPy, genJson, SPEC, TS_OUT, PY_OUT, GO_OUT, JAVA_OUT };
