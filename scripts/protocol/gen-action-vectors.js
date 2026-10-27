#!/usr/bin/env node
'use strict';

/**
 * Generates the action-binding vectors (docs/protocol/vectors/action.json, ACTION-nnn) from the PRODUCTION implementation
 * (src/core/actions/actionHash.js, docs/protocol/PROTOCOL-V2.md section 5.1):
 *
 *   actionHash = SHA-256("QODIQA::ACTION::V2" || JCS-P1({v:2, tenantId, agentId, sessionId, seq, tool{server,name,schemaHash}, args, parentRequestHash, prevActionHash}))
 *   schemaHash = SHA-256("QODIQA::TOOL_SCHEMA::V1" || JCS-P1(schema))
 *
 * The inputs are bytes of JSON text (`argsText`, `schemaText`): both independent verifiers (verify-action-vectors.js, verify_action_vectors.py) build the
 * document text themselves and canonicalise it with their OWN JCS-P1 implementations, so a disagreement between JavaScript and Python on the canonical
 * form of an argument is caught here. A disagreement is a defect in the specification, the implementation or a verifier - never settled by editing a vector.
 *
 *   node scripts/protocol/gen-action-vectors.js            write docs/protocol/vectors/action.json
 *   node scripts/protocol/gen-action-vectors.js --check    regenerate in memory and compare with the committed file (exit 1 on any difference)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { computeActionHash, computeSchemaHash, buildActionDocument, ActionHashError } = require('../../src/core/actions/actionHash');
const { canonicalJcsP1 } = require('../../src/validation/jcsP1');

const FILE = path.join(__dirname, '..', '..', 'docs', 'protocol', 'vectors', 'action.json');
const H = (c) => c.repeat(64);
const BS = String.fromCharCode(92);          // a backslash, written without escapes so the vector text is exactly what is meant
const A1 = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const S1 = 'bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb';
const base = (over = {}) => ({ tenantId: 'tenant-a', agentId: A1, sessionId: S1, seq: 1, tool: { server: 'files', name: 'read', schemaHash: H('e') }, parentRequestHash: null, prevActionHash: null, argsText: '{"p\\u0061th":"/tmp/a.txt"}', ...over });

const ACTION_CASES = [
  ['minimal first action', base()],
  ['empty arguments object', base({ argsText: '{}' })],
  ['second action chained to the first', base({ seq: 2, prevActionHash: H('1') })],
  ['parent request hash present', base({ parentRequestHash: H('f') })],
  ['tool name with a slash and server with dots', base({ tool: { server: 'mcp.fs-1', name: 'files/read:v2', schemaHash: H('d') } })],
  ['a member name written with an escape equals the literal name (same hash as the first case)', base({ argsText: '{"p' + BS + 'u0061th":"/tmp/a.txt"}' })],
  ['argument keys given unsorted (canonical order is by UTF-16 code unit)', base({ argsText: '{"z":1,"a":2,"m":{"y":true,"b":null}}' })],
  ['same members, other textual order: identical canonical form', base({ argsText: '{"m":{"b":null,"y":true},"a":2,"z":1}' })],
  ['decimal numbers (JCS-P1 allows them)', base({ argsText: '{"x":10.5,"y":-0.25,"z":0.1}' })],
  ['exponent lexemes are normalised', base({ argsText: '{"a":1e2,"b":1E-2,"c":5e0}' })],
  ['negative zero is zero', base({ argsText: '{"a":-0,"b":0}' })],
  ['largest safe integer', base({ argsText: '{"n":9007199254740991}' })],
  ['arrays, booleans and null', base({ argsText: '{"l":[1,"two",false,null,[],{}]}' })],
  ['composed (NFC) non-ASCII text', base({ argsText: '{"name":"café über 中文"}' })],
  ['escape sequences are decoded then re-encoded canonically', base({ argsText: '{"s":"\\u00e9\\n\\"q\\"\\\\ \\u0001 /"}' })],
  ['supplementary-plane character sorts by UTF-16 code units', base({ argsText: '{"\\ud83d\\ude00":1,"\\uff5e":2,"b":3}' })],
  ['whitespace in the argument text is irrelevant', base({ argsText: ' {\n  "a" : 1 ,\t"b" : [ 1 , 2 ]\n} ' })],
  ['deep but allowed nesting', base({ argsText: `${'{"a":'.repeat(30)}1${'}'.repeat(30)}` })],
  ['seq 1 with a long tenant id', base({ tenantId: 'T'.repeat(64) })],
  ['a different schemaHash is a different action', base({ tool: { server: 'files', name: 'read', schemaHash: H('c') } })],
  ['a different session is a different action', base({ sessionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' })],
  // refusals - the precise code, not just "invalid"
  ['tenant id with a space', base({ tenantId: 'a b' })],
  ['tenant id empty', base({ tenantId: '' })],
  ['agent id in upper case', base({ agentId: A1.toUpperCase() })],
  ['agent id is a UUID v1', base({ agentId: 'aaaaaaaa-aaaa-1aaa-8aaa-aaaaaaaaaaaa' })],
  ['session id with a wrong variant', base({ sessionId: 'bbbbbbbb-bbbb-4bbb-cbbb-bbbbbbbbbbbb' })],
  ['seq 0', base({ seq: 0 })],
  ['seq negative', base({ seq: -1 })],
  ['seq is a string', base({ seq: '1' })],
  ['seq 2 with a null prevActionHash', base({ seq: 2, prevActionHash: null })],
  ['seq 1 with a prevActionHash', base({ seq: 1, prevActionHash: H('1') })],
  ['prevActionHash is not 64 hex digits', base({ seq: 2, prevActionHash: 'abc' })],
  ['parentRequestHash in upper case', base({ parentRequestHash: H('F') })],
  ['tool without schemaHash', base({ tool: { server: 'files', name: 'read' } })],
  ['tool with an extra member', base({ tool: { server: 'files', name: 'read', schemaHash: H('e'), extra: 1 } })],
  ['tool server starts with a dot', base({ tool: { server: '.files', name: 'read', schemaHash: H('e') } })],
  ['tool schemaHash is not hex', base({ tool: { server: 'files', name: 'read', schemaHash: 'zz' } })],
  ['arguments are an array', base({ argsText: '[1,2]' })],
  ['arguments are a string', base({ argsText: '"x"' })],
  ['arguments are null', base({ argsText: 'null' })],
  ['argument text not in Unicode normalization form C', base({ argsText: '{"s":"e\\u0301"}' })],
  ['integer beyond the safe range', base({ argsText: '{"n":1152921504606846976}' })],
  ['lone surrogate in an argument string', base({ argsText: '{"s":"\\ud800"}' })],
  ['forbidden member name __proto__', base({ argsText: '{"__proto__":{"x":1}}' })],
  ['nesting deeper than 64 levels', base({ argsText: `${'{"a":'.repeat(80)}1${'}'.repeat(80)}` })],
];

const SCHEMA_CASES = [
  ['empty object schema', '{"type":"object"}'],
  ['object schema with properties and required', '{"type":"object","required":["path"],"properties":{"path":{"type":"string","maxLength":64}}}'],
  ['member order does not matter', '{"properties":{"path":{"maxLength":64,"type":"string"}},"required":["path"],"type":"object"}'],
  ['a different schema is a different hash', '{"type":"object","required":["path"],"properties":{"path":{"type":"string","maxLength":65}}}'],
  ['numeric keywords', '{"type":"object","properties":{"n":{"type":"integer","minimum":1,"maximum":1e2}}}'],
  ['non-object schema is refused', '[]'],
];

const pad = (n) => String(n).padStart(3, '0');
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

/** The document text both verifiers build: members in a fixed order, the argument text spliced in verbatim. */
function documentText(i) {
  const js = (v) => JSON.stringify(v);
  return `{"v":2,"tenantId":${js(i.tenantId)},"agentId":${js(i.agentId)},"sessionId":${js(i.sessionId)},"seq":${js(i.seq)},"tool":${js(i.tool)},"args":${i.argsText},"parentRequestHash":${js(i.parentRequestHash)},"prevActionHash":${js(i.prevActionHash)}}`;
}

function expectedFor(input) {
  let args;
  try { args = JSON.parse(input.argsText); } catch { return { error: { code: 'ACTION_INVALID_ARGS' } }; }
  try {
    const parts = { tenantId: input.tenantId, agentId: input.agentId, sessionId: input.sessionId, seq: input.seq, tool: input.tool, args, parentRequestHash: input.parentRequestHash, prevActionHash: input.prevActionHash };
    const actionHash = computeActionHash(parts);
    const canonical = canonicalJcsP1(buildActionDocument(parts), { maxBytes: 270_336 });
    return { ok: { canonicalSha256: sha(canonical), ...(canonical.length <= 400 ? { canonical } : {}), actionHash } };
  } catch (e) {
    if (!(e instanceof ActionHashError)) throw e;
    return { error: { code: e.code, ...(e.cause && e.cause.code ? { jcs: e.cause.code } : {}) } };
  }
}

function build() {
  const cases = [];
  ACTION_CASES.forEach(([description, input], i) => {
    const e = expectedFor(input);
    cases.push({ id: `ACTION-${pad(i + 1)}`, kind: 'action', description, input, ...(e.ok ? { expected: e.ok } : { expectedError: e.error }) });
  });
  SCHEMA_CASES.forEach(([description, schemaText], i) => {
    const id = `ACTION-${pad(ACTION_CASES.length + i + 1)}`;
    try { cases.push({ id, kind: 'schema', description, input: { schemaText }, expected: { schemaHash: computeSchemaHash(JSON.parse(schemaText)) } }); } catch (e) {
      if (!(e instanceof ActionHashError)) throw e;
      cases.push({ id, kind: 'schema', description, input: { schemaText }, expectedError: { code: e.code } });
    }
  });
  // the two members of "same members, other textual order" must agree - the generator refuses a vector set that does not show it
  const byDesc = (d) => cases.find((c) => c.description === d);
  if (byDesc('argument keys given unsorted (canonical order is by UTF-16 code unit)').expected.actionHash !== byDesc('same members, other textual order: identical canonical form').expected.actionHash) throw new Error('key order changed the hash');
  const v = {
    format: 'qodiqa-vectors/1', family: 'action', spec: 'docs/protocol/PROTOCOL-V2.md section 5.1', specVersion: 'v2-freeze-1', generatedBy: 'scripts/protocol/gen-action-vectors.js',
    domains: { action: 'QODIQA::ACTION::V2', toolSchema: 'QODIQA::TOOL_SCHEMA::V1' },
    documentText: 'members in this order: v, tenantId, agentId, sessionId, seq, tool, args, parentRequestHash, prevActionHash - input.argsText spliced verbatim, other members as JSON; canonicalised with JCS-P1',
    cases,
  };
  v.counts = { cases: cases.length, accepted: cases.filter((c) => c.expected).length, refused: cases.filter((c) => c.expectedError).length };
  return v;
}

if (require.main === module) {
  const text = `${JSON.stringify(build(), null, 2)}\n`;
  if (process.argv.includes('--check')) {
    const have = fs.existsSync(FILE) ? fs.readFileSync(FILE, 'utf8') : '';
    const ok = have === text;
    process.stdout.write(`${JSON.stringify({ ok, file: 'docs/protocol/vectors/action.json', generatedSha256: sha(text), committedSha256: sha(have) })}\n`);
    if (!ok) { process.stderr.write('[action-vectors] DRIFT: run `npm run protocol:vectors` and review the diff\n'); process.exit(1); }
  } else {
    fs.writeFileSync(FILE, text);
    process.stdout.write(`${JSON.stringify({ wrote: path.relative(process.cwd(), FILE), cases: build().counts })}\n`);
  }
}

module.exports = { build, documentText, ACTION_CASES, SCHEMA_CASES };
