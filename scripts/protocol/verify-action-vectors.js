#!/usr/bin/env node
'use strict';

/**
 * INDEPENDENT verifier for the action-binding vectors (docs/protocol/vectors/action.json, ACTION-nnn).
 *
 * Imports NOTHING from src/ or services/: only node:crypto/fs/path and the independent JCS-P1 implementation of verify-v2-vectors.js (which itself imports nothing
 * from src/). The document is rebuilt from the vector's input as TEXT and canonicalised by that parser - so the canonical form of an argument is re-derived by an
 * implementation that is not the production one. The Python counterpart is verify_action_vectors.py.
 *
 *   node scripts/protocol/verify-action-vectors.js [file.json]     exit 1 on any mismatch
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseJcsP1, Refusal } = require('./verify-v2-vectors');

const ACTION_DOMAIN = 'QODIQA::ACTION::V2';
const SCHEMA_DOMAIN = 'QODIQA::TOOL_SCHEMA::V1';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const TENANT = /^[A-Za-z0-9_-]{1,64}$/;
const SERVER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TOOL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const sha = (domain, canonical) => crypto.createHash('sha256').update(domain, 'utf8').update(canonical, 'utf8').digest('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

function actionVerdict(i) {
  const no = (code, jcs) => ({ error: { code, ...(jcs ? { jcs } : {}) } });
  if (typeof i.tenantId !== 'string' || !TENANT.test(i.tenantId)) return no('ACTION_INVALID_TENANT');
  if (typeof i.agentId !== 'string' || !UUID_V4.test(i.agentId)) return no('ACTION_INVALID_AGENT');
  if (typeof i.sessionId !== 'string' || !UUID_V4.test(i.sessionId)) return no('ACTION_INVALID_SESSION');
  if (typeof i.seq !== 'number' || !Number.isSafeInteger(i.seq) || i.seq < 1) return no('ACTION_INVALID_SEQ');
  const t = i.tool;
  if (!isObj(t) || Object.keys(t).sort().join(',') !== 'name,schemaHash,server') return no('ACTION_INVALID_TOOL');
  if (typeof t.server !== 'string' || !SERVER.test(t.server) || typeof t.name !== 'string' || !TOOL.test(t.name) || typeof t.schemaHash !== 'string' || !HEX64.test(t.schemaHash)) return no('ACTION_INVALID_TOOL');
  if (!String(i.argsText).trimStart().startsWith('{')) return no('ACTION_INVALID_ARGS');
  if (i.parentRequestHash !== null && !(typeof i.parentRequestHash === 'string' && HEX64.test(i.parentRequestHash))) return no('ACTION_INVALID_PARENT');
  if (i.prevActionHash !== null && !(typeof i.prevActionHash === 'string' && HEX64.test(i.prevActionHash))) return no('ACTION_INVALID_PREV');
  if ((i.seq === 1) !== (i.prevActionHash === null)) return no('ACTION_INVALID_PREV');
  const js = JSON.stringify;
  const text = `{"v":2,"tenantId":${js(i.tenantId)},"agentId":${js(i.agentId)},"sessionId":${js(i.sessionId)},"seq":${js(i.seq)},"tool":${js(i.tool)},"args":${i.argsText},"parentRequestHash":${js(i.parentRequestHash)},"prevActionHash":${js(i.prevActionHash)}}`;
  let canonical;
  try { ({ canonical } = parseJcsP1(Buffer.from(text, 'utf8'))); } catch (e) { if (e instanceof Refusal) return no('ACTION_ARGS_NOT_CANONICALIZABLE', e.code); throw e; }
  return { ok: { canonical, actionHash: sha(ACTION_DOMAIN, canonical) } };
}

function schemaVerdict(i) {
  if (!String(i.schemaText).trimStart().startsWith('{')) return { error: { code: 'SCHEMA_INVALID' } };
  let canonical;
  try { ({ canonical } = parseJcsP1(Buffer.from(i.schemaText, 'utf8'))); } catch (e) { if (e instanceof Refusal) return { error: { code: 'SCHEMA_NOT_CANONICALIZABLE', jcs: e.code } }; throw e; }
  return { ok: { schemaHash: sha(SCHEMA_DOMAIN, canonical) } };
}

function verifyCase(c) {
  const v = c.kind === 'schema' ? schemaVerdict(c.input) : actionVerdict(c.input);
  if (c.expectedError) {
    if (!v.error) return [false, 'expected a refusal, derived a hash'];
    return v.error.code === c.expectedError.code && (v.error.jcs || null) === (c.expectedError.jcs || null) ? [true] : [false, `refusal ${JSON.stringify(v.error)} != ${JSON.stringify(c.expectedError)}`];
  }
  if (!v.ok) return [false, `expected a hash, refused ${JSON.stringify(v.error)}`];
  if (c.kind === 'schema') return v.ok.schemaHash === c.expected.schemaHash ? [true] : [false, 'schemaHash differs'];
  if (v.ok.actionHash !== c.expected.actionHash) return [false, 'actionHash differs'];
  if (sha256(v.ok.canonical) !== c.expected.canonicalSha256) return [false, 'canonical form differs'];
  if (c.expected.canonical !== undefined && c.expected.canonical !== v.ok.canonical) return [false, 'canonical text differs'];
  return [true];
}

function verifyFile(file) {
  const v = JSON.parse(fs.readFileSync(file, 'utf8'));
  const failures = [];
  for (const c of v.cases) { const [ok, why] = verifyCase(c); if (!ok) failures.push({ id: c.id, description: c.description, why }); }
  return { file: path.basename(file), family: v.family, cases: v.cases.length, failed: failures.length, failures };
}

module.exports = { verifyCase, verifyFile };

if (require.main === module) {
  const file = process.argv[2] || path.join(__dirname, '..', '..', 'docs', 'protocol', 'vectors', 'action.json');
  const r = verifyFile(file);
  process.stdout.write(`${JSON.stringify({ implementation: 'verify-action-vectors.js (independent, node)', checks: r.cases, failed: r.failed, reports: [r] }, null, 2)}\n`);
  process.exit(r.failed ? 1 : 0);
}
