#!/usr/bin/env node
'use strict';

/**
 * INDEPENDENT verifier for the delegation-chain vectors (docs/protocol/vectors/delegation.json, DELEG-nnn).
 *
 * Imports NOTHING from src/ or services/: only node:crypto/fs/path and the independent JCS-P1 implementation of verify-v2-vectors.js (which itself imports nothing
 * from src/). The chain rules of docs/protocol/DELEGATION.md are re-implemented here from the specification text alone; the digest is rebuilt by canonicalising the
 * envelope with that parser, and the signature is checked with node:crypto. The Python counterpart is verify_delegation_vectors.py.
 *
 *   node scripts/protocol/verify-delegation-vectors.js [file.json]     exit 1 on any mismatch
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseJcsP1 } = require('./verify-v2-vectors');

const DOMAIN = 'QODIQA::DELEGATION::V1';
const CLASSES = ['read', 'write', 'file', 'database', 'external_api', 'command', 'communication', 'financial', 'delegate'];
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SIG_RE = /^[A-Za-z0-9+/]{86}==$/;
const TENANT = /^[A-Za-z0-9_-]{1,64}$/;
const SERVER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TOOL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const PAYLOAD_KEYS = 'classes,delegationId,depth,issuerAgentId,kind,maxActions,maxDepth,parentDigest,parentId,rootAgentId,subjectAgentId,tenantId,tools,v';
const ENVELOPE_KEYS = 'expiry,payload,publicKeyId,signature,timestamp';
const MAX_DEPTH = 8; const MAX_SKEW = 5 * 60_000;
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi;
const toolKey = (t) => `${t.server}\u0000${t.name}`;

function shapeOk(p) {
  if (!isObj(p) || Object.keys(p).sort().join(',') !== PAYLOAD_KEYS) return false;
  if (p.v !== 1 || p.kind !== 'delegation') return false;
  if (typeof p.delegationId !== 'string' || !UUID_V4.test(p.delegationId)) return false;
  if (typeof p.tenantId !== 'string' || !TENANT.test(p.tenantId)) return false;
  if (p.parentId !== null && !(typeof p.parentId === 'string' && UUID_V4.test(p.parentId))) return false;
  if (p.parentDigest !== null && !(typeof p.parentDigest === 'string' && HEX64.test(p.parentDigest))) return false;
  if ((p.parentId === null) !== (p.parentDigest === null)) return false;
  for (const k of ['rootAgentId', 'issuerAgentId', 'subjectAgentId']) if (typeof p[k] !== 'string' || !UUID_V4.test(p[k])) return false;
  if (!isInt(p.depth, 1, MAX_DEPTH) || !isInt(p.maxDepth, 1, MAX_DEPTH)) return false;
  if (!Array.isArray(p.classes) || !p.classes.length || !p.classes.every((c) => CLASSES.includes(c))) return false;
  for (let i = 1; i < p.classes.length; i++) if (!(p.classes[i - 1] < p.classes[i])) return false;
  if (p.tools !== null) {
    if (!Array.isArray(p.tools) || !p.tools.length || p.tools.length > 100) return false;
    for (const t of p.tools) if (!isObj(t) || Object.keys(t).sort().join(',') !== 'name,server' || typeof t.server !== 'string' || !SERVER.test(t.server) || typeof t.name !== 'string' || !TOOL.test(t.name)) return false;
    for (let i = 1; i < p.tools.length; i++) if (!(toolKey(p.tools[i - 1]) < toolKey(p.tools[i]))) return false;
  }
  if (p.maxActions !== null && !isInt(p.maxActions, 1, 100000)) return false;
  return true;
}

const digestOf = (e) => {
  const text = JSON.stringify({ expiry: e.expiry, payload: e.payload, publicKeyId: e.publicKeyId, timestamp: e.timestamp });
  const { canonical } = parseJcsP1(Buffer.from(text, 'utf8'));
  return crypto.createHash('sha256').update(DOMAIN, 'utf8').update(canonical, 'utf8').digest();
};

function widens(parent, child, parentExpiry, childExpiry) {
  if (!child.classes.every((c) => parent.classes.includes(c))) return true;
  if (parent.tools !== null) {
    if (child.tools === null) return true;
    const allowed = new Set(parent.tools.map(toolKey));
    if (!child.tools.every((t) => allowed.has(toolKey(t)))) return true;
  }
  if (parent.maxActions !== null && (child.maxActions === null || child.maxActions > parent.maxActions)) return true;
  return childExpiry > parentExpiry;
}

function verdict(input, keys) {
  const { chain, now } = input;
  const no = (reason, index) => ({ ok: false, reason, ...(index !== undefined ? { index } : {}) });
  if (!Array.isArray(chain) || chain.length < 1 || chain.length > MAX_DEPTH) return no('DELEGATION_INVALID');
  const agents = []; let prev = null; let prevDigest = null; let root = null;
  for (let i = 0; i < chain.length; i++) {
    const e = chain[i];
    if (!isObj(e) || Object.keys(e).sort().join(',') !== ENVELOPE_KEYS) return no('DELEGATION_INVALID', i);
    const p = e.payload;
    if (!shapeOk(p)) return no('DELEGATION_INVALID', i);
    if (typeof e.signature !== 'string' || !SIG_RE.test(e.signature) || Buffer.from(e.signature, 'base64').toString('base64') !== e.signature) return no('DELEGATION_INVALID', i);
    if (!isInt(e.timestamp, 1, Number.MAX_SAFE_INTEGER) || !isInt(e.expiry, 1, Number.MAX_SAFE_INTEGER) || e.expiry <= e.timestamp || typeof e.publicKeyId !== 'string' || !e.publicKeyId.trim()) return no('DELEGATION_INVALID', i);
    let digest;
    try { digest = digestOf(e); } catch { return no('DELEGATION_INVALID', i); }
    const key = keys.find((k) => k.publicKeyId === e.publicKeyId);
    if (!key) return no('DELEGATION_INVALID', i);
    let sigOk = false;
    try { sigOk = crypto.verify(null, digest, crypto.createPublicKey({ key: Buffer.from(key.publicKeySpkiB64, 'base64'), format: 'der', type: 'spki' }), Buffer.from(e.signature, 'base64')); } catch { sigOk = false; }
    if (!sigOk) return no('DELEGATION_INVALID', i);
    if (p.tenantId !== key.clientId) return no('DELEGATION_INVALID', i);
    if (root && p.tenantId !== root.payload.tenantId) return no('DELEGATION_INVALID', i);
    if (i === 0) {
      if (p.parentId !== null || p.depth !== 1 || p.rootAgentId !== p.issuerAgentId) return no('DELEGATION_INVALID', i);
      root = e; agents.push(p.issuerAgentId);
    } else if (p.parentId !== prev.payload.delegationId || p.parentDigest !== prevDigest || p.issuerAgentId !== prev.payload.subjectAgentId || p.depth !== prev.payload.depth + 1
      || p.maxDepth !== root.payload.maxDepth || p.rootAgentId !== root.payload.rootAgentId) return no('DELEGATION_INVALID', i);
    if (p.depth > p.maxDepth) return no('DELEGATION_DEPTH_EXCEEDED', i);
    if (p.subjectAgentId === p.issuerAgentId || agents.includes(p.subjectAgentId)) return no('DELEGATION_CYCLE', i);
    agents.push(p.subjectAgentId);
    if (prev) {
      if (widens(prev.payload, p, prev.expiry, e.expiry)) return no('DELEGATION_ATTENUATION_VIOLATION', i);
      if (e.timestamp < prev.timestamp) return no('DELEGATION_INVALID', i);
    }
    if (e.timestamp > now + MAX_SKEW) return no('DELEGATION_INVALID', i);
    if (e.expiry <= now) return no('DELEGATION_INVALID', i);
    prev = e; prevDigest = digest.toString('hex');
  }
  const leaf = chain[chain.length - 1]; const lp = leaf.payload;
  return { ok: true, depth: lp.depth, maxDepth: lp.maxDepth, chainHash: prevDigest, rootAgentId: lp.rootAgentId, issuerAgentId: lp.issuerAgentId, subjectAgentId: lp.subjectAgentId, tenantId: lp.tenantId,
    delegationId: lp.delegationId, classes: lp.classes, tools: lp.tools, maxActions: lp.maxActions, expiry: leaf.expiry };
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function verifyFile(file) {
  const v = JSON.parse(fs.readFileSync(file, 'utf8'));
  const failures = [];
  for (const c of v.cases) {
    const got = verdict(c.input, v.keys);
    if (!same(got, c.expected)) failures.push({ id: c.id, description: c.description, got, expected: c.expected });
  }
  return { file: path.basename(file), family: v.family, cases: v.cases.length, failed: failures.length, failures };
}

module.exports = { verdict, verifyFile, SPKI_PREFIX };

if (require.main === module) {
  const file = process.argv[2] || path.join(__dirname, '..', '..', 'docs', 'protocol', 'vectors', 'delegation.json');
  const r = verifyFile(file);
  process.stdout.write(`${JSON.stringify({ implementation: 'verify-delegation-vectors.js (independent, node)', checks: r.cases, failed: r.failed, reports: [r] }, null, 2)}\n`);
  process.exit(r.failed ? 1 : 0);
}
