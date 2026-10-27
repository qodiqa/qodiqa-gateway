'use strict';

/**
 * Delegation tokens and chains (/ domain QODIQA::DELEGATION::V1, specification docs/protocol/DELEGATION.md).
 *
 * A delegation grants a subset of one agent's authority to another agent. It is a signed envelope - the same Ed25519 tenant key as every artifact, a different DOMAIN:
 *
 *   digest    = SHA-256( "QODIQA::DELEGATION::V1" || JCS-P1({ expiry, payload, publicKeyId, timestamp }) )       (the 32 bytes that are signed)
 *   envelope  = { expiry, payload, publicKeyId, signature, timestamp }                                           signature: canonical base64 (88 chars)
 *   payload   = { v:1, kind:"delegation", delegationId, tenantId, parentId, parentDigest, rootAgentId, issuerAgentId, subjectAgentId, depth, maxDepth,
 *                 classes, tools, maxActions }
 *
 * A CHAIN is the list of envelopes root -> leaf. Each link names its parent by id AND by the parent's digest, so the chain is bound end to end and the leaf's digest
 * (`chainHash`) identifies the whole chain. Rights only SHRINK down a chain (strict attenuation):
 *   classes     subset of the parent's classes
 *   tools       a parent with a tool list restricts the child to a subset of it (the child cannot be unrestricted); a parent without one imposes nothing
 *   maxActions  a parent with a limit imposes one on the child, not larger
 *   expiry      not after the parent's; the link is issued at or after the parent's timestamp
 *   depth       parent's + 1, never above maxDepth (fixed by the root grant, at most MAX_DEPTH_CAP); the delegate of the last depth cannot delegate further
 *   cycle       no agent appears twice in root.issuer, subject_0, subject_1, ...
 *
 * verifyChain checks one link at a time, root first, and reports the FIRST failure in this order:
 *   shape -> signature -> tenant -> linkage -> depth -> cycle -> attenuation -> time (-> key lifecycle, production only).
 * Reasons (V2-FREEZE 7.5): DELEGATION_INVALID, DELEGATION_DEPTH_EXCEEDED, DELEGATION_CYCLE, DELEGATION_ATTENUATION_VIOLATION (DELEGATION_REVOKED is state: the store).
 * The same rules are re-implemented without any QODIQA import in scripts/protocol/verify-delegation-vectors.js and verify_delegation_vectors.py
 * and pinned by docs/protocol/vectors/delegation.json (DELEG-nnn).
 */

const crypto = require('crypto');
const { canonicalJcsP1, JcsError } = require('../../validation/jcsP1');
const { sign, verify } = require('../../infra/crypto/ed25519');

const DELEGATION_DOMAIN = 'QODIQA::DELEGATION::V1';
const MAX_DEPTH_CAP = 8;
const MAX_ACTIONS_CAP = 100_000;
const MAX_TOOLS = 100;
const ACTION_CLASSES = Object.freeze(['read', 'write', 'file', 'database', 'external_api', 'command', 'communication', 'financial', 'delegate']);
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SIG_RE = /^[A-Za-z0-9+/]{86}==$/;
const TENANT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SERVER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TOOL_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const ENVELOPE_KEYS = ['expiry', 'payload', 'publicKeyId', 'signature', 'timestamp'];
const PAYLOAD_KEYS = ['classes', 'delegationId', 'depth', 'issuerAgentId', 'kind', 'maxActions', 'maxDepth', 'parentDigest', 'parentId', 'rootAgentId', 'subjectAgentId', 'tenantId', 'tools', 'v'];
const MAX_SKEW_MS = 5 * 60_000;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v, min, max) => Number.isSafeInteger(v) && v >= min && v <= max;

class DelegationError extends Error { constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.name = 'DelegationError'; this.code = code; } }

function envelopeDigest({ expiry, payload, publicKeyId, timestamp }) {
  return crypto.createHash('sha256').update(DELEGATION_DOMAIN, 'utf8').update(canonicalJcsP1({ expiry, payload, publicKeyId, timestamp }, { maxBytes: 65_536 }), 'utf8').digest();
}
const digestHex = (envelope) => envelopeDigest(envelope).toString('hex');

const sortedUnique = (a) => Array.isArray(a) && a.every((x, i) => i === 0 || a[i - 1] < x);
const toolKey = (t) => `${t.server}\u0000${t.name}`;

/** @returns {string|null} what is wrong with the payload shape, or null */
function shapeProblem(p) {
  if (!isObj(p) || Object.keys(p).sort().join(',') !== PAYLOAD_KEYS.join(',')) return 'payload members';
  if (p.v !== 1 || p.kind !== 'delegation') return 'v / kind';
  if (typeof p.delegationId !== 'string' || !UUID_V4.test(p.delegationId)) return 'delegationId';
  if (typeof p.tenantId !== 'string' || !TENANT_RE.test(p.tenantId)) return 'tenantId';
  if (p.parentId !== null && !(typeof p.parentId === 'string' && UUID_V4.test(p.parentId))) return 'parentId';
  if (p.parentDigest !== null && !(typeof p.parentDigest === 'string' && HEX64.test(p.parentDigest))) return 'parentDigest';
  if ((p.parentId === null) !== (p.parentDigest === null)) return 'parentId / parentDigest';
  for (const k of ['rootAgentId', 'issuerAgentId', 'subjectAgentId']) if (typeof p[k] !== 'string' || !UUID_V4.test(p[k])) return k;
  if (!isInt(p.depth, 1, MAX_DEPTH_CAP) || !isInt(p.maxDepth, 1, MAX_DEPTH_CAP)) return 'depth / maxDepth';
  if (!Array.isArray(p.classes) || !p.classes.length || !p.classes.every((c) => ACTION_CLASSES.includes(c)) || !sortedUnique(p.classes)) return 'classes';
  if (p.tools !== null) {
    if (!Array.isArray(p.tools) || !p.tools.length || p.tools.length > MAX_TOOLS) return 'tools';
    for (const t of p.tools) if (!isObj(t) || Object.keys(t).sort().join(',') !== 'name,server' || typeof t.server !== 'string' || !SERVER_RE.test(t.server) || typeof t.name !== 'string' || !TOOL_RE.test(t.name)) return 'tools';
    if (!p.tools.every((t, i) => i === 0 || toolKey(p.tools[i - 1]) < toolKey(t))) return 'tools order';
  }
  if (p.maxActions !== null && !isInt(p.maxActions, 1, MAX_ACTIONS_CAP)) return 'maxActions';
  return null;
}

const normaliseTools = (tools) => (tools == null ? null : [...tools].map((t) => ({ server: t.server, name: t.name })).sort((a, b) => (toolKey(a) < toolKey(b) ? -1 : 1)));

/** Build a payload (validated). `parent` is the parent's ENVELOPE (or null for a root grant). */
function buildPayload({ delegationId, tenantId, parent, issuerAgentId, subjectAgentId, classes, tools, maxActions, maxDepth }) {
  const root = parent === null || parent === undefined;
  const payload = {
    v: 1, kind: 'delegation', delegationId, tenantId,
    parentId: root ? null : parent.payload.delegationId, parentDigest: root ? null : digestHex(parent),
    rootAgentId: root ? issuerAgentId : parent.payload.rootAgentId, issuerAgentId, subjectAgentId,
    depth: root ? 1 : parent.payload.depth + 1, maxDepth: root ? maxDepth : parent.payload.maxDepth,
    classes: [...new Set(classes)].sort(), tools: normaliseTools(tools), maxActions: maxActions == null ? null : maxActions,
  };
  const bad = shapeProblem(payload);
  if (bad) throw new DelegationError('DELEGATION_INVALID', bad);
  return payload;
}

function _checkEnvelopeInput({ payload, timestamp, expiry, publicKeyId }) {
  const bad = shapeProblem(payload);
  if (bad) throw new DelegationError('DELEGATION_INVALID', bad);
  if (!isInt(timestamp, 1, Number.MAX_SAFE_INTEGER) || !isInt(expiry, 1, Number.MAX_SAFE_INTEGER) || expiry <= timestamp) throw new DelegationError('DELEGATION_INVALID', 'timestamp < expiry');
  if (typeof publicKeyId !== 'string' || !publicKeyId.trim()) throw new DelegationError('DELEGATION_INVALID', 'publicKeyId');
}

function signDelegation(fields, privDer) {
  _checkEnvelopeInput(fields);
  const { payload, timestamp, expiry, publicKeyId } = fields;
  return Object.freeze({ expiry, payload, publicKeyId, signature: sign(envelopeDigest({ expiry, payload, publicKeyId, timestamp }), privDer), timestamp });
}

async function signDelegationNative(fields, nativeSign) {
  _checkEnvelopeInput(fields);
  const { payload, timestamp, expiry, publicKeyId } = fields;
  const sig = await nativeSign(publicKeyId, envelopeDigest({ expiry, payload, publicKeyId, timestamp }));
  if (!Buffer.isBuffer(sig) || sig.length !== 64) throw new Error('signDelegationNative: the native signing provider did not return a 64-byte Ed25519 signature');
  return Object.freeze({ expiry, payload, publicKeyId, signature: sig.toString('base64'), timestamp });
}

const isSubset = (a, b) => a.every((x) => b.includes(x));

/** Attenuation of a child payload against its parent's: @returns {string|null} what widens, or null */
function attenuationProblem(parent, child, parentExpiry, childExpiry) {
  if (!isSubset(child.classes, parent.classes)) return 'classes';
  if (parent.tools !== null) {
    if (child.tools === null) return 'tools';
    const allowed = new Set(parent.tools.map(toolKey));
    if (!child.tools.every((t) => allowed.has(toolKey(t)))) return 'tools';
  }
  if (parent.maxActions !== null && (child.maxActions === null || child.maxActions > parent.maxActions)) return 'maxActions';
  if (childExpiry > parentExpiry) return 'expiry';
  return null;
}

/**
 * @param {object[]} chain  envelopes, root first
 * @param {{ now?: number, resolveKey: (id:string)=>({found:boolean, pubDer?:Buffer, clientId?:string}), keyCheck?: (link:object)=>(string|null), maxSkewMs?: number }} o
 * @returns {{ ok: true, depth: number, chainHash: string, rootAgentId: string, issuerAgentId: string, subjectAgentId: string, tenantId: string, delegationId: string, classes: string[], tools: object[]|null,
 *             maxActions: number|null, expiry: number, maxDepth: number }
 *          | { ok: false, reason: string, detail?: string, index?: number }}
 */
function verifyChain(chain, { now = Date.now(), resolveKey, keyCheck, maxSkewMs = MAX_SKEW_MS } = {}) {
  const no = (reason, detail, index) => ({ ok: false, reason, ...(detail ? { detail } : {}), ...(index !== undefined ? { index } : {}) });
  if (!Array.isArray(chain) || chain.length < 1 || chain.length > MAX_DEPTH_CAP) return no('DELEGATION_INVALID', 'chain length');
  const agents = [];
  let prev = null; let prevDigest = null; let root = null;
  for (let i = 0; i < chain.length; i++) {
    const e = chain[i];
    // shape
    if (!isObj(e) || Object.keys(e).sort().join(',') !== ENVELOPE_KEYS.join(',')) return no('DELEGATION_INVALID', 'envelope members', i);
    const p = e.payload;
    const bad = shapeProblem(p);
    if (bad) return no('DELEGATION_INVALID', bad, i);
    if (typeof e.signature !== 'string' || !SIG_RE.test(e.signature) || Buffer.from(e.signature, 'base64').toString('base64') !== e.signature) return no('DELEGATION_INVALID', 'signature encoding', i);
    if (!isInt(e.timestamp, 1, Number.MAX_SAFE_INTEGER) || !isInt(e.expiry, 1, Number.MAX_SAFE_INTEGER) || e.expiry <= e.timestamp || typeof e.publicKeyId !== 'string' || !e.publicKeyId.trim()) return no('DELEGATION_INVALID', 'timestamp / expiry / publicKeyId', i);
    // signature
    let digest;
    try { digest = envelopeDigest(e); } catch (err) { if (err instanceof JcsError) return no('DELEGATION_INVALID', 'not canonicalisable', i); throw err; }
    const key = resolveKey(e.publicKeyId);
    if (!key || !key.found || !verify(digest, e.signature, key.pubDer)) return no('DELEGATION_INVALID', 'signature', i);
    // tenant
    if (p.tenantId !== key.clientId) return no('DELEGATION_INVALID', 'tenant', i);
    if (root && p.tenantId !== root.payload.tenantId) return no('DELEGATION_INVALID', 'tenant', i);
    // linkage
    if (i === 0) {
      if (p.parentId !== null || p.depth !== 1 || p.rootAgentId !== p.issuerAgentId) return no('DELEGATION_INVALID', 'root link', i);
      root = e; agents.push(p.issuerAgentId);
    } else {
      if (p.parentId !== prev.payload.delegationId || p.parentDigest !== prevDigest || p.issuerAgentId !== prev.payload.subjectAgentId || p.depth !== prev.payload.depth + 1
        || p.maxDepth !== root.payload.maxDepth || p.rootAgentId !== root.payload.rootAgentId) return no('DELEGATION_INVALID', 'link to parent', i);
    }
    // depth
    if (p.depth > p.maxDepth) return no('DELEGATION_DEPTH_EXCEEDED', undefined, i);
    // cycle
    if (p.subjectAgentId === p.issuerAgentId || agents.includes(p.subjectAgentId)) return no('DELEGATION_CYCLE', undefined, i);
    agents.push(p.subjectAgentId);
    // attenuation
    if (prev) {
      const wide = attenuationProblem(prev.payload, p, prev.expiry, e.expiry);
      if (wide) return no('DELEGATION_ATTENUATION_VIOLATION', wide, i);
      if (e.timestamp < prev.timestamp) return no('DELEGATION_INVALID', 'issued before its parent', i);
    }
    // time
    if (e.timestamp > now + maxSkewMs) return no('DELEGATION_INVALID', 'issued in the future', i);
    if (e.expiry <= now) return no('DELEGATION_INVALID', 'expired', i);
    if (keyCheck) { const k = keyCheck({ publicKeyId: e.publicKeyId, timestamp: e.timestamp, now }); if (k) return no('DELEGATION_INVALID', k, i); }
    prev = e; prevDigest = digest.toString('hex');
  }
  const leaf = chain[chain.length - 1]; const lp = leaf.payload;
  return { ok: true, depth: lp.depth, chainHash: prevDigest, rootAgentId: lp.rootAgentId, issuerAgentId: lp.issuerAgentId, subjectAgentId: lp.subjectAgentId, tenantId: lp.tenantId, delegationId: lp.delegationId,
    classes: lp.classes, tools: lp.tools, maxActions: lp.maxActions, expiry: leaf.expiry, maxDepth: lp.maxDepth };
}

module.exports = { DELEGATION_DOMAIN, MAX_DEPTH_CAP, MAX_ACTIONS_CAP, ACTION_CLASSES, DelegationError, envelopeDigest, digestHex, shapeProblem, buildPayload, signDelegation, signDelegationNative,
  attenuationProblem, verifyChain, normaliseTools };
