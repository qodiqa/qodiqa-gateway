'use strict';

/**
 * Protocol V2 claims and version negotiation (docs/protocol/PROTOCOL-V2.md sections 4 and 7).
 *
 *   classifyPayload(payload, opts)  -> { ok: true, version: 1 } | { ok: true, version: 2, qodiqa } | { ok: false, reason }
 *   verifyBindingV2(artifact, request) -> { bound: true, requestId } | { bound: false, reason: 'REQUEST_MISMATCH', details: {} }
 *   validateIssuanceBlock(v2)       -> normalized `payload.qodiqa` block for /sign, or throws IssuanceError
 *
 * A payload without a top-level `qodiqa` key is V1. `qodiqa` is read by exact key match at the top level only.
 */

const { computeRequestHashV2, buildDocument, hashDocument, validateBindHeaders, BindingError } = require('./requestBindingV2');
const { isValidRequestId } = require('./requestId');

const HEX_RE = /^[0-9a-f]{64}$/;
const QODIQA_KEYS_REQUEST = new Set(['v', 'kind', 'bind', 'model', 'limits', 'crit']);
const UNDERSTOOD_INNER_FIELDS = new Set(['v', 'kind', 'bind', 'model', 'limits', 'crit', 'agentId', 'sessionId', 'seq', 'actionHash', 'approvalRef']);
const NEVER_CRITICAL = new Set(['crit', 'v', 'kind', 'bind']);
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const isSafeInt = (x, min) => typeof x === 'number' && Number.isSafeInteger(x) && x >= min;

const env = (name, dflt) => (process.env[name] === undefined || process.env[name] === '' ? dflt : process.env[name]);
const acceptsV2 = () => env('QODIQA_PROTOCOL_V2_ACCEPT', 'false') === 'true';
const issuesV2 = () => env('QODIQA_PROTOCOL_V2_ISSUE', 'false') === 'true';

/** The lowest protocol version accepted for a tenant: the maximum of the environment minimum and the tenant's own setting (V2-FREEZE 7.3). */
function minProtocolVersion(tenantId) {
  let min = parseInt(env('QODIQA_PROTOCOL_MIN_VERSION', '1'), 10);
  if (!(min === 1 || min === 2)) min = 1;
  try {
    const t = tenantId ? require('../core/tenancy/tenantRegistry').getTenant(tenantId) : null;
    if (t && (t.minProtocolVersion === 2)) min = Math.max(min, 2);
  } catch (_) { /* the control plane being unavailable is handled by the tenant checks that already ran */ }
  return min;
}

function validateReceivedBlock(q, expectedKind) {
  if (!isObj(q)) return 'UNSUPPORTED_PROTOCOL_VERSION';
  if (q.v !== 2) return 'UNSUPPORTED_PROTOCOL_VERSION';
  const kind = q.kind === undefined ? 'request' : q.kind;
  if (kind !== 'request' && kind !== 'action') return 'UNSUPPORTED_PROTOCOL_VERSION';
  if (q.crit !== undefined) {
    if (!Array.isArray(q.crit) || q.crit.length === 0 || new Set(q.crit).size !== q.crit.length) return 'UNSUPPORTED_PROTOCOL_VERSION';
    for (const c of q.crit) {
      if (typeof c !== 'string' || NEVER_CRITICAL.has(c)) return 'UNSUPPORTED_PROTOCOL_VERSION';
      if (!UNDERSTOOD_INNER_FIELDS.has(c)) return 'UNSUPPORTED_CRITICAL_CLAIM';
    }
  }
  if (kind !== expectedKind) return 'WRONG_ARTIFACT_KIND';
  if (!isObj(q.bind) || !Array.isArray(q.bind.headers)) return 'REQUEST_MISMATCH';
  try { validateBindHeaders(q.bind.headers); } catch (_) { return 'REQUEST_MISMATCH'; }
  if (q.model !== undefined && q.model !== null && typeof q.model !== 'string') return 'REQUEST_MISMATCH';
  if (q.limits !== undefined) {
    if (!isObj(q.limits)) return 'REQUEST_MISMATCH';
    if (q.limits.maxTokens !== undefined && !isSafeInt(q.limits.maxTokens, 1)) return 'REQUEST_MISMATCH';
    if (q.limits.maxCostMicros !== undefined && !isSafeInt(q.limits.maxCostMicros, 0)) return 'REQUEST_MISMATCH';
  }
  return null;
}

/**
 * @param {object} payload            the (signature-verified) artifact payload
 * @param {{ tenantId?: string|null, expectedKind?: 'request'|'action' }} [opts]
 */
function classifyPayload(payload, { tenantId = null, expectedKind = 'request' } = {}) {
  const has = payload !== null && typeof payload === 'object' && Object.prototype.hasOwnProperty.call(payload, 'qodiqa');
  if (!has) {
    if (minProtocolVersion(tenantId) > 1) return { ok: false, reason: 'PROTOCOL_VERSION_TOO_LOW' };
    if (expectedKind === 'action') return { ok: false, reason: 'WRONG_ARTIFACT_KIND' };
    return { ok: true, version: 1 };
  }
  if (!acceptsV2()) return { ok: false, reason: 'UNSUPPORTED_PROTOCOL_VERSION' };
  const bad = validateReceivedBlock(payload.qodiqa, expectedKind);
  if (bad) return { ok: false, reason: bad };
  return { ok: true, version: 2, qodiqa: payload.qodiqa };
}

/**
 * Request binding for a V2 artifact. `request` must carry { method, target, rawHeaders, rawBody } (the received request, unparsed).
 * Constant details: nothing about which component differed leaves this function (V2-FREEZE 7.6).
 */
function verifyBindingV2(artifact, request) {
  const block = () => Object.freeze({ bound: false, reason: 'REQUEST_MISMATCH', details: Object.freeze({}) });
  const p = artifact && artifact.payload;
  if (!isObj(p) || !isObj(p.qodiqa) || !isObj(p.qodiqa.bind)) return block();
  if (!isValidRequestId(p.requestId)) return block();
  if (typeof p.requestHash !== 'string' || !HEX_RE.test(p.requestHash)) return block();
  if (!isObj(request) || typeof request.target !== 'string') return block();
  const crypto = require('crypto');
  let actual;
  try {
    actual = computeRequestHashV2({ method: request.method, target: request.target, rawHeaders: request.rawHeaders || [], body: request.rawBody || Buffer.alloc(0) }, p.qodiqa.bind.headers);
  } catch (e) {
    if (e instanceof BindingError) return block();
    throw e;
  }
  if (!crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(p.requestHash, 'hex'))) return block();
  return Object.freeze({ bound: true, requestId: p.requestId });
}

/** The output cap a V2 artifact carries (`payload.qodiqa.limits.maxTokens`), or null. Only call on an artifact that passed enforcement. */
function artifactMaxTokens(artifact) {
  const q = artifact && artifact.payload && artifact.payload.qodiqa;
  const m = q && q.limits && q.limits.maxTokens;
  return Number.isSafeInteger(m) && m >= 1 ? m : null;
}

class IssuanceError extends Error {
  constructor(reason, detail) { super(detail || reason); this.reason = reason; }
}

/** Validates the `v2` block of a /sign request and returns the normalized `payload.qodiqa` content (without `v`/`kind`). */
function validateIssuanceBlock(v2) {
  if (!isObj(v2)) throw new IssuanceError('INVALID_REQUEST', 'v2 must be an object');
  for (const k of Object.keys(v2)) if (!['bind', 'model', 'limits', 'crit'].includes(k)) throw new IssuanceError('INVALID_REQUEST', `unknown v2 field ${k}`);
  if (!isObj(v2.bind) || Object.keys(v2.bind).some((k) => k !== 'headers')) throw new IssuanceError('INVALID_REQUEST', 'v2.bind must be { headers: [...] }');
  try { validateBindHeaders(v2.bind.headers); } catch (e) { throw new IssuanceError('INVALID_REQUEST', e.reason || e.message); }
  const out = { bind: { headers: [...v2.bind.headers] } };
  if (v2.model !== undefined) {
    if (v2.model !== null && typeof v2.model !== 'string') throw new IssuanceError('INVALID_REQUEST', 'v2.model must be a string or null');
    out.model = v2.model;
  }
  if (v2.limits !== undefined) {
    if (!isObj(v2.limits)) throw new IssuanceError('INVALID_REQUEST', 'v2.limits must be an object');
    for (const k of Object.keys(v2.limits)) if (!['maxTokens', 'maxCostMicros'].includes(k)) throw new IssuanceError('INVALID_REQUEST', `unknown limit ${k}`);
    if (v2.limits.maxTokens !== undefined && !isSafeInt(v2.limits.maxTokens, 1)) throw new IssuanceError('INVALID_REQUEST', 'limits.maxTokens must be a positive safe integer');
    if (v2.limits.maxCostMicros !== undefined) throw new IssuanceError('INVALID_REQUEST', 'limits.maxCostMicros is not enforceable yet');
    out.limits = { ...v2.limits };
  }
  if (v2.crit !== undefined) {
    if (!Array.isArray(v2.crit) || v2.crit.length === 0 || new Set(v2.crit).size !== v2.crit.length) throw new IssuanceError('INVALID_REQUEST', 'v2.crit must be a non-empty list without duplicates');
    for (const c of v2.crit) if (typeof c !== 'string' || NEVER_CRITICAL.has(c) || !QODIQA_KEYS_REQUEST.has(c)) throw new IssuanceError('INVALID_REQUEST', 'bad v2.crit entry');
    out.crit = [...v2.crit];
  }
  return out;
}

module.exports = { artifactMaxTokens, classifyPayload, verifyBindingV2, validateIssuanceBlock, IssuanceError, acceptsV2, issuesV2, minProtocolVersion, buildDocument, hashDocument };
