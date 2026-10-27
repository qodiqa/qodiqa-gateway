'use strict';

/**
 * The approval statement: what the gateway signs AFTER the approver's MFA step-up, so that "who approved what, when"
 * can be checked offline with the tenant's public key.
 *
 *   digest    = SHA-256( "QODIQA::APPROVAL::V1" || JCS-P1({ expiry, payload, publicKeyId, timestamp }) )         (the 32 bytes that are signed)
 *   envelope  = { expiry, payload, publicKeyId, signature, timestamp }          timestamp = when decided, expiry = payload.expiresAt (ms)
 *   payload   = { v: 1, kind: "approval", approvalId, tenantId, actionHash, agentId, sessionId, seq, requesterId, approverId, decision: "APPROVED" | "DENIED",
 *                 notBefore, expiresAt, mfa: "step-up", policyRuleId }
 *
 * An approval is bound to ONE action by `actionHash` (V2-FREEZE section 5.1) and to one position in one session (`sessionId`, `seq`); it is valid between `notBefore` and
 * `expiresAt` (both integer milliseconds). The approver is never the requester (`approverId != requesterId`). A DENIED statement is signed too: the refusal is evidence.
 *
 * verifyApproval checks, in this order (first failure wins):
 *   shape -> signature -> tenant -> expectations (the action it is presented for) -> decision -> window
 * Reasons (V2-FREEZE 7.5): APPROVAL_INVALID, APPROVAL_EXPIRED. (APPROVAL_REQUIRED is the absence of an approval, decided by the caller.)
 */

const crypto = require('crypto');
const { canonicalJcsP1, JcsError } = require('../../validation/jcsP1');
const { sign, verify } = require('../../infra/crypto/ed25519');

const APPROVAL_DOMAIN = 'QODIQA::APPROVAL::V1';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SIG_RE = /^[A-Za-z0-9+/]{86}==$/;
const TENANT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const ENVELOPE_KEYS = 'expiry,payload,publicKeyId,signature,timestamp';
const PAYLOAD_KEYS = 'actionHash,agentId,approvalId,approverId,decision,expiresAt,kind,mfa,notBefore,policyRuleId,requesterId,seq,sessionId,tenantId,v';
const MAX_SKEW_MS = 5 * 60_000;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi;
const idStr = (v) => typeof v === 'string' && v.length >= 1 && v.length <= 256 && !/[\u0000-\u001f\u007f]/.test(v);

class ApprovalTokenError extends Error { constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.name = 'ApprovalTokenError'; this.code = code; } }

function envelopeDigest({ expiry, payload, publicKeyId, timestamp }) {
  return crypto.createHash('sha256').update(APPROVAL_DOMAIN, 'utf8').update(canonicalJcsP1({ expiry, payload, publicKeyId, timestamp }, { maxBytes: 65_536 }), 'utf8').digest();
}
const digestHex = (e) => envelopeDigest(e).toString('hex');

/** @returns {string|null} what is wrong with the payload shape, or null */
function shapeProblem(p) {
  if (!isObj(p) || Object.keys(p).sort().join(',') !== PAYLOAD_KEYS) return 'payload members';
  if (p.v !== 1 || p.kind !== 'approval') return 'v / kind';
  if (typeof p.approvalId !== 'string' || !UUID_V4.test(p.approvalId)) return 'approvalId';
  if (typeof p.tenantId !== 'string' || !TENANT_RE.test(p.tenantId)) return 'tenantId';
  if (typeof p.actionHash !== 'string' || !HEX64.test(p.actionHash)) return 'actionHash';
  if (typeof p.agentId !== 'string' || !UUID_V4.test(p.agentId) || typeof p.sessionId !== 'string' || !UUID_V4.test(p.sessionId)) return 'agentId / sessionId';
  if (!isInt(p.seq, 1, Number.MAX_SAFE_INTEGER)) return 'seq';
  if (!idStr(p.requesterId) || !idStr(p.approverId) || !idStr(p.policyRuleId)) return 'requesterId / approverId / policyRuleId';
  if (p.decision !== 'APPROVED' && p.decision !== 'DENIED') return 'decision';
  if (!isInt(p.notBefore, 1, Number.MAX_SAFE_INTEGER) || !isInt(p.expiresAt, 1, Number.MAX_SAFE_INTEGER) || p.expiresAt <= p.notBefore) return 'notBefore / expiresAt';
  if (p.mfa !== 'step-up') return 'mfa';
  return null;
}

function _check({ payload, timestamp, expiry, publicKeyId }) {
  const bad = shapeProblem(payload);
  if (bad) throw new ApprovalTokenError('APPROVAL_INVALID', bad);
  if (!isInt(timestamp, 1, Number.MAX_SAFE_INTEGER) || expiry !== payload.expiresAt || expiry <= timestamp) throw new ApprovalTokenError('APPROVAL_INVALID', 'timestamp < expiry = expiresAt');
  if (payload.approverId === payload.requesterId) throw new ApprovalTokenError('APPROVAL_INVALID', 'the approver is the requester');
  if (typeof publicKeyId !== 'string' || !publicKeyId.trim()) throw new ApprovalTokenError('APPROVAL_INVALID', 'publicKeyId');
}

function signApproval(fields, privDer) {
  _check(fields);
  const { payload, timestamp, expiry, publicKeyId } = fields;
  return Object.freeze({ expiry, payload, publicKeyId, signature: sign(envelopeDigest({ expiry, payload, publicKeyId, timestamp }), privDer), timestamp });
}

async function signApprovalNative(fields, nativeSign) {
  _check(fields);
  const { payload, timestamp, expiry, publicKeyId } = fields;
  const sig = await nativeSign(publicKeyId, envelopeDigest({ expiry, payload, publicKeyId, timestamp }));
  if (!Buffer.isBuffer(sig) || sig.length !== 64) throw new Error('signApprovalNative: the native signing provider did not return a 64-byte Ed25519 signature');
  return Object.freeze({ expiry, payload, publicKeyId, signature: sig.toString('base64'), timestamp });
}

/**
 * @param {object} envelope
 * @param {{ now?: number, resolveKey: Function, expect?: { actionHash?, tenantId?, agentId?, sessionId?, seq?, approvalId? }, maxSkewMs?: number, keyCheck?: Function }} o
 * @returns {{ ok: true, payload: object, digest: string } | { ok: false, reason: 'APPROVAL_INVALID'|'APPROVAL_EXPIRED', detail?: string }}
 */
function verifyApproval(envelope, { now = Date.now(), resolveKey, expect = {}, maxSkewMs = MAX_SKEW_MS, keyCheck } = {}) {
  const no = (reason, detail) => ({ ok: false, reason, ...(detail ? { detail } : {}) });
  if (!isObj(envelope) || Object.keys(envelope).sort().join(',') !== ENVELOPE_KEYS) return no('APPROVAL_INVALID', 'envelope members');
  const p = envelope.payload;
  const bad = shapeProblem(p);
  if (bad) return no('APPROVAL_INVALID', bad);
  if (typeof envelope.signature !== 'string' || !SIG_RE.test(envelope.signature) || Buffer.from(envelope.signature, 'base64').toString('base64') !== envelope.signature) return no('APPROVAL_INVALID', 'signature encoding');
  if (!isInt(envelope.timestamp, 1, Number.MAX_SAFE_INTEGER) || envelope.expiry !== p.expiresAt || envelope.expiry <= envelope.timestamp || typeof envelope.publicKeyId !== 'string' || !envelope.publicKeyId.trim()) return no('APPROVAL_INVALID', 'timestamp / expiry');
  let digest;
  try { digest = envelopeDigest(envelope); } catch (e) { if (e instanceof JcsError) return no('APPROVAL_INVALID', 'not canonicalisable'); throw e; }
  const key = resolveKey(envelope.publicKeyId);
  if (!key || !key.found || !verify(digest, envelope.signature, key.pubDer)) return no('APPROVAL_INVALID', 'signature');
  if (p.tenantId !== key.clientId) return no('APPROVAL_INVALID', 'tenant');
  for (const k of ['actionHash', 'tenantId', 'agentId', 'sessionId', 'seq', 'approvalId']) if (expect[k] !== undefined && expect[k] !== p[k]) return no('APPROVAL_INVALID', `not for this ${k}`);
  if (p.approverId === p.requesterId) return no('APPROVAL_INVALID', 'the approver is the requester');
  if (p.decision !== 'APPROVED') return no('APPROVAL_INVALID', 'denied');
  if (envelope.timestamp > now + maxSkewMs) return no('APPROVAL_INVALID', 'decided in the future');
  if (now < p.notBefore) return no('APPROVAL_INVALID', 'not yet valid');
  if (now >= p.expiresAt) return no('APPROVAL_EXPIRED');
  if (keyCheck) { const k = keyCheck({ publicKeyId: envelope.publicKeyId, timestamp: envelope.timestamp, now }); if (k) return no('APPROVAL_INVALID', k); }
  return { ok: true, payload: p, digest: digest.toString('hex') };
}

module.exports = { APPROVAL_DOMAIN, MAX_SKEW_MS, ApprovalTokenError, envelopeDigest, digestHex, shapeProblem, signApproval, signApprovalNative, verifyApproval };
