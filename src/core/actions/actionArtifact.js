'use strict';

/**
 * The action artifact.
 *
 * An action artifact authorises ONE action of ONE agent session. It is signed with the tenant's artifact key but in a DIFFERENT domain, so an ordinary
 * artifact never verifies as an action artifact (and vice versa) even under the same key:
 *
 *   envelopeHash = SHA-256( "QODIQA::ACTION_ARTIFACT::V1" || canonical({ expiry, payload, publicKeyId, timestamp }) )   signature: Ed25519, canonical base64 (88 chars)
 *   payload      = { requestId, tenantId, qodiqa: { v: 2, kind: "action", bind: { headers: [] }, agentId, sessionId, seq, actionHash, approvalRef?, crit? } }
 *
 * No requestHash / policyHash / callerContext: it binds an ACTION (actionHash), not an HTTP request; the agent identity replaces callerContext. It is issued
 * only by POST /v1/actions/authorize (/sign refuses `qodiqa` in caller data). verifyActionArtifact checks everything about the artifact itself; the executor
 * (src/core/actions/executor.js) adds the checks that need state (nonce, session sequence, registry, agent liveness).
 */

const crypto = require('crypto');
const { canonicalJcsP1, JcsError } = require('../../validation/jcsP1');
const { sign, verify } = require('../../infra/crypto/ed25519');
const { checkTimestamp, checkSkew, checkExpiry, MAX_SKEW_MS } = require('../../validation/timeCheck');

const ACTION_ARTIFACT_DOMAIN = 'QODIQA::ACTION_ARTIFACT::V1';
const ENVELOPE_KEYS = ['expiry', 'payload', 'publicKeyId', 'signature', 'timestamp'];
const QODIQA_KEYS = new Set(['v', 'kind', 'bind', 'agentId', 'sessionId', 'seq', 'actionHash', 'approvalRef', 'crit']);
const PAYLOAD_KEYS = ['qodiqa', 'requestId', 'tenantId'];
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const CANONICAL_SIG_RE = /^[A-Za-z0-9+/]{86}==$/;
const MAX_ACTION_TTL_MS = 60_000;                       // as every artifact: at most 60 s between issuance and expiry

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function envelopeDigest({ expiry, payload, publicKeyId, timestamp }) {
  return crypto.createHash('sha256').update(ACTION_ARTIFACT_DOMAIN, 'utf8').update(canonicalJcsP1({ expiry, payload, publicKeyId, timestamp }, { maxBytes: 65_536 }), 'utf8').digest();
}

/** The payload of an action artifact (validated shape). */
function buildActionPayload({ requestId, tenantId, agentId, sessionId, seq, actionHash, approvalRef }) {
  const q = { v: 2, kind: 'action', bind: { headers: [] }, agentId, sessionId, seq, actionHash };
  if (approvalRef !== undefined && approvalRef !== null) q.approvalRef = approvalRef;
  const payload = { requestId, tenantId, qodiqa: q };
  const bad = shapeProblem(payload);
  if (bad) throw new TypeError(`buildActionPayload: ${bad}`);
  return payload;
}

/** @returns {string|null} what is wrong with the payload shape, or null */
function shapeProblem(payload) {
  if (!isObj(payload) || Object.keys(payload).sort().join(',') !== PAYLOAD_KEYS.join(',')) return 'payload must be exactly { requestId, tenantId, qodiqa }';
  if (typeof payload.requestId !== 'string' || !UUID_V4.test(payload.requestId)) return 'requestId must be a UUID v4';
  if (typeof payload.tenantId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(payload.tenantId)) return 'tenantId';
  const q = payload.qodiqa;
  if (!isObj(q)) return 'qodiqa';
  for (const k of Object.keys(q)) if (!QODIQA_KEYS.has(k)) return `qodiqa.${k} is not understood`;
  if (q.v !== 2 || q.kind !== 'action') return 'qodiqa must be { v: 2, kind: "action" }';
  if (!isObj(q.bind) || Object.keys(q.bind).join(',') !== 'headers' || !Array.isArray(q.bind.headers) || q.bind.headers.length !== 0) return 'qodiqa.bind must be { headers: [] }';
  if (typeof q.agentId !== 'string' || !UUID_V4.test(q.agentId)) return 'qodiqa.agentId';
  if (typeof q.sessionId !== 'string' || !UUID_V4.test(q.sessionId)) return 'qodiqa.sessionId';
  if (!Number.isSafeInteger(q.seq) || q.seq < 1) return 'qodiqa.seq';
  if (typeof q.actionHash !== 'string' || !HEX64.test(q.actionHash)) return 'qodiqa.actionHash';
  if (q.approvalRef !== undefined && !(typeof q.approvalRef === 'string' && q.approvalRef.length > 0 && q.approvalRef.length <= 128)) return 'qodiqa.approvalRef';
  if (q.crit !== undefined) return 'qodiqa.crit is not supported';
  return null;
}

function signActionArtifact({ payload, timestamp, expiry, publicKeyId }, privDer) {
  const bad = shapeProblem(payload);
  if (bad) throw new TypeError(`signActionArtifact: ${bad}`);
  if (!Number.isSafeInteger(timestamp) || !Number.isSafeInteger(expiry) || timestamp <= 0 || expiry <= timestamp) throw new TypeError('signActionArtifact: timestamp < expiry, both positive integers');
  if (expiry - timestamp > MAX_ACTION_TTL_MS) throw new TypeError(`signActionArtifact: an action artifact lives at most ${MAX_ACTION_TTL_MS} ms`);
  if (typeof publicKeyId !== 'string' || !publicKeyId.trim()) throw new TypeError('signActionArtifact: publicKeyId');
  if (!Buffer.isBuffer(privDer) || !privDer.length) throw new TypeError('signActionArtifact: privDer');
  const signature = sign(envelopeDigest({ expiry, payload, publicKeyId, timestamp }), privDer);
  return Object.freeze({ expiry, payload, publicKeyId, signature, timestamp });
}

/** As signActionArtifact for a key that never leaves its provider (Vault Transit / HSM): nativeSign(publicKeyId, digestBuffer) -> 64-byte signature. */
async function signActionArtifactNative({ payload, timestamp, expiry, publicKeyId }, nativeSign) {
  const bad = shapeProblem(payload);
  if (bad) throw new TypeError(`signActionArtifactNative: ${bad}`);
  if (!Number.isSafeInteger(timestamp) || !Number.isSafeInteger(expiry) || timestamp <= 0 || expiry <= timestamp) throw new TypeError('signActionArtifactNative: timestamp < expiry, both positive integers');
  if (expiry - timestamp > MAX_ACTION_TTL_MS) throw new TypeError(`signActionArtifactNative: an action artifact lives at most ${MAX_ACTION_TTL_MS} ms`);
  if (typeof publicKeyId !== 'string' || !publicKeyId.trim() || typeof nativeSign !== 'function') throw new TypeError('signActionArtifactNative: publicKeyId, nativeSign');
  const sig = await nativeSign(publicKeyId, envelopeDigest({ expiry, payload, publicKeyId, timestamp }));
  if (!Buffer.isBuffer(sig) || sig.length !== 64) throw new Error('signActionArtifactNative: the native signing provider did not return a 64-byte Ed25519 signature');
  return Object.freeze({ expiry, payload, publicKeyId, signature: sig.toString('base64'), timestamp });
}

/**
 * Verify the artifact itself (no state). Order is deliberate: shape, kind, signature - then time and key lifecycle, which only a valid signer learns about.
 * @param {object} artifact
 * @param {{ now?: number, resolveKey?: (id:string)=>({found:boolean, pubDer?:Buffer, clientId?:string, status?:string, timeline?:object}), maxSkewMs?: number }} [o]
 * @returns {{ ok: true, payload: object, actionHash: string, tenantId: string, agentId: string, sessionId: string, seq: number, requestId: string, publicKeyId: string, expiry: number }
 *          | { ok: false, reason: string }}
 */
function verifyActionArtifact(artifact, { now = Date.now(), resolveKey = require('../../validation/resolveKey').resolveKey, maxSkewMs = MAX_SKEW_MS } = {}) {
  const no = (reason) => ({ ok: false, reason });
  if (!isObj(artifact) || Object.keys(artifact).sort().join(',') !== ENVELOPE_KEYS.join(',')) return no('ACTION_ARTIFACT_INVALID');
  const { payload, signature, timestamp, expiry, publicKeyId } = artifact;
  if (!isObj(payload) || typeof signature !== 'string' || !CANONICAL_SIG_RE.test(signature) || Buffer.from(signature, 'base64').toString('base64') !== signature
    || !Number.isSafeInteger(timestamp) || !Number.isSafeInteger(expiry) || timestamp <= 0 || timestamp >= expiry || typeof publicKeyId !== 'string' || !publicKeyId.trim()) return no('ACTION_ARTIFACT_INVALID');
  // an ordinary artifact (no qodiqa block, or kind "request") is the wrong kind - never an action artifact
  const q = payload.qodiqa;
  if (!isObj(q) || q.kind !== 'action') return no('WRONG_ARTIFACT_KIND');
  if (shapeProblem(payload)) return no('ACTION_ARTIFACT_INVALID');
  const key = resolveKey(publicKeyId);
  let digest;
  try { digest = envelopeDigest({ expiry, payload, publicKeyId, timestamp }); } catch (e) { if (e instanceof JcsError) return no('ACTION_ARTIFACT_INVALID'); throw e; }
  if (!verify(digest, signature, key.found ? key.pubDer : null)) return no('ACTION_SIGNATURE_INVALID');          // an unknown key and a wrong signature look the same
  if (payload.tenantId !== key.clientId) return no('ACTION_TENANT_MISMATCH');                                     // tenant A's key cannot speak for tenant B
  if (expiry - timestamp > MAX_ACTION_TTL_MS) return no('ACTION_ARTIFACT_INVALID');
  const ts = checkTimestamp(timestamp, now); if (!ts.valid) return no(ts.reason);
  const ex = checkExpiry(expiry, now); if (!ex.valid) return no(ex.reason);
  const sk = checkSkew(timestamp, now, maxSkewMs); if (!sk.valid) return no(sk.reason);
  // key lifecycle exactly as for ordinary artifacts (a retired key verifies only what it signed before retirement; a revoked / archived key never)
  let timeline;
  try { timeline = require('../signing/keyStatusTimeline').effective(publicKeyId, key.timeline || { status: key.status }); } catch (e) { if (e && e.name === 'ControlPlaneError') return no(e.code); throw e; }
  const lc = require('../../validation/keyLifecycle').checkExecution(timeline, ts.tsMs, now);
  if (!lc.valid) return no(lc.reason);
  return { ok: true, payload, actionHash: q.actionHash, tenantId: payload.tenantId, agentId: q.agentId, sessionId: q.sessionId, seq: q.seq, requestId: payload.requestId, publicKeyId, expiry };
}

module.exports = { ACTION_ARTIFACT_DOMAIN, MAX_ACTION_TTL_MS, envelopeDigest, buildActionPayload, signActionArtifact, signActionArtifactNative, verifyActionArtifact, shapeProblem };
