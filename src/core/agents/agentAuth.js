'use strict';

/**
 * Who is calling? - the per-request identity check for agent callers. Used by every endpoint that acts on behalf of an agent (the action
 * authorisation, the tool proxy): there is no cache and no "remembered" login - each request is checked against the stores.
 *
 *   1. the (tenant, agent, session) triple must be live: the agent is active, the session is active and not expired (agentStore.checkSession);
 *      an unknown, foreign-tenant or foreign-agent session answers identically (AGENT_SESSION_UNKNOWN);
 *   2. if the agent has registered a public key, the request must carry a PROOF OF POSSESSION: an Ed25519 signature by that key over
 *      SHA-256("QODIQA::AGENT_REQUEST::V1" || JCS-like canonical { v, tenantId, agentId, sessionId, requestId }) - a leaked or guessed session id alone
 *      does not let anyone act as the agent (AGENT_PROOF_REQUIRED / AGENT_PROOF_INVALID). The requestId is the one the action artifact will consume, so a
 *      proof cannot be replayed for another request.
 *
 * PRIVILEGE SEPARATION (user <-> agent). An agent is NOT an operator and NOT the user it acts for:
 *   * it is not an RBAC principal - no role in src/core/rbac/roles.js grants anything to an agent identity, and the admin plane never accepts one;
 *   * what it may do is exactly allowedActionClasses of ITS identity (further narrowed by tenant policy and by the registered tool), never the rights of
 *     ownerUserId; the user it acts for is recorded (`actsFor`) so the evidence says on whose behalf, but ownership is not an authority;
 *   * a session cannot exceed its agent (agentStore.startSession takes the minimum).
 */

const crypto = require('crypto');
const agents = require('./agentStore');

const PROOF_DOMAIN = 'QODIQA::AGENT_REQUEST::V1';
const HEX_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** The digest the agent signs to prove possession of its key for one request. */
function proofDigest({ tenantId, agentId, sessionId, requestId }) {
  const canonical = JSON.stringify({ agentId, requestId, sessionId, tenantId, v: 1 });      // keys in sorted order; all values are plain strings
  return crypto.createHash('sha256').update(PROOF_DOMAIN, 'utf8').update(canonical, 'utf8').digest();
}

/** Sign a proof (used by the agent runtime and by tests). privateKey: a KeyObject or PKCS8 DER Buffer. */
function signProof(ctx, privateKey) {
  const key = Buffer.isBuffer(privateKey) ? crypto.createPrivateKey({ key: privateKey, format: 'der', type: 'pkcs8' }) : privateKey;
  return crypto.sign(null, proofDigest(ctx), key).toString('base64');
}

function _verifySig(publicKeySpkiB64, digest, sigB64) {
  try {
    const sig = Buffer.from(String(sigB64), 'base64');
    if (sig.length !== 64 || sig.toString('base64') !== sigB64) return false;
    return crypto.verify(null, digest, crypto.createPublicKey({ key: Buffer.from(publicKeySpkiB64, 'base64'), format: 'der', type: 'spki' }), sig);
  } catch { return false; }
}

/**
 * @param {{ tenantId: string, agentId: string, sessionId: string, requestId?: string, proof?: string }} caller
 * @returns {Promise<{ ok: true, agent: object, session: object, actsFor: string|null, allowedActionClasses: string[] } | { ok: false, reason: string }>}
 */
async function verifyAgentCaller(caller) {
  const c = caller || {};
  const live = await agents.checkSession(c.tenantId, c.agentId, c.sessionId);
  if (!live.ok) return live;
  if (live.agent.publicKey) {
    if (typeof c.proof !== 'string' || !c.proof) return { ok: false, reason: 'AGENT_PROOF_REQUIRED' };
    if (typeof c.requestId !== 'string' || !HEX_UUID.test(c.requestId)) return { ok: false, reason: 'AGENT_PROOF_INVALID' };
    if (!_verifySig(live.agent.publicKey, proofDigest({ tenantId: c.tenantId, agentId: c.agentId, sessionId: c.sessionId, requestId: c.requestId.toLowerCase() }), c.proof)) return { ok: false, reason: 'AGENT_PROOF_INVALID' };
  }
  return { ok: true, agent: live.agent, session: live.session, actsFor: live.agent.ownerUserId, allowedActionClasses: [...live.agent.allowedActionClasses] };
}

module.exports = { PROOF_DOMAIN, proofDigest, signProof, verifyAgentCaller };
