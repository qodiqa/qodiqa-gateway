import crypto from 'node:crypto';
import { ValidationError } from '../errors.js';

/** Domain of the agent's proof of possession. */
export const AGENT_PROOF_DOMAIN = 'QODIQA::AGENT_REQUEST::V1';

export interface AgentProofContext {
  tenantId: string;
  agentId: string;
  sessionId: string;
  /** The `requestId` you pass to `actions.authorize()` (a UUID v4) - the proof is for THIS request only. */
  requestId: string;
}

/** SHA-256( "QODIQA::AGENT_REQUEST::V1" || {"agentId":..,"requestId":..,"sessionId":..,"tenantId":..,"v":1} ). */
export function agentProofDigest(ctx: AgentProofContext): Buffer {
  for (const k of ['tenantId', 'agentId', 'sessionId', 'requestId'] as const) {
    if (typeof ctx[k] !== 'string' || ctx[k] === '') throw new ValidationError(`"${k}" is required to sign an agent proof.`);
  }
  const canonical = JSON.stringify({ agentId: ctx.agentId, requestId: ctx.requestId, sessionId: ctx.sessionId, tenantId: ctx.tenantId, v: 1 });
  return crypto.createHash('sha256').update(AGENT_PROOF_DOMAIN, 'utf8').update(canonical, 'utf8').digest();
}

/**
 * Sign the proof of possession an agent with a registered public key must attach to every authorisation request (`proof`). `privateKey` is a KeyObject, a PEM string or a
 * PKCS#8 DER buffer; the signature is Ed25519 over the digest, base64.
 */
export function signAgentProof(ctx: AgentProofContext, privateKey: crypto.KeyObject | string | Buffer): string {
  let key: crypto.KeyObject;
  if (typeof privateKey === 'string') key = crypto.createPrivateKey(privateKey);
  else if (Buffer.isBuffer(privateKey)) key = crypto.createPrivateKey({ key: privateKey, format: 'der', type: 'pkcs8' });
  else key = privateKey;
  return crypto.sign(null, agentProofDigest(ctx), key).toString('base64');
}

/** A fresh Ed25519 key pair for an agent: register `publicKey` (base64 SPKI) with `agents.create()`, keep `privateKey` in the agent runtime. */
export function generateAgentKeyPair(): { publicKey: string; privateKey: crypto.KeyObject } {
  const kp = crypto.generateKeyPairSync('ed25519');
  return { publicKey: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'), privateKey: kp.privateKey };
}
