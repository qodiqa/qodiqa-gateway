'use strict';

/**
 * Independent verifier — witness-cosigned checkpoint ANCHORS (customer-held anchor export).
 * NO src/ import, Node built-ins only. Restated from the documented contract (src/core/audit/anchoring/witness.js):
 *
 *   cosign digest = SHA-256( "QODIQA::WITNESS_COSIGN::V1" || canonical({ v:1, witnessId, checkpointId,
 *                   checkpointPayloadHash, chainLength, headHash, previousCheckpointHash, checkpointCreatedAt }) )
 *   cosignature   = Ed25519(digest), base64; witness public keys = SPKI DER, supplied OUT OF BAND (--witness-keys)
 *   anchor record = { anchorVersion: 1, checkpoint: { payload, payloadHash, signature }, cosignatures: [...], exportedAt }
 *
 * For each anchor, against TRUSTED checkpoint keys + TRUSTED witness keys + the audit log (+ the live checkpoint set):
 *   ANCHOR_CHECKPOINT_INVALID   the anchored checkpoint does not verify under a trusted checkpoint key (forged)
 *   ANCHOR_NOT_WITNESSED        fewer than --min-witnesses trusted cosignatures (wrong / missing trust anchor)
 *   ANCHORS_NOT_MONOTONIC       an anchor position decreases, or an equal position changes head
 *   CHAIN_ROLLED_BACK           the log is shorter than an anchored position (tail truncation / rollback)
 *   CHAIN_REWRITTEN             the log's entry at the anchored position does not have the anchored head hash
 *   CHECKPOINT_DELETED          the anchored checkpoint is missing from the live checkpoint sidecar
 *   CHECKPOINT_REPLACED         the live checkpoint with that id has a different payload hash (re-signed history)
 */

const crypto = require('crypto');
const { canonicalize } = require('./canonical');
const checkpoint = require('./checkpoint');

const COSIGN_DOMAIN = 'QODIQA::WITNESS_COSIGN::V1';
const STATEMENT_FIELDS = ['v', 'witnessId', 'checkpointId', 'checkpointPayloadHash', 'chainLength', 'headHash', 'previousCheckpointHash', 'checkpointCreatedAt'];

function statement(cp, witnessId) {
  const p = cp.payload;
  return { v: 1, witnessId, checkpointId: p.checkpointId, checkpointPayloadHash: cp.payloadHash, chainLength: p.chainLength,
    headHash: p.headHash, previousCheckpointHash: p.previousCheckpointHash ?? null, checkpointCreatedAt: p.createdAt };
}
function digest(st) {
  const c = {}; for (const f of STATEMENT_FIELDS) c[f] = st[f] === undefined ? null : st[f];
  return crypto.createHash('sha256').update(COSIGN_DOMAIN, 'utf8').update(canonicalize(c), 'utf8').digest();
}
function verifyCosig(cp, cosig, witnessKeys) {
  const list = Array.isArray(witnessKeys) ? witnessKeys : ((witnessKeys && witnessKeys.keys) || []);
  const k = list.find((x) => x.keyId === cosig.keyId);
  if (!k) return `WITNESS_KEY_UNTRUSTED:${cosig.keyId}`;
  if (['revoked', 'compromised'].includes(String(k.status || '').toLowerCase())) return `WITNESS_KEY_REVOKED:${cosig.keyId}`;
  if (k.witnessId && k.witnessId !== cosig.witnessId) return 'WITNESS_ID_MISMATCH';
  try {
    const pub = crypto.createPublicKey({ key: Buffer.from(k.publicKey, 'base64'), format: 'der', type: 'spki' });
    const sig = Buffer.from(String(cosig.signature), 'base64');
    if (sig.length !== 64) return 'WITNESS_SIGNATURE_MALFORMED';
    return crypto.verify(null, digest(statement(cp, cosig.witnessId)), pub, sig) ? null : 'WITNESS_SIGNATURE_INVALID';
  } catch (e) { return `WITNESS_VERIFY_ERROR:${e.message}`; }
}

/**
 * @param {object} o
 * @param {object[]} o.anchors               parsed anchor records
 * @param {string[]} o.entryHashes           hash of every log entry in order (index 0 = entry 1 of the verified range)
 * @param {number}   [o.offset=0]            lifetime count of entries BEFORE entryHashes[0] (pruned prefix)
 * @param {object[]|null} o.checkpoints      the live checkpoint sidecar records, or null when not supplied
 * @param {Function} o.resolve               checkpoint.keyResolver(--checkpoint-keys)
 * @param {object}   o.witnessKeys           --witness-keys body
 * @param {number}   [o.minWitnesses=1]
 */
function verifyAnchors({ anchors, entryHashes, offset = 0, checkpoints = null, resolve, witnessKeys, minWitnesses = 1 }) {
  const findings = [];
  const live = checkpoints ? new Map(checkpoints.map((c) => [c.payload && c.payload.checkpointId, c])) : null;
  const total = offset + entryHashes.length;
  let prev = null;
  anchors.forEach((a, i) => {
    const f = (code, detail) => findings.push({ anchor: i, code, detail });
    const cp = a && a.checkpoint;
    if (!cp || !cp.payload) { f('ANCHOR_MALFORMED', 'no checkpoint'); return; }
    const v = checkpoint.verifySignedCheckpoint(cp, resolve);
    if (!v.ok) f('ANCHOR_CHECKPOINT_INVALID', v.reason);
    const reasons = (a.cosignatures || []).map((c) => verifyCosig(cp, c, witnessKeys));
    // the quorum counts DISTINCT witnesses (by key and by id): a cosignature repeated in the record is one witness
    const seen = new Set();
    const tl = Array.isArray(witnessKeys) ? witnessKeys : ((witnessKeys && witnessKeys.keys) || []);
    const good = (a.cosignatures || []).filter((c, j) => {
      if (reasons[j] !== null) return false;
      const k = tl.find((x) => x.keyId === c.keyId); const m = k && k.publicKey ? `pub:${Buffer.from(String(k.publicKey), 'base64').toString('hex')}` : c.keyId; const id = `id:${c.witnessId}`;
      if (seen.has(m) || seen.has(id)) return false; seen.add(m); seen.add(id); return true;
    }).length;
    if (good < minWitnesses) f('ANCHOR_NOT_WITNESSED', `${good}/${minWitnesses} trusted cosignatures (${reasons.filter(Boolean).join(', ') || 'none'})`);
    const { chainLength: n, headHash, checkpointId } = cp.payload;
    if (prev && (n < prev.n || (n === prev.n && headHash !== prev.h))) f('ANCHORS_NOT_MONOTONIC', `position ${n} after ${prev.n}`);
    prev = { n, h: headHash };
    if (total < n) f('CHAIN_ROLLED_BACK', `the log holds ${total} entries; anchored checkpoint ${checkpointId} vouches for ${n}`);
    else if (n > offset) {
      const h = entryHashes[n - offset - 1];
      if (h !== headHash) f('CHAIN_REWRITTEN', `entry ${n} is ${h || 'missing'}; anchored head is ${headHash}`);
    }
    if (live) {
      const l = live.get(checkpointId);
      if (!l) f('CHECKPOINT_DELETED', `anchored checkpoint ${checkpointId} (entry ${n}) is absent from the checkpoint sidecar`);
      else if (l.payloadHash !== cp.payloadHash) f('CHECKPOINT_REPLACED', `sidecar ${checkpointId} payloadHash ${l.payloadHash} ≠ anchored ${cp.payloadHash}`);
    }
  });
  return { valid: findings.length === 0, anchors: anchors.length, findings };
}

module.exports = { COSIGN_DOMAIN, STATEMENT_FIELDS, statement, digest, verifyCosig, verifyAnchors };
