'use strict';

/**
 * — customer-held ANCHORS for signed audit checkpoints.
 *
 * publishAnchor(signedCheckpoint)  co-signs the checkpoint with every configured witness (./witness.js) and appends one
 *   anchor record to QODIQA_ANCHOR_EXPORT_PATH — an append-only JSONL file meant to live OUTSIDE the gateway host's
 *   control (a customer-mounted volume, a WORM bucket sync target, a separate system). Record:
 *     { anchorVersion: 1, checkpoint: { payload, payloadHash, signature }, cosignatures: [...], exportedAt }
 *
 * verifyChainAgainstAnchors(...)  the detection side, used at boot (fail-closed in production when anchoring is
 *   configured) and restated independently in scripts/audit-repro/verify/anchors.js. For every anchor it proves:
 *     ANCHOR_CHECKPOINT_INVALID     the anchored checkpoint's own signature verifies under a TRUSTED checkpoint key
 *     ANCHOR_NOT_WITNESSED          ≥ minWitnesses cosignatures verify under TRUSTED witness keys
 *     CHAIN_ROLLED_BACK             the live chain is at least as long as the anchored position (tail truncation /
 *                                   rollback below an anchored point is detected)
 *     CHAIN_REWRITTEN               the live entry at the anchored position has the anchored head hash
 *     CHECKPOINT_DELETED            the anchored checkpoint is still present in the live checkpoint set
 *     CHECKPOINT_REPLACED           …with the SAME payload hash (a re-signed replacement history is caught even though
 *                                   it verifies under the real checkpoint key)
 *     ANCHORS_NOT_MONOTONIC         anchor positions never decrease, and an equal position never changes head
 */

const fs = require('fs');
const path = require('path');
const { verifyCheckpoint } = require('../checkpoint/checkpoint');
const { statementFor, verifyCosignature, witnessesFromEnv, minWitnessesFromEnv } = require('./witness');

function exportPathFromEnv(env = process.env) { return env.QODIQA_ANCHOR_EXPORT_PATH || null; }

function readAnchors(file) {
  if (!file || !fs.existsSync(file)) return [];
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i]) continue;
    try { out.push(JSON.parse(lines[i])); } catch {
      if (i >= lines.length - 2) break; // torn final line from a crash mid-append: ignored, like the checkpoint sidecar
      const e = new Error(`AUDIT_ANCHOR_EXPORT_CORRUPT: line ${i + 1} of ${file} is not JSON`); e.code = 'AUDIT_ANCHOR_EXPORT_CORRUPT'; throw e;
    }
  }
  return out;
}

/**
 * Co-sign with every witness and append the anchor. Witness refusals/failures are reported, never hidden: a refused
 * cosignature (rollback/equivocation) is exactly the signal an operator must see.
 * @param {object} [o.trustedWitnessKeys]  trusted witness keys for the publish-time check (default: QODIQA_WITNESS_PUBLIC_KEYS;
 *                                          no keys = no publish-time check)
 * @returns {Promise<{ record: object|null, errors: {witnessId, code, message}[] }>}
 * ER 2026-10-06: async — an exec witness no longer blocks the event loop while it co-signs.
 */
// phase 7: the trusted witness key set used to check each cosignature AT PUBLISH TIME. Unreadable
// is reported (never thrown): the anchor is still exported, and the boot / offline verifier remains the authority.
function _publishTrustSet(explicit) {
  if (explicit !== undefined) return { keys: explicit };
  try { return { keys: trustedWitnessKeysFromEnv() }; } catch (e) { return { keys: { keys: [] }, error: e }; }
}

// (M8): offer the exported predecessors of `signed` (walking previousCheckpointHash back through the export,
// at most MAX_CATCHUP) to a witness, oldest first. Errors on individual predecessors are ignored here: the witness's own
// rules decide, and the caller retries `signed` and reports the refusal if the gap could not be closed.
const MAX_CATCHUP = 32;
async function _catchUp(w, signed, exportPath) {
  const byHash = new Map();
  for (const a of readAnchors(exportPath)) if (a && a.checkpoint && a.checkpoint.payloadHash) byHash.set(a.checkpoint.payloadHash, a.checkpoint);
  const chain = [];
  let h = signed.payload && signed.payload.previousCheckpointHash;
  while (h && byHash.has(h) && chain.length < MAX_CATCHUP) { const cp = byHash.get(h); chain.push(cp); h = cp.payload.previousCheckpointHash; }
  for (const cp of chain.reverse()) { try { await w.cosign(cp); } catch { /* the witness's rules decide; see caller */ } }
}

// (D-7): the public key material behind a trusted key id - two ids for one key are one witness.
function _pubOf(list, keyId) { const k = (list || []).find((x) => x && x.keyId === keyId); return k && k.publicKey ? `pub:${Buffer.from(String(k.publicKey), 'base64').toString('hex')}` : null; }

async function publishAnchor(signedCheckpoint, { witnesses = witnessesFromEnv(), exportPath = exportPathFromEnv(), trustedWitnessKeys, requireCosignature = false, minWitnesses } = {}) {
  const cosignatures = []; const errors = []; let verifiedCount = 0; const _countedKeys = new Set();
  const trust = _publishTrustSet(trustedWitnessKeys);
  if (trust.error) errors.push({ witnessId: null, code: 'WITNESS_TRUST_SET_UNREADABLE', message: `cosignatures not checked at publish: ${trust.error.message}` });
  const trustedList = Array.isArray(trust.keys) ? trust.keys : ((trust.keys && trust.keys.keys) || []);
  for (const w of witnesses) {
    let c;
    try { c = await w.cosign(signedCheckpoint); } catch (e0) {
      // (M8): a witness now refuses a checkpoint that does not chain to the one it witnessed last. A genuine chain
      // hits that when an earlier checkpoint never reached this witness (timeout/outage): catch up by offering the
      // missed predecessors from the export, oldest first — each is itself subject to the witness's rules, so this
      // cannot obtain a cosignature the witness would not give — then retry once. Otherwise the refusal stands.
      let e = e0;
      if (e0 && e0.code === 'WITNESS_FORK_REFUSED' && exportPath) {
        try { await _catchUp(w, signedCheckpoint, exportPath); c = await w.cosign(signedCheckpoint); } catch (e1) { e = e1 && e1.code === 'WITNESS_FORK_REFUSED' ? e1 : e0; }
      }
      if (!c) { errors.push({ witnessId: w.witnessId, code: e.code || 'WITNESS_ERROR', message: e.message }); continue; }
    }
    cosignatures.push(c);
    let verifiedHere = trustedList.length === 0 && !trust.error;   // ANCHOR-1: with no keys configured every cosignature counts (as before); D-8: an UNREADABLE trust set counts none
    // phase 7: a cosignature that does not verify for THIS checkpoint's statement under the trusted
    // witness keys (wrong key, a cosignature replayed from another checkpoint, a witness signing something else) used
    // to surface only at the next boot as ANCHOR_NOT_WITNESSED. It is now reported immediately. It is still kept in the
    // export record as evidence (the customer's trust set may differ); verifiers ignore it either way.
    if (trustedList.length) {
      const v = verifyCosignature(statementFor(signedCheckpoint, w.witnessId), c, trust.keys);
      if (!v.ok) errors.push({ witnessId: w.witnessId, code: 'WITNESS_COSIGNATURE_UNVERIFIED', message: `cosignature from ${w.witnessId} does not verify for checkpoint ${signedCheckpoint.payload && signedCheckpoint.payload.checkpointId}: ${v.reason}` });
      else verifiedHere = true;
    }
    const _mat = _pubOf(trustedList, c.keyId) || c.keyId;
    if (verifiedHere && !_countedKeys.has(_mat)) { _countedKeys.add(_mat); verifiedCount++; }   // one witness KEY (its material, not its label) counts once
  }
  if (!exportPath) return { record: null, errors };
  // / ANCHOR-1: with witnesses configured and NO
  // cosignature that verifies under the trusted witness keys, write nothing — the checkpoint is HELD (it stays in the
  // live checkpoint set) and exported later, in chain order, once a witness cosigns it (publishAnchorBacklog). An
  // unwitnessed record turned a witness outage into a production boot failure (ANCHOR_NOT_WITNESSED) no bootstrap clears.
  // with several witnesses configured the anchor needs min(minWitnesses, witnesses) verified cosignatures — one compromised or
  // unreachable witness can neither anchor alone nor (below the minimum) let the checkpoint through unwitnessed.
  const need = Math.min(witnesses.length, Number.isInteger(minWitnesses) && minWitnesses > 0 ? minWitnesses : minWitnessesFromEnv(process.env, witnesses.length));
  if (requireCosignature && witnesses.length > 0 && verifiedCount < Math.max(1, need)) {
    if (verifiedCount > 0) errors.push({ witnessId: null, code: 'WITNESS_QUORUM_NOT_MET', message: `${verifiedCount} verified cosignature(s), ${need} required: the checkpoint is held` });
    return { record: null, errors, held: true };
  }
  const record = { anchorVersion: 1, checkpoint: { payload: signedCheckpoint.payload, payloadHash: signedCheckpoint.payloadHash, signature: signedCheckpoint.signature },
    cosignatures, exportedAt: new Date().toISOString() };
  fs.mkdirSync(path.dirname(exportPath), { recursive: true });
  // PH16-D2: whole-record write (a short write throws → reported as export_failed, never as
  // anchored) and NO append onto a torn tail. The export is customer-held storage, so by default a torn tail is refused
  // (AUDIT_ANCHOR_EXPORT_TORN — alerted through QodiqaAnchorExportFailed) rather than rewritten; the owner may opt in to
  // copy-then-truncate repair with QODIQA_ANCHOR_EXPORT_TORN_TAIL=repair.
  require('../jsonlAppend').appendJsonlRecord(exportPath, record, {
    onTornTail: process.env.QODIQA_ANCHOR_EXPORT_TORN_TAIL === 'repair' ? 'repair' : 'refuse', errorPrefix: 'AUDIT_ANCHOR_EXPORT', mode: 0o640,
    emit: (l, t, d) => { try { require('../../../../services/logger').emit(l, t, d); } catch { /* best-effort */ } } });
  return { record, errors };
}

/**
 * ANCHOR-1: publish `signedCheckpoint` after the HELD checkpoints before it (`backlog`:
 * live, signed, not yet exported, oldest first). Each is offered to the witnesses in chain order — which is the
 * witness's own catch-up order, so no fork refusal arises — and exported only with a verified cosignature. The first
 * one that is not witnessed stops the run: it and everything after it stay held (the export stays monotonic and never
 * holds an unwitnessed record). Returns the last item's result plus { exported, held }.
 */
async function publishAnchorBacklog(signedCheckpoint, { backlog = [], ...opts } = {}) {
  const items = (backlog.length > MAX_BACKLOG ? backlog.slice(0, MAX_BACKLOG) : [...backlog, signedCheckpoint])   // D-3: oldest first, never skipping ahead of a held checkpoint;
  const errors = []; let exported = 0; let last = { record: null };
  for (const item of items) {
    last = await publishAnchor(item, { ...opts, requireCosignature: true });
    for (const e of last.errors || []) errors.push({ ...e, checkpointId: item.payload && item.payload.checkpointId });
    if (!last.record) break;
    exported++;
  }
  const total = backlog.length + 1;   // everything waiting, including what this run did not offer
  return { record: exported === total ? last.record : null, errors, exported, held: total - exported };
}
const MAX_BACKLOG = 256;   // per publish run; a longer backlog drains over the following runs

/**
 * @param {object}   o
 * @param {object[]} o.anchors                 anchor records (readAnchors)
 * @param {number}   o.chainLength             live lifetime modern-entry count
 * @param {(n:number)=>Promise<string|null>} o.headHashAt   hash of live entry n (1-based) or null
 * @param {object[]} o.checkpoints             live signed checkpoints (PG and/or sidecar)
 * @param {(keyId:string)=>Buffer|{pubDer,status,retiredAt}} o.resolveCheckpointKey   TRUSTED checkpoint public key resolver
 * @param {object}   o.trustedWitnessKeys      { keys: [...] } supplied out of band
 * @param {number}   [o.minWitnesses=1]
 * @param {number} [o.prunedBefore=0] entries ≤ this are archived: position checks below it are skipped
 * @returns {Promise<{ ok: boolean, checked: number, findings: {anchor:number, code:string, detail:string}[] }>}
 */
async function verifyChainAgainstAnchors({ anchors, chainLength, headHashAt, checkpoints, resolveCheckpointKey, trustedWitnessKeys,
  minWitnesses = 1, prunedBefore = 0 }) {
  const findings = [];
  const byId = new Map((checkpoints || []).map((c) => [c.payload && c.payload.checkpointId, c]));
  let prev = null;
  for (let i = 0; i < anchors.length; i++) {
    const a = anchors[i]; const f = (code, detail) => findings.push({ anchor: i, code, detail });
    const cp = a && a.checkpoint;
    if (!cp || !cp.payload) { f('ANCHOR_MALFORMED', 'no checkpoint'); continue; }
    const v = verifyCheckpoint(cp, { resolvePublicKey: resolveCheckpointKey });
    if (!v.ok) f('ANCHOR_CHECKPOINT_INVALID', v.reason);
    const st = (wid) => statementFor(cp, wid);
    // the quorum counts DISTINCT witnesses (by key and by id): a cosignature repeated in the record, or one key trusted under two ids, is one witness
    const _seenW = new Set(); const _tl = Array.isArray(trustedWitnessKeys) ? trustedWitnessKeys : ((trustedWitnessKeys && trustedWitnessKeys.keys) || []);
    const good = (a.cosignatures || []).filter((c) => { if (!verifyCosignature(st(c.witnessId), c, trustedWitnessKeys).ok) return false; const m = _pubOf(_tl, c.keyId) || c.keyId; const id = `id:${c.witnessId}`; if (_seenW.has(m) || _seenW.has(id)) return false; _seenW.add(m); _seenW.add(id); return true; });
    if (good.length < minWitnesses) {
      const why = (a.cosignatures || []).map((c) => verifyCosignature(st(c.witnessId), c, trustedWitnessKeys).reason).filter(Boolean);
      f('ANCHOR_NOT_WITNESSED', `${good.length}/${minWitnesses} trusted cosignatures${why.length ? ` (${why.join(', ')})` : ''}`);
    }
    const { chainLength: n, headHash, checkpointId } = cp.payload;
    if (prev && (n < prev.chainLength || (n === prev.chainLength && headHash !== prev.headHash))) f('ANCHORS_NOT_MONOTONIC', `position ${n} after ${prev.chainLength}`);
    prev = { chainLength: n, headHash };
    if (chainLength < n) f('CHAIN_ROLLED_BACK', `live chain holds ${chainLength} entries; anchored checkpoint ${checkpointId} vouches for ${n}`);
    else if (n > prunedBefore) {
      const h = await headHashAt(n);
      if (h !== headHash) f('CHAIN_REWRITTEN', `live entry ${n} is ${h || 'missing'}; anchored head is ${headHash}`);
    }
    const live = byId.get(checkpointId);
    if (!live) f('CHECKPOINT_DELETED', `anchored checkpoint ${checkpointId} (entry ${n}) is absent from the live checkpoint set`);
    else if (live.payloadHash !== cp.payloadHash) f('CHECKPOINT_REPLACED', `live checkpoint ${checkpointId} has payloadHash ${live.payloadHash}; anchored ${cp.payloadHash}`);
  }
  return { ok: findings.length === 0, checked: anchors.length, findings };
}

function trustedWitnessKeysFromEnv(env = process.env) {
  const p = env.QODIQA_WITNESS_PUBLIC_KEYS;
  if (!p) return { keys: [] };
  const j = JSON.parse(fs.readFileSync(p, 'utf8'));
  return Array.isArray(j) ? { keys: j } : j;
}

module.exports = { publishAnchor, publishAnchorBacklog, verifyChainAgainstAnchors, readAnchors, exportPathFromEnv, trustedWitnessKeysFromEnv };
