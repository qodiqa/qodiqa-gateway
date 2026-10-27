'use strict';

/**
 * independent verifier — transparency log. No src/ imports.
 *
 *   payloadHash  = SHA-256(canonical(payload))                                  (no domain)
 *   entryHash    = SHA-256("QODIQA::TRANSPARENCY::V1" ‖ canonical({8 entry fields}))
 *   entry sig    = Ed25519 over the 32 raw bytes of entryHash
 *   root digest  = SHA-256("QODIQA::TRANSPARENCY_ROOT::V1" ‖ canonical({6 root fields}))
 *   root sig     = Ed25519 over the 32-byte root digest
 *   Merkle       = RFC 6962: leaf = SHA-256(0x00 ‖ entryHashBytes), node = SHA-256(0x01 ‖ L ‖ R),
 *                  split at the largest power of two < n
 *   public keys  = base64 SPKI DER (/.well-known/qodiqa/transparency-keys)
 * Cross-check with the audit chain: every leaf whose payload carries auditEntryHash must name an
 * entry of the verified audit chain with the same decision (and, where the entry records one, the
 * same request id — the leaf's artifact_id column carries the request id, not the audit artifactId).
 */

const crypto = require('crypto');
const { canonicalize } = require('./canonical');

const ENTRY_DOMAIN = 'QODIQA::TRANSPARENCY::V1';
const ROOT_DOMAIN = 'QODIQA::TRANSPARENCY_ROOT::V1';
const ENTRY_FIELDS = ['transparencyId', 'entryType', 'artifactId', 'evidenceChainId', 'verificationId', 'payloadHash', 'previousEntryHash', 'signerKeyId'];
const ROOT_FIELDS = ['rootId', 'seqFrom', 'seqTo', 'entryCount', 'rootHash', 'previousRootHash'];

const pick = (r, camel, snake) => (r[camel] !== undefined ? r[camel] : r[snake]);

function entryRecord(r) {
  return {
    id: r.id !== undefined ? Number(r.id) : null,
    transparencyId: pick(r, 'transparencyId', 'transparency_id'),
    entryType: pick(r, 'entryType', 'entry_type'),
    artifactId: pick(r, 'artifactId', 'artifact_id') ?? null,
    evidenceChainId: pick(r, 'evidenceChainId', 'evidence_chain_id') ?? null,
    verificationId: pick(r, 'verificationId', 'verification_id') ?? null,
    payloadHash: pick(r, 'payloadHash', 'payload_hash'),
    previousEntryHash: pick(r, 'previousEntryHash', 'previous_entry_hash') ?? null,
    signerKeyId: pick(r, 'signerKeyId', 'signer_key_id'),
    signature: r.signature,
    entryHash: pick(r, 'entryHash', 'entry_hash'),
    payload: r.payload,
  };
}

function rootRecord(r) {
  const n = (v) => (v === undefined || v === null ? null : Number(v));
  return {
    rootId: pick(r, 'rootId', 'root_id'), seqFrom: n(pick(r, 'seqFrom', 'seq_from')), seqTo: n(pick(r, 'seqTo', 'seq_to')),
    entryCount: pick(r, 'entryCount', 'entry_count'), rootHash: pick(r, 'rootHash', 'root_hash'),
    previousRootHash: pick(r, 'previousRootHash', 'previous_root_hash') ?? null,
    signerKeyId: pick(r, 'signerKeyId', 'signer_key_id'), signature: r.signature,
  };
}

const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

function payloadHash(payload) { return sha256hex(canonicalize(payload ?? {})); }

function entryHash(rec) {
  const o = {}; for (const f of ENTRY_FIELDS) o[f] = rec[f] ?? null;
  return crypto.createHash('sha256').update(ENTRY_DOMAIN, 'utf8').update(canonicalize(o), 'utf8').digest('hex');
}

function rootDigest(rec) {
  const o = {}; for (const f of ROOT_FIELDS) o[f] = rec[f] ?? null;
  return crypto.createHash('sha256').update(ROOT_DOMAIN, 'utf8').update(canonicalize(o), 'utf8').digest();
}

/** Ed25519 verify. Also reports whether the signature is in canonical padded base64 (88 chars, round-trips). */
function verifySig(digest32, sigB64, pubB64) {
  if (typeof sigB64 !== 'string' || typeof pubB64 !== 'string') return { ok: false, canonicalEncoding: false };
  const sig = Buffer.from(sigB64, 'base64');
  if (Buffer.from(pubB64, 'base64').toString('base64') !== pubB64) return { ok: false, canonicalEncoding: false };   // gate L-4: canonical key encoding only
  const canonicalEncoding = sigB64.length === 88 && sig.toString('base64') === sigB64;
  if (sig.length !== 64) return { ok: false, canonicalEncoding };
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(pubB64, 'base64'), format: 'der', type: 'spki' });
    return { ok: crypto.verify(null, digest32, key, sig), canonicalEncoding };
  } catch { return { ok: false, canonicalEncoding }; }
}

const leaf = (hex) => crypto.createHash('sha256').update(Buffer.from([0])).update(Buffer.from(hex, 'hex')).digest();
const node = (l, r) => crypto.createHash('sha256').update(Buffer.from([1])).update(l).update(r).digest();
function largestPow2Below(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
function subtree(leaves) {
  if (leaves.length === 1) return leaves[0];
  const k = largestPow2Below(leaves.length);
  return node(subtree(leaves.slice(0, k)), subtree(leaves.slice(k)));
}
function merkleRoot(entryHashes) { return subtree(entryHashes.map(leaf)).toString('hex'); }
// the RFC6962 side sequence (deepest first) of leaf `leafIndex` in a `treeSize`-leaf tree; a path
// is accepted only with exactly these sides, so a proof is bound to its claimed position. null for an invalid pair.
function expectedPathSides(leafIndex, treeSize) {
  if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize) || leafIndex < 0 || leafIndex >= treeSize) return null;
  const sides = []; let size = treeSize; let idx = leafIndex;
  while (size > 1) {
    let k = 1; while (k * 2 < size) k *= 2;
    if (idx < k) { sides.push('right'); size = k; } else { sides.push('left'); idx -= k; size -= k; }
  }
  return sides.reverse();
}

function verifyInclusion(entryHashHex, path, rootHex, leafIndex, treeSize) {
  if (!Array.isArray(path)) return false;
  const sides = expectedPathSides(leafIndex, treeSize);
  if (!sides || path.length !== sides.length || path.some((st, i) => !st || st.side !== sides[i])) return false;
  let cur = leaf(entryHashHex);
  for (const step of path) {
    const sib = Buffer.from(step.hash, 'hex');
    if (step.side === 'right') cur = node(cur, sib);
    else if (step.side === 'left') cur = node(sib, cur);
    else return false;
  }
  return cur.toString('hex') === rootHex;
}

// key STATUS is honoured. A key published (or supplied) as `revoked` is not a
// trust anchor — a leaf or root it signed fails (REVOKED_KEY) instead of verifying. (No signing time is covered by the
// entry hash, so a deprecated key cannot be time-bounded here; it still verifies, as the production verifier does.)
function keyMap(keys) {
  const list = Array.isArray(keys) ? keys : (keys && Array.isArray(keys.keys) ? keys.keys : []);
  return new Map(list.map((k) => [k.keyId, { publicKey: k.publicKey, revoked: String(k.status || '').toLowerCase() === 'revoked' }]));
}
function sigCheck(pubs, keyId, msg, signature) {
  const k = pubs.get(keyId);
  if (!k) return { verdict: 'UNKNOWN_KEY' };
  if (k.revoked) return { verdict: 'REVOKED_KEY' };
  const s = verifySig(msg, signature, k.publicKey);
  return { verdict: s.ok ? 'PASS' : 'FAIL', nonCanonical: s.ok && !s.canonicalEncoding };
}

/**
 * Verify transparency entries (ordered by id), roots and inclusion proofs; cross-check leaves
 * against the audit chain's verified entries.
 */
/**
 * opts.partial: the export deliberately omits leaves. Without it, a signed root covering ids that are not in
 * the export is a FAILURE (a tail deleted behind an intact root), not a pass.
 */
function verifyTransparency({ entries = [], roots = [], proofs = [], keys = [], auditEntries = null, partial = false }) {
  const pubs = keyMap(keys);
  const out = { entries: [], roots: [], proofs: [], crossCheck: null, valid: true, nonCanonicalSignatures: 0, lateLeaves: [] };
  const recs = entries.map(entryRecord).sort((a, b) => (a.id ?? 0) - (b.id ?? 0));
  // a leaf that entered the log through the recovery queue / file journal / in-memory buffer after an interruption states so inside its (hashed,
  // signed) payload: payload.recovery = { late: true, replica, seq, queuedAt }; seq with the original payload.recordedAt gives its original order.
  // Reported, never a failure: a late leaf is a legitimate, disclosed event.
  const seen = new Map(); out.lateLeafAnomalies = [];
  for (const r of recs) if (r.payload && r.payload.recovery && r.payload.recovery.late === true) out.lateLeaves.push({ id: r.id, transparencyId: r.transparencyId, replica: r.payload.recovery.replica ?? null, seq: r.payload.recovery.seq ?? null, queuedAt: r.payload.recovery.queuedAt ?? null, recordedAt: r.payload.recordedAt ?? null });
  // anomalies of the late-leaf markers: a (replica, seq) pair used twice (DUPLICATE_SEQ). A seq that goes backwards is NOT checked
  for (const l of out.lateLeaves) {
    const key = l.replica + '#' + l.seq;
    if (seen.has(key)) out.lateLeafAnomalies.push({ kind: 'DUPLICATE_SEQ', replica: l.replica, seq: l.seq, ids: [seen.get(key), l.id] }); else seen.set(key, l.id);
  }
  let prev = null; let prevId = null;
  for (const r of recs) {
    const res = { id: r.id, transparencyId: r.transparencyId, checks: {} };
    res.checks.PAYLOAD_HASH = r.payload === undefined ? 'NOT_EXPORTED' : (payloadHash(r.payload) === r.payloadHash ? 'PASS' : 'FAIL');
    const eh = entryHash(r);
    res.checks.ENTRY_HASH = eh === r.entryHash ? 'PASS' : 'FAIL';
    res.checks.CHAIN_LINK = (r.previousEntryHash ?? null) === prev ? 'PASS' : 'FAIL';
    res.checks.ID_CONTINUITY = prevId === null || r.id === prevId + 1 ? 'PASS' : 'FAIL';
    const sc = sigCheck(pubs, r.signerKeyId, Buffer.from(eh, 'hex'), r.signature);
    res.checks.SIGNATURE = sc.verdict;
    if (sc.nonCanonical) { res.checks.SIGNATURE_ENCODING = 'NON_CANONICAL'; out.nonCanonicalSignatures++; }
    res.valid = Object.entries(res.checks).every(([k, v]) => v === 'PASS' || v === 'NOT_EXPORTED' || k === 'SIGNATURE_ENCODING');
    if (!res.valid) out.valid = false;
    out.entries.push(res);
    prev = r.entryHash; prevId = r.id;
  }

  const byId = new Map(recs.map((r) => [r.id, r]));
  let prevRoot = null;
  for (const raw of [...roots].sort((a, b) => Number(pick(a, 'seqTo', 'seq_to')) - Number(pick(b, 'seqTo', 'seq_to')))) {
    const r = rootRecord(raw);
    const res = { rootId: r.rootId, seqFrom: r.seqFrom, seqTo: r.seqTo, checks: {} };
    const sc = sigCheck(pubs, r.signerKeyId, rootDigest(r), r.signature);
    res.checks.ROOT_SIGNATURE = sc.verdict;
    if (sc.nonCanonical) { res.checks.SIGNATURE_ENCODING = 'NON_CANONICAL'; out.nonCanonicalSignatures++; }
    // a root covers the WHOLE log up to seqTo (ids 1..seqTo), not just the range it newly
    // added (seqFrom..seqTo): production builds cumulative RFC 6962 trees (src/core/transparency/registrar.js,
    // generateRoot — required for consistency proofs; AT-078) and entryCount is that tree's size. The version
    // recomputed over seqFrom..seqTo, which is only equivalent for the first root, so every later root read INVALID.
    const covered = [];
    for (let id = 1; id <= r.seqTo; id++) covered.push(byId.get(id));
    if (covered.every(Boolean)) {
      res.checks.ROOT_HASH = merkleRoot(covered.map((c) => c.entryHash)) === r.rootHash ? 'PASS' : 'FAIL';
      res.checks.ENTRY_COUNT = Number(r.entryCount) === covered.length ? 'PASS' : 'FAIL';
    } else res.checks.ROOT_HASH = partial ? 'ENTRIES_NOT_EXPORTED' : 'ENTRIES_MISSING'; // fail unless --partial
    res.checks.ROOT_LINK = prevRoot === null || (r.previousRootHash ?? null) === prevRoot ? 'PASS' : 'FAIL';
    res.valid = Object.entries(res.checks).every(([k, v]) => v === 'PASS' || v === 'ENTRIES_NOT_EXPORTED' || k === 'SIGNATURE_ENCODING');
    if (!res.valid) out.valid = false;
    out.roots.push(res);
    prevRoot = r.rootHash;
  }

  for (const p of proofs) {
    const res = { transparencyId: p?.entry?.transparencyId ?? null, checks: {} };
    if (!p || !p.entry || !p.root || !p.proof) { res.checks.STRUCTURE = 'FAIL'; res.valid = false; out.valid = false; out.proofs.push(res); continue; }
    const e = entryRecord(p.entry); const r = rootRecord(p.root);
    const li = Number(p.proof.leafIndex); const ts = Number(p.proof.treeSize);
    res.checks.LEAF_INDEX_RANGE = li >= 0 && li < ts ? 'PASS' : 'FAIL';
    res.checks.TREE_SIZE = ts === Number(r.entryCount) ? 'PASS' : 'FAIL';   // the tree the signed root covers
    res.checks.ENTRY_HASH = entryHash(e) === e.entryHash ? 'PASS' : 'FAIL';
    res.checks.MERKLE_PATH = verifyInclusion(e.entryHash, p.proof.merklePath, r.rootHash, li, ts) ? 'PASS' : 'FAIL';
    res.checks.ENTRY_SIGNATURE = sigCheck(pubs, e.signerKeyId, Buffer.from(e.entryHash, 'hex'), e.signature).verdict;
    res.checks.ROOT_SIGNATURE = sigCheck(pubs, r.signerKeyId, rootDigest(r), r.signature).verdict;
    res.valid = Object.values(res.checks).every((v) => v === 'PASS');
    if (!res.valid) out.valid = false;
    out.proofs.push(res);
  }

  if (auditEntries) {
    const byHash = new Map(auditEntries.filter((e) => e && typeof e.hash === 'string').map((e) => [e.hash, e]));
    const cc = { leavesWithAuditHash: 0, matched: 0, missing: [], mismatched: [] };
    for (const r of recs) {
      const aeh = r.payload && r.payload.auditEntryHash;
      if (!aeh) continue;
      cc.leavesWithAuditHash++;
      const a = byHash.get(aeh);
      if (!a) { cc.missing.push({ id: r.id, auditEntryHash: aeh }); continue; }
      // The binding is auditEntryHash (the leaf is signed, the audit hash covers the entry). The
      // leaf's artifact_id column carries the REQUEST id (enforcementBridge: artifactId =
      // requestId), which the audit entry records only in its UNHASHED requestId field — compared
      // when the entry has one, never against the audit artifactId.
      const bad = [];
      if (r.payload.decision !== a.decision) bad.push('decision');
      if (a.schemaVersion === 7 || a.schemaVersion === 8) {
        // v7/v8 (SCHEMA-V7-DESIGN.md R-9/R-10; v8 keeps the three v7 types and their leaf rules, a leaf that points at a v8-only type
        // follows the lifecycle rule: it states payload.entryType and registers under the entry's own artifactId): requestId is a HASHED field of every entry (null when there is none), the
        // INTENT / STREAM_OPENED leaves register under the entry's own suffixed artifactId and state payload.entryType
        // (absent on DECISION leaves), and a DECISION leaf registers under the request id (the entry's artifactId when
        // the entry has no requestId).
        const lifecycle = a.entryType !== 'DECISION';
        if ((r.payload.entryType ?? 'DECISION') !== a.entryType) bad.push('entryType');
        if (a.requestId !== null && a.requestId !== undefined && r.payload.requestId !== a.requestId) bad.push('requestId');
        const expectedLeafArtifact = lifecycle ? a.artifactId : (a.requestId ?? a.artifactId);
        if (r.artifactId !== null && r.artifactId !== expectedLeafArtifact) bad.push('artifactId');
      } else if (a.requestId !== undefined && r.artifactId !== null && r.artifactId !== a.requestId) bad.push('requestId');
      if (bad.length) cc.mismatched.push({ id: r.id, auditEntryHash: aeh, fields: bad });
      else cc.matched++;
    }
    // the reverse direction — every v7 audit entry of a type that is ALWAYS registered (INTENT, STREAM_OPENED,
    // DECISION; SCHEMA-V7-DESIGN R-10/R-11) must have a leaf. Checked only on a complete export (not --partial).
    const leafed = new Set(recs.map((r) => r.payload && r.payload.auditEntryHash).filter(Boolean));
    cc.auditWithoutLeaf = partial ? [] : auditEntries
      .filter((a) => a && (a.schemaVersion === 7 || a.schemaVersion === 8) && ['INTENT', 'STREAM_OPENED', 'DECISION'].includes(a.entryType) && !leafed.has(a.hash))
      .map((a) => ({ hash: a.hash, entryType: a.entryType }));
    cc.valid = cc.missing.length === 0 && cc.mismatched.length === 0 && cc.auditWithoutLeaf.length === 0;
    if (!cc.valid) out.valid = false;
    out.crossCheck = cc;
  }
  return out;
}

module.exports = { ENTRY_DOMAIN, ROOT_DOMAIN, ENTRY_FIELDS, ROOT_FIELDS, payloadHash, entryHash, rootDigest, verifySig, merkleRoot, verifyInclusion, expectedPathSides, verifyTransparency, entryRecord, rootRecord };
