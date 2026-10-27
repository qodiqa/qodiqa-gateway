'use strict';

/**
 * Independent verifier — the downloadable proof `qodiqa-proof/1` (docs/protocol/VECTORS-FORMAT.md section 3, AUDIT-V8-FREEZE section 4).
 * NO src/ import, Node built-ins and the sibling verifier modules only. Everything is re-derived from the protocol documents; nothing is
 * taken from the server that generated the document.
 *
 * Document:
 *   { format: "qodiqa-proof/1", generatedAt, subject: { tenantId, requestId },
 *     artifact?,                       the artifact the request consumed (held by the caller; the gateway does not store it)
 *     auditEntries: [ ... ],           the request's own entries in chain order (INTENT / STREAM_OPENED, DECISION, COMMIT)
 *     chainPath?: [ ... ],             the CONTIGUOUS chain from the first entry of the request to the checkpoint head
 *     transparency?: { leaf, inclusionProof: { leafIndex, treeSize, merklePath }, root },
 *     checkpoint?: { payload, payloadHash, signature },
 *     anchors?: [ { kind, receipt } ],
 *     receipt?, keys: [ { keyId, publicKeySpkiB64, status, activatedAt?, retiredAt?, revokedAt? } ] }
 *
 * Verdict: INVALID when any check fails; otherwise VALID_PARTIAL when an optional part is absent or cannot be evaluated here (the reason is
 * listed in `partial`); otherwise VALID. A part can lower the verdict, never raise it.
 *
 * Check ids (`checks[].id`; a failed one is also listed in `failed` with its code):
 *   FORMAT, SUBJECT, KEYS,
 *   ARTIFACT_SHAPE, ARTIFACT_SIGNATURE, ARTIFACT_KEY_WINDOW, ENTRY_HASH:<n>, ENTRY_REQUEST, ENTRY_SIGNATURE_BINDING, ENTRY_REQUEST_HASH,
 *   ISSUED_AT_MISMATCH, LIFECYCLE, TRANSPARENCY, TRANSPARENCY_BINDING, CHECKPOINT, CHAIN_PATH, RECEIPT, RECEIPT_BINDING, ANCHORS
 */

const crypto = require('crypto');
const { canonicalize } = require('./canonical');
const contract = require('./auditContract');
const transparency = require('./transparency');
const checkpoint = require('./checkpoint');
const receipt = require('./receipt');
const anchorTrust = require('./anchorTrust');

const FORMAT = 'qodiqa-proof/1';
const ARTIFACT_DOMAIN = 'QODIQA::ARTIFACT::V1';
const ARTIFACT_KEYS = ['expiry', 'payload', 'publicKeyId', 'signature', 'timestamp'];
const NOT_A_SIGNATURE = new Set(['UNAVAILABLE', 'SYSTEM']);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function envelopeHash(a) {
  return crypto.createHash('sha256').update(ARTIFACT_DOMAIN, 'utf8')
    .update(canonicalize({ expiry: a.expiry, payload: a.payload, publicKeyId: a.publicKeyId, timestamp: a.timestamp }), 'utf8').digest();
}

/**
 * @param {any} doc
 * @param {{ nowMs?: number, anchorTrust?: object }} [opts] anchorTrust: a repository loaded with anchorTrust.loadAnchorRepo — "trust from the anchor" mode:
 *   the checkpoint is verified under the ANCHORED checkpoint keys and must be (or be covered by) an anchored statement; only then can the verdict be VALID.
 * @returns {{ verdict: 'VALID'|'VALID_PARTIAL'|'INVALID', checks: {id:string, ok:boolean, detail?:string}[], failed: {id:string, code:string}[], partial: string[] }}
 */
function verifyProof(doc, opts = {}) {
  const checks = []; const failed = []; const partial = [];
  const pass = (id, detail) => { checks.push({ id, ok: true, ...(detail ? { detail } : {}) }); };
  const fail = (id, code, detail) => { checks.push({ id, ok: false, detail: detail || code }); failed.push({ id, code }); };
  const finish = () => ({ verdict: failed.length ? 'INVALID' : (partial.length ? 'VALID_PARTIAL' : 'VALID'), checks, failed, partial });

  if (!isObj(doc)) { fail('FORMAT', 'NOT_AN_OBJECT'); return finish(); }
  if (doc.format !== FORMAT) { fail('FORMAT', 'UNKNOWN_FORMAT', `format ${JSON.stringify(doc.format)}`); return finish(); }
  pass('FORMAT');
  const requestId = isObj(doc.subject) && typeof doc.subject.requestId === 'string' && doc.subject.requestId ? doc.subject.requestId : null;
  if (!requestId) { fail('SUBJECT', 'SUBJECT_MISSING'); return finish(); }
  pass('SUBJECT');

  // ── keys ──────────────────────────────────────────────────────────────────────
  const keyList = Array.isArray(doc.keys) ? doc.keys : null;
  if (!keyList || !keyList.every((k) => isObj(k) && typeof k.keyId === 'string' && typeof k.publicKeySpkiB64 === 'string')) { fail('KEYS', 'KEYS_MALFORMED'); return finish(); }
  pass('KEYS');
  const keyById = new Map(keyList.map((k) => [k.keyId, k]));
  const txKeys = keyList.map((k) => ({ keyId: k.keyId, publicKey: k.publicKeySpkiB64, status: k.status }));

  // ── the artifact (optional) ────────────────────────────────────────────────────
  let artifact = null;
  if (doc.artifact === undefined || doc.artifact === null) partial.push('ARTIFACT_ABSENT');
  else if (!isObj(doc.artifact) || Object.keys(doc.artifact).sort().join(',') !== ARTIFACT_KEYS.join(',')) fail('ARTIFACT_SHAPE', 'ARTIFACT_SHAPE');
  else {
    pass('ARTIFACT_SHAPE');
    const a = doc.artifact;
    const key = keyById.get(a.publicKeyId);
    if (!key) fail('ARTIFACT_SIGNATURE', 'UNKNOWN_KEY', String(a.publicKeyId));
    else {
      let digest = null;
      try { digest = envelopeHash(a); } catch (e) { fail('ARTIFACT_SIGNATURE', 'ARTIFACT_NOT_CANONICALIZABLE', e.code || e.message); }
      if (digest) {
        const s = transparency.verifySig(digest, a.signature, key.publicKeySpkiB64);
        if (!s.canonicalEncoding) fail('ARTIFACT_SIGNATURE', 'SIGNATURE_NOT_CANONICAL');
        else if (!s.ok) fail('ARTIFACT_SIGNATURE', 'BAD_SIGNATURE');
        else { pass('ARTIFACT_SIGNATURE'); artifact = a; }
      }
      // key window at issue time: a key revoked at or before the issue time, or not yet active, did not authorise this artifact
      const t = a.timestamp;
      if (Number.isFinite(key.revokedAt) && t >= key.revokedAt) fail('ARTIFACT_KEY_WINDOW', 'KEY_REVOKED_AT_ISSUE');
      else if (Number.isFinite(key.activatedAt) && t < key.activatedAt) fail('ARTIFACT_KEY_WINDOW', 'KEY_NOT_YET_ACTIVE');
      else pass('ARTIFACT_KEY_WINDOW');
    }
  }

  // ── the request's audit entries ────────────────────────────────────────────────
  const entries = Array.isArray(doc.auditEntries) ? doc.auditEntries : null;
  if (!entries || entries.length === 0 || !entries.every(isObj)) { fail('ENTRY_HASH:0', 'AUDIT_ENTRIES_MISSING'); return finish(); }
  let entriesOk = true;
  entries.forEach((e, i) => {
    const r = contract.checkEntryHash(e);
    if (r.ok) pass(`ENTRY_HASH:${i}`); else { fail(`ENTRY_HASH:${i}`, r.code); entriesOk = false; }
  });
  const ownsRequest = (e) => e.requestId === requestId || (typeof e.artifactId === 'string' && (e.artifactId === requestId || e.artifactId.startsWith(`${requestId}:`)));
  if (entries.every(ownsRequest)) pass('ENTRY_REQUEST'); else { fail('ENTRY_REQUEST', 'ENTRY_REQUEST_MISMATCH'); entriesOk = false; }

  // the entries state the signature and request hash of the artifact they consumed
  if (artifact) {
    const real = entries.filter((e) => typeof e.signature === 'string' && !NOT_A_SIGNATURE.has(e.signature));
    if (real.every((e) => e.signature === artifact.signature)) pass('ENTRY_SIGNATURE_BINDING'); else fail('ENTRY_SIGNATURE_BINDING', 'ENTRY_SIGNATURE_MISMATCH');
    const hashed = entries.filter((e) => typeof e.requestHash === 'string' && e.requestHash !== 'UNAVAILABLE');
    if (hashed.every((e) => e.requestHash === artifact.payload.requestHash)) pass('ENTRY_REQUEST_HASH'); else fail('ENTRY_REQUEST_HASH', 'REQUEST_HASH_MISMATCH');
    // AUDIT-V8-FREEZE 4: issuedAt MUST equal the attached artifact's timestamp
    const bad = entries.filter((e) => e.schemaVersion === 8 && e.issuedAt !== null && e.issuedAt !== undefined && e.issuedAt !== artifact.timestamp);
    if (bad.length) fail('ISSUED_AT_MISMATCH', 'ISSUED_AT_MISMATCH'); else pass('ISSUED_AT_MISMATCH');
  }

  // lifecycle of the request: INTENT / STREAM_OPENED, then DECISION, then COMMIT (v8)
  const rank = { INTENT: 0, STREAM_OPENED: 1, DECISION: 2, COMMIT: 3 };
  const types = entries.map((e) => (e.schemaVersion >= 7 ? e.entryType : 'DECISION'));
  const ordered = types.every((t, i) => rank[t] !== undefined && (i === 0 || rank[t] >= rank[types[i - 1]]));
  const decisions = types.filter((t) => t === 'DECISION').length;
  if (!ordered) fail('LIFECYCLE', 'LIFECYCLE_ORDER');
  else if (decisions !== 1) fail('LIFECYCLE', decisions === 0 ? 'NO_DECISION' : 'TWO_DECISIONS');
  else if (types.includes('COMMIT') && types.lastIndexOf('COMMIT') < types.indexOf('DECISION')) fail('LIFECYCLE', 'COMMIT_WITHOUT_DECISION');
  else pass('LIFECYCLE');
  const decision = entries.find((e, i) => types[i] === 'DECISION') || null;

  // ── transparency leaf + inclusion + signed root (optional) ─────────────────────
  if (!isObj(doc.transparency)) partial.push('TRANSPARENCY_ABSENT');
  else {
    const t = doc.transparency;
    let tv;
    try { tv = transparency.verifyTransparency({
      entries: [], roots: [], keys: txKeys, partial: true, auditEntries: entries,
      proofs: [{ entry: t.leaf, root: t.root, proof: t.inclusionProof ? { leafIndex: t.inclusionProof.leafIndex, treeSize: t.inclusionProof.treeSize, merklePath: t.inclusionProof.merklePath } : undefined }],
    });
    } catch (e) { tv = { proofs: [{ valid: false, checks: `malformed transparency part: ${e.message}` }] }; }   // gate L-5: malformed input is INVALID, never a thrown TypeError
    const p = tv.proofs[0];
    if (p && p.valid) pass('TRANSPARENCY'); else fail('TRANSPARENCY', 'TRANSPARENCY_INVALID', JSON.stringify(p ? p.checks : null));
    // the leaf must document one of THIS request's entries (the DECISION) with the same decision
    const leaf = isObj(t.leaf) ? transparency.entryRecord(t.leaf) : null;
    const target = leaf && leaf.payload ? entries.find((e) => e.hash === leaf.payload.auditEntryHash) : null;
    if (target && leaf.payload.requestId === requestId && (!decision || target.hash === decision.hash || target.entryType !== 'DECISION') && leaf.payload.decision === target.decision) pass('TRANSPARENCY_BINDING');
    else fail('TRANSPARENCY_BINDING', 'LEAF_DOES_NOT_DOCUMENT_ENTRY');
  }

  // ── signed checkpoint (optional) and the contiguous path up to its head ────────
  const cp = isObj(doc.checkpoint) ? doc.checkpoint : null;
  if (!cp) partial.push('CHECKPOINT_ABSENT');
  else {
    const verdict = checkpoint.verifySignedCheckpoint(cp, opts.anchorTrust ? checkpoint.keyResolver({ keys: opts.anchorTrust.keys.checkpoint }) : (keyId) => {
      const k = keyById.get(keyId);
      if (!k) throw new Error(`KEY_UNKNOWN:${keyId}`);
      if (String(k.status || '').toLowerCase() === 'revoked') throw new Error(`KEY_REVOKED:${keyId}`);
      return Buffer.from(k.publicKeySpkiB64, 'base64');
    });
    if (verdict.ok) pass('CHECKPOINT'); else fail('CHECKPOINT', verdict.reason || 'CHECKPOINT_INVALID');
    const path = Array.isArray(doc.chainPath) ? doc.chainPath : null;
    if (!path) partial.push('CHAIN_NOT_ANCHORED');
    else if (!verdict.ok) fail('CHAIN_PATH', 'CHECKPOINT_NOT_VERIFIED');
    else {
      let ok = path.length > 0 && path.every(isObj);
      let code = ok ? null : 'CHAIN_PATH_EMPTY';
      if (ok) for (let i = 0; i < path.length && ok; i++) {
        const r = contract.checkEntryHash(path[i]);
        if (!r.ok) { ok = false; code = `PATH_ENTRY_${r.code}`; }
        else if (i > 0 && path[i].prevHash !== path[i - 1].hash) { ok = false; code = 'PATH_BROKEN_LINK'; }
      }
      if (ok && path[path.length - 1].hash !== cp.payload.headHash) { ok = false; code = 'PATH_DOES_NOT_REACH_HEAD'; }
      if (ok) {
        const inPath = new Set(path.map((e) => e.hash));
        const uncovered = entries.filter((e) => !inPath.has(e.hash));
        if (uncovered.length) { ok = false; code = 'ENTRY_NOT_IN_PATH'; }
      }
      if (ok) pass('CHAIN_PATH'); else fail('CHAIN_PATH', code);
    }
  }

  // ── receipt (optional) ─────────────────────────────────────────────────────────
  if (doc.receipt === undefined || doc.receipt === null) partial.push('RECEIPT_ABSENT');
  else {
    const rv = receipt.verifyReceiptDocument(doc.receipt, txKeys, {});
    if (rv.ok) pass('RECEIPT'); else fail('RECEIPT', rv.reason);
    const rb = receipt.bindsTo(isObj(doc.receipt) ? doc.receipt : {}, { requestId, decision: decision ? decision.decision : undefined, entryHash: decision ? decision.hash : undefined });
    if (rb.ok) pass('RECEIPT_BINDING'); else fail('RECEIPT_BINDING', `RECEIPT_MISMATCH:${rb.mismatches.join(',')}`);
  }

  // ── anchors (optional): the anchor kinds (git / OpenTimestamps / RFC 3161) are evaluated by the anchor verifiers ──
  if (opts.anchorTrust) {
    // the anchors repository is the authority; receipts of other kinds are listed as not evaluated
    const ev = anchorTrust.evaluateProof(doc, opts.anchorTrust);
    for (const c of ev.checks) checks.push(c);
    for (const x of ev.failed) failed.push(x);
    for (const x of ev.partial) partial.push(x);
    if (!ev.failed.length && ev.covered) {
      pass('ANCHORS', 'checkpoint anchored in the anchors repository');
      for (const k of new Set((Array.isArray(doc.anchors) ? doc.anchors : []).map((a) => a && a.kind).filter((k) => k === 'ots' || k === 'rfc3161'))) partial.push(`ANCHOR_RECEIPT_NOT_EVALUATED:${k}`);
    }
  } else if (!Array.isArray(doc.anchors) || doc.anchors.length === 0) partial.push('ANCHORS_ABSENT');
  else if (!doc.anchors.every((a) => isObj(a) && ['git', 'ots', 'rfc3161'].includes(a.kind) && typeof a.receipt === 'string')) fail('ANCHORS', 'ANCHOR_MALFORMED');
  else { pass('ANCHORS', 'present, not evaluated by this verifier'); partial.push('ANCHORS_NOT_EVALUATED'); }

  if (!entriesOk && !failed.length) fail('ENTRY_HASH:0', 'ENTRIES_INVALID');
  return finish();
}

module.exports = { FORMAT, verifyProof, envelopeHash };
