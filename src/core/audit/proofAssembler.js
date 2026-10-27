'use strict';

/**
 * Proof assembler: builds the downloadable proof `qodiqa-proof/1` (docs/protocol/VECTORS-FORMAT.md section 3) of ONE request from the
 * gateway's own stores — the request's audit entries, the contiguous chain path from its first entry to the earliest signed checkpoint that covers it,
 * the transparency leaf with its inclusion proof and signed root, the receipt, the external anchors and the public keys needed to check all of it.
 *
 * It asserts nothing the stores do not hold: every part is optional and left out when it cannot be assembled (the verifier then lowers the verdict, it
 * never guesses). The artifact itself is not stored by the gateway; the caller adds it when verifying (`qodiqa-proof-verify --artifact`).
 *
 * Tenant isolation: the request's entries are looked up WITH the tenant; an unknown request and a request of another tenant give the same answer
 * (`NOT_FOUND`), so a caller cannot learn that another tenant's request exists.
 */

const entryBuilder = require('./entryBuilder');

const FORMAT = 'qodiqa-proof/1';
const MAX_PATH_ENTRIES = 20_000;            // the chain path (request's first entry .. checkpoint head) is bounded; a longer one is left out
const PAGE = 5000;
const TRUE_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** The default dependencies: the real stores (required lazily so that the assembler can be unit-tested with fakes). */
function defaultDeps() {
  const auditLog = require('./audit-log');
  return {
    getEntry: (artifactId, tenantId) => auditLog.getArtifactById(artifactId, tenantId),
    positionOf: (artifactId) => auditLog.getModernPositionByArtifactId(artifactId),
    page: (pos, limit) => auditLog.getModernChainPage({ cursor: { m: pos }, limit }),
    transparencyEntries: (artifactId) => require('../transparency/logStore').getByArtifactId(artifactId),
    inclusion: (entry) => require('../transparency/proofLookup').getInclusionProofForEntry(entry),
    signedCheckpoints: async () => {
      const out = [];
      const pgPool = require('../../infra/postgres/pool');
      if (pgPool.isEnabled()) {
        try {
          const r = await pgPool.query('SELECT payload, payload_hash, signature FROM audit_signed_checkpoints ORDER BY chain_length', [], 'proof_checkpoints');
          for (const x of r.rows) out.push({ payload: x.payload, payloadHash: String(x.payload_hash).trim(), signature: x.signature });
        } catch { /* PostgreSQL unavailable: the sidecar below still answers */ }
      }
      const { readSidecar } = require('./checkpoint/checkpointWriter');
      const seen = new Set(out.map((c) => c.payload.checkpointId));
      for (const c of readSidecar(process.env.QODIQA_AUDIT_LOG || require('path').join(__dirname, '..', '..', '..', 'audit.log'))) if (!seen.has(c.payload.checkpointId)) out.push(c);
      return out.sort((a, b) => a.payload.chainLength - b.payload.chainLength);
    },
    receipt: (requestId) => require('../transparency/receiptStore').getReceipt(requestId),
    anchorsFor: async (payloadHash) => {
      const ea = require('./anchoring/externalAnchors');
      return (await ea.listByPayloadHash(payloadHash)).filter((r) => r.status === 'confirmed' && r.receipt).map((r) => ({ kind: r.kind, receipt: r.receipt }));
    },
    checkpointKeys: () => require('./checkpoint/checkpointKeyStore').listKeys(),
    transparencyKeys: () => require('../transparency/transparencyKeyStore').listKeys(),
    artifactKeys: () => { try { return require('../../../services/artifact/keyStore').listKeys(); } catch { return []; } },
  };
}

const ms = (v) => { const t = typeof v === 'number' ? v : Date.parse(v); return Number.isFinite(t) ? t : undefined; };
function keyRecord(k) {
  const pub = k.publicKeyB64 || k.publicKeySpkiB64;
  if (!k.keyId || typeof pub !== 'string' || !TRUE_BASE64.test(pub)) return null;
  const out = { keyId: k.keyId, publicKeySpkiB64: pub, status: k.status };
  const a = ms(k.createdAt); const r = ms(k.retiredAt); const v = ms(k.revokedAt);
  if (a !== undefined) out.activatedAt = a;
  if (r !== undefined) out.retiredAt = r;
  if (v !== undefined) out.revokedAt = v;
  return out;
}

/**
 * @param {{ tenantId: string, requestId: string, nowMs?: number }} q
 * @returns {Promise<{ ok: false, code: 'NOT_FOUND' } | { ok: true, proof: object, parts: object }>}
 */
async function assembleProof({ tenantId, requestId, nowMs = Date.now(), allowForeignEntries = false }, deps = defaultDeps()) {
  // ── the request's own entries (tenant-scoped) ─────────────────────────────────
  const ids = [entryBuilder.lifecycleArtifactId(requestId, 'INTENT'), entryBuilder.lifecycleArtifactId(requestId, 'STREAM_OPENED'), requestId, `${requestId}:commit`];
  const found = [];
  for (const id of ids) {
    const e = await deps.getEntry(id, tenantId);
    if (e && e.tenantId === tenantId) found.push({ id, e });
  }
  if (!found.length) return { ok: false, code: 'NOT_FOUND' };
  const withPos = [];
  for (const f of found) withPos.push({ ...f, pos: await deps.positionOf(f.id) });
  const positioned = withPos.every((f) => Number.isInteger(f.pos));
  withPos.sort((a, b) => (positioned ? a.pos - b.pos : String(a.e.timestamp).localeCompare(String(b.e.timestamp))));
  const entries = withPos.map((f) => JSON.parse(JSON.stringify(f.e)));
  const decision = entries.find((e) => (e.schemaVersion >= 7 ? e.entryType : 'DECISION') === 'DECISION') || null;
  const parts = { entries: entries.length, transparency: false, checkpoint: false, chainPath: false, receipt: false, anchors: 0 };
  const keyIds = new Set();
  const doc = { format: FORMAT, generatedAt: nowMs, subject: { tenantId, requestId }, auditEntries: entries };
  for (const e of entries) if (e.publicKeyId) keyIds.add(e.publicKeyId);

  // ── transparency leaf + inclusion proof + signed root ─────────────────────────
  let tKeyIds = [];
  if (decision) {
    try {
      const rows = (await deps.transparencyEntries(requestId)) || [];
      const leaf = rows.find((r) => r.payload && r.payload.auditEntryHash === decision.hash) || null;
      if (leaf) {
        const inc = await deps.inclusion(leaf);
        if (inc && inc.proof && inc.proof.proof && inc.proof.proof.leafIndex >= 0 && inc.proof.root) {
          doc.transparency = { leaf: JSON.parse(JSON.stringify(leaf)),
            inclusionProof: { leafIndex: inc.proof.proof.leafIndex, treeSize: inc.proof.proof.treeSize, merklePath: inc.proof.proof.merklePath }, root: inc.proof.root };
          tKeyIds = [leaf.signer_key_id || leaf.signerKeyId, inc.proof.root.signerKeyId];
          parts.transparency = true;
        }
      }
    } catch { /* the transparency store is unavailable: the part is left out */ }
  }

  // ── the earliest signed checkpoint that covers the request, and the contiguous path up to its head ──
  let cp = null;
  if (positioned) {
    const first = withPos[0].pos; const last = withPos[withPos.length - 1].pos;
    try {
      cp = (await deps.signedCheckpoints()).find((c) => c.payload.chainLength > last) || null;
      if (cp && cp.payload.chainLength - first <= MAX_PATH_ENTRIES) {
        const path = [];
        for (let pos = first; pos < cp.payload.chainLength;) {
          const page = await deps.page(pos, Math.min(PAGE, cp.payload.chainLength - pos));
          if (!page.entries.length) break;
          for (const e of page.entries) path.push(JSON.parse(JSON.stringify(e)));
          pos += page.entries.length;
        }
        // D-0: the contiguous path is the chain between the request and the checkpoint head and contains OTHER tenants' raw entries. A tenant-scoped
        // caller never gets them: the path (and with it the checkpoint binding) is withheld unless the caller is explicitly allowed the platform-wide chain.
        const foreign = path.filter((e) => e.tenantId !== tenantId).length;
        if (foreign > 0 && !allowForeignEntries) { parts.chainPathWithheld = foreign; cp = null; }
        else if (path.length === cp.payload.chainLength - first && path[path.length - 1].hash === cp.payload.headHash) {
          doc.checkpoint = { payload: cp.payload, payloadHash: cp.payloadHash, signature: cp.signature };
          doc.chainPath = path;
          parts.checkpoint = true; parts.chainPath = true;
        } else cp = null;
      } else cp = null;
    } catch { cp = null; }
  }

  // ── receipt and external anchors ──────────────────────────────────────────────
  try { const r = await deps.receipt(requestId); if (r && r.requestId === requestId) { doc.receipt = r; parts.receipt = true; tKeyIds.push(r.keyId); } } catch { /* absent */ }
  if (doc.checkpoint) {
    try { const a = await deps.anchorsFor(doc.checkpoint.payloadHash); if (a.length) { doc.anchors = a; parts.anchors = a.length; } } catch { /* absent */ }
  }

  // ── the public keys the verifier needs ────────────────────────────────────────
  const keys = []; const add = (k) => { const r = k && keyRecord(k); if (r && !keys.some((x) => x.keyId === r.keyId)) keys.push(r); };
  const wanted = (list, ids2) => list.filter((k) => ids2.includes(k.keyId));
  try { for (const k of wanted(deps.artifactKeys(), [...keyIds])) add(k); } catch { /* none */ }
  try { for (const k of wanted(deps.transparencyKeys(), tKeyIds.filter(Boolean))) add(k); } catch { /* none */ }
  if (doc.checkpoint) { try { for (const k of wanted(deps.checkpointKeys(), [doc.checkpoint.payload.keyId])) add(k); } catch { /* none */ } }
  doc.keys = keys;
  return { ok: true, proof: doc, parts };
}

module.exports = { assembleProof, defaultDeps, FORMAT, MAX_PATH_ENTRIES };
