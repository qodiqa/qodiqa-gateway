'use strict';

/**
 * Deterministic builders for the audit vector families (docs/protocol/vectors/audit-v8.json, audit-proof.json).
 *
 * Everything is produced by the PRODUCTION writers (entryBuilder, signArtifact, signCheckpoint, receiptDigest) with PUBLISHED TEST SEEDS and a
 * frozen clock, so regenerating the files yields identical bytes. The Merkle leaf / root use the documented algorithms through the independent
 * verifier's own primitives. The verdicts in the vector files are produced by the independent Node verifier (scripts/audit-repro/verify) and
 * re-derived by the Python verifier and by the production entry checks.
 */

const crypto = require('crypto');
const eb = require('../../src/core/audit/entryBuilder');
const { signArtifact } = require('../../src/validation/signArtifact');
const { signCheckpoint } = require('../../src/core/audit/checkpoint/checkpoint');
const { receiptDigest } = require('../../src/core/transparency/receipt');
const transparency = require('../audit-repro/verify/transparency');
const contract = require('../audit-repro/verify/auditContract');

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const seedOf = (label) => crypto.createHash('sha256').update(`QODIQA published audit-proof test seed: ${label}`, 'utf8').digest();
const keyOf = (label) => {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seedOf(label)]), format: 'der', type: 'pkcs8' });
  return { priv, privDer: priv.export({ format: 'der', type: 'pkcs8' }), pubB64: crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).toString('base64') };
};
const H = (c) => c.repeat(64);
const RID = '5b1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b';
const OTHER_A = '9c1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b';
const OTHER_B = '9c1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a60';
const T0 = 1790000000000;

/** Run fn with a frozen, deterministic clock: every `new Date()` / hrtime tick advances 1 s / 1 unit. */
function withFixedClock(fn) {
  const RealDate = Date; const realHr = process.hrtime.bigint;
  let t = T0; let hr = 1000000n;
  global.Date = class extends RealDate {
    constructor(...a) { if (a.length === 0) { super(t); t += 1000; } else super(...a); }
    static now() { const v = t; t += 1000; return v; }
  };
  process.hrtime.bigint = () => { hr += 1000n; return hr; };
  try { return fn(); } finally { global.Date = RealDate; process.hrtime.bigint = realHr; }
}

const clone = (o) => JSON.parse(JSON.stringify(o));
const build = (spec, prev) => clone(eb.buildEntry(eb.normalizeFields(spec), prev));

/** Re-seal an entry after a mutation, so only the shape (not the hash) is wrong. */
function reseal(e) {
  const out = { ...e };
  out.canonical = contract.expectedCanonical(out);
  out.hash = contract.auditHash(out.canonical);
  return out;
}

const KEYS = { artifact: keyOf('artifact'), transparency: keyOf('transparency'), checkpoint: keyOf('checkpoint'), receipt: keyOf('receipt'), other: keyOf('other') };
const KEY_IDS = { artifact: 'tenant1:key_v1', transparency: 'tr-test:key_v1', checkpoint: 'cp-test:key_v1', receipt: 'tr-test:key_v9' };

/** A complete v8 proof (artifact, 5-entry chain, transparency leaf, checkpoint, receipt, one anchor) — the base of every proof vector. */
function buildBaseProof({ v8 = true, issuedAt = T0 } = {}) {
  const prevFlag = process.env.QODIQA_AUDIT_SCHEMA_V8;
  if (v8) process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true'; else delete process.env.QODIQA_AUDIT_SCHEMA_V8;
  try {
    return withFixedClock(() => {
      const requestHash = H('a');
      const artifact = clone(signArtifact({
        payload: { requestId: RID, requestHash, policyHash: H('b'), provider: 'local', tenantId: 'tenant1' },
        timestamp: T0, expiry: T0 + 60000, publicKeyId: KEY_IDS.artifact,
      }, KEYS.artifact.privDer));
      const facts = v8 ? { issuedAt, protocolVersion: 1 } : {};
      const base = { inputHash: requestHash, signature: artifact.signature, requestHash, policyHash: H('b'), verificationResult: true, tenantId: 'tenant1' };
      const outputHash = eb.outputHashOf('the answer');
      const filler = (id) => ({ ...base, signature: 'sig-other', artifactId: id, decision: 'ALLOW', stage: 'PROVIDER_EXECUTION', outputHash: eb.EMPTY_OUTPUT_HASH, requestId: id, executingProvider: 'local' });
      const specs = [
        filler(OTHER_A),
        { ...base, artifactId: eb.lifecycleArtifactId(RID, 'INTENT'), entryType: 'INTENT', decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', requestId: RID, executingProvider: 'local', ...facts },
        { ...base, artifactId: RID, decision: 'ALLOW', stage: 'PROVIDER_EXECUTION', outputHash, requestId: RID, executingProvider: 'local', ...facts },
      ];
      if (v8) specs.push({ artifactId: `${RID}:commit`, entryType: 'COMMIT', decision: 'ALLOW', reason: 'RESPONSE_DELIVERED', signature: artifact.signature, requestId: RID, tenantId: 'tenant1', outputHash, bytesDelivered: 10, completionStatus: 'COMPLETE', ...facts });
      specs.push(filler(OTHER_B));
      const chain = []; let prev = 'GENESIS';
      for (const s of specs) { const e = build(s, prev); chain.push(e); prev = e.hash; }
      const mine = chain.filter((e) => e.requestId === RID);
      const decision = mine.find((e) => (e.entryType ?? 'DECISION') === 'DECISION');
      const chainPath = chain.slice(chain.findIndex((e) => e.requestId === RID));

      const payload = { requestId: RID, decision: 'ALLOW', reason: 'ALL_CHECKS_PASSED', stage: 'PROVIDER_EXECUTION', auditEntryHash: decision.hash, tenantId: 'tenant1' };
      const leaf = { id: 1, transparencyId: '6f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a01', entryType: 'AUDIT', artifactId: RID, evidenceChainId: null, verificationId: null, payloadHash: transparency.payloadHash(payload), previousEntryHash: null, signerKeyId: KEY_IDS.transparency };
      leaf.entryHash = transparency.entryHash(leaf);
      leaf.signature = crypto.sign(null, Buffer.from(leaf.entryHash, 'hex'), KEYS.transparency.priv).toString('base64');
      leaf.payload = payload;
      const root = { rootId: '6f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a02', seqFrom: 1, seqTo: 1, entryCount: 1, rootHash: transparency.merkleRoot([leaf.entryHash]), previousRootHash: null, signerKeyId: KEY_IDS.transparency };
      root.signature = crypto.sign(null, transparency.rootDigest(root), KEYS.transparency.priv).toString('base64');

      const checkpoint = clone(signCheckpoint({ checkpointId: '6f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a03', chainLength: chain.length, headHash: chain[chain.length - 1].hash, createdAt: new Date(T0 + 5000).toISOString() },
        { keyStore: { ensureActiveKey: () => ({ keyId: KEY_IDS.checkpoint, version: 1, privDer: KEYS.checkpoint.privDer }) } }));

      const unsignedReceipt = { v: 1, requestId: RID, decision: 'ALLOW', issuedAt: T0 + 2000, entryHash: decision.hash, leafHash: H('b'), keyId: KEY_IDS.receipt };
      const receipt = { ...unsignedReceipt, signature: crypto.sign(null, receiptDigest(unsignedReceipt), KEYS.receipt.priv).toString('base64') };

      const doc = {
        format: 'qodiqa-proof/1', generatedAt: T0 + 10000, subject: { tenantId: 'tenant1', requestId: RID },
        artifact, auditEntries: mine, chainPath,
        transparency: { leaf, inclusionProof: { leafIndex: 0, treeSize: 1, merklePath: [] }, root },
        checkpoint, anchors: [{ kind: 'git', receipt: 'anchors/2026-10-21.json@0000000000000000000000000000000000000000' }], receipt,
        keys: [
          { keyId: KEY_IDS.artifact, publicKeySpkiB64: KEYS.artifact.pubB64, status: 'active', activatedAt: T0 - 1000, retiredAt: null, revokedAt: null },
          { keyId: KEY_IDS.transparency, publicKeySpkiB64: KEYS.transparency.pubB64, status: 'active' },
          { keyId: KEY_IDS.checkpoint, publicKeySpkiB64: KEYS.checkpoint.pubB64, status: 'active' },
          { keyId: KEY_IDS.receipt, publicKeySpkiB64: KEYS.receipt.pubB64, status: 'active' },
        ],
      };
      return { doc, chain, mine, decision, artifact };
    });
  } finally { if (prevFlag === undefined) delete process.env.QODIQA_AUDIT_SCHEMA_V8; else process.env.QODIQA_AUDIT_SCHEMA_V8 = prevFlag; }
}

module.exports = { KEYS, KEY_IDS, H, RID, OTHER_A, T0, build, reseal, clone, withFixedClock, buildBaseProof, keyOf };
