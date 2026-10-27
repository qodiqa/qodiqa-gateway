'use strict';

/**
 * Test fixture for the proof verifiers: builds a complete `qodiqa-proof/1` document from the PRODUCTION writers (entryBuilder,
 * signArtifact, signCheckpoint, issueReceipt) with throw-away Ed25519 keys, so the independent verifiers are checked against what the
 * gateway really produces. The Merkle leaf / root are built with the documented algorithms (the independent verifier's own primitives,
 * proven equal to production by the existing differential suites).
 */

const crypto = require('crypto');
const eb = require('../../../../src/core/audit/entryBuilder');
const { signArtifact } = require('../../../../src/validation/signArtifact');
const { signCheckpoint } = require('../../../../src/core/audit/checkpoint/checkpoint');
const transparency = require('../../verify/transparency');

const H = (c) => c.repeat(64);
const RID = '5b1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b';
const OTHER = '9c1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b';
const TIMESTAMP = 1790000000000;

function ed25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { pubB64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'), privDer: privateKey.export({ format: 'der', type: 'pkcs8' }), priv: privateKey };
}
const build = (spec, prev) => JSON.parse(JSON.stringify(eb.buildEntry(eb.normalizeFields(spec), prev)));

/**
 * @param {{ v8?: boolean, commit?: boolean, issuedAt?: number }} [o]
 */
function buildProof(o = {}) {
  const v8 = o.v8 !== false;
  const prevFlag = process.env.QODIQA_AUDIT_SCHEMA_V8;
  if (v8) process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true'; else delete process.env.QODIQA_AUDIT_SCHEMA_V8;
  try {
    const artKey = ed25519(); const txKey = ed25519(); const cpKey = ed25519();
    const keyId = 'tenant1:key_v1';
    const requestHash = H('a');
    const artifact = signArtifact({
      payload: { requestId: RID, requestHash, policyHash: H('b'), provider: 'local', tenantId: 'tenant1' },
      timestamp: TIMESTAMP, expiry: TIMESTAMP + 60000, publicKeyId: keyId,
    }, artKey.privDer);

    const facts = v8 ? { issuedAt: o.issuedAt ?? TIMESTAMP, protocolVersion: 1 } : {};
    const base = { inputHash: requestHash, signature: artifact.signature, requestHash, policyHash: H('b'), verificationResult: true, tenantId: 'tenant1' };
    const outputHash = eb.outputHashOf('the answer');
    const filler = (id) => ({ ...base, signature: 'sig-other', artifactId: id, decision: 'ALLOW', stage: 'PROVIDER_EXECUTION', outputHash: eb.EMPTY_OUTPUT_HASH, requestId: id, executingProvider: 'local' });
    const specs = [
      filler(OTHER),
      { ...base, artifactId: eb.lifecycleArtifactId(RID, 'INTENT'), entryType: 'INTENT', decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', requestId: RID, executingProvider: 'local', ...facts },
      { ...base, artifactId: RID, decision: 'ALLOW', stage: 'PROVIDER_EXECUTION', outputHash, requestId: RID, executingProvider: 'local', ...facts },
    ];
    if (v8 && o.commit !== false) {
      specs.push({ artifactId: `${RID}:commit`, entryType: 'COMMIT', decision: 'ALLOW', reason: 'RESPONSE_DELIVERED', signature: artifact.signature, requestId: RID, tenantId: 'tenant1', outputHash, bytesDelivered: 10, completionStatus: 'COMPLETE', ...facts });
    }
    specs.push(filler(`${OTHER.slice(0, -1)}0`));
    const chain = []; let prev = 'GENESIS';
    for (const s of specs) { const e = build(s, prev); chain.push(e); prev = e.hash; }
    const mine = chain.filter((e) => e.requestId === RID);
    const first = chain.findIndex((e) => e.requestId === RID);
    const decision = mine.find((e) => (e.entryType ?? 'DECISION') === 'DECISION');
    const chainPath = chain.slice(first);

    // transparency: one leaf documenting the DECISION, a one-leaf tree, a signed root
    const payload = { requestId: RID, decision: 'ALLOW', reason: 'ALL_CHECKS_PASSED', stage: 'PROVIDER_EXECUTION', auditEntryHash: decision.hash, tenantId: 'tenant1' };
    const leafRec = { id: 1, transparencyId: crypto.randomUUID(), entryType: 'AUDIT', artifactId: RID, evidenceChainId: null, verificationId: null, payloadHash: transparency.payloadHash(payload), previousEntryHash: null, signerKeyId: 'tr-test:key_v1' };
    leafRec.entryHash = transparency.entryHash(leafRec);
    leafRec.signature = crypto.sign(null, Buffer.from(leafRec.entryHash, 'hex'), txKey.priv).toString('base64');
    leafRec.payload = payload;
    const root = { rootId: crypto.randomUUID(), seqFrom: 1, seqTo: 1, entryCount: 1, rootHash: transparency.merkleRoot([leafRec.entryHash]), previousRootHash: null, signerKeyId: 'tr-test:key_v1' };
    root.signature = crypto.sign(null, transparency.rootDigest(root), txKey.priv).toString('base64');

    const cp = signCheckpoint({ chainLength: chain.length, headHash: chain[chain.length - 1].hash, createdAt: new Date(TIMESTAMP + 5000).toISOString() },
      { keyStore: { ensureActiveKey: () => ({ keyId: 'cp-test:key_v1', version: 1, privDer: cpKey.privDer }) } });

    const doc = {
      format: 'qodiqa-proof/1', generatedAt: TIMESTAMP + 10000, subject: { tenantId: 'tenant1', requestId: RID },
      artifact, auditEntries: mine, chainPath,
      transparency: { leaf: leafRec, inclusionProof: { leafIndex: 0, treeSize: 1, merklePath: [] }, root },
      checkpoint: cp, anchors: [],
      keys: [
        { keyId, publicKeySpkiB64: artKey.pubB64, status: 'active', activatedAt: TIMESTAMP - 1000, retiredAt: null, revokedAt: null },
        { keyId: 'tr-test:key_v1', publicKeySpkiB64: txKey.pubB64, status: 'active' },
        { keyId: 'cp-test:key_v1', publicKeySpkiB64: cpKey.pubB64, status: 'active' },
      ],
    };
    return { doc, chain, mine, decision, artifact, keys: { artKey, txKey, cpKey }, requestId: RID };
  } finally { if (prevFlag === undefined) delete process.env.QODIQA_AUDIT_SCHEMA_V8; else process.env.QODIQA_AUDIT_SCHEMA_V8 = prevFlag; }
}

module.exports = { buildProof, ed25519, H, RID, TIMESTAMP };
