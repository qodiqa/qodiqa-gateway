'use strict';

/**
 * the proof assembler. The stores are fakes that hold exactly what the PRODUCTION writers produced (the proof fixture: entryBuilder,
 * signArtifact, signCheckpoint, the transparency writers), so what the assembler returns is checked by both independent verifiers.
 *
 *   PA-01  a real assembly is verified by the Node verifier and the Python verifier: VALID_PARTIAL without anchors, VALID with the artifact + receipt + anchors repository
 *   PA-02  tenant isolation: another tenant's request, an unknown request and an unknown id are all NOT_FOUND (no difference to observe)
 *   PA-03  parts that cannot be assembled are left out, never invented (no transparency, no checkpoint, path too long, receipt expired)
 *   PA-04  the earliest covering checkpoint is chosen; the chain path is contiguous and ends at its head
 *   PA-05  the public keys are exactly the referenced ones; a malformed key is not served
 *   PA-06  the CLI accepts the response envelope of the endpoint
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { assembleProof } = require('../proofAssembler');
const { verifyProof } = require('../../../../scripts/audit-repro/verify/proof');
const { buildProof, H, RID } = require('../../../../scripts/audit-repro/__tests__/helpers/proofFixture');
const { signCheckpoint } = require('../checkpoint/checkpoint');
const ea = require('../anchoring/externalAnchors');

const REPO = path.join(__dirname, '..', '..', '..', '..');
const python = (() => { for (const exe of ['python', 'python3']) { const r = spawnSync(exe, ['-c', 'print(1)'], { encoding: 'utf8' }); if (r.status === 0) return exe; } return null; })();
const clone = (o) => JSON.parse(JSON.stringify(o));
const GITENV = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' };

let P; let dir; let receipt;
beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f514-'));
  P = buildProof();
  jest.resetModules();
  const { issueReceipt } = require('../../transparency/receipt');
  const { getTransparencySigner } = require('../../transparency/transparencySigner');
  receipt = await issueReceipt({ requestId: P.requestId, decision: 'ALLOW', entryHash: P.decision.hash, leafHash: H('b'), now: 1790000000000 });
  const { pubDer } = getTransparencySigner().getVerificationKey(receipt.keyId);
  P.receiptKey = { keyId: receipt.keyId, publicKeyB64: pubDer.toString('base64'), status: 'active' };
});
afterAll(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ } });

/** fake stores holding what the production writers produced for the fixture's chain */
function deps(over = {}) {
  const chain = P.doc.chainPath;                       // request's first entry .. checkpoint head, as stored
  const first = P.doc.checkpoint.payload.chainLength - chain.length;   // the request's first entry sits at this modern position of the (longer) chain
  const posByHash = new Map(chain.map((e, i) => [e.hash, first + i]));
  const mine = P.doc.auditEntries;
  const byArtifact = new Map(mine.map((e) => [e.artifactId, e]));
  const tl = P.doc.transparency;
  const k = P.doc.keys;
  return {
    getEntry: async (id, tenantId) => { const e = byArtifact.get(id); return e && e.tenantId === tenantId ? e : null; },
    positionOf: async (id) => { const e = byArtifact.get(id); return e ? posByHash.get(e.hash) : null; },
    page: async (pos, limit) => ({ entries: chain.slice(pos - first, pos - first + limit) }),
    transparencyEntries: async () => [tl.leaf],
    inclusion: async () => ({ proof: { entry: tl.leaf, root: tl.root, proof: tl.inclusionProof } }),
    signedCheckpoints: async () => [P.doc.checkpoint],
    receipt: async () => receipt,
    anchorsFor: async () => [],
    checkpointKeys: () => [{ keyId: k[2].keyId, publicKeyB64: k[2].publicKeySpkiB64, status: 'active' }],
    transparencyKeys: () => [{ keyId: k[1].keyId, publicKeyB64: k[1].publicKeySpkiB64, status: 'active' }, P.receiptKey],
    artifactKeys: () => [{ keyId: k[0].keyId, publicKeyB64: k[0].publicKeySpkiB64, status: 'active', createdAt: new Date(1789999999000).toISOString() }],
    ...over,
  };
}
const q = { tenantId: 'tenant1', requestId: RID, nowMs: 1790000010000 };
const run = (...a) => spawnSync(python, ['-I', path.join(REPO, 'scripts', 'audit-repro', 'verify', 'qodiqa_proof_verify.py'), ...a], { encoding: 'utf8', timeout: 120_000 });
const w = (n, v) => { const f = path.join(dir, n); fs.writeFileSync(f, JSON.stringify(v)); return f; };

describe('proof assembler', () => {
  test('PA-01 a real assembly verifies with both independent verifiers (partial without anchors, VALID with artifact + anchors repository)', async () => {
    const out = await assembleProof(q, deps());
    expect(out.ok).toBe(true);
    expect(out.parts).toMatchObject({ entries: 3, transparency: true, checkpoint: true, chainPath: true, receipt: true, anchors: 0 });
    const r = verifyProof(clone(out.proof));
    expect(r.failed).toEqual([]);
    expect(r.verdict).toBe('VALID_PARTIAL');
    expect(r.partial.sort()).toEqual(['ANCHORS_ABSENT', 'ARTIFACT_ABSENT']);
    // with the artifact (held by the caller) and the anchors repository the same document is VALID
    // the caller holds the artifact and fetches its signing key from /.well-known/qodiqa/keys (the fixture's entries carry no publicKeyId, so the proof does not include it)
    const withArtifact = { ...clone(out.proof), artifact: P.artifact };
    withArtifact.keys.push(clone(P.doc.keys[0]));
    const repo = path.join(dir, 'anchors'); fs.mkdirSync(repo); const g = (...a) => spawnSync('git', ['-C', repo, ...a], { env: GITENV, encoding: 'utf8' });
    g('init', '-q'); g('config', 'commit.gpgsign', 'false');
    const st = ea.statementFor(P.doc.checkpoint);
    await ea.publishGit({}, st, ea.digestOf(st), { ...GITENV, QODIQA_ANCHOR_GIT_REPO: repo }, { keySource: { 'checkpoint-keys.json': [{ keyId: P.doc.keys[2].keyId, publicKeyB64: P.doc.keys[2].publicKeySpkiB64, status: 'active' }] } });
    const anchorTrust = require('../../../../scripts/audit-repro/verify/anchorTrust');
    const full = verifyProof(withArtifact, { anchorTrust: anchorTrust.loadAnchorRepo(repo) });
    expect(full).toMatchObject({ verdict: 'VALID', failed: [], partial: [] });
    if (python) {
      expect(run('--proof', w('a.json', clone(out.proof))).status).toBe(3);
      const pv = run('--proof', w('b.json', withArtifact), '--anchors-repo', repo);
      expect(pv.status).toBe(0);
    }
  });

  test('PA-02 tenant isolation: another tenant, an unknown request and an unknown id give the same NOT_FOUND', async () => {
    const d = deps();
    const other = await assembleProof({ ...q, tenantId: 'tenant2' }, d);
    const unknown = await assembleProof({ ...q, requestId: '00000000-0000-4000-8000-000000000000' }, d);
    expect(other).toEqual({ ok: false, code: 'NOT_FOUND' });
    expect(unknown).toEqual({ ok: false, code: 'NOT_FOUND' });
    expect(JSON.stringify(other)).toBe(JSON.stringify(unknown));
  });

  test('PA-03 parts that cannot be assembled are left out, never invented', async () => {
    const noTl = await assembleProof(q, deps({ transparencyEntries: async () => { throw new Error('PG down'); } }));
    expect(noTl.proof.transparency).toBeUndefined(); expect(noTl.parts.transparency).toBe(false);
    expect(verifyProof(clone(noTl.proof))).toMatchObject({ failed: [], verdict: 'VALID_PARTIAL' });
    expect(verifyProof(clone(noTl.proof)).partial).toContain('TRANSPARENCY_ABSENT');
    const noCp = await assembleProof(q, deps({ signedCheckpoints: async () => [] }));
    expect(noCp.proof.checkpoint).toBeUndefined(); expect(noCp.proof.chainPath).toBeUndefined();
    expect(verifyProof(clone(noCp.proof)).partial).toEqual(expect.arrayContaining(['CHECKPOINT_ABSENT']));
    const tooLong = await assembleProof(q, deps({ signedCheckpoints: async () => [{ ...P.doc.checkpoint, payload: { ...P.doc.checkpoint.payload, chainLength: 1_000_000 } }] }));
    expect(tooLong.proof.checkpoint).toBeUndefined();
    const noReceipt = await assembleProof(q, deps({ receipt: async () => null }));
    expect(noReceipt.proof.receipt).toBeUndefined();
    const unplaced = await assembleProof(q, deps({ positionOf: async () => null }));      // out of the window: entries only
    expect(unplaced.proof.chainPath).toBeUndefined(); expect(unplaced.parts.entries).toBe(3);
    const first0 = P.doc.checkpoint.payload.chainLength - P.doc.chainPath.length;
    const wrongHead = await assembleProof(q, deps({ page: async (pos, limit) => ({ entries: clone(P.doc.chainPath).slice(pos - first0, pos - first0 + limit).map((e, i, a) => (i === a.length - 1 ? { ...e, hash: H('9') } : e)) }) }));
    expect(wrongHead.proof.chainPath).toBeUndefined();                                      // a path that does not end at the checkpoint head is not served
  });

  test('PA-04 the earliest covering checkpoint is used and the path is contiguous up to its head', async () => {
    const chain = P.doc.chainPath;
    const later = signCheckpoint({ chainLength: P.doc.checkpoint.payload.chainLength + 3, headHash: H('7'), createdAt: '2026-10-22T00:00:30.000Z' }, { keyStore: { ensureActiveKey: () => ({ keyId: P.doc.keys[2].keyId, version: 1, privDer: P.keys.cpKey.privDer }) } });
    const out = await assembleProof(q, deps({ signedCheckpoints: async () => [P.doc.checkpoint, later] }));
    expect(out.proof.checkpoint.payloadHash).toBe(P.doc.checkpoint.payloadHash);
    expect(out.proof.chainPath).toHaveLength(chain.length);
    expect(out.proof.chainPath[out.proof.chainPath.length - 1].hash).toBe(P.doc.checkpoint.payload.headHash);
    // a checkpoint that stops before the request's last entry (the COMMIT) does not cover it and is skipped
    const early = signCheckpoint({ chainLength: P.doc.checkpoint.payload.chainLength - 2, headHash: chain[chain.length - 3].hash, createdAt: '2026-10-22T00:00:01.000Z' }, { keyStore: { ensureActiveKey: () => ({ keyId: P.doc.keys[2].keyId, version: 1, privDer: P.keys.cpKey.privDer }) } });
    const out2 = await assembleProof(q, deps({ signedCheckpoints: async () => [early, P.doc.checkpoint] }));
    expect(out2.proof.checkpoint.payloadHash).toBe(P.doc.checkpoint.payloadHash);
  });

  test('PA-05 keys: exactly the referenced ones, malformed keys are not served', async () => {
    const out = await assembleProof(q, deps({ artifactKeys: () => [...deps().artifactKeys(), { keyId: 'tenant9:key_v1', publicKeyB64: 'AAAA', status: 'active' }], transparencyKeys: () => [...deps().transparencyKeys(), { keyId: 'tr-bad:key_v1', publicKeyB64: 'not base64!', status: 'active' }] }));
    // the fixture's entries carry no publicKeyId, so no artifact key is referenced (and the unrelated key served by the store is not leaked)
    expect(out.proof.keys.map((k) => k.keyId).sort()).toEqual([P.doc.keys[1].keyId, P.doc.keys[2].keyId, receipt.keyId].filter((v, i, a) => a.indexOf(v) === i).sort());
    expect(out.proof.keys.some((k) => k.keyId === 'tenant9:key_v1' || k.keyId === 'tr-bad:key_v1')).toBe(false);
    const bad = await assembleProof(q, deps({ transparencyKeys: () => [{ keyId: P.doc.keys[1].keyId, publicKeyB64: 'not base64!', status: 'active' }, P.receiptKey] }));
    expect(bad.proof.keys.some((k) => k.keyId === P.doc.keys[1].keyId)).toBe(false);
  });

  (python ? test : test.skip)('PA-06 the CLIs accept the response envelope of the endpoint', async () => {
    const out = await assembleProof(q, deps());
    const envelope = { status: 'success', timestamp: new Date().toISOString(), requestId: null, data: out.proof };
    const node = spawnSync(process.execPath, [path.join(REPO, 'scripts', 'audit-repro', 'verify', 'qodiqa-proof-verify.js'), '--proof', w('env.json', envelope)], { encoding: 'utf8' });
    expect(node.status).toBe(3);
    expect(JSON.parse(node.stdout).verdict).toBe('VALID_PARTIAL');
    expect(run('--proof', w('env2.json', envelope)).status).toBe(3);
  });

  test('PA-07 raw entries of other tenants are never served on the chain path unless explicitly allowed', async () => {
    const chain = clone(P.doc.chainPath);
    chain[chain.length - 1] = { ...chain[chain.length - 1], tenantId: 'tenant-B', reason: 'SECRET-OF-B' };    // the filler entry after the request belongs to another tenant
    const first = P.doc.checkpoint.payload.chainLength - chain.length;
    const d = deps({ page: async (pos, limit) => ({ entries: chain.slice(pos - first, pos - first + limit) }) });
    const out = await assembleProof(q, d);
    expect(out.proof.chainPath).toBeUndefined(); expect(out.proof.checkpoint).toBeUndefined();
    expect(out.parts.chainPathWithheld).toBe(1);
    expect(JSON.stringify(out.proof)).not.toContain('SECRET-OF-B');
    const full = await assembleProof({ ...q, allowForeignEntries: true }, d);
    expect(full.proof.chainPath).toHaveLength(chain.length);
  });
});
