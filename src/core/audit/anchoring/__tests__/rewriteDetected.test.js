'use strict';

/**
 * the rewrite test. Someone with the database / audit log (and, in the worst case, the checkpoint signing key) modifies an entry and REBUILDS
 * the hash chain so that it is internally perfect. Only what sits outside their reach can still say it happened: the witnesses' own logs, the
 * witness-cosigned export, the external anchors repository.
 *
 *   RW-01  the attack works against the chain alone: the rewritten chain is self-consistent (that is why anchors exist)
 *   RW-02  against the witness-cosigned anchors, the rewritten chain is CHAIN_REWRITTEN at the anchored position (production verifier and independent verifier)
 *   RW-03  re-signing the checkpoint with the stolen key and replacing the live checkpoint set: CHECKPOINT_REPLACED / the forged checkpoint cannot be witnessed
 *   RW-04  the witnesses refuse to cosign a different head for a position they already witnessed (both of them), so the forged checkpoint never gains a cosignature
 *   RW-05  rewriting the customer-held export too: a forged record without verifying cosignatures is ANCHOR_NOT_WITNESSED, and the external git anchors flag the fork
 *   RW-06  truncating the tail (rollback) is CHAIN_ROLLED_BACK
 *   RW-07  the control: the untouched chain verifies against the same anchors
 */

jest.mock('../../../../../services/logger', () => ({ emit: jest.fn() }));

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const eb = require('../../entryBuilder');
const { signCheckpoint } = require('../../checkpoint/checkpoint');
const anchors = require('../anchors');
const ea = require('../externalAnchors');
const { LocalFileWitness } = require('../witness');
const indepAnchors = require('../../../../../scripts/audit-repro/verify/anchors');
const indepCheckpoint = require('../../../../../scripts/audit-repro/verify/checkpoint');
const contract = require('../../../../../scripts/audit-repro/verify/auditContract');
const anchorTrust = require('../../../../../scripts/audit-repro/verify/anchorTrust');

const N = 40; const ANCHORED = 30; const TAMPER_AT = 10;   // 0-based index of the entry the attacker changes
let dir; let cpKey; let cpPubDer; let w1; let w2; let trust; let exp; let anchorRec; let signedCp; let original; let anchorsRepo;
const GITENV = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' };
const git = (cwd, ...a) => { const r = spawnSync('git', ['-C', cwd, ...a], { encoding: 'utf8', env: GITENV }); if (r.status !== 0) throw new Error(`git ${a.join(' ')}: ${r.stderr}`); return r.stdout; };

const spec = (i, decision = 'ALLOW') => ({ artifactId: `art-${i}`, inputHash: 'a'.repeat(64), decision, outputHash: eb.EMPTY_OUTPUT_HASH, signature: 's'.repeat(64),
  requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 't' });
function build(mutate) {
  const out = []; let prev = 'GENESIS';
  for (let i = 0; i < N; i++) { const e = JSON.parse(JSON.stringify(eb.buildEntry(eb.normalizeFields(mutate ? mutate(i) : spec(i)), prev))); out.push(e); prev = e.hash; }
  return out;
}
const cpOf = (chain, n, id) => signCheckpoint({ checkpointId: id, chainLength: n, headHash: chain[n - 1].hash, createdAt: new Date(1790000000000 + n * 1000).toISOString() },
  { keyStore: { ensureActiveKey: () => ({ keyId: 'cp-rw:key_v1', version: 1, privDer: cpKey.privDer }) } });
const verifyAgainst = (chain, o = {}) => anchors.verifyChainAgainstAnchors({
  anchors: o.anchors || [anchorRec], chainLength: chain.length, headHashAt: async (n) => (chain[n - 1] ? chain[n - 1].hash : null),
  checkpoints: o.checkpoints || [signedCp], resolveCheckpointKey: () => ({ pubDer: cpPubDer, status: 'active' }), trustedWitnessKeys: trust, minWitnesses: 2, prunedBefore: 0 });
const indep = (chain, o = {}) => indepAnchors.verifyAnchors({ anchors: o.anchors || [anchorRec], entryHashes: chain.map((e) => e.hash), offset: 0, checkpoints: o.checkpoints || [signedCp],
  resolve: indepCheckpoint.keyResolver({ keys: [{ keyId: 'cp-rw:key_v1', publicKey: cpPubDer.toString('base64'), status: 'active' }] }),
  witnessKeys: trust, minWitnesses: 2 });

beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f59-'));
  const kp = crypto.generateKeyPairSync('ed25519');
  cpKey = { privDer: kp.privateKey.export({ format: 'der', type: 'pkcs8' }) }; cpPubDer = kp.publicKey.export({ format: 'der', type: 'spki' });
  original = build();
  signedCp = cpOf(original, ANCHORED, 'cp-original');
  const mk = (id) => new LocalFileWitness({ witnessId: id, keyPath: path.join(dir, `${id}-key.json`), logPath: path.join(dir, `${id}-log.jsonl`) });
  w1 = mk('w-a'); w2 = mk('w-b');
  trust = { keys: [w1.publicKeyRecord(), w2.publicKeyRecord()] };
  exp = path.join(dir, 'anchors.jsonl');
  const r = await anchors.publishAnchor(signedCp, { witnesses: [w1, w2], exportPath: exp, trustedWitnessKeys: trust, requireCosignature: true, minWitnesses: 2 });
  anchorRec = r.record;
  // the external anchors repository (what the operator mirrors outside the gateway)
  anchorsRepo = path.join(dir, 'anchors-repo'); fs.mkdirSync(anchorsRepo); git(anchorsRepo, 'init', '-q'); git(anchorsRepo, 'config', 'commit.gpgsign', 'false');
  const st = ea.statementFor(signedCp);
  await ea.publishGit({}, st, ea.digestOf(st), { ...GITENV, QODIQA_ANCHOR_GIT_REPO: anchorsRepo }, { keySource: { 'checkpoint-keys.json': [{ keyId: 'cp-rw:key_v1', publicKeyB64: cpPubDer.toString('base64'), status: 'active' }] } });
});
afterAll(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ } });

describe('a rewritten, re-chained history is detected by the anchors', () => {
  test('RW-07 control: the untouched chain verifies against the anchors (two cosignatures)', async () => {
    expect(anchorRec.cosignatures).toHaveLength(2);
    expect(await verifyAgainst(original)).toMatchObject({ ok: true, findings: [] });
    expect(indep(original)).toMatchObject({ valid: true, findings: [] });
  });

  test('RW-01 the attack works against the chain alone: the rewritten chain is internally perfect', () => {
    const forged = build((i) => spec(i, i === TAMPER_AT ? 'BLOCK' : 'ALLOW'));
    expect(forged[TAMPER_AT].decision).toBe('BLOCK');
    expect(forged[TAMPER_AT].hash).not.toBe(original[TAMPER_AT].hash);
    expect(forged[N - 1].hash).not.toBe(original[N - 1].hash);
    expect(contract.walkChain(forged, { startPrevHash: 'GENESIS' }).valid).toBe(true);     // nothing in the chain itself says it was changed
  });

  test('RW-02 against the witness-cosigned anchors the rewritten chain is CHAIN_REWRITTEN (production and independent verifier)', async () => {
    const forged = build((i) => spec(i, i === TAMPER_AT ? 'BLOCK' : 'ALLOW'));
    const prod = await verifyAgainst(forged);
    expect(prod.ok).toBe(false);
    expect(prod.findings.map((f) => f.code)).toContain('CHAIN_REWRITTEN');
    const ind = indep(forged);
    expect(ind.valid).toBe(false);
    expect(ind.findings.map((f) => f.code)).toContain('CHAIN_REWRITTEN');
  });

  test('RW-03 re-signing the checkpoint with the stolen key and replacing the live set: still detected', async () => {
    const forged = build((i) => spec(i, i === TAMPER_AT ? 'BLOCK' : 'ALLOW'));
    const reSigned = cpOf(forged, ANCHORED, 'cp-original');      // same id, new head, valid signature
    const prod = await verifyAgainst(forged, { checkpoints: [reSigned] });
    expect(prod.findings.map((f) => f.code)).toEqual(expect.arrayContaining(['CHAIN_REWRITTEN', 'CHECKPOINT_REPLACED']));
    expect(indep(forged, { checkpoints: [reSigned] }).findings.map((f) => f.code)).toEqual(expect.arrayContaining(['CHAIN_REWRITTEN', 'CHECKPOINT_REPLACED']));
    const dropped = await verifyAgainst(forged, { checkpoints: [] });                     // or simply delete it from the live set
    expect(dropped.findings.map((f) => f.code)).toContain('CHECKPOINT_DELETED');
  });

  test('RW-04 both witnesses refuse a different head for a position they already witnessed: the forged checkpoint gains no cosignature', async () => {
    const forged = build((i) => spec(i, i === TAMPER_AT ? 'BLOCK' : 'ALLOW'));
    const reSigned = cpOf(forged, ANCHORED, 'cp-forged');
    for (const w of [w1, w2]) await expect((async () => w.cosign(reSigned))()).rejects.toMatchObject({ code: 'WITNESS_EQUIVOCATION_REFUSED' });
    // and a publish with the quorum required holds it (nothing is exported without verified cosignatures)
    const r = await anchors.publishAnchor(reSigned, { witnesses: [w1, w2], exportPath: path.join(dir, 'forged-export.jsonl'), trustedWitnessKeys: trust, requireCosignature: true, minWitnesses: 2 });
    expect(r.record).toBeNull(); expect(r.held).toBe(true);
    expect(fs.existsSync(path.join(dir, 'forged-export.jsonl'))).toBe(false);
  });

  test('RW-05 rewriting the customer-held export as well: the forged record is not witnessed, and the external git anchors flag the fork', async () => {
    const forged = build((i) => spec(i, i === TAMPER_AT ? 'BLOCK' : 'ALLOW'));
    const reSigned = cpOf(forged, ANCHORED, 'cp-original');
    const forgedRecord = { anchorVersion: 1, checkpoint: { payload: reSigned.payload, payloadHash: reSigned.payloadHash, signature: reSigned.signature }, cosignatures: anchorRec.cosignatures, exportedAt: anchorRec.exportedAt };
    const prod = await verifyAgainst(forged, { anchors: [forgedRecord], checkpoints: [reSigned] });
    expect(prod.ok).toBe(false);
    expect(prod.findings.map((f) => f.code)).toContain('ANCHOR_NOT_WITNESSED');              // the old cosignatures are for another statement
    // the external anchors repository still pins the original head
    const repo = anchorTrust.loadAnchorRepo(anchorsRepo);
    expect(repo.findings).toEqual([]);
    const ev = anchorTrust.evaluateProof({ checkpoint: reSigned, keys: [], auditEntries: [], chainPath: [] }, repo);
    expect(ev.failed).toEqual(expect.arrayContaining([{ id: 'CHECKPOINT_ANCHORED', code: 'CHECKPOINT_FORKS_ANCHOR' }]));   // same position, a different head
    const reSignedNewPos = cpOf(forged, ANCHORED, 'cp-other-id');                              // a fresh checkpoint id does not help the attacker either
    expect(anchorTrust.evaluateProof({ checkpoint: reSignedNewPos, keys: [], auditEntries: [], chainPath: [] }, repo).failed)
      .toEqual(expect.arrayContaining([{ id: 'CHECKPOINT_ANCHORED', code: 'CHECKPOINT_FORKS_ANCHOR' }]));
  });

  test('RW-08 one compromised witness cannot reach the quorum by repeating its own cosignature (or by being trusted under two ids)', async () => {
    const one = anchorRec.cosignatures[0];
    const dup = { ...anchorRec, cosignatures: [one, { ...one }] };
    const prod = await verifyAgainst(original, { anchors: [dup] });
    expect(prod.findings.map((x) => x.code)).toContain('ANCHOR_NOT_WITNESSED');
    expect(indep(original, { anchors: [dup] }).findings.map((x) => x.code)).toContain('ANCHOR_NOT_WITNESSED');
    // the same key trusted under a second witness id, with a cosignature the key really made for that id
    const second = new LocalFileWitness({ witnessId: 'w-a-alias', keyPath: path.join(dir, 'w-a-key.json'), logPath: path.join(dir, 'alias-log.jsonl') });
    const alias = second.cosign(signedCp);
    const trust2 = { keys: [...trust.keys, { ...second.publicKeyRecord() }] };
    const aliased = { ...anchorRec, cosignatures: [one, alias] };
    const r = await anchors.verifyChainAgainstAnchors({ anchors: [aliased], chainLength: original.length, headHashAt: async (n) => original[n - 1].hash, checkpoints: [signedCp],
      resolveCheckpointKey: () => ({ pubDer: cpPubDer, status: 'active' }), trustedWitnessKeys: trust2, minWitnesses: 2, prunedBefore: 0 });
    expect(r.findings.map((x) => x.code)).toContain('ANCHOR_NOT_WITNESSED');
  });

  test('RW-06 truncating the tail below the anchored position is CHAIN_ROLLED_BACK', async () => {
    const truncated = original.slice(0, ANCHORED - 5);
    expect((await verifyAgainst(truncated)).findings.map((f) => f.code)).toContain('CHAIN_ROLLED_BACK');
    expect(indep(truncated).findings.map((f) => f.code)).toContain('CHAIN_ROLLED_BACK');
  });
});
