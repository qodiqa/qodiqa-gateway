'use strict';

/**
 * labelling.
 *   M8   the witness enforced position, not predecessor: a checkpoint ABOVE its top with a fabricated head and
 *        predecessor (a forward fork) was co-signed. It must now be refused (WITNESS_FORK_REFUSED) unless an explicit
 *        re-baseline bound to that exact statement is configured, which is then recorded in the witness log.
 *   M10  the boot check verified only the anchors present in the export: removing the export's tail went undetected.
 *        The export's top is now cross-checked against the local witness log head and the live checkpoint set.
 * a `local` witness is not independent of the operator: boot results say so (anchoringIndependence).
 * Regression tests: each fails on the pre-fix code (HEAD 233d723c) and passes after the fix.
 * Throwaway keys only (generated per run in a temp dir). No network, no DB.
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { signCheckpoint } = require('../src/core/audit/checkpoint/checkpoint');
const { LocalFileWitness, ThreadedLocalWitness, anchoringIndependence, statementFor } = require('../src/core/audit/anchoring/witness');
const anchors = require('../src/core/audit/anchoring/anchors');
const cpw = require('../src/core/audit/checkpoint/checkpointWriter');

const H = (n) => crypto.createHash('sha256').update(`dd026-head-${n}`).digest('hex');
function ckKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { keyId: `cp-dd026-${crypto.randomBytes(3).toString('hex')}:key_v1`, version: 1,
    privDer: privateKey.export({ type: 'pkcs8', format: 'der' }), pubDer: publicKey.export({ type: 'spki', format: 'der' }) };
}
const realCk = ckKey();
const ks = { ensureActiveKey: () => realCk };
const resolveReal = (keyId) => { if (keyId !== realCk.keyId) throw new Error(`unknown checkpoint key ${keyId}`); return realCk.pubDer; };
const sign = (n, prev, head = H(n)) => signCheckpoint({ chainLength: n, headHash: head, previousCheckpointHash: prev ? prev.payloadHash : null }, { keyStore: ks });

let dir;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dd026-')); });
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });
const mkWitness = (o = {}) => new LocalFileWitness({ witnessId: 'w-dd026', keyPath: path.join(dir, 'w', 'key.json'), logPath: path.join(dir, 'w', 'log.jsonl'), ...o });

describe('M8 — the witness enforces the predecessor, not only the position', () => {
  test('DD026-M8-01 a forward fork (higher position, fabricated head and predecessor) is REFUSED and nothing is recorded', () => {
    const w = mkWitness();
    const c20 = sign(20); const c44 = sign(44, c20);
    w.cosign(c20); w.cosign(c44);
    const forged = signCheckpoint({ chainLength: 50, headHash: 'f'.repeat(64), previousCheckpointHash: 'a'.repeat(64) }, { keyStore: ks });
    expect(() => w.cosign(forged)).toThrow(expect.objectContaining({ code: 'WITNESS_FORK_REFUSED' }));
    // pre-fix: co-signed. Nothing logged, no position claimed:
    expect(w.head()).toEqual({ chainLength: 44, checkpointPayloadHash: c44.payloadHash, headHash: H(44) });
    expect(fs.existsSync(path.join(dir, 'w', 'log.jsonl.positions', '50'))).toBe(false);
  });

  test('DD026-M8-02 a fork that re-links to an OLDER witnessed checkpoint (skipping the top) is refused', () => {
    const w = mkWitness();
    const c20 = sign(20); const c44 = sign(44, c20);
    w.cosign(c20); w.cosign(c44);
    expect(() => w.cosign(sign(60, c20, 'e'.repeat(64)))).toThrow(expect.objectContaining({ code: 'WITNESS_FORK_REFUSED' }));
  });

  test('DD026-M8-03 the genuine chained successor is co-signed; idempotency and rollback/equivocation are unchanged', () => {
    const w = mkWitness();
    const c20 = sign(20); const c44 = sign(44, c20); const c60 = sign(60, c44);
    w.cosign(c20); const k44 = w.cosign(c44);
    expect(w.cosign(c44)).toEqual(k44); // idempotent at the top
    expect(w.cosign(c60)).toEqual(expect.objectContaining({ witnessId: 'w-dd026' }));
    expect(() => w.cosign(sign(10))).toThrow(expect.objectContaining({ code: 'WITNESS_ROLLBACK_REFUSED' }));
    expect(() => w.cosign(sign(60, c44, 'd'.repeat(64)))).toThrow(expect.objectContaining({ code: 'WITNESS_EQUIVOCATION_REFUSED' }));
  });

  test('DD026-M8-04 an explicit re-baseline bound to the exact statement is accepted and LOGGED; a stale ack is not', () => {
    const c20 = sign(20); mkWitness().cosign(c20);
    const fresh = sign(70); // new history root: no predecessor
    const ack = `70:${fresh.payloadHash.slice(0, 16)}`;
    expect(() => mkWitness({ rebaselineAck: `71:${fresh.payloadHash.slice(0, 16)}` }).cosign(fresh)).toThrow(expect.objectContaining({ code: 'WITNESS_FORK_REFUSED' }));
    expect(() => mkWitness().cosign(fresh)).toThrow(new RegExp(`rebaselineAck=${ack}`));
    expect(mkWitness({ rebaselineAck: ack }).cosign(fresh)).toEqual(expect.objectContaining({ witnessId: 'w-dd026' }));
    const last = fs.readFileSync(path.join(dir, 'w', 'log.jsonl'), 'utf8').trim().split('\n').pop();
    expect(JSON.parse(last).rebaseline).toEqual({ previousTop: { chainLength: 20, checkpointPayloadHash: c20.payloadHash }, ack });
    // after the re-baseline the new history continues normally (chained) without the ack
    expect(mkWitness().cosign(sign(80, fresh))).toEqual(expect.objectContaining({ witnessId: 'w-dd026' }));
  });

  test('DD026-M8-05 the gateway (worker-thread) witness refuses the fork too', async () => {
    const tw = new ThreadedLocalWitness({ witnessId: 'w-dd026', keyPath: path.join(dir, 'w', 'key.json'), logPath: path.join(dir, 'w', 'log.jsonl') });
    const c1 = sign(1); await tw.cosign(c1);
    await expect(tw.cosign(sign(2, null, 'c'.repeat(64)))).rejects.toMatchObject({ code: 'WITNESS_FORK_REFUSED' });
    await expect(tw.cosign(sign(2, c1))).resolves.toEqual(expect.objectContaining({ witnessId: 'w-dd026' }));
  });

  test('DD026-M8-06 publishAnchor catches a witness up on a missed predecessor from the export (no false refusal after an outage)', async () => {
    const w = mkWitness(); const exportPath = path.join(dir, 'customer', 'anchors.jsonl');
    const c10 = sign(10); const c20 = sign(20, c10); const c30 = sign(30, c20);
    expect((await anchors.publishAnchor(c10, { witnesses: [w], exportPath, trustedWitnessKeys: [] })).errors).toEqual([]);
    const down = { witnessId: 'w-dd026', cosign: async () => { const e = new Error('down'); e.code = 'WITNESS_TIMEOUT'; throw e; } };
    expect((await anchors.publishAnchor(c20, { witnesses: [down], exportPath, trustedWitnessKeys: [] })).errors[0].code).toBe('WITNESS_TIMEOUT');
    const r = await anchors.publishAnchor(c30, { witnesses: [w], exportPath, trustedWitnessKeys: [] });
    expect(r.errors).toEqual([]);
    expect(r.record.cosignatures).toHaveLength(1);
    expect(w.head().chainLength).toBe(30);
    // …but a real fork is still refused and reported as a refusal
    const fork = sign(40, c20, 'b'.repeat(64));
    const rf = await anchors.publishAnchor(fork, { witnesses: [w], exportPath, trustedWitnessKeys: [] });
    expect(rf.errors.map((e) => e.code)).toEqual(['WITNESS_FORK_REFUSED']);
  });
});

describe('M10 — boot detects a truncated anchor export', () => {
  // A real chain of 3 anchored checkpoints (10/20/30) with a local witness and a sidecar.
  async function setup() {
    const witness = mkWitness();
    const exportPath = path.join(dir, 'customer', 'anchors.jsonl');
    const c10 = sign(10); const c20 = sign(20, c10); const c30 = sign(30, c20);
    for (const c of [c10, c20, c30]) expect((await anchors.publishAnchor(c, { witnesses: [witness], exportPath, trustedWitnessKeys: [] })).errors).toEqual([]);
    const logPath = path.join(dir, 'audit.log');
    const writeSidecar = (cps) => fs.writeFileSync(`${logPath}.checkpoints.jsonl`, cps.map((c) => JSON.stringify(c)).join('\n') + '\n');
    writeSidecar([c10, c20, c30]);
    const events = [];
    const deps = (over = {}) => ({
      auditLog: { memorySnapshot: () => ({ modernCount: 30 }), getModernEntryAt: async (i) => ({ hash: H(i + 1) }), getChainStart: () => null },
      pgPool: { isEnabled: () => false }, keyStore: { getPublicKey: (id) => ({ pubDer: resolveReal(id) }) },
      emit: (l, t, d) => events.push({ l, t, d }), logPath,
      anchoring: { exportPath: () => exportPath, enabled: () => true, read: anchors.readAnchors, verify: anchors.verifyChainAgainstAnchors,
        trustedWitnessKeys: () => ({ keys: [witness.publicKeyRecord()] }), witnesses: () => [witness], independence: () => 'none-local-witness' },
      ...over });
    const truncateExport = (keep) => { const lines = fs.readFileSync(exportPath, 'utf8').split('\n').filter(Boolean); fs.writeFileSync(exportPath, lines.slice(0, keep).join('\n') + '\n'); };
    return { witness, exportPath, c10, c20, c30, deps, events, writeSidecar, truncateExport };
  }
  const envKeys = ['QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP', 'QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK', 'NODE_ENV'];
  let saved;
  beforeEach(() => { saved = Object.fromEntries(envKeys.map((k) => [k, process.env[k]])); for (const k of envKeys) delete process.env[k]; });
  afterEach(() => { for (const k of envKeys) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });

  test('DD026-M10-01 genuine state passes and reports the export tail + the independence label', async () => {
    const s = await setup();
    await expect(cpw.verifyAnchorsAtBoot(s.deps())).resolves.toEqual({ checked: true, anchors: 3, anchoringIndependence: 'none-local-witness',
      exportTail: { exportTop: 30, witnessesChecked: 1, unexportedLive: 0 } });
    expect(s.events.map((e) => e.t)).toEqual(expect.arrayContaining(['AUDIT_ANCHORING_NOT_INDEPENDENT', 'AUDIT_ANCHORS_BOOT_VERIFIED']));
  });

  test('DD026-M10-02 export tail removed + chain above the remaining anchor rewritten + checkpoints re-signed → FAILS CLOSED (witness head)', async () => {
    const s = await setup();
    s.truncateExport(1); // only the anchor at 10 remains
    const r20 = sign(20, s.c10, 'a'.repeat(64)); // insider's re-signed replacement, chaining to the remaining anchor
    s.writeSidecar([s.c10, r20]);
    const d = s.deps({ auditLog: { memorySnapshot: () => ({ modernCount: 20 }), getModernEntryAt: async (i) => ({ hash: i === 19 ? 'a'.repeat(64) : H(i + 1) }), getChainStart: () => null } });
    // pre-fix: resolves { checked: true, anchors: 1 }
    await expect(cpw.verifyAnchorsAtBoot(d)).rejects.toMatchObject({ code: 'AUDIT_ANCHOR_BOOT_FAILED',
      findings: expect.arrayContaining([expect.objectContaining({ code: 'ANCHOR_EXPORT_TRUNCATED' })]) });
  });

  test('DD026-M10-03 export tail removed, witness log not readable (exec witness): >1 live checkpoints above the export → FAILS CLOSED', async () => {
    const s = await setup();
    s.truncateExport(1);
    const d = s.deps({ anchoring: { ...s.deps().anchoring, witnesses: () => [{ witnessId: 'remote' }], independence: () => 'unverified-exec-witness' } });
    await expect(cpw.verifyAnchorsAtBoot(d)).rejects.toThrow(/ANCHOR_EXPORT_TRUNCATED .*2 live checkpoints \(entries 20, 30\)/);
  });

  test('DD026-M10-04 one live checkpoint above the export that does not chain to it → FAILS CLOSED', async () => {
    const s = await setup();
    s.truncateExport(2);
    const odd = sign(30, s.c10, H(30));
    s.writeSidecar([s.c10, s.c20, odd]);
    const d = s.deps({ anchoring: { ...s.deps().anchoring, witnesses: () => [] } });
    await expect(cpw.verifyAnchorsAtBoot(d)).rejects.toThrow(/does not chain to it/);
  });

  test('DD026-M10-05 benign crash window (newest checkpoint witnessed/signed but not exported) passes with a WARN', async () => {
    const s = await setup();
    s.truncateExport(2); // the export append of c30 never happened; c30 is in the sidecar and the witness log
    await expect(cpw.verifyAnchorsAtBoot(s.deps())).resolves.toMatchObject({ checked: true, anchors: 2, exportTail: { exportTop: 20, unexportedLive: 1 } });
    expect(s.events.map((e) => e.t)).toContain('AUDIT_ANCHOR_EXPORT_BEHIND');
  });

  test('DD026-M10-06 the explicit bootstrap override is honoured (and in production only with the head-bound ack)', async () => {
    const s = await setup();
    s.truncateExport(1);
    process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP = 'true';
    await expect(cpw.verifyAnchorsAtBoot(s.deps())).resolves.toMatchObject({ checked: true });
    expect(s.events.map((e) => e.t)).toContain('AUDIT_ANCHOR_EXPORT_TAIL_BOOTSTRAP');
    process.env.NODE_ENV = 'production';
    await expect(cpw.verifyAnchorsAtBoot(s.deps())).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOTSTRAP_REFUSED' });
  });
});

describe('honest independence labelling', () => {
  test('DD001-01 anchoringIndependence() never labels local (or none) as independent', () => {
    expect(anchoringIndependence({ QODIQA_WITNESS_MODE: 'local' })).toBe('none-local-witness');
    expect(anchoringIndependence({})).toBe('none-no-witness');
    expect(anchoringIndependence({ QODIQA_WITNESS_MODE: 'exec' })).toBe('unverified-exec-witness');
  });
  test('DD001-02 the production posture result carries the label', () => {
    const w = mkWitness();
    const r = cpw.verifyAnchoringPosture({ anchoring: { exportPath: () => path.join(dir, 'a.jsonl'), witnesses: () => [w],
      trustedWitnessKeys: () => ({ keys: [w.publicKeyRecord()] }), independence: () => anchoringIndependence({ QODIQA_WITNESS_MODE: 'local' }) } });
    expect(r).toEqual({ witnesses: 1, trustedKeys: 1, anchoringIndependence: 'none-local-witness' });
  });
  test('DD001-03 the statement format (wire) is unchanged', () => {
    expect(Object.keys(statementFor(sign(1), 'x')).sort()).toEqual(['chainLength', 'checkpointCreatedAt', 'checkpointId', 'checkpointPayloadHash', 'headHash', 'previousCheckpointHash', 'v', 'witnessId']);
  });
});
