'use strict';

/**
 * two co-signing witnesses, each a SEPARATE PROCESS with its own key and its own append-only log.
 *
 *   MW-01  QODIQA_WITNESSES_CONFIG builds one witness per entry; duplicate ids / bad modes are refused
 *   MW-02  minWitnessesFromEnv: 2 with two witnesses, 1 with one, an explicit value wins
 *   MW-03  two real witnesses both cosign: the anchor is exported with two verifying cosignatures
 *   MW-04  one witness refusing (rollback) leaves the checkpoint HELD with WITNESS_QUORUM_NOT_MET: one compromised/outvoted witness cannot anchor alone
 *   MW-05  a witness that is down: held; once it is back the backlog drains in chain order
 *   MW-06  a cosignature from a key outside the trust set does not count towards the quorum
 *   MW-07  the two witnesses keep independent logs and keys (a fork offered to one is refused by it, the other is unaffected)
 *   MW-08  boot rules for the witness list
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { witnessesFromEnv, minWitnessesFromEnv, LocalFileWitness, statementFor, verifyCosignature } = require('../witness');
const { publishAnchor, publishAnchorBacklog, readAnchors } = require('../anchors');

const REPO = path.join(__dirname, '..', '..', '..', '..', '..');
const COSIGN = path.join(REPO, 'scripts', 'anchor', 'witness-cosign.js');
let dir;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f56-')); });
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

const H = (n) => crypto.createHash('sha256').update(`head-${n}`).digest('hex');
let seq = 0;
const cp = (chainLength, prev = null, head = H(chainLength)) => {
  const payload = { checkpointId: `cp-${++seq}`, chainLength, headHash: head, previousCheckpointHash: prev, createdAt: '2026-10-22T00:00:00.000Z' };
  return { payload, payloadHash: crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex'), signature: 's' };
};

/** One witness = its own key + log directory; returns the config entry and its trust record. */
function witnessEntry(id, extra = {}) {
  const keyPath = path.join(dir, `${id}-key.json`); const logPath = path.join(dir, `${id}-log.jsonl`);
  const trust = new LocalFileWitness({ witnessId: id, keyPath, logPath }).publicKeyRecord();   // creates the key
  return { entry: { witnessId: id, mode: 'exec', command: process.execPath, args: [COSIGN], ...extra }, trust, keyPath, logPath };
}
function config(entries, envs) {
  const f = path.join(dir, 'witnesses.json'); fs.writeFileSync(f, JSON.stringify(entries)); return f;
}
/** Exec witnesses read their key/log from the environment of the gateway process: give each its own through a wrapper script. */
function wrapped(w) {
  const js = path.join(dir, `${w.entry.witnessId}-run.js`);
  fs.writeFileSync(js, `process.env.WITNESS_ID=${JSON.stringify(w.entry.witnessId)};process.env.WITNESS_KEY_PATH=${JSON.stringify(w.keyPath)};process.env.WITNESS_LOG_PATH=${JSON.stringify(w.logPath)};require(${JSON.stringify(COSIGN)});`);
  return { ...w.entry, args: [js] };
}
const setup = (ids) => { const ws = ids.map((i) => witnessEntry(i)); const entries = ws.map(wrapped); return { ws, entries, list: witnessesFromEnv({ QODIQA_WITNESSES_CONFIG: config(entries) }), trust: { keys: ws.map((w) => w.trust) } }; };
const exp = () => path.join(dir, 'anchors.jsonl');

describe('multiple co-signing witnesses', () => {
  test('MW-01 the witness list is built from QODIQA_WITNESSES_CONFIG and validated', () => {
    const { list } = setup(['w-a', 'w-b']);
    expect(list.map((w) => w.witnessId)).toEqual(['w-a', 'w-b']);
    const f = (v) => { const p = path.join(dir, 'bad.json'); fs.writeFileSync(p, JSON.stringify(v)); return { QODIQA_WITNESSES_CONFIG: p }; };
    expect(() => witnessesFromEnv(f([]))).toThrow(/non-empty/);
    expect(() => witnessesFromEnv(f([{ witnessId: 'x', mode: 'exec', command: 'c' }, { witnessId: 'x', mode: 'exec', command: 'c' }]))).toThrow(/duplicate witnessId/);
    expect(() => witnessesFromEnv(f([{ witnessId: 'x', mode: 'carrier-pigeon' }]))).toThrow(/mode must be/);
    expect(() => witnessesFromEnv(f([{ witnessId: 'x', mode: 'exec' }]))).toThrow(/command is required/);
    expect(() => witnessesFromEnv(f([{ witnessId: 'x', mode: 'local', keyPath: 'k' }]))).toThrow(/keyPath and logPath/);
    expect(() => witnessesFromEnv({ QODIQA_WITNESSES_CONFIG: path.join(dir, 'missing.json') })).toThrow(/unreadable/);
  });

  test('MW-02 the quorum is 2 with two witnesses, 1 with one, and an explicit value wins', () => {
    expect(minWitnessesFromEnv({}, 2)).toBe(2);
    expect(minWitnessesFromEnv({}, 3)).toBe(2);
    expect(minWitnessesFromEnv({}, 1)).toBe(1);
    expect(minWitnessesFromEnv({}, 0)).toBe(1);
    expect(minWitnessesFromEnv({ QODIQA_ANCHOR_MIN_WITNESSES: '3' }, 3)).toBe(3);
    expect(minWitnessesFromEnv({ QODIQA_ANCHOR_MIN_WITNESSES: '1' }, 2)).toBe(1);
  });

  test('MW-03 two real witness processes both cosign: the exported anchor carries two verifying cosignatures', async () => {
    const { list, trust } = setup(['w-a', 'w-b']);
    const signed = cp(10);
    const r = await publishAnchor(signed, { witnesses: list, exportPath: exp(), trustedWitnessKeys: trust, requireCosignature: true });
    expect(r.errors).toEqual([]);
    expect(r.record.cosignatures.map((c) => c.witnessId).sort()).toEqual(['w-a', 'w-b']);
    for (const c of r.record.cosignatures) expect(verifyCosignature(statementFor(signed, c.witnessId), c, trust)).toEqual({ ok: true });
    expect(readAnchors(exp())).toHaveLength(1);
  });

  test('MW-04 one witness refusing (rollback) holds the checkpoint: a single witness cannot anchor alone', async () => {
    const { list, trust, ws } = setup(['w-a', 'w-b']);
    // w-b has already witnessed a LATER position (as if it had seen a longer chain): it refuses to go back
    const w2 = new LocalFileWitness({ witnessId: 'w-b', keyPath: ws[1].keyPath, logPath: ws[1].logPath });
    await w2.cosign(cp(50));
    const r = await publishAnchor(cp(10), { witnesses: list, exportPath: exp(), trustedWitnessKeys: trust, requireCosignature: true });
    expect(r.record).toBeNull(); expect(r.held).toBe(true);
    expect(r.errors.map((e) => e.code)).toEqual(expect.arrayContaining(['WITNESS_ROLLBACK_REFUSED', 'WITNESS_QUORUM_NOT_MET']));
    expect(fs.existsSync(exp())).toBe(false);
  });

  test('MW-05 a witness that is down holds the checkpoint; when it returns the backlog drains in chain order', async () => {
    const a = witnessEntry('w-a'); const b = witnessEntry('w-b');
    const good = wrapped(b);
    const broken = { ...good, args: [path.join(dir, 'does-not-exist.js')], retries: 0 };
    const trust = { keys: [a.trust, b.trust] };
    const down = witnessesFromEnv({ QODIQA_WITNESSES_CONFIG: config([wrapped(a), broken]) });
    const first = cp(10); const second = cp(20, first.payloadHash);
    const r1 = await publishAnchorBacklog(first, { witnesses: down, exportPath: exp(), trustedWitnessKeys: trust });
    expect(r1.exported).toBe(0); expect(r1.held).toBe(1); expect(fs.existsSync(exp())).toBe(false);
    const up = witnessesFromEnv({ QODIQA_WITNESSES_CONFIG: config([wrapped(a), good]) });
    const r2 = await publishAnchorBacklog(second, { witnesses: up, exportPath: exp(), trustedWitnessKeys: trust, backlog: [first] });
    expect(r2.exported).toBe(2); expect(r2.held).toBe(0);
    expect(readAnchors(exp()).map((x) => x.checkpoint.payload.chainLength)).toEqual([10, 20]);
    for (const rec of readAnchors(exp())) expect(rec.cosignatures).toHaveLength(2);
  });

  test('MW-06 a cosignature under a key outside the trust set does not count towards the quorum', async () => {
    const { list, ws } = setup(['w-a', 'w-b']);
    const stranger = witnessEntry('w-b-impostor').trust;
    const trust = { keys: [ws[0].trust, { ...stranger, witnessId: 'w-b' }] };   // the operator trusts a DIFFERENT key for w-b
    const r = await publishAnchor(cp(10), { witnesses: list, exportPath: exp(), trustedWitnessKeys: trust, requireCosignature: true });
    expect(r.record).toBeNull(); expect(r.held).toBe(true);
    expect(r.errors.map((e) => e.code)).toEqual(expect.arrayContaining(['WITNESS_COSIGNATURE_UNVERIFIED', 'WITNESS_QUORUM_NOT_MET']));
  });

  test('MW-07 the witnesses keep independent logs and keys: a fork is refused by the witness that saw the original, the other keeps its own history', async () => {
    const { list, ws } = setup(['w-a', 'w-b']);
    const orig = cp(10);
    await list[0].cosign(orig);     // only w-a saw it
    const fork = cp(10, null, 'f'.repeat(64));
    await expect(list[0].cosign(fork)).rejects.toMatchObject({ code: 'WITNESS_EQUIVOCATION_REFUSED' });
    await expect(list[1].cosign(fork)).resolves.toBeDefined();   // w-b never saw the original: its own log decides
    expect(fs.readFileSync(ws[0].logPath, 'utf8')).not.toBe(fs.readFileSync(ws[1].logPath, 'utf8'));
    expect(JSON.parse(fs.readFileSync(ws[0].keyPath, 'utf8'))).not.toEqual(JSON.parse(fs.readFileSync(ws[1].keyPath, 'utf8')));
  });

  test('MW-08 boot rules: a witness list must be valid, with distinct ids, and the minimum cannot exceed the witnesses', () => {
    const { validateBoot } = require('../../../../infra/config/bootValidator');
    const f = (v) => { const p = path.join(dir, 'boot.json'); fs.writeFileSync(p, typeof v === 'string' ? v : JSON.stringify(v)); return p; };
    const ok = [{ witnessId: 'a', mode: 'exec', command: 'x' }, { witnessId: 'b', mode: 'exec', command: 'y' }];
    const fatal = (env) => validateBoot({ NODE_ENV: 'development', ...env }).fatal.map((x) => x.variable);
    expect(fatal({ QODIQA_WITNESSES_CONFIG: f(ok) })).not.toContain('QODIQA_WITNESSES_CONFIG');
    expect(fatal({ QODIQA_WITNESSES_CONFIG: f('not json') })).toContain('QODIQA_WITNESSES_CONFIG');
    expect(fatal({ QODIQA_WITNESSES_CONFIG: f([ok[0], ok[0]]) })).toContain('QODIQA_WITNESSES_CONFIG');
    expect(fatal({ QODIQA_WITNESSES_CONFIG: f(ok), QODIQA_ANCHOR_MIN_WITNESSES: '3' })).toContain('QODIQA_ANCHOR_MIN_WITNESSES');
  });
});
