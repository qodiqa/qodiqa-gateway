'use strict';

/**
 * sealed, non-destructive audit archive export (scripts/audit/archive-export.js) and its independent verifier.
 *
 *   AE-01  export: a prune-compatible archive + seal + index entry; the live audit.log is byte-identical afterwards and nothing is deleted
 *   AE-02  idempotent: a second run re-verifies and reports ALREADY_EXPORTED, adds no index entry
 *   AE-03  a second export (older checkpoint) is chained to the first in the index
 *   AE-04  --dry-run writes nothing; with no signed checkpoint there is nothing to export; an unknown checkpoint id is refused
 *   AE-05  tamper controls — each must FAIL the independent verifier: flipped segment byte, manifest re-hashed after a flip, seal by an unknown key,
 *          flipped seal signature, missing seal, edited index entry, removed index entry
 *   AE-06  the CLI verifier exit codes
 *   AE-07  the exporter contains no deletion primitive; the verifier is independent (no src/, no npm package)
 */

jest.mock('../../../services/logger', () => ({ emit: jest.fn(), flush: jest.fn() }));

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..', '..');
const EXPORT = path.join(REPO, 'scripts', 'audit', 'archive-export.js');
const N = 60;
jest.setTimeout(120_000);

let dir; let LOG; let ROOT; let cpKeys; let hashes; let envChild;
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f58-'));
  LOG = path.join(dir, 'audit.log'); ROOT = path.join(dir, 'archive');
  process.env.QODIQA_CHECKPOINT_KEYS_PATH = path.join(dir, 'checkpoint-keys.json');
  process.env.QODIQA_AUDIT_LOG = LOG;
  jest.resetModules();
  const eb = require('../../../src/core/audit/entryBuilder');
  const { signCheckpoint } = require('../../../src/core/audit/checkpoint/checkpoint');
  cpKeys = require('../../../src/core/audit/checkpoint/checkpointKeyStore');
  const lines = []; hashes = []; let prev = 'GENESIS';
  for (let i = 0; i < N; i++) {
    const e = eb.buildEntry(eb.normalizeFields({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: eb.EMPTY_OUTPUT_HASH,
      signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 't' }), prev);
    lines.push(JSON.stringify(e)); hashes.push(e.hash); prev = e.hash;
  }
  fs.writeFileSync(LOG, `${lines.join('\n')}\n`);
  const cps = [20, 50].map((n) => signCheckpoint({ chainLength: n, headHash: hashes[n - 1], createdAt: new Date(1790000000000 + n * 1000).toISOString() }));
  fs.writeFileSync(`${LOG}.checkpoints.jsonl`, `${cps.map((c) => JSON.stringify(c)).join('\n')}\n`);
  global.__cps = cps;
  envChild = { ...process.env, NODE_ENV: 'test', QODIQA_AUDIT_LOG: LOG, QODIQA_CHECKPOINT_KEYS_PATH: process.env.QODIQA_CHECKPOINT_KEYS_PATH, QODIQA_PG_ENABLED: 'false' };
});
afterAll(() => {
  delete process.env.QODIQA_CHECKPOINT_KEYS_PATH; delete process.env.QODIQA_AUDIT_LOG;
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
});

function run(...args) {
  const r = spawnSync(process.execPath, [EXPORT, '--archive-root', ROOT, ...args], { env: envChild, encoding: 'utf8', timeout: 100_000 });
  let out = null; try { out = JSON.parse(r.stdout.trim().split('\n').pop()); } catch { /* */ }
  return { status: r.status, out, stderr: r.stderr, stdout: r.stdout };
}
const resolver = () => require('../../audit-repro/verify/checkpoint').keyResolver({ keys: cpKeys.publishedKeys().map((k) => ({ keyId: k.keyId, publicKey: k.publicKeySpkiDerB64, status: k.status })) });
const V = () => require('../../audit-repro/verify/archive');

describe('sealed archive export', () => {
  test('AE-01 export: archive + seal + index entry, live log untouched, nothing deleted', () => {
    const before = sha(LOG);
    const r = run();
    expect(r.out).toMatchObject({ result: 'EXPORTED', marked: true, deleted: 0, entries: 50, to: { count: 50, hash: hashes[49] }, from: { count: 0, hash: 'GENESIS' } });
    expect(sha(LOG)).toBe(before);
    expect(fs.readFileSync(`${LOG}.checkpoints.jsonl`, 'utf8').split('\n').filter(Boolean)).toHaveLength(2);
    const d = path.join(ROOT, `export-${global.__cps[1].payload.checkpointId}`);
    expect(fs.readdirSync(d).sort()).toEqual(['audit.log.segment', 'checkpoint.json', 'manifest.json', 'seal.json']);
    expect(fs.readFileSync(path.join(d, 'audit.log.segment'), 'utf8').split('\n').filter(Boolean)).toHaveLength(50);
    const v = V().verifyExport(d, resolver());
    expect(v).toMatchObject({ valid: true, entries: 50 });
    expect(V().verifyIndex(ROOT, resolver())).toMatchObject({ valid: true, exports: 1, findings: [] });
  });

  test('AE-02 a second run is idempotent', () => {
    const idx = fs.readFileSync(path.join(ROOT, 'archive-index.jsonl'), 'utf8');
    const r = run();
    expect(r.out).toMatchObject({ result: 'ALREADY_EXPORTED', marked: false });
    expect(fs.readFileSync(path.join(ROOT, 'archive-index.jsonl'), 'utf8')).toBe(idx);
  });

  test('AE-03 an older checkpoint exports too, chained to the first index entry', () => {
    const older = global.__cps[0].payload.checkpointId;
    const r = run('--checkpoint-id', older, '--note', 'first 20');
    expect(r.out).toMatchObject({ result: 'EXPORTED', marked: true, entries: 20 });
    const recs = fs.readFileSync(path.join(ROOT, 'archive-index.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    expect(recs.map((x) => x.seq)).toEqual([1, 2]);
    expect(recs[1].prevEntryHash).toBe(recs[0].entryHash);
    expect(JSON.parse(fs.readFileSync(path.join(ROOT, `export-${older}`, 'manifest.json'), 'utf8')).note).toBe('first 20');
    expect(V().verifyIndex(ROOT, resolver())).toMatchObject({ valid: true, exports: 2 });
  });

  test('AE-04 dry-run writes nothing, no checkpoint means nothing to export, an unknown id is refused', () => {
    const newRoot = path.join(dir, 'dry');
    const d = spawnSync(process.execPath, [EXPORT, '--archive-root', newRoot, '--dry-run'], { env: envChild, encoding: 'utf8' });
    expect(JSON.parse(d.stdout.trim().split('\n').pop())).toMatchObject({ result: 'DRY_RUN', plan: { entries: 50 } });
    expect(fs.existsSync(newRoot)).toBe(false);
    const u = run('--checkpoint-id', 'no-such-checkpoint');
    expect(u.status).toBe(2); expect(u.out.result).toBe('REFUSED');
    const bare = path.join(dir, 'bare'); fs.mkdirSync(bare);
    fs.copyFileSync(LOG, path.join(bare, 'audit.log'));
    const n = spawnSync(process.execPath, [EXPORT, '--archive-root', path.join(bare, 'a')], { env: { ...envChild, QODIQA_AUDIT_LOG: path.join(bare, 'audit.log') }, encoding: 'utf8' });
    expect(JSON.parse(n.stdout.trim().split('\n').pop())).toMatchObject({ result: 'NOTHING_TO_EXPORT' });
  });

  test('AE-05 tamper controls: every manipulation fails the independent verifier', () => {
    const id = global.__cps[1].payload.checkpointId;
    const copy = (name) => { const t = path.join(dir, name); fs.cpSync(path.join(ROOT, `export-${id}`), t, { recursive: true }); return t; };
    const reason = (d) => V().verifyExport(d, resolver());
    // 1 flipped segment byte
    let t = copy('t1'); let seg = fs.readFileSync(path.join(t, 'audit.log.segment')); seg[10] ^= 1; fs.writeFileSync(path.join(t, 'audit.log.segment'), seg);
    expect(reason(t)).toMatchObject({ valid: false, reason: 'ARCHIVE_FILE_SHA256_MISMATCH:audit.log.segment' });
    // 2 flipped byte with the manifest re-hashed: the chain walk catches the entry; a manifest edited after sealing is caught by the seal
    t = copy('t2'); seg = fs.readFileSync(path.join(t, 'audit.log.segment')); seg[10] ^= 1; fs.writeFileSync(path.join(t, 'audit.log.segment'), seg);
    const man = JSON.parse(fs.readFileSync(path.join(t, 'manifest.json'), 'utf8')); man.files['audit.log.segment'].sha256 = crypto.createHash('sha256').update(seg).digest('hex');
    fs.writeFileSync(path.join(t, 'manifest.json'), JSON.stringify(man, null, 1));
    expect(reason(t).reason).toMatch(/^ARCHIVE_SEGMENT_/);
    t = copy('t2b'); const man2 = JSON.parse(fs.readFileSync(path.join(t, 'manifest.json'), 'utf8')); man2.note = 'edited after sealing';
    fs.writeFileSync(path.join(t, 'manifest.json'), JSON.stringify(man2, null, 1));
    expect(reason(t)).toMatchObject({ valid: false, reason: 'SEAL_MANIFEST_MISMATCH' });
    // 3 sealed by a key the verifier does not know
    t = copy('t3'); const evil = crypto.generateKeyPairSync('ed25519');
    const seal = JSON.parse(fs.readFileSync(path.join(t, 'seal.json'), 'utf8'));
    const dg = crypto.createHash('sha256').update('QODIQA::AUDIT_ARCHIVE_SEAL::V1').update(seal.manifestSha256).digest();
    fs.writeFileSync(path.join(t, 'seal.json'), JSON.stringify({ ...seal, keyId: 'evil:key_v1', signature: crypto.sign(null, dg, evil.privateKey).toString('base64') }));
    expect(reason(t)).toMatchObject({ valid: false, reason: 'SEAL_KEY_UNKNOWN' });
    // 4 flipped seal signature
    t = copy('t4'); const s4 = JSON.parse(fs.readFileSync(path.join(t, 'seal.json'), 'utf8')); const b = Buffer.from(s4.signature, 'base64'); b[0] ^= 1;
    fs.writeFileSync(path.join(t, 'seal.json'), JSON.stringify({ ...s4, signature: b.toString('base64') }));
    expect(reason(t)).toMatchObject({ valid: false, reason: 'SEAL_SIGNATURE_INVALID' });
    // 5 missing seal
    t = copy('t5'); fs.unlinkSync(path.join(t, 'seal.json'));
    expect(reason(t)).toMatchObject({ valid: false, reason: 'SEAL_MISSING' });
    // 6 / 7 index: an edited entry, a removed entry
    const root2 = path.join(dir, 'idx'); fs.cpSync(ROOT, root2, { recursive: true });
    const f = path.join(root2, 'archive-index.jsonl'); const recs = fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    fs.writeFileSync(f, `${JSON.stringify({ ...recs[0], to: { ...recs[0].to, count: 49 } })}\n${JSON.stringify(recs[1])}\n`);
    expect(V().verifyIndex(root2, resolver()).findings.map((x) => x.code)).toContain('INDEX_ENTRY_HASH');
    fs.writeFileSync(f, `${JSON.stringify(recs[1])}\n`);
    expect(V().verifyIndex(root2, resolver()).findings.map((x) => x.code)).toEqual(expect.arrayContaining(['INDEX_SEQ', 'INDEX_LINK_BROKEN']));
  });

  test('AE-08 a torn index line and an empty seal from a killed process do not wedge the export; the index states the real range and never a path', () => {
    const id = global.__cps[0].payload.checkpointId;
    const ROOT8 = path.join(dir, 'root8'); fs.cpSync(ROOT, ROOT8, { recursive: true });
    const run8 = (...a) => {
      const r = spawnSync(process.execPath, [EXPORT, '--archive-root', ROOT8, ...a], { env: envChild, encoding: 'utf8', timeout: 100_000 });
      return { out: JSON.parse(r.stdout.trim().split(String.fromCharCode(10)).pop()), status: r.status };
    };
    const idxFile = path.join(ROOT8, 'archive-index.jsonl');
    const before = fs.readFileSync(idxFile, 'utf8');
    fs.appendFileSync(idxFile, '{"seq":3,"exportedAt":"x","checkp');                       // killed mid-append
    fs.writeFileSync(path.join(ROOT8, `export-${id}`, 'seal.json'), '');                  // killed while sealing
    const r = run8('--checkpoint-id', id);
    expect(r.out).toMatchObject({ result: 'EXPORTED' });                                    // the incomplete directory was set aside, not deleted
    expect(fs.readdirSync(ROOT8).some((x) => x.startsWith(`export-${id}.incomplete-`))).toBe(true);
    const lines = fs.readFileSync(idxFile, 'utf8').split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThanOrEqual(before.split('\n').filter(Boolean).length);
    expect(V().verifyIndex(ROOT8, resolver()).findings.filter((x) => x.code !== 'INDEX_ARCHIVE_MANIFEST_MISMATCH')).toEqual([]);
    // D-10: an index entry that lies about the range, and one whose checkpoint id is a path
    const root2 = path.join(dir, 'idx2'); fs.cpSync(ROOT8, root2, { recursive: true });
    const f2 = path.join(root2, 'archive-index.jsonl');
    const recs = fs.readFileSync(f2, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const entryHash = require('../../audit-repro/verify/archive').entryHashOf;
    recs[0] = { ...recs[0], to: { ...recs[0].to, count: recs[0].to.count - 1 } }; recs[0].entryHash = entryHash(recs[0]);
    for (let i = 1; i < recs.length; i++) { recs[i].prevEntryHash = recs[i - 1].entryHash; recs[i].entryHash = entryHash(recs[i]); }
    fs.writeFileSync(f2, recs.map((x) => JSON.stringify(x)).join('\n') + '\n');
    expect(V().verifyIndex(root2, resolver()).findings.map((x) => x.code)).toContain('INDEX_ARCHIVE_RANGE_MISMATCH');
    const recs3 = [{ ...recs[0], checkpointId: '../../etc' }]; recs3[0].prevEntryHash = 'GENESIS'; recs3[0].seq = 1; recs3[0].entryHash = entryHash(recs3[0]);
    fs.writeFileSync(f2, JSON.stringify(recs3[0]) + '\n');
    expect(V().verifyIndex(root2, resolver()).findings.map((x) => x.code)).toContain('INDEX_MALFORMED');
  });

  test('AE-06 the CLI verifier: 0 valid, 1 invalid, 2 usage', () => {
    const keys = path.join(dir, 'keys.json');
    fs.writeFileSync(keys, JSON.stringify({ keys: cpKeys.publishedKeys().map((k) => ({ keyId: k.keyId, publicKey: k.publicKeySpkiDerB64, status: k.status })) }));
    const cli = path.join(REPO, 'scripts', 'audit-repro', 'verify', 'qodiqa-archive-verify.js');
    const id = global.__cps[1].payload.checkpointId;
    const run2 = (...a) => spawnSync(process.execPath, [cli, ...a], { encoding: 'utf8' });
    expect(run2('--checkpoint-keys', keys, '--archive', path.join(ROOT, `export-${id}`)).status).toBe(0);
    expect(run2('--checkpoint-keys', keys, '--index', ROOT).status).toBe(0);
    expect(run2('--checkpoint-keys', keys, '--archive', path.join(dir, 't1')).status).toBe(1);
    expect(run2('--checkpoint-keys', keys).status).toBe(2);
  });

  test('AE-07 the exporter has no deletion primitive; the verifier is independent', () => {
    const src = fs.readFileSync(EXPORT, 'utf8').replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, '');
    for (const word of ['unlinkSync', 'rmSync', 'rmdirSync', 'truncateSync', 'ftruncate', 'DELETE FROM', 'writeFileSync(LOG_PATH']) expect(src).not.toContain(word);
    for (const f of ['archive.js', 'qodiqa-archive-verify.js']) {
      const v = fs.readFileSync(path.join(REPO, 'scripts', 'audit-repro', 'verify', f), 'utf8');
      for (const m of v.matchAll(/require\('([^']+)'\)/g)) expect(['crypto', 'fs', 'path'].includes(m[1]) || m[1].startsWith('./')).toBe(true);
    }
  });
});
