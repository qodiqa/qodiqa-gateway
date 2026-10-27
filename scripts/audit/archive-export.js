#!/usr/bin/env node
'use strict';
/**
 * QODIQA audit ARCHIVE EXPORT — the non-destructive half of audit retention.
 *
 *   node scripts/audit/archive-export.js [--checkpoint-id ID] [--archive-root DIR] [--note TEXT] [--dry-run]
 *
 * Copies the audit chain's file segment up to a SIGNED checkpoint into a self-verifying archive, SEALS it with a signature of the audit-checkpoint key,
 * and MARKS the export in an append-only, hash-chained index. It deletes NOTHING: audit.log, audit_chain, evidence_chain_records and
 * platform_audit_events are not touched. Removing history stays the job of scripts/audit/prune.js (operator-run, off until a retention period is set,
 * archive-verified first), and ENFORCEMENT events of platform_audit_events are never deleted automatically (src/core/audit/retention.js) — an archive
 * is how long-lived evidence leaves the hot store, not a licence to drop it.
 *
 * Safe while the server runs: the exported prefix is immutable (the chain is append-only) and only files under the archive root are written.
 *
 * Archive layout (prune-compatible, so the same independent verifier reads both): <root>/export-<checkpointId>/
 *   manifest.json     { v:1, tool, kind:"export", createdAt, checkpointId, note?, from:{count,hash}, to:{count,hash}, files:{name:{sha256,bytes}} }
 *   checkpoint.json   the signed checkpoint the segment ends at
 *   audit.log.segment the chain lines, byte for byte
 *   prior-base.json   (only when the chain was pruned before) the signed base record the segment starts from
 *   seal.json         { v:1, manifestSha256, keyId, signature, sealedAt }  Ed25519 over SHA-256("QODIQA::AUDIT_ARCHIVE_SEAL::V1" || manifestSha256)
 * <root>/archive-index.jsonl   one line per export: { seq, exportedAt, checkpointId, from, to, manifestSha256, sealKeyId, prevEntryHash, entryHash }
 *
 * Idempotent: an export that already exists is re-verified and reported, never rewritten.
 * Exit 0 = exported / already exported / nothing to export · 1 = failed · 2 = refused.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const REPO = path.join(__dirname, '..', '..');
const SEAL_DOMAIN = 'QODIQA::AUDIT_ARCHIVE_SEAL::V1';
const INDEX_FILE = 'archive-index.jsonl';
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

class Refusal extends Error { constructor(m) { super(m); this.refusal = true; } }

function parseArgs(argv) {
  const a = { 'dry-run': false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith('--')) throw new Refusal(`unexpected argument ${k}`);
    const n = k.slice(2);
    if (n === 'dry-run') { a[n] = true; continue; }
    if (!['checkpoint-id', 'archive-root', 'note'].includes(n)) throw new Refusal(`unknown option ${k}`);
    if (i + 1 >= argv.length) throw new Refusal(`${k} needs a value`);
    a[n] = argv[++i];
  }
  return a;
}

const sealDigest = (manifestSha256) => crypto.createHash('sha256').update(SEAL_DOMAIN, 'utf8').update(manifestSha256, 'utf8').digest();
const entryHashOf = (rec) => sha256(JSON.stringify({ seq: rec.seq, exportedAt: rec.exportedAt, checkpointId: rec.checkpointId, from: rec.from, to: rec.to,
  manifestSha256: rec.manifestSha256, sealKeyId: rec.sealKeyId, prevEntryHash: rec.prevEntryHash }));

function fsyncFile(p) { const fd = fs.openSync(p, 'r+'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function writeDurable(p, data) { fs.writeFileSync(p, data); fsyncFile(p); }

// D-5: a process killed mid-append leaves a torn last line. It is dropped (it was never a complete entry; its archive is sealed and is marked again),
// so one crash cannot make every later export fail.
function readIndex(root) {
  const f = path.join(root, INDEX_FILE);
  if (!fs.existsSync(f)) return [];
  const text = fs.readFileSync(f, 'utf8');
  const lines = text.split('\n');
  const out = []; let torn = false;
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i]) continue;
    try { out.push(JSON.parse(lines[i])); } catch { if (i >= lines.length - 2) { torn = true; break; } throw new Error('archive-index.jsonl is corrupt before its last line'); }
  }
  if (torn || (text.length && !text.endsWith('\n'))) fs.writeFileSync(f, out.map((r) => JSON.stringify(r)).join('\n') + (out.length ? '\n' : ''));
  return out;
}

// an export is complete only with a readable seal (an empty or torn seal.json is a crash leftover: the directory is set aside, never deleted)
function sealComplete(dir) {
  try { const x = JSON.parse(fs.readFileSync(path.join(dir, 'seal.json'), 'utf8')); return !!(x && x.manifestSha256 && x.signature); } catch { return false; }
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  // Read-only view of the chain, exactly as a follower boot loads it (fully validated, fail-closed on any defect).
  process.env.QODIQA_AUDIT_FOLLOWER = 'true';
  const LOG_PATH = process.env.QODIQA_AUDIT_LOG || path.join(REPO, 'audit.log');
  let auditLog;
  try { auditLog = require(path.join(REPO, 'src/core/audit/audit-log')); } catch (e) { throw new Error(`the audit chain does not verify — nothing exported: ${e.message}`); }
  const logger = require(path.join(REPO, 'services/logger'));
  const { verifyCheckpoint } = require(path.join(REPO, 'src/core/audit/checkpoint/checkpoint'));
  const cpKeys = require(path.join(REPO, 'src/core/audit/checkpoint/checkpointKeyStore'));
  const { readSidecar } = require(path.join(REPO, 'src/core/audit/checkpoint/checkpointWriter'));
  const indep = require(path.join(REPO, 'scripts/audit-repro/verify/checkpoint'));
  const { prefixScan } = require('./prune');

  const snap = auditLog.memorySnapshot();
  const start = auditLog.getChainStart();
  if (snap.totalCount !== snap.modernCount) throw new Refusal(`the chain holds ${snap.totalCount - snap.modernCount} legacy (pre-hash) lines — they are not exported`);
  if (start.state === 'full-file') throw new Refusal('a prune was interrupted (the log still holds a prefix its base record has already taken): finish it with scripts/audit/prune.js first');
  const currentBase = fs.existsSync(auditLog.BASE_PATH) ? JSON.parse(fs.readFileSync(auditLog.BASE_PATH, 'utf8')) : null;
  const prior = start.state === 'rebased' ? currentBase : null;
  const fromCount = prior ? prior.checkpoint.payload.chainLength : 0;
  const fromHash = prior ? prior.checkpoint.payload.headHash : 'GENESIS';
  const root = path.resolve(args['archive-root'] || process.env.QODIQA_AUDIT_ARCHIVE_ROOT || path.join(path.dirname(LOG_PATH), 'audit-archive'));
  const resolvePub = indep.keyResolver({ keys: cpKeys.publishedKeys().map((k) => ({ keyId: k.keyId, publicKey: k.publicKeySpkiDerB64, status: k.status })) });

  // ── the checkpoint to export up to: a verified signed checkpoint that the chain really reaches ──
  const candidates = [];
  for (const s of readSidecar(LOG_PATH)) {
    const p = s.payload;
    if (!verifyCheckpoint(s).ok || !(p.chainLength > start.startCount) || p.chainLength > snap.modernCount) continue;
    if (args['checkpoint-id'] && p.checkpointId !== args['checkpoint-id']) continue;
    const e = await auditLog.getModernEntryAt(p.chainLength - 1);
    if (!e || e.hash !== p.headHash) continue;
    candidates.push(s);
  }
  candidates.sort((a, b) => b.payload.chainLength - a.payload.chainLength);
  const C = candidates[0];
  if (!C) {
    if (args['checkpoint-id']) throw new Refusal(`no verified signed checkpoint ${args['checkpoint-id']} that this chain reaches`);
    return { result: 'NOTHING_TO_EXPORT', chainStart: start.startCount, chainLength: snap.modernCount };
  }
  const cp = C.payload;
  const dir = path.join(root, `export-${cp.checkpointId}`);
  const plan = { checkpointId: cp.checkpointId, from: { count: fromCount, hash: fromHash }, to: { count: cp.chainLength, hash: cp.headHash }, entries: cp.chainLength - fromCount, archiveDir: dir };
  if (args['dry-run']) return { result: 'DRY_RUN', plan };

  fs.mkdirSync(root, { recursive: true });
  let created = false;
  if (!sealComplete(dir)) {
    if (fs.existsSync(dir)) { fs.renameSync(dir, `${dir}.incomplete-${Date.now()}`); }      // an interrupted export: kept aside, never deleted
    fs.mkdirSync(dir, { recursive: true });
    const files = {};
    const segPath = path.join(dir, 'audit.log.segment');
    const { off } = prefixScan(LOG_PATH, cp.chainLength - fromCount);
    const rfd = fs.openSync(LOG_PATH, 'r'); const wfd = fs.openSync(segPath, 'w'); const buf = Buffer.alloc(1 << 20);
    try { let pos = 0; while (pos < off) { const r = fs.readSync(rfd, buf, 0, Math.min(buf.length, off - pos), pos); if (r <= 0) throw new Error('short read'); fs.writeSync(wfd, buf, 0, r); pos += r; } fs.fsyncSync(wfd); } finally { fs.closeSync(rfd); fs.closeSync(wfd); }
    const seg = fs.readFileSync(segPath); files['audit.log.segment'] = { sha256: sha256(seg), bytes: seg.length };
    const put = (name, data) => { writeDurable(path.join(dir, name), data); files[name] = { sha256: sha256(data), bytes: Buffer.byteLength(data) }; };
    put('checkpoint.json', JSON.stringify(C));
    if (prior) put('prior-base.json', JSON.stringify(prior));
    const man = { v: 1, tool: 'scripts/audit/archive-export.js', kind: 'export', createdAt: new Date().toISOString(), checkpointId: cp.checkpointId,
      ...(args.note ? { note: String(args.note).slice(0, 500) } : {}), from: { count: fromCount, hash: fromHash }, to: { count: cp.chainLength, hash: cp.headHash }, pg: null, evidence: null, files };
    const manText = JSON.stringify(man, null, 1);
    writeDurable(path.join(dir, 'manifest.json'), manText);
    // verified by the independent verifier's own code BEFORE it is sealed
    const av = indep.verifyArchive(dir, resolvePub, { hash: fromHash, count: fromCount });
    if (!av.valid) throw new Error(`the archive does not verify, not sealed: ${av.reason}`);
    const key = cpKeys.ensureActiveKey();
    const manifestSha256 = sha256(manText);
    const signature = crypto.sign(null, sealDigest(manifestSha256), crypto.createPrivateKey({ key: key.privDer, format: 'der', type: 'pkcs8' })).toString('base64');
    writeDurable(path.join(dir, 'seal.json'), JSON.stringify({ v: 1, manifestSha256, keyId: key.keyId, signature, sealedAt: new Date().toISOString() }));
    created = true;
  }
  // ── mark: append-only, hash-chained index (once per archive) ──
  const manifestSha256 = sha256(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const seal = JSON.parse(fs.readFileSync(path.join(dir, 'seal.json'), 'utf8'));
  const index = readIndex(root);
  let marked = false;
  if (!index.some((r) => r.manifestSha256 === manifestSha256)) {
    const last = index[index.length - 1];
    const rec = { seq: (last ? last.seq : 0) + 1, exportedAt: new Date().toISOString(), checkpointId: cp.checkpointId, from: plan.from, to: plan.to, manifestSha256,
      sealKeyId: seal.keyId, prevEntryHash: last ? last.entryHash : 'GENESIS' };
    rec.entryHash = entryHashOf(rec);
    fs.appendFileSync(path.join(root, INDEX_FILE), `${JSON.stringify(rec)}\n`); fsyncFile(path.join(root, INDEX_FILE));
    marked = true;
  }
  const out = { result: created ? 'EXPORTED' : 'ALREADY_EXPORTED', marked, ...plan, manifestSha256, sealKeyId: seal.keyId, deleted: 0 };
  logger.emit('INFO', 'AUDIT_ARCHIVE_EXPORTED', out);
  return out;
}

if (require.main === module) {
  main().then((out) => { try { require(path.join(REPO, 'services/logger')).flush(); } catch { /* */ } console.log(JSON.stringify(out)); process.exitCode = 0; },
    (e) => { try { require(path.join(REPO, 'services/logger')).flush(); } catch { /* */ } console.log(JSON.stringify({ result: e.refusal ? 'REFUSED' : 'FAILED', reason: e.message })); process.exitCode = e.refusal ? 2 : 1; });
}

module.exports = { main, parseArgs, SEAL_DOMAIN, INDEX_FILE, sealDigest, entryHashOf };
