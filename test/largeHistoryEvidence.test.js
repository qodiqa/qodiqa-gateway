'use strict';

/**
 * — large-history, fixed-heap regression for the evidence generator. Before: every evidence
 * package / verification / export request called getAuditChain() — one authorised admin request on a large log
 * exhausted the heap and killed the gateway. A valid 100,000-entry chain (production entryBuilder) is served by the
 * REAL audit-log in a child process under a FIXED 200 MB V8 heap:
 *
 *   LE-1  package (artifact position + chain integrity), verification output, filtered export complete with the right
 *         counts; the streamed unfiltered export writes exactly the 100,000 entries on disk (sha256 of the bytes)
 *   LE-2  the previous materialising computation (getAuditChain + verifyAuditChainDetailed) exhausts the same heap —
 *         the test can detect the defect
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const N = 100_000;
const HEAP_CAP_MB = 200;
const TARGET = 12_345;

let dir; let logPath; let expectedSha; let targetId;
beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut11-le-'));
  logPath = path.join(dir, 'audit.log');
  const eb = require(path.join(ROOT, 'src/core/audit/entryBuilder'));
  const fd = fs.openSync(logPath, 'w');
  const sha = crypto.createHash('sha256');
  let prev = 'GENESIS'; let buf = [];
  for (let i = 0; i < N; i++) {
    const id = crypto.randomUUID();
    if (i === TARGET) targetId = id;
    const e = eb.buildEntry(eb.normalizeFields({ artifactId: id, inputHash: 'a'.repeat(64), decision: i % 7 === 0 ? 'BLOCK' : 'ALLOW',
      outputHash: eb.EMPTY_OUTPUT_HASH, signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64),
      verificationResult: i % 7 !== 0, tenantId: `t-${i % 3}` }), prev);
    const line = JSON.stringify(e);
    sha.update((i === 0 ? '' : ',') + line);
    buf.push(line); prev = e.hash;
    if (buf.length === 5000) { fs.writeSync(fd, buf.join('\n') + '\n'); buf = []; }
  }
  if (buf.length) fs.writeSync(fd, buf.join('\n') + '\n');
  fs.closeSync(fd);
  expectedSha = sha.digest('hex');
}, 120_000);
afterAll(() => { if (dir) fs.rmSync(dir, { recursive: true, force: true }); });

function run(script) {
  const env = { ...process.env, QODIQA_AUDIT_LOG: logPath, QODIQA_PG_ENABLED: 'false', NODE_OPTIONS: '', T_ID: targetId };
  const r = spawnSync(process.execPath, [`--max-old-space-size=${HEAP_CAP_MB}`, '-e', script], { cwd: ROOT, env, encoding: 'utf8', timeout: 240_000, maxBuffer: 64 * 1024 * 1024 });
  const line = (r.stdout.split('\n').find((l) => l.startsWith('AUT11_RESULT ')) || '').slice('AUT11_RESULT '.length);
  return { r, out: line ? JSON.parse(line) : null };
}

test(`LE-1 package, verification and both exports over ${N.toLocaleString('en')} entries under a ${HEAP_CAP_MB} MB heap`, () => {
  const { r, out } = run(`
    const crypto = require('crypto');
    const g = require('./src/core/evidence/generator');
    let peak = 0; const s = setInterval(() => { peak = Math.max(peak, process.memoryUsage().heapUsed); }, 5); s.unref();
    (async () => {
      const id = process.env.T_ID; const o = {};
      let t = Date.now();
      const pkg = (await g.generateEvidencePackage(id, [], null)).package;
      o.pkgMs = Date.now() - t; o.position = pkg.sections.audit.artifactPosition; o.integrity = pkg.sections.audit.chainIntegrity;
      t = Date.now();
      const v = await g.generateVerificationOutput(id, []);
      o.verifyMs = Date.now() - t; o.verifyChain = v.verifications.chain; o.overall = v.overallStatus;
      const f = await g.exportAuditChain(id, true);
      o.filtered = { n: f.entries.length, meta: f.meta };
      const h = crypto.createHash('sha256'); let bytes = 0;
      t = Date.now();
      const meta = await g.streamAuditChainExport(id, async (c) => { h.update(c); bytes += c.length; });
      o.streamMs = Date.now() - t; o.stream = { sha: h.digest('hex'), bytes, meta };
      o.peakHeapMB = Math.round(Math.max(peak, process.memoryUsage().heapUsed) / 1e6);
      process.stdout.write('AUT11_RESULT ' + JSON.stringify(o) + '\\n'); process.exit(0);
    })().catch((e) => { process.stdout.write('AUT11_RESULT ' + JSON.stringify({ error: e.stack }) + '\\n'); process.exit(3); });`);
  expect(r.stderr).not.toMatch(/heap out of memory/i);
  expect(r.status).toBe(0);
  expect(out.error).toBeUndefined();
  expect(out.position).toEqual({ index: TARGET, totalInChain: N, found: true });
  expect(out.integrity).toMatchObject({ valid: true, tamperingDetected: false, entriesVerified: N });
  expect(out.verifyChain).toMatchObject({ status: 'VALID', valid: true, entriesVerified: N });
  expect(out.filtered.n).toBe(1);
  expect(out.filtered.meta).toMatchObject({ totalChain: N, exportedCount: 1, chainIntegrity: { valid: true, entriesVerified: N } });
  expect(out.stream.sha).toBe(expectedSha);
  expect(out.stream.meta).toMatchObject({ filtered: false, totalChain: N, exportedCount: N, chainIntegrity: { valid: true, entriesVerified: N } });
  process.stdout.write(`LE-1: package ${out.pkgMs} ms, verify ${out.verifyMs} ms, streamed export ${out.streamMs} ms (${out.stream.bytes} bytes), peak heap ${out.peakHeapMB} MB\n`);
}, 300_000);

test(`LE-2 the previous materialising computation exhausts the same ${HEAP_CAP_MB} MB heap (the test detects the defect)`, () => {
  const { r } = run(`
    const a = require('./src/core/audit/audit-log');
    a.getAuditChain().then((chain) => { const v = a.verifyAuditChainDetailed(chain); process.stdout.write('AUT11_RESULT ' + JSON.stringify({ completed: true, n: chain.length, valid: v.valid }) + '\\n'); process.exit(0); });`);
  expect(r.status).not.toBe(0);
  expect(`${r.stderr}${r.stdout}`).toMatch(/heap out of memory|Allocation failed/i);
}, 300_000);
