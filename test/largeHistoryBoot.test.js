'use strict';

/**
 * — large-history boot regression.
 *
 * Found after the rc-2b42ddb2 1-hour soak: the dashboard aggregation store (loaded unconditionally by src/app.js)
 * materialised the WHOLE audit history with getAuditChain() at module load, so above ~200k entries the gateway could
 * not boot (V8 heap OOM, crash loop). The store now walks the history with audit-log.forEachChainEntry() (one page in
 * memory, event loop yielded between pages).
 *
 * This suite generates a genuinely valid 100,000-entry hash chain with the production entryBuilder, then boots in a
 * child process under a FIXED 200 MB V8 heap:
 *   LH-1  the production dashboard store (src/dashboard/store) completes its history scan and counts every entry
 *   LH-2  the previous full-array path (initialize(getAuditChain)) exhausts the same heap — the test can detect the defect
 * Measured when written: paged peak heap 111 MB at 100k (60 MB at 300k under a 200 MB cap); full-array 293 MB at 100k.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const N = 100_000;
const HEAP_CAP_MB = 200;

let dir; let logPath;
beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut08-lh-'));
  logPath = path.join(dir, 'audit.log');
  const eb = require(path.join(ROOT, 'src/core/audit/entryBuilder'));
  const fd = fs.openSync(logPath, 'w');
  let prev = 'GENESIS'; let buf = [];
  for (let i = 0; i < N; i++) {
    const normalized = eb.normalizeFields({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: i % 7 === 0 ? 'BLOCK' : 'ALLOW',
      outputHash: eb.EMPTY_OUTPUT_HASH, signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64),
      verificationResult: i % 7 !== 0, tenantId: `t-${i % 3}` });
    const e = eb.buildEntry(normalized, prev);
    buf.push(JSON.stringify(e)); prev = e.hash;
    if (buf.length === 5000) { fs.writeSync(fd, buf.join('\n') + '\n'); buf = []; }
  }
  if (buf.length) fs.writeSync(fd, buf.join('\n') + '\n');
  fs.closeSync(fd);
}, 120_000);
afterAll(() => { if (dir) fs.rmSync(dir, { recursive: true, force: true }); });

function boot(script) {
  const env = { ...process.env, QODIQA_AUDIT_LOG: logPath, QODIQA_PG_ENABLED: 'false', NODE_OPTIONS: '' };
  return spawnSync(process.execPath, [`--max-old-space-size=${HEAP_CAP_MB}`, '-e', script], { cwd: ROOT, env, encoding: 'utf8', timeout: 120_000, maxBuffer: 64 * 1024 * 1024 });
}
const resultLine = (out) => (out.split('\n').find((l) => l.startsWith('AUT08_RESULT ')) || '').slice('AUT08_RESULT '.length);

test(`LH-1 the production dashboard store boots a ${N.toLocaleString('en')}-entry history under a ${HEAP_CAP_MB} MB heap`, () => {
  const r = boot(`
    const store = require('./src/dashboard/store');
    store.initializationComplete.then((visited) => {
      process.stdout.write('AUT08_RESULT ' + JSON.stringify({ visited, executions: store.getExecutions().length,
        overview: store.getMetrics().getOverview(), heapMB: Math.round(process.memoryUsage().heapUsed / 1e6) }) + '\\n');
      process.exit(0);
    }, (e) => { process.stdout.write('AUT08_RESULT ' + JSON.stringify({ error: e.message }) + '\\n'); process.exit(3); });`);
  expect(r.stderr).not.toMatch(/heap out of memory/i);
  expect(r.status).toBe(0);
  const out = JSON.parse(resultLine(r.stdout));
  expect(out.visited).toBe(N);
  expect(out.executions).toBeGreaterThan(0);
}, 120_000);

test(`LH-2 the previous full-array path exhausts the same ${HEAP_CAP_MB} MB heap (the test detects the defect)`, () => {
  const r = boot(`
    const a = require('./src/core/audit/audit-log');
    const { AggregationStore } = require('./src/dashboard/store/AggregationStore');
    const { MetricsEngine } = require('./src/dashboard/metrics/MetricsEngine');
    const retention = require('./src/dashboard/retention');
    const s = new AggregationStore({ subscribe() {} }, new MetricsEngine(retention), retention);
    Promise.resolve(s.initialize(a.getAuditChain)).then(() => { process.stdout.write('AUT08_RESULT {"completed":true}\\n'); process.exit(0); });`);
  expect(r.status).not.toBe(0);
  expect(`${r.stderr}${r.stdout}`).toMatch(/heap out of memory|Allocation failed/i);
}, 120_000);
