'use strict';

/**
 * — large-history, fixed-heap regression for the runtime mirror-checkpoint advancement and the
 * startup locate. A genuinely valid 100,000-entry hash chain (production entryBuilder) in a real audit.log, loaded by
 * the REAL audit-log module in a child process under a FIXED 200 MB V8 heap. The PostgreSQL mirror is a stand-in that
 * serves the same entries lazily from the file page by page (seq = position + 1), so neither side is ever materialised.
 *
 *   LA-1  one advancement run verifies 99,000 entries (checkpoint 1,000 → signed checkpoint 100,000) and writes exactly
 *         one checkpoint, within the heap cap
 *   LA-2  the next boot's fast path starts from that checkpoint, locates it by newline count (no prefix parse) and
 *         checks only the remainder; the parse-based locate reaches the same verdict (timings reported)
 *   LA-3  one tampered mirror row 60,000 entries into the range → refused, nothing written, within the heap cap
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
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut08f-la-'));
  logPath = path.join(dir, 'audit.log');
  const eb = require(path.join(ROOT, 'src/core/audit/entryBuilder'));
  const fd = fs.openSync(logPath, 'w');
  let prev = 'GENESIS'; let buf = [];
  for (let i = 0; i < N; i++) {
    const e = eb.buildEntry(eb.normalizeFields({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: i % 7 === 0 ? 'BLOCK' : 'ALLOW',
      outputHash: eb.EMPTY_OUTPUT_HASH, signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64),
      verificationResult: i % 7 !== 0, tenantId: `t-${i % 3}` }), prev);
    buf.push(JSON.stringify(e)); prev = e.hash;
    if (buf.length === 5000) { fs.writeSync(fd, buf.join('\n') + '\n'); buf = []; }
  }
  if (buf.length) fs.writeSync(fd, buf.join('\n') + '\n');
  fs.closeSync(fd);
}, 120_000);
afterAll(() => { if (dir) fs.rmSync(dir, { recursive: true, force: true }); });

// Child-process harness: real audit-log + mirrorConsistencyCheck, a lazy file-backed PG stand-in, a fake pool.
const HARNESS = `
  const a = require('./src/core/audit/audit-log');
  const mc = require('./src/core/audit/mirrorConsistencyCheck');
  const TAMPER_SEQ = Number(process.env.T_TAMPER_SEQ || 0);
  const N = Number(process.env.N);
  let peak = 0; const sample = () => { peak = Math.max(peak, process.memoryUsage().heapUsed); };
  const sampler = setInterval(sample, 5); sampler.unref();
  const cursors = new Map();
  const checkpoints = [];
  async function hashAt(pos) { return (await a.getModernHashesAt([pos])).get(pos) || null; }
  const pg = {
    async getLatestAuditCheckpoint() { return checkpoints.reduce((m, c) => (!m || c.chainLength > m.chainLength ? c : m), null); },
    async insertAuditCheckpoint(c) { checkpoints.push(c); },
    async fetchRowBySeq(seq) { return hashAt(seq - 1); },
    async countChainRows() { return a.getChainStats().modernLength; },
    async countChainRowsThroughSeq(seq) { return Math.min(seq, a.getChainStats().modernLength); },
    async fetchChainBatch(from, n) {
      if (from >= a.getChainStats().modernLength) return [];
      const page = await a.getModernChainPage({ cursor: cursors.get(from) || { m: from }, limit: n, durable: true });
      if (page.nextCursor) cursors.set(from + page.entries.length, page.nextCursor);
      sample();
      return page.entries.map((e, i) => {
        const row = { ...e, seq: from + i + 1 };
        if (row.seq === TAMPER_SEQ) row.canonical = row.canonical.replace('"ALLOW"', '"BLOCK"');
        return row;
      });
    },
    async findSignedCheckpointForAdvance(after, max) {
      const len = Math.floor(max / 1000) * 1000;
      if (len <= after) return null;
      return { payload: { checkpointId: 'cp-' + len, chainLength: len, headHash: await hashAt(len - 1), pgSeq: len } };
    },
  };
  const pool = { isEnabled: () => true, withTransaction: async (fn) => fn({ query: async () => ({ rows: [{ acquired: true }] }) }) };
  (async () => {
    const out = {};
    checkpoints.push({ chainLength: 1000, hash: await hashAt(999), seq: 1000, createdBy: 'startup-mirror-check' });
    peak = 0;
    let t = Date.now();
    out.advance = await mc.advanceMirrorCheckpoint({ _env: {}, _pgPool: pool, _pgAuditBackend: pg, _auditLog: a, _emit: () => {}, maxEntries: 100000 });
    out.advanceMs = Date.now() - t; sample(); out.advancePeakHeapMB = Math.round(peak / 1e6);
    out.written = checkpoints.filter((c) => c.createdBy === 'runtime-mirror-advance').map((c) => c.chainLength);
    if (out.advance.advanced) {
      // next boot: the fast path from the advanced checkpoint, newline locate vs the parse-based locate
      t = Date.now();
      out.bootNewline = await mc._checkpointFastPath({ _auditLog: a, _pgAuditBackend: pg, fileCount: N, start: null });
      out.bootNewlineMs = Date.now() - t;
      const parseOnly = { ...a, locateModernCursor: undefined };
      t = Date.now();
      out.bootParse = await mc._checkpointFastPath({ _auditLog: parseOnly, _pgAuditBackend: pg, fileCount: N, start: null });
      out.bootParseMs = Date.now() - t;
      // a checkpoint OUTSIDE the in-memory window (entry 50,000): where the parse-based locate pays the prefix parse
      const mid = { ...pg, getLatestAuditCheckpoint: async () => ({ chainLength: 50000, hash: await hashAt(49999), seq: 50000 }) };
      t = Date.now();
      out.midNewline = await mc._checkpointFastPath({ _auditLog: a, _pgAuditBackend: mid, fileCount: N, start: null });
      out.midNewlineMs = Date.now() - t;
      t = Date.now();
      out.midParse = await mc._checkpointFastPath({ _auditLog: parseOnly, _pgAuditBackend: mid, fileCount: N, start: null });
      out.midParseMs = Date.now() - t;
    }
    sample(); out.peakHeapMB = Math.round(peak / 1e6);
    process.stdout.write('AUT08F_RESULT ' + JSON.stringify(out) + '\\n');
    process.exit(0);
  })().catch((e) => { process.stdout.write('AUT08F_RESULT ' + JSON.stringify({ error: e.stack }) + '\\n'); process.exit(3); });`;

function run(extraEnv = {}) {
  const env = { ...process.env, QODIQA_AUDIT_LOG: logPath, QODIQA_PG_ENABLED: 'false', NODE_OPTIONS: '', N: String(N), ...extraEnv };
  const r = spawnSync(process.execPath, [`--max-old-space-size=${HEAP_CAP_MB}`, '-e', HARNESS],
    { cwd: ROOT, env, encoding: 'utf8', timeout: 240_000, maxBuffer: 64 * 1024 * 1024 });
  const line = (r.stdout.split('\n').find((l) => l.startsWith('AUT08F_RESULT ')) || '').slice('AUT08F_RESULT '.length);
  return { r, out: line ? JSON.parse(line) : null };
}

test(`LA-1/LA-2 advancement over ${N.toLocaleString('en')} entries under a ${HEAP_CAP_MB} MB heap; the next boot checks only the remainder`, () => {
  const { r, out } = run();
  expect(r.stderr).not.toMatch(/heap out of memory/i);
  expect(r.status).toBe(0);
  expect(out.error).toBeUndefined();
  expect(out.advance).toMatchObject({ advanced: true, from: 1000, to: N, entries: N - 1000, startLocate: 'newline' });
  expect(out.written).toEqual([N]);
  expect(out.bootNewline).toMatchObject({ ok: true, checkpointLength: N, suffixChecked: 0, locate: 'newline' });
  expect(out.bootParse).toMatchObject({ ok: true, checkpointLength: N, suffixChecked: 0, locate: 'parse' });
  expect(out.midNewline).toMatchObject({ ok: true, checkpointLength: 50000, suffixChecked: N - 50000, locate: 'newline' });
  expect(out.midParse).toMatchObject({ ok: true, checkpointLength: 50000, suffixChecked: N - 50000, locate: 'parse' });
  process.stdout.write(`LA-1/2: advance ${out.advanceMs} ms (peak heap ${out.advancePeakHeapMB} MB); boot from the advanced checkpoint: newline ${out.bootNewlineMs} ms / parse ${out.bootParseMs} ms; boot from entry 50,000: newline ${out.midNewlineMs} ms / parse ${out.midParseMs} ms; peak heap ${out.peakHeapMB} MB\n`);
}, 300_000);

test('LA-3 a tampered mirror row deep in the range → refused, nothing written, within the heap cap', () => {
  const { r, out } = run({ T_TAMPER_SEQ: '61000' });
  expect(r.stderr).not.toMatch(/heap out of memory/i);
  expect(r.status).toBe(0);
  expect(out.advance).toMatchObject({ advanced: false, refused: true });
  expect(['PG_RANGE_INVALID', 'RANGE_DIVERGENCE']).toContain(out.advance.reason);
  expect(out.advance.at).toBe(60_999);
  expect(out.written).toEqual([]);
}, 300_000);
