'use strict';

/**
 * — byte-offset index for the boot anchor check.
 * Acceptance criteria G-1..G-6:
 *
 * Real audit-log (file mode, 20-entry window) over 3,000 valid chained entries (production entryBuilder), anchors at
 * every 500th entry. verifyAnchorsAtBoot() runs with the real lookup path; the anchoring layer is injected so that its
 * POSITION check (headHashAt vs the anchored head — CHAIN_ROLLED_BACK / CHAIN_REWRITTEN, exactly as
 * anchors.verifyChainAgainstAnchors does it) is what decides; signature/witness checks are untouched by this change.
 * Every tamper case runs through BOTH the new indexed lookup and the previous parse-pass lookup ("old").
 *
 * valid chain → PASS through the offset index; index written; next boot CONSISTENT
 * verdict equivalence (G-1): anchored history re-hashed / prefix line deleted / deleted + padded (byte offsets
 *         unchanged) / prefix line inserted / file truncated → FAIL in both; blank line in the prefix → PASS in both
 *         (the new path falls back to the parse pass and does not write the index)
 * a tampered index never decides (G-2): wrong offsets / wrong hashes / another log's index + valid chain → PASS,
 *         WARN INCONSISTENT, rebuilt; tampered index + rewritten chain → FAIL
 * missing → INFO REBUILT; malformed → WARN MALFORMED; wrong version → WARN VERSION; all rebuilt after a pass
 * safe reconstruction (G-4): no index written by a failing check; a failed write is a WARN and the boot passes;
 *         the follower never writes
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const eb = require('../../entryBuilder');

const N = 3000;
const EVERY = 500;

function build(n = N, from = 'GENESIS', start = 0) {
  const lines = []; const hashes = []; let prev = from;
  for (let i = start; i < start + n; i++) {
    const e = eb.buildEntry(eb.normalizeFields({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: eb.EMPTY_OUTPUT_HASH,
      signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 't' }), prev);
    lines.push(JSON.stringify(e)); hashes.push(e.hash); prev = e.hash;
  }
  return { lines, hashes };
}

describe('byte-offset anchor index', () => {
  let dir; let file; let base; let a; let anchorIndex;
  const write = (lines) => fs.writeFileSync(file, lines.join('\n') + '\n');
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut08g-'));
    file = path.join(dir, 'audit.log');
    base = build();
    write(base.lines);
    process.env.QODIQA_AUDIT_LOG = file;
    process.env.QODIQA_AUDIT_WINDOW_SIZE = '20';
    jest.resetModules();
    a = require('../../audit-log');
    anchorIndex = require('../../anchoring/anchorIndex');
  });
  afterEach(() => {
    delete process.env.QODIQA_AUDIT_LOG; delete process.env.QODIQA_AUDIT_WINDOW_SIZE;
    jest.resetModules();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const anchorsFor = (hashes) => {
    const out = [];
    for (let n = EVERY; n <= N; n += EVERY) out.push({ checkpoint: { payload: { checkpointId: `cp-${n}`, chainLength: n, headHash: hashes[n - 1] }, payloadHash: `ph-${n}` } });
    return out;
  };

  async function boot({ old = false, follower = false, anchors = anchorsFor(base.hashes) } = {}) {
    const events = [];
    const cw = require('../checkpointWriter');
    const auditLog = old ? { ...a, getModernHashesAtByOffset: undefined } : (follower ? { ...a, isFollower: () => true } : a);
    const anchoring = {
      exportPath: () => path.join(dir, 'anchors.jsonl'),
      read: () => anchors,
      independence: () => 'test',
      trustedWitnessKeys: () => ({ keys: [] }),
      witnesses: () => [],
      // the position check of anchors.verifyChainAgainstAnchors, verbatim in substance
      verify: async ({ anchors: list, chainLength, headHashAt, prunedBefore }) => {
        const findings = [];
        for (const x of list) {
          const { chainLength: n, headHash } = x.checkpoint.payload;
          if (chainLength < n) findings.push({ code: 'CHAIN_ROLLED_BACK', detail: String(n) });
          else if (n > prunedBefore) { const h = await headHashAt(n); if (h !== headHash) findings.push({ code: 'CHAIN_REWRITTEN', detail: String(n) }); }
        }
        return { ok: findings.length === 0, checked: list.length, findings };
      },
    };
    try {
      const r = await cw.verifyAnchorsAtBoot({ auditLog, anchoring, logPath: file, emit: (l, t, d) => events.push({ l, t, d }),
        pgPool: { isEnabled: () => false }, backend: {} });
      const v = events.find((e) => e.t === 'AUDIT_ANCHORS_BOOT_VERIFIED');   // lookup / index status are reported in the event
      return { ok: true, r: { ...r, lookup: v.d.lookup, anchorIndex: v.d.anchorIndex }, events };
    } catch (e) {
      return { ok: false, code: e.code, findings: e.findings, events };
    }
  }
  const ev = (res, t) => res.events.filter((e) => e.t === t);

  test('valid chain → PASS through the offset index; index written; next boot CONSISTENT', async () => {
    const r1 = await boot();
    expect(r1.ok).toBe(true);
    expect(r1.r).toMatchObject({ lookup: 'offset-index', anchorIndex: 'MISSING' });
    expect(ev(r1, 'AUDIT_ANCHOR_INDEX_REBUILT')[0].d.reason).toBe('MISSING');
    const idx = anchorIndex.readIndex(file);
    expect(idx.status).toBe('OK');
    expect(idx.index.entries.size).toBe(N / EVERY);
    for (const [pos, rec] of idx.index.entries) {
      expect(rec.hash).toBe(base.hashes[pos]);
      const line = fs.readFileSync(file).subarray(rec.off).toString('utf8').split('\n')[0];
      expect(JSON.parse(line).hash).toBe(base.hashes[pos]);
    }
    const r2 = await boot();
    expect(r2.r).toMatchObject({ lookup: 'offset-index', anchorIndex: 'CONSISTENT' });
    expect(ev(r2, 'AUDIT_ANCHOR_INDEX_INCONSISTENT')).toHaveLength(0);
  });

  describe('verdict equivalence with the previous parse-pass lookup', () => {
    const cases = {
      'anchored history re-hashed from entry 1,200': () => { const re = build(N - 1200, base.hashes[1199], 1200); return [...base.lines.slice(0, 1200), ...re.lines]; },
      'prefix line 700 deleted': () => base.lines.filter((_, i) => i !== 700),
      'prefix line 700 deleted, line 699 padded (all later byte offsets unchanged)': () => {
        const l = base.lines.slice(); const pad = Buffer.byteLength(l[700]) + 1;
        l[699] = l[699] + ' '.repeat(pad); l.splice(700, 1); return l;
      },
      'a line inserted before entry 900': () => { const l = base.lines.slice(); l.splice(900, 0, base.lines[10]); return l; },
      'file truncated below the last anchors': () => base.lines.slice(0, 1800),
    };
    for (const [name, mutate] of Object.entries(cases)) {
      test(`${name} → FAIL in both`, async () => {
        await boot();                         // a clean boot first: an index exists, as in production
        write(mutate());
        const now = await boot(); const before = await boot({ old: true });
        expect(before.ok).toBe(false);
        expect(now.ok).toBe(false);
        expect(now.code).toBe('AUDIT_ANCHOR_BOOT_FAILED');
        expect(now.findings.map((f) => f.code).sort()).toEqual(before.findings.map((f) => f.code).sort());
      });
    }
    test('a blank line in the prefix (benign) → PASS in both; the new path falls back to the parse pass and does not write', async () => {
      await boot();
      const indexBefore = fs.readFileSync(anchorIndex.indexPath(file), 'utf8');
      const l = base.lines.slice(); l.splice(400, 0, ''); write(l);
      const now = await boot(); const before = await boot({ old: true });
      expect(before.ok).toBe(true);
      expect(now.ok).toBe(true);
      expect(now.r.lookup).toBe('parse');
      expect(ev(now, 'AUDIT_ANCHOR_INDEX_INCONSISTENT')).toHaveLength(1);   // the layout changed since the last boot
      expect(fs.readFileSync(anchorIndex.indexPath(file), 'utf8')).toBe(indexBefore);
    });
  });

  test('a tampered index never decides', async () => {
    await boot();
    const p = anchorIndex.indexPath(file);
    const doc = JSON.parse(fs.readFileSync(p, 'utf8'));
    for (const variant of ['offsets', 'hashes', 'otherLog']) {
      const d = JSON.parse(JSON.stringify(doc));
      if (variant === 'offsets') d.entries = d.entries.map(([pos, off, h]) => [pos, off + 17, h]);
      if (variant === 'hashes') d.entries = d.entries.map(([pos, off]) => [pos, off, 'e'.repeat(64)]);
      if (variant === 'otherLog') d.logHead = 'f'.repeat(64);
      fs.writeFileSync(p, JSON.stringify(d));
      const r = await boot();
      expect(r.ok).toBe(true);
      expect(r.r.anchorIndex).toBe('INCONSISTENT');
      expect(ev(r, 'AUDIT_ANCHOR_INDEX_INCONSISTENT')[0].d.reason).toBe(variant === 'otherLog' ? 'LOG_IDENTITY' : 'OFFSET_OR_HASH_MISMATCH');
      expect(anchorIndex.compareIndex(anchorIndex.readIndex(file).index,
        { logHead: base.hashes[0], offsets: new Map(doc.entries.map(([q, off]) => [q, off])), hashes: new Map(doc.entries.map(([q, , h]) => [q, h])) }).consistent).toBe(true); // rebuilt
    }
    // a "matching" index cannot rescue a rewritten chain
    fs.writeFileSync(p, JSON.stringify(doc));
    const re = build(N - 1200, base.hashes[1199], 1200);
    write([...base.lines.slice(0, 1200), ...re.lines]);
    const bad = await boot();
    expect(bad.ok).toBe(false);
    expect(bad.findings.some((f) => f.code === 'CHAIN_REWRITTEN')).toBe(true);
  });

  test('missing / malformed / wrong version → reported and rebuilt after a pass', async () => {
    const p = anchorIndex.indexPath(file);
    for (const [content, status, reason] of [['{not json', 'MALFORMED', 'MALFORMED'], [JSON.stringify({ version: 99, entries: [] }), 'VERSION', 'VERSION'],
      [JSON.stringify({ version: 1, entries: [[1, -5, 'x']] }), 'MALFORMED', 'MALFORMED']]) {
      fs.writeFileSync(p, content);
      const r = await boot();
      expect(r.ok).toBe(true);
      expect(r.r.anchorIndex).toBe(status);
      expect(ev(r, 'AUDIT_ANCHOR_INDEX_INCONSISTENT')[0].d.reason).toBe(reason);
      expect(anchorIndex.readIndex(file).status).toBe('OK');
    }
  });

  test('safe reconstruction: nothing written by a failing check, a failed write never fails the boot, the follower never writes', async () => {
    const p = anchorIndex.indexPath(file);
    write(base.lines.slice(0, 1800));
    expect((await boot()).ok).toBe(false);
    expect(fs.existsSync(p)).toBe(false);
    write(base.lines);
    expect((await boot({ follower: true })).ok).toBe(true);
    expect(fs.existsSync(p)).toBe(false);
    fs.mkdirSync(p);                         // the index path is unwritable
    const r = await boot();
    expect(r.ok).toBe(true);
    expect(ev(r, 'AUDIT_ANCHOR_INDEX_WRITE_FAILED')).toHaveLength(1);
  });
});
