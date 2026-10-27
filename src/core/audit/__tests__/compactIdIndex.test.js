'use strict';

/**
 * — the streamed full scan's artifact-ID bookkeeping moved from two Sets of strings to an exact
 * CompactIdIndex (fingerprint + byte offset, every fingerprint match confirmed by re-reading the earlier entry), and the
 * full scans read in 64 KiB chunks. Criteria:
 * ACCEPTANCE-CRITERIA.md.
 *
 *   IX   the index on its own: exactness under forced collisions, growth, fail-closed confirmation reads
 *   A2   differential: byte-identical reports from the pinned PRE-CHANGE module (fixtures/previous-audit-log) and the new one
 *        — validateChainIntegrityFromDurableStoreChunked (restore probe / integrity endpoint) and verifyFullChainFromDisk
 *        (verifier full scan) — on every fixture, with and without forced fingerprint collisions
 *   A3   a failed confirmation read fails the scan (never "not a duplicate")
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const NEW = path.join(__dirname, '..', 'audit-log.js');
const ORACLE = path.join(__dirname, 'fixtures', 'previous-audit-log', 'audit-log.oracle.js');
const EMPTY = require('../entryBuilder').EMPTY_OUTPUT_HASH;

jest.setTimeout(120000);

const uuid = () => crypto.randomUUID();
const allow = (o = {}) => ({ artifactId: uuid(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: EMPTY, signature: 's'.repeat(64),
  requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64), verificationResult: true, ...o });
const block = (o = {}) => ({ artifactId: uuid(), decision: 'BLOCK', ...o });

function withLog(logPath, fn) {
  const saved = { QODIQA_AUDIT_LOG: process.env.QODIQA_AUDIT_LOG, QODIQA_AUDIT_ORDERING_MODE: process.env.QODIQA_AUDIT_ORDERING_MODE };
  process.env.QODIQA_AUDIT_LOG = logPath;
  delete process.env.QODIQA_AUDIT_ORDERING_MODE;
  return Promise.resolve().then(fn).finally(() => {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });
}

/** A valid chain through the REAL append path: `n` entries, replays of earlier entries every 7th, one replay of an absent original. */
async function buildChain(n) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aut18-'));
  const log = path.join(dir, 'audit.log');
  await withLog(log, async () => {
    jest.resetModules();
    const a = require(NEW);
    const ids = [];
    for (let i = 0; i < n; i++) {
      let e;
      if (i > 0 && i % 7 === 0) e = block({ executionContext: { replayOf: ids[i - 3], stage: 'REPLAY_GUARD', reason: 'REPLAY_DETECTED' } });
      else if (i === n - 2) e = block({ executionContext: { replayOf: `absent-${uuid()}`, stage: 'REPLAY_GUARD', reason: 'REPLAY_DETECTED' } });
      else e = allow();
      ids.push(e.artifactId);
      await a.append(e);
    }
    await a.drainPendingWrites();
  });
  return { dir, log };
}

const lines = (log) => fs.readFileSync(log, 'utf8').split('\n').filter(Boolean);

/**
 * Run one implementation: a fresh module instance (audit-log.js boots at require time) is booted on the CLEAN log, then
 * the file is replaced by the case's content and the three full scans run — exactly the situation they exist for
 * (tampering after boot; the restore probe re-reads the file fresh). `bootOnCase` instead boots on the case itself
 * (load-time verification, compared separately).
 */
async function run(modPath, cleanLines, caseText, { collide = false, bootOnCase = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aut18-run-'));
  const log = path.join(dir, 'audit.log');
  fs.writeFileSync(log, bootOnCase ? caseText : `${cleanLines.join('\n')}\n`);
  return withLog(log, async () => {
    jest.resetModules();
    if (collide) require('../compactIdIndex')._setFingerprintForTests(() => [7, 7]);   // every ID collides
    try {
      let m;
      try { m = require(modPath); } catch (e) { return { loadThrew: e.message }; }
      if (bootOnCase) return { loaded: true, length: m.getChainLength() };
      fs.writeFileSync(log, caseText);
      const integrity = await m.validateChainIntegrityFromDurableStoreChunked();
      const full = m.verifyFullChainFromDisk();
      const fullChunked = await m.verifyFullChainFromDiskChunked();
      return { integrity, full, fullChunked };
    } finally {
      require('../compactIdIndex')._setFingerprintForTests(null);
    }
  });
}

async function expectIdentical(cleanLines, caseText, opts = {}) {
  const before = await run(ORACLE, cleanLines, caseText, { bootOnCase: opts.bootOnCase });
  const after = await run(NEW, cleanLines, caseText, opts);
  expect(JSON.parse(JSON.stringify(after))).toEqual(JSON.parse(JSON.stringify(before)));
  return { before, after };
}

// ── IX: the index ────────────────────────────────────────────────────────────────────────────────────────────────
describe('CompactIdIndex', () => {
  const { CompactIdIndex, _setFingerprintForTests } = require('../compactIdIndex');
  afterEach(() => _setFingerprintForTests(null));

  test('IX-1 exact set semantics through several growths (200k distinct IDs, then every one again)', () => {
    const store = new Map();
    const ix = new CompactIdIndex((off) => store.get(off));
    for (let i = 0; i < 200000; i++) { const id = `id-${i}`; store.set(i * 10, id); expect(ix.add(id, i * 10)).toBe(false); }
    expect(ix.size).toBe(200000);
    expect(ix.capacity).toBeGreaterThanOrEqual(400000);
    for (let i = 0; i < 200000; i += 997) expect(ix.add(`id-${i}`, 999999999)).toBe(true);
    expect(ix.has('id-199999')).toBe(true);
    expect(ix.has('id-200000')).toBe(false);
    expect(ix.size).toBe(200000);
  });

  test('IX-2 forced fingerprint collisions: distinct IDs are never duplicates, equal IDs always are', () => {
    _setFingerprintForTests(() => [1, 2]);
    const store = new Map();
    const ix = new CompactIdIndex((off) => store.get(off));
    for (let i = 0; i < 300; i++) { store.set(i, `x-${i}`); expect(ix.add(`x-${i}`, i)).toBe(false); }
    expect(ix.confirmReads).toBe((300 * 299) / 2);   // every earlier slot was confirmed and rejected
    expect(ix.add('x-150', 1000)).toBe(true);
    expect(ix.has('x-0')).toBe(true);
    expect(ix.has('y')).toBe(false);
  });

  test('IX-3 a failed confirmation read throws (fail closed), it is never "not a duplicate"', () => {
    _setFingerprintForTests(() => [3, 4]);
    const ix = new CompactIdIndex(() => { throw new Error('EIO'); });
    expect(ix.add('a', 0)).toBe(false);          // empty table: nothing to confirm
    expect(() => ix.add('b', 10)).toThrow('EIO');
    expect(() => ix.has('a')).toThrow('EIO');
  });
});

// ── A2: differential against the pinned pre-change module ───────────────────────────────────────────────────────
describe('differential: pre-change module (oracle) vs new — byte-identical reports', () => {
  let base;
  beforeAll(async () => { base = await buildChain(60); });

  const cases = {
    'clean chain (with replays, one of an absent original)': (ls) => ls,
    'duplicate artifact line, adjacent': (ls) => [...ls.slice(0, 11), ls[10], ...ls.slice(11)],
    'duplicate artifact line, far apart': (ls) => [...ls.slice(0, 50), ls[2], ...ls.slice(50)],
    'duplicate after an earlier failure (tampered hash at 5)': (ls) => {
      const t = JSON.parse(ls[5]); t.hash = 'f'.repeat(64);
      return [...ls.slice(0, 5), JSON.stringify(t), ...ls.slice(6, 40), ls[1], ...ls.slice(40)];
    },
    'forged legacy key': (ls) => { const t = JSON.parse(ls[20]); t.legacy = false; return [...ls.slice(0, 20), JSON.stringify(t), ...ls.slice(21)]; },
    'malformed JSON line': (ls) => [...ls.slice(0, 30), '{not json', ...ls.slice(30)],
    'torn tail (no final newline)': (ls) => ls,
  };

  const caseText = (name, mutate) => `${mutate(lines(base.log)).join('\n')}\n${name.startsWith('torn') ? '{"artifactId":"torn' : ''}`;

  for (const [name, mutate] of Object.entries(cases)) {
    for (const collide of [false, true]) {
      test(`A2 ${name}${collide ? ' — every fingerprint forced to collide' : ''}`, async () => {
        const { after } = await expectIdentical(lines(base.log), caseText(name, mutate), { collide });
        if (name.startsWith('duplicate artifact line')) {
          expect(after.integrity.chainValid).toBe(false);
          expect(JSON.stringify(after.integrity)).toMatch(/AUDIT_DUPLICATE_ENTRY/);
        }
        if (name.startsWith('clean')) {
          expect(after.integrity.chainValid).toBe(true);
          expect(JSON.stringify(after.integrity)).toMatch(/"replaysLinked":[1-9]/);   // replay linkage exercised
        }
      });
    }
    test(`A2 load-time (boot on the case) ${name}`, async () => {
      await expectIdentical(lines(base.log), caseText(name, mutate), { bootOnCase: true });
    });
  }

  test('A2 a longer chain (1,500 entries): identical reports', async () => {
    const big = await buildChain(1500);
    await expectIdentical(lines(big.log), `${lines(big.log).join('\n')}\n`);
    const dup = lines(big.log); dup.splice(1400, 0, dup[3]);
    const { after } = await expectIdentical(lines(big.log), `${dup.join('\n')}\n`);
    expect(JSON.stringify(after.integrity)).toMatch(/AUDIT_DUPLICATE_ENTRY/);
  });
});

// ── A3: fail-closed confirmation read inside the scan ───────────────────────────────────────────────────────────
describe('fail-closed', () => {
  test('A3 an I/O error on a confirmation read fails the integrity scan (chainValid false, parse error reported)', async () => {
    const { log } = await buildChain(20);
    const res = await withLog(log, async () => {
      jest.resetModules();
      require('../compactIdIndex')._setFingerprintForTests(() => [5, 6]);
      const realOpen = fs.openSync;
      const m = require(NEW);
      let opens = 0;
      const spy = jest.spyOn(fs, 'openSync').mockImplementation((p, ...a) => {
        if (p === log && ++opens > 1) { const e = new Error('EIO: simulated read failure'); e.code = 'EIO'; throw e; }
        return realOpen(p, ...a);
      });
      try { return await m.validateChainIntegrityFromDurableStoreChunked(); } finally { spy.mockRestore(); require('../compactIdIndex')._setFingerprintForTests(null); }
    });
    expect(res.chainValid).toBe(false);
    expect(res.parseError).toMatch(/EIO/);
  });
});
