'use strict';

/**
 * the audit verifier's PG-divergence check is streamed instead of materialized, and must
 * reach exactly the same verdicts. Found by the soak: every 15-minute run blocked the event loop for up to
 * 1.2 s at 75,000 entries (growing with the chain) and stalled live traffic
 *.
 *
 *   DS-01  forEachModernChainPage() delivers exactly getModernChain()'s entries, in order — bounded window with
 *          durable pages, unbounded window, and a window that has not wrapped yet
 *   DS-02  crossValidateRecordsAsync() returns the same result object as crossValidateRecords() for every
 *          mismatch reason, duplicates, reordering, and 400 random mutations — and the same exception for a null
 *          PG row
 *   DS-03  crossValidateRecordsAsync() yields to the event loop on large inputs (the sync version cannot)
 *   DS-04  _compactForDivergence() preserves every comparison: cross-validating compacted records gives the
 *          same result as cross-validating the raw ones, on the DS-02 cases
 *   DS-05  verifyPgDivergence() through the new paged functions reports the same violations as through the
 *          original calls, for each mismatch scenario
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { crossValidateRecords, crossValidateRecordsAsync } = require('../mirrorConsistencyCheck');
const { createChainVerifier, _compactForDivergence } = require('../verifier/ChainVerifier');
const { orderByHashLinks } = require('../../../utils/hashLinkOrder');

// ── fixtures ────────────────────────────────────────────────────────────────
function chain(n, tag = 'x') {
  const out = []; let prev = 'GENESIS';
  for (let i = 0; i < n; i++) {
    const e = { hash: `${tag}h${i}`, prevHash: prev, artifactId: `${tag}a${i}`, canonical: `{"i":${i},"t":"${tag}"}` };
    out.push(e); prev = e.hash;
  }
  return out;
}
const clone = (a) => a.map((e) => (e ? { ...e } : e));

function mutations(n) {
  const base = chain(n);
  const cases = [];
  const add = (name, file, pg) => cases.push({ name, file, pg });
  add('identical', clone(base), clone(base));
  add('pg missing last (MISSING_IN_PG)', clone(base), clone(base).slice(0, -1));
  add('pg extra row (MISSING_IN_FILE)', clone(base), [...clone(base), { hash: 'extra', prevHash: base[n - 1].hash, artifactId: 'ae', canonical: 'c' }]);
  { const pg = clone(base); pg[3].canonical += ' '; add('metadata mismatch', clone(base), pg); }
  { const pg = clone(base); pg[4].prevHash = 'zz'; add('prev-hash mismatch', clone(base), pg); }
  { const pg = clone(base); pg[5].hash = 'rehashed'; add('hash mismatch by artifactId', clone(base), pg); }
  { const pg = clone(base); pg[0].prevHash = 'NOT-GENESIS'; add('genesis prev mismatch', clone(base), pg); }
  { const pg = clone(base); pg[0].hash = 'g2'; add('genesis hash mismatch', clone(base), pg); }
  { const pg = clone(base); pg.push({ ...pg[2] }); add('duplicate hash in pg', clone(base), pg); }
  { const pg = clone(base).reverse(); add('pg reversed order', clone(base), pg); }
  { const pg = clone(base); delete pg[6].canonical; add('pg canonical missing', clone(base), pg); }
  { const f = clone(base); const pg = clone(base); f[2].canonical = null; pg[2].canonical = null; add('both canonical null', f, pg); }
  { const pg = clone(base); pg[7].artifactId = undefined; pg[7].hash = 'nohash'; add('no hash, no artifactId match', clone(base), pg); }
  add('empty file', [], clone(base));
  add('empty pg', clone(base), []);
  add('both empty', [], []);
  return cases;
}

function randomCases(count, seed = 7) {
  let s = seed; const rnd = () => { s = (s * 1103515245 + 12345) % 2147483648; return s / 2147483648; };
  const out = [];
  for (let c = 0; c < count; c++) {
    const n = 1 + Math.floor(rnd() * 40);
    const base = chain(n, `r${c}`);
    const file = clone(base); const pg = clone(base);
    const edits = Math.floor(rnd() * 3);
    for (let e = 0; e < edits; e++) {
      const i = Math.floor(rnd() * n); const kind = Math.floor(rnd() * 7);
      const tgt = rnd() < 0.5 ? file : pg; if (!tgt[i]) continue;
      if (kind === 0) tgt[i].canonical += '!';
      else if (kind === 1) tgt[i].prevHash = 'p?';
      else if (kind === 2) tgt[i].hash = `h?${c}${e}`;
      else if (kind === 3) tgt.splice(i, 1);
      else if (kind === 4) tgt.push({ ...tgt[i] });
      else if (kind === 5) tgt.sort(() => rnd() - 0.5);
      else tgt[i].artifactId = `a?${c}${e}`;
    }
    out.push({ name: `random-${c}`, file, pg });
  }
  return out;
}

// ── DS-01 ───────────────────────────────────────────────────────────────────
describe('DS-01 forEachModernChainPage() == getModernChain()', () => {
  const ENV = ['QODIQA_AUDIT_LOG', 'QODIQA_AUDIT_WINDOW_SIZE'];
  let saved;
  const created = []; // this run's own audit-log dirs — removed after each case (the teardown convention)
  beforeEach(() => { saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]])); });
  afterEach(() => {
    for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    const tmp = path.resolve(os.tmpdir());
    for (const d of created.splice(0)) {
      if (path.dirname(path.resolve(d)) === tmp && path.basename(d).startsWith('qodiqa-w9ds-')) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
    }
  });

  async function freshWith(window, n) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w9ds-'));
    created.push(dir);
    process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit.log');
    process.env.QODIQA_AUDIT_WINDOW_SIZE = window;
    let audit; jest.isolateModules(() => { audit = require('../audit-log'); });
    for (let i = 0; i < n; i++) {
      await audit.append({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 's'.repeat(64),
        requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64), verificationResult: true });
    }
    return audit;
  }
  async function viaPages(audit, limit) {
    const got = []; const sizes = [];
    const n = await audit.forEachModernChainPage(async (page) => { sizes.push(page.length); got.push(...page); await new Promise((r) => setImmediate(r)); }, { limit });
    return { got, sizes, n };
  }

  test.each([
    ['bounded window, durable pages', '5', 23, 4],
    ['unbounded window', 'unbounded', 17, 5],
    ['window not yet wrapped', '1000', 9, 4],
  ])('%s', async (_name, window, n, limit) => {
    const audit = await freshWith(window, n);
    const expected = await audit.getModernChain();
    const { got, sizes, n: count } = await viaPages(audit, limit);
    expect(expected).toHaveLength(n);
    expect(count).toBe(n);
    expect(got.map((e) => e.hash)).toEqual(expected.map((e) => e.hash));
    expect(got).toEqual(expected);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(limit);
  });
});

// ── DS-02 / DS-04 ───────────────────────────────────────────────────────────
describe('DS-02 crossValidateRecordsAsync() == crossValidateRecords()', () => {
  const all = [...mutations(12), ...randomCases(400)];
  test.each(all.map((c) => [c.name, c]))('%s', async (_name, c) => {
    const sync = crossValidateRecords(clone(c.file), clone(c.pg));
    const async_ = await crossValidateRecordsAsync(clone(c.file), clone(c.pg));
    expect(async_).toEqual(sync);
  });

  test('a null PG row: both versions throw the same error at the same point', async () => {
    const f = chain(3); const pg = [...clone(f), null];
    let syncErr; try { crossValidateRecords(f, pg); } catch (e) { syncErr = e; }
    let asyncErr; try { await crossValidateRecordsAsync(f, pg); } catch (e) { asyncErr = e; }
    expect(syncErr).toBeInstanceOf(TypeError);
    expect(asyncErr).toBeInstanceOf(TypeError);
    expect(asyncErr.message).toBe(syncErr.message);
  });
});

describe('DS-04 compaction preserves every comparison', () => {
  const all = [...mutations(12), ...randomCases(400, 11)];
  test.each(all.map((c) => [c.name, c]))('%s', (_name, c) => {
    const raw = crossValidateRecords(clone(c.file), clone(c.pg));
    const compact = crossValidateRecords(c.file.map(_compactForDivergence), c.pg.map(_compactForDivergence));
    expect(compact).toEqual(raw);
  });

  test('digest shape: strings hashed, other values kept', () => {
    expect(_compactForDivergence({ hash: 'h', prevHash: 'p', artifactId: 'a', canonical: 'abc', extra: 1 })).toEqual({
      hash: 'h', prevHash: 'p', artifactId: 'a', canonical: `sha256:${crypto.createHash('sha256').update('abc').digest('hex')}` });
    expect(_compactForDivergence({ hash: 'h', canonical: null }).canonical).toBeNull();
    expect(_compactForDivergence({ hash: 'h' }).canonical).toBeUndefined();
    expect(_compactForDivergence(null)).toBeNull();
  });
});

// ── DS-03 ───────────────────────────────────────────────────────────────────
describe('DS-03 the async comparison yields', () => {
  test('20,000 matching entries: other macrotasks run during the comparison', async () => {
    const f = chain(20_000); const pg = clone(f);
    let ticks = 0; let running = true;
    const spin = () => { if (!running) return; ticks++; setImmediate(spin); };
    setImmediate(spin);
    const r = await crossValidateRecordsAsync(f, pg);
    running = false;
    expect(r.firstMismatch).toBeNull();
    expect(r.recordsChecked).toBe(20_000);
    // three loops of 20,000 with a yield every 2,048 iterations → ≥ 20 yields
    expect(ticks).toBeGreaterThanOrEqual(20);
  });
});

// ── DS-05 ───────────────────────────────────────────────────────────────────
describe('DS-05 verifyPgDivergence(): paged path == original path', () => {
  const quiet = new Proxy({}, { get: () => ({ inc: () => {}, set: () => {}, observe: () => {} }) });
  const pgPool = { isEnabled: () => true };
  function verifierFor({ file, pg, paged }) {
    const auditLog = paged
      ? { ORDERING_MODE: 'single-node', forEachModernChainPage: async (onPage, { limit }) => { for (let i = 0; i < file.length; i += limit) await onPage(file.slice(i, i + limit)); return file.length; } }
      : { ORDERING_MODE: 'single-node', getModernChain: async () => file };
    const pgBackend = {
      validateChainLinks: async () => ({ valid: true, brokenLinks: 0 }),
      ...(paged
        ? { loadChainFromPgCompact: async (compact, { onPage }) => { const rows = orderByHashLinks(pg.map((r) => ({ ...r }))).rows.map(compact); for (let i = 0; i < rows.length; i += 3) await onPage(rows.slice(i, i + 3)); return rows; } }
        : { loadChainFromPg: async () => orderByHashLinks(pg.map((r) => ({ ...r }))).rows }),
    };
    const mirrorCheck = paged ? { crossValidateRecords, crossValidateRecordsAsync } : { crossValidateRecords };
    return createChainVerifier({ config: { batchSize: 3 }, _auditLog: auditLog, _pgPool: pgPool, _pgBackend: pgBackend,
      _mirrorCheck: mirrorCheck, _verifierState: {}, _metrics: quiet, _emit: () => {} });
  }
  const strip = (r) => ({ success: r.success, entriesChecked: r.entriesChecked, violations: (r.violations || []).map(({ detectedAt, ...v }) => v) });

  test.each(mutations(9).map((c) => [c.name, c]))('%s', async (_name, c) => {
    const original = await verifierFor({ file: c.file, pg: c.pg, paged: false }).verifyPgDivergence('MANUAL');
    const paged = await verifierFor({ file: c.file, pg: c.pg, paged: true }).verifyPgDivergence('MANUAL');
    // Not vacuous: the original path really ran, and flags exactly the cases the sync comparison flags.
    const expectMismatch = crossValidateRecords(clone(c.file), orderByHashLinks(clone(c.pg)).rows).firstMismatch !== null;
    expect(original.success).toBe(true);
    expect(original.violations.length > 0).toBe(expectMismatch);
    expect(strip(paged)).toEqual(strip(original));
  });
});
