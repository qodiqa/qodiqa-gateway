'use strict';

/**
 * — the verifier's bounds, in process.
 *
 *   CT-01  3 consecutive non-completing runs of a mode → CRITICAL AUDIT_CHAIN_VERIFIER_NOT_COMPLETING, once per episode
 *   CT-02  a completing run resets the count and emits COMPLETING_AGAIN after an escalation; modes are independent
 *   CT-03  verifier lag = appended − verified; WARN LAGGING above the threshold (edge-triggered), INFO when recovered
 *   DL-01  a run past its deadline → TIMEOUT + WARN AUDIT_CHAIN_VERIFIER_RUN_TIMEOUT; the mutex stays held until the
 *          run really ends (a tick meanwhile is SKIPPED, never concurrent); 3 timeouts → CRITICAL NOT_COMPLETING
 *   SM-01  the bounded-memory divergence merge reaches the SAME verdict as the full comparison on every mutation case
 *          (it decides alone only when both sides agree position by position; any disagreement falls back)
 * SM-02 PG ahead of the file page, and an in-flight file tail resolved by the recheck, are decided
 *          without the full comparison; a missing tail entry falls back and is reported exactly as before
 * SM-03 a large healthy chain is decided by the merge alone, paged on both sides
 *   IC-01  incremental catch-up is capped per tick and the watermark advances across ticks until caught up
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const { createCompletionTracker } = require('../verifier/completionTracker');
const { createVerifierRunner } = require('../verifier/index');
const { createChainVerifier } = require('../verifier/ChainVerifier');
const { crossValidateRecords, crossValidateRecordsAsync } = require('../mirrorConsistencyCheck');

const quiet = new Proxy({}, { get: () => ({ inc: () => {}, set: () => {}, observe: () => {} }) });

describe('completion tracker', () => {
  test('CT-01/CT-02 escalation and recovery per mode', () => {
    const ev = [];
    const t = createCompletionTracker({ emit: (l, e, d) => ev.push({ l, e, d }), metrics: quiet });
    t.record('FULL', 'TIMEOUT'); t.record('FULL', 'FAILED');
    expect(ev.filter((x) => x.e === 'AUDIT_CHAIN_VERIFIER_NOT_COMPLETING')).toHaveLength(0);
    t.record('FULL', 'TIMEOUT');
    t.record('FULL', 'TIMEOUT');
    const crit = ev.filter((x) => x.e === 'AUDIT_CHAIN_VERIFIER_NOT_COMPLETING');
    expect(crit).toHaveLength(1);                          // once per episode
    expect(crit[0]).toMatchObject({ l: 'CRITICAL', d: { mode: 'FULL', consecutive: 3 } });
    expect(ev.filter((x) => x.e === 'AUDIT_CHAIN_VERIFIER_RUN_INCOMPLETE')).toHaveLength(4);
    t.record('INCREMENTAL', 'COMPLETE');                   // other mode unaffected
    expect(t.state().consecutive.FULL).toBe(4);
    t.record('FULL', 'COMPLETE');
    expect(ev.at(-1)).toMatchObject({ l: 'INFO', e: 'AUDIT_CHAIN_VERIFIER_COMPLETING_AGAIN', d: { mode: 'FULL' } });
    expect(t.state().consecutive.FULL).toBe(0);
  });

  test('CT-03 lag metric and edge-triggered LAGGING', () => {
    const ev = []; let appended = 100;
    const t = createCompletionTracker({ emit: (l, e, d) => ev.push({ l, e, d }), metrics: quiet, lagWarnEntries: 50, getAppendedCount: () => appended });
    expect(t.recordWatermark(80)).toBe(20);
    appended = 1000;
    expect(t.recordWatermark(100)).toBe(900);
    t.recordWatermark(200);                                // still lagging: no second WARN
    expect(ev.filter((x) => x.e === 'AUDIT_CHAIN_VERIFIER_LAGGING')).toHaveLength(1);
    t.recordWatermark(990);
    expect(ev.at(-1)).toMatchObject({ l: 'INFO', e: 'AUDIT_CHAIN_VERIFIER_LAG_RECOVERED' });
  });
});

describe('runner deadline', () => {
  test('DL-01 timeout reported, mutex held until the run ends, escalation after 3', async () => {
    const ev = [];
    let release;
    const fakeVerifier = { verify: () => new Promise((r) => { release = r; }), verifyPgDivergence: async () => ({ success: true }), getLastResult: () => null };
    jest.isolateModules(() => {
      jest.doMock('../verifier/ChainVerifier', () => ({ createChainVerifier: () => fakeVerifier }));
      const { createVerifierRunner: mk } = require('../verifier/index');
      global.__runner = mk({ config: { enabled: true, maxRetries: 0, retryDelayMs: 1, incrementalIntervalMs: 0, fullIntervalMs: 0, pgDivergenceIntervalMs: 0,
        deadlinesMs: { FULL: 30 } }, _emit: (l, e, d) => ev.push({ l, e, d }), _metrics: quiet, _auditLog: { getChainStats: () => ({ modernLength: 0 }) } });
    });
    const runner = global.__runner; delete global.__runner;
    const r1 = await runner.verifyNow('FULL');
    expect(r1).toMatchObject({ success: false, outcome: 'TIMEOUT' });
    expect(ev.some((x) => x.e === 'AUDIT_CHAIN_VERIFIER_RUN_TIMEOUT')).toBe(true);
    expect(runner.isScanning()).toBe(true);                // the run is still going: mutex held
    const r2 = await runner.verifyNow('FULL');
    expect(r2).toMatchObject({ skipped: true });           // never concurrent
    release({ success: true, violations: [], entriesChecked: 0 });
    await new Promise((r) => setTimeout(r, 5));
    expect(runner.isScanning()).toBe(false);
    for (let i = 0; i < 2; i++) { const p = runner.verifyNow('FULL'); await p; release({ success: true }); await new Promise((r) => setTimeout(r, 5)); }
    expect(ev.filter((x) => x.e === 'AUDIT_CHAIN_VERIFIER_NOT_COMPLETING')).toHaveLength(1);
    jest.dontMock('../verifier/ChainVerifier');
  });
});

// ── the bounded-memory merge ─────────────────────────────────────────────────
function chain(n, tag = 'x') {
  const out = []; let prev = 'GENESIS';
  for (let i = 0; i < n; i++) { const e = { hash: `${tag}h${i}`, prevHash: prev, artifactId: `${tag}a${i}`, canonical: `{"i":${i}}` }; out.push(e); prev = e.hash; }
  return out;
}
const clone = (a) => a.map((e) => ({ ...e }));

function verifierFor({ file, pg, streaming, lookup, pageSize = 3 }) {
  const events = []; const held = { maxFileBuf: 0 };
  const auditLog = {
    ORDERING_MODE: 'single-node',
    getChainStats: () => ({ modernLength: file.length }),
    getModernChainPage: async ({ cursor, limit }) => {
      const from = cursor ? cursor.m : 0;
      const entries = file.slice(from, from + Math.min(limit, pageSize));
      return { entries, startPos: from, nextCursor: from + entries.length < file.length ? { m: from + entries.length } : null };
    },
    forEachModernChainPage: async (onPage, { limit }) => { for (let i = 0; i < file.length; i += limit) await onPage(file.slice(i, i + limit)); return file.length; },
    drainMirrorWriter: async () => {},
  };
  const backend = {
    validateChainLinks: async () => ({ valid: true, brokenLinks: 0 }),
    queryByArtifactId: async (id) => (lookup ? lookup(id) : null),
    loadChainFromPgCompact: async (compact) => require('../../../utils/hashLinkOrder').orderByHashLinks(pg.map((r) => ({ ...r }))).rows.map(compact),
    ...(streaming ? { forEachChainPageCompactInSnapshot: async (compact, { onPage }) => {
      for (let i = 0; i < pg.length; i += 4) { if ((await onPage(pg.slice(i, i + 4).map((r) => compact({ ...r })))) === false) break; }
    } } : {}),
  };
  const v = createChainVerifier({ config: { batchSize: 3, streamingDivergence: streaming }, _auditLog: auditLog, _pgPool: { isEnabled: () => true }, _pgBackend: backend,
    _mirrorCheck: { crossValidateRecords, crossValidateRecordsAsync }, _verifierState: {}, _metrics: quiet, _emit: (l, e, d) => events.push({ l, e, d }) });
  return { v, events, held };
}
const strip = (r) => ({ success: r.success, entriesChecked: r.entriesChecked, violations: (r.violations || []).map(({ detectedAt, ...x }) => x) });

function cases() {
  const base = chain(14);
  const out = [];
  const add = (name, file, pg, extra = {}) => out.push({ name, file, pg, ...extra });
  add('identical', clone(base), clone(base));
  add('metadata mismatch', clone(base), (() => { const p = clone(base); p[6].canonical += ' '; return p; })());
  add('prev-hash mismatch', clone(base), (() => { const p = clone(base); p[5].prevHash = 'zz'; return p; })());
  add('hash mismatch by artifact', clone(base), (() => { const p = clone(base); p[7].hash = 'rehash'; return p; })());
  add('pg missing middle', clone(base), clone(base).filter((_, i) => i !== 4));
  add('pg extra stray row', clone(base), [...clone(base), { hash: 'stray', prevHash: 'nowhere', artifactId: 'ax', canonical: 'c' }]);
  add('pg reversed', clone(base), clone(base).reverse());
  add('pg duplicate row', clone(base), (() => { const p = clone(base); p.push({ ...p[3] }); return p; })());
  add('empty pg', clone(base), []);
  add('in-flight tail found on recheck', clone(base), clone(base).slice(0, 12), { lookup: (id) => base.find((e) => e.artifactId === id) });
  add('in-flight tail still missing', clone(base), clone(base).slice(0, 12), { lookup: () => null });
  return out;
}

describe('bounded-memory divergence merge', () => {
  test.each(cases().map((c) => [c.name, c]))('SM-01 same verdict as the full comparison: %s', async (_n, c) => {
    const full = await verifierFor({ file: c.file, pg: c.pg, streaming: false, lookup: c.lookup }).v.verifyPgDivergence('MANUAL');
    const merged = await verifierFor({ file: c.file, pg: c.pg, streaming: true, lookup: c.lookup }).v.verifyPgDivergence('MANUAL');
    expect(strip(merged)).toEqual(strip(full));
  });

  test('SM-02 healthy, and an in-flight tail, are decided by the merge alone', async () => {
    const base = chain(40);
    const h = verifierFor({ file: base, pg: clone(base), streaming: true });
    const r = await h.v.verifyPgDivergence('MANUAL');
    expect(r.violations).toEqual([]);
    expect(h.events.some((x) => x.e === 'AUDIT_CHAIN_VERIFIER_DIVERGENCE_FULL_COMPARE')).toBe(false);
    const t = verifierFor({ file: base, pg: clone(base).slice(0, 37), streaming: true, lookup: (id) => base.find((e) => e.artifactId === id) });
    const r2 = await t.v.verifyPgDivergence('MANUAL');
    expect(r2.violations).toEqual([]);
    expect(t.events.find((x) => x.e === 'AUDIT_CHAIN_VERIFIER_TAIL_RECHECKED').d).toMatchObject({ tailLength: 3, resolved: true, streamed: true });
    expect(t.events.some((x) => x.e === 'AUDIT_CHAIN_VERIFIER_DIVERGENCE_FULL_COMPARE')).toBe(false);
    const m = verifierFor({ file: base, pg: clone(base).filter((_, i) => i !== 9), streaming: true });
    const r3 = await m.v.verifyPgDivergence('MANUAL');
    // the merge stops (a held row never finds its parent, or positions disagree) and the full comparison decides
    expect(['POSITIONAL_MISMATCH', 'PG_UNLINKED_ROWS']).toContain(m.events.find((x) => x.e === 'AUDIT_CHAIN_VERIFIER_DIVERGENCE_FULL_COMPARE').d.reason);
    expect(r3.violations.map((v) => v.reason)).toEqual(['PG_MIRROR_MISSING_IN_PG']);
  });

  test('SM-03 a large healthy chain is decided by the merge alone', async () => {
    const base = chain(5000);
    const h = verifierFor({ file: base, pg: clone(base), streaming: true });
    const r = await h.v.verifyPgDivergence('MANUAL');
    expect(r.entriesChecked).toBe(5000);
    expect(h.events.some((x) => x.e === 'AUDIT_CHAIN_VERIFIER_DIVERGENCE_FULL_COMPARE')).toBe(false);
  });
});

describe('incremental catch-up cap', () => {
  test('IC-01 at most maxIncrementalEntries per tick; the watermark advances until caught up', async () => {
    const entries = require('../../audit/entryBuilder');
    let prev = 'GENESIS'; const file = [];
    for (let i = 0; i < 250; i++) { const e = entries.buildEntry(entries.normalizeFields({ artifactId: `ic-${i}`, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true }), prev); file.push(e); prev = e.hash; }
    let state = null;
    const auditLog = require('../audit-log');
    const facade = {
      ORDERING_MODE: 'single-node',
      getChainStats: () => ({ modernLength: file.length }),
      getModernChainPage: async ({ cursor, limit }) => { const from = cursor ? cursor.m : 0; const es = file.slice(from, from + limit); return { entries: es, startPos: from, nextCursor: from + es.length < file.length ? { m: from + es.length } : null }; },
      verifyAuditChainDetailedChunked: auditLog.verifyAuditChainDetailedChunked,
    };
    const v = createChainVerifier({ config: { maxIncrementalEntries: 100 }, _auditLog: facade, _pgPool: { isEnabled: () => false }, _pgBackend: {},
      _verifierState: { loadFileState: async () => state, saveFileState: async (s) => { state = s; } }, _metrics: quiet, _emit: () => {} });
    const r1 = await v.verify({ mode: 'INCREMENTAL' });
    expect(r1).toMatchObject({ entriesChecked: 100, watermarkIndex: 100, caughtUp: false });
    const r2 = await v.verify({ mode: 'INCREMENTAL' });
    expect(r2).toMatchObject({ entriesChecked: 100, watermarkIndex: 200, caughtUp: false });
    const r3 = await v.verify({ mode: 'INCREMENTAL' });
    expect(r3).toMatchObject({ entriesChecked: 50, watermarkIndex: 250, caughtUp: true });
    expect([r1, r2, r3].every((r) => r.violations.length === 0)).toBe(true);
  });
});
