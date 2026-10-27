'use strict';

/**
 * — the PG-divergence check rechecks an in-flight tail before alerting.
 * Before: an entry appended to the file just before the verifier read it, whose PG dual-write had not committed
 * when the verifier read PG, raised a false CRITICAL AUDIT_CHAIN_CORRUPTED (PG_MIRROR_MISSING_IN_PG) at exactly
 * the chain tail.
 *
 *   TR-01  in-flight tail, written by recheck time → no violation; the mirror writer is drained BEFORE the lookup
 *   TR-02  tail still missing after the recheck → CRITICAL PG_MIRROR_MISSING_IN_PG, as before
 *   TR-03  a gap in the MIDDLE of the chain → violation at once, no recheck lookup at all
 *   TR-04  tail present on recheck but written differently → reported (METADATA mismatch), not hidden
 *   TR-05  a backend without queryByArtifactId → alert as before
 *   TR-06  a missing tail longer than 1,000 entries (a stalled mirror) → alert, no recheck
 *   TR-07  after a resolved tail, the rest of the check still runs: an extra PG row → MISSING_IN_FILE
 */

const { crossValidateRecords, crossValidateRecordsAsync } = require('../mirrorConsistencyCheck');
const { createChainVerifier } = require('../verifier/ChainVerifier');

function chain(n) {
  const out = []; let prev = 'GENESIS';
  for (let i = 0; i < n; i++) { const e = { hash: `h${i}`, prevHash: prev, artifactId: `a${i}`, canonical: `{"i":${i}}` }; out.push(e); prev = e.hash; }
  return out;
}
const quiet = new Proxy({}, { get: () => ({ inc: () => {}, set: () => {}, observe: () => {} }) });

function run({ file, pgSnapshot, lookup, drain, withLookup = true }) {
  const events = [];
  const calls = { lookups: [], order: [] };
  const auditLog = {
    ORDERING_MODE: 'single-node',
    forEachModernChainPage: async (onPage) => { await onPage(file); return file.length; },
    ...(drain !== false ? { drainMirrorWriter: async () => { calls.order.push('drain'); if (drain) await drain(); } } : {}),
  };
  const pgBackend = {
    validateChainLinks: async () => ({ valid: true, brokenLinks: 0 }),
    loadChainFromPgCompact: async (compact) => pgSnapshot.map((r) => compact({ ...r })),
    ...(withLookup ? { queryByArtifactId: async (id) => { calls.lookups.push(id); calls.order.push('lookup'); return lookup ? lookup(id) : null; } } : {}),
  };
  const v = createChainVerifier({ config: { batchSize: 3 }, _auditLog: auditLog, _pgPool: { isEnabled: () => true }, _pgBackend: pgBackend,
    _mirrorCheck: { crossValidateRecords, crossValidateRecordsAsync }, _verifierState: {}, _metrics: quiet,
    _emit: (level, type, data) => events.push({ level, type, data }) });
  return v.verifyPgDivergence('SCHEDULED').then((r) => ({ r, events, calls }));
}
const reasons = (r) => r.violations.map((v) => v.reason);

describe('in-flight tail recheck', () => {
  test('TR-01 tail written by recheck time → no violation; drain happens before the lookup', async () => {
    const file = chain(6); const pg = file.slice(0, 5);
    const { r, events, calls } = await run({ file, pgSnapshot: pg, lookup: (id) => file.find((e) => e.artifactId === id) });
    expect(r.success).toBe(true);
    expect(r.violations).toEqual([]);
    expect(calls.lookups).toEqual(['a5']);
    expect(calls.order).toEqual(['drain', 'lookup']);
    const ev = events.find((e) => e.type === 'AUDIT_CHAIN_VERIFIER_TAIL_RECHECKED');
    expect(ev.data).toMatchObject({ tailLength: 1, foundOnRecheck: 1, resolved: true });
    expect(events.some((e) => e.type === 'AUDIT_CHAIN_CORRUPTED')).toBe(false);
  });

  test('TR-02 tail still missing → CRITICAL PG_MIRROR_MISSING_IN_PG, as before', async () => {
    const file = chain(6);
    const { r, events } = await run({ file, pgSnapshot: file.slice(0, 4), lookup: () => null });
    expect(reasons(r)).toEqual(['PG_MIRROR_MISSING_IN_PG']);
    expect(r.violations[0].severity).toBe('CRITICAL');
    expect(r.violations[0].sequence).toBe(4);
    expect(events.find((e) => e.type === 'AUDIT_CHAIN_VERIFIER_TAIL_RECHECKED').data).toMatchObject({ tailLength: 2, foundOnRecheck: 0, resolved: false, stillMismatched: 'MISSING_IN_PG' });
  });

  test('TR-03 a gap in the middle of the chain → violation at once, no lookup', async () => {
    const file = chain(6); const pg = file.filter((_, i) => i !== 2);
    const { r, calls } = await run({ file, pgSnapshot: pg, lookup: (id) => file.find((e) => e.artifactId === id) });
    expect(reasons(r)).toEqual(['PG_MIRROR_MISSING_IN_PG']);
    expect(r.violations[0].sequence).toBe(2);
    expect(calls.lookups).toEqual([]);
  });

  test('TR-04 tail present on recheck but written differently → reported, not hidden', async () => {
    const file = chain(6);
    const { r } = await run({ file, pgSnapshot: file.slice(0, 5), lookup: (id) => ({ ...file.find((e) => e.artifactId === id), canonical: 'tampered' }) });
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0].reason).not.toBe('PG_MIRROR_MISSING_IN_PG');
    expect(r.violations[0].sequence).toBe(5);
  });

  test('TR-05 a backend without the lookup → alert as before', async () => {
    const file = chain(6);
    const { r, calls } = await run({ file, pgSnapshot: file.slice(0, 5), withLookup: false });
    expect(reasons(r)).toEqual(['PG_MIRROR_MISSING_IN_PG']);
    expect(calls.order).toEqual([]);
  });

  test('TR-06 a missing tail longer than 1,000 entries (stalled mirror) → alert, no recheck', async () => {
    const file = chain(1_200);
    const { r, calls } = await run({ file, pgSnapshot: file.slice(0, 150), lookup: (id) => file.find((e) => e.artifactId === id) });
    expect(reasons(r)).toEqual(['PG_MIRROR_MISSING_IN_PG']);
    expect(calls.lookups).toEqual([]);
  });

  test('TR-07 after a resolved tail the rest of the check runs: an extra PG row → MISSING_IN_FILE', async () => {
    const file = chain(6);
    const stray = { hash: 'stray', prevHash: 'nowhere', artifactId: 'ax', canonical: 'c' };
    const { r } = await run({ file, pgSnapshot: [...file.slice(0, 5), stray], lookup: (id) => file.find((e) => e.artifactId === id) });
    expect(reasons(r)).toEqual(['PG_MIRROR_MISSING_IN_FILE']);
  });
});
