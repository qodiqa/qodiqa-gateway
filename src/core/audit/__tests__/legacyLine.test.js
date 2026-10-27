'use strict';

/**
 * legacy-line classification.
 *
 *three readers took the "legacy" (pre-hash-chain) classification from a `legacy`
 * key stored IN the line: the fast-path boot tail window, the full-disk scan and _walkChain.
 * A line carrying it skipped every check, so an inserted line verified as a valid chain
 * (repro-run1.json: variant B + rewritten anchor → boot ACCEPTED, verifyFullChainFromDisk
 * valid:true). Separately the boot loader accepted a legacy-shaped (no inputHash) line ANYWHERE,
 * even appended after the genuine tail with the genuine anchor untouched (variant A).
 *
 * The classification is now derived only (no inputHash), marked non-enumerable, and valid only
 * in the pre-hash prefix. These tests pin both the refusals and that genuine data still loads.
 *
 * LL-01  genuine chain: boots, full-disk verify valid
 * LL-02  genuine pre-hash prefix + chain: boots; derived flag is never serialized back out
 * LL-03  legacy-shaped line after the chain (tail, genuine anchor untouched): boot refuses
 * LL-04  inserted line with a stored `legacy` key + rewritten anchor: boot refuses
 * LL-05  same line inserted AFTER a clean boot: full-disk verify reports it (was valid:true)
 * LL-06  _walkChain: stored key → tampered; derived flag after a chained entry → tampered;
 *        derived flag at the GENESIS prefix → skipped (valid)
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const fs = require('fs');
const os = require('os');
const path = require('path');
const { normalizeFields, buildEntry } = require('../entryBuilder');

const savedLog = process.env.QODIQA_AUDIT_LOG;
const savedAnchor = process.env.QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH;
const created = []; // temp dirs this suite created — removed afterwards (only those)
afterAll(() => { for (const d of created) fs.rmSync(d, { recursive: true, force: true }); });
afterEach(() => {
  process.env.QODIQA_AUDIT_LOG = savedLog;
  if (savedAnchor === undefined) delete process.env.QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH;
  else process.env.QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH = savedAnchor;
});

function chain(n, prefix = 'll') {
  const out = []; let prev = 'GENESIS';
  for (let i = 0; i < n; i++) {
    const e = buildEntry(normalizeFields({
      artifactId: `${prefix}-${i}`, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 's' + i,
      requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, publicKeyId: 'w7:key_v1',
    }), prev);
    out.push(JSON.stringify(e)); prev = e.hash;
  }
  return out;
}

function writeLog(lines, { anchor = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w7-ll-'));
  created.push(dir);
  const log = path.join(dir, 'audit.log');
  const text = lines.join('\n') + '\n';
  fs.writeFileSync(log, text);
  if (anchor === 'match') {
    // an attacker rewriting the unsigned anchor to match the file exactly
    const parsed = lines.map((l) => JSON.parse(l));
    const modern = parsed.filter((e) => e.inputHash != null);
    fs.writeFileSync(log + '.sum', JSON.stringify({ count: parsed.length, tailHash: modern[modern.length - 1].hash,
      v2: { totalCount: parsed.length, modernCount: modern.length, allowCount: 0, blockCount: 0, replayCount: 0, headHash: modern[0].hash, byteLength: Buffer.byteLength(text) } }));
  }
  delete process.env.QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH;
  process.env.QODIQA_AUDIT_LOG = log;
  return log;
}

function boot() {
  let mod; let err = null;
  jest.isolateModules(() => {
    try { mod = require('../audit-log'); } catch (e) { err = e; }
  });
  return { mod, err };
}

const legacyPrefixLine = (i) => JSON.stringify({ timestamp: '2026-01-01T00:00:00.000Z', artifactId: `pre-hash-${i}`, status: 'ALLOW' });
const forgedFlagLine = (template) => JSON.stringify({ ...JSON.parse(template), artifactId: 'forged-allow', legacy: true });

describe('legacy-line classification', () => {
  test('LL-01 a genuine chain boots and verifies from disk', () => {
    writeLog(chain(3));
    const { mod, err } = boot();
    expect(err).toBeNull();
    const v = mod.verifyFullChainFromDisk();
    expect(v.walkResult).toMatchObject({ valid: true, entriesVerified: 3 });
  });

  test('LL-02 a genuine pre-hash prefix still boots, and the derived flag is never serialized', async () => {
    writeLog([legacyPrefixLine(0), legacyPrefixLine(1), ...chain(2)]);
    const { mod, err } = boot();
    expect(err).toBeNull();
    const page = await mod.getChainPage({ limit: 10 });
    const pre = page.entries.find((e) => e.artifactId === 'pre-hash-0');
    expect(pre.legacy).toBe(true);
    expect(JSON.stringify(pre)).not.toMatch(/legacy/);
    // Documented (SCHEMA-V6 §legacy): the full-disk verifier has always refused pre-hash lines
    // (AUDIT_ENTRY_MISSING — nothing to verify); boot merely tolerates them as history.
    expect(mod.verifyFullChainFromDisk().walkResult).toMatchObject({ valid: false, reason: 'AUDIT_ENTRY_MISSING', offendingIndex: 0 });
  });

  test('LL-03 a legacy-shaped line appended after the chain is refused at boot, genuine anchor untouched', () => {
    const genuine = chain(3);
    const log = writeLog(genuine);
    expect(boot().err).toBeNull();                                  // writes the genuine anchor
    fs.appendFileSync(log, JSON.stringify({ timestamp: new Date().toISOString(), artifactId: 'forged', decision: 'ALLOW' }) + '\n');
    const { err } = boot();
    expect(err && err.message).toMatch(/legacy-shaped line after the first hash-chained entry/);
  });

  test('LL-04 an inserted line carrying a stored legacy key is refused at boot even with a rewritten anchor', () => {
    const g = chain(3);
    writeLog([g[0], forgedFlagLine(g[1]), g[1], g[2]], { anchor: 'match' });
    const { err } = boot();
    expect(err && err.message).toMatch(/stored legacy flag/);
  });

  test('LL-05 the same insertion after a clean boot is reported by the full-disk verifier', () => {
    const g = chain(3);
    const log = writeLog(g);
    const { mod, err } = boot();
    expect(err).toBeNull();
    fs.writeFileSync(log, [g[0], forgedFlagLine(g[1]), g[1], g[2]].join('\n') + '\n');
    const v = mod.verifyFullChainFromDisk();
    expect(v.walkResult).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: 'STORED_LEGACY_FLAG', tamperingDetected: true, offendingIndex: 1 });
  });

  test('LL-06 _walkChain: stored key and derived-after-chained are tampering; a GENESIS prefix is skipped', () => {
    writeLog(chain(1));
    const { mod } = boot();
    const g = chain(2).map((l) => JSON.parse(l));
    const derived = (o) => { Object.defineProperty(o, 'legacy', { value: true, enumerable: false }); return o; };

    const stored = mod.verifyAuditChainDetailed([g[0], { ...g[1], legacy: true }]);
    expect(stored).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: 'STORED_LEGACY_FLAG', offendingIndex: 1 });

    const after = mod.verifyAuditChainDetailed([g[0], derived({ timestamp: 't', artifactId: 'x' }), g[1]]);
    expect(after).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: 'LEGACY_AFTER_MODERN', offendingIndex: 1 });

    const prefix = mod.verifyAuditChainDetailed([derived({ timestamp: 't', artifactId: 'x' }), g[0], g[1]]);
    expect(prefix).toMatchObject({ valid: true, entriesVerified: 2 });
  });
});
