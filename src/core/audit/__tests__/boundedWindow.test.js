'use strict';

/**
 * regression suite — bounded in-memory audit window + streamed boot.
 *
 * Pins the two properties exists to guarantee, so a regression fails a
 * test instead of an OOM in production:
 *
 *   1. BOUNDED MEMORY — the in-memory chain[] is a tail window whose length
 *      never exceeds QODIQA_AUDIT_WINDOW_SIZE, independent of how many
 * entries the lifetime history holds. Lifetime counters and
 * head/tail hashes stay EXACT across the eviction boundary, and
 *      lookups older than the window still resolve via the durable-store
 * fallback. The paginated API walks the full history in stable
 * order and is cursor-resumable.
 *
 *   2. STREAMED BOOT — startup never reads the whole audit.log into memory
 *      in one call: no fs.readFileSync(LOG_PATH) on either boot path (B1
 *      covers both the anchor-v2 fast path and the full-validation fallback),
 *      and the streamed reader works with a fixed buffer far smaller than
 *      the file (B2).
 *
 * Unlike most audit suites this one uses the REAL filesystem (per-test
 * mkdtemp under os.tmpdir(), same location test/support/jest.setup.js uses for the
 * default test audit log) because the durable-store fallback and the
 * streamed boot are exactly the code paths fs mocks would bypass.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

function uuid() { return crypto.randomUUID(); }

function allowParams(overrides = {}) {
  return {
    artifactId:         uuid(),
    inputHash:          'a'.repeat(64),
    decision:           'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:          's'.repeat(64),
    requestHash:        'r'.repeat(64),
    policyHash:         'p'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

const ENV_KEYS = ['QODIQA_AUDIT_LOG', 'QODIQA_AUDIT_WINDOW_SIZE', 'QODIQA_AUDIT_BOOT_CHUNK_BYTES'];
let _savedEnv;

beforeEach(() => {
  _savedEnv = {};
  for (const k of ENV_KEYS) _savedEnv[k] = process.env[k];
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (_savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = _savedEnv[k];
  }
  jest.restoreAllMocks();
});

/**
 * Fresh audit-log module instance against a real on-disk log.
 * @param {object} opts
 * @param {string}  [opts.dir]     reuse an existing log dir (reboot scenarios)
 * @param {string}  [opts.window]  QODIQA_AUDIT_WINDOW_SIZE value
 * @param {string}  [opts.chunk]   QODIQA_AUDIT_BOOT_CHUNK_BYTES value
 * @param {(mods: object) => void} [opts.beforeRequire] runs inside the module
 *   registry isolate after env setup, before audit-log loads (for spies on
 *   modules the boot path itself requires).
 */
function freshAudit({ dir, window, chunk, beforeRequire } = {}) {
  const logDir = dir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f01-'));
  process.env.QODIQA_AUDIT_LOG = path.join(logDir, 'audit.log');
  if (window !== undefined) process.env.QODIQA_AUDIT_WINDOW_SIZE = window;
  else delete process.env.QODIQA_AUDIT_WINDOW_SIZE;
  if (chunk !== undefined) process.env.QODIQA_AUDIT_BOOT_CHUNK_BYTES = chunk;
  else delete process.env.QODIQA_AUDIT_BOOT_CHUNK_BYTES;

  let audit;
  jest.isolateModules(() => {
    if (beforeRequire) beforeRequire({ logger: require('../../../../services/logger') });
    audit = require('../audit-log');
  });
  return { audit, logDir };
}

describe('W: bounded window with exact lifetime accounting', () => {
  test('in-memory window never exceeds QODIQA_AUDIT_WINDOW_SIZE while lifetime counters stay exact', async () => {
    const { audit } = freshAudit({ window: '5' });
    const ids = [];
    for (let i = 0; i < 12; i++) ids.push((await audit.append(allowParams())).artifactId);

    const stats = audit.getWindowStats();
    expect(stats.windowSize).toBe(5);
    expect(stats.windowLength).toBe(5);          // the bound, not 12
    expect(stats.totalCount).toBe(12);           // lifetime accounting unaffected
    expect(audit.getChainLength()).toBe(12);

    const report = audit.validateChainIntegrity();
    expect(report.chainValid).toBe(true);
    expect(report.chainLength).toBe(12);
    expect(report.allowCount).toBe(12);
    expect(report.blockCount).toBe(0);
  });

  test('lookups older than the window fall back to the durable store and still resolve', async () => {
    const { audit } = freshAudit({ window: '5' });
    const first = await audit.append(allowParams());
    for (let i = 0; i < 10; i++) await audit.append(allowParams());

    // `first` has been evicted from the window (10 appends > window 5) …
    expect(audit.getWindowStats().windowLength).toBe(5);
    // … but the durable-store fallback still finds it, field-for-field.
    const found = await audit.getArtifactById(first.artifactId);
    expect(found).not.toBeNull();
    expect(found.hash).toBe(first.hash);
    // In-window lookups keep working too.
    const last = (await audit.getModernChainPage({ cursor: null, limit: 1000 }));
    expect(await audit.getArtifactById(last.entries[last.entries.length - 1].artifactId)).not.toBeNull();
    // Replay/nonce dedup helpers also resolve out-of-window via the fallback.
    expect(await audit.alreadyExecuted(first.artifactId)).toBe(true);
  });

  test('getModernChainPage() walks the full history in append order and is cursor-resumable', async () => {
    const { audit } = freshAudit({ window: '5' });
    const ids = [];
    for (let i = 0; i < 13; i++) ids.push((await audit.append(allowParams())).artifactId);

    // Full walk in pages of 4.
    const walked = [];
    let cursor = null;
    let savedMidCursor = null;
    let pageNo = 0;
    do {
      const page = await audit.getModernChainPage({ cursor, limit: 4 });
      expect(page.entries.length).toBeLessThanOrEqual(4);
      walked.push(...page.entries.map(e => e.artifactId));
      pageNo += 1;
      if (pageNo === 2) savedMidCursor = page.nextCursor;  // resume point after 8 entries
      cursor = page.nextCursor;
    } while (cursor);
    expect(walked).toEqual(ids);  // stable order: exact append order, no gaps, no dupes

    // Resumability: a saved cursor reproduces the identical suffix later.
    const resumed = [];
    cursor = savedMidCursor;
    while (cursor) {
      const page = await audit.getModernChainPage({ cursor, limit: 4 });
      resumed.push(...page.entries.map(e => e.artifactId));
      cursor = page.nextCursor;
    }
    expect(resumed).toEqual(ids.slice(8));
  });

  test('reboot on the same log keeps lifetime counters/hashes exact and refills only the window', async () => {
    const { audit, logDir } = freshAudit({ window: '5' });
    for (let i = 0; i < 12; i++) await audit.append(allowParams());
    const before = audit.validateChainIntegrity();

    const { audit: rebooted } = freshAudit({ dir: logDir, window: '5' });
    const after = rebooted.validateChainIntegrity();
    expect(after.chainValid).toBe(true);
    expect(after.chainLength).toBe(12);
    expect(after.headHash).toBe(before.headHash);
    expect(after.tailHash).toBe(before.tailHash);
    expect(rebooted.getWindowStats().windowLength).toBe(5);

    // And the durable full scan agrees with the in-memory accounting.
    const durable = await rebooted.validateChainIntegrityFromDurableStoreChunked();
    expect(durable.chainValid).toBe(true);
    expect(durable.chainLength).toBe(12);
    expect(durable.tailHash).toBe(before.tailHash);
  });

  test('appends continue seamlessly across the eviction boundary after a windowed reboot', async () => {
    const { audit, logDir } = freshAudit({ window: '3' });
    for (let i = 0; i < 7; i++) await audit.append(allowParams());

    const { audit: rebooted } = freshAudit({ dir: logDir, window: '3' });
    const e8 = await rebooted.append(allowParams());
    expect(rebooted.getChainLength()).toBe(8);
    expect(rebooted.validateChainIntegrity().tailHash).toBe(e8.hash);
    const durable = await rebooted.validateChainIntegrityFromDurableStoreChunked();
    expect(durable.chainValid).toBe(true);
    expect(durable.chainLength).toBe(8);
  });

  test('E1 escape hatch: QODIQA_AUDIT_WINDOW_SIZE=unbounded restores keep-everything and WARNs at boot', async () => {
    let warnSpy;
    const { audit } = freshAudit({
      window: 'unbounded',
      beforeRequire: ({ logger }) => { warnSpy = jest.spyOn(logger, 'emit'); },
    });
    expect(audit.WINDOW_SIZE).toBe(Infinity);
    expect(audit.getWindowStats().unbounded).toBe(true);
    expect(warnSpy).toHaveBeenCalledWith('WARN', 'AUDIT_WINDOW_UNBOUNDED', expect.any(Object));

    for (let i = 0; i < 12; i++) await audit.append(allowParams());
    expect(audit.getWindowStats().windowLength).toBe(12);  // nothing evicted
  });
});

describe('B: streamed boot — startup never reads the whole file in one call', () => {
  // Builds a real on-disk chain, then reboots with fs.readFileSync spied:
  // the boot may readFileSync SMALL sidecar files (the .sum anchor, the WAL
  // tail is read via fd) but never audit.log itself.
  async function _bootAndCollectReadFileSyncTargets({ deleteSum }) {
    const { audit, logDir } = freshAudit({ window: '5' });
    for (let i = 0; i < 25; i++) await audit.append(allowParams());
    const logPath = path.join(logDir, 'audit.log');
    if (deleteSum) {
      // Force the full-validation fallback path by making the anchor
      // unavailable to the NEXT boot (renamed, not deleted — evidence stays).
      fs.renameSync(logPath + '.sum', logPath + '.sum.aside');
    }

    const targets = [];
    const { audit: rebooted } = freshAudit({
      dir: logDir,
      window: '5',
      chunk: '1024',  // far smaller than the ~25-entry file — forces multi-chunk streaming
      beforeRequire: () => {
        const orig = fs.readFileSync;
        jest.spyOn(fs, 'readFileSync').mockImplementation((p, ...rest) => {
          targets.push(String(p));
          return orig(p, ...rest);
        });
      },
    });
    jest.restoreAllMocks();
    return { rebooted, logPath, targets };
  }

  test('B1a anchor-v2 fast path: boot is correct and never fs.readFileSync()s audit.log', async () => {
    const { rebooted, logPath, targets } = await _bootAndCollectReadFileSyncTargets({ deleteSum: false });
    expect(targets).not.toContain(logPath);
    const report = rebooted.validateChainIntegrity();
    expect(report.chainValid).toBe(true);
    expect(report.chainLength).toBe(25);
  });

  test('B1b full-validation fallback (no anchor): still streamed, never fs.readFileSync()s audit.log', async () => {
    const { rebooted, logPath, targets } = await _bootAndCollectReadFileSyncTargets({ deleteSum: true });
    expect(targets).not.toContain(logPath);
    const report = rebooted.validateChainIntegrity();
    expect(report.chainValid).toBe(true);
    expect(report.chainLength).toBe(25);
  });

  test('B2 a fixed 1KB boot buffer reproduces the identical state a default-buffer boot builds', async () => {
    const { audit, logDir } = freshAudit({ window: '5' });
    for (let i = 0; i < 25; i++) await audit.append(allowParams());
    const defaultBoot = freshAudit({ dir: logDir, window: '5' }).audit.validateChainIntegrity();
    const smallBoot   = freshAudit({ dir: logDir, window: '5', chunk: '1024' }).audit.validateChainIntegrity();
    expect(smallBoot.chainValid).toBe(true);
    expect(smallBoot.chainLength).toBe(defaultBoot.chainLength);
    expect(smallBoot.headHash).toBe(defaultBoot.headHash);
    expect(smallBoot.tailHash).toBe(defaultBoot.tailHash);
    expect(smallBoot.allowCount).toBe(defaultBoot.allowCount);
  });
});
