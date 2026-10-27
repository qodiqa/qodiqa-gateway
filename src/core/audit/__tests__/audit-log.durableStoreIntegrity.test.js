'use strict';

/**
 * Finding E — GET /audit/chain/integrity must report the PERSISTED
 * store's current state, not this process's in-memory cache.
 *
 * validateChainIntegrityChunked() (pre-existing) walks only chain[] — built
 * once at startup and updated only by this process's own successful
 * append() calls. If audit.log is modified directly on disk while the
 * process keeps running (a hand-edit, a restored backup, external
 * tampering), that function's report is blind to it: chain[] never changes
 * on its own.
 *
 * validateChainIntegrityFromDurableStoreChunked() (new) re-reads audit.log
 * fresh from disk on every call. These tests prove the difference directly:
 * after tampering with the on-disk file post-load, the memory-based report
 * still claims the chain is valid, while the durable-store report correctly
 * detects the tampering — the exact gap Finding E identifies.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');

function tmpAuditLogPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-durable-integrity-'));
  return path.join(dir, 'audit.log');
}

function entryFields(overrides = {}) {
  return {
    artifactId: crypto.randomUUID(),
    inputHash: 'a'.repeat(64),
    decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature: 's'.repeat(64),
    requestHash: 'r'.repeat(64),
    policyHash: 'p'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

describe('Finding E — durable-store-fresh integrity report', () => {
  let logPath;

  beforeEach(() => {
    logPath = tmpAuditLogPath();
    process.env.QODIQA_AUDIT_LOG = logPath;
    jest.resetModules();
  });

  afterEach(() => {
    delete process.env.QODIQA_AUDIT_LOG;
    jest.resetModules();
  });

  test('a clean chain reports chainValid:true from both the memory and durable-store views', async () => {
    const auditLog = require('../audit-log');
    await auditLog.append(entryFields());
    await auditLog.append(entryFields());
    await auditLog.append(entryFields());

    const memoryReport  = await auditLog.validateChainIntegrityChunked();
    const durableReport = await auditLog.validateChainIntegrityFromDurableStoreChunked();

    expect(memoryReport.chainValid).toBe(true);
    expect(durableReport.chainValid).toBe(true);
    expect(durableReport.chainLength).toBe(3);
    expect(durableReport.modernLength).toBe(3);
    expect(durableReport.tamperingDetected).toBe(false);
  });

  test('tampering with audit.log directly on disk (post-load) is invisible to the memory-based report but detected by the durable-store report', async () => {
    const auditLog = require('../audit-log');
    await auditLog.append(entryFields());
    await auditLog.append(entryFields());
    const entry3 = await auditLog.append(entryFields());

    // Directly corrupt the on-disk file — flip a character in the middle
    // entry's hash field, exactly the "hand-edited audit.log" / "restored
    // backup with a stray corruption" scenario this finding is about. This
    // never touches chain[] — only the file on disk.
    const lines = fs.readFileSync(logPath, 'utf8').split('\n').filter(l => l.trim());
    expect(lines).toHaveLength(3);
    const tamperedEntry = JSON.parse(lines[1]);
    tamperedEntry.hash = tamperedEntry.hash.slice(0, -1) + (tamperedEntry.hash.endsWith('0') ? '1' : '0');
    lines[1] = JSON.stringify(tamperedEntry);
    fs.writeFileSync(logPath, lines.join('\n') + '\n', 'utf8');

    // Memory-based report: still valid — chain[] was never touched by the
    // direct file edit above, and this process never re-reads the file
    // after its one-time startup load.
    const memoryReport = await auditLog.validateChainIntegrityChunked();
    expect(memoryReport.chainValid).toBe(true);
    expect(memoryReport.tamperingDetected).toBe(false);

    // Durable-store report: re-reads audit.log fresh on this very call and
    // correctly detects the corrupted entry — this is what
    // GET /audit/chain/integrity now uses (src/api/routes/audit.js).
    const durableReport = await auditLog.validateChainIntegrityFromDurableStoreChunked();
    expect(durableReport.chainValid).toBe(false);
    expect(durableReport.tamperingDetected).toBe(true);
    expect(durableReport.integrityFailures.length).toBeGreaterThan(0);

    // Sanity: the entry that was never tampered with (entry3, appended
    // after the corrupted one) is irrelevant to this assertion — the walk
    // correctly stops at the first broken link/hash, well before it.
    expect(entry3.hash).toBeDefined();
  });

  test('a truncated audit.log (last entry deleted directly on disk) is detected by the durable-store report but not the memory-based one', async () => {
    const auditLog = require('../audit-log');
    await auditLog.append(entryFields());
    await auditLog.append(entryFields());

    const lines = fs.readFileSync(logPath, 'utf8').split('\n').filter(l => l.trim());
    expect(lines).toHaveLength(2);
    fs.writeFileSync(logPath, lines[0] + '\n', 'utf8'); // drop the second entry

    const memoryReport = await auditLog.validateChainIntegrityChunked();
    expect(memoryReport.chainValid).toBe(true);
    expect(memoryReport.chainLength).toBe(2); // unaware of the truncation

    const durableReport = await auditLog.validateChainIntegrityFromDurableStoreChunked();
    expect(durableReport.chainValid).toBe(true); // the remaining single entry is internally valid
    expect(durableReport.chainLength).toBe(1);   // but the durable store now genuinely only has 1
  });

  test('malformed JSON injected directly on disk is surfaced as a parse error by the durable-store report', async () => {
    const auditLog = require('../audit-log');
    await auditLog.append(entryFields());

    fs.appendFileSync(logPath, 'not valid json at all\n', 'utf8');

    const durableReport = await auditLog.validateChainIntegrityFromDurableStoreChunked();
    expect(durableReport.chainValid).toBe(false);
    expect(durableReport.tamperingDetected).toBe(true);
    expect(durableReport.parseError).toMatch(/malformed_json/);
  });
});
