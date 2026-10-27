'use strict';

/**
 * Persistence Recovery Journal — FAILOVER-1 remediation
 *
 * journal.js is the filesystem-backed, last-resort durable store
 * recoveryManager.enqueue() falls back to when the PostgreSQL-backed
 * recovery queue's own INSERT fails. These tests exercise it directly
 * against a real (temporary) directory on disk — no mocking of fs — since
 * the entire point of this module is genuine crash/corruption safety.
 *
 * J-01  appendEntry writes a durable, readable entry
 * J-02  appendEntry with the same operationId twice overwrites deterministically (idempotent)
 * J-03  removeEntry deletes the file; it no longer appears in listEntries
 * J-04  removeEntry on a non-existent journalId does not throw (idempotent cleanup)
 * J-05  listEntries returns entries oldest-first
 * J-06  malformed JSON entry is quarantined (.corrupt) and excluded, without throwing
 * J-07  checksum-tampered entry is quarantined and excluded
 * J-08  getStats reflects depth / oldestEntryAgeMs / totalBytes correctly
 * J-09  appendEntry throws on missing operationId/operationType
 * J-10  listEntries on a not-yet-created directory returns [] without throwing
 * J-11  appendEntry survives operationId values containing characters unsafe for filenames
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

let journal;
let TEST_DIR;

function freshTestDir() {
  return path.join(os.tmpdir(), `qodiqa-prq-journal-test-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`);
}

beforeEach(() => {
  TEST_DIR = freshTestDir();
  process.env.QODIQA_PRQ_JOURNAL_DIR = TEST_DIR;
  jest.resetModules();
  journal = require('../journal');
});

afterEach(() => {
  delete process.env.QODIQA_PRQ_JOURNAL_DIR;
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
});

function makeOperation(overrides = {}) {
  return {
    operationId:   'att:11111111-1111-1111-1111-111111111111',
    operationType: 'ATTESTATION_SAVE',
    service:       'attestation',
    payload:       { attestationId: '11111111-1111-1111-1111-111111111111', attestationDecision: 'ATTESTED' },
    ...overrides,
  };
}

describe('journal.appendEntry / listEntries', () => {
  test('J-01: appendEntry writes a durable, readable entry', async () => {
    const op = makeOperation();
    const { journalId } = await journal.appendEntry(op);
    expect(typeof journalId).toBe('string');

    const entries = await journal.listEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0].journalId).toBe(journalId);
    expect(entries[0].operation.operationId).toBe(op.operationId);
    expect(entries[0].operation.operationType).toBe(op.operationType);
    expect(entries[0].operation.payload).toEqual(op.payload);

    // Actually on disk, not just in-memory.
    const files = fs.readdirSync(TEST_DIR);
    expect(files).toEqual([`${journalId}.json`]);
  });

  test('J-02: re-journaling the same operationId overwrites deterministically', async () => {
    const op = makeOperation();
    const first  = await journal.appendEntry(op);
    const second = await journal.appendEntry({ ...op, lastError: 'still failing', retryCount: 2 });

    expect(second.journalId).toBe(first.journalId);

    const entries = await journal.listEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0].operation.lastError).toBe('still failing');
    expect(entries[0].operation.retryCount).toBe(2);
  });

  test('J-05: listEntries returns entries oldest-first', async () => {
    await journal.appendEntry(makeOperation({ operationId: 'att:first' }));
    await new Promise(r => setTimeout(r, 5));
    await journal.appendEntry(makeOperation({ operationId: 'att:second' }));
    await new Promise(r => setTimeout(r, 5));
    await journal.appendEntry(makeOperation({ operationId: 'att:third' }));

    const entries = await journal.listEntries();
    expect(entries.map(e => e.operation.operationId)).toEqual([
      'att:first', 'att:second', 'att:third',
    ]);
  });

  test('J-09: appendEntry throws on missing operationId', async () => {
    await expect(journal.appendEntry(makeOperation({ operationId: undefined })))
      .rejects.toThrow(/operationId is required/);
  });

  test('J-09b: appendEntry throws on missing operationType', async () => {
    await expect(journal.appendEntry(makeOperation({ operationType: undefined })))
      .rejects.toThrow(/operationType is required/);
  });

  test('J-10: listEntries on a not-yet-created directory returns [] without throwing', async () => {
    // Point at a directory that has never been created and never touched by
    // _ensureDir() in this test (simulates a fresh install before any
    // failure has ever occurred).
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
    const entries = await journal.listEntries();
    expect(entries).toEqual([]);
  });

  test('J-11: operationId with colons and slashes is journaled and retrieved safely', async () => {
    const op = makeOperation({
      operationId:   'whd:endpoint-abc/123:event-def:456',
      operationType: 'WEBHOOK_DELIVERY',
      service:       'webhooks',
      payload:       { endpointId: 'endpoint-abc/123', eventId: 'event-def:456' },
    });
    await journal.appendEntry(op);
    const entries = await journal.listEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0].operation.operationId).toBe(op.operationId);
    // Filename itself must not contain the raw unsafe characters.
    const files = fs.readdirSync(TEST_DIR);
    expect(files[0]).toMatch(/^[0-9a-f]{64}\.json$/);
  });
});

describe('journal.removeEntry', () => {
  test('J-03: removeEntry deletes the file; it no longer appears in listEntries', async () => {
    const op = makeOperation();
    const { journalId } = await journal.appendEntry(op);
    expect(await journal.listEntries()).toHaveLength(1);

    await journal.removeEntry(journalId);
    expect(await journal.listEntries()).toHaveLength(0);
    expect(fs.existsSync(path.join(TEST_DIR, `${journalId}.json`))).toBe(false);
  });

  test('J-04: removeEntry on a non-existent journalId does not throw', async () => {
    await expect(journal.removeEntry('0'.repeat(64))).resolves.toBeUndefined();
  });
});

describe('journal corruption handling', () => {
  test('J-06: malformed JSON entry is quarantined and excluded, without throwing', async () => {
    await journal.appendEntry(makeOperation({ operationId: 'att:good' }));

    // Hand-corrupt a second entry directly on disk.
    const corruptPath = path.join(TEST_DIR, `${'f'.repeat(64)}.json`);
    fs.writeFileSync(corruptPath, '{ this is not valid json', 'utf8');

    const entries = await journal.listEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0].operation.operationId).toBe('att:good');

    // The corrupt file was quarantined, not deleted or left as-is.
    expect(fs.existsSync(corruptPath)).toBe(false);
    expect(fs.existsSync(`${corruptPath}.corrupt`)).toBe(true);
  });

  test('J-07: checksum-tampered entry is quarantined and excluded', async () => {
    const { journalId } = await journal.appendEntry(makeOperation({ operationId: 'att:tampered' }));
    const filePath = path.join(TEST_DIR, `${journalId}.json`);

    const record = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    record.payload.attestationDecision = 'TAMPERED'; // mutate without recomputing checksum
    fs.writeFileSync(filePath, JSON.stringify(record), 'utf8');

    const entries = await journal.listEntries();
    expect(entries).toHaveLength(0);
    expect(fs.existsSync(filePath)).toBe(false);
    expect(fs.existsSync(`${filePath}.corrupt`)).toBe(true);
  });
});

describe('journal.getStats', () => {
  test('J-08a: empty journal reports zeroed stats', async () => {
    const stats = await journal.getStats();
    expect(stats).toEqual({ depth: 0, oldestEntryAgeMs: 0, totalBytes: 0 });
  });

  test('J-08b: non-empty journal reports depth, age, and byte size', async () => {
    await journal.appendEntry(makeOperation({ operationId: 'att:one' }));
    await new Promise(r => setTimeout(r, 20));
    await journal.appendEntry(makeOperation({ operationId: 'att:two' }));

    const stats = await journal.getStats();
    expect(stats.depth).toBe(2);
    expect(stats.oldestEntryAgeMs).toBeGreaterThanOrEqual(0);
    expect(stats.totalBytes).toBeGreaterThan(0);
  });
});
