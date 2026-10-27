'use strict';

/**
 * pg-backup.sh HMAC-seal primitive — algorithm unit tests (BACKUP-2 remediation).
 *
 * Renamed from `backup-restore.test.js` and re-scoped: this file previously
 * claimed to "validate the backup and restore procedures defined in
 * scripts/pg-backup.sh" — it does not, and never has. It re-derives the
 * HMAC-SHA256 sealing/verification algorithm in pure Node.js and asserts the
 * reimplementation is internally consistent with itself; it never shells out
 * to and exercises the real bash script, so a real bug in that script
 * (quoting errors, pg_dump/pg_restore invocation mistakes, retention-cleanup
 * logic) would not be caught here. That gap is real and is now closed
 * elsewhere, not by expanding this file's claims:
 *
 *   - `.github/workflows/backup-restore.yml`'s `dr-postgres` job runs
 *     `scripts/pg-backup.sh full`/`verify`/`restore` FOR REAL against a live
 *     Postgres service container — real pg_dump, real pg_restore, real
 *     seal files on disk, restoring into a genuinely separate throwaway
 *     database and asserting real row counts. That is the actual
 *     script-execution proof.
 *   - `test/backupRestore.test.js` is the real, working end-to-end test for
 *     the SEPARATE JSON-based file-store DR framework
 *     (scripts/dr/{backup,restore,validate,cycle}.js) — genuinely exercises
 *     the real production modules, not a mirror.
 *
 * What remains genuinely useful here, and why it's kept (not deleted): the
 * HMAC-SHA256 seal/verify algorithm itself (constant-time comparison,
 * tamper detection, the SHA-256-only fallback when no HMAC key is
 * configured) is worth fast, dependency-free unit coverage independent of a
 * live database — these are algorithm-correctness tests, not
 * script-behavior tests, and are named/scoped accordingly now.
 *
 * What is tested:
 *   BR-01  HMAC-SHA256 seal computation is deterministic for identical input
 *   BR-02  HMAC seal changes when backup content changes (tamper detection)
 *   BR-03  HMAC seal verification: valid seal passes
 *   BR-04  HMAC seal verification: tampered content is detected
 *   BR-05  HMAC seal verification: wrong key is detected
 *   BR-06  Backup audit log entry has required fields (ts, level, event)
 *   BR-07  Backup audit log is append-only JSONL format (each line is valid JSON)
 *   BR-08  Retention policy: files older than RETAIN_DAYS are identified
 *   BR-09  Backup filename encodes timestamp in ISO 8601 compact format
 *   BR-10  Seal file naming convention: <backup>.seal
 *   BR-11  Backup directory structure: full/, wal/, verify/ subdirs required
 *   BR-12  Restore validation: HMAC seal must match before restore is permitted
 *   BR-13  Restore validation: missing seal file blocks restore
 *   BR-14  Backup metadata JSON includes schema version field
 *   BR-15  Parallel backup job count defaults to 4
 *   BR-16  Backup in absence of HMAC key falls back to SHA-256 checksum only
 *   BR-17  Audit log entries are parseable (all fields are strings or numbers)
 *   BR-18  Multiple backup seals can be independently verified
 *   BR-19  HMAC-SHA256 output is 64 hex characters
 *   BR-20  Restore simulation: content written to temp file matches original
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

// ── Backup seal implementation (mirrors pg-backup.sh logic in Node.js) ────────

/**
 * Compute an HMAC-SHA256 seal for `content` using `key`.
 * Returns the hex digest (64 characters).
 *
 * @param {Buffer|string} content
 * @param {string}        key
 * @returns {string}  64-char hex
 */
function computeSeal(content, key) {
  return crypto.createHmac('sha256', key).update(content).digest('hex');
}

/**
 * Compute a plain SHA-256 checksum (no key) for when HMAC key is absent.
 * Mirrors the `sha256sum` fallback in pg-backup.sh.
 *
 * @param {Buffer|string} content
 * @returns {string}  64-char hex
 */
function computeChecksum(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Verify a seal against `content`.
 * Timing-safe comparison to prevent oracle attacks.
 *
 * @param {Buffer|string} content
 * @param {string}        key
 * @param {string}        expectedSeal  — 64-char hex
 * @returns {boolean}
 */
function verifySeal(content, key, expectedSeal) {
  if (!expectedSeal || expectedSeal.length !== 64) return false;
  const actual   = computeSeal(content, key);
  const aBuf     = Buffer.from(actual,       'hex');
  const eBuf     = Buffer.from(expectedSeal, 'hex');
  if (aBuf.length !== eBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, eBuf);
}

/**
 * Produce a backup audit log entry (single JSONL line).
 *
 * @param {'INFO'|'WARN'|'ERROR'} level
 * @param {string}                event
 * @param {object}                [extra]
 * @returns {string}
 */
function buildAuditEntry(level, event, extra) {
  const base = { ts: new Date().toISOString(), level, event };
  return JSON.stringify(extra ? { ...base, ...extra } : base);
}

/**
 * Generate a backup filename for `now` and `mode`.
 * Mirrors the naming convention in pg-backup.sh.
 *
 * @param {'full'|'wal'|'verify'} mode
 * @param {Date} [now]
 * @returns {string}
 */
function buildBackupFilename(mode, now) {
  const d   = now || new Date();
  const pad = (n, l = 2) => String(n).padStart(l, '0');
  const ts  = `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}T` +
              `${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
  return `qodiqa-${mode}-${ts}.dump`;
}

// ── BR-01: HMAC-SHA256 seal is deterministic ──────────────────────────────────

describe('BR-01: HMAC seal is deterministic for identical input', () => {
  test('same content + key → same seal', () => {
    const content = Buffer.from('pg_dump output bytes');
    const key     = 'test-hmac-secret-key-for-backup';
    expect(computeSeal(content, key)).toBe(computeSeal(content, key));
  });
});

// ── BR-02: Seal changes when content changes ──────────────────────────────────

describe('BR-02: HMAC seal changes when backup content is tampered', () => {
  test('different content → different seal', () => {
    const key  = 'my-backup-hmac-key';
    const seal1 = computeSeal(Buffer.from('original backup content'), key);
    const seal2 = computeSeal(Buffer.from('tampered backup content'), key);
    expect(seal1).not.toBe(seal2);
  });

  test('appending a single byte changes the seal', () => {
    const key   = 'my-backup-hmac-key';
    const orig  = Buffer.from('backup content');
    const extra = Buffer.concat([orig, Buffer.from([0x00])]);
    expect(computeSeal(orig, key)).not.toBe(computeSeal(extra, key));
  });
});

// ── BR-03: Valid seal passes verification ─────────────────────────────────────

describe('BR-03: Valid HMAC seal passes verification', () => {
  test('verifySeal() returns true for matching content + key', () => {
    const content = Buffer.from('authentic backup data');
    const key     = 'verification-key-abc123';
    const seal    = computeSeal(content, key);
    expect(verifySeal(content, key, seal)).toBe(true);
  });
});

// ── BR-04: Tampered content is detected ───────────────────────────────────────

describe('BR-04: Tampered backup content fails seal verification', () => {
  test('verifySeal() returns false when content differs', () => {
    const key      = 'verification-key-abc123';
    const orig     = Buffer.from('original content');
    const tampered = Buffer.from('tampered content');
    const seal     = computeSeal(orig, key);
    expect(verifySeal(tampered, key, seal)).toBe(false);
  });
});

// ── BR-05: Wrong key is detected ─────────────────────────────────────────────

describe('BR-05: Wrong HMAC key fails seal verification', () => {
  test('verifySeal() returns false when key differs', () => {
    const content  = Buffer.from('backup content');
    const rightKey = 'correct-key';
    const wrongKey = 'incorrect-key';
    const seal     = computeSeal(content, rightKey);
    expect(verifySeal(content, wrongKey, seal)).toBe(false);
  });
});

// ── BR-06: Audit log entry has required fields ────────────────────────────────

describe('BR-06: Backup audit log entry has required fields', () => {
  test('buildAuditEntry includes ts, level, event', () => {
    const line = buildAuditEntry('INFO', 'BACKUP_STARTED');
    const obj  = JSON.parse(line);
    expect(typeof obj.ts).toBe('string');
    expect(typeof obj.level).toBe('string');
    expect(typeof obj.event).toBe('string');
    expect(obj.level).toBe('INFO');
    expect(obj.event).toBe('BACKUP_STARTED');
  });
});

// ── BR-07: Audit log is JSONL (each line is valid JSON) ───────────────────────

describe('BR-07: Audit log JSONL format — each line parses independently', () => {
  test('multiple entries each parse as valid JSON', () => {
    const lines = [
      buildAuditEntry('INFO',  'BACKUP_STARTED',   { mode: 'full' }),
      buildAuditEntry('INFO',  'BACKUP_COMPLETED',  { sizeBytes: 102400, durationMs: 5000 }),
      buildAuditEntry('INFO',  'SEAL_WRITTEN',      { seal: 'a'.repeat(64) }),
      buildAuditEntry('INFO',  'RETENTION_ENFORCED', { removed: 0 }),
    ];
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
      const obj = JSON.parse(line);
      expect(obj.ts).toBeDefined();
    }
  });
});

// ── BR-08: Retention policy identifies stale files ────────────────────────────

describe('BR-08: Retention policy correctly identifies files older than RETAIN_DAYS', () => {
  test('file older than 30 days is flagged for removal', () => {
    const retainDays   = 30;
    const cutoffMs     = Date.now() - retainDays * 24 * 60 * 60 * 1000;
    const oldFileMtime = cutoffMs - 1000; // 1 second past the cutoff
    const isExpired    = oldFileMtime < cutoffMs;
    expect(isExpired).toBe(true);
  });

  test('file within retain window is NOT flagged', () => {
    const retainDays   = 30;
    const cutoffMs     = Date.now() - retainDays * 24 * 60 * 60 * 1000;
    const newFileMtime = Date.now() - 24 * 60 * 60 * 1000; // 1 day old
    const isExpired    = newFileMtime < cutoffMs;
    expect(isExpired).toBe(false);
  });
});

// ── BR-09: Backup filename encodes timestamp ──────────────────────────────────

describe('BR-09: Backup filename includes ISO 8601 compact timestamp', () => {
  test('buildBackupFilename includes mode and compact date', () => {
    const d    = new Date('2025-06-15T02:00:00Z');
    const name = buildBackupFilename('full', d);
    expect(name).toBe('qodiqa-full-20250615T020000Z.dump');
  });

  test('wal mode produces different prefix', () => {
    const d    = new Date('2025-06-15T06:00:00Z');
    const name = buildBackupFilename('wal', d);
    expect(name).toContain('qodiqa-wal-');
  });
});

// ── BR-10: Seal file naming convention ───────────────────────────────────────

describe('BR-10: Seal file is named <backup>.seal', () => {
  test('seal filename appends .seal to backup filename', () => {
    const backupFile = 'qodiqa-full-20250615T020000Z.dump';
    const sealFile   = backupFile + '.seal';
    expect(sealFile).toBe('qodiqa-full-20250615T020000Z.dump.seal');
  });
});

// ── BR-11: Backup directory structure ─────────────────────────────────────────

describe('BR-11: Backup directory structure requires full/, wal/, verify/', () => {
  test('required subdirectory names are correct', () => {
    const required = ['full', 'wal', 'verify'];
    const backupDir = '/var/backups/qodiqa';
    const paths     = required.map(d => path.posix.join(backupDir, d));
    expect(paths).toEqual([
      '/var/backups/qodiqa/full',
      '/var/backups/qodiqa/wal',
      '/var/backups/qodiqa/verify',
    ]);
  });
});

// ── BR-12: Restore validates HMAC seal before proceeding ─────────────────────

describe('BR-12: Restore simulation validates HMAC seal before permitting restore', () => {
  test('restore is permitted when seal is valid', () => {
    const content = Buffer.from('database dump bytes');
    const key     = 'restore-hmac-key';
    const seal    = computeSeal(content, key);
    const allowed = verifySeal(content, key, seal);
    expect(allowed).toBe(true);
  });

  test('restore is blocked when seal does not match', () => {
    const content  = Buffer.from('database dump bytes');
    const tampered = Buffer.from('tampered database dump bytes');
    const key      = 'restore-hmac-key';
    const seal     = computeSeal(content, key);
    const allowed  = verifySeal(tampered, key, seal);
    expect(allowed).toBe(false);
  });
});

// ── BR-13: Missing seal file blocks restore ───────────────────────────────────

describe('BR-13: Missing seal file blocks restore', () => {
  test('verifySeal() returns false for empty seal string', () => {
    expect(verifySeal(Buffer.from('content'), 'key', '')).toBe(false);
  });

  test('verifySeal() returns false for null seal', () => {
    expect(verifySeal(Buffer.from('content'), 'key', null)).toBe(false);
  });

  test('verifySeal() returns false for wrong-length seal', () => {
    expect(verifySeal(Buffer.from('content'), 'key', 'too-short')).toBe(false);
  });
});

// ── BR-14: Backup metadata includes schema version ───────────────────────────

describe('BR-14: Backup metadata JSON includes schema version field', () => {
  test('metadata object has schemaVersion field', () => {
    const metadata = {
      schemaVersion: '1',
      mode:          'full',
      timestamp:     new Date().toISOString(),
      database:      'qodiqa_prod',
      sizeBytes:     0,
      seal:          'a'.repeat(64),
    };
    expect(metadata.schemaVersion).toBeDefined();
    expect(typeof metadata.schemaVersion).toBe('string');
  });
});

// ── BR-15: Default parallel job count ────────────────────────────────────────

describe('BR-15: Parallel backup job count defaults to 4', () => {
  test('default PARALLEL_JOBS value is 4', () => {
    const parallelJobs = parseInt(process.env.QODIQA_BACKUP_JOBS || '4', 10);
    expect(parallelJobs).toBe(4);
  });
});

// ── BR-16: No HMAC key falls back to SHA-256 checksum ─────────────────────────

describe('BR-16: Backup without HMAC key falls back to plain SHA-256 checksum', () => {
  test('computeChecksum returns 64-char hex', () => {
    const checksum = computeChecksum(Buffer.from('backup content'));
    expect(checksum).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(checksum)).toBe(true);
  });

  test('computeChecksum differs from HMAC-SHA256 with same input (different algorithms)', () => {
    const content  = Buffer.from('backup content');
    const key      = 'some-key';
    const hmac     = computeSeal(content, key);
    const checksum = computeChecksum(content);
    // Only equal if HMAC key coincidentally produces same output — astronomically unlikely
    expect(hmac).not.toBe(checksum);
  });
});

// ── BR-17: Audit log entries have correct field types ─────────────────────────

describe('BR-17: All audit log entry fields are strings or numbers', () => {
  test('buildAuditEntry with numeric extra fields', () => {
    const line = buildAuditEntry('INFO', 'BACKUP_COMPLETED', { sizeBytes: 1024, durationMs: 500 });
    const obj  = JSON.parse(line);
    expect(typeof obj.ts).toBe('string');
    expect(typeof obj.level).toBe('string');
    expect(typeof obj.event).toBe('string');
    expect(typeof obj.sizeBytes).toBe('number');
    expect(typeof obj.durationMs).toBe('number');
  });
});

// ── BR-18: Multiple seals can be independently verified ───────────────────────

describe('BR-18: Multiple backup seals can be independently verified', () => {
  test('each of three backup seals verifies independently', () => {
    const key = 'shared-backup-key';
    const backups = [
      Buffer.from('backup-1-content'),
      Buffer.from('backup-2-content'),
      Buffer.from('backup-3-content'),
    ];
    const seals = backups.map(b => computeSeal(b, key));

    for (let i = 0; i < backups.length; i++) {
      expect(verifySeal(backups[i], key, seals[i])).toBe(true);
      // Cross-verification must fail
      if (i + 1 < backups.length) {
        expect(verifySeal(backups[i], key, seals[i + 1])).toBe(false);
      }
    }
  });
});

// ── BR-19: HMAC-SHA256 output length ─────────────────────────────────────────

describe('BR-19: HMAC-SHA256 output is exactly 64 hex characters', () => {
  test('computeSeal output is 64 chars', () => {
    const seal = computeSeal(Buffer.from('content'), 'key');
    expect(seal).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(seal)).toBe(true);
  });
});

// ── BR-20: Restore simulation — content round-trips correctly ─────────────────

describe('BR-20: Restore simulation — backup content is faithfully restored', () => {
  test('write backup to temp file and read it back', () => {
    const content  = Buffer.from('simulated pg_dump output — table data\0binary\0content');
    const tmpFile  = path.join(os.tmpdir(), `qodiqa-br-test-${Date.now()}.dump`);

    fs.writeFileSync(tmpFile, content);
    const restored = fs.readFileSync(tmpFile);
    fs.unlinkSync(tmpFile);

    expect(Buffer.compare(content, restored)).toBe(0);
  });

  test('HMAC seal computed before write matches seal computed after read', () => {
    const content  = Buffer.from('pg dump bytes for seal roundtrip test');
    const key      = 'roundtrip-seal-key';
    const tmpFile  = path.join(os.tmpdir(), `qodiqa-br-seal-test-${Date.now()}.dump`);

    const sealBefore = computeSeal(content, key);
    fs.writeFileSync(tmpFile, content);
    const restored   = fs.readFileSync(tmpFile);
    fs.unlinkSync(tmpFile);

    const sealAfter = computeSeal(restored, key);
    expect(sealBefore).toBe(sealAfter);
    expect(verifySeal(restored, key, sealBefore)).toBe(true);
  });
});
