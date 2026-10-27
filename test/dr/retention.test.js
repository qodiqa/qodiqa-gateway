'use strict';

/**
 * Tiered (daily/weekly/monthly) backup retention — remediation.
 *
 * Covers both the pure classification logic (classifyBackups) and the real
 * filesystem enforcement (enforceRetention) against actual backup.js-shaped
 * directories, so this is not just a logic test but a proof that retention
 * genuinely deletes what it says it will and nothing else.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { classifyBackups, discoverBackups, enforceRetention, resolveRetentionConfig } = require('../../scripts/dr/retention');

function daysAgo(n) {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000);
}

describe('classifyBackups (pure logic)', () => {
  test('keeps the most recent N as daily with no weekly/monthly beyond them', () => {
    const entries = Array.from({ length: 5 }, (_, i) => ({ id: `b${i}`, createdAt: daysAgo(i) }));
    const { keep, remove } = classifyBackups(entries, { dailyCount: 7, weeklyCount: 4, monthlyCount: 12 });
    expect(keep).toHaveLength(5);
    expect(remove).toHaveLength(0);
    expect(keep.every(e => e.tier === 'daily')).toBe(true);
  });

  test('excess recent backups beyond dailyCount are removed unless they anchor a distinct week/month', () => {
    // 10 backups, one per day, daily=3 — days 3..9 fall outside the daily
    // window; each distinct ISO week among them should be picked up by the
    // weekly tier (up to weeklyCount), the rest removed.
    const entries = Array.from({ length: 10 }, (_, i) => ({ id: `b${i}`, createdAt: daysAgo(i) }));
    const { keep, remove } = classifyBackups(entries, { dailyCount: 3, weeklyCount: 2, monthlyCount: 0 });

    const dailyKept  = keep.filter(e => e.tier === 'daily');
    const weeklyKept = keep.filter(e => e.tier === 'weekly');
    expect(dailyKept).toHaveLength(3);
    expect(weeklyKept.length).toBeLessThanOrEqual(2);
    expect(keep.length + remove.length).toBe(10);
    // No id appears in both keep and remove.
    const keptIds = new Set(keep.map(e => e.id));
    expect(remove.every(e => !keptIds.has(e.id))).toBe(true);
  });

  test('monthly tier picks the newest backup per distinct calendar month beyond daily+weekly', () => {
    const entries = [
      { id: 'recent',    createdAt: daysAgo(1) },
      { id: 'month-2ago-new', createdAt: new Date(Date.UTC(2026, 3, 20)) },
      { id: 'month-2ago-old', createdAt: new Date(Date.UTC(2026, 3, 5)) },
      { id: 'month-3ago',     createdAt: new Date(Date.UTC(2026, 2, 10)) },
    ];
    const { keep, remove } = classifyBackups(entries, { dailyCount: 1, weeklyCount: 0, monthlyCount: 2 });
    const keptIds = keep.map(e => e.id).sort();
    expect(keptIds).toEqual(['month-2ago-new', 'month-3ago', 'recent'].sort());
    expect(remove.map(e => e.id)).toEqual(['month-2ago-old']);
  });

  test('fewer backups than every tier budget keeps all of them, removes none', () => {
    const entries = [{ id: 'only-one', createdAt: new Date() }];
    const { keep, remove } = classifyBackups(entries, { dailyCount: 7, weeklyCount: 4, monthlyCount: 12 });
    expect(keep).toHaveLength(1);
    expect(remove).toHaveLength(0);
  });

  test('empty input produces empty output without throwing', () => {
    const { keep, remove } = classifyBackups([], { dailyCount: 7, weeklyCount: 4, monthlyCount: 12 });
    expect(keep).toEqual([]);
    expect(remove).toEqual([]);
  });

  test('entries with unparseable createdAt are dropped rather than crashing', () => {
    const entries = [
      { id: 'good', createdAt: new Date().toISOString() },
      { id: 'bad',  createdAt: 'not-a-date' },
    ];
    const { keep, remove } = classifyBackups(entries, { dailyCount: 7, weeklyCount: 4, monthlyCount: 12 });
    expect(keep.map(e => e.id)).toEqual(['good']);
    expect(remove).toHaveLength(0);
  });
});

describe('resolveRetentionConfig', () => {
  const ORIGINAL_ENV = { ...process.env };
  afterEach(() => { process.env = { ...ORIGINAL_ENV }; });

  test('falls back to documented defaults when nothing is configured', () => {
    delete process.env.QODIQA_DR_RETAIN_DAILY;
    delete process.env.QODIQA_DR_RETAIN_WEEKLY;
    delete process.env.QODIQA_DR_RETAIN_MONTHLY;
    expect(resolveRetentionConfig()).toEqual({ dailyCount: 7, weeklyCount: 4, monthlyCount: 12 });
  });

  test('env vars override defaults; explicit opts override env vars', () => {
    process.env.QODIQA_DR_RETAIN_DAILY = '3';
    expect(resolveRetentionConfig().dailyCount).toBe(3);
    expect(resolveRetentionConfig({ dailyCount: 99 }).dailyCount).toBe(99);
  });

  test('invalid env var values fall back to the default rather than NaN', () => {
    process.env.QODIQA_DR_RETAIN_WEEKLY = 'not-a-number';
    expect(resolveRetentionConfig().weeklyCount).toBe(4);
  });
});

describe('enforceRetention (real filesystem)', () => {
  let root;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-retention-test-'));
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  function makeBackupDir(name, createdAt) {
    const dir = path.join(root, name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({ createdAt: createdAt.toISOString() }));
    fs.writeFileSync(path.join(dir, 'auditLog.dat'), 'fake-backup-content');
    return dir;
  }

  test('discoverBackups reads createdAt from each manifest.json', () => {
    makeBackupDir('qodiqa-backup-a', daysAgo(0));
    makeBackupDir('qodiqa-backup-b', daysAgo(1));
    const found = discoverBackups(root);
    expect(found).toHaveLength(2);
    expect(found.every(e => typeof e.createdAt === 'string')).toBe(true);
  });

  test('discoverBackups falls back to directory mtime when manifest.json is missing', () => {
    const dir = path.join(root, 'qodiqa-backup-nomani');
    fs.mkdirSync(dir, { recursive: true });
    const found = discoverBackups(root);
    expect(found).toHaveLength(1);
    expect(new Date(found[0].createdAt).getTime()).not.toBeNaN();
  });

  test('discoverBackups on a nonexistent root returns an empty list, not an error', () => {
    expect(discoverBackups(path.join(root, 'does-not-exist'))).toEqual([]);
  });

  test('actually deletes only the backups classified as remove, and nothing else on disk', () => {
    for (let i = 0; i < 6; i++) makeBackupDir(`qodiqa-backup-${i}`, daysAgo(i));

    const result = enforceRetention(root, { dailyCount: 2, weeklyCount: 1, monthlyCount: 0 });

    expect(result.failures).toEqual([]);
    const remainingDirs = fs.readdirSync(root);
    expect(remainingDirs).toHaveLength(result.kept.length);
    for (const kept of result.kept) {
      expect(fs.existsSync(kept.path)).toBe(true);
    }
    for (const removed of result.removed) {
      expect(fs.existsSync(removed.path)).toBe(false);
    }
  });

  test('dry-run mode reports planned removals but deletes nothing', () => {
    for (let i = 0; i < 5; i++) makeBackupDir(`qodiqa-backup-${i}`, daysAgo(i));

    const result = enforceRetention(root, { dailyCount: 1, weeklyCount: 0, monthlyCount: 0, dryRun: true });

    expect(result.removed).toEqual([]);
    expect(result.planned.length).toBeGreaterThan(0);
    expect(fs.readdirSync(root)).toHaveLength(5);
  });

  test('zero-count tiers remove everything beyond what an earlier tier already kept', () => {
    for (let i = 0; i < 3; i++) makeBackupDir(`qodiqa-backup-${i}`, daysAgo(i));
    const result = enforceRetention(root, { dailyCount: 0, weeklyCount: 0, monthlyCount: 0 });
    expect(fs.readdirSync(root)).toHaveLength(0);
    expect(result.kept).toHaveLength(0);
  });
});
