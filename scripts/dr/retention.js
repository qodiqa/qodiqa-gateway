'use strict';

/**
 * QODIQA Disaster Recovery — Tiered Backup Retention.
 *
 * Applies a standard grandfather-father-son (daily/weekly/monthly) rotation
 * scheme to the timestamped backup directories produced by backup.js
 * (`<rootDir>/qodiqa-backup-<createdAt>/manifest.json`). Nothing here is
 * PostgreSQL-specific — scripts/pg-backup.sh implements the equivalent
 * count-based tiering for its own `*.dump` files directly in bash (see its
 * `enforce_tier_retention()`), so the two backup mechanisms stay consistent
 * without sharing code across the bash/Node boundary.
 *
 * Retention counts are NEVER hardcoded into the decision logic itself — every
 * call site (CLI, CronJob, systemd timer) supplies them via opts/env, with a
 * conservative default only used when nothing is configured at all.
 *
 * Algorithm (classic GFS rotation, deterministic given a fixed `now`):
 *   1. Sort all backups newest-first by their manifest's createdAt.
 *   2. DAILY tier   = the `dailyCount` most recent backups, unconditionally.
 *   3. WEEKLY tier  = walking the remaining (older) backups oldest-included
 *      first is unnecessary — for each ISO week not already represented by a
 *      kept backup, keep the newest backup that falls in that week, up to
 *      `weeklyCount` distinct weeks.
 *   4. MONTHLY tier = same idea over remaining backups, grouped by
 *      UTC calendar month, up to `monthlyCount` distinct months.
 *   5. Everything not kept by any tier is eligible for removal.
 *
 * A backup already kept by an earlier (more granular) tier is never also
 * "spent" against a coarser tier's budget — each tier only considers backups
 * not already retained.
 */

const fs   = require('fs');
const path = require('path');

const DEFAULT_DAILY_COUNT   = 7;
const DEFAULT_WEEKLY_COUNT  = 4;
const DEFAULT_MONTHLY_COUNT = 12;

function _envInt(name, def) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const v = parseInt(raw, 10);
  return Number.isFinite(v) && v >= 0 ? v : def;
}

function resolveRetentionConfig(opts = {}) {
  return {
    dailyCount:   opts.dailyCount   ?? _envInt('QODIQA_DR_RETAIN_DAILY',   DEFAULT_DAILY_COUNT),
    weeklyCount:  opts.weeklyCount  ?? _envInt('QODIQA_DR_RETAIN_WEEKLY',  DEFAULT_WEEKLY_COUNT),
    monthlyCount: opts.monthlyCount ?? _envInt('QODIQA_DR_RETAIN_MONTHLY', DEFAULT_MONTHLY_COUNT),
  };
}

// ISO-8601 week identifier (UTC), e.g. "2026-W29".
function _isoWeekKey(date) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const dayNum = (d.getUTCDay() + 6) % 7; // Monday = 0
  d.setUTCDate(d.getUTCDate() - dayNum + 3); // nearest Thursday
  const firstThursday = new Date(Date.UTC(d.getUTCFullYear(), 0, 4));
  const week = 1 + Math.round(((d - firstThursday) / 86400000 - 3 + ((firstThursday.getUTCDay() + 6) % 7)) / 7);
  return `${d.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
}

function _monthKey(date) {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
}

/**
 * Pure classification function — no filesystem access.
 *
 * @param {Array<{ id: string, createdAt: string|Date }>} entries
 * @param {{ dailyCount?: number, weeklyCount?: number, monthlyCount?: number }} [opts]
 * @returns {{ keep: object[], remove: object[] }} entries annotated with `tier`
 *   ('daily'|'weekly'|'monthly') when kept, or `tier: null` when eligible for removal.
 */
function classifyBackups(entries, opts = {}) {
  const { dailyCount, weeklyCount, monthlyCount } = resolveRetentionConfig(opts);

  const normalized = entries
    .map(e => ({ ...e, _date: e.createdAt instanceof Date ? e.createdAt : new Date(e.createdAt) }))
    .filter(e => !Number.isNaN(e._date.getTime()))
    .sort((a, b) => b._date - a._date); // newest first

  const kept = new Set();
  const result = [];

  const daily = normalized.slice(0, dailyCount);
  for (const e of daily) kept.add(e.id);

  const remainingAfterDaily = normalized.slice(dailyCount);
  const seenWeeks = new Set();
  const weekly = [];
  for (const e of remainingAfterDaily) {
    if (weekly.length >= weeklyCount) break;
    const wk = _isoWeekKey(e._date);
    if (seenWeeks.has(wk)) continue;
    seenWeeks.add(wk);
    weekly.push(e);
    kept.add(e.id);
  }

  const remainingAfterWeekly = remainingAfterDaily.filter(e => !kept.has(e.id));
  const seenMonths = new Set();
  const monthly = [];
  for (const e of remainingAfterWeekly) {
    if (monthly.length >= monthlyCount) break;
    const mk = _monthKey(e._date);
    if (seenMonths.has(mk)) continue;
    seenMonths.add(mk);
    monthly.push(e);
    kept.add(e.id);
  }

  for (const e of normalized) {
    const { _date, ...rest } = e;
    if (daily.includes(e))      result.push({ ...rest, tier: 'daily' });
    else if (weekly.includes(e)) result.push({ ...rest, tier: 'weekly' });
    else if (monthly.includes(e)) result.push({ ...rest, tier: 'monthly' });
    else                          result.push({ ...rest, tier: null });
  }

  return {
    keep:   result.filter(e => e.tier !== null),
    remove: result.filter(e => e.tier === null),
  };
}

/**
 * Discover backup.js-produced directories under `rootDir` (each containing a
 * manifest.json with a createdAt field) and return retention entries.
 * A directory whose manifest.json is missing/unreadable falls back to its
 * mtime rather than being silently skipped — an unreadable manifest is not a
 * license to leak disk space forever.
 */
function discoverBackups(rootDir) {
  if (!fs.existsSync(rootDir)) return [];
  return fs.readdirSync(rootDir, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => {
      const dirPath = path.join(rootDir, d.name);
      const manifestPath = path.join(dirPath, 'manifest.json');
      let createdAt;
      try {
        createdAt = JSON.parse(fs.readFileSync(manifestPath, 'utf8')).createdAt;
      } catch {
        createdAt = fs.statSync(dirPath).mtime.toISOString();
      }
      return { id: d.name, path: dirPath, createdAt };
    });
}

/**
 * Enforce tiered retention against a real directory of backups.
 * Never touches anything outside `rootDir`'s immediate children. Deletion
 * failures for one backup do not prevent attempting the rest (best-effort,
 * but every failure is reported — never silently swallowed).
 *
 * @param {string} rootDir
 * @param {{ dailyCount?: number, weeklyCount?: number, monthlyCount?: number, dryRun?: boolean }} [opts]
 * @returns {{ kept: object[], removed: object[], failures: object[] }}
 */
function enforceRetention(rootDir, opts = {}) {
  const entries = discoverBackups(rootDir);
  const { keep, remove } = classifyBackups(entries, opts);

  const failures = [];
  const removed = [];

  if (!opts.dryRun) {
    for (const e of remove) {
      try {
        fs.rmSync(e.path, { recursive: true, force: true });
        removed.push(e);
      } catch (err) {
        failures.push({ id: e.id, path: e.path, error: err.message });
      }
    }
  }

  return { kept: keep, removed: opts.dryRun ? [] : removed, planned: remove, failures };
}

module.exports = { classifyBackups, discoverBackups, enforceRetention, resolveRetentionConfig };

if (require.main === module) {
  const args = process.argv.slice(2);
  const rootDir = args.find(a => !a.startsWith('--'));
  const dryRun  = args.includes('--dry-run');
  const getFlag = (name) => {
    const arg = args.find(a => a.startsWith(`--${name}=`));
    return arg ? parseInt(arg.split('=')[1], 10) : undefined;
  };

  if (!rootDir) {
    console.error('Usage: node retention.js <backupsRootDir> [--daily=N] [--weekly=N] [--monthly=N] [--dry-run]');
    process.exit(2);
  }

  const result = enforceRetention(rootDir, {
    dailyCount:   getFlag('daily'),
    weeklyCount:  getFlag('weekly'),
    monthlyCount: getFlag('monthly'),
    dryRun,
  });

  console.log(JSON.stringify({
    event: dryRun ? 'RETENTION_DRY_RUN' : 'RETENTION_ENFORCED',
    rootDir,
    keptCount:    result.kept.length,
    removedCount: result.removed.length,
    plannedRemovalCount: result.planned.length,
    failureCount: result.failures.length,
    failures: result.failures,
  }, null, 2));

  process.exitCode = result.failures.length > 0 ? 1 : 0;
}
