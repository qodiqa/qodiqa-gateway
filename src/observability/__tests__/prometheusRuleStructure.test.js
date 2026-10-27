'use strict';

/**
 * 2026-10-06 —.
 * No promtool offline, so the shipped PrometheusRule files are checked structurally:
 *
 *   PR-01  both rule files parse; every rule has alert, expr, labels.severity (critical|warning|info),
 *          annotations.summary and annotations.runbook_url; alert names are unique across both files
 *   PR-02  every runbook_url resolves to a repository file and, when it has a #fragment, to a heading (GitHub slug)
 *          or an explicit id in that file
 *   PR-03  every equality label matcher on a gateway metric whose label set is seeded (served with labels before any
 *          event) names a label value the gateway actually serves — a typo'd outcome/cause/stage/reason would
 *          otherwise make the rule silently never fire
 * PR-04 the gateway rule covers the alert set the audit asked for (guards against a rule being dropped)
 *   PR-05  expressions are single-line (MR-03 / SD-06 scan `expr:` lines) and parenthesis-balanced
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const metrics = require('../metrics');

const REPO = path.join(__dirname, '..', '..', '..');
const DIR = path.join(REPO, 'deploy', 'kubernetes', 'overlays', 'examples', 'monitoring');
const FILES = ['prometheusrule.yaml', 'backup-prometheusrule.yaml'];

const load = (f) => yaml.load(fs.readFileSync(path.join(DIR, f), 'utf8'));
const rulesOf = (doc) => doc.spec.groups.flatMap((g) => g.rules.map((r) => ({ ...r, group: g.name })));

// GitHub's heading anchor: lower-case, drop everything but letters/digits/space/-/_, spaces → '-'.
const slug = (h) => h.trim().toLowerCase().replace(/[^\p{L}\p{N} _-]/gu, '').replace(/ /g, '-');
function anchorsOf(file) {
  const text = fs.readFileSync(file, 'utf8');
  const out = new Set();
  let inFence = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*```/.test(line)) { inFence = !inFence; continue; }
    if (inFence) continue;
    const m = line.match(/^#{1,6}\s+(.*?)\s*#*\s*$/);
    if (m) out.add(slug(m[1]));
  }
  for (const m of text.matchAll(/\bid="([^"]+)"/g)) out.add(m[1]);
  return out;
}

describe('shipped PrometheusRule structure', () => {
  const all = FILES.flatMap((f) => rulesOf(load(f)).map((r) => ({ ...r, file: f })));

  test('PR-01 every rule is complete and alert names are unique', () => {
    expect(all.length).toBeGreaterThan(40);
    const problems = [];
    for (const r of all) {
      if (typeof r.alert !== 'string' || !/^Qodiqa[A-Za-z0-9]+$/.test(r.alert)) problems.push(`${r.file}: bad alert name ${r.alert}`);
      if (typeof r.expr !== 'string' || !r.expr.trim()) problems.push(`${r.alert}: no expr`);
      if (!r.labels || !['critical', 'warning', 'info'].includes(r.labels.severity)) problems.push(`${r.alert}: severity ${r.labels && r.labels.severity}`);
      if (!r.annotations || typeof r.annotations.summary !== 'string' || !r.annotations.summary.trim()) problems.push(`${r.alert}: no summary`);
      if (!r.annotations || typeof r.annotations.runbook_url !== 'string' || !r.annotations.runbook_url.trim()) problems.push(`${r.alert}: no runbook_url`);
      if (r.for !== undefined && !/^\d+[smhd]$/.test(String(r.for))) problems.push(`${r.alert}: bad for ${r.for}`);
    }
    expect(problems).toEqual([]);
    const names = all.map((r) => r.alert);
    expect(names.filter((n, i) => names.indexOf(n) !== i)).toEqual([]);
  });

  test('PR-02 every runbook_url resolves to an existing file and heading', () => {
    const broken = [];
    for (const r of all) {
      const [rel, frag] = r.annotations.runbook_url.split('#');
      const file = path.join(REPO, rel);
      if (!fs.existsSync(file)) { broken.push(`${r.alert}: missing file ${rel}`); continue; }
      if (frag && !anchorsOf(file).has(frag)) broken.push(`${r.alert}: no heading #${frag} in ${rel}`);
    }
    expect(broken).toEqual([]);
  });

  test('PR-03 equality matchers on seeded gateway metrics name a served label value', () => {
    const text = metrics.collect(0);
    const TARGET_LABELS = new Set(['namespace', 'service', 'job', 'instance', 'pod', 'endpoint', 'le']);
    const gateway = rulesOf(load('prometheusrule.yaml'));
    const bad = [];
    let checked = 0;
    for (const r of gateway) {
      for (const m of r.expr.matchAll(/(qodiqa_[a-z0-9_]+)\{([^}]*)\}/g)) {
        const [, name, body] = m;
        const served = text.split('\n').filter((l) => l.startsWith(`${name}{`));
        if (served.length === 0) continue; // lazily-labelled: no served label set to compare against
        for (const mm of body.matchAll(/([a-zA-Z_]+)\s*=\s*"([^"]*)"/g)) {
          const [, label, value] = mm;
          if (TARGET_LABELS.has(label)) continue;
          checked += 1;
          if (!served.some((l) => l.includes(`${label}="${value}"`))) bad.push(`${r.alert}: ${name}{${label}="${value}"} is never served`);
        }
      }
    }
    expect(checked).toBeGreaterThan(5);
    expect(bad).toEqual([]);
  });

  test('PR-04 the gateway rule carries the alert set', () => {
    const names = new Set(rulesOf(load('prometheusrule.yaml')).map((r) => r.alert));
    const required = [
      'QodiqaTransparencyEnforcementFailures', 'QodiqaProviderFailures', 'QodiqaRedisStoreDown', 'QodiqaExecutionIntegrityDegraded',
      'QodiqaMirrorCrosscheckDivergence', 'QodiqaMirrorCountDrift', 'QodiqaAuditPgSyncLag', 'QodiqaPgCircuitOpen', 'QodiqaPgPoolSaturated',
      'QodiqaChecksumAnchorPgWriteFailing', 'QodiqaQueueBacklog', 'QodiqaPrqPersistFailed', 'QodiqaKeyRotationOverdue',
      'QodiqaSigningProviderUnavailable', 'QodiqaEventLoopUnhealthy', 'QodiqaNonceViolation', 'QodiqaReplaySpike',
      'QodiqaTransparencyGapUnrecoverable', 'QodiqaCheckpointTickFailed', 'QodiqaMfaLockouts', 'QodiqaOpsAuthFailureBurst',
      'QodiqaRbacDenialBurst', 'QodiqaScrapeDown', 'QodiqaMetricsAbsent',
      'QodiqaRedisConnectionDegraded', // phase 11
      'QodiqaPrqJournalWriteFailed', 'QodiqaTransparencyPersistFailures', 'QodiqaPubsubSignatureRejects', // phase 11
    ];
    expect(required.filter((n) => !names.has(n))).toEqual([]);
    const backup = new Set(rulesOf(load('backup-prometheusrule.yaml')).map((r) => r.alert));
    expect(['QodiqaDrBackupFailed', 'QodiqaDrBackupStale', 'QodiqaDrBackupVerifyFailed', 'QodiqaDrRestoreValidationFailed'].filter((n) => !backup.has(n))).toEqual([]);
    // phase 11 (DEPLOY-BACKUP.md §7): verify, WAL-archive and audit-log-backup failures, per-tier staleness
    expect(['QodiqaBackupStale', 'QodiqaBackupVerifyFailed', 'QodiqaBackupVerifyStale', 'QodiqaWalArchiveVerifyFailed', 'QodiqaWalArchiveMetricsStale',
      'QodiqaAuditLogBackupFailed', 'QodiqaAuditLogBackupStale'].filter((n) => !backup.has(n))).toEqual([]);
  });

  test('PR-06 the Redis connection-state alert ignores the unlabelled default 0 and fires below HEALTHY', () => {
    const r = rulesOf(load('prometheusrule.yaml')).find((x) => x.alert === 'QodiqaRedisConnectionDegraded');
    expect(r.expr).toMatch(/qodiqa_redis_connection_state_code\{purpose!=""\}\s*<\s*3/);
    expect(r.for).toBeDefined();
    // the unlabelled default series the guard exists for is really what an unset gauge serves
    const { Gauge } = require('../metrics');
    expect(new Gauge('x_probe', 'h').format()).toMatch(/^x_probe 0$/m);
  });

  test('PR-07 (DEPLOY-BACKUP.md §7) QodiqaBackupStale uses each tier\'s own limit (daily 26 h, weekly 8 d, monthly 32 d)', () => {
    const r = rulesOf(load('backup-prometheusrule.yaml')).find((x) => x.alert === 'QodiqaBackupStale');
    const limits = {};
    for (const m of r.expr.matchAll(/tier="(\w+)"\}\)\s*>\s*(\d+)/g)) limits[m[1]] = Number(m[2]);
    expect(limits).toEqual({ daily: 93600, weekly: 691200, monthly: 2764800 });
    // the same defaults scripts/pg-backup.sh verify enforces
    const sh = fs.readFileSync(path.join(REPO, 'scripts', 'pg-backup.sh'), 'utf8');
    for (const [tier, v] of Object.entries(limits)) expect(sh).toMatch(new RegExp(`${tier}\\)\\s+max_age=${v}\\b`));
    // every backup-side metric a rule reads is one a backup script writes
    const writers = ['pg-backup.sh', 'pg-wal-archive.sh', 'backup-audit-log.sh'].map((f) => fs.readFileSync(path.join(REPO, 'scripts', f), 'utf8')).join('\n');
    const used = rulesOf(load('backup-prometheusrule.yaml')).filter((x) => x.group !== 'qodiqa.dr').flatMap((x) => x.expr.match(/qodiqa_[a-z0-9_]+/g) || []);
    expect([...new Set(used)].filter((n) => !writers.includes(`${n} `) && !writers.includes(`${n}{`))).toEqual([]);
  });

  test('PR-05 expressions are single-line and parenthesis/brace balanced', () => {
    const bad = [];
    for (const r of all) {
      if (/\n/.test(r.expr.trim())) bad.push(`${r.alert}: multi-line expr`);
      let depth = 0;
      for (const ch of r.expr) {
        if (ch === '(' || ch === '{' || ch === '[') depth += 1;
        if (ch === ')' || ch === '}' || ch === ']') depth -= 1;
        if (depth < 0) break;
      }
      if (depth !== 0) bad.push(`${r.alert}: unbalanced`);
    }
    expect(bad).toEqual([]);
  });
});
