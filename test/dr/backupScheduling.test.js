'use strict';

/**
 * Structural checks for the scheduling artifacts — Kubernetes
 * CronJobs/ConfigMap/PVC, systemd timers/services, and the backup Docker
 * image. Deliberately text/regex-based rather than a full YAML parse: this
 * repo has no YAML-parsing dependency (js-yaml etc.) and adding one purely
 * for a test would be exactly the "redundant framework" the remediation
 * brief says not to introduce. These checks exist to catch the class of
 * regression that matters most here — a CronJob silently losing its
 * fail-closed settings, a retention value creeping back in as a literal
 * instead of a configured env var, a new CronJob added without its
 * scheduling counterpart — not full schema validation (kubectl/kustomize
 * already did that during development; see the report).
 */

const fs   = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');

function read(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

describe('Kubernetes backup CronJobs', () => {
  const manifest = read('deploy/kubernetes/base/backup-cronjobs.yaml');
  const EXPECTED_CRONJOBS = [
    'qodiqa-pg-backup-daily',
    'qodiqa-pg-backup-weekly',
    'qodiqa-pg-backup-monthly',
    'qodiqa-pg-backup-incremental',
    'qodiqa-pg-backup-verify',
    'qodiqa-pg-backup-verify-wal',
    'qodiqa-dr-backup',
    'qodiqa-dr-restore-validation',
  ];

  test.each(EXPECTED_CRONJOBS)('%s CronJob is defined', (name) => {
    expect(manifest).toMatch(new RegExp(`name:\\s*${name}\\b`));
  });

  test('every CronJob document has a schedule and a configurable timeZone field', () => {
    const docs = manifest.split(/^---$/m).filter(d => /kind:\s*CronJob/.test(d));
    expect(docs.length).toBe(EXPECTED_CRONJOBS.length);
    for (const doc of docs) {
      expect(doc).toMatch(/schedule:\s*"/);
      expect(doc).toMatch(/timeZone:\s*"/);
    }
  });

  test('every CronJob is fail-closed: Forbid concurrency, OnFailure restart, bounded retries/deadline', () => {
    const docs = manifest.split(/^---$/m).filter(d => /kind:\s*CronJob/.test(d));
    for (const doc of docs) {
      expect(doc).toMatch(/concurrencyPolicy:\s*Forbid/);
      expect(doc).toMatch(/restartPolicy:\s*OnFailure/);
      expect(doc).toMatch(/backoffLimit:\s*\d+/);
      expect(doc).toMatch(/activeDeadlineSeconds:\s*\d+/);
      expect(doc).toMatch(/successfulJobsHistoryLimit:\s*\d+/);
      expect(doc).toMatch(/failedJobsHistoryLimit:\s*\d+/);
    }
  });

  test('every container drops all Linux capabilities and cannot escalate privileges', () => {
    const docs = manifest.split(/^---$/m).filter(d => /kind:\s*CronJob/.test(d));
    for (const doc of docs) {
      expect(doc).toMatch(/capabilities:\s*\{\s*drop:\s*\[ALL\]\s*\}/);
      expect(doc).toMatch(/allowPrivilegeEscalation:\s*false/);
      expect(doc).toMatch(/runAsNonRoot:\s*true/);
    }
  });

  test('retention counts are sourced from config, never hardcoded as literal numbers in commands', () => {
    // The tier NAME (daily/weekly/monthly) is a deliberate per-CronJob
    // selector, not a magic number — only actual retention COUNTS must
    // never appear as bare literals in a command/args block.
    const commandBlocks = manifest.match(/command:[\s\S]*?(?=\n\s{0,10}\S+:|\n---|\Z)/g) || [];
    for (const block of commandBlocks) {
      // Any bare standalone integer (not part of a $(VAR) reference, a
      // schedule string, or a tier name) inside a shell -c block would be a
      // hardcoded retention value regression.
      const suspicious = block.match(/--(daily|weekly|monthly)=\d+/);
      expect(suspicious).toBeNull();
    }
    expect(manifest).toMatch(/QODIQA_DR_RETAIN_DAILY/);
    expect(manifest).toMatch(/QODIQA_DR_RETAIN_WEEKLY/);
    expect(manifest).toMatch(/QODIQA_DR_RETAIN_MONTHLY/);
  });

  test('PostgreSQL password is sourced from a Secret, never inlined', () => {
    expect(manifest).not.toMatch(/PGPASSWORD:\s*"[^$]/);
    expect(manifest).toMatch(/key:\s*postgres-password/);
  });

  test('alert webhook reference is always optional (never required at job start)', () => {
    const refs = manifest.match(/key:\s*alert-webhook-url[^\n]*/g) || [];
    expect(refs.length).toBeGreaterThan(0);
    for (const ref of refs) {
      expect(ref).toMatch(/optional:\s*true/);
    }
  });
});

describe('Kubernetes WAL-archive verify CronJob', () => {
  const manifest = read('deploy/kubernetes/base/backup-cronjobs.yaml');
  const doc = manifest.split(/^---$/m).find(d => /name:\s*qodiqa-pg-backup-verify-wal\b/.test(d));

  test('is defined, on a 5-minute schedule', () => {
    expect(doc).toBeDefined();
    expect(doc).toMatch(/schedule:\s*"\*\/5 \* \* \* \*"/);
  });

  test('runs pg-wal-archive.sh --verify', () => {
    expect(doc).toMatch(/pg-wal-archive\.sh.*--verify/);
  });

  test('is fail-closed like its sibling qodiqa-pg-backup-verify (OnFailure, bounded single retry)', () => {
    expect(doc).toMatch(/concurrencyPolicy:\s*Forbid/);
    expect(doc).toMatch(/restartPolicy:\s*OnFailure/);
    expect(doc).toMatch(/backoffLimit:\s*1\b/);
  });

  test('mounts the same qodiqa-pg-backups PVC the archiver writes into', () => {
    expect(doc).toMatch(/claimName:\s*qodiqa-pg-backups/);
  });
});

describe('Kubernetes backup ConfigMap + PVC', () => {
  test('backup-configmap.yaml defines every retention tier with no hardcoded value elsewhere overriding it', () => {
    const cm = read('deploy/kubernetes/base/backup-configmap.yaml');
    for (const key of [
      'QODIQA_BACKUP_RETAIN_DAILY', 'QODIQA_BACKUP_RETAIN_WEEKLY', 'QODIQA_BACKUP_RETAIN_MONTHLY',
      'QODIQA_DR_RETAIN_DAILY', 'QODIQA_DR_RETAIN_WEEKLY', 'QODIQA_DR_RETAIN_MONTHLY',
      'QODIQA_WAL_ARCHIVE_DIR', 'QODIQA_WAL_ARCHIVE_RETAIN_DAYS', 'QODIQA_WAL_ARCHIVE_TIMEOUT_SECONDS',
    ]) {
      expect(cm).toMatch(new RegExp(`${key}:\\s*"[^"]+"`));
    }
  });

  test('backup-pvc.yaml defines both backup volumes as ReadWriteMany (avoids cross-CronJob node-attach failures)', () => {
    const pvc = read('deploy/kubernetes/base/backup-pvc.yaml');
    const docs = pvc.split(/^---$/m).filter(d => /kind:\s*PersistentVolumeClaim/.test(d));
    expect(docs).toHaveLength(2);
    for (const doc of docs) {
      expect(doc).toMatch(/ReadWriteMany/);
    }
    expect(pvc).toMatch(/name:\s*qodiqa-pg-backups/);
    expect(pvc).toMatch(/name:\s*qodiqa-dr-backups/);
  });

  test('base/kustomization.yaml wires in all three new backup resources', () => {
    const kustom = read('deploy/kubernetes/base/kustomization.yaml');
    expect(kustom).toMatch(/backup-configmap\.yaml/);
    expect(kustom).toMatch(/backup-pvc\.yaml/);
    expect(kustom).toMatch(/backup-cronjobs\.yaml/);
  });

  // This assertion used to be `expect(secret).toMatch(/alert-webhook-url:\s*<.*>/)`
  // -- an angle-bracket placeholder. The manifest has since migrated EVERY key in
  // secret.yaml away from that form to a valid-base64 `REPLACE_WITH_REAL_*_BEFORE_DEPLOY`
  // marker, because an angle-bracket value is not valid base64 and made every
  // strict schema validator (kubeconform -strict, kubectl apply
  // --dry-run=server) fail on this file specifically -- see secret.yaml's own
  // comment at `key-encryption-key`.
  // The manifest was right and the test was
  // stale: zero angle-bracket placeholders remain anywhere in its data block,
  // and this was the only key still asserted in the old form.
  //
  // The replacement is deliberately STRONGER than what it replaces, not weaker.
  // The old regex only checked for a pair of angle brackets; these checks
  // additionally require the value to be genuinely valid base64 (the property
  // was protecting), to decode to an unmistakable REPLACE marker, and
  // to not be a real webhook URL -- which is the actual thing this manifest
  // must never ship with.
  test('secret.yaml has an optional alert-webhook-url placeholder', () => {
    const secret = read('deploy/kubernetes/base/secret.yaml');
    const m = secret.match(/^\s*alert-webhook-url:\s*(\S+)\s*$/m);
    expect(m).not.toBeNull();

    const value = m[1];
    // Valid base64, round-trip exact (ignoring padding) -- the schema-validity
    // property strict Kubernetes validators enforce on a Secret's data values.
    const decoded = Buffer.from(value, 'base64');
    expect(decoded.toString('base64').replace(/=+$/, '')).toBe(value.replace(/=+$/, ''));

    // A placeholder, not a real secret.
    const text = decoded.toString('utf8');
    expect(text).toMatch(/^REPLACE_WITH_REAL_.*_BEFORE_DEPLOY/);
    expect(text).not.toMatch(/^https?:\/\//);
  });

  test('every secret.yaml data value is a valid-base64 REPLACE placeholder, never a real secret', () => {
    // Generalises the case above to the whole file, so the next key added
    // cannot quietly reintroduce the non-base64 form removed, and so a
    // real secret can never be committed here unnoticed.
    const secret = read('deploy/kubernetes/base/secret.yaml');
    const dataBlock = secret.slice(secret.indexOf('\ndata:'));
    const entries = [...dataBlock.matchAll(/^ {2}([a-z0-9-]+):\s*(\S+)\s*$/gm)];
    expect(entries.length).toBeGreaterThanOrEqual(6);

    for (const [, key, value] of entries) {
      const decoded = Buffer.from(value, 'base64');
      expect({ key, roundTrips: decoded.toString('base64').replace(/=+$/, '') === value.replace(/=+$/, '') })
        .toEqual({ key, roundTrips: true });
      expect({ key, text: decoded.toString('utf8') })
        .toEqual({ key, text: expect.stringMatching(/^REPLACE_WITH_REAL_.*_BEFORE_DEPLOY/) });
    }
  });
});

describe('deploy/docker/backup.Dockerfile', () => {
  const dockerfile = read('deploy/docker/backup.Dockerfile');

  test('installs bash and PostgreSQL client tools required by scripts/pg-backup.sh', () => {
    expect(dockerfile).toMatch(/apk add[^\n]*\bbash\b/);
    expect(dockerfile).toMatch(/apk add[^\n]*"?postgresql\$\{PG_CLIENT_MAJOR\}-client"?/);
  });

  // the npm bundled with the base image carried the image's CRITICAL/HIGH node-package findings and
  // no backup job runs it — removed, as did for the production image; the OS packages with a published fix are
  // upgraded to EXACT versions (a withdrawn version fails the build — the signal to bump the pinned base).
  test('the runtime stage removes npm/npx/corepack/yarn and pins the fixed musl/zlib versions', () => {
    const finalStage = dockerfile.slice(dockerfile.indexOf('AS final'));
    expect(finalStage).toMatch(/rm -rf \/usr\/local\/lib\/node_modules\/npm \/usr\/local\/lib\/node_modules\/corepack/);
    for (const bin of ['npm', 'npx', 'corepack', 'yarn', 'yarnpkg']) expect(finalStage).toContain(`/usr/local/bin/${bin}`);
    expect(finalStage).toMatch(/apk add --no-cache --upgrade musl=1\.2\.5-r11 musl-utils=1\.2\.5-r11 zlib=1\.3\.2-r1/);
    // the deps stage keeps npm (it installs the dependencies); only the runtime image drops it
    expect(dockerfile.slice(0, dockerfile.indexOf('AS final'))).toMatch(/RUN npm ci --omit=dev --ignore-scripts/);
  });

  // the client major is a build argument whose DEFAULT is the shipped compose server's major — a
  // pg_dump newer than the server wrote dumps no shipped tool could restore (postgresql17-client vs postgres:16.15).
  test('the default PG_CLIENT_MAJOR equals the shipped compose PostgreSQL major', () => {
    const arg = dockerfile.match(/^ARG PG_CLIENT_MAJOR=(\d+)$/m);
    expect(arg).not.toBeNull();
    const compose = read(path.join('deploy', 'docker', 'docker-compose.prod.yml'));
    const server = compose.match(/^\s*image:\s*postgres:(\d+)\.\d+/m);
    expect(server).not.toBeNull();
    expect(arg[1]).toBe(server[1]);
    expect(dockerfile).not.toMatch(/apk add[^\n]*postgresql17-client/);
  });

  test('keeps scripts/ and does not strip it (unlike the production Dockerfile)', () => {
    const stripBlock = dockerfile.match(/RUN rm -rf[\s\S]*?(?=\n\nRUN|\n\nUSER)/);
    expect(stripBlock).not.toBeNull();
    expect(stripBlock[0]).not.toMatch(/^\s*scripts\/\s*$/m);
  });

  test('runs as a non-root user', () => {
    expect(dockerfile).toMatch(/USER qodiqa/);
  });

  test('has its own per-Dockerfile .dockerignore override so scripts/ and docs/ reach the build context', () => {
    const ignore = read('deploy/docker/backup.Dockerfile.dockerignore');
    expect(ignore).not.toMatch(/^scripts\/\s*$/m);
    expect(ignore).not.toMatch(/^docs\/\s*$/m);
  });
});

describe('shell scripts', () => {
  test('backup-audit-log.sh exists, is bash, and supports backup/verify/restore modes', () => {
    const script = read('scripts/backup-audit-log.sh');
    expect(script).toMatch(/^#!\/usr\/bin\/env bash/);
    // PL13-03: errtrace (E) is now REQUIRED — without it the ERR trap never ran for a failure
    // inside a mode function (a silent exit: no alert, no failure metric). Was /set -euo pipefail/.
    expect(script).toMatch(/^set -Eeuo pipefail$/m);
    expect(script).toMatch(/run_backup\(\)/);
    expect(script).toMatch(/run_verify\(\)/);
    expect(script).toMatch(/run_restore\(\)/);
  });

  test('backup-audit-log.sh verify fails closed on a stale backup', () => {
    const script = read('scripts/backup-audit-log.sh');
    expect(script).toMatch(/MAX_AGE_SECONDS/);
    expect(script).toMatch(/age_seconds.*-gt.*MAX_AGE_SECONDS/);
  });

  test('pg-wal-archive.sh exists, is bash, and supports archive_command + --verify modes', () => {
    const script = read('scripts/pg-wal-archive.sh');
    expect(script).toMatch(/^#!\/usr\/bin\/env bash/);
    // PL13-03: errtrace (E) is now REQUIRED (see the backup-audit-log.sh test). Was /set -euo pipefail/.
    expect(script).toMatch(/^set -Eeuo pipefail$/m);
    expect(script).toMatch(/archive_segment\(\)/);
    expect(script).toMatch(/run_verify\(\)/);
    expect(script).toMatch(/--verify/);
  });

  test('pg-wal-archive.sh refuses to overwrite an existing archived segment with different content', () => {
    const script = read('scripts/pg-wal-archive.sh');
    expect(script).toMatch(/refusing to overwrite existing archived segment/);
  });

  test('pg-backup.sh has a pitr-restore subcommand that refuses to restore over an existing target', () => {
    const script = read('scripts/pg-backup.sh');
    expect(script).toMatch(/run_pitr_restore\(\)/);
    expect(script).toMatch(/pitr-restore\)\s*run_pitr_restore/);
    expect(script).toMatch(/target PGDATA directory already exists/);
  });
});

describe('systemd timers and services (self-hosted deployments)', () => {
  const EXPECTED_UNITS = [
    'qodiqa-pg-backup-daily',
    'qodiqa-pg-backup-weekly',
    'qodiqa-pg-backup-monthly',
    'qodiqa-pg-backup-incremental',
    'qodiqa-pg-backup-verify',
    'qodiqa-dr-backup',
    'qodiqa-dr-restore-validation',
  ];

  test.each(EXPECTED_UNITS)('%s has both a .service and a .timer unit', (name) => {
    expect(fs.existsSync(path.join(ROOT, 'deploy/systemd', `${name}.service`))).toBe(true);
    expect(fs.existsSync(path.join(ROOT, 'deploy/systemd', `${name}.timer`))).toBe(true);
  });

  test.each(EXPECTED_UNITS)('%s.timer schedules via OnCalendar and survives host downtime (Persistent=true)', (name) => {
    const timer = read(`deploy/systemd/${name}.timer`);
    expect(timer).toMatch(/OnCalendar=\S+/);
    expect(timer).toMatch(/Persistent=true/);
    expect(timer).toMatch(/WantedBy=timers\.target/);
  });

  test.each(EXPECTED_UNITS)('%s.service reads configuration from an EnvironmentFile, never hardcodes retention', (name) => {
    const service = read(`deploy/systemd/${name}.service`);
    expect(service).toMatch(/EnvironmentFile=\/etc\/qodiqa\/backup\.env/);
    expect(service).toMatch(/ExecStart=\S+/);
    expect(service).not.toMatch(/RETAIN\w*=\d+/); // no inlined retention count
  });

  test.each(EXPECTED_UNITS)('%s.service is hardened (NoNewPrivileges, ProtectSystem)', (name) => {
    const service = read(`deploy/systemd/${name}.service`);
    expect(service).toMatch(/NoNewPrivileges=yes/);
    expect(service).toMatch(/ProtectSystem=strict/);
  });

  test('backup.env.example documents every retention and metrics variable the scripts read', () => {
    const env = read('deploy/systemd/backup.env.example');
    for (const key of [
      'QODIQA_BACKUP_RETAIN_DAILY', 'QODIQA_BACKUP_RETAIN_WEEKLY', 'QODIQA_BACKUP_RETAIN_MONTHLY',
      'QODIQA_DR_RETAIN_DAILY', 'QODIQA_DR_RETAIN_WEEKLY', 'QODIQA_DR_RETAIN_MONTHLY',
      'QODIQA_BACKUP_METRICS_FILE', 'PGHOST', 'PGUSER', 'PGPASSWORD',
    ]) {
      expect(env).toMatch(new RegExp(`^${key}=`, 'm'));
    }
  });

  test('dr-backup-run.sh wrapper is valid, executable-intent bash referenced by qodiqa-dr-backup.service', () => {
    const wrapper = read('deploy/systemd/dr-backup-run.sh');
    expect(wrapper).toMatch(/^#!\/usr\/bin\/env bash/);
    expect(wrapper).toMatch(/set -euo pipefail/);
    const service = read('deploy/systemd/qodiqa-dr-backup.service');
    expect(service).toMatch(/dr-backup-run\.sh/);
  });
});

describe('systemd audit-log-backup units', () => {
  const EXPECTED_UNITS = ['qodiqa-audit-log-backup', 'qodiqa-audit-log-backup-verify'];

  test.each(EXPECTED_UNITS)('%s has both a .service and a .timer unit', (name) => {
    expect(fs.existsSync(path.join(ROOT, 'deploy/systemd', `${name}.service`))).toBe(true);
    expect(fs.existsSync(path.join(ROOT, 'deploy/systemd', `${name}.timer`))).toBe(true);
  });

  test.each(EXPECTED_UNITS)('%s.timer fires every 5 minutes and survives host downtime', (name) => {
    const timer = read(`deploy/systemd/${name}.timer`);
    expect(timer).toMatch(/OnCalendar=\*:\d\/5/);
    expect(timer).toMatch(/Persistent=true/);
    expect(timer).toMatch(/WantedBy=timers\.target/);
  });

  test.each(EXPECTED_UNITS)('%s.service is hardened and reads configuration from an EnvironmentFile', (name) => {
    const service = read(`deploy/systemd/${name}.service`);
    expect(service).toMatch(/EnvironmentFile=\/etc\/qodiqa\/backup\.env/);
    expect(service).toMatch(/NoNewPrivileges=yes/);
    expect(service).toMatch(/ProtectSystem=strict/);
    expect(service).not.toMatch(/RETAIN\w*=\d+/);
  });

  test('qodiqa-audit-log-backup.service runs backup-audit-log.sh backup', () => {
    expect(read('deploy/systemd/qodiqa-audit-log-backup.service')).toMatch(/backup-audit-log\.sh backup/);
  });

  test('qodiqa-audit-log-backup-verify.service runs backup-audit-log.sh verify', () => {
    expect(read('deploy/systemd/qodiqa-audit-log-backup-verify.service')).toMatch(/backup-audit-log\.sh verify/);
  });

  test('backup.env.example documents the new audit-log and WAL-archive variables', () => {
    const env = read('deploy/systemd/backup.env.example');
    for (const key of [
      'QODIQA_AUDIT_BACKUP_DIR', 'QODIQA_AUDIT_BACKUP_RETAIN_DAYS', 'QODIQA_AUDIT_BACKUP_MAX_AGE_SECONDS',
      'QODIQA_WAL_ARCHIVE_DIR', 'QODIQA_WAL_ARCHIVE_RETAIN_DAYS', 'QODIQA_WAL_ARCHIVE_TIMEOUT_SECONDS',
    ]) {
      expect(env).toMatch(new RegExp(`^${key}=`, 'm'));
    }
  });
});

describe('Documentation', () => {
  test('backup-scheduling.md exists and documents every CronJob', () => {
    const doc = read('docs/operations/backup-scheduling.md');
    for (const name of [
      'qodiqa-pg-backup-daily', 'qodiqa-pg-backup-weekly', 'qodiqa-pg-backup-monthly',
      'qodiqa-pg-backup-incremental', 'qodiqa-pg-backup-verify',
      'qodiqa-dr-backup', 'qodiqa-dr-restore-validation',
    ]) {
      expect(doc).toContain(name);
    }
  });

  test('backup-runbook.md and disaster-recovery.md cross-reference backup-scheduling.md', () => {
    expect(read('docs/operations/backup-runbook.md')).toMatch(/Backup Scheduling\]\(backup-scheduling\.md\)/);
    expect(read('docs/operations/disaster-recovery.md')).toMatch(/Backup Scheduling\]\(backup-scheduling\.md\)/);
  });

  test('deploy/env/production.env.example documents the new backup scheduling variables', () => {
    const env = read('deploy/env/production.env.example');
    expect(env).toMatch(/QODIQA_BACKUP_RETAIN_DAILY/);
    expect(env).toMatch(/QODIQA_DR_RETAIN_DAILY/);
  });


  test('backup-runbook.md documents both new scripts by name', () => {
    const doc = read('docs/operations/backup-runbook.md');
    expect(doc).toContain('scripts/backup-audit-log.sh');
    expect(doc).toContain('scripts/pg-wal-archive.sh');
  });

  test('disaster-recovery.md no longer claims an unenforced 1-hour PostgreSQL RPO', () => {
    const doc = read('docs/operations/disaster-recovery.md');
    expect(doc).toMatch(/RPO.*5 minutes/);
  });
});

describe('package.json scripts', () => {
  test('exposes dr:verify and dr:retention alongside the existing dr:* scripts', () => {
    const pkg = JSON.parse(read('package.json'));
    expect(pkg.scripts['dr:verify']).toBe('node scripts/dr/verify.js');
    expect(pkg.scripts['dr:retention']).toBe('node scripts/dr/retention.js');
  });

  test('exposes dr:rto', () => {
    const pkg = JSON.parse(read('package.json'));
    expect(pkg.scripts['dr:rto']).toBe('node scripts/dr/rtoHarness.js');
  });
});
