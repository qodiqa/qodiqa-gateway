# QODIQA Backup Scheduling

**Remediation — Automated Backup Scheduling**

| Field | Value |
|-------|-------|
| Document | Backup Scheduling Guide |
| Version | 1.0.0 |
| Owner | Platform Engineering / SRE |
| Audience | SRE, Platform Engineer, On-Call |
| Classification | Internal — Operational |

---

## 1. Why this document exists

Before this remediation, QODIQA shipped a complete PostgreSQL backup script
(`scripts/pg-backup.sh`) and a complete file+Postgres disaster-recovery
framework (`scripts/dr/*.js`), both fully documented in
[Backup Runbook](backup-runbook.md) and [Disaster Recovery](disaster-recovery.md)
— but neither was wired to any Kubernetes CronJob, systemd timer, or other
scheduler. Every documented RPO (1 hour for PostgreSQL, 5 minutes for the
audit chain) was **unenforced**: backups only happened when a human ran a
script by hand. This document describes the fix — the actual scheduling
layer — and how to operate it.

**update:** closed the scheduling gap, but the specific numbers
were never re-verified against what the shipped schedule actually
delivers — the fastest job was hourly, not 5 minutes, and nothing backed up
the audit log file at all (the script this document's own §3 pointed to,
`scripts/backup-audit-log.sh`, didn't exist). built that missing
script, added continuous PostgreSQL WAL archiving, and added the two new
verification CronJobs/timers below (§3) — see
[Disaster Recovery §1](disaster-recovery.md#1-recovery-objectives) for the full before/after.

## 2. What was added

| Component | Purpose | Reuses |
|-----------|---------|--------|
| `deploy/kubernetes/base/backup-cronjobs.yaml` | 8 Kubernetes CronJobs (below; one of them, `qodiqa-pg-backup-incremental`, ships suspended) | `scripts/pg-backup.sh`, `scripts/dr/*.js` unmodified in behavior |
| `deploy/kubernetes/base/backup-configmap.yaml` | Non-secret configuration (retention, paths) | — |
| `deploy/kubernetes/base/backup-pvc.yaml` | Storage for backup output | Same ReadWriteMany pattern as `qodiqa-keystore` (see `pvc.yaml`) |
| `deploy/docker/backup.Dockerfile` | Image for the CronJobs (has `scripts/`, `docs/`, `bash`, PostgreSQL client tools — the production `Dockerfile` deliberately strips all of these) | — |
| `deploy/systemd/*.timer` / `*.service` | Equivalent scheduling for self-hosted/bare-metal deployments | Same scripts, same `backup.env` |
| `scripts/dr/retention.js` | Count-based daily/weekly/monthly rotation for `scripts/dr/backup.js` output | New, pure-function, unit-tested (`test/dr/retention.test.js`) |
| `scripts/pg-backup.sh` tier support | Count-based daily/weekly/monthly rotation for `pg_dump` output | Extended existing script, additive only |
| `scripts/dr/verify.js` | Non-destructive backup verification (reuses `restore.js`'s own checksum validation) | New, thin wrapper — zero duplicated checksum logic |
| `scripts/dr/metricsFile.js`, `scripts/dr/alert.js` | Prometheus textfile metrics + failure webhook, shared by all Node DR scripts | New, mirrors `scripts/pg-backup.sh`'s existing `ALERT_WEBHOOK_URL` pattern |
| `scripts/backup-audit-log.sh` | High-frequency (5 min) audit-log file backup — the script §5.1 of the Backup Runbook always documented but never shipped | New, mirrors `scripts/pg-backup.sh`'s seal/metrics/alert conventions |
| `scripts/pg-wal-archive.sh` | Continuous PostgreSQL WAL archiving (`archive_command` target) + staleness verification | New — closes the gap between the documented and actually-enforced PostgreSQL RPO |
| `deploy/kubernetes/base/backup-cronjobs.yaml`'s `qodiqa-pg-backup-verify-wal` | 5-minute WAL-archive staleness check | New CronJob, same file |
| `deploy/systemd/qodiqa-audit-log-backup{,-verify}.{service,timer}` | Self-hosted 5-minute audit-log backup + verification | New |
| `scripts/dr/rtoHarness.js` | Timestamped RTO drill measurement — see DR RTO Measurement | New |

Nothing about the actual backup/restore/validate LOGIC changed. `scripts/pg-backup.sh full`
still does exactly what it did before if invoked with no tier argument;
`scripts/dr/backup.js`, `restore.js`, `validate.js`, `cycle.js` are unchanged
except for opt-in metrics/alert hooks in their CLI entrypoints.

## 3. The eight CronJobs

| CronJob | Schedule (default, UTC) | Runs | Covers |
|---------|--------------------------|------|--------|
| `qodiqa-pg-backup-daily` | `0 2 * * *` | `pg-backup.sh full daily` | Full `pg_dump`, retained: `QODIQA_BACKUP_RETAIN_DAILY` (default 7) |
| `qodiqa-pg-backup-weekly` | `0 3 * * 0` | `pg-backup.sh full weekly` | Retained: `QODIQA_BACKUP_RETAIN_WEEKLY` (default 4) |
| `qodiqa-pg-backup-monthly` | `0 4 1 * *` | `pg-backup.sh full monthly` | Retained: `QODIQA_BACKUP_RETAIN_MONTHLY` (default 12) |
| `qodiqa-pg-backup-incremental` | `0 */6 * * *` — **SUSPENDED** (`suspend: true`) | `pg-backup.sh incremental` | **UNSUPPORTED.** `pg-backup.sh incremental` logs `BACKUP_INCREMENTAL_UNSUPPORTED` and exits 2: `pg_basebackup` needs the `REPLICATION` attribute on `qodiqa_backup`, which is deliberately not granted (design decision; [database role management](database-role-management.md)). No base backups are produced, so point-in-time restore is not available ([Restore Runbook §5.5](restore-runbook.md#55-point-in-time-restore-from-continuous-wal-archive)). Do not unsuspend it before an administrator grants REPLICATION. |
| `qodiqa-pg-backup-verify` | `30 2 * * *` | `pg-backup.sh verify daily` | Seal check, `pg_restore --list`, full-table-coverage check |
| `qodiqa-pg-backup-verify-wal` | `*/5 * * * *` | `pg-wal-archive.sh --verify` | **New.** WAL-archive staleness/integrity check — proves segments are being archived and sealed every 5 minutes. It does **not** by itself give a 5-minute PostgreSQL RPO: replaying archived WAL needs a base backup, and none is produced while `qodiqa-pg-backup-incremental` is unsupported (row above). Requires the external PostgreSQL server's own `archive_command` to be configured — see [Backup Runbook §3.5](backup-runbook.md#35-continuous-wal-archiving) |
| `qodiqa-dr-backup` | `0 * * * *` | `backup.js --with-postgres` + `retention.js` + `verify.js` | Every PostgreSQL table (incl. audit_chain/transparency_log_entries mirrors) + encrypted key store |
| `qodiqa-dr-restore-validation` | `0 5 * * 1` | `cycle.js` | Full backup → restore into an isolated DB → validate cycle |

These CronJobs live in `deploy/kubernetes/base/` and are wired into both
topology overlays' `kustomization.yaml` (they run identically regardless of
which audit-ordering topology is deployed — see
`deploy/kubernetes/kustomization.yaml`'s header comment for why there is no
longer a single top-level `kubectl apply -k deploy/kubernetes/` entry point).
Apply with whichever overlay this environment runs:

```bash
kubectl apply -k deploy/kubernetes/overlays/single-node/      # production
# — or, NON-PRODUCTION only —
kubectl apply -k deploy/kubernetes/overlays/distributed/
```

The `distributed` overlay is not a production topology: the production boot validator refuses the distributed mode
until its audit chain has signed checkpoints and anchors.

**Not a CronJob — self-hosted/systemd only:** the audit-log-file
backup (`scripts/backup-audit-log.sh`) cannot run as a standalone
Kubernetes CronJob at all (§4's scope boundary — a separate pod cannot
reach the per-pod-exclusive audit-log volume). It ships as
`deploy/systemd/qodiqa-audit-log-backup.timer` (`OnCalendar=*:0/5`) and
`qodiqa-audit-log-backup-verify.timer` (`OnCalendar=*:2/5`) for self-hosted
deployments, where the file is directly reachable. See §5 below.

**Incremental runs:** the 5-minute run no longer copies the whole log. A **base** (the whole
log, as before) is taken once a day (`QODIQA_AUDIT_BACKUP_REBASE_HOURS`, default 24; the planned rebase waits for
`QODIQA_BACKUP_WINDOW_UTC` when set) or whenever the log was rewritten or pruned; every other run writes a **segment**
holding only the bytes appended since the previous run, with an HMAC-sealed metadata file chaining it to the
previous run (byte range, data sha256, previous-meta sha256). The 5-minute cadence (RPO) is unchanged. `verify`
checks the whole sealed chain; `restore <base>` reassembles base + segments and refuses any gap, reorder or edited
byte. `QODIQA_AUDIT_BACKUP_INCREMENTAL=false` restores full copies every run. The WAL captured with a run is kept
only when its batch continues the backed-up prefix (a batch already committed inside it is omitted, at backup and
again at restore — restoring it made boot refuse). Retention removes whole chains only. A restore is checked by the production chain probe
.

## 4. Known scope boundary — read before relying on this in production

`scripts/dr/backup.js` and `scripts/dr/cycle.js` also cover three
file-based components: the audit chain (`audit.log`), the policy store
(`policy-store.json`), and the organizations/tenants caches. In QODIQA's
Kubernetes topology (single-node StatefulSet, `replicas: 1`)
(`deploy/kubernetes/overlays/single-node/statefulset.yaml`), the audit log is a **per-pod
exclusive ReadWriteOnce volume**, and the policy/org/tenant files are not
persisted to any shared volume at all. A standalone CronJob pod has no
architecturally safe way to read them — mounting an already-exclusively-
claimed RWO volume is not possible, and even if it were, reading a file
mid-write from a different pod risks a torn read.

Because of this, `qodiqa-dr-backup` and `qodiqa-dr-restore-validation` are
**scoped to what a standalone pod can reach**: the encrypted key store (via
the existing ReadWriteMany `qodiqa-keystore` PVC) and the entire
PostgreSQL-backed state (every table, including both mirrors — see
ADR-AUDIT-CHAIN-ARCHITECTURE.md for
why the PostgreSQL mirror is itself a valid rebuild source for the audit
chain). Their manifests/validation results correctly and honestly record
`auditLog` / `policyStore` / `organizations` / `tenants` as `present: false`
— this is **disclosed, expected behavior in this topology**, not a defect
introduced by this remediation.

`scripts/dr/cycle.js`'s `DR_VALIDATE_COMPLETE` log line reports each probe's
result individually (`auditChainValid`, `policyStoreValid`, `keyStoreValid`,
`postgresValid`) as well as the ANDed `overallValid` — for the standalone
Kubernetes CronJob, expect `overallValid: false` with `postgresValid: true`
as the healthy signal; alerting/dashboards should key off the per-probe
fields for this job, not the aggregate.

**If you need full-fidelity restore validation including the per-pod file
components**, run `scripts/dr/cycle.js` via `kubectl exec` against the live
pod (`qodiqa-0`) instead — those env vars already point at real mounted files there.
Self-hosted single-instance deployments (below) do not have this limitation
at all: `qodiqa-dr-backup.service` runs on the same host as the live
`qodiqa` process, so every file-based component is directly reachable.

## 5. Self-hosted / systemd deployments

`deploy/systemd/` mirrors every CronJob above as a `.timer` + `.service`
pair, driven by a single `EnvironmentFile` (`/etc/qodiqa/backup.env` — see
`deploy/systemd/backup.env.example` for the full template):

```bash
sudo mkdir -p /etc/qodiqa /var/backups/qodiqa /var/backups/qodiqa-dr
sudo cp deploy/systemd/backup.env.example /etc/qodiqa/backup.env
sudo chmod 640 /etc/qodiqa/backup.env
sudo chown root:qodiqa /etc/qodiqa/backup.env
# edit /etc/qodiqa/backup.env with real values

sudo cp deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
sudo cp deploy/systemd/dr-backup-run.sh /opt/qodiqa/deploy/systemd/dr-backup-run.sh
sudo chmod +x /opt/qodiqa/deploy/systemd/dr-backup-run.sh

sudo systemctl daemon-reload
# qodiqa-pg-backup-incremental is deliberately NOT enabled: pg-backup.sh refuses `incremental` with
# BACKUP_INCREMENTAL_UNSUPPORTED / exit 2 until an administrator grants REPLICATION to qodiqa_backup — enabling its
# timer would only produce a failed unit and an alert every 6 hours. The Kubernetes CronJob is `suspend: true` for
# the same reason.
for t in qodiqa-pg-backup-daily qodiqa-pg-backup-weekly qodiqa-pg-backup-monthly \
         qodiqa-pg-backup-verify qodiqa-pg-wal-archive-verify \
         qodiqa-dr-backup qodiqa-dr-restore-validation \
         qodiqa-audit-log-backup qodiqa-audit-log-backup-verify; do
  sudo systemctl enable --now "${t}.timer"
done

# Verify
systemctl list-timers 'qodiqa-*'
```

Every timer sets `Persistent=true` — if the host is down at the scheduled
time, the job runs once at next boot instead of being silently skipped
until the next cycle.

## 6. Configuration

Nothing is hardcoded. Every schedule-adjacent value is one of:

- **Retention counts** — `QODIQA_BACKUP_RETAIN_{DAILY,WEEKLY,MONTHLY}`,
  `QODIQA_DR_RETAIN_{DAILY,WEEKLY,MONTHLY}` — ConfigMap (`backup-configmap.yaml`)
  or `backup.env`.
- **Cron schedule strings** — the one thing the Kubernetes `CronJob` API
  requires as a literal `spec.schedule` field, not an env-var lookup. Override
  per-environment with a Kustomize overlay patch:

  ```yaml
  # 
  patches:
    - target: { kind: CronJob, name: qodiqa-pg-backup-daily }
      patch: |
        - op: replace
          path: /spec/schedule
          value: "0 8 * * *"
  ```

  For systemd, edit the `.timer` unit's `OnCalendar=` directly (or drop-in
  override via `systemctl edit qodiqa-pg-backup-daily.timer`).
- **Timezone** — Kubernetes: `spec.timeZone` (requires Kubernetes ≥ 1.27),
  set per CronJob, overridable the same way as schedule. systemd: timers
  run in the host's local timezone by default; the scripts themselves always
  timestamp/log in UTC regardless (see `scripts/pg-backup.sh`'s header
  comment) — only the wall-clock firing time is timezone-sensitive.
- **Alerting** — `ALERT_WEBHOOK_URL`, optional everywhere, no-op-safe if unset.
  Kubernetes: `secret.yaml`'s `alert-webhook-url` key (treated as a secret —
  most webhook URLs embed a bearer-token-like path). systemd: `backup.env`.
- **Seal key** — `QODIQA_BACKUP_HMAC_KEY` (the HMAC-SHA256 integrity seal over every
  backup file) comes from its own `secret.yaml` key, `backup-hmac-key`, in every backup CronJob — it is no longer
  mapped to `key-encryption-key` (the application KEK must not double as a MAC key). `pg-backup.sh` refuses a
  placeholder seal key, one under 32 characters, or one equal to `QODIQA_BACKUP_ENCRYPTION_KEY`. **Cutover:** backups
  sealed before the switch were sealed with the KEK value. `verify` checks only the newest backup, so the first full
  backup after the switch verifies normally; to verify or restore an OLDER backup, run that one command with
  `QODIQA_BACKUP_HMAC_KEY` set to the old KEK value. WAL segments are sealed by `pg-wal-archive.sh` on the database
  host with whatever key that host's environment supplies — set it to the same `backup-hmac-key` value there, or
  `qodiqa-pg-backup-verify-wal` will report seal mismatches.
- **Verification cadence / restore-validation cadence** — literal
  `spec.schedule` values on `qodiqa-pg-backup-verify` /
  `qodiqa-dr-restore-validation`, same override mechanism as any other schedule.

## 7. Restore Validation Setup

`qodiqa-dr-restore-validation` / `qodiqa-dr-restore-validation.service` need
a genuinely separate database to restore into — never the live one.
Provision it once:

```bash
# Explicit host/port for the cluster you mean (never rely on the localhost:5432 default — on a workstation that is
# usually a live cluster); passwords from PGPASSFILE / QODIQA_PG_MIG_PASSWORD in the environment, never in a URL or argv.
# migrate.js prefers QODIQA_PG_URL when it is set — make sure it is unset in this shell.
createdb -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" qodiqa_restore_validation
QODIQA_PG_HOST="$PGHOST" QODIQA_PG_PORT="$PGPORT" QODIQA_PG_DATABASE=qodiqa_restore_validation \
  QODIQA_PG_MIG_USER=qodiqa_test node src/infra/postgres/migrate.js
```

This is exactly what `.github/workflows/backup-restore.yml`'s `dr-postgres`
job already does for CI, on every push/PR and its own daily `0 5 * * *`
schedule — that workflow proves the DR *mechanism* works; the CronJobs/
timers in this document are what make it run automatically in *production*.

## 8. Observability

CronJob/systemd-timer pods and units are short-lived and cannot be scraped
directly by Prometheus. Every script in this remediation writes a
Prometheus textfile-collector `.prom` file (`scripts/dr/metricsFile.js`,
and the equivalent `write_prom_metrics()` in `scripts/pg-backup.sh`) —
point your `node_exporter` (or equivalent agent)'s textfile collector
directory at the same volume these are written to
(`QODIQA_BACKUP_METRICS_FILE`) to expose them in Prometheus. The collector
reads every `*.prom` file in that directory, and each job writes its OWN file
(2026-10-06 — previously every mode replaced one shared
file, so e.g. the 02:30 verify erased a failed 02:00 full backup's
`success=0`): `pg-backup.sh` writes `<QODIQA_BACKUP_METRICS_FILE minus
.prom>_<mode>_<tier>.prom` (e.g. `qodiqa_pg_backup_full_daily.prom`,
`qodiqa_pg_backup_verify_daily.prom`) and renames a leftover shared file to
`*.prom.superseded`; the DR backup job's `verify.js` step writes
`…_verify.prom` next to `backup.js`'s file. Metric names and labels are
unchanged. Metrics emitted:

- `qodiqa_pg_backup_success{mode,tier}` / `..._last_run_timestamp_seconds` / `..._size_bytes`
- `qodiqa_dr_backup_success` / `..._last_success_timestamp_seconds` / `..._duration_seconds` / `..._components_present`
- `qodiqa_dr_backup_verify_success` / `..._components_checked` / `..._postgres_tables_checked`
- `qodiqa_dr_restore_validation_success` / `..._duration_seconds`

Kubernetes' own `kube-state-metrics` additionally exposes
`kube_job_status_succeeded` / `kube_job_status_failed` /
`kube_cronjob_next_schedule_time` per CronJob out of the box — a
complete dashboard should combine both.

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `BACKUP_SEAL_MISMATCH` on every verify run | `QODIQA_BACKUP_HMAC_KEY` unset in this environment — pre-DR-3 bug, fixed as part of this remediation (see `scripts/pg-backup.sh`'s `seal_backup()` comment) | Set `QODIQA_BACKUP_HMAC_KEY`; if genuinely running without one, this now compares hash-only correctly (fixed) |
| CronJob pod `Pending` forever | `ReadWriteOnce` PVC already attached to a different node | Use a `ReadWriteMany`-capable `StorageClass` (see `backup-pvc.yaml`) or pin all backup CronJobs to one node via `nodeSelector` |
| `qodiqa-dr-backup` / restore-validation always shows `auditChainValid: false` / `policyStoreValid: false` | Expected — see §4, "Known scope boundary" | Not a bug; use `kubectl exec` against a live replica for full-fidelity validation, or rely on the per-probe fields |
| `Backup coverage gap` in verify output | A table in `scripts/dr/table-registry.js`'s inventory has no rows dumped — often a migration not yet applied in this environment | Run `node src/infra/postgres/migrate.js`, re-run verify |
| `RETENTION_ENFORCED` shows `prunedCount: 0` every run | Fewer backups exist than the configured retain count — expected during initial rollout | No action; pruning begins once the count is exceeded |
| Alert webhook never fires | `ALERT_WEBHOOK_URL` unset (by design, no-op) | Set the secret/env var if alerting is desired |

---

*Cross-references: [Backup Runbook](backup-runbook.md) | [Disaster Recovery](disaster-recovery.md) | [Backup → Restore Validation](backup-restore-validation.md) | DR RTO Measurement*
