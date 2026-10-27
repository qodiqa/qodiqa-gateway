# QODIQA Restore Runbook

**Operations & Production Readiness**

| Field | Value |
|-------|-------|
| Document | Restore Runbook |
| Version | 1.0.0 |
| Owner | Platform Engineering |
| Audience | SRE, Platform Engineer, On-Call |
| Classification | Internal — Operational |
| Last Updated | 2026-07-03 |

---

## Table of Contents

1. [Overview](#1-overview)
2. [Restore Decision Matrix](#2-restore-decision-matrix)
3A. [Complete Restore From a DR Backup (single-node, same host)](#3a-complete-restore-from-a-dr-backup-single-node-same-host)
3. [Full System Restore](#3-full-system-restore)
4. [Partial Restore](#4-partial-restore)
5. [Database Restore](#5-database-restore)
6. [Audit Chain Restore](#6-audit-chain-restore)
7. [Artifact Restore](#7-artifact-restore)
8. [Configuration Restore](#8-configuration-restore)
9. [Consistency Verification](#9-consistency-verification)
10. [Post-Restore Validation](#10-post-restore-validation)

---

## 1. Overview

A restore operation recovers QODIQA data from backup. The scope of the restore depends on the nature of the failure.

**Restore invariant (single-node/file-authoritative deployments only —
`QODIQA_AUDIT_ORDERING_MODE=single-node`, the default):** The audit chain
file (`audit.log`) and the PostgreSQL `audit_chain` table must be consistent
after any restore. If they diverge, the file is authoritative and the
PostgreSQL table can be rebuilt from the file.

**Supported production topology.** Production runs **single-node only**: the Kubernetes
`single-node` overlay (`deploy/kubernetes/overlays/single-node/statefulset.yaml` — a **StatefulSet** named `qodiqa`,
`replicas: 1`, a correctness bound, not a capacity setting) or `deploy/docker/docker-compose.prod.yml`
(`QODIQA_DEPLOYMENT_MODE: single-node`). The boot validator refuses `distributed` in production
. The
distributed paragraphs below describe a **non-production** topology only.

**Command conventions in this runbook.** `psql`, `pg_restore` and `scripts/pg-backup.sh` take the target from
`PGHOST`/`PGPORT`/`PGUSER`/`PGDATABASE` and the password from a `0600` `PGPASSFILE` (or a `PGPASSWORD` environment
variable filled from your secret store, e.g. `PGPASSWORD="${QODIQA_PG_TEST_PASSWORD}"`) — never put a password in a
connection URL or type it literally on the command line (URLs and argv are visible in `ps` and shell history). Set `PGHOST`/`PGPORT` explicitly to
the cluster you mean to restore; never rely on a `localhost:5432` default, which on a workstation is usually some other,
live cluster. `/metrics` is on the authenticated ops surface: examples read it with
`curl -H @"$OPS_AUTH_HEADER_FILE" …`, where `OPS_AUTH_HEADER_FILE` is a `0600` file containing one line
`Authorization: Bearer <viewer operator API key>` (curl reads the header from the file, so the key never appears in
argv); `/metrics` also needs `QODIQA_DIAGNOSTICS_ENABLED=true` and a source address inside `QODIQA_OPS_IP_ALLOWLIST`.

**In distributed mode** (`QODIQA_AUDIT_ORDERING_MODE=distributed` — the Kubernetes `distributed` overlay; **not
supported in production**, see above), this invariant is reversed: there is no local
`audit.log` file at all — the PostgreSQL `audit_chain` table is the sole
authoritative source, and restore's mandatory integrity gate verifies it
directly (see [Backup → Restore Validation
§2.1/§4.3](backup-restore-validation.md#21-deployment-mode-aware-audit-evidence)
for the full mode-aware restore procedure and `scripts/dr/backup.js`'s
`manifest.auditOrderingMode` field, which records which mode a given backup
was actually taken under).

**Recovery time expectations** (estimates, not yet measured against a live
drill — see DR RTO Measurement for how the next
drill turns these into real numbers):

| Restore Scope | Expected Duration |
|---------------|------------------|
| Configuration only | 2–5 minutes |
| Key store only | 5–10 minutes |
| Audit log file only | 5–10 minutes |
| PostgreSQL (1 GB DB) | 15–30 minutes |
| PostgreSQL (10 GB DB) | 60–120 minutes |
| PostgreSQL point-in-time restore | **Not available** — see [§5.5](#55-point-in-time-restore-from-continuous-wal-archive) |
| Full system | 2–4 hours |

---

## 2. Restore Decision Matrix

| Failure Scenario | Restore Scope | Primary Section |
|-----------------|--------------|----------------|
| Configuration change caused outage | Config restore | Section 8 |
| Key store file corrupted or deleted | Key store restore | Section 8.2 |
| Policy file corrupted or deleted | Config restore | Section 8.3 |
| Audit log file corrupted | Audit chain restore | Section 6 |
| PostgreSQL data corrupted | Database restore | Section 5 |
| PostgreSQL table dropped accidentally | Partial database restore | Section 4 |
| Complete data loss | Full system restore | **Section 3A** (from a `scripts/dr/backup.js` backup); Section 3 for the component-by-component path |
| Evidence package missing | Partial database restore | Section 7 |

---

## 3A. Complete Restore From a DR Backup (single-node, same host)

. This is the procedure the restricted-pilot gate was proven with. It ran on the shipped
compose (`deploy/docker/docker-compose.prod.yml`), with a hot backup under load and real-size history; the record is
. It applies wherever the backup job can read the gateway's
files: the systemd units, or the backup image run on the compose host. The Kubernetes `qodiqa-dr-backup` CronJob
cannot read the per-pod audit-log/anchor volume (see the scope note at the top of
`deploy/kubernetes/base/backup-cronjobs.yaml`), so this complete-state guarantee does not cover that topology.

**What a DR backup holds.** `scripts/dr/backup.js <dir> --with-postgres`, encrypted and sealed:

| Group | Contents |
|---|---|
| Database | A `pg_dump --format=custom` of every table, from a snapshot exported **before** any file is read |
| Audit chain | The log, its checkpoints, signed base record, `.wal` and `.sum` |
| Anchoring | The anchor export, the local witness log and its position claims |
| Recovery journal | The persistence-recovery journal |
| Key stores | Artifact keys and key archive, checkpoint keys, transparency keys, the key-record MAC keyring |

In production, RBAC, signing identities, tenants, organizations and policies are PostgreSQL rows
(`control_plane_records`) and come back with the database.

Files are copied in dependency order (`scripts/dr/components.js`), so a backup taken while the gateway runs is
consistent: every exported anchor is in the copied witness log, every checkpoint in the copied sidecar, and every
signing key in the copied key store. The database mirror lags the copied log, which is the normal state that boot
recovery backfills.

**What it does not hold** — restore these from your secret store and configuration management, exactly like a fresh
deployment:
- the deployment secrets in `.env.prod` (KEK, role passwords, Redis credentials, admin/ops tokens);
- the witness private key and the witness public-key trust set (`./witness`, provisioned outside the gateway, ideally
  by another party);
- TLS material;
- `policies.json`.

Two derived files are deliberately left out and are rebuilt at boot: `<audit.log>.anchor-index.json` and
`<audit.log>.verify.json`. Redis is not restored; nonces are short-lived.

**Prerequisite — client major.** `pg_dump`/`pg_restore` must have the server's major: the backup image is built with
`PG_CLIENT_MAJOR=16` for the shipped `postgres:16.15` (`deploy/docker/backup.Dockerfile`). `backup.js` refuses a mismatch
(`PG_DUMP_VERSION_MISMATCH`) and `restore.js` refuses before touching the target (`PG_RESTORE_VERSION_MISMATCH`).

1. **Backup** — the job's environment = the live service's paths (`deploy/systemd/backup.env.example`:
   `NODE_ENV=production`, every `QODIQA_*_PATH`, the anchor export, the witness log, and the libpq `PG*` variables as
   `qodiqa_backup`, preferably with `PGSSLMODE=verify-full`):
   ```bash
   node scripts/dr/backup.js /var/backups/qodiqa-dr/qodiqa-backup-$(date -u +%Y%m%dT%H%M%SZ) --with-postgres
   ```
2. **Verify** (offline; no database, no KEK):
   ```bash
   node scripts/dr/verify.js <backup dir>      # BACKUP_VERIFY_OK
   ```
3. **Fresh target.** Deploy a new stack with the deployment secrets: `.env.prod`, `./witness`, `./tls`, `policies.json`.
   Start `postgres` and `redis` only. Run `node src/infra/postgres/migrate.js` as the bootstrap
   identity; this creates the roles. Then set the role passwords (`scripts/db/role-credentials.js --rotate …`, then
   `--harden-unused`). Create the gateway's volumes without starting it: `docker compose … create qodiqa`.
4. **Restore** into those freshly created, empty volumes and the migrated database. Run it with the backup image,
   mounting logs at `/restore`, data at `/restore/data` and anchors at `/restore/anchors`:
   ```bash
   node scripts/dr/restore.js <backup dir> /restore --allow-existing --no-erasure-ledger
   ```
   - `--allow-existing` is needed only because the two nested mount points exist inside `/restore`. Use it only after
     confirming the volumes were created a moment ago and are empty.
   - Connect as the identity that migrated the source. In the shipped compose that is the cluster bootstrap superuser,
     so set `QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE=true` for this run. Never do that on a shared cluster.
   - Replace `--no-erasure-ledger` with `--erasure-ledger <off-host export>` whenever an export
     (`scripts/dr/erasureLedger.js`) newer than the backup exists. `--no-erasure-ledger` accepts the documented
     backup window.
   - `restore.js` checks the seal and every checksum. It then runs `pg_restore --clean --if-exists --no-owner
     --exit-on-error --single-transaction` and reconciles every table's row count against the backup snapshot. It also
     verifies the chain heads, rebuilds the mirror count, and verifies the restored audit chain. It reports
     `RESTORE_COMPLETE` only if all of these pass.
   - **SECURITY DEFINER ownership.** `--no-owner` makes the restoring role the owner of every
     restored object, the 47 SECURITY DEFINER functions included. On a schema at migration 079 or later, both restore
     paths (`restore.js` via `scripts/dr/pgDump.js`, and `scripts/pg-backup.sh restore`) immediately hand those functions
     back to the NOLOGIN, non-superuser `qodiqa_definer` (`scripts/dr/definer-ownership.sql`) and verify the result; any
     failure fails the restore (`RESTORE_DEFINER_OWNERSHIP_FAILED`, target INCOMPLETE). Preconditions on the target
     cluster: the role `qodiqa_definer` exists (migration 079 has run on that cluster at least once) and the restoring
     identity is a superuser or can `SET ROLE qodiqa_definer`. A pre-079 schema is reported
     (`RESTORE_DEFINER_OWNERSHIP_PRE_ER16`) and must be migrated before use. The JSON DR path only verifies ownership
     (its target is migrated by the chain).
   - **Schema ownership.** On a schema at 081 or later the same restore paths first run
     `scripts/dr/schema-ownership.sql`: every table, sequence, index, type and non-definer function goes back to the
     NOLOGIN `qodiqa_owner`, and the restore fails (`RESTORE_SCHEMA_OWNERSHIP_FAILED`) unless ownership, backup-role
     read coverage and default privileges (only `FOR ROLE qodiqa_owner`) verify. **The supported restore identity is the
     bootstrap identity (`qodiqa_test` shape) — no superuser, no `QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE`** — proven on
     PostgreSQL 16 and 17. A
     dump taken before 081 still names the source's bootstrap role in its default privileges and needs that role name
     (or a superuser) on the target.
   - **Audit WAL.** The WAL is copied before the log, so it can hold a batch already committed inside the
     copied log. Restoring that batch makes boot refuse ("the WAL batch does not continue the log"). The backup
     records such a WAL as omitted (`omitted.reason: WAL_BATCH_COMMITTED_IN_LOG`). `restore.js` re-checks any WAL
     against the restored log: a committed batch is renamed to `audit.log.wal.committed-batch`, never deleted, and
     every entry is already in the log. A batch that continues the log is left for boot recovery to replay. A WAL from
     another chain fails the restore (`RESTORED_WAL_INCONSISTENT`). `RESTORE_COMPLETE` reports the outcome in
     `auditWal`.
5. **Boot** the gateway (`docker compose … up -d qodiqa`). Expect READY with `AUDIT_CHECKPOINT_BOOT_VERIFIED`,
   `AUDIT_ANCHORS_BOOT_VERIFIED`, `AUDIT_MIRROR_CONSISTENCY_VERIFIED` (after `AUDIT_MIRROR_BOOT_RECOVERY` backfills the
   lag) and `KEY_VALIDATED`, with no ERROR. A signed request must return EXECUTE.
6. **Validate**: after new traffic the file and mirror counts are equal, and the independent verifier
   (`scripts/audit-repro/verify/qodiqa-audit-verify.js --audit <copy of audit.log>`) reports VALID.

Measured RTO and RPO:-7.

### 3A.1 Witness key and trust list — custody and recovery (outside the gateway backup)

The witness private key (`witness-key.json`) and the witness public-key trust list (`witness-public-keys.json`) are
**never** in a gateway DR backup. The witness exists to constrain the gateway's operators, so its key must not be
recoverable from the gateway's own backups. Recovery depends on them, so these conditions are **pilot preconditions**.

**Custody (owner / witness operator — EXTERNAL, not verifiable from the repository):**
- Hold both files in a secret store that the gateway host's operators cannot write, ideally operated by the witness
  party.
- Keep at least one copy off the gateway host and outside the region or account of the gateway backups (C5), so a
  single loss cannot take both.

**Access control:**
- *Read* for the deployment pipeline that provisions `./witness` (compose) or the witness Secret (Kubernetes).
- *Write* only for the witness operator.
- Every read audited.
- The trust list (public) may also be published to auditors. That is recommended: it lets them verify anchors
  independently.

**Availability during DR:**
- The secret store must be reachable from the recovery environment without the failed gateway host. Credentials for
  it must not live only on that host.
- Record the store, path, version and the expected `keyId` alongside the C5 off-site location.

**Recovery procedure** (step 3 of §3A):
1. Retrieve both files into the target's `./witness` (mode 0600, read-only mount).
2. Before booting, check that the key matches the trust list:
   ```bash
   WITNESS_ID=qodiqa-witness-1 WITNESS_KEY_PATH=witness/witness-key.json WITNESS_LOG_PATH=/dev/null \
     node scripts/anchor/witness-cosign.js --public-key
   ```
   The printed `keyId` and `publicKey` must equal an `active` entry of `witness/witness-public-keys.json`; stop if they
   do not.
3. Boot (§3A step 5). `AUDIT_ANCHORS_BOOT_VERIFIED` proves the trust list verifies every restored anchor. The next
   checkpoint's anchor appearing in `anchors.jsonl` proves the private key cosigns again; the export holds only
   cosigned records (ANCHOR-1).

**Verified:**
- Witness material provided from outside the backup.
- The check above printed `keyId wit-e83fe10bced6c4c1` = the trust-list entry, with the public key equal.
- Boot `AUDIT_ANCHORS_BOOT_VERIFIED`.
- After restore the export grew from 443,895 to 447,231 bytes: a new cosigned anchor at chainLength 409,736.

**Not verified here:** the custody, access-control and availability conditions of a real secret store. There is no
secret store in this environment; owner/external.

**If the witness key is lost:** restored anchors still verify against the trust list, but no new checkpoint can be
cosigned. With anchoring required in production, checkpoints are then held (ANCHOR-1) until a witness is available.
Provisioning a NEW witness key needs a trust-list update and a re-baseline acknowledged by the witness
(`rebaselineAck`); that is an operator decision with audit-trail implications, not a routine recovery step.

### 3A.2 Backup scheduling — off-peak only (pilot)

Run backups off-peak: a backup that runs during peak traffic can slow request handling, and no claim is made that concurrent backups keep latency within any bound.

**Control:** set `QODIQA_BACKUP_WINDOW_UTC="HH:MM-HH:MM"` (UTC, end exclusive, may wrap midnight) in the backup jobs'
environment.
- `scripts/dr/backup.js` and `scripts/pg-backup.sh full|incremental` refuse to START outside it, loudly: exit 1,
  `BACKUP_OUTSIDE_WINDOW`, alert, failure metric. A schedule that drifts out of the window is therefore seen, never
  silently skipped.
- A malformed value is refused.
- `QODIQA_BACKUP_WINDOW_OVERRIDE=true` runs one deliberately and is logged.
- Unset = no restriction (non-pilot behaviour unchanged).

**Pilot settings:**
- Agree a no-contracted-traffic window with the partners, e.g. `02:00-05:00`, and set it.
- Schedule `qodiqa-dr-backup` and the pg-backup timers inside it. The shipped `qodiqa-dr-backup.timer` is `hourly` and
  the Kubernetes CronJob `0 * * * *`. For the pilot, override them to daily inside the window. That changes the RPO from
  1 h to 24 h for the DR backup — **design decision**.
- `scripts/backup-audit-log.sh` (every 5 minutes) is NOT window-guarded today. It copies and gzips the WHOLE audit log
  each run (3 GB at pilot scale), which is continuous heavy I/O during contracted traffic. Tracked as : make
  it incremental (append-only copy of the new bytes), or confine it to the window and accept a longer RPO for the file
  copy. The PostgreSQL mirror, written synchronously with every append, still holds the chain between backups.

---

## 3. Full System Restore

A full system restore is required after complete infrastructure loss. Execute the steps in this exact order.

### 3.1 Stop All QODIQA Instances

```bash
# Kubernetes (single-node overlay: StatefulSet qodiqa)
kubectl scale statefulset/qodiqa --replicas=0 -n qodiqa
kubectl get pods -n qodiqa  # Verify no pods running

# Docker
docker compose -f deploy/docker/docker-compose.prod.yml stop qodiqa
```

### 3.2 Restore PostgreSQL Database

See [Section 5](#5-database-restore) for the complete database restore procedure. Execute it now before restoring any application files.

```bash
# Summary: restore PostgreSQL from the latest clean backup. pg-backup.sh writes encrypted, sealed dumps to
# ${QODIQA_BACKUP_DIR}/full/<daily|weekly|monthly>/qodiqa_<timestamp>.dump.enc (+ .seal beside each);
# QODIQA_BACKUP_DIR defaults to /var/backups/qodiqa (the Kubernetes backup ConfigMap sets /backups/pg).
ls -t "${QODIQA_BACKUP_DIR:-/var/backups/qodiqa}"/full/*/*.dump.enc | head -5
# Full procedure in Section 5
```

### 3.3 Restore Key Store

```bash
# Identify the key store backup corresponding to the backup timestamp
# Key store backups are in /opt/qodiqa/backups/keys/
KEYS_BACKUP=$(ls -t /opt/qodiqa/backups/keys/keys-*.json | head -1)
echo "Restoring key store from: $KEYS_BACKUP"

# Verify the backup is valid JSON
jq . "$KEYS_BACKUP" > /dev/null || { echo "FATAL: Key backup is not valid JSON"; exit 1; }

# Restore the key store
cp "$KEYS_BACKUP" "$QODIQA_KEYS_PATH"
echo "Key store restored"
```

### 3.4 Restore Audit Log File

```bash
# Identify the audit log backup corresponding to the backup timestamp
# Use the backup closest to (but before) the PostgreSQL backup timestamp
AUDIT_BACKUP=$(ls -t /opt/qodiqa/backups/audit/audit-*.log.gz | head -1)
echo "Restoring audit log from: $AUDIT_BACKUP"

# Decompress to restore location
gzip -d -c "$AUDIT_BACKUP" > "$QODIQA_AUDIT_LOG"

# Verify the restored audit log
ENTRY_COUNT=$(wc -l < "$QODIQA_AUDIT_LOG")
echo "Audit log restored: $ENTRY_COUNT entries"

# Verify last entry is valid JSON
tail -1 "$QODIQA_AUDIT_LOG" | jq '.hash' && echo "Last entry valid JSON: OK"
```

### 3.5 Restore Configuration

Policies are **not** restored from a file. the enforced policy set lives in the PostgreSQL control plane
(`control_plane_records`, see [Control plane](control-plane.md)), so it comes back with the database restore in §3.2.
`POLICY_FILE` is only an import source for the one-time control-plane import (`scripts/controlPlane/import.js`); copying
a file over it changes nothing that is enforced, and `SIGHUP` re-derives the enforced set from the control plane, not
from the file.

```bash
# Restore environment (re-inject secrets from secrets management system)
# Secrets are not backed up to disk — retrieve from Vault/AWS Secrets Manager
```

### 3.6 Restore Certificates

```bash
CERT_BACKUP_DIR=$(ls -td /opt/qodiqa/backups/certs/certs-*/ | head -1)
echo "Restoring certificates from: $CERT_BACKUP_DIR"

cp "${CERT_BACKUP_DIR}/redis-client.crt" "$REDIS_TLS_CERT"
cp "${CERT_BACKUP_DIR}/redis-client.key" "$REDIS_TLS_KEY"
cp "${CERT_BACKUP_DIR}/redis-ca.crt" "$REDIS_TLS_CA"

[[ "$QODIQA_PG_SSL" == "true" ]] && {
  cp "${CERT_BACKUP_DIR}/pg-client.crt" "$QODIQA_PG_SSL_CERT"
  cp "${CERT_BACKUP_DIR}/pg-client.key" "$QODIQA_PG_SSL_KEY"
  cp "${CERT_BACKUP_DIR}/pg-ca.crt" "$QODIQA_PG_SSL_CA"
}
echo "Certificates restored"
```

### 3.7 Start Infrastructure Services

```bash
# Start Redis
docker compose -f deploy/docker/docker-compose.prod.yml up -d redis
# redis-cli takes the password from REDISCLI_AUTH (exported from your secret store) — never -a <password> or a
# password inside REDIS_URL, both of which land in argv and shell history.
# Wait for Redis health
until redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" PING 2>/dev/null | grep -q PONG; do
  echo "Waiting for Redis..."
  sleep 2
done
echo "Redis: READY"
```

### 3.8 Start QODIQA

```bash
# Kubernetes — replicas 1 is the only supported count (single-node StatefulSet)
kubectl scale statefulset/qodiqa --replicas=1 -n qodiqa
kubectl rollout status statefulset/qodiqa -n qodiqa --timeout=120s

# Docker
docker compose -f deploy/docker/docker-compose.prod.yml up -d qodiqa
```

### 3.9 Full Restore Validation

Proceed to [Section 10 — Post-Restore Validation](#10-post-restore-validation).

---

## 4. Partial Restore

A partial restore recovers a specific table or data set without replacing the entire database.

> ** Extraction databases follow §5's rules:** create the scratch database
> `OWNER qodiqa_test`, seal-check the backup first (`./scripts/pg-backup.sh verify`), restore as `qodiqa_test`
> (never `qodiqa_app`, never `postgres`), and connect with `PGHOST`/`PGPORT` from your environment, never a literal
> `localhost:5432`. `pg-backup.sh` writes encrypted `*.dump.enc` files with a `.seal`, which `pg_restore --table` cannot
> read directly, so the backup is restored **in full into the scratch database** with `./scripts/pg-backup.sh restore`
> (it decrypts, refuses a superuser, and fails closed on a bad seal) and the needed table/rows are then read from there.
> The earlier `OWNER qodiqa_app` / `--no-owner --no-acl` / `.dump.gz` steps are superseded; they remain in git history.
>
> **What `verify` checks (re-verified against `scripts/pg-backup.sh` `run_verify`/`run_restore`, 2026-10-06).**
> `./scripts/pg-backup.sh verify [tier]` takes **no file argument**: it checks only the **newest** backup in
> `${QODIQA_BACKUP_DIR}/full` (or `full/<tier>`) — seal, decryption, `pg_restore --list` and table coverage. It says
> nothing about an older `$BACKUP_FILE` you chose. `./scripts/pg-backup.sh restore "$BACKUP_FILE"` verifies the
> **chosen** file's seal itself (and decrypts it) before restoring anything, and refuses on a mismatch, so for a chosen
> older file that built-in check is the seal check; run `verify` as well only to confirm the backup set as a whole.

### 4.1 Restore a Specific Table from Full Backup

```bash
# Example: restore the transparency_log_entries table

BACKUP_FILE="<chosen .dump.enc; its .seal beside it>"
TABLE="transparency_log_entries"
./scripts/pg-backup.sh verify            # newest backup only; restore below re-checks the CHOSEN file's seal

# Create a temporary database for selective extraction
psql -U postgres -c "CREATE DATABASE qodiqa_extract OWNER qodiqa_test;"

# Restore the (encrypted) backup into the temporary database as qodiqa_test
echo RESTORE | PGHOST="${PGHOST}" PGPORT="${PGPORT}" PGUSER=qodiqa_test PGPASSWORD="${QODIQA_PG_TEST_PASSWORD}" \
  PGDATABASE=qodiqa_extract ./scripts/pg-backup.sh restore "$BACKUP_FILE"

# Verify the extracted table
psql -U postgres -d qodiqa_extract -c "SELECT COUNT(*), MAX(created_at) FROM $TABLE;"

# Determine the insertion point — what's the last entry id in production?
# (transparency_log_entries has no sequence_number column; its ordering key is the BIGSERIAL primary key `id`,
#  migration 011)
psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -c "SELECT MAX(id) FROM $TABLE;"

# Insert missing rows from the extract into production
# (only rows with an id greater than what production already has)
psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -c "
  INSERT INTO $TABLE
  SELECT * FROM dblink(
    'dbname=qodiqa_extract user=qodiqa_test',
    'SELECT * FROM $TABLE'
  ) AS t(/* column definitions */)
  ON CONFLICT (id) DO NOTHING;
"

# Clean up
psql -U postgres -c "DROP DATABASE qodiqa_extract;"
```

### 4.2 Restore a Deleted Row

```bash
# For a row deleted from a non-immutable table:
BACKUP_FILE="<chosen .dump.enc; its .seal beside it>"
ROW_ID="your-evidence-package-id"        # evidence_packages.id (UUID)
./scripts/pg-backup.sh verify            # newest backup only; restore below re-checks the CHOSEN file's seal

# Extract to temporary database (as qodiqa_test; never qodiqa_app, never postgres)
psql -U postgres -c "CREATE DATABASE qodiqa_extract OWNER qodiqa_test;"
echo RESTORE | PGHOST="${PGHOST}" PGPORT="${PGPORT}" PGUSER=qodiqa_test PGPASSWORD="${QODIQA_PG_TEST_PASSWORD}" \
  PGDATABASE=qodiqa_extract ./scripts/pg-backup.sh restore "$BACKUP_FILE"

# Extract the specific row
psql -U postgres -d qodiqa_extract -c \
  "SELECT * FROM evidence_packages WHERE id = '$ROW_ID';" \
  --csv > /tmp/restore-row.csv

# Review before inserting into production
cat /tmp/restore-row.csv

# Insert after review
psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -c "\COPY evidence_packages FROM '/tmp/restore-row.csv' CSV HEADER;"

psql -U postgres -c "DROP DATABASE qodiqa_extract;"
```

**Note:** The `audit_chain` and `transparency_log_entries` tables are append-only for the application role by GRANT (it holds SELECT/INSERT only), and `audit_chain` additionally carries migration 076's guard trigger (UPDATE/DELETE/TRUNCATE refused for every role without a declared maintenance intent). If rows are missing from these tables (which should not happen under normal operations), see the Audit Chain Restore (Section 6) and Transparency Recovery (Section 48.11) procedures.

---

## 5. Database Restore

> **[ER, 2026-10-06] This section was rewritten.** The previous §5.1–§5.4 restored **as `qodiqa_app` with
> `--no-owner --no-acl`**, which would have made the application role own every table (so it could disable RLS),
> dropped every grant, expected a `.dump.gz` format `pg-backup.sh` no longer writes, and recreated `qodiqa` in place.
> It is superseded by the procedure below, which was exercised end to end on a migrated copy of LIVE
> (
>). The previous text remains in git history.

**Rules.**
- Restore **into a new database**, validate, then switch the application. Never `DROP DATABASE qodiqa` before a validated restore exists.
- Restore **as `qodiqa_test`** (the bootstrap/migration identity). **Never as a superuser:** `pg-backup.sh restore` uses `pg_restore --no-owner`, so the restoring role owns every restored object, including all SECURITY DEFINER functions; the script refuses a superuser unless `QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE=true` (throwaway targets only). **Never as `qodiqa_app`.**
- Encrypted backups only (`QODIQA_BACKUP_REQUIRE_ENCRYPTION=true`); the seal must verify before anything is restored.
- The restoring role must be the bootstrap/migration identity (`qodiqa_test`). It must own the bootstrap default
  privileges and be able to `SET ROLE qodiqa_mig`. A role that only owns the target database fails on
  `ALTER DEFAULT PRIVILEGES FOR ROLE …` *after* all data is loaded and *before* any GRANT is applied (measured,
  phase 13/14). `pg-backup.sh` then logs `RESTORE_FAILED` and alerts that the target is INCOMPLETE.
  **Discard that database. Never point the application at it.**

### 5.1 Pre-Restore Preparation

```bash
# Stop QODIQA (mandatory)
kubectl scale statefulset/qodiqa --replicas=0 -n qodiqa
kubectl get pods -n qodiqa  # Confirm zero pods

# Keys from custody (never from the cluster being restored): QODIQA_BACKUP_ENCRYPTION_KEY, QODIQA_BACKUP_HMAC_KEY
export QODIQA_BACKUP_REQUIRE_ENCRYPTION=true
ls -lt "${QODIQA_BACKUP_DIR}"/full/*.dump.enc "${QODIQA_BACKUP_DIR}"/full/*/*.dump.enc 2>/dev/null | head -10
BACKUP_FILE="<chosen .dump.enc preceding the failure>"   # its .seal must sit beside it

# Seal + decryptability + table coverage of the NEWEST backup in full/ (or in full/<tier> with a tier argument).
# It does not check an older ${BACKUP_FILE}; `restore` below verifies the chosen file's seal itself and refuses on a
# mismatch.
./scripts/pg-backup.sh verify daily      # expect BACKUP_SEAL_OK and BACKUP_VERIFY_OK
```

`verify` also fails when the newest backup is older than its tier's limit (daily 26 h, weekly 8 d, monthly 32 d;
`QODIQA_BACKUP_MAX_AGE_SECONDS` overrides, `0` disables). When verifying a backup fetched from off-site storage for a
restore, run `QODIQA_BACKUP_MAX_AGE_SECONDS=0 ./scripts/pg-backup.sh verify <tier>`. `BACKUP_VERIFY_OK` reports the
dump's `dbname`, `serverVersion` and `pgDumpVersion`. Confirm they are the expected database, and that the restoring
`pg_restore` is at least `pgDumpVersion`.

### 5.2 Restore Into a New Database and Validate

```bash
NEW_DB="qodiqa_restored_$(date +%Y%m%d%H%M)"
psql -U postgres -c "CREATE DATABASE ${NEW_DB} OWNER qodiqa_test;"
# If restoring as qodiqa_test fails with "permission denied for schema public" on an OWNER TO qodiqa_mig
# statement (raw pg_restore without --no-owner), first run, as qodiqa_test in NEW_DB:
#   GRANT CREATE ON SCHEMA public TO qodiqa_mig;

# Password from a 0600 PGPASSFILE holding the qodiqa_test line — never typed on the command line.
echo RESTORE | PGHOST=<host> PGPORT=<port> PGUSER=qodiqa_test PGPASSFILE=<path to 0600 pgpass> PGDATABASE="${NEW_DB}" \
  ./scripts/pg-backup.sh restore "${BACKUP_FILE}"     # expect RESTORE_START … RESTORE_COMPLETE

# Validate before switching:
psql -d "${NEW_DB}" -c "SELECT count(*), max(version) FROM qodiqa_migrations;"   # equals the source
psql -d "${NEW_DB}" -c "SELECT pg_get_userbyid(proowner), count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND prosecdef GROUP BY 1;"   # qodiqa_test only — never a superuser
# PM-01 canonical privilege comparison (test/integration/privilegeRls.integration.test.js;
# with OA3_PG_DATABASE="${NEW_DB}"): expect only the differences recorded for the source (after qodiqa_read login:false)
# Audit chain: run the chain verifier against the restored mirror (Section 6 / Section 10)
```

### 5.3 Switch Over

Point the application at the validated database (`QODIQA_PG_DATABASE="${NEW_DB}"`), or — only with explicit owner
approval, because it is destructive — rename the old database aside and the restored one into place:

```bash
psql -U postgres -c "ALTER DATABASE qodiqa RENAME TO qodiqa_pre_restore_$(date +%Y%m%d%H%M);"   # keep, do not drop
psql -U postgres -c "ALTER DATABASE ${NEW_DB} RENAME TO qodiqa;"
kubectl scale statefulset/qodiqa --replicas=1 -n qodiqa   # 1 is the only supported count
```

### 5.4 Post-Restore Checks

```bash
psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -c "VACUUM ANALYZE;"
node scripts/db/role-credentials.js --check            # no role accepts its published placeholder
# Readiness: GET /ready must report PostgreSQL and the audit mirror healthy (Section 10)
```

### 5.5 Point-in-Time Restore from Continuous WAL Archive

> **NOT SUPPORTED IN PRODUCTION.** Point-in-time restore needs a physical base backup, and
> the only producer of one, `./scripts/pg-backup.sh incremental` (`pg_basebackup`), is disabled: it logs
> `BACKUP_INCREMENTAL_UNSUPPORTED` and exits 2, and the `qodiqa-pg-backup-incremental` CronJob ships with
> `suspend: true` (`deploy/kubernetes/base/backup-cronjobs.yaml`). `pg_basebackup` needs the `REPLICATION` attribute on
> `qodiqa_backup`, which is deliberately not granted (design decision; see
> [Database role management — backup role](database-role-management.md)). Until an administrator grants
> it and re-enables the job, there is no base backup for `pitr-restore` to start from, and the recovery points are the
> daily/weekly/monthly full backups only (§5.2). The procedure below is kept for that future decision; do not plan an
> RPO on it.

Use this instead of §5.2/§5.3 when you need to recover to a specific point
in time (e.g., "just before the bad migration ran") rather than the most
recent full backup — continuous WAL archiving
([Backup Runbook §3.5](backup-runbook.md#35-continuous-wal-archiving))
makes this possible down to a 5-minute granularity instead of only the
daily/weekly/monthly full-backup boundaries.

```bash
# 1. Prepare a fresh PGDATA directory from the most recent base backup plus
#    archived WAL — this step is prepare-and-instruct, not fully
#    orchestrated (see scripts/pg-backup.sh's header comment for why
#    PostgreSQL process lifecycle stays operator-owned throughout this repo).
LATEST_BASEBACKUP=$(ls -t "${QODIQA_BACKUP_DIR:-/var/backups/qodiqa}/wal"/*.tar.gz | head -1)

./scripts/pg-backup.sh pitr-restore \
  "${LATEST_BASEBACKUP}" \
  /var/lib/postgresql/pitr-restore \
  "2026-07-21 14:30:00 UTC"     # or "latest" to replay every archived segment

# 2. Start PostgreSQL against the prepared directory (exact command printed
#    by the script above):
pg_ctl -D /var/lib/postgresql/pitr-restore -l /var/lib/postgresql/pitr-restore/recovery.log start

# 3. Monitor WAL replay
tail -f /var/lib/postgresql/pitr-restore/recovery.log

# 4. Once promoted (recovery.signal is removed automatically by PostgreSQL),
#    run the same post-restore repair and validation as §5.4 and §9/§10 below.
```

**Never point this at a live, in-use PGDATA directory** — `pitr-restore`
refuses to write into a target that already exists, matching this repo's
"never restore over an existing instance" convention used throughout
`scripts/dr/restore.js`.

---

## 6. Audit Chain Restore

**Applies to single-node/file-authoritative deployments only.** In
distributed mode there is no local `audit.log` file to restore — the
authoritative `audit_chain` table is restored and cryptographically
re-verified as part of the normal PostgreSQL restore (Section 5) via
`scripts/dr/restore.js`'s mode-aware integrity gate; nothing in this
section applies. See [Backup → Restore Validation
§4.3](backup-restore-validation.md#43-distributed-mode-audit-chain-restore)
for the distributed-mode restore procedure.

### 6.1 File Restore

```bash
AUDIT_LOG="${QODIQA_AUDIT_LOG:-/opt/qodiqa/logs/audit.log}"

# Stop QODIQA (mandatory — cannot restore audit log while process is running)
kubectl scale statefulset/qodiqa --replicas=0 -n qodiqa

# Identify the correct backup
ls -lt /opt/qodiqa/backups/audit/audit-*.log.gz | head -10
AUDIT_BACKUP="/opt/qodiqa/backups/audit/audit-20260703-120000.log.gz"

# Restore the audit log file
gzip -d -c "$AUDIT_BACKUP" > "$AUDIT_LOG"

# Restore the companion files if backed up
# WAL file: only if it corresponds to the same backup timestamp
# Sum file: will be recomputed on startup from the restored audit.log

# Verify line count
LINE_COUNT=$(wc -l < "$AUDIT_LOG")
echo "Audit log restored: $LINE_COUNT entries"

# Verify the first entry (genesis)
head -1 "$AUDIT_LOG" | jq '{hash, prevHash, timestamp}'
# Expected: {"hash": "...", "prevHash": "GENESIS", "timestamp": "..."}

# Verify the last entry
tail -1 "$AUDIT_LOG" | jq '{hash, prevHash, artifactId, decision}'
```

### 6.2 Rebuilding the PostgreSQL Audit Chain Replica from the File

After restoring the file, the PostgreSQL `audit_chain` mirror can be out of sync with it. Startup does **not**
resynchronise it: the mirror count reconciler (`src/core/audit/mirrorCountReconciler.js`, at boot and every 6 h) and
the mirror consistency check only **report** drift; they never repair it.

> ** This procedure was replaced.** It previously ran
> `TRUNCATE TABLE audit_chain CASCADE` as `postgres` and re-inserted rows with a hand-written 10-column INSERT. On any
> database at migration 076 or later, TRUNCATE/UPDATE/DELETE on `audit_chain` is refused for every role unless the
> transaction declares an allowed maintenance intent (`prune`, `rebuild`, `fixture`), and the hand-written INSERT
> omitted the v7 columns (075) and the mirror counter (073), so the mirror would diverge even with the guard bypassed.
> The previous text remains in git history.

Stop QODIQA first. Then:

```bash
# 1. Never TRUNCATE audit_chain by hand and never hand-insert rows.
#
# 2. Missing rows (file ahead of the mirror): backfill with the idempotent, INSERT-only importer, which projects
#    entries through the same mirror projection the server uses (ON CONFLICT DO NOTHING). It also imports the other
#    file stores it is pointed at, so review its dry run first.
QODIQA_AUDIT_LOG=<restored audit.log> node scripts/migrate-files-to-pg.js --dry-run
QODIQA_AUDIT_LOG=<restored audit.log> node scripts/migrate-files-to-pg.js
#
# 3. Ordering: check that the mirror's seq order equals the hash-chain order, and re-sequence only if the check
#    fails. The --apply path is the declared `rebuild` maintenance intent migration 076 requires; it needs a
#    BYPASSRLS identity (QODIQA_PG_ADMIN_USER / QODIQA_PG_ADMIN_PASSWORD) - see the script header.
node scripts/audit-mirror-rebuild.js --database <db>                                   # read-only check
node scripts/audit-mirror-rebuild.js --database <db> --apply --confirm-database <db>   # only if the check fails
#
# 4. If the mirror holds rows that are NOT in the restored file (the file is behind the mirror), do not delete them:
#    restore the database from the matching backup instead (Section 5).
```

### 6.3 Audit Chain Integrity Verification

After restore, QODIQA verifies chain integrity on startup. Additionally:

```bash
# Verify hash chain continuity in the restored file
node -e "
const fs = require('fs');
const crypto = require('crypto');
const lines = fs.readFileSync(process.env.QODIQA_AUDIT_LOG, 'utf8')
  .split('\n').filter(Boolean)
  .map(l => JSON.parse(l));

let valid = true;
for (let i = 1; i < lines.length; i++) {
  if (lines[i].prevHash !== lines[i-1].hash) {
    console.error('Hash chain broken at entry', i, ':', lines[i].hash);
    valid = false;
    break;
  }
}
console.log(valid ? 'Audit chain VALID' : 'Audit chain BROKEN');
console.log('Entries verified:', lines.length);
process.exit(valid ? 0 : 1);
"
```

---

## 7. Artifact Restore

Signed artifacts are stored in the PostgreSQL database. If a specific artifact is missing (corrupted or accidentally deleted from evidence tables):

```bash
# Restore a specific evidence package
# Extraction follows Section 5's identity rules (see the note in Section 4).
EVIDENCE_ID="ev-abc123"
BACKUP_FILE="<chosen .dump.enc; its .seal beside it>"
./scripts/pg-backup.sh verify            # newest backup only; restore below re-checks the CHOSEN file's seal

# Extract to temporary DB (as qodiqa_test; never qodiqa_app, never postgres)
psql -U postgres -c "CREATE DATABASE qodiqa_extract OWNER qodiqa_test;"
echo RESTORE | PGHOST="${PGHOST}" PGPORT="${PGPORT}" PGUSER=qodiqa_test PGPASSWORD="${QODIQA_PG_TEST_PASSWORD}" \
  PGDATABASE=qodiqa_extract ./scripts/pg-backup.sh restore "$BACKUP_FILE"

# Verify the evidence package exists in the backup (evidence_packages: primary key `id`, timestamp `generated_at`)
psql -U postgres -d qodiqa_extract -c \
  "SELECT id, generated_at FROM evidence_packages WHERE id = '$EVIDENCE_ID';"

# Restore to production
psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -c "
  INSERT INTO evidence_packages
  SELECT * FROM dblink(
    'host=${PGHOST} port=${PGPORT} dbname=qodiqa_extract user=qodiqa_test',
    'SELECT * FROM evidence_packages WHERE id = ''$EVIDENCE_ID'''
  ) AS t(id UUID, -- add all column definitions
    )
  ON CONFLICT (id) DO NOTHING;
"

psql -U postgres -c "DROP DATABASE qodiqa_extract;"
```

---

## 8. Configuration Restore

### 8.1 Environment Variable Restore

Retrieve from secrets management system (not from disk backups):

```bash
# HashiCorp Vault
vault kv get -format=json secret/qodiqa/production > /tmp/qodiqa-env.json
jq -r '.data.data | to_entries[] | "\(.key)=\(.value)"' /tmp/qodiqa-env.json > /etc/qodiqa/env
rm /tmp/qodiqa-env.json
chmod 600 /etc/qodiqa/env
echo "Environment restored from Vault"

# AWS Secrets Manager
aws secretsmanager get-secret-value \
  --secret-id qodiqa/production/env \
  --query SecretString \
  --output text | jq -r 'to_entries[] | "\(.key)=\(.value)"' > /etc/qodiqa/env
```

### 8.2 Key Store Restore

```bash
KEYS_BACKUP=$(ls -t /opt/qodiqa/backups/keys/keys-*.json | head -1)
cp "$KEYS_BACKUP" "$QODIQA_KEYS_PATH"
chmod 600 "$QODIQA_KEYS_PATH"
echo "Key store restored from: $(basename $KEYS_BACKUP)"

# Verify the file decrypts with the current KEK (QODIQA verifies this on startup).
# You can pre-validate with the automated DR key-store probe, which loads the
# restored file through the real key store module and (with the KEK present)
# performs a full Ed25519 sign+verify round-trip:
QODIQA_KEYS_PATH="$QODIQA_KEYS_PATH" \
  node scripts/dr/probes/keyStoreProbe.js
# Exit code 0 and "valid":true means the restored key store loads, its
# structural invariants hold, and every active key signs+verifies correctly.
```

### 8.3 Policy File Restore

**Superseded (see `server/startup.js` and [Control plane](control-plane.md)).**
the enforced policy set is control-plane state in PostgreSQL (`control_plane_records`) and is restored with the
database (Section 5). `POLICY_FILE` is an import source only: copying a backup over it does not change what is
enforced, and `SIGHUP` re-derives the enforced set from the control plane (log `POLICIES_RELOADED`,
`source: control-plane`), it does not re-read the file. Policy changes after a restore go through the policy API
(`/policy-ui/policies`, `/v1/policy/governance`), never through the file.

---

## 9. Consistency Verification

After any restore, verify consistency across all QODIQA data stores.

### 9.1 Audit Chain vs PostgreSQL Consistency

```bash
# Count entries in file vs database
FILE_COUNT=$(wc -l < "$QODIQA_AUDIT_LOG")
PG_COUNT=$(psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -t -c "SELECT COUNT(*) FROM audit_chain;" | tr -d ' \n')

echo "Audit log file entries: $FILE_COUNT"
echo "PostgreSQL audit_chain rows: $PG_COUNT"

if [[ $FILE_COUNT -ne $PG_COUNT ]]; then
  echo "WARNING: Audit chain file ($FILE_COUNT) and PostgreSQL replica ($PG_COUNT) differ"
  echo "The file is authoritative. The PostgreSQL replica may need rebuild."
  # Rebuild per Section 6.2
fi
```

### 9.2 Transparency Log Completeness

```bash
# Verify the transparency log has no id gaps (ordering key: BIGSERIAL primary key `id`, migration 011 — there is no
# sequence_number column). A BIGSERIAL can skip values after a rolled-back insert, so a non-zero result is a lead
# for the gap scanner (Transparency Recovery §3.1), not proof of loss by itself.
psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -c "
  WITH numbered AS (
    SELECT id,
           LAG(id) OVER (ORDER BY id) AS prev
    FROM transparency_log_entries
  )
  SELECT COUNT(*) AS gaps
  FROM numbered
  WHERE prev IS NOT NULL AND id != prev + 1;
"
# Expected: gaps = 0
```

### 9.3 Key Store vs JWKS Endpoint Consistency

After QODIQA starts, verify the JWKS endpoint matches the restored key store:

```bash
# Get active key ID from key store
ACTIVE_KEY_ID=$(jq -r '.keys[] | select(.status == "active") | .keyId' "$QODIQA_KEYS_PATH")
echo "Key store active key: $ACTIVE_KEY_ID"

# Get active key ID from JWKS endpoint
JWKS_KEY_ID=$(curl -sf http://localhost:3000/.well-known/qodiqa/keys | jq -r '.keys[0].kid')
echo "JWKS active key: $JWKS_KEY_ID"

[[ "$ACTIVE_KEY_ID" == "$JWKS_KEY_ID" ]] && \
  echo "Key ID consistency: OK" || \
  echo "MISMATCH: key store vs JWKS — investigate immediately"
```

### 9.4 Policy Consistency

There is no `/policy/status` endpoint, and `POLICY_FILE` is not what is enforced (§8.3). Check the enforced set
through the authenticated policy API instead, and compare it with what the restored database should hold:

```bash
# Policies as the running instance sees them (operator API key with READ_POLICIES; header read from a 0600 file)
curl -sf -H @"$OPS_AUTH_HEADER_FILE" http://localhost:3000/policy-ui/policies | jq .
# The boot / SIGHUP log line POLICIES_RELOADED carries the enforced count (source: control-plane)
```

---

## 10. Post-Restore Validation

Run after every restore operation, before returning to production traffic.

### 10.1 System Health Checks

```bash
curl -sf http://localhost:3000/health && echo "Liveness: OK"
curl -sf http://localhost:3000/ready && echo "Readiness: OK"
# /metrics is ops-authenticated (src/app.js:179): Authorization header read from a 0600 file (Section 1 conventions)
INTEGRITY=$(curl -sf -H @"$OPS_AUTH_HEADER_FILE" http://localhost:3000/metrics | grep '^qodiqa_execution_integrity_full' | awk '{print $NF}')
echo "Integrity metric: $INTEGRITY"  # Expected: 1
```

### 10.2 Smoke Test Suite

No smoke-test script ships in the repository. Run the eight smoke tests of
[Deployment Runbook §8.1](deployment-runbook.md#81-core-endpoint-smoke-tests) by hand against the restored instance;
all must PASS before returning to traffic.

### 10.3 Audit Chain Continuity Confirmation

```bash
# Verify the audit chain is valid after restore, using the automated DR probe.
# It loads the restored NDJSON file through the real audit-log module (which
# replays the WAL and validates the anti-deletion checksum on load) and runs
# validateChainIntegrity() — synchronous, no async wrapper.
QODIQA_AUDIT_LOG="$QODIQA_AUDIT_LOG" \
  node scripts/dr/probes/auditChainProbe.js
# Prints a JSON report; exit code 0 and "valid":true means the chain is
# continuous and untampered. "tamperingDetected":true means a hash-chain
# break or checksum mismatch was found in the restored file.
```

For a single command that runs all three integrity probes (audit chain, key
store, policy store) against a restored target directory, use the automated
validator instead:

```bash
node scripts/dr/validate.js /path/to/restored/root
# Exit 0 iff every probe reports valid:true.
```

### 10.4 Restore Documentation

Document every restore operation:

```bash
cat >> /opt/qodiqa/logs/restore-history.log << EOF
=== RESTORE EVENT ===
Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Operator: ${OPERATOR_NAME:-unknown}
Scope: ${RESTORE_SCOPE:-unknown}
Backup used: ${BACKUP_FILE:-unknown}
Incident ref: ${INCIDENT_REF:-N/A}
Audit chain entries after restore: $(wc -l < "$QODIQA_AUDIT_LOG")
PG audit_chain rows: $(psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -t -c "SELECT COUNT(*) FROM audit_chain;")
Smoke tests: PASS/FAIL
======================
EOF
```

---

*Cross-references: [Backup Runbook](backup-runbook.md) | [Disaster Recovery](disaster-recovery.md) | DR RTO Measurement | [Rollback Runbook](rollback-runbook.md) | [Transparency Recovery](transparency-recovery.md) | Audit Chain Architecture*
