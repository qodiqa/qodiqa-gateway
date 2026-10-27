# QODIQA Backup → Restore Validation

**Operations & Production Readiness**

| Field | Value |
|-------|-------|
| Document | Backup → Restore Validation |
| Version | 1.0.0 |
| Owner | Platform Engineering / SRE |
| Audience | SRE, Platform Engineer, On-Call, CI |
| Classification | Internal — Operational |
| Last Updated | 2026-07-06 |

---

## Table of Contents

1. [Overview](#1-overview)
2. [Supported Backup Components](#2-supported-backup-components)
3. [Backup Procedure](#3-backup-procedure)
4. [Restore Procedure](#4-restore-procedure)
5. [Validation Procedure](#5-validation-procedure)
6. [Integrity Verification](#6-integrity-verification)
7. [Failure Scenarios](#7-failure-scenarios)
8. [Rollback Behavior](#8-rollback-behavior)
9. [Disaster Recovery Cycle](#9-disaster-recovery-cycle)
10. [CI Validation](#10-ci-validation)
11. [Exit Criteria](#11-exit-criteria)
12. [Operational Recommendations](#12-operational-recommendations)

---

## 1. Overview

QODIQA ships an automated **Backup → Restore validation framework** that proves a
complete deployment can be backed up and restored into a clean environment
**without any loss of cryptographic validity, protocol correctness, audit-chain
integrity, or operational state.**

This is deliberately *not* a bare backup tool. Every restore is followed by a
**functional validation pass** that loads the restored files through the *real*
production modules (`src/core/audit/audit-log.js`, `policy/policyStore.js`,
`services/artifact/keyStore.js`) — the same code a live server runs at startup —
and confirms the restored state is genuinely operational, not merely
byte-identical.

The framework lives under `scripts/dr/` and is exposed through npm scripts:

| npm script | Underlying command | Purpose |
|------------|-------------------|---------|
| `npm run dr:backup`   | `node scripts/dr/backup.js`   | Create a backup |
| `npm run dr:restore`  | `node scripts/dr/restore.js`  | Restore a backup into a clean target |
| `npm run dr:validate` | `node scripts/dr/validate.js` | Validate a restored target |
| `npm run dr:cycle`    | `node scripts/dr/cycle.js`    | Full backup → restore → validate cycle |
| `npm run dr:test`     | `jest ... backupRestore\|dr/` | File-based DR suite + offline coverage guard (no DB required) |
| `npm run dr:test:postgres` | `jest ... dr/postgresFullCoverage` | Live full-coverage proof against a real Postgres (creates/drops its own throwaway DBs) |

**Relationship to the existing runbooks.** This document covers the *automated,
CI-runnable* validation framework. The manual, operator-driven procedures for a
production incident remain in the [Backup Runbook](backup-runbook.md) and
[Restore Runbook](restore-runbook.md); the physical/logical PostgreSQL backup
tooling remains `scripts/pg-backup.sh`. This framework complements those: it is
the mechanism that continuously *proves* the DR path works, so that a real
incident is not the first time a restore is exercised.

---

## 2. Supported Backup Components

The authoritative component registry is `scripts/dr/components.js`, which resolves
every file path from the **same environment variable + default** that the owning
module itself uses — so the backup can never target a different file than the one
production actually reads.

| Component | Env var (default) | Required | Description |
|-----------|-------------------|:--------:|-------------|
| `auditLog` | `QODIQA_AUDIT_LOG` (`audit.log`) | Mode-dependent (see §2.1) | Audit Chain — authoritative NDJSON hash chain in single-node mode (spec §11); superseded by the PostgreSQL `audit_chain` table in distributed mode |
| `auditLogWal` | `QODIQA_AUDIT_LOG` + `.wal` | No | Audit Chain write-ahead log (crash recovery) |
| `auditLogSum` | `QODIQA_AUDIT_LOG` + `.sum` | No | Audit Chain anti-deletion checksum |
| `keyStore` | `QODIQA_KEYS_PATH` (`data/keys.json`) | **Yes** | Encrypted signing key store (AES-256-GCM at rest) |
| `keyArchive` | `QODIQA_KEYS_ARCHIVE_PATH` (`data/key-archive.json`) | No | Retired / rotated key archive |
| `policyStore` | `QODIQA_POLICY_STORE` (`data/policy-store.json`) | **Yes** | Policy Engine version history |
| `organizations` | `ORG_STORE_PATH` (`data/organizations.json`) | No | Organization registry (best-effort cache) |
| `tenants` | `TENANT_STORE_PATH` (`data/tenants.json`) | No | Tenant registry (best-effort cache) |

**PostgreSQL.** When `QODIQA_PG_URL`
(or `DATABASE_URL`) is set, the backup dumps **every** base table in the `public`
schema as JSON row sets via the `pg` client library (no dependency on
`pg_dump`/`pg_restore` binaries). Coverage is *discovered live* from
`information_schema.tables` at backup time (`scripts/dr/table-registry.js`'s
`discoverTables()`) — **not** a hand-maintained list — so a newly created
production table is captured automatically on the very next backup, with no
code change. As of this writing that is 55 tables spanning every data category
QODIQA persists: consent (`consent_records`, `consent_audit_log`,
`consent_scopes`), investigations (`investigations`, `investigation_artifacts`,
`investigation_audit_events`), compliance (`compliance_reports`,
`compliance_control_assessments`, `compliance_evidence_refs`, …), audit
(`audit_chain`, `platform_audit_events`, `audit_retention_policies`,
`audit_legal_holds`), security (`kms_provider_events`,
`kms_encrypted_data_keys`, `signing_keys`), operational state
(`qodiqa_alerts`, `qodiqa_incidents`, `gap_scanner_state`), and configuration
(`policies`, `policy_versions`, `organizations`, `tenants`).

The definitive table inventory — parsed statically from the migration SQL
files, so it needs no database connection — lives in
`scripts/dr/table-registry.js`'s `EXPECTED_TABLES`. Run
`node scripts/dr/table-registry.js --json` to print it. The (empty by default)
`EXCLUDED_TABLES` map is the *only* sanctioned way to opt a real table out of
backup coverage, and every entry requires a `reason` — enforced by
`test/dr/backupCoverage.test.js`, which fails the build if a table is
excluded without justification, or if the static/live inventories disagree
(schema drift).

Tables are dumped — and later restored, since restore simply replays the
manifest's table list in the order it was recorded — in a **foreign-key-safe
(parent-before-child) order**, computed once via `getRestoreOrder()`'s
topological sort over the live FK graph. After restore, every SERIAL /
BIGSERIAL / IDENTITY sequence touched by an explicit-value INSERT is
re-synced to `MAX(column) + 1`, so a subsequent DEFAULT-driven INSERT can
never collide with restored data. Restore is additive and idempotent
(`ON CONFLICT DO NOTHING`), matching the append-only nature of the audit and
transparency tables.

A dedicated post-restore probe (`scripts/dr/probes/postgresProbe.js`) verifies
three things beyond "every insert succeeded": every table's restored row
count matches what was dumped, every foreign key constraint in the restore
target is `convalidated`, and no sequence lags behind the max value of the
column it backs. `scripts/dr/validate.js` folds this probe's result into
`overallValid` whenever a backup included a Postgres component.

**Redis / Nonce Store (diagnostic only).** The nonce store is *intentionally
ephemeral* — its correctness property is "each `requestId` accepted at most once
within its TTL", and it is never a source of truth. The `--with-redis` snapshot
records only key **count** and a TTL sample as a diagnostic; it is **never
restored**. Redis durability is Redis's own responsibility (AOF/RDB persistence).
An empty nonce store after restore is safe by design: QODIQA fails closed on
nonce-store unavailability. See the header comment in `scripts/dr/redis.js`.

**Excluded by design.** HSM/KMS-managed keys (external, never in the backup),
the KEK (backed up separately via the secrets manager — see
[Backup Runbook §8](backup-runbook.md)), and the ephemeral nonce store.

**Required vs. optional.** A `Required` component that is *present* in the source
is always backed up; if it is *missing* at backup time it is recorded as absent,
and restore will **fail closed** (`REQUIRED_COMPONENT_MISSING`) rather than
silently produce an incomplete deployment. Optional components are backed up when
present and skipped without error when absent.

### 2.1 Deployment-mode-aware audit evidence

`auditLog` is **not** unconditionally required — it is required only in
**single-node** mode, where it is the audit chain's sole authoritative store.
In **distributed** mode (`QODIQA_AUDIT_ORDERING_MODE=distributed` —
`docker-compose.prod.yml`'s reference topology, and one of the two supported
Kubernetes overlays), the authoritative chain lives in PostgreSQL's
`audit_chain` table instead, and a genuinely fresh distributed deployment
**never produces a local `audit.log` file at all**., `restore.js`
treated `auditLog` as unconditionally `critical`, which meant a distributed
backup could be taken but could **never be restored** — it always failed with
`REQUIRED_COMPONENT_MISSING` for a file that was never supposed to exist
(root-caused during the production-provisioning rehearsal).

Every backup now records which source was authoritative for *that specific
backup*, in a new top-level manifest field:

| Field | Meaning |
|-------|---------|
| `auditOrderingMode` | `'single-node'` or `'distributed'` — resolved **at backup time** via `src/infra/config/deploymentMode.js`'s `getResolvedDeploymentConfig()`, the exact same resolution `server/startup.js`'s own `DEPLOYMENT_MODE_RESOLVED` boot-log event uses. Absent on a pre-H113 manifest, which `manifest.js`'s `buildManifest()` treats as `'single-node'` for full backward compatibility. |

Restore trusts this field — recorded at backup time, on whatever host/process
actually took the backup — rather than re-deriving the mode from the
*restore-time* environment, which may be a different host/process entirely.
See §4.3 for how restore enforces audit evidence per mode.

---

## 3. Backup Procedure

```bash
# Back up the currently-configured deployment into a timestamped directory:
node scripts/dr/backup.js [outputDir] [--with-postgres] [--with-redis]

# Examples:
node scripts/dr/backup.js                                  # → backups/qodiqa-backup-<ts>/
node scripts/dr/backup.js /opt/qodiqa/dr/backup-2026-07-06
node scripts/dr/backup.js /opt/qodiqa/dr/b1 --with-postgres --with-redis
```

Each backup directory is self-contained:

```
<backupDir>/
├── manifest.json        # sealed manifest — see below
├── auditLog.dat          # one .dat per present component
├── auditLogSum.dat
├── keyStore.dat
├── keyArchive.dat
├── policyStore.dat
├── pg_<table>.json       # only with --with-postgres
└── redis_nonces.json     # only with --with-redis (diagnostic)
```

### 3.1 Manifest and metadata

`manifest.json` is the single self-describing record of the backup. It carries
the metadata required by the checklist — timestamp, application version, and
protocol version — plus a per-component checksum table:

| Field | Meaning |
|-------|---------|
| `manifestVersion` | Manifest schema version (`1`) |
| `protocolVersion` | QODIQA protocol version (`v1`, spec §19.1) |
| `backupId` | UUID v4 unique to this backup event |
| `createdAt` | ISO-8601 UTC timestamp |
| `appVersion` | Application version, read from `package.json` |
| `nodeVersion` | Node.js version the backup ran under |
| `components[]` | Per-component: `name`, `present`, `required`, `relativePath`, `archiveFile`, `sha256`, `sizeBytes` |
| `postgres` / `redis` | Present only when the respective flag was used |
| `auditOrderingMode` | `'single-node'` or `'distributed'` — which source is authoritative for THIS backup's audit evidence |
| `manifestChecksum` | SHA-256 that **seals the manifest itself** |

### 3.2 Determinism

Backups are deterministic: components are always emitted in the fixed order
defined by `components.js`, and every checksum is a plain SHA-256 of the copied
file's bytes. Two backups of an unchanged source produce identical per-component
checksums — only `backupId`, `createdAt`, and the resulting `manifestChecksum`
differ (as expected for two distinct backup *events*). This property is asserted
by the test suite (`determinism` describe block).

---

## 4. Restore Procedure

```bash
# Restore a backup into a CLEAN target directory:
node scripts/dr/restore.js <backupDir> <targetRoot> [--allow-existing]
```

Restore is **fail-closed, multi-phase, and all-or-nothing**:

1. **Validation phase** (`validateComponents`) — the manifest's own integrity is
   verified first (JSON well-formedness + self-checksum), then every present
   component's archive file is checked for existence, checksum match, and size
   match. **Nothing is written to the target during this phase.**
2. **Restore phase** (`restoreComponents`) — entered *only* if the validation
   phase raised nothing. Each present component is copied to its canonical
   restore path under `targetRoot`.
3. **Postgres restore** — when the manifest has a `postgres` section, the
   dumped rows are replayed into the restore target (§4.2) *before* the next
   phase, since that phase must validate data that has actually landed, not
   whatever pre-existed in the target.
4. **Mandatory audit-chain integrity gate** — always runs, and `restore.js`
   throws (`AUDIT_CHAIN_INTEGRITY_FAILED`) rather than resolving if it fails.
   Mode-aware as of see §4.3.

### 4.1 Never restore over a running instance

Restore refuses to write into a `targetRoot` that already contains files
(`TARGET_NOT_CLEAN`), structurally enforcing the "never restore over an existing
running instance" requirement. `--allow-existing` overrides this only when an
operator has explicitly confirmed the target is safe. A pre-existing file in a
refused target is left **untouched**.

### 4.2 PostgreSQL restore target

When the manifest contains a `postgres` section, restore replays the dumped rows.
Set `QODIQA_PG_RESTORE_URL` to restore into a **separate, clean database** rather
than the live one it was dumped from — matching the "never restore over a
running instance" rule for the database component too. Without it, restore falls
back to the dump URL (an idempotent no-op via `ON CONFLICT DO NOTHING`).
`runRestore()` also accepts an explicit `pgConnectionString` option, taking
precedence over both env vars — used by callers (like `cycle.js`) that resolve
the target once and need the *same* value reused for the audit-chain gate below.

**Known limitation.** The weekly `qodiqa-dr-restore-validation` job
cannot pass with the shipped `QODIQA_PG_RESTORE_USER: qodiqa_app` (`deploy/kubernetes/base/backup-configmap.yaml`),
which lacks UPDATE on sequences (measured: `permission denied for sequence …`). The restore-target writer identity is
an open design decision. The DR JSON restore order
was wrong whenever the dump ran as `qodiqa_backup`; this is fixed by PL13-09 (`scripts/dr/table-registry.js` reads the
foreign-key graph from `pg_catalog`).

### 4.3 Distributed-mode audit-chain restore

The final restore phase — a mandatory, non-skippable gate — dispatches on the
backup manifest's own `auditOrderingMode` (§2.1), never on the restore-time
environment:

**`auditOrderingMode: 'single-node'`** (or absent — a pre-H113 manifest):
behavior is unchanged from. The restored `audit.log` file is
required to have actually been restored (`AUDIT_LOG_NOT_RESTORED` if not), then
its hash-chain linkage is verified via `scripts/dr/probes/auditChainProbe.js`
— the real `src/core/audit/audit-log.js` module, loaded fresh in a child
process, running `validateChainIntegrityFromDurableStoreChunked()`.

**`auditOrderingMode: 'distributed'`**: there is no local file to check — a
genuinely fresh distributed deployment never has one (§2.1). Instead:

1. The manifest **must** have a `postgres` section at all
   (`DISTRIBUTED_MODE_BACKUP_MISSING_POSTGRES_COMPONENT` if not — e.g. an
   operator ran a distributed-mode backup without `--with-postgres`).
2. That section **must** include a `present: true` entry for the `audit_chain`
   table specifically (`DISTRIBUTED_MODE_BACKUP_MISSING_AUDIT_TABLE` if not —
   e.g. a transient dump error for just that one table).
3. A restore-target Postgres connection string **must** be resolvable
   (`PG_CONNECTION_STRING_NOT_AVAILABLE` if not).
4. `scripts/dr/probes/auditChainPgProbe.js` then verifies the **just-restored**
   `audit_chain` rows using the **same production chain-walk function** as the
   single-node probe — `validateChainIntegrityFromDurableStoreChunked()`
   already internally dispatches to PostgreSQL when
   `QODIQA_AUDIT_ORDERING_MODE=distributed` (it is the function
   `hydrateFromPgIfDistributed()` uses at real distributed-mode server boot,
   and the same one the live audit-chain verifier's PG-authoritative path
   uses) — so no new cryptographic verification logic exists for this path;
   it is a thin bootstrap (initialize the PG connection pool, force the
   ordering mode, require the real module fresh) around code already proven
   in production.
5. The probe cross-checks the number of rows it actually loaded
   (`report.chainLength`) against the row count **the backup itself
   recorded** for `audit_chain`. A restored chain **shorter** than the backup
   recorded fails closed (`RESTORED_CHAIN_SHORTER_THAN_BACKUP`) — this
   specifically defends against `pgAuditBackend.loadChainFromPg()`'s fail-open
   hazard: it returns an **empty array**, not a thrown error, whenever the PG
   connection pool was never actually initialized, which would otherwise let
   a probe that never really connected anywhere report `entriesVerified: 0,
   valid: true` — a textbook vacuous pass. A restored chain *longer* than
   recorded is not itself a failure (the target may have received newer
   writes since the backup, in a real operational sequence) but is still
   reported.

**The authoritative distributed table is `audit_chain`** — the exact table
`qodiqa_audit_chain_full_read()` / `pgAuditBackend.loadChainFromPg()` read
(confirmed directly against `src/infra/postgres/pg-audit-backend.js` and
migration 044's SQL) — **not** `platform_audit_events`, a real but entirely
separate table (used by `src/core/audit/centralStore.js`) that has nothing to
do with the cryptographic hash chain.

### 4.4 Encryption at rest and chain heads

**Encryption.** The DR JSON backup holds every tenant's rows. `scripts/dr/archiveCrypto.js` encrypts each
archive with the exact `scripts/pg-backup.sh` scheme (openssl `enc` AES-256-CBC, PBKDF2-HMAC-SHA256, 200 000
iterations, random salt; `QODIQA_BACKUP_ENCRYPTION_KEY`) and seals the manifest with HMAC-SHA256
(`QODIQA_BACKUP_HMAC_KEY`, distinct, ≥ 32 characters, no `REPLACE_WITH` placeholder). The manifest records the
SHA-256 of every ciphertext and an `encryption` block (scheme only, never key material); `manifest.json.seal`
authenticates the manifest and therefore every ciphertext. Restore and `dr:verify` check the seal first, then each
ciphertext's checksum, then decrypt; a wrong key, an edited manifest (even with a recomputed `manifestChecksum`), a
flipped ciphertext byte or a missing seal fails closed (`BACKUP_SEAL_MISMATCH`, `CHECKSUM_MISMATCH` /
`ARCHIVE_CHECKSUM_MISMATCH`, `BACKUP_SEAL_MISSING`, `BACKUP_KEYS_MISSING`). Plaintext is refused under
`QODIQA_BACKUP_REQUIRE_ENCRYPTION=true` or `NODE_ENV=production` unless `QODIQA_BACKUP_ALLOW_PLAINTEXT=true` (logged
`BACKUP_PLAINTEXT_OVERRIDE`; never lifts an explicit require). Any archive can be decrypted without QODIQA code:
`openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -pass env:QODIQA_BACKUP_ENCRYPTION_KEY -in pg_<table>.json.enc`.
Tests: `test/dr/drBackupEncryption.test.js`, `test/dr/chainHeadRestore.integration.test.js` (CH-02).

**Chain heads.** `audit_chain_head`, `evidence_chain_head`, `transparency_log_head` and
`transparency_roots_head` are single-row pointers seeded at genesis by migrations 026/042 — so every migrated restore
target already has them, and the generic `ON CONFLICT DO NOTHING` used to keep the target's GENESIS row: the next
production append chained from genesis (a second genesis in evidence / transparency / roots; every distributed audit
append refused on the unique prev-hash index — reproduced 2026-10-09).
`restorePostgres()` now restores these four tables with `ON CONFLICT (id) DO UPDATE` and, before reporting success,
verifies (`scripts/dr/chainHeads.js`) that each head equals the backed-up head AND the tail of its restored ledger
(`CHAIN_HEAD_RESTORE_FAILED` otherwise). `audit_chain_head` is only maintained in distributed ordering, so its
head = tail check is enforced for a distributed-mode backup and reported otherwise. The postgres probe (`dr:cycle`,
`validateRestoredState`) re-checks head = tail. The restore identity must be able to write the head rows (they are
FORCE-RLS tables whose UPDATE policy admits only `qodiqa_app`; a superuser or BYPASSRLS identity can) — which identity
restores in production is the open design decision D-R.

**Not restored as data, by design:** `audit_chain_verifier_state`, `gap_scanner_state` (cursor singletons — the
target keeps its fresh cursor, so the verifier / gap scanner re-scan from the start), seeded catalogue rows
(`qodiqa_migrations`, `compliance_frameworks`, `consent_scopes`, `audit_retention_policies`) that the target's own
migrations already inserted; all are reported in `RESTORE_ROWS_SKIPPED`.

---

## 5. Validation Procedure

```bash
# Validate a restored target by exercising the real production modules:
node scripts/dr/validate.js <targetRoot>
```

Validation runs each integrity probe in an **isolated child process** with the
relevant environment variable pointed at the restored file, so each probe loads
the real production module against the restored state exactly as a fresh server
startup would:

| Probe | Module exercised | Proves |
|-------|------------------|--------|
| `auditChainProbe.js` | `src/core/audit/audit-log.js` | Single-node mode only (§4.3): WAL replay + anti-deletion checksum on load, then `validateChainIntegrity()` — chain is continuous and untampered |
| `auditChainPgProbe.js` | `src/core/audit/audit-log.js` via PostgreSQL | Distributed mode only (§4.3): the just-restored `audit_chain` rows form a continuous, untampered chain, cross-checked against the backup's own recorded row count so a probe that never really connected cannot vacuously pass |
| `policyStoreProbe.js` | `policy/policyStore.js` | Store loads and every active policy version parses |
| `keyStoreProbe.js` | `services/artifact/keyStore.js` | Structural invariants hold; **with the KEK present**, decrypts each active key and performs a full Ed25519 sign+verify round-trip + fingerprint check |

`validateRestoredState()` accepts an `auditOrderingMode` option (defaulting to
`'single-node'` for backward compatibility) to select which of the two audit
probes above to run — `scripts/dr/cycle.js` passes the backup manifest's own
`manifest.auditOrderingMode` through automatically.

`validate.js` **fails closed on ambiguity**: `overallValid` is true only if every
probe *explicitly* reports `valid: true`. A missing/undefined result (a probe
contract violation) is never treated as passing.

---

## 6. Integrity Verification

The framework verifies integrity at three layers, so corruption anywhere in the
chain is caught:

1. **Manifest seal** — `manifestChecksum` (SHA-256 of the canonicalised manifest,
   via the project's own `src/utils/stableStringify.js`) is verified *before*
   any per-file checksum in the manifest is trusted. A tampered manifest is
   rejected (`MANIFEST_CHECKSUM_MISMATCH`) before it can misdirect the restore.
2. **Per-file checksum + size** — every present component's `.dat` file must
   match both its recorded SHA-256 and byte size. A single flipped byte
   (`CHECKSUM_MISMATCH`) or a truncated file (`CHECKSUM_MISMATCH` / `SIZE_MISMATCH`)
   aborts the restore.
3. **Functional integrity** — post-restore, the real modules re-verify the
   *content*: the audit chain's hash-chain continuity and anti-deletion checksum,
   the key store's structural invariants and cryptographic round-trip, and the
   policy store's parseability.

### 6.1 Cryptographic invariance

The `keyStoreProbe` computes each active key's fingerprint
(`SHA-256(UTF8(publicKeyB64))`, spec §12.3) after restore. The test suite asserts
this fingerprint is **byte-identical before and after restore**, proving no
cryptographic value changes across the DR cycle. The Ed25519 sign+verify
round-trip proves the restored, KEK-decrypted private key still produces valid
signatures.

---

## 7. Failure Scenarios

Every failure scenario produces a **deterministic, coded error** and fails
closed. These are exercised by the automated test suite (Section 10):

| Scenario | Detected as | Behavior |
|----------|-------------|----------|
| Missing manifest | `MANIFEST_MISSING` | Restore aborts, nothing written |
| Corrupted manifest (invalid JSON) | `MANIFEST_CORRUPT` | Restore aborts |
| Tampered manifest (checksum mismatch) | `MANIFEST_CHECKSUM_MISMATCH` | Restore aborts before trusting any checksum |
| Malformed manifest (`components` not an array) | `MANIFEST_MALFORMED` | Restore aborts |
| Missing archive file for a present component | `ARCHIVE_FILE_MISSING` | Restore aborts |
| Corrupted archive (flipped byte) | `CHECKSUM_MISMATCH` | Restore aborts |
| Truncated / interrupted backup | `CHECKSUM_MISMATCH` / `SIZE_MISMATCH` | Restore aborts |
| Missing **required** component | `REQUIRED_COMPONENT_MISSING` | Restore aborts |
| Nonexistent backup directory | `BACKUP_DIR_MISSING` | Restore aborts |
| Restore over a non-empty target | `TARGET_NOT_CLEAN` | Refused; existing files untouched |
| Corrupted restored content (post-restore edit) | `tamperingDetected: true` | Validation reports `valid: false` |
| Corrupted / missing key material | probe `valid: false` (non-zero exit) | Validation fails |
| Distributed-mode backup with no Postgres component at all | `DISTRIBUTED_MODE_BACKUP_MISSING_POSTGRES_COMPONENT` | Restore aborts (`AUDIT_CHAIN_INTEGRITY_FAILED`) |
| Distributed-mode backup whose Postgres component never captured `audit_chain` | `DISTRIBUTED_MODE_BACKUP_MISSING_AUDIT_TABLE` | Restore aborts (`AUDIT_CHAIN_INTEGRITY_FAILED`) |
| Distributed-mode restore with no resolvable Postgres connection string | `PG_CONNECTION_STRING_NOT_AVAILABLE` | Restore/validation aborts, never a vacuous pass |
| Distributed-mode restored chain shorter than the backup's own recorded row count | `RESTORED_CHAIN_SHORTER_THAN_BACKUP` | Restore aborts (`AUDIT_CHAIN_INTEGRITY_FAILED`) — defends against `loadChainFromPg()`'s fail-open empty-array-on-disabled-pool behavior |
| Tampered distributed-mode `audit_chain` archive (hash-chain break, PG path) | `tamperingDetected: true` via `auditChainPgProbe.js` | Restore aborts (`AUDIT_CHAIN_INTEGRITY_FAILED`) |

"Interrupted backup" and "interrupted restore" are covered by the truncation and
all-or-nothing behaviors respectively: a partial `.dat` fails its size/checksum
check, and restore's two-phase design guarantees a failed run leaves the target
untouched (Section 8).

---

## 8. Rollback Behavior

The restore is **all-or-nothing**. Because all integrity validation occurs in the
validation phase *before* the restore phase writes anything, a failure at any
validation step means **zero bytes are written to the target directory**. There
is no partially-restored state to roll back from — the operator retries with a
known-good backup against a still-clean target. This is asserted directly by the
test suite (`validation phase writes NOTHING to the target when it fails`).

For the PostgreSQL component, restore is additive and idempotent
(`ON CONFLICT DO NOTHING`), so a re-run after a partial failure converges to the
correct row set without duplication.

---

## 9. Disaster Recovery Cycle

`scripts/dr/cycle.js` is the single deterministic entrypoint that runs the
complete cycle against the currently-configured deployment:

```bash
node scripts/dr/cycle.js
# 1. Backup every present component into a scratch backup dir
# 2. Restore into a fresh, empty, clean target dir
# 3. Validate the restored state via the real production modules
# Exit 0 iff every present required component restored AND every probe passed.
```

PostgreSQL is included automatically when `QODIQA_PG_URL` is set; Redis
diagnostics when `REDIS_URL` is set. The scratch directory is cleaned on exit
unless `DR_CYCLE_KEEP=1` is set (for post-mortem inspection).

For CI or drills against a scratch data set, `scripts/dr/seed.js` populates a
realistic live-like state first (an active signing key, several real audit-chain
entries, a stored policy, and — when Postgres is available — one representative
`audit_chain` row).

### 9.1 Expected execution time

| Operation | Typical duration |
|-----------|------------------|
| File-only backup | < 100 ms |
| File-only restore | < 100 ms |
| Validation (3 child-process probes) | ~0.3–1.0 s |
| Full file-only cycle (`dr:cycle`) | < 2 s |
| Full Jest suite (`dr:test`, 18 cases) | ~3–4 s |
| Postgres-inclusive cycle (CI, small data set) | seconds; scales with row count |

These are small because QODIQA's authoritative stores are file-based; a real
production PostgreSQL restore scales with database size (see
[Restore Runbook §1](restore-runbook.md) for large-DB expectations).

---

## 10. CI Validation

The framework runs automatically via `.github/workflows/backup-restore.yml` on
every push/PR to protected branches and on a daily schedule (`05:00 UTC`), with
two jobs:

1. **`dr-file-based`** (no external services) — runs the full Jest suite (happy
   path + every failure scenario), the offline backup-coverage regression
   guard (`test/dr/backupCoverage.test.js`, no DB required), and a seeded
   end-to-end CLI cycle. This alone is a complete DR proof for QODIQA's
   file-authoritative stores.
2. **`dr-postgres`** (Postgres + Redis service containers) — runs schema
   migrations against both a live and a clean restore-target database, runs
   the live full-coverage integration test
   (`test/dr/postgresFullCoverage.integration.test.js`, `npm run
   dr:test:postgres`) against its own throwaway databases, seeds live state
   with representative rows across **every** data category (consent,
   investigations, compliance reports, audit chain), runs the cycle restoring
   into a **genuinely separate clean database** (`QODIQA_PG_RESTORE_URL`),
   and asserts the restored row count matches the live set for **every table
   in the schema** — not just `audit_chain` — plus an explicit per-row check
   for each DR-1-named category.

Both jobs produce a deterministic pass/fail with no manual intervention. The CI
KEK is a fixed test-only value so the cryptographic round-trip probe can run.
`QODIQA_DR_REQUIRE_KEK_ROUNDTRIP=true` is also set so CI
*asserts* the round-trip actually completed rather than merely attempting it
— see §12 below.

---

## 11. Exit Criteria

A Backup → Restore validation run is considered **PASS** only when all of the
following hold (this is exactly what `cycle.js` / `dr:test` enforce):

- [ ] Backup completed and every **required** present component was captured.
- [ ] `manifest.json` seal verifies.
- [ ] Every present component's checksum **and** size match on restore.
- [ ] Restore wrote into a **clean** target (or was intentionally `--allow-existing`).
- Audit chain probe: `valid: true`, `tamperingDetected: false`, expected entry count. **Mandatory as remediation**: `restore.js` itself refuses to resolve — throwing `AUDIT_CHAIN_INTEGRITY_FAILED` — unless this probe passes; a checksum-valid but chain-broken restore can no longer be reported as a successful restore (`restore -> integrity verification -> success`, never `restore -> success`). **Mode-aware as** (§4.3): single-node checks the restored `audit.log` file; distributed checks the just-restored PostgreSQL `audit_chain` rows via the same production chain-walk function, since a genuinely fresh distributed deployment never produces a local file at all.
- [ ] Policy store probe: `valid: true`, expected policy count.
- Key store probe: `valid: true`; with KEK, cryptographic round-trip `ok: true`, **including** the known-plaintext `kekRoundTrip` check. With `QODIQA_DR_REQUIRE_KEK_ROUNDTRIP=true`, an absent KEK is itself a failure (`KEK_ROUNDTRIP_REQUIRED_BUT_KEK_ABSENT`) rather than a silent structural-only pass.
- [ ] Key fingerprint identical before and after restore.
- (Postgres) **every** table discovered in the live schema was dumped — `coverage.dumpedTableCount === coverage.discoveredTableCount`.
- [ ] (Postgres) restored row count equals the live row count, for every table, not a sample.
- [ ] (Postgres) every foreign key constraint in the restore target is `convalidated` (no dangling references).
- [ ] (Postgres) every SERIAL/BIGSERIAL/IDENTITY sequence is at or ahead of `MAX(column)` in the restore target.
- [ ] (Postgres) `EXCLUDED_TABLES` has no entries without a `reason`, and the static/live table inventories agree (`test/dr/backupCoverage.test.js`).
- [ ] Every failure scenario is detected with its expected coded error.

Any single unmet criterion → non-zero exit → **FAIL**.

---

## 12. Operational Recommendations

- **Schedule regular restore drills.** CI runs the cycle daily; additionally run
  `npm run dr:cycle` against a *staging* copy of production data monthly, aligning
  with the "monthly full restore test" in [Backup Runbook §11.2](backup-runbook.md).
- **Keep the KEK out of the backup.** The key store is encrypted at rest and safe
  to back up; the KEK must be recovered separately from the secrets manager. The
  `keyStoreProbe` only performs the cryptographic round-trip when the KEK is
  present in the environment — a structural-only pass (no `cryptoRoundTrip`) means
  the KEK was absent, not that the key store is invalid. Note that for any store
  with at least one active key (i.e. every real deployment), `keyStore.js`'s own
  fail-closed load already refuses to even structurally validate without a KEK —
  a graceful structural-only pass is only actually reachable for an
  empty/never-rotated store.
- **Run a genuine KEK-recovery drill periodically, not just a structural
  restore.** A clean `dr:cycle` run proves nothing about KEK recoverability
  unless a KEK was actually supplied and its round-trip asserted — set
  `QODIQA_DR_REQUIRE_KEK_ROUNDTRIP=true` alongside the recovered KEK for the
  monthly staging drill above so the run fails outright if nobody actually
  performed (or rehearsed) the out-of-band KEK recovery step, rather than
  quietly reporting `cryptoRoundTrip: null` as if that were acceptable for a
  drill whose entire point is proving KEK recovery works. Leave the flag unset
  for restore-validation runs that are legitimately scoped away from KEK access
  (e.g. the standalone-pod K8s CronJob — see
  `deploy/kubernetes/base/backup-cronjobs.yaml`'s "Known scope boundary" note).
- **Restore into a clean target, always.** Never point `targetRoot` at a live
  data directory. Use `QODIQA_PG_RESTORE_URL` for a clean Postgres target.
- **Treat any coded failure as a hard stop.** The error codes in Section 7 are
  deterministic; a `CHECKSUM_MISMATCH` or `MANIFEST_CHECKSUM_MISMATCH` means the
  backup is untrustworthy — select a different backup rather than forcing the
  restore.
- **Preserve the scratch dir on failure.** Set `DR_CYCLE_KEEP=1` when a cycle
  fails, to inspect the intermediate backup/restore artifacts during a post-mortem.
- **Back up the audit log at high frequency.** It is the authoritative store and
  its RPO target is 5 minutes ([Disaster Recovery §1](disaster-recovery.md)) —
  enforced by `scripts/backup-audit-log.sh` (self-hosted) or, in the
  Kubernetes topology where the file itself is unreachable by a standalone
  pod, by continuous WAL archiving of the Postgres-mirrored `audit_chain`
  table (`scripts/pg-wal-archive.sh`, remediation — previously nothing
  ran on this cadence at all).

---

*Cross-references: [Backup Runbook](backup-runbook.md) | [Restore Runbook](restore-runbook.md) | [Disaster Recovery](disaster-recovery.md) | Audit Chain Architecture | [Reliability Guide](../architecture/RELIABILITY_GUIDE.md)*
