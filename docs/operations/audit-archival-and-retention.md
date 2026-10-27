# Audit Archival and Retention Policy

**Scope:** what leaves the hot audit store, how it leaves, how that is proven, and what is never deleted automatically.

## The policy in one table

| Data | Automatic deletion | Archive | Removal |
|---|---|---|---|
| `audit.log` / `audit_chain` (the hash chain) | **Never** | `scripts/audit/archive-export.js` (sealed copy, any time, server running) | Only `scripts/audit/prune.js`, operator-run with the server stopped, off until `QODIQA_AUDIT_RETENTION_DAYS` is set, after the range is archived **and** the archive verified, and only up to a signed checkpoint |
| `evidence_chain_records` | **Never** | exported by `prune.js` (PostgreSQL deployments) | with the chain prefix, by `prune.js` only |
| `platform_audit_events`, category **ENFORCEMENT** | **Never** — the retention engine (`src/core/audit/retention.js`) excludes it unconditionally and a legal hold blocks every other category | (database backup, `docs/operations/backup-runbook.md`) | not removed by any scheduled job |
| `platform_audit_events`, other categories | after `retain_until`, unless on legal hold, by the dedicated `qodiqa_retention` role | database backup | the scheduled retention cycle |
| Signed checkpoints, checkpoint sidecar, external anchors, transparency leaves | **Never** | included in every archive that ends at a checkpoint | not removed |

Nothing in this policy deletes enforcement evidence on a timer. An archive is how long-lived evidence is moved to cold storage and proven intact there; it is **not** a reason to drop the original, and the exporter itself contains no deletion primitive (a test pins that).

## Exporting a sealed archive

```bash
node scripts/audit/archive-export.js [--checkpoint-id ID] [--archive-root DIR] [--note TEXT] [--dry-run]
```

It copies the file chain from the start of the live log (or from the prior base record, if the chain was pruned before) up to the newest **verified signed checkpoint** that the chain actually reaches (or the one named), and writes `<archive-root>/export-<checkpointId>/`:

| File | Content |
|---|---|
| `audit.log.segment` | the chain lines, byte for byte |
| `checkpoint.json` | the signed checkpoint the segment ends at |
| `prior-base.json` | only after an earlier prune: the signed base record the segment starts from |
| `manifest.json` | SHA-256 and size of every file, the range (`from`/`to` counts and hashes), the tool and an optional note |
| `seal.json` | `{ manifestSha256, keyId, signature }` — an Ed25519 signature by the audit-checkpoint key over `SHA-256("QODIQA::AUDIT_ARCHIVE_SEAL::V1" ‖ manifestSha256)` |

The archive is verified by the independent verifier's own code **before** it is sealed. The export is **marked** in `<archive-root>/archive-index.jsonl` — one append-only line per export (`seq`, `exportedAt`, `checkpointId`, the range, `manifestSha256`, `sealKeyId`), each line hash-chained to the previous one — and an `AUDIT_ARCHIVE_EXPORTED` event is logged. It is idempotent (an existing export is re-verified and reported, never rewritten), safe while the server runs (the exported prefix of an append-only chain does not change), and writes only under the archive root. Default archive root: `QODIQA_AUDIT_ARCHIVE_ROOT`, else `audit-archive/` next to the audit log (the same directory `prune.js` uses; the two never collide: `export-…` vs the bare checkpoint id).

Limits, stated: the exporter covers the **file chain**. A PostgreSQL-authoritative deployment keeps the chain in `audit_chain`; its long-term copy is the database backup (`docs/operations/backup-runbook.md`) and the prune archive of `prune.js`, which also exports the PostgreSQL rows. Moving the archive to cold storage (object store, tape, another account) is the operator's step — QODIQA writes the sealed directory and the index and does not upload anywhere.

## Verifying an archive, years later

```bash
node scripts/audit-repro/verify/qodiqa-archive-verify.js --checkpoint-keys keys.json --archive <export dir>
node scripts/audit-repro/verify/qodiqa-archive-verify.js --checkpoint-keys keys.json --index <archive root>
```

`keys.json` is the body of `/.well-known/qodiqa/checkpoint-keys` or, better, `keys/checkpoint-keys.json` of the **anchors repository**, which holds the public keys outside the gateway's control. The verifier needs nothing else: it checks every file hash, the entry hashes and links of the segment, that the segment ends exactly at the signed checkpoint, the checkpoint signature, the seal signature and that the manifest was not edited after sealing; for the index it checks sequence, hash chain and each archive present. An archive that is no longer on disk (moved to cold storage) is listed under `missingArchives`, not reported as failed — bring it back and verify it. Exit code 0 = valid, 1 = invalid.

**Limit.** The index is hash-chained but not attested from outside: removing its first or last entry and re-chaining still verifies. Keep the index (and the archives) in storage the gateway operator cannot rewrite, or anchor its head hash in the anchors repository.

To prove an archive is the one that was anchored, compare its `checkpoint.json` payload hash with the anchored statements of the anchors repository (`anchors/<date>.jsonl`): an anchored checkpoint pins the chain head, so an archive that ends at it cannot have been rewritten.

## Operator routine

1. Decide the retention period for the hot store (`QODIQA_AUDIT_RETENTION_DAYS`, off by default).
2. Run `archive-export.js` on a schedule (cron / systemd timer — see `docs/operations/backup-scheduling.md`); copy the archive root to cold storage; keep the index.
3. Verify a sample of archives from cold storage with `qodiqa-archive-verify.js` on a schedule that matches your audit policy.
4. Only then, and only if the hot store must shrink, stop the server and run `prune.js` (it archives and verifies again by itself).

Last verified: 2026-10-22
