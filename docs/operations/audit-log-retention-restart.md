# Audit Log Retention & Restart — Interim Single-Node Runbook

**Scope:** single-node, file-authoritative deployments (`audit.log` is the
evidence authority). In the recommended production profile
(`QODIQA_DEPLOYMENT_MODE=distributed`, PostgreSQL-authoritative) most of this
runbook is superseded by ordinary database operations; see
[CONFIGURATION_REFERENCE.md §6](../configuration/reference.md) and the
ADR.

> **Archival and retention policy:** how a sealed, non-destructive archive of this log is exported and verified, and what is never deleted automatically: [audit-archival-and-retention.md](audit-archival-and-retention.md).

## What changed with

- The process keeps only the most recent `QODIQA_AUDIT_WINDOW_SIZE`
  (default 10,000) entries in memory. `audit.log` on disk is the full,
  append-only evidence record — **it is never truncated or rotated by the
  application**, and it must not be rotated by generic log tooling
  (logrotate et al.): every entry is hash-chained to its predecessor, so
  splitting or compressing the live file breaks chain verification and
  trips the anti-deletion checksum anchor (`audit.log.sum`) at next boot.
- Startup no longer reads the whole file into memory. With an intact
  `audit.log.sum` (anchor v2) the boot validates only the delta since the
  last recorded append plus the tail window; without it (first boot after
  the upgrade, or a restored anchor-less backup) it runs one full
  **streamed** validation pass — fixed memory, time proportional to file
  size — then writes the v2 anchor so subsequent boots take the fast path.

## Restart expectations

| Situation | Boot behaviour |
|---|---|
| Clean restart, `audit.log.sum` present | Fast path: O(delta + window) reads; sub-second on multi-GB logs when the delta is small. |
| First boot upgrade (earlier `.sum` has no v2 block) | One full streamed validation pass (bounded memory), then the `.sum` is upgraded in place. Expect boot time proportional to file size for that one restart. |
| `.sum` missing/damaged | Same full streamed pass. If the log itself fails validation, boot fails CLOSED exactly as. |
| Crash during an append | WAL replay (`audit.log.wal`) recovers or rolls back the in-flight entry first, unchanged from earlier behaviour. |

## Retention

The application imposes **no retention limit**: disk growth is
~0.7 KB/entry (working figure from the 1M-entry proof chain —
677 MB / 1M entries). Plan capacity accordingly.

- **Do not delete or truncate `audit.log`** on a live single-node system.
  There is no supported in-place pruning: the file is the evidence
  authority and the chain is anchored at GENESIS.
- When history must move off the node (compliance archival, disk
  pressure), the supported path is **backup + migration to the
  PG-authoritative profile**, where retention becomes a database concern:
  follow [backup-runbook.md](backup-runbook.md) to capture
  `audit.log` + `audit.log.sum`, verify the copy with
  `scripts/dr/probes/auditChainProbe.js` (full streamed re-validation,
  exit 0 = valid), then bring the node up in `distributed` mode.
- The background Chain Verifier's FULL scans
  ([audit-chain-integrity-verification.md](audit-chain-integrity-verification.md))
  re-read the durable store on every pass and are unaffected by the
  window size.

## Sizing the window

`QODIQA_AUDIT_WINDOW_SIZE` trades steady-state RSS against how much recent
history is served from memory. Out-of-window lookups remain correct — they
fall back to a bounded-memory file scan (or indexed SQL in distributed
mode) — but are slower than in-window hits. The default 10,000 fits the
dashboard/evidence hot set for typical single-node loads.

**The window is also the file-mode replay horizon (documented
limitation, design decision 2026-08-26).** Replay/duplicate rejection on the
append path (`replay_detected` / `already_executed`) keys off the in-memory
window in file mode: reuse of a nonce or artifactId older than the window
is appended as a new, correctly-chained entry, not rejected. There is no
durable on-disk nonce index in file mode — the window IS the horizon, and
every file-mode boot announces it with the `AUDIT_REPLAY_HORIZON_BOUNDED`
WARN (naming the configured size). What still holds: request-level replay
protection (the Redis nonce store + `STRICT_REPLAY_PROTECTION`) is
unaffected; distributed (PG-authoritative) mode keeps durable uniqueness
via PostgreSQL UNIQUE constraints regardless of window size.

**CORRECTED:** the production profile does *not*
categorically avoid this horizon.'s production gate only requires
`pgPool.isEnabled()` — a `NODE_ENV=production` deployment can satisfy that
with `QODIQA_DEPLOYMENT_MODE=single-node` + `QODIQA_PG_ENABLED=true`
while `QODIQA_AUDIT_ORDERING_MODE` stays `single-node` (confirmed directly
against `src/infra/config/deploymentMode.js`'s resolver: this combination
yields `pgEnabled:true`, `auditOrderingMode:'single-node'`). In that
configuration PG is only a best-effort, non-blocking mirror of the audit
log (`_appendOne`'s dual-write) — not durable append-time dedup — so the
horizon still applies and the boot WARN still fires, correctly. Only
genuine distributed ordering (`QODIQA_DEPLOYMENT_MODE=distributed` or
`QODIQA_AUDIT_ORDERING_MODE=distributed`) removes it. Operators who need a
longer file-mode horizon can raise the window (at RSS cost) — or move to
the distributed-ordering profile, which removes the horizon entirely.

`QODIQA_AUDIT_WINDOW_SIZE=unbounded` (WARN at boot) restores earlier
keep-everything behaviour for one release only, as a rollback hatch — do
not use it as standing configuration.
