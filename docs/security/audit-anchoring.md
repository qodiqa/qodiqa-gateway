# Audit anchoring — witnesses and customer-held anchors

## Why this exists

The audit chain is hash-linked, and signed checkpoints vouch for its head at regular positions. Both are **tamper-evident against outsiders only**. The checkpoint signing key, the audit log and the database all live on the gateway host. Anyone with host or database access can:

- truncate the tail;
- rewrite a prefix and re-chain it;
- re-sign fresh checkpoints that verify;
- delete checkpoints. A boot that finds none treats them as "none yet".

All four are practical against an unanchored deployment.

Anchoring moves the proof **outside the host's trust domain**.

1. **Witnesses** co-sign each signed checkpoint statement. A statement pins the checkpoint id, its payload hash, its chain position, its head hash and its predecessor. Each witness uses its **own** key and keeps its **own** append-only log. A witness refuses to co-sign:
   - a lower chain position than it has already witnessed (`WITNESS_ROLLBACK_REFUSED`);
   - the same position with a different head (`WITNESS_EQUIVOCATION_REFUSED`);
   - a higher position whose `previousCheckpointHash` is not the payload hash of the checkpoint it witnessed last
. Before that change a forward fork — a
     fabricated head and predecessor above the witness's top — **was co-signed**.

   **Corrected 2026-10-09.** This section used to say that a rolled-back or forked history "cannot even obtain
   a cosignature". That was false for forward forks until the predecessor rule above. It is true now **only against a
   witness whose key and log the attacker does not control**. With `QODIQA_WITNESS_MODE=local` the gateway host holds
   the witness key and log, so a host-level insider can sign anything with them.

   The only way past the predecessor rule is an explicit re-baseline. It is bound to one exact statement:
   `QODIQA_WITNESS_REBASELINE_ACK=<chainLength>:<first 16 hex of the checkpoint payload hash>` for local mode, or the
   `rebaselineAck` option of `LocalFileWitness`. The refusal message names the value. The witness writes the accepted
   re-baseline into its own log as `rebaseline: { previousTop, ack }`. The gateway also catches up a witness that missed
   a checkpoint (for example after a timeout): it offers the missed predecessors from the export, oldest first, and each
   one is still checked against the witness's rules.
2. **Anchor export.** Every checkpoint, with its cosignatures, is appended to `QODIQA_ANCHOR_EXPORT_PATH`. This append-only JSONL file belongs on storage the gateway operator does not control alone: a customer-mounted volume, a WORM bucket sync target, a separate system.
3. **Verification.**
   - **At boot** (fail-closed: `AUDIT_ANCHOR_BOOT_FAILED`).
   - **Offline**, with the independent verifier:

     ```bash
     node scripts/audit-repro/verify/qodiqa-audit-verify.js \
       --audit audit.log --checkpoint-keys checkpoint-keys.json \
       --anchors anchors.jsonl --witness-keys witness-keys.json \
       --checkpoints audit.log.checkpoints.jsonl
     ```

   Both report:

   | Finding | Meaning |
   |---|---|
   | `CHAIN_ROLLED_BACK` | the log is shorter than an anchored position (tail truncation / rollback) |
   | `CHAIN_REWRITTEN` | the entry at an anchored position has a different hash |
   | `CHECKPOINT_DELETED` | an anchored checkpoint vanished from the live set |
   | `CHECKPOINT_REPLACED` | same checkpoint id, different payload — a re-signed history, even under the real key |
   | `ANCHOR_CHECKPOINT_INVALID` | forged checkpoint |
   | `ANCHOR_NOT_WITNESSED` | missing or untrusted cosignatures — wrong trust anchor, or an edited export |
   | `ANCHORS_NOT_MONOTONIC` | anchors out of order, or the same position with two different heads |
   | `ANCHOR_EXPORT_TRUNCATED` | the export's tail is missing. Either a local witness's log holds a higher position, or a different checkpoint at the export's top, than the export does. Or more than one live signed checkpoint lies above the export's last anchor, or one lies above it and does not chain to it. One unexported newest checkpoint that does chain to the last anchor is the crash/shutdown window: it passes with the WARN `AUDIT_ANCHOR_EXPORT_BEHIND`. The override is the same reported `QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP`(+`_ACK` in production) as for the other boot checks. |

## Configuration

| Variable | Meaning |
|---|---|
| `QODIQA_WITNESS_MODE` | `none` (default) · `local` · `exec` |
| `QODIQA_WITNESS_ID` | identifier recorded in statements (default `witness-1`) |
| `QODIQA_WITNESS_KEY_PATH`, `QODIQA_WITNESS_LOG_PATH` | `local` mode: the witness's key and log. The key **must not** sit inside the gateway key-store directory (production refuses it). A local witness is only as independent as the custody of that file — e.g. a volume or secret owned by another team. |
| `QODIQA_WITNESS_EXEC`, `QODIQA_WITNESS_EXEC_ARGS` | `exec` mode: an operator-provided command that receives `{statement}` on stdin and prints a cosignature. This is the adapter for a witness in **another trust domain** (customer HSM, separate service). `scripts/anchor/witness-cosign.js` is a reference witness to run there. QODIQA never contacts a network itself. **Environment:** the command does **not** inherit the gateway's environment; it receives only OS essentials (`PATH`, `SystemRoot`, `TEMP`/`TMP`, `HOME`/`USERPROFILE`, locale, `TZ`), every `WITNESS_*` / `QODIQA_WITNESS_*` variable, and the names listed in `QODIQA_WITNESS_EXEC_ENV_PASS` (comma-separated). **Refusals:** exit status 3 with `WITNESS_ROLLBACK_REFUSED` / `WITNESS_EQUIVOCATION_REFUSED` on stderr is reported as `AUDIT_ANCHOR_WITNESS_REFUSED`; any other failure as `AUDIT_ANCHOR_WITNESS_FAILED`. **Non-blocking:** the command runs asynchronously (it no longer blocks the event loop for the witness's duration); timeout 10 s. Every outcome is counted in `qodiqa_audit_anchor_events_total{outcome}` (alerts: `docs/operations/metrics-and-alerting.md` §11.6). |
| `QODIQA_WITNESS_PUBLIC_KEYS` | the **trusted** witness public keys (`{keys:[{witnessId, keyId, publicKey, status}]}`), obtained out of band (`witness-cosign.js --public-key` on the witness side) |
| `QODIQA_ANCHOR_EXPORT_PATH` | the customer-held append-only anchor file |
| `QODIQA_ANCHOR_MIN_WITNESSES` | trusted cosignatures required per anchor (default 1 when witness keys are configured, and always at least 1 in production) |
| `QODIQA_AUDIT_CHECKPOINT_EVERY` / `_MAX_AGE_MS` | checkpoint cadence — **defaults tightened to 1,000 entries / 15 min** (were 10,000 / 24 h). This is the rewrite window between pinned positions. |

**Production requires anchoring: fail-closed, no waiver.** The boot validator REFUSES a production boot that is missing any of:
- an anchor export;
- a witness (`local`/`exec`);
- the witness public keys.

It also refuses a placeholder value, a missing witness file, or a `QODIQA_AUDIT_ANCHORING_WAIVER`.

At boot, production then checks that the trusted key set holds at least one active key, and that a local witness's own key is in it (`AUDIT_ANCHORING_POSTURE_VERIFIED`, otherwise `AUDIT_ANCHOR_BOOT_FAILED`).

- **Distributed mode** (`QODIQA_DEPLOYMENT_MODE=distributed`) runs no signed checkpoints and no anchors yet. It is therefore **refused in production**, and `deploy:validate` asserts that refusal for the shipped distributed overlay.
- **The chain is checked at every boot:**
  - every signed checkpoint must verify;
  - each must link to its predecessor (`previousCheckpointHash`);
  - the PostgreSQL and sidecar checkpoint sets must agree;
  - the latest checkpoint must not leave more than 2 × `QODIQA_AUDIT_CHECKPOINT_EVERY` entries uncovered, nor be older than 2 × `QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS` while new entries exist.
- **Missing anchors:** an anchor export that is missing or empty while the chain is longer than 2 × that interval fails the boot.
- **Bootstrap (re-baselining an existing chain) — corrected 2026-10-05 (C13).** `QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true`
  skips exactly the checks above that would otherwise fail (missing anchors, missing checkpoints, a broken checkpoint
  chain, newest checkpoints missing from the sidecar, uncovered or stale entries). Outside production it works as a
  plain switch for one boot. **In production it is not an ordinary switch any more:**
  - the boot validator refuses `true` unless `QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK=<chainLength>:<first 16 hex of the
    newest entry's hash>` is also set;
  - the checkpoint boot check compares that acknowledgement with the LIVE chain and fails the boot
    (`AUDIT_CHECKPOINT_BOOTSTRAP_REFUSED`) on any mismatch — the refusal message names the value for the current head,
    to be set only after investigating why the check failed. `true` with NO acknowledgement is refused earlier, by the
    boot validator, which cannot name the value; to obtain it, boot once with a placeholder such as
    `QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK=0:0000000000000000` (refused, and the message names the exact value), or
    compute it as `<number of entries in audit.log>:<first 16 hex of the last entry's hash>`. The shipped Docker
    Compose file passes both variables through (empty by default). the accepted boot also
    publishes the latest signed checkpoint to a missing or empty export on the scheduler's first tick
    (`AUDIT_ANCHOR_EXPORT_REESTABLISHED`), so the following ordinary restart passes;
  - an acknowledgement left set stops matching as soon as one more entry is appended, so the bypass cannot be pre-set
    or left on;
  - acceptance is reported at ERROR (`AUDIT_CHECKPOINT_BOOTSTRAP_ACCEPTED`), not WARN;
  - a healthy chain never consults it.
  **Residual (stated, not hidden):** someone who controls both the host configuration and the logs can still re-baseline
  once, deliberately and visibly. What still detects that is the copy of the anchors and the witness log held in another
  trust domain — the offline verifier run against that copy reports the rollback.

Outside production, nothing configured gives the warning `AUDIT_ANCHORING_NOT_CONFIGURED`.

## What this does and does not give you

- **Gives:** once a checkpoint is witnessed and exported, nobody holding only the gateway host can make entries ≤ its position disappear or change, or substitute re-signed checkpoints, without the boot check and the offline verifier reporting it.
- **Does not give:**
  - protection of entries written **after** the latest witnessed checkpoint (bounded by the cadence above);
  - independence if the witness key and the anchor file end up in the same hands as the gateway host. Custody is an operator responsibility; the boot validator refuses the most obvious mistake.
- **Independence.** The "Gives" bullet above holds only against someone who does
  **not** also control the witness key, the witness log and the export. **The shipped production manifests
  (`deploy/docker/docker-compose.prod.yml`, the single-node Kubernetes overlay) use `QODIQA_WITNESS_MODE=local`.** In
  that mode the witness key is a plaintext file that the gateway process reads, and the witness log and export sit on
  gateway-mounted storage. On those deployments, an insider with gateway host or container access, plus the KEK, can
  rewrite the history, re-sign checkpoints, re-witness them and rewrite the export, and the boot check still passes.
  The anchoring there is **not independent of the operator**. The product now states this itself:
  - `verifyAnchoringPosture()`, which production boot emits as `AUDIT_ANCHORING_POSTURE_VERIFIED`, carries
    `anchoringIndependence`;
  - every anchor boot verification emits `AUDIT_ANCHORS_BOOT_VERIFIED` with `anchoringIndependence`;
  - in local mode the boot also emits the WARN `AUDIT_ANCHORING_NOT_INDEPENDENT`.

  Values:
  - `none-local-witness`: local mode;
  - `none-no-witness`: no witness;
  - `unverified-exec-witness`: exec mode. QODIQA cannot check that the command reaches another trust domain; only the
    external acceptance contract below can establish that.

  No mode yields an "independent" label from inside the product. Whether production should refuse `local` is an open
  design decision. Refusing it today would break every shipped configuration.
- **Export tail (M10) with an exec witness.** The gateway cannot read a remote witness's log. Suppose an insider
  truncates the export and replaces the newest live checkpoints with one re-signed checkpoint that chains to the
  remaining top. The boot does not see that. The witness then refuses the next checkpoint (`WITNESS_FORK_REFUSED` →
  `AUDIT_ANCHOR_WITNESS_REFUSED`), and V5 in the design (witness log vs. customer copy) reports it.
- **External services:** none are contacted by QODIQA. Attaching a public transparency witness (e.g. an RFC 9162-style log) means pointing `exec` mode at an adapter for it.

## Witness failure semantics and the second-trust-domain acceptance contract

Appended; nothing above is changed. Full record and test map:.

**No second trust domain exists in any environment QODIQA has been tested in.** Every test and probe below runs the
gateway and the witness on one machine (or one container). The contract at the end of this section is what an
independent party must run and produce before anyone may claim one.

- **Asynchronous in every mode.** `exec`: a child process, never `execFileSync`. `local`: the gateway runs
  `LocalFileWitness` on a worker thread (`ThreadedLocalWitness`), because the synchronous class re-reads its whole log
  per call (87 ms of blocked event loop at ~1 year of records before this change). `none`: nothing runs.
- **Timeout** (`exec` 10 s, `local` 10 s): settles at the timeout even if a grandchild of a wrapper still holds the pipe;
  POSIX kills the witness's whole process group. A late reply is never used.
- **Retry:** `exec` only, bounded — `QODIQA_WITNESS_EXEC_RETRIES` 0..3, default 1 — and only for transient failures
  (timeout, crash, non-zero exit other than 3/64). Safe because the witness is idempotent for the identical statement.
  Never retried: refusals (exit 3), bad request (exit 64), malformed reply, missing command, shutdown.
  Worst-case wait per checkpoint = (retries + 1) × timeout + 250 ms × (1 + … + retries); default 20.25 s, max 41.5 s,
  off the request path but holding the single-flight checkpoint chain.
- **Malformed reply** → `WITNESS_MALFORMED_RESPONSE` (reply must be an object with the same `witnessId`, a string
  `keyId` ≤ 128, a base64 64-byte signature, an optional string `cosignedAt` ≤ 64).
- **Publish-time binding:** with `QODIQA_WITNESS_PUBLIC_KEYS` set, each cosignature is verified against THIS
  checkpoint's statement when it is published; a mismatch (wrong key, cosignature replayed from another checkpoint) is
  reported as `WITNESS_COSIGNATURE_UNVERIFIED` immediately, not first at the next boot.
- **Reference witness (`scripts/anchor/witness-cosign.js`):** rejects malformed statements (exit 64); claims each chain
  position atomically (`<WITNESS_LOG_PATH>.positions/<chainLength>`, hard-link exclusive create) before signing, so
  concurrent requests cannot obtain two cosignatures for one position; survives a crash mid-append (a torn final log
  line is closed with a `\t#torn` marker and skipped, never truncated). The positions directory and the log must be on a
  filesystem that supports hard links; otherwise every cosign fails closed. The positions directory is part of the
  witness's state: back it up and archive it with the log, never delete it.
- **Shutdown:** a process `exit` hook kills every in-flight exec witness; `abortInFlightWitnesses()` kills them earlier
  and refuses new calls (`WITNESS_SHUTTING_DOWN`). Wiring it into the gateway's ordered shutdown is a recorded
  follow-up (server/startup.js is outside this change).
- **Not changed (design decisions, see the evidence file):** the witness enforces position and per-position uniqueness,
  not predecessor linkage; `cosignedAt`/`exportedAt` stay unsigned (M9); no automatic witness-log ↔ export
  cross-check (M10).

### Acceptance contract for a second trust domain (EXTERNAL — not met)

A deployment may state that its audit anchors are witnessed "in a second trust domain" only when an independent party
(the **witness operator**, organisationally separate from the gateway operator, with its own administrators) has run
the following and signed the resulting evidence:

1. **Custody.** The witness private key is generated on the witness operator's host (W-2) or in its HSM/KMS;
   the gateway operator has no login, no backup access and no snapshot access to that host/account, the witness log or
   the positions directory. Evidence: the access list of the witness host/account, signed by the witness operator.
2. **Protocol.** The witness implements exactly the `QODIQA::WITNESS_COSIGN::V1` statement and rules: Ed25519 over
   SHA-256(tag ‖ stableStringify(statement)); refuse a lower position (exit 3 `WITNESS_ROLLBACK_REFUSED`); refuse a
   different head/payload hash at a witnessed or claimed position (exit 3 `WITNESS_EQUIVOCATION_REFUSED`), including
   under concurrent requests; idempotent for the identical statement; exit 64 for a malformed statement; only the
   statement on stdin, the cosignature JSON on stdout.
3. **Transport.** The gateway reaches the witness only through `QODIQA_WITNESS_EXEC` (e.g. ssh ForceCommand), with a
   clean environment, a timeout well under 10 s measured on the real link, and no gateway secret on the witness side.
4. **Gateway verification.** `QODIQA_WITNESS_PUBLIC_KEYS` holds the trust record delivered out of band; boot shows
   `AUDIT_ANCHORING_POSTURE_VERIFIED` and `AUDIT_ANCHORS_BOOT_VERIFIED`; no `WITNESS_COSIGNATURE_UNVERIFIED`.
5. **V1–V6** of, run by the customer/witness operator against their
   own copies (not the gateway's), all passing, with the negative controls (rollback, equivocation, truncated log)
   reproduced on the real deployment.

## Witness outages: unwitnessed checkpoints are held

With witnesses configured, a signed checkpoint is written to the anchor export **only** with at least one cosignature
that verifies under the trusted witness keys (`QODIQA_WITNESS_PUBLIC_KEYS`). Before this change the normal path exported
a record even with zero cosignatures, and the next production boot then failed `ANCHOR_NOT_WITNESSED` with no bootstrap
path. Now:

- **During an outage** the checkpoint is **held**: it stays in the live checkpoint set (sidecar + PostgreSQL) and is not
  exported. `AUDIT_ANCHOR_HELD` (WARN) reports how many are held.
- **When the witness returns**, the next checkpoint run offers the held checkpoints oldest first (the witness's own
  catch-up order) and exports each, in chain order, once it is witnessed (`AUDIT_ANCHOR_BACKLOG_EXPORTED`). The export
  never contains an unwitnessed record and stays monotonic.
- **A restart while checkpoints are held** finds more than one live checkpoint above the export's last anchor and fails
  closed with `ANCHOR_EXPORT_TRUNCATED` — the same finding as a truncated export, because from the export alone the two
  cannot be told apart. After checking that the witness was unavailable (its log ends at the export's last anchor), boot
  once with the documented bootstrap (`QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP` + its ACK); once the witness is back the backlog
  is exported and later boots pass without it.

