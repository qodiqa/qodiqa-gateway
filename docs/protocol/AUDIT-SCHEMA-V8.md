# QODIQA Audit schema v8

> **Status:** normative for audit schema version 8, which the gateway writes only when `QODIQA_AUDIT_SCHEMA_V8=true`; versions 1 to 7 stay verifiable.


## 1. Principles

1. **One new version for all waves.** `schemaVersion 8` adds every field the planned waves need. A field a wave does not use is present and
   `null` (the v7 rule). Later waves add *entry types and values*, not fields.
2. **Hash contract.** `hash = hex(SHA-256("QODIQA::AUDIT::V1" || sortedJSON(coreFields)))`, `coreFields` = exactly `CORE_HASH_FIELDS_V8` (below);
   `sortedJSON` is the existing `stableStringify` canonicalization (identical to RFC 8785 for every accepted value; the semantic evidence
   contains fractional scores, which is why the audit canonicalization is **not** restricted further). The domain tag is shared by all audit
   versions so a chain links across versions with one hash function; v8 adds no further reuse of the tag.
3. **No retroactive change.** The hash of an existing v1–v7 entry never changes.
4. **Gate: v8 is written from the gate on** (flag `QODIQA_AUDIT_SCHEMA_V8`, default off until then), because already needs `issuedAt`,
   `protocolVersion` and the `KILL_SWITCH` entry. **Reading and verifying v8 ships first** (in the phase, before the flag can be turned
   on) in the gateway verifier and the JavaScript independent verifier (the SDKs verify artifacts and receipts, not audit entries).
5. **The flag is one-directional.** An older verifier refuses a v8 entry (`isSupportedSchemaVersion`), and switching the flag off *after*
   v8 entries exist leaves a chain in which an older writer's v7 entries follow v8 ones, which every verifier reports as `SCHEMA_DOWNGRADE`.
   Therefore: roll verifiers forward before enabling, and treat enabling as a one-way step per deployment (a rollback of the *code* below the
   v8-capable version is not supported once v8 entries exist). A writer whose chain head is already v8 **refuses to append a v7 entry**.
6. **Fail-closed lifecycle.** The v7 rule (no provider call and no streamed byte without its `INTENT` / `STREAM_OPENED`) extends to the new entry
   types in section 3.

## 2. Fields

`CORE_HASH_FIELDS_V8 = CORE_HASH_FIELDS_V7 (28 fields) + 10 new fields`:

| field | type | meaning | first used by |
|---|---|---|---|
| `issuedAt` | integer ms or `null` | the artifact's `timestamp`, recorded in the entry that consumed it | |
| `protocolVersion` | integer or `null` | `1` for an artifact without `qodiqa`, else `qodiqa.v` | |
| `agentId` | string or `null` | agent identity (action entries) | |
| `sessionId` | string or `null` | agent session | |
| `actionSeq` | integer or `null` | position of the action in the session (≥ 1) | |
| `actionHash` | 64 hex or `null` | `actionHash` of V2-FREEZE section 5.1 | |
| `approvalRef` | string or `null` | approval id the entry depends on / records | |
| `dlp` | object or `null` | `{ rules: string, action: "DETECT"\|"REDACT"\|"BLOCK"\|"MASK", inputHashBefore, inputHashAfter }` — both hashes | |
| `bytesDelivered` | integer or `null` | exact number of output bytes delivered (`COMMIT`); `0` together with `completionStatus` `OUTCOME_UNKNOWN` means **unknown**, never "nothing was delivered" | |
| `completionStatus` | string or `null` | `COMPLETE`, `CANCELLED`, `ERROR`, `TIMEOUT`, `CLIENT_DISCONNECTED`, `OUTCOME_UNKNOWN` — the existing vocabulary of `streamEnforcer`/`aiChat` (which today keeps it inside `executionContext`) plus the two new values | |

`provider` / `model` / `executingProvider` keep their v5/v7 meaning. Further structured data lives in `executionContext` (hashed whole since v7), with
**frozen keys per entry type** (section 3), so a verifier can read it without guessing.

## 3. Entry types and their fixed values

v7 types `DECISION`, `INTENT`, `STREAM_OPENED` are unchanged. Lifecycle of one request: `INTENT` or `STREAM_OPENED` → `DECISION` →
`COMMIT` (v8, after the response was delivered or failed; for a stream the `DECISION` keeps its v7 meaning and `COMMIT` records what was actually
delivered). There is no separate `STREAM_CLOSED` type (draft 1 had one; `COMMIT` covers both).

Every v8 entry is a complete audit entry. The table fixes the values that are not free:

| `entryType` | `decision` | `stage` | `reason` | `artifactId` | other fixed fields | `executionContext` keys (frozen) |
|---|---|---|---|---|---|---|
| `COMMIT` | `ALLOW` | `COMMIT` | `RESPONSE_DELIVERED` or `RESPONSE_FAILED` | `<artifactId>:commit` | `outputHash`, `bytesDelivered`, `completionStatus`; `requestId` = the request's | — |
| `ACTION_INTENT` | `ALLOW` | `ACTION_DISPATCH` | `ACTION_AUTHORIZED` | `<actionRequestId>:action_intent` | `agentId`, `sessionId`, `actionSeq`, `actionHash` | `action: { tool: { server, name, schemaHash }, parentRequestHash, prevActionHash }` |
| `ACTION_COMMIT` | `ALLOW` | `ACTION_COMMIT` | `ACTION_COMPLETED` or `ACTION_FAILED` | `<actionRequestId>:action_commit` | as above + `outputHash`, `completionStatus` | `action` as above |
| `APPROVAL_REQUESTED` | `BLOCK` | `APPROVAL` | `APPROVAL_REQUIRED` | `<approvalId>:approval_requested` | `approvalRef`, `actionHash` | `approval: { requesterId, policyRuleId }` |
| `APPROVAL_DECIDED` | `ALLOW` if approved, else `BLOCK` | `APPROVAL` | `APPROVED` or `DENIED` | `<approvalId>:approval_decided` | `approvalRef`, `actionHash` | `approval: { requesterId, approverId, decision, notBefore, expiresAt, mfa }` |
| `APPROVAL_EXPIRED` | `BLOCK` | `APPROVAL` | `APPROVAL_EXPIRED` | `<approvalId>:approval_expired` | `approvalRef`, `actionHash` | `approval: { requesterId }` |
| `KILL_SWITCH` | `BLOCK` when activated, `ALLOW` when released | `KILL_SWITCH` | `KILL_SWITCH_ON` or `KILL_SWITCH_OFF` | `<eventId>:kill_switch` | `signature` = `SYSTEM` | `killSwitch: { operatorId, scope, stateHash }` |
| `DLP_TRANSFORM` | `BLOCK` for a blocking action, else `ALLOW` | `DLP` | the DLP action | `<requestId>:dlp_<in\|out>_<n>` (direction and a per-request counter, so several events per request do not collide on the unique `artifactId`) | `dlp` set | — |
| `DELEGATION_ISSUED` / `DELEGATION_REVOKED` | `ALLOW` | `DELEGATION` | `DELEGATION_ISSUED` / `DELEGATION_REVOKED` | `<delegationId>:delegation_issued` / `…:delegation_revoked` | — | `delegation: { chainHash, depth, rootAgentId, parentId }` |

**Required code changes** (deliverables, listed so the freeze is honest about them): `entryBuilder` must accept the new `entryType` values and their
fixed values; `v7Lifecycle`/`buildEntry` validation currently rejects every new type, requires `"UNAVAILABLE"` rather than `null` for the hash
fields of a BLOCK and refuses `outputHash` on anything but a `DECISION` — it is extended so that `COMMIT` and `ACTION_COMMIT` carry `outputHash`
and system entries carry `"UNAVAILABLE"` for the three input hashes (Amendment 1). The convention below is the frozen one.

Defaults for every field not listed in the table, for **all non-`DECISION` v8 entries**: `inputHash`, `requestHash`, `policyHash` are the string `"UNAVAILABLE"` for the **new** entry types of this table (Amendment 1, section 8: `null` would be read as a pre-hash legacy line by every walker and violates the `NOT NULL` columns); the three v7 types keep their v7 values for them; `publicKeyId`, `outputHash`,
`provider`, `model`, `executingProvider`, `semantic`, `tokenUsage`, `responseId`, `consentProvenance`, `policyDecision`, `callerContext` are `null` unless
stated in the table; additionally `verificationResult` stays a boolean as in v7 (`true` for `COMMIT` and `ACTION_*`, which are artifact-driven; `false` for the system entries `KILL_SWITCH`, `APPROVAL_*`, `DLP_TRANSFORM`, `DELEGATION_*`) and `organizationId` is the tenant's organization or `null`; `executionContext` is `null` where the table has "—"; `issuedAt` and `protocolVersion` are copied from the request's `DECISION` for `COMMIT` and from the action artifact for `ACTION_*`, and `null` for system entries (a `COMMIT`/`ACTION_*` entry copies the request's `requestId`/`tenantId`; `reason` of a `DLP_TRANSFORM` entry is `DLP_<ACTION>`, e.g. `DLP_REDACT`); `signature` is `SYSTEM`; `tenantId` is the tenant concerned (`"*"` for the platform-wide
kill switch). For artifact-driven entries (`COMMIT`, `ACTION_*`) `signature` is the artifact's signature as in v7.

`STREAM_OUTCOME_UNKNOWN` (boot reconciliation of an open stream) remains a `DECISION` BLOCK with `completionStatus "OUTCOME_UNKNOWN"` (owner
decision 2026-10-21): a normal end is a `COMMIT`, an unknown end is the reconciler's BLOCK; "unknown" is never a success.

## 4. Verification rules (added to V1 section 9)

* An entry verifies when its `canonical` equals `sortedJSON(coreFields)` for its `schemaVersion` and its `hash` is the domain hash of `canonical`.
* **Authenticity is two-layered, and the chain walk does not need the artifact.** The walk authenticates entries by the hash links and by the signed
  checkpoints and external anchors that cover the head. The artifact signature stored in an entry (`signature`) is verified
  when the artifact itself is supplied — in a `qodiqa-proof/1` bundle — against the envelope hash of the artifact; the value `UNAVAILABLE`
  (pre-authentication BLOCK) and `SYSTEM` (system entries) are not signatures and are not checked.
* A v8 entry after which an older version appears in the same walk is `SCHEMA_DOWNGRADE` (as v7).
* Lifecycle names are the existing ones, extended only for the new types: `MISSING_INTENT`, `INTENT_BEFORE_START`, `ORPHAN_INTENT` keep their v7
  meaning (the `INTENT`/`STREAM_OPENED` ↔ `DECISION` relation). New: `COMMIT_WITHOUT_DECISION` (failure in a walk from GENESIS, warning
  `COMMIT_BEFORE_START` in a bounded walk) and `ORPHAN_ACTION_INTENT` (warning; the boot reconciler turns old ones into an `ACTION_COMMIT`
  with `ACTION_FAILED`/`OUTCOME_UNKNOWN`). A `DECISION` without a `COMMIT` is **not** a warning for BLOCK decisions, for entries without an
  `executingProvider`, or for any `DECISION` written before the first `COMMIT` entry of the chain (v7 and early-v8 decisions). It is
  `ORPHAN_DECISION` (warning) only for a **v8** ALLOW `DECISION` with a non-null `executingProvider`, written after the first `COMMIT` entry of the chain,
  for which no `COMMIT` with the same `requestId` exists and whose own `timestamp` is older than the commit grace period (default 10 minutes) relative to the verification time `nowMs` (a verifier without a clock uses the
  timestamp of the last entry of the walk). The boot reconciler writes the missing `COMMIT` with `completionStatus "OUTCOME_UNKNOWN"`, and a
  `COMMIT` that cannot be written is retried through the durable outbox (migration 094) — it is never dropped.
* `ACTION_INTENT` is written by the **executor**, in the same transaction that consumes the action artifact's `requestId` and advances the session's `nextSeq` (never at authorization); `ACTION_COMMIT` is written after the outcome is known.
* For `ACTION_INTENT` entries, `actionSeq` MUST equal the previous `ACTION_INTENT`'s `actionSeq` of the same `sessionId` + 1 (`ACTION_ORDER_VIOLATION`); an `ACTION_COMMIT` carries the `actionSeq` and `actionHash` of its intent.
* `issuedAt` MUST equal the attached artifact's timestamp when the artifact is supplied (`ISSUED_AT_MISMATCH`).

## 5. Persistence

PostgreSQL stores the entry columns of the mirror in migration **083** (`MIGRATION_LEDGER.md`): nullable columns for the 10 fields, no change to
existing rows. The file chain stores the whole entry JSON. Both are verified by the same code.

## 6. Conformance

Vectors `AUDIT-V8-nnn` (append-only, `VECTORS-FORMAT.md`): one entry per entry type, mixed v7/v8 chains, each verification rule (good and bad), a
downgrade case. They are produced by the implementation and re-derived by `scripts/audit-repro/verify/` (JavaScript). A Python audit verifier does
**not** exist today; it is a deliverable (it must reproduce the float scores of the `semantic` field by implementing the ECMAScript number
serializer of V2-FREEZE 2.2 — the same number work as), and the vectors are not called "re-derived in Python" until it exists.

## 7. Freeze record

| decision | alternatives not taken | consequence |
|---|---|---|
| all 10 fields in one version, always present | add fields per wave | the hash contract is touched once; some fields are `null` for months |
| `dlp` carries both input hashes | only the hash after redaction | the trail proves what the caller sent and what the model saw |
| per-type frozen `executionContext` keys | free-form JSON | a chain of actions/approvals can be verified offline without guessing |
| `COMMIT` for both stream and non-stream; no `STREAM_CLOSED` | two closing types | one closing rule, fewer lifecycle states |
| authenticity from hash links + checkpoints + anchors; artifact signature checked with the artifact | mandatory per-entry signature check in the walk | does not pretend an entry carries data it does not have |
| v8 written from the gate, readers first, flag one-directional | v8 only |'s `issuedAt`/kill switch need it; the one-way nature is stated, not hidden |
| `STREAM_OUTCOME_UNKNOWN` stays a BLOCK | new entry type | "unknown" is never a success |

## 8. Amendments

**Amendment 1.** Section 3 said `inputHash`, `requestHash`, `policyHash` are `null` on entries that carry no request.
Implementing the readers showed this cannot work: (a) every walker (`isLegacyShaped` in the independent verifier, `_isLegacyShaped` in `audit-log.js`, `auditBaseCheck`, `migrate-files-to-pg`) classifies an entry whose `inputHash` is `null` as a **pre-hash legacy line**, which is refused after the first chained entry; (b) the PostgreSQL columns `input_hash`, `request_hash`, `policy_hash` are `NOT NULL`;
(c) five integrity checks require `typeof entry.inputHash === "string"`. The repository already has the convention for "this hash does not apply": the string `"UNAVAILABLE"` (an early BLOCK before authentication). The new entry types therefore carry `"UNAVAILABLE"` in those three fields; every other defaulted field stays `null`.
No v8 entry existed when this was decided (the flag was off), so no hash or verifier compatibility is affected. The shape check of both verifiers (`v8ShapeViolation`, `v8Shape`) enforces it, so an entry with `null` there is `INVALID_ENTRY_SHAPE`.

**Amendment 2 (2026-10-22, decision approved on 2026-10-22 - question option (a)).** Section 4 gave no rule for the sequence of the approval entries. writes `APPROVAL_REQUESTED`, `APPROVAL_DECIDED` and `APPROVAL_EXPIRED`
and an `ACTION_INTENT` that carries an `approvalRef`, so a chain can be checked for who approved what before it ran. New verifier rule (**failure** `APPROVAL_SEQUENCE_VIOLATION`, no change to any entry shape, field or hash): for one `approvalRef`,
`APPROVAL_REQUESTED` comes first and once; then `APPROVAL_DECIDED` (once) or `APPROVAL_EXPIRED`; an `APPROVAL_DECIDED` with reason `APPROVED` may be followed by `APPROVAL_EXPIRED` (granted and never spent) **or** by exactly one `ACTION_INTENT` whose `approvalRef`
is that reference and whose `actionHash` is the approval's; nothing follows `DENIED` or `EXPIRED`; the `actionHash` of every entry of the sequence is the same. In a walk from GENESIS an entry that names an unknown `approvalRef` is a failure; in a bounded walk
it is accepted (the earlier entries may precede the boundary). Implemented in `src/core/audit/v7Lifecycle.js` and `scripts/audit-repro/verify/auditContract.js` (differential tests `src/core/audit/__tests__/approvalSequence.test.js`). Revert = remove the two blocks.

