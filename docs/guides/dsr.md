# GDPR Data Subject Rights (DSR) Framework — QODIQA

**Version:** 1.1
**Date:** 2026-07-18
**Scope:** Articles 16 (Rectification), 17 (Erasure), 18 (Restriction), 20 (Portability)
**Remediates:** "Zero data-subject-rights tooling anywhere in the platform"; Compliance Finding no extension point for operator-owned PII stores (§16)

---

## 1. Introduction and Scope

This document describes the DSR framework added to remediate. It is
the implementation companion to, which
remains the platform's broader GDPR assessment — read that document first for
the data-flow analysis and controller/processor classification this
framework builds on. Section 4 of that document (Articles 16/17/18/20) has
been updated to point here.

QODIQA is a data **processor** (`gdpr.md` §3). Everything below describes
tooling the platform provides to operators (controllers) to fulfill DSR
requests they receive from their own data subjects — it does not change
QODIQA's processor role or invent a consumer-facing identity system.

## 2. Who Is a "Data Subject" in QODIQA

QODIQA has no end-user accounts of its own. The only person-like identifier
anywhere in the platform is `actor_id` — an opaque, operator-defined string
in the consent system (`src/core/consent/ConsentStore.js`), documented as
potentially identifying a natural person (`gdpr.md` §2.1). **This framework's
scope is `actor_id` only.** `rbac_users` (platform admin/operator logins),
organizations, and tenants are QODIQA's own operator identities, not data
subjects under this framework, and are out of scope.

Every DSR request (`dsr_requests.actor_id`) therefore addresses a specific
`actor_id`, and every right acts on that actor's rows in `consent_records`
and `consent_audit_log` — the only tables in the platform that hold
actor-linked, potentially personal data (verified directly from source; see
`gdpr.md` §2.1 for the full data-store inventory).

## 3. What Is, and Is Not, Rewritten

Two categories of storage behave very differently under this framework, and
conflating them was the root cause never being addressed casually:

| Store | Mutable? | Why |
|---|---|---|
| `consent_records` (current state) | **Yes** | Descriptive PII fields (`subject_name`, `metadata`, `tags`) are updatable in place. This is where Article 16/17/18 execute. |
| `consent_audit_log` (history) | **No** | Append-only by design (`ConsentStore.js:9-10`: "Records are never deleted... The audit log is append-only; updates to it are never issued"). No `UPDATE`/`DELETE` grant and no `UPDATE`/`DELETE` RLS policy exist for this table (migrations 018, 022). This framework does not add one. |
| `audit.log` / `platform_audit_events` (`ENFORCEMENT` category) — the cryptographic hash chain | **No** | No `actor_id` field exists in the chain schema (`entryBuilder.js` `CORE_HASH_FIELDS_V2`); no deletion/redaction primitive exists (`audit-log.js` exposes only `append()`/`appendMandatory()`); `retention.js` hard-excludes `ENFORCEMENT` events from automated deletion by explicit code guard (`retention.js:9,120,139,210`). |

This is a deliberate design decision, not a gap: GDPR Article 17(3)(b)
permits retaining data necessary for compliance with a legal obligation, and
17(3)(e) permits retention for the establishment, exercise, or defence of
legal claims. A tamper-evident enforcement record is exactly that kind of
legal-obligation data, and it contains no PII to begin with — see §7 below
for how erasure documents this explicitly on every request rather than
silently ignoring it.

## 4. Request Lifecycle

Every DSR request moves through a linear state machine, enforced by
`src/core/dsr/DataSubjectRightsService.js` and persisted in `dsr_requests`
(migration `028_dsr_framework.sql`):

```
RECEIVED → IDENTITY_VERIFIED → APPROVED → IN_PROGRESS → COMPLETED
                              ↘ REJECTED (identity verification failed)
                                                       ↘ FAILED (execution error)
```

- **RECEIVED** — `DataSubjectRightsService.createRequest()` opens a case file.
- **IDENTITY_VERIFIED** / **REJECTED** — `verifyIdentity()` records the outcome (§5).
- **APPROVED** — `approve()`; only reachable once identity is `VERIFIED`
  (`identityVerification.assertVerified`).
- **IN_PROGRESS → COMPLETED** — the right-specific service executes; only
  reachable from `APPROVED` (`identityVerification.assertApproved`, checked
  by every execution service).
- **FAILED** — any execution error is caught centrally in
  `DataSubjectRightsService._execute()`, which records the failure as a
  lifecycle event before re-raising the original error, so failures are
  never silently swallowed.

Every transition writes a row to `dsr_request_events` (append-only,
checksummed the same way as `consent_audit_log`) **and** emits a structured
`services/logger.js` event (`DSR_*`, classified `ACCESS_CONTROL` —
`src/core/audit/centralStore.js`), so every DSR request is itself an audit
event, per the task requirement, without inventing a parallel audit
mechanism.

## 5. Identity Verification — Model and Limits

QODIQA has no consumer-facing authentication. It cannot verify that the
person submitting a DSR request is the data subject the same way a
consumer product with logins can. **This is a real limitation, stated
plainly rather than worked around.**

What the framework does instead (`src/core/dsr/identityVerification.js`):
the RBAC-authenticated operator handling the request (already gated by
`opsAuth`/`rbac` — see §11) explicitly attests, on the record, how they
confirmed the requester's identity through their own out-of-band channel:

| Method | Meaning |
|---|---|
| `OPERATOR_ATTESTATION` | The operator's own support/KYC channel confirmed identity. |
| `PRIOR_ACCOUNT_VERIFICATION` | The requester was previously verified through an existing account/session in the operator's system. |
| `LEGAL_REQUEST` | The request is accompanied by a legal instrument (subpoena, court order, etc.). |

This is a **compensating control**: it makes the verification decision
attributable (`identity_verified_by`, `identity_verified_at`) and auditable
(`DSR_IDENTITY_VERIFIED` / `DSR_IDENTITY_VERIFICATION_FAILED` events), which
prevents an unauthenticated caller from ever reaching execution — no
execution service accepts a request that isn't `APPROVED`, and `APPROVED` is
unreachable without a `VERIFIED` result. It is not a claim that QODIQA
independently authenticates data subjects; that responsibility remains with
the operator, consistent with QODIQA's processor role (`gdpr.md` §3).

## 6. Article 16 — Rectification

`src/core/dsr/RectificationService.js` corrects a fixed allow-list of
mutable PII fields on a `consent_records` row: `subject_name`, `metadata`,
`tags` (`ConsentStore.RECTIFIABLE_FIELDS`). `actor_id`, `action`, `state`,
and timestamps are never rectifiable through this path — identity changes
are erasure (§7), state changes are lifecycle transitions, each with their
own audit semantics.

`ConsentStore.rectify()` performs the `UPDATE` and appends a
`CONSENT_RECTIFIED` entry to the existing `consent_audit_log` (no new audit
primitive). In addition, `RectificationService` writes one append-only
before/after row per corrected field to the new `dsr_rectifications` table
— superseded values are never overwritten, giving Article 16's "preserve
history, link superseded values" its own queryable trail scoped to the DSR
request, independent of the wider consent audit log.

## 7. Article 17 — Erasure

`src/core/dsr/ErasureService.js`:

1. For every `consent_records` row belonging to the actor,
   `ConsentStore.anonymize()` scrubs `subject_name` → `NULL`, `metadata` →
   `{}`, `tags` → `[]`, and forces the record into the terminal `REVOKED`
   state if it isn't already terminal (`EXPIRED` records stay `EXPIRED` —
   the state machine has no `EXPIRED → REVOKED` transition, and
   re-labeling isn't legally necessary). This is idempotent: erasing an
   already-erased actor re-applies the same scrub and records a fresh audit
   entry, so repeat requests remain fully auditable.
2. **Optional, opt-in** (`pseudonymizeActorId: true`): additionally
   pseudonymizes `actor_id` via `ConsentStore.pseudonymizeActor()` —
   `HMAC-SHA256(actorId, pepper)`, written only to `consent_records`. Off by
   default because `actor_id` is usually already a system/pseudonymous
   identifier, and rewriting it unconditionally would silently break an
   operator's own correlation; deployments where an operator populated
   `actor_id` with something directly identifying (e.g. an email) can opt in.
   The proof of this operation (`DSR_ACTOR_PSEUDONYMIZED` event) records a
   SHA-256 hash of the original `actor_id` and the pseudonym, **never the
   original value itself**.
3. Every erasure result documents `recordsRetained[]` explicitly — see the
   table below — rather than silently omitting untouched stores.

**This is the only code path that performs erasure.** The consent
management API's own revocation endpoints (`POST /consent/:id/revoke`,
`POST /consent/actor/:actorId/revoke`, and its deprecated legacy alias
`DELETE /consent/actor/:actorId` — see `docs/api/overview.md`) call
`ConsentStore.revoke()`, a state transition to `REVOKED` only. They never
call `ConsentStore.anonymize()`/`pseudonymizeActor()` above, never scrub a
PII field, and are not a substitute for the erasure workflow in this
section. The legacy `DELETE` route's misleading naming — a DELETE verb
implying a deletion that never happened — was (remediated
2026-07-21; see); this distinction predates
and is unaffected by that remediation, since revocation and erasure were
always, and remain, structurally separate functions with separate audit
event types (`CONSENT_REVOKED` vs. `CONSENT_ERASED`).

### What erasure does *not* touch, and why

| Store | Legal basis for retention | Compensating control |
|---|---|---|
| `audit.log` (cryptographic hash chain) | Art. 17(3)(b) — legal obligation to maintain a tamper-evident enforcement record; Art. 17(3)(e) — establishment/exercise/defence of legal claims | No `actor_id`/PII field exists in the chain schema to begin with; access is RBAC-gated (`READ_AUDIT`) |
| `platform_audit_events` (`ENFORCEMENT` category) | Same as above | `retention.js` hard-excludes this category from all automated deletion by design |
| `consent_audit_log` | Art. 17(3)(b) — necessary to demonstrate the integrity and history of consent-driven enforcement decisions | Append-only by pre-existing design (no `UPDATE`/`DELETE` grant or policy); access is RBAC-gated (`READ_AUDIT`/`MANAGE_CONSENT`); if `pseudonymizeActorId` was used, historical rows retain the **pre**-pseudonymization `actor_id` as immutable historical fact — this is the one known residual-disclosure limitation of the pseudonymization option, documented here rather than silently accepted |

## 8. Article 18 — Restriction

`src/core/dsr/RestrictionService.js` transitions every `ACTIVE`
`consent_records` row for the actor into the **existing** `SUSPENDED` state
— a transition the state machine already supports
(`ACTIVE ↔ SUSPENDED`, `ConsentStateModel.js:14-15`) — tagging
`suspension_reason = 'DSR_RESTRICTION:<requestId>'` so a later `lift()` call
resumes only the records this exact request restricted, never an unrelated
operator-issued suspension on the same actor.

This is the load-bearing reuse decision in the whole framework: every
consent verification call in the enforcement pipeline already gates on
`ConsentStateModel.isActiveNow()`/`effectiveState()`
(`ConsentStateModel.js:72-95`), so a suspended actor is automatically denied
at **every** existing enforcement point — restriction requires zero new
enforcement-side code. "Restriction status must be enforced everywhere
personal processing occurs" falls out of a state machine that already
exists, rather than requiring a new gate threaded through the codebase.

## 9. Article 20 — Portability

`src/core/dsr/PortabilityService.js` assembles a machine-readable export of
everything QODIQA holds about an `actor_id`: current + historical consent
records (`ConsentStore.list()`), the full consent audit trail
(`ConsentStore.getAuditLog()`), and the actor's own DSR request history
(`DSRStore.list()`). Supported formats: **JSON** (full package) and **CSV**
(consent records, flattened).

- **Checksum**: SHA-256 computed over the *exact bytes returned to the
  caller* — not a separately-canonicalized form — so the checksum the
  subject receives always verifies against their actual copy.
- **Storage**: only the checksum, format, size, and requester are persisted
  (`dsr_exports`) — the export payload itself is never stored server-side,
  so portability doesn't create a second at-rest copy of personal data.
- **Excluded**: private keys, Ed25519 signatures, API-key material — none of
  which exist in `consent_records`/`consent_audit_log` in the first place.
  `record_hash`/audit `checksum` fields **are** included: they are
  non-secret integrity hashes useful to the subject for verifying their own
  export, not secrets.
- **Known limitation**: the cryptographic audit chain (`audit.log`) has no
  `actor_id` field and cannot be reliably joined to a specific subject (see
  §3), so it is not included in the export. This is stated in the export's
  own `metadata.note` field, not silently omitted.

## 10. Audit Integration

Every DSR lifecycle transition is recorded twice, by design, for two
different audiences:

1. **`dsr_request_events`** — an append-only, checksummed table scoped to
   the request, mirroring `consent_audit_log`'s pattern exactly
   (`DSRStore.js` `_appendEvent()`). This is the record an auditor pulls up
   for one specific DSR case.
2. **`services/logger.js` `emit()`** — every `DSR_*` event flows into the
   general operational event store (`src/core/audit/centralStore.js`),
   classified `ACCESS_CONTROL` via the `DSR_` prefix mapping added
   alongside `RBAC_` (`centralStore.js`). This is the record that shows up
   in cross-cutting operational/security views alongside every other
   platform event.

## 11. Access Control

Two new RBAC permissions (`src/core/rbac/roles.js`), following the
`MANAGE_RETENTION` precedent (admin + compliance) rather than
`MANAGE_CONSENT` (admin-only) — DSR execution is a compliance function:

| Permission | Roles | Covers |
|---|---|---|
| `READ_DSR` | admin, auditor, compliance | List/inspect requests and their event trail |
| `MANAGE_DSR` | admin, compliance | Create, verify identity, approve, and execute any right |

Every admin route in `src/api/routes/admin/dsr.js` is gated by one of these
via the standard `adminStack()` composition (`server.js`) — rate limit → IP
allowlist → ops auth → RBAC resolve → `requirePermission()` → kill switch —
identical to every other admin router in the platform.

## 12. Administrative API

Mounted at `/v1/admin/dsr`:

| Method & Path | Permission | Purpose |
|---|---|---|
| `GET /v1/admin/dsr` | `READ_DSR` | List requests (filterable by actorId, tenantId, status, requestType) |
| `GET /v1/admin/dsr/:id` | `READ_DSR` | Request detail + full lifecycle event trail |
| `POST /v1/admin/dsr` | `MANAGE_DSR` | Create a request (`requestType`, `actorId`, ...) |
| `POST /v1/admin/dsr/:id/verify-identity` | `MANAGE_DSR` | Record identity verification (§5) |
| `POST /v1/admin/dsr/:id/approve` | `MANAGE_DSR` | Approve a verified request for execution |
| `POST /v1/admin/dsr/:id/rectify` | `MANAGE_DSR` | Execute Article 16 |
| `POST /v1/admin/dsr/:id/erase` | `MANAGE_DSR` | Execute Article 17 (`pseudonymizeActorId` optional) |
| `POST /v1/admin/dsr/:id/restrict` | `MANAGE_DSR` | Execute Article 18 |
| `POST /v1/admin/dsr/:id/lift` | `MANAGE_DSR` | Lift a completed Article 18 restriction |
| `POST /v1/admin/dsr/:id/export` | `MANAGE_DSR` | Execute Article 20 (`format`: `JSON`\|`CSV`) |

Response envelope matches the platform's newer routers (`compliance.js`):
`{ status: 'success', timestamp, requestId, data }` on success,
`{ status: 'error', timestamp, requestId, error: { code, message } }` on
failure. Gate failures (identity not verified / not approved) return `409`;
not-found returns `404`; validation and other execution errors return `400`.
Picked up automatically by the OpenAPI route scanner (`src/openapi/`) — no
manually-maintained spec file.

## 13. Administrator Runbook

A typical erasure request, end to end:

1. `POST /v1/admin/dsr` — `{ requestType: 'ERASURE', actorId: '<actor>', legalBasis: '...' }`
2. Confirm the requester's identity through your own channel, then
   `POST /v1/admin/dsr/:id/verify-identity` — `{ method: 'OPERATOR_ATTESTATION', result: 'VERIFIED', evidence: '...' }`
3. `POST /v1/admin/dsr/:id/approve`
4. `POST /v1/admin/dsr/:id/erase` — add `pseudonymizeActorId: true` only if
   `actor_id` in your deployment is itself directly identifying
5. `GET /v1/admin/dsr/:id` to retrieve the completed request's `result`
   (actions taken, records retained with legal justification) as evidence

Rectification, restriction, and portability follow the same
create → verify-identity → approve → execute shape.

## 14. Testing

See `src/core/dsr/__tests__/*.test.js` (unit, mocked persistence),
`src/api/routes/admin/dsr.test.js` (integration, mocked service layer —
covers RBAC gating with the real permission matrix, validation, error→status
mapping, full lifecycle happy paths), `src/infra/postgres/__tests__/migration028.test.js`
(migration runner + static content checks), and the extended
`src/core/consent/consent.test.js` (`rectify()`/`anonymize()`/`pseudonymizeActor()`).
Full counts are in the verification report
Operator extension target
coverage is in `ErasureTargetRegistry.test.js` and
`erasureTargetExtensions.test.js` — see §15.9.

## 15. Operator Extension Interface for Custom PII Stores

**Status: Implemented**

Sections 6–9 above describe erasure/portability for the stores QODIQA
itself owns (`consent_records`, `consent_audit_log`). Operators frequently
also hold `actor_id`-linked personal data in systems QODIQA has no
knowledge of — a CRM, a ticketing system, a billing database, a bespoke
PostgreSQL table, object storage, a third-party integration. Before this
remediation there was no formal way to bring such a store into a DSR
request; an operator's only option was a manual, out-of-band process
running alongside — and undocumented by — the DSR framework. This section
introduces `ErasureTargetRegistry.js`, a small, additive extension point
that closes that gap without touching QODIQA core code per integration.

### 15.1 Design principles

Matching the rest of this framework rather than introducing a new paradigm:

- **Deterministic execution** — targets run in registration order, always.
- **Explicit registration** — operators call `registerTarget()` directly at
  startup. No filesystem scanning, no plugin loading, no reflection, no DI
  container.
- **Auditable** — every invocation produces a `dsr_request_events` row via
  the existing `DSRStore.appendEvent()` trail (§10); no second audit system.
- **Additive only** — a deployment with zero registered targets behaves
  identically to before this remediation. No configuration change or
  migration is required to keep existing behavior.
- **Isolated failure** — one broken/unavailable operator system can never
  abort the DSR request or block any other target from running.

### 15.2 The `ErasureTarget` interface

Defined and fully documented in `src/core/dsr/ErasureTargetRegistry.js`:

```js
{
  id:     string,              // required, unique, stable across restarts
  name:   string,              // required, human-readable (audit/logs)
  erase:  async (context) => any,   // required
  export: async (context) => any,   // optional — omit if the store doesn't
                                     // support portability
}
```

`context`, supplied by QODIQA to every callback, is intentionally minimal —
just enough to perform an actor-scoped operation, nothing about QODIQA's
internal request/DB shape:

```js
{
  actorId:     string,          // the data subject's actor_id
  tenantId:    string | null,   // tenant scope, if applicable
  requestId:   string,          // the DSR request this invocation belongs to
  requestType: 'ERASURE' | 'PORTABILITY',
  performedBy: string,          // the operator/actor executing the DSR request
}
```

A callback's return value is opaque to QODIQA and is recorded verbatim as
that target's `result` in both the DSR response and the audit trail — so a
target should return only what belongs there (e.g. a row count), never raw
PII.

### 15.3 Registration

Explicit and synchronous, done once per target during application startup:

```js
const DataSubjectRightsService = require('./src/core/dsr/DataSubjectRightsService');

DataSubjectRightsService.registerErasureTarget({
  id:   'crm',
  name: 'Acme CRM',
  async erase({ actorId, tenantId }) {
    const rowsDeleted = await crmClient.purgeContact(actorId, { tenantId });
    return { rowsDeleted };
  },
  async export({ actorId }) {
    const contact = await crmClient.getContact(actorId);
    return contact ?? null;
  },
});
```

`registerErasureTarget`/`unregisterErasureTarget`/`listErasureTargets` on
`DataSubjectRightsService` are plain pass-throughs to
`ErasureTargetRegistry.registerTarget()`/`unregisterTarget()`/`getTargets()`
— exposed there so operator startup code has one DSR module to depend on,
consistent with `DataSubjectRightsService` already being "the single entry
point" for everything else in this framework (§1). The registry module
itself holds no business logic — it only stores and returns targets;
`unregisterTarget()`/`clear()` exist for tests and hot-reload scenarios, not
as part of normal runtime operation.

### 15.4 Execution flow

- **Erasure** (`ErasureService.erase()`) — after every built-in
  `consent_records` row for the actor is anonymized (§7), every registered
  target's `erase()` is invoked, in registration order, with the context
  above. Built-in erasure always runs first and is never skipped or
  reordered by a target.
- **Portability** (`PortabilityService.generateExport()`) — after the
  built-in JSON/CSV payload and its checksum are computed, every registered
  target's `export()` is invoked, in registration order. A target with no
  `export` callback is reported with `status: 'NOT_SUPPORTED'` — never
  silently skipped. Target results are returned alongside the payload
  (`customTargets`), not embedded inside the checksummed bytes, so the
  existing "checksum covers exactly the returned payload" guarantee (§9) and
  the CSV format's fixed column schema are unaffected by how many targets
  are registered.

Each invocation produces one deterministic result record:

```js
{
  targetId:    string,
  targetName:  string,
  operation:   'ERASE' | 'EXPORT',
  status:      'COMPLETED' | 'FAILED' | 'NOT_SUPPORTED',
  success:     boolean,
  startedAt:   string,   // ISO-8601
  durationMs:  number,
  result:      any,      // the callback's return value, or null
  error:       string | null,
}
```

These records are collected into `result.customTargets[]` on the DSR
request (visible via `GET /v1/admin/dsr/:id`, §12) and returned directly
from `generateExport()`'s response object.

### 15.5 Failure handling

A registered target is an untrusted extension point. If its callback
throws, that one invocation is recorded with `status: 'FAILED'` and the
error's message — the loop continues to the next target, and the overall
DSR request still reaches `COMPLETED`. No exception from a target callback
is ever swallowed silently: it is always visible in both the response and
the audit trail (§15.6). This mirrors the framework's existing failure
philosophy (§4): failures are recorded, never hidden, and never allowed to
corrupt state.

### 15.6 Audit behavior

Every target invocation appends one `dsr_request_events` row via the
existing `DSRStore.appendEvent()` (the same append-only, checksummed table
described in §10 — no separate audit primitive), with `event_type`
`DSR_EXTENSION_TARGET_ERASED` or `DSR_EXTENSION_TARGET_EXPORTED` and a
`detail` payload matching the result record in §15.4 (target identifier,
operation, success/failure, timestamp, duration, status, and error
information when applicable).

### 15.7 Determinism and thread safety

Targets are invoked in **registration order** — chosen over an
identifier-sort because it lets an operator's startup code read top-to-bottom
as the exact execution order, with no separate ordering rule to remember.
The registry stores targets in a plain array (never a plain-object key set),
specifically so ordering never depends on JavaScript's object-key iteration
rules. All registry operations are synchronous, and Node.js's single-threaded
event loop means there is no interleaving hazard as long as callers don't
`await` mid-registration (they don't need to).

### 15.8 Best practices

- Keep `id` stable across deployments/restarts — it is the durable
  identifier that ties audit history to a specific operator system.
- Return small, non-PII-bearing summaries from `erase()`/`export()` (counts,
  booleans, opaque references) — the return value is stored verbatim in the
  DSR response and audit trail.
- Treat `erase()` as idempotent where possible, the same way the built-in
  erasure path is (§7) — a repeated DSR request against an already-erased
  actor should not error.
- Register targets once, at startup, before the DSR admin API starts
  serving requests — this framework has no mechanism to notice a target
  registered mid-request.

### 15.9 Testing

`src/core/dsr/__tests__/ErasureTargetRegistry.test.js` covers the registry
in isolation (validation, registration order, `unregisterTarget`/`clear`).
`src/core/dsr/__tests__/erasureTargetExtensions.test.js` covers the
integration: a registered target is invoked exactly once with the correct
actor-scoped context, its result appears in both the DSR response and the
`dsr_request_events` audit trail, a failing target is isolated without
aborting the request, an export-incapable target is reported
`NOT_SUPPORTED`, and — with zero targets registered — behavior is
unchanged from before this remediation.

## 16. Known Limitations

Stated plainly, not glossed over:

- **Identity verification is attestation-based**, not independent
  authentication — see §5.
- **Portability cannot include the cryptographic audit chain** — it has no
  `actor_id` field to join on — see §9.
- **Pseudonymized `actor_id` remains visible in `consent_audit_log` history**
  — that table is immutable by pre-existing design — see §7.
- **Scope is `actor_id` only** — platform operator/admin identities
  (`rbac_users`, organizations, tenants) are not covered by this framework
  (§2); if an operator needs DSR tooling for its own platform-user
  identities, that is a separate, unscoped effort.
- **Operator extension targets are only as reliable as the operator's own
  systems** (§15) — QODIQA isolates and records a target's failure, but
  cannot make an unreachable third-party store succeed. A `FAILED` or
  `NOT_SUPPORTED` entry in `customTargets` means the operator must complete
  that portion of the request through their own remediation process; it is
  surfaced, not resolved, by this framework.
