# Multi-Tenant Organization Support — Component #39

QODIQA supports a two-level tenant hierarchy: **Organizations** (billing and
administrative entities) own **Tenants** (isolated execution contexts).  Every
AI execution request is cryptographically bound to a tenant identity derived
from the signing key; that identity is resolved to an organization before any
enforcement work begins.

---

## 1. Architecture Overview

```
┌────────────────────────────────────────────────────────┐
│                     Organization                       │
│  organizationId  organizationName  status  quotas      │
│                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │   Tenant A   │  │   Tenant B   │  │   Tenant C  │  │
│  │  (active)    │  │  (suspended) │  │  (active)   │  │
│  └──────────────┘  └──────────────┘  └─────────────┘  │
└────────────────────────────────────────────────────────┘
```

**One Organization → N Tenants.**  A tenant belongs to exactly one
organization.  A tenant without an organization is still valid (backward
compatibility — see §6).

---

## 2. Organization Model

| Field              | Type     | Notes                                         |
|--------------------|----------|-----------------------------------------------|
| `organizationId`   | UUID v4  | Immutable primary key, generated or supplied  |
| `organizationName` | string   | Mutable display name (max 128 chars)          |
| `status`           | enum     | `active` \| `suspended` \| `disabled`         |
| `createdAt`        | ISO-8601 | Set at registration, never changed            |
| `updatedAt`        | ISO-8601 | Updated on every mutation                     |
| `metadata`         | object   | Arbitrary key/value, merged non-destructively |
| `quotas`           | object   | Per-org limits (see §7)                       |
| `tenantIds`        | string[] | Reverse index — set of owned tenant IDs       |

### Status Lifecycle

```
         ┌──────────┐
   ───▶  │  active  │ ◀────────────────────────┐
         └────┬─────┘                           │
              │ suspend                         │ reactivate
              ▼                                 │
         ┌──────────┐                           │
         │suspended │ ─────────────────────────▶┘
         └────┬─────┘
              │ disable
              ▼
         ┌──────────┐
         │ disabled │  (terminal — no reactivation path enforced)
         └──────────┘
```

A `suspended` or `disabled` organization causes **all tenant requests** to be
blocked at Step 1c of the enforcement pipeline before any nonce or anomaly
quota is consumed.

---

## 3. Tenant Model (Component #39 extensions)

| Field            | Type     | Notes                                             |
|------------------|----------|---------------------------------------------------|
| `tenantId`       | string   | `[A-Za-z0-9_-]{1,64}`, matches key ID prefix     |
| `tenantName`     | string   | Mutable display name                              |
| `organizationId` | UUID v4  | Owning org; `null` for unassigned tenants         |
| `status`         | enum     | `active` \| `suspended` \| `disabled` \| `inactive` |
| `quotas`         | object   | Per-tenant overrides; `null` falls through to org |
| `createdAt`      | ISO-8601 | Immutable                                         |
| `updatedAt`      | ISO-8601 | Updated on every mutation                         |

---

## 4. Tenant Resolution

Tenant identity is **cryptographically derived** from the signing key — it
cannot be spoofed via headers or request body fields.

```
publicKeyId = "${tenantId}:key_v${version}"
                 ▲
                 └─── split(':')[0] → tenantId
```

This derivation happens inside `validateBoundRequest` immediately after
Ed25519 signature verification (Step 1b).

---

## 5. Enforcement Pipeline — Organization Check

```
Step 1 : validateArtifact()          — Ed25519 + schema + time bounds
Step 1b: assertActiveTenant()        — registry lookup, status check
Step 1c: assertActiveOrganization()  — org lookup, status check        ← NEW
Step 2 : verifyRequestBinding()      — requestId + requestHash
Step 3 : registerNonce()             — atomic replay prevention
Step 4 : checkAnomaly()              — per-key + global rate windows
Step 5 : checkPolicy()               — the tenant's policy set if one is
                                       stored, else the global set (§8)
```

Step 1c inserts **before** nonce registration, so a suspended/disabled
organization does not consume nonce or anomaly quota for blocked requests.

### Enforcement Results

| Condition                          | Result                                |
|------------------------------------|---------------------------------------|
| org active, tenant active          | `allowed: true`, `organizationId` set |
| org suspended                      | `allowed: false`, `reason: ORG_SUSPENDED` |
| org disabled                       | `allowed: false`, `reason: ORG_DISABLED`  |
| tenant has no org (legacy)         | `allowed: true`, `organizationId: null`   |
| tenant suspended                   | `allowed: false`, `reason: TENANT_SUSPENDED` |
| tenant disabled/inactive           | `allowed: false`, `reason: TENANT_INACTIVE`  |
| org-status sync channel disconnected | `allowed: false`, `reason: ORG_STATUS_SYNC_UNAVAILABLE` |
| org-status knowledge older than the bounded-propagation window | `allowed: false`, `reason: ORG_STATUS_STALE` |

---

## 6. Backward Compatibility

Tenants provisioned before Component #39 have no `organizationId`.  The
enforcement guard treats an **unassigned tenant as passing the org check** —
`assertActiveOrganization` returns `{ valid: true, organizationId: null }`.

All existing API keys and pre-existing test fixtures continue to work without
modification.  The `default` tenant (auto-created at keystore startup) is
never org-assigned and always passes.

---

## 7. Quota Resolution

Quotas are resolved at enforcement time using a three-tier priority:

```
1. Test override  (_thresholds injected by test harness)
2. Organization quotas  (from organizationRegistry)
3. Platform defaults  (DEFAULT_QUOTAS)
```

| Quota field                 | Default  | Notes                              |
|-----------------------------|----------|------------------------------------|
| `maxRequestsPerMinute`      | 5,000    | Per-org global anomaly ceiling     |
| `maxRequestsPerKeyPerMin`   | 100      | Per-key anomaly ceiling            |
| `maxStreamingSessions`      | 500      | Concurrent SSE sessions            |
| `retentionDays`             | 365      | Audit log retention period         |

Tenant-level quota overrides (`tenant.quotas`) are stored but currently flow
through the same resolution path as org quotas.  Per-key anomaly detection in
`checkAnomaly.js` uses `getQuotasForTenant()` to derive per-org thresholds.

---

## 8. Policy Scoping

**Actual behaviour (2026-08-26; policy floor added,
2026-08-26 — this section previously described an aspirational three-level
model that was never implemented):**

- **Per-tenant policy sets are real and governed, subject to a
  non-negotiable floor.** A tenant MAY have its own policy set, persisted
  authoritatively in PostgreSQL (`tenant_policy_sets`, migration 051),
  hydrated into `tenantPolicyRegistry` at boot and kept fresh by a periodic
  refresh. When present, the tenant's set **REPLACES** the global
  policy set (control plane; `policies.json` is import-only) for that tenant's `/ai/chat` evaluation (there is no
  layered platform→org→tenant merge — a tenant's *stored* set is the
  complete custom set for that tenant) — **but the set actually enforced is
  always floor ∪ tenant set.** The floor is every currently-enabled global
  policy (`REQUIRE_CONSENT` plus every other enforcement/denial policy — §6a): a tenant set may add
  policies and may tighten a floor policy's parameters, but may never
  disable, retype, or loosen one — enforced at draft/publish time (400
  `VALIDATION_FAILED`, naming the floor policy) and, belt and braces, at
  load time (a tampered stored row is restored with a
  `TENANT_POLICY_FLOOR_RESTORED` audit event). A tenant set that never
  mentions `REQUIRE_CONSENT` at all is legal to store — the floor is
  merged in live on every evaluation, so consent (and every other floor
  policy) is still required. The admin read below reports exactly what the
  tenant published, not the floor-inflated effective count. A tenant with
  **no** stored set gets the global policy set unchanged (the control-plane
  set; `policies.json` only seeds an empty store) — byte-for-
  byte the single-tenant behaviour.
- **Writes go only through the governed change-request flow** (
  `/v1/policy/governance`): a draft carrying a `tenantId` targets that
  tenant's set; maker-checker review/approval/publish apply unchanged, and
  every lifecycle event records the tenant id. There is no direct
  tenant-policy write API.
- **Per-tenant semantic configuration exists and is TIGHTEN-ONLY** —
  tier thresholds may only be lowered, `WARN_BLOCKS` only enabled, and an
  additional embedding score bar only at-or-below the pinned global
  threshold; loosening (or touching `REVIEW_BLOCKS`, classifiers, gates,
  FT flags) is rejected at write time and clamped at load time. Managed
  through the same governed flow with the reserved policyId
  `TENANT-SEMANTIC-CONFIG`., and §7 there
  for how a tenant's effective config hash is stamped into decision
  evidence.
- Reads: `GET /v1/admin/tenants/:tenantId/policy-config` (admin stack)
  reports the effective per-tenant configuration and its fallback state.
- Deployments without PostgreSQL never hydrate tenant configuration:
  every tenant runs on the global policy set and pinned semantic defaults
  (production requires PostgreSQL, so this only describes
  dev/file mode).
- Organization-level policy scoping does **not** exist. A platform → org →
  tenant hierarchy remains a possible future design, not current
  behaviour.

---

## 9. Nonce Isolation

Each tenant's nonces are namespaced with a scoped key (`docs/protocol/QODIQA-PROTOCOL.md`) — the tenant prefixes the WHOLE key, including the store's own
`qodiqa:req:v2:` prefix, not just the `requestId`:

```
nonce store key = "${tenantId}:qodiqa:req:v2:${requestId}"
```

Two different tenants may legitimately use the same `requestId` value in the
same time window without triggering replay detection.  A replay within the
same tenant is still caught.  `nonceStore.buildNonceKey(requestId, tenantId)`
is the single source of truth for this format.

---

## 10. Metrics Cardinality

Three organization-level Prometheus metrics are registered:

| Metric                        | Type    | Labels                        |
|-------------------------------|---------|-------------------------------|
| `qodiqa_org_requests_total`   | Counter | `organizationId`, `tenantId`  |
| `qodiqa_org_blocks_total`     | Counter | `organizationId`, `tenantId`  |
| `qodiqa_org_active_sessions`  | Gauge   | `organizationId`              |

**Cardinality**: bounded by the number of registered organizations × tenants.
Because both registries are finite and provisioned by operators (not derived
from end-user input), cardinality is predictable and does not grow with
request volume.

---

## 11. Administration API

All admin routes require ops-level authentication (`_opsIpAllow` + `_opsAuth`
+ `_rbacGate`) and are mounted at `/v1/admin/`.

<!-- two operator prerequisites this section did not state, both
     reproduced by a literal rehearsal against the Compose reference
     topology (NODE_ENV=production). -->
> **Before using this API in production:**
>
> 1. **The admin surface is off by default.** Every admin route also sits
>    behind the ops kill-switch (`src/middleware/opsEnabled.js`,
>    `docs/security/SECURITY_GUIDE.md` §10.1), and `QODIQA_ADMIN_ENABLED`
> (its own switch since `QODIQA_DIAGNOSTICS_ENABLED` no longer opens
> it) defaults to
>    `false` when `NODE_ENV=production`. Until it is set to `true`, `POST /v1/admin/tenants` returns `404 NOT_FOUND` even for a
>    fully authenticated admin whose RBAC check passed — by design, so a
>    disabled surface cannot be enumerated. Neither
>    `deploy/docker/docker-compose.prod.yml` nor the Kubernetes manifests set
>    it; enable it deliberately (and only for as long as you need it), or
>    register tenants out-of-band via `registerTenant()` against the same
>    `TENANT_STORE_PATH` the server reads.
> 2. **A registered tenant cannot sign until it has its own signing key.**
>    Tenant identity is derived from the key prefix (§4), so `POST /sign` for a
>    signing identity scoped to a newly registered `tenantId` fails closed with
>    `503 KEY_UNAVAILABLE` until a key exists for that exact id — provision it
>    the same way as the first key (`docs/deployment/deployment-lifecycle.md` Step 1:
>    `keyManager.rotate('<tenantId>')`), then restart (or wait for the key
>    store's periodic reload).

### Organizations

| Method   | Path                                         | Action                     |
|----------|----------------------------------------------|----------------------------|
| `POST`   | `/v1/admin/organizations`                    | Register organization      |
| `GET`    | `/v1/admin/organizations`                    | List all organizations     |
| `GET`    | `/v1/admin/organizations/:orgId`             | Get organization           |
| `PATCH`  | `/v1/admin/organizations/:orgId`             | Update name/status/quotas  |
| `POST`   | `/v1/admin/organizations/:orgId/tenants/:id` | Assign tenant to org       |
| `DELETE` | `/v1/admin/organizations/:orgId/tenants/:id` | Remove tenant from org     |

#### Register organization (POST /v1/admin/organizations)

```json
{
  "organizationId":   "optional-uuid-v4",
  "organizationName": "Acme Corp",
  "status":           "active",
  "metadata":         { "region": "us-east-1" },
  "quotas": {
    "maxRequestsPerMinute": 10000,
    "retentionDays": 730
  }
}
```

Idempotent: supplying an existing `organizationId` returns the existing record.

#### Update organization (PATCH /v1/admin/organizations/:orgId)

```json
{
  "status":   "suspended",
  "metadata": { "suspendedReason": "billing-failure" }
}
```

`metadata` and `quotas` are merged non-destructively (existing keys are
preserved unless overwritten).

**`status` changes:** a `status` field in the request body is routed
through `organizationRegistry.publishOrganizationStatus()`, which writes the
new status to the shared Redis-backed authoritative store and broadcasts it
before this request is reported successful. If that durable write fails
(Redis unavailable), the endpoint returns **`503
ORG_STATUS_PROPAGATION_UNAVAILABLE`** and the status change is **not**
applied anywhere — this is deliberate: reporting success while unable to
propagate would leave other workers unboundedly stale, defeating the
guarantee in §14. Retry once Redis is reachable. `organizationName`,
`metadata`, and `quotas` in the same request are applied locally regardless
(they are not part of the bounded-propagation guarantee).

### Tenants

| Method  | Path                            | Action             |
|---------|---------------------------------|--------------------|
| `POST`  | `/v1/admin/tenants`             | Register tenant    |
| `GET`   | `/v1/admin/tenants`             | List all tenants   |
| `GET`   | `/v1/admin/tenants/:tenantId`   | Get tenant         |
| `PATCH` | `/v1/admin/tenants/:tenantId`   | Update tenant      |

GET list responses include an `organization` field with the full org record
(or `null` for unassigned tenants).

---

## 12. Database Schema

Migration `020_organizations.sql` creates:

- `organizations` table — UUID PK, status check constraint, quotas JSONB, RLS
- `tenants` table — FK to organizations (ON DELETE SET NULL), RLS
- `organization_id` column backfilled onto `platform_audit_events`
- `updated_at` trigger on both tables

Row-Level Security follows the pattern from migration 018:
- Admin sessions (no `qodiqa.tenant_id` set) can read all organizations
- Only `qodiqa_admin` / `rds_superuser` may write

---

## 13. Persistence

Both registries use **dual persistence**: in-memory Maps are authoritative for
the enforcement hot path; file-backed JSON stores (`data/organizations.json`,
`data/tenants.json`) survive process restarts.

Writes are atomic: data is written to a `.tmp` file first, then renamed over
the target.  Rename failures fall back to copy+delete.  Persistence errors are
swallowed — the in-memory state remains authoritative.

**This in-memory Map is per-process.** In a multi-worker deployment (Node
cluster, PM2 cluster mode, or multiple hosts behind a load balancer), each
worker holds its own independent copy, populated once from the JSON file at
module load and never re-read afterward. Prior to nothing reconciled
these copies — an organization's `status` field specifically (the field that
gates request execution) is now additionally synchronized across workers
with a documented, bounded delay. See §14 below. All other fields
(`organizationName`, `metadata`, `quotas`, tenant assignment) remain
process-local, exactly as described above — only `status` propagation is
addressed by this remediation.

---

## 14. Multi-Worker Status Propagation — Bounded Consistency

### 14.1 The problem this section documents

Before this remediation, an organization suspension applied via the admin API
was only ever written to the worker process that handled the PATCH request —
and to that worker's local `data/organizations.json` file. Every other
worker in the deployment kept serving traffic against its own, now-stale,
in-memory copy indefinitely — there was no polling, no cache TTL, and no
pub/sub. The only way another worker would observe the change was a process
restart. This is **worse** than "eventually consistent": it is permanently
inconsistent until an operator intervenes.

### 14.2 Mechanism

Only the `status` field is synchronized cluster-wide (see §13). Two
independent, complementary paths, both backed by a single Redis Hash
(`qodiqa:org:status`, one field per `organizationId`, value `{status,
updatedAt}`) that acts as the shared authoritative record:

1. **Instant push** — `src/core/organizations/status/OrgStatusPublisher.js`
   writes the authoritative Redis record, then broadcasts a signed,
   versioned, replay-protected event over Redis pub/sub
   (`qodiqa:org:status:change`). Every worker's
   `OrgStatusSubscriber.js` applies it to its local in-memory record on
   receipt — typically within the pub/sub round-trip latency (single-digit
   to low tens of ms).
2. **Bounded reconciliation sweep** — every worker independently re-reads
   the *entire* authoritative Redis Hash (`HGETALL`, one round trip
   regardless of organization count) on a fixed interval,
   `ORG_STATUS_RECONCILE_INTERVAL_MS` (default **5000ms**), and on every
   Redis reconnect. This is the belt-and-suspenders fallback for any pub/sub
   message a worker missed (e.g. during a brief disconnect) — it never
   depends on PostgreSQL and never scales with request volume.

Both paths write through a **monotonic guard**: an incoming update is applied
only if its `updatedAt` is not older than the last-applied value for that
org, so an out-of-order delivery (or a reconciliation sweep racing a fresher
push) can never regress a worker back to a stale status. Millisecond ties
(genuinely possible under real concurrency) are resolved by "last processed
wins" — consistent cluster-wide because a single Redis channel delivers
messages to every subscriber in the same order.

### 14.3 Fail-closed guarantee — the actual maximum propagation bound

`assertActiveOrganization()` does not trust a worker's local `status` value
unconditionally. Before returning a decision for an org-scoped tenant, it
checks two things (both skipped entirely — falling back to the pre-COMP-8
behavior — if the org-status subscriber was never started, e.g. in unit
tests or a minimal single-process deployment that hasn't wired up the
subscriber):

- **Subscriber connectivity** — if the worker's `OrgStatusSubscriber` has
  been started but is not currently connected to Redis (down, mid-reconnect,
  etc.), every org-scoped request on that worker is immediately denied
  (`ORG_STATUS_SYNC_UNAVAILABLE`). There is no interval, however short,
  during which a disconnected worker can keep serving on unconfirmed state.
- **Bounded staleness** — if the worker's last confirmed sync for that
  specific org is older than `ORG_STATUS_RECONCILE_INTERVAL_MS`, the request
  is denied (`ORG_STATUS_STALE`) rather than trusting expired state.

Combined, the documented guarantee is:

> **A suspension is enforced on every connected, healthy worker within
> `ORG_STATUS_RECONCILE_INTERVAL_MS` (5000ms by default) — typically far
> sooner, via instant pub/sub push. A worker that cannot confirm current
> status denies immediately. There is no window in which staleness silently
> exceeds this bound.**

This is a **strong (bounded-delay) consistency model, not strong
consistency and not unbounded eventual consistency**: reads can briefly
observe a value up to `ORG_STATUS_RECONCILE_INTERVAL_MS` old, but never
older, and any inability to prove freshness converts to a denial rather than
a stale allow.

### 14.4 What this does NOT cover

- **Provisioning/assignment propagation** — a brand-new organization, or a
  tenant→organization assignment, is out of scope for (which is
  scoped to *suspension* propagation of orgs already known to a worker).
  Those still rely on the pre-existing JSON-file/Postgres path and are not
  bounded by this mechanism.
- **In-flight requests** — a request already past the Step 1c gate when a
  suspension is applied is not retroactively cancelled; only *subsequent*
  requests are blocked. This matches every other synchronous enforcement
  gate in this pipeline (tenant status, consent revocation, etc.).
- **`organizationName`/`metadata`/`quotas`** — unaffected; still
  process-local (§13).

### 14.5 Operational configuration

| Env var                                    | Default | Meaning                                              |
|---------------------------------------------|---------|-------------------------------------------------------|
| `ORG_STATUS_RECONCILE_INTERVAL_MS`          | 5000    | Reconciliation sweep interval = documented max bound  |
| `ORG_STATUS_SUBSCRIBER_STARTUP_TIMEOUT_MS`  | 10000   | Startup fails FATAL if not connected+reconciled by then |
| `ORG_STATUS_SUBSCRIBER_MAX_RECONNECTS`      | 10      | Bounded reconnect attempts before giving up            |
| `ORG_STATUS_MAX_EVENT_AGE_MS`               | 30000   | Replay-protection window for pub/sub events            |
| `QODIQA_MAC_KEYS_PATH` | beside `QODIQA_KEYS_PATH` | MAC keyring: events AND the `qodiqa:org:status` hash records are signed, mandatorily; unsigned/tampered ones are ignored |
| `ORG_STATUS_SIGNING_KEY` | — | Deprecated: ignored, boot warns if set |

Startup is **FATAL** if the org-status subscriber cannot connect and perform
its initial reconciliation sweep within the startup timeout (mirrors the
existing consent-revocation subscriber contract) — a worker never enters
normal operating mode without a confirmed-fresh view of organization status.

Shutdown: `OrgStatusSubscriber`/`OrgStatusPublisher`/`OrgStatusStore` are
disconnected as part of the standard graceful-shutdown sequence in
`server.js`.

### 14.6 Race conditions considered

| Scenario                                   | Outcome                                                        |
|---------------------------------------------|------------------------------------------------------------------|
| Suspend during request execution           | Not retroactive (§14.4) — inherent to any synchronous gate       |
| Suspend immediately before execution        | Blocked, as long as the worker is connected/fresh                 |
| Suspend while a reconciliation sweep runs  | Monotonic guard — sweep can't undo a fresher pub/sub push and vice versa |
| Two concurrent suspend/resume updates      | Last-write-wins by `updatedAt`; ties resolved by delivery order (§14.2) |
| Worker restart                             | Full reconciliation sweep runs **before** `start()` resolves — bound is zero at boot, not "eventually" |
| Redis reconnect                            | Immediate one-off reconciliation sweep on `ready` (isReconnect), independent of the periodic timer |
| Redis fully unavailable                    | Fail-closed (§14.3) — every org-scoped request denied until reconnected |

---

## 15. Operational Guidance

### Suspending an organization

```bash
curl -X PATCH https://ops.example.com/v1/admin/organizations/<orgId> \
  -H "Authorization: Bearer $OPS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"suspended","metadata":{"reason":"payment-overdue"}}'
```

All tenants under the org are blocked immediately on the worker that handled
this request, and on every other worker within `ORG_STATUS_RECONCILE_INTERVAL_MS`
(5000ms by default; see §14) — no restart required.  The reverse index
(`tenantId → orgId`) is held in-memory and consulted on every request.

### Reassigning a tenant to a different organization

A tenant can only belong to one organization.  To move it:

```bash
# 1. Remove from current org
curl -X DELETE .../organizations/<oldOrgId>/tenants/<tenantId>

# 2. Assign to new org
curl -X POST .../organizations/<newOrgId>/tenants/<tenantId>
```

### Checking which org owns a tenant

```bash
curl https://ops.example.com/v1/admin/tenants/<tenantId>
# → { ..., "organization": { "organizationId": "...", "status": "active", ... } }
```

---

## 16. Sequence Diagrams

### Successful request (tenant assigned to active org)

```
Client          validateBoundRequest         OrgRegistry         Downstream
  │                     │                        │                    │
  │──artifact──▶        │                        │                    │
  │             Step 1: validateArtifact          │                    │
  │             Step 1b: assertActiveTenant       │                    │
  │             Step 1c: assertActiveOrganization─▶                   │
  │                     │           { valid:true, organizationId }     │
  │             Step 2: verifyRequestBinding       │                   │
  │             Step 3: registerNonce              │                   │
  │             Step 4: checkAnomaly               │                   │
  │             Step 5: checkPolicy                │                   │
  │                     │                          │                   │
  │◀──allowed: true ────│                          │                   │
  │    organizationId   │                          │                   │
  │                     │──────────────────────────────────────────▶  │
```

### Request blocked by suspended organization (Step 1c)

```
Client          validateBoundRequest         OrgRegistry
  │                     │                        │
  │──artifact──▶        │                        │
  │             Step 1: validateArtifact          │
  │             Step 1b: assertActiveTenant       │
  │             Step 1c: assertActiveOrganization─▶
  │                     │       { valid:false, reason:'ORG_SUSPENDED' }
  │◀─ 403 ──────────────│
  │   ORG_SUSPENDED     │    (nonce and anomaly quota NOT consumed)
```

---

## 17. Security Model

- **Tenant identity is cryptographic**: derived from the Ed25519 signing key;
  no client-supplied header or body field can override it.
- **Fail-closed**: any error in `assertActiveOrganization` falls through to
  `{ valid: true, organizationId: null }` only when the tenant has no org
  assignment (backward compat).  If an org exists but the status is invalid,
  the request is blocked.
- **Cross-tenant isolation**: the nonce namespace (`tenantId:qodiqa:req:v2:requestId`)
  and anomaly counters (`publicKeyId`) are per-tenant; one tenant's traffic
  cannot exhaust another tenant's quota.
- **Cross-org assignment blocked**: `assignTenantToOrg` throws
  `TENANT_ALREADY_ASSIGNED` if the tenant is already owned by a different org,
  preventing unauthorized org-hopping.
- **Org status propagates with a documented, bounded delay**:
  on the worker that processes the admin PATCH, the change is visible
  immediately. On every other worker in a multi-worker deployment, it is
  visible within `ORG_STATUS_RECONCILE_INTERVAL_MS` (5000ms by default) —
  typically far sooner via instant Redis pub/sub push — or that worker
  denies all org-scoped requests until it can confirm current status. Prior
  to this bullet was inaccurate for any multi-worker deployment: a
  suspension only ever took effect on the one worker that processed the
  request, with no bound at all on the others.
