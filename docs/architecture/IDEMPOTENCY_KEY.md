# Idempotency-Key — `POST /ai/chat` (API-2)

Full design reference for the `Idempotency-Key` header. For the request/response
contract, see `docs/api/overview.md`'s [Idempotent retries](../api/overview.md#idempotent-retries)
section — this document covers the *why* and the *how it works* behind it.

## 1. The problem

A client that times out waiting for `/ai/chat` cannot tell whether the request actually
completed. Retrying blindly risks:

- invoking the AI provider a second time (double token consumption, double billing),
- creating two independent audit/transparency artifacts for what is really one logical
  request,
- returning an inconsistent decision to the caller across the two attempts.

QODIQA's existing per-request **nonce** (`artifact.payload.requestId`, `src/validation/nonceStore.js`)
does not solve this: a genuine retry is *freshly signed* — new `requestId`, new
`timestamp`, new `expiry` — precisely because artifacts are single-use and short-lived
by design. Two freshly-signed artifacts for "the same logical
request, attempted twice" look, to the nonce store, exactly like two different requests.
`Idempotency-Key` is a second, orthogonal layer that lets the *client* assert "these are
the same logical request" across any number of independently-signed retry attempts.

## 2. Where it runs in the pipeline

```
POST /ai/chat
  → content-type guard
  → Idempotency-Key header validation (format/size only — no store access yet)
  → body + artifact header validation
  → validateBoundRequest()      [signature, binding, nonce, anomaly — UNCHANGED]
  → ── idempotency gate ──      [NEW — authenticated tenant/identity now known]
  → checkPolicy() / semantic policy / provider execution / audit / transparency
```

The gate runs **after** authentication (so the fingerprint can bind to the
*authenticated* tenant and identity — see §3) and **before** policy evaluation,
semantic checks, and provider dispatch, so that a replayed retry:

- never re-consumes rate-limit quota,
- never re-runs consent/policy/semantic evaluation,
- never reaches the provider a second time.

See `src/api/routes/aiChat.js`'s `_runEnforcementPipeline()` (search `API-2:` comments)
and `src/core/idempotency/idempotencyGate.js`.

## 3. Request fingerprinting

An `Idempotency-Key` alone only identifies *that the client considers this a retry* — it
says nothing about *what* is being retried. Binding the key to the specific request it
was issued for is what prevents a key from being replayed against a different request.

`src/core/idempotency/fingerprint.js` computes a domain-separated SHA-256 over:

| Field | Source | Why |
|---|---|---|
| `tenantId` | `validateBoundRequest()` result (post-signature-verification) | authenticated tenant |
| `organizationId` | `validateBoundRequest()` result | tenant's org boundary |
| `publicKeyId` | `validateBoundRequest()` result | authenticated signing identity |
| `callerId` | `validateBoundRequest()` result | authenticated caller, when present |
| `provider` | `artifact.payload.provider` | which AI provider would be invoked |
| `requestHash` | `artifact.payload.requestHash` | QODIQA's existing request-binding hash — `SHA-256(method + path + body)`, see `src/validation/requestHash.js` |

`requestHash` is the key piece: because `/ai/chat`'s body schema is `.passthrough()`
(`src/validation/schemas/aiChat.schema.js`), it transitively covers every
execution-affecting field in the body — `prompt`, `model`, `stream`, and any additional
fields a client sends — without this module needing to enumerate them, and it stays
correct as that schema evolves.

**Deliberately excluded:** `timestamp`, `expiry`, `requestId`, `traceId`, or any other
per-attempt generated value. Two independently-signed artifacts for the same logical
retry always produce the same fingerprint; the actual signed bytes differ every time
by design.

**Consent context** is not a separate input: in this pipeline consent is *resolved* from
`tenantId` during policy evaluation, not supplied by the client as a distinct field, so
it is already covered transitively via `tenantId`.

## 4. Storage & durability

**Decision: reuse the existing Redis-backed, AOF-durable pattern already established for
nonce-based replay protection** (`src/validation/nonceStore.js`), rather than adding
PostgreSQL as a new dependency for this feature specifically.

Why: PostgreSQL is optional in this deployment (`QODIQA_PG_ENABLED`, off by default),
while Redis is already a hard runtime dependency for every `/ai/chat` request (nonce,
anomaly, rate-limit enforcement), with its own durability guarantee already enforced at
startup (`STRICT_REPLAY_PROTECTION` — refuses to start without AOF persistence
configured). Reusing it means idempotency inherits an *already-operational* durability
guarantee instead of introducing a second storage dependency this one feature alone
would need — see `docs/deployment/redis-persistence.md`.

`src/core/idempotency/idempotencyStore.js` implements exactly four primitives:

| Operation | Redis command | Purpose |
|---|---|---|
| `reserve()` | `SET key value NX PX <reservationTtl>` | atomic — across every worker/pod/process, one and only one caller can win |
| `complete()` | `SET key value XX PX <retentionTtl>` | overwrites *only* a reservation this process holds; never resurrects an expired/released key |
| `release()` | `DEL key` | frees the key immediately for a fresh attempt |
| `get()` | `GET key` | read-only lookup, used for polling |

**Key format:** `<tenantId>:qodiqa:idem:v1:<idempotencyKey>` — tenant scoping is baked
into the key itself (mirrors `nonceStore.buildNonceKey`'s convention), so cross-tenant
replay is structurally impossible, not merely checked in application code.

**Stored record** (JSON value):

```json
{
  "status":      "pending | completed",
  "fingerprint": "<hex>",
  "tenantId":    "<string|null>",
  "createdAt":   "<epoch-ms>",
  "completedAt": "<epoch-ms, once completed>",
  "httpStatus":  "<number, once completed>",
  "body":        "<the exact JSON response body to replay, once completed>"
}
```

## 5. Atomic reservation & concurrency

```
gate() → store.reserve(tenant, key, fingerprint, reservationTtl)
           │
           ├─ won the SET NX → outcome "proceed": caller executes normally
           │
           └─ lost the SET NX → read the existing record:
                ├─ fingerprint differs           → outcome "conflict"        (422)
                ├─ status "completed", fp matches → outcome "replay"          (200, cached body)
                └─ status "pending",  fp matches  → poll (bounded wait) →
                      ├─ becomes "completed" in time → "replay"
                      └─ still pending at deadline    → "in_progress"          (409)
```

Two requests racing the *identical* `(tenant, key, fingerprint)` therefore can never both
execute: Redis's `SET NX` is a single atomic command regardless of which of N
application processes issued it — this is the same guarantee `nonceStore.register()`
already relies on for replay protection, applied here to duplicate suppression instead.

Polling is bounded by `IDEMPOTENCY_WAIT_TIMEOUT_MS` (default 10,000 ms, polled every
`IDEMPOTENCY_POLL_INTERVAL_MS`, default 200 ms) — comfortably inside a client's own
request timeout budget.

## 6. Scope decision: only a successful EXECUTE is ever replayed

This is the single most important design decision in this remediation, so it is called
out explicitly (also documented at the top of `idempotencyGate.js`):

**`complete()` — the only call that marks a reservation "completed" and therefore
replayable — is invoked from exactly one place: after the AI provider call, the mandatory
audit-chain write, and the mandatory transparency-log write have *all* durably
succeeded.** Every other terminal outcome — a validation BLOCK, a policy/semantic BLOCK,
a provider error, a route-level timeout, an audit or transparency persistence failure —
calls `release()` instead, which deletes the reservation immediately so a corrected or
simply-repeated retry gets a fully fresh evaluation.

Consequences:

- **Provider invocation happens at most once** per `(tenant, key)` that ever reaches a
  successful outcome. A genuinely failed/blocked/timed-out attempt never "burns" the key
  — the client's next retry (same key) is treated exactly like a first attempt.
- This is deliberately conservative: it never risks replaying a *stale* decision (e.g. a
  policy BLOCK whose underlying rate-limit/consent state may have legitimately changed
  between attempts) — at the cost of not short-circuiting the (cheap, non-billable)
  re-validation work for a request that will not result in provider execution anyway.
- It fully satisfies the actual reliability concern the finding raises — duplicate
  **provider** execution, duplicate **billing**, duplicate **successful** audit artifacts
  — because none of those things happen on a BLOCK/error path in the first place.

## 7. Failure-state handling

| State | Behavior |
|---|---|
| Execution still running (concurrent duplicate) | Bounded poll, then `409 IDEMPOTENCY_REQUEST_IN_PROGRESS` if still pending |
| Execution failed (policy/semantic BLOCK, provider error) | `release()` — key immediately available for a fresh, non-stale retry |
| Execution timed out (`REQUEST_TIMEOUT`) | `release()` — same as above; this is precisely the scenario the finding describes |
| Reservation abandoned (process crash mid-execution) | Self-heals via `reservationTtlMs` expiry (`AI_CHAT_TIMEOUT_MS + 15s` by default) — no sweeper process needed |
| Expired key (past retention TTL) | Redis TTL auto-deletes the record; the key may execute again as if new |
| Storage unavailable | `503 IDEMPOTENCY_STORE_UNAVAILABLE` — fails closed *only* for requests that supply the header; every other request is completely unaffected |
| Partial persistence failure (`complete()`/`release()` itself throws) | Logged (`IDEMPOTENCY_COMPLETE_FAILED` / `IDEMPOTENCY_RELEASE_FAILED`), swallowed — the request's own HTTP response and mandatory audit/transparency evidence are never affected; worst case is a future retry re-executes rather than replays (the pre-remediation behavior, not a regression) or a reservation lingers until its short TTL expires |

## 8. Security & abuse prevention

- **Header validation** (`src/core/idempotency/idempotencyKey.js`) — rejects malformed
  values (empty, non-string, repeated header, whitespace/control characters) and
  oversized values (`IDEMPOTENCY_HEADER_MAX_BYTES`, `IDEMPOTENCY_KEY_MAX_LENGTH`) before
  the key ever reaches the store.
- **Tenant isolation** — structural, not just checked: the tenant ID is part of the
  Redis key itself (§4), so a tenant cannot address, conflict with, or replay another
  tenant's record even given the exact same key string.
- **Reservation TTL bounds storage growth from abandoned keys** — nothing accumulates
  indefinitely without ever completing or expiring.
- **Unbounded key creation** — bounded the same way every other `/ai/chat` request
  already is: signature verification (a key is only ever addressed after
  `validateBoundRequest()` succeeds) and the existing anomaly/rate-limit layers upstream
  of the gate.

## 9. Multi-instance / horizontal scaling

No single-process assumption anywhere in this design: the reservation is a single
atomic Redis command observed identically by every worker/pod/instance; the completed
record is durable Redis state, not process memory. A request handled by instance A and
its retry handled by instance B behave identically to both being handled by the same
instance.

## 10. Configuration

See `deploy/env/production.env.example`'s "Idempotency-Key support (API-2)" section for the full
list of environment variables (`IDEMPOTENCY_ENABLED`, `IDEMPOTENCY_KEY_MAX_LENGTH`,
`IDEMPOTENCY_HEADER_MAX_BYTES`, `IDEMPOTENCY_RESERVATION_TTL_MS`,
`IDEMPOTENCY_RETENTION_TTL_MS`, `IDEMPOTENCY_WAIT_TIMEOUT_MS`,
`IDEMPOTENCY_POLL_INTERVAL_MS`) with defaults and guidance.

## 11. Known scope boundary

- **Streaming (`stream: true`) is not supported** — an SSE stream has no single response
  body to durably cache and replay. The combination is explicitly rejected
  (`400 IDEMPOTENCY_STREAMING_UNSUPPORTED`) rather than silently ignoring the header.
- A BLOCK decision is never replayed (§6) — only ever a successful `EXECUTE`. A retry
  under a key whose only prior attempt was blocked always re-runs the full pipeline.

## 12. Tests

- `src/core/idempotency/__tests__/idempotencyKey.test.js` — header validation
- `src/core/idempotency/__tests__/fingerprint.test.js` — fingerprint determinism/binding
- `src/core/idempotency/__tests__/idempotencyStore.test.js` — Redis primitives (mocked client)
- `src/core/idempotency/__tests__/idempotencyGate.test.js` — reservation/replay/conflict/
  concurrency/store-unavailable outcomes
- `src/api/routes/__tests__/aiChatIdempotency.test.js` — full HTTP-level integration:
  first execution, replay, concurrent duplicates (provider invoked exactly once),
  independent keys, key/body conflict, malformed/oversized keys, tenant isolation,
  streaming rejection, unrelated early failure never poisoning a key
