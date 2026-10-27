# Auth-Failure Lockout — Shared Ops Token

Full design reference for the operations-endpoint auth-failure lockout control. For
configuration knobs, see `deploy/env/production.env.example`'s "Auth-Failure Lockout" section — this
document covers the *why* and the *how it works* behind it.

 extended the original IP-only design with a second, credential-identity
scoped counter — see [§4](#4-identity--dual-identity-model) and
[§5b](#5b-distributed-guessing-protection) below.

## 1. The problem

`src/middleware/opsAuth.js` authenticates every Admin/Ops request against two credential
types: a per-operator API key, or the deprecated shared `QODIQA_OPS_TOKEN`. The general
Admin rate limiter in front of it (`src/middleware/adminProtection.js`,
`QODIQA_OPS_RATE_LIMIT_MAX`/`_WINDOW_MS`, default 120 requests/minute/IP) throttles
*throughput*, not credential *outcome* — a wrong guess consumes exactly the same budget
as a correct request. At the default rate that is 172,800 guesses/day/IP against the
shared token, indefinitely, with no growing cost to the attacker and no signal
distinguishing "an operator is slow to type" from "someone is brute-forcing the token."
There was no dedicated failure counter, no escalating delay, and no lockout.

## 2. Where it runs

```
Admin/Ops request
  → rate limit (general throughput — QODIQA_OPS_RATE_LIMIT_MAX)
  → IP allowlist (optional)
  → ops auth ──────────────────────────────────────────────
      1. authLockout.precheck(req)   [NEW]
           locked?   → 429 AUTH_LOCKED_OUT, Retry-After — credential never evaluated
           backoff?  → delay before proceeding (deterministic exponential)
      2. per-operator API key check
      3. shared-token constant-time comparison
      4. on success → authLockout.recordSuccess(req)   [NEW]
         on invalid-token failure → authLockout.recordFailure(req)   [NEW]
  → RBAC resolve / permission / diagnostics gate
```

See `src/middleware/opsAuth.js`'s `AUTH-2` header comment and `src/core/authLockout/`.
`src/middleware/healthAuth.js` delegates to the same `opsAuth` middleware (only when
`QODIQA_HEALTH_PROBE_AUTH_REQUIRED=true`) and is passed the identical `authLockout`
instance from `server.js`, so `/health`/`/ready` share the same per-source state as
every other ops endpoint — it is the same shared token, and therefore the same
brute-force surface, regardless of which route receives the guess.

## 3. What counts as a failure

Only one branch of `opsAuth.js` calls `recordFailure()`: the final "an invalid token was
presented" branch (`OPS_AUTH_INVALID_TOKEN`). Deliberately excluded:

| Scenario | Why it does not count |
|---|---|
| Missing credential (no header at all) | Nothing was guessed — there is no credential outcome to score. |
| Disabled operator's otherwise-correct API key | The credential itself is *valid*; punishing it would lock out a legitimate operator whose account state changed, not an attacker. |
| RBAC store lookup error | Not a credential outcome — an internal fault, not evidence of a guess. |
| Ops auth not configured at all (`OPS_CONFIG_NO_TOKEN`) | A misconfiguration, not an attempted credential. |

This matches the requirement that the counter track invalid-token *presentations*
specifically, so the control cannot itself become a denial-of-service lever against an
operator who mistypes a header name or whose account was disabled for an unrelated
reason.

## 4. Identity / dual-identity model

The primary source identifier is `ip:{req.clientIp}` — the same trusted-proxy-aware client
IP resolution already used by the rate limiter and RBAC (`middleware/clientIp.js`), so the
lockout inherits the same `QODIQA_OPS_TRUST_PROXY` posture: correct behind a configured
reverse proxy, and not spoofable by an arbitrary `X-Forwarded-For` header when proxy
trust isn't configured. There is no authenticated identity to key on *before*
authentication succeeds — IP is the only signal available at this point in the pipeline,
matching the rate limiter's own `'ip:unknown'` fail-secure fallback for the rare case a
client IP cannot be resolved at all.

**The residual gap this closed:** an IP-only counter bounds a single source, but a
distributed attacker who rotates across many source IPs while repeating the *same*
guessed credential never accumulates enough failures against any one IP to trip its
counter — each IP's slice of the attack can stay comfortably under threshold forever. The
admin rate limiter in front of this control is also per-IP, so it doesn't close this gap
either.

**The fix — a second, credential-identity scoped counter.** Whenever a credential is
presented, `src/middleware/opsAuth.js` extracts it (a `Bearer` header or `x-ops-token`
value — parsing only, not evaluation) and passes it to `authLockout.precheck()` /
`recordFailure()` / `recordSuccess()` alongside the request. `src/core/authLockout/
index.js`'s `_credentialIdentity` derives a second identity from it:

```
cred:{ SHA-256(presentedCredential) truncated to N bytes, hex-encoded }
```

`N` is configurable (`QODIQA_OPS_AUTH_LOCKOUT_CREDENTIAL_HASH_BYTES`, default 16 bytes /
128 bits, range 1–32) via `src/infra/config/opsConfig.js`. This identity is:

- **One-way** — SHA-256 is not reversible; the hash cannot be turned back into the
  credential.
- **Never the raw credential** — the presented credential exists only as a local
  variable for the duration of the hash computation. It is never written to Redis, never
  logged (see [§10](#10-observability)), never included in a metric label, never placed in
  telemetry, evidence, or an exception message.
- **Not itself treated as secret** — it doesn't need to resist guessing, only collisions;
  128 bits of a cryptographic hash is far beyond any practical collision risk for this
  purpose.

Because the credential-identity counter accumulates every failed attempt against that
*specific guessed value*, regardless of which IP it arrived from, a distributed
credential-guessing campaign now trips this counter on its own schedule — proportional to
total guesses against that credential, not to any single IP's share of them.

**Both counters are independent and either can trigger the lockout decision:**

```
locked = ip.locked OR credential.locked
```

A locked-out source is rejected before any credential comparison runs (see
[§2](#2-where-it-runs)), and the aggregate decision is reported without ever exposing
*which specific* credential or IP identity was involved beyond the (bounded, three-value)
`lockScope` field described in [§10](#10-observability).

## 5. Algorithm

State per identity: `{ count, lockedUntil }`, stored under key `authlock:v1:{identity}`
(`authlock:v1:ip:{address}` or `authlock:v1:cred:{truncatedSha256Hex}` — see
[§4](#4-identity--dual-identity-model)). Three operations, each a single atomic Lua
script in Redis (`src/core/authLockout/algorithm.js`):

- **`PRECHECK_LUA`** — read-only except for clearing an *expired* lock (auto-recovery
  side effect). Reports whether the source is currently locked, and — if not — the
  current failure count (used to derive the backoff delay).
- **`RECORD_FAILURE_LUA`** — increments the counter and, if this failure crosses
  `QODIQA_OPS_AUTH_LOCKOUT_MAX_FAILURES` **and no lock is already active**, sets
  `lockedUntil = now + QODIQA_OPS_AUTH_LOCKOUT_DURATION_MS`.
- **`RECORD_SUCCESS_LUA`** — clears the counter(s) entirely; a credential that
  authenticates successfully has no reason to keep any failure streak alive.

### 5a. Dual-key evaluation, one round trip

Every script takes a **primary key** (`KEYS[1]`, always the IP identity) and an
**optional secondary key** (`KEYS[2]`, the credential identity). When no credential was
presented, the caller passes a one-element `keys` array and Redis leaves `KEYS[2]` as Lua
`nil` — the script takes the exact same code path as the pre-WP-012, IP-only version, with
identical output. When a credential *is* presented, the caller passes a two-element array
and the **same single `EVAL`** evaluates both counters via a shared Lua helper function
(`check_key` / `record_one` / `clear_one` in `algorithm.js`), returning both results in one
reply. There is no second script and no second round trip in either case — the dual-key
path costs Redis nothing beyond the trivially larger reply payload (four extra integers).

This is what makes the design "atomic per the requirements": a burst of concurrent
requests against the same IP *and* the same credential is still serialized entirely by
Redis's single-threaded command execution, exactly as the original single-counter design
was — did not introduce a second write path that could race against the first.

The "no lock already active" guard is the single most important correctness property of
this design, and it applies **independently to each identity**: once a lockout episode
begins for the IP identity, or for the credential identity, further failures that arrive
before *that identity's* lock expires — concurrent attackers, retried requests, anything —
do **not** push its `lockedUntil` further out. The duration is fixed at the instant the
threshold is crossed and cannot be extended by anything that happens afterward. Without
this guard, an attacker could keep a source (or a credential) locked out indefinitely
simply by continuing to send requests — a denial-of-service lever against the legitimate
operator that owns that IP, or against every operator who might legitimately hold that
credential. (In practice this rarely matters in the failure direction anyway: once locked,
`precheck` rejects requests *before* any credential is evaluated, so `recordFailure` is not
reached again until the lock expires — but the guard holds even in adversarial orderings
where that isn't true.)

Backoff, below the threshold, is a pure deterministic function (no randomness, no
jitter — unlike the Redis reconnect-strategy backoff elsewhere in this codebase, this
one is intentionally predictable so the same failure count always produces the same
observable delay):

```
delay(count) = min(maxDelayMs, minDelayMs * 2^(count - 1))   for count >= 1, else 0
```

With the default `minDelayMs=250, maxDelayMs=5000`: 250ms, 500ms, 1000ms, 2000ms,
4000ms, 5000ms (capped), 5000ms, ... The delay is applied by `await`ing before the
credential comparison runs, not by rejecting the request — a source under threshold
still gets a normal 401 (or 200, if it finally guesses right), just slower. Backoff
remains driven by the IP counter alone (unchanged from pre-WP-012 behavior) — the
credential counter contributes only to the lockout decision itself, not to backoff pacing,
since a fresh IP always starts its own backoff at zero regardless of that credential's
history elsewhere.

### 5b. Distributed guessing protection

Worked example with the default `QODIQA_OPS_AUTH_LOCKOUT_MAX_FAILURES=5`: an attacker
controlling 100 source IPs, each sending 4 guesses of the *same* credential (20 below any
single IP's threshold), never trips the IP counter — no single IP reaches 5 failures. But
every one of those 400 guesses is scored against the *same* credential identity, so the
credential counter crosses its threshold on the 5th guess overall, regardless of which of
the 100 IPs it came from — the lockout triggers long before the IP-only design would ever
have noticed the campaign. This is exactly the scenario
`test/security/authLockoutCredential.security.test.js` exercises end-to-end.

Conversely, an attacker guessing many *different* credentials from a single IP still trips
the IP counter exactly as before — the two counters are complementary, not a replacement
for one another: IP scoping catches "one source hammering anything"; credential scoping
catches "one target, hammered from everywhere."

## 6. Why the key's TTL includes a safety margin

This applies identically to both the IP key and the credential key — both identities share
the same `QODIQA_OPS_AUTH_LOCKOUT_*` duration/window configuration
([§4](#4-identity--dual-identity-model)), so `computeKeyTtlSeconds()` produces one
TTL value that `RECORD_FAILURE_LUA` applies via `EXPIRE` to whichever key(s) it touches in
a given call — the credential key gets exactly the same safety margin the IP key always
had.

The Redis key backing `{count, lockedUntil}` carries its own blanket TTL (so an
abandoned failure streak from a source that gives up is eventually garbage collected,
independent of the lock timestamp inside it). That TTL must exceed `lockedUntil`, or
Redis could silently delete the whole record — including the still-valid lock — before
`lockedUntil` has actually passed, letting a locked-out source back in early.

With default configuration, `QODIQA_OPS_AUTH_LOCKOUT_FAILURE_WINDOW_MS` equals
`QODIQA_OPS_AUTH_LOCKOUT_DURATION_MS`, so a naive `TTL = max(failureWindowMs,
lockoutDurationMs)` would expire the whole key at (numerically) the *exact same instant*
the lock itself expires — a race with no deterministic winner. `computeKeyTtlSeconds()`
(`src/core/authLockout/algorithm.js`) therefore adds a fixed 60-second safety margin on
top, guaranteeing the explicit `lockedUntil <= now` check inside `PRECHECK_LUA` always
observes and reports the transition (emitting `AUTH_LOCKOUT_EXPIRED` and decrementing the
active-lockout gauge). The blanket TTL becomes purely a long-horizon "this identity has
been quiet, garbage collect it" backstop — never the primary expiry-detection path. This
was caught by `src/core/authLockout/__tests__/authLockout.test.js`'s AL-15 test before it
ever affected the actual lockout duration users experience — it only affects when the
*expiry is reported*, not how long a source stays locked (`lockedUntil` itself is
unaffected either way).

## 7. Concurrency

Both mutating operations execute as a single Redis `EVAL` — Redis's single-threaded
command execution serializes concurrent callers, so there are no lost updates: a burst of
N concurrent invalid-credential requests increments the counter exactly N times, and the
lock is set exactly once, by whichever call is the first to observe the threshold
crossed. This holds identically whether the `EVAL` touches one key or two — the dual-key
path is still one script, one round trip, so it inherits the same serialization
guarantee with no additional locking or coordination. `MemoryStorage` (dev/test fallback)
achieves the same guarantee for a different reason — its methods are `async` but contain
no internal `await` between reading and writing state, so Node's single-threaded event
loop cannot interleave two concurrent callers mid-operation, for either identity. See
`authLockout.test.js`'s AL-19/AL-20 (counter correctness and single-trigger-under-
concurrency), `test/auth-lockout.test.js`'s AL-E17, and
`test/concurrency/authLockoutCredential.concurrency.test.js` (the dual-counter equivalents, including
many concurrent IPs racing to trip the same credential's counter) for the property
verified through the real HTTP middleware and, where `REDIS_URL` is set, real Redis
`EVAL`.

## 8. Fail-closed on storage outage

If Redis is unreachable, `precheck()`/`recordFailure()`/`recordSuccess()` throw;
`createAuthLockout()` catches this and returns `{ locked: true, storageUnavailable: true
}` from `precheck` — the caller (and every legitimate operator) sees a 429 rather than
the control silently disabling itself. This mirrors this codebase's established posture
for every other security-critical store (rate limiter, nonce store, idempotency store):
never fail open on a security control. `QODIQA_OPS_AUTH_LOCKOUT_ENABLED=false` is the
explicit, operator-chosen way to disable the control — an infrastructure outage is not.

## 9. Distributed deployments

`src/core/authLockout/storage.js` mirrors `src/core/rateLimit/storage.js`'s exact
pattern: a `RedisStorage`/`MemoryStorage` pair behind a common interface, using the same
`createManagedRedisClient()` factory (`purpose: 'authLockout'`) — the same self-healing
reconnect/failover behavior already proven for rate limiting applies here with no new
code paths. `RedisStorage` is selected whenever `REDIS_URL` is set; every instance in a
horizontally-scaled deployment reads and writes the same Redis-backed counters, so
enforcement is consistent regardless of which instance a given request lands on. Without
`REDIS_URL`, `MemoryStorage` is used — single-process only, intended for local
development and tests, and explicitly not a production posture for a
multi-instance deployment (an attacker distributing guesses across instances would see
independent, non-cumulative counters).

This is precisely what makes the credential counter effective in the deployment shape it
is designed for: every application instance, regardless of which one a given guess lands
on, reads and writes the *same* `authlock:v1:cred:{hash}` key in the shared Redis backend.
A distributed attacker gains nothing by spreading guesses across instances *or* across
source IPs — both dimensions of "distribution" collapse onto the same shared counter.

## 10. Observability

Structured events (`services/logger.js`, classified `SECURITY` except
`AUTH_LOCKOUT_RESET`, which is `AUDIT` — see `services/logClassifier.js`):

| Event | Level | When |
|---|---|---|
| `AUTH_LOCKOUT_BACKOFF_APPLIED` | INFO | A request was delayed before its credential was evaluated. |
| `AUTH_LOCKOUT_TRIGGERED` | WARN | This failure crossed the threshold; a lockout just started. |
| `AUTH_LOCKOUT_ACTIVE` | WARN | A request hit an already-active lockout and was rejected pre-emptively. |
| `AUTH_LOCKOUT_EXPIRED` | INFO | A lockout was found expired on the next request from that source (auto-recovery). |
| `AUTH_LOCKOUT_RESET` | INFO | A successful authentication followed one or more prior failures. |
| `AUTH_LOCKOUT_STORAGE_FAILURE` | ERROR | Redis was unreachable; the request failed closed. |

`AUTH_LOCKOUT_TRIGGERED`, `AUTH_LOCKOUT_ACTIVE`, and `AUTH_LOCKOUT_EXPIRED` additionally
carry a `lockScope` field: one of the three fixed strings `'ip'`, `'credential'`,
or `'both'`, identifying which counter(s) drove the event. This is intentionally the
*only* new field these events carry — enough for an operator to distinguish "this is a
single noisy source" from "this is a distributed campaign against one credential" without
ever exposing which IP or which credential-hash was involved beyond what `identity`
already reported.

None of these ever include the presented credential, the configured token, or any
credential material — **not even its hash** — only `identity` (`ip:...`, exactly as
before the credential identity is deliberately never logged, see next
paragraph), `requestId`, `path`, `lockScope`, and counters/timestamps.

**Why the credential hash itself is never logged**, even though it isn't the raw
credential: emitting it would create a new, unbounded-cardinality identifier in the log
stream tied to a specific guessed value, and — combined with timing — could let a reader
correlate log lines across requests for the same credential without any operational
benefit that `lockScope` doesn't already provide. `src/core/authLockout/index.js`'s
`_credentialIdentity()` is used only to build the Redis key handed to `storage.js`; it is
never passed to `emit()`.

Prometheus metrics (`src/observability/metrics.js`, `/metrics`):

- `qodiqa_auth_lockout_failures_total` — unlabeled, one increment per recorded failure
  event (unchanged from pre-WP-012).
- `qodiqa_auth_lockout_triggered_total{scope="ip"|"credential"|"both"}` — labeled by the
  same bounded, three-value `lockScope` as the logs above. This is a **bounded**
  label (exactly 3 possible values, never derived from the credential or its hash) — it
  does not reintroduce the per-identity cardinality problem the original design
  deliberately avoided.
- `qodiqa_auth_lockout_active` (gauge, best-effort — incremented on trigger,
  decremented when an expired lock is next observed; not swept proactively, so it can
  transiently overstate currently-active lockouts between a lock's real expiry and the
  next request from that source)
- `qodiqa_auth_lockout_recoveries_total`
- `qodiqa_auth_lockout_backoff_applied_total`
- `qodiqa_auth_lockout_storage_failures_total`

## 11. Configuration

See `deploy/env/production.env.example`'s "Auth-Failure Lockout" section and
`src/infra/config/opsConfig.js`'s header comment for the full list
(`QODIQA_OPS_AUTH_LOCKOUT_ENABLED`, `_MAX_FAILURES`, `_DURATION_MS`, `_BACKOFF_MIN_MS`,
`_BACKOFF_MAX_MS`, `_FAILURE_WINDOW_MS`). A misconfigured `BACKOFF_MIN_MS >
BACKOFF_MAX_MS` is clamped (min = max) rather than rejected at startup — a config typo
degrades to "no backoff growth," not to every ops endpoint refusing to start.

The credential counter deliberately reuses every one of those same thresholds —
`_MAX_FAILURES`, `_DURATION_MS`, `_FAILURE_WINDOW_MS` all apply identically to both
identities, avoiding a parallel set of knobs for a marginal benefit. The one new setting
is `QODIQA_OPS_AUTH_LOCKOUT_CREDENTIAL_HASH_BYTES` (default 16, range 1–32) — the
truncation length of the credential's SHA-256 identity. An out-of-range or unparseable
value falls back to the default rather than failing startup, matching every other numeric
knob in this file.

## 12. Operational recovery

Lockouts recover automatically — no operator action, no admin endpoint, no manual Redis
key deletion required. If an operator needs *immediate* recovery ahead of the configured
duration (e.g. an internal script briefly mis-configured with a stale token, now fixed,
still locked out), the only supported path today is deleting the corresponding
`authlock:v1:ip:{address}` Redis key directly — there is no dedicated unlock API, by
design: adding one would itself become a new attack surface requiring its own
authentication and its own lockout. When the credential counter (rather than the IP
counter) is the one holding a lock, the equivalent recovery path is
`authlock:v1:cred:{hash}` — but since the hash is deliberately never logged
([§10](#10-observability)), an operator can only reach it by recomputing
`SHA-256(credential)[:N]` from the credential itself, truncated to the configured
`QODIQA_OPS_AUTH_LOCKOUT_CREDENTIAL_HASH_BYTES`. This is intentional: it means recovery
requires possessing the credential, not just observing logs.

## 13. Tracked technical debt: full removal of `QODIQA_OPS_TOKEN`

's required remediation explicitly calls out prioritizing "the codebase's own
already-planned removal of the deprecated shared `QODIQA_OPS_TOKEN`." That removal is
referenced throughout the codebase (`src/middleware/opsAuth.js`'s header comment,
`docs/operations/upgrade-runbook.md`'s migration section, `docs/operations/
startup-runbook.md`'s startup warning, `deploy/env/production.env.example`) but has no dedicated
tracking entry of its own — the closest existing
entry, ****, covers the narrower concern of the token's *value* lacking
minimum-length/weak-value validation while it remains in use, not its eventual removal.
This gap is noted here as technical debt for a future change (the shared-token
authentication branch in `src/middleware/opsAuth.js`'s "§2. Shared token" section, and its
corresponding config in `src/infra/config/opsConfig.js`, are the removal's scope) rather
than addressed by this one,'s own instruction not to remove it as part of this
change.
