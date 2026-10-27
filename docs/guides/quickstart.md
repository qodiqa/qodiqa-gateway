# QODIQA Quickstart

Get QODIQA running locally and observe `BLOCK` and `EXECUTE`. This guide sets up a local evaluation instance, not a production deployment. Only the local (Ollama) provider is exercised end to end; the adapters for hosted providers are experimental.

> **Embedding screening is off in the sandbox.** Its models and reference data are not included in this repository; the sandbox sets `QODIQA_SEM_EMBEDDING_ENABLED=false`. The rule-based screening still runs. Authorization, policy, audit and evidence work as described below. A Docker Compose version of the sandbox is `docker compose -f docker-compose.quickstart.yml up`.

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Node.js | 22 or later | `node --version` |
| npm | bundled with Node | `npm --version` |
| Redis | ≥ 6.0 | Required for replay protection, anomaly detection, and rate limiting. On Windows, [Memurai](https://www.memurai.com/) is a Redis-protocol-compatible drop-in. |
| PostgreSQL | 15–18 | Required by the default policy (`POL-001: REQUIRE_CONSENT`) — see [Provision Consent](#provision-consent-postgresql) below |
| At least one AI provider | — | Any one of: an OpenAI API key (starts with `sk-`, from platform.openai.com/api-keys), an Anthropic/Gemini/Mistral key, or a local OpenAI-compatible runtime such as [Ollama](https://ollama.com) with a model pulled (`ollama pull qwen2.5:7b`). If none is configured, `npm run dev` automatically falls back to a local runtime at `http://127.0.0.1:11434/v1` — see [Fastest path](#fastest-path-npm-run-dev) below. **For a local runtime you must also choose the model** — see [Local / Ollama model selection](#local--ollama-model-selection). |

### Local / Ollama model selection

 The `local` provider sends the request's `model` to your runtime. Do one
of the following:

- set `PROVIDER_DEFAULT_MODEL_LOCAL=<the model you pulled>` in `.env`, e.g.
  `PROVIDER_DEFAULT_MODEL_LOCAL=qwen2.5:7b`; **or**
- include `"model": "<the model you pulled>"` in every request body. The body is signed, so put
  the same `model` in the `/sign` request's `request.body` and in the `/ai/chat` body.

Set the model explicitly with one of the two options above.

> **Shell**: every command in this guide uses POSIX/bash syntax (`&`, `$(...)`, `<<<`, `mkdir -p`). On Windows, run these in Git Bash or WSL, not `cmd.exe` or PowerShell.

---

## Zero-setup sandbox: `qodiqa dev`

Needs Node.js 22+, Docker (for a disposable Redis and PostgreSQL) and nothing else: no provider account, no `.env`.

```bash
npm run dev:sandbox            # or: node bin/qodiqa.js dev [--port 3000] [--redis-url ...] [--no-docker-redis] [--no-docker-pg]
```

It starts the **real gateway** (the same code path as `npm start`, the full enforcement pipeline) in a fresh temporary directory, with a built-in **sandbox provider** that answers `[sandbox] <your last message>` (a stand-in for the
model only; every request is still verified, checked against consent and the sandbox policies, and audited), sandbox policies (`scripts/dev/policies.sandbox.json`: consent required, plus a demo content rule that refuses the phrase
`sandbox-block-me`), and disposable Redis and PostgreSQL containers (tmpfs-backed, stopped on exit; PostgreSQL holds the consent registry, which the sandbox grants to its own dev identity). The signing key is printed once at start:

```bash
curl -s -X POST localhost:3000/sign -H "Authorization: Bearer $SK" -H 'content-type: application/json'   -d '{"request":{"method":"POST","path":"/ai/chat","body":{"prompt":"hello"}},"payload":{"userId":"me"},"ttl":60000}'
# then POST /ai/chat with the artifact (base64 of the JSON) in x-qodiqa-artifact and the same body: {"decision":"EXECUTE", "response":"[sandbox] hello", ...}
```

Not a production configuration (development profile, throw-away keys and data). There is no hosted sandbox.

---

## Fastest path: `npm run dev`

For local development, skip the manual secret generation and key provisioning below entirely
(Redis is still required — see below):

```bash
git clone <repo>
cd qodiqa-gateway
npm install
docker run --rm -d -p 127.0.0.1:6379:6379 redis:7 --requirepass <dev-password>   # bind to loopback; set REDIS_URL accordingly
npm run dev
```

> If anything already listens on 6379 (for example another QODIQA instance's Redis holding
> real data), publish a different free host port instead (`-p 127.0.0.1:56379:6379`) — never point a quickstart at an
> existing Redis. Put the endpoint in `.env` as `REDIS_URL=redis://127.0.0.1:<port>` and the password as
> `REDIS_PASSWORD=<dev-password>` (`src/infra/redis/clientConfig.js` reads it separately), not inside the URL. Use a
> throwaway, randomly generated `<dev-password>` (`openssl rand -hex 16`) — `--requirepass` is visible in the process
> list.

This alone gets you a running server that correctly `BLOCK`s every request (the default,
secure state). To see a genuine `EXECUTE` decision — the goal of this guide — you also
need PostgreSQL-backed consent provisioned, covered in
[Provision Consent (PostgreSQL)](#provision-consent-postgresql) below. Read this whole
guide top to bottom before running commands out of order.

`npm run dev` runs `scripts/bootstrap-dev.js`, which prepares a fully isolated, ephemeral
development environment and then launches the real `server.js` inside it — the complete
production enforcement pipeline (cryptographic verification, consent evaluation, policy
evaluation, audit logging), unmodified. Specifically it:

- generates a fresh, cryptographically random Key Encryption Key, using
  `crypto.randomBytes` — never hard-coded, never reused,
- provisions an isolated Ed25519 signing key store and transparency key store in a fresh
  OS temp directory (never `data/keys.json`, never the production key store),
- provisions a fresh, dev-scoped **signing identity** in an isolated signing-identity
  store (never `data/signing-identities.json`) and prints its `sk_...` signing API key
  to the console once — see [Generate Artifact](#generate-artifact) below for how to use
  it. There is no shared `QODIQA_SIGN_TOKEN` secret to generate or configure; every
  caller of `POST /sign` authenticates with its own individually-issued key (see
  [Provision a Signing Identity](#provision-a-signing-identity) below for the
  manual-path equivalent),
- redirects the audit log to that same temp directory (never `audit.log`),
- sets `NODE_ENV=development`,
- probes whether Redis is reachable and, if it is not, **fails fast with an actionable
  error** rather than attempting to launch the server — Redis is a genuine, unconditional
  prerequisite (the consent-revocation subscriber has no dev-mode bypass; see
  [docs/guides/installation.md](installation.md) for the full explanation),
- if Redis is reachable, relaxes `STRICT_REPLAY_PROTECTION`'s stricter AOF-durability
  startup check by default (individual requests still fail closed at request time — see
  [docs/guides/installation.md](installation.md)),
- falls back to the `local` AI provider type if no real provider API key is configured (a
  real, production-supported provider for self-hosted runtimes like Ollama — not a mock;
  `/ai/chat` correctly returns `PROVIDER_UNAVAILABLE` if nothing is listening there),
- **if `QODIQA_PG_ENABLED=true` is set, also provisions PostgreSQL** (creates the
  configured database if missing, applies migrations, and grants development consent for
  the freshly generated dev signing key) via `scripts/lib/devConsent.js` — through the
  real, unmodified `src/core/consent` API, never raw SQL. **With `QODIQA_PG_ENABLED`
  unset (the default), this step is a complete no-op**, and the default policy set's
  `POL-001: REQUIRE_CONSENT` will then BLOCK every `/ai/chat` request with
  `CONSENT_STORE_UNAVAILABLE` — see
  [Provision Consent (PostgreSQL)](#provision-consent-postgresql) below, which is
  required before "Execute First Authorized Request" will succeed as documented.

Every invocation of `npm run dev` is fully isolated from every other — nothing persists
between runs, and production data (other than the PostgreSQL database itself, which is
real and persistent) is never read, written, or required. See
[docs/guides/installation.md](installation.md) for the complete development/production isolation model.

The rest of this guide documents the **manual, production-parity** setup (`npm start`),
useful when you want a persistent local key store or to test the exact production startup
path.

---

## Environment Setup

```bash
cd qodiqa-gateway
npm install
cp deploy/env/production.env.example .env
```

Open `.env` and replace every `<REPLACE_WITH_...>` placeholder. The required variables are covered in the next section. Leave all others at their defaults for local development.

### Local Development Overrides

`deploy/env/production.env.example` is written for a real production deployment — most of it is
genuinely safe to leave at its defaults for local development, per above, but a handful
of production-oriented defaults will actively break a plain local setup (TLS against a
plain local service, or a path meaningless outside a real deployment host) rather than
just being unnecessary. Set these explicitly for local development, gathered here in one
place instead of discovered one at a time later in this guide:

```
REDIS_URL=redis://localhost:6379
REDIS_TLS=false
QODIQA_PG_SSL=false
```

(`REDIS_TLS` is a separate switch from `REDIS_URL`'s own `redis://`/`rediss://` scheme —
setting `REDIS_URL` alone is not enough; see [Start Redis](#start-redis) below.
`QODIQA_PG_SSL` is covered again with connection details in
[Provision Consent (PostgreSQL)](#provision-consent-postgresql) below.)

The `QODIQA_KEYS_PATH`, `QODIQA_AUDIT_LOG`, and `POLICY_FILE` lines are commented out by
default — leave them commented out for local development. Each has a
safe, repo-relative built-in default for local development; only uncomment and set a real
absolute path for an actual production deployment on a host you control.

**`POLICY_FILE` is stricter than the other two in production**: `QODIQA_KEYS_PATH`/
`QODIQA_AUDIT_LOG` remain genuinely optional even in a real deployment (their repo-relative
default is merely inconvenient there, not unsafe). `POLICY_FILE` is different — its
repo-relative default (`policies.json`) is a demo/development fixture, and
`NODE_ENV=production` refuses to start without an explicit `POLICY_FILE` at all (`FATAL
POLICY_FILE_REQUIRED`); see [`deploy/env/production.env.example`](../../deploy/env/production.env.example) and
`docs/configuration/reference.md` §13. This QUICKSTART is local-development-only, so the
guidance above (leave it commented out here) is unaffected — this note exists so a reader
copying this same commented-out pattern into a production `.env` doesn't carry it over
unedited.

---

## Generate Required Secrets

Run these commands to generate cryptographically secure values. Paste each output into `.env`.

```bash
# Key Encryption Key — 64 hex characters (256-bit AES-256-GCM key)
# Encrypts the Ed25519 signing key store at rest.
openssl rand -hex 32
# → paste as: QODIQA_KEY_ENCRYPTION_KEY=<output>

# Execution Invariant Secret — 64 hex characters (256-bit HMAC-SHA256 key).
# Read by services/secrets/secretsProvider.js's getExecutionInvariantSecret(); the
# /ai/chat EXECUTE path's provider-dispatch step uses it to HMAC-bind the execution
# invariant context (verifiedCtx) before calling the AI provider, and
# services/execution-guard.js checks that binding on the way back. The boot
# validator refuses to start without it in every profile (rule secret.invariant
# in src/infra/config/bootValidator.js: missing, empty or not 64 hex characters
# is FATAL), so set it before the first start. Must be a DIFFERENT value from
# QODIQA_KEY_ENCRYPTION_KEY (purpose isolation between the two secrets is
# enforced — see docs/configuration/reference.md).
openssl rand -hex 32
# → paste as: QODIQA_EXECUTION_INVARIANT_SECRET=<output>

# Client identifier — identifies this deployment in artifacts and the key store
# → set as: QODIQA_CLIENT_ID=my-local-dev

# OpenAI API key — obtained from platform.openai.com/api-keys
# → set as: OPENAI_API_KEY=sk-...

# Ops token (deprecated shared token) — accepted only for /metrics and
# /diagnostics. It does NOT authorize /audit, /consent, /key-admin or any other
# RBAC-gated route (RBAC is unconditional; those need a per-operator API key,
# see "Verify Audit Trail" below). Optional for this guide.
openssl rand -hex 32
# → paste as: QODIQA_OPS_TOKEN=<output>
```

Your `.env` must contain at minimum:

```
QODIQA_KEY_ENCRYPTION_KEY=<64 hex chars>
QODIQA_EXECUTION_INVARIANT_SECRET=<64 hex chars, different from the KEK above>
QODIQA_CLIENT_ID=my-local-dev
OPENAI_API_KEY=sk-...
QODIQA_OPS_TOKEN=<32+ chars>
```

`.env` is already gitignored — never commit it. In production, inject
`QODIQA_EXECUTION_INVARIANT_SECRET` via your secret manager rather than a file on disk,
same as `QODIQA_KEY_ENCRYPTION_KEY`.

There is no `QODIQA_SIGN_TOKEN` to generate — `POST /sign` no longer accepts a shared
secret. Every caller authenticates with its own individually-issued signing API key; see
[Provision a Signing Identity](#provision-a-signing-identity) below.

---

## Provision First Signing Key

> If you're following the [Fastest path](#fastest-path-npm-run-dev) (`npm run dev`)
> instead, skip this step entirely — `scripts/bootstrap-dev.js` provisions an isolated
> signing key for you automatically on every run (never `data/keys.json`), and prints
> confirmation ("Provisioned isolated signing key for client...") in its own startup
> output. This section is required only for the manual, production-parity path
> (`npm start`) below.

QODIQA refuses to start with an empty key store. Run this once to generate the initial Ed25519 signing key pair and write it encrypted to `data/keys.json`. `data/` is created automatically on first write if it doesn't already exist — no separate `mkdir` step is required.

Provision the key (env vars are loaded from `.env` via `--require dotenv/config`):

```bash
node --require dotenv/config \
  -e "require('./services/artifact/keyManager').rotate(process.env.QODIQA_CLIENT_ID)"
```

Expected log output to stdout:

```
{"ts":"2026-...","level":"INFO","event":"KEY_CREATED","clientId":"my-local-dev","keyId":"my-local-dev:key_v1","version":1,"status":"active"}
```

The key identifier `my-local-dev:key_v1` follows the format `<clientId>:key_v<version>`.

> `data/keys.json` contains encrypted private key material. Do not commit it to version control.

---

## Provision the Consent-Signer Key

> If you're following the [Fastest path](#fastest-path-npm-run-dev) (`npm run dev`)
> instead, skip this step entirely — `scripts/bootstrap-dev.js`
> provisions an isolated consent-signer key for you automatically on every run too,
> confirmed in its own startup output ("Provisioned isolated consent-signer key (serves
> GET /public-key)"). This section is required only for the manual, production-parity
> path (`npm start`) below.

`GET /public-key` serves the public half of a separate, reserved signing identity —
`consent-signer` — not any tenant's own key from the step above. It is not provisioned
by anything else in this guide (outside `npm run dev`'s own bootstrap, see above) — a
production deployment following only the manual steps in this guide would have
`/public-key` return `500 KEY_UNAVAILABLE` indefinitely without it. Run this once,
alongside "Provision First Signing Key" above:

```bash
node --require dotenv/config scripts/provision-consent-signer.js
```

Re-running it is safe — it reports `ALREADY_EXISTS` and takes no action if the key is
already provisioned, the same idempotent pattern as the rest of this guide.

---

## Provision a Signing Identity

`POST /sign` authenticates every caller as its own individually-issued, individually-
revocable **signing identity** — there is no shared secret. Provision one now with
[`scripts/provision-signing-identity.js`](../../scripts/provision-signing-identity.js):

```bash
node scripts/provision-signing-identity.js \
  --name my-local-dev-cli \
  --tenant-id my-local-dev \
  --environment development
```

- `--tenant-id` must match `QODIQA_CLIENT_ID` above (`my-local-dev`) — a signing identity
  can only ever sign artifacts against its own tenant's key (`data/keys.json` entry from
  the previous step).
- `--environment` must match the environment the running server resolves at request time
  (`QODIQA_ENVIRONMENT` if set, otherwise `NODE_ENV`, otherwise `development` — see
  `src/core/signing/serverEnvironment.js`). **Which one is correct depends on which path
  you're following, not just on what's shown here:**
  - [Fastest path](#fastest-path-npm-run-dev) (`npm run dev`) — `development` is correct;
    `scripts/bootstrap-dev.js` forces `NODE_ENV=development` regardless of `.env`.
  - [Path B](#path-b--npm-start-manual-production-parity) (`npm start`) — use
    `--environment production` instead. `deploy/env/production.env.example` (copied to `.env` in
    [Environment Setup](#environment-setup)) sets `NODE_ENV=production` by default, and
    nothing in this path overrides it.

  A mismatch is rejected at request time with `403 SCOPE_ENVIRONMENT_MISMATCH`, not at
  provisioning time — so this only surfaces once you try to execute a request, not here.

Expected output:

```json
{
  "status": "PROVISIONED",
  "identityId": "<uuid-v4>",
  "name": "my-local-dev-cli",
  "tenantId": "my-local-dev",
  "environment": "development",
  "allowedProviders": null,
  "issuedAt": "2026-...",
  "apiKey": "sk_<64 hex characters>",
  "message": "Store this signing API key securely now — it will never be displayed again. Use it as \"Authorization: Bearer <apiKey>\" against POST /sign."
}
```

The `apiKey` (`sk_...`) is printed **exactly once** — it is stored only as a salted hash
in `data/signing-identities.json` and can never be recovered later. Copy it now; you'll
use it as `SIGN_TOKEN` in [Generate Artifact](#generate-artifact) below. Re-running the
same command without `--rotate` reports `ALREADY_PROVISIONED` rather than reprinting the
key — pass `--rotate` to issue a new one (this immediately invalidates the old key).

Also save `identityId` — it's the UUID every artifact this identity signs carries as
`payload.callerContext.callerId`, and it's what [Provision Consent (PostgreSQL)](#provision-consent-postgresql)'s
Path B grants consent against below:

```bash
export SIGNING_IDENTITY_ID=<the identityId UUID from the output above>
```

> If you're following the [Fastest path](#fastest-path-npm-run-dev) (`npm run dev`)
> instead, skip this step entirely — a dev-scoped signing identity is provisioned for you
> automatically on every run, and its key is printed in the startup banner.

---

## Start Redis

QODIQA requires Redis for replay protection (nonce store), anomaly detection, and policy rate limiting. For development, start a local Redis instance:

```bash
redis-server
```

For production replay-protection guarantees, Redis must run with AOF persistence:

```bash
redis-server --appendonly yes --appendfsync everysec
```

Verify Redis is reachable:

```bash
redis-cli ping
# Expected: PONG
```

`deploy/env/production.env.example`'s own shipped defaults are TLS-oriented and will not connect to
the plain, local Redis instance started above — see
[Local Development Overrides](#local-development-overrides) in Environment Setup, which
you should already have applied (`REDIS_URL=redis://localhost:6379`, `REDIS_TLS=false` —
two independent switches; changing the URL scheme alone is not enough). If Redis
connections are failing here, that's the first thing to check. `REDIS_USERNAME`/
`REDIS_PASSWORD` can be left unset — this local instance has no ACL configured.

---

## Start QODIQA

```bash
npm start
```

Expected startup log lines (one JSON object per line):

```
{"ts":"...","level":"INFO","event":"KEY_MANAGER_READY","activeKeys":1,...}
{"ts":"...","level":"INFO","event":"POLICIES_LOADED","count":5,"ids":["POL-001","POL-002","POL-003","POL-004","POL-NEW"]}
{"ts":"...","level":"INFO","event":"NONCE_STORE_READY",...}
{"ts":"...","level":"INFO","event":"ANOMALY_STORE_READY",...}
{"ts":"...","level":"INFO","event":"RATE_LIMIT_STORE_READY",...}
{"ts":"...","level":"INFO","event":"GATEWAY_RUNTIME_READY",...}
{"ts":"...","level":"INFO","event":"GATEWAY_START","port":3000,"ready":true,...}
```

If a Redis store fails to connect, `GATEWAY_RUNTIME_DEGRADED` (all stores) or `GATEWAY_RUNTIME_PARTIAL_FAILURE` (some stores) is emitted instead of `GATEWAY_RUNTIME_READY`, and requests requiring that store are blocked fail-closed until it reconnects.

---

## Verify Health

```bash
curl -s http://localhost:3000/health
```

Expected response (HTTP 200):

```json
{"status":"ok","uptime":3.4}
```

Check readiness (includes per-store Redis status):

```bash
curl -s http://localhost:3000/ready
```

Expected response when all stores are connected (HTTP 200):

```json
{
  "ready": true,
  "components": {
    "nonceStore": true,
    "anomalyStore": true,
    "rateLimitStore": true
  }
}
```

HTTP 503 with `"ready": false` means one or more Redis stores are unavailable.

---

## Provision Consent (PostgreSQL)

The default `policies.json` ships with `POL-001: REQUIRE_CONSENT` **enabled** — this is
the correct, secure default and is not something this guide weakens. That policy
unconditionally checks the [Runtime Consent Registry](../../README.md), which is backed
by PostgreSQL. **Skip this section and every `/ai/chat` call below will BLOCK with
`CONSENT_STORE_UNAVAILABLE`** (see [docs/operations/troubleshooting.md](../operations/troubleshooting.md)),
regardless of how correctly everything else was set up.

You need a running PostgreSQL instance (15–18). If you don't have one locally:

```bash
# Generate throwaway local passwords once, in this shell only (never commit or reuse them):
export QODIQA_PG_PASSWORD="$(openssl rand -hex 16)"
export QODIQA_PG_TEST_PASSWORD="$(openssl rand -hex 16)"
# `-e POSTGRES_PASSWORD` with no `=value` copies it from this shell's environment, so the password
# never appears on the docker command line (process list, shell history):
POSTGRES_PASSWORD="$QODIQA_PG_PASSWORD" docker run --rm -d --name qodiqa-pg -p 127.0.0.1:55432:5432 \
  -e POSTGRES_USER=qodiqa_app -e POSTGRES_PASSWORD -e POSTGRES_DB=qodiqa \
  postgres:17
```

> Use a free host port bound to 127.0.0.1 (55432 here, never 5432): publishing 5432 collides with — or silently
> targets — any PostgreSQL already running on the host. Never point a quickstart at an existing cluster.
> Making `qodiqa_app` the container superuser is a local-evaluation convenience only: a superuser bypasses RLS, so
> tenant-isolation behaviour in this setup is **not** representative of production, where `qodiqa_app` is the
> least-privilege role created by migration 002.

Add the following to `.env`:

```
QODIQA_PG_ENABLED=true
QODIQA_PG_HOST=127.0.0.1
QODIQA_PG_PORT=55432
QODIQA_PG_USER=qodiqa_app
QODIQA_PG_PASSWORD=<the QODIQA_PG_PASSWORD value generated above>
QODIQA_PG_SSL=false
```

(`127.0.0.1`, not `localhost`: the container is published on IPv4 loopback only, and `localhost` can resolve to
`::1` first.)

`QODIQA_PG_SSL=false` is only appropriate for local development against the container
above. Production deployments must use TLS — see
[docs/configuration/reference.md](../configuration/reference.md#6-postgresql-configuration).

### Bootstrap the `qodiqa_test` role (required once, for both paths)

Both paths below need a PostgreSQL role that can create a database and, on a genuinely
fresh cluster, apply role-management migrations (`qodiqa_mig` itself doesn't exist until
migration 002 creates it, and cannot grant itself `BYPASSRLS` at migration 018 — PostgreSQL
only allows a role that already holds `BYPASSRLS` to grant it to another). Neither the app
role (`qodiqa_app`, deliberately least-privilege) nor the default migration identity can do
this on a database that has never been migrated before. This is a one-time, documented
operator action — see
[docs/operations/database-role-management.md](../operations/database-role-management.md)
for the full rationale — not something either path automates for you.

Using the `postgres` superuser (or, if you used the Docker command above, `qodiqa_app` —
that container's `POSTGRES_USER` *is* its superuser, a Docker-specific convenience, not a
general-purpose shortcut):

```bash
# SQL on stdin (heredoc), not in -c: keeps the password out of psql's argv. psql prompts for the
# superuser's own password (for the Docker container: the QODIQA_PG_PASSWORD generated above).
psql -h 127.0.0.1 -p 55432 -U <superuser: postgres, or qodiqa_app for the Docker container> -d postgres <<SQL
CREATE ROLE qodiqa_test WITH LOGIN CREATEDB CREATEROLE BYPASSRLS PASSWORD '${QODIQA_PG_TEST_PASSWORD}';
SQL
```

Add to `.env`:

```
QODIQA_PG_TEST_USER=qodiqa_test
QODIQA_PG_TEST_PASSWORD=<the QODIQA_PG_TEST_PASSWORD value generated above>
```

> If the commands below still fail with `permission denied to alter role` after the
> `CREATE ROLE` above, run `GRANT qodiqa_mig TO qodiqa_test WITH ADMIN OPTION, INHERIT TRUE, SET TRUE;`
> as the superuser too — PostgreSQL 16+ restricts a `CREATEROLE` role's administrative reach to
> roles it created itself or was explicitly granted admin-option membership on, and migration 055's
> `SET ROLE qodiqa_mig` additionally needs the membership's SET (and INHERIT) option; with ADMIN
> alone a fresh chain stops at 055 with `must be able to SET ROLE "qodiqa_mig"`. See
> `docs/operations/database-role-management.md` and
> §2a for the full mechanism.

### Path A — `npm run dev` (recommended for this guide)

**Leave `QODIQA_PG_DATABASE` unset in `.env` for this path** — with it unset,
`scripts/lib/devConsent.js` generates a fresh, isolated, per-boot database name
automatically and migrates it using the `qodiqa_test` role bootstrapped above (privileged
enough for a genuinely fresh database; the default migration identity is not — see above).
Setting `QODIQA_PG_DATABASE` explicitly opts out of this isolation and is covered under
Path B below instead.

With `QODIQA_PG_ENABLED=true` set in `.env` (and `QODIQA_PG_DATABASE` unset), just re-run
`npm run dev`. `scripts/bootstrap-dev.js` detects the flag and automatically creates and
migrates an isolated database, and grants a development consent record — against the
freshly generated dev signing *identity's own id* (the value every artifact it signs
carries as `payload.callerContext.callerId`, and what verification actually looks up by;
not the signing key's own id, a different value from a different store) — for every
configured AI provider, idempotently, on every invocation. Look for these lines in its
output:

```
[bootstrap-dev] QODIQA_PG_ENABLED=true — provisioning the development PostgreSQL schema and consent grant...
[bootstrap-dev] No QODIQA_PG_DATABASE set — using a fresh, isolated per-boot database "qodiqa_dev_a1b2c3d4" (never the shared "qodiqa" database).
[bootstrap-dev] Development database "qodiqa_dev_a1b2c3d4" does not exist — creating it...
[bootstrap-dev] Created development database "qodiqa_dev_a1b2c3d4".
[bootstrap-dev] Development schema up to date (78 migration(s) applied this run, 0 already current).
[bootstrap-dev] Granted development consent: actor_id=9c3f2b1a-....-.... action=openai tenant_id=dev-local
```

Nothing further is required — proceed to [Generate Artifact](#generate-artifact) below.
See [docs/operations/troubleshooting.md "Development PostgreSQL databases accumulate"](../operations/troubleshooting.md)
for cleanup guidance on these per-boot databases.

> **One-off isolated run on a machine whose `.env` already sets `QODIQA_PG_DATABASE`**
> (e.g. it was previously set for Path B): shell-unsetting the variable for a single
> invocation does **not** isolate the boot — `bootstrap-dev.js`'s `dotenv.config()` runs
> first and re-fills it from `.env` regardless (`dotenv`'s `populate()` only skips keys
> already present; a shell-level unset makes the key absent, not present-but-empty). Pass
> an explicit empty string instead, which survives `dotenv` and is treated as unset by
> `devConsent.js`:
> ```bash
> QODIQA_PG_DATABASE= npm run dev
> ```
> From PowerShell, `$env:QODIQA_PG_DATABASE = ""` **deletes** the variable rather than
> emptying it, hitting the same dotenv-backfill problem — set it inside the process
> instead: `node -e "process.env.QODIQA_PG_DATABASE='';require('./scripts/bootstrap-dev.js')"`.

### Path B — `npm start` (manual, production-parity)

This path reuses one persistent database across runs — add to `.env`:

```
QODIQA_PG_DATABASE=qodiqa
```

**If you're using the Docker command above, skip this step** — `POSTGRES_DB=qodiqa` in
that command already created the database as part of container startup. If you're using
your own existing PostgreSQL instance instead, the database does not exist yet and must be
created once, using the `qodiqa_test` role bootstrapped above (`CREATEDB`):

```bash
psql -h 127.0.0.1 -p 55432 -U qodiqa_test -d postgres -c "CREATE DATABASE qodiqa;"
```

(`-d postgres` targets the maintenance database explicitly — `qodiqa_test` has no
same-named database of its own to fall back to by default, unlike the `postgres`
superuser used in the `CREATE ROLE` step above.)

Apply the schema once, using the same idempotent migration runner every environment uses.
**First run against a fresh database:** the default `QODIQA_PG_MIG_USER` (`qodiqa_mig`)
cannot apply migrations 002 or 018 on a database that has never been migrated before —
`migrate.js` fails loudly with `PG_MIGRATE_ROLE_PRIVILEGE_DENIED` and names the exact
remedy if you skip this. Use the `qodiqa_test` role bootstrapped above for this first run:

```bash
QODIQA_PG_MIG_USER=qodiqa_test QODIQA_PG_MIG_PASSWORD="$QODIQA_PG_TEST_PASSWORD" \
  node --require dotenv/config src/infra/postgres/migrate.js
```

Subsequent runs (no new role-management migrations pending) can use the default
`QODIQA_PG_MIG_USER` instead — see
[docs/operations/database-role-management.md](../operations/database-role-management.md)
for the full explanation of why this split exists.

**This path runs with `NODE_ENV=production`** — `deploy/env/production.env.example`'s own default,
left untouched by this path's "manual, production-parity" instructions. This has two
consequences worth knowing about before you start the server, not after it fails:

- **`QODIQA_KEYS_PATH` must be set to a path outside this project directory.**
  `src/infra/secrets/secretValidation.js` refuses to start in production if the key store
  resolves inside the repo (the default, `data/keys.json`, does). Add to `.env`, using any
  absolute path outside this checkout — e.g. `~/.qodiqa/keys.json` on Linux/macOS, or on
  Windows an absolute path with a drive letter such as
  `C:/Users/<you>/.qodiqa/keys.json` (a `/`-prefixed POSIX-style path is not portable
  here — see the [Execute First Authorized Request](#execute-first-authorized-request)
  section's own note on Windows path handling):
  ```
  QODIQA_KEYS_PATH=<an absolute path outside this project directory>
  ```
  Then re-run [Provision First Signing Key](#provision-first-signing-key) and
  [Provision the Consent-Signer Key](#provision-the-consent-signer-key) above — they write
  to whatever `QODIQA_KEYS_PATH` currently resolves to, so both must run again after
  changing it.
- **Replay-protection strictness cannot be relaxed via `.env` on this path.** Production
  mode always enforces `STRICT_REPLAY_PROTECTION` regardless of that variable's value (a
  deliberate anti-config-drift control — see `server/startup.js`'s own `REPLAY-2` comment).
  Use the AOF-enabled `redis-server --appendonly yes --appendfsync everysec` command from
  [Start Redis](#start-redis) above, not the plain one — otherwise the server FATALs at
  startup with `STRICT_REPLAY_PROTECTION_VIOLATION`.
- When you reach [Provision a Signing Identity](#provision-a-signing-identity) below, pass
  `--environment production` to match (`--environment development`, the example shown
  there, only matches `npm run dev`'s own forced-development mode) — otherwise `/sign`
  refuses to sign (`403 SCOPE_ENVIRONMENT_MISMATCH`).

Then grant consent for your provisioned signing identity through the real consent API
(the same code path `POST /consent` uses in production, called directly here so this
guide doesn't also require setting up an RBAC operator account just to test the happy
path). This must be granted against the signing identity's own `identityId` — the value
`POST /sign` stamps onto every artifact as `payload.callerContext.callerId`, and the
exact value verification looks up by (see `services/policy/evaluators/requireConsent.js`).
It is **not** the artifact-signing key's own id (`<clientId>:key_v1`) — a different
identifier from a different store that happens to look similar:

```bash
node --require dotenv/config -e "
  require('./src/infra/postgres/pool').initialize();
  require('./src/core/consent').grant({
    actor_id:    process.env.SIGNING_IDENTITY_ID,
    action:      'openai',
    tenant_id:   process.env.QODIQA_CLIENT_ID,
    granted_by:  'quickstart',
    granted_via: 'MANUAL',
    grant_reference: 'docs/guides/quickstart.md manual provisioning',
  }).then(r => { console.log('Granted consent record', r.id); process.exit(0); })
    .catch(e => { console.error(e); process.exit(1); });
"
```

`SIGNING_IDENTITY_ID` must be set in your shell — see
[Provision a Signing Identity](#provision-a-signing-identity) above. `action` must match
the provider your signed request resolves to (see [Where did `payload.provider: "openai"`
come from?](#execute-first-authorized-request) below) — use `openai` if you only
configured `OPENAI_API_KEY`, as this guide does.
For production operator workflows (RBAC-authenticated `POST /consent`), see
[docs/security/RBAC_MODEL.md](../security/RBAC_MODEL.md) and
[README.md](../../README.md).

---

## Generate Artifact

An artifact is a cryptographically signed authorization token bound to a specific request. The `/sign` endpoint creates one, authenticated by your signing API key as `Authorization: Bearer <key>`.

Set `SIGN_TOKEN` to the `sk_...` key for whichever path you followed:

- **Fastest path (`npm run dev`)**: copy the "Signing API Key" printed in the startup banner.
- **Manual path (`npm start`)**: use the `apiKey` printed by [Provision a Signing Identity](#provision-a-signing-identity) above.

```bash
export SIGN_TOKEN=<the sk_... key from whichever path you followed>

curl -s -X POST http://localhost:3000/sign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SIGN_TOKEN" \
  -d '{
    "request": {
      "method": "POST",
      "path": "/ai/chat",
      "body": { "prompt": "Hello, what is 2 + 2?" }
    }
  }'
```

Expected response (HTTP 200):

```json
{
  "artifactId": "<uuid-v4>",
  "artifact": {
    "expiry": 1749470060000,
    "payload": {
      "requestId": "<uuid-v4>",
      "requestHash": "<64-char hex>",
      "policyHash": "<64-char hex>",
      "provider": "openai",
      "tenantId": "my-local-dev",
      "callerContext": {
        "callerId": "<signing identity id>",
        "callerName": "<signing identity name>",
        "environment": "development",
        "credentialType": "api-key"
      }
    },
    "publicKeyId": "my-local-dev:key_v1",
    "signature": "<base64-encoded Ed25519 signature>",
    "timestamp": 1749470000000
  },
  "meta": {
    "keyId": "my-local-dev:key_v1",
    "expiresAt": 1749470060000,
    "effectiveTtlMs": 60000,
    "ttlClamped": false,
    "tenantId": "my-local-dev",
    "callerId": "<signing identity id>"
  },
  "requestId": "<uuid-v4>"
}
```

`meta.expiresAt` is a Unix millisecond timestamp. The artifact lives at most 60 s (the maximum artifact age verification accepts): with no `ttl` the default is 60 000 ms, and a larger requested `ttl` is clamped to it — `meta.effectiveTtlMs` is the TTL actually granted and `meta.ttlClamped` is `true` when the request asked for more. `artifact.payload.callerContext` is an immutable snapshot of the authenticated signing identity, embedded in the signed envelope for caller-attribution; `meta.callerId` mirrors its `callerId` at the top level for convenience. The `artifact` object must be JSON-serialized and base64-encoded before sending as the `x-qodiqa-artifact` header.

**Where did `payload.provider: "openai"` come from?** For any request whose signed `request.path` is `/ai/chat`, `/sign` resolves which AI provider the resulting artifact authorizes — locked into the artifact at signing time, not decided later at execution. The request above never set `payload.provider` explicitly, so `/sign` auto-resolved it to `openai` because it's the only AI provider this Quickstart configured (`OPENAI_API_KEY`).

This auto-resolution only fires when it's unambiguous:

- **Exactly one provider enabled** (as in this guide) → auto-resolved to that provider.
- **Zero or more than one provider enabled** → `/sign` returns `400 { "reason": "PROVIDER_REQUIRED", "details": { "enabledProviders": [...] } }`. You must supply `payload.provider` explicitly.

To pin a specific provider regardless of server configuration — required once you configure more than one provider — pass it explicitly:

```bash
curl -s -X POST http://localhost:3000/sign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SIGN_TOKEN" \
  -d '{
    "request": {
      "method": "POST",
      "path": "/ai/chat",
      "body": { "prompt": "Hello, what is 2 + 2?" }
    },
    "payload": { "provider": "openai" }
  }'
```

An explicit `payload.provider` is validated immediately: an unrecognized name returns `400 PROVIDER_NOT_SUPPORTED`; a recognized but unconfigured provider (missing API key) returns `400 PROVIDER_NOT_CONFIGURED`.

---

## Execute First Authorized Request

The request body sent to `/ai/chat` must be **identical** to what was signed. The SDK handles artifact minting, encoding, and attachment automatically.

### Using the JavaScript SDK

The maintained JavaScript SDK lives at `sdk/javascript`. Build it once with
`npm run sdk:build` (the `dist/` output is not committed — see [README.md "Quick start"](../../README.md#quick-start)). The root [`examples/quickstart.js`](../../examples/quickstart.js)
runs exactly this flow end to end — `QODIQA_SIGN_TOKEN` here is just this example's own
shell-variable name for the `sk_...` key from whichever path you followed above (the
`npm run dev` banner, or [Provision a Signing Identity](#provision-a-signing-identity)):

```bash
QODIQA_SIGN_TOKEN=<the sk_... key from whichever path you followed> node examples/quickstart.js
```

```javascript
const { QodiqaClient } = require('./sdk/javascript/dist/index.js');

const client = new QodiqaClient({
  baseUrl:   'http://localhost:3000',
  signToken: process.env.QODIQA_SIGN_TOKEN,
});

const signed = await client.sign.sign({
  request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello, what is 2 + 2?' } },
});

const artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');
const result = await client.chat.create(artifactB64, { prompt: 'Hello, what is 2 + 2?' });

console.log(result.decision);  // "EXECUTE"
console.log(result.aiText);    // "<AI text — raw string>"
```

`client.sign.sign()` calls `POST /sign` to obtain an artifact; `client.chat.create()` base64-encodes it, attaches it as `x-qodiqa-artifact`, and dispatches the request to `/ai/chat`. This omits `payload.provider` — the server auto-resolves it since only one provider is configured. Pass an optional `payload` to pin a specific provider (required once more than one is enabled):

```javascript
const signed = await client.sign.sign({
  request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello, what is 2 + 2?' } },
  payload: { provider: 'openai' },
});
```


### Using the Python SDK

The maintained Python SDK lives at `sdk/python` (not yet published to PyPI — install it
from the repo). `sdk/python/examples/basic_client.py` runs the same flow end to end —
again, `QODIQA_SIGN_TOKEN` is just this example's shell-variable name for the `sk_...` key:

```bash
pip install ./sdk/python
QODIQA_SIGN_TOKEN=<the sk_... key from whichever path you followed> python sdk/python/examples/basic_client.py
```

```python
import base64, json, os
from qodiqa import QodiqaClient

client = QodiqaClient(
    base_url='http://localhost:3000',
    sign_token=os.environ['QODIQA_SIGN_TOKEN'],
)

signed = client.sign.sign({
    'request': {'method': 'POST', 'path': '/ai/chat', 'body': {'prompt': 'Hello, what is 2 + 2?'}},
})

artifact_b64 = base64.b64encode(json.dumps(signed['artifact']).encode()).decode()
result = client.chat.create(artifact_b64, {'prompt': 'Hello, what is 2 + 2?'})

print(result['decision'])       # 'EXECUTE'
print(result.get('aiText'))     # '<AI text — raw string>'
```

### Using curl (two steps)

```bash
# SIGN_TOKEN: the sk_... key from whichever path you followed — see Generate Artifact above
export SIGN_TOKEN=<the sk_... key from whichever path you followed>

# Step 1: sign the exact request you intend to make
SIGN_RESPONSE=$(curl -s -X POST http://localhost:3000/sign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SIGN_TOKEN" \
  -d '{"request":{"method":"POST","path":"/ai/chat","body":{"prompt":"Hello, what is 2 + 2?"}}}')

# Step 2: encode the artifact (JSON.stringify then base64)
# Reads via process.env, not stdin — `/dev/stdin` (e.g. via `<<<`) is a POSIX path
# that Git Bash on Windows silently rewrites to a literal `C:\dev\stdin` before a
# native Windows Node binary ever sees it (ENOENT), even though Git Bash is this
# guide's own named Windows shell (see Prerequisites above). This form works
# identically on Git Bash, WSL, and Linux/macOS.
export SIGN_RESPONSE
ARTIFACT=$(node -e "
  const d = JSON.parse(process.env.SIGN_RESPONSE);
  process.stdout.write(Buffer.from(JSON.stringify(d.artifact)).toString('base64'));
")

# Step 3: execute with the artifact attached
curl -s -X POST http://localhost:3000/ai/chat \
  -H "Content-Type: application/json" \
  -H "x-qodiqa-artifact: $ARTIFACT" \
  -d '{"prompt":"Hello, what is 2 + 2?"}'
```

Expected response (HTTP 200):

```json
{
  "decision": "EXECUTE",
  "reason": "ALL_CHECKS_PASSED",
  "response": "2 + 2 equals 4.",
  "artifactId": "<uuid-v4>",
  "keyId": "my-local-dev:key_v1",
  "requestId": "<uuid-v4>",
  "transparency": {
    "transparencyId": "<uuid-v4>",
    "entryHash": "<64-char hex>",
    "leafHash": "<64-char hex>",
    "signerKeyId": "my-local-dev:key_v1",
    "persisted": true,
    "inclusionProofRef": "/transparency/proof/<transparencyId>"
  },
  "aiDisclosure": {
    "aiGenerated": true,
    "provider": "local",
    "model": "<model>",
    "notice": "This response was generated by an AI system."
  }
}
```

`response` is a raw string containing the AI output. `transparency` is this decision's RFC 6962 Merkle transparency-log registration (see [docs/architecture/overview.md](../architecture/overview.md)). `aiDisclosure` marks the output as AI-generated (EU AI Act Art. 50; the response also carries `X-QODIQA-AI-Generated: true`) — show `notice` to your end users.

---

## Execute First Unauthorized Request

Send a request to `/ai/chat` without any artifact:

```bash
curl -s -X POST http://localhost:3000/ai/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Hello, what is 2 + 2?"}'
```

Expected response (HTTP 200 — every policy/verification `BLOCK` on `/ai/chat` is a resolved decision value, not an HTTP error; see [SECURITY.md](../../SECURITY.md) and the findings register):

```json
{
  "decision": "BLOCK",
  "reason": "MISSING_ARTIFACT",
  "details": {},
  "requestId": "<uuid-v4>"
}
```

Every request without a valid artifact is blocked at the input guard before the enforcement pipeline runs.

---

## Verify Audit Trail

Every enforcement decision — both `EXECUTE` and `BLOCK` — is appended to a cryptographically chained audit log. Retrieve the record for an artifact by its `requestId` (from the `/sign` response `artifactId` field):

`/audit/:artifactId` is an operator endpoint, not a public one. It requires a **per-operator RBAC API key** (`ok_<64 hex>`) whose role holds `READ_AUDIT`, sent as a bearer credential. A request without a credential, or with an invalid one, returns `401 { "reason": "UNAUTHORIZED" }`.

Issue the first operator key **out of band**, on the host, against the same control-plane store the server uses. In development/test memory mode, the RBAC store is read once at boot, so issue the key **before** (re)starting the server:

```bash
npm run rbac:bootstrap-key      # prints {"status":"PROVISIONED", ..., "apiKey":"ok_..."} exactly once
# store the printed apiKey securely; it is never shown again (re-run with --rotate to replace it)
```

Then:

```bash
OPERATOR_KEY='<the ok_... apiKey printed above>'

curl -s http://localhost:3000/audit/<requestId-from-sign-response> \
  -H "Authorization: Bearer $OPERATOR_KEY"
```

Further operators are created through the `/rbac` API with this key (see `docs/security/RBAC_MODEL.md`).

Expected response (HTTP 200):

```json
{
  "status": "success",
  "timestamp": "2026-06-09T12:00:00.000Z",
  "requestId": "<uuid-v4>",
  "data": {
    "artifactId": "<uuid-v4>",
    "lineageState": "COMPLETE",
    "execution": {
      "found": true,
      "decision": "ALLOW",
      "stage": "PROVIDER_EXECUTION",
      "reason": null,
      "provider": "openai",
      "timestamp": "2026-06-09T12:00:00.000Z",
      "verificationResult": true
    },
    "verification": { "outcome": "VERIFIED", ... },
    "policy": { "outcome": "ALLOWED", ... },
    "consent": { "outcome": "GRANTED" },
    "replay": { "replayDetected": false, "replayAttempts": 0, "attempts": [] },
    "chainIntegrity": { "valid": true, "entriesVerified": 1, "tamperingDetected": false },
    "lineageCompleteness": { "hasExecution": true, "complete": true },
    "resolvedAt": "2026-06-09T12:00:01.000Z"
  }
}
```

`data.chainIntegrity.valid: true` confirms hash-chain integrity. `data.execution.decision: "ALLOW"` confirms the request was executed.

The endpoint validates the UUID v4 format of `artifactId` and returns HTTP 400 with `INVALID_ARTIFACT_ID` for malformed identifiers.

---

## Verify Public Key Endpoint

Retrieve all active and deprecated public keys (revoked keys are excluded):

```bash
curl -s http://localhost:3000/.well-known/qodiqa/keys
```

Expected response (HTTP 200):

```json
{
  "keys": [
    {
      "keyId": "my-local-dev:key_v1",
      "algorithm": "ed25519",
      "publicKey": "<base64-encoded SPKI-DER public key>",
      "status": "active"
    }
  ],
  "requestId": "<uuid-v4>"
}
```

---

## Verify Public Key Discovery by ID

Retrieve a specific key by its identifier:

```bash
curl -s http://localhost:3000/.well-known/qodiqa/keys/my-local-dev:key_v1
```

Expected response (HTTP 200):

```json
{
  "keyId": "my-local-dev:key_v1",
  "algorithm": "ed25519",
  "publicKey": "<base64-encoded SPKI-DER public key>",
  "status": "active",
  "requestId": "<uuid-v4>"
}
```

Key identifiers must match `[A-Za-z0-9_-]{1,64}:key_v[0-9]+`. Revoked or unknown keys return HTTP 404.

---

## Next Steps

- `docs/architecture/overview.md` — how enforcement layers interact
- `docs/architecture/enforcement-flow.md` — complete per-request decision pipeline
- `docs/operations/troubleshooting.md` — diagnosis and resolution for all failure modes
- `docs/operations/runbook.md` — key rotation, policy reload, and graceful shutdown
