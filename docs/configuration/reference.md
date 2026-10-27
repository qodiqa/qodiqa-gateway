# QODIQA Configuration Reference

**Last verified:** 2026-10-25

Complete reference for every environment variable accepted by QODIQA. Variables marked
**Required** cause `process.exit(1)` at startup if absent or invalid. Variables marked
**Recommended** have defaults that are safe for development but should be explicitly set
in production.

Validation is implemented and
`src/infra/secrets/secretValidation.js`. Run `node start.js` to see validation output.

**Related documents:**
- `docs/deployment/production.md` — deployment guide with example configurations
- `docs/guides/providers.md` — full AI provider reference (capabilities, limits, error codes per provider)
- `docs/security/secrets-management.md` — KEK and secret rotation procedures
- `docs/security/key-management.md` — key lifecycle operations
- `docs/deployment/redis-tls.md` — Redis TLS configuration
- `docs/operations/startup-runbook.md` — startup validation sequence

---

## Quick Reference

| Variable | Required | Default | Category |
|----------|----------|---------|----------|
| `QODIQA_KEY_ENCRYPTION_KEY` | Yes | — | Security |
| `QODIQA_EXECUTION_INVARIANT_SECRET` | Yes | — | Security |
| `QODIQA_CLIENT_ID` | Yes | — | Identity |
| `OPENAI_API_KEY` ¹ | Yes ¹ | — | AI Provider |
| `PORT` | No | `3000` | Server |
| `QODIQA_BIND_HOST` | No | `0.0.0.0` | Server |
| `QODIQA_TOOL_SELF_APPROVAL` | No | unset | Tool gateway (development only: lets one operator register and approve a changed tool version; ignored in production) |
| `QODIQA_ANCHOR_EXEC_ENV_PASS` | No | unset | Audit anchoring (comma-separated variable names passed to git and the OTS/TSA adapters in addition to PATH, HOME, TEMP and QODIQA_ANCHOR_*) |
| `NODE_ENV` | Yes | — | Server |
| `QODIQA_DSR_PSEUDONYM_PEPPER` | Yes in production | — | Security |
| `QODIQA_MAC_KEYS_PATH` | File must exist in production | `mac-keys.json` beside `QODIQA_KEYS_PATH` | Security — MAC keyring signing consent-cache entries and revocation/org-status pub/sub; provision once with `node scripts/security/macKeyring.js init`, share with every node |
| `REVOCATION_SIGNING_KEY` / `ORG_STATUS_SIGNING_KEY` | **Deprecated** — ignored; boot warns if set | — | Security |
| `RL_ENABLED` | `true` required in production | `true` iff `REDIS_URL` set | Rate limiting |
| `QODIQA_ADMIN_ENABLED` | No | `false` in production | Admin plane |
| `QODIQA_DIAGNOSTICS_ENABLED` | No | `false` in production | Diagnostics plane |
| `REDIS_URL` | No | `redis://localhost:6379` | Redis |
| `STRICT_REPLAY_PROTECTION` | No | `true` | Enforcement |
| `AI_CHAT_TIMEOUT_MS` | No | `30000` | Enforcement |
| `QODIQA_DEPLOYMENT_MODE` | No | *(legacy vars)* | Deployment Topology |
| `QODIQA_PG_ENABLED` | No | `false` | PostgreSQL |
| `QODIQA_ALLOWED_ORIGINS` | Recommended | deny-all | CORS |
| `TRUSTED_PROXY` | No | `loopback` | Proxy trust — peers whose `X-Forwarded-For` is honoured; whole private ranges are fatal in production without `QODIQA_TRUSTED_PROXY_BROAD_ACK=true`. See docs/deployment/production.md "Proxy trust" |
| `TRUSTED_PROXY_REAL_IP` | No | unset | Proxy trust — `true` only when the trusted proxy sets `X-Real-IP` itself; otherwise the header is ignored |
| `QODIQA_ANCHOR_EXPORT_PATH`, `QODIQA_WITNESS_MODE`, `QODIQA_WITNESS_PUBLIC_KEYS` (+ `_KEY_PATH`/`_LOG_PATH` for `local`, `_EXEC` for `exec`) | **Yes in production** | unset / `none` | Audit anchoring — witness-cosigned checkpoint anchors; see docs/security/audit-anchoring.md |
| `QODIQA_AUDIT_ANCHORING_WAIVER` | **Refused in production** | unset | Removed escape hatch: production has no anchoring waiver; distributed mode is refused in production until |
| `QODIQA_KMS_PROVIDER` | No | `local` | Key Management |
| `QODIQA_KEY_ROTATION_SCHEDULE` | No | `monthly` | Key Management |
| `QODIQA_CONFIG_SECRETS_PROVIDER` | No | `env` | Secrets Management |
| `QODIQA_PORTAL_ENABLED` | No | `false` | Tenant Portal |
| `QODIQA_PORTAL_SESSION_SECRET` | Required if portal enabled | — | Tenant Portal |
| `QODIQA_OIDC_ISSUER` | Required if portal enabled | — | Tenant Portal |
| `QODIQA_ADMISSION_{SIGN,AI_CHAT,VERIFY,ACTIONS,TOOLS}_MAX_INFLIGHT` / `_QUEUE` / `_QUEUE_TIMEOUT_MS` | No | sign 64/128, ai_chat 16/32, verify 64/128, actions 64/128, tools 16/32, wait 1000 ms | Admission control per route family: requests above the in-flight limit wait in a FIFO queue of at most `_QUEUE` for at most `_QUEUE_TIMEOUT_MS`, else `503 SERVER_OVERLOADED` + `Retry-After` before any work is done. `QODIQA_ADMISSION_RETRY_AFTER_SEC` (default 1) sets the hint. |
| `QODIQA_OIDC_CONFIG_PATH` | No | unset (federation off) | JSON file of OIDC bearer-token providers for `/sign` and the operator API ([IDENTITY](../guides/IDENTITY.md)) |
| `QODIQA_OIDC_ALLOW_INSECURE` | No | `false` | Permits a plain-http / loopback IdP; ignored in production |
| `QODIQA_SAML_CONFIG_PATH` | No | unset (SAML off) | JSON file of SAML 2.0 providers; mounts `/auth/saml/*`; a bad file stops the start |
| `QODIQA_LDAP_CONFIG_PATH` | No | unset (LDAP off) | JSON file of LDAP / Active Directory providers; mounts `POST /auth/ldap/login`; a bad file stops the start |

¹ At least one valid AI provider is required (every provider credential is checked for
placeholders and format). See [AI Provider Keys](#5-ai-provider-keys).
Every production rule, with exact messages: [`docs/configuration/boot-rules.md`](boot-rules.md).

There is no `QODIQA_SIGN_TOKEN` variable — `POST /sign` authenticates callers via
individually-issued signing identities instead of a shared secret. See "Signing
identities" below.

---

## 1. Server Configuration

### `PORT`

- **Type**: integer
- **Range**: 1–65535
- **Default**: `3000`
- **Description**: TCP port on which the HTTP server listens.
- **Production recommendation**: Run behind a TLS-terminating load balancer; set `PORT`
  to an unprivileged port (>1024).

```
PORT=8080
```

### `NODE_ENV`

- **Type**: string
- **Accepted values**: `production`, `development`, `test`
- **Default**: none — **required**: unset, empty, or any other value
  (`prod`, `Production`, `staging`, …) refuses to boot with `BOOT_VALIDATION_FATAL`.
- **Description**: Selects the boot-validation profile and security-sensitive behaviour:
  - `production`: HSTS header enabled; every production rule in
    [`docs/configuration/boot-rules.md`](boot-rules.md) is enforced and any
    violation refuses to boot.
  - `development` / `test`: HSTS disabled; the same rules report most findings as warnings
    (presence/shape of the KEK, invariant secret, client id and a provider stay fatal).
- **Production requirement**: Must be set to `production`.

```
NODE_ENV=production
```

### `MAX_BODY_BYTES`

- **Type**: integer (bytes)
- **Default**: `65536` (64 KiB)
- **Description**: Maximum request body size accepted by the JSON body parser.
  Requests exceeding this limit are rejected with HTTP 413.

```
MAX_BODY_BYTES=65536
```

---

## 2. Security Tokens

### Signing identities (`POST /sign` authentication)

- **Not an environment variable.** replaced the single shared-secret
  `QODIQA_SIGN_TOKEN` with per-identity signing API keys — there is no shared secret to
  configure here.
- **Console UI copy check:** `public/js/console.js`'s `/sign` acceptance-list copy is
  checked against this description by — it must
  never regress to describing the removed single-shared-token model (a "signing token
  header", an "incorrect signing token", or a `SIGN_NOT_AVAILABLE` response, none of which
  exist in the current implementation).
- **Description**: Every caller of `POST /sign` authenticates with its own
  individually-issued, individually-revocable signing API key:
  `Authorization: Bearer sk_<64 hex chars>`. Credentials are resolved by
  `src/core/signing/signingIdentityStore.js` and enforced by
  `src/middleware/signAuth.js` — a missing or unresolvable credential returns 401
  `UNAUTHORIZED`; a resolvable but disabled/revoked/under-permissioned identity returns
  403 `FORBIDDEN`. There is no header fallback and no shared-secret fallback.
- **Generation**: Keys are always generated server-side with `crypto.randomBytes(32)` and
  stored as a SHA-256 hash — never user-supplied, so weak/placeholder values are
  structurally impossible.
- **Issuance**: `node scripts/provision-signing-identity.js --tenant-id <id> --name <name>
  --environment <env>` (prints the `sk_...` key once) or `POST
  /signing-identities/:id/api-key`. See `docs/guides/quickstart.md`'s "Provision a Signing Identity"
  section for the full walkthrough.

### `QODIQA_OPS_TOKEN`

- **Type**: string
- **Minimum length**: 32 characters (when set)
- **Deprecated**: prefer per-user RBAC API keys
- **Description**: Shared authentication token for the operator API. All requests to
  `/audit`, `/keys`, `/policy-ui`, `/rbac`, `/consent`, `/compliance`, and other operator
  endpoints require this token (or a per-operator RBAC API key, which RBAC-gated routes require).
- **Usage**: `Authorization: Bearer <token>` on all operator API requests.
- **Validation**: This variable is optional — omitting it disables the shared-token auth
  path and leaves per-operator RBAC API keys as the only credential. If it is set,
  startup aborts when the value is empty or whitespace-only, shorter than 32 characters,
  or matches any pattern in the weak-token list (e.g., `test`, `admin`, `changeme`,
  `password`, `123456`, `token`, `your-token`).

```
QODIQA_OPS_TOKEN=<REPLACE_WITH_64_HEX_CHARS: openssl rand -hex 32>
```

### `QODIQA_ADMIN_ENABLED` / `QODIQA_DIAGNOSTICS_ENABLED`

- **Type**: boolean string (`true` | `false`); only the literal `true` enables when set
- **Default**: `false` in production, `true` otherwise
- **Description**: Two independent kill switches.
  `QODIQA_ADMIN_ENABLED` gates every RBAC-gated admin mount (`adminStack()`: `/audit`,
  `/rbac`, `/key-admin`, `/consent`, `/v1/admin/*`, …); `QODIQA_DIAGNOSTICS_ENABLED`
  gates `/metrics`, `/diagnostics`, `/diagnostics/profile` (`opsOnlyStack()`). A disabled
  plane answers 404 after authentication. the diagnostics switch gated both — see
.
- **Production requirement**: enabling either plane requires `QODIQA_OPS_TOKEN`.
- **Note**: the previously documented `QODIQA_OPS_ENABLED` is not read by any code.

### `QODIQA_HEALTH_PROBE_AUTH_REQUIRED`

- **Type**: boolean string
- **Accepted values**: `true`, `false`
- **Default**: `false`
- **Description**: `/health` and `/ready` are unauthenticated by default — required for
  Kubernetes `httpGet` probes and Docker `HEALTHCHECK` to function, since neither can
  supply the `QODIQA_OPS_TOKEN` bearer credential used by `/metrics` and `/diagnostics`.
  Setting this to `true` requires the exact same credential (`Authorization: Bearer` or
  `X-Ops-Token`) on `/health` and `/ready` as well. If you enable this, you must also
  configure your orchestrator's probe to send the credential (Kubernetes:
  `httpGet.httpHeaders`; see `docs/deployment/kubernetes-probes.md`) — otherwise probes will fail
  with 401 and the deployment will not become healthy.
- **Safety note**: this is defense-in-depth, not a requirement for safety — `/health` and
  `/ready` are contractually restricted to minimal, non-sensitive output regardless of
  this setting (enforced by a regression test; see `docs/deployment/kubernetes-probes.md`).

```
QODIQA_HEALTH_PROBE_AUTH_REQUIRED=false
```

### `QODIQA_HEALTH_REQUIRE_LOOPBACK`

- **Type**: boolean string
- **Accepted values**: `true`, `false`
- **Default**: `false`
- **Description**: When `true`, `/health` and `/ready` additionally reject any request
  whose TCP socket address is not loopback (`127.0.0.0/8` or `::1`). This check reads the
  raw socket address — it cannot be bypassed via `X-Forwarded-For` or `X-Real-IP`.
  **Do not enable this for Kubernetes deployments** — kubelet connects to the Pod IP over
  the pod network, never via loopback, so enabling this would reproduce the exact
  deploy-breaking failure this setting exists to avoid. It is intended for Docker Compose
  or bare-metal deployments, where Docker's `HEALTHCHECK` always executes inside the
  container (i.e. always over loopback).

```
QODIQA_HEALTH_REQUIRE_LOOPBACK=false
```

### `QODIQA_HEALTH_RATE_LIMIT_MAX` / `QODIQA_HEALTH_RATE_LIMIT_WINDOW_MS`

- **Type**: integer (string)
- **Default**: `240` requests per `60000` ms (per client IP), respectively
- **Description**: Sliding-window rate limit applied to `/health` and `/ready`, independent
  of authentication settings. Defense-in-depth against using these endpoints as a probing
  or amplification vector; the default is generous enough for any normal orchestrator
  polling interval (a single prober hitting every 5s is ~12 requests/minute).

```
QODIQA_HEALTH_RATE_LIMIT_MAX=240
QODIQA_HEALTH_RATE_LIMIT_WINDOW_MS=60000
```

### `QODIQA_OPS_RATE_LIMIT_MAX` / `QODIQA_OPS_RATE_LIMIT_WINDOW_MS`

- **Type**: integer (string)
- **Default**: `120` requests per `60000` ms (per client IP), respectively
- **Description**: Sliding-window rate limit applied to every Admin/Ops route (`/audit`,
  `/rbac`, `/key-admin`, `/consent`, `/v1/webhooks`, etc. — see `docs/security/SECURITY_GUIDE.md`
  §10) via `src/middleware/adminProtection.js`. Runs before IP allowlisting, ops
  authentication, and RBAC, so it throttles brute-force/credential-stuffing attempts
  against ops credentials without requiring a valid credential first. Separate from
  `QODIQA_HEALTH_RATE_LIMIT_MAX`, which applies only to `/health` and `/ready`.

```
QODIQA_OPS_RATE_LIMIT_MAX=120
QODIQA_OPS_RATE_LIMIT_WINDOW_MS=60000
```

---

## 3. Key Management

### `QODIQA_KEY_ENCRYPTION_KEY`

- **Type**: hexadecimal string
- **Format**: exactly 64 hexadecimal characters (32 bytes)
- **Required**: Yes (unless a KMS provider supplies the KEK at startup)
- **Description**: The Key Encryption Key (KEK) used to encrypt Ed25519 private keys at
  rest with AES-256-GCM. This is the most security-critical secret in the system.
- **Validation**: Startup aborts if:
  - Absent or not exactly 64 hex characters.
  - All bytes are zero.
  - All nibbles are identical.
  - The value is a repeating 2-character byte pattern.
  - The value matches common placeholder patterns.
- **Security**: Never log this value. Never include it in artifacts, responses, or metrics.
  Use a KMS-backed KEK in production (`QODIQA_KMS_PROVIDER` != `local`).

```
QODIQA_KEY_ENCRYPTION_KEY=<REPLACE_WITH_64_HEX_CHARS: openssl rand -hex 32>
```

### `QODIQA_EXECUTION_INVARIANT_SECRET`

- **Type**: hexadecimal string
- **Format**: exactly 64 hexadecimal characters (32 bytes)
- **Required**: Yes, in practice — no startup FATAL check gates this one, so the server
  boots without it, but `POST /ai/chat`'s EXECUTE path fails the first time it's reached.
- **Description**: HMAC-SHA256 key used to cryptographically bind the execution
  invariant context (`verifiedCtx`) minted by the `/ai/chat` enforcement pipeline before
  the provider-dispatch step calls the AI provider. `services/execution-guard.js` checks
  this binding on the way back, rejecting a forged-but-correctly-shaped `verifiedCtx`.
  Read via `getExecutionInvariantSecret()` in `services/secrets/secretsProvider.js`.
- **Validation**: `src/infra/secrets/secretValidation.js`'s `_checkExecutionInvariantSecret`
  checks (WARN in development, FATAL in production) for:
  - All bytes zero, or all nibbles identical.
  - A repeating 2-character byte pattern.
  - An identical value to `QODIQA_KEY_ENCRYPTION_KEY` — the two secrets protect
    different security boundaries (key-at-rest encryption vs. execution-invariant
    binding) and must be independent, so a leak/rotation of one is not a leak/rotation
    of the other.
- **Production recommendation**: Generate with `openssl rand -hex 32`; inject via your
  secret manager, same as `QODIQA_KEY_ENCRYPTION_KEY`.

```
QODIQA_EXECUTION_INVARIANT_SECRET=<REPLACE_WITH_64_HEX_CHARS: openssl rand -hex 32>
```

### `QODIQA_CLIENT_ID`

- **Type**: string
- **Required**: Yes
- **Description**: The default tenant/client identifier. Used as the prefix of all signing
  key IDs (`<clientId>:key_v<N>`). Also used as the default `tenantId` when no tenant is
  specified.
- **Validation**: Must not match weak ID patterns (`test`, `demo`, `example`, `placeholder`).

```
QODIQA_CLIENT_ID=acme-corp
```

### `QODIQA_KEYS_PATH`

- **Type**: file path
- **Default**: `./data/keys.json` relative to the project root
- **Description**: Path to the encrypted key store file. In production, this file must be
  outside the project root (e.g., `/etc/qodiqa/keys.json`) and accessible only by the
  QODIQA process user.
- **Validation**: In production (`NODE_ENV=production`), startup aborts if this path is
  inside the project root directory.

```
QODIQA_KEYS_PATH=/etc/qodiqa/keys.json
```

### `QODIQA_KMS_PROVIDER`

- **Type**: string
- **Accepted values**: `local`, `vault-kv`, `aws-kms`, `azure-kv`, `gcp-kms`,
  `vault-transit`, `hsm`
- **Default**: `local`
- **Description**: Selects the KMS backend for KEK management. In `local` mode, the KEK
  is read directly from `QODIQA_KEY_ENCRYPTION_KEY`. In all other modes, the KMS supplies
  the KEK at startup and `QODIQA_KEY_ENCRYPTION_KEY` is not required.
- **Warning**: In production, a warning is emitted if this is `local`, recommending a
  KMS-backed provider.
- **Validation**: Backend selection and its parameters are validated centrally in
  `src/infra/keys/kmsConfig.js` — a missing or invalid required field FATALs at startup
  naming the exact field (e.g. `AWS_KMS_KEY_ID is not set.`), before the provider itself
  is constructed. Every field below is real, source-verified (`src/infra/keys/providers/*.js`)
  — this table previously listed variable names that did not match any provider's actual
  code (fixed as part of items 21/22;
- **SDK availability**: each cloud/Vault/HSM backend's SDK is an `optionalDependency` in
  `package.json` (not installed by default). Selecting a backend whose SDK is not
  installed FATALs at startup naming the backend, the missing package, and the exact
  `npm install` command — see `src/infra/keys/sdkAvailability.js`.
- **Which entrypoint honors this variable**: both `npm start` (`node server.js`) and
  `node start.js` initialize the selected KMS provider — this was not always true, see
  the note under "Entrypoints" below.
- **Implementation**: `src/infra/keys/keyProviderFactory.js`

```
QODIQA_KMS_PROVIDER=aws-kms
```

#### KMS-specific variables (required unless noted optional; source: provider file)

| Provider | Required variables | Optional variables (defaults shown) |
|----------|---------------------|--------------------------------------|
| `local` | *(none)* | — |
| `vault-kv` | `VAULT_ROLE_ID`+`VAULT_SECRET_ID` **or** `VAULT_TOKEN` | `VAULT_ADDR` (`http://127.0.0.1:8200`), `VAULT_NAMESPACE`, `VAULT_KEK_PATH` (`qodiqa/kek`), `VAULT_KEK_MOUNT` (`secret`), `VAULT_TLS_CA_CERT` |
| `vault-transit` | `VAULT_ROLE_ID`+`VAULT_SECRET_ID` **or** `VAULT_TOKEN` | `VAULT_ADDR`, `VAULT_NAMESPACE`, `VAULT_TRANSIT_MOUNT` (`transit`), `VAULT_TLS_CA_CERT` |
| `aws-kms` | `AWS_KMS_KEY_ID`, `AWS_KMS_REGION` | `AWS_KMS_EDK_PATH` (`data/kek.edk`); AWS credentials via the standard SDK chain (env, `~/.aws`, IMDS, ECS task role) |
| `azure-kv` | `AZURE_KEY_VAULT_URI`, `AZURE_KEY_VAULT_KEY_NAME` | `AZURE_KEY_VAULT_KEY_VER` (latest), `AZURE_WRAPPED_KEY_PATH` (`data/kek.wk`); Azure credentials via `DefaultAzureCredential` |
| `gcp-kms` | `GCP_KMS_PROJECT`, `GCP_KMS_KEYRING`, `GCP_KMS_KEY` | `GCP_KMS_LOCATION` (`global`), `GCP_KMS_KEY_VERSION` (`1`), `GCP_KMS_KEY_TYPE` (`symmetric`, or `asymmetric`), `GCP_WRAPPED_KEY_PATH` (`data/kek.gcp`); GCP credentials via GOOGLE_APPLICATION_CREDENTIALS |
| `hsm` | `HSM_PKCS11_LIB`, and `HSM_PKCS11_PIN` **or** `HSM_PKCS11_PIN_FILE` | `HSM_PKCS11_SLOT` (`0`), `HSM_KEY_INDEX_PATH` (`data/hsm-keys.json`) |

SDK required per provider (`npm install <package>` if the FATAL names it as missing):
`vault-kv`/`vault-transit` → `node-vault`; `aws-kms` → `@aws-sdk/client-kms`; `azure-kv` →
`@azure/keyvault-keys` **and** `@azure/identity`; `gcp-kms` → `@google-cloud/kms`; `hsm` →
`pkcs11js`.

### `QODIQA_CONFIG_SECRETS_PROVIDER`

- **Type**: string
- **Accepted values**: `env`, `vault-kv`
- **Default**: `env`
- **Description**: Selects the backend for *application-config* secrets — Redis/
  PostgreSQL passwords, AI provider API keys, `QODIQA_OPS_TOKEN`, alerting/log-shipping
  credentials, and `QODIQA_DSR_PSEUDONYM_PEPPER`. This is INDEPENDENT of
  `QODIQA_KMS_PROVIDER` above, which only covers the KEK. In `env` mode (default),
  behavior is unchanged from before these variables are read from `.env`/the
  process environment exactly as always. In `vault-kv` mode, every managed variable is
  fetched from Vault at startup and any value still present in `.env` for a managed name
  the fetch does NOT return is deleted from `process.env` — never used as a fallback.
- **Fail-closed**: if the provider cannot be reached, authenticated, or returns a
  malformed response, startup FATALs and exits — there is no path back to using a
  plaintext value already in the environment.
- **Which entrypoint honors this variable**: both `npm start` (`node server.js`) and
  `node start.js` bootstrap the selected config-secrets provider — before either requires
  `server/startup.js`, because several managed names are captured at module-load time by
  `services/providers/config.js` and `src/alerting/notification/channels/*.js`.
- **Implementation**: `src/infra/configSecrets/configSecretsFactory.js`
- **Full inventory**:; see also `docs/security/secrets-management.md`'s
  "Application-config secrets provider" section.

```
QODIQA_CONFIG_SECRETS_PROVIDER=vault-kv
QODIQA_CONFIG_SECRETS_VAULT_MOUNT=secret
QODIQA_CONFIG_SECRETS_VAULT_PATH=qodiqa/app-config
```

| Provider | Required variables | Optional variables (defaults shown) |
|----------|---------------------|--------------------------------------|
| `env` | *(none)* | — |
| `vault-kv` | `VAULT_ROLE_ID`+`VAULT_SECRET_ID` **or** `VAULT_TOKEN` (shared with the KMS `vault-kv`/`vault-transit` provider above — same Vault deployment, a different KV v2 path) | `VAULT_ADDR` (`http://127.0.0.1:8200`), `VAULT_NAMESPACE`, `VAULT_TLS_CA_CERT`, `QODIQA_CONFIG_SECRETS_VAULT_MOUNT` (`secret`), `QODIQA_CONFIG_SECRETS_VAULT_PATH` (`qodiqa/app-config`) |

### Automatic Key Rotation

Controls the background scheduler (`services/artifact/rotationScheduler.js`) that
rotates each client's Ed25519 signing key on a configurable cadence. See
`docs/security/key-management.md` — "Automatic rotation scheduler" for the full lifecycle,
cluster-safety, and KMS-compatibility model.

| Variable | Required | Default | Description |
|---|---|---|---|
| `QODIQA_KEY_ROTATION_ENABLED` | No | `true` | Master on/off switch. `false` disables the scheduler entirely; manual rotation remains available. |
| `QODIQA_KEY_ROTATION_SCHEDULE` | No | `monthly` | Preset rotation cadence: `daily`, `weekly`, `monthly`, or `disabled`. |
| `QODIQA_KEY_ROTATION_INTERVAL_MS` | No | — | Explicit rotation interval override, in milliseconds. Takes precedence over `_SCHEDULE`. |
| `QODIQA_KEY_ROTATION_INTERVAL_DAYS` | No | — | Explicit rotation interval override, in days. Takes precedence over `_SCHEDULE` but not over `_INTERVAL_MS`. |
| `QODIQA_KEY_ROTATION_CHECK_INTERVAL_MS` | No | `3600000` (1h) | How often the scheduler scans all known clients for due rotations. |
| `QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS` | No | `300000` (5m) | How often each instance reloads `keys.json` from disk to pick up rotations performed by other instances sharing the same key store. |
| `QODIQA_KEY_ROTATION_LOCK_TTL_MS` | No | `30000` | TTL of the Redis-backed distributed rotation lock (`SET NX PX`), one key per clientId. Must exceed the worst-case rotation duration. |
| `QODIQA_KEY_ROTATION_MAX_RETRIES` | No | `3` | Maximum retry attempts for a failed rotation within a single scheduler cycle. |
| `QODIQA_KEY_ROTATION_RETRY_DELAY_MS` | No | `5000` | Delay between retry attempts. |
| `QODIQA_KEY_ROTATION_CLIENT_IDS` | No | all known clients | Optional comma-separated allowlist restricting which clients the scheduler manages. |

An unrecognized `QODIQA_KEY_ROTATION_SCHEDULE` value falls back to `monthly` with a `KEY_ROTATION_SCHEDULE_INVALID` warning — it does not abort startup.

```
QODIQA_KEY_ROTATION_SCHEDULE=weekly
QODIQA_KEY_ROTATION_LOCK_TTL_MS=60000
```

Requires Redis (already a hard runtime dependency) for the distributed rotation lock; no additional infrastructure is needed.

---

## 4. Redis Configuration

QODIQA maintains several independent Redis connections (at least 15 managed clients). If separate URLs are not
specified, all stores use `REDIS_URL`. (The Persistence Recovery Queue is not
in this list — its durable store is PostgreSQL, not Redis, ;.)

### `REDIS_URL`

- **Type**: URL string
- **Accepted schemes**: `redis://` (plaintext), `rediss://` (TLS)
- **Default**: `redis://localhost:6379`
- **Description**: Default Redis connection URL used by all stores that do not have an
  explicit URL override.
- **Validation**: Must be a valid URL with `redis://` or `rediss://` scheme.

```
REDIS_URL=rediss://redis.internal:6380
```

### Per-store URL overrides

| Variable | Store | Purpose |
|----------|-------|---------|
| `QODIQA_REDIS_NONCE_URL` | Nonce store | Replay protection |
| `QODIQA_REDIS_ANOMALY_URL` | Anomaly store | Burst detection |
| `QODIQA_REDIS_RATE_URL` | Rate limit store | Policy rate limits |
| `QODIQA_REDIS_CONSENT_URL` | Consent cache | Consent revocation |

All override variables follow the same format as `REDIS_URL`.

### Redis TLS Variables

| Variable | Type | Description |
|----------|------|-------------|
| `REDIS_TLS` | boolean | Force TLS on all Redis connections regardless of URL scheme. |
| `REDIS_TLS_CA` | file path | Path to CA certificate PEM file for mTLS verification. |
| `REDIS_TLS_CERT` | file path | Path to client certificate PEM file. Required together with `REDIS_TLS_KEY`. |
| `REDIS_TLS_KEY` | file path | Path to client private key PEM file. Required together with `REDIS_TLS_CERT`. |
| `REDIS_TLS_REJECT_UNAUTHORIZED` | boolean | Set `false` to disable certificate verification. **Never use in production.** Warns in development, fatal error in production. |

```
REDIS_TLS=true
REDIS_TLS_CA=/etc/ssl/certs/redis-ca.pem
REDIS_TLS_CERT=/etc/ssl/certs/qodiqa-redis-client.pem
REDIS_TLS_KEY=/etc/ssl/private/qodiqa-redis-client-key.pem
```

### `STRICT_REPLAY_PROTECTION`

- **Type**: boolean string
- **Accepted values**: `true`, `false`
- **Default**: `true`
- **Description**: When `true`, QODIQA checks Redis AOF persistence configuration at
  startup. If AOF is not enabled with `appendfsync=everysec` or `appendfsync=always`,
  startup is aborted. This prevents a scenario where a Redis restart after a crash loses
  nonces, creating a window for replay attacks.
- **Production requirement**: Must be `true`.

```
STRICT_REPLAY_PROTECTION=true
```

### Redis Connection Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_CONNECT_TIMEOUT_MS` | `5000` | Maximum time to establish a Redis connection (1–60,000 ms). |
| `REDIS_COMMAND_TIMEOUT_MS` | `3000` | Maximum time for a Redis command to complete. |

---

## 5. AI Provider Keys

At least one AI provider must be enabled for QODIQA to start (checked by `hasAnyProvider()`
in `services/providers/config.js`; enforced at startup in `server.js` — see
[`FATAL NO_PROVIDER_CONFIGURED`](../operations/troubleshooting.md)). A provider
becomes enabled automatically the moment its **enabling variable** is present — there is no
separate on/off flag. Full behavior, execution flow, and SSRF policy for each provider are
documented in [Provider architecture](../../README.md) and
`services/providers/config.js`.

| Provider | Enabling variable | Optional variables |
|----------|--------------------|---------------------|
| `openai` | `OPENAI_API_KEY` | `OPENAI_TIMEOUT_MS` |
| `anthropic` | `ANTHROPIC_API_KEY` | `ANTHROPIC_TIMEOUT_MS`, `ANTHROPIC_MAX_TOKENS` |
| `gemini` | `GEMINI_API_KEY` | `GEMINI_TIMEOUT_MS` |
| `mistral` | `MISTRAL_API_KEY` | `MISTRAL_BASE_URL`, `MISTRAL_TIMEOUT_MS` |
| `llama` | `LLAMA_BASE_URL` | `LLAMA_API_KEY`, `LLAMA_TIMEOUT_MS` |
| `local` | `LOCAL_BASE_URL` | `LOCAL_API_KEY`, `LOCAL_TIMEOUT_MS` |
| `azure` | `AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_API_KEY` (or `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` for Microsoft Entra) | `AZURE_OPENAI_API_VERSION`, `AZURE_OPENAI_AUTH` (`api-key`\|`entra`), `AZURE_OPENAI_TIMEOUT_MS`, `AZURE_OPENAI_MAX_TOKENS`, `AZURE_OPENAI_DEPLOYMENTS` (restrictive deployment allowlist), `PROVIDER_DEFAULT_MODEL_AZURE`, `PROVIDER_FAILOVER_AZURE` |
| `bedrock` | `BEDROCK_REGION` + `BEDROCK_ACCESS_KEY_ID` + `BEDROCK_SECRET_ACCESS_KEY` | `BEDROCK_SESSION_TOKEN`, `BEDROCK_TIMEOUT_MS`, `BEDROCK_MAX_TOKENS`, `BEDROCK_ALLOWED_MODELS` (restrictive allowlist), `PROVIDER_DEFAULT_MODEL_BEDROCK`, `PROVIDER_FAILOVER_BEDROCK` |
| `compat-<id>` | registered at runtime through `/v1/admin/providers` | the API key is read from the environment variable the entry names (`COMPAT_KEY_*`); `QODIQA_COMPAT_ALLOW_LOCAL=true` (never in production) permits plain-http / loopback endpoints in development |

`llama` and `local` are enabled by their **base URL**, not an API key — the key is optional
because most self-hosted/cloud-hosted OpenAI-compatible endpoints for these two providers do
not require authentication. All other providers are enabled by their API key alone; their
base URL is hardcoded (not configurable) as part of SSRF protection (see
[Provider base URLs are not configurable](#provider-base-urls-are-not-configurable) below).

### `OPENAI_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Range**: any positive integer (non-positive or non-numeric values fall back to the default)
- **Default**: `30000`
- **Description**: Per-request timeout for OpenAI API calls. Does not affect the overall
  `AI_CHAT_TIMEOUT_MS` race.

### `ANTHROPIC_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Default**: `30000`
- **Description**: Per-request timeout for Anthropic Messages API calls.

### `ANTHROPIC_MAX_TOKENS`

- **Type**: integer
- **Default**: `4096`
- **Description**: `max_tokens` sent on every Anthropic Messages API request (Anthropic requires this field; the other providers do not have an equivalent config-level default).

### `GEMINI_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Default**: `30000`
- **Description**: Per-request timeout for Gemini `generateContent` calls.

### `MISTRAL_BASE_URL`

- **Type**: URL string
- **Default**: `https://api.mistral.ai/v1`
- **Description**: Overrides the Mistral API base URL. If set, the URL is validated against
  the same SSRF policy as the hardcoded provider URLs (`services/providers/ssrf.js`,
  `validateProviderUrl`) at module load time — an invalid or non-allowlisted, non-HTTPS, or
  private-network URL throws `PROVIDER_CONFIG_INVALID` and prevents the module from loading.

### `MISTRAL_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Default**: `30000`
- **Description**: Per-request timeout for Mistral API calls.

### `LLAMA_BASE_URL`

- **Type**: URL string
- **Required**: to enable the `llama` provider
- **Description**: Base URL for a Llama deployment exposing an OpenAI-compatible chat
  completions API (cloud-hosted, e.g. Groq/Together AI/Fireworks, or self-managed
  llama.cpp/vLLM). Validated at first client construction: tried first against the strict
  public-provider validator, then against the relaxed local validator (which permits
  private-network and `http://` destinations) — see `services/providers/ssrf.js`. An invalid
  URL throws `PROVIDER_CONFIG_INVALID` when the provider is first called.

### `LLAMA_API_KEY`

- **Type**: string
- **Default**: none (falls back to the literal string `'llama'` if unset, since the `openai`
  SDK client requires a non-empty `apiKey` even when the deployment enforces no
  authentication)
- **Description**: Optional bearer key for Llama deployments that require authentication.

### `LLAMA_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Default**: `30000`

### `LOCAL_BASE_URL`

- **Type**: URL string
- **Required**: to enable the `local` provider
- **Description**: Base URL for a self-hosted OpenAI-compatible runtime (Ollama, llama.cpp
  server, LM Studio, Jan.ai, etc.). Validated with the relaxed local validator
  (`validateLocalProviderUrl`), which allows `http://` and private-network/localhost
  destinations — an intentional policy exception for operator-configured, operator-accountable
  self-hosted endpoints. An invalid URL (unparseable, or a non-`http`/`https` scheme) throws
  `PROVIDER_CONFIG_INVALID`.

### `LOCAL_API_KEY`

- **Type**: string
- **Default**: none (falls back to the literal string `'local'` if unset, for the same reason as `LLAMA_API_KEY`)

### `LOCAL_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Default**: `30000`

### Provider failover

`PROVIDER_FAILOVER_<PROVIDER_NAME>` — one variable per provider, all optional. If the primary
provider named in the artifact fails with a retryable error (`PROVIDER_UNAVAILABLE`,
`PROVIDER_RATE_LIMITED`, `PROVIDER_TIMEOUT`), the router (`services/providers/router.js`)
attempts exactly one failover hop to the provider named here. The failover target must itself
be an enabled provider name; failover chains longer than one hop are not attempted.

| Variable | Effect |
|---|---|
| `PROVIDER_FAILOVER_OPENAI` | Failover target if `openai` fails |
| `PROVIDER_FAILOVER_ANTHROPIC` | Failover target if `anthropic` fails |
| `PROVIDER_FAILOVER_GEMINI` | Failover target if `gemini` fails |
| `PROVIDER_FAILOVER_MISTRAL` | Failover target if `mistral` fails |
| `PROVIDER_FAILOVER_LLAMA` | Failover target if `llama` fails |
| `PROVIDER_FAILOVER_LOCAL` | Failover target if `local` fails |

Example: `PROVIDER_FAILOVER_OPENAI=anthropic` — if `openai` fails with a retryable error, the
router retries the same request against `anthropic` — only after identity, provider scope and consent
re-pass for the target. The executing provider is recorded in the audit entry's unhashed
`executionContext`; the hash-protected `provider` field is the requested one (v7, design decision D4).

### Provider base URLs are not configurable

For `openai`, `anthropic`, and `gemini`, the base URL is hardcoded in the adapter
(`services/providers/openai.js`, `anthropic.js`, `gemini.js`) and validated against the SSRF
allowlist at module load time — there is no environment variable to override it. Setting
`OPENAI_BASE_URL` has no effect on outbound requests; the SDK client reads it, but the adapter
overrides `baseURL` with the hardcoded value, and emits `PROVIDER_BASE_URL_OVERRIDE_IGNORED`
at WARN level if the variable is set. `mistral` is the one exception among the public
providers — its base URL **is** configurable via `MISTRAL_BASE_URL`, still subject to SSRF
validation. `llama` and `local` are entirely operator-configured via `LLAMA_BASE_URL` /
`LOCAL_BASE_URL` since they have no fixed public endpoint.

---

## 6. PostgreSQL Configuration

### `QODIQA_DEPLOYMENT_MODE`

- **Type**: string
- **Accepted values**: `single-node`, `distributed`
- **Default**: unset — falls through to the legacy `QODIQA_PG_ENABLED` /
  `QODIQA_AUDIT_ORDERING_MODE` variables below, exactly as every release
  before this variable existed.
- **Description**: The single authoritative deployment-topology switch,
  resolved by `src/infra/config/deploymentMode.js`. `distributed` resolves
  PostgreSQL enabled, distributed audit-chain ordering, migration 026
  verification (auto-applied if `QODIQA_PG_AUTO_MIGRATE=true` and missing),
  and multi-instance safety — with no other variable required. `single-node`
  forces single-node ordering while still honoring `QODIQA_PG_ENABLED` for
  the optional PostgreSQL dual-write mirror. Takes precedence over the
  legacy variables below whenever both are set; an unrecognized value fails
  startup rather than silently falling back. See
  docs/protocol/AUDIT-SCHEMA-V8.md's
  "Decision Update" section for the full design.
- **Production recommendation**: `single-node` (or unset). `distributed` is
  **fatal with `NODE_ENV=production`** until (`bootValidator.js`,
); `deploy/docker/docker-compose.prod.yml` sets `single-node`, and
  only the non-production `overlays/distributed/` sets `distributed`.

```
QODIQA_DEPLOYMENT_MODE=single-node
```

Related variables consumed only when `QODIQA_DEPLOYMENT_MODE=distributed`:

- `QODIQA_PG_AUTO_MIGRATE` (`true`/`false`, default `false`) — automatically
  applies pending migrations (including migration 026) at startup if missing,
  rather than failing closed with a remediation diagnostic. Recommended for
  single-instance topologies; avoid on a multi-replica overlay where
  concurrent pods would race to migrate.
- `QODIQA_REPLICA_COUNT` (integer, default `1`) — operator-declared replica
  count, used by the illegal-topology startup assertion (PostgreSQL enabled +
  ordering not distributed + more than one replica). Kubernetes gives a pod
  no built-in way to learn its own replica count; see
  `QODIQA_K8S_SINGLE_REPLICA` below for the identical, pre-existing gap.

### `QODIQA_PG_ENABLED` (legacy — superseded by `QODIQA_DEPLOYMENT_MODE` above)

- **Type**: boolean string
- **Accepted values**: `true`, `false`
- **Default**: `false`
- **Description**: When `true`, initializes the PostgreSQL connection pool
  (`src/infra/postgres/pool.js`). This is required for the **Runtime Consent Registry**
  (`src/core/consent/`) to function — the default `policies.json` ships
  with `POL-001: REQUIRE_CONSENT` enabled, and `ConsentVerifier` fails closed with
  `CONSENT_STORE_UNAVAILABLE` on every consent-gated request whenever this flag is
  not `true`. This is by design (fail-closed), not a bug — but it means
  `QODIQA_PG_ENABLED` is a **de facto required** variable for any deployment that
  keeps the default policy set. See docs/guides/quickstart.md's "Provision Consent
  (PostgreSQL)" section and [docs/operations/troubleshooting.md](../operations/troubleshooting.md).
  When `true`, this same flag also enables PostgreSQL dual-write for the audit
  chain (all entries written to both the NDJSON file and the `audit_chain` table),
  plus the transparency log, evidence chain, compliance, certification, and
  attestation subsystems. When `false`, only the file-based audit chain is active
  and consent enforcement is permanently blocked.
- **Production recommendation**: Set to `true`.

```
QODIQA_PG_ENABLED=true
```

### PostgreSQL connection variables

- **Type**: see below
- **Required when**: `QODIQA_PG_ENABLED=true`
- **Description**: Read directly by `src/infra/postgres/pool.js`. Either set
  `QODIQA_PG_URL` alone, or set the `QODIQA_PG_HOST`/`PORT`/`DATABASE`/`USER`/`PASSWORD`
  group — `QODIQA_PG_URL` takes precedence if both are set. There is no
  `DATABASE_URL` variable read anywhere in the enforcement pipeline; scripts under
  `scripts/dr/` use `DATABASE_URL` for disaster-recovery tooling only, which is a
  separate, unrelated connection.

| Variable | Default | Description |
|---|---|---|
| `QODIQA_PG_URL` | *(none)* | Full connection URL, e.g. `postgresql://user:pass@host:5432/db?sslmode=require` |
| `QODIQA_PG_HOST` | `localhost` | Hostname (used only if `QODIQA_PG_URL` is unset) |
| `QODIQA_PG_PORT` | `5432` | Port |
| `QODIQA_PG_DATABASE` | `qodiqa` | Database name |
| `QODIQA_PG_USER` | `qodiqa_app` | Username |
| `QODIQA_PG_PASSWORD` | *(none)* | Password |
| `QODIQA_PG_SSL` | `true` in production, `false` otherwise | `true` to require TLS |
| `QODIQA_PG_SSL_CA` / `_CERT` / `_KEY` | *(none)* | mTLS certificate paths |

```
QODIQA_PG_HOST=pg.internal
QODIQA_PG_PORT=5432
QODIQA_PG_DATABASE=qodiqa
QODIQA_PG_USER=qodiqa_app
QODIQA_PG_PASSWORD=secret
QODIQA_PG_SSL=true
```

### Migration runner connection variables (`QODIQA_PG_MIG_USER` / `QODIQA_PG_MIG_PASSWORD`)

- **Type**: string
- **Required when**: `QODIQA_PG_ENABLED=true` and you run `src/infra/postgres/migrate.js` against a database with a dedicated migration role provisioned
- **Description**: Read directly by `src/infra/postgres/migrate.js`, deliberately
  separate from `QODIQA_PG_USER`/`QODIQA_PG_PASSWORD` above (which `pool.js`
  uses for the request-serving connection). `qodiqa_mig` (migration 002) holds
  schema-modifying DDL rights that `qodiqa_app` does not — running migrations
  under a distinct identity keeps the request-serving pool's credential from
  ever needing DDL privileges.
- **: never part of the gateway's environment.** The running service does not read either
  variable; give them only to the separate, one-shot migration job / operator shell. A production gateway boot
  refuses `QODIQA_PG_MIG_PASSWORD` (`secret.pg_migration_credential_absent`; other profiles warn), and the shipped
  compose service and Kubernetes pods no longer receive it. Migration 079 (role-creating, like 002/018/038/060/065/067)
  also needs the CREATEROLE bootstrap identity or a superuser.

| Variable | Default | Description |
|---|---|---|
| `QODIQA_PG_MIG_USER` | `qodiqa_mig` | Migration-runner username |
| `QODIQA_PG_MIG_PASSWORD` | falls back to `QODIQA_PG_PASSWORD` | Migration-runner password |
| `QODIQA_PG_MIG_LOCK_TIMEOUT_MS` | `30000` | ER 2026-10-06. Operator CLI only (`node src/infra/postgres/migrate.js`): `lock_timeout` for each migration, set after the run has taken the migration advisory lock (the same key as the server's auto-migrate, so the two never apply DDL concurrently). A blocked migration fails cleanly and the next run resumes from it. `0` disables; must be a non-negative integer |

**Role-management migrations need a CREATEROLE identity.** Migrations 002, 018, 038, 060, 065 and 067 create or
alter roles; `qodiqa_mig` cannot run them. A run that includes any of them, including upgrading LIVE from 057 to the
chain end on disk (108; 078 when this was written), uses `QODIQA_PG_MIG_USER=qodiqa_test` (or the deployment's bootstrap identity). `qodiqa_mig`
is enough only when no role migration is pending (rehearsal: as `qodiqa_mig` the run fails at 060 with 42501;
).

**Other variables:**
- `QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE` (default unset): `scripts/pg-backup.sh restore` refuses to run as a superuser, because `pg_restore --no-owner` makes the restoring role own every SECURITY DEFINER function. `true` overrides it for a throwaway target only (CI's service container), and is logged as a WARN.
- `QODIQA_BACKUP_MAX_AGE_SECONDS`: `scripts/pg-backup.sh verify` fails closed (alert, `qodiqa_pg_backup_success{mode="verify"} 0`) when the newest backup is older. `0` disables the check — use `QODIQA_BACKUP_MAX_AGE_SECONDS=0` when verifying a backup fetched from off-site storage for a restore.
- `QODIQA_WITNESS_EXEC_ENV_PASS` (default unset): comma-separated names of extra environment variables an `exec` witness command may receive. By default it gets only OS essentials and `WITNESS_*` / `QODIQA_WITNESS_*` (docs/security/audit-anchoring.md).
- `QODIQA_WITNESS_EXEC_RETRIES` (default `1`, an integer `0`..`3`; anything else is fatal at boot — the production anchoring posture check fails with `AUDIT_ANCHOR_BOOT_FAILED`, and outside production the checkpoint tick fails; `src/core/audit/anchoring/witness.js` `witnessesFromEnv`, phase 7): retries of a transient exec-witness failure (timeout, crash, non-zero exit other than 3/64). Never for refusals (exit 3), bad requests (exit 64) or malformed replies.
- `QODIQA_ANCHOR_EXPORT_TORN_TAIL`: what the customer-held anchor export (`QODIQA_ANCHOR_EXPORT_PATH`) does when its last line is torn (a non-empty file not ending in a newline, after a short write or a crash mid-append). `refuse`: nothing is appended, the publish fails with `AUDIT_ANCHOR_EXPORT_TORN` and is reported as an export failure (alert `QodiqaAnchorExportFailed`); the operator decides. `repair`: the bytes after the last newline are first copied to `<file>.torn-<timestamp>`, then the file is truncated to the last newline and the record is appended (fsync'd). Rewriting customer-held storage is an operator decision, so `repair` is opt-in (`src/core/audit/anchoring/anchors.js`, `src/core/audit/jsonlAppend.js`).
- `QODIQA_AUDIT_MIRROR_MAX_DEPTH`: bound on the in-memory PostgreSQL audit-mirror backlog. At the bound, admission refuses new `/sign` and `/ai/chat` requests (503 `SERVER_OVERLOADED`, cause `audit_backlog`) and `GET /ready` reports `auditBacklog: false`, until the backlog drains to half (docs/operations/metrics-and-alerting.md §11.7).
- `QODIQA_AUDIT_MIRROR_BATCH`: maximum number of queued audit entries the single-node PostgreSQL audit-mirror writer (`src/core/audit/audit-log.js`) writes in one batch — one guard query, one mirror transaction and one evidence transaction per same-tenant run, FIFO, with an automatic per-entry fallback if a batch fails. `1` restores the previous strictly per-entry writer. Batches only form when entries accumulate while a write is in flight, so at low load a batch is one entry and latency is unchanged. Measured on a disposable PostgreSQL 17 (3,000 entries, 50 concurrent): about 141 mirrored entries/s at `1` and about 409/s at `64`. It does not change the backlog bound (`QODIQA_AUDIT_MIRROR_MAX_DEPTH`) or the authoritative file chain.

```
QODIQA_PG_MIG_USER=qodiqa_mig
QODIQA_PG_MIG_PASSWORD=secret
```

### `QODIQA_PG_POOL_MAX`

- **Type**: integer
- **Default**: `10`
- **Description**: Maximum number of PostgreSQL connections in the connection pool.

### `QODIQA_PG_STATEMENT_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Default**: `30000`
- **Description**: Maximum execution time for any single SQL statement. Statements
  exceeding this limit are cancelled and an error is returned.

---

## 7. Enforcement Tuning

### `AI_CHAT_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Default**: `30000` (30 seconds)
- **Description**: Total time budget for the entire `/ai/chat` enforcement-and-execution
  pipeline, including the AI provider call. If the pipeline exceeds this budget, the
  request is cancelled and `REQUEST_TIMEOUT` (HTTP 504) is returned. The AI provider call
  may still complete asynchronously; the caller receives a timeout response.

```
AI_CHAT_TIMEOUT_MS=30000
```

### `VERIFY_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Default**: `5000` (5 seconds)
- **Description**: Total time budget for the `/verify` endpoint (dry-run pipeline). Must
  be shorter than `AI_CHAT_TIMEOUT_MS` since the verify path has no AI provider call.

```
VERIFY_TIMEOUT_MS=5000
```

### `AUDIT_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Default**: `10000` (10 seconds)
- **Range**: 1–600,000 (validated by `runEnvValidation()`; out-of-range or non-integer
  values are a fatal startup error in production, a startup warning otherwise — the
  runtime consumer falls back to the default of `10000` for any non-positive or
  non-numeric value regardless of environment)
- **Description**: Timeout for the `GET /audit/chain/integrity` chain-walk endpoint
  (`src/api/routes/audit.js`). Walking the full audit chain can be expensive on large
  logs; this timeout ensures the endpoint never blocks indefinitely under adversarial
  conditions. On timeout, the endpoint returns `503 { decision: "BLOCK", reason:
  "AUDIT_TIMEOUT" }`. This is unrelated to any PostgreSQL write-queue draining during
  shutdown, which is instead bounded by `SHUTDOWN_TIMEOUT_MS`.
- **Note**: the reference deployment examples (`deploy/docker/docker-compose.prod.yml`,
  `deploy/kubernetes/base/configmap.yaml`, `deploy/env/production.env.example`) set this explicitly to
  `10000`, matching the code default, for the same reason every other timeout variable
  in those files is spelled out explicitly rather than left implicit.

```
AUDIT_TIMEOUT_MS=10000
```

### Bounded Audit Chain Window

Since the in-process audit chain is a **bounded tail window**, not the
full history: the durable store (audit.log in single-node mode, PostgreSQL in
distributed mode) is the authority for anything older, and startup streams
the log with a fixed-size buffer instead of reading the whole file. Lifetime
counters and head/tail hashes remain exact for the entire history. See

for the full design, and
[docs/operations/audit-log-retention-restart.md](../operations/audit-log-retention-restart.md) (archival and retention policy, sealed exports: [docs/operations/audit-archival-and-retention.md](../operations/audit-archival-and-retention.md))
for the single-node retention/restart runbook.

| Variable | Default | Description |
|---|---|---|
| `QODIQA_AUDIT_WINDOW_SIZE` | `10000` | Number of most-recent audit entries kept in process memory. Any positive integer. The literal string `unbounded` restores the earlier keep-everything behaviour and logs `AUDIT_WINDOW_UNBOUNDED` (WARN) at boot — this escape hatch exists for one release only; its removal is documented in the ADR. in single-node **file mode** this window is also the audit-chain **replay/duplicate horizon** — a nonce or artifactId reused from older than the window is appended, not rejected (`replay_detected`/`already_executed` only fire inside the window; there is no durable on-disk nonce index). Announced at every file-mode boot by the `AUDIT_REPLAY_HORIZON_BOUNDED` WARN. Request-level replay protection (Redis nonce store) is unaffected; distributed (PG-authoritative) mode keeps durable uniqueness via PG UNIQUE constraints regardless of this value; the production profile cannot run file mode at all. |
| `QODIQA_AUDIT_BOOT_CHUNK_BYTES` | `1048576` | Fixed read-buffer size for the streamed startup pass and durable-store fallback scans. Boot memory is O(window + this buffer), independent of audit.log size. |

**Production recommendation:** single-node with the PostgreSQL mirror, anchored. Production refuses `QODIQA_DEPLOYMENT_MODE=distributed` (see §6 above). Single-node file-authoritative mode remains fully supported with the bounded window.

```
QODIQA_AUDIT_WINDOW_SIZE=10000
```

### Live Audit Chain Integrity Verifier

Background verifier for the execution audit chain (`audit.log` /
`audit_chain`) — "Decision
Update: Live Audit Chain Integrity Verifier" and
`docs/operations/audit-chain-integrity-verification.md` for the full
operational picture. All variables below live in
`src/core/audit/verifier/verifierConfig.js`.

| Variable | Default | Description |
|---|---|---|
| `QODIQA_AUDIT_VERIFIER_ENABLED` | `true` | Background runner on/off. Defaults ON (opt-out), unlike the Transparency Gap Scanner. |
| `QODIQA_AUDIT_VERIFIER_INCREMENTAL_INTERVAL` | `60s` | Frequent tail-only check. Named (`30s`,`60s`,`5m`,`15m`,`1h`,`24h`) or raw milliseconds. |
| `QODIQA_AUDIT_VERIFIER_FULL_INTERVAL` | `4h` | Infrequent full from-disk / paginated PG rescan — this is the actual worst-case historical-tamper detection-latency bound, since INCREMENTAL only ever checks the tail delta. |
| `QODIQA_AUDIT_VERIFIER_PG_DIVERGENCE_INTERVAL` | `15m` | Dual-write file-vs-PG periodic check (single-node + `QODIQA_PG_ENABLED=true` only). |
| `QODIQA_AUDIT_VERIFIER_BATCH_SIZE` | `1000` | PG pagination batch size for full/incremental PG-mode scans. |
| `QODIQA_AUDIT_VERIFIER_MAX_RETRIES` | `3` | Background-runner retry count on an engine failure (not on a detected violation). |
| `QODIQA_AUDIT_VERIFIER_RETRY_DELAY_MS` | `5000` | Delay between those retries. |
| `QODIQA_AUDIT_VERIFIER_STARTUP_SCAN` | `false` | Run one incremental tick immediately when the runner starts, instead of waiting for the first interval. |
| `QODIQA_AUDIT_VERIFIER_RECOVERY_MODE` | `false` | Downgrades the startup watermark-continuity gate's FATAL to a supervised WARN. Mirrors `QODIQA_AUDIT_MIRROR_RECOVERY_MODE`'s naming/behavior — never leave enabled as standing configuration. |
| `QODIQA_AUDIT_VERIFIER_FULL_ON_WATERMARK_MISMATCH` | `true` | In recovery mode, run an immediate FULL forensics scan after a watermark mismatch rather than waiting for the next scheduled one. |
| `QODIQA_AUDIT_VERIFIER_MANUAL_TIMEOUT_MS` | `30000` | Timeout for the admin `POST /audit/chain/verifier/verify` endpoint. |

```
QODIQA_AUDIT_VERIFIER_ENABLED=true
QODIQA_AUDIT_VERIFIER_INCREMENTAL_INTERVAL=60s
QODIQA_AUDIT_VERIFIER_FULL_INTERVAL=4h
```

### `STREAM_MAX_DURATION_MS`

- **Type**: integer (milliseconds)
- **Default**: `300000` (5 minutes)
- **Description**: Maximum duration of a single streaming AI response. When this timer
  fires, the stream is terminated with a `stream_cancelled` SSE event. This prevents
  runaway streaming connections from exhausting server resources.

```
STREAM_MAX_DURATION_MS=300000
```

### Clock skew tolerance (not environment-configurable)

Clock skew is checked in two independent directions by `src/validation/timeCheck.js`,
neither of which is configurable via an environment variable (Task #29 remediation —
this section previously documented a fictional `CLOCK_SKEW_TOLERANCE_MS` variable that
the implementation never reads):

- **Forward drift** (artifact timestamp in the future): a tolerance of `FUTURE_SKEW_MS` = 5,000 ms (fixed in the code). A timestamp more than 5,000 ms ahead of the server's current time is rejected with reason `FUTURE_TIMESTAMP`.
- **Backward drift** (artifact timestamp older than the server clock): rejected with
  reason `TIME_SKEW_EXCEEDED` once the drift exceeds `MAX_SKEW_MS`, a hardcoded constant
  (60,000 ms / 1 minute) in `src/validation/timeCheck.js`. It can only be overridden by
  passing `_maxSkewMs` directly to `validateArtifact()`, which is for test use only.

NTP synchronization is required on all nodes to prevent false positives from either check.

---

## 8. Access Control

### `QODIQA_RBAC_ENABLED` (deprecated — no longer has any effect)

RBAC permission checks are **always enforced** on every operator API endpoint listed
in `docs/security/RBAC_MODEL.md` — there is no way to disable them. Prior versions
read this variable and, when unset or `false`, treated every authenticated operator
request as having the `admin` role. That fail-open behavior has been removed
entirely; it cannot be re-introduced through configuration.

If this variable is present in your environment, remove it — it is read only to log
a one-time startup warning (`RBAC_ALWAYS_ENFORCED`) and has no effect on
authorization. Every administrative action requires an explicit RBAC user record
with `role: "admin"`, created via `bootstrapAdmin()` at first startup or
`POST /rbac/users` by an existing admin — see `docs/security/RBAC_MODEL.md` for the
full authorization model and how to provision operator accounts.

---

## 9. CORS Configuration

### `QODIQA_ALLOWED_ORIGINS`

- **Type**: comma-separated list of origin strings
- **Default**: none (all cross-origin requests are denied in production)
- **Description**: Allowlist of origins permitted to make cross-origin requests. Only
  required if browser-based clients call the QODIQA API directly. Most deployments serve
  QODIQA from a backend and do not require CORS configuration.
- **Format**: `https://app.example.com,https://portal.example.com`
- **Security**: Never use `*`. All origins must be explicitly listed.

```
QODIQA_ALLOWED_ORIGINS=https://app.acme-corp.com,https://portal.acme-corp.com
```

---

## 10. Transparency Log

### `TRANSPARENCY_SIGNER`

- **Type**: string
- **Accepted values**: `software`
- **Default**: `software`
- **Note**: `hsm` is defined in the codebase but not supported in this release.

```
TRANSPARENCY_SIGNER=software
```

### `TRANSPARENCY_ROOT_INTERVAL_MS`

- **Type**: integer (milliseconds)
- **Default**: `60000` (1 minute)
- **Description**: Interval at which the transparency log root scheduler generates and
  signs a new Merkle root covering all entries written since the last root.

---

## 11. Shutdown Configuration

### `SHUTDOWN_TIMEOUT_MS`

- **Type**: integer (milliseconds)
- **Default**: `30000` (30 seconds)
- **Description**: Maximum time allowed for graceful shutdown before `SIGKILL` is sent.
  Should match or be less than the Kubernetes `terminationGracePeriodSeconds` (recommended
  value: 60 seconds to allow buffer).

```
SHUTDOWN_TIMEOUT_MS=30000
```

---

## 12. Alerting and Observability

### `QODIQA_ALERTING_ENABLED`

- **Type**: boolean string
- **Default**: `true`
- **Description**: When `true`, the alerting framework is initialized at startup. The
  alerting subsystem is supplemental to enforcement; disabling it does not affect the
  enforcement pipeline.

### Log sanitization

Every call to `emit()` (`services/logger.js`) — the sole structured-logging entry point,
used for stdout/stderr output, the dashboard SSE event bus, and the optional PostgreSQL
central store — passes its `extra` payload through the sanitization pipeline
(`services/logSanitizer.js`) before it is written anywhere. This is unconditional: there
is no environment variable to disable it, and no "debug" or verbose mode that bypasses it.
Two independent mechanisms apply:

1. **Field-name redaction** (always on, not configurable): any object key whose
   normalized name (lowercased, non-alphanumeric characters stripped) matches one of 81
   known sensitive stems (`authorization`, `password`, `apikey`, `token`, `secret`,
   `privatekey`, `email`, `ssn`, `iban`, `creditcard`, etc. — see
   `SENSITIVE_FIELD_STEMS` in `services/logSanitizer.js` for the full list) has its
   entire value replaced with `[REDACTED]`, regardless of the value's type or content.
2. **Value-pattern scanning** (each category independently configurable): string values
   that were not already redacted by field name are scanned for specific patterns and
   replaced with a typed placeholder.

| Variable | Type | Default | Effect when `true`/enabled |
|---|---|---|---|
| `LOG_SANITIZER_SCAN_PII` | boolean string | `true` | Scans string values for emails (`[EMAIL]`), phone numbers (`[PHONE]`), and SSNs/IBANs/Luhn-validated credit card numbers (`[PII]`) |
| `LOG_SANITIZER_SCAN_TOKENS` | boolean string | `true` | Scans string values for JWTs, `Bearer`/`Basic` credentials → `[TOKEN]` |
| `LOG_SANITIZER_SCAN_CRYPTO` | boolean string | `true` | Scans string values for PEM-encoded key/certificate blocks → `[CRYPTO]` |
| `LOG_SANITIZER_REDACT_IP` | boolean string | `false` | Scans string values for IPv4 addresses → `[IP]`. **Off by default** — IPv4 addresses appearing in string values are not redacted unless this is explicitly enabled. |
| `LOG_SANITIZER_MAX_DEPTH` | integer | `10` (range 1–50) | Maximum object recursion depth before substituting `[MAX_DEPTH]` |
| `LOG_SANITIZER_MAX_STRING` | integer | `10000` (range 100–1,000,000) | Maximum string length before truncating and appending `...[TRUNCATED]` |

This sanitization pipeline applies only to structured logs emitted via `emit()`. It is
**not** in the write path of the audit chain (`src/core/audit/audit-log.js`), which never
calls `logSanitizer.js` — the audit chain's freedom from PII is a property of its schema
(only SHA-256 hashes, UUIDs, and decision metadata are ever written to an audit entry),
not of this sanitization mechanism. and
 for the full data-inventory treatment.

### `QODIQA_OPS_IP_ALLOWLIST`

- **Type**: comma-separated list of IP addresses or CIDR ranges
- **Default**: none (all IPs allowed)
- **Description**: IP allowlist for operator API endpoints. When set, only requests from
  listed IPs can reach `/audit`, `/keys`, `/rbac`, etc.

### Metrics OTLP export bridge

The `/metrics` endpoint (`src/api/routes/metrics.js`) is QODIQA's primary metrics
surface: a zero-dependency, in-memory, never-throwing Prometheus text-format registry
(`src/observability/metrics.js`), scraped on demand. It is **completely unaffected** by
everything below — these variables control an entirely optional, additional,
**push**-based export of a translated copy of the same registry to an OpenTelemetry
Collector or compatible OTLP/HTTP endpoint, on a timer. Disabled by default. Mirrors the
existing distributed-tracing bridge (`QODIQA_OTEL_ENABLED` /
`src/observability/tracing/`) — this uses the identical hand-rolled OTLP/HTTP JSON
exporter pattern (no `@opentelemetry/*` package, reuses the same
`src/observability/logShipping/_transport.js` HTTPS client both already depend on), and
shares that subsystem's `QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT` / `QODIQA_OTEL_SERVICE_NAME`
so one collector target and one service identity serve both signals.

| Variable | Type | Default | Description |
|---|---|---|---|
| `QODIQA_OTEL_METRICS_ENABLED` | boolean string | `false` | Enables the metrics export bridge. Independent of `QODIQA_OTEL_ENABLED` (tracing) — a site may enable one signal without the other. |
| `QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT` | HTTPS URL | none | **Shared with tracing.** Must start with `https://` (enforced) — export is skipped and a `METRICS_EXPORT_CONFIG_INVALID` error is logged if enabled without a valid HTTPS endpoint. |
| `QODIQA_OTEL_SERVICE_NAME` | string | `qodiqa` | **Shared with tracing.** Reported as the `service.name` resource attribute on every export. |
| `QODIQA_OTEL_METRICS_EXPORT_INTERVAL_MS` | integer | `60000` | How often the current registry state is pushed. Floored at `5000` — a lower value silently falls back to the default rather than hammering a collector. |

**Reliability contract**, verified in `src/observability/metricsExport/__tests__/` and
against a real `otel/opentelemetry-collector-contrib` container: at most one export is
ever in flight at a time (a tick that fires while the previous export is still awaiting
the collector is skipped, not queued — bounded memory, no pile-up of concurrent
outbound connections under a slow collector); export failures (network error, timeout,
4xx/5xx) are caught and never propagate — the request-serving path and `/metrics` itself
are never affected by a collector outage; the export timer is `unref()`'d and never
blocks graceful shutdown, which also triggers one final bounded export attempt via the
existing shutdown-handler chain (`METRICS_EXPORT` entry, alongside `TRACING`).

---

## 13. Policy Configuration

### `POLICY_FILE`

- **Type**: file path
- **Default**: `./policies.json` (repository root) — **outside production only**; see below.
- **Required**: **YES, in production** (`NODE_ENV=production`). There is no safe
  default in production; startup fails closed with a `FATAL POLICY_FILE_REQUIRED` event
  and `process.exit(1)` if this variable is unset. Every other environment (development,
  test, CI) keeps the previous, intentional behavior: `npm run dev` and the test suite boot
  against the repository's own `policies.json` out of the box when this variable is unset,
  unchanged.
- **What `policies.json` is for**: it is a **demo/development fixture**, not a production
  policy set — an always-on (though currently empty) `BLOCK_IP` rule and demo-tuned
  `RATE_LIMIT` values, meant to let a fresh local checkout enforce something meaningful
  immediately. Shipping it as the silent production default was exactly the risk
  closes: an operator who never explicitly chose a policy file would otherwise silently
  inherit these demo semantics in production.
- **What to use in production**: copy [`deploy/env/production.policies.example`](../../deploy/env/production.policies.example)
  (repository root) to a path outside the repository (e.g. `/opt/qodiqa/config/policies.json` —
  the path both `deploy/docker/docker-compose.prod.yml` and
  `deploy/kubernetes/base/configmap.yaml` already use), review and adjust every policy for
  your deployment, then set `POLICY_FILE` to that path. The example differs from the demo
  file's exact semantics — most notably, its `BLOCK_IP` policy ships **disabled** rather than
  enabled-with-an-empty-list, avoiding a rule that looks active but isn't.
- **How it is selected**: read once by `server/startup.js` at boot (via
  `services/policy/loader.js`'s `resolvePolicyFilePath()`, which encodes the production rule
  above) and again by `src/core/policy/store.js`'s own independent bootstrap (the
  policy-management API's persistent store) — both apply the identical rule, so there is one
  contract, not two that could drift. The file is import-only: it seeds an empty control-plane store once, and later edits change nothing. `SIGHUP` re-reads the control plane, not this file; change policy through the policy management API.
- **Format**: see `deploy/env/production.policies.example` for the full schema by example — an object
  with a `policies` array; each entry has `id` (`/^[A-Za-z0-9_-]{1,64}$/`), `type` (one of
  `REQUIRE_CONSENT`, `BLOCK_IP`, `TIME_WINDOW`, `RATE_LIMIT` — `services/policy/evaluators/`),
  `priority` (integer, lower runs first), `enabled` (boolean), and a type-specific `config`
  object. At least one enabled `REQUIRE_CONSENT` policy is mandatory — the loader refuses to
  start otherwise.

```bash
# Production
POLICY_FILE=/opt/qodiqa/config/policies.json
```

### `POLICY_BUILDER_ENABLED`

- **Type**: boolean string
- **Default**: `false`
- **Description**: Enables the web-based policy visual builder UI at `/policy-ui`. Should
  be disabled in production or restricted to trusted operator IPs.

---

## 14. Example: Minimal Production Configuration

```bash
# Server
NODE_ENV=production
PORT=3000

# Identity
QODIQA_CLIENT_ID=acme-corp

# Security tokens
QODIQA_OPS_TOKEN=<openssl rand -hex 32>

# Key encryption and execution invariant binding — two independent secrets
QODIQA_KEY_ENCRYPTION_KEY=<openssl rand -hex 32>
QODIQA_EXECUTION_INVARIANT_SECRET=<openssl rand -hex 32, different from the KEK above>
QODIQA_KMS_PROVIDER=local
QODIQA_KEYS_PATH=/etc/qodiqa/keys.json

# Policy file — REQUIRED in production; copy deploy/env/production.policies.example
# to this path first and review/adjust its policies for your deployment.
POLICY_FILE=/etc/qodiqa/policies.json

# There is no QODIQA_SIGN_TOKEN to set — after deployment, provision at least one
# signing identity: node scripts/provision-signing-identity.js --tenant-id acme-corp \
#   --name <name> --environment production

# Redis
REDIS_URL=rediss://redis.internal:6380
REDIS_TLS=true
REDIS_TLS_CA=/etc/ssl/certs/redis-ca.pem
STRICT_REPLAY_PROTECTION=true

# PostgreSQL (required for consent enforcement — see §6 above)
QODIQA_PG_ENABLED=true
QODIQA_PG_URL=postgresql://qodiqa:secret@pg.internal:5432/qodiqa?sslmode=require

# AI Providers
OPENAI_API_KEY=sk-...


# CORS (only if browser clients call this API directly)
# QODIQA_ALLOWED_ORIGINS=https://app.acme-corp.com
```

---

## 15. Startup Validation Behaviour

Since one boot validator, `src/infra/config/bootValidator.js`, decides
whether a process may start. `server/startup.js` runs it (`runBootValidation()`) right after
loading `.env` and **before any listener opens**. It absorbs the two former passes
(`envValidation.js` and `secretValidation.js`, now thin facades that delegate to it) and the
separate inline startup checks (provider presence, KEK, client id, portal dev-auth).

- **One schema, all violations at once.** Variable shapes and policy rules compile into
  one Zod schema. Every violation is collected, so an operator sees all of them in one boot
  attempt.
- **Refuse:** one `FATAL BOOT_VALIDATION_FATAL` event (`profile`, `violationCount`,
  `violations[]` of `{variable, rule, message}`) followed by exit code 1.
- **Warn:** one `WARN BOOT_CONFIG_WARNING` per finding; the process starts.
- **Pass:** `INFO BOOT_VALIDATION_OK`.
- **Messages** name the variable and the rule and never contain a value (except `NODE_ENV`'s).
- **The full rule table** — every rule with its production/development/test outcome and exact
  message — is [`docs/configuration/boot-rules.md`](boot-rules.md). It is
  generated from the validator itself, and a unit test fails if it drifts.
- **After a successful start,** `INFO BOOT_REPORT` states what the process actually
  established: observed PostgreSQL/Redis TLS, applied migrations, key ids, enabled providers,
  rate limiting, planes and the semantic fingerprint (`src/infra/config/bootReport.js`;
  written to `QODIQA_BOOT_REPORT_PATH` when set).

`POLICY_FILE_REQUIRED` remains as a second check at policy loading. In production,
boot validation already refuses a missing `POLICY_FILE` first.

There is no validation of `QODIQA_SIGN_TOKEN` beyond a dead-variable warning — it does not
exist. Signing identity API keys are always generated server-side via
`crypto.randomBytes(32)`, never user-supplied.

---

## 16. Tenant Self-Service Portal

Disabled by default. When enabled, mounts a login page and a read-only, RBAC-gated portal
(identity/keys/consent) at `/tenant-portal`, authenticated via OIDC SSO. See
 and
 for the full design and rationale.
None of this affects any existing route, RBAC role, or authentication path when disabled.

| Variable | Type | Default | Description |
|---|---|---|---|
| `QODIQA_PORTAL_ENABLED` | boolean string | `false` | Mounts `/tenant-portal` (`src/app.js`). All other variables below are inert while this is `false`. |
| `QODIQA_PORTAL_DEV_AUTH_ENABLED` | boolean string | `false` | Enables `GET /tenant-portal/dev-login`, a non-production-only shortcut that mints a session for a synthetic identity without a real OIDC round-trip. **Fail-closed in production**: boot validation refuses (`FATAL BOOT_VALIDATION_FATAL`, variable `QODIQA_PORTAL_DEV_AUTH_ENABLED`) if this is `true` while `NODE_ENV=production` — a redundant request-time check in `src/api/routes/tenantPortal.js` also 404s the route in that case. Never set this in a production environment. |
| `QODIQA_PORTAL_SESSION_SECRET` | string (M-07-managed) | none (throws if unset) | HMAC-SHA256 signing key for tenant-portal session tokens and the OIDC flow-state carrier (`services/portal/portalSessionToken.js`, `services/portal/oidcFlowState.js`). A dedicated, purpose-isolated secret — never the KEK, never `QODIQA_EXECUTION_INVARIANT_SECRET`. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. Listed in `src/infra/configSecrets/managedSecrets.js` — sourced from Vault when `QODIQA_CONFIG_SECRETS_PROVIDER=vault-kv` (§3 above). |
| `QODIQA_PORTAL_SESSION_TTL_MS` | integer | `28800000` (8 hours) | Session token lifetime. |
| `QODIQA_PORTAL_USER_STORE_PATH` | file path | `data/tenant-portal-users.json` | JIT-provisioned portal user store (mirrors `src/core/rbac/store.js`'s atomic-JSON-file persistence). |
| `QODIQA_PORTAL_RATE_LIMIT_MAX` | integer | `60` | Max requests per window for the `tenant_portal` rate-limit surface (`src/core/rateLimit/config.js`) — a **different** surface from the pre-existing, unrelated `portal` surface (Public Verification Portal, Component #23). |
| `QODIQA_PORTAL_RATE_LIMIT_WINDOW_MS` | integer | `60000` | Rate-limit window for the same surface. |
| `QODIQA_OIDC_ISSUER` | URL | none | The OIDC identity provider's issuer URL, used for discovery (`src/core/portal/oidcClient.js`). Required (login/callback fail closed) whenever the portal is enabled. |
| `QODIQA_OIDC_CLIENT_ID` | string | none | OIDC confidential-client ID. Required whenever the portal is enabled. |
| `QODIQA_OIDC_CLIENT_SECRET` | string (M-07-managed) | none | OIDC confidential-client secret. Required whenever the portal is enabled. Listed in `src/infra/configSecrets/managedSecrets.js`, same Vault sourcing as `QODIQA_PORTAL_SESSION_SECRET` above. |
| `QODIQA_OIDC_REDIRECT_URI` | URL | none | The callback URL registered with the identity provider, e.g. `https://<host>/tenant-portal/callback`. Required whenever the portal is enabled. |
| `QODIQA_OIDC_TENANT_CLAIM` | string | `tenant_id` | Name of the ID-token claim carrying the caller's tenant identifier. The claimed value is validated against `src/core/tenancy/tenantRegistry.js`'s `assertActiveTenant()` before any session is minted — an inactive or unknown tenant fails the login. |

**Fail-closed behaviour**: `GET /tenant-portal/login` and `/callback` redirect to
`/tenant-login.html?error=login_unavailable` if `QODIQA_OIDC_ISSUER`/`QODIQA_OIDC_CLIENT_ID`/
`QODIQA_OIDC_CLIENT_SECRET`/`QODIQA_OIDC_REDIRECT_URI` are incomplete — there is no fallback
authentication path. `openid-client` is an `optionalDependency` (`package.json`); if it is not
installed, the same fail-closed redirect applies with a clear "run `npm install openid-client`"
error logged server-side, never surfaced to the client.

---

## 17. Key-file locations, KEK provisioning and key recovery

Record:.

**Production key-file locations.** The `QODIQA_KEYS_PATH` rule now covers every key file the
process reads or writes. In production (`NODE_ENV=production`) boot validation refuses
(`FATAL BOOT_VALIDATION_FATAL`, rule `retained.key_file_paths`) when any of these resolves inside the
application directory — each path is resolved exactly the way its owning module resolves it:

| Variable | Refused in production when | Module default |
|---|---|---|
| `QODIQA_TRANSPARENCY_KEYS_PATH` | unset, or inside the application directory | `data/transparency-keys.json` (the audit-checkpoint key file defaults beside it) |
| `QODIQA_CHECKPOINT_KEYS_PATH` | set and inside the application directory | beside `QODIQA_TRANSPARENCY_KEYS_PATH` |
| `QODIQA_MAC_KEYS_PATH`, `QODIQA_KEYS_ARCHIVE_PATH` | set and inside the application directory | beside `QODIQA_KEYS_PATH` |
| `QODIQA_WITNESS_KEY_PATH` | set and inside the application directory (and, as before, inside the key-store directory) | none |
| `AWS_KMS_EDK_PATH` / `GCP_WRAPPED_KEY_PATH` / `AZURE_WRAPPED_KEY_PATH` | the one for the active KEK provider (`QODIQA_KMS_PROVIDER`, or `QODIQA_KMS_KEK_PROVIDER` under `vault-transit`/`hsm`) is unset or inside the application directory | `data/kek.edk` / `data/kek.gcp` / `data/kek.wk` under the working directory |
| `HSM_KEY_INDEX_PATH` | `QODIQA_KMS_PROVIDER=hsm` and unset or inside the application directory | `data/hsm-keys.json` under the working directory |

Put all of them on the same dedicated secret volume as `QODIQA_KEYS_PATH` (e.g. `/opt/qodiqa/data/`).

**Explicit new-KEK provisioning.**

| Variable | Type | Default | Description |
|---|---|---|---|
| `QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY` | exact string `true` | unset | With `aws-kms`/`gcp-kms`/`azure-kv`, a missing wrapped-KEK file used to make the provider mint a NEW KEK silently. In production that is now refused before any KMS call (`KMS_WRAPPED_KEY_MISSING`, nothing written) unless this is exactly `true`. Set it for ONE run only — first provisioning, or the local→KMS migration (`node scripts/migrate-keys-json-kek.js --execute --provision-new-kek` sets it for its own process). Never leave it in a deployment's standing environment: a lost wrapped-key file must be restored, not replaced. Development/test keep the implicit first-run generation. Every generation logs `WARN KMS_WRAPPED_KEY_PROVISIONED`, and the file is created with `wx` (never overwrites). |

**Boot-time key checks.** Production startup now also decrypts and self-tests the MAC keyring right after the
checkpoint-key check: a keyring written under another KEK (`kekFingerprint` mismatch), a corrupt
one, or a missing one is `FATAL MAC_KEYRING_STARTUP_FAILED`. The transparency and checkpoint key files are held
to the artifact store's rules: a plaintext private key is re-encrypted and re-scanned at bootstrap
(startup aborts if any remains), a record whose map key, `keyId`, `clientId:key_v<version>` or `purpose`
disagree is FATAL, and both files are re-read on the fleet-wide reload tick
(`QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS`) without ever un-revoking a key. Revoked records in `keys.json`,
the two Ed25519 key files and the HSM index carry `revokedAt`; files written earlier load with
`revokedAt: null`.

**Offline recovery of an expired artifact key.** An expired active key is FATAL at boot, so the
online `POST /key-admin/:clientId/rotate` is unreachable. Run, in the deployment's own environment (the
script never loads `.env`):

```
node scripts/keys/rotate-offline.js --client <id> --mode graceful|emergency \
  --operator <who> --reason "<why>"                                   # dry run: prints the plan, exit 2
node scripts/keys/rotate-offline.js --client <id> --mode graceful|emergency \
  --operator <who> --reason "<why>" --confirm-offline-recovery        # takes the Redis rotation lock (REDIS_URL)
#   ... or add --no-lock instead of REDIS_URL, ONLY after stopping every instance sharing the key file
```

`graceful` keeps the expired key verifying what it signed (deprecated); `emergency` revokes it. Exit codes:
0 rotated, 1 failed, 2 dry run, 3 nothing to recover (key not expired / no active key), 4 lock refused,
64 usage. Every run logs `KEY_OFFLINE_RECOVERY_STARTED`/`_COMPLETED`/`_FAILED` (and `_UNLOCKED` for
`--no-lock`) with operator and reason; the key store's own `KEY_DEPRECATED`/`KEY_REVOKED`/`KEY_ROTATED`
events carry `triggeredBy: offline-recovery-cli:<operator>`.

---

## Protocol V2 switches (experimental, off by default)

Protocol V2 (`docs/protocol/PROTOCOL-V2.md`) is behind switches; with all of them unset the gateway behaves exactly as before.

| Variable | Default | Effect |
|---|---|---|
| `QODIQA_PROTOCOL_V2_ACCEPT` | `false` | When `true`, `/ai/chat` accepts artifacts whose payload carries the `qodiqa` block (version, bound headers, model, limits). When `false` such an artifact is `UNSUPPORTED_PROTOCOL_VERSION`. |
| `QODIQA_PROTOCOL_V2_ISSUE` | `false` | When `true`, `/sign` accepts a top-level `v2` block and issues V2 artifacts. Enable only after every verifier accepts V2 (accept first, issue last). |
| `QODIQA_PROTOCOL_MIN_VERSION` | `1` | `2` makes the gateway refuse V1 artifacts (`PROTOCOL_VERSION_TOO_LOW`); a tenant may also carry `minProtocolVersion: 2`. |

## Signed receipts

| Variable | Default | Effect |
|---|---|---|
| `QODIQA_RECEIPT_TTL_SECONDS` | `3600` | How long a signed receipt stays retrievable through `GET /v1/transparency/receipt/{requestId}` (kept in Redis when `REDIS_URL` is set, else in process memory). `0` stores nothing (the endpoint then answers 404); the maximum is 604800 (7 days); an invalid value falls back to the default. The receipt is always returned in the `/ai/chat` response regardless; the durable evidence is the audit entry and the transparency inclusion proof. |

## Audit schema v8 switch (one-way, off by default)

Audit schema v8 (`docs/protocol/AUDIT-SCHEMA-V8.md`) adds ten hashed fields and the entry types the later waves need. Reading and verifying v8 ships first (the gateway verifier and the independent verifier in `scripts/audit-repro/verify/`); writing it is a separate switch.

| Variable | Default | Effect |
|---|---|---|
| `QODIQA_AUDIT_SCHEMA_V8` | `false` | Only the literal `true` enables it. When `true` the writer stamps `schemaVersion 8` and records `issuedAt` / `protocolVersion` in the entries of a request. **One-way:** once v8 entries exist, a writer with the flag off refuses to append (`AUDIT_SCHEMA_DOWNGRADE_REFUSED`), and every verifier reports a v7 entry after a v8 one as `SCHEMA_DOWNGRADE`. Roll every verifier forward and apply migration 083 before enabling. |

## 18. Dedicated key-encryption keys for the audit key stores

The artifact signing keys (`QODIQA_KEYS_PATH`), the transparency log keys (`QODIQA_TRANSPARENCY_KEYS_PATH`) and the audit-checkpoint keys
(`QODIQA_CHECKPOINT_KEYS_PATH`) are three separate files, in three trust domains (a forged artifact, a forged log entry, a forged checkpoint).
Their paths are separate and configurable. Until all three were encrypted under the one `QODIQA_KEY_ENCRYPTION_KEY`; now the transparency and
checkpoint stores can each have a KEK of their own:

| Variable | Default | Effect |
|---|---|---|
| `QODIQA_TRANSPARENCY_KEY_ENCRYPTION_KEY` | unset | 64 hex characters. Set: the transparency key file is encrypted, sealed (record MACs) and fingerprinted under this KEK. Unset: the shared KEK, exactly as before. |
| `QODIQA_CHECKPOINT_KEY_ENCRYPTION_KEY` | unset | The same for the audit-checkpoint key file. |
| `QODIQA_AUDIT_KEK_SEPARATION` | `off` | `off` is silent. `warn` (production) reports every audit store that shares a KEK with another. `enforce` (production) refuses to boot unless the artifact, transparency and checkpoint KEKs are three different values. |

Rules: a scoped KEK that is not exactly 64 hex characters (or is a trivial repeating pattern) is a hard failure (boot validation and the key store), never a silent fallback to the
shared KEK. A key file records the fingerprint of the KEK that encrypted it: starting under a different KEK (a scoped KEK added, changed or removed) fails closed with
`KEK_FINGERPRINT_MISMATCH`, naming the variable in use, before any key is decrypted — the same guard rail as for the shared KEK. Switching an existing deployment to a dedicated KEK therefore
means provisioning that store afresh under it (move the old key file aside and keep its PUBLIC keys published, so older signatures keep verifying) — a
deliberate operator step, not something boot does silently; there is no in-place re-encryption. The scoped KEKs apply to the local KEK provider and to the others alike (the variable overrides the provider for that one store).

## 19. Transparency evidence store: file journal and unavailability bound

| Variable | Default | Effect |
|---|---|---|
| `QODIQA_PRQ_JOURNAL_DIR` | `data/prq-journal` (development) | The append-only, fsync'ed file journal that holds a transparency leaf while PostgreSQL cannot take it. **In production it must be a persistent volume outside the application directory** (boot validation warns when unset and refuses a path inside the application directory or on a container's root filesystem); the shipped Compose and Kubernetes templates set it under `/opt/qodiqa/data`. |
| `QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS` | `60000` | How long neither the recovery queue nor the journal may be able to take a leaf before new EXECUTE decisions are refused (503 `TRANSPARENCY_JOURNAL_UNAVAILABLE`) and `/ready` reports not ready. 1000 – 3600000; any other value falls back to the default. |

Leaves that reached the log through the queue, the journal or the in-memory buffer carry `payload.recovery = { late: true, replica, seq, queuedAt }` and keep their original `recordedAt`. The original order is the original `recordedAt`; `seq` is per process (a new process is a new `replica` id), is never reused and only breaks ties and exposes gaps. Only a PostgreSQL persistence failure is queued; a signer or validation failure is not (it would be dead-lettered by the replay handler) — it opens the unavailability window instead. See `docs/operations/alert-runbooks.md` ("Transparency evidence store unavailable").

## 20. External anchoring of audit checkpoints

A signed checkpoint and its witness cosignatures prove nothing against someone who controls the gateway host and its keys. An **external anchor** pins the checkpoint's position and head in a system that host does not control, with a time. QODIQA itself contacts no network and never pushes: it writes to a local anchors repository and calls operator-provided executables.

| Variable | Default | Effect |
|---|---|---|
| `QODIQA_ANCHOR_GIT_REPO` | unset | A git **working tree outside the gateway's control** (production refuses a path inside the application directory). Each anchored checkpoint is appended to `anchors/<UTC date>.jsonl` and committed (`anchor <chainLength> <digest>`, author `QODIQA Anchor <anchor@qodiqa.invalid>` unless `QODIQA_ANCHOR_GIT_AUTHOR` = `Name <email>`). Publishing the repository (a mirror, CI, another machine) is the operator's job. |
| `QODIQA_ANCHOR_GIT_SIGN` | unset | `true`: the commit is signed (`git commit -S`, with the repository's configured signing key — GPG or SSH); a signing failure is a failed anchor. |
| `QODIQA_ANCHOR_OTS_EXEC` | unset | An executable that receives `{ kind, digestHex, statement }` as JSON on stdin and prints `{ "receipt": "<text>", "ref": "<optional>" }` — the OpenTimestamps stamp of the digest (e.g. a wrapper around `ots stamp`). |
| `QODIQA_ANCHOR_TSA_EXEC` | unset | The same for an RFC 3161 timestamp token (a wrapper around `openssl ts` / curl to a TSA). |
| `QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS` | `86400000` | At most one checkpoint per interval is anchored externally (1000 .. 604800000); the shutdown checkpoint is always anchored. |

Beside the anchors the git adapter commits the **public** keys a verifier needs (`keys/checkpoint-keys.json`, `keys/transparency-keys.json`, append-only: a key id is never removed and never changes its key — a change is refused), so `qodiqa-proof-verify --anchors-repo <dir>` can verify a proof without asking the gateway.

The anchored **statement** is `{ v: 1, checkpointId, payloadHash, chainLength, headHash, createdAt }`; its digest is `SHA-256("QODIQA::EXTERNAL_ANCHOR::V1" ‖ canonical JSON)` — recomputable from the checkpoint alone. Anchoring is **asynchronous and never blocks** a request or a checkpoint: each (checkpoint, kind) is a row of `external_anchors` (migration 099) that goes `pending` → `confirmed` (with its receipt) or stays `pending` with the last error and attempt count (retried every minute; `failed` after 10 attempts). Metrics: `qodiqa_external_anchor_total{kind,outcome}`, `qodiqa_external_anchor_pending`, `qodiqa_external_anchor_oldest_pending_seconds`; see "External anchor failing" in `docs/operations/alert-runbooks.md`.

## 21. Several co-signing witnesses

`QODIQA_WITNESSES_CONFIG` is the path of a JSON array that replaces the single-witness variables (`QODIQA_WITNESS_MODE`, `QODIQA_WITNESS_ID`, …). Each entry: `{ "witnessId": "…", "mode": "exec"|"local", "command": "…", "args": ["…"], "retries": 1 }` for an exec witness (a separate process — ideally on another host or account, reached through the operator's transport; `scripts/anchor/witness-cosign.js` is the reference implementation with its own key and append-only log), or `{ "witnessId", "mode": "local", "keyPath", "logPath" }`. Witness ids must be distinct.

An anchor is exported only when at least `QODIQA_ANCHOR_MIN_WITNESSES` cosignatures **verify under the trusted witness keys** (`QODIQA_WITNESS_PUBLIC_KEYS`): the default is **2 when two or more witnesses are configured**, otherwise 1. Below that the checkpoint is **held** (error `WITNESS_QUORUM_NOT_MET`) and exported later, in chain order, once enough witnesses cosign it. Each witness refuses rollback, equivocation and forks against its own log, so one compromised or lagging witness can neither anchor alone nor drag the other along. Independence between operators is a deployment fact the software cannot verify (`anchoringIndependence()` still reports `unverified-exec-witness`).

## 22. Multi-turn conversations

| Variable | Default | Effect |
|---|---|---|
| `QODIQA_MULTI_TURN_ENABLED` | `true` | `/ai/chat` accepts `messages` (+ `system`) as an alternative to `prompt` (docs/api/overview.md, "Multi-turn"). `false` refuses them again as `UNSUPPORTED_FIELD` (the pre-F6A behaviour). The request binding already covers the whole body, so every turn is signed; every role is screened. |

## 23. Content screening switches

| Variable | Default | Effect |
|---|---|---|
| `QODIQA_SEM_FT3_ENABLED` | `true` | The fine-tuned screening gate. The model file is not part of this repository; without it the gate cannot start, so a deployment without the model sets this to `false`. In production that is refused unless it is acknowledged (next row). |
| `QODIQA_SEM_EMBEDDING_ENABLED` | `true` | Set to `false` to start the gateway without the embedding screening layer. Its models and reference data are not distributed with every copy of the repository; with the layer on and those resources absent, the gateway refuses to start. With it off nothing is loaded, the layer never blocks, and the rule engine still runs. In production this also needs `QODIQA_SEM_EMBEDDING_OFF_ACK=true`. |
| `QODIQA_SEM_EMBEDDING_OFF_ACK` | unset | Set to `true` together with `QODIQA_SEM_EMBEDDING_ENABLED=false` to run production without the embedding screening layer. The boot then records a warning that content screening is limited to the rule engine. The acknowledgement changes nothing on its own. |
| `QODIQA_SEM_FT3_OFF_ACK` | unset | Set to `true` together with `QODIQA_SEM_FT3_ENABLED=false` to run production without the fine-tuned screening gate. The boot then records a warning that content screening is reduced to the base gates. The acknowledgement changes nothing on its own. |

Authorization, policy, audit and evidence do not depend on content screening.

---

environment variable is added or an existing variable's behaviour changes.*
