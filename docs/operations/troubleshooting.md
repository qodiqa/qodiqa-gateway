# TROUBLESHOOTING

This guide covers every failure mode in the QODIQA enforcement pipeline, its log events, and the steps to resolve it.

---

## How to read this guide

Every block decision returns a JSON body. Match the `reason` field to the section below.

```json
{
  "decision": "BLOCK",
  "reason": "<REASON_CODE>",
  "details": {},
  "requestId": "<uuid-v4>"
}
```

For startup failures, match the `event` field in the FATAL or ERROR log line.

---

## Request-path failures

### POST /sign — UNAUTHORIZED / FORBIDDEN

**Symptom**: `POST /sign` returns `401 { "decision": "BLOCK", "reason": "UNAUTHORIZED" }` or `403 { "decision": "BLOCK", "reason": "FORBIDDEN" }` instead of a signed artifact.

**Cause**: As of `/sign` has no shared secret — every caller authenticates as its own individually-issued **signing identity** (`src/middleware/signAuth.js`, `src/core/signing/signingIdentityStore.js`). Authentication and authorization are checked separately:

| Reason | HTTP | Cause |
|---|---|---|
| `UNAUTHORIZED` | 401 | No `Authorization: Bearer <sk_...>` header was sent, or the key does not resolve to any provisioned signing identity. There is no signing-identity-store equivalent of a "startup fails if empty" gate — an empty or missing store simply means every `/sign` call 401s until an identity is provisioned; the server itself starts normally. |
| `FORBIDDEN` | 403 | The credential resolved to a real identity, but that identity is disabled, revoked, or lacks the `SIGN_ARTIFACT` permission. |
| `FORBIDDEN` (`SCOPE_ENVIRONMENT_MISMATCH`) | 403 | The identity's `environment` does not match the server's resolved environment (`QODIQA_ENVIRONMENT`, falling back to `NODE_ENV`, falling back to `development` — see `src/core/signing/serverEnvironment.js`). Checked on every request, not just at issuance. |
| `FORBIDDEN` (`SCOPE_PROVIDER_DENIED`) | 403 | The identity's `allowedProviders` list does not include the AI provider the signed request resolves to. |

**Resolution**: Provision a signing identity with `node scripts/provision-signing-identity.js --name <name> --tenant-id <tenantId> --environment <environment>` (see [docs/guides/quickstart.md — Provision a Signing Identity](../guides/quickstart.md#provision-a-signing-identity)), or via `POST /signing-identities` if an RBAC admin already exists. Use the printed `sk_...` key as `Authorization: Bearer <key>`. For `SCOPE_ENVIRONMENT_MISMATCH`, re-provision with the `--environment` matching the running server. For `SCOPE_PROVIDER_DENIED`, either re-provision with a broader `--providers` list or omit it entirely (`null` = whatever the tenant has enabled).

There is no `QODIQA_SIGN_TOKEN` environment variable to set — it is not read anywhere in this codebase (confirmed: `src/infra/secrets/secretValidation.js` explicitly documents that it is intentionally no longer validated, having been fully replaced by per-identity signing keys).

---

### MISSING_ARTIFACT

**Symptom**: HTTP 200. No `x-qodiqa-artifact` header was sent, or the header was empty.

**Resolution**: Obtain a signed artifact from `POST /sign` and attach it as the `x-qodiqa-artifact` header. The artifact must be JSON-serialized and base64-encoded:

```javascript
const { QodiqaClient } = require('./sdk/javascript/dist/index.js');
const client = new QodiqaClient({ signToken: process.env.QODIQA_SIGN_TOKEN });
const signed = await client.sign.sign({
  request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello' } },
});
const artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');
const result = await client.chat.create(artifactB64, { prompt: 'Hello' });
```

Or manually:

```bash
ARTIFACT=$(node -e "
  const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  process.stdout.write(Buffer.from(JSON.stringify(d.artifact)).toString('base64'));
" <<< "$SIGN_RESPONSE")

curl -X POST http://localhost:3000/ai/chat \
  -H "Content-Type: application/json" \
  -H "x-qodiqa-artifact: $ARTIFACT" \
  -d '{"prompt":"Hello"}'
```

---

### ARTIFACT_TOO_LARGE

**Symptom**: HTTP 413. The `x-qodiqa-artifact` header exceeds the maximum allowed size.

**Resolution**: Artifacts are compact by design. An oversized artifact indicates the signed payload contains an unexpectedly large body. Keep the `body` field in the sign request small — only include what the AI chat endpoint needs.

---

### ARTIFACT_DECODE_FAILED

**Symptom**: HTTP 200. The `x-qodiqa-artifact` header value is not valid base64 or does not decode to a JSON object.

**Resolution**: Verify the artifact was encoded correctly. The encoding must be:

```javascript
Buffer.from(JSON.stringify(artifact), 'utf8').toString('base64')
```

Do not URL-encode the header value. Do not add newlines or padding characters.

---

### ARTIFACT_INVALID_TYPE

**Symptom**: HTTP 200. The artifact decoded successfully but the result is not a JSON object (e.g., it is an array or a scalar).

**Resolution**: The `artifact` field in the `/sign` response is the JSON object that must be serialized and base64-encoded. Do not serialize the entire `/sign` response — only the `artifact` field.

---

### INVALID_ARTIFACT

**Symptom**: HTTP 200. The artifact object failed structural validation.

**Causes**:

| Issue | Detail |
|---|---|
| Missing required field | Artifact must have exactly 5 fields: `expiry`, `payload`, `publicKeyId`, `signature`, `timestamp` |
| Extra field present | No fields beyond the 5 schema keys are permitted |
| Field type mismatch | `timestamp` and `expiry` must be positive safe integers (Unix ms); `signature` must be a base64 string decoding to exactly 64 bytes; `publicKeyId` must be a non-empty string |
| Undefined field value | No field value may be `undefined` — use `null` for absent optional payload fields |
| Payload not a plain object | `payload` must be a plain object — not an array, Date, Map, Set, or other type |

**Resolution**: Use the JavaScript SDK (`client.sign.sign()` then `client.chat.create()`) or the `/sign` endpoint to create artifacts. Do not construct artifact objects manually.

---

### INVALID_SIGNATURE

**Symptom**: HTTP 200. The Ed25519 signature does not verify against the artifact envelope and the resolved public key.

**Causes**:
- Any field in the envelope (`expiry`, `payload`, `publicKeyId`, `timestamp`) was modified after signing.
- The artifact was signed with a different key than `publicKeyId` indicates.
- The request body sent to `/ai/chat` differs from what was signed (this produces `REQUEST_MISMATCH`, not `INVALID_SIGNATURE`).

**Resolution**: Do not modify the artifact envelope after receiving it from `/sign`. Re-sign if any request parameters change.

---

### KEY_NOT_FOUND

**Symptom**: the gateway never returns this reason. An artifact whose `publicKeyId` is unknown or no longer resolvable is reported as `INVALID_SIGNATURE` (so the existence of a key is not observable), and a revoked key that still resolves gives `KEY_REVOKED`. Only the offline verifier scripts print `KEY_NOT_FOUND`.

**Resolution**:
1. Check the active key: `curl http://localhost:3000/.well-known/qodiqa/keys`
2. If the key was intentionally revoked, sign again with the active key.
3. If the key store was re-provisioned, artifacts signed with the old key can no longer be verified.

---

### EXPIRED

**Symptom**: HTTP 200. `now >= artifact.expiry` — the artifact has passed its expiry timestamp.

**Resolution**: Re-sign the request. Artifacts have a short validity window by design. Call `client.sign.sign()` again for each `client.chat.create()` request.

---

### FUTURE_TIMESTAMP

**Symptom**: HTTP 200. `artifact.timestamp > now + 5 000 ms` (`FUTURE_SKEW_MS`) — the artifact's creation timestamp is more than 5 seconds in the future.

**Resolution**: Check the signing host's system clock. The clock must not be more than 5 seconds ahead of the enforcing gateway's clock. Synchronize using NTP.

---

### TIME_SKEW_EXCEEDED

**Symptom**: HTTP 200. The artifact's timestamp is more than 60 seconds in the past at the time of enforcement.

**Cause**: The artifact was signed more than 60 seconds before the enforcement request arrived, or there is clock drift of more than 60 seconds between the signing host and the gateway.

**Resolution**:
1. Re-sign immediately before executing. Artifacts are single-use; do not cache and reuse them.
2. Ensure the signing host's clock is within 60 seconds of the gateway's clock (NTP synchronization).

---

### REQUEST_MISMATCH

**Symptom**: HTTP 200. The artifact's `requestHash` does not match the actual request sent to `/ai/chat`.

**Cause**: The `method`, `path`, or `body` of the request sent to `/ai/chat` differs from what was hashed at signing time. The hash is computed over `{method, path, body}` using canonical serialization (sorted keys, no whitespace).

**Resolution**: The request body sent to `/ai/chat` must be byte-for-byte identical to the body sent to `/sign`. Do not modify the request between signing and execution. Sign and send the same body object with the SDK (`client.sign.sign()` then `client.chat.create()`).

---

### REPLAY_DETECTED

**Symptom**: HTTP 200. The `requestId` in the artifact payload has already been registered in the nonce store.

**Log event**: `NONCE_V2_REPLAY_DETECTED`

**Cause**: A request carrying this artifact was already processed. Each artifact can only be used once.

**Resolution**: Re-sign to obtain a new artifact with a fresh `requestId`. Artifacts are single-use by design.

---

### NONCE_STORE_ERROR

**Symptom**: HTTP 200. The nonce store was unavailable when the nonce registration was attempted.

**Resolution**: This is the same underlying cause as a Redis nonce store outage. See [Redis store unavailable](#redis-store-unavailable).

---

### ANOMALY_DETECTED

**Symptom**: HTTP 200.

**Log events**: `ANOMALY_THRESHOLD_EXCEEDED` on block; `ANOMALY_STATE_INCREMENTED` on every request (INFO).

**Type field in log**:

| Type | Cause |
|---|---|
| `SIGNATURE_BURST` | Per-key sliding window exceeded: more than 100 requests from the same `publicKeyId` within 60 seconds |
| `RATE_BURST` | Global sliding window exceeded: more than 5 000 requests across all keys within 60 seconds |
| `STORE_ERROR` | Anomaly store unavailable (fail-closed). Log event: `ANOMALY_STORE_UNAVAILABLE` |

**Resolution for burst**:
- Investigate the source of the traffic spike. Legitimate traffic should not exceed these thresholds.
- If the threshold is intentionally too low for your workload, set the organization quotas `maxRequestsPerKeyPerMin` / `maxRequestsPerMinute` (organization API); there are no `ANOMALY_*` environment variables, and the defaults are 100 per key and 5,000 global per 60 s. The anomaly store must be available and reconnected for the counters to clear after the 60-second window.

**Resolution for store error**: See [Redis store unavailable](#redis-store-unavailable).

---

### CONSENT_MISSING

**Symptom**: HTTP 200, `policyId` in response body identifies the `REQUIRE_CONSENT` policy.

**Cause**: The request reached the `REQUIRE_CONSENT` policy evaluator but the artifact's `valid` flag was not `true`. This indicates the artifact failed an upstream check that did not halt the pipeline as expected.

**Resolution**: This reason should not appear in normal operation — the pipeline blocks on any artifact validation failure before policy evaluation. If it appears, inspect the enforcement middleware chain for misconfigurations.

---

### CONSENT_STORE_UNAVAILABLE

**Symptom**: HTTP 200, `policyId` identifies the `REQUIRE_CONSENT` policy. **This is the first error a brand-new installation following the default `policies.json` will hit on its very first `/ai/chat` call**, immediately after a correctly-signed artifact is accepted.

**Cause**: `POL-001: REQUIRE_CONSENT` is enabled by default. Its evaluator (`services/policy/evaluators/requireConsent.js`) delegates to the Runtime Consent Registry (`src/core/consent/ConsentVerifier.js`), which requires PostgreSQL. `QODIQA_PG_ENABLED` is `false` by default — with the pool disabled, `ConsentVerifier` fails closed rather than allowing the request through.

**Resolution**: Set `QODIQA_PG_ENABLED=true` and the `QODIQA_PG_*` connection variables, then provision a consent record. See [docs/guides/quickstart.md — Provision Consent (PostgreSQL)](../guides/quickstart.md#provision-consent-postgresql) for the exact steps for both `npm run dev` (automatic) and `npm start` (manual). See also [docs/configuration/reference.md §6](../configuration/reference.md#6-postgresql-configuration).

This is intentional fail-closed behavior, not a defect — QODIQA never allows a consent-gated request through when it cannot verify consent, even if that means blocking traffic during onboarding or a PostgreSQL outage.

---

### CONSENT_NOT_FOUND

**Symptom**: HTTP 200, `policyId` identifies the `REQUIRE_CONSENT` policy. PostgreSQL is reachable (no `CONSENT_STORE_UNAVAILABLE`), but the request still blocks.

**Cause**: No consent record exists for the exact `(actor_id, action, tenant_id)` triple — `actor_id` is the authenticated caller identity (`payload.callerContext.callerId`, the signing identity's id; only an artifact with no caller context falls back to the signer's `publicKeyId`), `action` is `artifact.payload.provider`, and `tenant_id` is the client that owns the signing key, resolved from the key store for that `publicKeyId` (`src/validation/validateBoundRequest.js:137`, CRYPTO-6; `services/policy/evaluators/requireConsent.js:94`).

**Resolution**: Grant a consent record for that exact triple — see [docs/guides/quickstart.md — Provision Consent (PostgreSQL)](../guides/quickstart.md#provision-consent-postgresql) or `POST /consent` (requires `MANAGE_CONSENT` RBAC permission; see `docs/security/RBAC_MODEL.md`).

---

### CONSENT_REVOKED / CONSENT_EXPIRED / CONSENT_SUSPENDED / CONSENT_NOT_ACTIVE

**Symptom**: HTTP 200, `policyId` identifies the `REQUIRE_CONSENT` policy. A consent record exists (distinguishable from `CONSENT_NOT_FOUND` by the `consentId` in the audit record) but is not in the `ACTIVE` state.

**Cause**: The matching consent record's effective state (`src/core/consent/ConsentStateModel.js`) is `REVOKED`, `EXPIRED` (past `expires_at`), `SUSPENDED` (within a `suspended_until` window), or `PENDING`.

**Resolution**: Inspect the record via `GET /consent/:id` and its history via `GET /consent/:id/history`. A revoked or expired record is never silently reactivated — grant a new one, or `POST /consent/:id/resume` for a suspended record, via an RBAC-authenticated operator call.

---

### CONSENT_SCOPE_MISMATCH / CONSENT_SCOPE_MISSING

**Symptom**: HTTP 200, `policyId` identifies the `REQUIRE_CONSENT` policy. The consent record is `ACTIVE` but still blocks.

**Cause**: The policy's `requiredScope` config (or the record's own `required_scope`) does not match the record's granted `scope`.

**Resolution**: Grant consent with the matching `scope`, or update the policy's `requiredScope` through the policy API (the enforced set lives in the control plane; `policies.json` is import-only since `docs/operations/control-plane.md`).

---

### CONSENT_CONTEXT_INCOMPLETE / CONSENT_EVALUATION_ERROR

**Symptom**: HTTP 200, `policyId` identifies the `REQUIRE_CONSENT` policy.

**Cause**: `CONSENT_CONTEXT_INCOMPLETE` — the verified artifact's `publicKeyId` or `payload.provider` could not be resolved into `context.userId`/`context.action` (should not occur with a correctly-signed artifact). `CONSENT_EVALUATION_ERROR` — an unexpected exception was thrown during evaluation; check the `CONSENT_EVALUATION_ERROR` ERROR-level log line for the underlying message.

**Resolution**: For `CONSENT_CONTEXT_INCOMPLETE`, verify the artifact was signed via `POST /sign` and not hand-constructed. For `CONSENT_EVALUATION_ERROR`, inspect the log detail and PostgreSQL connectivity/health (`GET /consent/health`).

---

### IP_BLOCKED

**Symptom**: HTTP 200, `policyId` identifies a `BLOCK_IP` policy.

**Cause**: The request's source IP matches an entry in the `BLOCK_IP` policy's blocklist.

**Resolution**: The source IP is explicitly blocked by policy. If the block is unintended, change the policy through the policy API — the enforced set lives in the control plane and `policies.json` is import-only, so editing the file and sending SIGHUP changes nothing (`server/startup.js` SIGHUP handler). See [Policy updates](runbook.md#policy-updates).

---

### RATE_LIMIT_EXCEEDED

**Symptom**: HTTP 200, `policyId` identifies a `RATE_LIMIT` policy.

**Log event**: `POLICY_RATE_LIMIT_EXCEEDED`

**Cause**: The request exceeded the rate limit configured in the matching `RATE_LIMIT` policy for the context key (user ID or IP, depending on policy configuration).

**Resolution**: The caller is sending requests faster than allowed by policy. If the limit is intentionally too low for your workload, update the policy's `limit` and `windowMs` values through the policy API (control plane; `policies.json` is import-only).

---

### OUTSIDE_TIME_WINDOW

**Symptom**: HTTP 200, `policyId` identifies a `TIME_WINDOW` policy.

**Cause**: The request arrived outside all permitted time windows defined in the matching policy. The server clock (UTC) is the request time.

**Resolution**: Requests are only permitted during the configured time windows. If the window is misconfigured, update the policy through the policy API (control plane; `policies.json` is import-only).

---

### MISSING_PROMPT / INVALID_REQUEST_BODY

**Symptom**: HTTP 400.

**Cause**: The request body to `/ai/chat` did not contain a non-empty `prompt` string field, or the body was not a JSON object.

**Resolution**: Ensure the request body is `{"prompt":"..."}` with a non-empty string value. The body must be valid JSON with `Content-Type: application/json`.

---

### Provider errors (4xx/5xx)

**Symptom**: HTTP 400, 500, 502, 503, or 504. The `reason` field identifies the provider error. QODIQA supports eight providers (`openai`, `anthropic`, `gemini`, `mistral`, `llama`, `local`, `azure`, `bedrock` — the last two experimental, selected via `artifact.payload.provider` — see [Provider architecture](../../README.md)); the codes below are identical across all of them, and the affected provider is reported in the `provider` field of the corresponding `PROVIDER_EXECUTION` audit/log event, not implied by the reason code itself.

| Reason | HTTP | Cause |
|---|---|---|
| `MISSING_PROVIDER` | 400 | The signed artifact's `payload.provider` field is missing or not a string |
| `PROVIDER_MODEL_NOT_ALLOWED` | 400 | Requested `model` is not in that provider's allowlist (`services/providers/config.js`; empty allowlist for `llama`/`local` means any non-empty model name is accepted) |
| `PROVIDER_INVALID_REQUEST` | 400 | Outbound request failed the adapter's payload validation (missing/empty `messages`, disallowed `role`, non-string `content`) |
| `PROVIDER_REQUEST_REJECTED` | 400 | Outbound request exceeded the adapter's size limits (more than 50 messages, or more than 32,768 bytes of combined message content) |
| `PROVIDER_RESPONSE_INVALID` | 502 | The provider returned a response without usable text output (route-level defensive check in `aiChat.js`; distinct from the adapter-level `PROVIDER_INVALID_RESPONSE` below) |
| `PROVIDER_UNAVAILABLE` | 503 | The provider's API is unreachable, returned a 5xx, or the provider name is not registered at all |
| `PROVIDER_RATE_LIMITED` | 503 | The provider returned HTTP 429 |
| `PROVIDER_AUTH_FAILED` | 503 | The provider returned HTTP 401/403 — its API key is invalid, expired, or missing at call time |
| `PROVIDER_TIMEOUT` / `REQUEST_TIMEOUT` | 504 | The outbound provider call exceeded its configured timeout (`<PROVIDER>_TIMEOUT_MS`, default 30,000 ms) |
| `PROVIDER_NOT_CONFIGURED` | 500 | The named provider is registered but not enabled (its required API key or base URL environment variable is unset) |
| `PROVIDER_CONFIG_INVALID` | 500 | A configured base URL (`MISTRAL_BASE_URL`, `LLAMA_BASE_URL`, `LOCAL_BASE_URL`) failed SSRF/URL validation at first use |
| `PROVIDER_INVALID_RESPONSE` | 500 | Adapter-level: the raw upstream payload had no usable text field (falls through the route's default HTTP-status case) |

**Resolution**: For `PROVIDER_AUTH_FAILED` or `PROVIDER_NOT_CONFIGURED`, verify the relevant provider's API key / base URL environment variable in `.env` (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `LLAMA_BASE_URL`, `LOCAL_BASE_URL`). For `PROVIDER_CONFIG_INVALID`, check that any configured base URL passes SSRF validation (`services/providers/ssrf.js`) — public providers require an HTTPS, non-private, allowlisted hostname; `llama`/`local` accept private-network HTTP/HTTPS endpoints. For `PROVIDER_UNAVAILABLE`, `PROVIDER_RATE_LIMITED`, and `PROVIDER_TIMEOUT`, check the upstream provider's status page — these do not indicate a QODIQA configuration problem, and the router already retries once via any configured `PROVIDER_FAILOVER_<PROVIDER_NAME>` before surfacing the error.

---

## Redis store unavailable

**Symptoms**:
- `REPLAY_PROTECTION_DEGRADED` — nonce store unavailable; all execution blocked
- `ANOMALY_PROTECTION_DEGRADED` — anomaly store unavailable; all execution blocked
- `POLICY_RATE_LIMIT_DEGRADED` — rate limit store unavailable; all execution blocked
- `GATEWAY_RUNTIME_DEGRADED` — all three stores unavailable simultaneously
- `GATEWAY_RUNTIME_PARTIAL_FAILURE` — one or more (but not all) stores unavailable
- `/ready` → HTTP 503 `{"ready":false,...}`
- `qodiqa_execution_integrity_full{} 0`

**Impact**: All `POST /ai/chat` requests are blocked fail-closed. No execution is possible while any Redis store is unavailable.

**Resolution**:
1. Check Redis connectivity: `redis-cli ping`. If this fails, restore the Redis instance.
2. Verify `REDIS_URL` in `.env` points to the correct host and port (default: `redis://localhost:6379`).
3. Check Redis authentication if `REDIS_PASSWORD` or `REDIS_USERNAME` is set.
4. The store client reconnects automatically (exponential backoff capped at 30 s, no attempt limit). On successful reconnection, `GATEWAY_RUNTIME_RECOVERED` and `GATEWAY_STATE_RECOVERED` are emitted and `/ready` returns 200.
5. If the maximum reconnect attempts (5) are exhausted, `/ready` continues to return 503. Restart the gateway after restoring Redis: `kubectl rollout restart statefulset/qodiqa -n qodiqa` (the production single-node overlay is a StatefulSet; `deployment/qodiqa` exists only in the non-production distributed overlay) or restart the process.

**Redis reconnect flapping**: If `REDIS_RECONNECT_FLAPPING`, `REDIS_RUNTIME_UNSTABLE`, or `REDIS_READINESS_FLAPPING` appear (more than 3 reconnect events in 60 seconds), investigate Redis host stability, connection limits, and network reliability before the issue escalates to MAX_RECONNECTS exhaustion.

**Startup failure**: If a store fails at startup, `REDIS_STARTUP_FAILED` is emitted (once per failed store). `REDIS_RUNTIME_DEGRADED` is then emitted as a summary. The gateway starts but `/ready` returns 503. Restore Redis and restart.

---

## Startup failures

> the configuration checks below (no provider, missing KEK, missing client id)
> are reported by the boot validator as **one** `FATAL BOOT_VALIDATION_FATAL` event listing every violation
> (`src/infra/config/bootValidator.js`, `docs/configuration/boot-rules.md`); `server/` no longer emits the separate
> `NO_PROVIDER_CONFIGURED` / `KEY_ENCRYPTION_KEY_NOT_CONFIGURED` / `CLIENT_ID_NOT_CONFIGURED` events. Match the
> violation text inside `BOOT_VALIDATION_FATAL`; the causes and resolutions below still apply.

### No AI provider configured (`BOOT_VALIDATION_FATAL`, rule `providers`)

**Symptom**: Process exits immediately with a `BOOT_VALIDATION_FATAL` event whose violation reads: `No AI provider is configured. Set at least one of: OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, MISTRAL_API_KEY, LLAMA_BASE_URL, LOCAL_BASE_URL.`

**Cause**: At startup, `hasAnyProvider()` (`services/providers/config.js`) found that none of the eight supported providers is enabled. A provider is enabled automatically when its required environment variable is present — there is no default provider.

**Resolution**: Set at least one of the following, matching whichever provider(s) you intend to use:

| Provider | Required variable | Notes |
|---|---|---|
| `openai` | `OPENAI_API_KEY` | Obtain from platform.openai.com/api-keys |
| `anthropic` | `ANTHROPIC_API_KEY` | — |
| `gemini` | `GEMINI_API_KEY` | — |
| `mistral` | `MISTRAL_API_KEY` | — |
| `llama` | `LLAMA_BASE_URL` | Cloud-hosted (Groq, Together AI, Fireworks) or self-managed OpenAI-compatible endpoint |
$1| `azure`, `bedrock` | see docs/guides/providers.md | Experimental adapters |

On successful startup, `PROVIDERS_CONFIGURED` is emitted at INFO level listing the enabled provider names.

---

### Missing key-encryption key (`BOOT_VALIDATION_FATAL`)

**Symptom**: Process exits with a `BOOT_VALIDATION_FATAL` event naming `QODIQA_KEY_ENCRYPTION_KEY`.

**Resolution**: Set `QODIQA_KEY_ENCRYPTION_KEY` to a 64-hex-character (256-bit) value in `.env`. Generate with `openssl rand -hex 32`.

---

### Missing client id (`BOOT_VALIDATION_FATAL`)

**Symptom**: Process exits with a `BOOT_VALIDATION_FATAL` event naming `QODIQA_CLIENT_ID`.

**Resolution**: Set `QODIQA_CLIENT_ID` to a non-empty string in `.env`.

---

### KEY_MANAGER_STARTUP_FAILED

**Symptom**: Process exits after `KEY_MANAGER_STARTUP_FAILED` FATAL event. One or more `KEY_EXPIRED_STARTUP` ERROR events precede it.

**Cause**: One or more active keys in `data/keys.json` have passed their `expiresAt` timestamp.

**Resolution**: Rotate the key before starting (a running server is not required — only environment variables):

```bash
node --require dotenv/config \
  -e "require('./services/artifact/keyManager').rotate(process.env.QODIQA_CLIENT_ID)"
```

After a graceful rotation, `KEY_DEPRECATED` and `KEY_ROTATED` are emitted (an emergency rotation emits `KEY_REVOKED`). Then start the server. Perform a rolling restart in Kubernetes to propagate the new key to all instances.

> `KEY_EXPIRING_SOON` (fewer than 30 days to expiry) and `KEY_ROTATION_OVERDUE` (past 90-day rotation deadline) are warnings only — startup continues. Rotate promptly to avoid a future hard failure at `expiresAt`.

---

### KEYSTORE_EMPTY

**Symptom**: Process exits after `KEYSTORE_EMPTY` FATAL event.

**Cause**: `data/keys.json` exists but contains no active keys (all keys were revoked, or the file is empty).

**Resolution**: Provision an initial key:

```bash
mkdir -p data
node --require dotenv/config \
  -e "require('./services/artifact/keyManager').rotate(process.env.QODIQA_CLIENT_ID)"
```

Expected log output: `KEY_CREATED` with `keyId: "<clientId>:key_v1"`.

---

### POLICY_LOAD_FAILED

**Symptom**: Process exits after `POLICY_LOAD_FAILED` FATAL event.

**Cause**: `policies.json` is missing, not valid JSON, exceeds 1 MB, contains more than 100 policies, or contains no enabled `REQUIRE_CONSENT` policy.

**Resolution**: Fix `policies.json` and restart. The file must:
- Be valid JSON
- Be ≤ 1 MB
- Contain ≤ 100 policies
- Contain at least one enabled policy of type `REQUIRE_CONSENT`

---

### STRICT_REPLAY_PROTECTION_VIOLATION

**Symptom**: Process exits after `STRICT_REPLAY_PROTECTION_VIOLATION` FATAL event.

**Cause**: `STRICT_REPLAY_PROTECTION=true` is set but Redis is unreachable or not configured with durable AOF persistence (`appendonly yes` + `appendfsync everysec`).

**Resolution**: Either configure Redis with AOF persistence before starting, or set `STRICT_REPLAY_PROTECTION=false` (not recommended for production). See `REDIS_PERSISTENCE_WARNING` and `REDIS_PERSISTENCE_UNSAFE` log events for details.

---

## Runtime operations failures

### POLICY_RELOAD_FAILED (after SIGHUP)

**Symptom**: `POLICY_RELOAD_FAILED` ERROR event is emitted after sending SIGHUP. The previous policy set remains active.

**Cause**: Re-reading the enforced policy set from the control plane failed (`server/startup.js` SIGHUP handler). SIGHUP does **not** re-read `policies.json` — the file is import-only, so editing it never changes enforcement.

**Resolution**: Check control-plane connectivity (PostgreSQL, `qodiqa_control`; `docs/operations/control-plane.md`) and re-send SIGHUP. Change policy through the policy API, not by editing `policies.json`. The gateway continues operating under the previous policy during this window. On success, `POLICIES_RELOADED` (`source: "control-plane"`) is emitted.

```bash
# Linux / macOS
kill -HUP <pid>

# Docker
docker exec <container> kill -HUP 1

# Kubernetes
kubectl exec -n qodiqa <pod> -- kill -HUP 1
```

---

## Audit chain issues

### Chain integrity failure

**Symptom**: `AUDIT_INTEGRITY_VIOLATION` error thrown at startup (process exits), or `GET /audit/chain/integrity` returns `chainValid: false`.

**Investigation**: `/audit/chain/integrity` is an operator endpoint — it requires `Authorization: Bearer <QODIQA_OPS_TOKEN>` (or a per-operator RBAC API key). A request without valid credentials returns `401 UNAUTHORIZED`, not the report.

```bash
curl http://localhost:3000/audit/chain/integrity \
  -H "Authorization: Bearer $QODIQA_OPS_TOKEN"
```

Returns `chainValid`, `tamperingDetected`, `entriesVerified`, and integrity failure details.

**Cause**: The `audit.log` file was truncated, modified externally, or disk I/O caused partial writes. The audit log is append-only and hash-chained — any modification is detectable.

**Resolution**: The audit log is evidence. Do not delete or modify it. Preserve the file and investigate disk errors or unauthorized access before taking any action. If a startup failure was caused by a corrupted audit log, contact your security team — this may indicate tampering.

### `503 AUDIT_PERSISTENCE_FAILED` on `/ai/chat`

**Symptom**: A request that should have succeeded returns `503 { decision: "BLOCK", reason: "AUDIT_PERSISTENCE_FAILED" }` instead of `200 EXECUTE`. Log shows `CRITICAL AUDIT_APPEND_FAILED` with `stage: "ALLOW"`.

**Cause**: The mandatory file-based audit write (`appendMandatory()`) failed on every retry attempt — almost always a filesystem problem on the audit log's volume (disk full, permission error, read-only filesystem, too many open files). The AI provider call had already succeeded at this point; QODIQA discarded that response rather than report success without durable evidence. This is fail-closed by design, not a bug — see README.md "Fail-closed evidence recording".

**Investigation**:
```bash
# Check disk space and permissions on the audit log volume
df -h "$(dirname "${QODIQA_AUDIT_LOG:-./audit.log}")"
ls -la "${QODIQA_AUDIT_LOG:-./audit.log}"*

# Check for the underlying fs error in the CRITICAL log line's "error" field
```

**Resolution**: Fix the underlying filesystem issue (free disk space, correct permissions, remount as read-write). No audit data is lost or corrupted by this failure — the request that hit it was never recorded as ALLOW, so there is nothing to reconcile. Once the filesystem issue is resolved, retried requests will succeed normally. If failures persist, check `QODIQA_AUDIT_APPEND_MAX_RETRIES` / `QODIQA_AUDIT_APPEND_RETRY_DELAY_MS` — the defaults (2 retries, 50ms) are tuned for transient hiccups, not sustained outages.

### `CRITICAL STREAM_AUDIT_FAILED` after a streaming session

**Symptom**: A streamed response completed normally (the client received all chunks), but the log shows `CRITICAL STREAM_AUDIT_FAILED` for that `streamId`.

**Cause**: Same underlying failure mode as `AUDIT_PERSISTENCE_FAILED` above, but by the time the audit write runs, the SSE response has already been fully sent — there is no way to fail the request closed retroactively. This is an evidence gap that needs operator reconciliation, not a request-handling bug.

**Resolution**: Fix the underlying filesystem issue (same steps as above). Cross-reference the `streamId`/`requestId` in application logs (provider call, chunk counts) to manually reconstruct what happened for compliance purposes if that specific execution's evidence is needed.

### `PG_AUDIT_PERSIST_FAILED` / `EVIDENCE_CHAIN_PERSIST_FAILED`

**Symptom**: Log shows `ERROR PG_AUDIT_PERSIST_FAILED` or `ERROR EVIDENCE_CHAIN_PERSIST_FAILED`. The request itself succeeded normally (`200`/`403` as expected).

**Cause**: The optional PostgreSQL dual-write of the audit entry, or the evidence-chain record it triggers (only active when `QODIQA_PG_ENABLED=true`), failed. This never affects the HTTP response — the file-based audit chain is the mandatory, always-active store.

**Investigation / Resolution**: If the error is a connectivity/resource issue (connection refused, pool exhaustion, timeout), it has already been durably queued in the Persistence Recovery Queue for automatic retry — see `docs/operations/postgresql-failure.md` §3.4 to monitor queue depth and drain progress. If the error is a data/constraint/syntax issue, it was NOT queued (retrying a deterministic failure is pointless) — investigate the schema or the audit entry shape directly.

### Development PostgreSQL databases accumulate (`npm run dev`)

**Symptom**: Multiple `qodiqa_dev_<random hex>` databases appear on your local PostgreSQL cluster over time (visible via `psql -l` or `SELECT datname FROM pg_database WHERE datname LIKE 'qodiqa_dev_%'`).

**Cause**: This is expected, not a leak. Every `npm run dev` boot with `QODIQA_PG_ENABLED=true` and no explicit `QODIQA_PG_DATABASE` set generates a fresh, uniquely-named, disposable database for that boot only (`scripts/lib/devConsent.js`'s `provisionDevConsent()`), so consent grants and the PostgreSQL audit-chain mirror never write into the shared `qodiqa` database with no file-side counterpart — the isolation gap that caused a real, reconciled incident. Each boot's database name is set on `process.env.QODIQA_PG_DATABASE` before `server.js` is spawned as a child process, so the running server's own PG-backed subsystems (consent, audit mirror) land in the same isolated database too — never the shared one.

**Resolution**: expected, not a leak. Dropping them is a destructive action: on the project's shared cluster it needs current owner authorization. To reuse one database across boots, set `QODIQA_PG_DATABASE` **and** pass `QODIQA_PG_ALLOW_SHARED=true` inline for that invocation (for example `QODIQA_PG_DATABASE=<name> QODIQA_PG_ALLOW_SHARED=true npm run dev`) — never put `QODIQA_PG_ALLOW_SHARED` in `.env`, which the bootstrap isolation guard refuses (`scripts/lib/bootstrapIsolationGuard.js`); never point it at `qodiqa`. Without that inline override, the guard refuses any database the run did not generate itself.

### `npm run dev` FATAL: could not create isolated development database

**Symptom**: `npm run dev` exits immediately with `[bootstrap-dev] FATAL: Could not create isolated development database "qodiqa_dev_<hex>": ...`.

**Cause**: Creating the per-boot isolated database (above) requires the `qodiqa_test` role's `CREATEDB` privilege, via `QODIQA_PG_TEST_USER`/`QODIQA_PG_TEST_PASSWORD` — deliberately never the ambient `QODIQA_PG_USER`/`PASSWORD` identity (`qodiqa_app`), which the spawned server itself uses and is not expected to hold `CREATEDB`. This is fatal by design, not best-effort: silently falling back to the shared `qodiqa` database on a creation failure is exactly the isolation gap this feature exists to close (the `audit_chain` seq 157 incident) — a boot that quietly degrades into writing real rows into shared state is the finding recurring, not a convenience worth preserving.

**Resolution**, either of:
1. Grant/verify `CREATEDB` on the `qodiqa_test` role and confirm `QODIQA_PG_TEST_USER`/`QODIQA_PG_TEST_PASSWORD` are set in `.env`, then re-run `npm run dev`.
2. Reuse one persistent database across boots — a conscious opt-out of per-boot isolation: set `QODIQA_PG_DATABASE` **and** pass `QODIQA_PG_ALLOW_SHARED=true` inline for that invocation, exactly as in the "databases accumulate" entry above (never in `.env` — `scripts/lib/bootstrapIsolationGuard.js` refuses that — and never the shared `qodiqa` database).

---

## Diagnostic commands

```bash
# Liveness
curl http://localhost:3000/health

# Readiness (per-store Redis state)
curl http://localhost:3000/ready

# Prometheus metrics (Redis store gauges)
curl http://localhost:3000/metrics | grep -E 'execution_integrity|redis_store_up'

# Active public keys
curl http://localhost:3000/.well-known/qodiqa/keys

# Look up an audit record by requestId — operator endpoint, requires ops auth
curl http://localhost:3000/audit/<requestId> \
  -H "Authorization: Bearer $QODIQA_OPS_TOKEN"

# Full chain integrity walk (rate-limited: 30/min) — operator endpoint, requires ops auth
curl http://localhost:3000/audit/chain/integrity \
  -H "Authorization: Bearer $QODIQA_OPS_TOKEN"

# Redis connectivity
redis-cli ping
```

`/audit/*` endpoints return `401 UNAUTHORIZED` without a valid `QODIQA_OPS_TOKEN` (or per-operator RBAC API key) — see `docs/api/overview.md`.

---

## Quick-reference: reason codes and HTTP status

**:** this used to be a hand-maintained table —
one of three independent copies of the same vocabulary (the others being
`docs/architecture/enforcement-flow.md`'s decision table and `src/reasons.js`'s partial
subset), which could and did drift out of sync with each other.
**`src/errors/catalog.js` is
now the single, machine-readable source of truth** for every reason code's
HTTP status, human description, pipeline category, and retry guidance —
`src/errors/__tests__/catalog.governance.test.js` fails the build if it
and `src/reasons.js` (or this document's reference to it) ever disagree.

Look up any reason code directly in that file rather than in a prose table
here — it is guaranteed current, this paragraph is not. As a quick pointer
to the stages: **correction** — artifact decode/
validation/replay/anomaly/policy/semantic checks on `/ai/chat` (every
per-reason "Symptom" section above this one) return **200** with
`decision:'BLOCK'` in the body, not 403 (except `ARTIFACT_TOO_LARGE`,
**413**) — this paragraph itself said 403 until this correction, stale
since the remediation moved those to 200 and `src/errors/catalog.js`
was never updated to match (see that file's own "Consent" category comment
and `docs/architecture/enforcement-flow.md`'s matching correction for the full account,
including the one genuine exception: `POST /consent/verify` still wraps
any consent-reason failure in a literal 403, unaffected). Input-guard
and most provider-request failures return **400**; provider outages return
**502 (response invalid)**, **503 (unavailable/rate-limited/auth-failed)**,
or **504 (timeout)**; provider misconfiguration returns **500**; and
`AUDIT_PERSISTENCE_FAILED` returns **503**.

---

## Test suite tiers

QODIQA's test suites are split into distinct tiers with distinct npm scripts — pick the one that matches what you're actually verifying:

| Script | What it runs | Live Redis/Postgres required? |
|---|---|---|
| `npm test` / `npm run test:unit` | `src/**/*.test.js` — component and unit tests (dependency-injected stores, no live infra) | No |
| `npm run test:component` | `test/**/*.test.js` — mocked/component-level tests, including files historically suffixed `.integration.test.js`. These exercise contract and failure-injection logic against in-memory stand-ins, **not** live infrastructure. | No |
| `npm run test:integration` | Deprecated alias for `test:component`, kept for backward compatibility with existing scripts/CI invocations. Prefer `test:component` in new tooling. | No |
| `npm run acceptance` | `test/acceptance/` — the genuine live-infrastructure tier: spawns and kills real Redis/Postgres processes and independent HTTP provider stubs. | Yes |
| `npm run test:harness` | Standalone red-team/adversarial protocol harnesses (`adversarial.harness.js`, `pipeline.harness.js`, `guarantee.demo.js`) — self-executing scripts, not Jest suites; also included automatically in `npm run test:all`. | No |
| `npm run benchmark` | `benchmark.js` — performance benchmarking, not a pass/fail test. | No |

If you need to confirm behavior against real Redis/Postgres, use `npm run acceptance`, not `test:component`/`test:integrationtest:integration` was renamed rather than the underlying tests being rewritten to hit live infrastructure).

## See also

- `docs/guides/quickstart.md` — setup and first run
- `docs/architecture/overview.md` — how enforcement layers interact
- `docs/guides/providers.md` — full AI provider reference (capabilities, limits, error codes per provider)
- `docs/architecture/enforcement-flow.md` — complete per-request decision pipeline
- `docs/architecture/verification-flow.md` — dry-run verification pipeline
- `src/errors/catalog.js` — the machine-readable source of truth for every reason code's HTTP status, description, category, and retryability
- `docs/operations/runbook.md` — key rotation, policy reload, graceful shutdown
