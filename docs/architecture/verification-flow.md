# VERIFICATION FLOW

The `/verify` endpoints run the complete enforcement pipeline as a **dry run** — same decision logic as `/ai/chat`, no side effects. No AI execution occurs. No nonce is consumed. No rate-limit quota is decremented. No audit record is written.

---

## Endpoints

| Endpoint | Method | Rate limit | Purpose |
|---|---|---|---|
| `POST /verify/v2` | POST | 60 req / 60 s (configurable) | Primary verification endpoint |
| `POST /verify` | POST | 30 req / 60 s | Public verification endpoint |

Both endpoints use the same handler and produce identical responses. The `/verify/v2` path is intended for trusted callers that need higher throughput; the `/verify` path is for public or external callers.

---

## Request format

The verify endpoints accept a JSON body containing the artifact as a **plain object** and the request as a **plain object**. This differs from `/ai/chat`, which accepts the artifact as a base64-encoded string in a header.

```json
{
  "artifact": {
    "expiry":      1749470300000,
    "payload":     { "requestId": "<uuid-v4>", "requestHash": "<64-char hex>", "provider": "openai", "tenantId": "my-local-dev", "callerContext": { "callerId": "<signing-identity-uuid>", "callerName": "ci-runner", "environment": "production", "credentialType": "api-key" } },
    "publicKeyId": "my-local-dev:key_v1",
    "signature":   "<base64-encoded Ed25519 signature>",
    "timestamp":   1749470000000
  },
  "request": {
    "method": "POST",
    "path":   "/ai/chat",
    "body":   { "prompt": "Hello, what is 2 + 2?" }
  }
}
```

Only `artifact` and `request` are accepted at the top level. Any other key returns HTTP 400 with `UNEXPECTED_FIELDS`.

---

## Response semantics

The verification endpoint uses a different HTTP status convention from `/ai/chat`:

| Condition | HTTP | Response |
|---|---|---|
| Input validation error | 400 | `{ decision: 'BLOCK', reason, details: {}, requestId }` |
| Pipeline BLOCK | **200** | `{ decision: 'BLOCK', reason, details: {}, requestId }` |
| Pipeline EXECUTE | **200** | `{ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', artifactId, keyId, callerId, requestId }` |
| Internal error or timeout | **200** | `{ decision: 'BLOCK', reason: 'INTERNAL_ERROR', details: {}, requestId }` |

Both BLOCK and EXECUTE return HTTP 200 when the pipeline ran to completion. HTTP 400 is used only for malformed input that cannot enter the pipeline. This design allows callers to check the `decision` field without special-casing HTTP status codes.

`keyId` (`publicKeyId`) identifies which shared tenant signing key produced the artifact; `callerId` identifies which specific authenticated caller requested that signature — `null` for an artifact signed before this remediation shipped.3.1.

---

## Input guards (HTTP 400)

These run before the enforcement pipeline. A failure here produces HTTP 400 and the pipeline does not run.

| Check | Reason |
|---|---|
| `req.body` is not a plain object | `INVALID_REQUEST_BODY` |
| Body contains unknown top-level keys | `UNEXPECTED_FIELDS` |
| `artifact` is absent or null | `MISSING_ARTIFACT` |
| `artifact` is not a plain object | `INVALID_ARTIFACT_TYPE` |
| `request` is absent or null | `MISSING_REQUEST` |
| `request` is not a plain object | `INVALID_REQUEST_TYPE` |
| `artifact` serialized size exceeds 8 192 bytes | `INVALID_ARTIFACT` |
| `request` serialized size exceeds 4 096 bytes | `INVALID_REQUEST` |
| `artifact` object nesting depth exceeds 12 | `INVALID_ARTIFACT` |
| `request` object nesting depth exceeds 12 | `INVALID_REQUEST` |

The size and depth guards protect against DoS vectors: deeply nested objects cause stack exhaustion during canonicalization; oversized objects inflate hashing time.

---

## Dry-run stores

The verify endpoint substitutes read-only wrappers for the three Redis-backed stores. These wrappers produce the same enforcement decisions as the runtime stores without mutating any state.

### Dry-run nonce store

```javascript
// dry-run: reads isRegistered(), never writes
register(requestId) → { registered: !alreadyUsed }
```

- If the `requestId` already exists in the nonce store: returns `{ registered: false }` → `REPLAY_DETECTED` (same decision as runtime)
- If the `requestId` is new: returns `{ registered: true }` — does **not** write the nonce to Redis
- If Redis is unavailable: throws → `NONCE_STORE_ERROR` (fail-closed, same as runtime)

### Dry-run anomaly store

```javascript
// dry-run: reads peek() (count without writing), simulates next write
record(key, nowMs, windowMs) → { count: current + 1 }
```

- Calls `anomalyStore.peek()` to read the current window count without incrementing
- Returns `count + 1` — simulates what `checkAnomaly` would see after recording this request
- Threshold comparisons produce the same BLOCK/PASS decision as runtime
- If Redis is unavailable: throws → `ANOMALY_DETECTED` type `STORE_ERROR` (fail-closed, same as runtime)

### Dry-run policy store

```javascript
// dry-run: reads rate-limit counts, never increments
getCount(key, windowSeconds) → realStore.getCount(key, windowSeconds)
increment(key, windowSeconds) → no-op
```

- `getCount` delegates to the real rate-limit store — `RATE_LIMIT` evaluations see the same window count as the runtime
- `increment` is a no-op — verification never consumes rate-limit quota
- Stateless evaluators (`REQUIRE_CONSENT`, `BLOCK_IP`, `TIME_WINDOW`) are unaffected; they do not use the store

---

## Pipeline steps

The verify endpoint runs the same 5-step pipeline as `/ai/chat`. Because dry-run stores are used, all Redis operations are read-only.

### Steps 1–4: `validateBoundRequest()`

Identical to the runtime path. Runs under a 5-second timeout (configurable via `VERIFY_TIMEOUT_MS`).

- **Step 1**: `validateArtifact()` — Ed25519 signature verification, schema checks, time bounds, key resolution
- **Step 2**: `verifyRequestBinding()` — requestHash binding check, timing-safe compare
- **Step 3**: `registerNonce()` (dry-run) — reads nonce store without writing
- **Step 4**: `checkAnomaly()` (dry-run) — reads anomaly store without incrementing

On block: returns HTTP 200 with `{ decision: 'BLOCK', reason, details, requestId }`.

Reason codes are normalized by `normalizeReason()` before returning. Legacy codes are mapped to canonical forms:

| Legacy code | Canonical code |
|---|---|
| `MALFORMED_ARTIFACT` | `INVALID_ARTIFACT` |
| `TIMESTAMP_IN_FUTURE` | `FUTURE_TIMESTAMP` |
| `REQUEST_HASH_MISMATCH` | `REQUEST_MISMATCH` |
| `NONCE_ALREADY_USED` | `REPLAY_DETECTED` |

### Step 5: `checkPolicy()` (dry-run)

Identical to the runtime path, using the dry-run policy store. Rate-limit counts are read but not incremented.

On block: returns HTTP 200 with `{ decision: 'BLOCK', reason, details, requestId }`.

### Policy drift detection

After step 5 passes, the handler compares `artifact.payload.policyHash` to the live policy hash:

```javascript
if (!policyHashesEqual(artifact.payload.policyHash, livePolicyHash)) {
  emit('WARN', 'POLICY_DRIFT_DETECTED', { ... })
}
```

`POLICY_DRIFT_DETECTED` is informational only. It never blocks verification.

### EXECUTE response

If all 5 steps pass:

```json
{
  "decision":   "EXECUTE",
  "reason":     "ALL_CHECKS_PASSED",
  "artifactId": "<uuid-v4>",
  "keyId":      "my-local-dev:key_v1",
  "requestId":  "<uuid-v4>"
}
```

No AI provider call is made. No audit record is written.

---

## What verification confirms

A `decision: 'EXECUTE'` response from `/verify` confirms that, at the moment of the check:

- The artifact has a valid Ed25519 signature
- The artifact is not expired and not future-dated
- The artifact's `publicKeyId` resolves to an active or deprecated (non-revoked) key
- The `requestHash` in the artifact matches the `request` object in the body
- The `requestId` has not previously been used in a live execution (replay check)
- The request would not have triggered anomaly detection thresholds (burst check)
- All policies would pass (consent, IP block, time window, rate limit)

A `decision: 'EXECUTE'` from `/verify` does **not** consume the artifact. The same artifact can subsequently be submitted to `/ai/chat` to execute.

---

## What verification does not confirm

- **Execution guarantee**: A `EXECUTE` result from `/verify` does not guarantee that the same artifact will execute at `/ai/chat`. Between the verify call and the execution call, the nonce may have been consumed by a concurrent execution, the anomaly window may have been crossed by other traffic, or a policy reload may have changed the policy set.
- **No audit record**: Verification decisions are not written to the audit chain. Only `/ai/chat` writes audit records.
- **No nonce registration**: The `requestId` is not registered during verification. It remains available for a live execution at `/ai/chat`.

---

## Timeout

The full pipeline runs under a 5-second timeout (`VERIFY_TIMEOUT_MS`, default 5 000 ms). A timeout returns:

```json
{ "decision": "BLOCK", "reason": "INTERNAL_ERROR", "details": {}, "requestId": "..." }
```

HTTP 200.

---

## Differences from `/ai/chat`

| Aspect | `/ai/chat` | `/verify` |
|---|---|---|
| Artifact input | Base64-encoded in `x-qodiqa-artifact` header | Plain object in JSON body `artifact` field |
| Request input | Inferred from actual HTTP request body | Explicit `request` object in JSON body |
| On pipeline BLOCK | HTTP 403 | HTTP 200 |
| On pipeline EXECUTE | HTTP 200 (with AI response) | HTTP 200 (no AI response) |
| AI execution | Yes | No |
| Nonce consumed | Yes | No |
| Anomaly counter incremented | Yes | No |
| Rate-limit quota consumed | Yes | No (read-only) |
| Audit record written | Yes | No |
| Timeout | 30 s | 5 s |

---

## Example: successful verification

```bash
SIGN_TOKEN=$(grep QODIQA_SIGN_TOKEN .env | cut -d= -f2)

# Step 1: sign the request
SIGN_RESPONSE=$(curl -s -X POST http://localhost:3000/sign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SIGN_TOKEN" \
  -d '{"request":{"method":"POST","path":"/ai/chat","body":{"prompt":"Hello"}}}')

# Step 2: extract the artifact object
ARTIFACT=$(echo "$SIGN_RESPONSE" | node -e "
  const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  process.stdout.write(JSON.stringify(d.artifact));
")

# Step 3: verify (artifact as object, not base64)
curl -s -X POST http://localhost:3000/verify/v2 \
  -H "Content-Type: application/json" \
  -d "{
    \"artifact\": $ARTIFACT,
    \"request\": {\"method\":\"POST\",\"path\":\"/ai/chat\",\"body\":{\"prompt\":\"Hello\"}}
  }"
```

Expected response (HTTP 200):

```json
{
  "decision":   "EXECUTE",
  "reason":     "ALL_CHECKS_PASSED",
  "artifactId": "<uuid-v4>",
  "keyId":      "my-local-dev:key_v1",
  "requestId":  "<uuid-v4>"
}
```

---

## See also

- `docs/guides/quickstart.md` — setup and first run
- `docs/architecture/enforcement-flow.md` — complete runtime decision pipeline with all reason codes
- `docs/architecture/overview.md` — component topology
- `docs/operations/troubleshooting.md` — diagnosis and resolution for all failure modes
- `docs/operations/runbook.md` — key rotation, policy reload, graceful shutdown
