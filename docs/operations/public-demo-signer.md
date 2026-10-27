# Public demo: demo signer and seed (operator runbook)

This runbook covers the **product** side of an anonymous public demo. It does not cover hosting, TLS, DNS or the reverse proxy.

**Introduced:** 2026-10-14, launch plan R-02, R-03 and R-10.

## What the demo does

Anonymous visitors cannot hold an `sk_` signing key. Instead:

1. **The demo signer** (`services/demoSigner`, `npm run demo-signer`) holds three server-side demo identities.
   - It is a **separate process**. It is never mounted inside the gateway, so `/demo/*` on the gateway stays 404.
2. For each visitor action, the signer signs exactly one request, `POST /v1/ai/chat` with body `{prompt}`, using the identity for the chosen scenario.
3. It returns `{request, artifactHeader, artifactId, expiresAt}`. An artifact expires in at most 60 s and can be used once.
4. **The visitor's browser** sends exactly `request.body` to `request.path` on the gateway, with header `x-qodiqa-artifact: <artifactHeader>`.
   - Every visitor action therefore runs the gateway's full enforcement path: signature, binding, replay, consent, policy, semantic check and execution invariant.
   - Re-sending the same artifact shows `REPLAY_DETECTED`.
   - Editing the body shows a binding/signature BLOCK.

| Scenario | Identity | Tenant | Deterministic result |
|---|---|---|---|
| `allowed` | `demo-allowed` | `demo` | EXECUTE |
| `consent_revoked` | `demo-revoked` | `demo` | BLOCK `CONSENT_REVOKED` |
| `policy_denied` | `demo-denied` | `demo-denied` (tenant policy `DEMO-DENY-ALL`: `BLOCK_IP` 0.0.0.0/0 + ::/0) | BLOCK `IP_BLOCKED` |

Consent is keyed to the signing identity and the provider, and tenant policy sets replace the global set for that tenant only. That is why each scenario has its own identity, and why the deny scenario has its own tenant.

## 1. Seed (once, idempotent)

```bash
node scripts/demo/seed-demo.js --gateway <internal gateway URL> --environment production --maker-key-file <ok_ file> --reviewer-key-file <ok_ file> --approver-key-file <ok_ file> --maker-otp-file <json> --reviewer-otp-file <json> --approver-otp-file <json> --out-dir <secret dir>
```

**Requirements:**
- **Three distinct operators.** Maker-checker governance applies: the deny policy is drafted by the maker, reviewed by the reviewer, and approved and published by the approver.
- **Gateway admin plane:** must be reachable from where the seed runs.
- **MFA step-up:** required on every mutating admin call in production. Each OTP file is JSON, `{"totpSecret": "...", "recoveryCodes": [...]}`.

**What it does:**
- **Re-running:** changes nothing.
- **Dry run:** `--dry-run` lists the actions without writing anything.
- **Keys:** written to `<out-dir>/<identity>.key` with mode 0600, never overwritten, never printed.

**Consent records:** the seed records lawful basis `consent` and a purpose stating that these are demo scenario identities with no personal data. Both are configurable in `seedDemoLib` (`lawfulBasis`, `purpose`). The choice of lawful basis is an operator decision.

## 2. Demo signer configuration

| Variable | Default | Meaning |
|---|---|---|
| `DEMO_SIGNER_ENABLED` | off | `true` to sign. Anything else is the **kill switch**: every sign request returns 503 `DEMO_DISABLED`. |
| `DEMO_GATEWAY_URL` | — | Internal gateway URL (required when enabled) |
| `DEMO_REDIS_URL` | — | Redis for quotas (required). **Fail-closed:** Redis unavailable → 503 `DEMO_QUOTA_UNAVAILABLE`. |
| `DEMO_KEY_FILE_ALLOWED` / `_REVOKED` / `_DENIED` | — | Key files from the seed. Mode 0600 or tighter is enforced on POSIX. Each must hold a distinct identity. |
| `DEMO_IP_HASH_SECRET` | — | ≥ 32 characters. Quota keys and logs use an HMAC of the client IP, never the address. |
| `DEMO_PER_IP_PER_MIN` / `_PER_DAY` | 10 / 50 | Per-client quotas |
| `DEMO_GLOBAL_PER_MIN` | 30 | Global quota. Start-up refuses values above 50: every visitor shares the demo identities, so the gateway's per-identity `/sign` (60/min), anomaly (100/min) and policy (100/min) ceilings are global. |
| `DEMO_MAX_PROMPT_CHARS` | 2000 | Prompt cap, in code points. `stream`, `model` and unknown fields are refused. |
| `DEMO_TRUSTED_PROXY` | `loopback` | Proxies whose `X-Forwarded-For` is honoured. Same format as the gateway's `TRUSTED_PROXY`. |
| `DEMO_ALLOWED_ORIGIN` | none | The single browser origin allowed by CORS. No credentials. |
| `DEMO_CHAT_PATH` | `/v1/ai/chat` | Must match the path the browser posts to (it is bound into the artifact) |

**On any invalid setting,** the signer refuses to start and lists every problem.

## 3. Gateway settings for a public demo (data minimisation, R-10)

| Setting | Why |
|---|---|
| `LOG_SANITIZER_REDACT_IP=true` | Visitor IPv4 **and IPv6** addresses become `[IP]` in logs. IPv6 is covered since S-02. |
| `LOCAL_MAX_TOKENS=<n>` (e.g. 256) | Caps each answer from the local model, bounding compute per anonymous request (R-06) |
| `PROVIDER_ALLOWED_MODELS_LOCAL=<model>` | Only the pulled demo model can be called (R-07) |
| `PROVIDER_DEFAULT_MODEL_LOCAL=<model>` | The signer never sends `model`; the gateway uses this default |
| `QODIQA_ADMIN_ENABLED=false`, `QODIQA_DIAGNOSTICS_ENABLED=false`, `QODIQA_PORTAL_ENABLED` unset | The operator plane stays off on the public instance. Since R-09 / OD-3 a disabled plane answers **404 to every caller before authentication**, so its routes are not enumerable (anonymous sweep: 1 enumerable route, the public `POST /sign`). Still route only the demo operations publicly (defence in depth). |

**Not changed by the demo, and disclosed instead:**
- **Audit records:** the audit chain keeps unsalted hashes of each request and output permanently. These records are excluded from erasure.
- **Idempotency cache:** the signer never forwards or sets `Idempotency-Key`, and browsers cannot send it cross-origin (it is not an allowed CORS header). So no demo output is cached by idempotency.

## 4. Emergency stop

| Need | Action | Effect |
|---|---|---|
| Stop new demo signatures | Restart the signer with `DEMO_SIGNER_ENABLED=false` | 503 `DEMO_DISABLED` for every request |
| Stop already-issued artifacts too | `node scripts/revoke-signing-identity.js --name demo-allowed --reason "<why>"` (repeat for the other identities) | `/sign` with that key → 401. Any artifact minted before → BLOCK `SIGNING_IDENTITY_REVOKED` at `/ai/chat`. Propagates within the bound (5 s). |
| Resume | `node scripts/provision-signing-identity.js --name demo-allowed --tenant-id demo --environment <env> --rotate`, write the new key to the key file (0600), restart the signer | The revoked key never comes back |

## 5. Verification

| What | Tests |
|---|---|
| Unit | `npx jest services/demoSigner scripts/demo src/core/signing services/policy` |
| Real gateway, real PostgreSQL and Redis, stub provider | `bash npx jest test/integration/revokeSigningIdentity.integration.test.js --runInBand` |
