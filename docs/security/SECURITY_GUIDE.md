# QODIQA Security Hardening Guide

**Version:** 1.0

**Last Updated:** 2026-07-02

---

## 1. Overview

This guide is the master reference for all security hardening controls introduced. It supplements the detailed per-subsystem documentation in this directory with an operational perspective: what was implemented, how to configure it, and how to verify it is active.

QODIQA is a Node.js 22 + Express 4 AI enforcement gateway., the system had foundational security controls (CORS allowlist, HSTS, X-Frame-Options, signed artifacts). hardened the attack surface across seven domains: HTTP security headers, container runtime, network transport, reverse proxy validation, process runtime, filesystem, and supply chain.

### Controls Summary

| Phase | Control | File |
|-------|---------|------|
| 46.6 | Dependency supply chain verification | `scripts/verify-supply-chain.js` |
| 46.7 | CycloneDX 1.5 SBOM generation | `scripts/generate-sbom.js` |
| 46.8 | Dependency integrity verification | `scripts/verify-deps.js` |
| 46.9 | Secret scanning (gitleaks) | `.gitleaks.toml` |
| 46.10 | Container security hardening | `Dockerfile` |
| 46.11 | Path traversal protection | REMOVED as dead code — see §7 for the current, accurate state |
| 46.12 | Runtime process hardening | `src/runtime/processHardening.js` |
| 46.13 | HTTP transport timeouts | `src/infra/network/tlsDefaults.js` |
| 46.14 | Permissions-Policy header | `src/infra/security/headers.js` |
| 46.15 | Content Security Policy (API_CSP + PORTAL_CSP) | `src/infra/security/csp.js` |
| 46.16 | Proxy chain validation | `src/infra/network/proxyValidation.js` |
| 46.CI | GitHub Actions security pipeline | `.github/workflows/security.yml` |

---

## 2. Security Headers

All security headers are applied via `src/infra/security/headers.js` (Helmet v8 wrapper) and `src/infra/security/csp.js` (CSP per-response override).

### 2.1 Content Security Policy

QODIQA maintains two CSP policies:

#### API_CSP (applied to all `res.json()` responses)

```
default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none';
connect-src 'none'; font-src 'none'; object-src 'none'; media-src 'none';
frame-src 'none'; worker-src 'none'; manifest-src 'none';
frame-ancestors 'none'; base-uri 'none'; form-action 'none'
```

This is the strictest possible CSP. All resource loading and scripting is denied. Applied to the large majority of QODIQA traffic (JSON enforcement API responses).

**Implementation:** `src/infra/security/csp.js` — `createCspMiddleware()` patches `res.json()` to set `API_CSP` before headers are sent.

#### PORTAL_CSP (applied to HTML responses via Helmet global CSP)

```
default-src 'none'; script-src 'self';
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;
connect-src 'self'; worker-src 'none'; object-src 'none'; media-src 'none';
manifest-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'none'
```

**(remediated):** `script-src` no longer carries `'unsafe-inline'`. Every inline `<script>` block and inline event-handler attribute (`onclick`, `onchange`, `oninput`, …) previously present in `public/*.html` has been moved to external files under `public/js/*.js`, referenced via `<script src="…" defer>`; dynamically-generated markup uses `data-action`/`data-*` attributes resolved by a delegated `addEventListener` listener instead of inline `onclick="…"` strings. `script-src 'self'` alone is now sufficient, and any future inline-script regression is blocked by the browser rather than silently executing.

`style-src` still carries `'unsafe-inline'` — the portal pages use inline `<style>` blocks, a separate, lower-severity concern (style injection cannot achieve script execution) out of scope for. Required for Google Fonts and same-origin styling.

### 2.2 Permissions-Policy

All 28 browser features are denied:

```
accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(),
cross-origin-isolated=(), display-capture=(), document-domain=(),
encrypted-media=(), execution-while-not-rendered=(),
execution-while-out-of-viewport=(), fullscreen=(), geolocation=(),
gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(),
navigation-override=(), payment=(), picture-in-picture=(),
publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(),
wake-lock=(), web-share=(), xr-spatial-tracking=()
```

**Implementation:** Added by the `securityHeaders` wrapper in `headers.js` after Helmet's header pass, because Helmet v8 does not include a Permissions-Policy helper.

### 2.3 Complete Header Set

| Header | Value | Applied By |
|--------|-------|------------|
| `Content-Security-Policy` | `API_CSP` (JSON) or `PORTAL_CSP` (HTML) | `csp.js` + Helmet |
| `Permissions-Policy` | All 28 features denied | `headers.js` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (production only) | Helmet |
| `X-Frame-Options` | `DENY` | Helmet |
| `X-Content-Type-Options` | `nosniff` | Helmet |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Helmet |
| `X-DNS-Prefetch-Control` | `off` | Helmet |
| `X-Download-Options` | `noopen` | Helmet |
| `X-Permitted-Cross-Domain-Policies` | `none` | Helmet |
| `Cross-Origin-Opener-Policy` | `same-origin` | Helmet |
| `Origin-Agent-Cluster` | `?1` | Helmet |
| `X-XSS-Protection` | `0` (disabled — legacy header misleads browsers) | Helmet |
| `X-Powered-By` | Removed | Helmet |

### 2.4 CORS Headers

CORS is managed by `src/infra/cors/corsPolicy.js`:

| Setting | Value | Rationale |
|---------|-------|-----------|
| `origin` | Explicit allowlist from `QODIQA_ALLOWED_ORIGINS` | No wildcard; fail-closed if unset in production |
| `methods` | `GET, HEAD, POST, OPTIONS` | No PUT/PATCH/DELETE for browser clients |
| `allowedHeaders` | `Content-Type, Authorization, X-Ops-Token, X-Request-ID, X-Qodiqa-Artifact` | Explicit; no implicit reflection |
| `exposedHeaders` | `X-Request-ID, Content-Disposition` | Minimal exposure |
| `credentials` | `false` | Bearer token model; no cookies |
| `maxAge` | `86400` | Preflight cached for 24 hours |

---

## 3. Container Security Controls

All container security controls are documented in the Dockerfile and must be enforced at runtime via the Docker run command or container orchestrator configuration.

### 3.1 Non-Root User

```dockerfile
RUN addgroup --system --gid 1000 qodiqa \
 && adduser  --system --uid 1000 --ingroup qodiqa \
             --no-create-home --shell /sbin/nologin qodiqa
...
USER qodiqa
```

The process runs as uid/gid 1000 with no login shell and no home directory. It cannot write to files owned by `root`, even within the container.

### 3.2 File Permissions

```dockerfile
# Application files: root:qodiqa ownership, mode 0750, from an allow-listed build context
COPY --chown=root:qodiqa --chmod=0750 . .

# Runtime directories: qodiqa-owned, restricted permissions
RUN mkdir -p /opt/qodiqa/data /opt/qodiqa/logs /opt/qodiqa/config /opt/qodiqa/anchors \
 && chown -R qodiqa:qodiqa /opt/qodiqa \
 && chmod 700 /opt/qodiqa/data /opt/qodiqa/logs /opt/qodiqa/anchors \
 && chmod 750 /opt/qodiqa/config
```

- `/app/` files: `root:qodiqa` ownership, mode `0750` (rwxr-x---) — process can read and run, cannot write
- `/opt/qodiqa/data/`: mode `700` (rwx------) — process can read/write own data files
- `/opt/qodiqa/logs/`: mode `700` — process can write audit log
- `/opt/qodiqa/config/`: mode `750` — process can read config files

### 3.3 Dropped Capabilities

Required Docker run flags:

```bash
docker run \
  --read-only \
  --user 1000:1000 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=deploy/docker/seccomp.json \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -p 127.0.0.1:3000:3000 \
  qodiqa:1.0.0
```

| Flag | Effect |
|------|--------|
| `--read-only` | Root filesystem read-only; no file modification in `/app` |
| `--user 1000:1000` | Non-root uid/gid |
| `--cap-drop ALL` | Removes all Linux capabilities including `CAP_NET_RAW`, `CAP_PTRACE`, `CAP_SYS_ADMIN` |
| `--security-opt no-new-privileges:true` | Process cannot gain privileges via setuid/setgid binaries |
| `--security-opt seccomp=...` | Custom seccomp profile restricts available system calls |
| `--tmpfs /tmp:rw,noexec,nosuid,size=64m` | Writable `/tmp` limited to 64 MiB; `noexec` prevents execution; `nosuid` prevents privilege escalation |

### 3.4 Build Context and Image Content

The image is built from an allow-listed `.dockerignore` (everything is excluded, only runtime inputs are re-included), and the Dockerfile fails the build if keys, certificates, keystores or `.env` files reach `/app`.

### 3.5 `node_modules` Ownership

```dockerfile
COPY --from=deps --chown=root:qodiqa /build/node_modules ./node_modules
```

`node_modules` is owned by `root:qodiqa`. The `qodiqa` process (uid 1000) can read packages but cannot modify, add, or delete installed packages. This prevents an attacker with process-level code execution from patching installed modules at runtime.

---

## 4. Network Hardening

### 4.1 HTTP Transport Timeouts

Applied by `src/infra/network/tlsDefaults.js` — `configureTlsDefaults(server)` called after `app.listen()` in `server.js`.

| Setting | Default | Env Var Override | Rationale |
|---------|---------|-----------------|-----------|
| `server.keepAliveTimeout` | 65,000 ms (65 s) | `KEEP_ALIVE_TIMEOUT_MS` | Above typical proxy keep-alive of 60 s; prevents keep-alive exhaustion (Slowloris variant) |
| `server.headersTimeout` | 66,000 ms (66 s) | `HEADERS_TIMEOUT_MS` | Must be > `keepAliveTimeout` to avoid Node.js race condition; blocks Slowloris |
| `server.requestTimeout` | 120,000 ms (120 s) | `REQUEST_TIMEOUT_MS` | Limits slow-body attacks |
| `server.maxHeadersCount` | 100 | `MAX_HEADERS_COUNT` | Prevents header-flood memory exhaustion |

**Invariant:** `headersTimeout` > `keepAliveTimeout` is enforced at startup — misconfiguration causes `process.exit(1)` with a structured error.

**Optional:** `server.maxConnections` can be set via `MAX_HTTP_CONNECTIONS`. Defaults to unlimited (safe behind a load balancer with its own connection limits).

### 4.2 TLS

Node.js 22 built-in TLS defaults:
- Minimum version: TLS 1.2
- SSLv3, TLS 1.0, TLS 1.1: not negotiated
- No explicit override required; this behavior is documented and tested

---

## 5. Proxy Validation

Applied by `src/infra/network/proxyValidation.js` — `createProxyValidationMiddleware()` registered early in the Express chain.

### 5.1 X-Forwarded-For Chain Depth

```javascript
const MAX_FORWARDED_DEPTH = parseInt(process.env.MAX_FORWARDED_DEPTH || '10', 10);
```

Each entry in the `X-Forwarded-For` chain must:
1. Be a syntactically valid IP address (verified via `net.isIP()`)
2. Not exceed `MAX_FORWARDED_DEPTH` entries (default 10)

A chain exceeding the depth limit or containing an invalid IP returns:
```json
{ "decision": "BLOCK", "reason": "PROXY_CHAIN_TOO_DEEP" }
{ "decision": "BLOCK", "reason": "INVALID_FORWARDED_IP" }
```

### 5.2 X-Forwarded-Proto Validation

In production (`NODE_ENV=production`) with `ENFORCE_HTTPS_PROTO` not set to `false`:

- Requests where `X-Forwarded-Proto` is not `https` return `{ "decision": "BLOCK", "reason": "INSECURE_PROTOCOL" }`
- This ensures requests that arrived at the load balancer over plain HTTP are rejected at the application layer

### 5.3 Host Header Allowlist

Configure `QODIQA_ALLOWED_HOSTS` (comma-separated hostnames, without port):

```
QODIQA_ALLOWED_HOSTS=api.example.com,portal.example.com
```

Requests with a `Host` header not in the allowlist return `{ "decision": "BLOCK", "reason": "INVALID_HOST_HEADER" }`.

**Warning:** A startup warning is emitted if `QODIQA_ALLOWED_HOSTS` is not set in production:
> `QODIQA_ALLOWED_HOSTS is not set in production. Set it to the expected hostname(s) of this deployment to prevent host header injection attacks.`

### 5.4 TRUSTED_PROXY Configuration

Set `TRUSTED_PROXY` to the specific IP or CIDR of your reverse proxy:

```
TRUSTED_PROXY=10.0.1.5        # single proxy IP
TRUSTED_PROXY=10.0.0.0/24    # proxy subnet
```

**Do not use:** `TRUSTED_PROXY=*`, `TRUSTED_PROXY=0.0.0.0/0` — these trust all upstream IPs and allow any client to forge `X-Forwarded-*` headers. The startup `validateProxyConfig()` call emits a FATAL-level warning for wildcard patterns.

`TRUSTED_PROXY` is the single source of truth for trust-boundary decisions
across the whole process — the same parsed value is used for Express's own
`trust proxy` setting (`server.js`) AND for `req.clientIp` resolution
(`src/infra/network/clientIpResolver.js`, wired via `middleware/clientIp.js`).
`req.clientIp` feeds audit logging, rate limiting, and anomaly detection, so
misconfiguring `TRUSTED_PROXY` affects all of them identically — there is no
separate "trust proxy for logging" vs. "trust proxy for routing" setting to
keep in sync. Named presets are supported (`loopback` — the default — `linklocal`, `uniquelocal`; `uniquelocal` is fatal in production without `QODIQA_TRUSTED_PROXY_BROAD_ACK=true`), matching the same IANA-reserved ranges Express
uses for its built-in presets.

### 5.5 Startup Validation

`validateProxyConfig(env)` is called at startup and emits structured warnings for:
- Wildcard `TRUSTED_PROXY`
- `TRUSTED_PROXY` not set in production
- `ENFORCE_HTTPS_PROTO=false` in production
- `QODIQA_ALLOWED_HOSTS` not set in production

---

## 6. Process Hardening

Applied by `src/runtime/processHardening.js` — `applyProcessHardening()` is the **first** call in `server.js`, before `require('dotenv').config()` or any other initialization.

### 6.1 Process Title

```javascript
process.title = 'qodiqa-gateway';
```

Replaces Node.js default title (which is the full command line, potentially including env var values on some platforms) with a safe, fixed identifier. Visible in `ps`, `top`, and container runtime process lists.

### 6.2 umask Enforcement

```javascript
process.umask(0o027);
```

Forces file creation mode to `640` (rw-r-----) for files and `750` (rwxr-x---) for directories. Prevents newly created audit log entries, key files, and config files from being world-readable.

Applied only if `process.umask()` is available (not in Worker threads).

### 6.3 Unhandled Rejection / Exception Handlers

```javascript
process.on('unhandledRejection', (reason) => {
  log('FATAL', 'UNHANDLED_REJECTION', { message: reason.message });
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  log('FATAL', 'UNCAUGHT_EXCEPTION', { message: err.message });
  process.exit(1);
});
```

Both handlers:
1. Emit a structured log event with only the `message` field (no stack trace, no file paths)
2. Call `process.exit(1)` immediately

**Rationale:** An unhandled rejection/exception leaves the process in an unknown state. Crashing fast is safer than continuing in a potentially corrupt state. The container orchestrator (Kubernetes, ECS) will restart the process.

### 6.4 Cluster Worker Prevention

```javascript
if (cluster.isWorker) {
  log('FATAL', 'PROCESS_CLUSTER_WORKER_DETECTED', { ... });
  process.exit(1);
}
```

QODIQA's hash-chained audit log assumes a single writer per process. Running as a Node.js cluster worker would create a split-brain audit log. Use a process manager (PM2 fork mode, systemd) with a single worker per audit log file.

### 6.5 NODE_ENV Validation

A warning is emitted if `NODE_ENV` is not set. The following controls are only active when `NODE_ENV=production`:
- HSTS (`Strict-Transport-Security`)
- Strict secret validation (exits on weak secrets)
- X-Forwarded-Proto enforcement
- PostgreSQL TLS by default

---

## 7. Filesystem Hardening

A dedicated path-validation module (which would have exported `resolveSafe()`, `validateConfigPath()`, and `assertWithinBase()`) was built during planning but was never wired into any call site — a repository-wide grep found zero non-test importers — and was removed as dead code. None of those three functions, nor the module itself, exists in the current codebase.

The only path-safety mechanism that actually exists today is `src/infra/secrets/secretValidation.js`'s `_checkProductionKeystorePath()`:

- Applies to `QODIQA_KEYS_PATH` only.
- Runs in production (`NODE_ENV=production`) only.
- Rejects a resolved path that lies inside the project root — an app-root-containment check — causing startup to fail closed (`assertSecretsValid()`).
- Does **not** block `..` sequences or NUL bytes, perform any general traversal validation, or resolve symlinks.

`QODIQA_AUDIT_LOG` and `POLICY_FILE` have no equivalent check in any environment — a misconfigured value for either is not caught by any application-level control today. See `docs/security/THREAT_MODEL.md` §7.3/§7.4 for the full, current statement of this residual risk.

---

## 8. Operational Security Checklist

### 8.1 Pre-Deployment Checklist

| Check | Command / Verification |
|-------|------------------------|
| All CI security jobs pass | Check GitHub Actions status on latest commit |
| No HIGH/CRITICAL CVEs | `npm audit --audit-level=high` |
| `NODE_ENV=production` set | Verify in deployment manifest |
| `QODIQA_KEY_ENCRYPTION_KEY` is not a placeholder | `secretValidation.js` will abort startup if weak |
| At least one signing identity is provisioned | there is no `QODIQA_SIGN_TOKEN` shared secret — each caller's `sk_...` key is always server-generated via `crypto.randomBytes(32)` (`signingIdentityStore.js`), never user-supplied, so `secretValidation.js` does not weak-check it (see its own comment on why) |
| `TRUSTED_PROXY` is set to proxy IP/CIDR | Check startup logs for `CORS_VALIDATION_WARN` |
| `QODIQA_ALLOWED_HOSTS` is set | Check startup logs for proxy validation warnings |
| `QODIQA_ALLOWED_ORIGINS` is set | Check startup logs for `CORS_VALIDATION_WARN` |
| `QODIQA_PG_SSL=true` in production | PostgreSQL TLS required |
| Docker flags: `--read-only --cap-drop ALL --security-opt no-new-privileges:true` | Verify container runtime config |
| `/opt/qodiqa/data`, `/opt/qodiqa/logs` mounted as volumes | Verify Docker/K8s volume mounts |
| Redis `maxmemory-policy noeviction` for nonce store | Verify Redis configuration |

### 8.2 Runtime Monitoring Alerts

The following structured log events should trigger alerts:

| Event | Level | Action |
|-------|-------|--------|
| `ANOMALY_THRESHOLD_EXCEEDED` | WARN | Investigate burst source; check for key compromise |
| `NONCE_STORE_ERROR` | ERROR | Check Redis connectivity; executions are blocked |
| `ANOMALY_STORE_UNAVAILABLE` | ERROR | Check Redis; executions are blocked |
| `TENANT_KEY_EXPIRED_ACTIVE` | CRITICAL | Rotate key immediately |
| `TENANT_KEY_PROVISIONING_FAILED` | CRITICAL | Manual key provisioning required |
| `UNHANDLED_REJECTION` | FATAL | Process restarting; investigate root cause |
| `UNCAUGHT_EXCEPTION` | FATAL | Process restarting; investigate root cause |
| `SECRET_VALIDATION_FAILED` | FATAL | Weak secret in production; replace immediately |
| `CORS_VALIDATION_FATAL` | FATAL | Invalid `QODIQA_ALLOWED_ORIGINS`; fix before restart |
| `KEY_ROTATION_OVERDUE` | WARN | Schedule key rotation |
| `KEY_EXPIRING_SOON` | WARN | Plan key rotation |
| `KEY_ROTATION_SCHEDULER_FAILED` | ERROR | Automatic rotation failed after retries; investigate KMS/provider connectivity, rotate manually if needed |
| `KEY_ROTATION_SCHEDULER_RELOAD_FAILED` | WARN | Instance could not reload `keys.json`; investigate file corruption or permissions |
| `KEY_ROTATION_PROVIDER_DEPRECATE_FAILED` | ERROR | Native signing provider (Vault Transit/HSM) rejected key deprecation; rotation aborted, old key still active |

### 8.3 Key Rotation

```bash
# Rotate the active signing key pair for a tenant:
curl -X POST https://api.example.com/key-admin/my-tenant/rotate \
  -H "X-Ops-Token: ok_<your-ops-token>"
```

`/key-admin/{clientId}/rotate` is **emergency** rotation: the new key becomes active and the old key is revoked at once, so in-flight artifacts signed with it stop verifying. For planned, zero-downtime rotation use `POST /key-admin/{clientId}/rotate-graceful` (or the scheduler): the old key is deprecated and verifies only artifacts signed before its retirement, and only for the deprecated-key window (max artifact age + skew, `src/validation/keyLifecycle.js`). Both routes require `MANAGE_KEYS`, plus MFA step-up whenever MFA is required (`src/middleware/mfaStepUp.js`) — in that case a shared ops token with no enrolled operator identity is refused (`MFA_ENROLLMENT_REQUIRED`). (previously described `/rotate` as keeping the old key verifiable until expiry.)

An automatic rotation scheduler also runs continuously (`QODIQA_KEY_ROTATION_SCHEDULE`, default `monthly`), rotating each client's key without operator action. In multi-instance deployments, a Redis-backed distributed lock ensures only one instance performs a given rotation, and every instance periodically reloads the key store so the change is visible fleet-wide without a manual restart. Check current status via:

```bash
curl https://api.example.com/key-admin/rotation-scheduler/status \
  -H "X-Ops-Token: ok_<your-ops-token>"
```

See `docs/security/key-management.md` — "Automatic rotation scheduler" for the full configuration and cluster-safety model.

---

## 9. Known Security Limitations and Assumptions

### 9.1 `'unsafe-inline'` in PORTAL_CSP — remediated

`PORTAL_CSP` previously included `script-src 'unsafe-inline'` because portal HTML files contained substantial inline script blocks and event-handler attributes. This has been remediated: every inline `<script>` block was moved to an external file under `public/js/*.js` (referenced via `<script src="…" defer>`), and every `onclick`/`onchange`/`oninput` attribute — including ones generated dynamically inside template-literal HTML strings — was converted to `data-action`/`data-*` attributes resolved by a single delegated `document.addEventListener(...)` per event type. `script-src` is now `'self'` only, in both `src/infra/security/csp.js` (`PORTAL_CSP`) and `src/infra/security/headers.js` (Helmet's `contentSecurityPolicy` directive).

`style-src 'unsafe-inline'` remains — the portal pages still use inline `<style>` blocks. This is a separate, lower-severity concern (style injection cannot achieve script execution) not addressed.

### 9.2 KEK in Environment Variable

The default key provider (`QODIQA_KMS_PROVIDER=local`) stores the Key Encryption Key in the `QODIQA_KEY_ENCRYPTION_KEY` environment variable. In shared container environments, environment variables may be visible to co-tenants via `docker inspect`, `/proc/self/environ`, or similar vectors.

**Recommendation:** Use an external KMS provider in production:

| Provider | `QODIQA_KMS_PROVIDER` Value |
|----------|------------------------------|
| HashiCorp Vault KV | `vault-kv` |
| HashiCorp Vault Transit (native signing) | `vault-transit` |
| AWS KMS | `aws-kms` |
| Azure Key Vault | `azure-kv` |
| Google Cloud KMS | `gcp-kms` |
| PKCS#11 HSM | `hsm` |

### 9.3 Redis as Single Point of Failure for Nonce Enforcement

If Redis becomes unavailable, `registerNonce()` returns `NONCE_STORE_ERROR` and all enforcement executions are blocked (fail-closed). This is the correct security behavior but creates an availability dependency.

**Mitigations:** Redis persistence (`appendonly yes`); Redis replica for failover; Redis Sentinel or Cluster for high availability.

### 9.4 Process Memory and Key Material

Ed25519 private keys are decrypted into process memory during signing operations. Node.js does not provide guaranteed memory zeroing. A memory disclosure vulnerability (e.g., in a native module or Node.js itself) could expose key material.

**Recommendation:** Use `vault-transit` or `hsm` key provider to keep private key material outside the QODIQA process entirely.

### 9.5 Symlink Resolution

No application-level path-containment mechanism exists for `QODIQA_KEYS_PATH`, `QODIQA_AUDIT_LOG`, or `POLICY_FILE` (see §7) — there is no `../`-escape guard for a symlink to bypass in that sense. The one real check, `secretValidation.js`'s `_checkProductionKeystorePath()`, also does not call `fs.realpathSync()`, so a symlink pointed at by `QODIQA_KEYS_PATH` that resolves outside the project root would not be caught by it either.

**Mitigation:** OS-level filesystem permissions prevent unauthorized symlink creation. Container read-only filesystem prevents any file creation in `/app`.

### 9.6 Audit Log File Backup

The file-based hash-chained audit log is not automatically backed up. If the audit log file is destroyed (disk failure, accidental deletion), audit evidence is lost even though the PostgreSQL copy remains.

**Recommendation:** Configure periodic backup of `/opt/qodiqa/logs/` to object storage; monitor `getChainLength()` telemetry for unexpected resets.

---

## 10. Admin/Ops Endpoint Defense-in-Depth

Every Admin/Ops route (audit, rbac, key-admin, consent, webhooks, evidence,
transparency/portal/attestation/certification admin surfaces, policy
simulation/visualization, organization/tenant administration, etc.) is
composed from the **same** ordered stack of independent layers, built once
by `createAdminProtection()` (`src/middleware/adminProtection.js`) and
consumed in `server.js` as `_adminStack(permission)`. No route can omit or
reorder a layer, because no route assembles the stack itself — one factory
does, for all of them.

RBAC (`src/middleware/rbac.js`) remains the authoritative authorization
mechanism throughout — see `RBAC_MODEL.md`. The layers below are additive
defense-in-depth around it, not a replacement for it.

### 10.1 The stack, in order

| # | Layer | Module | Behavior |
|---|-------|--------|----------|
| 1 | Rate limit | `src/core/rateLimit/middleware.js` (`ops_admin` surface) | Per-identity sliding-window throttle, applied **before** any auth/RBAC work — blunts credential-stuffing and brute-force attempts against ops credentials. `QODIQA_OPS_RATE_LIMIT_MAX` / `_WINDOW_MS` (default 120 req/60s). Redis-backed and shared across every instance in a multi-replica deployment — see §10.3. |
| 2 | IP allowlist | `src/middleware/opsIpAllowlist.js` | Opt-in (`QODIQA_OPS_IP_ALLOWLIST_ENABLED`), fail-closed network-layer restriction. |
| 3 | Ops auth | `src/middleware/opsAuth.js` | Per-operator API key (preferred) or deprecated shared token. Fail-closed 401. |
| 4 | RBAC resolve | `src/middleware/rbac.js` (`createRbacResolveMiddleware`) | Requires a resolved identity; 403 if none. |
| 5 | Permission (per-mount) | `src/middleware/rbac.js` (`createRequirePermission`) | Requires the specific permission for that mount, where one applies (some mounts — e.g. `/rbac`, `/policy-ui` — gate permissions per sub-route internally instead; see each router's own `requirePermission` usage). |
| 6 | Plane gate (kill switch) | `src/middleware/opsEnabled.js` | Admin stack: `QODIQA_ADMIN_ENABLED`; `/metrics`/`/diagnostics`: `QODIQA_DIAGNOSTICS_ENABLED` — two independent switches, both default `false` in production. Returns 404 — not 401/403 — so a disabled surface cannot be distinguished from a nonexistent one. |

`/metrics` and `/diagnostics` intentionally use a coarser variant
(`_opsOnlyStack()`: rate limit → IP allowlist → ops auth → diagnostics gate, no RBAC)
because they expose only non-sensitive aggregate operational signals —
see `RBAC_MODEL.md` §6. `/health` and `/ready` use a separate, documented
model tuned for orchestrator probe compatibility (`docs/deployment/kubernetes-probes.md`)
and are not part of the Admin surface.

### 10.2 Task #27 remediation (defense-in-depth audit)

A repository-wide audit of every Admin route found the stack above already
applied almost everywhere, with one inconsistency: `/key-admin` was missing
the ops-gate kill-switch layer that every sibling Admin route had. Migrating
every mount onto the single shared factory fixed this as a natural
consequence of centralization — `/key-admin` now respects
the admin kill switch like every other Admin route. No RBAC
permission, role, or success-response shape changed for any route.

The audit also added:
- Rate limiting across the entire Admin surface (previously only
  `/health`/`/ready` had it).
- Explicit `405 METHOD_NOT_ALLOWED` catch-alls on the Admin routers that
  lacked one, matching each router's own established response-envelope
  convention (several distinct conventions pre-exist across the routes
  directory — this remediation did not unify them, only ensured each router
  applies its own convention consistently to unsupported methods).
- A fail-closed fix in `src/api/routes/policyProvenance.js`, which
  previously treated a missing `requirePermission` injection as a signal to
  grant expanded content visibility (`isInvestigator = ... || !requirePermission`)
  rather than denying. `requirePermission` is now a mandatory constructor
  argument, matching the stricter pattern already used by
  `src/api/routes/rbacAdmin.js` and `src/api/routes/prqDlq.js`.

### 10.3 distributed rate limiting on every remaining route

Every public, verification, and administrative endpoint now enforces its
rate limit via the distributed, Redis-backed limiter at
`src/core/rateLimit/middleware.js` (`createRateLimitMiddleware`) — the same
implementation already used by the certification, attestation, transparency,
portal, webhooks, and sign/verify-auth surfaces. This closed the last
remaining High-severity gap where a handful of routes (`/verify`,
`/verify/v2`, `/audit/*`, `/audit-viewer/*`, `/evidence-chain/*`,
`/evidence/*`, `/keys`, `/public-keys`, `/policy-ui/*`, `/provenance/*`,
`/rbac/*`, `/.well-known/qodiqa/keys`, plus the ops-boundary `/health` and
admin rate limiters in `server/startup.js`) still used
`middleware/publicRateLimit.js` — an in-memory, single-process limiter. In a
horizontally-scaled deployment, each replica enforced its own independent
counter under that limiter, so the effective limit was `configured limit ×
replica count` instead of the configured limit.

**`middleware/publicRateLimit.js` is now deprecated** and retained only for
its own unit tests and a couple of pre-existing rate-limiter-algorithm tests
— new code must never import it. In a multi-instance deployment
(`QODIQA_AUDIT_ORDERING_MODE=distributed`), `src/core/rateLimit/
startupGuard.js` walks the fully-mounted Express app at boot and refuses to
start if any route still mounts the legacy limiter, closing the gap
permanently rather than relying on code review alone.

## 11. Document Index

| Document | Phase | Description |
|----------|-------|-------------|
| `THREAT_MODEL.md` | 46.1 | Assets, trust boundaries, entry points, attack surfaces |
| `STRIDE_ANALYSIS.md` | 46.2 | STRIDE threat analysis for every subsystem |
| `ASVS_CONTROL_MATRIX.md` | 46.3 | OWASP ASVS v4.0 control mapping (V1–V14) |
| `API_SECURITY_OWASP.md` | 46.4 | OWASP API Security Top 10 2023 validation |
| `MITRE_ATTACK_MAPPING.md` | 46.5 | MITRE ATT&CK Enterprise technique mapping |
| `SUPPLY_CHAIN_SECURITY.md` | 46.6–46.9 | Supply chain verification, SBOM, secret scanning, CI |
| `SECURITY_GUIDE.md` | 46 | This document — operational security reference |
