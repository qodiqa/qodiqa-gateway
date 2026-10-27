# `src/middleware/`

Authentication, authorization, administrative protection, and other
application-specific security middleware — behavior specific to QODIQA's
trust model, not generic HTTP plumbing.

Examples in this directory:

- `rbac.js` — RBAC resolution and permission enforcement
- `adminProtection.js` — admin/ops defense-in-depth stack (rate-limit →
  IP-allowlist → ops-auth → RBAC-resolve → permission → diagnostics-gate)
- `opsAuth.js`, `opsIpAllowlist.js`, `opsEnabled.js` — operational endpoint
  authentication and gating
- `healthAuth.js`, `healthLoopback.js` — health/readiness probe security
- `signAuth.js` — signing endpoint authentication
- `apiVersion.js` — API version header stamping

This is distinct from [`middleware/`](../../middleware/README.md), which
holds generic HTTP request/response infrastructure with no QODIQA-specific
authorization logic. See that directory's README for the full distinction.
Both directories are intentional and governed separately by
`.dependency-cruiser.js` (see `docs/architecture/overview.md`).
