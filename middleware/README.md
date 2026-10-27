# `middleware/`

Generic HTTP request/response infrastructure — behavior that would be the
same in any Express service, regardless of what QODIQA does.

Examples in this directory:

- `requestId.js` — request ID generation
- `clientIp.js` — trusted-proxy-aware client IP resolution
- `enforceContentType.js` — content-type enforcement
- Policy enforcement is not a middleware here. The real chain is `src/api/routes/aiChat.js` / `src/api/routes/verify.js`
  → `src/validation/checkPolicy.js` → `services/policy/evaluatePolicyDecision.js` → `services/policy/engine.js`
.

This is distinct from [`src/middleware/`](../src/middleware/README.md),
which holds authentication, authorization, administrative protection, and
other application-specific security middleware. See that directory's README
for the full distinction. Both directories are intentional and governed
separately by `.dependency-cruiser.js` (see `docs/architecture/overview.md`).
