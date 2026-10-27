# API Versioning

## Current state: `/v1` is a cosmetic alias, by design

>  This section previously said every `/v1/*` route is the same
> router already mounted at the corresponding unversioned path. That is true only for the dual-mounted routes.
> Only the core protocol routes are dual-mounted (`/ai/chat`, `/ai/chat/stream`, `/verify`,
> `/verify/v2`, the portal, transparency and evidence-package surfaces — 27 paths). Several surfaces exist only
> unversioned (`/sign`, `/consent`, `/audit`, `/rbac`, `/key-admin`, …) or only under `/v1`
> (`/v1/webhooks`, `/v1/admin/*`, …). `docs/api/openapi.json` is the authoritative path list.
> `app.use('/v1', createApiVersionMiddleware())` only stamps a header; it does not rewrite paths.

Where a route is mounted under both `/v1/*` and its unversioned path (`/v1/ai/chat`, `/v1/verify`,
`/v1/verify/v2`, `/v1/portal`, `/v1/evidence`, `/v1/transparency`), the two mount points share the **identical
router instance** — see `server.js`'s route-mounting section and `src/middleware/apiVersion.js`. There is currently exactly one API version, so
there is no behavioral difference between calling a path with or without the
`/v1` prefix; the only thing `/v1` adds today is the `X-QODIQA-API-Version`
response header, stamped by `createApiVersionMiddleware()`.

This is a deliberate, disciplined choice for a genuinely single-version API —
reusing one router instance for both mount points makes version drift
*structurally impossible* (there is no second copy of the handler to
accidentally diverge).,
finding **API-6**, for the full audit rationale; its own conclusion is "fine
to ship as-is."

## What this means for integrators

Calling `/v1/x` today does **not** carry the usual guarantee that a real API
version implies — "this path's behavior is pinned to v1 semantics forever,
even after `/v2` ships" — because there is no `/v2` yet, so that guarantee has
never been exercised. It holds today only because there is exactly one
version. This is a known, accepted latency cost documented here rather than a
defect: the real version-branch-point architecture (a router-factory-per-version
pattern) will be designed *when* a genuinely breaking `/v2` is actually needed,
not preemptively — building that machinery now, for a version that doesn't
exist, would be speculative infrastructure with no way to validate it's
correct until it's actually used.

## What IS real today: Deprecation/Sunset headers

Individual routes can be marked deprecated independently of the `/v1` prefix,
using the shared helper `src/middleware/deprecation.js`
(`sendDeprecationHeaders()`), which sets RFC 8594 `Deprecation`/`Sunset`/`Link`
response headers and emits a structured `WARN` log event. This replaces two
previously-duplicated, independent implementations of the same header set
(`src/api/routes/consent.js`'s legacy `DELETE /consent/actor/:actorId` route,
and `src/api/routes/keys.js`'s legacy `GET /keys` route) — both now call the
shared helper. Use it for any future route that needs to signal deprecation
ahead of removal; see either of those two routes for a usage example.

Root-level changes across releases are tracked in `CHANGELOG.md`.

## When a real `/v2` is needed

At that point:
1. Introduce a router-factory pattern — a function that builds a router
   parameterized by version, rather than reusing one static instance across
   both mount points.
2. Mount `/v2/*` with the new factory output; `/v1/*` keeps using the
   existing (frozen) router instances, unchanged.
3. Apply `sendDeprecationHeaders()` to every `/v1` route being superseded,
   with a real `Sunset` date.
4. Update this document with the concrete `/v2` scope and timeline.

This is intentionally not built out speculatively today — see API-6 above.
