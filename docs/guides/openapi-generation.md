# OpenAPI / Swagger Generation — Component #42

Automatic OpenAPI 3.1.0 specification generation for the complete QODIQA REST API.

## What it does

- Generates a complete OpenAPI 3.1.0 specification covering **364 documented operations across 324 paths** in 40 tag groups. The default build mounts 369 operations: the 364 documented plus 5 reviewed undocumented ones (`KNOWN_UNDOCUMENTED`: the `/docs` UI and the three `/diagnostics/profile/*` endpoints), and 11 more exist only behind feature flags (9 tenant-portal routes behind `QODIQA_PORTAL_ENABLED`, 2 stage-timing routes behind `QODIQA_BENCH_STAGE_TIMING`; `conditionalRoutes.test.js`) (see [the project history](../the project history) for the full inventory and gap-closure history — the count above was 126 before that remediation).
- Serves the spec as JSON (`/openapi.json`) and YAML (`/openapi.yaml`) from the running process.
- Provides an interactive Swagger UI explorer at `/docs`.
- Uses in-memory caching — spec is built once and frozen; subsequent requests are near-zero cost.
- Pure-JS YAML serialiser — no `js-yaml` or other external dependencies.
- No CDN dependency at all: the spec and the Swagger UI assets (swagger-ui-dist 5.17.14, vendored, SRI-pinned) are served by the gateway itself.

## Architecture

```
src/openapi/
├── constants.js          — INFO, SERVERS, TAGS, EXTERNAL_DOCS, API_VERSION
├── schemaGenerator.js    — Schema object factories (makeString, makeObject, ref, …)
├── componentsBuilder.js  — Reusable components (schemas, responses, parameters, securitySchemes)
├── routeScanner.js       — Static registry of all endpoint definitions
├── generator.js          — Assembles spec; in-memory cache with Object.freeze()
├── swaggerUi.js          — Swagger UI HTML page generator + allowlisted self-hosted assets (vendor/swagger-ui-dist-5.17.14/)
├── index.js              — Public entry point re-exporting all public API
├── writers/
│   ├── jsonWriter.js     — JSON serialiser (JSON.stringify wrapper)
│   └── yamlWriter.js     — Pure-JS YAML serialiser (block style, no deps)
└── openapi.test.js       — 149-test Jest suite

src/api/routes/openapi.js — Express router: /openapi.json, /openapi.yaml, /docs
```

### Data flow

```
Request → createOpenApiRouter
              │
              ├─ GET /openapi.json ──► generateSpec() ──► writeJson()  ──► response
              ├─ GET /openapi.yaml ──► generateSpec() ──► writeYaml()  ──► response
              └─ GET /docs        ──► renderSwaggerUiHtml() ──────────────► response

generateSpec()
    │
    ├─ buildComponents()  ─ componentsBuilder.js
    │      ├─ securitySchemes (BearerAuth, OpsTokenHeader, SignToken)
    │      ├─ schemas (35+ named schemas)
    │      ├─ responses (8 standard error responses)
    │      └─ parameters (22+ named parameters)
    │
    └─ buildPaths()       ─ routeScanner.js
           └─ 364 operations across all QODIQA routes
```

## Endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `GET /openapi.json` | None | Full OpenAPI 3.1.0 spec as JSON |
| `GET /openapi.yaml` | None | Full OpenAPI 3.1.0 spec as YAML |
| `GET /docs` | None | Swagger UI interactive explorer |

### Cache-Control

- `/openapi.json` and `/openapi.yaml`: `public, max-age=300` (5 minutes)
- `/docs`: `public, max-age=60` (1 minute — shorter to pick up spec changes quickly)

### Force refresh

Append `?fresh=1` to regenerate the spec, bypassing the in-memory cache:

```
GET /openapi.json?fresh=1
GET /openapi.yaml?fresh=1
```

## Security schemes

| Scheme | Type | Header |
|---|---|---|
| `BearerAuth` | HTTP Bearer | `Authorization: Bearer <ok_... per-operator key, or shared QODIQA_OPS_TOKEN>` |
| `OpsTokenHeader` | API Key | `x-ops-token: <token>` (deprecated; prefer `BearerAuth`) |
| `SigningApiKey` | HTTP Bearer | `Authorization: Bearer sk_<64 hex chars>` — per-identity signing API key for `POST /sign` |

Most operational endpoints require `BearerAuth`. `POST /sign` requires `SigningApiKey`. `/ai/chat` and `/verify` authenticate via the signed artifact itself (`x-qodiqa-artifact` header), not a bearer scheme. Public endpoints (`/health`, `/ready`, `/openapi.*`, `/docs`) require no authentication.

## Endpoint coverage

| Tag group | Count |
|---|---|
| AI Execution | 4 |
| Consent | 9 |
| Signing & Verification | 6 |
| Audit | 8 |
| Compliance | 5 |
| Attestation | 6 |
| Certification | 10 |
| Webhooks | 5 |
| RBAC | 8 |
| Organization Admin | 5 |
| Tenant Admin | 5 |
| Policy Management | 7 |
| Policy Simulation | 2 |
| Policy Visual | 7 |
| Transparency Log | 6 |
| Verification Portal | 5 |
| Evidence | 5 |
| Keys | 6 |
| Alerting | 4 |
| Health / Metrics | 4 |
| Audit Store | 15 |
| Audit Viewer | 12 |
| Data Subject Rights | 10 |
| Policy Governance | 16 |
| Signing Identities | 7 |
| … | … |

Full count: **364 operations** (`docs/inventory.generated.json`).

## Drift prevention

`src/openapi/routeParity.test.js` statically extracts every `router.<method>('<path>', ...)` registration from the route-handler source files, maps each through the mount-prefix table `server.js` uses, and diffs the result against `buildPaths()`. It fails the build if an implemented route is undocumented, a documented route doesn't exist, or a path's HTTP methods differ — run it directly with `npm run validate:openapi`.

The mount-prefix table itself lives in `src/openapi/routeMounts.js` (`MOUNTS` + `EXPLICIT_ROUTES`) — extracted out of `routeParity.test.js` so it has a single owner shared with the response-envelope governance described next, instead of two hand-copied lists that could drift from each other.

## Committed contract and live-route parity

The implementation is the source of truth; the published contract is a generated artifact, never hand-edited:

- **`docs/api/openapi.json`** is the committed, deterministic output of `generateSpec({ fresh: true })` (no environment or clock inputs). `npm run openapi:generate` rewrites it; `npm run openapi:check` (`scripts/openapi/contract.js --check`) regenerates in memory and exits 1 on any byte difference, printing the operations added/removed and the first differing JSON pointers. `src/openapi/committedContract.test.js` (OC-01..03, with negative controls) runs the same check inside the unit gate.
- **Live-route parity** — `src/openapi/liveRouteParity.test.js` (LP-01..04) boots the real Express app, instruments every `app.use` / `Router.use` / `express.Router`, walks the live router stack and diffs the result against `buildPaths()`. Unlike the static `routeParity.test.js` below it cannot miss a route registered dynamically; a router invoked through a wrapper closure must be listed in its reviewed `OPAQUE_MOUNTS`, and the four intentionally undocumented routes (`GET /docs/` and the three diagnostics/profile routes) are pinned in `KNOWN_UNDOCUMENTED`.
- **Response contract** — `scripts/contract/live-contract.js` boots the server and validates real response bodies against the committed schemas; `scripts/contract/sdk-openapi-check.js` checks every JS/Python SDK call against a documented operation with matching auth.
- **CI** — `npm run contract:check` (OpenAPI + protocol vectors + spec sections + SDK contract) is the `specs-equal-code` job in `.github/workflows/doc-drift-check.yml`.

## Response envelope governance

A second, complementary drift-prevention layer governs *response shapes* rather than route existence: `src/api/responseEnvelopes.js` is a hand-maintained registry (same "static declarative registry, reviewed alongside the code, cannot drift silently" philosophy as `routeScanner.js`) that names every distinct top-level JSON response shape used across the API and which route file produces it. `src/api/response.js`'s header comment is the authoritative prose version of the same taxonomy.

`src/api/__tests__/responseEnvelopeGovernance.test.js` is the automated force keeping the two in sync, and part of the mandatory `unit` CI job (it lives under `src/`, which `.github/workflows/test.yml` already runs on every push/PR — no separate CI wiring needed). It checks:

1. **Coverage** — every route file in `routeMounts.js`'s `MOUNTS` list is classified into an envelope type.
2. **Doc/registry parity** — every envelope type name in `responseEnvelopes.js` appears in `response.js`'s header comment, and vice versa is implied by construction. A route file that grows a new response shape without both updates fails here.
3. **Static conformance** — every route file defaulted to the management envelope (i.e. *not* given an explicit override) actually `require()`s `response.js` and calls `success()`/`failure()`. This is the "new undocumented response type" gate: a file that silently stops using the shared builder, and isn't given an explicit classification, fails the build.
4. **Runtime parity** — for the route files explicitly named (`/keys`, `/public-keys`, `/public-key`, `/health`, `/ready`, `/health/redis`, `/.well-known/qodiqa/keys`), the handler is actually invoked and the real response body's top-level key set is asserted against the registered envelope type — genuine runtime-vs-registry parity, not just a static claim.
5. **Synthetic mutation detection** — `checkEnvelopeShape()` (the same function used in step 4) is fed deliberately mismatched bodies (missing key, extra key, renamed key) and must report each mismatch, proving the detection mechanism itself is sound.

Two intentionally out of scope for this pass (documented, not silently skipped): full property-level parity between every route's runtime response, its OpenAPI schema, and its Zod validation schema across the entire ~150-route surface, and the `success:false` shutdown-response shape emitted by `src/runtime/requestDrain.js` ahead of route handlers (not tied to any single route file, so it falls outside `routeMounts.js`-based classification — see `docs/api/overview.md`'s `/ai/chat` section for that shape).

## Reusable components

### Schemas (35+)

`Uuid`, `Timestamp`, `ActorId`, `Action`, `Scope`, `TenantId`, `PaginationMeta`, `SuccessEnvelope`, `ErrorEnvelope`, `EnforcementDecision`, `Artifact`, `SignedRequest`, `ConsentRecord`, `ConsentGrantRequest`, `PolicyRule`, `PolicyDefinition`, `WebhookEndpoint`, `WebhookCreateRequest`, `WebhookUpdateRequest`, `RbacUser`, `RbacCreateUserRequest`, `RbacUpdateUserRequest`, `Organization`, `OrgCreateRequest`, `Tenant`, `TenantCreateRequest`, `ComplianceReport`, `GraphNode`, `GraphEdge`, `SignRequest`, `SignResponse`, `AiChatRequest`, `SimulationContext`, `SimulationResult`, `AttestationResult`, `TransparencyEntry`, `HealthStatus`, `VerifyRequest`

### Responses (9)

`BadRequest` (400), `Unauthorized` (401), `Forbidden` (403), `NotFound` (404), `Conflict` (409), `TooManyRequests` (429), `InternalError` (500), `ServiceShuttingDown` (503), `ReadinessUnavailable` (503, `GET /ready` only)

### Parameters (22+)

Pagination: `PageParam`, `PageSizeParam`, `SortOrderParam`
Resource IDs: `UuidPathParam`, `PolicyIdParam`, `TenantIdParam`, `OrgIdParam`, `AttestationIdParam`, `CertificationIdParam`, `BatchIdParam`, `WebhookIdParam`, `TransparencyIdParam`, `ConsentIdParam`, `ActorIdParam`, `KeyIdPathParam`, `UserIdParam`, `ArtifactIdParam`, `ReportIdParam`, `DlqIdParam`, `AlertIdParam`, `PortalIdParam`, `FrameworkIdParam`

## Standard response envelopes

### Success response

```json
{
  "status": "success",
  "timestamp": "2025-06-30T12:00:00.000Z",
  "requestId": "550e8400-...",
  "data": { ... }
}
```

### Enforcement decision

```json
{
  "decision": "EXECUTE",
  "reason": "RULES_MATCHED",
  "requestId": "550e8400-...",
  "details": {}
}
```

> Enforcement endpoints return HTTP **200** regardless of the `decision` value. A `BLOCK` decision is a successful enforcement outcome, not an error.

## Pure-JS YAML serialiser

`writeYaml()` in `src/openapi/writers/yamlWriter.js` implements a full block-style YAML serialiser with no external dependencies:

- Handles all JSON-compatible types: objects, arrays, strings, numbers, booleans, null
- Quotes YAML 1.1/1.2 reserved words (`true`, `false`, `null`, `yes`, `no`, `on`, `off`, …)
- Quotes strings that parse as numbers (integers, floats, hex, octal)
- Quotes strings with flow indicators (`{`, `}`, `[`, `]`, `#`, …)
- Multiline strings use literal block scalar (`|`)
- `Infinity` serialises as `.inf`; `-Infinity` as `-.inf`
- Output is always block style — no flow collections

## Swagger UI

The UI page (`/docs`) is generated by `src/openapi/swaggerUi.js`:

- Loads the Swagger UI bundle, preset, stylesheet and favicons from `/docs/assets/*`, served by this process from `src/openapi/vendor/swagger-ui-dist-5.17.14/` (the npm-registry release, unmodified, Apache-2.0 LICENSE + NOTICE alongside), each script/stylesheet with its pinned sha384 integrity
- The initializer is a same-origin script (`/docs/assets/swagger-initializer.js`) configured through `data-spec-url` — no inline script, so the page works under the gateway's HTML CSP (`script-src 'self'`) unchanged. (2026-10-05: the earlier CDN + inline design was refused by that CSP and rendered nothing in a browser.)
- Fetches the spec from `/openapi.json` at page load — always reflects the live generated spec
- Features enabled: `deepLinking`, `filter`, `tryItOutEnabled`, `persistAuthorization`
- Injects `x-request-id` header into every Try-It-Out request for traceability
- Dark theme with QODIQA brand colours

## Caching

```javascript
const { generateSpec, invalidateCache } = require('./src/openapi');

// Get (or generate and cache) the spec
const spec = generateSpec();

// Force regeneration (e.g. after a hot-reload)
const fresh = generateSpec({ fresh: true });

// Explicit cache invalidation
invalidateCache();
```

The cached spec is `Object.freeze()`d — it cannot be mutated after generation.

## Adding a new endpoint

1. Open `src/openapi/routeScanner.js`.
2. Find the appropriate section (or add a new one).
3. Call `add(path, method, _op(...))` with a complete operation descriptor.
4. If a new schema is needed, add it to `componentsBuilder.js` and reference it via `sg.ref('Name')`.
5. The spec regenerates automatically on the next request to `/openapi.json`.

```javascript
// Example: adding POST /v1/widgets
add('/v1/widgets', 'post', _op(
  'createWidget',         // operationId (must be unique)
  'Create a widget',      // summary
  ['Widgets'],            // tags (must match a tag in constants.js)
  OPS_AUTH,               // security
  {
    '201': _success('Widget created', sg.ref('Widget')),
    ...Object.assign({}, _STD_ERRORS, _AUTH_ERRORS),
  },
  {
    description: 'Creates a new widget.',
    requestBody: _body(sg.ref('WidgetCreateRequest'), 'Widget definition'),
  },
));
```

## Tests

149 tests across 13 describe blocks:

| Block | Tests |
|---|---|
| `generateSpec — top-level structure` | 9 |
| `components — schemas` | 6 |
| `components — responses` | 3 |
| `components — parameters` | 5 |
| `components — security schemes` | 3 |
| `paths — coverage and structure` | 9 |
| `writeJson` | 7 |
| `writeYaml` | 16 |
| `renderSwaggerUiHtml` | 13 |
| `generateSpec — caching` | 6 |
| `createOpenApiRouter` | 12 |
| `schemaGenerator helpers` | 16 |
| `determinism` | 3 |

```bash
npx jest src/openapi/openapi.test.js
```

## Dependencies

No new npm dependencies. Uses only:

- Node.js built-ins (`module`, `path`)
- Express (already a project dependency)
- Swagger UI's browser assets vendored under `src/openapi/vendor/` and served by the gateway (no CDN)

## Files created

| File | Purpose |
|---|---|
| `src/openapi/constants.js` | INFO, SERVERS, TAGS, EXTERNAL_DOCS |
| `src/openapi/schemaGenerator.js` | Schema factory helpers |
| `src/openapi/componentsBuilder.js` | Reusable component definitions |
| `src/openapi/routeScanner.js` | Static endpoint registry |
| `src/openapi/generator.js` | Spec assembly + caching |
| `src/openapi/swaggerUi.js` | Swagger UI HTML generator |
| — | Public entry point |
| `src/openapi/writers/jsonWriter.js` | JSON serialiser |
| `src/openapi/writers/yamlWriter.js` | Pure-JS YAML serialiser |
| `src/api/routes/openapi.js` | Express routes |
| `src/openapi/openapi.test.js` | 149-test Jest suite |
| `docs/guides/openapi-generation.md` | This document |

## Files modified

| File | Change |
|---|---|
| `server.js` | Added `require('./src/api/routes/openapi')` and `app.use('/', createOpenApiRouter())` |
