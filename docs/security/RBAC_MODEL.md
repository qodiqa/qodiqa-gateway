# QODIQA RBAC Authorization Model

**Version:** 2.1

**Last Updated:** 2026-07-28

> **2026-07-28 update:** §5 is rewritten to describe custom
> roles. Prior versions of this document advertised "five roles" without
> qualifying that the platform's real permission model is 32 fine-grained
> permissions, and had no path from one to the other short of code changes
> — an auditor reading only this document could reasonably conclude the
> five roles were the only unit of access control available. Custom roles
> (operator-defined, named permission sets drawn from the same fixed
> matrix) close that gap. No fail-closed guarantee in §3, no provisioning
> path in §4, and no permission definition in the matrix itself changed —
>

---

## 1. Summary

RBAC authorization is **always enforced** on every operator API endpoint that
manages state or reads sensitive data. There is no configuration flag,
missing identity, malformed input, or internal failure that grants
administrative access without an explicit, persisted RBAC user record with
role `admin`. This document describes the model, the vulnerability it
replaced, and the operational bootstrap procedure.

---

## 2. What changed and why

### 2.1 The prior model (removed)

Before this remediation, `src/middleware/rbac.js` read `QODIQA_RBAC_ENABLED`
at startup. When unset or `false` — the documented default — the module:

- Attached a synthetic identity (`{ id: '_service', role: 'admin', synthetic: true }`)
  to **every** request, regardless of whether it carried any credential.
- Turned every `requirePermission(...)` check into a no-op that always called
  `next()`.

The practical effect: any caller who passed the (separate, coarser) ops
authentication layer — including via the deprecated shared
`QODIQA_OPS_TOKEN` — was silently granted full administrative access to
every RBAC-gated endpoint, with no RBAC assignment, no audit trail
attributing the action to a real identity, and no way to revoke it short of
revoking the shared token entirely.

### 2.2 The current model

`src/middleware/rbac.js` no longer has a disabled mode. `createRbacResolveMiddleware`
and `createRequirePermission` always run their strict logic:

1. **Resolve**: if `req.rbacUser` was not set by the authentication layer
   (`createOpsAuthMiddleware`, via a resolved per-operator API key), the
   request is denied with `403 FORBIDDEN`. No identity header (including the
   historical `X-Ops-Actor`) is ever consulted.
2. **Authorize**: `isPermitted(user.role, permission)` (`src/core/rbac/roles.js`)
   is evaluated against the real permission matrix. Any exception during
   evaluation is caught and denies the request — it never falls through to
   `next()`.

`QODIQA_RBAC_ENABLED` is still read, solely to emit a one-time
`RBAC_ALLOW`/`RBAC_ALWAYS_ENFORCED`-family startup log if it is present, so a
config value that used to matter never silently stops mattering without the
operator being told. It has no effect on authorization.

---

## 3. Fail-closed guarantees

| Condition | Outcome |
|---|---|
| No credential presented | `403 FORBIDDEN` |
| Credential resolves to no user (unknown API key) | `401` at the ops-auth layer (never reaches RBAC) |
| Credential resolves to a disabled user | `401` at the ops-auth layer |
| `req.rbacUser` unset when a permission check runs | `403 FORBIDDEN` (`RBAC_NOT_RESOLVED`) |
| `req.rbacUser.role` is missing, empty, or not a canonical role | `403 FORBIDDEN` (`isPermitted` returns `false` for any invalid role) |
| Permission name not in the matrix | Throws at **route-registration time** (fail-fast developer error, not a runtime bypass) |
| `isPermitted()` throws internally | Caught, logged (`RBAC_PERMISSION_ENGINE_ERROR`), request denied `403` — never `500`, never allowed |
| `QODIQA_RBAC_ENABLED` unset, `false`, or any other value | No effect — enforcement is unconditional |
| RBAC store file missing or corrupt | Treated as an empty store (`src/core/rbac/store.js` `_loadFromDisk`) — no users exist, so every permission check denies until users are (re)created |

There is no branch anywhere in `src/middleware/rbac.js` that calls `next()`
without either (a) an already-set `req.rbacUser`, or (b) a successful,
positive `isPermitted()` result against that user's real role.

---

## 4. Administrator provisioning — the only two paths

Every `admin`-role user is created through one of exactly two paths, both
fully audited:

1. **`bootstrapAdmin()`** (`src/core/rbac/store.js`, called once at every
   server startup via `server.js`) — creates a user named by
   `QODIQA_RBAC_BOOTSTRAP_ADMIN_ID` (default `bootstrap-admin`) **only if no
   enabled admin user exists yet**. Idempotent; a no-op on every subsequent
   startup once an admin exists. Emits `RBAC_BOOTSTRAP_ADMIN_CREATED` (WARN).
2. **`POST /rbac/users`** with `role: "admin"`, called by an existing,
   authenticated admin through the ops API. Emits `RBAC_ADMIN_USER_CREATED` (INFO).

Neither path can be triggered by an unauthenticated request, a missing
identity, or a configuration toggle.

### 4.1 Bootstrapping the very first API key

`bootstrapAdmin()` creates the **user record** but not an API key — issuing
one requires `POST /rbac/users/:id/api-key`, which itself requires
`MANAGE_USERS`, which requires an already-authenticated admin. This is
deliberate: there is no HTTP-reachable route that mints the first credential,
because any such route would itself be an implicit-admin path.

Instead, provision the first key **out-of-band**, with direct access to the
running environment:

```bash
# Run inside the container/pod/host — never over the network
npm run rbac:bootstrap-key
```

This runs `scripts/rbac-bootstrap-key.js`, which calls the exact same
`bootstrapAdmin()` / `issueApiKey()` functions the HTTP admin API uses,
against the same RBAC store file (`QODIQA_RBAC_STORE_PATH`). It prints the
plaintext API key exactly once. Store it securely (e.g. your secrets
manager), then use it to create individually-attributed operator accounts:

```bash
curl -X POST https://your-host/rbac/users \
  -H "Authorization: Bearer <bootstrap key>" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","role":"auditor"}'

curl -X POST https://your-host/rbac/users/<alice-user-id>/api-key \
  -H "Authorization: Bearer <bootstrap key>"
```

Re-running `npm run rbac:bootstrap-key` after a key already exists reports
`ALREADY_PROVISIONED` and takes no action; pass `--rotate` to force-reissue
(this immediately invalidates the previous key).

---

## 5. Roles and permissions

Six canonical, built-in roles (`src/core/rbac/roles.js`): `admin`,
`auditor`, `compliance`, `operator`, `viewer`, and `tenant` (see
§5.2). The full permission matrix, and which built-in role(s) each
permission is granted to, is enumerated in that file and is the single
source of truth for those six roles — this document does not duplicate it
to avoid drift. Query it live via `GET /rbac/permissions` (requires an
authenticated identity, no specific permission).

### 5.2 The `tenant` role

`ROLES.TENANT` is a sixth built-in role, but it is **not another tier on
the admin/auditor/compliance/operator/viewer console-operator ladder**
above — it is a different identity CLASS entirely: an authenticated tenant
self-service portal user (`src/core/portal/`), signed in via OIDC SSO, and
scoped to exactly one tenant. It carries exactly three, tenant-scoped,
read-only permissions (`READ_TENANT_IDENTITY`, `READ_TENANT_KEYS`,
`READ_TENANT_CONSENT`)'s "RBAC" section
for the full table and the rationale for also including `admin` on each of
those three permissions.

**This role is authenticated and authorized through the SAME `isPermitted`/
`requirePermission()` code paths as every other role** — `src/middleware/
portalAuth.js` populates `req.rbacUser = { id, username, role: 'tenant',
enabled }` from a validated portal session token (not an `ok_` operator
API key), and `src/middleware/rbac.js`'s `createRbacResolveMiddleware()`/
`createRequirePermission()` run completely unmodified on top of it. No
second authorization system was introduced for. What IS new is a
second, orthogonal SCOPING concept this role's routes rely on —
`req.tenantContext.tenantId`, server-derived from the same session token —
which the permission matrix itself has no awareness of (a `tenant` user's
`READ_TENANT_KEYS` grant says nothing about *which* tenant; the route
handler enforces that separately). for the
full authentication design's "Tenant
isolation" section for the enforcement chain.

### 5.1 Custom roles

The five built-in roles are fixed bundles of the platform's 48 permissions
— least-privilege for a deployment whose access needs don't map cleanly
onto one of those five bundles previously required either over- or
under-granting a built-in role, or a code change to add a sixth. **Custom
roles** close that gap: an admin can define a named role as an arbitrary
subset of the same 48 permissions, entirely through the API, with no code
change and no deployment.

- **What a custom role is**: a persisted `{ id, name, description,
  permissions[], enabled }` record (`src/core/rbac/customRoleStore.js`).
  Its `id` always carries a `custom:` prefix (e.g. `custom:policy-reviewer`)
  — a namespace that can never collide with a canonical role name, today's
  five or any added in the future, so a custom role can never be mistaken
  for, or silently shadow, a built-in one.
- **What it is not**: a way to grant a permission that doesn't already
  exist in the matrix, or to change what the five built-in roles can do.
  Creating, updating, or deleting a custom role has zero effect on
  `admin`/`auditor`/`compliance`/`operator`/`viewer` — those five code
  paths in `src/core/rbac/roles.js` are unmodified and unaware custom roles
  exist at all.
- **Authorization**: `src/middleware/rbac.js`'s `requirePermission()` calls
  `src/core/rbac/authorize.js`'s `isPermitted(role, permission)`, which
  composes the two role kinds — the fixed matrix for the five built-ins,
  the role's own stored permission list for a `custom:` ID. **The
  authorization engine evaluates permissions, never role names, for both
  kinds identically** — a custom role is exactly as real to
  `requirePermission()` as a built-in one.
- **Fail-closed by construction**: disabling a custom role
  (`enabled: false`) immediately denies every permission it granted, for
  every user who holds it, without touching a single user record — the
  same pattern §3's table already documents for every other RBAC failure
  mode. An unknown or deleted role ID denies everything, the same as an
  unrecognized canonical role string always has.
- **Provisioning API** (all under `/rbac/roles`, `MANAGE_USERS` required
  except where noted):
  - `POST /rbac/roles` — create (name + permissions; validated against the
    real permission matrix — unknown permissions, duplicates, and
    non-array/non-string structures are all rejected before anything is
    persisted).
  - `PATCH /rbac/roles/:id` — update name/description/permissions/enabled
    (canonical as of the API-9/WP-030 remediation — this is always a partial
    update, which is PATCH semantics). `PUT /rbac/roles/:id` still works
    identically, marked deprecated via `Deprecation`/`Link` response headers
    (see `docs/api/versioning.md`). A role's `id` never changes on rename, so
    existing user assignments never silently break.
  - `DELETE /rbac/roles/:id` — refuses (409) to delete a role currently
    assigned to any user unless `?force=true` is passed.
  - `POST /rbac/roles/validate` — dry-run permission-list validation; reads
    only, creates nothing (any authenticated identity with `READ_USERS`).
  - `GET /rbac/roles` / `GET /rbac/roles/:id` — list/read, built-in and
    custom roles together (any authenticated identity).
  - Every route above returns `422 CANNOT_MODIFY_BUILTIN` if `:id` names
    one of the five built-in roles — those remain code-defined, not
    API-editable, by design.
- **Custom roles never reduce security**: a custom role can only ever be
  built from permissions that already exist in the matrix — it cannot
  introduce a new capability the platform doesn't already define elsewhere.
  Creating one is itself gated behind `MANAGE_USERS`, i.e. only an existing
  admin can create a role at all (including one that carries an
  admin-exclusive permission such as `MANAGE_KEYS`) — this is no different
  in principle from an existing admin creating a new user with `role:
  "admin"` today.
- **Backward compatibility**: a deployment that never calls any
  `/rbac/roles` mutation route is completely unaffected — every existing
  user, still assigned one of the five built-in role strings, is evaluated
  by the exact same, unmodified code path (`src/core/rbac/roles.js`) as
  before this feature existed.

See for the full design record and
`src/core/rbac/customRoleStore.test.js` (44 tests) /
 for verification.

**Permission != identity separation.** This role/permission matrix answers
"is this account allowed to attempt action X" — it does not by itself
prevent the same individual from performing two incompatible steps of a
workflow (e.g. authoring and approving their own change), since two
different accounts can legitimately share a role. The policy-governance
maker-checker layer is the one place in this codebase that adds a
second, identity-level check on top of the permission check — see
`docs/guides/policy-governance.md` §5 and
`src/core/policy/governance/makerCheckerRules.js`.

---

## 6. What is NOT part of this model

- **The shared `QODIQA_OPS_TOKEN`** (deprecated) authenticates requests at
  the ops-auth layer but never sets `req.rbacUser` — it cannot satisfy any
  RBAC-gated route. It remains usable only for routes that require ops
  authentication alone (`/metrics`, `/diagnostics`; `/health` and `/ready`
  are unauthenticated by default — see `docs/deployment/kubernetes-probes.md`).
- **`X-Ops-Actor`** and any other client-supplied identity header are never
  consulted for RBAC resolution, regardless of value.
- **IP allowlisting** (`QODIQA_OPS_IP_ALLOWLIST_ENABLED`) is a separate,
  additive network-layer control — it narrows *who can reach* an endpoint,
  it does not grant or substitute for a role.
- **Rate limiting and the diagnostics kill-switch** are likewise separate,
  additive layers, not part of the RBAC model itself. See
  `docs/security/SECURITY_GUIDE.md` §10 for the full layered stack — every
  Admin route composes RBAC together with these other controls via a single
  shared factory (`src/middleware/adminProtection.js`).

---

## 7. Regression coverage

- `src/core/rbac/rbac.invariants.test.js` — structural invariants over the
  permission matrix, role definitions, and middleware factory, including
  explicit regression guards (INV-24) that no configuration input can ever
  produce a synthetic or implicit identity.
- — full RBAC store, resolve middleware,
  `requirePermission` middleware, and `/rbac` admin API behavior, including
  a dedicated regression section (RB-69…RB-74) asserting the removed
  fail-open behavior cannot be reconstructed via the legacy `{ enabled }`
  option shape.
- `scripts/rbac-bootstrap-key.test.js` — the out-of-band bootstrap script,
  run as a real child process against a disposable store.
