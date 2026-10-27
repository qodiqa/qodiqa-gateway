# Security policy

Reports of weaknesses are welcome and taken seriously.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use one of:

1. **GitHub private vulnerability reporting**: the "Report a vulnerability" button under the repository's Security tab (preferred).
2. **Email**: security@qodiqa.com.

Include what you found, how to reproduce it, the version or commit, and what you think the impact is.

## What to expect

- Acknowledgement within 5 working days.
- A first assessment within 15 working days.
- A fix or a documented mitigation for confirmed issues, with credit in the changelog if you want it.
- We ask for 90 days of coordinated disclosure, and will tell you if we need less or more.

This is a small team and these windows are targets, not guarantees.

## Scope

In scope: the gateway (`src/`, `services/`, `server/`), the SDKs under `sdk/`, the deployment assets under `deploy/`, and documentation that overstates what the code does. Out of scope: findings that require an already-compromised host or operator, and denial of service by volume alone.

## Supported versions

Release 1.0.0 is the only release so far. Security fixes go to the default branch and ship in the next release.

## Trust boundaries and security model

This section states what the gateway protects, where the boundaries are, and what you have to protect yourself.

### Credentials

The gateway uses three kinds of credentials. None of them grants more than its own row below.

| Credential | Authenticates | Grants |
|---|---|---|
| Ops bearer token (`X-Ops-Token`, a shared secret kept for compatibility) | Coarse access to the operator API | The routes that accept the ops token only; it never carries RBAC permissions |
| RBAC operator API key | One attributable operator | The permissions of that operator's role, evaluated on every request |
| Signing-identity API key (`sk_` prefix) | One `/sign` caller | Signed artifacts for that identity only; issued individually and revocable |

The ops token and client-supplied identity headers such as `X-Ops-Actor` are never used to resolve an RBAC identity. An RBAC identity comes only from an authenticated per-operator credential.

### Tenant isolation

Tenant isolation is enforced by the application on every request. PostgreSQL row-level security (forced, not just enabled) is an additional layer: a query that runs without the right tenant context does not see another tenant's rows. It guards against application bugs; it is not a hard boundary.

- The tenant context is the session setting `qodiqa.tenant_id`, which the application sets for each transaction. A session of an application database role can set it to any value, so **database credentials are all-tenant credentials**. Store them like signing keys. Run `node scripts/db/role-credentials.js --check` on every cluster you provision: it fails while a role still has its published placeholder credential.
- Platform-level rows (with no tenant) are visible in every tenant context on the tables whose policies allow it.
- Some insert policies accept any `tenant_id`; the application is responsible for writing the right one.

A per-tenant database role, or a tenant context that only a signed value can set, would give hard isolation. The gateway does not provide it.

### What "consent" means here

Consent in QODIQA (`POST /consent`, the `REQUIRE_CONSENT` policy type) is an authorization between machines: it answers "is this verified caller currently allowed to run this action". It is not a record of a person's consent under data-protection law. If your use needs that kind of consent, your application collects it before it sends a request to the gateway; the gateway has no way to collect, show or record it.

### Trust posture

API clients, provider responses and anonymous browser clients are untrusted. PostgreSQL and Redis are trusted infrastructure, but their results are still checked for consistency, and a failure of either makes the gateway refuse the request rather than assume the best.

### Public capability URLs

The read routes in the table below need no authentication. Their only protection is the identifier in the URL: a random version-4 UUID (122 random bits, from `crypto.randomUUID()`) returned by the request that created the resource. Anyone holding the URL can read the resource for as long as the record is kept. This is intentional, so that a verifier can check a result without an account.

- **What protects them:** the identifier cannot be guessed. Reads by identifier are not rate-limited per identifier, and a link has no expiry or revocation while its record is retained.
- **What they withhold:** the requester's IP address is never returned. The transparency routes return verification fields only (no tenant, registrar, signer key version or payload); the public `GET /transparency/entries` listing has no tenant filter and no tenant field.
- **What they reveal:** the resource itself: the attestation, the certification result, summary and certificate, or the portal verification result and report. Treat the URL like a password. Do not put it in shared logs, tickets or chat, and do not link to it from a page whose `Referer` header could leak it.
- **Not provided:** per-viewer access control, audience restriction, link expiry or revocation. If you need them, do not expose these routes publicly (for example keep them behind your ingress).

<!-- capability-urls:begin (kept equal to docs/api/openapi.json by src/openapi/capabilityUrlDocs.test.js) -->
| Capability URL (GET, no authentication) | Identifier |
|---|---|
| `/v1/attestation/{attestationId}` | attestation id |
| `/v1/certification/{certificationId}` | certification id |
| `/v1/certification/{certificationId}/summary` | certification id |
| `/v1/certification/{certificationId}/certificate` | certification id |
| `/portal/result/{verificationId}` · `/v1/portal/result/{verificationId}` | portal verification id |
| `/portal/report/{verificationId}` · `/v1/portal/report/{verificationId}` | portal verification id |
| `/transparency/entry/{transparencyId}` · `/v1/transparency/entry/{transparencyId}` | transparency id |
| `/transparency/verify/{transparencyId}` · `/v1/transparency/verify/{transparencyId}` | transparency id |
| `/transparency/proof/{transparencyId}` · `/v1/transparency/proof/{transparencyId}` | transparency id |
| `/transparency/receipt/{requestId}` · `/v1/transparency/receipt/{requestId}` | request id (the `payload.requestId` of the artifact; the signed receipt of its decision, kept for a bounded window — `QODIQA_RECEIPT_TTL_SECONDS`, default 3600 s) |
| `/transparency/consistency/{fromRootId}/{toRootId}` · `/v1/transparency/consistency/{fromRootId}/{toRootId}` | root ids |
<!-- capability-urls:end -->

The public key-discovery routes (`/.well-known/qodiqa/keys/{keyId}`, `/.well-known/qodiqa/transparency-keys/{keyId}`, `/.well-known/qodiqa/checkpoint-keys/{keyId}`) are public by design. They serve public keys only and are not capability URLs.
