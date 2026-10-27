# Versioning and deprecation policy

> **Status:** DRAFT 5 for the freeze; binding after `APPROVAL:` in `V2-FREEZE.md`.
> Complements `docs/api/versioning.md` (HTTP path versioning) and `COMPATIBILITY.md` (what must keep working).

## Four independent version axes

| axis | where it lives | form | changes when |
|---|---|---|---|
| **Software release** | git tag, `package.json`, SDK packages | semantic versioning `MAJOR.MINOR.PATCH` | every release; MAJOR only for a breaking change of a public interface listed below |
| **Protocol** | `payload.qodiqa.v` (no `qodiqa` = V1, then `2`), domain tags `…::V<n>` | integer | a change to what is hashed or signed or to the verification procedure |
| **Audit schema** | `schemaVersion` of each entry | integer (1–7 today, 8 frozen) | a change to the hashed field set |
| **HTTP API** | path prefix `/v1`, `docs/api/openapi.json` | `/v<major>` | a breaking change of a request/response contract |

The axes move independently: a PATCH release never changes a protocol or schema version; a protocol or schema version bump requires a MINOR
(or MAJOR if it removes support) of the software and a freeze document like this one.

## Public interfaces covered by semver

HTTP API (OpenAPI), the protocol documents and vectors, the JavaScript and Python SDK public APIs, the `qodiqa-proof/*` format, the audit
verifier CLI, environment variables listed in `docs/configuration/reference.md`, and the migration numbering.
Everything else (internal modules, scripts, evidence layout) is not a public interface.

## Deprecation

1. A deprecation is announced in the release notes and in `CHANGELOG.md` with: what, why, the replacement, the earliest removal date.
2. Minimum period before removal: **two MINOR releases and 90 days**, whichever is longer; security-driven removals may be shorter but are
   announced with the reason.
3. Deprecated HTTP behavior is signalled with the `Deprecation` and `Sunset` response headers (the existing pattern in `docs/api/versioning.md`)
   and a warning log/metric; SDKs emit a deprecation warning once per process.
4. A protocol or schema version is never "removed" for verification: old artifacts and entries must stay verifiable (COMPATIBILITY.md).
   Only *issuing* in an old version may be switched off.
5. Experimental features (anything not yet through its phase gate) are behind a flag, absent from OpenAPI, labelled "experimental" in the
   documentation, and carry no compatibility promise until the flag default flips.

## Release checklist (excerpt)

`npm run contract:check`, `npm run protocol:check`, vectors unchanged (append-only), migration ledger consistent, `claims:check` green,
SBOM and checksums generated, CHANGELOG entry with deprecations.
