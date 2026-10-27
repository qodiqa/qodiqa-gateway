# Compatibility policy

> **Status:** DRAFT 5 for the freeze; binding after `APPROVAL:` in `V2-FREEZE.md`.

## What stays valid forever

1. **V1 artifacts** (no `payload.qodiqa`): the verification procedure, the hash and signature construction, the vectors and the error
   codes of `QODIQA-PROTOCOL.md` are never changed in a way that turns a valid V1 artifact into an invalid one, and never turns an invalid one
   into a valid one. Hardening that rejects *more* malformed input is allowed only where the rejected input had no legitimate producer, is
   recorded in the protocol text with the date, and ships with vectors.
2. **Audit entries v1–v7** and their hashes; **transparency entries** and signed roots already published; **checkpoints** already signed.
3. **Existing HTTP endpoints** under `/v1` and their response shapes (additive changes only: new optional fields, new endpoints, new enum
   values that older clients can ignore). Breaking changes require a new major path prefix (`/v2`), run in parallel for at least one
   deprecation period (VERSIONING.md).

## Rules for changes

| change | allowed? | how |
|---|---|---|
| new optional field in a response | yes | document in OpenAPI; SDKs ignore unknown fields |
| new required request field | no | add as optional with a safe default |
| new error `reason` | yes | add to the catalog and to the SDK enums before it can be emitted; clients treat unknown reasons as `BLOCK` |
| new protocol claim | yes | inside `payload.qodiqa`; if verifiers must understand it, list it in `qodiqa.crit` |
| new hash/signature construction | only as a new versioned tag (`…::V2`) | old construction stays verifiable |
| new audit field | only through a schema version | `AUDIT-V8-FREEZE.md` is the last planned one |
| removing or renaming anything above | no | deprecate, keep verifying, document |

## Reserved names and one-way switches

* The only new reserved top-level payload name is `qodiqa` (V2-FREEZE 1.2); `/sign` refuses it in caller data on every version, so no V1 artifact can carry it.
  Other V2 field names live inside it and cannot collide with caller data.
* The switch `QODIQA_AUDIT_SCHEMA_V8` is one-directional per deployment (AUDIT-V8-FREEZE 1.5): enable only after every verifier reads v8.
* Before `QODIQA_PROTOCOL_V2_ACCEPT` is enabled, `/sign` must already refuse the `qodiqa` key in caller data (`RESERVED_CLAIM`).
* Clients that form-encode a space as `+` in a query that must be bound have to use `%20`; `/sign` says so (`QUERY_NOT_BINDABLE`).
* `QODIQA_PROTOCOL_V2_ACCEPT` may be switched off again (V2 artifacts become `UNSUPPORTED_PROTOCOL_VERSION`); `QODIQA_PROTOCOL_MIN_VERSION=2` closes the V1 downgrade.

## Fail-closed on the unknown

A component that meets a version, claim, schema version, vector format or proof format it does not know **refuses** (names the reason) and
never guesses: `UNSUPPORTED_PROTOCOL_VERSION`, `UNSUPPORTED_CRITICAL_CLAIM`, unknown `schemaVersion` (V1 document, section 9), unknown
`format` of a proof. The one deliberate exception is forward compatibility for *non-critical* claims, which are ignored but still covered by the
signature.

## Mixed deployments

A V1-only verifier accepts the signature of a V2 artifact but does not enforce its new claims, and a V1 gateway fails a V2 request's binding
(`REQUEST_MISMATCH`) — see V2-FREEZE section 7. Upgrade order: verifiers/SDKs first, gateway second, issuers last. The switches
`QODIQA_PROTOCOL_V2_ACCEPT` then `QODIQA_PROTOCOL_V2_ISSUE` encode that order.

## Supported-version matrix

| component | protocol V1 | protocol V2 | audit schema |
|---|---|---|---|
| gateway | yes | gate (flags) | v1–v7 verify; v8 read, v8 write from the gate (flag, one-way) |
| JavaScript / Python SDK | yes | | SDK artifact verifiers read V2 and receipts; audit-entry verification in the SDKs is not provided |
| independent verifiers | yes (JavaScript, Python) | (JavaScript); the Python verifier gains the number serializer | JavaScript: v1–v8; Python audit verifier is a deliverable |
