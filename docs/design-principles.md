# Design principles

Why QODIQA is built the way it is. Each principle names the property it protects and the cost it accepts.

## Authorize before executing

A request is authorized by a short-lived signed artifact, not by a standing credential. The artifact expires within at most 60 seconds and is single-use. The cost is one extra call before each request; the gain is that a leaked artifact is worth almost nothing.

## Bind the authorization to the request

An artifact is tied to the method, the path and the body of the request it authorizes. It cannot be reused for a different request. Protocol V2 extends the binding to the query string and chosen headers. The cost is that the client must know the request before asking for the artifact.

## Write intent before acting

The intent of a request is written to a write-ahead log, with fsync, before the provider is called. If the process dies, the record shows what was about to happen, and entries left open are closed at the next start. The cost is a synchronous write on the request path.

## Fail closed

When PostgreSQL is stopped, requests are refused with 503 without calling the provider, and the gateway recovers on its own. Beyond its configured limits the gateway refuses new work immediately instead of queueing without bound. A replica that cannot confirm the kill-switch state refuses requests. The cost is availability: the gateway prefers refusing to guessing.

## Make the record independently checkable

Decisions go into a hash chain and a Merkle transparency log. The verifiers are separate programs with no dependency on the gateway's code, in two languages, pinned by shared test vectors. The point is that a customer or auditor does not have to trust the operator's software to check the record.

## Do not let the operator be the only witness

A log held only by the party it describes proves little. Checkpoints can be anchored outside the gateway and co-signed by witnesses with their own keys. This is opt-in; verification without external anchors is circular, because keys and anchors come from the same instance.

## Separate duties

Policy changes need three different operators. Delegated authority only narrows. Consequential agent actions can require a one-use approval bound to that action. The cost is more steps; the gain is that no single account can change policy alone.

## Keep tenants apart in the application first

Tenants are separated in the application layer, with per-tenant keys, nonces, policy sets and consent. PostgreSQL row-level security adds defence in depth but is not treated as a boundary on its own.

## Specify the contract, then generate from it

The OpenAPI specification is generated from the code and checked in CI. Protocol test vectors are published and checked by independent implementations. Four protocol state machines are modelled in TLA+ and model-checked within small bounds; the models describe the protocol, not the code.

## Treat content screening as a layer, not a guarantee

Screening of prompts is an optional layer, oriented to English, and not a protection guarantee. The cryptographic controls above do not depend on it.
