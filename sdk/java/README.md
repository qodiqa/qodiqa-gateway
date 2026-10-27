# QODIQA Java SDK

`dev.qodiqa:qodiqa-sdk` (provisional coordinates) — a client for a QODIQA gateway and an offline verifier for its artifacts. Java 17+, one runtime dependency (Jackson).

> Status: **tested and verified internally**. Not yet published.

## Call any documented operation

```java
QodiqaClient c = QodiqaClient.builder().baseUrl("https://gateway.example.com").apiKey(System.getenv("QODIQA_OPS_KEY")).build();
QodiqaClient.Response r = c.call("listAlerts", QodiqaClient.CallArgs.none());
JsonNode doc = r.json();
```

`QodiqaClient.operations()` lists the 364 operations of the HTTP contract (generated from `docs/api/openapi.json`; `npm run sdk:check` in the repository fails when the table drifts).
Path/query/header mistakes are rejected before any request; credentials follow the contract; SSE operations use `stream()` (events until `[DONE]`; an early end is an error). Retries follow the
gateway's contract (idempotent verbs on 429/5xx; POST only on 429 and never on `/ai/chat`; `SERVER_OVERLOADED` always; never after `MFA_LOCKED`); an `otpSupplier` answers the operator MFA
step-up once. Errors are `QodiqaException` with a `Kind` (AUTHENTICATION, RATE_LIMIT, VERIFICATION, ...), HTTP status, reason, request id and details.

## Verify an artifact offline

```java
var keys = new Verify.StaticKeyProvider(trustBundleJson);                       // [{keyId, publicKey (base64 SPKI), status}]
var verifier = new Verify.ArtifactVerifier(keys, null, 0, false, null);
Verify.ArtifactVerification r = verifier.verify(Canonical.parse(artifactJson), null);   // r.verificationStatus == "valid"
```

`Verify.decideArtifact` is the gateway's own V1 decision procedure (key lifecycle, time limits); `Verify.requestHash`, `Verify.policyHash`, `Canonical.canonicalize` and `Verify.domainHash`
expose the protocol's canonical forms.

## What is tested

`mvn test` runs the shared protocol vectors (copied byte-for-byte into `src/test/resources/vectors`): V1 canonicalization, domain tags, artifact envelopes, the 21 verification decisions,
request binding, policy hash, the 9 artifact and 11 transparency-proof vectors of `test-vectors/artifact-v1.json`; plus an HTTP test (JDK `HttpServer`) that calls every operation of the
contract and checks verb, URL, credential and body. The same vectors pass in the JavaScript, Python and Go SDKs and in two independent verifiers.

## Known limits

- Protocol **V1** only: the V2 families (JCS-P1 canonicalization, action/delegation/approval/receipt/audit-v8 vectors) are not implemented in this SDK yet.
- No typed request/response models (JSON trees); no remote key discovery provider yet.
- Validated against a local test server only, not a production gateway.
