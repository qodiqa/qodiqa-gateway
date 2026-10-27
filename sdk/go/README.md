# QODIQA Go SDK

`github.com/qodiqa/qodiqa-go` — a client for a QODIQA gateway and an offline verifier for its artifacts. Standard library only (Go 1.21+).

> Status: **tested and verified internally** (see "What is tested"). Not yet published; the module path is provisional until the project's publishing step.

## Call any documented operation

```go
c, _ := qodiqa.New(qodiqa.Config{BaseURL: "https://gateway.example.com", APIKey: os.Getenv("QODIQA_OPS_KEY")})
res, err := c.Call(ctx, "listAlerts", qodiqa.CallArgs{})
if err != nil {
    if e, ok := qodiqa.AsError(err); ok && e.Kind == qodiqa.KindRateLimit { /* e.RetryAfter */ }
}
doc, _ := res.JSON()
```

`Operations()` lists the 364 operations of the HTTP contract (generated from `docs/api/openapi.json`; `npm run sdk:check` in the repository fails when this table drifts). Path/query/header
mistakes are rejected before any request; credentials follow the contract (`APIKey` for operator operations, `SignToken` for signing, none for public ones). SSE operations use
`Stream` (events until the `[DONE]` frame; a stream that ends early is an error). Retries follow the gateway's contract (idempotent verbs on 429/5xx; POST only on 429 and never on `/ai/chat`;
`SERVER_OVERLOADED` always; never after `MFA_LOCKED`); an `OTPProvider` answers the operator MFA step-up once. Request and response bodies are plain JSON (`any`).

## Verify an artifact offline

```go
keys, _ := qodiqa.NewStaticKeyProvider([]qodiqa.StaticKeyEntry{{KeyID: "tenant:key_v1", PublicKey: spkiBase64, Status: "active"}})
v, _ := qodiqa.NewArtifactVerifier(qodiqa.ArtifactVerifierOptions{Keys: keys})
artifact, _ := qodiqa.ParseJSON(raw)         // keeps numbers exact
r := v.Verify(artifact, nil)                  // r.VerificationStatus == "valid"
```

`DecideArtifact` is the gateway's own V1 decision procedure (key lifecycle, time limits) for a trust bundle with key timelines; `RequestHash`, `PolicyHash`, `Canonicalize` and
`DomainHash` expose the protocol's canonical forms.

## What is tested

`go test ./...` runs the shared protocol vectors (copied byte-for-byte into `testdata/`): V1 canonicalization (8), domain tags (all), artifact envelopes, the 21 verification decisions, request
binding, policy hash, and the 9 artifact + 11 transparency-proof vectors of `test-vectors/artifact-v1.json`; plus an HTTP test that calls every operation of the contract against a local
server and checks verb, URL, credential and body. The same vectors pass in the JavaScript, Python and Java SDKs and in two independent verifiers.

## Known limits

- Protocol **V1** only: the V2 families (JCS-P1 canonicalization, action/delegation/approval/receipt/audit-v8 vectors) are not implemented in this SDK yet.
- Strings with lone UTF-16 surrogates are not canonicalised like JavaScript (Go decodes them to U+FFFD).
- No typed request/response models; no remote key discovery provider yet (use `StaticKeyProvider` with a trust bundle you obtained out of band).
- Validated against a local test server only, not a production gateway.
