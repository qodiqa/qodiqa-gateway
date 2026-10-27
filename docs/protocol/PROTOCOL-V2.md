# QODIQA Protocol V2

> **Status:** normative for protocol V2 artifacts. V2 issuance is off by default (`QODIQA_PROTOCOL_V2_ISSUE`).
> **Relation to the current protocol:** `docs/protocol/QODIQA-PROTOCOL.md` (V1, as implemented) stays valid and unchanged. V2 is
> additive: a V1 artifact verifies exactly as before (see `COMPATIBILITY.md`).

Key words MUST / MUST NOT / SHOULD are normative. Hashes are lowercase hex SHA-256 unless stated; times are Unix epoch milliseconds.

## 0. What this document freezes

1. identifiers (domain tags, claim names, error codes) — section 1;
2. the canonicalization profile used by every V2 hash — section 2;
3. the V2 request binding — section 3, and the V2 artifact claims — section 4;
4. the action binding (`actionHash`) and the action artifact — section 5;
5. the signed receipt — section 6;
6. version negotiation and failure behaviour — section 7.

Anything not listed is not frozen. Names reserved for later waves are fixed in section 1 so that waves cannot collide.

## 1. Identifiers

### 1.1 Domain tags

A V2 hash is `SHA-256(utf8(tag) || utf8(canonical))` (tag bytes immediately followed by canonical bytes, no separator, as V1 section 2).

| tag | used for | wave |
|---|---|---|
| `QODIQA::REQUEST::V2` | `requestHash` of a V2 artifact (section 3) | |
| `QODIQA::ACTION::V2` | `actionHash` (section 5) | |
| `QODIQA::ACTION_ARTIFACT::V1` | envelope hash of an **action artifact** (section 5.2) — a different domain from `QODIQA::ARTIFACT::V1` | |
| `QODIQA::TOOL_SCHEMA::V1` | `schemaHash` of a registered tool schema | |
| `QODIQA::RECEIPT::V1` | signed receipt (section 6) | |
| `QODIQA::APPROVAL::V1` | human approval statement | |
| `QODIQA::DELEGATION::V1` | delegation token / chain link | |
| `QODIQA::KILL_SWITCH::V1` | signed kill-switch state | |
| `QODIQA::ANCHOR::V1` | external anchor statement over a checkpoint | |

The ordinary artifact envelope keeps its V1 tag `QODIQA::ARTIFACT::V1`. `QODIQA::AUDIT::V1` stays the audit entry domain
(`AUDIT-V8-FREEZE.md`). No tag may be reused for a different input shape. Every tag above MUST appear in the generated registry of the V1
document when implemented; `spec-check` fails if a tag here is implemented under another spelling.

### 1.2 Reserved payload names

V2 adds **exactly one** reserved top-level payload name: **`qodiqa`** (an object, section 4). Everything V2 needs — version, binding list,
model, limits, critical claims, action fields — lives inside it, so no generic name (`v`, `model`, `limits`, `kind`, `seq`, …) is
taken from existing or caller-supplied payloads. The V1 reserved names (`requestId`, `requestHash`, `policyHash`, `tenantId`,
`callerContext`) stay reserved; `/sign` refuses (HTTP 400, code `RESERVED_CLAIM`) a caller payload whose **top level** contains the key `qodiqa` or a look-alike of it (different case,
surrounding whitespace) on every protocol version. Look-alikes of the V1 reserved names keep today's behaviour (dropped with a warning), so existing V1
callers are not broken; a V2 request (section 4) refuses them as well; nesting the key deeper (inside `claims`) is not a
reservation breach and has no effect, because verifiers read `qodiqa` only at the top level of the payload by exact key match. For a V2
artifact the only other top-level names allowed are `provider` and `claims` (section 4).

### 1.3 Reserved error codes

Existing V1 codes keep their meaning. New codes (HTTP mapping under `QODIQA_BLOCK_HTTP_MODE=status` in parentheses):
`UNSUPPORTED_PROTOCOL_VERSION` (400), `PROTOCOL_VERSION_TOO_LOW` (403), `UNSUPPORTED_CRITICAL_CLAIM` (400), `ARTIFACT_REVOKED` (403),
`KILL_SWITCH_ACTIVE` (503), `ACTION_MISMATCH` (403), `ACTION_REPLAY` (409), `ACTION_ORDER_VIOLATION` (409), `WRONG_ARTIFACT_KIND` (403),
`TOOL_NOT_ALLOWED` (403), `TOOL_SCHEMA_CHANGED` (409), `TOOL_ARGUMENTS_INVALID` (400), `STREAM_TOOLS_UNSUPPORTED` (400), `APPROVAL_REQUIRED`
(see 7.5), `APPROVAL_INVALID` (403), `APPROVAL_EXPIRED` (403), `DELEGATION_INVALID` (403), `DELEGATION_ATTENUATION_VIOLATION` (403),
`DELEGATION_DEPTH_EXCEEDED` (403), `DELEGATION_CYCLE` (403), `DELEGATION_REVOKED` (403), `DLP_BLOCKED` (403), `SESSION_LIMIT_EXCEEDED` (429),
`SESSION_EXPIRED` (403), `RESERVED_CLAIM` (400), `QUERY_NOT_BINDABLE` (400, at issuance only; section 3). Binding failures of a V2 request keep the V1 code `REQUEST_MISMATCH`.

Canonicalization error codes (section 2.7) are a separate vocabulary used by libraries and vectors.

## 2. Canonicalization profile JCS-P1

V2 hashes are computed over **JCS-P1**: RFC 8785 (JSON Canonicalization Scheme), with the input restrictions below. The restrictions only
*reject* inputs; for every accepted input the output is byte-identical to RFC 8785 and to the V1 canonicalizer (`src/utils/stableStringify.js`).
A hash is always computed over the **value** of the parsed JSON, never over its text.

2.1 **Parsing.** The input is UTF-8 text (invalid UTF-8, a BOM or a declared non-UTF-8 charset ⇒ `INVALID_UTF8`). The parser MUST be
a strict JSON parser that (a) rejects duplicate object keys (`DUPLICATE_KEY`), (b) parses **every number to an IEEE-754 double**, and (c)
rejects a number that is not finite after parsing (`NON_FINITE_NUMBER`, e.g. `1e999`). `JSON.parse` and `express.json()` do not satisfy (a);
gateways and SDKs use a dedicated parser (and `JSON.parse`/`json.loads` are used only to parse values that cannot contain duplicate keys).
Python implementations MUST convert integer literals through `float()` semantics (so `2^53+1` and `9007199254740993` parse to the same
double as in JavaScript). Because the hash is over the double, **every number whose magnitude (the parsed double) exceeds 2^53−1 (9007199254740991) is rejected, however it is spelled**
(`NUMBER_OUT_OF_RANGE`: `9007199254740993`, `1e17`, `9007199254740992.0`, `1e300`), so that two different integers can never hash alike and
the canonical text of an accepted number always parses back to itself. Numbers of magnitude ≤ 2^53−1, with or without fraction or exponent, are
accepted (the value is the double they denote); `1e-300` is accepted.

2.2 **Numbers** follow RFC 8785 section 3.2.2.3 (ECMAScript `Number::toString`): `-0` serializes as `0`; `1.0`, `1e0` and `1` are the same value
and the same canonical text `1`; `0.7` stays `0.7`; the exponent form of RFC 8785 applies only to magnitudes below 1e-6, since larger ones are out of range here. Protocol identifiers and counters (`seq`, `limits.*`) MUST be safe
integers (validated at the field, section 4). **Whoever executes bound data (a tool server, a provider) MUST be given the canonical JCS-P1 text of
the bound value, not the text the client sent**: the hash binds the value, and a consumer that re-parses a different spelling (for example with
exact decimals) could see a different number than the one that was authorized. Decimals therefore
travel as numbers (tool arguments with `0.7`, JSON Schema `minimum: 0.5`) — no string encoding is required.

2.3 **Strings** MUST already be in Unicode NFC (Unicode 15.0 or later; a string that is NFC under the Unicode Normalization Stability policy
is NFC in every later version) and MUST NOT contain lone surrogates; otherwise `STRING_NOT_NFC` / `LONE_SURROGATE`. This applies to every
string, **including object keys**, and to the derived strings of section 3 (path, decoded query names and values, header values). The
canonicalizer never normalizes silently.

2.4 **Objects:** keys sorted by UTF-16 code units (RFC 8785 section 3.2.3); `__proto__`, `constructor`, `prototype` as keys are rejected
(`FORBIDDEN_KEY`). Arrays keep their order. A JSON value is built from objects, arrays, strings, numbers, `true`, `false`, `null`;
`undefined`, functions, symbols, bigints, dates and non-plain objects are `UNSUPPORTED_TYPE`.

2.5 **Limits.** Depth: a scalar has depth 0; an array or object has depth 1 + the maximum depth of its members; the value is rejected
(`MAX_DEPTH_EXCEEDED`) above **64**. An empty array or object has depth 1. Size: the canonical bytes of the **whole hashed document** are ≤ 1 MiB (for the request binding the
document of section 3; for an action, `A` of section 5.1) and the canonical payload of a signed artifact ≤ 64 KiB (`MAX_SIZE_EXCEEDED`).

2.6 **Known parser hazard.** One Node.js release line (v24.19.0, V8 13.6) mis-parses object keys after a key containing a backslash
(`JSON.parse` returns `\` for a later `"`); the production runtime (Node 22) is not affected. The dedicated parser of 2.1 makes the protocol
independent of the host `JSON.parse`; the repository records the issue as a defect.

2.7 **Error codes:** `INVALID_UTF8`, `INVALID_JSON`, `DUPLICATE_KEY`, `NON_FINITE_NUMBER`, `STRING_NOT_NFC`, `LONE_SURROGATE`, `FORBIDDEN_KEY`,
`UNSUPPORTED_TYPE`, `MAX_DEPTH_EXCEEDED`, `MAX_SIZE_EXCEEDED`, `NUMBER_OUT_OF_RANGE`. When an input breaks several rules, the code reported is the first rule
in this order: `INVALID_UTF8`, `INVALID_JSON`, `DUPLICATE_KEY`, `NON_FINITE_NUMBER`, `NUMBER_OUT_OF_RANGE`, `FORBIDDEN_KEY`, `UNSUPPORTED_TYPE`, `STRING_NOT_NFC`,
`LONE_SURROGATE`, `MAX_DEPTH_EXCEEDED`, `MAX_SIZE_EXCEEDED`.

Vectors `V2-CANON-*` (the RFC 8785 number vectors, every rejection class above, and the cases on which draft 1 was ambiguous) are generated
from the implementation and re-derived by the independent verifiers — see `VECTORS-FORMAT.md`. A second implementation written by someone
other than the author MUST reproduce them before the gate.

## 3. V2 request binding

`requestHash(V2) = SHA-256("QODIQA::REQUEST::V2" || JCS-P1({ v: 2, method, path, query, headers, body }))` where

* **`method`** — one of `GET POST PUT PATCH DELETE HEAD OPTIONS` (ASCII, matched case-insensitively and upper-cased); anything else is refused.
* **`path`** — the path component of the raw request-target, which MUST be in origin-form (it starts with `/`; absolute-form, authority-form and `*` are
  refused; a `#`, a space or a control character (U+0000–U+001F, U+007F) in the target is refused), exactly as received: no query string, no normalization (no dot-segment
  removal, no percent-decoding, no case folding, trailing and doubled slashes kept). It MUST be ASCII (non-ASCII must arrive percent-encoded);
  a request-target with raw non-ASCII bytes is refused. A different spelling of the same resource is a different path.
* **`query`** — the substring after the first `?` (none, or an empty one after `?`, ⇒ `[]`). The raw query MUST NOT contain `+` or `;`
  (use `%20` / `%2B` / `%3B`): different backends read these differently, so the request is refused (`REQUEST_MISMATCH`) rather than guessed.
  Split on `&`; **empty segments are ignored** (`a=1&&b=2` and `a=1&b=2` are the same query). Each segment is split at the first `=` (none ⇒
  value `""`); name and value are percent-decoded as strict UTF-8 (`%` not followed by two hex digits, or an invalid UTF-8 result ⇒ refused).
  The pairs are **stably sorted by name only** (UTF-16 code units), keeping the original relative order of pairs with the same name, so the order
  of repeated parameters **is** bound (`a=1&a=2` ≠ `a=2&a=1`). The value is an array of `[name, value]` arrays.
* **`headers`** — an object whose keys are exactly the names in the artifact's `qodiqa.bind.headers` (lower-case, unique, section 4) and whose
  values are: the field value(s) decoded as strict UTF-8; for each received field line, leading and trailing SP and HTAB removed; lines of the
  same name joined with `", "` in the order received; a listed header that is absent ⇒ `null`. The gateway MUST read the raw header list (a
  runtime that folds duplicate headers silently, such as Node's `req.headers`, does not suffice).
* **`body`** — the body bytes as received, after removing any transfer framing; a request with a `Content-Encoding` other than `identity` is refused
  (`REQUEST_MISMATCH`), so the hashed bytes are always the bytes of the JSON text — parsed by the parser of 2.1 (a plain JSON object); an **absent or empty body is `{}`**; a body that is valid JSON but not
  an object is refused.

Header-name rules: `^[a-z0-9-]{1,64}$`, at most 16, none of `x-qodiqa-artifact`, `authorization`, `proxy-authorization`, `cookie`, `set-cookie`,
`host`, `content-length`, `transfer-encoding`, `connection`, `keep-alive`, `te`, `trailer`, `upgrade`, `via`, `forwarded`, `x-forwarded-for`.

Whitespace-only body text is invalid JSON (`INVALID_JSON`); only a body of **zero bytes** is the empty body `{}`. A BOM is never stripped: in a
header or query it is the character U+FEFF; at the start of a body it is `INVALID_UTF8` (as in 2.1).

**At issuance** `/sign` builds the same hashed document from the `request` it is given (`method`, `path`, `body` as V1, plus the optional `query`
(raw string, without `?`) and `headers` (object of the bound names) fields, and the top-level `v2` block of section 4) and refuses with
`QUERY_NOT_BINDABLE` and a message naming the offending character if the query contains a raw `+` or `;` — so a client learns why, instead of
failing later with `REQUEST_MISMATCH`.

Verification (V2): `qodiqa.v === 2`, `payload.requestId` is a UUID v4, `payload.requestHash` is 64 lowercase hex, the hash recomputed from the
request actually received equals it (constant time), and `qodiqa.bind.headers` satisfies the rules above — else `REQUEST_MISMATCH`. The
failure response carries **constant** `details` (no `issue` text, no indication of which component differed). The query is always bound in V2.

## 4. V2 artifact claims

The envelope is unchanged (`expiry`, `payload`, `publicKeyId`, `signature`, `timestamp`; V1 section 3). A V2 payload has these top-level names only:

| name | type | required | meaning |
|---|---|---|---|
| `requestId`, `tenantId` | as V1 | yes | |
| `requestHash`, `policyHash`, `callerContext` | as V1 | yes for `kind: "request"` only | `requestHash` is the V2 hash of section 3; an action artifact (5.2) has none of the three |
| `provider` | string | AI routes | as V1 |
| `claims` | plain object | no | the **only** place for caller-supplied application data |
| `qodiqa` | object | yes | the V2 block below |

`payload.qodiqa`:

| field | type | required | meaning |
|---|---|---|---|
| `v` | integer `2` | yes | protocol version |
| `kind` | `"request"` or `"action"` | no (default `request`) | what the artifact authorizes; verification points accept only their own kind (`WRONG_ARTIFACT_KIND`) |
| `bind` | `{ headers: string[] }` | yes | which headers are bound (section 3); may be empty; no duplicates |
| `model` | string or `null` | AI routes | the model the artifact authorizes; MUST equal the model in the (bound) body |
| `limits` | `{ maxTokens?: safe int ≥ 1, maxCostMicros?: safe int ≥ 0 }` | no | caps the gateway MUST apply to the provider call |
| `crit` | string[] | no | non-empty when present, no duplicates, each entry the name of a field **inside `qodiqa`** (never a top-level name, never `crit`, `v`, `kind` or `bind`, which every V2 verifier must understand anyway); a verifier that does not understand an entry ⇒ `UNSUPPORTED_CRITICAL_CLAIM`. Unknown fields inside `qodiqa` that are not listed in `crit` are ignored (but signed) |
| action fields | see 5.2 | `kind: "action"` only | |

**`/sign` request for V2.** The caller sends the V1 body plus a top-level `v2` object `{ bind: { headers: [...] }, model?, limits?, crit? }`; the
gateway computes `requestHash` (section 3) and builds `payload.qodiqa = { v: 2, kind: "request", ...v2 }`. Caller application data goes to
`claims`. `/sign` rejects any other top-level payload name and any unknown field inside `v2` (strict by default), and **never** issues
`kind: "action"`. A verifier ignores unknown top-level names of a received artifact (they are signed but have no effect).

**Canonicalization of artifacts.** The envelope hash (V1 section 3.2) keeps the V1 canonical form (`stableStringify`), for V1 and V2 alike; it is not
changed. The JCS-P1 limits (depth 64, NFC, number range, size 64 KiB) are enforced **at issuance** — `/sign` for the whole payload including `claims`,
`/v1/actions/authorize` for action artifacts — and are not re-applied by a verifier to a received artifact: a verifier that rejected an artifact for a
JCS-P1 limit that the signed canonical form tolerates would disagree with V1 verifiers about the same signature. (Hashes of V2 requests and actions are
over JCS-P1 documents and are checked in full.) A verifier SHOULD reject a received artifact that contains duplicate keys; since it verifies the
signature over its own parse, a parser disagreement fails closed in any case. "At issuance" means issuance of V2 artifacts; `/sign` for V1 is unchanged.

Time rule (as V1): `timestamp` and `expiry` are positive safe integers, `timestamp < expiry`; window, tolerance and the 60 s maximum
lifetime as V1.

## 5. Action binding

### 5.1 `actionHash`

For an agent tool call (wave) `actionHash = SHA-256("QODIQA::ACTION::V2" || JCS-P1(A))` with
`A = { v: 2, tenantId, agentId, sessionId, seq, tool: { server, name, schemaHash }, args, parentRequestHash, prevActionHash }`:

* `agentId`, `sessionId` — gateway-issued UUID v4; `seq` — safe integer starting at 1, equal to the session's `nextSeq` at authorization (5.2: incremented atomically with the consumption of the action's `requestId`);
  `prevActionHash` — the previous action's hash, `null` for `seq = 1`;
* `tool.server` — registered server id; `tool.name`; `tool.schemaHash = SHA-256("QODIQA::TOOL_SCHEMA::V1" || JCS-P1(argument JSON Schema))`;
  a changed schema changes the hash and is refused (`TOOL_SCHEMA_CHANGED`);
* `args` — the exact arguments, validated against the registered schema, under JCS-P1 (numbers may be decimals);
* `parentRequestHash` — the V2 `requestHash` of the model request in whose context the action was proposed, or `null`.

### 5.2 The action artifact

An **action artifact** is signed with a different envelope domain: `envelopeHash = SHA-256("QODIQA::ACTION_ARTIFACT::V1" ||
canonical({expiry, payload, publicKeyId, timestamp}))`, signature as V1 section 3.2. An ordinary artifact therefore never verifies as an
action artifact and vice versa, even under the same key. Its payload:

`{ requestId, tenantId, qodiqa: { v: 2, kind: "action", bind: { headers: [] }, agentId, sessionId, seq, actionHash, approvalRef?, crit? } }`

It is issued **only** by `POST /v1/actions/authorize`; `/sign` signs only the ordinary domain and refuses `qodiqa` in caller data. The
executor recomputes `actionHash` from what it is about to execute and compares in constant time (`ACTION_MISMATCH`); the `requestId` is consumed
exactly once (`ACTION_REPLAY`); `seq` MUST equal the session's stored `nextSeq`, which the executor increments atomically with consuming the `requestId` (`ACTION_ORDER_VIOLATION`); the artifact kind MUST be `action`
(`WRONG_ARTIFACT_KIND`). Action artifacts have no `requestHash`, `policyHash` or `callerContext` (they bind an action, not an HTTP request); the agent identity in `agentId` replaces `callerContext`.

## 6. Signed receipt

`receipt = { v: 1, requestId, decision, issuedAt, entryHash, leafHash, keyId, signature }` (no `tenantId` and no `reason`: the unauthenticated retrieval below must not reveal more than the outcome) where `requestId` is the `payload.requestId` of the consumed artifact (the same value hashed into the audit entry's `requestId`), `decision` is the
`decision` (`ALLOW`/`BLOCK`) of the audit `DECISION` entry of that request, `issuedAt` is the time (ms) the receipt is signed, `entryHash` is the hash of that
`DECISION` entry and `leafHash` the hash of the transparency leaf registered for it (both 64 hex), `keyId` is a **transparency** key, and
`signature = base64(Ed25519.sign(SHA-256("QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature))))` (raw 32-byte digest).

* A receipt may also be issued for an `ACTION_COMMIT` entry (the `{ result, receipt }` response of `POST /v1/tools/call`): then `requestId` is the action
artifact's `requestId`, `decision` the entry's decision, and `entryHash`/`leafHash` refer to that entry and its leaf. A receipt is signed once, when the response is produced, and never re-signed. It exists only for a **persisted** leaf. If the leaf cannot be persisted the response is a fail-closed BLOCK (503) and carries no
  receipt; where transparency is not fail-closed the `receipt` field is **absent** (never `null`, never a receipt with a null hash).
* A receipt whose `keyId` is revoked verifies only in the timed mode (a `trustedAt` from an independent authority before `revokedAt`).
* It proves *that the gateway recorded the decision*, not that the decision was correct.
* Retrieval (`GET /v1/transparency/receipt/{requestId}`) is authorized by knowledge of `requestId` (UUID v4, 122 bits of entropy) — the one
  deliberate exception to "every endpoint is authenticated" (`ENDPOINTS-RESERVED.md`); the response contains the receipt only. The signed document is frozen with this field set.

## 7. Version negotiation and failure behaviour

1. **Selector.** A payload with **no** `qodiqa` key is V1. A payload with a `qodiqa` object is read by its `v`: `2` ⇒ V2 rules; any other value or
   type ⇒ `UNSUPPORTED_PROTOCOL_VERSION`. (Because artifacts live at most 60 s and `qodiqa` is refused in caller data on every version, no
   existing V1 artifact can contain the key.) There is no downgrade: an artifact with `qodiqa` is never verified under V1 rules.
2. **Switches.** Issuance of V2 artifacts is behind `QODIQA_PROTOCOL_V2_ISSUE` and acceptance behind `QODIQA_PROTOCOL_V2_ACCEPT` (both default
   off until the gate). With acceptance off, a V2 artifact is `UNSUPPORTED_PROTOCOL_VERSION`. V1 behaviour is unchanged either way.
3. **Minimum version.** `QODIQA_PROTOCOL_MIN_VERSION` (default `1`) and the per-tenant setting `minProtocolVersion` (default `1`, stored in the signed
   control plane so that one compromised node cannot lower it) set the lowest protocol version a gateway accepts; below it ⇒ `PROTOCOL_VERSION_TOO_LOW`. A tenant that needs the bound query/headers sets it to `2`,
   which closes the downgrade in which an issuer simply picks V1.
4. **Old verifiers.** A V1-only verifier given a V2 artifact verifies the signature but does not enforce the claims inside `qodiqa`; a V1
   gateway checks the V1 `requestHash` and fails (`REQUEST_MISMATCH`), never accepting silently. Components that enforce V2 claims MUST honour
   `crit`. Upgrade order: verifiers/SDKs, then gateway, then issuers.
5. **`APPROVAL_REQUIRED`.** The HTTP response is `202` with the management envelope `{ status: "pending", data: { approvalId } }` — it is not a
   protocol decision; the audit entry records `decision: "BLOCK"`, `reason: "APPROVAL_REQUIRED"` until an approval is decided (fail-closed).
6. **Uniform failures.** Every V2 rejection that depends on request content returns `REQUEST_MISMATCH` with constant details.

## 8. Conformance

Vectors (append-only, `VECTORS-FORMAT.md`): `V2-CANON-*`, `V2-REQ-*` (≥ 40 including every case on which draft 1 was ambiguous), `V2-ART-*`,
`ACTION-*` (≥ 30, wave), `V2-RECEIPT-*`. All V1 vectors listed in `docs/protocol/vectors/INDEX.json` MUST NOT change; `npm run protocol:check`
and both independent verifiers gate every change. The Python canonicalizer and SDK gain the number serializer of 2.2 (they refuse
non-integers today); until then V2 hashes are produced by the gateway and checked by the JavaScript verifiers only.

## 9. Freeze record

| decision | alternatives not taken | consequence |
|---|---|---|
| numbers: full RFC 8785 (doubles), no integers-only restriction | integers only with decimals as strings (draft 1) | tool arguments and JSON Schemas keep their natural numbers; every language needs the ECMAScript number formatter (vectors from RFC 8785 guard it) |
| strings must already be NFC (reject, never normalize) | silent normalization | the bytes hashed are the bytes sent |
| V2 claims live in one reserved object `qodiqa` | generic top-level names (`v`, `model`, `limits`, …) | no collision with caller payloads; one rule for `/sign` |
| action artifacts use their own envelope domain | same domain + `kind` claim | a `/sign` client cannot forge an action artifact |
| query: `+` and `;` refused, stable sort by name, empty segments ignored | form-decoding of `+`; sort by (name, value) | proxies/parsers cannot disagree about the meaning of the bound query; repeated-parameter order is bound |
| headers bound only when listed, secrets and hop-by-hop excluded | bind all headers | stable against proxy-added headers |
| tenant minimum protocol version | issuer's choice | closes downgrade to V1 |
| receipt only for persisted leaves; public retrieval by requestId | receipt with null hashes; authenticated retrieval | a receipt is never weaker than the log; auditors can fetch without credentials |
| uniform `REQUEST_MISMATCH` details; but a clear refusal at issuance for `+`/`;` | helpful diagnostics at verification | no oracle on which component differed; clients that form-encode spaces as `+` must switch to `%20` and are told so when they sign |
| envelope hash keeps the V1 canonical form; JCS-P1 limits enforced at issuance only | JCS-P1 for the envelope too | a V1 verifier and a V2 verifier can never disagree about one signature |
| every number beyond ±(2^53−1) rejected (spelling-independent); executors receive canonical text | reject only integer spellings (draft 3: a canonical text that failed its own parser); accept all doubles | two different integers can never hash alike; consumers cannot be given a different spelling |
| receipt without `tenantId`/`reason` | full receipt | the one unauthenticated endpoint reveals only the outcome |

<!-- APPROVAL RECORD — written by the owner, or by the agent only after (re-verification of draft 5) is green and exists. -->
