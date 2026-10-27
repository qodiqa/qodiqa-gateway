# Policy language (ABAC) and the extended rule types

Rules live in the tenant's policy set. They are validated when the set is loaded, evaluated in `priority` order (the first refusal decides), covered by `policyHash`, and published through the
normal four-eyes governance. This page covers the attribute-based rule (`ABAC`) added and the ready-made rules built on it. The older types (`REQUIRE_CONSENT`, `BLOCK_IP`,
`TIME_WINDOW`, `RATE_LIMIT`) and the data rules (`DLP`, `DATA_RESIDENCY`) are unchanged.

## The ABAC rule

```json
{ "id": "ABAC_MODEL_ALLOW", "type": "ABAC", "priority": 31, "enabled": true,
  "config": { "abacFormat": 1, "effect": "REQUIRE", "reason": "MODEL_NOT_ALLOWED",
              "when": { "attr": "request.model", "op": "in", "value": ["gpt-4o-mini", "gpt-4o"] } } }
```

* `effect: "DENY"` refuses the request **when the condition is true**. `effect: "REQUIRE"` refuses **unless the condition is true**.
* **A missing attribute** makes a comparison false. So a DENY rule does not fire on something it cannot see, and a REQUIRE rule refuses on it: **write allow-lists as REQUIRE** (default deny).
* The refusal reason is `ABAC_<reason>` (`reason` is 1-32 characters of `A-Z 0-9 _`); the label tells the operator which rule fired (the reasons of ABAC rules are chosen by the policy author, so they are not enumerated in the error catalogue).
* `appliesTo: "request"` (default) is evaluated on `/ai/chat` (and on `/verify/v2`, which sees the same attributes, and on a failover target). `appliesTo: "tool"` is evaluated when a tool call is
  **authorised** (`POST /v1/actions/authorize`), before a chain position is reserved.

### Conditions

A condition is a JSON tree - no code, no regular expressions: `{ "all": [...] }`, `{ "any": [...] }`, `{ "not": {...} }` or a leaf `{ "attr": "...", "op": "...", "value": ... }`.
Operators: `eq ne in notIn lt lte gt gte between exists notExists startsWith endsWith contains cidr hasAny hasAll`. Bounds: depth 6, 100 nodes, 200 values per array, strings of 256
characters. The attribute must be in the catalogue below and the operator and value must suit its type; anything else **fails when the policy is loaded**.

### Attributes

| Attribute | Type | Source |
|---|---|---|
| `subject.userId`, `subject.callerId`, `tenant.id` | string | the verified signing key, the authenticated caller, the tenant |
| `request.provider` | string | the provider named by the signed artifact |
| `request.model` | string | the request body |
| `request.purpose`, `request.dataRegion` | string | **declared by the caller** in the body (`purpose`, `dataRegion`): a claim, not a proof |
| `request.stream`, `request.promptChars`, `request.messages` | boolean / number | the request body |
| `cost.estimatedTokens` | number | an upper estimate (characters / 3) |
| `resource.classification` | string | PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED, computed by the DLP classifier (see [DLP.md](DLP.md)); absent when the DLP module is not installed |
| `resource.categories` | string[] | the DLP rule ids found in the request (CARD, EMAIL, ...) |
| `env.hour`, `env.dow`, `env.ip` | number / string | UTC time of the evaluation, client IP |
| `ops.mode` | string | `normal` / `degraded` / `maintenance` / `incident`, from `QODIQA_OPS_MODE` on the instance (anything else is `normal`) |
| `tool.server`, `tool.name`, `tool.class`, `tool.reversible`, `agent.id` | string / boolean | the tool call being authorised (tool scope) |

The classification is computed only when an enabled ABAC rule mentions a `resource.*` attribute, because it costs a DLP scan of the request. It is computed on the request **as received**
(before an earlier DLP rule redacts it), so a rule on it sees what the caller sent.

### Ready-made rules

`services/policy/abac/templates.js` builds complete rules for: a per-user allow- or deny-list, a model allow- or deny-list, a required declared purpose, a required data region,
a data-classification ceiling (optionally only toward some providers), a data-category deny-list (refuse a request carrying card numbers, say), an operational-mode deny (refuse during
maintenance or an incident), and for tools: an allow-list of server/name pairs and a deny-list of action classes. They are ordinary ABAC rules - read, hash and simulate them as such.

## Budgets, quotas and cost accounting

```json
{ "id": "BUDGET_DAILY", "type": "BUDGET", "priority": 50, "enabled": true,
  "config": { "budgetFormat": 1, "scope": "tenant", "period": "day",
              "limits": { "requests": 10000, "tokens": 5000000, "costMicros": 25000000 },
              "perRequest": { "maxTokens": 20000, "maxCostMicros": 500000, "maxLatencyMs": 30000 },
              "pricing": { "currency": "USD", "inputPerMillionMicros": 2000000, "outputPerMillionMicros": 8000000, "assumedOutputTokens": 1000 } } }
```

* `scope: tenant` counts everyone of the tenant together, `caller` counts each authenticated caller separately; `models` restricts a rule to some models. Periods (`minute` ... `month`) are
  **fixed buckets aligned to the Unix epoch** (a day is a UTC day), so a limit can be reached twice within a short span that straddles a bucket boundary. Money is in millionths of the rule's currency (`costMicros`), rounded up per request.
* **When it is charged.** Not in the rule evaluation: just before the provider is called, after every other rule (consent, ABAC, DLP, residency, ...) has passed, so a request refused for another
  reason never uses a budget. The charge is atomic (a Lua script on Redis; exactly `limit` of N parallel requests win) and uses an **upper estimate** (the prompt's tokens, plus
  `assumedOutputTokens` at the output price for money). If any counter would exceed its limit, nothing stays charged and the request is refused: `BUDGET_EXCEEDED_REQUESTS|TOKENS|COST`
  (HTTP 429, a throttle), `BUDGET_REQUEST_TOO_LARGE|TOO_COSTLY` (a per-request limit). If the counters cannot be reached the request is refused (`BUDGET_UNAVAILABLE`, 503 in status mode).
* **Settling.** When the provider answers, the estimate is replaced by the real usage it reported (input and output tokens; the counters move down or up), the cost is computed from `pricing`
  and recorded as a `COST_ACCOUNTED` event (model, tokens, `costMicros`, currency, `estimated: true` when the provider reported no usage). A provider error answer, or a failure before the provider was called, returns the whole
  reservation; a call cut short after it was dispatched (latency limit, client abort) stays charged with the estimate. A streaming request is charged with the estimate and not settled (a stream reports no usage to settle with); one refused before dispatch is refunded.
* **Latency.** `maxLatencyMs` (the smallest of the applicable rules) bounds the provider call: when it is exceeded the call is abandoned and the request fails as a timeout (`REQUEST_TIMEOUT`, 504),
  even if the provider ignores cancellation; its late answer is discarded. The estimate stays charged (the provider was called).
* **Tariffs** come from the operator in the rule today; provider price lists and routing by cost arrive with.

## Custom content rules

A tenant can block (or only detect) its own words, phrases and patterns in requests and/or answers:

```json
{ "id": "POL-CR", "type": "CONTENT_RULE", "priority": 20, "enabled": true,
  "config": { "contentFormat": 1, "direction": "input", "action": "BLOCK",
    "items": [ { "id": "proj", "kind": "phrase", "value": "project nightingale" },
               { "id": "code", "kind": "regex", "value": "nx-[0-9]{4}", "weight": 2 } ],
    "threshold": 2,
    "thresholds": [ { "models": ["strict-model"], "threshold": 1 }, { "purposes": ["legal"], "threshold": 3 } ],
    "scope": { "models": ["m1"], "purposes": ["support"] } } }
```

- `kind`: `word` (whole word), `phrase` (substring), `regex`. Case-insensitive unless `caseInsensitive: false`. At most 200 items.
- Text is normalised before matching (NFKD, invisible, blank-looking and combining characters removed, whitespace collapsed), so zero-width splitting, fullwidth forms and extra spaces do not hide an item.
- The rule fires when the weights of the DISTINCT matched items reach the threshold that applies; `thresholds` entries (first match wins) override it per model and/or declared `purpose`; `scope` limits the rule to listed models/purposes (an unknown model or missing declaration counts as in scope).
- Regular expressions run on a linear-time engine (no backtracking, so no ReDoS); lookaround, back-references, `` and named groups are refused when the policy is saved, as are patterns above 512 characters or 500 states. Text above 256 KiB cannot be scanned by a regex: a BLOCK rule refuses it (`CONTENT_RULE_UNAVAILABLE`).
- Answers: `CONTENT_RULE_BLOCKED` with `details.contentRule` (rule id, item ids, score, threshold) - never the matched text. An output-direction rule cannot be applied to a stream: `CONTENT_RULE_STREAMING_UNSUPPORTED`.

## Known limits

- `purpose` and `dataRegion` are declared by the caller; rules that scope on them (`scope.purposes`, `thresholds.purposes`, ABAC `request.purpose`) are policy routing, not a security boundary. Use model, tenant and caller scopes for enforcement.
- Streaming requests ignore `perRequest.maxLatencyMs`, are charged with the estimate (a stream reports no usage) and keep the charge when the stream fails after it started.
- The token estimate is an upper bound (1/3 per character, 2 per character beyond U+02FF); the real count is settled when the provider reports usage.
- Content rules normalise (NFKD, invisible and blank-looking characters, combining marks, case) but do not fold look-alike letters from other scripts or leetspeak; add those spellings as items.
- Content-rule regex scanning is bounded (10 million state-steps per check, about 0.4 s of CPU in the worst case); a BLOCK rule refuses text beyond that. The token estimate is an upper bound for common tokenisers; it is not proven for base64/hex text or byte-level tokenisers.
- The rule-result cache is off by default (`QODIQA_POLICY_DECISION_CACHE=true` turns it on).

## Routing

A ROUTING rule picks the provider (and model) for a request from an operator-listed set of candidates:

```json
{ "id": "POL-ROUTE", "type": "ROUTING", "priority": 20, "enabled": true,
  "config": { "routingFormat": 1, "strategy": "cheapest", "modelMode": "fill",
    "when": { "attr": "request.purpose", "op": "eq", "value": "support" },
    "candidates": [ { "provider": "openai", "model": "gpt-4o-mini" }, { "provider": "local" } ],
    "pricing": { "openai": { "currency": "USD", "inputPerMillionMicros": 150000, "outputPerMillionMicros": 600000 }, "local": { "currency": "USD", "inputPerMillionMicros": 0, "outputPerMillionMicros": 0 } } } }
```

* `strategy`: `ordered` (as listed), `cheapest` (estimated cost of this request from `pricing`; a candidate with no price sorts last), `fastest` (recent average latency of the provider; unmeasured providers after measured ones), `least-loaded` (calls in flight on this process). Degraded providers are tried after healthy ones.
* The first enabled ROUTING rule (by priority, then id) whose `when` is true decides. A candidate other than the provider the artifact names is used **only if the same caller is authorised for it now** - the failover authorisation: signing identity enabled with `SIGN_ARTIFACT`, the identity's provider scope, consent and the effective policies (residency, data-class limits, ABAC, all evaluated FOR THE CANDIDATE and the model that would be sent). A candidate that fails is skipped (the reason is recorded); the artifact's own provider is the last fallback.
* `modelMode`: `fill` (default) uses a candidate's `model` only when the request named none; `override` always replaces the request's model. Routing runs **before** the budget is reserved, so quotas, tariffs and latency limits apply to the provider and model that will serve the request.
* The decision is recorded in the audit entry (`executionContext.routed`: rule, strategy, from/to, model replacement, candidates skipped and why) next to `requestedProvider` / `executingProvider`.
* Data-class transmission rules per provider are ABAC rules (`dataClassLimit(max, { providers })` in the ready-made rules above) and apply to a routed or failover target the same way.
* Streaming requests are routed the same way (the routed provider streams; a failover mid-way is never attempted once the stream was accepted).

## What this does not do

* A declared attribute (`purpose`, `dataRegion`) is only as good as the caller. The rules make a declaration **mandatory** and **auditable**; they cannot make it true.
* Custom content-blocking rules, the decision cache and the policy-format migration are described in their own sections as they are added.
* Budget buckets are aligned to the epoch (not rolling), and a quota counted per instance group is only as shared as the policy store (Redis) is: with the in-memory store each process counts alone.
