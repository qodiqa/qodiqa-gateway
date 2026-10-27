# Policy Simulation Engine — Component #40

> **2026-07-28 correction:** earlier versions of this document,
> and of's NIST AI RMF "MAP 1"
> bullet, described this engine as supporting "historical replay" and
> "replay of past requests." Those claims did not match the implementation:
> the engine has no code path that reads the audit log, the transparency
> log, or any other historical record. It evaluates only a synthetic
> context object supplied directly in the API request body, optionally
> including a caller-chosen timestamp (§16). This document is corrected to
> describe that accurately. No code changed as part of this correction.

The Policy Simulation Engine evaluates authorization decisions against the live policy set (or any draft/proposed set) **without any execution side effects**. It is the correct tool for what-if analysis, policy change impact assessment, and pre-deployment policy validation, using synthetic execution scenarios supplied by the caller. Simulation results do not depend on historical production data unless explicitly provided by future extensions.

## Table of Contents

1. [Core Guarantee: Zero Side Effects](#1-core-guarantee-zero-side-effects)
2. [Architecture](#2-architecture)
3. [API Reference](#3-api-reference)
4. [Request and Response Shapes](#4-request-and-response-shapes)
5. [Policy Version Selection](#5-policy-version-selection)
6. [Evaluation Trace](#6-evaluation-trace)
7. [Risk Classification](#7-risk-classification)
8. [Organization and Tenant Boundaries](#8-organization-and-tenant-boundaries)
9. [Dry-Run Policy Store](#9-dry-run-policy-store)
10. [Batch Simulation](#10-batch-simulation)
11. [Policy Comparison](#11-policy-comparison)
12. [Prometheus Metrics](#12-prometheus-metrics)
13. [SDK Usage](#13-sdk-usage)
14. [Authentication](#14-authentication)
15. [Error Handling](#15-error-handling)
16. [Implementation Notes](#16-implementation-notes)

---

## 1. Core Guarantee: Zero Side Effects

Every simulation call is **read-only**. The engine guarantees it will never:

| What it will NOT do | Why this matters |
|---|---|
| Register a nonce | Replay protection state is untouched |
| Increment a rate-limit counter | Quota consumption is unaffected |
| Write an audit record | Audit chain remains clean |
| Contact an AI provider | No latency, no cost, no data egress |
| Deliver a webhook | Downstream systems are not notified |
| Commit an artifact | Content-addressed storage is unmodified |
| Open a streaming connection | SSE/stream state is not mutated |

The field `executionPrevented: true` is present on every response object and every batch result item.

---

## 2. Architecture

```
POST /v1/policy/simulate
POST /v1/policy/compare
POST /v1/policy/simulate/batch
          │
          ▼
 src/api/routes/policySimulate.js   ← auth + routing
          │
          ▼
 src/core/simulation/simulationEngine.js
          │
          ├─ _resolvePolicies()         ← live OR provided draft/proposed
          │       │
          │       └─ services/policy/loader.js → validateAndPrepare()
          │
          ├─ _checkOrgBoundary()        ← assertActiveOrganization()
          │
          ├─ makeDryRunPolicyStore()    ← read-only wrapper around livePolicyStore
          │       └─ getCount() passed through
          │       └─ increment() is a no-op
          │
          └─ services/policy/engine.js → evaluate()   ← SINGLE evaluator
                    │
                    └─ returns { decision, reason, policyId }
                              │
                              ▼
                    _buildTrace()        ← derived deterministically
                    _buildExplanation()
                    _classifyRisk()
```

**Key design principle**: there is only one policy evaluator (`engine.evaluate()`). The simulation path calls it identically to the live enforcement path. The only differences are the policy store (dry-run) and the absence of post-decision side effects.

---

## 3. API Reference

All endpoints require ops-level authentication (see [Authentication](#14-authentication)).

### POST /v1/policy/simulate

Run a single policy simulation.

```
POST /v1/policy/simulate
Authorization: Bearer <ops-token>
Content-Type: application/json
```

### POST /v1/policy/compare

Compare two policy sets against the same context to identify decision changes.

```
POST /v1/policy/compare
Authorization: Bearer <ops-token>
Content-Type: application/json
```

### POST /v1/policy/simulate/batch

Run up to 100 simulations concurrently.

```
POST /v1/policy/simulate/batch
Authorization: Bearer <ops-token>
Content-Type: application/json
```

---

## 4. Request and Response Shapes

### Single Simulation

**Request**

```json
{
  "context": {
    "userId":    "my-key:key_v1",
    "action":    "openai",
    "tenantId":  "acme-corp:key_v1",
    "requestId": "optional-trace-id",
    "ip":        "203.0.113.42",
    "timestamp": 1736164800
  },
  "policies": null,
  "scenario": "what-if: new IP allowlist"
}
```

All `context` fields are optional. `policies` is omitted to use the live policy set; provide an array to simulate against a draft (see [Policy Version Selection](#5-policy-version-selection)).

**Response** (`data` field of the envelope)

```json
{
  "simulationId":     "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "decision":         "BLOCK",
  "reason":           "IP_BLOCKED",
  "policyId":         "pol-blocklist-v2",
  "policyVersion":    "current",
  "policyHash":       "sha256:a3f9...",
  "tenantId":         "acme-corp:key_v1",
  "organizationId":   "org-acme",
  "riskLevel":        "HIGH",
  "matchedRules":     [{ "policyId": "pol-consent", "type": "REQUIRE_CONSENT", "priority": 5 }],
  "failedRules":      [{ "policyId": "pol-blocklist-v2", "type": "BLOCK_IP", "priority": 10, "reason": "IP_BLOCKED" }],
  "evaluationTrace":  [
    { "policyId": "pol-consent",       "type": "REQUIRE_CONSENT", "priority": 5,  "outcome": "PASSED",  "skipped": false },
    { "policyId": "pol-blocklist-v2",  "type": "BLOCK_IP",        "priority": 10, "outcome": "BLOCKED", "skipped": false, "reason": "IP_BLOCKED" },
    { "policyId": "pol-rate-limit",    "type": "RATE_LIMIT",      "priority": 20, "outcome": "SKIPPED", "skipped": true  }
  ],
  "explanation":      "Blocked by policy \"pol-blocklist-v2\" (type: BLOCK_IP, priority: 10). Reason: IP_BLOCKED.",
  "executionPrevented": true,
  "durationMs":       3,
  "scenario":         "what-if: new IP allowlist"
}
```

### Policy Comparison

**Request**

```json
{
  "context": { "ip": "203.0.113.42" },
  "currentPolicies":  null,
  "proposedPolicies": [
    { "id": "pol-new", "type": "BLOCK_IP", "enabled": true, "priority": 10,
      "config": { "blocklist": ["203.0.113.42"], "cidrs": [] } }
  ],
  "scenario": "proposed: add IP block"
}
```

`currentPolicies` is optional — omit to compare against the live set. `proposedPolicies` is required.

**Response**

```json
{
  "comparison":      true,
  "scenario":        "proposed: add IP block",
  "decisionChanged": true,
  "old": {
    "decision":    "EXECUTE",
    "reason":      "ALL_CHECKS_PASSED",
    "policyId":    "SYSTEM",
    "policyHash":  "sha256:b4a1...",
    "riskLevel":   "LOW",
    "explanation": "All 1 enabled policy rule(s) passed. Execution would be permitted."
  },
  "proposed": {
    "decision":    "BLOCK",
    "reason":      "IP_BLOCKED",
    "policyId":    "pol-new",
    "policyHash":  "sha256:c9f2...",
    "riskLevel":   "HIGH",
    "explanation": "Blocked by policy \"pol-new\" (type: BLOCK_IP, priority: 10). Reason: IP_BLOCKED."
  },
  "changedRules": [
    { "policyId": "pol-new", "change": "ADDED", "oldOutcome": null, "newOutcome": "BLOCKED" }
  ],
  "tenantId":           null,
  "organizationId":     null,
  "executionPrevented": true
}
```

### Batch Simulation

**Request** (max 100 items)

```json
{
  "simulations": [
    { "context": { "ip": "1.2.3.4" }, "scenario": "clean IP" },
    { "context": { "ip": "10.0.0.1" }, "scenario": "blocked IP" }
  ],
  "policies": null
}
```

**Response**

```json
{
  "batchId":   "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "total":     2,
  "allowed":   1,
  "blocked":   1,
  "results": [
    { "simulationId": "...", "decision": "EXECUTE", "executionPrevented": true, ... },
    { "simulationId": "...", "decision": "BLOCK",   "executionPrevented": true, ... }
  ],
  "executionPrevented": true
}
```

---

## 5. Policy Version Selection

| `policies` value | `policyVersion` in response | Behaviour |
|---|---|---|
| Omitted / `null` | `"current"` | Uses the live in-memory policy set — identical to what the enforcement path uses at this instant |
| `[]` or invalid array | — | Returns `INVALID_POLICY_SET` error result (no throw) |
| Valid policy array | `"provided"` | Passed through `validateAndPrepare()` — same validation as production |

Draft and proposed policies must satisfy the same constraints as production policies (at least one `REQUIRE_CONSENT` policy must be present and enabled). This prevents simulation from silently bypassing consent checks.

For comparison (`/compare`), `currentPolicies` follows the same rules. `proposedPolicies` must always be an array (may be empty, which produces `INVALID_POLICY_SET` on the proposed side).

---

## 6. Evaluation Trace

The `evaluationTrace` array reconstructs the step-by-step policy evaluation without re-running the engine. It is derived deterministically from the single engine result and the priority-sorted enabled-policy array:

| Engine result | Trace |
|---|---|
| `EXECUTE` | All enabled policies → `PASSED` |
| `BLOCK` with `policyId = "SYSTEM"` | Empty trace (system guard fired before policy evaluation) |
| `BLOCK` with specific `policyId` | Policies before it → `PASSED`; blocking policy → `BLOCKED` with `reason`; policies after it → `SKIPPED` |

Each trace entry:

```json
{
  "policyId": "pol-rate-limit",
  "type":     "RATE_LIMIT",
  "priority": 20,
  "outcome":  "PASSED | BLOCKED | SKIPPED | UNKNOWN",
  "skipped":  false,
  "reason":   "RATE_LIMITED"
}
```

`reason` is only present on `BLOCKED` entries.

---

## 7. Risk Classification

| `reason` | `riskLevel` |
|---|---|
| `ALL_CHECKS_PASSED` | `LOW` |
| `RATE_LIMITED`, `CONSENT_*`, `TIME_WINDOW_DENIED`, `POLICY_BLOCKED` | `MEDIUM` |
| `IP_BLOCKED`, `ANOMALY_DETECTED`, `EVALUATOR_ERROR`, `EVALUATOR_MISSING`, `INVALID_CONTEXT`, `NO_POLICIES_LOADED`, `NO_ENABLED_POLICIES`, `INVALID_POLICY_SET`, `ORG_SUSPENDED`, `ORG_DISABLED` | `HIGH` |
| Any unmapped reason on a BLOCK decision | `MEDIUM` |

An EXECUTE decision always returns `LOW` regardless of which policies ran.

---

## 8. Organization and Tenant Boundaries

When `context.tenantId` is provided, the simulation checks `assertActiveOrganization(tenantId)` before calling the engine.

| Organization state | Simulation result |
|---|---|
| Active | Proceeds normally; `organizationId` is populated in the response |
| Suspended | Returns `BLOCK` / `ORG_SUSPENDED` / `HIGH` with empty `evaluationTrace` |
| Disabled | Returns `BLOCK` / `ORG_DISABLED` / `HIGH` with empty `evaluationTrace` |
| Tenant has no organization | Proceeds normally; `organizationId` is `null` |

This mirrors the Step 1c check in the live enforcement pipeline (`src/validation/validateBoundRequest.js`, `assertActiveTenant()` → `assertActiveOrganization()`; `middleware/enforcePolicy.js` was removed in `4bae6188`).

---

## 9. Dry-Run Policy Store

The simulation engine wraps `livePolicyStore` with `makeDryRunPolicyStore()` (from `src/validation/dryRunStores.js`):

```javascript
function makeDryRunPolicyStore(livePolicyStore) {
  return {
    getCount(key, windowSecs) { return livePolicyStore.getCount(key, windowSecs); },
    increment(_key, _windowSecs) { /* no-op */ },
  };
}
```

Rate-limit counters are read (so RATE_LIMITED decisions are accurate) but never incremented. This is the same pattern used by `/verify/v2`.

---

## 10. Batch Simulation

- Maximum batch size: **100** items (enforced by both the engine and the route layer).
- Simulations run concurrently via `Promise.all()`.
- Each item may have its own `context`, `policies`, and `scenario`.
- A shared `policies` array can be provided at the batch level; it applies to items that omit their own `policies` key. Item-level `policies` takes precedence.
- `batchId`, `total`, `allowed`, and `blocked` summary fields are always present.
- Error objects (`{ error, message }`) on individual items do not fail the batch — the response always has `total` result objects.

---

## 11. Policy Comparison

`/v1/policy/compare` runs two simulations in parallel and diffs the traces:

```
changedRules entry:
  { policyId, change: "ADDED" | "REMOVED" | "OUTCOME_CHANGED", oldOutcome, newOutcome }
```

- `ADDED` — policy exists in proposed but not in current
- `REMOVED` — policy exists in current but not in proposed
- `OUTCOME_CHANGED` — policy exists in both but its trace outcome differs (e.g. PASSED → BLOCKED)

`decisionChanged` is `true` when the top-level `old.decision !== proposed.decision`.

---

## 12. Prometheus Metrics

Five metrics are exported by the simulation engine:

| Metric | Type | Labels | Description |
|---|---|---|---|
| `qodiqa_simulations_total` | Counter | `decision`, `policyVersion` | Total single simulations completed |
| `qodiqa_simulation_duration_ms` | Histogram | — | Simulation latency (ms) |
| `qodiqa_simulation_failures_total` | Counter | `reason` | Simulations that failed with an error result |
| `qodiqa_policy_comparisons_total` | Counter | `decisionChanged` | Total policy comparisons completed |
| `qodiqa_batch_simulations_total` | Counter | — | Total batch simulation requests |

All metrics are registered in `src/observability/metrics.js` and exposed on the standard `/metrics` endpoint.

---

## 13. SDK Usage

### Node.js / TypeScript

```typescript
import { QodiqaClient } from '@qodiqa/sdk';

const client = new QodiqaClient({
  baseUrl:  'https://gateway.example.com',
  opsToken: process.env.QODIQA_OPS_TOKEN,
});

// Single simulation
const result = await client.simulation.simulate({
  context: { userId: 'my-key:key_v1', action: 'openai', ip: '203.0.113.42' },
  scenario: 'what-if: new requester',
});
console.log(result.data.decision);         // "EXECUTE" | "BLOCK"
console.log(result.data.executionPrevented); // true

// Policy comparison
const comparison = await client.simulation.compare({
  context:          { ip: '203.0.113.42' },
  proposedPolicies: myDraftPolicies,
  scenario:         'draft v2 review',
});
console.log(comparison.data.decisionChanged);
console.log(comparison.data.changedRules);

// Batch
const batch = await client.simulation.batch({
  simulations: contexts.map(context => ({ context })),
});
console.log(`${batch.data.blocked} of ${batch.data.total} would be blocked`);
```

### Python (synchronous)

```python
from qodiqa import QodiqaClient

with QodiqaClient(base_url="https://gateway.example.com", ops_token="...") as client:
    result = client.simulation.simulate({
        "context": {"userId": "my-key:key_v1", "action": "openai", "ip": "203.0.113.42"},
        "scenario": "what-if: new requester",
    })
    print(result["data"]["decision"])            # "EXECUTE" or "BLOCK"
    print(result["data"]["executionPrevented"])  # True

    comparison = client.simulation.compare({
        "context": {"ip": "203.0.113.42"},
        "proposedPolicies": my_draft_policies,
    })
    print(comparison["data"]["decisionChanged"])
```

### Python (asynchronous)

```python
import asyncio
from qodiqa import AsyncQodiqaClient

async def main():
    async with AsyncQodiqaClient(base_url="...", ops_token="...") as client:
        result = await client.simulation.simulate({
            "context": {"ip": "10.0.0.1"},
        })
        print(result["data"]["riskLevel"])  # "HIGH" (IP_BLOCKED)

asyncio.run(main())
```

---

## 14. Authentication

All three simulation endpoints are mounted behind the ops middleware chain:

```
_opsIpAllow → _opsAuth → _rbacResolve → _opsGate
```

Callers must provide a valid ops token. The RBAC gate enforces that the caller has ops-level access. Standard sign tokens are not accepted.

---

## 15. Error Handling

**Validation errors** (invalid policy set, missing required fields) return error simulation results rather than HTTP 4xx — the batch can still complete. The individual result shape is:

```json
{
  "simulationId":     "...",
  "error":            true,
  "reason":           "INVALID_POLICY_SET",
  "message":          "PolicyLoader: policies must be a non-empty array",
  "executionPrevented": true,
  "durationMs":       0
}
```

**Structural errors** (missing `proposedPolicies` on compare, batch exceeds 100 items) throw synchronously before any evaluation occurs, resulting in HTTP 400 from the route handler:

```json
{
  "status":    "error",
  "error":     "COMPARISON_REQUIRES_PROPOSED_POLICIES",
  "message":   "proposedPolicies is required and must be an array",
  "requestId": "..."
}
```

---

## 16. Implementation Notes

**Single evaluator**: `services/policy/engine.js:evaluate()` is the only place policy decisions are computed. The simulation path calls it with identical arguments to the live enforcement path. There is no second policy evaluator.

**Caller-supplied timestamp**: Pass a Unix timestamp in `context.timestamp`. TIME_WINDOW policies evaluate against the provided timestamp rather than `Date.now()`, letting a caller construct a synthetic scenario that asks "what decision would this policy set produce at this point in time." This is not historical replay: the engine does not look up, read, or derive the timestamp (or any other field) from the audit log or any other record of a real past request — the entire context, including the timestamp, is supplied by the caller in the API request body, exactly like every other simulation.

**Determinism**: Given the same context and the same policy set, `runSimulation` always returns the same decision. The only non-deterministic field is `simulationId` (a fresh UUID per call) and `durationMs`.

**Test isolation**: The `_policyStore` override parameter (visible in function signatures but undocumented in the API) is used by the test suite to inject a spy store that records `getCount` and `increment` calls. Production callers should not pass this parameter.

**File locations**:

| File | Role |
|---|---|
| `src/core/simulation/simulationEngine.js` | Core engine: `runSimulation`, `runComparison`, `runBatch`, `_buildTrace`, `_diffPolicyTraces` |
| `src/api/routes/policySimulate.js` | Express router for the three API endpoints |
| `src/observability/metrics.js` | 5 simulation metrics (counters + histogram) |
| `server.js` | Mounts router at `/v1/policy` |
| `sdk/javascript/src/resources/simulation.ts` | TypeScript SDK resource |
| `sdk/javascript/src/types.ts` | TypeScript type definitions for all simulation shapes |
| `sdk/python/qodiqa/resources/simulation.py` | Python SDK resource (sync + async) |
| `test/policySimulation.test.js` | 50 unit tests |
