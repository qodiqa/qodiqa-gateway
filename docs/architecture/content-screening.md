# QODIQA Semantic Policy Engine

**Component:** Semantic Policy Engine
**Version:** 1.0.0
**Status:** Implemented

**Scope.** This document describes the bundled keyword classifiers, one of two semantic-detection layers. The embedding-similarity gate (`src/core/semantic/embeddingSimilarity/`) is a separate layer that runs in the same pipeline. Content screening is optional and best-effort: it is tuned for English and for direct requests, it misses paraphrases and other languages, and it flags some legitimate requests. No detection rate is claimed. The fine-tuned screening models are not included in this repository; without them the gate runs with `QODIQA_SEM_FT3_ENABLED=false`, as the sandbox does.

---

## Table of Contents

1. [What This Engine Is](#1-what-this-engine-is)
2. [Architecture](#2-architecture)
3. [Pipeline Integration — Streaming and Non-Streaming Parity](#3-pipeline-integration--streaming-and-non-streaming-parity)
4. [Classifier Lifecycle](#4-classifier-lifecycle)
5. [The Registry](#5-the-registry)
6. [Scoring](#6-scoring)
7. [Thresholds and Configuration](#7-thresholds-and-configuration)
8. [Evidence Model](#8-evidence-model)
9. [Adding a Bundled Classifier](#9-adding-a-bundled-classifier)
10. [Writing a Custom Classifier / Enterprise Policy Pack](#10-writing-a-custom-classifier--enterprise-policy-pack)
11. [Evaluation](#11-evaluation)
12. [Known Limitations](#12-known-limitations)

---

## 1. What This Engine Is

The Semantic Policy Engine evaluates the *semantic intent* of a request's prompt text — what is being asked — independent of every other QODIQA control, which all verify who is asking and whether they are authorized to ask at all. It runs after Consent Verification and the non-semantic Policy Engine (`services/policy/engine.js`), and before Execution Invariant / Provider Routing, for both streaming and non-streaming requests.

It exists because the rest of the enforcement pipeline (signature, binding, replay, consent, IP/rate/time policy) never inspects the request's *content* — a fully valid, correctly signed, correctly bound, replay-clean, consent-passing, policy-passing artifact could still instruct the model to disable QODIQA's own controls, and nothing upstream of this engine would have caught it.

**Hard architectural invariant — deterministic, non-LLM decision authority:** every classifier is a pure, synchronous function of the request text. No classifier calls an external model, and the engine's own decision logic (`scoring/scoreAggregator.js`) is pure arithmetic over classifier outputs. An LLM could in principle be added later as one more classifier contributing a signal, but it may never become the sole or final authority over ALLOW/WARN/REVIEW/DENY — QODIQA's own deterministic scoring always makes that call. This means the engine's output is reproducible: the same prompt always produces the same decision, with no dependency on a third party's availability or non-deterministic output.

**Provider independence:** the engine receives only `{ prompt, provider (metadata only), tenantId, requestId }` — never a provider handle or provider-specific request shape. The exact same evaluation occurs regardless of which provider the artifact names.

---

## 2. Architecture

All engine code lives under `src/core/semantic/` (self-contained; imports nothing from `services/policy/` or `services/providers/`):

| File | Role |
|---|---|
| `index.js` | Public entry point — `runSemanticPolicyEngine(context)`. Runs classifiers → aggregates → resolves action → builds evidence. |
| `reasons.js` | Taxonomy: `SEMANTIC_REASONS` (18 reason codes), `SEVERITY` (LOW/MEDIUM/HIGH/CRITICAL), `DECISION` (ALLOW/WARN/REVIEW/DENY). |
| `textSignals.js` | Pure text primitives: `normalize()` (NFKC + zero-width/bidi evasion-char stripping + lowercase), `scoreSignals()` (noisy-OR weighted-signal combination), `coOccurs()` (proximity check between two patterns). |
| `classifier/baseClassifier.js` | `defineClassifier()` factory — turns a declarative `{id, reason, severity, signals[], refine?}` spec into a `classify(context)` function. |
| `classifier/classifiers/*.js` | Bundled classifiers. |
| `registry/classifierRegistry.js` | Auto-discovers every file in `classifier/classifiers/` via `fs.readdirSync`; also exposes `registerClassifier()` for runtime plugins. |
| `scoring/confidence.js` | `SEVERITY_WEIGHT` map and `weightedScore = confidence × weight`; `decisionForScore()`. |
| `scoring/scoreAggregator.js` | "Worst finding wins" aggregation across all classifiers that fired. |
| `policies/semanticPolicy.js` | Config loader — kill switch, thresholds, disabled-classifier list, all env-overridable. |
| `policies/semanticActions.js` | Maps a decision to `{ blocks, decision, reason }` — DENY always blocks, REVIEW blocks unless explicitly opted out, WARN blocks only if explicitly opted in (see §3.3). |
| — | Builds the evidence record attached to the audit trail. |
| `fixtures/redTeamCorpus.js` | Reusable red-team prompt corpus. |
| `__tests__/` | Unit tests, red-team regression suite. |

```
runSemanticPolicyEngine(context)
        │
        ├── loadSemanticPolicy()                    (policies/semanticPolicy.js)
        │     — kill switch, thresholds, disabled classifiers
        │
        ├── getClassifiers(policy)                  (registry/classifierRegistry.js)
        │     — auto-discovered + runtime-registered, minus disabled
        │
        ├── for each classifier: classifier.classify(context)
        │     — isolated try/catch; a throwing classifier is logged and skipped,
        │       never crashes the request or disables the rest of the engine
        │
        ├── aggregate(results, policy)               (scoring/scoreAggregator.js)
        │     — weightedScore per result, sorted, highest wins
        │
        ├── resolveAction(aggregateResult, policy)    (policies/semanticActions.js)
        │     — decision -> { blocks, decision, reason }, per-tier gated by
        │       policy.enforcement (see §3.3)
        │
        └── buildSemanticEvidence(...)
              — built for EVERY request, including ALLOW
```

---

## 3. Pipeline Integration — Streaming and Non-Streaming Parity

The engine is wired into exactly one file, `src/api/routes/aiChat.js`, at exactly one call site pattern: `_runSemanticCheck()`, called identically from both `_enforceAndExecute()` (non-streaming) and `_enforceAndStream()` (streaming), immediately after the shared enforcement pipeline (`_runEnforcementPipeline()` — signature, binding, replay, anomaly, non-semantic policy) and before provider execution in either mode.

```
                    _runEnforcementPipeline()
                    (steps 1-5, shared, unchanged)
                              │
                    ┌─────────┴─────────┐
              non-streaming          streaming
                    │                     │
         _runSemanticCheck()   _runSemanticCheck()   <- identical function,
                    │                     │              identical DENY audit path
              DENY? 200 BLOCK*      DENY? 200 JSON*
              (provider never       (provider never
               called)               called, SSE
                    │                 never started)
                    ▼                     ▼
              _executeAI()          streamResponse()
```

\* HTTP 200 `{decision:'BLOCK'}` in the default `QODIQA_BLOCK_HTTP_MODE=decision`; 403 only with the opt-in
`QODIQA_BLOCK_HTTP_MODE=status` (`src/api/blockHttpStatus.js`, `semantics` class).

On semantic DENY, the provider is never reached in either mode: the non-streaming path returns before `_executeAI()`, the streaming path returns before `streamResponse()` — i.e. before `res.flushHeaders()` and before the SSE `stream_started` event.

### 3.1 Objective 1 fix — audit evidence parity on ALLOW

Before the two paths' audit records for an ALLOWED request were not identical in shape. The non-streaming ALLOW audit entry's `executionContext` included the full semantic evidence object (`executionContext.semantic`), but the streaming path's audit entry (written by `streamEnforcer.js`'s `_writeAuditStreamRecord()`) never received or recorded it — the field was simply absent.

**Fix:** `semantic.evidence` is now threaded through `_enforceAndStream()` → `streamResponse(res, req, artifact, authResult, ...)` (a new `semanticEvidence` field on `authResult`) → `_writeAuditStreamRecord()`, which now writes `executionContext.semantic` identically to the non-streaming path. This applies to both ALLOW and cancelled/error termination records, since the semantic evidence was already computed before streaming began in every case that reaches `streamResponse()` at all.

Verified by `src/api/routes/__tests__/aiChat.stream.test.js` (`STREAM-SEMANTIC-04`), which asserts the streaming ALLOW audit record's `executionContext.semantic` is present and structurally matches the non-streaming shape.

### 3.2 Objective 6 fix — audit evidence completeness on DENY

A second, independent gap existed on the DENY side of *both* paths (they share `_writeAuditBlock()`/`_runSemanticCheck()`, so this was not a streaming-specific bug): the audit entry's `executionContext` for a semantic DENY carried only `{ stage: 'SEMANTIC_POLICY', reason }` — the full evidence object (`score`, `confidence`, `matchedPolicies[]`) was computed and included in the synchronous BLOCK response body (HTTP 200 by default, 403 with `QODIQA_BLOCK_HTTP_MODE=status`), but never reached the persisted audit chain. An auditor replaying the chain later would see *that* a request was denied and *why* (the reason string), but not *which classifiers fired, at what confidence/score* — unlike the ALLOW path, which already carried the complete evidence object.

**Fix:** `_writeAuditBlock()` in `aiChat.js` now accepts an optional `semantic` field, and `_runSemanticCheck()` passes `semantic.evidence` into it on DENY. DENY and ALLOW audit records now carry structurally identical `executionContext.semantic` evidence.

Verified by `SEMANTIC-05` (persisted DENY entry has complete evidence), `SEMANTIC-06` (deterministic `matchedPolicies` ordering across repeated identical requests), `SEMANTIC-07` (ALLOW entries for WARN-tier findings remain fully evidenced), and `STREAM-SEMANTIC-03` in `aiChat.stream.test.js` for the streaming side.

### 3.3 remediation — REVIEW and WARN tiers now gate execution

**Prior behavior:** `resolveAction()` set `blocks: aggregateResult.decision === DECISION.DENY` unconditionally — the *only* tier that halted execution was DENY. With the shipped default thresholds (WARN 0.35, REVIEW 0.55, DENY 0.70), any prompt scoring in `[0, 0.70)` reached the provider completely unimpeded, including prompts the engine's own scoring classified as REVIEW — a tier whose name implies a review gate but which, in the actual implementation, had no gating effect at all. Tracked as finding.

**Fix:** `resolveAction(aggregateResult, policy)` now switches explicitly on every tier — there is no fallthrough path where a tier proceeds simply because it isn't DENY:

| Tier | Default | Override |
|---|---|---|
| `ALLOW` | never blocks | not configurable |
| `WARN` | does not block (advisory) | `QODIQA_SEMANTIC_WARN_BLOCKS=true` opts in to blocking |
| `REVIEW` | blocks | `QODIQA_SEMANTIC_REVIEW_BLOCKS=false` opts out |
| `DENY` | always blocks | not configurable under any env var |

This is enforced in exactly one place (`semanticActions.js`), which both `_enforceAndExecute()` and `_enforceAndStream()` consume identically via `_runSemanticCheck()` — so streaming and non-streaming parity, established in §3.1/§3.2, is preserved for the enforcement fix as well: there is no second code path that could apply a different rule to one mode.

Verified by `semanticEngine.test.js`'s "decision tiers" suite (unit level — all four tiers, both defaults and opt-in/opt-out overrides) and `aiChat.test.js`'s `SEMANTIC-08`/`SEMANTIC-09` (full HTTP pipeline — REVIEW blocks by default with the provider never called, and only proceeds given an explicit opt-out).

### 3.4 Output-side reuse (request AND response are classified by the same engine)

Everything in §1–§3.3 above describes classifying the caller's *request* prompt. closes
the remaining gap: nothing inspected what the **provider generated**. A response that itself
leaked a system prompt, completed a jailbreak, or echoed a policy-bypass instruction reached the
caller untouched. This is not a second engine — it is a second *call site* for the exact same
`runSemanticPolicyEngine()`, `executeClassifiers()`, `scoreAggregator.js`, `semanticActions.js`,
and `semanticEvidence.js` described above, passing the **response text** as `context.prompt`
instead of the request prompt:

```
runSemanticPolicyEngine({ prompt: <response text>, provider, tenantId, requestId, surface })
```

`context.surface` (default `'REQUEST'`, added) is the *only* change to `index.js` — a
purely descriptive field threaded into the evidence object (`evidence.surface`) so audit records
self-describe which side of the exchange produced them. It never affects classification, scoring,
or the ALLOW/WARN/REVIEW/DENY decision — `src/core/semantic/__tests__/outputSemantic.regression.test.js`
asserts, for every case in the confirmed-exploit corpus, that classifying the identical text as
`surface: 'REQUEST'` vs. `surface: 'RESPONSE'` produces an identical `decision`/`reason`/`score`.
`classifierExecution.js` needed no change at all — it was already generic over
`ctx.normalizedPrompt`.

Call sites:

| Surface | Where | File |
|---|---|---|
| `'RESPONSE'` | After a successful non-streaming provider call, before the ALLOW audit write | `src/api/routes/aiChat.js`'s `_runOutputSemanticCheck()` |
| `'RESPONSE_STREAM'` | Per provider chunk, before it is forwarded to the client | `src/streaming/outputSemanticWindow.js`, invoked from `src/streaming/streamEnforcer.js` |

A BLOCK on the response surface takes the same shape as any other BLOCK: `_writeAuditBlock()`
with `stage: 'SEMANTIC_POLICY_OUTPUT'` (distinct from the request-side `'SEMANTIC_POLICY'` stage,
so audit tooling can tell which side triggered a denial), the route returns the BLOCK body — HTTP 200 by default, 403 only
with `QODIQA_BLOCK_HTTP_MODE=status` (`src/api/blockHttpStatus.js`) — and
critically — the idempotency reservation is released, not completed, so a blocked output is never
cached as a replayable EXECUTE. On ALLOW, the response-side evidence is *also* recorded
(`executionContext.outputSemantic`, alongside the existing `executionContext.semantic` for the
request side) — full evidence parity on every execution, not only blocked ones.

**Known limitation, found during manual red-team validation:** the bundled classifiers were
calibrated to detect *request-style* attack phrasing (`"reveal your system prompt"`,
`"ignore all previous instructions"`). Reusing them unmodified for output text means they detect
a response that *echoes* or *completes* that phrasing (e.g. a jailbroken continuation, a leaked
system-prompt instruction) very reliably, but a response that discloses an actual secret *value*
without request-style framing (e.g. a bare API key or password appearing in prose) may not trip
`credential-extraction`/`pii-extraction`'s signals, since those classifiers look for someone
*asking for* a credential, not a credential *appearing* in output. This is a pre-existing property
of the classifier signal set, not a gap introduced's architecture — and per the explicit
"reuse the existing classifiers, do not create new ones" constraint this remediation operates
under, closing it means calibrating/adding classifier signals for credential-shaped *content*
(e.g. regex-style secret-pattern detection), a separate, focused piece of follow-up work, not an
output-pipeline change.

See `docs/architecture/streaming.md` §15 for the streaming-specific sliding-window design, the
deterministic leak-bound guarantee, and production tuning guidance.

---

## 4. Classifier Lifecycle

A classifier is any object shaped `{ id: string, classify(context) => result|null }`. `result` is `{ id, confidence, severity, reason, evidence }` or `null` ("found nothing" — not itself a decision).

Bundled classifiers (as, in `src/core/semantic/classifier/classifiers/`):

| Classifier ID | Reason | Severity | Signals |
|---|---|---|---|
| `security-override` | `SECURITY_OVERRIDE_ATTEMPT` | CRITICAL | 3 (+ proximity refine) |
| `jailbreak` | `JAILBREAK_ATTEMPT` | HIGH | 8 |
| `prompt-injection` | `PROMPT_INJECTION_ATTEMPT` | MEDIUM | 7 |
| `system-prompt-extraction` | `SYSTEM_PROMPT_EXTRACTION` | HIGH¹ | 6 |
| `tool-abuse` | `TOOL_ABUSE_ATTEMPT` | MEDIUM | 6 |
| `policy-bypass` | `POLICY_BYPASS_ATTEMPT` | HIGH | 5 |
| `data-exfiltration` | `DATA_EXFILTRATION` | CRITICAL | 5² |
| `credential-extraction` | `CREDENTIAL_EXTRACTION` | HIGH | 4 |
| `memory-extraction` | `MEMORY_EXTRACTION` | HIGH | 4 |
| `impersonation` | `IMPERSONATION_ATTEMPT` | MEDIUM | 4 |
| `pii-extraction` | `PII_EXTRACTION` | HIGH | 3 |
| `unauthorized-tool-request` | `UNAUTHORIZED_TOOL_REQUEST` | HIGH | 3 |
| `file-enumeration` | `FILE_SYSTEM_ENUMERATION` | HIGH | 4 (+ 2 proximity refines) |

¹ Raised from MEDIUM to HIGH calibration — see in §12.
² `exfiltrate_keyword` signal weight lowered calibration — see in §12.

`unauthorized-tool-request` is a new row above, split out of `tool-abuse` (`src/core/semantic/classifier/classifiers/unauthorizedToolRequest.js`) — its three signals (`unauthorized_tool_phrase`, `tool_scope_escalation`, `chained_tool_escalation`) previously lived inside `tool-abuse` but could only ever report `TOOL_ABUSE_ATTEMPT` under `defineClassifier()`'s one-reason-per-classifier-file contract, permanently mislabeling this code. `tool-abuse` keeps its remaining 6 signals unchanged. Reasons defined in `reasons.js` with **no** bundled classifier as of this phase: none — removed the five that had zero producer anywhere in the codebase (`ROLE_ESCALATION_ATTEMPT`, `SECRET_EXTRACTION`, `CHAIN_OF_THOUGHT_REQUEST`, `MODEL_MANIPULATION`, `PROVIDER_ESCAPE_ATTEMPT` — confirmed via git history that no classifier for any of them ever existed) and fixed the sixth (`UNAUTHORIZED_TOOL_REQUEST`, row above).

The bundled set includes `file-enumeration` (`src/core/semantic/classifier/classifiers/fileEnumeration.js`, `FILE_SYSTEM_ENUMERATION` reason; 4 base signals + 2 `coOccurs()` proximity refines). **There are 13 bundled classifiers** — verify with `ls src/core/semantic/classifier/classifiers/*.js`.

### Classifier lifecycle states

```
written (declarative signal set via defineClassifier())
   │
   ▼
dropped into classifier/classifiers/*.js
   │
   ▼
auto-discovered on first getClassifiers() call, process-lifetime cached
   │
   ▼
evaluated on every request (unless disabled via QODIQA_SEMANTIC_DISABLED_CLASSIFIERS)
   │
   ▼
contributes a result (or null) to scoreAggregator on every request it fires on
```

There is no hot-reload: `classifierRegistry.js`'s `_autoDiscovered` cache is computed once per process and never invalidated. A new classifier file requires a process restart to take effect. This is an intentional simplicity/determinism trade-off, not an oversight — flagged again in §14 for anyone considering hot-reload as a future feature.

---

## 5. The Registry

`registry/classifierRegistry.js` is the sole extensibility surface for the engine — the architectural property that lets it scale to "hundreds of classifiers" without ever modifying `index.js` or the scoring code:

- **Auto-discovery**: every `.js` file under `classifier/classifiers/` that exports `{ id: string, classify: function }` is picked up automatically via `fs.readdirSync`. Dropping a new file in that directory is the entire integration surface for a bundled classifier.
- **Runtime registration**: `registerClassifier({ id, classify })`, exported from `src/core/semantic/index.js`, lets a customer-specific plugin or a separately-versioned policy pack register additional classifiers without touching this module or the engine at all. Duplicate IDs (against either auto-discovered or already-registered classifiers) throw.
- **Disabling**: `getClassifiers(policy)` filters by `policy.disabledClassifiers` (an operational decision via `QODIQA_SEMANTIC_DISABLED_CLASSIFIERS`, not a code change) on every call.
- **Test isolation**: `_resetRegisteredForTests()` clears runtime-registered classifiers between test files; auto-discovered (bundled) classifiers are never cleared, since they are a fixed property of the filesystem.

---

## 6. Scoring

Two-stage, fully deterministic:

**Stage 1 — per-classifier confidence (`textSignals.scoreSignals`)**: each classifier declares a set of `{ pattern, weight, tag }` signals. A signal "fires" if its regex matches the normalized prompt text. Multiple fired signals combine via **noisy-OR**, not a naive sum or bare max:

```
confidence = 1 - Π(1 - weight_i)   for every fired signal i
```

This lets several weak, independent indicators add up to a confident detection, while a single strong (high-weight) signal can also reach high confidence alone — a naive sum can blow past 1 and over-rewards repetition; a bare max is equivalent to single-pattern matching and ignores corroborating signals.

Some classifiers layer a `refine(text, base)` step on top (e.g. `security-override`'s proximity bonus when an override verb appears near a security-control noun) — structural refinement is purely a function of the already-normalized text and the base score, never the raw context, so it cannot depend on anything outside the text itself.

**Stage 2 — cross-classifier aggregation (`scoreAggregator.aggregate`)**: every classifier that returns a non-null result gets a `weightedScore = confidence × SEVERITY_WEIGHT[severity]` (LOW 0.35, MEDIUM 0.6, HIGH 0.85, CRITICAL 1.0). The engine's decision is driven by the **single highest weighted score** across all classifiers that fired — "the worst finding wins" — not an average, so one high-confidence CRITICAL match is never diluted by several unrelated low-confidence classifiers also firing. Every classifier that met at least the WARN threshold is retained in `matched` for the evidence trail, so the full signal picture (not just the winner) is auditable.

```
decisionForScore(score, thresholds):
  score >= DENY threshold    -> DENY    (always blocks execution)
  score >= REVIEW threshold  -> REVIEW  (blocks execution by default — see §3.3)
  score >= WARN threshold    -> WARN    (recorded; blocks only if explicitly configured — see §3.3)
  else                       -> ALLOW   (never blocks)
```

Note that `decisionForScore()` only *classifies* the prompt into a tier — it is a pure function of score and thresholds, and does not decide whether that tier gates execution. `resolveAction()` (§3.3) is solely responsible for turning a tier into a blocking/non-blocking action.

---

## 7. Thresholds and Configuration

All in `policies/semanticPolicy.js`, env-overridable per the same pattern used elsewhere in QODIQA (`policies.json`, provider timeouts):

| Setting | Env var | Default |
|---|---|---|
| Engine kill switch | `QODIQA_SEMANTIC_POLICY_ENABLED` | `true` (enabled by default — this is a security control, not opt-in) |
| WARN threshold | `QODIQA_SEMANTIC_THRESHOLD_WARN` | `0.35` |
| REVIEW threshold | `QODIQA_SEMANTIC_THRESHOLD_REVIEW` | `0.55` |
| DENY threshold | `QODIQA_SEMANTIC_THRESHOLD_DENY` | `0.70` |
| Disabled classifiers | `QODIQA_SEMANTIC_DISABLED_CLASSIFIERS` | `` (comma-separated classifier IDs) |
| WARN blocks execution | `QODIQA_SEMANTIC_WARN_BLOCKS` | `false` (advisory by default; `true` opts in) |
| REVIEW blocks execution | `QODIQA_SEMANTIC_REVIEW_BLOCKS` | `true` (blocks by default; `false` opts out) |

DENY always halts execution before provider routing, and REVIEW does too unless a deployment explicitly opts out; WARN is advisory unless a deployment explicitly opts in (see §3.3 for the full rationale). Every decision — blocking or not — is fully recorded in evidence regardless of these settings, mirroring QODIQA's broader "record every decision" philosophy.

### 7.1 SEM-C (embedding-similarity) Five-gate configuration and boot auditability

The embedding-similarity classifier (`src/core/semantic/embeddingSimilarity/`, distinct from the classifier-registry tier documented above) runs up to five gates against one embedding — anchors, ensemble head, V9, V5, and whichever fine-tuned gate (FT-2 or FT-3) is enabled — each with its own threshold, all defined in `config.js` and, like the settings above, **deliberately env-overridable per-deployment** (`QODIQA_SEM_C_*`, `QODIQA_SEM_FT2_*`, `QODIQA_SEM_FT3_*` — see that file's own extensive per-threshold provenance comments for calibration history). This flexibility is intentional and is **not removed or restricted** by anything below.

**What adds is auditability, not a behavior change.** Every `init()` call (server startup, or `verify/runRealModelVerification.js`) emits exactly one structured event, `EMBEDDING_CLASSIFIER_CONFIG_EFFECTIVE`, containing every threshold and both FT flags — each as `{ default, effective }` — plus a `deviatesFromPinnedDefaults` summary flag. This is the single source of truth for "what was actually active for this process": an auditor never needs to reconstruct it from `config.js`'s source, the deployment environment, or multiple log lines.

When the process is running with `NODE_ENV=production` and any threshold or flag differs from its pinned default, a second event, `EMBEDDING_CLASSIFIER_CONFIG_DEVIATION` (level `WARN`), is also emitted, naming exactly which value(s) deviate (`key`, `type: 'threshold'|'flag'`, `default`, `effective`). This warning is **purely informational**: it never rejects, clamps, resets, or otherwise alters the configuration, and production deployments remain fully able to override any threshold or either FT flag exactly as before. No warning is emitted outside production, and none is emitted when the effective configuration already equals the pinned defaults. See `src/core/semantic/embeddingSimilarity/config.js`'s `PINNED_DEFAULTS`/`getDeviations()` and `index.js`'s `_emitEffectiveConfig()` for the implementation, and `__tests__/configAuditEvent.test.js` for the full test coverage.

### 7.2 Input normalization on the embedding path — wired, shipped disabled

**The defect.** This engine has always owned a normalization pipeline — `textSignals.js`'s `normalize()`: NFKC, cross-script confusable folding, zero-width/bidi/pictographic stripping, a bounded decode-and-rescan for base64, hex, URL encoding, HTML entities and Unicode escapes, Latin diacritic folding, character-repetition collapse and dictionary-bounded fragment reconstruction. It was wired to the wrong layer. `index.js` computes it once per request and threads it to the **keyword classifiers**; `requestSemanticCheck.js` then hands `embeddingGate.checkText()` the **original** prompt, and the embedding classifier embeds that raw string.

The consequence is the one the 2026-09-05 independent audit measured as G-01: 6 of 7 obfuscation classes bypassed the semantic layer entirely. The pipeline was being applied to the layer measured at 0 blocks and withheld from the layer carrying 100% of them.

**Why it is input representation and not model capacity.** Uppercasing is the single obfuscation class the audit found DETECTED, and the tokenizer control explains it: MiniLM is uncased, so clear and uppercased text produce *identical token id sequences*. The model never saw that transformation. It saw every other one raw — a 16-token prompt arrives as 43 tokens under leetspeak, 54 under letter spacing, 71 under punctuation insertion, 56 under ROT13.

**The stage.** `inputNormalization.js` produces candidate texts; `index.js`'s `classify()` scores the raw text first and ORs candidates on top. Beyond re-using the shared pipeline it adds three general transforms for the classes that pipeline has no rule for — leet folding, separated-letter collapse, and ROT13 gated by a frozen English unigram comparison. Each is defined over character classes or a statistical property of the text, never over a list of attack words: none can recognise an attack, they only undo a surface encoding, after which the unchanged gates decide.

Three properties are structural rather than measured:

- **Monotone** — the raw result is computed first and its DENY is never withdrawn, so no existing detection can be lost.
- **Fail-closed** — a non-READY result from the raw pass *or* from any candidate is returned immediately; a failure is never retried into an ALLOW.
- **Inert** — a candidate is emitted only on positive evidence that a transform fired, so ordinary text costs one embedding pass and returns an object with no normalization fields at all.

**No threshold, band, anchor, corpus or label changes.** A monotone OR cannot lose a detection, so nothing needs compensating. `__tests__/thresholdPinning.test.js` asserts this directly.

**The flag.** `QODIQA_SEM_NORMALIZE_ENABLED` defaults to `false`. Only the literal string `"true"` enables it, the same kill-switch convention both FT gates use. It appears in `EMBEDDING_CLASSIFIER_CONFIG_EFFECTIVE` alongside them, so a figure quoted without all three flag states is not reproducible. Enabling it is a separate design decision — for the complete measurement and the latency trade-off that decision turns on.

---

## 8. Evidence Model

 builds one evidence record per evaluated request (including ALLOW):

```js
{
  engineVersion: '1.0.0',
  timestamp: '<ISO 8601>',
  requestId, tenantId, provider,
  decision: 'ALLOW' | 'WARN' | 'REVIEW' | 'DENY',
  reason: '<SEMANTIC_REASONS value>' | null,
  confidence: <number 0-1>,     // top-scoring classifier's raw confidence
  score: <number 0-1>,           // top-scoring classifier's weighted score
  matchedPolicies: [
    { classifierId, reason, severity, confidence, weightedScore },
    ...
  ],
}
```

**Never contains raw prompt text** — `baseClassifier.js`'s `classify()` only ever stores matched *signal tags and weights* in a result's `evidence` field, never verbatim matched substrings, consistent with the rest of QODIQA's audit model (hashes and structured metadata, not payloads). Verified by `semanticEngine.test.js`'s "evidence never contains raw prompt text" test.

**Deterministic ordering**: `matchedPolicies` is sorted by `weightedScore` descending (the same sort `scoreAggregator.aggregate()` performs internally) — repeated evaluation of the identical prompt through the identical (stateless) classifier set always produces the identical ordering. Verified by `SEMANTIC-06` in `aiChat.test.js`.

This evidence object is embedded at `executionContext.semantic` in the audit-chain entry for every decision, ALLOW or DENY, streaming or non-streaming, as of the fixes in §3.1 and §3.2.

---

## 9. Adding a Bundled Classifier

1. Create.
2. Add the reason to `SEMANTIC_REASONS` in `reasons.js` if it's new.
3. Use `defineClassifier()`:

```js
'use strict';
const { defineClassifier } = require('../baseClassifier');
const { SEMANTIC_REASONS, SEVERITY } = require('../../reasons');

const SIGNALS = [
  { pattern: /\bsome regex\b/, weight: 0.40, tag: 'descriptive_tag' },
  // ... more signals
];

module.exports = defineClassifier({
  id: 'my-classifier',
  reason: SEMANTIC_REASONS.MY_REASON,
  severity: SEVERITY.HIGH,
  signals: SIGNALS,
  // refine(text, base) is optional — see security-override.js for a
  // proximity-bonus example
});
```

4. **Calibrate before merging** — this is the step most likely to be skipped and most likely to cause a production incident if it is:
   - Check that no single signal's `weight × SEVERITY_WEIGHT[severity]` alone crosses the WARN threshold (0.35) unless that signal is genuinely unambiguous on its own (see in §12 for the "DAN" case study — a 3-letter acronym is not unambiguous; a full named phrase usually is).
   - Run `node against the red-team corpus (add representative prompts for the new category to `fixtures/redTeamCorpus.js` first) and confirm zero new false positives against the benign corpus.
   - Add the new category's baseline to `DETECTION_BASELINE` in `semanticRedTeam.test.js`.
5. No changes to `index.js`, `classifierRegistry.js`, or `scoreAggregator.js` are ever required — that is the entire point of the registry design in §5.

---

## 10. Writing a Custom Classifier / Enterprise Policy Pack

For classifiers that should not live in the open-source/bundled directory (customer-specific detection logic, a licensed third-party policy pack, or a classifier that needs to ship on its own release cadence), use runtime registration instead of a bundled file:

```js
const { registerClassifier } = require('<qodiqa>/src/core/semantic');

registerClassifier({
  id: 'acme-corp-custom-classifier',
  classify(context) {
    // context: { prompt, provider, tenantId, requestId }
    // Must be synchronous and side-effect-free — no I/O, no external calls.
    // Return null for "no finding", or:
    if (someCondition(context.prompt)) {
      return {
        id: 'acme-corp-custom-classifier',
        confidence: 0.6,             // 0-1
        severity: 'HIGH',            // LOW | MEDIUM | HIGH | CRITICAL
        reason: 'ACME_POLICY_VIOLATION',  // any string — does not need to be
                                           // a value from SEMANTIC_REASONS
        evidence: { /* tags/weights only — never raw prompt substrings */ },
      };
    }
    return null;
  },
});
```

**A policy pack is simply a module that calls `registerClassifier()` for each classifier it contains**, loaded once at process startup (e.g. from `start.js` or an equivalent bootstrap module) before the first request is served. There is no separate "policy pack" API or manifest format — the registry's runtime-registration mechanism *is* the policy pack mechanism, by design (see the architectural note in §5).

Constraints enforced by the registry, not by convention:
- `id` and `classify` are required; `classify` must be a function.
- Duplicate `id` (against bundled or already-registered classifiers) throws at registration time, not silently overwrites.
- A classifier that throws during `classify()` is caught, logged (`SEMANTIC_CLASSIFIER_ERROR`), and skipped for that request — it can never crash a request or disable the rest of the engine (verified by `semanticEngine.test.js`).

Constraints **not** enforced by the registry (author responsibility):
- Determinism — `classify()` must be a pure function of `context`. No external model calls, no I/O, no randomness. This is a documented architectural invariant (§1), not a runtime-checked one.
- No raw prompt text in the returned `evidence` field — see §8.

---

## 11. Evaluation

The screening classifiers are covered by unit tests and by a red-team suite that runs in the repository. Measured detection figures are not published: the screening layers are optional components, and they are not a protection guarantee.

## 12. Known Limitations

Identified during hardening; per the phase's constraints, **none of these have been implemented** — they are catalogued for a future phase to prioritize, not spec'd out further here.

1. ~~**Six taxonomy reasons have no dedicated classifier**: `ROLE_ESCALATION_ATTEMPT`, `SECRET_EXTRACTION`, `CHAIN_OF_THOUGHT_REQUEST`, `MODEL_MANIPULATION`, `PROVIDER_ESCAPE_ATTEMPT`, `UNAUTHORIZED_TOOL_REQUEST`.~~ **RESOLVED.** The five with zero producer anywhere in the codebase (`ROLE_ESCALATION_ATTEMPT`, `SECRET_EXTRACTION`, `CHAIN_OF_THOUGHT_REQUEST`, `MODEL_MANIPULATION`, `PROVIDER_ESCAPE_ATTEMPT`) were removed from `SEMANTIC_REASONS` as obsolete taxonomy debt — git history confirms no classifier for any of them ever existed and was later deleted, and this section's own entry (this item) already documented them as deliberate, out-of-scope gaps rather than reserved taxonomy. `UNAUTHORIZED_TOOL_REQUEST` is now backed by its own dedicated classifier (`unauthorized-tool-request`, split out of `tool-abuse` — see §4's table). The live taxonomy is now 14 codes, each with exactly one producer; see `src/core/semantic/__tests__/reasonTaxonomyCoherence.test.js`'s entry. This does not change the corpus-category detection-rate figures in §12.2 (`SECRET_EXTRACTION`/`CHAIN_OF_THOUGHT_REQUESTS`/`PROVIDER_ESCAPE_ATTEMPTS`/`TOOL_ESCALATION` there are red-team corpus attack-category labels measuring incidental adjacent-classifier detection, a distinct concept from the reason-code taxonomy — see `redTeamCorpus.js`'s own header — and are's domain, untouched here).
2. ~~**No base64/encoding-aware classifier.**~~ **RESOLVED (TEST-3/AI-3 remediation, see §12.4).** `textSignals.js` now decodes embedded base64 (standard + URL-safe, recursively for nested encoding), URL-encoding, and HTML entities before any classifier pattern is evaluated. `BASE64_ENCODED_PROMPTS` is now 100% and enforced as a mandatory, zero-tolerance category — see `confirmedExploits.regression.test.js`.
3. **Non-English/multilingual coverage — NOT resolved as a protection claim.** The keyword layer has translated *phrase* signals (below), but independent out-of-sample measurement found non-English harmful requests effectively undetected (0/150 per language for es/fr/hi/ru/sr/tl), and the pooled independent recall of the semantic layer is about 18 % with a false-positive rate of about 15 %. The "100 %" figures below are **in-sample corpus-category results**, not a measure of real-world multilingual protection. The semantic layer is experimental and is not a safety guarantee. The original text follows for the record: ~~**No non-English/multilingual pattern coverage.**~~ RESOLVED (TEST-3/AI-3 remediation, see §12.4). `i18nSignals.js` adds translated attack-phrase signals across 13 languages, wired into the five classifiers whose English equivalents they mirror; `textSignals.js` also folds Cyrillic/Greek homoglyph substitutions. `MULTILINGUAL_ATTACKS` and `MIXED_LANGUAGE_ATTACKS` are now 100% and enforced as mandatory, zero-tolerance categories. This closes multilingual *phrase* detection for the canonical attack phrasing each classifier already targets in English — it is not a claim of paraphrase-proof coverage in every language (the same scope boundary the English classifiers themselves have, per limitation #4 below).
4. **Several narrow-pattern classifiers were paraphrase-fragile.** `memory-extraction`, `policy-bypass`, `tool-abuse`, and file-enumeration-shaped prompts (no classifier existed for the last) showed low-to-zero detection not because the underlying idea was uncatchable, but because the existing regexes required close-to-exact phrasing (e.g. requiring a verb and noun to be immediately adjacent with no words between them). Broadening these was explicitly out of scope for's calibration mandate (which was limited to thresholds/weights/severities, not rewriting classifier logic) — attempting it under time pressure without dedicated review would have risked trading detection gains for new false positives, the opposite of the phase's stated goal.
   **UPDATE:** all four have since been addressed. `memory-extraction`, `policy-bypass`, and `tool-abuse` were broadened with new structural (`coOccurs`-based proximity) signals plus explicit FP-mitigation defaults (verb-adjacent-object structure required; bare nouns never solo-trigger; low-weight-plus-corroboration for any bare-keyword signal, per the `data-exfiltration` classifier's own precedent); a new `file-enumeration` classifier was added, reusing the existing `FILE_SYSTEM_ENUMERATION` taxonomy reason (see item 1 above — no taxonomy extension needed). Zero new false positives were measured against the legitimate holdout across all four changes, verified independently after each one. Keyword-layer contribution against the adversarial corpus remained 0/192 both before and after this work — the corpus itself contains ~0 genuine exemplars of these four technique classes (a labeling artifact of its JailbreakBench/HarmBench provenance, not a detection gap), so this broadening measures real-world technique coverage, not a corpus-scoreboard movement.
5. **No classifier hot-reload.** `classifierRegistry.js`'s auto-discovery is cached once per process (`_autoDiscovered`). Adding a bundled classifier file requires a process restart to take effect. Reasonable for a deterministic, security-relevant control, but worth confirming this is the intended operational model as the classifier count grows.
6. **`/verify` (the dry-run endpoint) does not evaluate the semantic engine at all.** A caller cannot preview whether a given prompt would be semantically denied without actually attempting execution via `/ai/chat`. Whether this is in scope for the dry-run contract is a product decision, not evaluated further here.
7. **Scaling/maintainability, looking further ahead:** the "worst finding wins" aggregation and the registry's linear scan over all classifiers on every request are both O(n) in classifier count with no early-exit — fine at the 11 classifiers §13's benchmark was actually run against (the count is now 13, per §2/§4's correction, still comfortably within the same O(n) regime), but worth re-measuring if the classifier count grows into the hundreds the architecture is explicitly designed to support. No action indicated today; flagged for whoever adds classifier #50+.
8. **Long prompts (>~4k chars) exceed the latency budget under load — embedding-similarity (SEM-C) layer. DISCLOSED KNOWN LIMITATION.** The SEM-C anchor/gate path scores each ~256-token *window* of a prompt separately — windowing is what lets it catch a malicious span buried inside a long, mostly-benign prompt — so per-request latency is **linear in window count**. Measured on the shipped 76-anchor config: a ~1.9k-char prompt ≈ 180 ms and a ~6.5k-char prompt ≈ 350 ms on a SOFT in-process warm rig; the REAL fresh-process battery runs higher (the SOFT figures under-state absolute latency by roughly 5×, but the length-linear structure is what matters and it holds). This **exceeds the 100 ms latency budget for long prompts under load** — the pre-existing LONG-D6 finding (296 ms control), re-confirmed here. **FP=0 is unaffected** — this is a latency characteristic, not a detection or false-positive issue. Dispositioned as a **disclosed known limitation** on the paraphrase-bypass precedent, rather than remediated: long prompts are rare in typical traffic, and the remediation — a best-N window cap — would trade away detection on the capped tail. A **window cap remains available if a hard latency SLA on long prompts is required** (accepting the stated detection trade-off).'s P2-HYGIENE / LONG-D6 records for the measurement and the SOFT/REAL caveat.
