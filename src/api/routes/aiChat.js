'use strict';

/**
 * /ai/chat — V2 AI execution endpoint.
 *
 * Architecture guarantees:
 *   • enforceAndExecute() is the ONLY path to _executeAI().
 *   • validateBoundRequest() MUST return { allowed: true } before policy check runs.
 *   • Policy check (step 5) MUST pass before _executeAI() is called.
 *   • _executeAI() is module-private — not exported, unreachable from outside this module.
 *   • executeProviderCall() independently asserts assertExecutionInvariant() as a second
 *     layer of defence — any attempt to call it without a valid verifiedCtx throws.
 *
 * Request flow:
 *   POST /ai/chat
 *     → content-type guard
 *     → body + artifact header validation (input guard)
 *     → enforceAndExecute()
 *         → validateBoundRequest()   [Steps 1–4: sig, binding, nonce, anomaly]
 *         → _checkPolicy()           [Step 5: BLOCK_IP, CONSENT, RATE_LIMIT, TIME_WINDOW]
 *         → _executeAI()             [ONLY if steps 1–5 all pass]
 *             → executeProviderCall()  [asserts invariant, dispatches to provider handler]
 * → 200 EXECUTE | 200 BLOCK | 4xx/5xx error
 */

const { buildAiDisclosure, HEADER: AI_DISCLOSURE_HEADER } = require('../../core/compliance/aiDisclosure'); // (D9-A)
const crypto                   = require('crypto');
const { Router }               = require('express');
const { validateBoundRequest } = require('../../validation/validateBoundRequest');
const { requestAuditContextMiddleware, bindArtifactFacts, setRequestReceipt } = require('../../core/audit/requestAuditContext');
const _commitOf = new WeakMap();   // the EXECUTE result object → { tracker, outputHash, bytesDelivered } (settled by the route from the response)
const { createCommitTracker: _createCommitTracker, watchResponse: _watchCommitResponse } = require('../../core/audit/commitEntry');   //
const { issueReceipt } = require('../../core/transparency/receipt');
const { putReceipt } = require('../../core/transparency/receiptStore');
const { executeProviderCall }  = require('../../../services/execution');
const { mintExecutionToken }   = require('../../../services/executionInvariantToken');
const { checkPolicy }          = require('../../validation/checkPolicy');
const { runSemanticPolicyEngine } = require('../../core/semantic');
const embeddingGate = require('../../core/semantic/embeddingGate');
// the REQUEST-side half of _runSemanticCheck below (engine + embedding
// gate, no side effects) is shared with /verify's parity check — see
// requestSemanticCheck.js's header. _runOutputSemanticCheck (response-side,
//) stays on the direct runSemanticPolicyEngine/embeddingGate calls
// above — /verify never generates a response, so it never runs it.
const { evaluateConversationSemantic: evaluateRequestSemantic } = require('../../core/semantic/requestSemanticCheck');
const dlpStage = require('../../core/dlp/dlpService');
const budgetStage = require('../../core/budget/budgetStage');   //
const routingStage = require('../../core/routing/routingStage');   //
const costAccounting = require('../../core/providers/costAccounting');   //
const contentStage = require('../../core/content/contentStage');   //
const { buildFor: buildAttributesFor, effectiveModel, estimateTokens } = require('../../../services/policy/abac/requestAttributes');   //   // DLP rules of the policy set applied to the request text and to the answer
const { appendMandatory: _auditAppendMandatoryRaw } = require('../../core/audit/audit-log');
const _lifecycleReconciler = require('../../core/audit/lifecycleReconciler');   //
// every mandatory append's outcome feeds the /ready audit-persistence latch (src/api/auditPersistenceHealth.js).
const _auditAppendMandatory = require('../auditPersistenceHealth').track(_auditAppendMandatoryRaw);
const { outputHashOf: _outputHashOf, unrepresentableTextPath: _unrepresentablePath } = require('../../core/audit/entryBuilder');   // v7 R-5; F6-N2
const { writeLifecycleEntry }         = require('../../core/audit/lifecycleEntry'); // v7 R-8..R-11
const { currentContext: _tracingContext }         = require('../../observability/tracing/context');
const { policyHashesEqual }    = require('../../../services/policyHash');
// the effective (floor ∪ tenant) merge — never the raw stored set —
// so a tenant set can never drop REQUIRE_CONSENT or any other global
// enforcement policy.
const { getEffectivePoliciesForTenant } = require('../../core/tenancy/tenantPolicyRegistry');
const enforceContentType       = require('../../../middleware/enforceContentType');
const { emit }                 = require('../../../services/logger');
const { resolveDefaultModel }  = require('../../../services/providers/config');
const { aiChatBodySchema, findUnsupportedFields, findUnknownFields } = require('../../validation/schemas/aiChat.schema');
const { firstQodiqaReason }    = require('../../validation/helpers');
const { streamResponse }       = require('../../streaming/streamEnforcer');
const { registerEnforcementDecision } = require('../../core/transparency/enforcementBridge');
const { leafHash: _merkleLeafHash }   = require('../../core/transparency/merkle');
const { validateIdempotencyKey } = require('../../core/idempotency/idempotencyKey');
const idempotencyGate            = require('../../core/idempotency/idempotencyGate');
const { recordPreAuthReject }    = require('../../core/preauth/preAuthRejects');
const { isAiChatRoute }          = require('../../core/routing/canonicalRoute');
const signingIdentityStore       = require('../../core/signing/signingIdentityStore');
const { createRateLimitMiddleware, checkRateLimit } = require('../../core/rateLimit');
// stage timer (bench only; see src/observability/stageTimer.js). With the flag off, every
// ST.time*() below returns the original function and every `if (ST.ON)` block is skipped.
const ST = require('../../observability/stageTimer');
// · D7: HTTP status of an enforcement BLOCK — 200 by default, per-class 4xx/5xx when
// QODIQA_BLOCK_HTTP_MODE=status. See src/api/blockHttpStatus.js.
const { blockHttpStatus } = require('../blockHttpStatus');
const classificationBudget = require('../../core/semantic/classificationBudget'); // step 7
const _checkPolicyT            = ST.timeAsync('S24', checkPolicy);
const _evaluateRequestSemanticT = ST.timeAsync('S26', evaluateRequestSemantic);
const _mintExecutionTokenT     = ST.timeSync('S27', mintExecutionToken);
const _auditAppendMandatoryT   = ST.timeAsync('S33', _auditAppendMandatory);
const _registerEnforcementDecisionT = ST.timeAsync('S34', registerEnforcementDecision);
const _getEffectivePoliciesForTenantT = ST.timeSync('S23', getEffectivePoliciesForTenant);
const {
  streamingRejectedTotal,
  auditFailClosedRejectionsTotal,
  transparencyEnforcementEntriesTotal,
  transparencyEnforcementFailuresTotal,
  transparencyFailClosedRejectionsTotal,
  providerExecutionCancelledTotal,
  semanticOutputBlockedTotal,
}                              = require('../../observability/metrics');

const ARTIFACT_HDR           = 'x-qodiqa-artifact';
const IDEMPOTENCY_HDR        = 'idempotency-key';
const MAX_ARTIFACT_HDR_BYTES = 8 * 1024;   // 8 KB

// Configurable request timeout.  Covers the full enforce-and-execute pipeline
// including the AI provider call.  Fail-closed: timeout → BLOCK.
const AI_CHAT_TIMEOUT_MS = (() => {
  const v = parseInt(process.env.AI_CHAT_TIMEOUT_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 30_000;
})();

// API-2: master kill-switch — when false, the Idempotency-Key header is
// ignored entirely (treated as absent) and every request behaves exactly as
// it did before this remediation. Defaults on.
const IDEMPOTENCY_ENABLED = process.env.IDEMPOTENCY_ENABLED !== 'false';

// API-2: reservation TTL bounds an abandoned/crashed reservation (see
// idempotencyStore.js). It must comfortably exceed the longest an
// in-flight request can legitimately hold the reservation — the full
// enforce-and-execute pipeline is itself bounded by AI_CHAT_TIMEOUT_MS, so
// this tracks that value automatically with a fixed safety margin rather
// than needing independent tuning. Override only if a deployment's own
// operational needs require a wider window (e.g. a provider proxy that
// retries internally beyond AI_CHAT_TIMEOUT_MS).
const IDEMPOTENCY_RESERVATION_TTL_MS = (() => {
  const v = parseInt(process.env.IDEMPOTENCY_RESERVATION_TTL_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : AI_CHAT_TIMEOUT_MS + 15_000;
})();

// API-2: deterministic HTTP status for each idempotency-gate rejection —
// mirrors _providerStatus()'s role for provider error codes.
//
// API-9 remediation: IDEMPOTENCY_KEY_CONFLICT changed from 422 to
// 409 — the same idempotency key reused with a different request body is a
// resource conflict (the same class of failure as
// IDEMPOTENCY_REQUEST_IN_PROGRESS below), not an unprocessable-entity/
// business-rule failure. 422 is reserved for post-parse business-rule
// violations elsewhere in this API; a conflicting idempotency key isn't one.
function _idempotencyStatus(reason) {
  switch (reason) {
    case 'IDEMPOTENCY_KEY_TOO_LARGE':      return 413;
    case 'IDEMPOTENCY_KEY_INVALID':        return 400;
    case 'IDEMPOTENCY_KEY_CONFLICT':       return 409;
    case 'IDEMPOTENCY_REQUEST_IN_PROGRESS': return 409;
    case 'IDEMPOTENCY_STORE_UNAVAILABLE':  return 503;
    case 'IDEMPOTENCY_STREAMING_UNSUPPORTED': return 400;
    default: return 500;
  }
}

// Provider-execution error codes that mean "cancelled", not "failed" — both
// originate from the same AbortSignal firing (route-level timeout), but at
// different points in the dispatch chain (see _executeAI / executeProviderCall
// / services/providers/router.js).  Kept as a set so the audit write and the
// HTTP status mapping classify them identically.
const CANCELLATION_CODES = new Set(['REQUEST_TIMEOUT', 'PROVIDER_CANCELLED']);

// ── Audit helpers ─────────────────────────────────────────────────────────────

// Mandatory audit recording for a BLOCK decision. The HTTP response (:
// 200 {decision:'BLOCK',...} for policy/verification BLOCKs) is unaffected
// either way — a BLOCK decision was already reached — but the
// audit ENTRY for that decision is still mandatory evidence (protocol
// requirement: every decision, ALLOW or BLOCK, must be durably recorded).
// appendMandatory() retries transient failures a bounded number of times;
// if it still fails, this is escalated to CRITICAL (not silently absorbed
// as a single ERROR log line) so operators are alerted to an evidence gap
// even though the request's own disposition (blocked) is unaffected.
// (V2-FREEZE section 6): the signed receipt of a decision — only for a PERSISTED transparency leaf and an audit entry that
// was written. Failure to sign or store it never changes the response that was already decided: the field is then absent
// (never null) and the failure is escalated.
async function _receiptFor({ requestId, decision, auditEntryHash, registration }) {
  if (!requestId || !auditEntryHash || !registration || registration.persisted !== true || !registration.entryHash) return null;
  try {
    const receipt = await issueReceipt({ requestId, decision, entryHash: auditEntryHash, leafHash: _merkleLeafHash(registration.entryHash) });
    await putReceipt(receipt);
    return receipt;
  } catch (err) {
    emit('CRITICAL', 'RECEIPT_ISSUE_FAILED', { requestId, decision, error: err.message, code: err.code ?? null });
    return null;
  }
}

async function _writeAuditBlock(blockArgs) {
  const { artifactId = null, inputHash = null, signature = null, requestHash = null, policyHash = null, requestId = null, replayOf = null, tenantId = null, semantic = null, publicKeyId = null, completionStatus = null, consentProvenance = null, policyDecision = null, callerContext = null, provider = null, executingProvider = null, closesLifecycle = false, _reconcile = false } = blockArgs;
  let { reason, stage, model = null, extra = null } = blockArgs;   // reason/model/extra may be replaced below
  // what happened to the audit write (returned to the lifecycle reconciler; every other caller ignores it)
  let recorded = false; let duplicate = false;
  // / F6-N2: a BLOCK that CLOSES a lifecycle (its INTENT is already in the chain) must always be recordable. The
  // only values it carries that the INTENT did not are provider-derived (the provider's error code as `reason`, the
  // provider-returned `model`, and `extra`: responseId / tokenUsage / failover cause). If one of them holds U+0000 or a
  // lone surrogate, which the evidence-chain / recovery stores cannot represent (entryBuilder.unrepresentableTextPath),
  // those values are left out and the decision states it explicitly: reason AUDIT_UNREPRESENTABLE_TEXT. Nothing is
  // replaced or normalized, and the lifecycle is never left open.
  if (closesLifecycle && _unrepresentablePath({ reason, model, extra })) {
    emit('WARN', 'AUDIT_UNREPRESENTABLE_PROVIDER_VALUE', { requestId, stage, field: _unrepresentablePath({ reason, model, extra }) });
    reason = 'AUDIT_UNREPRESENTABLE_TEXT';
    model  = null;
    extra  = null;
  }
  const resolvedId = (typeof artifactId === 'string' && artifactId)
    ? artifactId
    : crypto.randomUUID();

  let auditEntryHash = null;
  try {
    const entry = await _auditAppendMandatoryT({
      artifactId:        resolvedId,
      inputHash:         inputHash   || undefined,
      decision:          'BLOCK',
      signature:         signature   || undefined,
      requestHash:       requestHash || undefined,
      policyHash:        policyHash  || undefined,
      verificationResult: false,
      tenantId:          tenantId    || undefined,
      publicKeyId:       publicKeyId || null,
      // correlation identifiers, not hash-protected — see
      // entryBuilder.js normalizeFields(). requestId may legitimately be
      // null here (e.g. an INPUT_GUARD-stage BLOCK before requestId was
      // established); traceId is null whenever OTel tracing is disabled.
      requestId,
      traceId: _tracingContext()?.traceId ?? null,
      // TRACE-2: immutable consent + policy-rule provenance, hash-protected
      // core fields on schemaVersion 3 audit entries (entryBuilder.js).
      // null whenever the BLOCK occurred before policy evaluation reached a
      // consent/rule decision (e.g. VALIDATION-stage blocks).
      consentProvenance,
      policyDecision,
      // authenticated-caller snapshot, hash-protected on
      // schemaVersion 4 (entryBuilder.js). null only for an artifact signed
      // before the remediation shipped (see sign.js/validateBoundRequest.js).
      callerContext,
      // hash-protected on schemaVersion 5 (entryBuilder.js). null
      // for any BLOCK that occurred before a provider/model was selected
      // (the common case — most BLOCKs happen before provider dispatch).
      provider,
      model,
      // hash-protected on schemaVersion 6 (entryBuilder.js) — same
      // values as the (unprotected, legacy) executionContext copies below,
      // promoted to the top level so tampering with the stated BLOCK reason,
      // recorded semantic classification, or linked provider response after
      // the fact invalidates the chain hash. tokenUsage/responseId for a
      // BLOCK only ever come from the output-semantic path's `extra`.
      stage,
      reason,
      semantic,
      tokenUsage: (extra && typeof extra === 'object') ? extra.tokenUsage ?? null : null,
      responseId: (extra && typeof extra === 'object') ? extra.responseId ?? null : null,
      // v7 (R-3/R-5/R-7): a BLOCK is a DECISION entry; nothing was delivered, so its outputHash is the hash of
      // the empty byte string (entryBuilder default for BLOCK). executingProvider is non-null only when a provider
      // was actually dispatched for this request — the lifecycle rules pair it with the request's INTENT.
      entryType:  'DECISION',
      executingProvider,
      executionContext:  {
        stage,
        reason,
        ...(replayOf ? { replayOf } : {}),
        ...(semantic ? { semantic } : {}),
        ...(publicKeyId ? { publicKeyId } : {}),
        ...(completionStatus ? { completionStatus } : {}),
        // optional extra fields for the output-semantic BLOCK path
        // (provider/model/responseId/tokenUsage) — additive, every existing
        // caller omits this and executionContext is unaffected.
        ...(extra && typeof extra === 'object' ? extra : {}),
      },
    }, { stage: 'BLOCK' });
    auditEntryHash = entry?.hash ?? null;
    recorded = true;
    // decision/policyHash/auditEntryHash embedded here so the row
    // this event produces in platform_audit_events (the canonical
    // correlation store, src/core/audit/centralStore.js) is a full join
    // surface into the audit chain, not just a name-and-id summary.
    emit('INFO', 'AUDIT_BLOCK_RECORDED', {
      artifactId: resolvedId, requestId, stage, reason,
      decision: 'BLOCK', policyHash: policyHash || null, auditEntryHash,
    });
  } catch (auditErr) {
    const alreadyIn = typeof auditErr.message === 'string' && auditErr.message.startsWith('already_executed');
    if (alreadyIn) {
      duplicate = true;
      emit('INFO', 'AUDIT_BLOCK_RECORDED', { artifactId: resolvedId, requestId, stage, reason, note: 'already_in_chain' });
    } else {
      // Not a benign duplicate — this is a genuine evidence-recording gap for a
      // BLOCK decision. Escalate loudly; the request itself was already denied.
      emit('CRITICAL', 'AUDIT_APPEND_FAILED', {
        artifactId: resolvedId, requestId, stage, reason,
        error: auditErr.message, code: auditErr.code ?? null,
      });
      // this BLOCK closes a lifecycle whose INTENT is already in the chain — retried until the store accepts it
      // (the same record, with the same artifactId, so a write that did land is recognised as a duplicate).
      if (closesLifecycle && !_reconcile && requestId) {
        _lifecycleReconciler.registerOpenLifecycle(requestId, { kind: 'block', retry: () => _writeAuditBlock({ ...blockArgs, artifactId: resolvedId, _reconcile: true }) });
      }
    }
  }

  // ── Transparency log write ─────────────────────────────────────────
  //
  // Every BLOCK decision — like every ALLOW decision below — is registered as
  // a transparency log leaf, attempted regardless of whether the audit write
  // above succeeded (auditEntryHash is simply null if it didn't). This
  // mirrors the audit chain's own BLOCK-path philosophy: the response was
  // already decided and is irreversible, so a transparency failure here is
  // escalated to CRITICAL rather than thrown — there is no "more blocked" to
  // fail closed to.
  try {
    const blockTransparencyReg = await _registerEnforcementDecisionT({
      bestEffort: true,   // a BLOCK cannot be made less safe; an unrecordable leaf is buffered, never dropped silently
      requestId: requestId || resolvedId,
      decision: 'BLOCK',
      reason,
      stage,
      auditEntryHash,
      inputHash,
      signature,
      policyHash,
      verificationResult: false,
      tenantId,
      publicKeyId,
      semantic,
      consentProvenance,
      policyRuleId:      policyDecision?.policyId      ?? null,
      policyRuleVersion: policyDecision?.policyVersion ?? null,
      policyRuleHash:    policyDecision?.policyRuleHash ?? null,
      callerId:          callerContext?.callerId ?? null,
    });
    transparencyEnforcementEntriesTotal.inc({ decision: 'BLOCK' });
    // the receipt of this BLOCK, for the response of the request that was blocked (see requestAuditContext.js)
    setRequestReceipt(requestId, await _receiptFor({ requestId, decision: 'BLOCK', auditEntryHash, registration: blockTransparencyReg }));

    // — BLOCK-path companion to.
    // registrar.js's non-PG branch signs the entry and returns
    // persisted:false without throwing (same mechanism as the ALLOW path
    // below);'s original fix only added this check to the ALLOW branch,
    // leaving BLOCK decisions to silently lose durable transparency
    // evidence under the identical condition. TRANSPARENCY_PERSISTENCE_DEGRADED
    // is decision-agnostic in OperationalDetector.js, so no detector change
    // is needed — emitting it here alone completes the coverage.
    if (blockTransparencyReg.persisted === false) {
      emit('WARN', 'TRANSPARENCY_PERSISTENCE_DEGRADED', {
        requestId:      requestId || resolvedId,
        transparencyId: blockTransparencyReg.transparencyId,
        tenantId,
        message: 'Transparency entry signed but not durably persisted (Postgres disabled) — evidentiary chain is sign-only for this decision.',
      });
    }
  } catch (transparencyErr) {
    transparencyEnforcementFailuresTotal.inc({ stage: 'BLOCK' });
    emit('CRITICAL', 'TRANSPARENCY_APPEND_FAILED', {
      artifactId: resolvedId, requestId, stage, reason,
      error: transparencyErr.message, code: transparencyErr.code ?? null,
    });
  }
  return { recorded, duplicate, auditEntryHash };
}
// the boot reconciliation closes the previous process's open lifecycles with this same writer.
_lifecycleReconciler.configure({ writeBlock: _writeAuditBlock, emit: (l, t, d) => emit(l, t, d) });

// ── Private: provider execution ───────────────────────────────────────────────

// ── provider failover authorization ─────────
// A failover target is never executed merely because it is configured: the
// same caller must be allowed to use it NOW —
//   1. its signing identity is enabled, not revoked, and holds SIGN_ARTIFACT;
//   2. the identity's provider scope (allowedProviders) includes the target;
//   3. consent and the tenant-effective policies pass FOR THE TARGET — the same
//      checkPolicy() evaluation the request just passed, with the target as the
//      consent action (REQUIRE_CONSENT uses payload.provider).
// Refusal returns the PRIMARY failure; the refusal is audited (executionContext).
function _makeFailoverAuthorizer(artifact, result, enforcement, opts) {
  return async (target, info) => {
    if (!result.callerId) return { ok: false, reason: 'NO_CALLER_IDENTITY' };
    let ident;
    try { ident = signingIdentityStore.getSigningIdentity(result.callerId); } catch (err) { return { ok: false, reason: err.code || 'IDENTITY_UNAVAILABLE' }; }
    if (!ident || ident.revoked || !ident.enabled) return { ok: false, reason: 'SIGNING_IDENTITY_REVOKED' };
    if (!Array.isArray(ident.permissions) || !ident.permissions.includes('SIGN_ARTIFACT')) return { ok: false, reason: 'IDENTITY_PERMISSION_DENIED' };
    if (Array.isArray(ident.allowedProviders) && !ident.allowedProviders.includes(target)) return { ok: false, reason: 'SCOPE_PROVIDER_DENIED' };
    const asTarget = { ...artifact, payload: { ...artifact.payload, provider: target } };
    // gate G-01: the model judged is the one that will be SENT to the target - the router forwards the primary's body (so the primary's default when the request named none), a routing
    // candidate carries its own (info.model) - never the target's own default, which would let a model-aware rule be sidestepped by omitting `model`.
    const attrs = buildAttributesFor(enforcement.requestBody, enforcement.effectivePolicies, artifact?.payload?.provider) || {};
    const sentModel = (info && typeof info.model === 'string' && info.model) ? info.model : attrs['request.model'];
    if (typeof sentModel === 'string' && sentModel) attrs['request.model'] = sentModel;
    const pr = await checkPolicy(enforcement.effectivePolicies, opts._policyStore, result.requestId, asTarget, true, result.publicKeyId, opts._clientIp, result.tenantId, attrs);
    if (!pr.allowed) return { ok: false, reason: pr.reason || 'POLICY_BLOCKED' };
    return { ok: true };
  };
}

/**
 * latency limit: a provider that does not honour its AbortSignal must still not hold the request past the limit. When a limit applies, the call is raced against the
 * (combined) signal: on abort the request fails with REQUEST_TIMEOUT exactly like a route-level timeout, and the abandoned call's late result or failure is discarded.
 */
function _withLatency(ms, signal, promise) {
  if (!ms) return promise;
  promise.catch(() => {});
  return new Promise((resolve, reject) => {
    const onAbort = () => { const e = new Error('REQUEST_TIMEOUT'); e.code = 'REQUEST_TIMEOUT'; reject(e); };
    if (signal.aborted) { onAbort(); return; }
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
  });
}

async function _executeAI(artifact, reqBody, requestId, _providerFn, traceOpts, signal) {
  const requestedProvider = artifact?.payload?.provider;
  if (typeof requestedProvider !== 'string' || !requestedProvider) {
    const err = new Error('MISSING_PROVIDER');
    err.code  = 'MISSING_PROVIDER';
    throw err;
  }

  // policy routing may have chosen another provider (and model) for this request before the budget was reserved; the artifact's own provider stays the "requested" one in the evidence
  const provider = (typeof traceOpts?.routedProvider === 'string' && traceOpts.routedProvider) ? traceOpts.routedProvider : requestedProvider;
  const routedInfo = traceOpts?.routed || null;

  // Cancellation is checked before any provider dispatch — including before
  // the injectable _providerFn used by tests — so a route-level timeout that
  // has already fired never allows a new outbound call to begin. This is the
  // single choke point every non-streaming provider call passes through.
  if (signal?.aborted) {
    const err = new Error('REQUEST_TIMEOUT');
    err.code  = 'REQUEST_TIMEOUT';
    throw err;
  }

  const tenantId       = traceOpts?.tenantId       ?? null;
  const organizationId = traceOpts?.organizationId ?? null;
  const policyHash     = traceOpts?.policyHash     ?? null;

  // mint a short-lived HMAC-SHA256 token binding this verifiedCtx to
  // the exact requestHash+policyHash the enforcement pipeline (Steps 1–5)
  // just verified. services/execution-guard.js re-derives and checks this
  // signature before any provider dispatch — a hand-built object of the
  // right shape is no longer sufficient to pass the invariant, only an
  // object signed by this same call is. mintExecutionToken() throws if
  // requestHash/policyHash are not valid 64-char hex — both are guaranteed
  // by this point (validateBoundRequest and checkPolicy's EXECUTE path both
  // already required it), so this is a fail-closed defensive check, not an
  // expected runtime path.
  const { issuedAt, signature } = _mintExecutionTokenT({
    requestHash: artifact.payload.requestHash,
    policyHash,
  });

  const verifiedCtx = Object.freeze({
    verified:       true,
    requestHash:    artifact.payload.requestHash,
    policyHash,
    artifactId:     requestId,
    tenantId,
    organizationId,
    issuedAt,
    signature,
  });

  const routing = { value: null };
  const traceMeta = {
    policyHash,
    // failover authorization + routing report (providers/failoverAuth.js)
    authorizeFailover: traceOpts?.authorizeFailover ?? null,
    onRouting: (r) => { routing.value = routedInfo ? { ...r, requestedProvider, routed: routedInfo } : r; if (typeof traceOpts?.onRouting === 'function') traceOpts.onRouting(routing.value); },
  };

  const { prompt, model } = reqBody;
  // resolveDefaultModel() is per-provider and shared with the streaming
  // path (src/streaming/streamEnforcer.js) so the two always agree — a
  // single global default was previously wrong (and unreachable via
  // validation) for every provider except openai. A provider with no
  // configured default returns null here, which the existing model-allowlist
  // check (services/providers/modelValidation.js) already rejects as
  // PROVIDER_MODEL_NOT_ALLOWED, exactly like any other invalid model — no
  // new error code or early-exit branch needed.
  const providerBody = {
    model:    (typeof traceOpts?.routedModel === 'string' && traceOpts.routedModel) ? traceOpts.routedModel : (typeof model === 'string' && model ? model : resolveDefaultModel(provider)),
    messages: require('../../validation/conversation').normalizeConversation(reqBody),   // the single prompt, or the caller's conversation
    // the signed output cap of a V2 artifact (adapters take min(configured cap, this)); absent for V1
    ...(require('../../validation/protocolV2').artifactMaxTokens(artifact) ? { maxTokens: require('../../validation/protocolV2').artifactMaxTokens(artifact) } : {}),
  };

  // v7 (R-8): the INTENT evidence entry is written IMMEDIATELY before provider execution — after the cancellation
  // and provider checks above (no INTENT for a request that never reaches dispatch) — and is fail-closed: if it
  // cannot be recorded (audit entry or its transparency leaf), the provider is never called.
  if (typeof traceOpts?.beforeDispatch === 'function') {
    try {
      await traceOpts.beforeDispatch({ provider, model: providerBody.model });
    } catch (err) {
      err.intentFailed = true;
      throw err;
    }
  }
  // The INTENT write can take long enough for the latency limit or the client to cancel the request: a cancelled request must not start the provider call (the caller
  // refunds the reservation because nothing was dispatched).
  if (signal?.aborted) {
    const err = new Error('REQUEST_TIMEOUT');
    err.code  = 'REQUEST_TIMEOUT';
    throw err;
  }
  if (typeof traceOpts?.onDispatch === 'function') traceOpts.onDispatch();

  const response = _providerFn
    ? await _providerFn(provider, providerBody, verifiedCtx, signal)
    : await executeProviderCall(provider, providerBody, verifiedCtx, traceMeta, signal);

  // All provider adapters return a normalized ProviderResponse.
  // response.output is the canonical text output field.
  const aiText = response?.output;
  if (typeof aiText !== 'string') {
    const err = new Error('PROVIDER_RESPONSE_INVALID');
    err.code  = 'PROVIDER_RESPONSE_INVALID';
    throw err;
  }

  return {
    aiText,
    responseId:  response?.executionMetadata?.responseId ?? null,
    model:       response?.model       ?? null,
    tokenUsage:  response?.tokenUsage  ?? null,
    routing:     routing.value || { requestedProvider, executingProvider: provider, failover: null, ...(routedInfo ? { routed: routedInfo } : {}) },
  };
}

// ── Shared enforcement pipeline (Steps 1–5) ──────────────────────────────────
//
// TRACE-2: checkPolicy() surfaces rule/consent provenance in different
// places depending on outcome — directly on the resolved value for ALLOW,
// under `.details` (the policy-check result's BLOCK body) for BLOCK. These two helpers
// normalize that so callers don't need to know which shape applies.
function _policyDecisionFrom(policyResult) {
  const src = policyResult.allowed ? policyResult : (policyResult.details || {});
  return {
    policyId:       src.policyId       ?? null,
    policyVersion:  src.policyVersion  ?? null,
    // TRACE-4: hash of the specific rule that decided (BLOCK only; null on
    // ALLOW — no single rule "decides" an ALLOW, every enabled rule had to
    // pass). Hash-protected as part of policyDecision on schemaVersion 3+
    // audit entries (entryBuilder.js) — no new schema version needed.
    policyRuleHash: src.policyRuleHash ?? null,
    engineVersion:  src.engineVersion  ?? null,
    evaluatedAt:    src.evaluatedAt    ?? null,
    evaluationPath: src.evaluationPath ?? [],
  };
}
function _consentProvenanceFrom(policyResult) {
  const src = policyResult.allowed ? policyResult : (policyResult.details || {});
  return src.consentProvenance ?? null;
}

// Runs validation, policy resolution, policy evaluation, and policy drift
// detection.  Returns either a BLOCK descriptor or an ALLOW descriptor.
// Both _enforceAndExecute and _enforceAndStream call this before diverging.

async function _runEnforcementPipeline(artifact, request, opts) {
  const { _store, _anomalyStore, _thresholds, _clock,
          _getPolicies, _policyStore, _clientIp,
          _idempotencyKey, _idempotencyStore } = opts;

  const result = await validateBoundRequest(artifact, request, {
    _store, _anomalyStore, _thresholds, _clock,
  });

  // Audit v8: from here on every audit entry of this request states when the artifact was issued and its protocol
  // version (entryBuilder reads them from the request context; ignored while QODIQA_AUDIT_SCHEMA_V8 is off).
  // (Also for an authenticated rejection such as a replay: it names its requestId, so its BLOCK entry and receipt belong to this request.)
  if (!result.preAuth) bindArtifactFacts({ requestId: result.requestId, issuedAt: artifact?.timestamp, protocolVersion: result.protocolVersion });

  if (!result.allowed && result.preAuth) {
    // unknown key, bad signature, expired / not yet valid —
    // no caller is authenticated, so nothing is written to the audit chain or
    // the transparency log. Same client response as before.
    recordPreAuthReject({ route: opts._route ?? null, reason: result.reason, stage: 'VALIDATION', clientIp: _clientIp ?? null, requestId: opts._requestId ?? null });
    return { decision: 'BLOCK', reason: result.reason, details: result.details || {} };
  }

  if (!result.allowed) {
    const replayOf = (result.reason === 'REPLAY_DETECTED' && typeof result.requestId === 'string')
      ? result.requestId : null;

    await _writeAuditBlock({
      inputHash:   artifact?.payload?.requestHash || null,
      signature:   artifact?.signature            || null,
      requestHash: artifact?.payload?.requestHash || null,
      reason:      result.reason,
      stage:       'VALIDATION',
      ...(replayOf ? { replayOf } : {}),
      publicKeyId: result.publicKeyId || null,
      callerContext: result.callerContext || null,
    });
    return { decision: 'BLOCK', reason: result.reason, details: result.details || {} };
  }

  const tenantId       = result.tenantId       || null;
  const organizationId = result.organizationId || null;

  // ── (D2): per-identity /ai/chat limit, now that the signature is verified.
  // Keyed by the authenticated caller or, failing that, the
  // verified signing key. A transport throttle (429 RATE_LIMITED + Retry-After),
  // like ai_chat_ip — not an enforcement decision, so not an audit entry.
  {
    const _tRl = ST.ON ? ST.start() : 0;
    const who = result.callerId || result.publicKeyId || null;
    const rl = await checkRateLimit('ai_chat_identity', {
      identity: `signingkey:${who ?? 'unknown'}`, signingKeyId: who, tenantId, reqId: opts._requestId ?? null, path: opts._route ?? null, method: 'POST',
    });
    if (ST.ON) ST.end('S21r', _tRl);
    if (!rl.allowed) {
      return { decision: 'BLOCK', reason: 'RATE_LIMITED', details: {}, retryAfterSeconds: rl.retryAfterSeconds ?? 60 };
    }
  }

  // ── per-tenant classification budget — charged BEFORE the prompt is classified. A
  // throttle (429 + Retry-After) like RATE_LIMITED above: no audit entry, no classification, no provider call. The
  // prompt itself is never truncated; it is either classified in full or refused here. See
  // src/core/semantic/classificationBudget.js.
  {
    const _conv = require('../../validation/conversation');
    const _len = request && request.body ? (_conv.enabled() && _conv.hasConversationFields(request.body) ? _conv.totalLength(request.body) : (typeof request.body.prompt === 'string' ? request.body.prompt.length : 0)) : 0;   // charged on everything the model reads
    const b = classificationBudget.take(tenantId, classificationBudget.windowsForLength(_len));
    if (!b.ok) {
      return { decision: 'BLOCK', reason: 'CLASSIFICATION_BUDGET_EXHAUSTED', details: {}, retryAfterSeconds: b.retryAfterSeconds };
    }
  }

  // ── provider scope, re-checked by the verifier ─────────────────
  // /sign enforces the signing identity's allowedProviders for every path the
  // canonical resolver maps to this route; the verifier re-checks it here, on
  // every alias, so an artifact minted before that fix (or by any other path
  // around it) cannot execute against a provider outside the identity's scope.
  // revocation reaches artifacts already minted. An artifact whose
  // signing identity has since been revoked, disabled or deleted (anywhere in
  // the cluster — the control plane) is refused, and a stale control-plane
  // snapshot fails closed (CONTROL_PLANE_STALE) instead of skipping the check.
  const _tScope = ST.ON ? ST.start() : 0;
  if (result.callerId) {
    let ident = null;
    try {
      ident = signingIdentityStore.getSigningIdentity(result.callerId);
    } catch (err) {
      if (err && err.name === 'ControlPlaneError') return { decision: 'BLOCK', reason: err.code, details: {} };
      ident = null;
    }
    if (!ident || ident.revoked || !ident.enabled) {
      if (ST.ON) ST.end('S21s', _tScope);
      await _writeAuditBlock({
        artifactId:  result.requestId,
        inputHash:   artifact?.payload?.requestHash || null,
        signature:   artifact?.signature            || null,
        requestHash: artifact?.payload?.requestHash || null,
        reason:      'SIGNING_IDENTITY_REVOKED',
        stage:       'SCOPE',
        requestId:   result.requestId,
        tenantId,
        publicKeyId: result.publicKeyId || null,
        callerContext: result.callerContext || null,
      });
      return { decision: 'BLOCK', reason: 'SIGNING_IDENTITY_REVOKED', details: {} };
    }
  }
  if (isAiChatRoute(request.path) && result.callerId) {
    let ident = null;
    try { ident = signingIdentityStore.getSigningIdentity(result.callerId); } catch { ident = null; }
    const provider = artifact?.payload?.provider ?? null;
    if (ident && Array.isArray(ident.allowedProviders) && !ident.allowedProviders.includes(provider)) {
      if (ST.ON) ST.end('S21s', _tScope);
      await _writeAuditBlock({
        artifactId:  result.requestId,
        inputHash:   artifact?.payload?.requestHash || null,
        signature:   artifact?.signature            || null,
        requestHash: artifact?.payload?.requestHash || null,
        reason:      'SCOPE_PROVIDER_DENIED',
        stage:       'SCOPE',
        requestId:   result.requestId,
        tenantId,
        publicKeyId: result.publicKeyId || null,
        callerContext: result.callerContext || null,
      });
      return { decision: 'BLOCK', reason: 'SCOPE_PROVIDER_DENIED', details: {} };
    }
  }
  if (ST.ON) ST.end('S21s', _tScope);

  // ── API-2: Idempotency gate ───────────────────────────────────────────────
  //
  // Runs immediately after authentication (tenantId/publicKeyId/callerId are
  // now known — the fingerprint requires "authenticated tenant, authenticated
  // identity") and BEFORE policy evaluation, semantic checks, or provider
  // execution — so a replayed retry never re-consumes rate-limit quota and
  // never re-invokes the provider. See src/core/idempotency/idempotencyGate.js
  // for the full design (reservation semantics, replay-scope decision,
  // concurrency handling).
  //
  // No-op when the caller sent no Idempotency-Key (idempotencyCtx stays
  // null throughout) — every existing caller is completely unaffected.
  let idempotencyCtx = null;
  if (_idempotencyKey) {
    const _tIdem = ST.ON ? ST.start() : 0;
    const gateResult = await idempotencyGate.gate({
      idempotencyKey:    _idempotencyKey,
      tenantId,
      organizationId,
      publicKeyId:       result.publicKeyId,
      callerId:          result.callerId,
      provider:          artifact?.payload?.provider || null,
      requestHash:       artifact?.payload?.requestHash || null,
      reservationTtlMs:  IDEMPOTENCY_RESERVATION_TTL_MS,
      _store:            _idempotencyStore,
    });
    if (ST.ON) ST.end('S22', _tIdem);

    if (gateResult.outcome === 'replay') {
      return { decision: 'REPLAY', replay: gateResult.record };
    }

    if (gateResult.outcome !== 'proceed') {
      await _writeAuditBlock({
        artifactId:  result.requestId,
        inputHash:   artifact?.payload?.requestHash || null,
        signature:   artifact?.signature            || null,
        requestHash: artifact?.payload?.requestHash || null,
        reason:      gateResult.reason,
        stage:       'IDEMPOTENCY_GATE',
        requestId:   result.requestId,
        tenantId,
        publicKeyId: result.publicKeyId || null,
        callerContext: result.callerContext || null,
      });
      return { decision: 'BLOCK', reason: gateResult.reason, details: gateResult.details || {} };
    }

    idempotencyCtx = gateResult.ctx;
  }

  const tenantPolicies    = _getEffectivePoliciesForTenantT(tenantId);
  const effectivePolicies = tenantPolicies ? (() => tenantPolicies) : _getPolicies;

  if (!effectivePolicies || !_policyStore) {
    await idempotencyGate.release(idempotencyCtx);
    await _writeAuditBlock({
      artifactId:  result.requestId,
      inputHash:   artifact?.payload?.requestHash || null,
      signature:   artifact?.signature            || null,
      requestHash: artifact?.payload?.requestHash || null,
      reason:      'POLICY_STATE_UNAVAILABLE',
      stage:       'POLICY_CHECK',
      requestId:   result.requestId,
      tenantId,
      publicKeyId: result.publicKeyId || null,
      callerContext: result.callerContext || null,
    });
    return { decision: 'BLOCK', reason: 'POLICY_STATE_UNAVAILABLE', details: {} };
  }

  let policyResult;
  try {
    // artifactValid=true is safe here — this line is only reached
    // when the validateBoundRequest() call above (line 311) already returned
    // allowed:true (an early BLOCK return at line 329 covers every other case).
    policyResult = await _checkPolicyT(
      effectivePolicies, _policyStore, result.requestId, artifact, true, result.publicKeyId, _clientIp, result.tenantId,
      buildAttributesFor(request && request.body, effectivePolicies, artifact?.payload?.provider ?? null),
    );
  } catch {
    await idempotencyGate.release(idempotencyCtx);
    await _writeAuditBlock({
      artifactId:  result.requestId,
      inputHash:   artifact?.payload?.requestHash || null,
      signature:   artifact?.signature            || null,
      requestHash: artifact?.payload?.requestHash || null,
      reason:      'INTERNAL_ERROR',
      stage:       'POLICY_CHECK',
      requestId:   result.requestId,
      tenantId,
      publicKeyId: result.publicKeyId || null,
      callerContext: result.callerContext || null,
    });
    return { decision: 'BLOCK', reason: 'INTERNAL_ERROR', details: {} };
  }

  if (!policyResult.allowed) {
    await idempotencyGate.release(idempotencyCtx);
    await _writeAuditBlock({
      artifactId:  result.requestId,
      inputHash:   artifact?.payload?.requestHash || null,
      signature:   artifact?.signature            || null,
      requestHash: artifact?.payload?.requestHash || null,
      policyHash:  policyResult.policyHash        || null,
      reason:      policyResult.reason,
      stage:       'POLICY_ENFORCEMENT',
      requestId:   result.requestId,
      tenantId,
      publicKeyId: result.publicKeyId || null,
      callerContext: result.callerContext || null,
      consentProvenance: _consentProvenanceFrom(policyResult),
      policyDecision:    _policyDecisionFrom(policyResult),
    });
    return { decision: 'BLOCK', reason: policyResult.reason, details: policyResult.details || {} };
  }

  // Policy drift detection — informational only, never blocks execution.
  const _tDrift = ST.ON ? ST.start() : 0;
  const _artifactPolicyHash = artifact?.payload?.policyHash ?? null;
  const _livePolicyHash     = policyResult.policyHash ?? null;
  if (typeof _artifactPolicyHash === 'string' && typeof _livePolicyHash === 'string') {
    if (!policyHashesEqual(_artifactPolicyHash, _livePolicyHash)) {
      emit('WARN', 'POLICY_DRIFT_DETECTED', {
        requestId:           result.requestId,
        policyDriftDetected: true,
        policyHashExpected:  _livePolicyHash,
        policyHashReceived:  _artifactPolicyHash,
      });
    }
  }
  if (ST.ON) ST.end('S25', _tDrift);

  return {
    decision:     'ALLOW',
    validationResult: result,
    policyResult,
    // the exact policy set the request passed — the failover
    // authorizer re-evaluates it for the failover target.
    effectivePolicies,
    requestBody: request && request.body,          // the failover re-evaluation builds its attributes from it
    tenantId,
    organizationId,
    // TRACE-2: resolved once here so both _enforceAndExecute and
    // _enforceAndStream can thread them into their respective audit writes
    // without re-deriving the ALLOW/BLOCK-shape distinction.
    consentProvenance: _consentProvenanceFrom(policyResult),
    policyDecision:    _policyDecisionFrom(policyResult),
    // API-2: null unless the caller sent an Idempotency-Key header — see
    // the gate above. _enforceAndExecute finalizes this (complete/release)
    // at every one of its own exit points.
    idempotencyCtx,
  };
}

// ── Semantic Policy Engine ────────────────────────────────────────────────────
//
// Runs after Consent Verification and the (non-semantic) Policy Engine, and
// before Execution Invariant / Provider Routing — see src/core/semantic/index.js
// for the full architecture rationale. Deterministic, provider-independent,
// and never itself calls an external model: it evaluates only the prompt
// text QODIQA already has in hand. `semantic.blocks` (see
// policies/semanticActions.js) is the single source of truth for whether the
// provider is reached: DENY always blocks, REVIEW blocks unless the
// deployment opted out, and WARN blocks only if the deployment opted in —
// there is no path here that lets a tier through by falling through a
// DENY-only check. Whenever it blocks, the request is denied and durably
// audited exactly like any other BLOCK, using the same _writeAuditBlock()
// every other enforcement failure uses.
async function _runSemanticCheck(artifact, reqBody, result, policyResult, tenantId) {
  // extracted to requestSemanticCheck.js so /verify's dry-run parity
  // check runs the exact same computation — see that module's header.
  const finalSemantic = await _evaluateRequestSemanticT({
    body:      reqBody,   // a conversation is screened role by role
    provider:  artifact?.payload?.provider || null,
    tenantId,
    requestId: result.requestId,
  });

  if (finalSemantic.blocks) {
    await _writeAuditBlock({
      artifactId:  result.requestId,
      inputHash:   artifact?.payload?.requestHash || null,
      signature:   artifact?.signature            || null,
      requestHash: artifact?.payload?.requestHash || null,
      policyHash:  policyResult?.policyHash       || null,
      reason:      finalSemantic.reason,
      stage:       'SEMANTIC_POLICY',
      requestId:   result.requestId,
      tenantId,
      semantic:    finalSemantic.evidence,
      publicKeyId: result.publicKeyId || null,
      callerContext: result.callerContext || null,
      // TRACE-2: policy enforcement already passed by this stage (semantic
      // runs after it) — the consent/rule provenance that authorized
      // reaching this point is known and belongs on this BLOCK entry too.
      consentProvenance: policyResult ? _consentProvenanceFrom(policyResult) : null,
      policyDecision:    policyResult ? _policyDecisionFrom(policyResult)    : null,
    });
  }

  return finalSemantic;
}

// ── Semantic Policy Engine — output side ─────────────────────────────
//
// Runs the identical engine (src/core/semantic/index.js) a second time per
// request, classifying the PROVIDER'S OUTPUT text instead of the caller's
// prompt — same classifier registry, same confidence/aggregation logic, same
// ALLOW/WARN/REVIEW/DENY tiers and the same `semantic.blocks` enforcement
// semantics as _runSemanticCheck() above (surface: 'RESPONSE' is metadata-only
// evidence tagging, see index.js). Runs after a successful provider call —
// the provider has already been contacted and cannot be un-called, but a
// BLOCK here still prevents the response from ever reaching the caller: the
// route returns the same 200 {decision:'BLOCK',...} as any other BLOCK.
async function _runOutputSemanticCheck(artifact, aiText, result, policyResult, tenantId, providerMeta) {
  const _tOut = ST.ON ? ST.start() : 0;
  // output beyond the classification cap is withheld, never truncated-and-released.
  const _outputTooLarge = typeof aiText === 'string' && aiText.length > classificationBudget.OUTPUT_MAX_CHARS;
  const semantic = _outputTooLarge
    ? { blocks: true, decision: 'DENY', reason: 'OUTPUT_TOO_LARGE', evidence: { surface: 'RESPONSE', outputChars: aiText.length, maxChars: classificationBudget.OUTPUT_MAX_CHARS } }
    : runSemanticPolicyEngine({
    prompt:     aiText,
    provider:   artifact?.payload?.provider || null,
    tenantId,
    requestId:  result.requestId,
    surface:    'RESPONSE',
  });

  // SEM-C session 3: same rule as _runSemanticCheck() above — the embedding
  // gate only runs when the keyword engine didn't already block, and only
  // its DENY (never its ALLOW) is substituted into finalSemantic.
  let finalSemantic = semantic;
  if (!semantic.blocks) {
    const embeddingResult = await embeddingGate.checkText(aiText, {
      requestId: result.requestId, tenantId, provider: artifact?.payload?.provider || null, surface: 'RESPONSE',
    });
    if (embeddingResult.blocks) finalSemantic = embeddingResult;
  }
  if (ST.ON) ST.end('S32', _tOut);
  // (step 7): the output's classification is charged to the tenant — never refused, bounded debt.
  if (!_outputTooLarge) classificationBudget.charge(tenantId, classificationBudget.windowsForLength(typeof aiText === 'string' ? aiText.length : 0));

  if (finalSemantic.blocks) {
    semanticOutputBlockedTotal.inc({ reason: finalSemantic.reason });
    await _writeAuditBlock({
      artifactId:  result.requestId,
      inputHash:   artifact?.payload?.requestHash || null,
      signature:   artifact?.signature            || null,
      requestHash: artifact?.payload?.requestHash || null,
      policyHash:  policyResult?.policyHash       || null,
      reason:      finalSemantic.reason,
      stage:       'SEMANTIC_POLICY_OUTPUT',
      requestId:   result.requestId,
      tenantId,
      semantic:    finalSemantic.evidence,
      publicKeyId: result.publicKeyId || null,
      callerContext: result.callerContext || null,
      consentProvenance: policyResult ? _consentProvenanceFrom(policyResult) : null,
      policyDecision:    policyResult ? _policyDecisionFrom(policyResult)    : null,
      // hash-protected top-level copies — see the (unprotected,
      // legacy) `extra` block below for the executionContext duplicates.
      provider: artifact?.payload?.provider || null,
      model:    providerMeta?.model         || null,
      // v7 (R-7): the provider that produced the blocked output.
      executingProvider: providerMeta?.executingProvider ?? null,
      closesLifecycle: true,   // / F6-N2 (provider-returned model / responseId / tokenUsage)
      // the response that got blocked never leaves the platform, but
      // which provider/model produced it — and its token cost — is still
      // valuable audit evidence, same fields the ALLOW path already records.
      extra: {
        provider:   artifact?.payload?.provider || null,
        model:      providerMeta?.model         || null,
        responseId: providerMeta?.responseId    || null,
        tokenUsage: providerMeta?.tokenUsage     || null,
      },
    });
  }

  return finalSemantic;
}

// ── Single enforcement entry point ────────────────────────────────────────────

async function _enforceAndExecute(artifact, request, reqBody, opts) {
  const enforcement = await _runEnforcementPipeline(artifact, request, opts);

  // API-2: a cache hit on a prior, durably-completed EXECUTE for this exact
  // (tenant, Idempotency-Key, fingerprint) — short-circuits everything below
  // (policy/semantic re-evaluation, provider dispatch, audit/transparency
  // writes never run again). See idempotencyGate.js for why only EXECUTE
  // outcomes are ever cached this way.
  if (enforcement.decision === 'REPLAY') {
    return { decision: 'REPLAY', replay: enforcement.replay };
  }

  if (enforcement.decision === 'BLOCK') {
    // R-16: carry the limiter's own retry delay to the response (it was dropped here, so non-stream
    // RATE_LIMITED / CLASSIFICATION_BUDGET_EXHAUSTED always answered Retry-After: 60).
    return { decision: 'BLOCK', reason: enforcement.reason, details: enforcement.details, retryAfterSeconds: enforcement.retryAfterSeconds };
  }

  const { validationResult: result, policyResult, tenantId, organizationId, consentProvenance, policyDecision, idempotencyCtx } = enforcement;

  const semantic = await _runSemanticCheck(artifact, reqBody, result, policyResult, tenantId);
  if (semantic.blocks) {
    await idempotencyGate.release(idempotencyCtx);
    return { decision: 'BLOCK', reason: semantic.reason, details: { semantic: semantic.evidence } };
  }

  // DLP, input: the DLP rules of the effective policy set run on the text the provider would receive (the request binding above covered the ORIGINAL body; the
  // DLP_TRANSFORM events carry the hash before and after, so the log of a changed request never reads as the request that arrived). Fail closed: see dlpService.
  const dlpPolicySet = enforcement.effectivePolicies();
  let execBody = reqBody;
  // custom content rules, input: judged on the request AS RECEIVED (before DLP rewrites it)
  {
    const cin = contentStage.check(dlpStage.textsOf(reqBody), dlpPolicySet, 'input', { model: effectiveModel(reqBody, artifact?.payload?.provider), purpose: reqBody && reqBody.purpose });
    if (cin.blocked) {
      await idempotencyGate.release(idempotencyCtx);
      return { decision: 'BLOCK', reason: cin.reason, details: { contentRule: cin.hits.map((h) => ({ ruleId: h.ruleId, items: h.items, score: h.score, threshold: h.threshold })) } };
    }
  }
  {
    const dlpIn = dlpStage.applyToBody(reqBody, dlpPolicySet);
    await dlpStage.recordEvents(dlpIn.events, { requestId: result.requestId, tenantId });
    if (dlpIn.blocked) {
      await idempotencyGate.release(idempotencyCtx);
      return { decision: 'BLOCK', reason: dlpIn.reason, details: { dlp: { direction: 'input', rules: [...new Set(dlpIn.events.flatMap((e) => e.rules))] } } };
    }
    execBody = dlpIn.body;
  }

  // policy routing: the effective ROUTING rule (if any) may send the request to another candidate provider/model - only one the SAME caller is authorised for now (the failover
  // authorisation, evaluated for the candidate) - and BEFORE the budget is reserved, so quotas, tariffs and latency limits apply to the provider and model that will really serve it.
  const _failoverAuth = _makeFailoverAuthorizer(artifact, result, enforcement, opts);
  const _requestedProvider = artifact?.payload?.provider;
  const routedRes = await routingStage.resolve({
    policies: dlpPolicySet, requestedProvider: _requestedProvider, body: execBody,
    attributes: buildAttributesFor(execBody, () => dlpPolicySet, _requestedProvider) || {},
    context: { userId: result.publicKeyId || null, callerId: result.callerId || null, tenantId, ip: opts._clientIp || null, timestamp: Math.floor(Date.now() / 1000) },
    authorize: (target, info) => _failoverAuth(target, info), estimatedTokens: estimateTokens(dlpStage.textsOf(execBody)),
  });
  const _servingProvider = routedRes.provider;

  // budgets and quotas: charged atomically with an upper estimate NOW - after every other rule has passed, so a request refused for another reason never uses a budget - and
  // settled with the real usage once the provider has answered (or refunded if it fails).
  const budget = await budgetStage.reserve({ policies: dlpPolicySet, store: opts._policyStore, tenantId, callerId: result.callerId, userId: result.publicKeyId,
    model: routedRes.model || effectiveModel(execBody, _servingProvider), estimatedTokens: estimateTokens(dlpStage.textsOf(execBody)) });
  if (!budget.allowed) {
    await idempotencyGate.release(idempotencyCtx);
    return { decision: 'BLOCK', reason: budget.reason, details: { budget: { policyId: budget.policyId } } };
  }
  const latencyMs = budgetStage.latencyLimitMs(dlpPolicySet, routedRes.model || effectiveModel(execBody, _servingProvider));
  const execSignal = latencyMs ? AbortSignal.any([opts._signal, AbortSignal.timeout(latencyMs)].filter(Boolean)) : opts._signal;

  let aiText, responseId, model, tokenUsage, routing;
  let routingSeen = null;
  let dispatched = false;
  const _intentPolicyHash = policyResult?.policyHash || artifact?.payload?.policyHash || null;
  try {
    ({ aiText, responseId, model, tokenUsage, routing } = await _withLatency(latencyMs, execSignal, _executeAI(artifact, execBody, result.requestId, opts._providerFn, {
      policyHash: policyResult.policyHash ?? null,
      tenantId,
      organizationId,
      authorizeFailover: _failoverAuth,
      routedProvider: _servingProvider, routedModel: routedRes.model, routed: routedRes.routed,
      onRouting: (r) => { routingSeen = r; },
      // v7 (R-8/R-10/R-11): INTENT entry + its own transparency leaf, fail-closed (see _executeAI).
      beforeDispatch: ({ provider: dispatchProvider, model: dispatchModel }) => writeLifecycleEntry('INTENT', {
        requestId:         result.requestId,
        inputHash:         artifact.payload.requestHash,
        signature:         artifact.signature,
        requestHash:       artifact.payload.requestHash,
        policyHash:        _intentPolicyHash,
        tenantId,
        organizationId,
        publicKeyId:       result.publicKeyId || null,
        traceId:           _tracingContext()?.traceId ?? null,
        consentProvenance,
        policyDecision,
        callerContext:     result.callerContext || null,
        provider:          artifact?.payload?.provider || null,
        model:             dispatchModel || null,
        semantic:          semantic.evidence,
        executingProvider: dispatchProvider,
        executionContext:  {
          stage:       'PROVIDER_DISPATCH',
          provider:    artifact?.payload?.provider || null,
          model:       dispatchModel || null,
          semantic:    semantic.evidence,
          publicKeyId: result.publicKeyId || null,
        },
      }, {
        append:   _auditAppendMandatoryT,
        register: _registerEnforcementDecisionT,
        onDegraded: (reg) => emit('WARN', 'TRANSPARENCY_PERSISTENCE_DEGRADED', {
          requestId: result.requestId, transparencyId: reg.transparencyId, tenantId,
          message: 'Transparency entry signed but not durably persisted (Postgres disabled) — evidentiary chain is sign-only for this decision.',
        }),
      }),
      onDispatch: () => { dispatched = true; },
    }, execSignal)));
  } catch (providerErr) {
    // a failure that is an ANSWER (the provider refused or errored, or it was never called) returns the reservation; a call the latency limit or the client cut short after dispatch
    // keeps the estimate charged (F8V-03: the provider may have done the work, and a timeout must not be a free retry)
    if (dispatched && execSignal && execSignal.aborted) await budgetStage.settle(budget.reservation, null); else await budgetStage.refund(budget.reservation);
    if (providerErr?.intentFailed && providerErr.code === 'AUDIT_UNREPRESENTABLE_TEXT') {
      // / F6-N2: a request-derived value the downstream raw stores cannot represent — the INTENT append was
      // refused before ANYTHING was persisted (no entry, no leaf, no pseudonym key) and the provider was never called.
      // There is no lifecycle to close, so no BLOCK is written either; the request is refused (422).
      emit('WARN', 'AUDIT_UNREPRESENTABLE_TEXT_REFUSED', { requestId: result.requestId, stage: 'INTENT', field: providerErr.field ?? null });
      await idempotencyGate.release(idempotencyCtx);
      throw providerErr;
    }
    if (providerErr?.intentFailed) {
      // v7 (R-8, fail-closed): the INTENT could not be recorded, so the provider was NEVER called. Best-effort
      // BLOCK DECISION (no provider executed → executingProvider null) closes any INTENT that did reach the chain;
      // the request is refused through the existing error contract (AUDIT_/TRANSPARENCY_PERSISTENCE_FAILED → 503).
      emit('CRITICAL', 'AUDIT_APPEND_FAILED', {
        error: providerErr.message, requestId: result.requestId, stage: 'INTENT', code: providerErr.code ?? null,
      });
      auditFailClosedRejectionsTotal.inc({ stage: 'INTENT' });
      await _writeAuditBlock({
        artifactId:  result.requestId,
        inputHash:   artifact?.payload?.requestHash || null,
        signature:   artifact?.signature            || null,
        requestHash: artifact?.payload?.requestHash || null,
        policyHash:  policyResult.policyHash        || null,
        reason:      providerErr.code || 'AUDIT_PERSISTENCE_FAILED',
        stage:       'PROVIDER_DISPATCH',
        requestId:   result.requestId,
        tenantId,
        publicKeyId: result.publicKeyId || null,
        callerContext: result.callerContext || null,
        provider: artifact?.payload?.provider || null,
      });
      await idempotencyGate.release(idempotencyCtx);
      throw providerErr;
    }
    // Cancellation (route-level timeout that fired before or during the
    // provider call) is recorded as CANCELLED evidence, distinct from a
    // genuine provider failure — see CANCELLATION_CODES below. Both codes
    // originate from the same abort signal; REQUEST_TIMEOUT means the signal
    // was already aborted before dispatch even began, PROVIDER_CANCELLED
    // means an in-flight outbound call was aborted mid-request.
    const isCancellation = CANCELLATION_CODES.has(providerErr?.code);
    if (isCancellation) {
      providerExecutionCancelledTotal.inc({ reason: providerErr.code });
    }
    // genuine provider failures (best-effort; labels bounded to a token shape, else 'other'/'OTHER').
    if (!isCancellation) { try { const _p = String(artifact?.payload?.provider ?? ''); const _c = String(providerErr?.code ?? ''); require('../../observability/metrics').providerFailuresTotal.inc({ provider: /^[a-z0-9_-]{1,32}$/i.test(_p) ? _p : 'other', code: /^[A-Z][A-Z0-9_]{1,47}$/.test(_c) ? _c : 'OTHER' }); } catch { /* best-effort metric */ } }
    await _writeAuditBlock({
      artifactId:  result.requestId,
      inputHash:   artifact?.payload?.requestHash || null,
      signature:   artifact?.signature            || null,
      requestHash: artifact?.payload?.requestHash || null,
      policyHash:  policyResult.policyHash        || null,
      reason:      providerErr?.code || 'PROVIDER_ERROR',
      stage:       isCancellation ? 'PROVIDER_EXECUTION_CANCELLED' : 'PROVIDER_EXECUTION',
      requestId:   result.requestId,
      tenantId,
      publicKeyId: result.publicKeyId || null,
      callerContext: result.callerContext || null,
      // provider was already selected/dispatched by this point even
      // though the call itself errored/was cancelled — the attempted
      // provider identity is still evidentiary.
      provider: artifact?.payload?.provider || null,
      completionStatus: isCancellation ? 'CANCELLED' : null,
      // requested vs executing provider, and a refused failover
      extra: routingSeen ? { requestedProvider: routingSeen.requestedProvider, executingProvider: routingSeen.executingProvider, failover: routingSeen.failover, ...(routingSeen.routed ? { routed: routingSeen.routed } : {}) } : (routedRes.routed ? { requestedProvider: _requestedProvider, executingProvider: _servingProvider, failover: null, routed: routedRes.routed } : undefined),
      // v7 (R-7): the provider actually dispatched (null when the call never started, e.g. pre-dispatch timeout).
      executingProvider: dispatched ? (routingSeen?.executingProvider || artifact?.payload?.provider || null) : null,
      closesLifecycle: dispatched,   // / F6-N2
    });
    await idempotencyGate.release(idempotencyCtx);
    throw providerErr;
  }

  // ── Late-completion guard ────────────────────────────────────────────────────
  //
  // The provider call above returned successfully — but if the route-level
  // timeout already fired while it was in flight, the client has already been
  // told the request failed (504 REQUEST_TIMEOUT). A provider adapter that
  // does not fully honor its AbortSignal (or a race where the response lands
  // in the same tick the signal aborts) could otherwise slip a late success
  // through to Step 6 below and get recorded as a normal ALLOW/EXECUTE — audit
  // evidence for an outcome the caller never received. Once the signal is
  // aborted, every outcome is CANCELLED, full stop; a technically-successful
  // response cannot un-cancel it. This is deliberately checked in the success
  // path too, not just the catch block above, precisely for that race.
  if (ST.ON) { const _tLate = ST.start(); void opts._signal?.aborted; ST.end('S31', _tLate); }
  // the same cancellation is re-checked immediately before the ALLOW append
  // (Step 6 below), because the output-side semantic check and the representability check between here and there
  // await too — a timeout that fires during them would otherwise still be recorded as ALLOW/EXECUTE.
  const _cancelAfterLateCompletion = async (metricReason) => {
    providerExecutionCancelledTotal.inc({ reason: metricReason });
    await _writeAuditBlock({
      artifactId:  result.requestId,
      inputHash:   artifact?.payload?.requestHash || null,
      signature:   artifact?.signature            || null,
      requestHash: artifact?.payload?.requestHash || null,
      policyHash:  policyResult.policyHash        || null,
      reason:      'REQUEST_TIMEOUT',
      stage:       'PROVIDER_EXECUTION_CANCELLED',
      requestId:   result.requestId,
      tenantId,
      publicKeyId: result.publicKeyId || null,
      callerContext: result.callerContext || null,
      // the provider call succeeded before the late-completion guard
      // fired — provider/model identity for this (cancelled) decision is known.
      provider: artifact?.payload?.provider || null,
      model:    model                       || null,
      completionStatus: 'CANCELLED',
      // v7 (R-7): the call completed; nothing was delivered (outputHash = hash of empty bytes).
      executingProvider: routing?.executingProvider || artifact?.payload?.provider || null,
      closesLifecycle: true,   // / F6-N2
    });
    await idempotencyGate.release(idempotencyCtx);
    const err = new Error('REQUEST_TIMEOUT');
    err.code  = 'REQUEST_TIMEOUT';
    throw err;
  };
  if (opts._signal?.aborted) await _cancelAfterLateCompletion('LATE_COMPLETION');

  // ── Output-side Semantic Policy Engine ─────────────────────────────
  //
  // The provider has already produced a response — that call cannot be
  // undone — but the response itself must still clear the same semantic bar
  // the request did before it is allowed to reach the caller. A BLOCK here
  // takes the exact same shape as every other enforcement BLOCK: the route
  // returns 200 {decision:'BLOCK',...}, and the idempotency reservation is released
  // (never marked "completed") so a blocked output is never cached as a
  // replayable EXECUTE.
  const _accounted = await budgetStage.settle(budget.reservation, tokenUsage);            // the real usage replaces the estimate (cost accounting event COST_ACCOUNTED)
  // tokens and cost of the provider that really served the call (tariff of the ROUTING rule in force) - metrics, and a COST_ACCOUNTED event when no BUDGET rule produced one
  try {
    const acct = costAccounting.account({ policies: dlpPolicySet, provider: routing?.executingProvider || _servingProvider, model, tokenUsage });
    if (acct && !(_accounted && _accounted.currency)) emit('INFO', 'COST_ACCOUNTED', { tenantId, model: model || null, provider: routing?.executingProvider || _servingProvider, inputTokens: tokenUsage.inputTokens, outputTokens: tokenUsage.outputTokens, estimated: false, costMicros: acct.costMicros, currency: acct.currency });
  } catch { /* accounting is observability: it never fails a request */ }
  const outputSemantic = await _runOutputSemanticCheck(
    artifact, aiText, result, policyResult, tenantId, { model, responseId, tokenUsage, executingProvider: routing?.executingProvider || artifact?.payload?.provider || null },
  );
  if (outputSemantic.blocks) {
    await idempotencyGate.release(idempotencyCtx);
    return { decision: 'BLOCK', reason: outputSemantic.reason, details: { semantic: outputSemantic.evidence } };
  }

  // custom content rules, output
  {
    const cout = contentStage.check([aiText], dlpPolicySet, 'output', { model: effectiveModel(reqBody, artifact?.payload?.provider), purpose: reqBody && reqBody.purpose });
    if (cout.blocked) {
      await idempotencyGate.release(idempotencyCtx);
      return { decision: 'BLOCK', reason: cout.reason, details: { contentRule: cout.hits.map((h) => ({ ruleId: h.ruleId, items: h.items, score: h.score, threshold: h.threshold })) } };
    }
  }

  // DLP, output: the answer is screened (and redacted / masked / withheld) before anything is delivered or hashed for the COMMIT.
  {
    const dlpOut = dlpStage.applyToText(aiText, dlpPolicySet, { inputTexts: dlpStage.textsOf(reqBody) });
    await dlpStage.recordEvents(dlpOut.events, { requestId: result.requestId, tenantId });
    if (dlpOut.blocked) {
      await idempotencyGate.release(idempotencyCtx);
      return { decision: 'BLOCK', reason: dlpOut.reason, details: { dlp: { direction: 'output', rules: [...new Set(dlpOut.events.flatMap((e) => e.rules))] } } };
    }
    aiText = dlpOut.text;
  }

  // ── / F6-N2: provider-returned values the downstream raw stores cannot represent ──────────────────────────
  // model / responseId / tokenUsage / the routing report came back from the provider AFTER the INTENT was recorded.
  // If one holds U+0000 or a lone surrogate the ALLOW entry could not be stored in evidence_chain_records / the
  // recovery queue, so it is never attempted: a BLOCK DECISION without those values (reason
  // AUDIT_UNREPRESENTABLE_TEXT) closes the lifecycle, nothing is delivered, and the request is refused (422).
  {
    const badField = _unrepresentablePath({ model, responseId, tokenUsage, routing });
    if (badField) {
      await _writeAuditBlock({
        artifactId:  result.requestId,
        inputHash:   artifact?.payload?.requestHash || null,
        signature:   artifact?.signature            || null,
        requestHash: artifact?.payload?.requestHash || null,
        policyHash:  policyResult.policyHash        || null,
        reason:      'AUDIT_UNREPRESENTABLE_TEXT',
        stage:       'PROVIDER_EXECUTION',
        requestId:   result.requestId,
        tenantId,
        publicKeyId: result.publicKeyId || null,
        callerContext: result.callerContext || null,
        consentProvenance,
        policyDecision,
        provider:    artifact?.payload?.provider || null,
        executingProvider: (typeof routing?.executingProvider === 'string' && !_unrepresentablePath({ p: routing.executingProvider })) ? routing.executingProvider : (artifact?.payload?.provider || null),
        closesLifecycle: true,
      });
      await idempotencyGate.release(idempotencyCtx);
      const err = new Error(`AUDIT_UNREPRESENTABLE_TEXT: provider-returned ${badField} contains U+0000 or an unpaired surrogate`);
      err.code = 'AUDIT_UNREPRESENTABLE_TEXT';
      err.field = badField;
      throw err;
    }
  }

  // ── Step 6: Audit write — MANDATORY, fail-closed ─────────────────────────────
  //
  // QODIQA is an evidence-first platform: a request must never be reported as
  // successful (EXECUTE) if the mandatory audit entry for that decision could
  // not be durably recorded. The AI provider has already been called by this
  // point — that side effect cannot be undone — but the platform still MUST
  // NOT tell the caller the request succeeded without durable evidence, so on
  // failure this throws rather than returning EXECUTE. The route handler's
  // outer catch (see _providerStatus) turns this into a 503, never a 200.
  const _auditPolicyHash = policyResult?.policyHash || artifact?.payload?.policyHash;

  if (typeof artifact?.payload?.requestHash !== 'string' || !_auditPolicyHash) {
    // Unreachable in practice — the enforcement pipeline guarantees both
    // fields by this point — but if it ever happens, fail closed rather than
    // silently return EXECUTE with no audit entry at all.
    emit('CRITICAL', 'AUDIT_APPEND_FAILED', {
      requestId: result.requestId, stage: 'ALLOW',
      error: 'missing requestHash or policyHash — cannot construct mandatory audit entry',
    });
    auditFailClosedRejectionsTotal.inc({ stage: 'ALLOW' });
    await idempotencyGate.release(idempotencyCtx);
    const failure = new Error('AUDIT_PERSISTENCE_FAILED: missing requestHash or policyHash');
    failure.code  = 'AUDIT_PERSISTENCE_FAILED';
    throw failure;
  }

  // last cancellation check before the ALLOW append. No await separates this check from the append call, so
  // a timeout that fired at any point up to here is recorded as CANCELLED (never ALLOW). The residual window — a
  // timeout that fires DURING the ALLOW append or the transparency registration after it — is documented in
  // docs/api/overview.md ("Timeouts and the audit record"); an append-only record cannot be withdrawn once durable.
  if (opts._signal?.aborted) await _cancelAfterLateCompletion('LATE_COMPLETION_BEFORE_ALLOW');

  let auditEntry;
  try {
    auditEntry = await _auditAppendMandatoryT({
      artifactId:        result.requestId,
      inputHash:         artifact.payload.requestHash,
      decision:          'ALLOW',
      signature:         artifact.signature,
      requestHash:       artifact.payload.requestHash,
      policyHash:        _auditPolicyHash,
      verificationResult: true,
      tenantId,
      organizationId:    organizationId || undefined,
      publicKeyId:       result.publicKeyId || null,
      // correlation identifiers, not hash-protected — see
      // entryBuilder.js normalizeFields(). artifactId already equals
      // result.requestId for ALLOW entries by convention; requestId is
      // still recorded explicitly so lookups don't depend on that
      // convention holding forever. traceId is null when OTel tracing is
      // disabled (see src/observability/tracing/index.js).
      requestId:  result.requestId,
      traceId:    _tracingContext()?.traceId ?? null,
      // TRACE-2: immutable consent + policy-rule provenance for this EXECUTE
      // decision, hash-protected on schemaVersion 3 entries.
      consentProvenance,
      policyDecision,
      // authenticated-caller snapshot, hash-protected on
      // schemaVersion 4 entries.
      callerContext:     result.callerContext || null,
      // hash-protected on schemaVersion 5 entries — same values as
      // the (unprotected, legacy) executionContext copies below, promoted
      // to the top level so tampering with provider/model attribution after
      // the fact invalidates the chain hash. See entryBuilder.js.
      provider: artifact?.payload?.provider || null,
      model:    model                       || null,
      // hash-protected on schemaVersion 6 entries — same values as
      // the (unprotected, legacy) executionContext copies below, promoted
      // to the top level so tampering with the recorded semantic
      // classification, token-usage figures, or linked provider response
      // after the fact invalidates the chain hash. ALLOW entries carry no
      // `reason` (that is a BLOCK-only concept) — stays null.
      stage:       'PROVIDER_EXECUTION',
      reason:      null,
      semantic:    semantic.evidence,
      tokenUsage:  tokenUsage || null,
      responseId:  responseId || null,
      // v7 (R-3/R-5/R-7): DECISION entry; outputHash binds the EXACT output content delivered to the client
      // (finalResult.response below is this same aiText); executingProvider = the provider that actually executed.
      entryType:         'DECISION',
      outputHash:        _outputHashOf(aiText),
      executingProvider: routing.executingProvider,
      executionContext:  {
        stage:       'PROVIDER_EXECUTION',
        provider:    artifact?.payload?.provider || null,
        // the provider that ACTUALLY executed, the one
        // requested, and the failover (from/to/cause) when there was one.
        // In executionContext now; entering the hashed fields is.
        requestedProvider: routing.requestedProvider,
        executingProvider: routing.executingProvider,
        failover:          routing.failover,
        ...(routing.routed ? { routed: routing.routed } : {}),   // the policy-routing decision (rule, strategy, from/to, model replacement, skipped candidates)
        responseId:  responseId || null,
        model:       model      || null,
        tokenUsage:  tokenUsage || null,
        semantic:    semantic.evidence,
        // output-side evidence recorded on every ALLOW too, not just
        // BLOCKs — full observability parity with the request-side field above.
        outputSemantic: outputSemantic.evidence,
        publicKeyId: result.publicKeyId || null,
      },
    }, { stage: 'ALLOW' });
    // decision/policyHash/auditEntryHash embedded here so the row
    // this event produces in platform_audit_events is a full join surface
    // into the audit chain — see the matching comment on the BLOCK path.
    // this ALLOW-path event is a routine success type, so platform_audit_events
    // now holds it only as a per-minute aggregate (centralStore AGGREGATED_EVENT_TYPES) — the per-request join
    // surface for an ALLOW is this stdout/SIEM line; the BLOCK path above (AUDIT_BLOCK_RECORDED) stays one row each.
    emit('INFO', 'AUDIT_EXECUTION_RECORDED', {
      artifactId: result.requestId,
      requestId:  result.requestId,
      provider:   artifact?.payload?.provider || null,
      decision: 'ALLOW', policyHash: _auditPolicyHash, auditEntryHash: auditEntry?.hash ?? null,
    });
  } catch (auditErr) {
    emit('CRITICAL', 'AUDIT_APPEND_FAILED', {
      error: auditErr.message, requestId: result.requestId, stage: 'ALLOW', code: auditErr.code ?? null,
    });
    auditFailClosedRejectionsTotal.inc({ stage: 'ALLOW' });
    // the provider ran and its INTENT is in the chain, but the ALLOW could not be
    // recorded and the client gets 503 with no content. The lifecycle is closed with what is true — a BLOCK
    // PROVIDER_OUTCOME_UNRECORDED, nothing delivered — as soon as the audit store accepts appends again.
    _lifecycleReconciler.registerOpenLifecycle(result.requestId, { kind: 'allow-unrecorded', retry: () => _writeAuditBlock({
      artifactId:  result.requestId,
      inputHash:   artifact.payload.requestHash,
      signature:   artifact.signature,
      requestHash: artifact.payload.requestHash,
      policyHash:  _auditPolicyHash,
      reason:      _lifecycleReconciler.REASON,
      stage:       'PROVIDER_EXECUTION',
      requestId:   result.requestId,
      tenantId,
      publicKeyId: result.publicKeyId || null,
      callerContext: result.callerContext || null,
      provider:    artifact?.payload?.provider || null,
      model:       model || null,
      executingProvider: routing.executingProvider,
      closesLifecycle: true,
      _reconcile: true,
    }) });
    // (verification): the provider has already executed. The reservation is deliberately NOT released: a retry with the same
    // Idempotency-Key (and a fresh artifact) would call the provider a second time; it now waits out the short reservation TTL.
    throw auditErr;
  }

  // from here the request has an ALLOW DECISION in the chain, so it owes a COMMIT: the exact bytes that reach the client (or that it
  // did not reach). The route settles the tracker from the HTTP response; a timeout that already fired, or an error before the response,
  // settles it as failed. With audit schema v8 off the COMMIT is not written (counted as skipped).
  const _commit = _createCommitTracker({ requestId: result.requestId, signature: artifact.signature, tenantId, organizationId: organizationId || undefined });
  if (opts._commitHolder) opts._commitHolder.tracker = _commit;
  if (opts._signal?.aborted) _commit.fail('TIMEOUT');

  // ── Step 7: Transparency log write — MANDATORY, fail-closed ────────
  //
  // Same evidence-first reasoning as the audit write above: the AI provider
  // has already been called, so a request must never be reported EXECUTE
  // without durable, externally-verifiable Merkle transparency evidence for
  // that same decision. On failure this throws — never silently degrades to
  // "recorded in the audit chain only" — so the route handler's outer catch
  // turns it into a 503, exactly like AUDIT_PERSISTENCE_FAILED.
  // (D3): a PostgreSQL PERSISTENCE failure no longer lands
  // here — enforcementBridge.js durably queues the leaf (recovery queue, or
  // the crash-safe journal when PG refuses the enqueue) and resolves
  // persisted:'pending'. Only a failure that could not be durably recorded,
  // or a non-persistence failure (signing, data), still throws into this
  // fail-closed 503.
  let transparencyReg;
  try {
    transparencyReg = await _registerEnforcementDecisionT({
      requestId:   result.requestId,
      decision:    'ALLOW',
      reason:      'ALL_CHECKS_PASSED',
      stage:       'PROVIDER_EXECUTION',
      auditEntryHash: auditEntry?.hash ?? null,
      inputHash:   artifact.payload.requestHash,
      signature:   artifact.signature,
      policyHash:  _auditPolicyHash,
      verificationResult: true,
      tenantId,
      publicKeyId: result.publicKeyId || null,
      provider:    artifact?.payload?.provider || null,
      semantic:    semantic.evidence,
      consentProvenance,
      policyRuleId:      policyDecision?.policyId      ?? null,
      policyRuleVersion: policyDecision?.policyVersion ?? null,
      callerId:          result.callerContext?.callerId ?? null,
    });
    transparencyEnforcementEntriesTotal.inc({ decision: 'ALLOW' });
  } catch (transparencyErr) {
    emit('CRITICAL', 'TRANSPARENCY_APPEND_FAILED', {
      error: transparencyErr.message, requestId: result.requestId, stage: 'ALLOW', code: transparencyErr.code ?? null,
    });
    transparencyEnforcementFailuresTotal.inc({ stage: 'ALLOW' });
    transparencyFailClosedRejectionsTotal.inc({ stage: 'ALLOW' });
    // (verification): provider already executed - keep the reservation (see the audit-failure path above) so an
    // Idempotency-Key retry cannot trigger a second provider call; it expires on its own after the reservation TTL.
    const failure = new Error(`TRANSPARENCY_PERSISTENCE_FAILED: ${transparencyErr.message}`);
    failure.code  = 'TRANSPARENCY_PERSISTENCE_FAILED';
    failure.cause = transparencyErr;
    // this point is AFTER the provider call and after the ALLOW audit entry. The INTENT (with its own
    // transparency leaf) is written BEFORE dispatch, so a transparency outage normally refuses the request before the provider is
    // reached; what remains is a failure in the window between INTENT and DECISION. The client must not read this 503 as "nothing
    // happened": the 503 body now states exactly what was and was not recorded.
    failure.outcome = { providerExecuted: true, auditRecorded: true, transparencyRecorded: false, responseWithheld: true };
    throw failure;
  }

  // registrar.js's non-PG branch (registrar.js:138-145) signs the entry
  // and returns persisted:false without throwing — the MANDATORY/fail-closed
  // comment on the try block above only covers registerEnforcementDecision()
  // itself throwing, not this deliberate degraded-success path. Without this
  // check, a Postgres-disabled deployment silently loses durable,
  // externally-verifiable transparency evidence for every decision while
  // every client-facing response looks identical to a fully-persisted one.
  if (transparencyReg.persisted === false) {
    emit('WARN', 'TRANSPARENCY_PERSISTENCE_DEGRADED', {
      requestId:      result.requestId,
      transparencyId: transparencyReg.transparencyId,
      tenantId,
      message: 'Transparency entry signed but not durably persisted (Postgres disabled) — evidentiary chain is sign-only for this decision.',
    });
  }

  const _allowReceipt = await _receiptFor({ requestId: result.requestId, decision: 'ALLOW', auditEntryHash: auditEntry?.hash ?? null, registration: transparencyReg });

  const finalResult = {
    decision:   'EXECUTE',
    reason:     'ALL_CHECKS_PASSED',
    response:   aiText,
    artifactId: result.requestId,
    keyId:      result.publicKeyId,
    // machine-readable + displayable disclosure.
    aiDisclosure: buildAiDisclosure({ tenantId, provider: artifact?.payload?.provider || null, model: model || null }),
    // (D3): persisted:'pending' — the leaf is durably queued after a PG
    // persistence failure (enforcementBridge.js); its entryHash/leafHash are
    // assigned when the drain worker chains and signs it, and are served by
    // inclusionProofRef. payloadHash commits to the recorded decision now.
    transparency: {
      transparencyId: transparencyReg.transparencyId,
      entryHash:       transparencyReg.entryHash,
      leafHash:        transparencyReg.entryHash ? _merkleLeafHash(transparencyReg.entryHash) : null,
      ...(transparencyReg.persisted === 'pending' ? { payloadHash: transparencyReg.payloadHash } : {}),
      signerKeyId:     transparencyReg.keyId,
      persisted:       transparencyReg.persisted,
      merkleRoot:      null,
      treeSize:        null,
      signedTreeHeadRef: null,
      // R-18: the versioned path is the one on the public allowlist (deploy/public-api/public-operations.json).
      inclusionProofRef: `/v1/transparency/proof/${transparencyReg.transparencyId}`,
    },
    // present only when the leaf is persisted and the receipt could be signed (never null)
    ...(_allowReceipt ? { receipt: _allowReceipt } : {}),
  };

  // API-2: the ONLY point that ever marks an idempotency reservation
  // 'completed' — a durable, successful EXECUTE. `requestId` (the per-HTTP-
  // call correlation id, distinct from `artifactId` above) is deliberately
  // NOT part of the cached body: the route handler always stamps the
  // CURRENT request's own requestId onto both a fresh response and a
  // replayed one, so log/trace correlation for the retry itself is never
  // stale. See API-2-REMEDIATION-REPORT.md §4.
  _commitOf.set(finalResult, { tracker: _commit, outputHash: _outputHashOf(aiText), bytesDelivered: Buffer.byteLength(aiText, 'utf8') });
  const _tIdc = ST.ON ? ST.start() : 0;
  await idempotencyGate.complete(idempotencyCtx, { httpStatus: 200, body: finalResult });
  if (ST.ON) ST.end('S35', _tIdc);

  return finalResult;
}

// ── Streaming enforcement entry point ────────────────────────────────────────
//
// Runs the shared enforcement pipeline (Steps 1–5), then hands off to
// streamResponse() which writes SSE events and the audit record.
//
// A pre-stream enforcement/semantic BLOCK → JSON 200 {decision:'BLOCK',...}.
// Enforcement success → SSE headers sent, stream begins.

// the pre-stream timeout answered 504 while enforcement was still running. Nothing may be executed or
// streamed for this request any more; the decision is still recorded (BLOCK REQUEST_TIMEOUT, no provider call).
async function _abandonStreamAfterTimeout(stage, artifact, enforcement, reqId) {
  const result = enforcement?.validationResult || {};
  emit('WARN', 'AI_CHAT_STREAM_ABANDONED_AFTER_TIMEOUT', { requestId: result.requestId ?? reqId, stage });
  providerExecutionCancelledTotal.inc({ reason: 'PRE_STREAM_TIMEOUT' });
  await _writeAuditBlock({
    artifactId:  result.requestId || null,
    inputHash:   artifact?.payload?.requestHash || null,
    signature:   artifact?.signature            || null,
    requestHash: artifact?.payload?.requestHash || null,
    policyHash:  enforcement?.policyResult?.policyHash || null,
    reason:      'REQUEST_TIMEOUT',
    stage,
    requestId:   result.requestId || reqId || null,
    tenantId:    enforcement?.tenantId || null,
    publicKeyId: result.publicKeyId || null,
  }).catch((err) => emit('ERROR', 'AI_CHAT_STREAM_TIMEOUT_AUDIT_FAILED', { requestId: result.requestId ?? reqId, error: err?.message }));
}

async function _enforceAndStream(artifact, request, reqBody, opts, res, req, reqId) {
  const enforcement = await _runEnforcementPipeline(artifact, request, opts);
  if (opts._signal?.aborted) {
    if (enforcement.decision !== 'BLOCK') await _abandonStreamAfterTimeout('PRE_STREAM_TIMEOUT_AFTER_ENFORCEMENT', artifact, enforcement, reqId);
    return;
  }

  if (enforcement.decision === 'BLOCK') {
    streamingRejectedTotal.inc({ reason: enforcement.reason });
    // pre-stream BLOCK, headers not yet sent — same 200 {decision:'BLOCK'}
    // contract as the non-streaming path (see _blockStatus's own comment).
    // the RATE_LIMITED throttle gets the same 429 + Retry-After as there.
    if (enforcement.reason === 'RATE_LIMITED' || enforcement.reason === 'CLASSIFICATION_BUDGET_EXHAUSTED') { //
      res.set('Retry-After', String(enforcement.retryAfterSeconds ?? 60));
      return res.status(429).json({ decision: 'BLOCK', reason: enforcement.reason, details: {}, requestId: reqId });
    }
    return res.status(blockHttpStatus(enforcement.reason)).json({
      decision: 'BLOCK', reason: enforcement.reason, details: enforcement.details, requestId: reqId,
    });
  }

  const { validationResult: result, policyResult, tenantId, organizationId, consentProvenance, policyDecision } = enforcement;

  const semantic = await _runSemanticCheck(artifact, reqBody, result, policyResult, tenantId);
  if (opts._signal?.aborted) {
    await _abandonStreamAfterTimeout('PRE_STREAM_TIMEOUT_AFTER_SEMANTIC', artifact, enforcement, reqId);
    return;
  }
  if (semantic.blocks) {
    streamingRejectedTotal.inc({ reason: semantic.reason });
    return res.status(blockHttpStatus(semantic.reason)).json({
      decision: 'BLOCK', reason: semantic.reason, details: { semantic: semantic.evidence }, requestId: reqId,
    });
  }

  // DLP on the streaming path: the input is screened exactly as on the non-streaming path; an OUTPUT rule needs the whole answer, which a stream does not have, so
  // while one is configured a stream is refused (fail closed) - the caller can ask without `stream`.
  const dlpPolicySet = enforcement.effectivePolicies();
  if (dlpStage.dlpPolicies(dlpPolicySet, 'output').length > 0) {
    streamingRejectedTotal.inc({ reason: 'DLP_OUTPUT_STREAMING_UNSUPPORTED' });
    return res.status(blockHttpStatus('DLP_OUTPUT_STREAMING_UNSUPPORTED')).json({ decision: 'BLOCK', reason: 'DLP_OUTPUT_STREAMING_UNSUPPORTED', details: {}, requestId: reqId });
  }
  {
    const cin = contentStage.check(dlpStage.textsOf(reqBody), dlpPolicySet, 'input', { model: effectiveModel(reqBody, artifact?.payload?.provider), purpose: reqBody && reqBody.purpose });
    if (cin.blocked) {
      streamingRejectedTotal.inc({ reason: cin.reason });
      return res.status(blockHttpStatus(cin.reason)).json({ decision: 'BLOCK', reason: cin.reason, details: { contentRule: cin.hits.map((h) => ({ ruleId: h.ruleId, items: h.items, score: h.score, threshold: h.threshold })) }, requestId: reqId });
    }
  }
  // an OUTPUT content rule needs the whole answer: refuse the stream like an output DLP rule does
  if (contentStage.rules(dlpPolicySet, 'output').length > 0) {
    streamingRejectedTotal.inc({ reason: 'CONTENT_RULE_STREAMING_UNSUPPORTED' });
    return res.status(blockHttpStatus('CONTENT_RULE_STREAMING_UNSUPPORTED')).json({ decision: 'BLOCK', reason: 'CONTENT_RULE_STREAMING_UNSUPPORTED', details: {}, requestId: reqId });
  }
  const dlpIn = dlpStage.applyToBody(reqBody, dlpPolicySet);
  await dlpStage.recordEvents(dlpIn.events, { requestId: result.requestId, tenantId });
  if (dlpIn.blocked) {
    streamingRejectedTotal.inc({ reason: dlpIn.reason });
    return res.status(blockHttpStatus(dlpIn.reason)).json({ decision: 'BLOCK', reason: dlpIn.reason, details: { dlp: { direction: 'input', rules: [...new Set(dlpIn.events.flatMap((e) => e.rules))] } }, requestId: reqId });
  }

  // policy routing for a stream: same stage, same authorisation, decided before the budget is reserved
  const _streamAuth = _makeFailoverAuthorizer(artifact, result, enforcement, opts);
  const _streamRequested = artifact?.payload?.provider;
  const streamRouted = await routingStage.resolve({
    policies: dlpPolicySet, requestedProvider: _streamRequested, body: dlpIn.body,
    attributes: buildAttributesFor(dlpIn.body, () => dlpPolicySet, _streamRequested) || {},
    context: { userId: result.publicKeyId || null, callerId: result.callerId || null, tenantId, ip: opts._clientIp || null, timestamp: Math.floor(Date.now() / 1000) },
    authorize: (target, info) => _streamAuth(target, info), estimatedTokens: estimateTokens(dlpStage.textsOf(dlpIn.body)),
  });

  // a streaming request is charged with the estimate (the stream reports no usage to settle with); a failure before dispatch returns it
  const streamBudget = await budgetStage.reserve({ policies: dlpPolicySet, store: opts._policyStore, tenantId, callerId: result.callerId, userId: result.publicKeyId,
    model: streamRouted.model || effectiveModel(dlpIn.body, streamRouted.provider), estimatedTokens: estimateTokens(dlpStage.textsOf(dlpIn.body)) });
  if (!streamBudget.allowed) {
    streamingRejectedTotal.inc({ reason: streamBudget.reason });
    return res.status(_blockStatus(streamBudget.reason)).json({ decision: 'BLOCK', reason: streamBudget.reason, details: { budget: { policyId: streamBudget.policyId } }, requestId: reqId });
  }
  let _streamDispatched = false;
  try {
  await streamResponse(res, req, artifact, {
    onDispatch: () => { _streamDispatched = true; },
    requestId:      result.requestId,
    tenantId,
    organizationId,
    policyHash: policyResult.policyHash ?? null,
    // TRACE-2: threaded down to streamEnforcer._writeAuditStreamRecord so
    // the streaming path's audit entry carries the same provenance as the
    // non-streaming path.
    consentProvenance,
    policyDecision,
    semanticEvidence: semantic.evidence,
    publicKeyId: result.publicKeyId || null,
    // same failover authorization as the non-streaming path
    authorizeFailover: _streamAuth,
    routedProvider: streamRouted.provider, routedModel: streamRouted.model, routed: streamRouted.routed,
    // the pre-stream timeout's signal — streamResponse re-checks it before INTENT and before dispatch
    preStreamSignal: opts._signal || null,
  }, dlpIn.body, reqId);
    if (!_streamDispatched) await budgetStage.refund(streamBudget.reservation);   // gate G-03: refused before the provider was called (INTENT failure, timeout, ...): nothing was used
  } catch (streamErr) { if (!_streamDispatched) await budgetStage.refund(streamBudget.reservation); throw streamErr; }   // gate N-02: a stream that was dispatched stays charged even if finishing it threw
}

// API-2: BLOCK reasons produced by the idempotency gate (idempotencyGate.js)
// carry their own specific HTTP semantics distinct from every other
// enforcement BLOCK — a 409/422/503 tells the client something concrete and
// actionable about the RETRY, not "denied". These are a retry-protocol
// signal, not an enforcement decision, and are unaffected.
const IDEMPOTENCY_BLOCK_REASONS = new Set([
  'IDEMPOTENCY_KEY_CONFLICT',
  'IDEMPOTENCY_REQUEST_IN_PROGRESS',
  'IDEMPOTENCY_STORE_UNAVAILABLE',
]);

// server-half remediation: every policy/verification enforcement BLOCK
// (Layers 1/3/5/6c — policy engine, nonce/replay/anomaly, artifact/signature
// verification, semantic content inspection) is a resolved decision value,
// not an authentication failure — /ai/chat has no bearer-token/RBAC layer of
// its own (that's Layer 2, gating /sign and /admin/* only), so there is no
// "genuine auth failure" reason in this route's own space to reserve 403
// for. Matches /verify's own already-live always-200-for-a-pipeline-BLOCK
// contract (verify.js:44-48). The enforcement OUTCOME is unchanged — a
// BLOCK still means the provider is never called; only the HTTP envelope
// changes.
function _blockStatus(reason) {
  // RATE_LIMITED (ai_chat_identity) is a transport throttle, answered 429
  // exactly like the ai_chat_ip limiter ahead of this route. No existing BLOCK
  // reason's status changes here.
  if (reason === 'RATE_LIMITED') return 429;
  // (step 7): the per-tenant classification budget is a throttle too.
  if (reason === 'CLASSIFICATION_BUDGET_EXHAUSTED') return 429;
  // a quota or budget of the tenant's policy set is used up - a throttle, like the two above.
  if (reason === 'BUDGET_EXCEEDED_REQUESTS' || reason === 'BUDGET_EXCEEDED_TOKENS' || reason === 'BUDGET_EXCEEDED_COST') return 429;
  // the control plane could not answer (stale snapshot) — the
  // request was refused for availability, not decided on its merits.
  if (reason === 'CONTROL_PLANE_STALE') return 503;
  // · D7: every other enforcement BLOCK — 200 unless QODIQA_BLOCK_HTTP_MODE=status.
  return IDEMPOTENCY_BLOCK_REASONS.has(reason) ? _idempotencyStatus(reason) : blockHttpStatus(reason);
}

// ── Provider error → HTTP status map ─────────────────────────────────────────

function _providerStatus(code) {
  switch (code) {
    case 'MISSING_PROVIDER':
    case 'PROVIDER_MODEL_NOT_ALLOWED':
    case 'PROVIDER_INVALID_REQUEST':
    case 'PROVIDER_REQUEST_REJECTED':
      return 400;
    case 'PROVIDER_RESPONSE_INVALID':
      return 502;
    case 'PROVIDER_TIMEOUT':
    case 'REQUEST_TIMEOUT':
    case 'PROVIDER_CANCELLED':
      return 504;
    // these were the default 500. A provider whose circuit breaker is OPEN (or that
    // the health tracker has marked degraded) is a dependency that cannot answer right now — 503 + Retry-After (set by
    // _providerRetryAfter below). A provider that is registered but not enabled on this deployment is an availability
    // / configuration condition of the server, not an internal invariant breach — 503 without Retry-After.
    // UNVERIFIED_EXECUTION_ATTEMPT deliberately stays 500 (default): it IS an internal invariant breach.
    case 'PROVIDER_CIRCUIT_OPEN':
    case 'PROVIDER_HEALTH_DEGRADED':
    case 'PROVIDER_NOT_CONFIGURED':
    case 'PROVIDER_UNAVAILABLE':
    case 'PROVIDER_RATE_LIMITED':
    case 'PROVIDER_AUTH_FAILED':
    case 'AUDIT_PERSISTENCE_FAILED':
    case 'TRANSPARENCY_PERSISTENCE_FAILED':
    case 'TRANSPARENCY_JOURNAL_UNAVAILABLE':   //
      return 503;
    // / F6-N2: a value the downstream evidence / recovery stores cannot represent (U+0000, lone surrogate) —
    // refused before any partial audit lifecycle could be persisted
    case 'AUDIT_UNREPRESENTABLE_TEXT':
      return 422;
    default:
      return 500;
  }
}

// Retry-After (seconds) for provider error codes that have a known recovery horizon, else null.
function _providerRetryAfter(code) {
  if (code === 'TRANSPARENCY_JOURNAL_UNAVAILABLE') return 30;   //
  if (code !== 'PROVIDER_CIRCUIT_OPEN' && code !== 'PROVIDER_HEALTH_DEGRADED') return null;
  try {
    const { CIRCUIT_BREAKER_CONFIG } = require('../../../services/providers/circuitBreakerConfig');
    return Math.max(1, Math.ceil(CIRCUIT_BREAKER_CONFIG.cbRecoveryMs / 1000));
  } catch { return 30; }
}

// ── Router factory ─────────────────────────────────────────────────────────────

module.exports = function createAiChatRouter(opts = {}) {
  const router = Router();

  // per-client-IP limit BEFORE the artifact is decoded —
  // the only throttle an unauthenticated caller meets on every alias.
  router.use(ST.wrapMiddleware('S11r', createRateLimitMiddleware('ai_chat_ip', { envelope: 'decision' })));
  // admission control — before content type, schema, artifact decode, signature verification
  // and nonce registration, so a refusal (503 SERVER_OVERLOADED + Retry-After) writes no evidence, never reaches a
  // provider and leaves the artifact's nonce unconsumed. See src/api/admission.js.
  router.use(ST.wrapMiddleware('S11a', require('../admission').get('ai_chat').middleware));

  router.post('/', ST.wrapMiddleware('S12', enforceContentType), requestAuditContextMiddleware, async (req, res) => {
    const reqId = req.requestId ?? null;
    // a reject before the caller is authenticated is
    // counted and sampled, never written to the audit chain / transparency log.
    const _preAuthReject = (reason, stage, details = null) => recordPreAuthReject({
      route: req.baseUrl || null, reason, stage, clientIp: req.clientIp ?? null, requestId: reqId, details,
    });

    // ── 0. Idempotency-Key header validation (API-2, optional header) ────────
    // The header NAME is already case-insensitive (Node lower-cases every
    // incoming header name); only the VALUE is validated here. Absent
    // entirely, or IDEMPOTENCY_ENABLED=false: idempotencyKey stays null and
    // every following step behaves exactly as it did before this
    // remediation — full backward compatibility.
    const _tIk = ST.ON ? ST.start() : 0;
    let idempotencyKey = null;
    if (IDEMPOTENCY_ENABLED) {
      const _idemRaw = req.headers[IDEMPOTENCY_HDR];
      if (_idemRaw !== undefined) {
        const _idemCheck = validateIdempotencyKey(_idemRaw);
        if (!_idemCheck.valid) {
          _preAuthReject(_idemCheck.reason, 'IDEMPOTENCY_KEY_VALIDATION');
          if (ST.ON) ST.end('S13', _tIk); // an early-return reject still closes its stage
          return res.status(_idempotencyStatus(_idemCheck.reason)).json({
            decision: 'BLOCK', reason: _idemCheck.reason, details: {}, requestId: reqId,
          });
        }
        idempotencyKey = _idemCheck.key;
      }
    }
    if (ST.ON) ST.end('S13', _tIk);

    // ── 1. Body guard (Zod schema validation) ────────────────────────────────
    const _tSchema = ST.ON ? ST.start() : 0;
    const _bodyParsed = aiChatBodySchema.safeParse(req.body);
    if (!_bodyParsed.success) {
      let reason = firstQodiqaReason(_bodyParsed.error, 'INVALID_REQUEST_BODY');
      // name the refused fields in the response and in the
      // audit entry's executionContext (no audit-schema change).
      const unsupported = reason === 'UNSUPPORTED_FIELD' ? findUnsupportedFields(req.body) : null;
      // tool traffic over a stream is refused with its own, explicit reason (tool calls arrive with over the non-streaming action API)
      if (unsupported && req.body && req.body.stream === true && unsupported.some((k) => ['tools', 'tool_choice', 'functions', 'function_call'].includes(k))) reason = 'STREAM_TOOLS_UNSUPPORTED';
      // (D1): pre-auth — the refused field names are kept in the
      // sampled PREAUTH_REJECT event and in the 400 body, no longer in the chain.
      _preAuthReject(reason, 'INPUT_GUARD', unsupported ? { unsupportedFields: unsupported } : null);
      if (ST.ON) ST.end('S14', _tSchema);
      return res.status(400).json({ decision: 'BLOCK', reason, details: unsupported ? { fields: unsupported } : {}, requestId: reqId });
    }

    // (D5-b → b1): any other field the route does not read is still
    // accepted (unchanged semantics) but no longer dropped silently.
    const _unknownFields = findUnknownFields(req.body);
    if (_unknownFields.length > 0) {
      emit('WARN', 'AI_CHAT_UNKNOWN_FIELDS_IGNORED', { requestId: reqId, fields: _unknownFields });
    }

    const { prompt } = _bodyParsed.data;
    if (ST.ON) ST.end('S14', _tSchema);

    // ── 2. Artifact decoding ──────────────────────────────────────────────────
    // these three pre-pipeline artifact-decode checks are earlier-depth
    // duplicates of what Layer 5's own INVALID_ARTIFACT already checks inside
    // validateArtifact.js (the same "same substantive failure, two pipeline
    // depths" pattern the matrix already documents for EXPIRED) — classified
    // identically to every other artifact-verification BLOCK: 200, not 403.
    const _tDecode = ST.ON ? ST.start() : 0;
    const rawHeader = req.headers[ARTIFACT_HDR];
    if (typeof rawHeader !== 'string' || !rawHeader) {
      _preAuthReject('MISSING_ARTIFACT', 'ARTIFACT_DECODE');
      if (ST.ON) ST.end('S15', _tDecode);
      return res.status(blockHttpStatus('MISSING_ARTIFACT')).json({ decision: 'BLOCK', reason: 'MISSING_ARTIFACT', details: {}, requestId: reqId });
    }

    if (rawHeader.length > MAX_ARTIFACT_HDR_BYTES) {
      _preAuthReject('ARTIFACT_TOO_LARGE', 'ARTIFACT_DECODE');
      if (ST.ON) ST.end('S15', _tDecode);
      return res.status(413).json({ decision: 'BLOCK', reason: 'ARTIFACT_TOO_LARGE', details: {}, requestId: reqId });
    }

    let artifact;
    try {
      artifact = JSON.parse(Buffer.from(rawHeader, 'base64').toString('utf8'));
    } catch {
      _preAuthReject('ARTIFACT_DECODE_FAILED', 'ARTIFACT_DECODE');
      if (ST.ON) ST.end('S15', _tDecode);
      return res.status(blockHttpStatus('ARTIFACT_DECODE_FAILED')).json({ decision: 'BLOCK', reason: 'ARTIFACT_DECODE_FAILED', details: {}, requestId: reqId });
    }

    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
      _preAuthReject('ARTIFACT_INVALID_TYPE', 'ARTIFACT_DECODE');
      if (ST.ON) ST.end('S15', _tDecode);
      return res.status(blockHttpStatus('ARTIFACT_INVALID_TYPE')).json({ decision: 'BLOCK', reason: 'ARTIFACT_INVALID_TYPE', details: {}, requestId: reqId });
    }
    if (ST.ON) ST.end('S15', _tDecode);

    // ── 3. Enforce and execute — the only path to the AI provider ─────────────
    // CRYPTO-4/REPLAY-5: bind the ACTUAL request path, not a hardcoded
    // literal. This router is mounted at four aliases (/ai/chat,
    // /ai/chat/stream, /v1/ai/chat, /v1/ai/chat/stream — see src/app.js)
    // sharing one router instance; a hardcoded CHAT_PATH made the "path"
    // component of the request-binding hash meaningless (identical for all
    // four regardless of which one actually received the request), so an
    // artifact signed for one alias verified identically at every other one.
    // Both official SDKs (sdk/javascript, sdk/python) always sign and send
    // to the literal '/ai/chat' path for both streaming and non-streaming
    // calls (streaming is toggled via a `stream: true` body flag, never a
    // different URL), so this is a no-op for all SDK-originated traffic — it
    // only changes behavior for a caller that signs for one alias and then
    // sends the request to a different one, which is exactly the gap being
    // closed. req.originalUrl (query string stripped) reflects the true
    // incoming path regardless of Express's mount-relative req.path/baseUrl.
    // the unparsed parts a V2 artifact binds (target with its query, the raw header list, the body bytes); V1 ignores them.
    const request    = { method: req.method, path: req.originalUrl.split('?')[0], body: req.body, target: req.originalUrl, rawHeaders: req.rawHeaders, rawBody: req.rawBody };
    const isStreaming = _bodyParsed.data.stream === true;

    // API-2: idempotent replay requires a durably-stored, complete HTTP
    // response body to hand back byte-for-byte — an SSE stream has no such
    // single "body" to cache and replay. Rather than silently ignoring the
    // header (which would defeat the caller's explicit request for an
    // exactly-once guarantee), this combination is rejected explicitly.
    const _tSic = ST.ON ? ST.start() : 0;
    if (isStreaming && idempotencyKey) {
      _preAuthReject('IDEMPOTENCY_STREAMING_UNSUPPORTED', 'IDEMPOTENCY_KEY_VALIDATION');
      return res.status(_idempotencyStatus('IDEMPOTENCY_STREAMING_UNSUPPORTED')).json({
        decision: 'BLOCK', reason: 'IDEMPOTENCY_STREAMING_UNSUPPORTED', details: {}, requestId: reqId,
      });
    }
    if (ST.ON) { ST.end('S16', _tSic); ST.label('stream', isStreaming); }

    if (isStreaming) {
      // Streaming path: enforcement runs first; if it passes, SSE response begins.
      //
      // AI_CHAT_TIMEOUT_MS bounds only the PRE-STREAM phase
      // (enforcement up to the SSE headers). this timer was never
      // cleared and raced the whole stream, so any legitimate stream longer
      // than AI_CHAT_TIMEOUT_MS was cut by res.end() below and mislabelled.
      // Once headers are out, the stream's own lifetime bounds apply
      // (streamEnforcer.js: STREAM_MAX_DURATION_MS, client-disconnect abort),
      // so the timer becomes a no-op; it is also cleared on completion and on
      // client disconnect so it never outlives the request.
      const _tTo = ST.ON ? ST.start() : 0;
      // aborted when the pre-stream timeout answers 504, so the still-running enforcement stops before the
      // provider (it used to run on and dispatch after the client had been told the request failed).
      const _preStreamAc = new AbortController();
      let _streamTimeoutId = null;
      const _clearStreamTimer = () => { clearTimeout(_streamTimeoutId); _streamTimeoutId = null; };
      // res (not req): on current Node, req emits 'close' as soon as the request
      // BODY has been read, which would clear the timer before enforcement even
      // starts. res 'close' fires on response completion and on connection loss.
      res.once('close', _clearStreamTimer);
      if (ST.ON) ST.end('S17', _tTo);
      try {
        await Promise.race([
          _enforceAndStream(artifact, request, req.body, {
            ...opts,
            _clientIp: req.clientIp ?? null,
            _route:     req.baseUrl || null,
            _requestId: reqId,
            _signal:    _preStreamAc.signal,
          }, res, req, reqId),
          new Promise((_, reject) => {
            _streamTimeoutId = setTimeout(() => {
              _streamTimeoutId = null;
              if (res.headersSent) return; // stream started: its own bounds apply
              _preStreamAc.abort('timeout');
              const err = new Error('REQUEST_TIMEOUT');
              err.code  = 'REQUEST_TIMEOUT';
              reject(err);
            }, AI_CHAT_TIMEOUT_MS);
            if (_streamTimeoutId.unref) _streamTimeoutId.unref();
          }),
        ]);
      } catch (err) {
        // If headers haven't been sent (enforcement failed before SSE started),
        // return a normal JSON error.  If headers were already sent (timeout
        // fired mid-stream), there is nothing we can do about the status code —
        // the stream enforcer will have already sent a stream_cancelled event.
        if (!res.headersSent) {
          const code   = err?.code || 'INTERNAL_ERROR';
          const status = _providerStatus(code);
          const _ra = _providerRetryAfter(code);
          if (_ra !== null) res.set('Retry-After', String(_ra));
          return res.status(status).json({ decision: 'BLOCK', reason: code, details: {}, requestId: reqId });
        }
        // Stream was in progress — ensure response is ended
        try { res.end(); } catch {}
      } finally {
        _clearStreamTimer();
        res.off('close', _clearStreamTimer);
      }
      return;
    }

    // Non-streaming path.
    //
    // Cancellation: an AbortController is created per request and its signal
    // threaded through _enforceAndExecute → _executeAI → executeProviderCall →
    // routeProviderCall → the provider adapter (see services/execution.js and
    // services/providers/router.js). When the timeout fires, ac.abort() is
    // called BEFORE the timeout promise rejects, so by the time the route
    // handler responds 504 to the client, in-flight provider work has already
    // been told to stop — an outbound HTTP request/SDK call in progress is
    // aborted at the network layer rather than left to run to completion
    // after the client has been told the request failed. The timer is
    // unref()'d and always cleared in `finally` so it cannot keep the process
    // alive or fire again after the race has already settled.
    let result;
    const _commitHolder = { tracker: null };   //
    const _tTo = ST.ON ? ST.start() : 0;
    const ac = new AbortController();
    let _timeoutId = null;
    if (ST.ON) ST.end('S17', _tTo);
    try {
      result = await Promise.race([
        _enforceAndExecute(artifact, request, req.body, {
          ...opts,
          _clientIp:        req.clientIp ?? null,
          _route:           req.baseUrl || null,
          _requestId:       reqId,
          _signal:          ac.signal,
          _idempotencyKey:  idempotencyKey,
          _commitHolder,
        }),
        new Promise((_, reject) => {
          _timeoutId = setTimeout(() => {
            ac.abort('timeout');
            const err = new Error('REQUEST_TIMEOUT');
            err.code  = 'REQUEST_TIMEOUT';
            reject(err);
          }, AI_CHAT_TIMEOUT_MS);
          if (_timeoutId.unref) _timeoutId.unref();
        }),
      ]);
    } catch (err) {
      const code   = err?.code || 'INTERNAL_ERROR';
      const status = _providerStatus(code);
      const _ra = _providerRetryAfter(code);
      if (_ra !== null) res.set('Retry-After', String(_ra));
      // an ALLOW DECISION may already be in the chain (timeout or a failure after the audit write): the response is an error with no content
      if (_commitHolder.tracker) _commitHolder.tracker.fail(code === 'REQUEST_TIMEOUT' ? 'TIMEOUT' : 'ERROR');
      return res.status(status).json({ decision: 'BLOCK', reason: code, details: (err && err.outcome) ? { ...err.outcome } : {}, requestId: reqId });
    } finally {
      clearTimeout(_timeoutId);
    }

    // API-2: cache hit — replay the original, durably-completed decision for
    // this (tenant, Idempotency-Key) pair byte-for-byte. `requestId` is the
    // only field re-stamped with THIS call's own value — see the comment on
    // idempotencyGate.complete() above for why.
    if (result.decision === 'REPLAY') {
      const { httpStatus, body } = result.replay;
      res.set(IDEMPOTENCY_HDR, idempotencyKey);
      res.set('Idempotency-Replayed', 'true');
      return res.status(httpStatus).json({ ...body, requestId: reqId });
    }

    if (idempotencyKey) res.set(IDEMPOTENCY_HDR, idempotencyKey);

    if (result.decision === 'BLOCK') {
      if (result.reason === 'RATE_LIMITED' || result.reason === 'CLASSIFICATION_BUDGET_EXHAUSTED') res.set('Retry-After', String(result.retryAfterSeconds ?? 60));
      return res.status(_blockStatus(result.reason)).json({
        decision:  'BLOCK',
        reason:    result.reason,
        details:   result.details || {},
        requestId: reqId,
      });
    }

    res.set(AI_DISCLOSURE_HEADER, 'true'); // (D9-A)
    const _ct = _commitOf.get(result);   // COMMIT = what the connection actually took (settled from the response: finish / close)
    if (_ct) _watchCommitResponse(res, _ct.tracker, _ct);
    return res.status(200).json({
      decision:   'EXECUTE',
      reason:     'ALL_CHECKS_PASSED',
      response:   result.response,
      artifactId: result.artifactId,
      keyId:      result.keyId,
      requestId:  reqId,
      transparency: result.transparency,
      aiDisclosure: result.aiDisclosure,
      ...(result.receipt ? { receipt: result.receipt } : {}),   // absent (never null) unless the leaf is persisted
    });
  });

  // Reject all other HTTP methods explicitly.
  router.use((req, res) => res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null }));

  return router;
};
