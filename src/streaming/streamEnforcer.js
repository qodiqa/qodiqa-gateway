'use strict';

/**
 * Stream Enforcer — SSE streaming lifecycle management.
 *
 * streamResponse() takes over the HTTP response after all 5 enforcement steps
 * have passed.  It:
 *   1. Registers the stream in the active registry
 *   2. Sets SSE response headers and flushes them
 *   3. Emits the stream_started event
 *   4. Asserts the execution invariant (via executeStreamingProviderCall)
 *   5. Forwards chunks to the client as SSE data events
 *   6. Handles all termination causes: completion, client disconnect, timeout, error
 *   7. Writes the audit record with streaming metadata
 *   8. Updates observability metrics
 *   9. Ends the response
 *
 * Security guarantees:
 *   • Authorization always precedes the first streamed token — this module
 *     is called ONLY after all enforcement steps pass.
 *   • The execution invariant is re-asserted in executeStreamingProviderCall
 *     as a second layer of defence.
 *   • Any enforcement failure during streaming terminates the stream
 *     immediately (fail-closed).
 *   • A single audit record is written per streaming session regardless of
 *     how the stream terminates.
 *
 * SSE event format:
 *   Every frame carries a native `event:` field (mirroring the `event`
 *   property still present in the JSON `data:` payload, kept for one
 *   deprecation cycle so existing SDK/client parsers that only read the
 *   JSON payload keep working unmodified — this is a purely additive
 *   change, not a breaking one) and a native `id:` field
 *   (`<streamId>:<sequence>`) that identifies each frame. The stream is NOT
 *   resumable: no `Last-Event-ID` is honoured and an artifact cannot be
 * reused to reconnect (API-12; corrected this comment,
 *   which previously claimed EventSource reconnection was meaningful). The
 *   very first frame also carries a `retry:` hint.
 *
 *   stream_started    — emitted once before any chunks; signals authorization complete
 * chunk_forwarded — one event per RELEASED text segment (this is
 *                        no longer necessarily one event per provider delta —
 *                        see outputSemanticWindow.js's header for why)
 *   stream_completed  — final event on normal completion
 *   stream_cancelled  — final event on any non-normal termination
 *   [DONE]            — raw SSE termination sentinel (always last; data-only,
 *                        no native `event:` field — OpenAI-style convention,
 *                        not the defect this remediation addresses)
 */

'use strict';

const { buildAiDisclosure, HEADER: AI_DISCLOSURE_HEADER } = require('../core/compliance/aiDisclosure'); // (D9-A)
const crypto                  = require('crypto');
const streamRegistry          = require('./streamRegistry');
const { executeStreamingProviderCall } = require('../../services/execution.stream');
const { mintExecutionToken }           = require('../../services/executionInvariantToken');
const { appendMandatory: _auditAppendMandatoryRaw } = require('../core/audit/audit-log');
const { createCommitTracker: _createCommitTracker, watchStreamEnd: _watchStreamEnd, completionStatusForStream: _completionStatusForStream } = require('../core/audit/commitEntry');   //
// every mandatory append's outcome feeds the /ready audit-persistence latch (src/api/auditPersistenceHealth.js).
const _auditAppendMandatory = require('../api/auditPersistenceHealth').track(_auditAppendMandatoryRaw);
const { createOutputHasher, EMPTY_OUTPUT_HASH, unrepresentableTextPath } = require('../core/audit/entryBuilder');   // v7 R-5; F6-N2
const { writeLifecycleEntry }          = require('../core/audit/lifecycleEntry');            // v7 R-8..R-11
const _lifecycleReconciler = require('../core/audit/lifecycleReconciler');   //
const { currentContext: _tracingContext }        = require('../observability/tracing/context');
const { emit }                         = require('../../services/logger');
const metrics                          = require('../observability/metrics');
const { registerEnforcementDecision }  = require('../core/transparency/enforcementBridge');
const { createOutputSemanticWindow }   = require('./outputSemanticWindow');
// stage timer (bench only; see src/observability/stageTimer.js) — the original functions when off.
const ST = require('../observability/stageTimer');
const _mintExecutionTokenT = ST.timeSync('S27', mintExecutionToken);
const _auditAppendMandatoryT = ST.timeAsync('S33', _auditAppendMandatory);
const _registerEnforcementDecisionT = ST.timeAsync('S34', registerEnforcementDecision);

// AbortSignal reason → terminal terminationReason for a cancelled stream. adds SERVER_SHUTDOWN (graceful
// shutdown cancels still-open streams so their closing DECISION is recorded before the force-exit timer).
function _cancelTerminationReason(reason) {
  if (reason === 'stream_timeout') return 'STREAM_TIMEOUT';
  if (reason === 'server_shutdown') return 'SERVER_SHUTDOWN';
  return 'CLIENT_DISCONNECT';
}
const { resolveDefaultModel }          = require('../../services/providers/config');

// Maximum duration for a single streaming session.
// After this interval the stream is terminated fail-closed with STREAM_TIMEOUT.
// Default: 5 minutes.  Set STREAM_MAX_DURATION_MS to override.
const STREAM_MAX_DURATION_MS = (() => {
  const v = parseInt(process.env.STREAM_MAX_DURATION_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 300_000;
})();

// ── SSE helpers ───────────────────────────────────────────────────────────────

// API-10 remediation: writes a native SSE frame — `event:`/`id:`/
// `retry:` fields ahead of `data:` — instead of only ever emitting a bare
// `data:` line with the event name buried inside the JSON payload. Additive:
// the JSON payload keeps its `event` property unchanged, so any client that
// only reads `data:` (as both bundled SDKs do today) is unaffected.
function _writeSSE(res, data, { id, retry } = {}) {
  try {
    const isString = typeof data === 'string';
    const payload   = isString ? data : JSON.stringify(data);
    let frame = '';
    if (retry !== undefined && retry !== null) frame += `retry: ${retry}\n`;
    if (!isString && data && typeof data.event === 'string') frame += `event: ${data.event}\n`;
    if (id !== undefined && id !== null) frame += `id: ${id}\n`;
    frame += `data: ${payload}\n\n`;
    res.write(frame);
  } catch { /* ignore write errors after client disconnect */ }
}

// ── Audit helpers ─────────────────────────────────────────────────────────────

// By the time this runs, every chunk (and the terminating SSE event) has
// already been sent to the client — there is no HTTP response left to
// withhold, so unlike the non-streaming path this cannot fail closed by
// rejecting the request. What it CAN and MUST do is retry transient
// failures (via appendMandatory) and, if still unrecorded, escalate to
// CRITICAL rather than a single easy-to-miss ERROR line, since a streamed
// execution with no audit entry is a real evidence gap requiring operator
// follow-up (see docs/security/SECURITY_GUIDE.md "Audit write failures").
async function _writeAuditStreamRecordOnce({
  requestId, artifact, tenantId, organizationId, policyHash,
  provider, model, streamId,
  startTime, chunkCount, byteCount,
  status, terminationReason, semanticEvidence, publicKeyId,
  consentProvenance = null, policyDecision = null,
  // { requestedProvider, executingProvider, failover }
  routing = null,
  // output-side evidence (see src/streaming/outputSemanticWindow.js) —
  // additive; present on both normal completion and a semantic-blocked
  // termination, mirroring the non-streaming path's `outputSemantic` field.
  outputSemanticEvidence = null,
  // v7 (R-5): hash of the exact content released to the client (createOutputHasher over every chunk_forwarded
  // delta, in order); EMPTY_OUTPUT_HASH when nothing was delivered.
  outputHash = EMPTY_OUTPUT_HASH,
  // v7 (R-7): the provider that actually executed; null when no provider call was made.
  executingProvider = null,
  _endTime = null,   // set by _writeAuditStreamRecord so a retried record keeps the first attempt's end time
}) {
  // / F6-N2: this DECISION closes a lifecycle whose INTENT / STREAM_OPENED are already in the chain, so it must
  // always be recordable. Its only provider-derived strings are the provider's error code (terminationReason) and the
  // routing report (failover cause). If one holds U+0000 or a lone surrogate — which evidence_chain_records / the
  // recovery queue cannot represent — they are left out and the record states it: terminationReason
  // AUDIT_UNREPRESENTABLE_TEXT, routing null. No replacement, no normalization, never an open lifecycle.
  if (unrepresentableTextPath({ terminationReason, routing })) {
    emit('WARN', 'AUDIT_UNREPRESENTABLE_PROVIDER_VALUE', { requestId, streamId, field: unrepresentableTextPath({ terminationReason, routing }) });
    terminationReason = 'AUDIT_UNREPRESENTABLE_TEXT';
    routing = null;
  }
  // derived straight off the already-signature-verified `artifact`
  // this function receives — no new param needed, mirrors how requestHash/
  // policyHash below are already read directly off artifact.payload.
  const callerContext = (artifact?.payload?.callerContext && typeof artifact.payload.callerContext === 'object')
    ? artifact.payload.callerContext
    : null;

  const _auditPolicyHash = policyHash || artifact?.payload?.policyHash;
  if (typeof artifact?.payload?.requestHash !== 'string' || !_auditPolicyHash) {
    emit('CRITICAL', 'STREAM_AUDIT_FAILED', {
      streamId, requestId,
      error: 'missing requestHash or policyHash — cannot construct mandatory audit entry',
    });
    return { recorded: false, failed: false, unrecordable: true };
  }

  const endTime    = Number.isFinite(_endTime) ? _endTime : Date.now();   // a retry records the stream's real end
  const durationMs = endTime - startTime;
  const decision   = status === 'completed' ? 'ALLOW' : 'BLOCK';

  let auditEntryHash = null;
  let skipTransparency = false;
  let recorded = false; let failed = false;   //
  try {
    const entry = await _auditAppendMandatoryT({
      artifactId:         requestId,
      inputHash:          artifact.payload.requestHash,
      decision,
      signature:          artifact.signature,
      requestHash:        artifact.payload.requestHash,
      policyHash:         _auditPolicyHash,
      verificationResult: decision === 'ALLOW',
      tenantId,
      organizationId:     organizationId || undefined,
      publicKeyId:        publicKeyId || null,
      // correlation identifiers, not hash-protected — see
      // entryBuilder.js normalizeFields().
      requestId,
      traceId: _tracingContext()?.traceId ?? null,
      // TRACE-2: same hash-protected provenance fields as the non-streaming
      // audit write in aiChat.js — resolved once in _runEnforcementPipeline
      // and threaded down through streamResponse()'s authResult.
      consentProvenance,
      policyDecision,
      // hash-protected on schemaVersion 4 entries.
      callerContext,
      // hash-protected on schemaVersion 5 entries — same values as
      // the (unprotected, legacy) executionContext copies below.
      provider,
      model,
      // hash-protected on schemaVersion 6 entries — same values as
      // the (unprotected, legacy) executionContext copies below, mirroring
      // aiChat.js's identical promotion. `reason` carries terminationReason
      // only for a BLOCK (aborted stream); an ALLOW (completed stream) has
      // no BLOCK-style reason, matching aiChat.js's own ALLOW-path contract.
      stage:      'PROVIDER_EXECUTION',
      reason:     decision === 'BLOCK' ? (terminationReason || null) : null,
      semantic:   semanticEvidence || null,
      tokenUsage: null,
      responseId: streamId,
      // v7 (R-3/R-5/R-7): the stream's DECISION entry.
      entryType: 'DECISION',
      outputHash,
      executingProvider,
      executionContext: {
        stage:            'PROVIDER_EXECUTION',
        provider,
        requestedProvider: routing ? routing.requestedProvider : provider,
        executingProvider: routing ? routing.executingProvider : provider,
        failover:          routing ? routing.failover : null,
        ...(routing && routing.routed ? { routed: routing.routed } : {}),   //
        responseId:       streamId,
        model,
        tokenUsage:       null,
        streamId,
        startTimestamp:   startTime,
        endTimestamp:     endTime,
        durationMs,
        chunkCount,
        byteCount,
        completionStatus: status === 'completed' ? 'COMPLETE' : status.toUpperCase(),
        terminationReason,
        semantic: semanticEvidence || null,
        outputSemantic: outputSemanticEvidence || null,
        publicKeyId: publicKeyId || null,
      },
    }, { stage: 'STREAM' });
    auditEntryHash = entry?.hash ?? null;
    // policyHash/auditEntryHash embedded here so the row this event
    // produces in platform_audit_events is a full join surface into the
    // audit chain — mirrors AUDIT_EXECUTION_RECORDED/AUDIT_BLOCK_RECORDED in
    // aiChat.js.
    emit('INFO', 'STREAM_AUDIT_RECORDED', {
      streamId, requestId, provider, decision,
      chunkCount, byteCount, durationMs, terminationReason,
      policyHash: _auditPolicyHash, auditEntryHash,
    });
    recorded = true;
  } catch (auditErr) {
    const alreadyIn = typeof auditErr.message === 'string' &&
                      auditErr.message.startsWith('already_executed');
    if (alreadyIn) {
      emit('INFO', 'STREAM_AUDIT_RECORDED', { streamId, requestId, note: 'already_in_chain' });
      skipTransparency = true;
    } else {
      emit('CRITICAL', 'STREAM_AUDIT_FAILED', {
        streamId, requestId, error: auditErr.message, code: auditErr.code ?? null,
      });
      failed = true;
    }
  }
  if (skipTransparency) return { recorded: false, duplicate: true, failed: false };

  // ── Transparency log write ─────────────────────────────────────────
  //
  // By this point every chunk has already been streamed to the client, so —
  // exactly like the audit write above — there is no response left to
  // withhold on failure. Escalate to CRITICAL rather than throwing.
  try {
    await _registerEnforcementDecisionT({
      bestEffort: true,   // the stream was already delivered; an unrecordable leaf is buffered, never dropped silently
      requestId,
      decision,
      reason:      terminationReason,
      stage:       'STREAM',
      auditEntryHash,
      inputHash:   artifact.payload.requestHash,
      signature:   artifact.signature,
      policyHash:  _auditPolicyHash,
      verificationResult: decision === 'ALLOW',
      tenantId,
      publicKeyId,
      provider,
      semantic:    semanticEvidence || null,
      consentProvenance,
      policyRuleId:      policyDecision?.policyId      ?? null,
      policyRuleVersion: policyDecision?.policyVersion ?? null,
      policyRuleHash:    policyDecision?.policyRuleHash ?? null,
      callerId:          callerContext?.callerId ?? null,
    });
    metrics.transparencyEnforcementEntriesTotal.inc({ decision });
  } catch (transparencyErr) {
    metrics.transparencyEnforcementFailuresTotal.inc({ stage: 'STREAM' });
    emit('CRITICAL', 'TRANSPARENCY_APPEND_FAILED', {
      streamId, requestId, stage: 'STREAM',
      error: transparencyErr.message, code: transparencyErr.code ?? null,
    });
  }
  return { recorded, failed, auditEntryHash };
}

// every stream record closes a lifecycle (INTENT / STREAM_OPENED are already in
// the chain). Content may already have reached the client, so a record that could not be written is retried AS IS —
// never replaced by a "nothing delivered" record — until the audit store accepts it (lifecycleReconciler).
async function _writeAuditStreamRecord(args0) {
  const args = { ...args0, _endTime: Date.now() };
  const r = await _writeAuditStreamRecordOnce(args);
  if (r && r.failed && !args._reconcile && args.requestId) {
    _lifecycleReconciler.registerOpenLifecycle(args.requestId, { kind: 'stream', retry: () => _writeAuditStreamRecordOnce({ ...args, _reconcile: true }) });
  }
  return r;
}

// ── Core streaming lifecycle ──────────────────────────────────────────────────

/**
 * Execute and stream a provider response over SSE.
 *
 * This function takes full control of the HTTP response.  It MUST only be
 * called after all 5 enforcement steps have passed and the caller has
 * verified that res.headersSent === false.
 *
 * @param {object}      res        — Express response object
 * @param {object}      req        — Express request (for disconnect detection)
 * @param {object}      artifact   — Decoded, signature-verified artifact
 * @param {object}      authResult — { requestId, tenantId, policyHash, organizationId, semanticEvidence,
 *   publicKeyId, consentProvenance, policyDecision } — the last two (TRACE-2) are threaded straight
 *   through to the mandatory audit write, unchanged.
 * @param {object}      reqBody    — Parsed request body: { prompt, model }
 * @param {string|null} reqId      — External request ID for correlation headers
 */
async function streamResponse(res, req, artifact, authResult, reqBody, reqId) {
  const { requestId, tenantId, policyHash, organizationId = null, semanticEvidence = null, publicKeyId = null,
          consentProvenance = null, policyDecision = null, authorizeFailover = null, preStreamSignal = null, onDispatch = null,
          routedProvider = null, routedModel = null, routed = null } = authResult;
  const provider = artifact?.payload?.provider;

  // the route's pre-stream timeout already answered 504 — open nothing, call nothing. (The route records the
  // BLOCK REQUEST_TIMEOUT decision itself when it abandons before this point.)
  if (preStreamSignal?.aborted || res.headersSent) {
    emit('WARN', 'STREAM_ABANDONED_BEFORE_OPEN', { requestId, reason: preStreamSignal?.aborted ? 'PRE_STREAM_TIMEOUT' : 'HEADERS_ALREADY_SENT' });
    return;
  }

  // ── Provider field guard ──────────────────────────────────────────────────────
  if (typeof provider !== 'string' || !provider) {
    // We have not yet sent headers, so a JSON error is still possible
    if (!res.headersSent) {
      res.status(400).json({
        decision: 'BLOCK', reason: 'MISSING_PROVIDER', details: {}, requestId: reqId,
      });
    }
    return;
  }

  // resolveDefaultModel() is per-provider and shared with the
  // non-streaming path (src/api/routes/aiChat.js) so the two always agree —
  // see that file's own comment at the equivalent line for the full
  // rationale. A provider with no configured default resolves to null here,
  // which the existing model-allowlist check already rejects as
  // PROVIDER_MODEL_NOT_ALLOWED, exactly like any other invalid model.
  // policy routing (decided in the route, before the budget) may have chosen another provider/model; `provider` stays the artifact's (the REQUESTED one in the evidence), `execProvider` serves
  const execProvider = (typeof routedProvider === 'string' && routedProvider) ? routedProvider : provider;
  const model     = (typeof routedModel === 'string' && routedModel) ? routedModel : (typeof reqBody.model === 'string' && reqBody.model ? reqBody.model : resolveDefaultModel(execProvider));
  const startTime = Date.now();

  // ── Register stream ───────────────────────────────────────────────────────────
  const streamId = streamRegistry.createStream({
    requestId, artifactId: requestId, provider: execProvider, model, tenantId, organizationId,
  });

  // ── v7 (R-8/R-10/R-11): INTENT + STREAM_OPENED, fail-closed, before any byte ─────────────────────────────
  // INTENT is written immediately before provider execution and STREAM_OPENED before the first streamed byte. Both
  // precede res.flushHeaders() below (the SSE headers are the stream's first bytes and are flushed before the provider
  // call starts), each with its own transparency leaf. If either cannot be recorded, no header and no byte is sent and
  // the provider is never called: JSON 503 through the existing error contract, and a best-effort BLOCK DECISION
  // (no provider executed) closes whatever lifecycle entry did reach the chain.
  {
    const lifecycleFields = {
      requestId,
      inputHash:         artifact.payload.requestHash,
      signature:         artifact.signature,
      requestHash:       artifact.payload.requestHash,
      policyHash:        policyHash || artifact?.payload?.policyHash || null,
      tenantId,
      organizationId,
      publicKeyId,
      traceId:           _tracingContext()?.traceId ?? null,
      consentProvenance,
      policyDecision,
      callerContext:     (artifact?.payload?.callerContext && typeof artifact.payload.callerContext === 'object') ? artifact.payload.callerContext : null,
      provider,
      model,
      semantic:          semanticEvidence || null,
      executingProvider: execProvider,
    };
    const lifecycleDeps = {
      append:   _auditAppendMandatoryT,
      register: _registerEnforcementDecisionT,
      onDegraded: (reg) => emit('WARN', 'TRANSPARENCY_PERSISTENCE_DEGRADED', {
        requestId, transparencyId: reg.transparencyId, tenantId,
        message: 'Transparency entry signed but not durably persisted (Postgres disabled) — evidentiary chain is sign-only for this decision.',
      }),
    };
    try {
      await writeLifecycleEntry('INTENT', {
        ...lifecycleFields,
        executionContext: { stage: 'PROVIDER_DISPATCH', provider, model, streamId, semantic: semanticEvidence || null, publicKeyId: publicKeyId || null },
      }, lifecycleDeps);
      await writeLifecycleEntry('STREAM_OPENED', {
        ...lifecycleFields,
        responseId:       streamId,
        executionContext: { stage: 'STREAM_OPENED', provider, model, streamId, publicKeyId: publicKeyId || null },
      }, lifecycleDeps);
    } catch (lifecycleErr) {
      const code = lifecycleErr?.code || 'AUDIT_PERSISTENCE_FAILED';
      if (code === 'AUDIT_UNREPRESENTABLE_TEXT') {
        // / F6-N2: a request-derived value the downstream raw stores cannot represent — the INTENT append was
        // refused before anything was persisted, nothing is open, so nothing is closed: 422, no header, no byte.
        emit('WARN', 'AUDIT_UNREPRESENTABLE_TEXT_REFUSED', { streamId, requestId, stage: 'LIFECYCLE', field: lifecycleErr.field ?? null });
        streamRegistry.finalizeStream(streamId, { terminationReason: code, status: 'error' });
        if (!res.headersSent) res.status(422).json({ decision: 'BLOCK', reason: code, details: {}, requestId: reqId });
        return;
      }
      emit('CRITICAL', 'STREAM_AUDIT_FAILED', { streamId, requestId, stage: 'LIFECYCLE', error: lifecycleErr?.message ?? String(lifecycleErr), code });
      metrics.auditFailClosedRejectionsTotal.inc({ stage: 'STREAM_LIFECYCLE' });
      streamRegistry.finalizeStream(streamId, { terminationReason: code, status: 'error' });
      if (!res.headersSent) {
        if (code === 'TRANSPARENCY_JOURNAL_UNAVAILABLE') res.set('Retry-After', '30');   // same as the non-streamed refusal
        res.status(503).json({ decision: 'BLOCK', reason: code, details: {}, requestId: reqId });
      }
      await _writeAuditStreamRecord({
        requestId, artifact, tenantId, organizationId, policyHash,
        provider, model, streamId, startTime,
        chunkCount: 0, byteCount: 0,
        status: 'error', terminationReason: code, semanticEvidence, publicKeyId,
        consentProvenance, policyDecision, outputSemanticEvidence: null,
        routing: null, outputHash: EMPTY_OUTPUT_HASH, executingProvider: null,
      });
      return;
    }
  }

  // the pre-stream timeout fired while INTENT/STREAM_OPENED were being written. The lifecycle is open but no
  // byte was sent and no provider was called: close it with an error record, exactly like a lifecycle failure.
  if (preStreamSignal?.aborted || res.headersSent) {
    emit('WARN', 'STREAM_ABANDONED_BEFORE_DISPATCH', { streamId, requestId });
    streamRegistry.finalizeStream(streamId, { terminationReason: 'REQUEST_TIMEOUT', status: 'error' });
    await _writeAuditStreamRecord({
      requestId, artifact, tenantId, organizationId, policyHash,
      provider, model, streamId, startTime,
      chunkCount: 0, byteCount: 0,
      status: 'error', terminationReason: 'REQUEST_TIMEOUT', semanticEvidence, publicKeyId,
      consentProvenance, policyDecision, outputSemanticEvidence: null,
      routing: null, outputHash: EMPTY_OUTPUT_HASH, executingProvider: null,
    });
    return;
  }

  // ── Cancellation: AbortController shared by timeout and client disconnect ─────
  const ac = new AbortController();

  let _timeoutId = null;
  if (STREAM_MAX_DURATION_MS > 0) {
    _timeoutId = setTimeout(() => {
      if (!ac.signal.aborted) ac.abort('stream_timeout');
    }, STREAM_MAX_DURATION_MS);
    if (_timeoutId.unref) _timeoutId.unref();
  }

  let _clientDisconnected = false;

  // listen on the RESPONSE, not the request. On current Node, IncomingMessage
  // 'close' fires as soon as the request BODY has been consumed — which express.json() did long before this point —
  // so the old req.on('close') listener never fired again and a client that went away mid-stream did not cancel the
  // provider: the stream ran to completion and was recorded as a 'completed' ALLOW for content nobody received (same
  // trap aiChat.js's pre-stream timer documents). res 'close' fires on connection loss and also after a normal
  // res.end(); writableEnded tells the two apart, so only an abnormal close aborts.
  function _onClientClose() {
    if (res.writableEnded) return;
    _clientDisconnected = true;
    if (!ac.signal.aborted) ac.abort('client_disconnect');
  }
  if (typeof res.on === 'function') res.on('close', _onClientClose);
  // The client may already have gone while INTENT/STREAM_OPENED were being written: 'close' will not fire again.
  if (res.destroyed === true) _onClientClose();
  // shutdown can cancel this stream (streamRegistry.cancelAll) so its closing DECISION is written before exit.
  streamRegistry.setCanceller(streamId, () => { if (!ac.signal.aborted) ac.abort('server_shutdown'); });

  // ── SSE response headers ──────────────────────────────────────────────────────
  res.setHeader('Content-Type',      'text/event-stream');
  res.setHeader('Cache-Control',     'no-cache, no-transform');
  res.setHeader('Connection',        'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.setHeader(AI_DISCLOSURE_HEADER, 'true'); // (D9-A)
  if (reqId) res.setHeader('X-Request-Id', reqId);
  res.flushHeaders();
  if (ST.ON) ST.mark('sse_headers_flushed');

  // ── Metrics: increment active streams ────────────────────────────────────────
  metrics.streamingActiveStreams.inc({});

  // ── Build verified execution context ─────────────────────────────────────────
  // identical binding to the non-streaming path (src/api/routes/
  // aiChat.js._executeAI) — mint a short-lived HMAC token over
  // requestHash+policyHash so execution-guard.js can cryptographically
  // verify this context, not just its shape.
  const _resolvedPolicyHash = policyHash || null;
  const { issuedAt, signature } = _mintExecutionTokenT({
    requestHash: artifact.payload.requestHash,
    policyHash:  _resolvedPolicyHash,
  });

  const verifiedCtx = Object.freeze({
    verified:    true,
    requestHash: artifact.payload.requestHash,
    policyHash:  _resolvedPolicyHash,
    artifactId:  requestId,
    tenantId,
    issuedAt,
    signature,
  });

  // failover authorization + the routing outcome for the audit record.
  let _routing = routed ? { requestedProvider: provider, executingProvider: execProvider, failover: null, routed } : null;
  const traceMeta    = { policyHash: _resolvedPolicyHash, authorizeFailover, onRouting: (r) => { _routing = routed ? { ...r, requestedProvider: provider, routed } : r; } };
  const providerBody = {
    model,
    messages: require('../validation/conversation').normalizeConversation(reqBody),   // the single prompt, or the caller's conversation
    // the signed output cap of a V2 artifact; absent for V1
    ...(require('../validation/protocolV2').artifactMaxTokens(artifact) ? { maxTokens: require('../validation/protocolV2').artifactMaxTokens(artifact) } : {}),
  };

  // API-10 remediation: monotonically increasing native SSE `id:` per frame,
  // scoped to this stream — meaningful for EventSource's Last-Event-ID
  // reconnection semantics.
  let _frameSeq = 0;
  const _nextFrameId = () => `${streamId}:${_frameSeq++}`;

  // ── Emit stream_started ───────────────────────────────────────────────────────
  _writeSSE(res, {
    event:      'stream_started',
    streamId,
    requestId,
    artifactId: requestId,
    provider: execProvider,
    model,
    // same disclosure as the JSON EXECUTE response.
    aiDisclosure: buildAiDisclosure({ tenantId, provider: execProvider, model }),
  }, { id: _nextFrameId(), retry: 3000 });

  emit('INFO', 'STREAM_STARTED', { streamId, requestId, provider, model, tenantId });

  // ── Streaming state ───────────────────────────────────────────────────────────
  let terminationReason     = 'COMPLETE';
  let status                = 'completed';
  let chunkIndex             = 0;
  let firstChunkTime        = null;
  let outputSemanticEvidence = null;

  // output-side semantic classification — classifies every chunk
  // BEFORE it is forwarded (see src/streaming/outputSemanticWindow.js for the
  // full design). Reuses the identical engine the non-streaming path uses.
  const outputWindow = createOutputSemanticWindow({ requestId, tenantId, provider: execProvider });

  // S30 for a stream = the provider loop minus the output checks (S32) and minus any
  // S29/S30 the router recorded inside it (non-native providers); SSE frame writes stay in S30.
  const _tLoop = ST.ON ? ST.start() : 0;
  const _before = ST.ON ? { s29: ST.get('S29'), s30: ST.get('S30'), s32: ST.get('S32') } : null;
  const _delivered = createOutputHasher();   // v7 R-5: exactly the content released to the client
  // the stream's COMMIT (what was actually delivered); created here, inside the request's async context, so it captures issuedAt/protocolVersion
  const _commit = _createCommitTracker({ requestId, signature: artifact.signature, tenantId, organizationId: organizationId || undefined });
  let _dispatched = false;
  try {
    _dispatched = true;
    if (typeof onDispatch === 'function') onDispatch();      // gate G-03: lets the route tell a stream that was dispatched from one that never reached the provider
    const chunkGen = executeStreamingProviderCall(
      execProvider, providerBody, verifiedCtx, traceMeta, ac.signal,
    );

    for await (const chunk of chunkGen) {
      // Client disconnect or timeout check on every chunk
      if (ac.signal.aborted) {
        const reason      = ac.signal.reason;
        terminationReason = _cancelTerminationReason(reason);
        status            = 'cancelled';
        // (S5): a cancellation detected here means any content this
        // window is still holding must never be released — discard it
        // explicitly rather than relying on the loop simply not writing it.
        outputWindow.discardPending();
        break;
      }

      const delta = chunk.delta;

      // Provider-side time-to-first-byte — measured at RECEIPT, unchanged
      // meaning from. This is deliberately NOT the same
      // instant as the client's time-to-first-byte any more (see below):
      // may hold this delta in the gate's pending buffer for one or
      // more further chunks before anything is released to the client.
      if (firstChunkTime === null) {
        firstChunkTime = Date.now();
        metrics.streamingProviderLatencyMs.observe({}, firstChunkTime - startTime);
      }

      // ── Output-side semantic gate — check-then-release ─────────
      // evaluate() returns `released`: the (possibly empty) text that has
      // just passed its check and may now be forwarded. It is NEVER the raw
      // `delta` unconditionally —
      const _tWin = ST.ON ? ST.start() : 0;
      const verdict = await outputWindow.evaluate(delta);
      if (ST.ON) ST.end('S32', _tWin);
      outputSemanticEvidence = verdict.evidence || outputSemanticEvidence;
      if (verdict.blocks) {
        // (step 7): the output classification cap reports itself; every other output block is unchanged.
        terminationReason = verdict.reason === 'OUTPUT_TOO_LARGE' ? 'OUTPUT_TOO_LARGE' : 'SEMANTIC_OUTPUT_BLOCKED';
        status            = 'blocked';
        metrics.streamingSemanticBlockedTotal.inc({ reason: verdict.reason || 'UNKNOWN' });
        emit('WARN', 'STREAM_SEMANTIC_OUTPUT_BLOCKED', {
          streamId, requestId, provider, reason: verdict.reason || null,
        });
        if (!ac.signal.aborted) ac.abort('semantic_output_block');
        break;
      }

      // (S5): re-check the abort signal immediately before writing —
      // a client disconnect/timeout that raced with the just-awaited check
      // must not cause a release. The buffer was already cleared inside
      // evaluate() (its content is now in `verdict.released`, a local
      // variable) — discard it explicitly rather than write it.
      if (verdict.released.length === 0 || ac.signal.aborted) {
        if (ac.signal.aborted) {
          const reason      = ac.signal.reason;
          terminationReason = _cancelTerminationReason(reason);
          status            = 'cancelled';
          break;
        }
        // Held, not released yet — nothing to write this iteration. Continue
        // consuming the provider so the buffer can keep filling.
        continue;
      }

      const byteLen = Buffer.byteLength(verdict.released, 'utf8');

      streamRegistry.recordChunk(streamId, byteLen);
      metrics.streamingChunksTotal.inc({});
      metrics.streamingBytesTotal.inc({}, byteLen);

      _writeSSE(res, { event: 'chunk_forwarded', delta: verdict.released, index: chunkIndex }, { id: _nextFrameId() });
      _delivered.update(verdict.released);
      if (ST.ON) ST.mark('first_content_forwarded');
      chunkIndex++;
    }

    // Catch abort that fires between chunk yields
    if (ac.signal.aborted && status !== 'cancelled' && status !== 'blocked') {
      const reason      = ac.signal.reason;
      terminationReason = _cancelTerminationReason(reason);
      status            = 'cancelled';
      outputWindow.discardPending();
    }

    // ── mandatory end-of-stream embedding recheck NOW GATES release ──
    // Only meaningful if the stream is still on track to report success — an
    // already cancelled/blocked stream has already discarded its buffer.
    // Unlike, this can (and, for the 152/378-char baseline
    // shape, does) prevent content from EVER reaching the client — see
    // outputSemanticWindow.js's evaluateFinal() header comment for the two
    // cases (gates a still-pending buffer vs. audit-only correction for
    // already-released content, the latter being the one remaining case
    // where SSE's lack of a recall mechanism still applies).
    if (status === 'completed') {
      const _tFin = ST.ON ? ST.start() : 0;
      const finalVerdict = await outputWindow.evaluateFinal();
      if (ST.ON) ST.end('S32', _tFin);
      outputSemanticEvidence = finalVerdict.evidence || outputSemanticEvidence;
      if (finalVerdict.blocks) {
        terminationReason = 'SEMANTIC_OUTPUT_BLOCKED_FINAL';
        status            = 'blocked';
        metrics.streamingSemanticBlockedFinalTotal.inc({ reason: finalVerdict.reason || 'UNKNOWN' });
        emit('WARN', 'STREAM_SEMANTIC_OUTPUT_BLOCKED_FINAL', {
          streamId, requestId, provider, reason: finalVerdict.reason || null,
        });
      } else if (finalVerdict.released.length > 0 && !ac.signal.aborted) {
        // release whatever was still held (the sub-cadence tail —
        // this is exactly the 152/378-char baseline content, now released
        // ONLY after having passed this check, never before).
        const byteLen = Buffer.byteLength(finalVerdict.released, 'utf8');
        streamRegistry.recordChunk(streamId, byteLen);
        metrics.streamingChunksTotal.inc({});
        metrics.streamingBytesTotal.inc({}, byteLen);
        _writeSSE(res, { event: 'chunk_forwarded', delta: finalVerdict.released, index: chunkIndex }, { id: _nextFrameId() });
        _delivered.update(finalVerdict.released);
        if (ST.ON) ST.mark('first_content_forwarded');
        chunkIndex++;
      }
    } else {
      // any status other than 'completed' (blocked/cancelled/error)
      // must never carry a leftover held buffer forward — explicit, defensive
      // discard so no later code path can accidentally reference it.
      outputWindow.discardPending();
    }

  } catch (err) {
    outputWindow.discardPending(); // (S4): provider error never flushes a buffered chunk
    if (err.name === 'AbortError' || ac.signal.aborted) {
      const reason      = ac.signal.reason;
      terminationReason = _cancelTerminationReason(reason);
      status            = 'cancelled';
    } else {
      terminationReason = err?.code || 'PROVIDER_ERROR';
      status            = 'error';
      metrics.streamingEnforcementFailuresTotal.inc({});
      try { const _p = String(execProvider ?? ''); const _c = String(err?.code ?? ''); metrics.providerFailuresTotal.inc({ provider: /^[a-z0-9_-]{1,32}$/i.test(_p) ? _p : 'other', code: /^[A-Z][A-Z0-9_]{1,47}$/.test(_c) ? _c : 'OTHER' }); } catch { /* phase 11: best-effort metric (streaming provider failures) */ }
      emit('WARN', 'STREAM_PROVIDER_ERROR', {
        streamId, requestId, provider,
        reason: terminationReason,
        error:  err?.message ?? String(err),
      });
      _writeSSE(res, {
        event:     'stream_cancelled',
        streamId,
        reason:    terminationReason,
        requestId,
      }, { id: _nextFrameId() });
    }
  }

  if (ST.ON) {
    const loopMs = ST.start() - _tLoop;
    const recorded = (ST.get('S29') - _before.s29) + (ST.get('S30') - _before.s30) + (ST.get('S32') - _before.s32);
    ST.add('S30', Math.max(0, loopMs - recorded));
    ST.label('stream', true);
    ST.label('streamStatus', status);
  }

  // ── Cleanup ───────────────────────────────────────────────────────────────────
  clearTimeout(_timeoutId);
  if (typeof res.off === 'function') res.off('close', _onClientClose);

  const finalState = streamRegistry.finalizeStream(streamId, { terminationReason, status });
  const durationMs = Date.now() - startTime;

  // ── Terminal SSE events ───────────────────────────────────────────────────────
  if (status === 'completed') {
    _writeSSE(res, {
      event:       'stream_completed',
      streamId,
      requestId,
      chunksTotal: chunkIndex,
      bytesTotal:  finalState?.bytesStreamed ?? 0,
      durationMs,
    }, { id: _nextFrameId() });
    metrics.streamingCompletedTotal.inc({ termination_reason: terminationReason });
  } else {
    if (status !== 'error') {
      // 'error' path already sent stream_cancelled above
      _writeSSE(res, {
        event:     'stream_cancelled',
        streamId,
        reason:    terminationReason,
        requestId,
      }, { id: _nextFrameId() });
    }
    metrics.streamingCancelledTotal.inc({ reason: terminationReason });
  }

  _writeSSE(res, '[DONE]', { id: _nextFrameId() });
  if (ST.ON) ST.mark('done_written');

  // ── Metrics ───────────────────────────────────────────────────────────────────
  metrics.streamingActiveStreams.dec({});
  metrics.streamingDurationMs.observe({}, durationMs);

  // (step 7): charge the stream's classified output to the tenant's classification budget (never refused).
  try {
    const budget = require('../core/semantic/classificationBudget');
    budget.charge(tenantId, budget.windowsForLength(outputWindow.classifiedChars()));
  } catch { /* budget accounting must never affect the stream's outcome */ }

  // ── Audit write ───────────────────────────────────────────────────────────────
  const _auditResult = await _writeAuditStreamRecord({
    requestId, artifact, tenantId, organizationId, policyHash,
    provider, model, streamId, startTime,
    chunkCount:  chunkIndex,
    byteCount:   finalState?.bytesStreamed ?? 0,
    status, terminationReason, semanticEvidence, publicKeyId,
    consentProvenance, policyDecision, outputSemanticEvidence,
    routing: _routing,
    outputHash: _delivered.digest(),
    executingProvider: _dispatched ? (_routing?.executingProvider || execProvider) : null,
  });

  emit('INFO', 'STREAM_TERMINATED', {
    streamId, requestId, provider, model,
    status, terminationReason, durationMs,
    chunkCount: chunkIndex,
    byteCount:  finalState?.bytesStreamed ?? 0,
    tenantId,
  });

  res.end();

  // COMMIT — only for a request whose DECISION is in the chain and whose provider was dispatched; settled when the response has ended
  if (_dispatched && _auditResult && (_auditResult.recorded || _auditResult.duplicate)) {
    const _hash = _delivered.digest();
    _watchStreamEnd(res, _commit, {
      delivered: status === 'completed', outputHash: _hash, bytesDelivered: _delivered.bytes(),
      completionStatus: _completionStatusForStream(status, terminationReason),
    });
  }
}

module.exports = { streamResponse };
