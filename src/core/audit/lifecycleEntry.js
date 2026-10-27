'use strict';

/**
 * audit schema v7 — lifecycle evidence entries.
 *
 *   INTENT         written immediately before provider execution          stage PROVIDER_DISPATCH
 *   STREAM_OPENED  written before the first streamed byte reaches the client  stage STREAM_OPENED
 *
 * Both are v7 audit entries with fixed `decision: "ALLOW"` / `outputHash: null` (R-8 / R-8a), a deterministic
 * suffixed artifactId (`:intent` / `:stream_opened`, R-9) and the request's hashed `requestId` as the link to the
 * later DECISION entry. Each registers its OWN transparency leaf in the same transparency/audit integrity chain as
 * every other enforcement decision (R-10) — under the suffixed artifactId, so the DECISION leaf stays the one found
 * for the request's artifact — and gets its own evidence-chain record through the ordinary audit mirror path (R-11).
 *
 * Fail-closed (R-8, R-14): the caller must not dispatch to the provider (INTENT) or send a byte (STREAM_OPENED) unless
 * this resolves. Every failure is surfaced through the existing error contract — `AUDIT_PERSISTENCE_FAILED` when the
 * audit entry could not be recorded (including a refused subject pseudonym), `TRANSPARENCY_PERSISTENCE_FAILED` when
 * its leaf could not be — with the underlying error preserved as `.cause`.
 *
 * The append / register functions are injected so each route keeps its own instrumented wrappers (stage timers).
 */

const {
  LIFECYCLE_FIXED, lifecycleArtifactId,
} = require('./entryBuilder');

function _failure(code, err) {
  if (err && err.code === code) return err;
  // / F6-N2: the write-time refusal keeps its own deterministic code (the caller maps it to 422, nothing persisted)
  if (err && err.code === 'AUDIT_UNREPRESENTABLE_TEXT') return err;
  const f = new Error(`${code}: ${err && err.message ? err.message : String(err)}`);
  f.code = code;
  f.cause = err;
  return f;
}

/**
 * @param {'INTENT'|'STREAM_OPENED'} kind
 * @param {object} f                 the request's audit fields (same names as appendMandatory()'s), plus
 *                                   `executingProvider` (the provider about to be called / streaming)
 * @param {object} deps
 * @param {Function} deps.append     appendMandatory-compatible: (fields, opts) → Promise<entry>
 * @param {Function} deps.register   registerEnforcementDecision-compatible: (opts) → Promise<registration>
 * @param {Function} [deps.onDegraded] called with the registration when the leaf was signed but not persisted
 * @returns {Promise<{ entry: object, registration: object, artifactId: string }>}
 */
async function writeLifecycleEntry(kind, f, { append, register, onDegraded } = {}) {
  const fixed = LIFECYCLE_FIXED[kind];
  if (!fixed) throw new Error(`invalid_entryType: ${kind} is not a lifecycle entry type`);
  if (typeof f.requestId !== 'string' || !f.requestId) throw new Error(`invalid_requestId: a ${kind} entry needs the request id`);
  const artifactId = lifecycleArtifactId(f.requestId, kind);
  // (D-F5-1): before the provider is dispatched, refuse a NEW execution while the transparency evidence store has been unavailable longer than
  // QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS (503 TRANSPARENCY_JOURNAL_UNAVAILABLE). BLOCK decisions are not affected.
  if (kind === 'INTENT') require('../transparency/journalHealth').assertAvailable();

  let entry;
  try {
    entry = await append({
      artifactId,
      entryType:          kind,
      decision:           fixed.decision,
      stage:              fixed.stage,
      outputHash:         null,
      reason:             null,
      tokenUsage:         null,
      responseId:         f.responseId ?? null,
      inputHash:          f.inputHash,
      signature:          f.signature,
      requestHash:        f.requestHash,
      policyHash:         f.policyHash,
      verificationResult: true,
      tenantId:           f.tenantId ?? undefined,
      organizationId:     f.organizationId ?? undefined,
      publicKeyId:        f.publicKeyId ?? null,
      requestId:          f.requestId,
      traceId:            f.traceId ?? null,
      consentProvenance:  f.consentProvenance ?? null,
      policyDecision:     f.policyDecision ?? null,
      callerContext:      f.callerContext ?? null,
      provider:           f.provider ?? null,
      model:              f.model ?? null,
      semantic:           f.semantic ?? null,
      executingProvider:  f.executingProvider ?? null,
      executionContext:   f.executionContext ?? null,
    }, { stage: kind });
  } catch (err) {
    throw _failure('AUDIT_PERSISTENCE_FAILED', err);
  }

  let registration;
  try {
    registration = await register({
      requestId:          f.requestId,
      artifactId,
      entryType:          kind,
      decision:           fixed.decision,
      reason:             null,
      stage:              fixed.stage,
      auditEntryHash:     entry?.hash ?? null,
      inputHash:          f.inputHash,
      signature:          f.signature,
      policyHash:         f.policyHash,
      verificationResult: true,
      tenantId:           f.tenantId ?? null,
      publicKeyId:        f.publicKeyId ?? null,
      provider:           f.executingProvider ?? f.provider ?? null,
      semantic:           f.semantic ?? null,
      consentProvenance:  f.consentProvenance ?? null,
      policyRuleId:       f.policyDecision?.policyId ?? null,
      policyRuleVersion:  f.policyDecision?.policyVersion ?? null,
      callerId:           f.callerContext?.callerId ?? null,
    });
  } catch (err) {
    throw _failure('TRANSPARENCY_PERSISTENCE_FAILED', err);
  }
  if (registration && registration.persisted === false && typeof onDegraded === 'function') {
    try { onDegraded(registration); } catch { /* observability must never mask the recorded evidence */ }
  }
  return { entry, registration, artifactId };
}

module.exports = { writeLifecycleEntry };
