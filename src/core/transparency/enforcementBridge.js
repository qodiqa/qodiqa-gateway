'use strict';

/**
 * Live Enforcement → Transparency Log bridge — remediation.
 *
 * Registers a single RFC6962 transparency log leaf for one finalized
 * /ai/chat enforcement decision (ALLOW or BLOCK; streaming or non-streaming
 * — both call this same function, see src/api/routes/aiChat.js and
 * src/streaming/streamEnforcer.js). This is a thin wrapper around
 * registrar.register() (the same append API attestor.js/evaluationEngine.js/
 * verificationPortal.js already use) — no Merkle hashing, signing, or
 * persistence logic is duplicated here, only the enforcement-specific leaf
 * payload shape.
 *
 * Payload contains only immutable verification evidence already computed by
 * the enforcement pipeline and the audit write that precedes this call:
 * request ID, artifact hash, a signature reference (not the raw signature
 * bytes), verification/decision outcome, policy hash, semantic evidence
 * (decision/score/matched classifiers — never raw prompt text), timestamp,
 * key identifier, a reference to the audit chain entry this leaf
 * corresponds to, provider, and tenant. Never includes prompt content, raw
 * signatures, API keys, or other secrets/customer payloads.
 *
 * TRACE-2: also carries consentId + a domain-separated hash of the full
 * ConsentProvenance object (not the object itself — same "reference, not raw
 * content" posture already used for `signatureRef` above), plus the matched
 * policyRuleId/policyRuleVersion. This lets a transparency-log consumer
 * cross-check that a given evidence package's consent section is the one
 * actually recorded in the tamper-evident Merkle log at decision time,
 * without duplicating consent PII (subject/scope/tenant) into the
 * transparency log itself — that full detail lives only in the audit chain
 * and evidence chain, which already are the hash-protected sources of truth.
 *
 * (D3): the synchronous registration stays the fast path.
 * When it fails on a PostgreSQL PERSISTENCE failure (isPersistenceFailure —
 * connection loss, pool exhaustion, circuit open), the registration is put on
 * the crash-safe recovery queue (TRANSPARENCY_SAVE; filesystem journal when PG
 * cannot take the enqueue) under a transparencyId assigned here, and the call
 * resolves { transparencyId, payloadHash, entryHash: null, persisted: 'pending' }.
 * entryHash and the signature are NOT produced for a pending leaf: both cover
 * previousEntryHash, which exists only under the PG head lock, so the drain
 * worker chains and signs the leaf exactly as a synchronous registration
 * would. Any other failure (signing, validation, data), or a queue that could
 * not durably record the operation, still throws — callers keep their
 * existing fail-closed / CRITICAL handling for those.
 */

const { randomUUID } = require('crypto');
const registrar     = require('./registrar');
const log           = require('./log');
const pgPool        = require('../../infra/postgres/pool');
const { emit }      = require('../../../services/logger');
const { sha256Hex, domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../infra/crypto/hashing');
const stableStringify = require('../../utils/stableStringify');
const journalHealth = require('./journalHealth');   //

/**
 * @param {object} opts
 * @param {string}      opts.requestId
 * @param {'ALLOW'|'BLOCK'} opts.decision
 * @param {string|null} [opts.reason]
 * @param {string|null} [opts.stage]              — enforcement stage label (VALIDATION, POLICY_ENFORCEMENT, SEMANTIC_POLICY, PROVIDER_EXECUTION, STREAM, ...)
 * @param {string|null} [opts.auditEntryHash]      — hash of the audit chain entry this leaf documents
 * @param {string|null} [opts.inputHash]           — artifact.payload.requestHash ('UNAVAILABLE' or absent → null)
 * @param {string|null} [opts.signature]           — artifact.signature; reduced to a hash reference, never stored raw
 * @param {string|null} [opts.policyHash]
 * @param {boolean}     [opts.verificationResult]
 * @param {string|null} [opts.tenantId]
 * @param {string|null} [opts.publicKeyId]
 * @param {string|null} [opts.provider]
 * @param {object|null} [opts.semantic]            — semantic.evidence (decision/score/matchedPolicies only)
 * @param {object|null} [opts.consentProvenance]   — TRACE-2: full ConsentProvenance object; only its
 *   consentId and a domain-separated hash of the whole object are stored in the leaf, never the object itself
 * @param {string|null} [opts.policyRuleId]        — TRACE-2: matched policy rule id (policyDecision.policyId)
 * @param {number|null} [opts.policyRuleVersion]   — TRACE-2: matched policy rule version
 * @param {string|null} [opts.policyRuleHash]      — TRACE-4: deterministic hash of the deciding rule's
 *   canonical content (policyDecision.policyRuleHash) — independently recomputable, see services/policyHash.js
 * @param {string|null} [opts.callerId] — authenticated caller identity
 *   (artifact.payload.callerContext.callerId) bound at /sign time; distinct from publicKeyId,
 *   which only proves which shared tenant key signed. Full callerContext already lives in the
 *   audit chain — only the id is echoed here for cross-referencing this Merkle leaf.
 * @param {string|null} [opts.artifactId] — v7 (R-9/R-10): the leaf's artifact id when it differs from
 *   requestId — the `:intent` / `:stream_opened` lifecycle entries register under their own suffixed id, so the
 *   DECISION leaf stays the one found for the request's artifact (proofLookup.getInclusionProofForArtifact uses the
 *   earliest leaf per artifactId). Omitted → requestId, exactly as before.
 * @param {string|null} [opts.entryType] — v7 (R-3/R-10): 'INTENT' | 'STREAM_OPENED' for lifecycle leaves.
 *   Recorded in the payload only when given, so every DECISION leaf payload is byte-for-byte unchanged.
 * @param {boolean} [opts.bestEffort=false] — for decisions whose response cannot be withheld (BLOCK, a delivered stream). When neither the recovery
 *   queue nor the file journal can take the leaf it is kept in the bounded in-memory buffer (journalHealth.js) and the call resolves
 *   { persisted: 'pending', durable: false } instead of throwing; the unavailability window it opens refuses new EXECUTE decisions once it is
 *   older than QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS. Without it (non-streamed ALLOW) the failure still throws and the response is withheld.
 * @returns {Promise<object>} same shape as registrar.register(): { transparencyId, entryHash, signature, keyId, persisted, row }
 */
async function registerEnforcementDecision({
  requestId,
  decision,
  reason = null,
  stage = null,
  auditEntryHash = null,
  inputHash = null,
  signature = null,
  policyHash = null,
  verificationResult = false,
  tenantId = null,
  publicKeyId = null,
  provider = null,
  semantic = null,
  consentProvenance = null,
  policyRuleId = null,
  policyRuleVersion = null,
  policyRuleHash = null,
  callerId = null,
  artifactId = null,
  entryType = null,
  bestEffort = false,
} = {}) {
  const signatureRef = (typeof signature === 'string' && signature && signature !== 'UNAVAILABLE')
    ? sha256Hex(signature)
    : null;

  const consentProvenanceHash = consentProvenance
    ? domainSeparatedHash(ARTIFACT_DOMAINS.CONSENT, stableStringify(consentProvenance)).toString('hex')
    : null;

  const payload = {
    requestId:           requestId || null,
    decision,
    reason,
    stage,
    artifactHash:        (typeof inputHash === 'string' && inputHash && inputHash !== 'UNAVAILABLE') ? inputHash : null,
    signatureRef,
    verificationResult:  verificationResult === true,
    policyHash:           (typeof policyHash === 'string' && policyHash && policyHash !== 'UNAVAILABLE') ? policyHash : null,
    provider:             provider || null,
    publicKeyId:          publicKeyId || null,
    auditEntryHash:       auditEntryHash || null,
    tenantId:             tenantId || null,
    semantic:             semantic || null,
    // TRACE-2: reference + hash, not the object — see file header comment.
    consentId:             consentProvenance?.consentId ?? null,
    consentProvenanceHash,
    policyRuleId:          policyRuleId    || null,
    policyRuleVersion:     policyRuleVersion ?? null,
    // TRACE-4: independently-recomputable hash of the deciding rule.
    policyRuleHash:        policyRuleHash  || null,
    // authenticated caller identity, distinct from publicKeyId.
    callerId:              callerId || null,
    ...(entryType ? { entryType } : {}),
    recordedAt:           new Date().toISOString(),
  };

  const registration = {
    transparencyId: randomUUID(),
    entryType:    'AUDIT',
    artifactId:   artifactId || requestId || null,
    payload,
    registeredBy: 'ai-chat-enforcement',
    tenantId:     tenantId || null,
  };

  try {
    const out = await registrar.register(registration);
    if (out && out.persisted === true) journalHealth.noteOk();
    return out;
  } catch (err) {
    return _enqueuePending(registration, err, { bestEffort });
  }
}

// (D1 of the independent verification): only a failure the replay handler will RETRY is queued - a PostgreSQL persistence failure (the TRANSPARENCY_SAVE
// handler answers every other error "non-retryable" and moves the leaf to the dead-letter queue, i.e. it would be lost while the caller was told 'pending').
// Anything else (a signer / KMS outage, a programming error) is not queued: it opens the unavailability window - so executions stop after the bound -, is
// counted and escalated, and is rethrown (a non-streamed ALLOW withholds its response; BLOCK and stream callers keep their existing CRITICAL handling).
function _refuseUnqueueable(err, registration) {
  journalHealth.noteFailure(err);
  const metrics = require('../../observability/metrics');
  try { metrics.transparencyUnrecordedTotal.inc({ reason: 'not_queueable' }); } catch { /* metrics are fail-safe */ }
  emit('CRITICAL', 'TRANSPARENCY_LEAF_UNRECORDED', { transparencyId: registration.transparencyId, artifactId: registration.artifactId, error: err && err.message, code: (err && err.code) ?? null,
    message: 'The leaf could not be registered and the failure is not one a retry fixes (signer / validation); it is not queued.' });
}

// The registration as it is queued: it carries the late/recovered marker INSIDE the payload (so it is hashed and signed with the leaf, and the
// payload hash returned to the caller already covers it). D4: the payload is JSON-normalised first, so the hash the caller is promised equals the
// hash after the queue / journal round trip (an undefined member hashes as null but is dropped by JSON). recordedAt keeps the original time.
function _markLate(registration) {
  if (registration.payload && registration.payload.recovery) return registration;
  const normalised = JSON.parse(JSON.stringify(registration.payload ?? {}));
  return { ...registration, payload: { ...normalised, recovery: journalHealth.recoveryMarker() } };
}

async function _queue(registration, err) {
  const { enqueueWithOutcome, OPERATION_TYPES } = require('../persistenceRecovery');
  const { durable } = await enqueueWithOutcome(OPERATION_TYPES.TRANSPARENCY_SAVE, { registration }, err);
  return durable;
}

// the bounded in-memory buffer drains through the same queue / journal path, in the original order
journalHealth.setFlusher(async (registration) => {
  if (!pgPool.isEnabled()) return false;
  return Boolean(await _queue(registration, new Error('buffered leaf')));
});

// D2: with nothing buffered the window still has to close by itself - the store is usable again when PostgreSQL answers or the journal volume is writable.
journalHealth.setProber(async () => {
  if (!pgPool.isEnabled()) return false;
  try { await pgPool.query('SELECT 1', [], 'transparency_journal_probe'); return true; } catch { /* PostgreSQL is down: the journal may still work */ }
  try { return await require('../persistenceRecovery/journal').probeWritable(); } catch { return false; }
});

// (D3) + (D-F5-1, option A): durable fallback for a failed registration - the recovery queue, else the file journal on the persistent
// volume. If nothing durable takes the leaf: BLOCK / stream decisions keep it in memory (bestEffort), a non-streamed ALLOW rethrows so its response
// is withheld; both open the unavailability window.
async function _enqueuePending(registration, err, { bestEffort = false } = {}) {
  const { isPersistenceFailure } = require('../persistenceRecovery');
  if (!pgPool.isEnabled()) throw err;
  if (!isPersistenceFailure(err)) { _refuseUnqueueable(err, registration); throw err; }
  const marked = _markLate(registration);

  let durable = false;
  try { durable = await _queue(marked, err); } catch (qErr) { err = qErr; }
  if (durable) {
    journalHealth.noteOk();
    const metrics = require('../../observability/metrics');
    try { metrics.transparencyPendingTotal.inc({ durable }); } catch { /* metrics are fail-safe */ }
    // O9: first N per window in full, the rest counted (src/observability/aggregatedEmit.js failureEmit)
    require('../../observability/aggregatedEmit').failureEmit(emit, 'WARN', 'TRANSPARENCY_ENTRY_PENDING', {
      transparencyId: marked.transparencyId, artifactId: marked.artifactId, durable, late: true, seq: marked.payload.recovery.seq,
      error: err.message, code: err.code ?? null,
    });
  } else {
    journalHealth.noteFailure(err);
    if (!bestEffort) throw err;
    if (!journalHealth.buffer(marked)) throw err;     // buffer full: the loss is escalated, and the caller's own CRITICAL handling applies
  }
  return {
    transparencyId: marked.transparencyId,
    payloadHash:    log.computePayloadHash(marked.payload),
    entryHash:      null,
    signature:      null,
    keyId:          null,
    persisted:      'pending',
    durable,
    row:            null,
  };
}

module.exports = { registerEnforcementDecision };
