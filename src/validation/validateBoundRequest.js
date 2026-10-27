'use strict';

/**
 * QODIQA V2 — Full request validation pipeline.
 *
 * This is the single entry point that callers MUST use to authorize execution.
 * All four steps must pass in order.  A failure at any step immediately
 * returns BLOCK — no subsequent steps run.
 *
 * ── Validation order (MUST NOT be reordered) ───────────────────────────────────
 *
 *   Step 1: validateArtifact(artifact)
 *     Verifies the Ed25519 signature over the full envelope
 *     (payload + timestamp + expiry + publicKeyId).  Checks schema, time bounds,
 *     and key resolution.  Any structural or cryptographic failure → BLOCK.
 *
 *   Step 2: verifyRequestBinding(artifact, request)
 *     Confirms requestId is a valid UUID v4 and requestHash matches the actual
 *     HTTP request (method + path + body).  Any mismatch → BLOCK.
 *
 *   Step 3: registerNonce(requestId, expiry)
 *     Atomically writes requestId to the persistent nonce store with TTL =
 *     artifact.expiry − now.  If requestId already exists → REPLAY_DETECTED.
 *     If store is unavailable → NONCE_STORE_ERROR.  Fail-closed in all cases.
 *
 *   Step 4: checkAnomaly(publicKeyId)
 *     Records this event in two sliding windows (per-key and global).
 *     If either window exceeds its threshold → ANOMALY_DETECTED.
 *     If anomaly store is unavailable → ANOMALY_DETECTED (fail-closed).
 *
 * ── Why this order? ───────────────────────────────────────────────────────────
 *
 *   Nonce registration (step 3) is deferred until AFTER signature and binding
 *   checks.  This prevents nonce-pollution: a crafted request that fails
 *   requestHash binding cannot permanently burn a valid requestId.  Only a
 *   fully valid, correctly signed, correctly bound artifact consumes a nonce.
 *
 *   Anomaly detection (step 4) runs AFTER nonce registration so that replay
 *   attacks do not consume anomaly quota.  Only genuinely novel, structurally
 *   valid requests increment the anomaly counters.
 */

// stage timer (bench only). With QODIQA_BENCH_STAGE_TIMING off each ST.time*() returns the original function.
const ST = require('../observability/stageTimer');
const validateArtifact             = ST.timeSync('S18', require('./validateArtifact').validateArtifact);
const verifyRequestBinding         = ST.timeSync('S20', require('./verifyRequestBinding').verifyRequestBinding);
const artifactRevocation           = require('../core/artifactRevocation');   //
const { emit }                     = require('../../services/logger');
const protocolV2                   = require('./protocolV2');   // V2 claims, version negotiation, V2 request binding
const registerNonce                = ST.timeAsync('S21', require('./registerNonce').registerNonce);
const checkAnomaly                 = ST.timeAsync('S21', require('./checkAnomaly').checkAnomaly);
const registerNonceAndCheckAnomaly = ST.timeAsync('S21', require('./registerNonceAndCheckAnomaly').registerNonceAndCheckAnomaly);
const assertActiveTenant           = ST.timeSync('S19', require('../core/tenancy/tenantRegistry').assertActiveTenant);
const assertActiveOrganization     = ST.timeSync('S19', require('../core/organizations/organizationRegistry').assertActiveOrganization);
const { resolveHaConfig }            = require('../infra/redis/haConfig');

// Item 17: resolved once, at module load ("startup" per the approved plan) —
// REDIS_MODE doesn't change at runtime, and resolveHaConfig() is a pure
// env-var read, so caching costs nothing and avoids a per-request env
// re-parse on this newly-shortened critical path. Combined-Lua runs in
// 'single' and 'sentinel' modes (both target one logical dataset on one
// node — no cross-key slot risk) and falls back to the sequential path only
// in 'cluster' mode, where the nonce key and the two anomaly keys aren't
// guaranteed to land on the same hash slot — see
// ITEM-17-REMEDIATION-REPORT.md §2 for the CROSSSLOT reasoning.
const _cachedHaMode = resolveHaConfig().mode;

/**
 * Validate an artifact against an HTTP request, register the nonce, and
 * check for anomalous traffic patterns.
 *
 * @param {any} artifact
 * @param {{ method: string, path: string, body: object }} request
 * @param {{
 *   _clock?:        () => number,
 *   _maxSkewMs?:    number,
 *   _store?:        object,
 *   _anomalyStore?: object,
 *   _thresholds?:   object,
 *   _combined?:     object,
 *   _haMode?:       'single'|'sentinel'|'cluster',
 *   _revocationStore?: object,
 * }} [opts]
 *   _clock:        internal clock override for time-sensitive tests (NEVER use in production)
 *   _store:        nonce store override for tests (NEVER use in production)
 *   _anomalyStore: anomaly store override for tests (NEVER use in production)
 *   _thresholds:   anomaly threshold override for tests (NEVER use in production)
 *   _combined:     combined nonce+anomaly store override for tests exercising
 *                  the item-17 combined-Lua path (NEVER use in production —
 *                  providing this forces the combined path regardless of
 *                  _haMode/REDIS_MODE, since a genuine cluster deployment
 *                  can't use it; see steps 3-4 below)
 *   _haMode:       Redis HA-mode override for tests (NEVER use in production)
 * _revocationStore: per-artifact revocation store override for tests
 *
 * @returns {Promise<
 *   { allowed: true,  requestId: string, publicKeyId: string, callerId: string|null, callerContext: object|null } |
 *   { allowed: false, reason: string, details: object, publicKeyId?: string|null, callerId?: string|null }
 * >}
 *   publicKeyId on a BLOCK result is only ever present (non-null) once Step 1
 *   has cryptographically verified the artifact's signature against that key
 *   — i.e. for BLOCKs at Step 1b/1c/2/3/4. Step 1's own BLOCK reasons
 *   (INVALID_ARTIFACT, KEY_NOT_FOUND, FUTURE_TIMESTAMP, EXPIRED,
 *   INVALID_SIGNATURE, TIME_SKEW_EXCEEDED) omit it: no key attribution can be
 *   asserted before signature verification actually succeeds.
 *
 * callerId/callerContext — the authenticated identity that
 *   requested this signature at /sign time, read out of the signature-
 *   verified artifact.payload.callerContext. null only for an artifact
 *   signed before this remediation shipped (self-expires within the
 *   existing max TTL) — see requireConsent.js's legacy fallback.
 */
async function validateBoundRequest(artifact, request, { _clock = Date.now, _store, _anomalyStore, _thresholds, _maxSkewMs, _combined, _haMode, _revocationStore } = {}) {

  // ── Step 1: Artifact signature validation ────────────────────────────────────
  const validation = validateArtifact(artifact, { _clock, _maxSkewMs });
  if (validation.decision !== 'EXECUTE') {
    // no key has been verified yet — this reject is
    // PRE-AUTHENTICATION. Callers keep it out of the audit chain and the
    // transparency log (src/core/preauth/preAuthRejects.js). Every later BLOCK
    // below has a verified key behind it and is recorded as before.
    return Object.freeze({
      allowed: false,
      reason:  validation.reason,
      details: validation.details,
      preAuth: true,
    });
  }

  // ── Step 1b: Tenant validation ────────────────────────────────────────────────
  // CRYPTO-6: tenantId comes directly from validateArtifact()'s own key-store
  // resolution (validation.details.clientId — services/artifact/keyStore.js's
  // getPublicKey() already resolved the real owning clientId via _legacyMap
  // for a legacy colon-less publicKeyId, same as for a modern one). Previously
  // this re-parsed the raw publicKeyId string independently via parseKeyId()
  // (Register #106), which throws — and therefore silently produced
  // tenantId=null — for any legacy key ID, placing that request's nonce in an
  // un-tenant-scoped namespace even though the key's real tenant was already
  // known internally. clientId is null only when publicKeyId truly encodes no
  // tenant (this key store's own authoritative answer), so the tenant/org
  // checks below are still correctly skipped in that case.
  const _publicKeyId = validation.details.publicKeyId;
  const tenantId      = validation.details.clientId ?? null;

  // ── authenticated caller identity ──────────────────────────────────
  // callerContext was embedded in payload at /sign time (src/api/routes/sign.js)
  // and is therefore covered by the signature verification that just succeeded
  // in Step 1 above — reading it off the raw `artifact` argument (not off
  // validation.details, which only ever surfaced publicKeyId/timestampMs/
  // expiryMs) is safe precisely because the envelope signature already proved
  // this payload, callerContext included, was not modified after signing.
  // null on any artifact signed before this remediation shipped (self-expires
  // within the existing max TTL — see requireConsent.js's fallback).
  const _callerContext = (artifact.payload && typeof artifact.payload.callerContext === 'object' && artifact.payload.callerContext !== null)
    ? artifact.payload.callerContext
    : null;
  const _callerId = (typeof _callerContext?.callerId === 'string' && _callerContext.callerId)
    ? _callerContext.callerId
    : null;

  if (tenantId) {
    // tenant and org state come from the control plane; a stale
    // snapshot (CONTROL_PLANE_STALE) blocks — it is never read as "active".
    let tenantResult; let orgResult;
    try {
      tenantResult = assertActiveTenant(tenantId);
      orgResult = tenantResult.valid ? assertActiveOrganization(tenantId) : null;
    } catch (err) {
      if (err && err.name === 'ControlPlaneError') {
        return Object.freeze({ allowed: false, reason: err.code, details: {}, publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext });
      }
      throw err;
    }
    if (!tenantResult.valid) {
      return Object.freeze({ allowed: false, reason: tenantResult.reason, details: {}, publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext });
    }

    // Step 1c: Organization boundary check — fail-closed if org is suspended/disabled.
    if (!orgResult.valid) {
      return Object.freeze({ allowed: false, reason: orgResult.reason, details: {}, publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext });
    }
  }

  // ── Step 1d: protocol version (V2-FREEZE 7) ────────────────────────────────────
  // No `qodiqa` claim = V1 (unchanged path below). With one, the version, the claim block, the artifact kind and the tenant's minimum
  // protocol version are checked here, after the signature (the claims are signed) and before the binding.
  const _proto = protocolV2.classifyPayload(/** @type {any} */ (artifact).payload, { tenantId });
  if (!_proto.ok) {
    return Object.freeze({ allowed: false, reason: _proto.reason, details: {}, publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext });
  }

  // ── Step 2: Request binding + requestId format ───────────────────────────────
  const binding = _proto.version === 2 ? protocolV2.verifyBindingV2(artifact, request) : verifyRequestBinding(artifact, request);
  if (binding.bound && _proto.version === 2 && _proto.qodiqa.model != null && !(request && request.body && request.body.model === _proto.qodiqa.model)) {
    // the artifact authorizes one model; the (bound) body must name exactly it
    return Object.freeze({ allowed: false, reason: 'REQUEST_MISMATCH', details: Object.freeze({}), publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext });
  }
  if (!binding.bound) {
    return Object.freeze({
      allowed: false,
      reason:  binding.reason,
      details: binding.details,
      publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext,
    });
  }

  // ── Step 2b: per-artifact revocation ────────────────────────────────────
  // After the signature and the binding (the requestId is only trustworthy now), BEFORE the nonce: a revoked artifact never
  // consumes its nonce. A store that cannot answer refuses — "cannot tell" is not "not revoked".
  try {
    if (await artifactRevocation.isRevoked(binding.requestId, { _store: _revocationStore })) {
      try { require('../observability/metrics').artifactRevokedBlocksTotal.inc(); } catch { /* metrics are best-effort */ }
      return Object.freeze({ allowed: false, reason: 'ARTIFACT_REVOKED', details: {}, publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext });
    }
  } catch (err) {
    emit('ERROR', 'ARTIFACT_REVOCATION_CHECK_FAILED', { error: err.message });
    return Object.freeze({ allowed: false, reason: 'ARTIFACT_REVOCATION_STATE_UNAVAILABLE', details: {}, publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext });
  }

  // ── Steps 3+4: nonce registration + anomaly detection ────────────────────────
  // expiry comes from the validated, signature-verified artifact envelope.
  //
  // Item 17: collapsed into one combined-Lua round trip when running against
  // the real production stores in single-node Redis mode. Falls back
  // automatically to the original two-function sequential path — unchanged
  // below — whenever a test injects _store/_anomalyStore (which can't
  // execute a combined EVAL) or REDIS_MODE=cluster (the nonce key and the
  // two anomaly keys aren't guaranteed to share a hash slot — see
  // ITEM-17-REMEDIATION-REPORT.md §2). Both branches produce identically-
  // shaped nonceResult/anomalyResult, so every BLOCK/ALLOW response below is
  // built exactly the same way regardless of which one ran.
  const _usingRealStores = _store === undefined && _anomalyStore === undefined;
  const _haModeResolved  = _haMode !== undefined ? _haMode : _cachedHaMode;
  const _useCombined     = _combined !== undefined || (_usingRealStores && _haModeResolved !== 'cluster');

  let nonceResult, anomalyResult;
  if (_useCombined) {
    ({ nonceResult, anomalyResult } = await registerNonceAndCheckAnomaly(
      binding.requestId, artifact.expiry, validation.details.publicKeyId,
      { _store: _combined, tenantId, _clock, _thresholds, issuedAtMs: validation.details.timestampMs },
    ));
  } else {
    nonceResult = await registerNonce(binding.requestId, artifact.expiry, { _store, tenantId, issuedAtMs: validation.details.timestampMs });
    if (nonceResult.ok) {
      anomalyResult = await checkAnomaly(validation.details.publicKeyId, {
        _store:      _anomalyStore,
        _clock,
        _thresholds,
        tenantId,
      });
    }
  }

  if (!nonceResult.ok) {
    // For REPLAY_DETECTED we surface the requestId so the caller can record a
    // correlated replay event in the audit chain (replayOf linkage).  Other
    // failure modes do not expose requestId because binding may be untrustworthy.
    if (nonceResult.reason === 'REPLAY_DETECTED') {
      return Object.freeze({
        allowed:   false,
        reason:    nonceResult.reason,
        details:   nonceResult.details || {},
        requestId: binding.requestId,
        publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext,
      });
    }
    return Object.freeze({
      allowed: false,
      reason:  nonceResult.reason,
      details: nonceResult.details || {},
      publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext,
    });
  }

  if (anomalyResult.block) {
    return Object.freeze({
      allowed: false,
      reason:  'ANOMALY_DETECTED',
      details: { type: anomalyResult.type },
      publicKeyId: _publicKeyId, callerId: _callerId, callerContext: _callerContext,
    });
  }

  const { organizationId = null } = tenantId
    ? assertActiveOrganization(tenantId)
    : {};

  return Object.freeze({
    allowed:        true,
    requestId:      binding.requestId,
    publicKeyId:    validation.details.publicKeyId,
    callerId:       _callerId,
    callerContext:  _callerContext,
    tenantId,
    organizationId: organizationId || null,
    protocolVersion: _proto.version,
    qodiqa:          _proto.version === 2 ? _proto.qodiqa : null,
  });
}

module.exports = { validateBoundRequest };
