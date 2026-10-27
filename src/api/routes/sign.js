'use strict';

const crypto                        = require('crypto');
const { Router }                    = require('express');
const { signArtifact, signArtifactNative } = require('../../validation/signArtifact');
const { envelopeHash }              = require('../../validation/canonicalize');
const { verify: verifyEd25519 }     = require('../../infra/crypto/ed25519');
const { computeRequestHash }        = require('../../validation/requestHash');
const protocolV2                    = require('../../validation/protocolV2');
const { computeRequestHashV2FromParts, BindingError } = require('../../validation/requestBindingV2');
const { canonicalJcsP1, JcsError }  = require('../../validation/jcsP1');
const { computePolicyHash }         = require('../../../services/policyHash');
const { getEffectivePoliciesForTenant } = require('../../core/tenancy/tenantPolicyRegistry'); //
const keyManager                    = require('../../../services/artifact/keyManager');
const { parseKeyId }                = require('../../../services/artifact/keyId');
const { emit, blocked }             = require('../../../services/logger');
const enforceContentType            = require('../../../middleware/enforceContentType');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { createSignAuthMiddleware }  = require('../../middleware/signAuth');
const { createAuthLockout }         = require('../../core/authLockout');

// /sign's auth-failure bucket — 10 failed
// credentials per minute from a source (or for one credential) → 429 for 5
// minutes. An independent lockout (key namespace 'sign') on the same
// Redis-backed store as the operator lockout; a storage outage fails CLOSED
// (D3: auth buckets never degrade). QODIQA_SIGN_AUTH_LOCKOUT_ENABLED=false turns
// it off outside production (the Jest setup does; production refuses it).
function _intEnv(name, dflt) { const v = parseInt(process.env[name], 10); return Number.isFinite(v) && v > 0 ? v : dflt; }
function _signAuthLockoutConfig() {
  return {
    authLockoutEnabled:             process.env.QODIQA_SIGN_AUTH_LOCKOUT_ENABLED !== 'false',
    authLockoutMaxFailures:         _intEnv('QODIQA_SIGN_AUTH_FAILURE_MAX', 10),
    authLockoutFailureWindowMs:     _intEnv('QODIQA_SIGN_AUTH_FAILURE_WINDOW_MS', 60_000),
    authLockoutDurationMs:          _intEnv('QODIQA_SIGN_AUTH_LOCKOUT_MS', 300_000),
    authLockoutBackoffMinMs:        0,
    authLockoutBackoffMaxMs:        0,
    authLockoutCredentialHashBytes: 16,
  };
}
const signingIdentityStore          = require('../../core/signing/signingIdentityStore');
const { isSigningPermitted }        = require('../../core/signing/signingPermissions');
const { resolveServerEnvironment }  = require('../../core/signing/serverEnvironment');
const { signBodySchema, MAX_TTL_MS, MIN_TTL_MS, RESERVED_PAYLOAD_KEYS } = require('../../validation/schemas/sign.schema');
const { MAX_ARTIFACT_AGE_MS } = require('../../validation/timeCheck');
const { firstQodiqaReason }         = require('../../validation/helpers');
const { getProviderConfig } = require('../../../services/providers/config');
// resolveProvider/listEnabledProviders (services/providers.js) are the SAME
// functions execution.js and router.js use to gate real dispatch — reusing
// them here (rather than re-deriving provider existence from config.js's
// CONFIGS keys) guarantees /sign can never accept a provider name that
// /ai/chat's execution path would then reject as unregistered. See
// services/providers/router.js's REGISTRY (the actual dispatch table) vs.
// config.js's CONFIGS (env-driven enablement only, no handler information).
const { resolveProvider, listEnabledProviders } = require('../../../services/providers');

// /sign is generic artifact-signing infrastructure — it binds an artifact to
// ANY downstream request path, not only AI execution (see
//which signs against
// /orders/create). payload.provider is overloaded: for AI execution it names
// the AI provider that will service the request; for any other bound path,
// the consent registry instead treats it as an opaque "action" identifier
// (see services/policy/evaluators/requireConsent.js) that has nothing to do
// with AI providers. Auto-resolution/validation below therefore only applies
// when the bound request targets the AI chat execution endpoint — for every
// other path, whatever payload.provider the caller supplied (including
// nothing at all) passes through untouched, exactly as before.
//
// '/ai/chat' is the ONLY canonical value here — src/api/routes/aiChat.js
// binds the artifact's requestHash against req.originalUrl (the ACTUAL
// incoming path), not a hardcoded constant, so a request signed for one
// alias (/ai/chat, /ai/chat/stream, /v1/ai/chat, /v1/ai/chat/stream — all
// four share one router instance) and then sent to a different one fails
// closed with REQUEST_MISMATCH. Both official SDKs always sign and send to
// the literal '/ai/chat' path for both streaming and non-streaming calls
// (streaming is toggled via a `stream: true` body flag, never a different
// URL), so '/ai/chat' is what callers should sign against regardless of
// which alias they intend to use.
const AI_CHAT_PATH = '/ai/chat';
// whether the provider-scope checks apply is decided by the shared
// canonical route resolver, not by comparing to AI_CHAT_PATH literally — every
// alias, case variant, trailing-slash, encoded or dot-segment form the router
// maps to the /ai/chat handler gets the same checks (see canonicalRoute.js).
const { isAiChatRoute } = require('../../core/routing/canonicalRoute');

// ── TRUST-1 remediation ────────────────────────────────────────────────────────
// /sign used to be a single-shared-token, unrated, unlimited signing oracle:
// one static QODIQA_SIGN_TOKEN authenticated every caller identically, every
// signed artifact used the SAME globally-configured QODIQA_CLIENT_ID
// regardless of who asked, and there was no rate limiting, no scoping, and no
// caller-level audit trail — anyone holding the token could mint unlimited
// production signing authority for any tenant. That model is gone entirely:
//
//   - Authentication: per-identity API key (Authorization: Bearer sk_<hex>),
//     resolved via src/core/signing/signingIdentityStore.js. No shared
//     secret exists anywhere in this path.
//   - Authorization: an identity must be enabled, unrevoked, and hold the
//     SIGN_ARTIFACT permission (src/middleware/signAuth.js).
//   - Scope: each identity is bound to exactly one tenantId (which signing
//     key it may use — never operator-suppliable), one deployment
//     environment (checked against the live server's environment), and
//     optionally a restricted set of AI providers.
//   - Rate limiting: per-identity ('sign' surface, keyed by signingKeyId —
//     see src/core/rateLimit/middleware.js) plus a coarser pre-auth,
//     IP-keyed throttle ('sign_auth' surface) that blunts brute-force
//     credential guessing before any credential is even resolved.
//   - Audit: every allow/deny emits a SIGN_DECISION event carrying identity,
//     scope, decision, and reason — see _auditDecision() below.
//
// See docs/security/RBAC_MODEL.md-equivalent rationale in
// src/core/signing/signingIdentityStore.js and src/middleware/signAuth.js.

module.exports = function createSignRouter(getPolicies, { _authLockout } = {}) {
  const router = Router();
  const signAuthLockout = _authLockout || createAuthLockout(_signAuthLockoutConfig(), { namespace: 'sign' });

  // Pre-authentication, IP-keyed throttle — runs before any credential is
  // resolved so repeated invalid-key guesses are bounded regardless of
  // whether they ever resolve to a real identity.
  router.use(createRateLimitMiddleware('sign_auth'));
  // admission control for /sign — before API-key authentication and signing (src/api/admission.js).
  router.use(require('../admission').get('sign').middleware);

  // Authenticate + authorize the caller. Fail-closed: no req.signingIdentity
  // means every downstream handler below is unreachable (signAuth itself
  // sends the 401/403 response and never calls next()).
  router.use(createSignAuthMiddleware({ store: signingIdentityStore, isSigningPermitted, authLockout: signAuthLockout, federation: require('../../core/identity/oidcService').federation(signingIdentityStore) }));   // null unless QODIQA_OIDC_CONFIG_PATH is set

  // Per-identity throttle — now keyed by req.signingKeyId (set by signAuth
  // above), so each signing identity gets an independent quota regardless of
  // how many other identities share its tenant.
  router.use(createRateLimitMiddleware('sign'));

  function _auditDecision(req, { decision, reason, extra = {} }) {
    const identity = req.signingIdentity || null;
    emit(decision === 'ALLOW' ? 'INFO' : 'WARN', 'SIGN_DECISION', {
      requestId:   req.requestId ?? null,
      ip:          req.clientIp ?? req.ip ?? null,
      decision,
      reason,
      identityId:  identity?.id ?? null,
      identityName: identity?.name ?? null,
      tenantId:    identity?.tenantId ?? null,
      environment: identity?.environment ?? null,
      ...extra,
    });
  }

  router.post('/', enforceContentType, async (req, res) => {
    const reqId = req.requestId ?? null;
    const identity = req.signingIdentity;

    function _block(status, reason, extra) {
      blocked(reqId, null, `SIGN_${reason}`);
      _auditDecision(req, { decision: 'BLOCK', reason, extra });
      return res.status(status).json({ decision: 'BLOCK', reason, details: {}, requestId: reqId });
    }

    // ── Environment scope ────────────────────────────────────────────────────
    // A credential scoped to (say) "staging" must never be usable to sign
    // artifacts on a "production" instance, even if it leaks or is reused
    // there — this is checked on every request, not just at issuance time.
    const serverEnvironment = resolveServerEnvironment();
    if (identity.environment !== serverEnvironment) {
      return _block(403, 'SCOPE_ENVIRONMENT_MISMATCH', {
        identityEnvironment: identity.environment,
        serverEnvironment,
      });
    }

    // Structural body validation via Zod schema (strict — rejects unexpected
    // keys, validates method enum, path byte length, body depth, and ttl range).
    const parsed = signBodySchema.safeParse(req.body);
    if (!parsed.success) {
      const reason = firstQodiqaReason(parsed.error, 'INVALID_REQUEST');
      return _block(400, reason);
    }

    const { request, payload, ttl, v2 } = parsed.data;

    // Normalise HTTP method — validation already confirmed it is a valid verb.
    const normalizedMethod = request.method.trim().toUpperCase();

    const rawPayload = (payload && typeof payload === 'object' && !Array.isArray(payload))
      ? payload : {};
    // (V2-FREEZE 1.2): the single V2 reserved name. Refused (not dropped) on every protocol version, so no V1 artifact can carry it.
    if (Object.keys(rawPayload).some((k) => k.trim().toLowerCase() === 'qodiqa')) return _block(400, 'RESERVED_CLAIM');
    const isV2 = v2 !== undefined;
    let v2Block = null;
    if (isV2) {
      if (!protocolV2.issuesV2()) return _block(400, 'UNSUPPORTED_PROTOCOL_VERSION');
      try { v2Block = protocolV2.validateIssuanceBlock(v2); } catch (err) { if (err instanceof protocolV2.IssuanceError) return _block(400, err.reason, { error: err.message }); throw err; }
      // caller data of a V2 artifact: only `provider` and `claims`
      if (Object.keys(rawPayload).some((k) => k !== 'provider' && k !== 'claims')) return _block(400, 'INVALID_REQUEST', { error: 'a V2 payload may contain only provider and claims' });
      if (rawPayload.claims !== undefined && (rawPayload.claims === null || typeof rawPayload.claims !== 'object' || Array.isArray(rawPayload.claims))) return _block(400, 'INVALID_REQUEST', { error: 'claims must be an object' });
    } else if (request.query !== undefined || request.headers !== undefined) {
      return _block(400, 'INVALID_REQUEST', { error: 'request.query and request.headers are bound only with a v2 block' });
    }
    // (verification): reserved claim names are matched case- and whitespace-insensitively ("TenantId", "tenantid", "tenantId ")
    // so a look-alike key cannot reach a third-party verifier that normalises names; the look-alike is dropped, not signed.
    const _reservedLower = new Set(RESERVED_PAYLOAD_KEYS.map((k) => k.toLowerCase()));
    const _lookalikes = Object.keys(rawPayload).filter((k) => _reservedLower.has(k.trim().toLowerCase()) && !RESERVED_PAYLOAD_KEYS.includes(k));
    const basePayload = _lookalikes.length
      ? Object.fromEntries(Object.entries(rawPayload).filter(([k]) => !_lookalikes.includes(k)))
      : rawPayload;
    if (_lookalikes.length) emit('WARN', 'SIGN_PAYLOAD_RESERVED_KEYS_DISCARDED', { keys: _lookalikes, lookalike: true, requestId: reqId });

    // caller payload keys that /sign sets itself are discarded (anti-spoofing, SIGN-CALLER-03) — now
    // visibly; and QODIQA_SIGN_PAYLOAD_STRICT=true narrows the free-form application context to the single documented claim `provider`.
    const _discarded = RESERVED_PAYLOAD_KEYS.filter((k) => Object.prototype.hasOwnProperty.call(basePayload, k));
    if (_discarded.length) emit('WARN', 'SIGN_PAYLOAD_RESERVED_KEYS_DISCARDED', { keys: _discarded, requestId: reqId });
    if (process.env.QODIQA_SIGN_PAYLOAD_STRICT === 'true') {
      const extra = Object.keys(basePayload).filter((k) => k !== 'provider');
      if (extra.length) return _block(400, 'INVALID_REQUEST');
    }

    // Resolve the AI provider that this artifact authorizes execution against
    // — ONLY when the bound request targets AI execution (see AI_CHAT_PATH
    // comment above). Locked in at sign time (not left to /ai/chat) so the
    // signed artifact is a complete, deterministic authorization — never
    // ambiguous about what it permits. An explicit payload.provider always
    // wins; when omitted, the request is only auto-resolved to the single
    // enabled provider — with more than one enabled, the caller must choose
    // explicitly (no implicit default among ambiguous options).
    const isAiChatRequest = isAiChatRoute(request.path);

    let resolvedProvider = typeof basePayload.provider === 'string' && basePayload.provider
      ? basePayload.provider : null;

    if (isAiChatRequest) {
      if (resolvedProvider) {
        // Same two-step gate, same order, as router.js's _dispatch(): first
        // "does a handler exist for this name" (resolveProvider — REGISTRY),
        // then "is it currently enabled" (getProviderConfig — CONFIGS). This
        // is the identical composition execution.js:61 and router.js:114-124
        // use, so /sign can never accept a name /ai/chat would then reject.
        if (!resolveProvider(resolvedProvider)) {
          return _block(400, 'PROVIDER_NOT_SUPPORTED', { provider: resolvedProvider });
        }
        const providerConfig = getProviderConfig(resolvedProvider);
        if (!providerConfig || !providerConfig.enabled) {
          return _block(400, 'PROVIDER_NOT_CONFIGURED', { provider: resolvedProvider });
        }
      } else {
        // listEnabledProviders() (services/providers.js → router.js) is
        // REGISTRY keys filtered by CONFIGS.enabled — the same function
        // router.js itself exposes, not a re-derivation from config.js alone.
        const enabledProviders = listEnabledProviders();
        if (enabledProviders.length !== 1) {
          blocked(reqId, null, `SIGN_PROVIDER_REQUIRED:${enabledProviders.length}`);
          _auditDecision(req, { decision: 'BLOCK', reason: 'PROVIDER_REQUIRED', extra: { enabledProviders } });
          return res.status(400).json({
            decision:  'BLOCK',
            reason:    'PROVIDER_REQUIRED',
            details:   { enabledProviders },
            requestId: reqId,
          });
        }
        resolvedProvider = enabledProviders[0];
      }

      // ── Provider scope ──────────────────────────────────────────────────────
      // Least privilege: an identity restricted to a subset of providers may
      // never bind an artifact to a provider outside that set, even one the
      // tenant itself has enabled.
      if (Array.isArray(identity.allowedProviders) && !identity.allowedProviders.includes(resolvedProvider)) {
        return _block(403, 'SCOPE_PROVIDER_DENIED', {
          provider: resolvedProvider,
          allowedProviders: identity.allowedProviders,
        });
      }
    }

    // Validate and cap TTL. Clamp to [MIN_TTL_MS, MAX_TTL_MS], then to the
    // identity's own maxTtlMs override when one is configured (tighter than
    // the global cap, never looser) — prevents zero-TTL, multi-day, or
    // over-privileged artifacts.
    //
    // verification refuses any artifact
    // older than MAX_ARTIFACT_AGE_MS (60 s) whatever its expiry says, so /sign
    // no longer grants more: a requested ttl above 60 s is CLAMPED (never
    // rejected — existing callers keep working) and the response says so
    // (meta.ttlClamped, meta.effectiveTtlMs). The default is the max age.
    let resolvedTtl = MAX_ARTIFACT_AGE_MS;
    if (ttl !== undefined && ttl !== null) {
      resolvedTtl = Math.min(Math.max(ttl, MIN_TTL_MS), MAX_TTL_MS);
    }
    if (typeof identity.maxTtlMs === 'number' && identity.maxTtlMs > 0) {
      resolvedTtl = Math.min(resolvedTtl, identity.maxTtlMs);
    }
    const ttlClamped = resolvedTtl > MAX_ARTIFACT_AGE_MS;
    if (ttlClamped) resolvedTtl = MAX_ARTIFACT_AGE_MS;

    let requestHash;
    try {
      if (isV2) {
        // every supplied header must be one of the bound names (lower-case); a bound name that is not supplied is bound as absent (null)
        for (const h of Object.keys(request.headers || {})) if (!v2Block.bind.headers.includes(h)) throw new BindingError('header is not in v2.bind.headers');
        requestHash = computeRequestHashV2FromParts({ method: normalizedMethod, path: request.path, query: request.query, headers: request.headers, body: request.body }, v2Block.bind.headers);
      } else {
        requestHash = computeRequestHash(normalizedMethod, request.path, request.body);
      }
    } catch (err) {
      if (err instanceof BindingError) return _block(400, err.code === 'QUERY_NOT_BINDABLE' ? 'QUERY_NOT_BINDABLE' : 'INVALID_REQUEST', { error: err.reason });
      return _block(400, 'INVALID_REQUEST', { error: err.message });
    }

    // clientId is the AUTHENTICATED identity's own tenantId scope — never an
    // operator-suppliable value and never a single global default. This is
    // the fix for the other half of the oracle: previously every caller
    // (regardless of who they were) signed against the SAME globally
    // configured QODIQA_CLIENT_ID, so there was no per-tenant isolation in
    // this path at all.
    const clientId = identity.tenantId;
    let key;
    try {
      key = keyManager.getSigningKey(clientId);
    } catch (err) {
      return _block(503, 'KEY_UNAVAILABLE', { error: err.message });
    }

    // hash the SAME policy set the execution path will evaluate for this tenant — the tenant-effective set
    // falling back to the global set only when the tenant has no stored set
    // (GLOBAL_FALLBACK), exactly as aiChat.js and verify.js resolve it. clientId (the authenticated identity's
    // tenant) is also the artifact key id's clientId, i.e. the execution path's tenant. Hashing the global set here
    // made POLICY_DRIFT_DETECTED fire on every request of every tenant that has tenant policies.
    let policies;
    try {
      policies = getEffectivePoliciesForTenant(clientId) || getPolicies();
    } catch {
      return _block(503, 'POLICY_UNAVAILABLE');
    }

    let policyHash;
    try {
      policyHash = computePolicyHash(policies);
    } catch (err) {
      return _block(500, 'SIGNING_FAILED', { error: err.message });
    }

    const now       = Date.now();
    const expiresAt = now + resolvedTtl;

    // ── remediation ──────────────────────────────────────────────────
    // TRUST-1 authenticated WHO may call /sign (req.signingIdentity), but that
    // identity used to be discarded after the authz check above — every
    // downstream consumer (consent, audit chain, evidence) fell back to
    // publicKeyId, which is shared by every caller of one tenant's key and
    // therefore proves only which KEY signed, not which CALLER requested the
    // signature.
    //
    // callerContext is an immutable snapshot of the authenticated identity,
    // embedded directly in payload — the same trick requestHash/policyHash
    // already use to get cryptographic protection "for free" from the
    // existing full-envelope Ed25519 signature (signArtifact/validateArtifact
    // sign over the entire {expiry,payload,publicKeyId,timestamp} envelope).
    // No new crypto primitive is introduced; this only widens what payload
    // durably records. Placed AFTER the ...basePayload spread, exactly like
    // requestId/tenantId below, so a client cannot inject a spoofed
    // payload.callerContext — the authenticated value always wins.
    const callerContext = Object.freeze({
      callerId:       identity.id,
      callerName:     identity.name,
      environment:    identity.environment,
      credentialType: identity.credentialType || 'api-key',
    });

    // Inner payload — all fields embedded in the artifact envelope. provider
    // is only injected for AI chat requests (see isAiChatRequest above) — for
    // any other bound path, basePayload.provider (if any) passes through as
    // the caller supplied it, unmodified.
    let innerPayload = {
      ...basePayload,
      ...(isAiChatRequest ? { provider: resolvedProvider } : {}),
      requestId:  crypto.randomUUID(),
      requestHash,
      policyHash,
      tenantId:   parseKeyId(key.keyId).tenantId,
      callerContext,
    };
    if (isV2) {
      // V2-FREEZE 4: only the V1 identity claims, provider, caller `claims` and ONE reserved block; the JCS-P1 limits (depth, NFC, number
      // range, 64 KiB) are enforced here, at issuance.
      let model = v2Block.model;
      if (isAiChatRequest) {
        const bodyModel = typeof request.body.model === 'string' ? request.body.model : null;
        if (model === undefined) model = bodyModel;
        else if (model !== null && bodyModel !== null && model !== bodyModel) return _block(400, 'INVALID_REQUEST', { error: 'v2.model differs from request.body.model' });
      }
      innerPayload = {
        requestId: innerPayload.requestId, requestHash, policyHash, tenantId: innerPayload.tenantId, callerContext,
        ...(isAiChatRequest ? { provider: resolvedProvider } : {}),
        ...(rawPayload.claims !== undefined ? { claims: rawPayload.claims } : {}),
        qodiqa: { v: 2, kind: 'request', bind: v2Block.bind, ...(model !== undefined ? { model } : {}), ...(v2Block.limits ? { limits: v2Block.limits } : {}), ...(v2Block.crit ? { crit: v2Block.crit } : {}) },
      };
      try { canonicalJcsP1(innerPayload, { maxBytes: 65_536 }); } catch (err) {
        if (err instanceof JcsError) return _block(400, 'INVALID_REQUEST', { error: err.code });
        throw err;
      }
    }

    let artifact;
    try {
      const envelope = { expiry: expiresAt, payload: innerPayload, publicKeyId: key.keyId, timestamp: now };
      if (key.nativeSigning) {
        // Vault Transit / HSM — the private key stays in the provider. keyManager.nativeSign re-checks
        // the key's status under the per-key lock; the returned signature is verified against the stored public key BEFORE the
        // artifact is released, so a misconfigured transit key can never hand a client an artifact every verifier rejects.
        artifact = await signArtifactNative(envelope, keyManager.nativeSign);
        if (!verifyEd25519(envelopeHash(envelope), artifact.signature, key.pubDer)) {
          throw new Error('native signature did not verify against the registered public key');
        }
      } else {
        artifact = signArtifact(envelope, key.privDer);
      }
    } catch (err) {
      return _block(500, 'SIGNING_FAILED', { error: err.message });
    }

    _auditDecision(req, {
      decision: 'ALLOW',
      reason:   'SIGNED',
      extra: {
        artifactId:  innerPayload.requestId,
        keyId:       key.keyId,
        expiresAt,
        boundMethod: normalizedMethod,
        boundPath:   request.path,
        provider:    isAiChatRequest ? resolvedProvider : null,
        requestHash,
        policyHash,
      },
    });

    return res.status(200).json({
      artifactId: innerPayload.requestId,
      artifact,
      meta: {
        keyId:     key.keyId,
        expiresAt,
        tenantId:  innerPayload.tenantId,
        callerId:  callerContext.callerId,
        effectiveTtlMs: resolvedTtl,
        ttlClamped,
        ...(isV2 ? { protocolVersion: 2 } : {}),
      },
      requestId: reqId,
    });
  });

  // Reject all other HTTP methods explicitly.
  router.use((req, res) => res.status(405).json({ decision: 'BLOCK', reason: 'METHOD_NOT_ALLOWED', details: {}, requestId: req.requestId ?? null }));

  return router;
};
