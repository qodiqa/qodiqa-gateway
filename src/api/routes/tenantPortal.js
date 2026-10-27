'use strict';

/**
 * Tenant Self-Service Portal —
 *
 * Mounted at /tenant-portal only when QODIQA_PORTAL_ENABLED === 'true' (see
 * src/app.js) — the feature does not exist at all in a deployment that
 * never opts in, matching this codebase's existing optional-capability
 * pattern (e.g. QODIQA_KMS_PROVIDER's non-local backends).
 *
 * Routes:
 *   GET  /tenant-portal/login             — begin OIDC Authorization Code
 *                                            + PKCE flow (redirect to IdP)
 *   GET  /tenant-portal/callback          — OIDC redirect target; exchanges
 *                                            the code, validates the ID
 *                                            token, resolves/creates the
 *                                            tenant-portal user, mints a
 *                                            session token
 *   GET  /tenant-portal/dev-login         — NON-PRODUCTION ONLY stub login
 *                                            (see the guard below and
 *)
 * POST /tenant-portal/logout — authenticated; revokes
 *                                            the caller's sessions server-
 *                                            side (session-version bump; see
 *)
 *   GET  /tenant-portal/api/me            — READ_TENANT_IDENTITY
 *   GET  /tenant-portal/api/keys          — READ_TENANT_KEYS
 *   GET  /tenant-portal/api/consent       — READ_TENANT_CONSENT
 * GET /tenant-portal/api/usage — READ_TENANT_USAGE
 * GET /tenant-portal/api/usage/export — READ_TENANT_USAGE
 *
 * TENANT ISOLATION (see src/middleware/portalAuth.js's header comment for
 * the full chain): every /api/* handler below reads ONLY
 * req.tenantContext.tenantId, set exclusively by portalSessionAuth from
 * the validated, server-signed session token. No handler in this file
 * reads req.headers['x-tenant-id'], req.query.tenantId, req.body.tenantId,
 * or any other client-supplied value as tenant identity — search this file
 * for "tenantContext" to verify that directly.
 */

const { Router } = require('express');
const crypto = require('crypto');

const oidcClient       = require('../../core/portal/oidcClient');
const tenantRegistry    = require('../../core/tenancy/tenantRegistry');
const portalUserStore   = require('../../core/portal/tenantPortalUserStore');
const consentRegistry   = require('../../core/consent');
const tenantKeyManager  = require('../../../services/artifact/tenantKeyManager');
const usageMeteringService = require('../../core/usage/usageMeteringService');
const { sanitizeCsvCell } = require('../../utils/csvSanitize');
const { mintSessionToken } = require('../../../services/portal/portalSessionToken');
const { mintFlowState, verifyFlowState } = require('../../../services/portal/oidcFlowState');
const { emit } = require('../../../services/logger');
const assurance = require('../../core/identity/assurance');   //
const { success, failure, internalError } = require('../response');

// Safe, generic, user-facing error codes — never the underlying exception
// message (see this file's error-handling notes below and
//'s "Failure behavior" section).
const LOGIN_ERROR_REDIRECT = '/tenant-login.html';

// the record's session version, normalised exactly like
// tenantPortalUserStore.sessionVersionOf() and src/middleware/portalAuth.js
// (absent / invalid = 0, i.e. never revoked), so the minted token's `sv`
// always equals what the middleware will compare it against.
function _sessionVersion(rec) {
  const v = rec ? rec.sessionVersion : undefined;
  return Number.isSafeInteger(v) && v >= 0 ? v : 0;
}

function _redirectWithError(res, code) {
  // A fixed, local, relative path — never anything derived from request
  // input — so this can never become an open redirect. See §18's "open
  // redirect" requirement.
  res.redirect(`${LOGIN_ERROR_REDIRECT}?error=${encodeURIComponent(code)}`);
}

/**
 * @param {object} deps
 * @param {(permission: string) => import('express').RequestHandler} deps.requirePermission
 *   — src/core/rbac/authorize.js's isPermitted, composed by
 *   src/middleware/rbac.js's createRequirePermission() — the SAME function
 *   every admin route already uses. No new authorization mechanism.
 * @param {import('express').RequestHandler} deps.portalSessionAuth
 *   — src/middleware/portalAuth.js's createPortalSessionMiddleware(), fully
 *   constructed by the composition root (server/startup.js).
 * @param {import('express').RequestHandler} deps.rbacResolve
 *   — src/middleware/rbac.js's createRbacResolveMiddleware() — REUSED
 *   unchanged; it only checks `if (req.rbacUser) next()`, which
 *   portalSessionAuth already satisfies.
 * @param {import('express').RequestHandler} deps.rateLimit
 *   — a createRateLimitMiddleware('tenant_portal', ...) instance, applied
 *   to every route in this router (public and authenticated alike).
 */
function createTenantPortalRouter({ requirePermission, portalSessionAuth, rbacResolve, rateLimit }) {
  const router = Router();

  router.use(rateLimit);

  // ── Public: begin login ──────────────────────────────────────────────────

  router.get('/login', async (req, res) => {
    try {
      const nonce        = crypto.randomBytes(16).toString('hex');
      const codeVerifier = crypto.randomBytes(32).toString('base64url');
      const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
      const state = mintFlowState({ nonce, codeVerifier });

      const authUrl = await oidcClient.buildAuthorizationUrl({ state, nonce, codeChallenge });
      emit('INFO', 'PORTAL_LOGIN_STARTED', { requestId: req.requestId ?? null });
      res.redirect(authUrl);
    } catch (err) {
      // Never expose IdP/library internals to the browser — see §19.
      emit('ERROR', 'PORTAL_LOGIN_INIT_FAILED', { requestId: req.requestId ?? null, error: err.message });
      _redirectWithError(res, 'login_unavailable');
    }
  });

  // ── Public: OIDC callback ────────────────────────────────────────────────

  router.get('/callback', async (req, res) => {
    const requestId = req.requestId ?? null;

    // req.query.state is attacker/IdP-controlled input at this point — it
    // is validated (signature + TTL) by verifyFlowState() below before ANY
    // of its contents (nonce, codeVerifier) are trusted. This IS the
    // CSRF/replay defense for the callback — see oidcFlowState.js's header
    // comment.
    const flow = verifyFlowState(typeof req.query.state === 'string' ? req.query.state : null);
    if (!flow) {
      emit('WARN', 'PORTAL_CALLBACK_INVALID_STATE', { requestId });
      return _redirectWithError(res, 'invalid_request');
    }

    let claims;
    try {
      const result = await oidcClient.exchangeCode({
        callbackParams: { code: req.query.code, state: req.query.state, iss: req.query.iss },
        codeVerifier:   flow.codeVerifier,
        expectedState:  req.query.state,
        expectedNonce:  flow.nonce,
      });
      claims = result.claims;
    } catch (err) {
      // Covers EVERY IdP/token-exchange failure mode uniformly (invalid
      // code, issuer/audience/signature/expiry/nonce mismatch, network
      // failure) — the user-facing outcome never distinguishes which
      // check failed (see §19: "do not leak whether another tenant/user
      // exists" applies equally to not leaking WHY authentication failed).
      emit('WARN', 'PORTAL_CALLBACK_TOKEN_EXCHANGE_FAILED', { requestId, error: err.message });
      return _redirectWithError(res, 'authentication_failed');
    }

    const tenantClaimName = process.env.QODIQA_OIDC_TENANT_CLAIM || 'tenant_id';
    const claimedTenantId = claims[tenantClaimName];

    // FAIL CLOSED: the tenant claim must name a tenant that ALREADY EXISTS
    // and is ACTIVE in tenantRegistry.js. An IdP asserting an unknown or
    // suspended/disabled tenant never reaches JIT provisioning — there is
    // no "create the tenant too" path here ('s
    // exclusions: tenant provisioning is out of scope).
    const tenantCheck = tenantRegistry.assertActiveTenant(
      typeof claimedTenantId === 'string' ? claimedTenantId : null,
    );
    if (!tenantCheck.valid) {
      emit('WARN', 'PORTAL_CALLBACK_TENANT_REJECTED', { requestId, reason: tenantCheck.reason });
      return _redirectWithError(res, 'tenant_not_provisioned');
    }

    if (typeof claims.sub !== 'string' || claims.sub.length === 0 || typeof claims.iss !== 'string') {
      emit('WARN', 'PORTAL_CALLBACK_MISSING_CLAIMS', { requestId });
      return _redirectWithError(res, 'authentication_failed');
    }

    // second factor for portal users - done at the identity provider, vouched for in the ID token (amr / acr + a recent auth_time). Opt-in, fail closed.
    if (assurance.required() && !assurance.portalAssured(claims)) {
      emit('WARN', 'PORTAL_CALLBACK_MFA_REQUIRED', { requestId });
      return _redirectWithError(res, 'mfa_required');
    }

    let portalUser;
    try {
      portalUser = await portalUserStore.findOrCreateByIdpSubject({
        idpIssuer:  claims.iss,
        idpSubject: claims.sub,
        tenantId:   tenantCheck.tenant.tenantId,
        email:      typeof claims.email === 'string' ? claims.email : null,
      });
    } catch (err) {
      // a control-plane refusal (stale snapshot / write conflict) fails the login closed.
      emit('ERROR', 'PORTAL_USER_RESOLVE_FAILED', { requestId, error: err.message, code: err.code ?? null });
      return _redirectWithError(res, 'login_unavailable');
    }

    if (!portalUser.enabled) {
      emit('WARN', 'PORTAL_CALLBACK_USER_DISABLED', { requestId, userId: portalUser.id });
      return _redirectWithError(res, 'account_disabled');
    }

    const sessionToken = mintSessionToken({
      portalUserId:   portalUser.id,
      tenantId:       portalUser.tenantId,
      role:           portalUser.role,
      sessionVersion: _sessionVersion(portalUser), //
    });

    emit('INFO', 'PORTAL_LOGIN_SUCCESS', { requestId, userId: portalUser.id, tenantId: portalUser.tenantId });

    // The token is passed in the URL FRAGMENT (#), never the query string —
    // fragments are never sent to the server (not logged in access logs,
    // never appear in Referer headers) and are only visible to
    // same-origin JavaScript. public/js/tenant-portal-login.js reads it,
    // moves it into sessionStorage, then strips it via
    // history.replaceState(). See §17's "do not store long-lived tokens in
    // localStorage" guidance — this uses sessionStorage (cleared when the
    // tab closes), not localStorage.
    res.redirect(`/tenant-portal.html#token=${encodeURIComponent(sessionToken)}`);
  });

  // ── NON-PRODUCTION ONLY: development authentication stub ────────────────
  //
  // Mounted UNCONDITIONALLY at the Express-route level (Express itself has
  // no runtime "unmount" primitive), but hard-gated at the TOP of the
  // handler by BOTH NODE_ENV and QODIQA_PORTAL_DEV_AUTH_ENABLED — and
  // server/startup.js additionally FATALs at startup (see that file) if
  // NODE_ENV==='production' and QODIQA_PORTAL_DEV_AUTH_ENABLED==='true' is
  // ever configured together, so this combination cannot silently exist in
  // a running production process at all. Belt-and-suspenders: even if
  // that startup gate were somehow bypassed, the check below independently
  // refuses the request. See __tests__/tenantPortal.test.js's
  // "production cannot use development authentication" suite and
  //'s "Local development/test strategy" section.
  router.get('/dev-login', async (req, res) => {
    const requestId = req.requestId ?? null;
    if (process.env.NODE_ENV === 'production' || process.env.QODIQA_PORTAL_DEV_AUTH_ENABLED !== 'true') {
      emit('WARN', 'PORTAL_DEV_AUTH_DENIED', { requestId, nodeEnv: process.env.NODE_ENV ?? null });
      return failure(res, 'NOT_FOUND', 'Not found', 404);
    }

    const tenantId = typeof req.query.tenantId === 'string' ? req.query.tenantId : null;
    const tenantCheck = tenantRegistry.assertActiveTenant(tenantId);
    if (!tenantCheck.valid) {
      return failure(res, 'BAD_REQUEST', 'Unknown or inactive tenantId', 400);
    }

    let portalUser;
    try {
      portalUser = await portalUserStore.findOrCreateByIdpSubject({
      idpIssuer:  'dev-auth-stub',
      idpSubject: `dev-user-${tenantCheck.tenant.tenantId}`,
      tenantId:   tenantCheck.tenant.tenantId,
      email:      `dev@${tenantCheck.tenant.tenantId}.local`,
      });
    } catch (err) {
      return failure(res, err.code || 'PORTAL_USER_RESOLVE_FAILED', 'Unable to resolve the portal user', err.status || 503);
    }

    const sessionToken = mintSessionToken({
      portalUserId:   portalUser.id,
      tenantId:       portalUser.tenantId,
      role:           portalUser.role,
      sessionVersion: _sessionVersion(portalUser), //
    });

    emit('WARN', 'PORTAL_DEV_AUTH_USED', { requestId, tenantId: portalUser.tenantId });
    res.redirect(`/tenant-portal.html#token=${encodeURIComponent(sessionToken)}`);
  });

  // ── Logout ─────────────────────────────────────────
  //
  // Authenticated by the SAME portalSessionAuth as /api/* — a missing,
  // invalid, expired or already-revoked token is 401 (before this
  // route was an unauthenticated audit-only no-op; the client already sends
  // its bearer token here and clears its own storage whatever the answer,
  // see public/js/tenant-portal.js). It then revokes the caller's sessions
  // server-side by incrementing their record's session version: the
  // presented token, and every other session of the same portal user, stops
  // working on its next request. Granularity is per USER, not per token —
  // logout signs the user out on every tab/device (there is no per-token
  // deny-list). Only the caller's OWN record is
  // touched — the id comes from the authenticated session, never from the
  // body/query.
  router.post('/logout', portalSessionAuth, async (req, res) => {
    const userId = req.portalSession.portalUserId;
    try {
      const rec = await portalUserStore.revokeSessions(userId, { reason: 'self_logout' });
      if (!rec) return failure(res, 'UNAUTHORIZED', 'Authentication required', 401);
      emit('INFO', 'PORTAL_LOGOUT', { requestId: req.requestId ?? null, userId, sessionsRevoked: true });
      return success(res, { loggedOut: true, sessionsRevoked: true });
    } catch (err) {
      // Fail closed and say so: the client must not believe the server-side
      // session ended when the write was refused (control-plane conflict/stale).
      emit('ERROR', 'PORTAL_LOGOUT_REVOKE_FAILED', { requestId: req.requestId ?? null, userId, error: err.message, code: err.code ?? null });
      return failure(res, 'PORTAL_LOGOUT_FAILED', 'Unable to end the session server-side; retry', 503);
    }
  });

  // ── Authenticated API surface ────────────────────────────────────────────

  const api = Router();
  api.use(portalSessionAuth, rbacResolve);

  api.get('/me', requirePermission('READ_TENANT_IDENTITY'), (req, res) => {
    const tenant = tenantRegistry.getTenant(req.tenantContext.tenantId);
    return success(res, {
      tenantId:   req.tenantContext.tenantId,
      tenantName: tenant ? tenant.tenantName : null,
      email:      req.rbacUser.username,
      role:       req.rbacUser.role,
    });
  });

  api.get('/keys', requirePermission('READ_TENANT_KEYS'), (req, res) => {
    try {
      const status = tenantKeyManager.getTenantKeyStatus(req.tenantContext.tenantId);
      // getTenantKeyStatus() already returns ONLY safe metadata (keyId,
      // version, status, createdAt/expiresAt/rotationDeadline,
      // day-counts, issues) — see services/artifact/tenantKeyManager.js's
      // _computeTenantStatus(); this handler adds no fields and strips
      // none, it is a pure pass-through of an EXISTING, already-audited
      // safe surface. Never contains publicKeyB64/private material by
      // construction (that function does not read them).
      return success(res, status);
    } catch (err) {
      return internalError(res, req, err, { label: 'PORTAL_KEYS_QUERY_FAILED', extra: { tenantId: req.tenantContext.tenantId } });
    }
  });

  api.get('/consent', requirePermission('READ_TENANT_CONSENT'), async (req, res) => {
    try {
      // tenant_id here is ALWAYS req.tenantContext.tenantId — server-derived,
      // never req.query.tenantId or any other client input. ConsentStore's
      // list() (via src/core/consent) internally routes a non-null tenant_id
      // through pool.withTenantTransaction(), which sets qodiqa.tenant_id
      // RLS context — the SAME reused, already-tested tenant
      // isolation mechanism the admin /consent router's own tenant-filtered
      // reads use. No new query, no new isolation logic.
      const { records, total } = await consentRegistry.list({
        tenant_id: req.tenantContext.tenantId,
        limit: 50,
        offset: 0,
      });
      return success(res, {
        records: records.map((r) => ({
          id:         r.id,
          actorId:    r.actor_id,
          action:     r.action,
          state:      r.state,
          version:    r.version,
          grantedAt:  r.granted_at,
          revokedAt:  r.revoked_at ?? null,
        })),
        total,
      });
    } catch (err) {
      return internalError(res, req, err, { label: 'PORTAL_CONSENT_QUERY_FAILED', extra: { tenantId: req.tenantContext.tenantId } });
    }
  });

  // Action 2 — usage metering API + CSV export. Both handlers read
  // ONLY req.tenantContext.tenantId (server-derived, see the file header
  // comment) and share one aggregation call so the JSON and CSV surfaces
  // can never disagree — see usageMeteringService.js's own header.
  function _usageQueryRange(req) {
    return {
      from: typeof req.query.from === 'string' ? req.query.from : undefined,
      to:   typeof req.query.to   === 'string' ? req.query.to   : undefined,
    };
  }

  function _usageErrorStatus(err) {
    return (err.code === 'USAGE_INVALID_RANGE' || err.code === 'USAGE_INVALID_TENANT') ? 400 : null;
  }

  api.get('/usage', requirePermission('READ_TENANT_USAGE'), async (req, res) => {
    try {
      const result = await usageMeteringService.aggregateTenantUsage({
        tenantId: req.tenantContext.tenantId,
        ..._usageQueryRange(req),
      });
      return success(res, result);
    } catch (err) {
      const status = _usageErrorStatus(err);
      if (status) return failure(res, err.code, err.message, status);
      return internalError(res, req, err, { label: 'PORTAL_USAGE_QUERY_FAILED', extra: { tenantId: req.tenantContext.tenantId } });
    }
  });

  api.get('/usage/export', requirePermission('READ_TENANT_USAGE'), async (req, res) => {
    try {
      const { totals, series } = await usageMeteringService.aggregateTenantUsage({
        tenantId: req.tenantContext.tenantId,
        ..._usageQueryRange(req),
      });
      // Same convention as src/api/routes/auditViewer.js's CSV export:
      // sanitizeCsvCell() per cell (INJ-7 formula-injection neutralization +
      // quote-escaping) and CRLF row separators (RFC 4180).
      const cols = ['day', 'executions', 'inputTokens', 'outputTokens', 'totalTokens'];
      const rows = series.map((r) => cols.map((c) => sanitizeCsvCell(r[c])).join(','));
      const totalRow = ['TOTAL', totals.executions, totals.inputTokens, totals.outputTokens, totals.totalTokens]
        .map((v) => sanitizeCsvCell(v)).join(',');
      const csv = [cols.join(','), ...rows, totalRow].join('\r\n');
      res.set('Content-Type', 'text/csv; charset=utf-8');
      res.set('Content-Disposition', 'attachment; filename="qodiqa-tenant-usage.csv"');
      return res.send(csv);
    } catch (err) {
      const status = _usageErrorStatus(err);
      if (status) return failure(res, err.code, err.message, status);
      return internalError(res, req, err, { label: 'PORTAL_USAGE_EXPORT_FAILED', extra: { tenantId: req.tenantContext.tenantId } });
    }
  });

  router.use('/api', api);

  return router;
}

module.exports = { createTenantPortalRouter };
