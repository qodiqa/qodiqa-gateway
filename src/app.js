'use strict';

// Application composition root.
//
// Owns Express app creation, middleware registration, the global middleware
// chain, route mounting, and error handler registration. This is a
// line-for-line relocation of what previously lived between `const app =
// express()` and the final error handler in server.js — order, middleware
// stack, and route mounting are unchanged.
//
// Does NOT start the server, initialize infrastructure, or bind sockets —
// createApp(ctx) only builds and returns the configured Express app.
// `ctx` supplies the already-constructed middleware instances and policy
// accessors produced by server/startup.js's dependency-initialization phase
// (see that module's header comment for why those are shared instances
// rather than rebuilt here).

const express        = require('express');
require('./runtime/expressAsyncSafety').install(); // audit 2026-10-20 (Z01a R1/R2): async route rejections -> next(err), never process.exit
const path           = require('path');
const { createSecurityHeaders } = require('./infra/security/headers');
const { createCspMiddleware }   = require('./infra/security/csp');
const { createCorsMiddleware } = require('./infra/cors/corsPolicy');
const { createProxyValidationMiddleware } = require('./infra/network/proxyValidation');
const { parseTrustedProxyConfig } = require('./infra/network/clientIpResolver');
const requestId      = require('../middleware/requestId');
const attachClientIp = require('../middleware/clientIp');
const createAiChatRouter = require('./api/routes/aiChat');
const createSignRouter   = require('./api/routes/sign');
const { createKillSwitchAdminRouter } = require('./api/routes/admin/killSwitch');
const { createProvidersAdminRouter } = require('./api/routes/admin/providers');   //
const { createSamlAuthRouter } = require('./api/routes/samlAuth');   //
const { createLdapAuthRouter } = require('./api/routes/ldapAuth');   //
const { createArtifactRevocationsAdminRouter } = require('./api/routes/admin/artifactRevocations');
const { createProofsRouter } = require('./api/routes/proofs');
const { createAgentsRouter } = require('./api/routes/agents');
const { createActionsRouter } = require('./api/routes/actions');
const { createDelegationsRouter } = require('./api/routes/delegations');
const { createToolsRouter } = require('./api/routes/tools');
const { createMcpServersRouter } = require('./api/routes/mcpServers');
const { createApprovalsRouter } = require('./api/routes/approvals');
const { createToolRegistryRouter } = require('./api/routes/toolRegistry');
const { createSessionsRouter } = require('./api/routes/agentSessions');
const { createKillSwitchGate, setKillSwitch } = require('./middleware/killSwitchGate');
setKillSwitch(require('./core/killSwitch'));
const publicKeysRouter   = require('./api/routes/publicKeys');
const keysRouter         = require('./api/routes/keys');
const createVerifyRouter = require('./api/routes/verify');
const wellKnownRouter    = require('./api/routes/well-known');
const publicKeyRouter    = require('./api/routes/public-key');
const auditRouter             = require('./api/routes/audit');
const dashboardRouter         = require('./api/routes/dashboard');
const createAuditViewerRouter      = require('./api/routes/auditViewer');
const createPolicyManagementRouter  = require('./api/routes/policyManagement');
const createPolicyProvenanceRouter  = require('./api/routes/policyProvenance');
const { createEvidenceChainRouter } = require('./api/routes/evidenceChain');
const createEvidenceRouter         = require('./api/routes/evidence');
const { createTransparencyPublicRouter,
        createTransparencyAdminRouter } = require('./api/routes/transparencyLog');
const { createVerificationPortalPublicRouter,
        createVerificationPortalAdminRouter } = require('./api/routes/verificationPortal');
const { createAttestationPublicRouter,
        createAttestationAdminRouter }        = require('./api/routes/attestation');
const { createCertificationPublicRouter,
        createCertificationAdminRouter }      = require('./api/routes/certification');
const { createCertificationBatchRouter }      = require('./api/routes/certificationBatch');
const { createWebhooksAdminRouter }           = require('./api/routes/webhooks');
const { createPrqDlqRouter }                 = require('./api/routes/prqDlq');
const { createOrganizationsAdminRouter }     = require('./api/routes/admin/organizations');
const { createTenantsAdminRouter }           = require('./api/routes/admin/tenants');
const { createDsrRouter }                    = require('./api/routes/admin/dsr');
const { createPolicyGovernanceRouter }       = require('./api/routes/admin/policyGovernance');
const { createPolicySimulateRouter }         = require('./api/routes/policySimulate');
const { createPolicyVisualRouter }           = require('./api/routes/policyVisual');
const { createOpenApiRouter }               = require('./api/routes/openapi');
const { createSigningIdentitiesAdminRouter } = require('./api/routes/admin/signingIdentities');
const { createTenantPortalRouter }          = require('./api/routes/tenantPortal');

const healthRouter         = require('./api/routes/health');
const readyRouter          = require('./api/routes/ready');
const healthRedisRouter    = require('./api/routes/healthRedis');
const metricsRouter        = require('./api/routes/metrics');
const diagnosticsRouter    = require('./api/routes/diagnostics');
const diagnosticsProfileRouter = require('./api/routes/diagnosticsProfile');
const requestDrainModule   = require('./runtime/requestDrain');
const { createEnforcementMiddleware,
        createVerificationMiddleware, createHttpResponseMetrics } = require('./observability/metricsMiddleware');
const { failure }                       = require('./api/response');
const { isBodyTooLarge, assertUtf8Body } = require('./api/bodyParseError'); // R-15 (A-1)
const { blocked }                      = require('../services/logger');
const rbacStore                        = require('./core/rbac/store');
const rbacCustomRoleStore              = require('./core/rbac/customRoleStore');
const createRbacAdminRouter            = require('./api/routes/rbacAdmin');
const keyAdminRouter                   = require('./api/routes/keyAdmin');
const createAuditStoreRouter           = require('./api/routes/auditStore');
const createComplianceRouter           = require('./api/routes/compliance');
const alertingFramework                = require('./alerting');
const { createConsentRouter }          = require('./api/routes/consent');
const { createApiVersionMiddleware }   = require('./middleware/apiVersion');
const { createOptionalAuth }          = require('./middleware/optionalAuth');
const { createMfaStepUp, RBAC_SELF_ENROLL, adminPlaneStepUpWhen } = require('./middleware/mfaStepUp');
// per-request stage timer — OFF by default (QODIQA_BENCH_STAGE_TIMING), refused in production by
// bootValidator; when OFF, ST.wrapMiddleware returns each middleware unchanged and nothing below is mounted.
const ST = require('./observability/stageTimer');

// ── Global fallback handlers (malformed-JSON guard below, the 404 catch-all,
// and the final error handler) run for every path, so they must pick the
// right envelope themselves rather than assuming one. The core protocol
// surface (QODIQA-PROTOCOL-SPEC.md §14.4) and the health/ready/metrics/
// diagnostics probes keep the pre-existing {decision,...} shape; every other
// path — the management/admin API surface — gets the canonical envelope
// (src/api/response.js), matching every route mounted on it above.
const _PROTOCOL_OR_PROBE_PREFIXES = [
  '/ai/chat', '/v1/ai/chat', '/verify', '/v1/verify', '/sign', '/v1/actions', '/v1/delegations', '/v1/tools',
  '/.well-known', '/health', '/ready', '/metrics', '/diagnostics',
];
function _isProtocolOrProbePath(path_) {
  return _PROTOCOL_OR_PROBE_PREFIXES.some(p => path_ === p || path_.startsWith(p + '/'));
}

function createApp(ctx) {
  const app = express();

  // ── Proxy trust — explicit allowlist; never blind global trust ────────────────
  // Single source of truth (src/infra/network/clientIpResolver.js) — this SAME
  // parsed list is what middleware/clientIp.js uses for req.clientIp, so
  // Express's own req.ip and req.clientIp can never disagree about trust.
  const _TRUSTED_PROXY = parseTrustedProxyConfig();
  app.set('trust proxy', _TRUSTED_PROXY);

  // stage timing (bench only) — opens the per-request record first; the bench readout is loopback-only.
  if (ST.ON) {
    app.use(ST.requestMiddleware);
    app.use('/__bench/stages', ST.benchRouter());
    require('./observability/benchSampler').start(); // closure diagnostic: no-op unless QODIQA_BENCH_SAMPLER_PATH
  }

  // ── Security headers — must precede all routes and other middleware ────────────
  app.use(ST.wrapMiddleware('S01', createSecurityHeaders()));

  // ── CSP override — narrows JSON API responses to strict API_CSP
  // Must follow createSecurityHeaders() so the JSON hook can override Helmet's
  // global PORTAL_CSP.  Must precede route handlers so the hook is installed.
  app.use(ST.wrapMiddleware('S02', createCspMiddleware()));

  // ── Proxy validation ───────────────────────────────────────────
  app.use(ST.wrapMiddleware('S03', createProxyValidationMiddleware()));

  // ── CORS — explicit allowlist, no wildcards, fail-closed ──────────────────────
  app.use(ST.wrapMiddleware('S04', createCorsMiddleware()));
  app.use(ST.wrapMiddleware('S05', requestId));
  app.use(ST.wrapMiddleware('S06', attachClientIp));
  app.use(createHttpResponseMetrics()); // every response, bounded labels
  // Distributed tracing — mounted immediately after requestId/clientIp
  // so root spans can attach req.requestId as a span attribute, and before
  // every route below (including /health, /ready) so the full request surface
  // produces trace trees. No-op middleware (calls next() synchronously) when
  // tracing is disabled or failed to initialize — see server/startup.js.
  app.use(ST.wrapMiddleware('S07', ctx.tracing.requestMiddleware));
  // Health and readiness probes are mounted before requestDrain so that:
  //   /health always returns 200 regardless of drain/shutdown state.
  //   /ready returns its own canonical 503 {ready:false} during shutdown,
  //   not the drain's SERVICE_SHUTTING_DOWN shape.
  //
  // /health and /ready are UNAUTHENTICATED by default — this is required for
  // Kubernetes/Docker/ECS probe compatibility and is safe only because both
  // routes are contractually restricted to minimal, non-sensitive output (see
  // src/api/routes/health.js, ready.js, and the content-safety regression test
  // in src/middleware/__tests__/healthContentSafety.test.js). Defense in depth:
  // rate-limited per client IP, subject to the IP allowlist when the operator
  // enables it, and optionally hardened via QODIQA_HEALTH_PROBE_AUTH_REQUIRED /
  // QODIQA_HEALTH_REQUIRE_LOOPBACK (see src/infra/config/opsConfig.js).
  //
  // Metrics and diagnostics carry materially more sensitive operational detail
  // (version, pid, Node version, per-process counters) and remain fully behind
  // the same authenticated, IP-allowlisted, kill-switch-gated path as before —
  // unchanged by this remediation.
  // Mounted BEFORE the plain '/health' prefix below: Express matches use()
  // mounts in registration order, and '/health' would otherwise also match
  // '/health/redis' as a prefix (falling through only because healthRouter has
  // no matching inner route) — registering the more specific path first avoids
  // that fallthrough running the same rate-limit/IP-allow/auth gates twice per
  // request.
  // the probe routes carry NO rate limiter.
  // The Redis-backed limiter that used to front them fails closed when Redis
  // is down, so during exactly the outage class /ready exists to report,
  // every probe got 429 RATE_LIMITED and the documented 503+components
  // readiness contract (docs/deployment/kubernetes-probes.md) was unreachable. Probes
  // are not enforcement routes — the fail-closed posture on enforcement
  // routes is unchanged — and the handlers are near-zero-cost cached reads,
  // so the limiter bought nothing an orchestrator needs. The rejected
  // alternative (approve 429-as-unready) is recorded in the register's.
  // The IP-allowlist / loopback / auth hardening layers are untouched.
  app.use('/health/redis', ctx.opsIpAllow, ctx.healthLoopback, ctx.healthAuth, healthRedisRouter);
  app.use('/health',      ctx.opsIpAllow, ctx.healthLoopback, ctx.healthAuth, healthRouter);
  app.use('/ready',       ctx.opsIpAllow, ctx.healthLoopback, ctx.healthAuth, readyRouter);
  app.use('/metrics',     ...ctx.opsOnlyStack(), metricsRouter);
  app.use('/diagnostics', ...ctx.opsOnlyStack(), diagnosticsRouter);
  // #4: CPU/GC/heap profiling — same opsOnlyStack() as /diagnostics,
  // PLUS ctx.profilingGate, a second and independent kill switch (see
  // src/middleware/profilingEnabled.js) since profiler data carries more
  // performance impact and information-disclosure risk than health-style
  // diagnostics. Deliberately a distinct path, not a sub-route of
  // /diagnostics, so it never inherits that route's established meaning.
  app.use('/diagnostics/profile', ...ctx.opsOnlyStack(), ctx.profilingGate, diagnosticsProfileRouter);
  // Request drain: returns 503 SERVICE_SHUTTING_DOWN for all new requests once
  // shutdown begins.  Must precede body parsing and all enforcement middleware so
  // that no enforcement logic executes after shutdown is initiated.
  app.use(ST.wrapMiddleware('S08', requestDrainModule.middleware));
  app.use(ST.wrapMiddleware('S09', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); }));

  app.use(ST.wrapMiddleware('S10', (req, res, next) => {
    // (SPEC 1.0.1 S-072): the body is UTF-8 only. Invalid byte sequences used to be silently replaced by U+FFFD by the parser, so the
    // bytes that were hashed/bound differ from the bytes that were read; they are now rejected as MALFORMED_JSON.
    express.json({ limit: ctx.maxBodyBytes, verify: (rq, rs, buf) => { assertUtf8Body(rq, rs, buf); rq.rawBody = buf; } })(req, res, (err) => {
      if (err && isBodyTooLarge(err)) {
        // R-15 (A-1): an oversize body is 413 PAYLOAD_TOO_LARGE (it was 400 MALFORMED_JSON).
        blocked(req.requestId, req.headers['x-qodiqa-artifact'] || null, 'PAYLOAD_TOO_LARGE', null);
        if (!_isProtocolOrProbePath(req.path)) {
          return failure(res, 'PAYLOAD_TOO_LARGE', 'Request body exceeds the configured size limit', 413);
        }
        return res.status(413).json({ decision: 'BLOCK', reason: 'PAYLOAD_TOO_LARGE', details: {}, requestId: req.requestId ?? null });
      }
      if (err) {
        blocked(req.requestId, req.headers['x-qodiqa-artifact'] || null, 'MALFORMED_JSON', null);
        if (!_isProtocolOrProbePath(req.path)) {
          return failure(res, 'MALFORMED_JSON', 'Malformed JSON in request body', 400);
        }
        return res.status(400).json({ decision: 'BLOCK', reason: 'MALFORMED_JSON', details: {}, requestId: req.requestId ?? null });
      }
      next();
    });
  }));

  // ── Route handler instances — created once, mounted at both unversioned and v1 paths ──
  // Single handler rule: one router instance per surface; both /path and /v1/path
  // execute the SAME handler object.  No logic is duplicated.
  const _aiChatRouter             = createAiChatRouter({ _getPolicies: ctx.getPolicies, _policyStore: ctx.policyStore });
  const _killGateChat             = createKillSwitchGate({ route: '/ai/chat' });   // first in the chain of every /ai/chat alias
  const _verifyRouter             = createVerifyRouter({ _getPolicies: ctx.getPolicies, _policyStore: ctx.policyStore });
  const _evidenceRouter           = createEvidenceRouter({ _getPolicies: ctx.getPolicies });
  // (D7 → B): public verification routes persist only for an authenticated
  // caller holding the write permission; anonymous calls are ephemeral. A
  // presented-but-invalid credential is refused, never downgraded.
  const _optionalAdmin = (permission) => createOptionalAuth(ctx.adminStack(permission));
  // MFA step-up on privileged mutations. Mounted after
  // the admin stack (req.rbacUser is set); GET/HEAD/OPTIONS never need a code.
  const _mfa              = require('./core/rbac/mfa');
  const _stepUp           = createMfaStepUp({ mfa: _mfa });
  const _stepUpRbac       = createMfaStepUp({ mfa: _mfa, when: (req) => !RBAC_SELF_ENROLL.test(req.path) });
  // State-changing operations are protected according to risk: every other admin-plane mount carries the step-up too, on every mutation except the documented
  // exemptions in src/middleware/mfaStepUp.js STEP_UP_EXEMPTIONS (verify/simulate/visualise endpoints that change no
  // protected state). Mounts NOT carrying it, by design: /portal and /v1/attestation admin (they share their prefix
  // with public verification routes and have no admin mutation except the exempt POST /v1/attestation/chain/verify —
  // src/openapi/mfaStepUpScope.test.js MS-04 fails if one is added), /metrics and /diagnostics (ops-token plane, not
  // admin plane), /tenant-portal (tenant-user sessions, not operators), and the enforcement / public
  // verification surfaces (/ai/chat, /sign, /verify — machine-to-machine, not operator plane).
  const _stepUpAdmin      = createMfaStepUp({ mfa: _mfa, when: adminPlaneStepUpWhen });
  const _transparencyPublicRouter = createTransparencyPublicRouter({ optionalAuth: _optionalAdmin('READ_TRANSPARENCY_LOG') });
  const _transparencyAdminRouter  = createTransparencyAdminRouter({ requirePermission: ctx.requirePermission });
  const _portalPublicRouter       = createVerificationPortalPublicRouter({ optionalAuth: _optionalAdmin('MANAGE_VERIFICATION_PORTAL') });
  const _portalAdminRouter        = createVerificationPortalAdminRouter({ requirePermission: ctx.requirePermission });

  // ── Single execution path ─────────────────────────────────────────────────────
  // ALL AI execution flows through validateBoundRequest → _checkPolicy → _executeAI
  // → executeProviderCall.  No other path to execution exists.
  // _getPolicies and _policyStore are required: policy enforcement is mandatory in
  // production.  Any policy engine failure → BLOCK (fail-closed).
  //
  // OPS-02 (#14): registration ORDER below is load-bearing, not cosmetic —
  // app.use(path, ...) matches by path-SEGMENT PREFIX, and Express tries
  // mounts in registration order, stopping at whichever one responds first.
  // '/ai/chat/stream' starts with '/ai/chat/', so mounting '/ai/chat' first
  // silently swallows every '/ai/chat/stream' request too (the router only
  // ever sees req.url stripped to '/stream', which matches no route, 405ing
  // via the catch-all in aiChat.js) — making the second mount permanently
  // unreachable dead code. This shipped broken until OPS-02 (#14) found it
  // live. Mounting the longer, more specific path FIRST fixes it: it claims
  // its own requests before '/ai/chat' ever gets a chance to prefix-match
  // them, while plain '/ai/chat' requests never match the longer prefix and
  // correctly fall through. Do not reorder these two lines; check any future
  // '/ai/chat/<x>' mount against this same hazard.
  //
  // /ai/chat/stream — convenience alias: identical router, sets stream:true by convention.
  // Clients may POST here with stream:true in the body to access SSE streaming.
  // The same enforcement pipeline runs — there is no shortcut to execution.
  app.use('/ai/chat/stream', _killGateChat, ST.wrapMiddleware('S11', createEnforcementMiddleware()), _aiChatRouter);
  app.use('/ai/chat', _killGateChat, ST.wrapMiddleware('S11', createEnforcementMiddleware()), _aiChatRouter);

  // ── Verification check (dry-run, no execution) ────────────────────────────────
  // _getPolicies and _policyStore ensure /verify/v2 evaluates the SAME policy set
  // as /ai/chat.  The verify router wraps _policyStore in makeDryRunPolicyStore
  // so rate-limit counters are read but never incremented — no side effects.
  app.use('/verify', createVerificationMiddleware(), _verifyRouter);

  // ── Signing ───────────────────────────────────────────────────────────────────
  app.use('/sign', createKillSwitchGate({ route: '/sign' }), createSignRouter(ctx.getPolicies));
  // X-QODIQA-API-Version: mounted BEFORE the first /v1 route. Audit remediation 2026-10-27: it used to sit after /v1/actions .. /v1/admin/dsr,
  // so every /v1 mount registered before it was answered without the header.
  app.use('/v1', createApiVersionMiddleware());
  // Per-action authorisation of an agent: the same credential, scope and limits as /sign
  app.use('/v1/actions', createKillSwitchGate({ route: '/v1/actions' }), createActionsRouter({ getPolicies: ctx.getPolicies }));
  // Delegation of authority between agents: the same credential and limits as /sign
  app.use('/v1/delegations', createKillSwitchGate({ route: '/v1/delegations' }), createDelegationsRouter());
  // The tool gateway: runs one authorised action against a registered MCP server; the same credential and limits as /sign
  app.use('/v1/tools', createKillSwitchGate({ route: '/v1/tools' }), createToolsRouter({ getPolicies: ctx.getPolicies }));

  // ── Public metadata ───────────────────────────────────────────────────────────
  app.use('/.well-known', wellKnownRouter);
  app.use('/public-key',  publicKeyRouter);
  app.use('/public-keys', publicKeysRouter);
  app.use('/keys',        keysRouter);
  app.use('/audit',        ...ctx.adminStack('READ_AUDIT'), _stepUpAdmin, auditRouter);
  app.use('/audit-viewer', ...ctx.adminStack('READ_AUDIT'), _stepUpAdmin, createAuditViewerRouter({ _getPolicies: ctx.getPolicies }));
  // Agent identities and their sessions - operator MFA step-up on every change
  app.use('/v1/agents',   ...ctx.adminStack(), _stepUp, createAgentsRouter({ requirePermission: ctx.requirePermission }));
  app.use('/v1/sessions', ...ctx.adminStack(), _stepUp, createSessionsRouter({ requirePermission: ctx.requirePermission }));
  app.use('/v1/tool-registry', ...ctx.adminStack(), _stepUp, createToolRegistryRouter({ requirePermission: ctx.requirePermission }));   //
  app.use('/v1/mcp/servers', ...ctx.adminStack(), _stepUp, createMcpServersRouter({ requirePermission: ctx.requirePermission }));   //
  // Human approval of agent actions: the decision is a state change by an operator - MFA step-up; the approver is never the requester
  app.use('/v1/approvals', ...ctx.adminStack(), _stepUp, createApprovalsRouter({ requirePermission: ctx.requirePermission }));
  // Downloadable proof of one request — auditor/compliance/admin, read only, every read logged
  app.use('/v1/proofs', ...ctx.adminStack('READ_AUDIT_PROOFS'), _stepUpAdmin, createProofsRouter({ requirePermission: ctx.requirePermission }));
  app.use('/policy-ui',    ...ctx.adminStack(), _stepUp,     createPolicyManagementRouter({ _reloadPolicies: ctx.reloadPolicies, requirePermission: ctx.requirePermission }));
  app.use('/provenance',      ...ctx.adminStack('READ_POLICY_PROVENANCE'), _stepUpAdmin, createPolicyProvenanceRouter({ requirePermission: ctx.requirePermission }));
  app.use('/evidence-chain', ...ctx.adminStack('READ_EVIDENCE_CHAIN'),     _stepUpAdmin, createEvidenceChainRouter({ requirePermission: ctx.requirePermission }));
  app.use('/evidence',       ...ctx.adminStack('GENERATE_EVIDENCE'),       _stepUpAdmin, _evidenceRouter);
  // Transparency Log — public verification endpoints (no auth required)
  app.use('/transparency', _transparencyPublicRouter);
  // Transparency Log — protected admin endpoints (ops auth + RBAC)
  app.use('/transparency', ...ctx.adminStack(), _stepUpAdmin, _transparencyAdminRouter);
  // Verification Portal — public submission and result endpoints (no auth required)
  app.use('/portal', _portalPublicRouter);
  // Verification Portal — protected admin endpoints (ops auth + RBAC)
  app.use('/portal', ...ctx.adminStack(), _portalAdminRouter);
  // Attestation API — public verification endpoints (versioned, no auth required)
  app.use('/v1/attestation', createAttestationPublicRouter({ optionalAuth: _optionalAdmin('MANAGE_ATTESTATIONS') }));
  // Attestation API — protected auditor/admin endpoints (ops auth + RBAC)
  app.use('/v1/attestation', ...ctx.adminStack(), createAttestationAdminRouter({ requirePermission: ctx.requirePermission }));
  // Certification Runtime — public evaluation endpoints (versioned, no auth required)
  //
  // this used to be mounted SECOND, after the admin router, on the
  // theory that mounting admin first was needed to stop the public
  // router's /:certificationId from swallowing /admin/history and
  // /admin/stats. That theory was wrong — Express's path-to-regexp
  // requires an exact segment-count match, so a bare /:certificationId
  // (one segment) never matches a two-segment path like /admin/history
  // regardless of mount order (verified directly against a standalone
  // Express instance before this fix landed, not assumed). The actual
  // effect of admin-first was much worse than the swallowing it was meant
  // to prevent: ctx.adminStack()'s auth middleware is unconditional for
  // the whole mounted prefix, and the admin router's own trailing
  // catch-all (METHOD_NOT_ALLOWED) never calls next() — together these
  // made the ENTIRE public certification API unreachable, authenticated
  // or not. Public-first, admin-second is the same order every sibling
  // split-router file (transparencyLog.js, verificationPortal.js,
  // attestation.js) already uses, for exactly this reason.
  app.use('/v1/certification', createCertificationPublicRouter());
  // Certification Runtime — protected auditor/admin endpoints (ops auth + RBAC)
  app.use('/v1/certification', ...ctx.adminStack(), _stepUpAdmin, createCertificationAdminRouter({ requirePermission: ctx.requirePermission }));
  // Batch Certification API — ops-protected, RBAC-gated
  app.use('/v1/certifications', ...ctx.adminStack(), _stepUpAdmin, createCertificationBatchRouter({ requirePermission: ctx.requirePermission }));
  app.use('/dashboard',    ...ctx.adminStack('VIEW_DASHBOARD'), _stepUpAdmin, dashboardRouter);
  app.use('/key-admin',    ...ctx.adminStack('MANAGE_KEYS'), _stepUp, keyAdminRouter);
  app.use('/rbac',         ...ctx.adminStack(), _stepUpRbac, createRbacAdminRouter({ store: rbacStore, customRoleStore: rbacCustomRoleStore, requirePermission: ctx.requirePermission }));
  app.use('/signing-identities', ...ctx.adminStack(), _stepUp, createSigningIdentitiesAdminRouter({ requirePermission: ctx.requirePermission }));
  app.use('/audit-store',  ...ctx.adminStack(), _stepUpAdmin, createAuditStoreRouter({ requirePermission: ctx.requirePermission }));
  app.use('/compliance',   ...ctx.adminStack(), _stepUpAdmin, createComplianceRouter({ requirePermission: ctx.requirePermission }));
  // the mount-level step-up now gates every /alerts mutation, so the router's own route-level step-up on
  // /:id/suppress is no longer injected — injecting both would demand two codes (the second a replay).
  app.use('/alerts',      ...ctx.adminStack('READ_AUDIT'),     _stepUpAdmin, alertingFramework.createAlertRouter({ requirePermission: ctx.requirePermission }));
  app.use('/consent',     ...ctx.adminStack('MANAGE_CONSENT'), _stepUpAdmin, createConsentRouter());
  // Tenant self-service portal — mounted ONLY when QODIQA_PORTAL_ENABLED
  // ==='true'; the route tree does not exist at all otherwise. Deliberately
  // NOT behind ctx.adminStack() — that stack authenticates via per-operator
  // ok_ API keys (createOpsAuthMiddleware), a different identity space from
  // tenant-portal users. Uses its own rate limiter + portalSessionAuth +
  // the SAME reused rbacResolve/requirePermission RBAC entry points. See
  // src/api/routes/tenantPortal.js and src/middleware/portalAuth.js.
  if (ctx.portalEnabled) {
    app.use('/tenant-portal', createTenantPortalRouter({
      requirePermission: ctx.requirePermission,
      portalSessionAuth: ctx.portalSessionAuth,
      rbacResolve:       ctx.rbacResolve,
      rateLimit:         ctx.portalRateLimit,
    }));
  }
  // SAML single sign-on - public by nature. Always mounted so the contract is stable; every route answers 404 unless QODIQA_SAML_CONFIG_PATH names that provider (a bad file fails the start).
  require('./core/identity/samlService').assertConfigured();
  app.use('/auth/saml', createSamlAuthRouter());
  // LDAP / Active Directory password sign-in - public by nature, same rule: 404 unless QODIQA_LDAP_CONFIG_PATH names the provider (a bad file fails the start).
  require('./core/identity/ldapService').assertConfigured();
  app.use('/auth/ldap', createLdapAuthRouter());
  // Webhooks — admin-only endpoint management; secrets returned once at creation
  app.use('/v1/webhooks', ...ctx.adminStack(), _stepUp, createWebhooksAdminRouter({ requirePermission: ctx.requirePermission }));
  // Persistence Recovery DLQ management — admin inspection and remediation
  app.use('/v1/prq', ...ctx.adminStack(), _stepUp, createPrqDlqRouter({ requirePermission: ctx.requirePermission }));
  // Organization administration — Component #39
  app.use('/v1/admin/organizations', ...ctx.adminStack('MANAGE_USERS'), _stepUp, createOrganizationsAdminRouter());
  // Tenant administration — Component #39
  app.use('/v1/admin/tenants', ...ctx.adminStack('MANAGE_USERS'), _stepUp, createTenantsAdminRouter());
  // Global kill switch — admin only, operator MFA step-up on every change
  app.use('/v1/admin/kill-switch', ...ctx.adminStack(), _stepUp, createKillSwitchAdminRouter({ requirePermission: ctx.requirePermission }));
  app.use('/v1/admin/providers', ...ctx.adminStack(), _stepUp, createProvidersAdminRouter({ requirePermission: ctx.requirePermission, getPolicies: ctx.getPolicies }));   //
  // Per-artifact revocation — admin only, operator MFA step-up on every change
  app.use('/v1/admin/artifact-revocations', ...ctx.adminStack(), _stepUp, createArtifactRevocationsAdminRouter({ requirePermission: ctx.requirePermission }));
  // Policy Governance / Maker-Checker administration — Component #45
  // fix: mounted BEFORE the broader /v1/policy prefix below. Express
  // matches app.use() mounts in registration order, and /v1/policy is a
  // strict prefix of /v1/policy/governance — mounting the broad prefix
  // first let policySimulateRouter's own next-less 405 catch-all
  // (policySimulate.js's `router.use((req, res) => ...)`, no `next` param)
  // swallow every /v1/policy/governance/* request before this router was
  // ever reached. See Findings Register.
  app.use('/v1/policy/governance', ...ctx.adminStack(), _stepUpAdmin, createPolicyGovernanceRouter({ requirePermission: ctx.requirePermission, _reloadPolicies: ctx.reloadPolicies }));
  // Policy Simulation Engine — Component #40
  // the visual router used to be mounted AFTER the simulate router
  // on the same /v1/policy prefix, and policySimulate.js ends in a next-less
  // 405 catch-all, so every /v1/policy/visual/* request got 405. It is now
  // mounted on its own narrower prefix BEFORE the broad one (same fix shape
  // as the governance mount above). The router's own routes are declared as
  // '/visual/...', so the mount-stripped prefix is restored before handing
  // over. Neither router's 405 catch-all is changed.
  const _policyVisualRouter = createPolicyVisualRouter(ctx.getPolicies);
  app.use('/v1/policy/visual', ...ctx.adminStack('READ_POLICIES'), _stepUpAdmin, (req, res, next) => {
    req.url = '/visual' + req.url;
    _policyVisualRouter(req, res, next);
  });
  app.use('/v1/policy', ...ctx.adminStack('READ_POLICIES'), _stepUpAdmin, createPolicySimulateRouter(ctx.getPolicies, ctx.policyStore));
  // GDPR Data Subject Rights administration — Component #44
  app.use('/v1/admin/dsr', ...ctx.adminStack(), _stepUp, createDsrRouter({ requirePermission: ctx.requirePermission }));

  // ── API v1 versioned routes ───────────────────────────────────────────────────
  // Each /v1/* path is an alias to the IDENTICAL handler instance already mounted
  // at the unversioned path above.  No logic is duplicated — the same router
  // object handles both.  The version header middleware stamps every response
  // routed through /v1 so clients can detect which API generation is in use.
  //
  // Future versions (/v2, /v3) follow the same pattern: create a new router
  // factory where behavior diverges; alias unchanged surfaces to the v1 instance.
  // (the version header middleware is mounted ahead of the first /v1 route, above, so every /v1 mount carries the header)
  // /v1/ai/chat/stream — versioned streaming alias. Same mount-order hazard
  // as the /ai/chat pair above — must be registered before /v1/ai/chat, not
  // after. See that mount site's comment for the full explanation.
  app.use('/v1/ai/chat/stream', _killGateChat, createEnforcementMiddleware(), _aiChatRouter);
  // /v1/ai/chat — identical to /ai/chat
  app.use('/v1/ai/chat', _killGateChat, createEnforcementMiddleware(), _aiChatRouter);
  // /v1/verify — identical to /verify
  app.use('/v1/verify', createVerificationMiddleware(), _verifyRouter);
  // /v1/evidence — identical to /evidence (ops-auth + RBAC preserved)
  app.use('/v1/evidence', ...ctx.adminStack('GENERATE_EVIDENCE'), _stepUpAdmin, _evidenceRouter);
  // /v1/transparency — public + admin, identical to /transparency
  app.use('/v1/transparency', _transparencyPublicRouter);
  app.use('/v1/transparency', ...ctx.adminStack(), _stepUpAdmin, _transparencyAdminRouter);
  // /v1/portal — public + admin, identical to /portal
  app.use('/v1/portal', _portalPublicRouter);
  app.use('/v1/portal', ...ctx.adminStack(), _portalAdminRouter);

  // OpenAPI spec + Swagger UI — public, no auth (spec contains no secrets)
  app.use('/', createOpenApiRouter());

  app.use(express.static(path.join(__dirname, '..', 'public')));

  app.use((req, res) => {
    if (!_isProtocolOrProbePath(req.path)) {
      return failure(res, 'NOT_FOUND', 'Not found', 404);
    }
    return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND', details: {}, requestId: req.requestId ?? null });
  });

  app.use((err, req, res, _next) => {
    blocked(req.requestId, null, err?.message || 'UNHANDLED_ERROR', null);
    // a control-plane refusal (stale snapshot 503, stale write 409)
    // thrown from any route keeps its status and code — never a generic 500.
    if (!res.headersSent && err && err.name === 'ControlPlaneError') {
      if (!_isProtocolOrProbePath(req.path)) return failure(res, err.code, err.message, err.status);
      return res.status(err.status).json({ decision: 'BLOCK', reason: err.code, details: {}, requestId: req.requestId ?? null });
    }
    if (!res.headersSent) {
      if (!_isProtocolOrProbePath(req.path)) {
        return failure(res, 'INTERNAL_ERROR', 'Internal server error', 500);
      }
      res.status(500).json({ decision: 'BLOCK', reason: 'INTERNAL_ERROR', details: {}, requestId: req.requestId ?? null });
    }
  });

  return app;
}

module.exports = { createApp };
