'use strict';

// Startup lifecycle module.
//
// Owns dependency initialization, startup sequencing, infrastructure
// bootstrap, HTTP server creation, and listening on the configured port.
// This is a line-for-line relocation of what previously ran at module scope
// and inside startServer() in server.js — behavior, order, and timing are
// unchanged. Only require() paths were adjusted for this file's location
// one directory below the repo root.
//
// Exports:
//   ctx         — values the composition root (src/app.js) needs to build
//                 the Express app: already-constructed middleware instances,
//                 policy accessors, and the shared rate-limit store. These
//                 are exposed here (not rebuilt in src/app.js) because
//                 several of them (e.g. the ops-auth lockout) are explicitly
//                 required to be a single shared instance across every
//                 surface that uses them — rebuilding them in a second
//                 module would silently create divergent instances.
//   startServer — async function(app); starts accepting traffic and
//                 performs the full startup sequence documented inline
//                 below.

// ── apply process-level security controls before anything else ──
const { applyProcessHardening } = require('../src/runtime/processHardening');
applyProcessHardening();

require('dotenv').config();

// the MAC keyring key file is created HERE, at boot, outside production (a request path never writes it). Production never creates it: the assertUsable() block below
// (and the boot validator) stop the start when it is missing.
if (process.env.NODE_ENV !== 'production') {
  try { require('../src/core/security/macKeyring').init(); } catch (err) { console.error(`MAC keyring could not be provisioned: ${err.message}`); process.exit(1); }
}

// ── deployment mode resolution — must run before every other require
// below that reads QODIQA_PG_ENABLED / QODIQA_AUDIT_ORDERING_MODE, most
// notably src/core/audit/multiInstanceGuard.js (computes its ORDERING_MODE
// constant at require() time) and src/infra/postgres/pool.js (reads
// QODIQA_PG_ENABLED live, but only once this module's own top-level
// pgPool.initialize() call runs, further down this file). See
// src/infra/config/deploymentMode.js's header comment for the full
// precedence model — this call is a no-op on the legacy vars whenever
// QODIQA_DEPLOYMENT_MODE is left unset.
const { applyDeploymentMode } = require('../src/infra/config/deploymentMode');
applyDeploymentMode();

const path            = require('path');
const http            = require('http');
const { runCorsValidation } = require('../src/infra/cors/corsPolicy');
const { validateProxyConfig } = require('../src/infra/network/proxyValidation');
const { configureTlsDefaults } = require('../src/infra/network/tlsDefaults');

const { loadPolicies, resolvePolicyFilePath } = require('../services/policy/loader');
const rateLimitStoreModule = require('../services/policy/store');
const keyManager         = require('../services/artifact/keyManager');
const nonceStore         = require('../src/validation/nonceStore');
const anomalyStore       = require('../src/validation/anomalyStore');
const idempotencyStore   = require('../src/core/idempotency/idempotencyStore');
const { getConfigSummary } = require('../src/infra/redis/clientConfig');
const requestDrainModule   = require('../src/runtime/requestDrain');
const eventLoopMonitor     = require('../src/runtime/eventLoopMonitor');
const redisPersistenceMonitor = require('../src/infra/redis/persistenceMonitor');
const keyExpiryMonitor    = require('../services/artifact/keyExpiryMonitor');
const latencySlaMonitor   = require('../src/observability/latencySlaMonitor');
const { registerHandlers: _registerShutdownHandlers } = require('../src/runtime/shutdown');
const { emitStartupDiagnostics, emitClockDiagnostics } = require('../src/runtime/startupDiagnostics');
const readinessStateModule = require('../src/runtime/readinessState');
const metricsModule        = require('../src/observability/metrics');
const { initTracing, loadTracingConfig } = require('../src/observability/tracing');
const { initMetricsOtlpBridge, loadMetricsExportConfig } = require('../src/observability/metricsExport');
const { runBootValidation }            = require('../src/infra/config/bootValidator');
const { emitBootReport: _emitBootReport } = require('../src/infra/config/bootReport');
const { loadOpsConfig }                = require('../src/infra/config/opsConfig');
const { createOpsAuthMiddleware }      = require('../src/middleware/opsAuth');
const { createOpsIpAllowlistMiddleware } = require('../src/middleware/opsIpAllowlist');
const { createOpsDiagnosticsGate, createOpsAdminGate, createOpsDiagnosticsPreAuthGate, createOpsAdminPreAuthGate } = require('../src/middleware/opsEnabled');
const { createProfilingDiagnosticsGate } = require('../src/middleware/profilingEnabled');
const { createHealthAuthMiddleware }     = require('../src/middleware/healthAuth');
const { createHealthLoopbackMiddleware } = require('../src/middleware/healthLoopback');
const { createRbacResolveMiddleware,
        createRequirePermission,
        loadRbacConfig }               = require('../src/middleware/rbac');
const { isPermitted: _rbacIsPermitted,
        isValidPermission: _rbacIsValidPermission } = require('../src/core/rbac/authorize');
const { createAdminProtection }        = require('../src/middleware/adminProtection');
const rbacStore                        = require('../src/core/rbac/store');
const tenantKeyManager                 = require('../services/artifact/tenantKeyManager');
const { createPortalSessionMiddleware } = require('../src/middleware/portalAuth');
const portalUserStore                  = require('../src/core/portal/tenantPortalUserStore');
const { verifySessionToken: _verifyPortalSessionToken } = require('../services/portal/portalSessionToken');
const { emit, registerCentralStore }   = require('../services/logger');
const pgPool                           = require('../src/infra/postgres/pool');
const { probeEvidenceStores }          = require('../src/infra/postgres/evidenceStoreReadiness');
const retentionPool                    = require('../src/infra/postgres/retentionPool');
// ER 2026-10-06: captured at load (not required lazily at shutdown) so a stop always reaches THIS instance's role
// pools — a lazy require from an isolated module registry (jest.isolateModules) resolved to a different instance.
const rolePools                         = require('../src/infra/postgres/rolePools');
const roleCredentials                  = require('../src/infra/postgres/roleCredentials');
const centralStore                     = require('../src/core/audit/centralStore');
const alertingFramework                = require('../src/alerting');
const consentRegistry                  = require('../src/core/consent');
const consentSubscriber                = require('../src/core/consent/revocation/RevocationSubscriber');
const consentPublisher                 = require('../src/core/consent/revocation/RevocationPublisher');
const orgStatusSubscriber              = require('../src/core/organizations/status/OrgStatusSubscriber');
const orgStatusPublisher               = require('../src/core/organizations/status/OrgStatusPublisher');
const orgStatusStore                   = require('../src/core/organizations/status/OrgStatusStore');
const organizationRegistry             = require('../src/core/organizations/organizationRegistry');
const {
  checkSingleInstance,
  checkStartupPreconditions: _checkAuditDistributedPreconditions,
  assertNoIllegalTopology: _assertNoIllegalTopology,
  ORDERING_MODE: _AUDIT_ORDERING_MODE,
}                                      = require('../src/core/audit/multiInstanceGuard');
const { startMonitoring: _startAuditPgLagMonitor } = require('../src/core/audit/pgLagMonitor');
const { hydrateFromPgIfDistributed: _hydrateAuditChainFromPg } = require('../src/core/audit/audit-log');
const { verifyMirrorConsistency: _verifyAuditMirrorConsistency } = require('../src/core/audit/mirrorConsistencyCheck');
const { verifyChainVerifierContinuity: _verifyAuditChainVerifierContinuity } = require('../src/core/audit/verifierStartupGate');
const { verifyRetentionPrivileges: _verifyRetentionPrivileges } = require('../src/core/audit/retentionPrivilegeCheck');
const { checkNoLegacyRateLimiters: _checkNoLegacyRateLimiters } = require('../src/core/rateLimit/startupGuard');
const {
  initialize: _initRateLimit,
  disconnect: _disconnectRateLimit,
  createRateLimitMiddleware,
  _isRlEnabled,
}                                      = require('../src/core/rateLimit');
const { isReady: _rateLimitStorageReady } = require('../src/core/rateLimit/storage');

// (step 4): the ONE definition of "request rate limiting is protecting
// traffic" — the limiter middleware is enabled (RL_ENABLED / REDIS_URL, see
// src/core/rateLimit/middleware.js _isRlEnabled) AND its Redis storage is
// ready. every startup/runtime event reported
// rateLimitProtectionActive from the POLICY store's readiness
// (services/policy/store.js), so it read true with RL_ENABLED=false.
// Policy-store readiness stays reported separately as rateLimitStoreReady.
function _requestRateLimitActive() {
  return _isRlEnabled() && _rateLimitStorageReady();
}
const {
  createAuthLockout,
  initialize: _initAuthLockout,
  disconnect: _disconnectAuthLockout,
}                                      = require('../src/core/authLockout');
const {
  initialize: _initRecoveryQueue,
  shutdown:   _shutdownRecoveryQueue,
}                                      = require('../src/core/persistenceRecovery');
const embeddingClassifier              = require('../src/core/semantic/embeddingSimilarity');

const PORT = parseInt(process.env.PORT || '3000', 10);
// the listen address is explicit. The default 0.0.0.0 is what a container needs (the platform or the compose port mapping decides who can reach it);
// set QODIQA_BIND_HOST=127.0.0.1 to bind loopback only when the gateway runs directly on a host behind a local reverse proxy.
const BIND_HOST = process.env.QODIQA_BIND_HOST || '0.0.0.0';

// ── Startup: boot validation — FIRST, before anything else is decided ────
// One declarative schema (src/infra/config/bootValidator.js, rules in
//) checks the whole configuration and reports every
// violation together: exact NODE_ENV profile, every secret (presence, strength,
// placeholder — including the execution-invariant secret, so no request can
// consume its nonce and then fail on it), provider keys, semantic override
// guards, rate limiting, PG/Redis TLS, admin/diagnostics planes and the
// retained production rules. Any fatal violation exits 1 here, before any
// listener opens. It replaces runEnvValidation(), runSecretValidation() and the
// inline provider / KEK / client-id / portal-dev-auth checks that followed.
runBootValidation();

// ── Startup: production must explicitly choose a policy file ─────────
// The repository-root policies.json is a demo/development fixture (an
// always-on BLOCK_IP rule, demo-tuned rate limits — see
// deploy/env/production.policies.example) and must never be silently assumed as the
// production default. Outside production, the existing developer convenience
// is unchanged: `npm run dev`/tests boot against policies.json out of the
// box when POLICY_FILE is unset. See services/policy/loader.js's
// resolvePolicyFilePath() for the full contract — shared with
// src/core/policy/store.js's own independent POLICY_FILE resolution, so
// there is exactly one rule, not two that could drift.
let POLICY_FILE;
try {
  POLICY_FILE = resolvePolicyFilePath(path.resolve(__dirname, '..', 'policies.json'));
} catch (err) {
  emit('FATAL', 'POLICY_FILE_REQUIRED', { message: err.message });
  process.exit(1);
}

// Configurable global request body limit.  Defaults to 65 536 bytes (64 KiB).
// Set MAX_BODY_BYTES in the environment to override for your deployment.
const MAX_BODY_BYTES = (() => {
  const v = parseInt(process.env.MAX_BODY_BYTES, 10);
  return Number.isFinite(v) && v > 0 ? v : 65_536;
})();

// STRICT_REPLAY_PROTECTION — refuse to start if Redis persistence guarantees are
// insufficient (AOF disabled, appendfsync unsafe, or Redis unreachable).
// Secure by default: true unless explicitly set to 'false'.
// Set STRICT_REPLAY_PROTECTION=false only in environments without durable Redis
// (e.g. development without Redis) and only with documented justification.
//
// REPLAY-2: NODE_ENV=production always forces strict mode, regardless of the
// env var. This closes a configuration-drift path — an operator who sets
// STRICT_REPLAY_PROTECTION=false for local/dev use (no durable Redis) could
// otherwise carry that same env file into production and unknowingly disable
// the crash-replay-window protection there too.
const STRICT_REPLAY = process.env.NODE_ENV === 'production'
  ? true
  : process.env.STRICT_REPLAY_PROTECTION !== 'false';

// evidence durability is mandatory in the production profile.
// "Production profile" is keyed on NODE_ENV=production — the exact same key
// REPLAY-2's STRICT_REPLAY forcing above already uses, and the key every
// shipped deploy profile sets (deploy/docker/docker-compose.prod.yml,
// deploy/kubernetes/base/configmap.yaml). No new knob is introduced.
// The gate itself runs at the top of startServer() below (it needs an async
// PG round-trip, mirroring the STRICT_REPLAY gate's own placement inside
// startServer() after its Redis probes). Non-production keeps today's
// behaviour: pool.js's PG_DISABLED WARN and the registrar's
// TRANSPARENCY_PERSISTENCE_DEGRADED WARN, with no refusal.
const REQUIRE_DURABLE_EVIDENCE = process.env.NODE_ENV === 'production';

// ── Startup: single-instance audit chain guard (single-node mode only) ───────
// The audit chain derives ordering from a process-local in-memory array.
// Multiple concurrent instances produce divergent chains.  This guard exits
// with code 1 if PM2 cluster mode or Node cluster workers are detected.
// See: docs/protocol/AUDIT-SCHEMA-V8.md
//
// Distributed mode's equivalent precondition (PostgreSQL, the ordering
// authority, must be reachable) runs inside startServer() below, after
// pgPool.initialize() — it needs an async PG round-trip, which can't happen
// at this synchronous, top-level point in the module. See
// src/core/audit/multiInstanceGuard.js.
if (_AUDIT_ORDERING_MODE !== 'distributed') {
  checkSingleInstance();
}

// ── Startup: enabled AI providers ─────────────────────────────────────────────
// Presence/validity of provider keys, the KEK, QODIQA_CLIENT_ID, the
// portal-dev-auth production refusal and the former env/secret
// validators are enforced by runBootValidation() above. A provider is enabled
// only by a key/URL that passes credentialRules (services/providers/config.js),
// so this list is exactly the set that passed boot validation.
const { getEnabledProviders } = require('../services/providers/config');
emit('INFO', 'PROVIDERS_CONFIGURED', { providers: getEnabledProviders() });

// ── Startup: KMS/Vault configuration + SDK-availability validation (items 21/22) ──
// Deliberately a NO-OP for the default 'local' provider — this file must
// stay byte-identical on that path (see the HARD CONDITION lock-in test at
// src/infra/keys/__tests__/serverEntrypointGate.lockin.test.js). For any
// other provider this duplicates the check keyProviderFactory.initialize()
// already performs before this module is even required, via start.js or
// server.js's Finding-D bootstrap branch — kept here anyway as defense in
// depth for any entrypoint that reaches server/startup.js without going
// through that bootstrap first (e.g. scripts/bootstrap-dev.js, if ever
// configured with a non-local provider).
if ((process.env.QODIQA_KMS_PROVIDER || 'local') !== 'local') {
  try {
    require('../src/infra/keys/kmsConfig').validateKmsConfig();
    require('../src/infra/keys/sdkAvailability').checkSdkAvailability(process.env.QODIQA_KMS_PROVIDER);
  } catch (err) {
    emit('FATAL', 'KMS_STARTUP_VALIDATION_FAILED', { message: err.message });
    process.exit(1);
  }
}

// ── Startup: CORS configuration validation ────────────────────────────────────
// Validates QODIQA_ALLOWED_ORIGINS format. Malformed origins abort startup.
// Missing in production emits WARN (fail-closed: all cross-origin denied).
runCorsValidation();

// ── Startup: validate key manager (KEK format + active key existence) ──────────
let _ks;
try {
  _ks = keyManager.validateStartup();
} catch (err) {
  emit('FATAL', 'KEY_MANAGER_STARTUP_FAILED', { message: err.message });
  process.exit(1);
}
if (_ks.totalActive === 0) {
  emit('FATAL', 'KEYSTORE_EMPTY', {
    message: 'No active signing keys found — provision keys via rotateKey() before starting.',
    clients: _ks.clients,
  });
  process.exit(1);
}
emit('INFO', 'KEY_MANAGER_READY', {
  activeKeys:          _ks.totalActive,
  secretProvider:      _ks.secretProvider,
  encryptionAlgorithm: _ks.encryptionAlgorithm,
});

// #9: startup already warned once (KEY_EXPIRING_SOON/KEY_ROTATION_OVERDUE
// above, via validateStartup()'s Steps 5-6) — start the periodic re-check so a
// long-running process doesn't go silent between restarts as keys approach expiry.
keyExpiryMonitor.initialize();

// ── Startup: validate transparency signer (Component #30) ─────────────────────
// Independent trust domain for transparency signing.  Auto-provisions a
// transparency key on first startup.  Fails closed on violations or expired keys.
try {
  const { getTransparencySigner: _getTS } = require('../src/core/transparency/transparencySigner');
  const _tsValidation = _getTS().validateStartup();
  emit('INFO', 'TRANSPARENCY_SIGNER_READY', _tsValidation);
} catch (err) {
  emit('FATAL', 'TRANSPARENCY_SIGNER_STARTUP_FAILED', { message: err.message });
  process.exit(1);
}

// ── Startup: audit-checkpoint signing key ───────────────
// A third, separate Ed25519 trust domain (src/core/audit/checkpoint/checkpointKeyStore.js): auto-provisioned on first
// startup, fails closed on a store violation or an expired key — exactly like the transparency key above.
try {
  const _cks = require('../src/core/audit/checkpoint/checkpointKeyStore');
  const _cpKey = _cks.ensureActiveKey();
  const _cpVal = _cks.validateKeyStore();
  if (_cpVal.violations.length || _cpVal.expiredKeys.length) {
    throw new Error(`checkpoint key store invalid: ${JSON.stringify({ violations: _cpVal.violations, expiredKeys: _cpVal.expiredKeys })}`);
  }
  emit('INFO', 'CHECKPOINT_KEY_READY', { keyId: _cpKey.keyId, totalActive: _cpVal.totalActive, expiringKeys: _cpVal.expiringKeys.length });
} catch (err) {
  emit('FATAL', 'CHECKPOINT_KEY_STARTUP_FAILED', { message: err.message });
  process.exit(1);
}

// ── Startup: MAC keyring decryptability ─────────────────
// Production only (the boot validator already requires the file to exist there): a wrong KEK (KEK-fingerprint guard)
// or a corrupt keyring is FATAL now, not at the first signed revocation / consent-cache read.
if (process.env.NODE_ENV === 'production') {
  try {
    emit('INFO', 'MAC_KEYRING_READY', require('../src/core/security/macKeyring').assertUsable());
  } catch (err) {
    emit('FATAL', 'MAC_KEYRING_STARTUP_FAILED', { message: err.message, code: err.code || null });
    process.exit(1);
  }
}

// ── Startup: multi-tenant key health — provision missing keys, warn on expiry ─
// Runs after keyManager.validateStartup() so security invariants (KEK, plaintext
// scan, structural checks) are already verified.  validateAllTenantsAtStartup()
// auto-provisions any tenant with no active key and emits CRITICAL + auto-rotates
// any tenant with an expired active key.  Throws only on provisioning failure.
let _allTenantsHealth;
try {
  const _startupClients = [process.env.QODIQA_CLIENT_ID];
  if (process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT &&
      process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT !== process.env.QODIQA_CLIENT_ID) {
    _startupClients.push(process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT);
  }
  _allTenantsHealth = tenantKeyManager.validateAllTenantsAtStartup(_startupClients);
} catch (err) {
  emit('FATAL', 'TENANT_KEY_STARTUP_FAILED', { message: err.message });
  process.exit(1);
}
emit('INFO', 'TENANT_KEYS_READY', {
  totalTenants:    _allTenantsHealth.totalTenants,
  healthyTenants:  _allTenantsHealth.healthyTenants,
  warningTenants:  _allTenantsHealth.warningTenants,
  criticalTenants: _allTenantsHealth.criticalTenants,
  overallStatus:   _allTenantsHealth.overallStatus,
});

// ── Startup: signing identity readiness (TRUST-1 remediation) ─────────────────
// Non-fatal by design: an empty signing-identity store is a valid (if inert)
// state — POST /sign fails closed for every caller (401) until an operator
// explicitly provisions at least one identity via
// scripts/provision-signing-identity.js or POST /signing-identities. There is
// no implicit bootstrap identity — that would reintroduce an anonymous-
// equivalent signing credential, exactly what this remediation removes.
// with the PostgreSQL control plane these checks need the first
// pull, so they run in startServer() right after controlPlane.start(); in
// memory mode they run here, at load, exactly as before.
const controlPlane = require('../src/core/controlPlane');
function _signingIdentityReadiness() {
  const signingIdentityStore = require('../src/core/signing/signingIdentityStore');
  let _signingIdentities = [];
  try {
    _signingIdentities = signingIdentityStore.listSigningIdentities();
  } catch (err) {
    emit('WARN', 'SIGNING_IDENTITY_STORE_UNREADABLE', { message: err.message });
  }
  const _activeSigningIdentities = _signingIdentities.filter(i => i.enabled && !i.revoked && i.apiKeyHash);
  emit(_activeSigningIdentities.length > 0 ? 'INFO' : 'WARN', 'SIGNING_IDENTITIES_READY', {
    totalIdentities:  _signingIdentities.length,
    activeIdentities: _activeSigningIdentities.length,
    message: _activeSigningIdentities.length > 0
      ? undefined
      : 'No active signing identities configured — POST /sign will deny every caller ' +
        'until one is provisioned (scripts/provision-signing-identity.js or POST /signing-identities).',
  });
}
if (!controlPlane.isPg()) _signingIdentityReadiness();

// ── Startup: operational endpoint security configuration ──────────────────────
// Loaded after key-manager validation so the emit function is guaranteed ready.
const _opsConfig  = loadOpsConfig();
// AUTH-2: one shared lockout instance for every ops-token-authenticated
// surface (_opsAuth below and, when QODIQA_HEALTH_PROBE_AUTH_REQUIRED=true,
// _healthAuth) — it is the shared token itself being protected, so all
// surfaces that accept it must contribute to, and be protected by, the same
// per-source failure/lockout state. See src/core/authLockout.
const _authLockout = createAuthLockout(_opsConfig);
const _opsAuth    = createOpsAuthMiddleware(_opsConfig, rbacStore, _authLockout);
_opsAuth.useFederation(require('../src/core/identity/operatorFederation').create(rbacStore));   // single sign-on for operators (OIDC bearer token, SAML session); null (no effect) unless configured
const _opsIpAllow = createOpsIpAllowlistMiddleware(_opsConfig);
// Separate instance (same config) for the admin/ops stack below — its
// failure body must be the canonical management envelope (src/api/response.js),
// not the probe-surface decision-shape _opsIpAllow above uses for /health,
// /ready, /health/redis. See src/middleware/opsIpAllowlist.js's `envelope` option.
const _adminIpAllow = createOpsIpAllowlistMiddleware(_opsConfig, { envelope: 'management' });
const _opsGate    = createOpsDiagnosticsGate(_opsConfig);
// the admin plane's own kill switch (QODIQA_ADMIN_ENABLED).
const _adminGate  = createOpsAdminGate(_opsConfig);
// #4: independent second kill switch for GET /diagnostics/profile/* —
// see src/middleware/profilingEnabled.js's header for why this is separate
// from _opsGate above.
const _profilingGate = createProfilingDiagnosticsGate(_opsConfig);
emit('INFO', 'OPS_CONFIG_READY', {
  authConfigured:     !!_opsConfig.token,
  diagnosticsEnabled: _opsConfig.diagnosticsEnabled,
  adminEnabled:       _opsConfig.adminEnabled,
  profilingDiagnosticsEnabled: _opsConfig.profilingDiagnosticsEnabled,
  ipAllowlistEnabled: _opsConfig.ipAllowlistEnabled,
  allowlistEntryCount: _opsConfig.allowlistEntries.length,
  trustProxy:         _opsConfig.trustProxy,
  authLockoutEnabled: _opsConfig.authLockoutEnabled,
  authLockoutMaxFailures: _opsConfig.authLockoutMaxFailures,
  authLockoutDurationMs: _opsConfig.authLockoutDurationMs,
});

// ── Startup: /health + /ready probe security configuration ────────────────────
// Deliberately NOT the same gate as /metrics, /diagnostics, /audit: Kubernetes
// httpGet probes and Docker HEALTHCHECK cannot supply the QODIQA_OPS_TOKEN
// bearer credential, so mounting these two behind _opsAuth unconditionally
// breaks every orchestrator deployment (probes fail 401 -> CrashLoopBackOff /
// pod never Ready). See src/middleware/healthAuth.js and
// docs/deployment/kubernetes-probes.md for the full security rationale.
//
// Centralized here — this is the ONLY place /health and /ready security is
// assembled; the health/ready route handlers themselves contain no auth logic.
const _healthAuth     = createHealthAuthMiddleware(_opsConfig, rbacStore, _authLockout);
const _healthLoopback = createHealthLoopbackMiddleware(_opsConfig);
// the 'health_probe' rate limiter that was
// constructed here and mounted ahead of /health, /health/redis and /ready is
// REMOVED. Being Redis-backed and fail-closed, it turned every probe into
// 429 RATE_LIMITED during a Redis outage — masking the documented
// 503+components readiness report in exactly the situation it exists for.
// Probes are not enforcement routes; every enforcement-route limiter and its
// fail-closed posture is unchanged. See src/app.js's probe mounts and the
// register's (which records the rejected 429-as-unready alternative).
emit('INFO', 'HEALTH_PROBE_CONFIG_READY', {
  authRequired:     _opsConfig.healthAuthRequired,
  requireLoopback:  _opsConfig.healthRequireLoopback,
  rateLimited:      false, // probe routes are deliberately unlimited
});

// ── Startup: RBAC configuration ───────────────────────────────────────────────
// RBAC authorization is unconditional — there is no "disabled" mode and no
// configuration flag that can cause a request to receive administrative
// privileges without an explicit, validated RBAC assignment. See
// src/middleware/rbac.js and docs/security/RBAC_MODEL.md.
loadRbacConfig(); // retained for its startup diagnostic — see module header
const _rbacResolve       = createRbacResolveMiddleware({ store: rbacStore });
const _requirePermission = createRequirePermission({
  isPermitted: _rbacIsPermitted,
  isValidPermission: _rbacIsValidPermission,
});

// ── Startup: Admin/Ops defense-in-depth stack (Task #27) ──────────────────────
// Centralizes the rate-limit → IP-allowlist → ops-auth → RBAC-resolve →
// permission → diagnostics-gate layering used by every Admin route below, so
// no route can accidentally omit or reorder a layer. RBAC itself (roles,
// permissions, isPermitted()) is untouched — this only assembles the
// surrounding layers. See src/middleware/adminProtection.js and
// docs/security/RBAC_MODEL.md.
const _adminRateLimit = createRateLimitMiddleware('ops_admin', {
  envelope:  'legacyFailure',
  onBlocked: (req) => emit('WARN', 'ADMIN_RATE_LIMITED', {
    path:      req.path,
    ip:        req.clientIp ?? req.ip ?? null,
    requestId: req.requestId ?? null,
  }),
});
const { adminStack: _adminStack, opsOnlyStack: _opsOnlyStack } = createAdminProtection({
  rateLimit:         _adminRateLimit,
  opsIpAllow:        _adminIpAllow,
  opsAuth:           _opsAuth,
  rbacResolve:       _rbacResolve,
  requirePermission: _requirePermission,
  opsGate:           _opsGate,
  adminGate:         _adminGate,
  // R-09 / OD-3 code option: a disabled plane is 404 before auth (non-enumerable)
  adminPreGate:      createOpsAdminPreAuthGate(_opsConfig),
  opsPreGate:        createOpsDiagnosticsPreAuthGate(_opsConfig),
});
emit('INFO', 'ADMIN_PROTECTION_READY', {
  adminEnabled:      _opsConfig.adminEnabled,
  rateLimitMax:      _opsConfig.opsRateLimitMax,
  rateLimitWindowMs: _opsConfig.opsRateLimitWindowMs,
});
if (!_opsConfig.adminEnabled) {
  // (D-B): the admin plane has its own switch; a deployment that
  // used QODIQA_DIAGNOSTICS_ENABLED=true to reach it now gets 404s — say why.
  emit('INFO', 'ADMIN_PLANE_DISABLED', {
    variable: 'QODIQA_ADMIN_ENABLED',
    message:  'Admin routes (/audit, /rbac, /key-admin, /consent, /v1/admin/*, …) return 404. Set QODIQA_ADMIN_ENABLED=true to enable them; QODIQA_DIAGNOSTICS_ENABLED no longer controls the admin plane.',
  });
}

// ── Startup: Tenant self-service portal ────────────────────────────────
// QODIQA_PORTAL_ENABLED gates whether src/app.js even mounts
// src/api/routes/tenantPortal.js — with it unset/false (the default) the
// portal does not exist as a code path at all, matching this codebase's
// existing optional-capability pattern (e.g. non-local QODIQA_KMS_PROVIDER
// backends). Middleware is still constructed unconditionally here (cheap,
// no I/O) so app.js can mount it directly when enabled without its own
// conditional construction logic.
//
// portalSessionAuth is built via DEPENDENCY INJECTION
// (createPortalSessionMiddleware({verifySessionToken, getPortalUserById})),
// not a direct src/core require inside src/middleware/portalAuth.js itself
// — see that file's header comment for why (.dependency-cruiser.js's
// no-middleware-to-core rule). _rbacResolve above is REUSED unchanged for
// portal routes too — it only checks `if (req.rbacUser) next()`, which
// portalSessionAuth already satisfies exactly like createOpsAuthMiddleware
// does for admin routes.
const _portalEnabled = process.env.QODIQA_PORTAL_ENABLED === 'true';
const _portalSessionAuth = createPortalSessionMiddleware({
  verifySessionToken: _verifyPortalSessionToken,
  getPortalUserById:  portalUserStore.getById,
});
const _portalRateLimit = createRateLimitMiddleware('tenant_portal', {
  envelope:  'management',
  onBlocked: (req) => emit('WARN', 'PORTAL_RATE_LIMITED', {
    path:      req.path,
    ip:        req.clientIp ?? req.ip ?? null,
    requestId: req.requestId ?? null,
  }),
});
emit('INFO', 'TENANT_PORTAL_CONFIG_READY', { enabled: _portalEnabled });

// Bootstrap initial admin if no admin user exists (idempotent, safe to call every startup)
async function _rbacBootstrap() {
  try {
    await rbacStore.bootstrapAdmin();
  } catch (e) {
    emit('ERROR', 'RBAC_BOOTSTRAP_FAILED', { error: e.message });
  }
  emit('INFO', 'RBAC_CONFIG_READY', {
    enforced:   true,
    userCount:  rbacStore.listUsers().length,
  });
}
if (!controlPlane.isPg()) _rbacBootstrap();

// ── Startup: Event Loop Delay Monitor ─────────────────────────────────
// Unconditional (unless QODIQA_EVENT_LOOP_MONITOR_ENABLED=false) and
// independent of every other subsystem below — the earliest and cheapest
// signal that synchronous I/O, GC, or CPU starvation is starting to affect
// request latency. Background-only: no request-path instrumentation. Stopped
// by eventLoopMonitor.shutdown() in the graceful shutdown sequence.
eventLoopMonitor.initialize();

// ── Startup: Request Latency SLA/p99 Monitor ─────────────────────
// Same unconditional/independent treatment as the event loop monitor above —
// reads requestDurationMs's already-recorded data on a background interval,
// no request-path instrumentation of its own.
latencySlaMonitor.initialize();

// ── Startup: PostgreSQL backend (optional) ────────────────────────────────────
// No-op unless QODIQA_PG_ENABLED=true; PG_DISABLED warn is emitted by pool.js.
pgPool.initialize();
// Background readiness probe (READY-50) — keeps pgPool.isHealthy() fresh via a
// bounded interval so GET /ready never issues a query itself. No-op when PG
// is disabled. Stopped by pgPool.shutdown() in the graceful shutdown sequence.
pgPool.startReadinessMonitor();

// ── Startup: dedicated retention role connection pool ───────────────
// Second, minimal pool authenticated as qodiqa_retention (migration
// 038_retention_dedicated_role.sql) — the automated audit-retention cleanup
// cycle's UPDATE/DELETE statements run through this pool instead of the
// general-purpose pgPool above. No-op unless QODIQA_PG_ENABLED=true (same
// gate as pgPool — same physical database, different login role). See
// src/infra/postgres/retentionPool.js.
retentionPool.initialize();

// ── Startup: governance publish reconciliation ──────────────────────
// Compares the file-based policy store (policies.json) against the Postgres
// governance ledger (policy_change_requests/policy_publications/
// policy_provenance_versions) once, emitting a structured event for any
// divergence found. Strictly a verification/alerting mechanism — read-only,
// never blocks startup, never calls process.exit(). Fire-and-forget, same
// pattern as alertingFramework.initialize() below. See
// src/core/policy/governance/reconciliation.js.
// in pg mode the policy store is readable only after the control plane's first pull.
// ER 2026-10-06: the promise is kept so stopLoadTimeSideEffects() can let an in-flight start settle before stopping it.
const _loadTimeControlPlaneStart = (controlPlane.isPg() ? controlPlane.start() : Promise.resolve()).then(() => require('../src/core/policy/governance/reconciliation').reconcile()).catch(err =>
  emit('ERROR', 'GOVERNANCE_RECONCILIATION_STARTUP_ERROR', { error: err.message })
);

// ── Startup: illegal multi-instance topology assertion ─────────────
// Synchronous — pgPool.isEnabled() only reflects reality once pgPool.initialize()
// above has run, so this cannot happen any earlier than this point. Runs
// unconditionally, regardless of ordering mode (unlike
// checkDistributedPreconditions() below, which is distributed-mode-only and
// async). See src/core/audit/multiInstanceGuard.js's assertNoIllegalTopology()
// for the invariant this enforces (PG enabled + ordering != distributed +
// more than one replica).
_assertNoIllegalTopology();

// centralStore is intentionally NOT wired into the logger here (
// remediation — see the registerCentralStore() call inside startServer(),
// after migration verification). Wiring it this early, immediately after
// pgPool.initialize(), used to mean every synchronous emit() call between
// here and startServer() — RBAC bootstrap, ops/admin protection stack setup,
// rate-limit/auth-lockout/recovery-queue/idempotency-store initialization,
// alerting framework startup, log-shipping config, policy loading, tracing
// init — fired a fire-and-forget PG INSERT into platform_audit_events
// (centralStore.ingest(), src/core/audit/centralStore.js) for EACH one, all
// before distributed mode's migration state was ever confirmed. Against a
// freshly-provisioned, not-yet-migrated database (platform_audit_events
// doesn't exist yet), every one of those inserts fails — but each failed
// attempt still checks out and holds a pool connection for its full round
// trip before erroring. With this many near-simultaneous attempts against
// the default QODIQA_PG_POOL_MAX=10, the pool saturates, callers queue past
// connectionTimeoutMillis, and pgCircuitBreaker.js (FAILOVER-2) classifies
// that queuing timeout as a connection-class failure and trips OPEN — at
// which point checkDistributedPreconditions()'s own migration-verification
// query (below, inside startServer()) fast-fails with PG_CIRCUIT_OPEN and is
// misreported as AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE, even though
// PostgreSQL itself is healthy. Reproduced directly against a real,
// unmigrated database during the remediation audit.
//
// Deferring registerCentralStore() until after migration state is confirmed
// closes this at the root: no centralStore writes are attempted — successful
// or failed — until the schema is known to exist, so there is no flood to
// exhaust the pool with in the first place. The (small, fixed) set of
// startup log lines between here and there is still written to stdout via
// the normal emit() path exactly as before; only their additional PG mirror
// copy is deferred by a few seconds. See startServer()'s registerCentralStore()
// call and pgCircuitBreaker.js's header comment for the breaker mechanics.

// ── Startup: distributed rate limiting (Redis-backed) ────────────────────────
// Non-fatal: if Redis is unavailable, failMode='closed' buckets return 429 and
// failMode='degrade' buckets use the per-process fallback.
// initialized whenever the limiter is enabled — which is now
// always, unless RL_ENABLED=false — exactly like the nonce and auth-lockout
// stores, which connect unconditionally (default redis://localhost:6379).
// the predicate was "RL_ENABLED when set, else REDIS_URL presence",
// so a deployment without REDIS_URL ran every HTTP limiter as a silent no-op.
const _rlInitPromise = _isRlEnabled()
  ? _initRateLimit().catch(err =>
    emit('WARN', 'RATE_LIMIT_INIT_FAILED', { error: err.message })
  )
  : null;

// ── Startup: auth-failure lockout (AUTH-2, Redis-backed) ─────────────────────
// Non-fatal: if Redis is unavailable, the lockout control fails-closed
// per-request (a locked-out-looking 429) rather than silently disabling
// itself — see src/core/authLockout/storage.js. No-op only when disabled via
// QODIQA_OPS_AUTH_LOCKOUT_ENABLED=false. no longer additionally gated on
// REDIS_URL — matches nonceStore.js/anomalyStore.js/rateLimitStoreModule's
// own unconditional initialize() calls above (line ~1140), which default to
// redis://localhost:6379 when REDIS_URL is unset. The old REDIS_URL gate
// here was the second half of Findings Register even after
// src/core/authLockout/index.js stopped falling back to MemoryStorage, this
// gate alone would have left the production RedisStorage singleton
// permanently uninitialized whenever REDIS_URL was unset — turning every
// precheck() into a permanent fail-closed lockout instead of a real,
// recoverable outage response.
// (D2): /sign's auth-failure bucket shares this storage singleton
// (namespaced keys), so it is initialised when EITHER lockout is enabled.
if (_opsConfig.authLockoutEnabled || process.env.QODIQA_SIGN_AUTH_LOCKOUT_ENABLED !== 'false') {
  _initAuthLockout().catch(err =>
    emit('WARN', 'AUTH_LOCKOUT_INIT_FAILED', { error: err.message })
  );
}

// ── Startup: persistence recovery queue (CHAIN-3: PostgreSQL-backed) ─────────
// Non-fatal: durable storage is the persistence_recovery_queue PostgreSQL
// table (migration 032) — Redis is not a dependency of this path at all.
// PRQ_ENABLED=false disables even when QODIQA_PG_ENABLED is set; PRQ_ENABLED
// =true forces it on regardless. See recoveryManager.js's header comment.
if (process.env.QODIQA_PG_ENABLED === 'true' || process.env.PRQ_ENABLED === 'true') {
  _initRecoveryQueue().catch(err =>
    emit('WARN', 'RECOVERY_QUEUE_INIT_FAILED', { error: err.message })
  );
}

// ── Startup: idempotency store (API-2, Redis-backed) ─────────────────────────
// Non-fatal, unlike nonce/anomaly/rate-limit below: the Idempotency-Key
// header is optional, so a store that fails to initialize does not degrade
// any existing request — it only means a request that explicitly supplies
// the header fails closed (IDEMPOTENCY_STORE_UNAVAILABLE, 503) until the
// store reconnects. See src/core/idempotency/idempotencyStore.js.
if (process.env.IDEMPOTENCY_ENABLED !== 'false') {
  idempotencyStore.initialize().catch(err =>
    emit('WARN', 'IDEMPOTENCY_STORE_INIT_FAILED', { error: err.message })
  );
}

// ── Startup: audit chain PG lag monitor ──────────────────────────────────────
// Non-blocking background monitor — emits AUDIT_PG_SYNC_LAG / AUDIT_PG_UNAVAILABLE
// / AUDIT_PG_RECOVERED so operators have visibility into PG replica health.
// The file chain remains authoritative; this is observability only.
// PG mirrors the MODERN entries only — compare like with like (mirrorConsistencyCheck does the same).
_startAuditPgLagMonitor({ getFileCount: () => require('../src/core/audit/audit-log').getChainStats().modernLength });

// ── Startup: notification channel configuration (MON-3) ──────────────────────
// QODIQA's alerting framework detects CRITICAL operational failures (Redis/
// PostgreSQL outages, HA violations, audit corruption, signing failures, ...)
// automatically. That detection is worthless if no notification channel is
// configured to actually deliver those alerts to a human. Every channel in
// src/alerting/notification/channels/ is disabled by default (secure by
// default), so this check exists purely to make that operational gap visible
// at startup rather than silent. See deploy/env/production.env.example's "NOTIFICATION
// CHANNELS (MON-3)" section and docs/operations/notification-setup.md.
{
  const _notificationChannels = alertingFramework.notificationService.listConfiguredChannels();
  if (_notificationChannels.length > 0) {
    emit('INFO', 'NOTIFICATION_CHANNELS_READY', { channels: _notificationChannels });
  } else if (process.env.QODIQA_REQUIRE_NOTIFICATION_CHANNEL === 'true') {
    emit('FATAL', 'NOTIFICATION_CHANNEL_REQUIRED_BUT_MISSING', {
      message: 'QODIQA_REQUIRE_NOTIFICATION_CHANNEL=true but no notification channel is ' +
               'configured — CRITICAL alerts would be detected but never delivered. Configure ' +
               'at least one of ALERT_WEBHOOK_URL, ALERT_SLACK_WEBHOOK_URL, ALERT_TEAMS_WEBHOOK_URL, ' +
               'ALERT_EMAIL_TO (+ provider vars), ALERT_PAGERDUTY_ROUTING_KEY, ALERT_SMS_TO ' +
               '(+ provider vars), or ALERT_SIEM_URL / ALERT_SIEM_SYSLOG_HOST. ' +
               'See deploy/env/production.env.example and docs/operations/notification-setup.md.',
    });
    process.exit(1);
  } else {
    emit('WARN', 'NO_NOTIFICATION_CHANNEL_CONFIGURED', {
      message: 'No notification channel is configured — CRITICAL operational alerts ' +
               '(PostgreSQL/Redis outages, HA violations, audit corruption, signing failures, ' +
               'policy invariant violations) will be detected and stored but NOT delivered to ' +
               'any operator. Configure at least one of ALERT_WEBHOOK_URL, ALERT_SLACK_WEBHOOK_URL, ' +
               'ALERT_TEAMS_WEBHOOK_URL, ALERT_EMAIL_TO, ALERT_PAGERDUTY_ROUTING_KEY, ALERT_SMS_TO, ' +
               'or ALERT_SIEM_URL. Set QODIQA_REQUIRE_NOTIFICATION_CHANNEL=true to make this fatal ' +
               'instead of a warning. See deploy/env/production.env.example and ' +
               'docs/operations/notification-setup.md.',
    });
  }
}

// ── Startup: Alerting & Notification Framework ────────────────────────────────
// Initialized synchronously here so the DetectionEngine subscribes to the
// eventBus before any meaningful events are emitted (policy load, Redis init).
// Framework failures are non-fatal — alerting is supplemental to enforcement.
// ER 2026-10-06: kept so stopLoadTimeSideEffects() lets the in-flight initial alert load finish first — otherwise it
// queried rolePools.reporting AFTER the role pools were closed, lazily re-creating the pool, which then lingered.
const _loadTimeAlertingInit = alertingFramework.initialize().catch(err =>
  emit('ERROR', 'ALERTING_FRAMEWORK_STARTUP_ERROR', { error: err.message })
);

// ── Startup: Bulk Audit Log Export / SIEM Integration ───────────────
// Ships the *complete* audit/log event stream — not just alert-derived
// events — to configured SIEM/ELK/Datadog/Splunk destinations. Wires the
// previously-unwired src/observability/logShipping subsystem by loading its
// config, creating the shipper, and subscribing it to the same logger
// eventBus DetectionEngine already reads for alerting (see
// src/observability/auditEventDispatcher.js for the full rationale).
// No-op (returns a no-op shipper) when no destination is enabled/valid —
// config validation only, never blocks startup on network reachability.
// Alerting is unaffected: SIEMChannel continues to receive Alert objects via
// its existing path; alert-triggering events are now additionally exported
// here as part of the full stream.
const { loadLogShipConfig: _loadLogShipConfig } = require('../src/observability/logShipping/config');
const { createLogShipper: _createLogShipper }    = require('../src/observability/logShipping');
const auditEventDispatcher = require('../src/observability/auditEventDispatcher');
const _logShipConfig = _loadLogShipConfig();
const _logShipper    = _createLogShipper(_logShipConfig);
auditEventDispatcher.attach(_logShipper);
emit('INFO', 'LOG_SHIPPING_READY', {
  elkEnabled:     Boolean(_logShipConfig.elk?.enabled && _logShipConfig.elk?.valid),
  datadogEnabled: Boolean(_logShipConfig.datadog?.enabled && _logShipConfig.datadog?.valid),
  splunkEnabled:  Boolean(_logShipConfig.splunk?.enabled && _logShipConfig.splunk?.valid),
  siemEnabled:    Boolean(_logShipConfig.siem?.enabled && _logShipConfig.siem?.valid),
});

// ── Startup: load and validate policies ───────────────────────────────────────
// POLICY_FILE is the IMPORT source only. It is still validated
// here (a broken file must not be imported), but what is ENFORCED is the
// control-plane policy store (src/core/policy/store.js enforcedPolicies()),
// the same on every replica and never rewritten to a file.
const globalPolicyStore = require('../src/core/policy/store');
try {
  const imported = loadPolicies(POLICY_FILE);
  emit('INFO', 'POLICIES_LOADED', { count: imported.length, ids: imported.map(p => p.id), role: 'import-source' });
  if (!controlPlane.isPg()) {
    const enforced = globalPolicyStore.enforcedPolicies();
    emit('INFO', 'POLICIES_ENFORCED', { count: enforced.length, ids: enforced.map(p => p.id), source: 'control-plane' });
  }
} catch (err) {
  emit('FATAL', 'POLICY_LOAD_FAILED', { error: err.message });
  process.exit(1);
}
function _enforcedPolicies() { return globalPolicyStore.enforcedPolicies(); }

const store = rateLimitStoreModule.createRedisStore();

// ── Startup: distributed tracing ───────────────────────────────────────
// Activates the existing OpenTelemetry-compatible tracing subsystem
// (src/observability/tracing) — implementation is untouched, this only wires
// it into the startup path. Config is loaded once here (rather than letting
// initTracing() load it internally) so the TRACING_READY diagnostic below can
// report on the same values without triggering a second
// TRACING_CONFIG_INVALID emission from config.js.
//
// Must run before `const app = express()` / route registration in the
// composition root, since _tracing.requestMiddleware is mounted as the first
// tracing-aware middleware in the chain — every route it wraps needs the
// tracer to already exist.
//
// Non-fatal by design: tracing is optional infrastructure. initTracing()
// itself never throws (no I/O happens synchronously — the OTLP exporter only
// performs network calls when spans are flushed, asynchronously, after
// startup), but this is wrapped defensively anyway so a future change to the
// tracing subsystem can never turn a tracing bug into a startup outage.
const _tracingConfig = loadTracingConfig();
let _tracing;
try {
  _tracing = initTracing(_tracingConfig);
} catch (err) {
  emit('WARN', 'TRACING_INIT_FAILED', {
    error:   err.message,
    message: 'Tracing initialization failed — continuing startup without tracing.',
  });
  _tracing = {
    requestMiddleware: (req, res, next) => next(),
    getHealth:  () => ({ component: 'opentelemetry', status: 'disabled' }),
    getMetrics: () => ({}),
    shutdown:   async () => {},
  };
}
const _tracingEnabled = _tracingConfig.enabled && _tracingConfig.valid;
emit('INFO', 'TRACING_READY', {
  enabled:      _tracingEnabled,
  configured:   _tracingConfig.enabled,
  exporter:     _tracingEnabled ? 'otlp' : 'noop',
  serviceName:  _tracingConfig.serviceName ?? null,
  sampleRate:   _tracingConfig.sampleRate ?? null,
});

// ── Startup: metrics OTLP export bridge ──────────────────────────────────
// Optional, disabled-by-default export-only adapter over the EXISTING
// /metrics Prometheus registry (src/observability/metrics.js) — that
// registry, its collect()/format() output, and the /metrics route itself
// are completely untouched by this. On its own timer (default 60s), reads
// the current registry state and pushes a translated OTLP copy to the same
// collector endpoint traces already target. Mirrors the tracing block
// above exactly (config loaded once here, non-fatal by design, no
// synchronous I/O so initMetricsOtlpBridge() cannot realistically throw
// today, wrapped defensively anyway for the same future-proofing reason).
const _metricsExportConfig = loadMetricsExportConfig();
let _metricsOtlpBridge;
try {
  _metricsOtlpBridge = initMetricsOtlpBridge(_metricsExportConfig);
} catch (err) {
  emit('WARN', 'METRICS_EXPORT_INIT_FAILED', {
    error:   err.message,
    message: 'Metrics OTLP export initialization failed — continuing startup without it (/metrics scrape is unaffected).',
  });
  _metricsOtlpBridge = { getHealth: () => ({ component: 'otlp_metrics_export', status: 'disabled' }), getStats: () => ({}), shutdown: async () => {} };
}
const _metricsExportEnabled = _metricsExportConfig.enabled && _metricsExportConfig.valid;
emit('INFO', 'METRICS_EXPORT_READY', {
  enabled:          _metricsExportEnabled,
  configured:       _metricsExportConfig.enabled,
  exporter:         _metricsExportEnabled ? 'otlp' : 'noop',
  serviceName:      _metricsExportConfig.serviceName ?? null,
  exportIntervalMs: _metricsExportConfig.exportIntervalMs ?? null,
});

process.on('SIGHUP', () => {
  // POLICY_FILE is import-only; the enforced set follows the control plane.
  try {
    const enforced = _enforcedPolicies();
    emit('INFO', 'POLICIES_RELOADED', { count: enforced.length, source: 'control-plane', note: 'POLICY_FILE is import-only; change policy through the policy API' });
  } catch (err) {
    emit('ERROR', 'POLICY_RELOAD_FAILED', { error: err.message });
  }
});

function _reloadPolicies() {
  // the enforced set is recomputed from the store on every change (every
  // replica); this only re-validates it now so a caller sees a failure here.
  const enforced = _enforcedPolicies();
  emit('INFO', 'POLICIES_RELOADED', { count: enforced.length, source: 'POLICY_UI' });
}

// ── Redis startup gating ──────────────────────────────────────────────────────
//
// Emits a structured startup event for a store initialization result.

function _emitStoreResult(source, result) {
  const ok = result.status === 'fulfilled';
  emit(
    ok ? 'INFO' : 'ERROR',
    ok ? `${source}_READY` : 'REDIS_STARTUP_FAILED',
    { source, ...(ok ? {} : { error: result.reason?.message ?? String(result.reason) }) },
  );
  return ok;
}

// ── Gateway runtime monitoring ────────────────────────────────────────────────
//
// Subscribes to store emitters and maintains a unified runtime integrity view.
// Emits gateway-level events when execution integrity changes at runtime.
// Called once at startup after both stores have been initialized.
//
// State is tracked in closure-local variables so each call to
// _setupRuntimeMonitoring is self-contained — there is exactly one call site.

function _setupRuntimeMonitoring(initialNonceReady, initialAnomalyReady, initialRlReady) {
  let _nonceReady   = initialNonceReady;
  let _anomalyReady = initialAnomalyReady;
  let _rlReady      = initialRlReady;
  let _wasDegraded  = !_nonceReady || !_anomalyReady || !_rlReady;

  function _currentIntegrityFields() {
    const full = _nonceReady && _anomalyReady && _rlReady;
    return {
      nonceStoreReady:          _nonceReady,
      anomalyStoreReady:        _anomalyReady,
      rateLimitStoreReady:      _rlReady,
      replayProtectionActive:   _nonceReady,
      anomalyProtectionActive:  _anomalyReady,
      rateLimitProtectionActive: _requestRateLimitActive(),
      requestRateLimitEnabled:   _isRlEnabled(),
      executionIntegrity:        full ? 'FULL' : 'DEGRADED',
    };
  }

  function _checkGatewayRecovery(source) {
    if (_nonceReady && _anomalyReady && _rlReady && _wasDegraded) {
      _wasDegraded = false;
      emit('INFO', 'GATEWAY_RUNTIME_RECOVERED', {
        source,
        ..._currentIntegrityFields(),
        note: 'all Redis stores operational — full execution integrity restored',
      });
      emit('INFO', 'GATEWAY_STATE_RECOVERED', {
        source,
        ..._currentIntegrityFields(),
        note: 'all three Redis stores operational',
      });
    }
  }

  function _emitGatewayState(source, reason) {
    const all  = _nonceReady && _anomalyReady && _rlReady;
    const none = !_nonceReady && !_anomalyReady && !_rlReady;
    if (all) return; // handled by _checkGatewayRecovery
    emit('WARN', none ? 'GATEWAY_STATE_UNHEALTHY' : 'GATEWAY_STATE_DEGRADED', {
      source,
      reason,
      ..._currentIntegrityFields(),
    });
  }

  nonceStore.emitter.on('degraded', ({ reason }) => {
    _nonceReady  = false;
    _wasDegraded = true;
    emit('WARN', 'REPLAY_PROTECTION_DEGRADED', {
      source:                 'NONCE_STORE',
      reason,
      executionBlocked:       true,
      replayProtectionActive: false,
      message:                'Nonce store unavailable — all execution requests blocked fail-closed.',
    });
    if (!_anomalyReady && !_rlReady) {
      emit('WARN', 'GATEWAY_RUNTIME_DEGRADED', {
        source: 'NONCE_STORE',
        reason,
        ..._currentIntegrityFields(),
        note: 'all Redis stores unavailable — all execution blocked fail-closed',
      });
    } else {
      emit('WARN', 'GATEWAY_RUNTIME_PARTIAL_FAILURE', {
        source: 'NONCE_STORE',
        reason,
        ..._currentIntegrityFields(),
        note: 'replay protection unavailable — execution blocked fail-closed',
      });
    }
    _emitGatewayState('NONCE_STORE', reason);
  });

  nonceStore.emitter.on('ready', ({ isReconnect }) => {
    if (!isReconnect) return; // initial ready handled at startup
    _nonceReady = true;
    _checkGatewayRecovery('NONCE_STORE');
    if (_wasDegraded && (!_anomalyReady || !_rlReady)) {
      emit('WARN', 'GATEWAY_RUNTIME_PARTIAL_FAILURE', {
        source: 'NONCE_STORE',
        ..._currentIntegrityFields(),
        note: 'replay protection recovered; one or more stores still unavailable',
      });
    }
  });

  anomalyStore.emitter.on('degraded', ({ reason }) => {
    _anomalyReady = false;
    _wasDegraded  = true;
    emit('WARN', 'ANOMALY_PROTECTION_DEGRADED', {
      source:                  'ANOMALY_STORE',
      reason,
      executionBlocked:        true,
      anomalyProtectionActive: false,
      message:                 'Anomaly store unavailable — all execution requests blocked fail-closed.',
    });
    if (!_nonceReady && !_rlReady) {
      emit('WARN', 'GATEWAY_RUNTIME_DEGRADED', {
        source: 'ANOMALY_STORE',
        reason,
        ..._currentIntegrityFields(),
        note: 'all Redis stores unavailable — all execution blocked fail-closed',
      });
    } else {
      emit('WARN', 'GATEWAY_RUNTIME_PARTIAL_FAILURE', {
        source: 'ANOMALY_STORE',
        reason,
        ..._currentIntegrityFields(),
        note: 'anomaly protection unavailable — execution blocked fail-closed',
      });
    }
    _emitGatewayState('ANOMALY_STORE', reason);
  });

  anomalyStore.emitter.on('ready', ({ isReconnect }) => {
    if (!isReconnect) return;
    _anomalyReady = true;
    _checkGatewayRecovery('ANOMALY_STORE');
    if (_wasDegraded && (!_nonceReady || !_rlReady)) {
      emit('WARN', 'GATEWAY_RUNTIME_PARTIAL_FAILURE', {
        source: 'ANOMALY_STORE',
        ..._currentIntegrityFields(),
        note: 'anomaly protection recovered; one or more stores still unavailable',
      });
    }
  });

  rateLimitStoreModule.emitter.on('degraded', ({ reason }) => {
    _rlReady     = false;
    _wasDegraded = true;
    emit('WARN', 'POLICY_RATE_LIMIT_DEGRADED', {
      source:                    'RATE_LIMIT_STORE',
      reason,
      executionBlocked:          true,
      rateLimitProtectionActive: _requestRateLimitActive(),
      message:                   'Rate limit store unavailable — distributed rate limiting degraded to fail-closed.',
    });
    if (!_nonceReady && !_anomalyReady) {
      emit('WARN', 'GATEWAY_RUNTIME_DEGRADED', {
        source: 'RATE_LIMIT_STORE',
        reason,
        ..._currentIntegrityFields(),
        note: 'all Redis stores unavailable — all execution blocked fail-closed',
      });
    } else {
      emit('WARN', 'GATEWAY_RUNTIME_PARTIAL_FAILURE', {
        source: 'RATE_LIMIT_STORE',
        reason,
        ..._currentIntegrityFields(),
        note: 'rate limit store unavailable',
      });
    }
    _emitGatewayState('RATE_LIMIT_STORE', reason);
  });

  rateLimitStoreModule.emitter.on('ready', ({ isReconnect }) => {
    if (!isReconnect) return;
    _rlReady = true;
    _checkGatewayRecovery('RATE_LIMIT_STORE');
    if (_wasDegraded && (!_nonceReady || !_anomalyReady)) {
      emit('WARN', 'GATEWAY_RUNTIME_PARTIAL_FAILURE', {
        source: 'RATE_LIMIT_STORE',
        ..._currentIntegrityFields(),
        note: 'rate limit store recovered; one or more stores still unavailable',
      });
    }
  });
}

// ── Metrics: Redis store gauge synchronisation ────────────────────────────────
//
// Subscribes to the same store emitters as _setupRuntimeMonitoring and keeps
// the Prometheus redis_store_up and execution_integrity_full gauges current.
// Called once at startup after store initialisation.  Purely observational —
// no enforcement behavior is changed.

function _setupMetricsFromStores(initialNonceReady, initialAnomalyReady, initialRlReady) {
  metricsModule.redisStoreUp.set({ store: 'nonce' },      initialNonceReady   ? 1 : 0);
  metricsModule.redisStoreUp.set({ store: 'anomaly' },    initialAnomalyReady ? 1 : 0);
  metricsModule.redisStoreUp.set({ store: 'rate_limit' }, initialRlReady      ? 1 : 0);
  metricsModule.executionIntegrityFull.set({}, (initialNonceReady && initialAnomalyReady && initialRlReady) ? 1 : 0);

  function _allNowReady() {
    return nonceStore.isReady() && anomalyStore.isReady() && rateLimitStoreModule.isReady();
  }

  nonceStore.emitter.on('degraded', () => {
    metricsModule.redisStoreUp.set({ store: 'nonce' }, 0);
    metricsModule.executionIntegrityFull.set({}, 0);
  });
  nonceStore.emitter.on('ready', () => {
    metricsModule.redisStoreUp.set({ store: 'nonce' }, 1);
    metricsModule.executionIntegrityFull.set({}, _allNowReady() ? 1 : 0);
  });

  anomalyStore.emitter.on('degraded', () => {
    metricsModule.redisStoreUp.set({ store: 'anomaly' }, 0);
    metricsModule.executionIntegrityFull.set({}, 0);
  });
  anomalyStore.emitter.on('ready', () => {
    metricsModule.redisStoreUp.set({ store: 'anomaly' }, 1);
    metricsModule.executionIntegrityFull.set({}, _allNowReady() ? 1 : 0);
  });

  rateLimitStoreModule.emitter.on('degraded', () => {
    metricsModule.redisStoreUp.set({ store: 'rate_limit' }, 0);
    metricsModule.executionIntegrityFull.set({}, 0);
  });
  rateLimitStoreModule.emitter.on('ready', () => {
    metricsModule.redisStoreUp.set({ store: 'rate_limit' }, 1);
    metricsModule.executionIntegrityFull.set({}, _allNowReady() ? 1 : 0);
  });
}

// ── startServer ──────────────────────────────────────────────────────────────
//
// Exported so that start.js (the production entry point) and server.js (the
// thin entrypoint) can call this after the composed Express app has been
// built. `app` is passed in explicitly — this module never creates or
// configures the Express app itself; that is src/app.js's responsibility.
//
async function startServer(app) {
    // ── -2.5. Production evidence-durability gate ─────────────────────
    // The production profile refuses to serve without durable evidence:
    // sign-only transparency (no PostgreSQL) and a configured-but-unusable
    // PostgreSQL (missing migrations, broken grants, unreachable) are both
    // startup FAILURES in production, never silent degradations. Mirrors the
    // STRICT_REPLAY gate below: FATAL + process.exit(1), one line naming the
    // missing prerequisite and the doc. First gate in startServer() so a
    // misconfigured production deployment fails in the cheapest possible way.
    // See docs/operations/deployment-runbook.md ("Durable-evidence vs
    // sign-only deployments") and in the register.
    if (REQUIRE_DURABLE_EVIDENCE) {
      if (!pgPool.isEnabled()) {
        emit('FATAL', 'EVIDENCE_DURABILITY_VIOLATION', {
          cause:      'PG_DISABLED',
          message:    'NODE_ENV=production requires durable evidence, but PostgreSQL is not ' +
                      'enabled — transparency would be sign-only and consent/evidence stores ' +
                      'unavailable. The server refuses to start.',
          resolution: 'Set QODIQA_DEPLOYMENT_MODE=distributed (recommended) or QODIQA_PG_ENABLED=true ' +
                      'with a migrated database. See docs/operations/deployment-runbook.md — ' +
                      '"Durable-evidence vs sign-only deployments".',
        });
        process.exit(1);
      }
      const evidenceReadiness = await probeEvidenceStores();
      if (!evidenceReadiness.ok) {
        emit('FATAL', 'EVIDENCE_DURABILITY_VIOLATION', {
          cause:      evidenceReadiness.cause,
          stores:     evidenceReadiness.stores,
          failures:   evidenceReadiness.failures,
          message:    'NODE_ENV=production requires durable evidence, but one or more ' +
                      'consent/evidence stores failed the boot readiness probe. The server ' +
                      'refuses to start rather than silently degrade to sign-only.',
          resolution: 'Verify QODIQA_PG_* connectivity, run pending migrations, and confirm the ' +
                      'application role can read consent_records / transparency_log_entries / ' +
                      'evidence_chain_records. See docs/operations/deployment-runbook.md — ' +
                      '"Durable-evidence vs sign-only deployments".',
        });
        process.exit(1);
      }
    } else if (!pgPool.isEnabled()) {
      // REL-02: outside production a file-only boot is allowed, but since audit schema v7 an AUTHENTICATED decision can
      // only be audited with a subject pseudonym whose key lives in PostgreSQL. Without it every such append fails
      // closed: nothing authenticated can EXECUTE and its BLOCKs are not in the chain. Say so at boot instead of
      // leaving the operator to discover it from refused requests.
      emit('WARN', 'EVIDENCE_INCOMPLETE_FILE_ONLY_MODE', {
        message:    'QODIQA_PG_ENABLED is not true: this deployment cannot audit authenticated decisions (audit schema v7 ' +
                    'pseudonymizes the caller with a key held in PostgreSQL). Authenticated requests will fail closed ' +
                    '(AUDIT_APPEND_FAILED / SUBJECT_PSEUDONYM_UNAVAILABLE) and their BLOCKs are not audited.',
        resolution: 'Enable PostgreSQL (QODIQA_PG_ENABLED=true with a migrated database) for any deployment that must ' +
                    'produce evidence. Production already refuses to start without it.',
      });
    }

    // ── -2.45. Migration-role credential gate ──
    // Migrations 002/038/060/065/067 create LOGIN roles with PUBLISHED placeholder
    // passwords. Prove — by attempting the login — that none of them still accepts
    // its placeholder; a role that does is a cross-tenant / BYPASSRLS backdoor with a
    // public password. Production: 'enforce' (default) → FATAL on any violation.
    // Elsewhere the gate is off unless QODIQA_PG_ROLE_CREDENTIAL_GATE=warn|enforce.
    // The gate only observes; it never alters a role (operator tool:
    // scripts/db/role-credentials.js, docs/operations/database-role-management.md).
    {
      const mode = process.env.QODIQA_PG_ROLE_CREDENTIAL_GATE || (REQUIRE_DURABLE_EVIDENCE ? 'enforce' : 'off');
      if (mode !== 'off' && pgPool.isEnabled()) {
        const probe = await roleCredentials.probeMigrationRoles();
        const summary = probe.results.map((x) => ({ role: x.role, migration: x.migration, result: x.result }));
        if (!probe.ok) {
          emit(mode === 'enforce' ? 'FATAL' : 'ERROR', 'PG_ROLE_PLACEHOLDER_CREDENTIAL', {
            roles: probe.violations.map((x) => x.role), results: summary,
            message: 'One or more migration-created PostgreSQL roles still accept the placeholder password published in the repository.',
            resolution: 'Rotate each listed role (ALTER ROLE … PASSWORD) or set it NOLOGIN — scripts/db/role-credentials.js --check / --harden. See docs/operations/database-role-management.md.',
          });
          if (mode === 'enforce') process.exit(1);
        } else if (!probe.proven) {
          emit('WARN', 'PG_ROLE_CREDENTIAL_UNPROVEN', { results: summary,
            message: 'No role accepted its placeholder, but some could not be probed from this host (pg_hba or connectivity). Verify them from a host that can reach them: scripts/db/role-credentials.js --check.' });
        } else {
          emit('INFO', 'PG_ROLE_CREDENTIALS_VERIFIED', { roles: summary.length, results: summary });
        }
      }
    }

    // ── -2.4. Control plane — after the gate, so a production
    // boot without PostgreSQL still reports EVIDENCE_DURABILITY_VIOLATION first ──
    // PostgreSQL-backed: the first pull must succeed before anything reads an
    // identity, a user, a tenant or a policy — otherwise every such read is
    // refused (CONTROL_PLANE_STALE), so starting without it is pointless.
    if (controlPlane.isPg()) {
      try {
        await controlPlane.start();
      } catch (err) {
        emit('FATAL', 'CONTROL_PLANE_UNAVAILABLE', {
          message: `The PostgreSQL control plane could not be loaded: ${err.message}`,
          resolution: 'Check QODIQA_PG_* / QODIQA_PG_CONTROL_PASSWORD, and that migrations 065/066 are applied. See docs/operations/control-plane.md.',
        });
        process.exit(1);
      }
      _signingIdentityReadiness();
      await _rbacBootstrap();
      const enforced = _enforcedPolicies();
      emit('INFO', 'POLICIES_ENFORCED', { count: enforced.length, ids: enforced.map(p => p.id), source: 'control-plane' });
    }

    // ── -2. Distributed audit chain preconditions (distributed mode only) ────
    // pgPool.initialize() has already run (top-level, above) by the time this
    // function is invoked — see start.js / the bottom of server.js. Refuses
    // to proceed (FATAL + exit(1), thrown by checkStartupPreconditions
    // itself) if PostgreSQL — the ordering authority in distributed mode —
    // isn't reachable. Then hydrates this replica's local chain[]/index
    // cache from PostgreSQL before accepting traffic. No-op in single-node
    // mode (its guard already ran synchronously above).
    if (_AUDIT_ORDERING_MODE === 'distributed') {
      const ok = await _checkAuditDistributedPreconditions();
      if (!ok) return; // already exited process(1); return keeps startServer() from continuing under test harnesses that stub _exit
      await _hydrateAuditChainFromPg();
    }

    // ── -1.9. Deployment mode resolution summary ────────────────────
    // Logged once startup has reached this point without a FATAL exit — i.e.
    // every invariant (topology assertion, and — distributed mode
    // only — migration verification / audit_chain_head reachability, both
    // just above) has already passed. See src/infra/config/deploymentMode.js.
    {
      const { getResolvedDeploymentConfig } = require('../src/infra/config/deploymentMode');
      const _deploymentConfig = getResolvedDeploymentConfig();
      emit('INFO', 'DEPLOYMENT_MODE_RESOLVED', {
        // deploymentMode is always exactly one of the two documented
        // QODIQA_DEPLOYMENT_MODE enum values, or null when that variable is
        // unset — never a third sentinel string. `source` (below) is the
        // separate, correct field for "how was this resolved": 'explicit'
        // (QODIQA_DEPLOYMENT_MODE set) vs 'legacy' (derived from
        // QODIQA_PG_ENABLED / QODIQA_AUDIT_ORDERING_MODE instead). A prior
        // revision of this log line folded 'legacy' into the deploymentMode
        // field itself via `?? 'legacy'` — a value no dashboard filtering on
        // deploymentMode IN ('single-node','distributed') would ever match,
        // silently hiding every legacy-configured deployment from that view.
        deploymentMode:      _deploymentConfig.deploymentMode,
        source:              _deploymentConfig.source,
        persistenceBackend:  pgPool.isEnabled() ? 'postgresql' : 'file',
        orderingBackend:     _AUDIT_ORDERING_MODE,
        migrationVerificationRequired: _deploymentConfig.migrationVerificationRequired,
        migrationStatus:     _deploymentConfig.migrationVerificationRequired ? 'verified' : 'not_required',
        autoMigrateEnabled:  _deploymentConfig.autoMigrateEnabled,
        replicaCount:        _deploymentConfig.replicaCount,
        startupValidation:   'PASSED',
      });
    }

    // ── -1.85. File-mode replay-horizon announcement ──────────────────
    // In single-node (file) mode, audit-chain-level replay/duplicate
    // rejection (`replay_detected` / `already_executed`) keys off the
    // bounded in-memory window: a nonce or artifactId reused from
    // OLDER than the last QODIQA_AUDIT_WINDOW_SIZE entries appends as a
    // new, correctly-chained entry instead of being rejected. This is a
    // DOCUMENTED LIMITATION (design decision 2026-08-26, action 2 —
    // no durable on-disk nonce index in file mode): the window IS the
    // explicit replay horizon, announced here so no operator discovers it
    // from an incident. Request-level replay protection (Redis nonce store
    // + STRICT_REPLAY) is unaffected, distributed mode keeps durable
    // uniqueness via PG UNIQUE constraints. CORRECTED:
    // the production profile does NOT categorically avoid this state —
    // only requires pgPool.isEnabled() (durable evidence storage), which a
    // NODE_ENV=production deployment can satisfy while
    // QODIQA_AUDIT_ORDERING_MODE stays 'single-node' (e.g.
    // QODIQA_DEPLOYMENT_MODE=single-node + QODIQA_PG_ENABLED=true — verified
    // via deploymentMode.js's own resolver: this combination yields
    // pgEnabled:true, auditOrderingMode:'single-node'). PG being enabled
    // only gives that deployment a best-effort, non-blocking PG mirror
    // (_appendOne's dual-write) — not durable append-time dedup. Only
    // genuine distributed ordering removes the horizon. Skipped when the
    // window is unbounded — the horizon is then the full history and
    // AUDIT_WINDOW_UNBOUNDED already warns about that configuration.
    if (_AUDIT_ORDERING_MODE !== 'distributed') {
      const { WINDOW_SIZE } = require('../src/core/audit/audit-log');
      if (Number.isFinite(WINDOW_SIZE)) {
        emit('WARN', 'AUDIT_REPLAY_HORIZON_BOUNDED', {
          windowSize: WINDOW_SIZE,
          message:    'File mode: audit-chain replay/duplicate rejection is bounded by the in-memory ' +
                      `window — the replay horizon is the last ${WINDOW_SIZE} entries ` +
                      '(QODIQA_AUDIT_WINDOW_SIZE). Reuse older than the window is appended, not rejected. ' +
                      'Request-level replay protection (Redis nonce store) is unaffected. ' +
                      'PG-authoritative deployments keep durable uniqueness. ' +
                      'See docs/operations/audit-log-retention-restart.md.',
        });
      }
    }

    // ── -1.83. Tenant configuration hydration ──────────────────
    // Loads every tenant's policy set + semantic config from PostgreSQL (the
    // persistence authority, migration 051) into the in-memory registries,
    // then starts the periodic refresh that keeps other replicas convergent.
    // No-op when PG is disabled (registries stay empty; every tenant falls
    // back to the global policies.json + pinned semantic defaults — the
    // documented dev semantics). In the production profile a hydration
    // failure is FATAL: booting with unhydrated registries would silently
    // downgrade every configured tenant to the global fallback — for a
    // tenant whose config tightens enforcement, that is a loosening, and
    // fail-closed is the required posture (same reasoning as the gate
    // above). Non-production keeps a WARN + empty-registry fallback.
    {
      const tenantConfigHydrator = require('../src/core/tenancy/tenantConfigHydrator');
      try {
        const hydration = await tenantConfigHydrator.hydrate();
        if (hydration.hydrated) tenantConfigHydrator.startRefresh();
      } catch (err) {
        if (REQUIRE_DURABLE_EVIDENCE) {
          emit('FATAL', 'TENANT_CONFIG_HYDRATION_FAILED', {
            message: 'Per-tenant policy/semantic configuration could not be hydrated from PostgreSQL — ' +
                     'booting would silently downgrade configured tenants to the global fallback. ' +
                     'The server refuses to start.',
            error: err.message,
          });
          process.exit(1);
        }
        emit('WARN', 'TENANT_CONFIG_HYDRATION_FAILED', {
          message: 'Per-tenant configuration hydration failed — continuing with empty tenant registries ' +
                   '(global fallback). Non-production only.',
          error: err.message,
        });
      }
    }

    // ── -1.8. Wire centralStore into logger ─────────────
    // Every subsequent emit() call is ingested into platform_audit_events
    // from this point on. Deliberately deferred to here — after the topology
    // assertion and, in distributed mode, migration verification have both
    // already succeeded above — rather than immediately after
    // pgPool.initialize() at module top level: see that call site's header
    // comment for the pool-exhaustion/circuit-breaker hazard this ordering
    // eliminates. Still runs well before the HTTP server starts accepting
    // traffic further down this function, so no request-path event is ever
    // missed.
    registerCentralStore(centralStore);

    // ── -1.51. Mirror recovery BEFORE the consistency check ─────────────────
    // A PG mirror that is an exact ordered PREFIX of the authoritative audit.log (a crash after fsync before the
    // mirror INSERT, or mirror writes lost to a PG outage) is brought up to the file tail through the live mirror
    // writer's own insert + evidence path. Nothing else is ever repaired: an empty mirror, a mirror whose tail is not
    // in the file chain, or a failed replay is left exactly as found and the unchanged fail-closed check below
    // decides. Idempotent. Rollback: QODIQA_AUDIT_MIRROR_BOOT_RECOVERY=off. See src/core/audit/mirrorBootRecovery.js.
    await require('../src/core/audit/mirrorBootRecovery').recoverMirrorBeforeBootCheck();

    // ── -1.5. Audit chain / PostgreSQL mirror consistency ──────────
    // Single-node mode with the PG mirror enabled only — a no-op in
    // distributed mode (PG is already the ordering authority there) and when
    // QODIQA_PG_ENABLED isn't set (no mirror to check against). Fails closed
    // (FATAL + exit(1)) before any request-serving setup below if the file
    // chain and PG mirror have diverged; never repairs or reconciles
    // automatically. See src/core/audit/mirrorConsistencyCheck.js.
    const _mirrorConsistent = await _verifyAuditMirrorConsistency();
    if (!_mirrorConsistent) return; // already exited process(1)

    // ── -1.49. audit_chain row-counter boot validation + reconciliation ──────────────
    // One exact cross-check of the migration 073 counter (read every 60 s by the PG lag monitor) against count(*),
    // then the same check every QODIQA_AUDIT_MIRROR_RECONCILE_INTERVAL_MS (default 6 h). Drift → CRITICAL
    // AUDIT_MIRROR_COUNT_DRIFT + alert; NEVER repaired automatically (owner-only rebuild). Non-fatal: the counter is
    // derived observability data — the fail-closed boot authorities are the checks above and below. Never on the 60 s
    // lag path. QODIQA_AUDIT_MIRROR_RECONCILE=off disables both. See src/core/audit/mirrorCountReconciler.js.
    {
      const _reconciler = require('../src/core/audit/mirrorCountReconciler');
      await _reconciler.validateAtBoot();
      _reconciler.startReconciler();
    }

    // ── -1.45. Live audit chain verifier watermark continuity (CHAIN-2) ──────
    // Catches what the mirror-consistency check above cannot: a coordinated
    // rollback of BOTH the file chain and its PG mirror together to an
    // older, mutually-consistent backup — which would still pass the
    // single-point-in-time file-vs-PG comparison above, and still pass
    // audit-log.js's own load-time hash-chain walk, because the restored
    // history is still internally a valid chain. Compares the durable state
    // just loaded against a watermark THIS deployment already confirmed in a
    // past run (persisted by the live verifier — see
    // src/core/audit/verifier/verifierState.js). O(1) — does not repeat the
    // full-chain walk loadFromDisk()/hydrateFromPgIfDistributed() already
    // performed above. Fails closed (FATAL + exit(1)) by default; never
    // repairs or reconciles automatically. See
    // src/core/audit/verifierStartupGate.js.
    const _verifierContinuityOk = await _verifyAuditChainVerifierContinuity();
    if (!_verifierContinuityOk) return; // already exited process(1)

    // ── -1.44. Signed audit checkpoint ─────────────
    // Single-node file chain only (the distributed chain's checkpoints are a item: every replica would sign).
    // FAIL-CLOSED: the latest signed checkpoint (PG and/or <audit.log>.checkpoints.jsonl) must verify with a
    // published, non-revoked checkpoint key and the chain must hold its headHash at its chainLength. Then the
    // scheduler signs a new one every QODIQA_AUDIT_CHECKPOINT_EVERY entries / 24 h, off the request path.
    if (_AUDIT_ORDERING_MODE !== 'distributed') {
      const _cpw = require('../src/core/audit/checkpoint/checkpointWriter');
      try {
        emit('INFO', 'AUDIT_CHECKPOINT_BOOT_CHECK', await _cpw.verifyLatestCheckpointAtBoot());
      } catch (err) {
        emit('FATAL', 'AUDIT_CHECKPOINT_BOOT_FAILED', { message: err.message });
        process.exit(1);
        return;
      }
      // against the customer-held anchor export (witness-cosigned checkpoints), when configured — FAIL-CLOSED
      // on deleted/replaced checkpoints, rollback below an anchored position or a rewritten prefix.
      try {
        // production anchoring must be REAL — at least one trusted witness key, and a local
        // witness whose own key is in that trusted set (otherwise no anchor could ever verify).
        if (process.env.NODE_ENV === 'production') emit('INFO', 'AUDIT_ANCHORING_POSTURE_VERIFIED', _cpw.verifyAnchoringPosture());
        emit('INFO', 'AUDIT_ANCHOR_BOOT_CHECK', await _cpw.verifyAnchorsAtBoot());
      } catch (err) {
        emit('FATAL', 'AUDIT_ANCHOR_BOOT_FAILED', { message: err.message, findings: err.findings || null });
        process.exit(1);
        return;
      }
      if (REQUIRE_DURABLE_EVIDENCE && !process.env.QODIQA_ANCHOR_EXPORT_PATH && (process.env.QODIQA_WITNESS_MODE || 'none') === 'none') {
        emit('WARN', 'AUDIT_ANCHORING_NOT_CONFIGURED', {
          message: 'No witness and no anchor export are configured: signed checkpoints are verifiable, but an insider with host/DB access can still rewrite recent history undetectably.',
          resolution: 'Set QODIQA_ANCHOR_EXPORT_PATH to customer-held storage and QODIQA_WITNESS_MODE=exec|local with QODIQA_WITNESS_PUBLIC_KEYS.',
        });
      }
      _cpw.startCheckpointScheduler();
    } else {
      // the distributed chain has no signed checkpoints or anchors yet. Production never reaches here
      // (the boot validator refuses distributed production); non-production says so at every boot.
      emit('WARN', 'AUDIT_ANCHORING_UNAVAILABLE_DISTRIBUTED', {
        message: 'Distributed mode: no signed checkpoints and no anchors run — an insider with database access can rewrite recent audit history undetectably.',
      });
    }

    // ── -1.4. Audit retention privilege validation ──────────
    // No-op unless QODIQA_PG_ENABLED=true. Verifies, via live catalog queries
    // against retentionPool, that the dedicated qodiqa_retention role (migration
    // 038_retention_dedicated_role.sql) actually holds every grant and RLS
    // policy retention.js's automated cleanup cycle requires. Fails closed
    // (FATAL + exit(1)) before any request-serving setup below if any is
    // missing or misconfigured. See src/core/audit/retentionPrivilegeCheck.js.
    const _retentionPrivilegesOk = await _verifyRetentionPrivileges();
    if (!_retentionPrivilegesOk) return; // already exited process(1)

    // ── -1.3. Rate-limiter distributed-enforcement precondition ─────
    // No-op in single-node mode. In a multi-instance deployment
    // (QODIQA_AUDIT_ORDERING_MODE=distributed), refuses to start if any
    // route in the now-fully-mounted `app` still uses the legacy
    // single-process limiter (middleware/publicRateLimit.js) — each replica
    // would otherwise enforce its own independent counter, multiplying the
    // effective limit by the replica count. See
    // src/core/rateLimit/startupGuard.js.
    if (!_checkNoLegacyRateLimiters(app)) return; // already exited process(1)

    // ── -1.25. Embedding-similarity classifier boot (SEM-C session 3) ────────
    // Owner-decided policy: block server start until the embedding backend
    // (ONNX MiniLM and
    // src/core/semantic/embeddingSimilarity/) is READY, rather than start
    // accepting traffic and fail-closed per-request during a loading/failed
    // window. This trades ~0.7-6s of added startup latency (cache-warm vs.
    // cold weight download, measured) for the simpler invariant "a request
    // is never evaluated against an embedding layer that isn't fully up."
    // See src/core/semantic/embeddingSimilarity/index.js's init()/
    // getStatus() for what READY actually verifies (model loaded + all 10
    // anchor embeddings computed).
    // Not wired into request enforcement here — see src/core/semantic/
    // embeddingGate.js and its call sites (src/api/routes/aiChat.js,
    // src/streaming/outputSemanticWindow.js) for that.
    // inference runs in a pool of worker threads (single-threaded ONNX sessions; at one thread
    // onnxruntime computes on the calling thread, so the main thread must not host it). Started BEFORE init() so
    // the anchor embeddings are produced the same way requests are. QODIQA_INFERENCE_WORKERS (boot rule
    // perf.inference_workers): default 4; 0 = in-process.
    const _inferenceWorkers = process.env.QODIQA_INFERENCE_WORKERS === undefined || process.env.QODIQA_INFERENCE_WORKERS === ''
      ? 4 : Number(process.env.QODIQA_INFERENCE_WORKERS);
    try {
      if (require('../src/core/semantic/embeddingSimilarity/config').EMBEDDING_ENABLED) {
        await require('../src/core/semantic/embeddingSimilarity/embeddingBackend').enablePool(_inferenceWorkers);
        emit('INFO', 'INFERENCE_POOL_READY', { workers: _inferenceWorkers });
      }
    } catch (err) {
      emit('FATAL', 'INFERENCE_POOL_STARTUP_FAILED', { workers: _inferenceWorkers, error: err.message });
      process.exit(1);
    }
    const _embeddingStatus = await embeddingClassifier.init();
    if (_embeddingStatus.status === 'DISABLED') {
      emit('WARN', 'EMBEDDING_CLASSIFIER_DISABLED', { impact: 'content screening is limited to the rule engine (QODIQA_SEM_EMBEDDING_ENABLED=false)' });
    } else if (_embeddingStatus.status !== 'READY') {
      emit('FATAL', 'EMBEDDING_CLASSIFIER_STARTUP_FAILED', {
        status: _embeddingStatus.status,
        error:  _embeddingStatus.error,
      });
      process.exit(1);
      return; // see other FATAL branches above/below for this exact pattern
    }
    if (_embeddingStatus.status === 'READY') emit('INFO', 'EMBEDDING_CLASSIFIER_READY', {
      model:       _embeddingStatus.model,
      anchorCount: _embeddingStatus.anchorCount,
      threshold:   _embeddingStatus.threshold,
    });

    // ── -1. Startup and clock diagnostics ────────────────────────────────────
    // Emitted once at startup — before Redis initialization — so the snapshot
    // captures the environment at launch time.  activeKeys and policyCount are
    // already validated above; passed in so diagnostics avoids re-deriving them.
    emitStartupDiagnostics({ activeKeys: _ks.totalActive, policyCount: _enforcedPolicies().length });
    emitClockDiagnostics();

    // ── 0. Redis security config summary ─────────────────────────────────────
    // Read env vars once before store initialization so we can emit auth/TLS
    // events at the gateway level and include the fields in GATEWAY_START.
    // Credentials are never logged — only the boolean config state is emitted.
    const _redisCfg = getConfigSummary();

    if (_redisCfg.authConfigured) {
      emit('INFO', 'REDIS_AUTH_CONFIGURED', { note: 'credentials present — validation deferred to store probe' });
    } else {
      emit('WARN', 'REDIS_AUTH_MISSING', {
        message: 'No Redis credentials configured. ' +
                 'Set REDIS_PASSWORD (and optionally REDIS_USERNAME) or embed ' +
                 'credentials in REDIS_URL for authenticated deployments.',
      });
    }

    if (_redisCfg.tlsEnabled) {
      emit('INFO', 'REDIS_TLS_ENABLED', { source: 'GATEWAY', tlsVerified: _redisCfg.tlsVerified, url: _redisCfg.urlRedacted });
    } else {
      emit('INFO', 'REDIS_TLS_DISABLED', {
        source:  'GATEWAY',
        message: 'Redis TLS not configured. Set REDIS_TLS=true or use a rediss:// URL ' +
                 'for encrypted transport in production.',
      });
    }

    // ── 1. Initialize live Redis stores concurrently ──────────────────────────
    // initialize() eagerly connects and runs a namespace probe — confirms the
    // actual runtime store (not a disconnected diagnostic client) is ready.
    // Promise.allSettled ensures both stores are attempted even if one fails.
    const [nonceResult, anomalyResult, rlResult] = await Promise.allSettled([
      nonceStore.initialize(),
      anomalyStore.initialize(),
      rateLimitStoreModule.initialize(),
    ]);

    const nonceReady   = _emitStoreResult('NONCE_STORE',        nonceResult);
    const anomalyReady = _emitStoreResult('ANOMALY_STORE',      anomalyResult);
    const rlReady      = _emitStoreResult('RATE_LIMIT_STORE',   rlResult);

    // (step 4): the request limiter's init was started at module load;
    // let it settle (bounded) so every rateLimitProtectionActive reported
    // below is the limiter's real state, not a race against its connect.
    if (_rlInitPromise) {
      await Promise.race([_rlInitPromise, new Promise((resolve) => setTimeout(resolve, 5000).unref())]);
    }

    // ── 2. Auth validation summary ────────────────────────────────────────────
    // The per-store probes already emitted REDIS_AUTH_VALIDATED if auth was
    // configured and the probe succeeded.  Emit a gateway-level summary here
    // that callers can correlate with GATEWAY_START.
    const authValidated = _redisCfg.authConfigured && nonceReady && anomalyReady && rlReady;
    if (_redisCfg.authConfigured) {
      emit(
        authValidated ? 'INFO' : 'WARN',
        authValidated ? 'REDIS_AUTH_VALIDATED' : 'REDIS_AUTH_FAILED',
        {
          source: 'GATEWAY', nonceReady, anomalyReady, rlReady,
          note: authValidated
            ? 'both store probes succeeded — credentials accepted by Redis'
            : 'one or more store probes failed — auth may have been rejected',
        },
      );
    }

    // ── 3. Persistence diagnostics via the live nonce store client ────────────
    // checkPersistence() uses the same Redis client as register() — diagnostics
    // reflect the actual runtime store, not a separate diagnostic connection.
    let persistDiag = null;
    if (nonceReady) {
      persistDiag = await nonceStore.checkPersistence();

      emit(persistDiag.safe ? 'INFO' : 'WARN', 'REDIS_PERSISTENCE_STATUS', {
        safe:        persistDiag.safe,
        aofEnabled:  persistDiag.aofEnabled,
        appendfsync: persistDiag.appendfsync,
        lastSave:    persistDiag.lastSave !== null ? new Date(persistDiag.lastSave).toISOString() : null,
        warnings:    persistDiag.warnings.length,
      });

      for (const w of persistDiag.warnings) {
        emit('WARN', 'REDIS_PERSISTENCE_WARNING', { detail: w });
      }

      if (persistDiag.safe) {
        emit('INFO', 'REDIS_PERSISTENCE_VALIDATED', { aofEnabled: persistDiag.aofEnabled, appendfsync: persistDiag.appendfsync });
      } else {
        emit('WARN', 'REDIS_PERSISTENCE_UNSAFE', {
          aofEnabled:  persistDiag.aofEnabled,
          appendfsync: persistDiag.appendfsync,
          warningCount: persistDiag.warnings.length,
          replayProtectionDegraded: true,
          message: 'Redis persistence is not durably configured — nonce state may be lost on restart.',
        });
        emit('WARN', 'REPLAY_PROTECTION_DEGRADED', {
          source:  'PERSISTENCE',
          message: 'Redis persistence is not durably configured. Nonce state may not survive a ' +
                   'Redis restart or crash. Replay protection integrity is reduced. ' +
                   'Set STRICT_REPLAY_PROTECTION=true to refuse startup under these conditions.',
        });
      }

      // #1: the check above runs once, here, at startup. Start the
      // recurring background validator too — same precondition (nonceReady)
      // as this one-shot check, same live connection (nonceStore), so
      // runtime drift (safe -> unsafe after boot) is no longer invisible.
      redisPersistenceMonitor.initialize();
    }

    // ── 4. STRICT_REPLAY gate: refuse to start if persistence is unsafe ───────
    if (STRICT_REPLAY) {
      const persistSafe = nonceReady && persistDiag?.safe === true;
      if (!persistSafe) {
        const diag = persistDiag ?? {};
        emit('FATAL', 'STRICT_REPLAY_PROTECTION_VIOLATION', {
          message:     'STRICT_REPLAY_PROTECTION=true but Redis connectivity or persistence ' +
                       'guarantees are insufficient. The server refuses to start to preserve ' +
                       'replay protection integrity.',
          nonceReady,
          anomalyReady,
          aofEnabled:  diag.aofEnabled  ?? null,
          appendfsync: diag.appendfsync ?? null,
          warnings:    diag.warnings    ?? [],
          nonceError:  nonceResult.status === 'rejected'
            ? (nonceResult.reason?.message ?? String(nonceResult.reason))
            : null,
          resolution:  'Ensure Redis is running with: appendonly yes, appendfsync everysec. ' +
                       'See docs/deployment/redis-persistence.md for production deployment requirements.',
        });
        process.exit(1);
      }
    }

    // ── 5. Emit startup degradation events ────────────────────────────────────
    // Explicit per-subsystem degradation events at startup so operators can
    // determine execution integrity state from the startup log alone.
    if (!nonceReady) {
      emit('WARN', 'REPLAY_PROTECTION_DEGRADED', {
        source:                 'STARTUP',
        executionBlocked:       true,
        replayProtectionActive: false,
        message:                'Nonce store failed to initialize — replay protection unavailable. ' +
                                'All execution requests will be blocked fail-closed.',
      });
    }
    if (!anomalyReady) {
      emit('WARN', 'ANOMALY_PROTECTION_DEGRADED', {
        source:                  'STARTUP',
        executionBlocked:        true,
        anomalyProtectionActive: false,
        message:                 'Anomaly store failed to initialize — anomaly protection unavailable. ' +
                                 'All execution requests will be blocked fail-closed.',
      });
    }
    if (!rlReady) {
      emit('WARN', 'POLICY_RATE_LIMIT_DEGRADED', {
        source:                    'STARTUP',
        executionBlocked:          true,
        rateLimitProtectionActive: _requestRateLimitActive(),
        message:                   'Rate limit store failed to initialize — distributed rate limiting degraded to fail-closed.',
      });
    }
    if (!nonceReady || !anomalyReady || !rlReady) {
      emit('WARN', 'REDIS_RUNTIME_DEGRADED', {
        nonceReady,
        anomalyReady,
        rlReady,
        replayProtectionActive:    nonceReady,
        anomalyProtectionActive:   anomalyReady,
        rateLimitProtectionActive: _requestRateLimitActive(),
        executionIntegrity:        'DEGRADED',
        message:                   'One or more Redis stores failed to initialize. All execution requests ' +
                                   'requiring Redis will be blocked fail-closed until stores reconnect.',
      });
    }

    // ── 5.5. Set up gateway runtime monitoring ────────────────────────────────
    // Subscribes to store emitters so gateway-level events are emitted
    // whenever execution integrity changes at runtime (reconnects, failures).
    _setupRuntimeMonitoring(nonceReady, anomalyReady, rlReady);
    _setupMetricsFromStores(nonceReady, anomalyReady, rlReady);

    // ── 5.6. Emit gateway startup integrity state ─────────────────────────────
    const _allReady           = nonceReady && anomalyReady && rlReady;
    const _noneReady          = !nonceReady && !anomalyReady && !rlReady;
    const _executionIntegrity = _allReady ? 'FULL' : 'DEGRADED';
    const _gatewayRuntimeEvent = _allReady
      ? 'GATEWAY_RUNTIME_READY'
      : _noneReady
        ? 'GATEWAY_RUNTIME_DEGRADED'
        : 'GATEWAY_RUNTIME_PARTIAL_FAILURE';
    const _gatewayStateEvent  = _allReady
      ? 'GATEWAY_STATE_READY'
      : _noneReady
        ? 'GATEWAY_STATE_UNHEALTHY'
        : 'GATEWAY_STATE_DEGRADED';

    const _startupFields = {
      source:                    'STARTUP',
      nonceStoreReady:           nonceReady,
      anomalyStoreReady:         anomalyReady,
      rateLimitStoreReady:       rlReady,
      replayProtectionActive:    nonceReady,
      anomalyProtectionActive:   anomalyReady,
      rateLimitProtectionActive: _requestRateLimitActive(),
      requestRateLimitEnabled:   _isRlEnabled(),
      executionIntegrity:        _executionIntegrity,
      redisPersistenceSafe:      persistDiag?.safe ?? null,
      authConfigured:            _redisCfg.authConfigured,
      authValidated,
      tlsEnabled:                _redisCfg.tlsEnabled,
    };

    emit(_allReady ? 'INFO' : 'WARN', _gatewayRuntimeEvent, _startupFields);
    emit(_allReady ? 'INFO' : 'WARN', _gatewayStateEvent,   _startupFields);

    // ── 5.7. Revocation subscriber — required control-plane dependency ───────────
    // This node must be subscribed to the revocation channel before accepting
    // consent-dependent traffic.  If it cannot connect within the startup timeout,
    // the node cannot guarantee immediate enforcement of revoked consent and must
    // not enter normal operating mode.
    try {
      await consentSubscriber.start();
      emit('INFO', 'REVOCATION_SUBSCRIBER_STARTUP_OK', { channel: 'qodiqa:consent:revocation' });
    } catch (err) {
      emit('FATAL', 'REVOCATION_SUBSCRIBER_STARTUP_FAILED', {
        error:   err.message,
        message: 'Cannot subscribe to consent revocation channel — node cannot guarantee ' +
                 'instant revocation enforcement. Ensure Redis is reachable and retry.',
      });
      process.exit(1);
    }

    // ── 5.7b. Organization-status subscriber — required control-plane ─────
    // dependency. This node must be subscribed to the org-status channel (and
    // have completed an initial reconciliation sweep against the Redis-backed
    // authoritative store) before accepting org-scoped traffic — otherwise a
    // suspension applied on another worker has no guaranteed upper bound on
    // when this node would observe it. See src/core/organizations/status/
    // OrgStatusSubscriber.js and docs/architecture/multi-tenancy.md for the documented
    // consistency model and maximum propagation delay.
    //
    // organizationRegistry.js and OrgStatusSubscriber.js no longer require()
    // each other (Finding 64 / that was a genuine circular
    // dependency papered over with lazy in-function requires). This
    // composition root wires them together explicitly, now that both modules
    // are loaded, before the subscriber is started.
    organizationRegistry.setOrgStatusSubscriber(orgStatusSubscriber);
    orgStatusSubscriber.setOrganizationRegistry(organizationRegistry);

    try {
      await orgStatusSubscriber.start();
      emit('INFO', 'ORG_STATUS_SUBSCRIBER_STARTUP_OK', {
        channel: 'qodiqa:org:status:change',
        maxPropagationWindowMs: orgStatusSubscriber.MAX_PROPAGATION_WINDOW_MS,
      });
    } catch (err) {
      emit('FATAL', 'ORG_STATUS_SUBSCRIBER_STARTUP_FAILED', {
        error:   err.message,
        message: 'Cannot subscribe to organization status channel — node cannot guarantee ' +
                 'bounded suspension propagation. Ensure Redis is reachable and retry.',
      });
      process.exit(1);
    }

    // ── 5.5. Proxy configuration validation ────────────────────
    const _proxyValidation = validateProxyConfig();
    if (_proxyValidation.warnings.length > 0) {
      for (const w of _proxyValidation.warnings) {
        emit('WARN', 'PROXY_CONFIG_WARNING', { message: w });
      }
    }
    emit('INFO', 'PROXY_CONFIG_VALIDATED', _proxyValidation.summary);

    // ── 5.6. close the audit lifecycles the previous process left open ──
    // Before the server listens nothing of this process is in flight, so every open INTENT in the tail window belongs to
    // a request of the previous process. Never fatal: what cannot be closed now is retried by the reconciler.
    try {
      await require('../src/core/audit/lifecycleReconciler').reconcileAtBoot();
    } catch (err) {
      emit('ERROR', 'AUDIT_LIFECYCLE_BOOT_RECONCILIATION_FAILED', { error: err.message });
    }
    // executed requests of the previous process that never got their COMMIT
    try {
      require('../src/core/audit/commitEntry'); // registers the COMMIT recorder with the reconciler and the recovery queue
      await require('../src/core/audit/lifecycleReconciler').reconcileCommitsAtBoot();
      // distributed ordering: peers' DECISIONs younger than the grace period were skipped above; look again periodically
      if (process.env.QODIQA_AUDIT_ORDERING_MODE === 'distributed') {
        const t = setInterval(() => { require('../src/core/audit/lifecycleReconciler').reconcileCommitsAtBoot().catch(() => {}); }, 5 * 60 * 1000);
        if (t.unref) t.unref();
      }
    } catch (err) {
      emit('ERROR', 'AUDIT_COMMIT_BOOT_RECONCILIATION_FAILED', { error: err.message });
    }

    // ── 6. Start accepting traffic ────────────────────────────────────────────
    // transport hardening is applied to the http.Server BEFORE .listen()
    // is called, not inside the listen callback. Node arms its internal
    // connections-checking sweep timer's period (connectionsCheckingInterval)
    // using whatever value is present at/before .listen() begins — a
    // reassignment inside the listen callback (the previous pattern here,
    // and Express's own app.listen() collapses server construction and
    // .listen() into one call, leaving no earlier hook point) never reaches
    // that already-armed timer. requestTimeout/headersTimeout/keepAliveTimeout
    // are unaffected by this distinction (the sweep reads them fresh on each
    // tick), but connectionsCheckingInterval specifically is not — confirmed
    // empirically, not assumed:
    const _httpServer = http.createServer(app);
    configureTlsDefaults(_httpServer, emit);
    _httpServer.listen(PORT, BIND_HOST, () => {
      readinessStateModule.setReady(_allReady);
      emit('INFO', 'GATEWAY_START', {
        port:                      PORT,
        activeKeys:                _ks.totalActive,
        strictReplayProtection:    STRICT_REPLAY,
        nonceStoreReady:           nonceReady,
        anomalyStoreReady:         anomalyReady,
        rateLimitStoreReady:       rlReady,
        replayProtectionActive:    nonceReady,
        anomalyProtectionActive:   anomalyReady,
        rateLimitProtectionActive: _requestRateLimitActive(),
        requestRateLimitEnabled:   _isRlEnabled(),
        executionIntegrity:        _executionIntegrity,
        redisPersistenceSafe:      persistDiag?.safe ?? null,
        authConfigured:            _redisCfg.authConfigured,
        authValidated,
        tlsEnabled:                _redisCfg.tlsEnabled,
        ready:                     _allReady,
      });
      // (step 4): one truthful, secret-free statement of what this process
      // is running with — observed, not inferred. Never throws (a reporting
      // fault emits BOOT_REPORT_FAILED instead). See src/infra/config/bootReport.js.
      _emitBootReport({
        opsConfig:                    _opsConfig,
        nonceReady, anomalyReady, rlReady,
        requestRateLimitEnabled:      _isRlEnabled(),
        requestRateLimitStorageReady: _rateLimitStorageReady(),
        requestRateLimitFailModes:    (() => {
          const s = require('../src/core/rateLimit').getConfig().surfaces; const out = { closed: [], degrade: [] };
          for (const [k, v] of Object.entries(s)) out[v.failMode === 'degrade' ? 'degrade' : 'closed'].push(k);
          return out;
        })(),
        executionIntegrity:           _executionIntegrity,
        // group commit on/off (QODIQA_AUDIT_GROUP_COMMIT rollback switch) + any boot WAL recovery action
        auditStorage:                 (() => { try { return require('../src/core/audit/audit-log').getStorageReport(); } catch { return null; } })(),
      }, {
        emit,
        deps: {
          listKeys:  () => keyManager.listPublicKeys,
          providers: () => getEnabledProviders(),
        },
      });
    });

    // ── 6.5. Schedule daily audit retention cycle ─────────────────────────────
    // Runs once 5 minutes after startup, then every 24 hours.
    // Only active when QODIQA_PG_ENABLED=true; no-op otherwise. Gated on
    // retentionPool — the pool runRetentionCycle() actually queries
    // through — rather than pgPool; both are enabled/disabled by the same env
    // var today, but this keeps the gate honest about the real dependency.
    if (retentionPool.isEnabled()) {
      const { runRetentionCycle } = require('../src/core/audit/retention');
      const { runTask } = require('../src/runtime/backgroundTasks/BackgroundTaskRunner');
      const _RETENTION_INTERVAL = 24 * 60 * 60 * 1000;
      // Finding 3.6: runs through BackgroundTaskRunner for consistent
      // isolation/logging/metrics; the `!result.ok` branch preserves the
      // pre-existing AUDIT_RETENTION_SCHEDULE_FAILED event operators
      // already grep for (BackgroundTaskRunner separately emits its own
      // generic BACKGROUND_TASK_FAILED/metric).
      const _runRetentionTick = () => runTask('audit-retention-cycle', () => runRetentionCycle())
        .then((result) => {
          if (!result.ok) emit('ERROR', 'AUDIT_RETENTION_SCHEDULE_FAILED', { error: result.error.message });
        });
      setTimeout(() => {
        _runRetentionTick();
        setInterval(_runRetentionTick, _RETENTION_INTERVAL).unref();
      }, 5 * 60 * 1000).unref();

      emit('INFO', 'AUDIT_RETENTION_SCHEDULED', {
        initialDelayMs: 300_000,
        intervalMs:     _RETENTION_INTERVAL,
      });
    }

    // ── 6.6. Start Transparency Gap Scanner (Component #34) ──────────────────
    // Only active when TRANSPARENCY_SCANNER_ENABLED=true and PG is enabled.
    // Scanner is non-blocking: failures are logged, never crash the process.
    //
    // CLN-04: GapScanner.js performs genuine sequence/hash/root verification
    // against the transparency log, but scannerConfig.js defaults it OFF.
    // That's a silent operational gap when PG is enabled — mirrors the MON-3
    // notification-channel check above (WARN by default, FATAL when
    // QODIQA_REQUIRE_TRANSPARENCY_SCANNER=true). See deploy/env/production.env.example's
    // "TRANSPARENCY GAP SCANNER (CLN-04)" section and
    // docs/operations/transparency-recovery.md §3.1.
    let _gapScanner = null;
    if (pgPool.isEnabled()) {
      if (process.env.TRANSPARENCY_SCANNER_ENABLED === 'true') {
        const { createScanner: _createGapScanner } =
          require('../src/core/transparency/scanner');
        _gapScanner = _createGapScanner();
        _gapScanner.start().catch(e =>
          emit('ERROR', 'TRANSPARENCY_SCANNER_START_FAILED', { error: e.message })
        );
        emit('INFO', 'TRANSPARENCY_SCANNER_CONFIG_ENABLED', {
          message: 'TRANSPARENCY_SCANNER_ENABLED=true — transparency log gap/hash/root ' +
                   'verification is active.',
        });
      } else if (process.env.QODIQA_REQUIRE_TRANSPARENCY_SCANNER === 'true') {
        emit('FATAL', 'TRANSPARENCY_SCANNER_REQUIRED_BUT_MISSING', {
          message: 'QODIQA_REQUIRE_TRANSPARENCY_SCANNER=true but TRANSPARENCY_SCANNER_ENABLED ' +
                   'is not "true" — the transparency log would run with no automated ' +
                   'sequence/hash/root gap detection. Set TRANSPARENCY_SCANNER_ENABLED=true. ' +
                   'See deploy/env/production.env.example and docs/operations/transparency-recovery.md.',
        });
        process.exit(1);
      } else {
        emit('WARN', 'NO_TRANSPARENCY_SCANNER_CONFIGURED', {
          message: 'TRANSPARENCY_SCANNER_ENABLED is not "true" — PostgreSQL is enabled but ' +
                   'the transparency log has no automated sequence/hash/root gap detection ' +
                   'running. Splices or corruption in transparency_log_entries / ' +
                   'transparency_roots will not be automatically detected. Set ' +
                   'TRANSPARENCY_SCANNER_ENABLED=true to enable it, or ' +
                   'QODIQA_REQUIRE_TRANSPARENCY_SCANNER=true to make this fatal instead of a ' +
                   'warning. See deploy/env/production.env.example and ' +
                   'docs/operations/transparency-recovery.md.',
        });
      }
    }

    // ── 6.6b. Start Transparency Root Scheduler ────────────────
    // rootScheduler.js existed but had no caller, so no signed Merkle root was
    // ever produced unless an operator called root generation by hand, and no
    // per-decision inclusion proof could resolve. On by default whenever PG is
    // enabled; QODIQA_TRANSPARENCY_ROOT_SCHEDULER_ENABLED=false opts out.
    // Interval: TRANSPARENCY_ROOT_INTERVAL_MS (default here 60000 — the
    // module's own default of 0 means "time trigger off", which is what left
    // it inert); TRANSPARENCY_ROOT_ENTRY_THRESHOLD adds an entry-count trigger.
    // Multi-replica safe: generateRoot() serializes on the roots head lock and
    // a losing replica's "no new entries" is a normal skip.
    let _rootScheduler = null;
    if (pgPool.isEnabled() && process.env.QODIQA_TRANSPARENCY_ROOT_SCHEDULER_ENABLED !== 'false') {
      const { createScheduler: _createRootScheduler } = require('../src/core/transparency/rootScheduler');
      const _rootEnvInt = (k, d) => {
        const n = parseInt(process.env[k] ?? '', 10);
        return Number.isFinite(n) && n >= 0 ? n : d;
      };
      _rootScheduler = _createRootScheduler({
        intervalMs:     _rootEnvInt('TRANSPARENCY_ROOT_INTERVAL_MS', 60_000),
        entryThreshold: _rootEnvInt('TRANSPARENCY_ROOT_ENTRY_THRESHOLD', 0),
      });
      _rootScheduler.start().catch(e =>
        emit('ERROR', 'TRANSPARENCY_ROOT_SCHEDULER_START_FAILED', { error: e.message })
      );
    }

    // ── 6.6c. Start Queue-Depth Monitor ────────────────────────────────
    // Samples every durable backlog (recovery queue by type, retries,
    // TRANSPARENCY_SAVE, DLQ, journal, audit mirror writer, unrooted
    // transparency span) into gauges and raises OPERATIONAL/QUEUE_BACKLOG
    // alerts at the thresholds documented in queueMonitor.js.
    let _queueMonitor = null;
    if (pgPool.isEnabled()) {
      _queueMonitor = require('../src/core/persistenceRecovery/queueMonitor').createQueueMonitor();
      _queueMonitor.start();
    }

    // ── 6.7. Start Automatic Key Rotation Scheduler + Trust-Store Reload ────
    // Fully self-configuring from env vars (see services/artifact/rotationScheduler.js).
    // Rotation and reload are independent: rotation ticking no-ops
    // when QODIQA_KEY_ROTATION_ENABLED=false or QODIQA_KEY_ROTATION_SCHEDULE=
    // disabled (manual rotation via POST /key-admin/:clientId/rotate remains
    // available either way), but trust-store reload — the mechanism that
    // propagates revocations, key replacements, and metadata updates made on
    // other instances or via a shared keys.json — keeps running on its own
    // cadence regardless, unless explicitly turned off via
    // QODIQA_KEY_RELOAD_ENABLED=false (not recommended for fleet deployments).
    const { getDefaultScheduler: _getRotationScheduler } = require('../services/artifact/rotationScheduler');
    const _rotationScheduler = _getRotationScheduler();
    _rotationScheduler.start();

    // ── 6.8. Start Live Audit Chain Integrity Verifier (CHAIN-2) ─────────────
    // Unlike the Transparency Gap Scanner above, this defaults to ENABLED
    // (QODIQA_AUDIT_VERIFIER_ENABLED, default 'true' — opt OUT, not opt in):
    // CHAIN-2 exists precisely because the primary execution audit chain had
    // no automated detector at all, and file-mode operation needs no
    // PostgreSQL precondition the way the Gap Scanner does. Runs
    // independently of PG being enabled — verifies the file chain in
    // single-node mode, the PostgreSQL chain in distributed mode, plus an
    // additional periodic file-vs-PG divergence check when dual-write is on.
    // Non-blocking: failures are logged, never crash the process. See
    // src/core/audit/verifier/index.js.
    const { getDefaultRunner: _getAuditChainVerifierRunner } = require('../src/core/audit/verifier');
    const _auditChainVerifierRunner = _getAuditChainVerifierRunner();
    _auditChainVerifierRunner.start().catch(e =>
      emit('ERROR', 'AUDIT_CHAIN_VERIFIER_START_FAILED', { error: e.message })
    );

    // ── 7. Register graceful shutdown handlers ────────────────────────────────
    // SIGTERM and SIGINT trigger the ordered shutdown sequence exactly once.
    // Shutdown order: NOT READY → close HTTP → drain requests → close Redis →
    //                 confirm audit flush → exit(0).
    //
    // PG_POOL placement depends on audit ordering mode: in single-node mode,
    // audit writes are fire-and-forget to PG (file is authoritative), so
    // closing PG_POOL alongside the other stores is harmless. In distributed
    // mode, pending appends drained by the audit flush step need PostgreSQL
    // — the ordering authority — to still be reachable, so PG_POOL must be
    // disconnected AFTER the flush (postFlushStores), not alongside it. See
    // src/runtime/shutdown.js's header comment.
    // (step 5): flush the batched platform_audit_events writer BEFORE the pool closes (bounded; never throws).
    const _pgPoolStoreEntry = { name: 'PG_POOL', store: { disconnect: async () => { await require('../src/core/audit/centralStore').flush().catch(() => {}); await pgPool.shutdown(); } } };
    _registerShutdownHandlers(_httpServer, [
      { name: 'TRACING',               store: { disconnect: () => _tracing.shutdown() } },
      { name: 'METRICS_EXPORT',        store: { disconnect: () => _metricsOtlpBridge.shutdown() } },
      { name: 'EVENT_LOOP_MONITOR',    store: { disconnect: () => eventLoopMonitor.shutdown() } },
      { name: 'REDIS_PERSISTENCE_MONITOR', store: { disconnect: () => redisPersistenceMonitor.shutdown() } },
      { name: 'KEY_EXPIRY_MONITOR',    store: { disconnect: () => keyExpiryMonitor.shutdown() } },
      { name: 'LATENCY_SLA_MONITOR',   store: { disconnect: () => latencySlaMonitor.shutdown() } },
      { name: 'ALERTING_FRAMEWORK',    store: { disconnect: () => alertingFramework.shutdown() } },
      { name: 'LOG_SHIPPER',           store: { disconnect: async () => { auditEventDispatcher.detach(); await _logShipper.shutdown(5000); } } },
      { name: 'TRANSPARENCY_SCANNER',  store: { disconnect: () => { if (_gapScanner) _gapScanner.stop(); } } },
      { name: 'TRANSPARENCY_ROOT_SCHEDULER', store: { disconnect: () => { if (_rootScheduler) _rootScheduler.stop(); } } },
      { name: 'QUEUE_DEPTH_MONITOR',   store: { disconnect: () => { if (_queueMonitor) _queueMonitor.stop(); } } },
      { name: 'AUDIT_CHAIN_VERIFIER',  store: { disconnect: () => _auditChainVerifierRunner.stop() } },
      { name: 'KEY_ROTATION_SCHEDULER', store: { disconnect: () => _rotationScheduler.stop() } },
      { name: 'KEY_ROTATION_LOCK',     store: { disconnect: () => require('../src/infra/keys/rotationLock').disconnect() } },
      { name: 'REVOCATION_SUBSCRIBER', store: { disconnect: () => consentSubscriber.stop() } },
      { name: 'REVOCATION_PUBLISHER',  store: { disconnect: () => consentPublisher.disconnect() } },
      { name: 'ARTIFACT_REVOCATION_STORE', store: { disconnect: () => require('../src/core/artifactRevocation').close() } },
      { name: 'ORG_STATUS_SUBSCRIBER', store: { disconnect: () => orgStatusSubscriber.stop() } },
      { name: 'ORG_STATUS_PUBLISHER',  store: { disconnect: () => orgStatusPublisher.disconnect() } },
      { name: 'ORG_STATUS_STORE',      store: { disconnect: () => orgStatusStore.disconnect() } },
      { name: 'CONSENT_CACHE',         store: { disconnect: () => require('../src/core/consent/ConsentCache').disconnect() } },
      { name: 'CONTROL_PLANE',         store: { disconnect: () => controlPlane.stop() } },
      { name: 'NONCE_STORE',           store: nonceStore },
      { name: 'ANOMALY_STORE',         store: anomalyStore },
      { name: 'RATE_LIMIT_STORE',      store: rateLimitStoreModule },
      { name: 'AUTH_LOCKOUT_STORE',    store: { disconnect: () => _disconnectAuthLockout() } },
      { name: 'IDEMPOTENCY_STORE',     store: idempotencyStore },
      { name: 'RECOVERY_QUEUE',        store: { disconnect: () => _shutdownRecoveryQueue() } },
      // Not part of the audit write/ordering path (unlike PG_POOL below) — the
      // retention cleanup cycle is an independent background job, so no
      // postFlushStores ordering constraint applies here.
      { name: 'RETENTION_POOL',        store: { disconnect: () => retentionPool.shutdown() } },
      // ER 2026-10-06: the role pools (system / reporting / control) were never closed on graceful shutdown.
      { name: 'ROLE_POOLS',            store: { disconnect: () => rolePools.shutdownAll() } },
      ...(_AUDIT_ORDERING_MODE === 'distributed' ? [] : [_pgPoolStoreEntry]),
    ], {
      requestDrain:     requestDrainModule,
      readinessState:   readinessStateModule,
      // KMS/HSM providers are torn down LAST (after every store, and after the PG flush in
      // distributed mode), so nothing still needing the KEK runs after it: the in-memory KEK is zeroized and the HSM
      // session is logged out instead of being left to the HSM's own session timeout.
      // GA-CKPT-RATE: the final signed audit checkpoint, after the request drain and while
      // PostgreSQL is still connected — single-node only, where the checkpoint scheduler runs (see step -1.44).
      preStoreHooks:    _AUDIT_ORDERING_MODE === 'distributed' ? [] : [
        { name: 'AUDIT_FINAL_CHECKPOINT', run: () => require('../src/core/audit/checkpoint/checkpointWriter').signFinalCheckpoint() }],
      postFlushStores:  [..._AUDIT_ORDERING_MODE === 'distributed' ? [_pgPoolStoreEntry] : [],
        { name: 'KMS_PROVIDERS', store: { disconnect: () => require('../src/infra/keys/keyProviderFactory').shutdown() } }],
    });
}

// ── ctx ──────────────────────────────────────────────────────────────────────
// Already-constructed values the composition root (src/app.js) mounts as
// middleware / passes into route factories. Exposed here rather than rebuilt
// in src/app.js because several of these (ops-auth, the shared auth-lockout
// instance, the admin/ops protection stacks) are required to be single
// shared instances — see the AUTH-2 and Task #27 comments above.
const ctx = {
  maxBodyBytes:      MAX_BODY_BYTES,
  getPolicies:       _enforcedPolicies,
  reloadPolicies:    _reloadPolicies,
  policyStore:       store,
  tracing:           _tracing,
  opsIpAllow:        _opsIpAllow,
  healthLoopback:    _healthLoopback,
  healthAuth:        _healthAuth,
  opsOnlyStack:       _opsOnlyStack,
  adminStack:        _adminStack,
  requirePermission: _requirePermission,
  profilingGate:     _profilingGate,
  // tenant self-service portal.
  portalEnabled:     _portalEnabled,
  portalSessionAuth: _portalSessionAuth,
  portalRateLimit:   _portalRateLimit,
  rbacResolve:       _rbacResolve,
};

/**
 * ER: undo everything that LOADING this module starts (module-level side effects, not startServer()).
 *
 * Loading server/startup.js initialises, at module scope: three monitors, the application and retention PostgreSQL
 * pools (with their readiness/lag monitors), the auth-lockout, idempotency and rate-limit Redis stores, the alerting
 * framework, and — when QODIQA_PG_ENABLED=true or PRQ_ENABLED=true — the persistence-recovery queue (worker + journal
 * worker). startServer()'s graceful-shutdown sequence stops all of these for a running server; an embedder that only
 * loads the module (the in-process route-parity suites) had no complete way to, and stopped only three monitors. Under
 * `jest --runInBand` with PostgreSQL enabled (the CI coverage-gate job) the leftovers kept the process alive forever:
 * the recovery worker's poll timer kept the event loop alive and kept querying the pool, so its sockets never idled out.
 * Uses the same disconnect calls as the graceful-shutdown list, in dependency order (recovery queue before the pool it
 * queries; pools last). Each step is isolated: one failure never skips the rest. Not called by the running server.
 */
async function stopLoadTimeSideEffects() {
  const steps = [
    ['RATE_LIMIT_INIT', () => _rlInitPromise],
    ['CONTROL_PLANE_START', () => _loadTimeControlPlaneStart],
    ['ALERTING_INIT', () => _loadTimeAlertingInit],
    ['CONTROL_PLANE', () => controlPlane.stop()],
    ['RECOVERY_QUEUE', () => _shutdownRecoveryQueue()],
    ['ALERTING', () => alertingFramework.shutdown()],
    ['AUTH_LOCKOUT_STORE', () => _disconnectAuthLockout()],
    ['IDEMPOTENCY_STORE', () => idempotencyStore.disconnect && idempotencyStore.disconnect()],
    ['RATE_LIMIT_STORE', () => rateLimitStoreModule.disconnect && rateLimitStoreModule.disconnect()],
    ['KEY_EXPIRY_MONITOR', () => keyExpiryMonitor.shutdown && keyExpiryMonitor.shutdown()],
    ['EVENT_LOOP_MONITOR', () => eventLoopMonitor.shutdown && eventLoopMonitor.shutdown()],
    ['LATENCY_SLA_MONITOR', () => latencySlaMonitor.shutdown && latencySlaMonitor.shutdown()],
    ['TRACING', () => _tracing && _tracing.shutdown && _tracing.shutdown()],
    ['METRICS_OTLP', () => _metricsOtlpBridge && _metricsOtlpBridge.shutdown && _metricsOtlpBridge.shutdown()],
    ['RETENTION_POOL', () => retentionPool.shutdown()],
    ['ROLE_POOLS', () => rolePools.shutdownAll()],
    ['PG_POOL', () => pgPool.shutdown()],
  ];
  const failures = [];
  for (const [name, fn] of steps) {
    try { await fn(); } catch (err) { failures.push({ name, error: err && err.message }); }
  }
  return { stopped: steps.map(([n]) => n), failures };
}

module.exports = { ctx, startServer, stopLoadTimeSideEffects };
