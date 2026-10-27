'use strict';

/**
 * Rate Limit Configuration —
 *
 * Centralized policy configuration with Zod schema validation.
 * Invalid configuration throws during loadConfig() — fail-fast at startup.
 *
 * Policy dimensions (all configurable):
 *   surfaces    — per API surface (always evaluated, basis for every request)
 *   tenants     — per tenant ID; overrides surface default for that tenant
 *   users       — per RBAC user (API key); overrides for that specific key
 *   signingKeys — per signing key ID; independent quota from API keys
 *   endpoints   — per named endpoint; most specific override
 *
 * Per-policy fields:
 *   maxRequests        — sustained limit per windowSeconds
 *   windowSeconds      — window duration (use 3600 for hourly, 86400 for daily)
 *   burstCapacity      — max requests in burstWindowSeconds (0 = disabled)
 *   burstWindowSeconds — burst detection window (default 5s)
 *   unlimited          — skip rate limiting for this identity (VIP bypass)
 *   disabled           — block all requests for this identity (revoked key etc)
 *
 * All surface defaults are overridable via environment variables:
 *   RL_{SURFACE}_MAX, RL_{SURFACE}_WINDOW, RL_{SURFACE}_BURST, RL_{SURFACE}_BURST_WINDOW
 */

const { z, integer }    = require('../../validation/zod');
const { emit } = require('../../../services/logger');

// ── Schemas ───────────────────────────────────────────────────────────────────

const PolicySchema = z.object({
  maxRequests:        z.number().check(integer()).positive(),
  windowSeconds:      z.number().check(integer()).positive(),
  burstCapacity:      z.number().check(integer()).min(0).default(0),
  burstWindowSeconds: z.number().check(integer()).positive().default(5),
  unlimited:          z.boolean().default(false),
  disabled:           z.boolean().default(false),
  // (D3 → C): behaviour when the Redis backend is unavailable. 'closed' →
  // 429 RATE_LIMIT_BACKEND_UNAVAILABLE (auth, /sign, admin); 'degrade' → the
  // same policy enforced by a per-process in-memory limiter + CRITICAL alert
  // (traffic surfaces). Set in code per surface, not by environment.
  failMode:           z.enum(['closed', 'degrade']).default('closed'),
});

const QuotaSchema = PolicySchema.extend({
  surface: z.string().optional(),
});

const ConfigSchema = z.object({
  surfaces:    z.record(z.string(), PolicySchema),
  tenants:     z.record(z.string(), QuotaSchema).default({}),
  users:       z.record(z.string(), QuotaSchema).default({}),
  signingKeys: z.record(z.string(), QuotaSchema).default({}),
  endpoints:   z.record(z.string(), PolicySchema).default({}),
});

// ── Environment variable helpers ──────────────────────────────────────────────

function _int(name, fallback) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

// ── Surface defaults ──────────────────────────────────────────────────────────

function _buildSurfaceDefaults() {
  return {
    // (D2 → Moderate): public reads 120/min per IP; failMode 'degrade' marks the
    // traffic surfaces (D3 → C). Every other surface keeps failMode 'closed'.
    portal:              { failMode: 'degrade', maxRequests: _int('RL_PORTAL_MAX', 120),              windowSeconds: _int('RL_PORTAL_WINDOW', 60),              burstCapacity: _int('RL_PORTAL_BURST', 20),              burstWindowSeconds: _int('RL_PORTAL_BURST_WINDOW', 5) },
    attestation:         { failMode: 'degrade', maxRequests: _int('RL_ATTESTATION_MAX', 120),          windowSeconds: _int('RL_ATTESTATION_WINDOW', 60),          burstCapacity: _int('RL_ATTESTATION_BURST', 10),         burstWindowSeconds: _int('RL_ATTESTATION_BURST_WINDOW', 5) },
    certification:       { failMode: 'degrade', maxRequests: _int('RL_CERTIFICATION_MAX', 120),        windowSeconds: _int('RL_CERTIFICATION_WINDOW', 60),        burstCapacity: _int('RL_CERTIFICATION_BURST', 5),         burstWindowSeconds: _int('RL_CERTIFICATION_BURST_WINDOW', 5) },
    certification_batch: { maxRequests: _int('RL_CERTIFICATION_BATCH_MAX', 20),  windowSeconds: _int('RL_CERTIFICATION_BATCH_WINDOW', 60),  burstCapacity: _int('RL_CERTIFICATION_BATCH_BURST', 5),   burstWindowSeconds: _int('RL_CERTIFICATION_BATCH_BURST_WINDOW', 5) },
    transparency:        { failMode: 'degrade', maxRequests: _int('RL_TRANSPARENCY_MAX', 120),         windowSeconds: _int('RL_TRANSPARENCY_WINDOW', 60),         burstCapacity: _int('RL_TRANSPARENCY_BURST', 15),        burstWindowSeconds: _int('RL_TRANSPARENCY_BURST_WINDOW', 5) },
    portal_admin:        { maxRequests: _int('RL_PORTAL_ADMIN_MAX', 500),        windowSeconds: _int('RL_PORTAL_ADMIN_WINDOW', 60),        burstCapacity: _int('RL_PORTAL_ADMIN_BURST', 50),        burstWindowSeconds: _int('RL_PORTAL_ADMIN_BURST_WINDOW', 5) },
    attestation_admin:   { maxRequests: _int('RL_ATTESTATION_ADMIN_MAX', 300),   windowSeconds: _int('RL_ATTESTATION_ADMIN_WINDOW', 60),   burstCapacity: _int('RL_ATTESTATION_ADMIN_BURST', 30),   burstWindowSeconds: _int('RL_ATTESTATION_ADMIN_BURST_WINDOW', 5) },
    certification_admin: { maxRequests: _int('RL_CERTIFICATION_ADMIN_MAX', 150), windowSeconds: _int('RL_CERTIFICATION_ADMIN_WINDOW', 60), burstCapacity: _int('RL_CERTIFICATION_ADMIN_BURST', 20), burstWindowSeconds: _int('RL_CERTIFICATION_ADMIN_BURST_WINDOW', 5) },
    transparency_admin:  { maxRequests: _int('RL_TRANSPARENCY_ADMIN_MAX', 300),  windowSeconds: _int('RL_TRANSPARENCY_ADMIN_WINDOW', 60),  burstCapacity: _int('RL_TRANSPARENCY_ADMIN_BURST', 30),  burstWindowSeconds: _int('RL_TRANSPARENCY_ADMIN_BURST_WINDOW', 5) },
    webhooks_admin:      { maxRequests: _int('RL_WEBHOOKS_ADMIN_MAX', 200),      windowSeconds: _int('RL_WEBHOOKS_ADMIN_WINDOW', 60),      burstCapacity: _int('RL_WEBHOOKS_ADMIN_BURST', 20),      burstWindowSeconds: _int('RL_WEBHOOKS_ADMIN_BURST_WINDOW', 5) },
    // (D2): /sign 60/min per signing identity (burst 15/5 s), 120/min per IP pre-auth (sign_auth).
    sign:                { maxRequests: _int('RL_SIGN_MAX', 60),                 windowSeconds: _int('RL_SIGN_WINDOW', 60),                 burstCapacity: _int('RL_SIGN_BURST', 15),                  burstWindowSeconds: _int('RL_SIGN_BURST_WINDOW', 5) },
    // sign_auth: coarse, IP-keyed throttle applied BEFORE credential
    // resolution (see src/middleware/signAuth.js) — blunts brute-force
    // guessing of signing API keys independent of the per-identity 'sign'
    // quota above, which only applies once a credential has resolved.
    sign_auth:           { maxRequests: _int('RL_SIGN_AUTH_MAX', 120),           windowSeconds: _int('RL_SIGN_AUTH_WINDOW', 60),            burstCapacity: _int('RL_SIGN_AUTH_BURST', 30),            burstWindowSeconds: _int('RL_SIGN_AUTH_BURST_WINDOW', 5) },
    audit:               { maxRequests: _int('RL_AUDIT_MAX', 30),               windowSeconds: _int('RL_AUDIT_WINDOW', 60),               burstCapacity: _int('RL_AUDIT_BURST', 5),                 burstWindowSeconds: _int('RL_AUDIT_BURST_WINDOW', 5) },

    // ── migrated off middleware/publicRateLimit.js ──────────────────
    // Each surface's default max/window mirrors that route's exact
    // pre-migration in-memory limit (see WP-007-REMEDIATION-REPORT.md).
    // Routes whose old limit was already env-configurable read that SAME
    // env var name here, so the operator-facing config contract is unchanged.
    verify_public:       { failMode: 'degrade', maxRequests: _int('RL_VERIFY_PUBLIC_MAX', 30),                        windowSeconds: _int('RL_VERIFY_PUBLIC_WINDOW', 60) },
    verify_v2:           { failMode: 'degrade', maxRequests: _int('VERIFY_V2_RATE_LIMIT_MAX', 60),                     windowSeconds: Math.round(_int('VERIFY_V2_RATE_LIMIT_WINDOW_MS', 60_000) / 1000) },
    audit_verifier_manual: { maxRequests: _int('RL_AUDIT_VERIFIER_MANUAL_MAX', 5),                windowSeconds: _int('RL_AUDIT_VERIFIER_MANUAL_WINDOW', 300) },
    audit_viewer:        { maxRequests: _int('RL_AUDIT_VIEWER_MAX', 60),                          windowSeconds: _int('RL_AUDIT_VIEWER_WINDOW', 60) },
    evidence_chain:      { maxRequests: _int('RL_EVIDENCE_CHAIN_MAX', 120),                       windowSeconds: _int('RL_EVIDENCE_CHAIN_WINDOW', 60) },
    evidence:            { maxRequests: _int('RL_EVIDENCE_MAX', 30),                              windowSeconds: _int('RL_EVIDENCE_WINDOW', 60) },
    keys:                { failMode: 'degrade', maxRequests: _int('RL_KEYS_MAX', 120),                                 windowSeconds: _int('RL_KEYS_WINDOW', 60) },
    public_keys:         { failMode: 'degrade', maxRequests: _int('RL_PUBLIC_KEYS_MAX', 120),                          windowSeconds: _int('RL_PUBLIC_KEYS_WINDOW', 60) },
    policy_management:   { maxRequests: _int('RL_POLICY_MANAGEMENT_MAX', 60),                     windowSeconds: _int('RL_POLICY_MANAGEMENT_WINDOW', 60) },
    policy_provenance:   { maxRequests: _int('RL_POLICY_PROVENANCE_MAX', 120),                    windowSeconds: _int('RL_POLICY_PROVENANCE_WINDOW', 60) },
    rbac_admin:          { maxRequests: _int('RL_RBAC_ADMIN_MAX', 60),                             windowSeconds: _int('RL_RBAC_ADMIN_WINDOW', 60) },
    well_known:          { failMode: 'degrade', maxRequests: _int('RL_WELL_KNOWN_MAX', 120),                           windowSeconds: _int('RL_WELL_KNOWN_WINDOW', 60) },
    // the archived-key discovery endpoint is expected to see far
    // less traffic than live discovery (only verifiers checking artifacts
    // old enough to have outlived the live keystore) — a materially lower
    // budget than 'well_known' both reflects that and limits the cost of
    // repeatedly rebuilding/serving the archive index.
    well_known_archived: { failMode: 'degrade', maxRequests: _int('RL_WELL_KNOWN_ARCHIVED_MAX', 20),                    windowSeconds: _int('RL_WELL_KNOWN_ARCHIVED_WINDOW', 60) },
    health_probe:        { failMode: 'degrade', maxRequests: _int('QODIQA_HEALTH_RATE_LIMIT_MAX', 240),                windowSeconds: Math.round(_int('QODIQA_HEALTH_RATE_LIMIT_WINDOW_MS', 60_000) / 1000) },
    ops_admin:           { maxRequests: _int('QODIQA_OPS_RATE_LIMIT_MAX', 120),                    windowSeconds: Math.round(_int('QODIQA_OPS_RATE_LIMIT_WINDOW_MS', 60_000) / 1000) },
    // tenant self-service portal (src/api/routes/tenantPortal.js). A
    // DIFFERENT surface from the pre-existing 'portal' entry above (the
    // unrelated Public Verification Portal, Component #23) — deliberately
    // named to avoid any ambiguity between the two.
    tenant_portal:       { maxRequests: _int('QODIQA_PORTAL_RATE_LIMIT_MAX', 60),                  windowSeconds: Math.round(_int('QODIQA_PORTAL_RATE_LIMIT_WINDOW_MS', 60_000) / 1000) },

    // ── ──────────────────────────────────────────────────
    // ai_chat_ip: per client IP, mounted BEFORE artifact decoding on every
    // /ai/chat alias — the only throttle an unauthenticated caller meets. It is
    // generous because a legitimate backend may send all of its users' traffic
    // from one egress IP; per-customer limiting is ai_chat_identity.
    ai_chat_ip:          { failMode: 'degrade', maxRequests: _int('RL_AI_CHAT_IP_MAX', 600),            windowSeconds: _int('RL_AI_CHAT_IP_WINDOW', 60),            burstCapacity: _int('RL_AI_CHAT_IP_BURST', 100),           burstWindowSeconds: _int('RL_AI_CHAT_IP_BURST_WINDOW', 5) },
    // ai_chat_identity: per verified signing identity, checked in the handler
    // right after the artifact signature has been verified.
    ai_chat_identity:    { failMode: 'degrade', maxRequests: _int('RL_AI_CHAT_IDENTITY_MAX', 1200),     windowSeconds: _int('RL_AI_CHAT_IDENTITY_WINDOW', 60) },
    // public_verify: the public verification routes that can persist records
    // (attestation/portal/transparency verify, D7), per IP, on top of their
    // router's read bucket.
    // public_docs: GET /openapi.json, /openapi.yaml, /docs
    public_docs:         { failMode: 'degrade', maxRequests: _int('RL_PUBLIC_DOCS_MAX', 120),              windowSeconds: _int('RL_PUBLIC_DOCS_WINDOW', 60) },
    public_verify:       { failMode: 'degrade', maxRequests: _int('RL_PUBLIC_VERIFY_MAX', 30),           windowSeconds: _int('RL_PUBLIC_VERIFY_WINDOW', 60) },
    // certification_evaluate: POST /v1/certification/evaluate (authenticated
    //) — writes attestations and transparency entries per call.
    certification_evaluate: { maxRequests: _int('RL_CERTIFICATION_EVALUATE_MAX', 20),               windowSeconds: _int('RL_CERTIFICATION_EVALUATE_WINDOW', 60), burstCapacity: _int('RL_CERTIFICATION_EVALUATE_BURST', 5), burstWindowSeconds: 5 },
  };
}

const KNOWN_SURFACES = new Set(Object.keys(_buildSurfaceDefaults()));

// ── Config state ──────────────────────────────────────────────────────────────

let _config = null;

/**
 * Load and validate rate limit configuration.
 * Throws on invalid configuration (fail-fast at startup).
 *
 * @param {object} [overrides] — merged into surface defaults (useful for testing)
 * @returns {object} validated, frozen-like config
 */
function loadConfig(overrides = {}) {
  const raw = {
    surfaces:    { ..._buildSurfaceDefaults(), ...(overrides.surfaces || {}) },
    tenants:     overrides.tenants     || {},
    users:       overrides.users       || {},
    signingKeys: overrides.signingKeys || {},
    endpoints:   overrides.endpoints   || {},
  };

  const result = ConfigSchema.safeParse(raw);
  if (!result.success) {
    const errors = result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ');
    emit('FATAL', 'RATE_LIMIT_CONFIG_INVALID', { errors });
    throw new Error(`Rate limit configuration invalid: ${errors}`);
  }

  _config = result.data;
  emit('INFO', 'RATE_LIMIT_CONFIG_LOADED', {
    surfaces:    Object.keys(_config.surfaces).length,
    tenants:     Object.keys(_config.tenants).length,
    users:       Object.keys(_config.users).length,
    signingKeys: Object.keys(_config.signingKeys).length,
    endpoints:   Object.keys(_config.endpoints).length,
  });
  return _config;
}

function getConfig() {
  if (!_config) loadConfig();
  return _config;
}

function _reset() { _config = null; }

module.exports = {
  loadConfig,
  getConfig,
  _reset,
  KNOWN_SURFACES,
  PolicySchema,
  QuotaSchema,
  ConfigSchema,
};
