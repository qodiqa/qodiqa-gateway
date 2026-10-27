'use strict';

/**
 * Route mount table — single source of truth for "which file implements
 * which mount prefix", shared by routeParity.test.js (OpenAPI-vs-implementation
 * parity) and src/api/responseEnvelopes.js (response-envelope
 * governance). Extracted into its own module (rather than living inline in
 * routeParity.test.js) so non-test code can require it without re-executing
 * a Jest test file's describe/test registrations.
 *
 * Mirrors server.js's app.use('<prefix>', ..., <router>) calls. A file may
 * appear more than once (e.g. aiChat.js is mounted at four distinct
 * prefixes). Keep in sync with server.js when routers are added, removed,
 * or remounted — this list is the one static fact neither consumer can
 * derive from source text alone.
 */

const MOUNTS = [
  { prefix: '/health/redis', file: 'src/api/routes/healthRedis.js' },
  { prefix: '/health',       file: 'src/api/routes/health.js' },
  { prefix: '/ready',        file: 'src/api/routes/ready.js' },
  { prefix: '/metrics',      file: 'src/api/routes/metrics.js' },
  { prefix: '/diagnostics',  file: 'src/api/routes/diagnostics.js' },
  // Item 27 (ITEM-26-RESPONSE-ENVELOPE-DECISION-RECORD.md, D26-5 point 1):
  // was mounted at app.js but absent from this list, making it invisible to
  // responseEnvelopeGovernance.test.js §A's coverage check. Its 3 routes are
  // intentionally excluded from the OpenAPI surface (routeParity.test.js's
  // KNOWN_UNDOCUMENTED) — unchanged by this addition, just now visible here too.
  { prefix: '/diagnostics/profile', file: 'src/api/routes/diagnosticsProfile.js' },
  { prefix: '/ai/chat',           file: 'src/api/routes/aiChat.js' },
  { prefix: '/ai/chat/stream',    file: 'src/api/routes/aiChat.js' },
  { prefix: '/v1/ai/chat',        file: 'src/api/routes/aiChat.js' },
  { prefix: '/v1/ai/chat/stream', file: 'src/api/routes/aiChat.js' },
  { prefix: '/verify',      file: 'src/api/routes/verify.js' },
  { prefix: '/v1/verify',   file: 'src/api/routes/verify.js' },
  { prefix: '/sign',        file: 'src/api/routes/sign.js' },
  { prefix: '/.well-known', file: 'src/api/routes/well-known.js' },
  { prefix: '/public-key',  file: 'src/api/routes/public-key.js' },
  { prefix: '/public-keys', file: 'src/api/routes/publicKeys.js' },
  { prefix: '/keys',        file: 'src/api/routes/keys.js' },
  { prefix: '/audit',        file: 'src/api/routes/audit.js' },
  { prefix: '/audit-viewer', file: 'src/api/routes/auditViewer.js' },
  { prefix: '/policy-ui',    file: 'src/api/routes/policyManagement.js' },
  { prefix: '/provenance',   file: 'src/api/routes/policyProvenance.js' },
  { prefix: '/evidence-chain', file: 'src/api/routes/evidenceChain.js' },
  { prefix: '/evidence',       file: 'src/api/routes/evidence.js' },
  { prefix: '/v1/evidence',    file: 'src/api/routes/evidence.js' },
  { prefix: '/transparency',    file: 'src/api/routes/transparencyLog.js' },
  { prefix: '/v1/transparency', file: 'src/api/routes/transparencyLog.js' },
  { prefix: '/portal',    file: 'src/api/routes/verificationPortal.js' },
  { prefix: '/v1/portal', file: 'src/api/routes/verificationPortal.js' },
  { prefix: '/v1/attestation', file: 'src/api/routes/attestation.js' },
  { prefix: '/v1/certification',  file: 'src/api/routes/certification.js' },
  { prefix: '/v1/certifications', file: 'src/api/routes/certificationBatch.js' },
  { prefix: '/dashboard',   file: 'src/api/routes/dashboard.js' },
  { prefix: '/key-admin',   file: 'src/api/routes/keyAdmin.js' },
  { prefix: '/rbac',        file: 'src/api/routes/rbacAdmin.js' },
  { prefix: '/signing-identities', file: 'src/api/routes/admin/signingIdentities.js' },
  { prefix: '/audit-store', file: 'src/api/routes/auditStore.js' },
  { prefix: '/compliance',  file: 'src/api/routes/compliance.js' },
  { prefix: '/alerts',      file: 'src/alerting/api/alertRoutes.js' },
  { prefix: '/consent',     file: 'src/api/routes/consent.js' },
  { prefix: '/v1/webhooks', file: 'src/api/routes/webhooks.js' },
  { prefix: '/v1/prq',      file: 'src/api/routes/prqDlq.js' },
  { prefix: '/v1/admin/organizations', file: 'src/api/routes/admin/organizations.js' },
  { prefix: '/v1/admin/tenants',       file: 'src/api/routes/admin/tenants.js' },
  { prefix: '/v1/admin/kill-switch',   file: 'src/api/routes/admin/killSwitch.js' },   //
  { prefix: '/v1/admin/providers',     file: 'src/api/routes/admin/providers.js' },    //
  { prefix: '/auth/saml',              file: 'src/api/routes/samlAuth.js' },           //
  { prefix: '/auth/ldap',              file: 'src/api/routes/ldapAuth.js' },           //
  { prefix: '/v1/admin/artifact-revocations', file: 'src/api/routes/admin/artifactRevocations.js' },   //
  { prefix: '/v1/proofs', file: 'src/api/routes/proofs.js' },   //
  { prefix: '/v1/agents', file: 'src/api/routes/agents.js' },   //
  { prefix: '/v1/sessions', file: 'src/api/routes/agentSessions.js' }, //
  { prefix: '/v1/tool-registry', file: 'src/api/routes/toolRegistry.js' }, //
  { prefix: '/v1/actions', file: 'src/api/routes/actions.js' }, //
  { prefix: '/v1/delegations', file: 'src/api/routes/delegations.js' }, //
  { prefix: '/v1/tools', file: 'src/api/routes/tools.js' }, //
  { prefix: '/v1/mcp/servers', file: 'src/api/routes/mcpServers.js' }, //
  { prefix: '/v1/approvals', file: 'src/api/routes/approvals.js' }, //
  { prefix: '/v1/policy', file: 'src/api/routes/policySimulate.js' },
  { prefix: '/v1/policy', file: 'src/api/routes/policyVisual.js' },
  { prefix: '/v1/admin/dsr',       file: 'src/api/routes/admin/dsr.js' },
  { prefix: '/v1/policy/governance', file: 'src/api/routes/admin/policyGovernance.js' },
];

// Routes served from hardcoded/variable paths (not string literals), so they
// cannot be extracted by routeParity.test.js's regex scan — declared
// explicitly instead. src/api/routes/openapi.js builds these from
// `options.jsonPath` etc., all defaulted in server.js's
// `createOpenApiRouter()` call (no overrides).
const EXPLICIT_ROUTES = [
  { method: 'get', path: '/openapi.json' },
  { method: 'get', path: '/openapi.yaml' },
  { method: 'get', path: '/docs' },
];

module.exports = { MOUNTS, EXPLICIT_ROUTES };
