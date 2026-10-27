'use strict';

/**
 * OpenAPI Generation — Constants
 *
 * Fixed metadata for the QODIQA OpenAPI 3.1 specification.
 * All strings here are authoritative — update this file when
 * product metadata changes (version, contact, licence, servers).
 */

const API_VERSION = '1.0.0';
const OPENAPI_VERSION = '3.1.0';

// ── Info object ───────────────────────────────────────────────────────────────

const INFO = Object.freeze({
  title: 'QODIQA API',
  version: API_VERSION,
  description: [
    'QODIQA is an AI Authorization and Consent Enforcement Platform.',
    '',
    'It is a **deterministic authorization layer** that decides whether an AI system',
    'is allowed to execute an action.',
    '',
    '**Core principles:**',
    '- Default Deny',
    '- Explicit Authorization',
    '- Immutable Decision Artifacts',
    '- Deterministic Evaluation',
    '- Cryptographic Trust',
    '- Human-readable Policies',
    '- Explainable Decisions',
    '- Audit-first Architecture',
    '',
    '## Authentication',
    '',
    'Ops-protected endpoints require a bearer token in the `Authorization` header.',
    'Two token types are accepted:',
    '',
    '- **Per-operator API key** (preferred): `Authorization: Bearer ok_<64-hex-chars>`',
    '- **Shared ops token** (deprecated): `Authorization: Bearer <ops-token>` or `x-ops-token: <token>`',
    '',
    'The `/sign` endpoint uses a separate credential: a per-identity signing API key,',
    '`Authorization: Bearer sk_<64-hex-chars>`, issued via `POST /signing-identities/{id}/api-key`.',
    'There is no shared signing secret — every caller has its own individually-revocable identity.',
    '',
    '## Response format',
    '',
    'All non-streaming endpoints return JSON.  Success responses are wrapped in a',
    'standard envelope: `{ status, timestamp, requestId, data }`.  Enforcement',
    'decision endpoints (`/verify`, `/ai/chat`) return',
    '`{ decision: "EXECUTE"|"BLOCK", reason, requestId, ... }`. They return HTTP 200 for',
    'EXECUTE and, in the default `decision` mode (QODIQA_BLOCK_HTTP_MODE), for enforcement',
    'BLOCKs — read `decision`, not the status. Transport, input-guard, throttle and dependency',
    'failures use 4xx/5xx in both modes (see each operation and `x-qodiqa-error-catalog`).',
  ].join('\n'),
  contact: Object.freeze({
    name: 'QODIQA',
    url: 'https://github.com/qodiqa/qodiqa-gateway',
    email: 'contact@qodiqa.com',
  }),
  license: Object.freeze({
    name: 'Apache-2.0',
    url: 'https://github.com/qodiqa/qodiqa-gateway/blob/main/LICENSE',
  }),
});

// ── Servers ───────────────────────────────────────────────────────────────────

const SERVERS = Object.freeze([
  Object.freeze({
    url: 'http://localhost:3000',
    description: 'Local development server',
  }),
  Object.freeze({
    url: 'https://gateway.example.com',
    description: 'Example of a hosted gateway',
  }),
]);

// ── Tags ──────────────────────────────────────────────────────────────────────

const TAGS = Object.freeze([
  { name: 'Health',                description: 'Health and readiness probes for load balancers and orchestrators' },
  { name: 'Metrics',               description: 'Prometheus-format operational metrics' },
  { name: 'Diagnostics',           description: 'Runtime diagnostics for platform engineers' },
  { name: 'Execution',             description: 'AI request execution with enforcement pipeline' },
  { name: 'Verification',          description: 'Verify signed artifacts without executing the underlying request' },
  { name: 'Signing',               description: 'Generate signed artifacts for downstream enforcement' },
  { name: 'Consent',               description: 'Consent registry: grant, revoke, suspend, resume, and query consent records' },
  { name: 'Policy Management',     description: 'Create, update, enable, disable, and version authorization policies' },
  { name: 'Policy Simulation',     description: 'Simulate and compare policy decisions without side-effects' },
  { name: 'Policy Visual Builder', description: 'Generate visual representations of authorization policies (Component #41)' },
  { name: 'Audit',                 description: 'Immutable append-only cryptographic enforcement audit chain' },
  { name: 'Audit Store',           description: 'Centralized cross-subsystem audit event store, search, and retention management' },
  { name: 'Audit Viewer',          description: 'Forensic audit chain explorer: search, timeline, export, and investigations' },
  { name: 'Compliance',            description: 'Compliance reporting and framework control assessment' },
  { name: 'Evidence',              description: 'Evidence packages: collect, export, and verify audit evidence' },
  { name: 'Attestation',           description: 'Cryptographic attestation of AI system behavior' },
  { name: 'Certification',         description: 'AI system certification against compliance frameworks' },
  { name: 'Transparency Log',      description: 'Append-only transparency log with Merkle root proofs' },
  { name: 'Verification Portal',   description: 'Public self-service verification portal' },
  { name: 'Provenance',            description: 'Policy change provenance and history tracking' },
  { name: 'Policy Governance',     description: 'Maker-checker policy change governance: draft, review, approve, publish, rollback, and emergency override' },
  { name: 'Data Subject Rights',   description: 'GDPR Data Subject Rights administration: rectification, erasure, restriction, and portability requests' },
  { name: 'RBAC',                  description: 'Role-based access control: users, roles, permissions, and API keys' },
  { name: 'Key Management',        description: 'Signing key lifecycle: rotate, revoke, and inspect' },
  { name: 'Signing Identities',    description: 'Per-identity signing credentials for POST /sign (TRUST-1)' },
  { name: 'Public Keys',           description: 'Public key discovery for artifact verification' },
  { name: 'Webhooks',              description: 'Webhook endpoint management and delivery log' },
  { name: 'Organizations',         description: 'Organization administration (multi-tenant hierarchy)' },
  { name: 'Tenants',               description: 'Tenant administration (multi-tenant hierarchy)' },
  { name: 'Agents',                description: 'Agent identities and their bounded sessions' },
  { name: 'Proofs',                description: 'Downloadable proof of one request, verifiable offline' },
  { name: 'Artifact revocation',   description: 'Withdraw one signed artifact before it is used' },
  { name: 'Kill switch',           description: 'Global kill switch — stop and resume all signing and execution' },
  { name: 'Alerts',                description: 'Alerting framework: alert list, lifecycle, notification channels, and real-time streams' },
  { name: 'Dashboard',             description: 'Operational dashboard data' },
  { name: 'Persistence Recovery',  description: 'Dead-letter queue and retry management' },
  { name: 'Well-Known',            description: 'IANA well-known endpoints for key discovery' },
  { name: 'Meta',                  description: 'Endpoints that describe the API itself (this specification and its interactive explorer)' },
]);

// ── External docs ─────────────────────────────────────────────────────────────

const EXTERNAL_DOCS = Object.freeze({
  description: 'QODIQA Platform Documentation',
  url: 'https://github.com/qodiqa/qodiqa-gateway',

});

module.exports = {
  OPENAPI_VERSION,
  API_VERSION,
  INFO,
  SERVERS,
  TAGS,
  EXTERNAL_DOCS,
};
