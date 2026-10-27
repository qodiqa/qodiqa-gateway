'use strict';

/**
 * Components Builder — OpenAPI Component #42
 *
 * Builds the reusable `components` section of the OpenAPI 3.1 specification.
 * Covers: schemas, responses, parameters, security schemes, examples, headers.
 *
 * All component names referenced elsewhere MUST be defined here.
 * No external state, no I/O — pure function.
 */

const sg = require('./schemaGenerator');

// ── Security schemes ──────────────────────────────────────────────────────────

const SECURITY_SCHEMES = {
  BearerAuth: {
    type: 'http',
    scheme: 'bearer',
    description: [
      'Per-operator API key (preferred) or shared ops token.',
      '',
      '**Per-operator API key**: `Authorization: Bearer ok_<64 hex chars>`',
      '',
      'API keys are issued via `POST /rbac/users/{id}/api-key` and stored as',
      'SHA-256 hashes — the plaintext is shown **once** at creation.',
      '',
      '**Shared ops token** (deprecated): `Authorization: Bearer <QODIQA_OPS_TOKEN>`',
    ].join('\n'),
  },
  OpsTokenHeader: {
    type: 'apiKey',
    in: 'header',
    name: 'x-ops-token',
    description: 'Deprecated shared ops token header. Prefer BearerAuth.',
  },
  SigningApiKey: {
    type: 'http',
    scheme: 'bearer',
    description: [
      'Per-identity signing API key (TRUST-1 remediation).',
      '',
      '`Authorization: Bearer sk_<64 hex chars>`',
      '',
      'Every caller of POST /sign authenticates with its own individually-',
      'issued, individually-revocable signing identity — there is no shared',
      'secret. Issued via `POST /signing-identities/{id}/api-key` or',
      '`scripts/provision-signing-identity.js`; stored as a SHA-256 hash —',
      'the plaintext is shown **once** at issuance. Each identity is scoped',
      'to one tenant, one deployment environment, and optionally a',
      'restricted set of AI providers.',
    ].join('\n'),
  },
};

// ── Reusable parameters ───────────────────────────────────────────────────────

const PARAMETERS = {
  // ── Canonical pagination (API-4 remediation) ──────────────────────────────
  //
  // `page`/`pageSize`/`sortOrder` are the canonical contract every collection
  // endpoint documents. `limit`/`offset`/`sortDir` below are the deprecated
  // aliases some endpoints additionally accept for backward compatibility —
  // see src/utils/pagination.js and API-4-REMEDIATION-REPORT.md.
  PageParam: {
    name: 'page',
    in: 'query',
    description: 'Page number (1-based). Canonical pagination parameter.',
    required: false,
    schema: sg.makeInteger({ minimum: 1, default: 1, example: 1 }),
  },
  PageSizeParam: {
    name: 'pageSize',
    in: 'query',
    description: 'Items per page (1–500). Canonical pagination parameter.',
    required: false,
    schema: sg.makeInteger({ minimum: 1, maximum: 500, default: 50, example: 50 }),
  },
  // /consent's pageSize is capped at 200 by its Zod schema (consent.schema.js) — the shared PageSizeParam says 500.
  ConsentPageSizeParam: {
    name: 'pageSize',
    in: 'query',
    description: 'Items per page (1–200). Canonical pagination parameter.',
    required: false,
    schema: sg.makeInteger({ minimum: 1, maximum: 200, default: 50, example: 50 }),
  },
  SortOrderParam: {
    name: 'sortOrder',
    in: 'query',
    description: 'Sort direction. Canonical pagination parameter.',
    required: false,
    schema: sg.makeString({ enum: ['asc', 'desc'], default: 'desc' }),
  },
  LimitParam: {
    name: 'limit',
    in: 'query',
    description: 'Deprecated alias for `pageSize`. Prefer `pageSize`.',
    required: false,
    deprecated: true,
    schema: sg.makeInteger({ minimum: 1, maximum: 500, example: 50 }),
  },
  OffsetParam: {
    name: 'offset',
    in: 'query',
    description: 'Deprecated alias for `page` (0-based item offset, honored exactly even when not page-aligned). Prefer `page`.',
    required: false,
    deprecated: true,
    schema: sg.makeInteger({ minimum: 0, example: 0 }),
  },
  SortDirParam: {
    name: 'sortDir',
    in: 'query',
    description: 'Deprecated alias for `sortOrder`. Prefer `sortOrder`.',
    required: false,
    deprecated: true,
    schema: sg.makeString({ enum: ['asc', 'desc'] }),
  },
  UuidPathParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Resource UUID',
  },
  PolicyIdParam: {
    name: 'policyId',
    in: 'path',
    required: true,
    schema: sg.makeString({ pattern: '^[A-Za-z0-9_-]{1,64}$', example: 'my-policy' }),
    description: 'Policy identifier',
  },
  TenantIdParam: {
    name: 'tenantId',
    in: 'path',
    required: true,
    schema: sg.TENANT_ID_SCHEMA,
    description: 'Tenant identifier',
  },
  OrgIdParam: {
    name: 'orgId',
    in: 'path',
    required: true,
    schema: sg.makeString({ pattern: '^[A-Za-z0-9_-]{1,64}$', example: 'org-acme' }),
    description: 'Organization identifier',
  },
  AttestationIdParam: {
    name: 'attestationId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Attestation identifier',
  },
  CertificationIdParam: {
    name: 'certificationId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Certification result identifier',
  },
  BatchIdParam: {
    name: 'batchId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Certification batch identifier',
  },
  WebhookIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Webhook endpoint identifier',
  },
  TransparencyIdParam: {
    name: 'transparencyId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Transparency log entry identifier',
  },
  ReceiptRequestIdParam: {
    name: 'requestId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'The payload.requestId of the consumed artifact (a UUID). Knowing it is the only authorization for this endpoint.',
  },
  ConsentIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Consent record identifier',
  },
  ActorIdParam: {
    name: 'actorId',
    in: 'path',
    required: true,
    schema: sg.ACTOR_ID_SCHEMA,
    description: 'Actor identifier',
  },
  KeyIdPathParam: {
    name: 'keyId',
    in: 'path',
    required: true,
    schema: sg.makeString({ example: 'default:key_v1', description: 'Key identifier in format <clientId>:key_v<n>' }),
    description: 'Key identifier',
  },
  UserIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'RBAC user identifier',
  },
  RoleIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.makeString({ example: 'custom:policy-reviewer', description: 'Built-in role name, or a "custom:"-prefixed custom role ID' }),
    description: 'RBAC role identifier',
  },
  ArtifactIdParam: {
    name: 'artifactId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Artifact identifier',
  },
  ReportIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Compliance report identifier',
  },
  DlqIdParam: {
    name: 'dlqId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'DLQ item identifier',
  },
  AlertIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Alert identifier',
  },
  PortalIdParam: {
    name: 'verificationId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Verification submission identifier',
  },
  FrameworkIdParam: {
    name: 'frameworkId',
    in: 'path',
    required: true,
    schema: sg.makeString({ enum: ['GDPR', 'EU_AI_ACT', 'ISO_42001', 'NIST_AI_RMF'], example: 'GDPR' }),
    description: 'Compliance framework identifier',
  },
  ClientIdParam: {
    name: 'clientId',
    in: 'path',
    required: true,
    schema: sg.makeString({ example: 'default' }),
    description: 'Signing key client identifier',
  },
  HoldNameParam: {
    name: 'holdName',
    in: 'path',
    required: true,
    schema: sg.makeString({ example: 'litigation-hold-2025-01' }),
    description: 'Legal hold name',
  },
  EventIdParam: {
    name: 'eventId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Central audit store event identifier',
  },
  OperationIdParam: {
    name: 'operationId',
    in: 'path',
    required: true,
    schema: sg.makeString({ example: 'att:550e8400-e29b-41d4-a716-446655440000' }),
    description: 'Persistence recovery queue operation identifier (prefixed by subsystem, e.g. att:, cert:)',
  },
  EvidenceIdParam: {
    name: 'evidenceId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Evidence chain record identifier',
  },
  ChangeRequestIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Policy governance change request identifier',
  },
  EmergencyIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Emergency policy override identifier',
  },
  SigningIdentityIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.makeString({ example: 'si_550e8400e29b' }),
    description: 'Signing identity identifier',
  },
  DsrRequestIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Data Subject Rights request identifier',
  },
  InvestigationIdParam: {
    name: 'id',
    in: 'path',
    required: true,
    schema: sg.makeString({ pattern: '^INV-[0-9A-F]{16}$', example: 'INV-0123456789ABCDEF' }),
    description: 'Audit investigation identifier',
  },
  FromRootIdParam: {
    name: 'fromRootId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Earlier Merkle root identifier',
  },
  ToRootIdParam: {
    name: 'toRootId',
    in: 'path',
    required: true,
    schema: sg.UUID_SCHEMA,
    description: 'Later Merkle root identifier',
  },
};

// ── Reusable schemas ──────────────────────────────────────────────────────────

const SCHEMAS = {

  // ── Primitives ──────────────────────────────────────────────────────────────

  Uuid: sg.UUID_SCHEMA,
  Timestamp: sg.ISO8601_SCHEMA,
  ActorId: sg.ACTOR_ID_SCHEMA,
  Action: sg.ACTION_SCHEMA,
  Scope: sg.SCOPE_SCHEMA,
  TenantId: sg.TENANT_ID_SCHEMA,

  // ── Pagination ───────────────────────────────────────────────────────────────

  // Canonical pagination metadata (API-4 remediation) — every paginated
  // response carries these fields (see src/utils/pagination.js
  // buildPaginationMeta/withPaginationMeta). `total` is kept for backward
  // compatibility alongside the canonical `totalItems` (same value, additive).
  PaginationMeta: sg.makeObject({
    page:            sg.makeInteger({ minimum: 1, example: 1 }),
    pageSize:        sg.makeInteger({ minimum: 1, maximum: 500, example: 50 }),
    total:           sg.makeInteger({ minimum: 0, example: 243, description: 'Deprecated alias for totalItems, kept for backward compatibility.' }),
    totalItems:      sg.makeInteger({ minimum: 0, example: 243 }),
    totalPages:      sg.makeInteger({ minimum: 0, example: 5 }),
    hasNextPage:     sg.makeBoolean({ example: true }),
    hasPreviousPage: sg.makeBoolean({ example: false }),
    sortOrder:        sg.makeString({ enum: ['asc', 'desc'], example: 'desc' }),
  }, { description: 'Canonical pagination metadata (API-4).' }),

  // ── Envelopes ────────────────────────────────────────────────────────────────

  SuccessEnvelope: sg.makeObject({
    status:    sg.makeString({ enum: ['success'], example: 'success' }),
    timestamp: sg.ISO8601_SCHEMA,
    requestId: sg.makeNullable(sg.UUID_SCHEMA),
    data:      {},
  }, { required: ['status', 'timestamp', 'requestId'] }),

  // Item 27 (ITEM-26-RESPONSE-ENVELOPE-DECISION-RECORD.md, D26-6): `error`
  // corrected from a string to an {code,message} object — no runtime path
  // ever produced the string form; the real MANAGEMENT_ERROR shape
  // (src/api/response.js's failure(), :74-78) nests error as an object.
  // `status` was already correct against that same shape.
  ErrorEnvelope: sg.makeObject({
    status:    sg.makeString({ enum: ['error'], example: 'error' }),
    error:     sg.makeObject({
      code:    sg.makeString({ description: 'Machine-readable error code. Protocol/enforcement codes are listed in the top-level `x-qodiqa-error-catalog`; management-API codes are route-specific (API-10).', example: 'INVALID_INPUT' }),
      message: sg.makeString({ description: 'Human-readable description', example: 'body.policy must be a plain object' }),
    }, { required: ['code', 'message'] }),
    timestamp: sg.ISO8601_SCHEMA,
    requestId: sg.makeNullable(sg.UUID_SCHEMA),
  }, { required: ['status', 'timestamp', 'error', 'requestId'] }),

  // Item 27 (D26-6): `policyId` removed — no live handler ever spreads it
  // into an HTTP response body (it exists only inside aiChat.js's internal
  // policyDecision object, built for audit-log construction, src/api/routes/
  // aiChat.js:327). Real bodies (aiChat.js:1189-1197, verify.js:143-153) are
  // a strict superset of {decision,reason,requestId} plus endpoint-specific
  // fields (`response`/`transparency` vs. `tenantId`/`callerId` — an
  // intentional asymmetry, D26-4) — not modeled field-by-field here, same as
  // before this fix; only the phantom field is removed.
  EnforcementDecision: sg.makeObject({
    decision:  sg.makeString({ enum: ['EXECUTE', 'BLOCK'], example: 'EXECUTE', description: 'Enforcement decision — always inspect this field, never the HTTP status alone. The dry-run verification endpoints (/verify, /v1/verify) return this body with HTTP 200 for both EXECUTE and BLOCK. The enforcement endpoints (/ai/chat, /v1/ai/chat, and their /stream variants) also return HTTP 200 for an enforcement BLOCK in the DEFAULT `decision` mode (QODIQA_BLOCK_HTTP_MODE unset or `decision`, src/api/blockHttpStatus.js); only in the opt-in `status` mode does a BLOCK carry its class status (400 malformed artifact, 403 invalid artifact/consent/policy/semantic, 409 replay, 429 policy rate rule, 500 internal, 503 dependency unavailable — docs/protocol/QODIQA-PROTOCOL.md). Transport throttles (429 RATE_LIMITED), input-guard 400s, 413, provider errors (502/503/504) are non-200 in both modes.' }),
    reason:    sg.makeString({ example: 'RULES_MATCHED:ALLOW_EFFECT', description: 'Machine-readable reason code. Every BLOCK reason, its class, its status-mode HTTP status and whether it is retryable are listed in the top-level `x-qodiqa-error-catalog` (API-09/API-10). The set is open: a reason not listed there is still a denial (status mode: 403).' }),
    requestId: sg.makeNullable({ ...sg.UUID_SCHEMA, description: 'Per-HTTP trace id (the same value as the `X-Request-ID` response header). Not the artifact id: to look up the audit record (GET /audit/{artifactId}) use the `artifactId` returned by POST /sign.' }),
    details:   sg.makeObject({}, { additionalProperties: true }),
    receipt:   sg.ref('SignedReceipt'),   // present only when the decision's audit entry and transparency leaf are persisted and the receipt could be signed (never null)
  }, { required: ['decision', 'reason', 'requestId'] }),

  // ── Artifact ─────────────────────────────────────────────────────────────────

  // the signed artifact exactly as issued by POST /sign and verified by src/validation/validateArtifact.js
  // (ARTIFACT_SCHEMA: exactly these 5 keys; any other key → INVALID_ARTIFACT). Normative definition and test vectors:
  // docs/protocol/QODIQA-PROTOCOL.md §2 and docs/protocol/vectors/.
  Artifact: sg.makeObject({
    payload:     sg.makeObject({
      provider:      sg.makeString({ description: 'Requested provider (present for AI routes)', example: 'openai' }),
      requestId:     sg.UUID_SCHEMA,
      requestHash:   sg.makeString({ description: 'Lowercase hex SHA-256 request binding (protocol §5)', example: '44e051a4f91257079a8be87f42aaaf159b3e34994a2023fe3e73aff51956dcac' }),
      policyHash:    sg.makeString({ description: 'Lowercase hex SHA-256 of the policy set at signing time (informational)', example: '0198efcd800b44a52ca570d82e3409947aabcdc637a34f718e839ec1befe9b1f' }),
      tenantId:      sg.TENANT_ID_SCHEMA,
      callerContext: sg.makeObject({}, { additionalProperties: true }),
    }, { additionalProperties: true, description: 'Signed payload; a plain object with no undefined values' }),
    publicKeyId: sg.makeString({ description: '<tenantId>:key_v<n>', example: 'dev-local:key_v1' }),
    signature:   sg.makeString({ description: 'Ed25519 signature, canonical standard base64 (exactly 88 characters ending "==")', example: '0WBYKyIgR3k9cWmkE9A+ilucBCFwju1Vgw0xAL57LkAEdlyEBQ1p5gVOL/sFl30tCDrcBGdeOOhNEXTyTa9RCw==' }),
    timestamp:   sg.makeInteger({ description: 'Issue time, Unix epoch milliseconds', example: 1790924920927 }),
    expiry:      sg.makeInteger({ description: 'Expiry, Unix epoch milliseconds', example: 1790924980927 }),
  }, { required: ['payload', 'publicKeyId', 'signature', 'timestamp', 'expiry'], additionalProperties: false }),

  // the protocol-surface BLOCK body used by POST /sign (src/api/routes/sign.js _block) and the signing-credential
  // middleware (src/middleware/signAuth.js _deny) for every non-200 status.
  DecisionBlock: sg.makeObject({
    decision:  sg.makeString({ enum: ['BLOCK'] }),
    reason:    sg.makeString({ example: 'INVALID_REQUEST', description: 'Machine-readable reason code; see the top-level `x-qodiqa-error-catalog` (API-09/API-10).' }),
    details:   sg.makeObject({}, { additionalProperties: true }),
    requestId: sg.makeNullable(sg.makeString()),
  }, { required: ['decision', 'reason'] }),

  SignedRequest: sg.makeObject({
    method: sg.makeString({ enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], example: 'POST' }),
    path:   sg.makeString({ maxLength: 2048, example: '/v1/ai/chat' }),
    body:   sg.makeObject({}, { additionalProperties: true, description: 'Request body (max 10 levels deep)' }),
  }, { required: ['method', 'path'] }),

  // ── Consent ──────────────────────────────────────────────────────────────────

  // Response shape (returned verbatim from the consent store/Postgres) —
  // intentionally snake_case, unaffected by the API-5/WP-030 request-casing
  // remediation, which only changed request bodies (ConsentGrantRequest and
  // the inline revoke/suspend/resume/verify request schemas in
  // src/openapi/routeScanner.js).
  ConsentRecord: sg.makeObject({
    id:          sg.UUID_SCHEMA,
    actor_id:    sg.ACTOR_ID_SCHEMA,
    action:      sg.ACTION_SCHEMA,
    state:       sg.makeString({ enum: ['PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED', 'SUSPENDED'], example: 'ACTIVE' }),
    scope:       sg.makeNullable(sg.SCOPE_SCHEMA),
    tenant_id:   sg.makeNullable(sg.TENANT_ID_SCHEMA),
    granted_by:  sg.makeNullable(sg.makeString({ example: 'admin' })),
    granted_at:  sg.ISO8601_SCHEMA,
    expires_at:  sg.makeNullable(sg.ISO8601_SCHEMA),
    created_at:  sg.ISO8601_SCHEMA,
    updated_at:  sg.ISO8601_SCHEMA,
    metadata:    sg.makeObject({}, { additionalProperties: true }),
    //
    lawful_basis:               sg.makeNullable(sg.makeString({ enum: ['consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interests'], description: 'GDPR Art. 6(1) lawful basis; null only when lawful_basis_status is LEGACY_UNSPECIFIED' })),
    purpose:                    sg.makeNullable(sg.makeString({ maxLength: 500 })),
    purpose_code:               sg.makeNullable(sg.makeString({ pattern: '^[a-z0-9_.-]{1,64}$' })),
    special_category_condition: sg.makeNullable(sg.makeString({ enum: ['art9_2_a', 'art9_2_b', 'art9_2_c', 'art9_2_d', 'art9_2_e', 'art9_2_f', 'art9_2_g', 'art9_2_h', 'art9_2_i', 'art9_2_j'], description: 'GDPR Art. 9(2) condition (a)-(j)' })),
    lawful_basis_status:        sg.makeString({ enum: ['SPECIFIED', 'LEGACY_UNSPECIFIED'], description: 'LEGACY_UNSPECIFIED = created before or without a stated basis; never auto-labelled' }),
  }, { required: ['id', 'actor_id', 'action', 'state', 'granted_at', 'created_at'] }),

  // API-5 remediation: camelCase is canonical (see
  // src/validation/schemas/consent.schema.js) — snake_case is still
  // accepted but deprecated (src/validation/normalizeLegacyBody.js), not
  // separately documented here to avoid duplicated/drifting examples.
  ConsentGrantRequest: sg.makeObject({
    actorId:         sg.ACTOR_ID_SCHEMA,
    action:          sg.ACTION_SCHEMA,
    grantedBy:       sg.makeString({ description: 'Identity granting consent', example: 'admin' }),
    scope:           sg.SCOPE_SCHEMA,
    requiredScope:   sg.makeString({ pattern: '^[a-zA-Z0-9_-]{1,128}$', description: 'Required scope for future checks', example: 'data_pii' }),
    tenantId:        sg.TENANT_ID_SCHEMA,
    grantReference:  sg.makeString({ description: 'External reference (DPA, ticket, etc.)', example: 'DPA-2025-001' }),
    subjectName:     sg.makeString({ description: 'Human-readable subject name', example: 'Alice Smith' }),
    actionDisplay:   sg.makeString({ description: 'Human-readable action description', example: 'Process personal data' }),
    policyReference: sg.makeString({ description: 'Reference to governing policy', example: 'GDPR-Art-6(1)(a)' }),
    tags:            sg.makeArray(sg.makeString(), { description: 'Classification tags' }),
    metadata:        sg.makeObject({}, { additionalProperties: true }),
    expiresAt:       sg.makeString({ format: 'date-time', description: 'Absolute expiry time' }),
    durationDays:    sg.makeInteger({ minimum: 1, description: 'Expiry as a number of days from now (a numeric string is also accepted)' }),
    //
    lawfulBasis:     sg.makeString({ enum: ['consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interests'], description: 'GDPR Art. 6(1) lawful basis (required)' }),
    purpose:         sg.makeString({ minLength: 1, maxLength: 500, description: 'Purpose of the processing (required)', example: 'Identity verification at building entry' }),
    purposeCode:     sg.makeString({ pattern: '^[a-z0-9_.-]{1,64}$', description: 'Optional machine grouping of purposes', example: 'access.entry' }),
    specialCategoryCondition: sg.makeString({ enum: ['art9_2_a', 'art9_2_b', 'art9_2_c', 'art9_2_d', 'art9_2_e', 'art9_2_f', 'art9_2_g', 'art9_2_h', 'art9_2_i', 'art9_2_j'], description: 'GDPR Art. 9(2) condition — required when the scope is a special category (400 SPECIAL_CATEGORY_CONDITION_REQUIRED)' }),
  }, { required: ['actorId', 'action', 'lawfulBasis', 'purpose'], additionalProperties: false,
    description: 'Strict (unknown keys -> 400). Deprecated snake_case aliases (actor_id, granted_by, lawful_basis, ...) are still accepted and translated (src/validation/normalizeLegacyBody.js).' }),

  // ── Policy ───────────────────────────────────────────────────────────────────

  PolicyRule: sg.makeObject({
    field:    sg.makeString({ description: 'Dot-notation context field path', example: 'action' }),
    operator: sg.makeString({
      enum: [
        'equals', 'notEquals', 'contains', 'notContains',
        'startsWith', 'endsWith', 'in', 'notIn',
        'greaterThan', 'lessThan', 'greaterThanOrEqual', 'lessThanOrEqual',
        'matches',
      ],
      example: 'equals',
    }),
    value:    { description: 'Value to compare against (string, number, boolean, or array)' },
    label:    sg.makeString({ description: 'Optional human-readable label for the rule' }),
  }, { required: ['field', 'operator', 'value'] }),

  PolicyDefinition: sg.makeObject({
    policyId:    sg.makeString({ pattern: '^[A-Za-z0-9_-]{1,64}$', example: 'my-policy' }),
    version:     sg.makeInteger({ minimum: 1, example: 1 }),
    effect:      sg.makeString({ enum: ['allow', 'deny'], example: 'allow' }),
    rules:       sg.makeArray(sg.ref('PolicyRule'), { minItems: 1 }),
    createdAt:   sg.ISO8601_SCHEMA,
    description: sg.makeString({ description: 'Human-readable policy description' }),
    inherits:    sg.makeArray(sg.makeString(), { description: 'Parent policy IDs' }),
    deprecated:  sg.makeBoolean({ description: 'Whether policy is deprecated', default: false }),
    expiresAt:   sg.makeString({ format: 'date-time', description: 'Policy expiry time' }),
  }, { required: ['policyId', 'version', 'effect', 'rules', 'createdAt'] }),

  // ── Webhook ──────────────────────────────────────────────────────────────────

  WebhookEndpoint: sg.makeObject({
    id:          sg.UUID_SCHEMA,
    tenantId:    sg.TENANT_ID_SCHEMA,
    url:         sg.makeString({ format: 'uri', example: 'https://example.com/hooks/qodiqa' }),
    eventTypes:  sg.makeArray(sg.makeString({ enum: ['certification.completed', 'attestation.completed', 'approval.requested', 'approval.decided', 'approval.expired', 'approval.cancelled'] })),
    enabled:     sg.makeBoolean({ example: true }),
    description: sg.makeNullable(sg.makeString()),
    createdAt:   sg.ISO8601_SCHEMA,
    updatedAt:   sg.ISO8601_SCHEMA,
  }, { required: ['id', 'tenantId', 'url', 'eventTypes', 'enabled', 'createdAt'] }),

  WebhookCreateRequest: sg.makeObject({
    tenantId:    sg.TENANT_ID_SCHEMA,
    url:         sg.makeString({ format: 'uri', description: 'HTTPS delivery URL', example: 'https://example.com/hooks/qodiqa' }),
    eventTypes:  sg.makeArray(sg.makeString({ enum: ['certification.completed', 'attestation.completed', 'approval.requested', 'approval.decided', 'approval.expired', 'approval.cancelled'] }), { minItems: 1 }),
    description: sg.makeString({ description: 'Optional description' }),
  }, { required: ['tenantId', 'url', 'eventTypes'] }),

  WebhookUpdateRequest: sg.makeObject({
    url:         sg.makeString({ format: 'uri' }),
    enabled:     sg.makeBoolean(),
    eventTypes:  sg.makeArray(sg.makeString({ enum: ['certification.completed', 'attestation.completed', 'approval.requested', 'approval.decided', 'approval.expired', 'approval.cancelled'] })),
    description: sg.makeString(),
  }, { description: 'At least one field required' }),

  // ── RBAC ─────────────────────────────────────────────────────────────────────

  // NOTE: `role` is a free-form identifier, not a fixed enum — it is
  // either one of the five built-in roles (admin, auditor, compliance,
  // operator, viewer) or the ID of an operator-defined custom role (always
  // prefixed `custom:`, e.g. `custom:policy-reviewer`). GET /rbac/roles
  // returns the live, authoritative list of every valid value.
  RbacUser: sg.makeObject({
    id:        sg.UUID_SCHEMA,
    username:  sg.makeString({ example: 'alice' }),
    role:      sg.makeString({ example: 'operator', description: 'One of the five built-in roles, or a custom role ID (see GET /rbac/roles)' }),
    enabled:   sg.makeBoolean({ example: true }),
    externalIdentity: sg.makeNullable(sg.ref('SigningIdentityExternal')),
    createdAt: sg.ISO8601_SCHEMA,
    updatedAt: sg.ISO8601_SCHEMA,
  }, { required: ['id', 'username', 'role', 'enabled', 'createdAt'] }),

  RbacCreateUserRequest: sg.makeObject({
    username: sg.makeString({ minLength: 1, maxLength: 128, example: 'alice' }),
    role:     sg.makeString({ example: 'operator', description: 'One of the five built-in roles, or a custom role ID (see GET /rbac/roles)' }),
    externalIdentity: sg.ref('SigningIdentityExternal'),
  }, { required: ['username', 'role'] }),

  RbacUpdateUserRequest: sg.makeObject({
    username: sg.makeString({ minLength: 1, maxLength: 128 }),
    role:     sg.makeString({ example: 'operator', description: 'One of the five built-in roles, or a custom role ID (see GET /rbac/roles)' }),
    enabled:  sg.makeBoolean(),
    externalIdentity: sg.makeNullable(sg.ref('SigningIdentityExternal')),
  }, { description: 'At least one field required' }),

  // ── RBAC Custom Roles ──────────────────────────────────────────────

  RbacRole: sg.makeObject({
    id:          sg.makeString({ example: 'custom:policy-reviewer', description: 'Built-in role name, or a "custom:"-prefixed custom role ID' }),
    name:        sg.makeString({ example: 'Policy Reviewer' }),
    description: sg.makeString({ example: 'Read-only policy review access' }),
    permissions: sg.makeArray(sg.makeString(), { example: ['READ_POLICIES', 'REVIEW_POLICY_CHANGE'] }),
    enabled:     sg.makeBoolean({ example: true }),
    builtIn:     sg.makeBoolean({ example: false, description: 'true for the five built-in roles; false for every custom role' }),
    createdAt:   sg.ISO8601_SCHEMA,
    updatedAt:   sg.ISO8601_SCHEMA,
  }, { required: ['id', 'name', 'permissions', 'enabled', 'builtIn'] }),

  RbacCreateRoleRequest: sg.makeObject({
    name:        sg.makeString({ minLength: 2, maxLength: 80, example: 'Policy Reviewer' }),
    description: sg.makeString({ maxLength: 500 }),
    permissions: sg.makeArray(sg.makeString(), { minItems: 1, example: ['READ_POLICIES', 'REVIEW_POLICY_CHANGE'] }),
  }, { required: ['name', 'permissions'] }),

  RbacUpdateRoleRequest: sg.makeObject({
    name:        sg.makeString({ minLength: 2, maxLength: 80 }),
    description: sg.makeString({ maxLength: 500 }),
    permissions: sg.makeArray(sg.makeString(), { minItems: 1 }),
    enabled:     sg.makeBoolean(),
  }, { description: 'At least one field required' }),

  RbacValidatePermissionsRequest: sg.makeObject({
    permissions: sg.makeArray(sg.makeString(), { minItems: 1, example: ['READ_POLICIES', 'NOT_A_REAL_PERMISSION'] }),
  }, { required: ['permissions'] }),

  // ── Organization / Tenant ────────────────────────────────────────────────────

  Organization: sg.makeObject({
    id:          sg.makeString({ pattern: '^[A-Za-z0-9_-]{1,64}$', example: 'org-acme' }),
    name:        sg.makeString({ example: 'Acme Corporation' }),
    tenantIds:   sg.makeArray(sg.TENANT_ID_SCHEMA),
    createdAt:   sg.ISO8601_SCHEMA,
    updatedAt:   sg.ISO8601_SCHEMA,
  }, { required: ['id', 'name', 'tenantIds', 'createdAt'] }),

  OrgCreateRequest: sg.makeObject({
    id:   sg.makeString({ pattern: '^[A-Za-z0-9_-]{1,64}$', example: 'org-acme' }),
    name: sg.makeString({ minLength: 1, maxLength: 256, example: 'Acme Corporation' }),
  }, { required: ['id', 'name'] }),

  Tenant: sg.makeObject({
    tenantId:  sg.TENANT_ID_SCHEMA,
    name:      sg.makeString({ example: 'ACME EU Division' }),
    status:    sg.makeString({ enum: ['active', 'suspended', 'deprovisioned'], example: 'active' }),
    minProtocolVersion: sg.makeInteger({ enum: [1, 2], description: 'The lowest protocol version this tenant accepts: 2 makes the gateway refuse V1 artifacts of this tenant (PROTOCOL_VERSION_TOO_LOW). Default 1.' }),
    createdAt: sg.ISO8601_SCHEMA,
    updatedAt: sg.ISO8601_SCHEMA,
  }, { required: ['tenantId', 'name', 'status', 'createdAt'] }),

  TenantCreateRequest: sg.makeObject({
    tenantId: sg.TENANT_ID_SCHEMA,
    name:     sg.makeString({ minLength: 1, maxLength: 256, example: 'ACME EU Division' }),
  }, { required: ['tenantId', 'name'] }),

  // ── Compliance ───────────────────────────────────────────────────────────────

  ComplianceReport: sg.makeObject({
    id:                sg.UUID_SCHEMA,
    framework:         sg.makeString({ enum: ['GDPR', 'EU_AI_ACT', 'ISO_42001', 'NIST_AI_RMF'] }),
    status:            sg.makeString({ enum: ['PENDING', 'RUNNING', 'COMPLETED', 'FAILED'] }),
    score:             sg.makeNullable(sg.makeNumber({ minimum: 0, maximum: 100, example: 92.5 })),
    generated_at:      sg.makeNullable(sg.ISO8601_SCHEMA),
    period_start:      sg.makeNullable(sg.ISO8601_SCHEMA),
    period_end:        sg.makeNullable(sg.ISO8601_SCHEMA),
    controls_assessed: sg.makeInteger({ minimum: 0, example: 150 }),
    controls_passed:   sg.makeInteger({ minimum: 0, example: 138 }),
    createdAt:         sg.ISO8601_SCHEMA,
  }, { required: ['id', 'framework', 'status', 'controls_assessed', 'controls_passed', 'createdAt'] }),

  // ── Visual builder ───────────────────────────────────────────────────────────

  GraphNode: sg.makeObject({
    id:        sg.makeString({ example: 'policy:my-policy:1' }),
    type:      sg.makeString({ enum: ['policy', 'rule', 'condition', 'group', 'capability', 'resource', 'action', 'decision'] }),
    label:     sg.makeString({ example: 'my-policy v1' }),
    riskLevel: sg.makeString({ enum: ['low', 'medium', 'high', 'critical'], example: 'low' }),
    data:      sg.makeObject({}, { additionalProperties: true }),
  }, { required: ['id', 'type', 'label', 'riskLevel'] }),

  GraphEdge: sg.makeObject({
    from:  sg.makeString({ example: 'policy:my-policy:1' }),
    to:    sg.makeString({ example: 'rule:my-policy:0' }),
    type:  sg.makeString({ enum: ['contains', 'requires', 'produces', 'inherits', 'depends'] }),
    label: sg.makeString({ example: 'rule' }),
  }, { required: ['from', 'to', 'type', 'label'] }),

  // ── Signing ──────────────────────────────────────────────────────────────────

  // API-07: mirrors src/validation/schemas/sign.schema.js exactly — both levels are .strict() (unknown keys -> 400) and
  // request.body is required (an empty object for a body-less request).
  SignRequest: sg.makeObject({
    request: sg.makeObject({
      method: sg.makeString({ enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], example: 'POST', description: 'Any other value -> 400 INVALID_METHOD' }),
      path:   sg.makeString({ maxLength: 2048, example: '/v1/ai/chat', description: 'At most 2048 UTF-8 BYTES (-> 400 PATH_TOO_LONG); maxLength here is the character bound only' }),
      body:   sg.makeObject({}, { additionalProperties: true, description: 'Required. The exact JSON body to be bound (use {} for a request without a body); at most 10 levels deep (-> 400 BODY_TOO_DEEP)' }),
      query:  sg.makeString({ description: 'Protocol V2 only (needs a v2 block): the raw query string WITHOUT the leading "?", bound into the artifact. A raw "+" or ";" is refused with 400 QUERY_NOT_BINDABLE — write %20, %2B, %3B.' }),
      headers: sg.makeObject({}, { additionalProperties: sg.makeString(), description: 'Protocol V2 only (needs a v2 block): the values of the headers named in v2.bind.headers (lower-case names); a header not listed there is refused.' }),
    }, { required: ['method', 'path', 'body'], additionalProperties: false }),
    payload: sg.makeObject({}, { additionalProperties: true, description: 'Optional additional payload. The name "qodiqa" (and any look-alike) is reserved: 400 RESERVED_CLAIM; caller data may be put under "claims" in a V2 artifact.' }),
    v2: sg.makeObject({
      bind:   sg.makeObject({ headers: sg.makeArray(sg.makeString({ pattern: '^[a-z0-9-]{1,64}$' }), { maxItems: 16, description: 'Names of the request headers whose values are bound (lower-case; none of x-qodiqa-artifact, authorization, proxy-authorization, cookie, set-cookie, host, content-length, transfer-encoding, connection, keep-alive, te, trailer, upgrade, via, forwarded, x-forwarded-for). May be empty.' }) }, { required: ['headers'], additionalProperties: false }),
      model:  sg.makeNullable(sg.makeString({ description: 'The one model this artifact authorizes; /ai/chat refuses a body that names another (REQUEST_MISMATCH).' })),
      limits: sg.makeObject({ maxTokens: sg.makeInteger({ minimum: 1, description: 'Caps the provider output for this request (enforced by the provider adapters, streaming included). maxCostMicros is not accepted yet.' }) }, { additionalProperties: false }),
      crit:   sg.makeArray(sg.makeString(), { minItems: 1, description: 'Claims a verifier MUST understand; an unknown critical claim is refused (UNSUPPORTED_CRITICAL_CLAIM).' }),
    }, { required: ['bind'], additionalProperties: false, description: 'Issue a protocol-V2 artifact (docs/protocol/PROTOCOL-V2.md; needs QODIQA_PROTOCOL_V2_ISSUE=true). The artifact then binds method, path, query, the listed headers and the body under JCS-P1 (requestHash over QODIQA::REQUEST::V2) and carries payload.qodiqa = { v: 2, kind: "request", bind, model?, limits?, crit? }.' }),
    ttl:     sg.makeNumber({ example: 60000, description: 'Requested artifact TTL in milliseconds. Default and effective maximum: 60 000 ms (60 s) — verification refuses any artifact older than the 60 s maximum artifact age, so a larger value is CLAMPED to 60 s (never rejected; the response reports `meta.ttlClamped` and `meta.effectiveTtlMs`); values below 1 000 ms are raised to 1 000 ms; the signing identity `maxTtlMs` can only lower it (src/api/routes/sign.js).' }),
  }, { required: ['request'], additionalProperties: false }),

  // Item 27 (D26-6): corrected against the real body (src/api/routes/
  // sign.js:316-326) — was missing `artifactId`/`meta` entirely and wrongly
  // flattened `keyId`/`expiresAt` to the top level. Already known drift,
  // found during item 14's work and explicitly deferred then (see
  // scripts/onboarding-contract-check.js:24-31); item 27 is where it lands.
  SignResponse: sg.makeObject({
    artifactId: sg.UUID_SCHEMA,
    artifact:   sg.ref('Artifact'),
    meta:       sg.makeObject({
      keyId:          sg.makeString({ example: 'default:key_v1' }),
      expiresAt:      sg.makeInteger({ description: 'Artifact expiry, Unix epoch milliseconds (= artifact.expiry)' }),
      tenantId:       sg.TENANT_ID_SCHEMA,
      callerId:       sg.UUID_SCHEMA,
      effectiveTtlMs: sg.makeInteger({ description: 'TTL actually applied (requested ttl clamped to the 60 s maximum artifact age)', example: 60000 }),
      ttlClamped:     sg.makeBoolean({ description: 'true when the requested ttl exceeded the maximum and was clamped' }),
    }, { required: ['keyId', 'expiresAt', 'tenantId', 'callerId', 'effectiveTtlMs', 'ttlClamped'] }),
    requestId:  sg.makeNullable(sg.UUID_SCHEMA),
  }, { required: ['artifactId', 'artifact', 'meta', 'requestId'] }),

  // ── AI Chat ──────────────────────────────────────────────────────────────────

  // API-08: mirrors src/validation/schemas/aiChat.schema.js — the body is NOT strict (other keys are accepted and
  // ignored, with a warning), except the seven provider-shaping fields below, which are refused.
  AiChatRequest: Object.assign(sg.makeObject({
    prompt:   sg.makeString({ minLength: 1, maxLength: 32768, description: 'Prompt text. Limit: 32 768 UTF-8 BYTES (-> 400 PROMPT_TOO_LARGE) - multi-byte characters count more than once, so maxLength (characters) is only an upper bound. Missing, non-string or whitespace-only -> 400 MISSING_PROMPT.', example: 'Summarise the latest EU AI Act requirements.' }),
    model:    sg.makeString({ description: 'Model identifier; over-long values -> 400 MODEL_TOO_LARGE', example: 'gpt-4o' }),
    stream:   sg.makeBoolean({ description: 'Enable streaming response', default: false }),
    provider: sg.makeString({ description: 'Accepted; the provider is taken from the signed artifact, not from this field', example: 'openai' }),
    messages: sg.makeArray(sg.makeObject({ role: sg.makeString({ enum: ['system', 'user', 'assistant'] }), content: sg.makeString({ minLength: 1 }) }, { required: ['role', 'content'] }), { minItems: 1, maxItems: 50, description: 'A multi-turn conversation INSTEAD of prompt: 1..50 messages, each content 1..32 768 UTF-8 bytes, whole conversation <= 131 072 bytes, the LAST message is role user. Every message is part of the signed request body, so changing, adding, dropping or reordering a turn after signing invalidates the artifact; every role is screened (the evidence names the role and position). Not allowed together with prompt (400 PROMPT_AND_MESSAGES). QODIQA_MULTI_TURN_ENABLED=false refuses it again.' }),
    system:   sg.makeString({ minLength: 1, description: 'System instruction, becomes the first message; only with messages.' }),
    purpose:  sg.makeString({ maxLength: 64, description: 'the purpose the caller DECLARES for this request ([A-Za-z0-9._:/ -]). A claim, not a proof: policy rules may require one (ABAC_PURPOSE_NOT_DECLARED) but QODIQA cannot verify it.', example: 'support' }),
    dataRegion: sg.makeString({ maxLength: 64, description: 'the region the caller DECLARES the data comes from (same character set). A claim, not a proof.', example: 'eu' }),
  }, { additionalProperties: true }), {
    anyOf: [{ required: ['prompt'] }, { required: ['messages'] }],
    not: { anyOf: ['tools', 'tool_choice', 'functions', 'function_call', 'response_format'].map((f) => ({ required: [f] })) },
    description: 'Either prompt or messages (+ optional system). Refused fields (400 UNSUPPORTED_FIELD, named in the error; on a streaming request the tool fields give 400 STREAM_TOOLS_UNSUPPORTED): tools, tool_choice, functions, function_call, response_format. Any other unknown field is accepted and ignored.',
  }),

  // ── Simulation ───────────────────────────────────────────────────────────────

  SimulationContext: sg.makeObject({
    action:   sg.ACTION_SCHEMA,
    endpoint: sg.makeString({ example: '/v1/ai/chat' }),
    consent:  sg.makeBoolean({ example: true }),
    metadata: sg.makeObject({}, { additionalProperties: true }),
  }, { required: ['action', 'endpoint', 'consent'] }),

  SimulationResult: sg.makeObject({
    decision:          sg.makeString({ enum: ['EXECUTE', 'BLOCK'] }),
    reason:            sg.makeString({ example: 'RULES_MATCHED:ALLOW_EFFECT' }),
    policyId:          sg.makeString({ example: 'my-policy' }),
    policyVersion:     sg.makeInteger({ minimum: 0 }),
    executionPrevented: sg.makeBoolean({ example: true }),
    evaluatedPolicies:  sg.makeInteger({ minimum: 0 }),
    durationMs:        sg.makeNumber({ minimum: 0 }),
  }, { required: ['decision', 'reason', 'executionPrevented'] }),

  // ── Attestation ──────────────────────────────────────────────────────────────

  AttestationResult: sg.makeObject({
    attestationId: sg.UUID_SCHEMA,
    status:        sg.makeString({ enum: ['VALID', 'INVALID', 'PENDING'] }),
    findings:      sg.makeArray(sg.makeString()),
    score:         sg.makeNumber({ minimum: 0, maximum: 100 }),
    createdAt:     sg.ISO8601_SCHEMA,
  }, { required: ['attestationId', 'status', 'createdAt'] }),

  // ── Transparency ─────────────────────────────────────────────────────────────

  // the transparency_log_entries row exactly as the public routes return it (snake_case, src/core/transparency/
  // logStore.js). the payload itself is never published. AUDIT_CHECKPOINT leaves (signed audit checkpoints, migration 070) appear in responses.
  TransparencyEntry: sg.makeObject({
    id:                  sg.makeString({ description: 'Log sequence number (bigint, serialised as a string)', example: '2' }),
    transparency_id:     sg.UUID_SCHEMA,
    entry_type:          sg.makeString({ enum: ['ARTIFACT', 'EVIDENCE', 'VERIFICATION', 'POLICY', 'AUDIT', 'SYSTEM', 'AUDIT_CHECKPOINT'] }),
    artifact_id:         sg.makeNullable(sg.makeString()),
    evidence_chain_id:   sg.makeNullable(sg.makeString()),
    verification_id:     sg.makeNullable(sg.makeString()),
    payload_hash:        sg.makeString({ description: 'Lowercase hex SHA-256 of the canonical payload' }),
    previous_entry_hash: sg.makeNullable(sg.makeString()),
    entry_hash:          sg.makeString({ description: 'Lowercase hex SHA-256("QODIQA::TRANSPARENCY::V1" || canonical entry)' }),
    signer_key_id:       sg.makeString(),
    signature:           sg.makeString({ description: 'Ed25519 signature, base64' }),
    created_at:          sg.ISO8601_SCHEMA,
  }, { required: ['id', 'transparency_id', 'entry_type', 'payload_hash', 'entry_hash', 'signer_key_id', 'signature', 'created_at'] }),

  // ── Health ───────────────────────────────────────────────────────────────────

  // transparency roots/proofs exactly as src/api/routes/transparencyLog.js returns them (verified live by
  // scripts/contract/live-contract.js). Root rows are the transparency_roots row (snake_case); list rows omit the signature.
  TransparencyRootRow: sg.makeObject({
    id:                 sg.makeString({ description: 'bigint, serialised as a string', example: '1' }),
    root_id:            sg.UUID_SCHEMA,
    seq_from:           sg.makeString({ description: 'bigint, serialised as a string' }),
    seq_to:             sg.makeString({ description: 'bigint, serialised as a string' }),
    entry_count:        sg.makeInteger({ minimum: 0 }),
    root_hash:          sg.makeString({ description: 'RFC 6962 Merkle root, lowercase hex' }),
    previous_root_hash: sg.makeNullable(sg.makeString()),
    signature:          sg.makeString({ description: 'Ed25519 over the root (present on GET /root, absent from list rows)' }),
    signer_key_id:      sg.makeString(),
    generated_by:       sg.makeString(),
    generated_at:       sg.ISO8601_SCHEMA,
  }, { required: ['id', 'root_id', 'seq_from', 'seq_to', 'entry_count', 'root_hash', 'previous_root_hash', 'signer_key_id', 'generated_by', 'generated_at'] }),

  TransparencyRootGenerated: sg.makeObject({
    rootId:           sg.UUID_SCHEMA,
    seqFrom:          sg.makeInteger({ minimum: 0 }),
    seqTo:            sg.makeInteger({ minimum: 0 }),
    entryCount:       sg.makeInteger({ minimum: 0 }),
    rootHash:         sg.makeString(),
    previousRootHash: sg.makeNullable(sg.makeString()),
    keyId:            sg.makeString(),
    persisted:        sg.makeBoolean(),
    generatedAt:      sg.ISO8601_SCHEMA,
  }, { required: ['rootId', 'seqFrom', 'seqTo', 'entryCount', 'rootHash', 'previousRootHash', 'keyId', 'persisted', 'generatedAt'] }),

  TransparencyInclusionProof: sg.makeObject({
    proofVersion: sg.makeString({ example: '2' }),
    proofType:    sg.makeString({ enum: ['TRANSPARENCY_INCLUSION'] }),
    generatedAt:  sg.ISO8601_SCHEMA,
    entry:        sg.makeObject({}, { additionalProperties: true, description: 'The entry in camelCase form (transparencyId, id, entryType, payloadHash, entryHash, …)' }),
    root:         sg.makeObject({}, { additionalProperties: true, description: 'The covering root in camelCase form (rootId, seqFrom, seqTo, rootHash, signature, …)' }),
    proof:        sg.makeObject({
      leafIndex:  sg.makeInteger({ minimum: 0 }),
      treeSize:   sg.makeInteger({ minimum: 1 }),
      merklePath: sg.makeArray(sg.makeObject({ hash: sg.makeString(), side: sg.makeString({ enum: ['left', 'right'] }) }, { required: ['hash', 'side'] })),
      merkleRoot: sg.makeString(),
    }, { required: ['leafIndex', 'treeSize', 'merklePath', 'merkleRoot'] }),
    verifiable:   sg.makeBoolean(),
  }, { required: ['proofVersion', 'proofType', 'entry', 'root', 'proof', 'verifiable'] }),

  // (docs/protocol/PROTOCOL-V2.md section 6): the signed receipt of a decision. It proves that the gateway RECORDED the decision
  // (audit entry + transparency leaf), nothing about the decision's correctness; it carries no tenant and no reason.
  SignedReceipt: sg.makeObject({
    v:         sg.makeInteger({ enum: [1], description: 'Receipt version' }),
    requestId: sg.UUID_SCHEMA,
    decision:  sg.makeString({ enum: ['ALLOW', 'BLOCK'], description: 'The decision of the audit DECISION entry of that request' }),
    issuedAt:  sg.makeInteger({ minimum: 0, description: 'Signing time, Unix epoch milliseconds' }),
    entryHash: sg.makeString({ description: 'Hash of the audit DECISION entry (64 lowercase hex)', example: '44e051a4f91257079a8be87f42aaaf159b3e34994a2023fe3e73aff51956dcac' }),
    leafHash:  sg.makeString({ description: 'RFC 6962 leaf hash of the transparency leaf registered for it (64 lowercase hex)', example: '0198efcd800b44a52ca570d82e3409947aabcdc637a34f718e839ec1befe9b1f' }),
    keyId:     sg.makeString({ description: 'A TRANSPARENCY key id (never an artifact key)', example: 'tr-default:key_v1' }),
    signature: sg.makeString({ description: 'base64(Ed25519.sign(SHA-256("QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature)))) — standard base64 of the 64-byte signature' }),
  }, { required: ['v', 'requestId', 'decision', 'issuedAt', 'entryHash', 'leafHash', 'keyId', 'signature'], additionalProperties: false }),

  // the global kill switch (src/core/killSwitch/index.js). The MAC never leaves the server.
  KillSwitchState: sg.makeObject({
    active:     sg.makeBoolean({ description: 'true while /sign and /ai/chat refuse every request (BLOCK KILL_SWITCH_ACTIVE, HTTP 503)' }),
    tampered:   sg.makeBoolean({ description: 'true when the stored record does not carry a valid MAC: treated as active (fail closed)' }),
    scope:      sg.makeString({ enum: ['global'] }),
    seq:        sg.makeInteger({ minimum: 0, description: 'Number of changes so far (0 = never activated)' }),
    eventId:    sg.makeNullable(sg.UUID_SCHEMA),
    operatorId: sg.makeNullable(sg.makeString()),
    reason:     sg.makeNullable(sg.makeString()),
    changedAt:  sg.makeNullable(sg.ISO8601_SCHEMA),
    stateHash:  sg.makeNullable(sg.makeString({ description: 'SHA-256 (hex) of the signed record content — the value the audit entry carries as executionContext.killSwitch.stateHash' })),
  }, { required: ['active', 'tampered', 'scope', 'seq'] }),

  // the dynamic OpenAI-compatible provider registry (src/core/providers/compatRegistry.js). The key itself is never stored or returned.
  ProviderRegistryEntry: sg.makeObject({
    id: sg.makeString({ pattern: '^[a-z][a-z0-9-]{1,30}$' }), name: sg.makeString({ description: 'The provider name used in artifacts and routing: compat-<id>' }),
    displayName: sg.makeNullable(sg.makeString({ maxLength: 80 })), baseUrl: sg.makeString({ description: 'https URL of a public DNS name (checked by the outbound policy; every resolved address and redirect hop is re-checked at connect time)' }),
    apiKeyEnv: sg.makeNullable(sg.makeString({ pattern: '^COMPAT_KEY_[A-Z0-9_]{1,48}$', description: 'NAME of the environment variable holding the key - never the key' })),
    keyConfigured: sg.makeNullable(sg.makeBoolean({ description: 'Whether that variable is set on the replica that answered' })),
    models: sg.makeArray(sg.makeString(), { description: 'Model allowlist; empty = any model' }), defaultModel: sg.makeNullable(sg.makeString()),
    timeoutMs: sg.makeInteger({ minimum: 1000, maximum: 300000 }), maxTokens: sg.makeNullable(sg.makeInteger({ minimum: 1, maximum: 8192 })), failoverProvider: sg.makeNullable(sg.makeString()),
    enabled: sg.makeBoolean(), revision: sg.makeInteger({ minimum: 1 }), createdAt: sg.ISO8601_SCHEMA, createdBy: sg.makeString(), updatedAt: sg.ISO8601_SCHEMA, updatedBy: sg.makeString(),
    configHash: sg.makeString({ description: 'SHA-256 (hex) of the signed record content' }),
  }, { required: ['id', 'name', 'baseUrl', 'models', 'timeoutMs', 'enabled', 'revision', 'configHash'] }),

  ProviderRegistryInput: sg.makeObject({
    id: sg.makeString({ pattern: '^[a-z][a-z0-9-]{1,30}$' }), displayName: sg.makeString({ maxLength: 80 }), baseUrl: sg.makeString(),
    apiKeyEnv: sg.makeString({ pattern: '^COMPAT_KEY_[A-Z0-9_]{1,48}$' }), models: sg.makeArray(sg.makeString()), defaultModel: sg.makeString(),
    timeoutMs: sg.makeInteger({ minimum: 1000, maximum: 300000 }), maxTokens: sg.makeInteger({ minimum: 1, maximum: 8192 }), failoverProvider: sg.makeString(), enabled: sg.makeBoolean(),
  }, { required: ['id', 'baseUrl'] }),

  KillSwitchChange: sg.makeObject({
    changed: sg.makeBoolean({ description: 'false when the switch was already in the requested state (idempotent)' }),
    state:   sg.ref('KillSwitchState'),
    audit:   sg.makeNullable(sg.makeObject({
      recorded:  sg.makeBoolean({ description: 'false when the audit-chain KILL_SWITCH entry could not be written; the change stands (an emergency stop never waits for the audit) and the failure is escalated' }),
      reason:    sg.makeString({ description: 'Why it was not recorded: AUDIT_SCHEMA_V8_DISABLED or AUDIT_APPEND_FAILED' }),
      entryHash: sg.makeNullable(sg.makeString()),
      stateHash: sg.makeString(),
    }, { required: ['recorded'] })),
  }, { required: ['changed', 'state'] }),

  // agent identities and sessions (src/core/agents/agentStore.js)
  Agent: sg.makeObject({
    tenantId: sg.makeString(), agentId: sg.makeString(), displayName: sg.makeString(), status: sg.makeString({ enum: ['active', 'suspended', 'revoked'] }),
    ownerUserId: sg.makeNullable(sg.makeString()), publicKey: sg.makeNullable(sg.makeString()), allowedActionClasses: sg.makeArray(sg.makeString({ enum: ['read', 'write', 'file', 'database', 'external_api', 'command', 'communication', 'financial', 'delegate'] })),
    maxActionsPerSession: sg.makeNullable(sg.makeInteger()), maxSessionSeconds: sg.makeNullable(sg.makeInteger()), costBudgetMicros: sg.makeNullable(sg.makeInteger()),
    createdBy: sg.makeString(), createdAt: sg.ISO8601_SCHEMA, updatedAt: sg.ISO8601_SCHEMA, revokedAt: sg.makeNullable(sg.ISO8601_SCHEMA),
  }, { required: ['tenantId', 'agentId', 'displayName', 'status', 'allowedActionClasses', 'createdBy', 'createdAt', 'updatedAt'] }),
  AgentSession: sg.makeObject({
    tenantId: sg.makeString(), sessionId: sg.UUID_SCHEMA, agentId: sg.makeString(), status: sg.makeString({ enum: ['active', 'ended', 'expired', 'killed'] }),
    startedAt: sg.ISO8601_SCHEMA, expiresAt: sg.ISO8601_SCHEMA, endedAt: sg.makeNullable(sg.ISO8601_SCHEMA), endedReason: sg.makeNullable(sg.makeString()),
    maxActions: sg.makeInteger(), actionsUsed: sg.makeInteger(), costBudgetMicros: sg.makeNullable(sg.makeInteger()), costUsedMicros: sg.makeInteger(),
    nextSeq: sg.makeInteger(), lastActionHash: sg.makeNullable(sg.makeString()), createdBy: sg.makeString(),
  }, { required: ['tenantId', 'sessionId', 'agentId', 'status', 'startedAt', 'expiresAt', 'maxActions', 'actionsUsed', 'costUsedMicros', 'nextSeq', 'createdBy'] }),

  // tool registry and per-action authorisation (src/core/actions/)
  ToolVersion: sg.makeObject({
    tenantId: sg.makeString(), server: sg.makeString(), name: sg.makeString(), version: sg.makeInteger(), status: sg.makeString({ enum: ['active', 'pending_review', 'superseded', 'disabled'] }),
    schema: sg.makeObject({}, { additionalProperties: true, description: 'The argument schema (a JSON Schema subset: no $ref, no pattern; additionalProperties defaults to false)' }),
    schemaHash: sg.makeString({ description: 'SHA-256(QODIQA::TOOL_SCHEMA::V1 || JCS-P1(schema)), hex' }),
    actionClass: sg.makeString({ enum: ['read', 'write', 'file', 'database', 'external_api', 'command', 'communication', 'financial', 'delegate'] }), reversible: sg.makeBoolean(), requiresApproval: sg.makeBoolean(),
    policy: sg.makeObject({}, { additionalProperties: true }), description: sg.makeNullable(sg.makeString()), createdBy: sg.makeString(), createdAt: sg.ISO8601_SCHEMA,
    approvedBy: sg.makeNullable(sg.makeString()), approvedAt: sg.makeNullable(sg.ISO8601_SCHEMA),
  }, { required: ['tenantId', 'server', 'name', 'version', 'status', 'schema', 'schemaHash', 'actionClass', 'reversible', 'requiresApproval', 'createdBy', 'createdAt'] }),
  ActionAuthorizeRequest: sg.makeObject({
    agentId: sg.UUID_SCHEMA, sessionId: sg.UUID_SCHEMA, tool: sg.makeObject({ server: sg.makeString(), name: sg.makeString() }, { required: ['server', 'name'] }),
    args: sg.makeObject({}, { additionalProperties: true, description: 'The tool arguments, validated against the registered schema and bound by actionHash (JCS-P1)' }),
    parentRequestHash: sg.makeNullable(sg.makeString({ description: 'Hex SHA-256 of the request that caused this action' })), requestId: sg.UUID_SCHEMA,
    proof: sg.makeString({ description: 'Ed25519 proof of possession by the agent key over QODIQA::AGENT_REQUEST::V1 (required when the agent has a registered key)' }),
    ttl: sg.makeInteger({ description: 'Artifact lifetime in ms, 1000-60000 (default 30000)' }), planId: sg.UUID_SCHEMA, delegationId: sg.UUID_SCHEMA, approvalId: sg.UUID_SCHEMA,
  }, { required: ['agentId', 'sessionId', 'tool', 'args'] }),

  // delegation of authority between agents (src/core/delegation/)
  DelegationToken: sg.makeObject({
    expiry: sg.makeInteger(), timestamp: sg.makeInteger(), publicKeyId: sg.makeString(), signature: sg.makeString({ description: 'Canonical base64 Ed25519 signature (88 characters) over SHA-256(QODIQA::DELEGATION::V1 || JCS-P1({expiry, payload, publicKeyId, timestamp}))' }),
    payload: sg.makeObject({}, { additionalProperties: true, description: '{ v:1, kind:"delegation", delegationId, tenantId, parentId, parentDigest, rootAgentId, issuerAgentId, subjectAgentId, depth, maxDepth, classes, tools, maxActions } (docs/protocol/DELEGATION.md)' }),
  }, { required: ['expiry', 'timestamp', 'publicKeyId', 'signature', 'payload'] }),
  Delegation: sg.makeObject({
    tenantId: sg.makeString(), delegationId: sg.UUID_SCHEMA, parentId: sg.makeNullable(sg.UUID_SCHEMA), rootAgentId: sg.makeString(), issuerAgentId: sg.makeString(), subjectAgentId: sg.makeString(),
    depth: sg.makeInteger(), maxDepth: sg.makeInteger(), classes: sg.makeArray(sg.makeString()), tools: sg.makeNullable(sg.makeArray(sg.makeObject({ server: sg.makeString(), name: sg.makeString() }))),
    maxActions: sg.makeNullable(sg.makeInteger()), actionsUsed: sg.makeInteger(), status: sg.makeString({ enum: ['active', 'revoked'] }), tokenDigest: sg.makeString(),
    issuedAt: sg.ISO8601_SCHEMA, expiresAt: sg.ISO8601_SCHEMA, createdBy: sg.makeString(), revokedAt: sg.makeNullable(sg.ISO8601_SCHEMA), revokedReason: sg.makeNullable(sg.makeString()), revokedBy: sg.makeNullable(sg.makeString()),
    token: sg.ref('DelegationToken'),
  }, { required: ['tenantId', 'delegationId', 'rootAgentId', 'issuerAgentId', 'subjectAgentId', 'depth', 'maxDepth', 'classes', 'status', 'tokenDigest', 'issuedAt', 'expiresAt', 'token'] }),
  DelegationIssueRequest: sg.makeObject({
    issuerAgentId: sg.UUID_SCHEMA, issuerSessionId: sg.UUID_SCHEMA, subjectAgentId: sg.UUID_SCHEMA, parentId: sg.UUID_SCHEMA,
    classes: sg.makeArray(sg.makeString()), tools: sg.makeArray(sg.makeObject({ server: sg.makeString(), name: sg.makeString() }, { required: ['server', 'name'] })),
    maxActions: sg.makeInteger(), ttlSeconds: sg.makeInteger({ description: '1-86400 (default 3600); a child asked for without one lives as long as its parent at most' }), maxDepth: sg.makeInteger({ description: 'Root grants only, 1-8 (default 3)' }),
    requestId: sg.UUID_SCHEMA, proof: sg.makeString(),
  }, { required: ['issuerAgentId', 'issuerSessionId', 'subjectAgentId', 'classes'] }),

  // the tool gateway and MCP servers (src/core/mcp/)
  McpServer: sg.makeObject({
    tenantId: sg.makeString(), serverId: sg.makeString(), url: sg.makeString(), transport: sg.makeString({ enum: ['streamable-http'] }),
    identity: sg.makeObject({}, { additionalProperties: true, description: '{ kind: "tls-spki-pin", sha256, trust: "ca-and-pin" | "pin-only" } for https, { kind: "none" } for local test servers only' }),
    configHash: sg.makeString(), status: sg.makeString({ enum: ['active', 'disabled'] }), localDestination: sg.makeBoolean(), description: sg.makeNullable(sg.makeString()),
    createdBy: sg.makeString(), createdAt: sg.ISO8601_SCHEMA, updatedAt: sg.ISO8601_SCHEMA, disabledAt: sg.makeNullable(sg.ISO8601_SCHEMA), disabledReason: sg.makeNullable(sg.makeString()), disabledBy: sg.makeNullable(sg.makeString()),
    lastRefreshAt: sg.makeNullable(sg.ISO8601_SCHEMA), lastRefreshTools: sg.makeNullable(sg.makeInteger()), lastError: sg.makeNullable(sg.makeString()),
  }, { required: ['tenantId', 'serverId', 'url', 'transport', 'identity', 'configHash', 'status', 'createdBy', 'createdAt'] }),
  ToolCallRequest: sg.makeObject({
    artifact: sg.makeObject({}, { additionalProperties: true, description: 'The action artifact returned by /v1/actions/authorize' }),
    tool: sg.makeObject({ server: sg.makeString(), name: sg.makeString() }, { required: ['server', 'name'] }),
    args: sg.makeObject({}, { additionalProperties: true, description: 'Exactly the arguments that were authorised: the gateway recomputes actionHash from them' }), parentRequestHash: sg.makeNullable(sg.makeString()),
  }, { required: ['artifact', 'tool', 'args'] }),
  ToolCallResponse: sg.makeObject({
    decision: sg.makeString({ enum: ['EXECUTE', 'BLOCK', 'ERROR'] }),
    result: sg.makeObject({ isError: sg.makeBoolean(), content: sg.makeArray(sg.makeObject({}, { additionalProperties: true })), provenance: sg.makeObject({}, { additionalProperties: true, description: '{ source: "mcp-tool", untrusted: true, serverId, tool, toolVersion, actionHash, requestId, withheld[], screening{ decision, findings[] }, contentHash }' }),
      delimited: sg.makeString({ description: 'The text of the result between <qodiqa:untrusted-tool-result> delimiters that cannot be forged from inside the data, ready to place in a prompt' }) }, { required: ['content', 'provenance', 'delimited'] }),
    receipt: sg.makeObject({}, { additionalProperties: true, description: '{ v:1, requestId, actionHash, seq, agentId, sessionId, tenantId, tool, serverConfigHash, status, outputHash, startedAt, finishedAt, delegation?, receiptHash } - the ledger record of the call, bound to the hash of what was delivered' }),
    reason: sg.makeString(), details: sg.makeObject({}, { additionalProperties: true }), audit: sg.makeString(), requestId: sg.makeNullable(sg.makeString()),
  }, { required: ['decision'] }),

  // human approval of agent actions (src/core/approvals/)
  ApprovalRequest: sg.makeObject({
    tenantId: sg.makeString(), approvalId: sg.UUID_SCHEMA, status: sg.makeString({ enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED'] }), sessionId: sg.UUID_SCHEMA, agentId: sg.makeString(), seq: sg.makeInteger(),
    actionHash: sg.makeString(), prevActionHash: sg.makeNullable(sg.makeString()), tool: sg.makeObject({ server: sg.makeString(), name: sg.makeString(), schemaHash: sg.makeString() }), actionClass: sg.makeString(),
    args: sg.makeObject({}, { additionalProperties: true, description: 'The arguments the approver is asked to approve (shown to operators only)' }), parentRequestHash: sg.makeNullable(sg.makeString()),
    planId: sg.makeNullable(sg.UUID_SCHEMA), delegationId: sg.makeNullable(sg.UUID_SCHEMA), requesterId: sg.makeString(), requesterUserId: sg.makeNullable(sg.makeString()), policyRuleId: sg.makeString(),
    requestedAt: sg.ISO8601_SCHEMA, expiresAt: sg.ISO8601_SCHEMA, approverId: sg.makeNullable(sg.makeString()), decidedAt: sg.makeNullable(sg.ISO8601_SCHEMA), decisionReason: sg.makeNullable(sg.makeString()),
    notBefore: sg.makeNullable(sg.ISO8601_SCHEMA), approvalExpiresAt: sg.makeNullable(sg.ISO8601_SCHEMA), decisionToken: sg.makeNullable(sg.makeObject({}, { additionalProperties: true, description: 'The signed approval statement (QODIQA::APPROVAL::V1)' })),
    mfa: sg.makeNullable(sg.makeString()), usedAt: sg.makeNullable(sg.ISO8601_SCHEMA), usedRequestId: sg.makeNullable(sg.UUID_SCHEMA), cancelledBy: sg.makeNullable(sg.makeString()), cancelledAt: sg.makeNullable(sg.ISO8601_SCHEMA), expiredAt: sg.makeNullable(sg.ISO8601_SCHEMA),
  }, { required: ['tenantId', 'approvalId', 'status', 'sessionId', 'agentId', 'seq', 'actionHash', 'tool', 'actionClass', 'args', 'requesterId', 'policyRuleId', 'requestedAt', 'expiresAt'] }),
  ApprovalRequesterView: sg.makeObject({
    approvalId: sg.UUID_SCHEMA, status: sg.makeString({ enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED'] }), actionHash: sg.makeString(), seq: sg.makeInteger(), tool: sg.makeObject({}, { additionalProperties: true }),
    agentId: sg.makeString(), sessionId: sg.UUID_SCHEMA, requestedAt: sg.ISO8601_SCHEMA, expiresAt: sg.ISO8601_SCHEMA, approverId: sg.makeNullable(sg.makeString()), decidedAt: sg.makeNullable(sg.ISO8601_SCHEMA),
    decisionReason: sg.makeNullable(sg.makeString()), notBefore: sg.makeNullable(sg.ISO8601_SCHEMA), approvalExpiresAt: sg.makeNullable(sg.ISO8601_SCHEMA), usedAt: sg.makeNullable(sg.ISO8601_SCHEMA), cancelledAt: sg.makeNullable(sg.ISO8601_SCHEMA),
  }, { required: ['approvalId', 'status', 'actionHash', 'seq'] }),
  ApprovalPending: sg.makeObject({
    status: sg.makeString({ enum: ['pending'] }), timestamp: sg.ISO8601_SCHEMA, requestId: sg.makeNullable(sg.makeString()),
    data: sg.makeObject({ approvalId: sg.UUID_SCHEMA, actionHash: sg.makeString(), seq: sg.makeInteger(), expiresAt: sg.makeString() }, { required: ['approvalId', 'actionHash', 'expiresAt'] }),
  }, { required: ['status', 'data'] }),
  ActionPlanRequest: sg.makeObject({
    agentId: sg.UUID_SCHEMA, sessionId: sg.UUID_SCHEMA, steps: sg.makeArray(sg.makeObject({ server: sg.makeString(), name: sg.makeString(), maxCalls: sg.makeInteger() }, { required: ['server', 'name', 'maxCalls'] })),
    ttlSeconds: sg.makeInteger({ description: 'Plan lifetime in seconds, 1-86400 (default 3600)' }), requestId: sg.UUID_SCHEMA, proof: sg.makeString(),
  }, { required: ['agentId', 'sessionId', 'steps'] }),
  ActionPlan: sg.makeObject({
    tenantId: sg.makeString(), planId: sg.UUID_SCHEMA, sessionId: sg.UUID_SCHEMA, agentId: sg.makeString(), steps: sg.makeArray(sg.makeObject({}, { additionalProperties: true })), used: sg.makeArray(sg.makeInteger()),
    planHash: sg.makeString({ description: 'SHA-256(QODIQA::ACTION_PLAN::V1 || JCS-P1(steps sorted by server+name)), hex' }), status: sg.makeString({ enum: ['active', 'closed'] }),
    createdBy: sg.makeString(), createdAt: sg.ISO8601_SCHEMA, expiresAt: sg.ISO8601_SCHEMA, closedAt: sg.makeNullable(sg.ISO8601_SCHEMA),
  }, { required: ['tenantId', 'planId', 'sessionId', 'agentId', 'steps', 'used', 'planHash', 'status', 'createdBy', 'createdAt', 'expiresAt'] }),
  ActionAuthorizeResponse: sg.makeObject({
    artifactId: sg.UUID_SCHEMA, artifact: sg.makeObject({}, { additionalProperties: true, description: 'The action artifact: { expiry, payload{ requestId, tenantId, qodiqa{ v:2, kind:action, bind, agentId, sessionId, seq, actionHash } }, publicKeyId, signature, timestamp }' }),
    action: sg.makeObject({ actionHash: sg.makeString(), seq: sg.makeInteger(), prevActionHash: sg.makeNullable(sg.makeString()), tool: sg.makeObject({}, { additionalProperties: true }), parentRequestHash: sg.makeNullable(sg.makeString()) }, { required: ['actionHash', 'seq', 'tool'] }),
    meta: sg.makeObject({}, { additionalProperties: true }), requestId: sg.makeNullable(sg.makeString()),
  }, { required: ['artifactId', 'artifact', 'action'] }),

  // the downloadable proof of one request (docs/protocol/VECTORS-FORMAT.md section 3); verified offline by scripts/audit-repro/verify/qodiqa-proof-verify.js.
  RequestProof: sg.makeObject({
    format:       sg.makeString({ enum: ['qodiqa-proof/1'] }),
    generatedAt:  sg.makeInteger({ description: 'Milliseconds since the epoch when the proof was assembled' }),
    subject:      sg.makeObject({ tenantId: sg.makeString(), requestId: sg.UUID_SCHEMA }, { required: ['tenantId', 'requestId'] }),
    auditEntries: sg.makeArray(sg.makeObject({}, { additionalProperties: true }), { description: "The request's own audit entries in chain order (INTENT / STREAM_OPENED, DECISION, COMMIT)" }),
    chainPath:    sg.makeArray(sg.makeObject({}, { additionalProperties: true }), { description: 'The contiguous chain from the first entry of the request to the head of the checkpoint (left out when it is not available)' }),
    transparency: sg.makeObject({}, { additionalProperties: true, description: 'Transparency leaf, inclusion proof and signed root (left out when not available)' }),
    checkpoint:   sg.makeObject({}, { additionalProperties: true, description: 'The earliest signed checkpoint that covers the request' }),
    anchors:      sg.makeArray(sg.makeObject({ kind: sg.makeString({ enum: ['git', 'ots', 'rfc3161'] }), receipt: sg.makeString() }, { required: ['kind', 'receipt'] })),
    receipt:      sg.makeObject({}, { additionalProperties: true, description: 'The signed receipt issued for the request (left out when expired from the receipt store)' }),
    keys:         sg.makeArray(sg.makeObject({ keyId: sg.makeString(), publicKeySpkiB64: sg.makeString(), status: sg.makeString() }, { required: ['keyId', 'publicKeySpkiB64'], additionalProperties: true })),
  }, { required: ['format', 'generatedAt', 'subject', 'auditEntries', 'keys'] }),

  // the record of a revoked artifact (src/core/artifactRevocation/index.js).
  ArtifactRevocation: sg.makeObject({
    requestId:  sg.UUID_SCHEMA,
    operatorId: sg.makeString(),
    reason:     sg.makeString({ maxLength: 500 }),
    tenantId:   sg.makeNullable(sg.makeString()),
    revokedAt:  sg.ISO8601_SCHEMA,
  }, { required: ['requestId', 'operatorId', 'reason', 'revokedAt'] }),

  TransparencyCheck: sg.makeObject({
    check:  sg.makeString(),
    result: sg.makeString({ enum: ['PASS', 'FAIL', 'SKIP'] }),
  }, { additionalProperties: true, required: ['check', 'result'] }),

  TransparencyEntryVerification: sg.makeObject({
    transparencyId:  sg.UUID_SCHEMA,
    verifiedAt:      sg.ISO8601_SCHEMA,
    durationMs:      sg.makeNumber({ minimum: 0 }),
    result:          sg.makeString({ enum: ['VALID', 'INVALID', 'PARTIAL', 'ERROR'] }),
    signatureValid:  sg.makeNullable(sg.makeBoolean()),
    signerKeyStatus: sg.makeNullable(sg.makeString()),
    integrityChecks: sg.makeArray(sg.ref('TransparencyCheck')),
    firstFailure:    sg.makeNullable(sg.ref('TransparencyCheck')),
  }, { required: ['transparencyId', 'result', 'integrityChecks', 'firstFailure'] }),

  // exactly the body src/api/routes/health.js sends (liveness only).
  HealthStatus: sg.makeObject({
    status:    sg.makeString({ enum: ['ok'], example: 'ok' }),
    uptime:    sg.makeNumber({ minimum: 0, example: 3600.5, description: 'Process uptime in seconds' }),
  }, { required: ['status', 'uptime'] }),

  // exactly the body src/api/routes/healthRedis.js sends.
  RedisHealthStatus: sg.makeObject({
    status: sg.makeString({ enum: ['healthy', 'recovering', 'degraded', 'disconnected'] }),
    stores: sg.makeObject({}, { additionalProperties: true, description: 'Per-store health (src/infra/redis/health.js)' }),
  }, { required: ['status', 'stores'] }),

  // ── Verify ───────────────────────────────────────────────────────────────────

  VerifyRequest: sg.makeObject({
    artifact: sg.ref('Artifact'),
    request:  sg.makeObject({
      method: sg.makeString({ enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] }),
      path:   sg.makeString({ example: '/v1/ai/chat' }),
      body:   sg.makeObject({}, { additionalProperties: true }),
    }, { required: ['method', 'path'] }),
  }, { required: ['artifact', 'request'] }),

  // ── Alerts ───────────────────────────────────────────────────────────────────

  Alert: sg.makeObject({
    id:        sg.UUID_SCHEMA,
    type:      sg.makeString({ example: 'ANOMALY' }),
    subtype:   sg.makeString({ example: 'RATE_SPIKE' }),
    severity:  sg.makeString({ enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], example: 'HIGH' }),
    status:    sg.makeString({ enum: ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'SUPPRESSED', 'FALSE_POSITIVE'], example: 'OPEN' }),
    title:     sg.makeString({ maxLength: 256, example: 'Anomalous request rate detected' }),
    tenantId:  sg.makeNullable(sg.TENANT_ID_SCHEMA),
    requestId: sg.makeNullable(sg.UUID_SCHEMA),
    artifactId: sg.makeNullable(sg.UUID_SCHEMA),
    incidentId: sg.makeNullable(sg.makeString()),
    createdAt: sg.ISO8601_SCHEMA,
    updatedAt: sg.ISO8601_SCHEMA,
  }, { required: ['id', 'type', 'subtype', 'severity', 'status', 'title', 'createdAt'] }),

  AlertCreateRequest: sg.makeObject({
    type:     sg.makeString({ example: 'ANOMALY' }),
    subtype:  sg.makeString({ example: 'RATE_SPIKE' }),
    severity: sg.makeString({ enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] }),
    title:    sg.makeString({ maxLength: 256 }),
    tenantId: sg.TENANT_ID_SCHEMA,
    requestId: sg.UUID_SCHEMA,
    artifactId: sg.UUID_SCHEMA,
    metadata: sg.makeObject({}, { additionalProperties: true }),
  }, { required: ['type', 'subtype', 'severity', 'title'] }),

  // ── Data Subject Rights (DSR) ──────────────────────────────────────────────────

  DsrRequest: sg.makeObject({
    id:            sg.UUID_SCHEMA,
    request_type:  sg.makeString({ enum: ['RECTIFICATION', 'ERASURE', 'RESTRICTION', 'PORTABILITY'], example: 'ERASURE' }),
    actor_id:      sg.ACTOR_ID_SCHEMA,
    tenant_id:     sg.makeNullable(sg.TENANT_ID_SCHEMA),
    status:        sg.makeString({ enum: ['RECEIVED', 'IDENTITY_VERIFIED', 'APPROVED', 'IN_PROGRESS', 'COMPLETED', 'REJECTED', 'FAILED'], example: 'RECEIVED' }),
    requested_by:  sg.makeString(),
    legal_basis:   sg.makeNullable(sg.makeString()),
    justification: sg.makeNullable(sg.makeString()),
    created_at:    sg.ISO8601_SCHEMA,
    updated_at:    sg.ISO8601_SCHEMA,
  }, { required: ['id', 'request_type', 'actor_id', 'status', 'created_at'] }),

  DsrCreateRequest: sg.makeObject({
    requestType:   sg.makeString({ enum: ['RECTIFICATION', 'ERASURE', 'RESTRICTION', 'PORTABILITY'] }),
    actorId:       sg.ACTOR_ID_SCHEMA,
    tenantId:      sg.TENANT_ID_SCHEMA,
    requestedBy:   sg.makeString(),
    legalBasis:    sg.makeString(),
    justification: sg.makeString(),
  }, { required: ['requestType', 'actorId'] }),

  // ── Policy Governance ──────────────────────────────────────────────────────────

  PolicyChangeRequest: sg.makeObject({
    id:            sg.UUID_SCHEMA,
    policyId:      sg.makeString({ pattern: '^[A-Za-z0-9_-]{1,64}$' }),
    tenantId:      sg.makeNullable(sg.TENANT_ID_SCHEMA),
    requestType:   sg.makeString({ enum: ['CREATE', 'UPDATE', 'ENABLE', 'DISABLE', 'ROLLBACK', 'ARCHIVE'] }),
    status:        sg.makeString({ enum: ['DRAFT', 'SUBMITTED', 'IN_REVIEW', 'REVIEWED', 'APPROVED', 'REJECTED', 'SCHEDULED', 'PUBLISHED', 'WITHDRAWN', 'EXPIRED'], example: 'DRAFT' }),
    payload:       sg.makeObject({}, { additionalProperties: true }),
    changeReason:  sg.makeNullable(sg.makeString()),
    authorId:      sg.makeNullable(sg.makeString()),
    createdAt:     sg.ISO8601_SCHEMA,
    updatedAt:     sg.ISO8601_SCHEMA,
  }, { required: ['id', 'policyId', 'requestType', 'status', 'createdAt'] }),

  // ── Signing Identities (TRUST-1) ────────────────────────────────────────────────

  SigningIdentity: sg.makeObject({
    id:               sg.makeString({ example: 'si_550e8400e29b' }),
    name:             sg.makeString({ example: 'payments-service-prod' }),
    tenantId:         sg.makeNullable(sg.TENANT_ID_SCHEMA),
    environment:      sg.makeString({ enum: ['production', 'staging', 'development'], example: 'production' }),
    allowedProviders: sg.makeNullable(sg.makeArray(sg.makeString())),
    permissions:      sg.makeArray(sg.makeString()),
    credentialType:   sg.makeString({ enum: ['api-key', 'oidc'], example: 'api-key' }),
    externalIdentity: sg.makeNullable(sg.ref('SigningIdentityExternal')),
    requireAssurance: sg.makeBoolean({ description: 'oidc identities only: the token must carry the identity provider second-factor assurance' }),
    maxTtlMs:         sg.makeNullable(sg.makeInteger()),
    enabled:          sg.makeBoolean({ example: true }),
    revoked:          sg.makeBoolean({ example: false }),
    revokedAt:        sg.makeNullable(sg.ISO8601_SCHEMA),
    revokedBy:        sg.makeNullable(sg.makeString()),
    revokedReason:    sg.makeNullable(sg.makeString()),
    hasApiKey:        sg.makeBoolean({ example: true }),
    apiKeyIssuedAt:   sg.makeNullable(sg.ISO8601_SCHEMA),
    lastUsedAt:       sg.makeNullable(sg.ISO8601_SCHEMA),
    createdAt:        sg.ISO8601_SCHEMA,
    createdBy:        sg.makeNullable(sg.makeString()),
    updatedAt:        sg.makeNullable(sg.ISO8601_SCHEMA),
    updatedBy:        sg.makeNullable(sg.makeString()),
  }, { required: ['id', 'name', 'environment', 'enabled', 'createdAt'] }),

  SigningIdentityExternal: sg.makeObject({
    issuer:  sg.makeString({ description: 'The OIDC issuer (https URL), exactly as the iss claim of the token' }),
    subject: sg.makeString({ maxLength: 255, description: 'The sub claim of the token' }),
  }, { required: ['issuer', 'subject'], description: 'The (issuer, subject) an oidc identity is linked to' }),

  SigningIdentityCreateRequest: sg.makeObject({
    name:             sg.makeString({ minLength: 1, maxLength: 128, example: 'payments-service-prod' }),
    tenantId:         sg.TENANT_ID_SCHEMA,
    environment:      sg.makeString({ enum: ['production', 'staging', 'development'] }),
    allowedProviders: sg.makeArray(sg.makeString()),
    permissions:      sg.makeArray(sg.makeString()),
    credentialType:   sg.makeString({ enum: ['api-key', 'oidc'], description: 'api-key (default) or oidc: authenticated by an OIDC bearer token of the linked (issuer, subject); an oidc identity has no API key' }),
    externalIdentity: sg.ref('SigningIdentityExternal'),
    requireAssurance: sg.makeBoolean(),
    maxTtlMs:         sg.makeNumber({ exclusiveMinimum: 0, description: 'Maximum artifact TTL (ms) for this identity — any positive number (signingIdentity.schema.js); the effective TTL is still clamped by /sign.' }),
  }, { required: ['name', 'tenantId', 'environment', 'permissions'] }),

  SigningIdentityUpdateRequest: sg.makeObject({
    allowedProviders: sg.makeArray(sg.makeString()),
    permissions:      sg.makeArray(sg.makeString()),
    maxTtlMs:         sg.makeNumber({ exclusiveMinimum: 0, description: 'Maximum artifact TTL (ms) for this identity — any positive number (signingIdentity.schema.js); the effective TTL is still clamped by /sign.' }),
    enabled:          sg.makeBoolean(),
    externalIdentity: sg.ref('SigningIdentityExternal'),
    requireAssurance: sg.makeBoolean(),
  }, { description: 'At least one field required' }),

  // ── Audit Store ──────────────────────────────────────────────────────────────

  AuditStoreEvent: sg.makeObject({
    eventId:       sg.UUID_SCHEMA,
    eventType:     sg.makeString({ example: 'ARTIFACT_ALLOWED' }),
    eventCategory: sg.makeString({ example: 'ENFORCEMENT' }),
    severity:      sg.makeString({ enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] }),
    outcome:       sg.makeNullable(sg.makeString()),
    component:     sg.makeNullable(sg.makeString()),
    artifactId:    sg.makeNullable(sg.UUID_SCHEMA),
    requestId:     sg.makeNullable(sg.UUID_SCHEMA),
    actorId:       sg.makeNullable(sg.ACTOR_ID_SCHEMA),
    tenantId:      sg.makeNullable(sg.TENANT_ID_SCHEMA),
    timestamp:     sg.ISO8601_SCHEMA,
  }, { required: ['eventId', 'eventType', 'timestamp'] }),

  // ── Audit Viewer ─────────────────────────────────────────────────────────────

  Investigation: sg.makeObject({
    id:           sg.makeString({ pattern: '^INV-[0-9A-F]{16}$', example: 'INV-0123456789ABCDEF' }),
    title:        sg.makeString(),
    investigator: sg.makeNullable(sg.makeString()),
    notes:        sg.makeNullable(sg.makeString()),
    artifactIds:  sg.makeArray(sg.UUID_SCHEMA),
    createdAt:    sg.ISO8601_SCHEMA,
  }, { required: ['id', 'title', 'artifactIds', 'createdAt'] }),

  InvestigationCreateRequest: sg.makeObject({
    title:        sg.makeString({ minLength: 1 }),
    investigator: sg.makeString(),
    notes:        sg.makeString(),
    artifactIds:  sg.makeArray(sg.UUID_SCHEMA),
  }, { required: ['title'] }),
};

// ── Reusable responses ────────────────────────────────────────────────────────

const RESPONSES = {
  BadRequest: {
    description: 'Bad request — validation error or malformed input (canonical error envelope, src/api/response.js buildFailureBody)',
    content: {
      'application/json': {
        schema: sg.ref('ErrorEnvelope'),
        example: { status: 'error', timestamp: '2026-10-02T00:00:00.000Z', requestId: '550e8400-e29b-41d4-a716-446655440000', error: { code: 'INVALID_INPUT', message: 'body.actor_id must be a non-empty string' } },
      },
    },
  },
  Unauthorized: {
    description: 'Unauthorized — missing or invalid operator credential (src/middleware/opsAuth.js → failure())',
    content: {
      'application/json': {
        schema: sg.ref('ErrorEnvelope'),
        example: { status: 'error', timestamp: '2026-10-02T00:00:00.000Z', requestId: '550e8400-e29b-41d4-a716-446655440000', error: { code: 'UNAUTHORIZED', message: 'Missing authentication credentials' } },
      },
    },
  },
  Forbidden: {
    description: 'Forbidden — insufficient permissions (src/middleware/rbac.js → failure())',
    content: {
      'application/json': {
        schema: sg.ref('ErrorEnvelope'),
        example: { status: 'error', timestamp: '2026-10-02T00:00:00.000Z', requestId: '550e8400-e29b-41d4-a716-446655440000', error: { code: 'FORBIDDEN', message: 'Insufficient permissions' } },
      },
    },
  },
  // / API-04: the operator MFA step-up (src/middleware/mfaStepUp.js) on the operations listed in
  // src/openapi/mfaStepUpScope.js. Each replaces the plain 401/403/429 on exactly those operations.
  UnauthorizedOrMfaRequired: {
    description: 'Unauthorized — missing or invalid operator credential (`UNAUTHORIZED`), or this mutation requires an operator MFA step-up code: no `X-QODIQA-OTP` header (`MFA_REQUIRED`) or a wrong/already-used code (`MFA_INVALID`, counts toward the lock). A TOTP code is accepted at most once per 30-second step.',
    content: {
      'application/json': {
        schema: sg.ref('ErrorEnvelope'),
        example: { status: 'error', timestamp: '2026-10-02T00:00:00.000Z', requestId: '550e8400-e29b-41d4-a716-446655440000', error: { code: 'MFA_REQUIRED', message: 'This action requires an MFA code in the X-QODIQA-OTP header' } },
      },
    },
  },
  ForbiddenOrMfaEnrollmentRequired: {
    description: 'Forbidden — insufficient permissions (`FORBIDDEN`), or the operator has no MFA enrolled (`MFA_ENROLLMENT_REQUIRED`: POST /rbac/me/mfa/enroll, then POST /rbac/me/mfa/confirm).',
    content: {
      'application/json': {
        schema: sg.ref('ErrorEnvelope'),
        example: { status: 'error', timestamp: '2026-10-02T00:00:00.000Z', requestId: '550e8400-e29b-41d4-a716-446655440000', error: { code: 'MFA_ENROLLMENT_REQUIRED', message: 'Enroll MFA first: POST /rbac/me/mfa/enroll, then POST /rbac/me/mfa/confirm' } },
      },
    },
  },
  TooManyRequestsOrMfaLocked: {
    description: 'Too many requests (see TooManyRequests), or MFA step-up locked after 5 failed codes in 15 minutes (`MFA_LOCKED`, canonical error envelope). Do not retry MFA_LOCKED before Retry-After.',
    headers: {
      'Retry-After': {
        schema: sg.makeInteger({ description: 'Seconds until another request (or MFA code) is accepted' }),
      },
    },
    content: {
      'application/json': {
        schema: { oneOf: [sg.ref('ErrorEnvelope'), sg.ref('DecisionBlock')] },
      },
    },
  },
  NotFound: {
    description: 'Not found — resource does not exist',
    content: {
      'application/json': {
        schema: sg.ref('ErrorEnvelope'),
        example: { status: 'error', timestamp: '2026-10-02T00:00:00.000Z', requestId: '550e8400-e29b-41d4-a716-446655440000', error: { code: 'NOT_FOUND', message: 'Record not found' } },
      },
    },
  },
  Conflict: {
    description: 'Conflict — resource already exists or state conflict',
    content: {
      'application/json': {
        schema: sg.ref('ErrorEnvelope'),
      },
    },
  },
  TooManyRequests: {
    description: 'Too many requests. The body depends on the rate-limit bucket\'s configured envelope (src/core/rateLimit/middleware.js _deny429): management and legacyFailure buckets send the canonical error envelope; the protocol-decision bucket sends the BLOCK decision body; protocol buckets send the flat limiter body.',
    headers: {
      'Retry-After': {
        schema: sg.makeInteger({ description: 'Seconds until the bucket allows another request' }),
      },
    },
    content: {
      'application/json': {
        schema: { oneOf: [
          sg.ref('ErrorEnvelope'),
          sg.ref('DecisionBlock'),
          sg.makeObject({
            error:             sg.makeString({ example: 'RATE_LIMITED' }),
            surface:           sg.makeString(),
            dimension:         sg.makeString(),
            reason:            sg.makeString(),
            retryAfterSeconds: sg.makeInteger({ minimum: 0 }),
            requestId:         sg.makeNullable(sg.makeString()),
          }, { required: ['error', 'surface', 'dimension', 'retryAfterSeconds'] }),
        ] },
      },
    },
  },
  InternalError: {
    description: 'Internal server error (src/api/response.js handleUnexpectedError; never the raw error message)',
    content: {
      'application/json': {
        schema: sg.ref('ErrorEnvelope'),
        example: { status: 'error', timestamp: '2026-10-02T00:00:00.000Z', requestId: '550e8400-e29b-41d4-a716-446655440000', error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } },
      },
    },
  },
  ServiceShuttingDown: {
    description: 'Service is shutting down. Returned by the request-drain middleware (`src/runtime/requestDrain.js`), mounted ahead of every route below, for all new requests received after graceful shutdown has begun. In-flight requests are still allowed to complete.',
    content: {
      'application/json': {
        schema: sg.makeObject({
          success: sg.makeBoolean({ example: false }),
          error:   sg.makeObject({
            code:    sg.makeString({ example: 'SERVICE_SHUTTING_DOWN' }),
            message: sg.makeString({ example: 'Service unavailable' }),
          }),
        }),
      },
    },
  },
  ReadinessUnavailable: {
    description: 'Service is not ready to accept traffic — during startup (before dependencies are confirmed), after graceful shutdown begins, or when a mandatory runtime dependency (a Redis store, PostgreSQL when enabled, or the consent revocation subscriber) is unavailable (READY-50). Returned only by `GET /ready` (`src/api/routes/ready.js`); this readiness-probe contract is distinct from the `SERVICE_SHUTTING_DOWN` response returned by every other endpoint.',
    content: {
      'application/json': {
        schema: sg.makeObject({
          ready: sg.makeBoolean({ example: false }),
          components: sg.makeObject({
            nonceStore:        sg.makeBoolean({ example: true }),
            anomalyStore:      sg.makeBoolean({ example: true }),
            rateLimitStore:    sg.makeBoolean({ example: false }),
            persistenceStore:  sg.makeBoolean({ example: true }),
            consentSubscriber: sg.makeBoolean({ example: true }),
          }),
        }),
      },
    },
  },
};

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Build the complete OpenAPI `components` object.
 *
 * @returns {object}
 */
function buildComponents() {
  return {
    securitySchemes: SECURITY_SCHEMES,
    schemas:         SCHEMAS,
    responses:       RESPONSES,
    parameters:      PARAMETERS,
  };
}

module.exports = { buildComponents, SCHEMAS, RESPONSES, PARAMETERS, SECURITY_SCHEMES };
