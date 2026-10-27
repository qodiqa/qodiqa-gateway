'use strict';

/**
 * Route Scanner — OpenAPI Component #42
 *
 * Static registry of all QODIQA REST endpoints.  Each entry fully describes
 * the endpoint for OpenAPI 3.1 path item generation.
 *
 * This is intentionally a static declarative registry rather than dynamic
 * Express route introspection, because:
 *  1. Express does not expose rich metadata (summaries, descriptions, examples).
 *  2. Static definitions cannot drift silently — they are reviewed alongside
 *     the route handler.
 *  3. Pure function output — no Express dependency, fully testable.
 *
 * To add a new endpoint:
 *  1. Add it to the appropriate section below.
 *  2. Reference component schemas/responses via $ref (no inline duplication).
 */

const sg = require('./schemaGenerator');

// ── Security requirement shortcuts ────────────────────────────────────────────

const NO_AUTH      = [];
// API-11: the ops middleware (src/middleware/opsAuth.js) accepts the credential as `Authorization: Bearer` OR the
// deprecated `x-ops-token` header — both are documented, as alternatives.
const OPS_AUTH     = [{ BearerAuth: [] }, { OpsTokenHeader: [] }];

// API-11: the health probes are mounted behind opsIpAllow + healthLoopback + healthAuth (src/app.js). Auth is OFF by
// default and switched on by QODIQA_HEALTH_PROBE_AUTH_REQUIRED=true (ops credential then required, 401 without it);
// QODIQA_HEALTH_REQUIRE_LOOPBACK=true refuses non-loopback callers with 403. Hence: anonymous OR an ops credential.
const HEALTH_AUTH  = [{}, { BearerAuth: [] }, { OpsTokenHeader: [] }];
const _HEALTH_CONDITIONAL_ERRORS = {
  '401': { description: 'Only when QODIQA_HEALTH_PROBE_AUTH_REQUIRED=true: missing or invalid ops credential.' },
  '403': { description: 'Only when QODIQA_HEALTH_REQUIRE_LOOPBACK=true: the caller is not on a loopback address ({decision:"BLOCK", reason:"FORBIDDEN"}), or the ops IP allow-list refused it.' },
};

// ── Standard response sets ────────────────────────────────────────────────────

const _STD_ERRORS = {
  '400': sg.responseRef('BadRequest'),
  '500': sg.responseRef('InternalError'),
  '503': sg.responseRef('ServiceShuttingDown'),
};

// /health, /ready, /metrics, and /diagnostics are mounted before the request-drain
// middleware in server.js, so — unlike every other endpoint — they can never
// receive the SERVICE_SHUTTING_DOWN response. Routes that need 400/500 without
// implying shutdown-503 support (e.g. /diagnostics) use this instead of _STD_ERRORS.
const _STD_ERRORS_NO_SHUTDOWN = {
  '400': sg.responseRef('BadRequest'),
  '500': sg.responseRef('InternalError'),
};

const _AUTH_ERRORS = {
  '401': sg.responseRef('Unauthorized'),
  '403': sg.responseRef('Forbidden'),
};

const _NOT_FOUND = {
  '404': sg.responseRef('NotFound'),
};

const _RATE_LIMITED = {
  '429': sg.responseRef('TooManyRequests'),
};

// ── Operation builder helper ──────────────────────────────────────────────────

function _op(operationId, summary, tags, security, responses, opts) {
  opts = opts || {};
  const op = {
    operationId,
    summary,
    tags,
    security,
    responses: Object.assign({}, responses),
  };
  if (opts.description) op.description = opts.description;
  if (opts.parameters)  op.parameters  = opts.parameters;
  if (opts.requestBody) op.requestBody  = opts.requestBody;
  if (opts.deprecated)  op.deprecated   = true;
  return op;
}

function _body(schemaRef, description, required) {
  return {
    required:    required !== false,
    description: description || null,
    content: { 'application/json': { schema: schemaRef } },
  };
}

// protocol-surface BLOCK decision body response (DecisionBlock schema).
function _decisionBlock(description) {
  return { description, content: { 'application/json': { schema: sg.ref('DecisionBlock') } } };
}

function _success(description, dataRef) {
  return sg.makeSuccessResponse(description, dataRef || sg.makeObject({}, { additionalProperties: true }));
}

function _enforcement(description) {
  return sg.makeEnforcementResponse(description || 'Enforcement decision (EXECUTE or BLOCK). HTTP 200 regardless of outcome.');
}

function _p(name, inLoc, schema, description, required) {
  return { name, in: inLoc, schema, description: description || null, required: !!required };
}

function _pPath(name, schema, description)  { return _p(name, 'path',  schema, description, true);  }
function _pQuery(name, schema, description) { return _p(name, 'query', schema, description, false); }

const _pageParams = [
  sg.paramRef('PageParam'),
  sg.paramRef('PageSizeParam'),
  sg.paramRef('SortOrderParam'),
];

// Canonical pagination params plus the deprecated limit/offset/sortDir
// aliases (API-4 remediation) — used by endpoints whose handler accepts both
// naming conventions via src/utils/pagination.js.
const _pageParamsWithLegacy = [
  ..._pageParams,
  sg.paramRef('LimitParam'),
  sg.paramRef('OffsetParam'),
  sg.paramRef('SortDirParam'),
];

// Canonical page/pageSize only, no sortOrder — used by endpoints that accept
// pagination but have no sort customization (hardcoded ordering server-side).
const _pageParamsNoSort = [
  sg.paramRef('PageParam'),
  sg.paramRef('PageSizeParam'),
  sg.paramRef('LimitParam'),
  sg.paramRef('OffsetParam'),
];

// ── Route registry ────────────────────────────────────────────────────────────

/**
 * Returns the OpenAPI `paths` object.
 *
 * @returns {object}  Record<string, PathItem>
 */
function buildPaths() {
  const paths = {};

  function add(path, method, op) {
    if (!paths[path]) paths[path] = {};
    paths[path][method] = op;
  }

  // ── Health & Readiness ────────────────────────────────────────────────────

  add('/health', 'get', _op(
    'getHealth', 'Health check', ['Health'], HEALTH_AUTH,
    {
      '200': { description: 'Service is healthy', content: { 'application/json': { schema: sg.ref('HealthStatus') } } },
      ..._HEALTH_CONDITIONAL_ERRORS,
    },
    { description: 'Returns the health status of the QODIQA service. Always returns 200 while the process is running — including during graceful shutdown — so orchestrators can distinguish "process alive" from "ready for traffic" (see /ready). Used by load balancers and orchestrators.' },
  ));

  add('/health/redis', 'get', _op(
    'getRedisHealth', 'Redis health check', ['Health'], HEALTH_AUTH,
    { '200': { description: 'Redis stores healthy, recovering or degraded', content: { 'application/json': { schema: sg.ref('RedisHealthStatus') } } }, '503': { description: 'Redis disconnected', content: { 'application/json': { schema: sg.ref('RedisHealthStatus') } } }, ..._HEALTH_CONDITIONAL_ERRORS },
    { description: 'Reports the health of the Redis-backed nonce/anomaly/rate-limit stores, independent of the main /health probe.' },
  ));

  add('/ready', 'get', _op(
    'getReadiness', 'Readiness probe', ['Health'], HEALTH_AUTH,
    {
      '200': { description: 'Service is ready to accept traffic', content: { 'application/json': { schema: sg.makeObject({ ready: sg.makeBoolean({ example: true }), timestamp: sg.ISO8601_SCHEMA }, {}) } } },
      '503': sg.responseRef('ReadinessUnavailable'),
      ..._HEALTH_CONDITIONAL_ERRORS,
    },
    { description: 'Returns readiness status. Returns 503 during startup or graceful shutdown.' },
  ));

  // ── Metrics ───────────────────────────────────────────────────────────────

  add('/metrics', 'get', _op(
    'getMetrics', 'Prometheus metrics', ['Metrics'], OPS_AUTH,
    {
      '200': { description: 'Prometheus text format metrics', content: { 'text/plain': { schema: sg.makeString({ description: 'Prometheus exposition format 0.0.4' }) } } },
      ..._AUTH_ERRORS,
    },
    { description: 'Returns operational metrics in Prometheus text exposition format. Requires ops authentication.' },
  ));

  // ── Diagnostics ───────────────────────────────────────────────────────────

  add('/diagnostics', 'get', _op(
    'getDiagnostics', 'Runtime diagnostics', ['Diagnostics'], OPS_AUTH,
    {
      '200': _success('Diagnostics data'),
      ..._AUTH_ERRORS,
      ..._STD_ERRORS_NO_SHUTDOWN,
    },
    { description: 'Returns detailed runtime diagnostics for platform engineers. Mounted before the request-drain middleware, so — like /health, /ready, and /metrics — this endpoint never returns SERVICE_SHUTTING_DOWN. Requires ops authentication and QODIQA_DIAGNOSTICS_ENABLED=true.' },
  ));

  // ── Execution ─────────────────────────────────────────────────────────────

  const _aiOp = (opId, path, summary) => _op(
    opId, summary, ['Execution'], NO_AUTH,
    {
      // / API-01: in the DEFAULT `decision` mode an enforcement BLOCK is HTTP 200 (src/api/blockHttpStatus.js);
      // the class statuses below apply only in the opt-in `status` mode. API-05: the SSE wire format of a stream.
      '200': {
        description: 'Enforcement decision. `decision: "EXECUTE"` (request executed), or — in the DEFAULT `decision` mode (QODIQA_BLOCK_HTTP_MODE unset or `decision`) — `decision: "BLOCK"` with the `reason` that stopped it. Clients MUST read `decision`; HTTP 200 alone does not mean the request executed. With `stream: true` an executing request answers `text/event-stream` instead (a BLOCK decided before the stream opens is still this JSON body).',
        // idempotency response headers (src/api/routes/aiChat.js; docs/architecture/IDEMPOTENCY_KEY.md).
        headers: {
          'Idempotency-Key': { description: 'Echo of the request `Idempotency-Key`, when one was sent and accepted.', schema: sg.makeString({}) },
          'Idempotency-Replayed': { description: '`true` when this response is the stored result of an earlier request with the same `Idempotency-Key` (only `requestId` is re-stamped); absent otherwise.', schema: sg.makeString({ enum: ['true'] }) },
        },
        content: {
          'application/json': { schema: sg.ref('EnforcementDecision') },
          'text/event-stream': {
            schema: sg.makeString({ description: 'Server-sent events (docs/architecture/streaming.md). Each frame is `event: <name>` (absent on `[DONE]`) + `id: <streamId>:<seq>` + `data: <JSON>`; the first frame also sends `retry: 3000`. Clients should read `data:`; the JSON payload repeats the `event` name. Event objects carry `event`: `stream_started`, then zero or more `chunk_forwarded` (`delta` = released output text), then exactly one terminal `stream_completed` or `stream_cancelled` (`reason`, e.g. SEMANTIC_OUTPUT_BLOCKED, OUTPUT_TOO_LARGE, STREAM_TIMEOUT, CLIENT_DISCONNECT, a provider error code), followed by the literal `data: [DONE]`. Output is released in semantic-window bursts after it has been classified; the stream is not resumable (no Last-Event-ID support) and an artifact cannot be reused to reconnect.' }),
          },
        },
      },
      '403': { description: '`status` mode only (QODIQA_BLOCK_HTTP_MODE=status): enforcement BLOCK (`decision: "BLOCK"`) for an invalid artifact, request mismatch, anomaly, consent, policy, tenant/identity, semantic or output-limit reason. The `reason` field identifies the cause (docs/protocol/QODIQA-PROTOCOL.md). In the default mode these are HTTP 200.', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      // the 409 is not status-mode-only — the idempotency gate answers 409 in both modes.
      '409': { description: '`REPLAY_DETECTED` (the artifact nonce was already used; `status` mode only — HTTP 200 in the default mode), or `IDEMPOTENCY_KEY_CONFLICT` / `IDEMPOTENCY_REQUEST_IN_PROGRESS` (both modes: the `Idempotency-Key` was reused with a different request, or its first request is still running).', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      // statuses the route emits in BOTH modes (src/api/routes/aiChat.js _providerStatus /
      // _idempotencyStatus, the 8 KB artifact-header cap, middleware/enforceContentType.js).
      '413': { description: 'Both modes: `ARTIFACT_TOO_LARGE` (the `x-qodiqa-artifact` header exceeds 8 KB) or `IDEMPOTENCY_KEY_TOO_LARGE` (the `Idempotency-Key` exceeds its length cap).', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      '415': { description: 'Both modes: `UNSUPPORTED_MEDIA_TYPE` — the request `Content-Type` is not `application/json`.', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      '422': { description: 'Both modes: `AUDIT_UNREPRESENTABLE_TEXT` — the request or provider output contains a value the evidence stores cannot represent (U+0000, a lone surrogate); refused before any partial audit record is written.', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      '429': sg.responseRef('TooManyRequests'),
      '502': { description: 'Both modes: `PROVIDER_RESPONSE_INVALID` — the AI provider returned a response that could not be used.', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      '504': { description: 'Both modes: `PROVIDER_TIMEOUT`, `REQUEST_TIMEOUT` (the pipeline exceeded AI_CHAT_TIMEOUT_MS) or `PROVIDER_CANCELLED`. The outcome is unknown to the client; a retry needs a freshly signed artifact (an `Idempotency-Key` makes the retry exactly-once).', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      ..._STD_ERRORS,
      '400': { description: '`status` mode only: enforcement BLOCK for a missing or unreadable artifact (MISSING_ARTIFACT, ARTIFACT_DECODE_FAILED, …). In both modes: request-body input-guard failures (canonical error envelope).', content: { 'application/json': { schema: { oneOf: [sg.ref('EnforcementDecision'), sg.ref('ErrorEnvelope')] } } } },
    },
    {
      description: [
        'Execute an AI request through the QODIQA enforcement pipeline.',
        '',
        'The enforcement pipeline performs:',
        '1. Artifact signature verification (Ed25519)',
        '2. Request binding validation',
        '3. Nonce replay protection',
        '4. Anomaly detection',
        '5. Policy evaluation',
        '6. AI provider execution (if allowed)',
        '',
        'Returns `decision: "EXECUTE"`, or `decision: "BLOCK"` if any pipeline step rejects the request. In the default `decision` mode both are HTTP 200 (read `decision`, not the status); in the opt-in `status` mode a BLOCK carries its class status (400/403/409/429/500/503). Retrying with the same artifact after the nonce was consumed answers REPLAY_DETECTED; only a 503 SERVER_OVERLOADED (admission control, before nonce registration) leaves the artifact reusable.',
        '',
        'The request **must** include a signed artifact in the `x-qodiqa-artifact` header.',
      ].join('\n'),
      parameters: [
        _p('x-qodiqa-artifact', 'header', sg.makeString({ description: 'Base64url-encoded signed artifact' }), 'Signed QODIQA artifact. Required.', true),
        // (src/core/idempotency/idempotencyKey.js: printable non-whitespace ASCII, default max 255).
        _p('Idempotency-Key', 'header', sg.makeString({ minLength: 1, maxLength: 255, pattern: '^[\\x21-\\x7E]+$', description: 'Opaque client token, printable non-whitespace ASCII; maximum length 255 by default (IDEMPOTENCY_KEY_MAX_LENGTH).' }), 'Optional exactly-once retry token (docs/architecture/IDEMPOTENCY_KEY.md). Rejected with `stream: true` (`IDEMPOTENCY_STREAMING_UNSUPPORTED`).', false),
      ],
      requestBody: _body(sg.ref('AiChatRequest'), 'AI chat execution request'),
    },
  );

  add('/ai/chat',        'post', _aiOp('executeAiChat',          '/ai/chat',        'Execute AI request (enforcement)'));
  add('/v1/ai/chat',     'post', _aiOp('executeAiChatV1',        '/v1/ai/chat',     'Execute AI request (enforcement, v1)'));
  // the /stream paths are aliases of /ai/chat (same router); streaming
  // is selected only by `"stream": true` in the signed body (aiChat.js `isStreaming = ….stream === true`).
  add('/ai/chat/stream', 'post', _aiOp('executeAiChatStream',    '/ai/chat/stream', 'AI request (alias of /ai/chat; streams only with stream: true)'));
  add('/v1/ai/chat/stream', 'post', _aiOp('executeAiChatStreamV1', '/v1/ai/chat/stream', 'AI request (alias of /v1/ai/chat; streams only with stream: true)'));

  // ── Verification ──────────────────────────────────────────────────────────

  const _verifyDesc = [
    'Verify a signed artifact without executing the underlying request.',
    '',
    'Performs the complete 5-step verification pipeline in dry-run mode:',
    '1. Ed25519 signature verification',
    '2. Request binding verification',
    '3. Nonce check (dry-run, no state write)',
    '4. Anomaly detection (dry-run)',
    '5. Policy evaluation',
    '',
    'Returns HTTP 200 with `decision: "EXECUTE"` or `decision: "BLOCK"`. No AI provider is called.',
  ].join('\n');

  add('/verify', 'post', _op(
    'verifyArtifact', 'Verify artifact', ['Verification'], NO_AUTH,
    {
      '200': { description: 'Verification result', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      '400': sg.responseRef('BadRequest'),
      '429': sg.responseRef('TooManyRequests'),
      ..._STD_ERRORS,
    },
    { description: _verifyDesc, requestBody: _body(sg.ref('VerifyRequest'), 'Artifact and original request to verify') },
  ));

  add('/v1/verify', 'post', _op(
    'verifyArtifactV1', 'Verify artifact (v1)', ['Verification'], NO_AUTH,
    {
      '200': { description: 'Verification result', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      '400': sg.responseRef('BadRequest'),
      '429': sg.responseRef('TooManyRequests'),
      ..._STD_ERRORS,
    },
    { description: _verifyDesc, requestBody: _body(sg.ref('VerifyRequest'), 'Artifact and original request to verify') },
  ));

  const _verifyV2Desc = _verifyDesc + '\n\nIdentical verification pipeline to /verify, exposed under a separate, independently configurable rate limit for higher-volume callers.';

  add('/verify/v2', 'post', _op(
    'verifyArtifactV2', 'Verify artifact (v2 rate limit tier)', ['Verification'], NO_AUTH,
    {
      '200': { description: 'Verification result', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      '400': sg.responseRef('BadRequest'),
      '429': sg.responseRef('TooManyRequests'),
      ..._STD_ERRORS,
    },
    { description: _verifyV2Desc, requestBody: _body(sg.ref('VerifyRequest'), 'Artifact and original request to verify') },
  ));

  add('/v1/verify/v2', 'post', _op(
    'verifyArtifactV2V1', 'Verify artifact (v1, v2 rate limit tier)', ['Verification'], NO_AUTH,
    {
      '200': { description: 'Verification result', content: { 'application/json': { schema: sg.ref('EnforcementDecision') } } },
      '400': sg.responseRef('BadRequest'),
      '429': sg.responseRef('TooManyRequests'),
      ..._STD_ERRORS,
    },
    { description: _verifyV2Desc, requestBody: _body(sg.ref('VerifyRequest'), 'Artifact and original request to verify') },
  ));

  // ── Signing ───────────────────────────────────────────────────────────────

  add('/sign', 'post', _op(
    'signRequest', 'Sign request', ['Signing'], [{ SigningApiKey: [] }],
    {
      '200': { description: 'Signed artifact', content: { 'application/json': { schema: sg.ref('SignResponse') } } },
      // every /sign refusal is the BLOCK decision body (src/api/routes/sign.js _block, src/middleware/signAuth.js _deny)
      '400': _decisionBlock('Invalid sign request (INVALID_REQUEST, PROVIDER_REQUIRED, PROVIDER_NOT_SUPPORTED, PROVIDER_NOT_CONFIGURED)'),
      '401': _decisionBlock('Signing credential missing, unknown or expired (UNAUTHORIZED, API_KEY_EXPIRED)'),
      '403': _decisionBlock('Signing identity not permitted (SCOPE_PROVIDER_DENIED, SCOPE_ENVIRONMENT_MISMATCH, …)'),
      // the pre-auth `sign_auth` and per-identity `sign` limiters (src/api/routes/sign.js).
      '429': sg.responseRef('TooManyRequests'),
      '500': _decisionBlock('Signing failed (SIGNING_FAILED)'),
      // exception E-OA-1: /sign also answers 503 KEY_UNAVAILABLE / POLICY_UNAVAILABLE as a DecisionBlock body; the
      // governance rule (openapi.test.js) keeps every drain-gated 503 on the canonical ServiceShuttingDown component.
      '503': sg.responseRef('ServiceShuttingDown'),
    },
    {
      description: [
        'Generate a signed artifact for a request.',
        '',
        'Refusals are BLOCK decision bodies (`DecisionBlock`). A 503 is either the shutdown-drain body or, when the signing key or the policy set is unavailable, a `DecisionBlock` with reason `KEY_UNAVAILABLE` or `POLICY_UNAVAILABLE`.',
        '',
        'The artifact can then be passed as `x-qodiqa-artifact` when executing via `/ai/chat`',
        'or verified independently via `/verify`.',
        '',
        'Requires `Authorization: Bearer <signing-api-key>` — a per-identity credential',
        'issued via `POST /signing-identities/{id}/api-key` (TRUST-1 remediation; there is',
        'no shared signing secret). The authenticated identity determines which tenant\'s',
        'signing key is used and which environment/providers the artifact may target.',
        '',
        'TTL defaults to 60 s (60 000 ms), the maximum artifact age: a larger value is clamped to 60 s',
        '(reported in `meta.ttlClamped` / `meta.effectiveTtlMs`), a value below 1 s is raised to 1 s, and the',
        'authenticated identity\'s own maxTtlMs can only lower it (API-07; previously documented as 5 min / [1 s, 24 h]).',
      ].join('\n'),
      requestBody: _body(sg.ref('SignRequest'), 'Request to sign'),
    },
  ));

  // ── Consent ───────────────────────────────────────────────────────────────

  add('/consent', 'post', _op(
    'grantConsent', 'Grant consent', ['Consent'], OPS_AUTH,
    {
      '201': _success('Consent record created', sg.ref('ConsentRecord')),
      '409': sg.responseRef('Conflict'),
      ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    { description: 'Grant consent for an actor to perform an action.', requestBody: _body(sg.ref('ConsentGrantRequest'), 'Consent grant request') },
  ));

  add('/consent', 'get', _op(
    'listConsent', 'List consent records', ['Consent'], OPS_AUTH,
    {
      '200': _success('Paginated consent records', sg.makeObject({ records: sg.makeArray(sg.ref('ConsentRecord')), total: sg.makeInteger({ minimum: 0 }), pagination: sg.ref('PaginationMeta') })),
      ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    {
      parameters: [
        // API-5 remediation: actorId/tenantId are canonical;
        // actor_id/tenant_id still accepted (deprecated) — see
        // src/validation/schemas/consent.schema.js's CONSENT_LIST_QUERY_ALIASES.
        _pQuery('actorId', sg.ACTOR_ID_SCHEMA, 'Filter by actor'),
        _pQuery('action',   sg.ACTION_SCHEMA,   'Filter by action'),
        _pQuery('tenantId', sg.TENANT_ID_SCHEMA, 'Filter by tenant'),
        _pQuery('state', sg.makeString({ enum: ['PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED', 'SUSPENDED'] }), 'Filter by state'),
        // Canonical (API-4) — takes precedence over limit/offset below when both given.
        sg.paramRef('PageParam'),
        sg.paramRef('ConsentPageSizeParam'),
        // Deprecated aliases, still accepted — see src/utils/pagination.js.
        sg.paramRef('LimitParam'),
        sg.paramRef('OffsetParam'),
      ],
    },
  ));

  add('/consent/revoked', 'get', _op(
    'listRevokedConsent', 'List revoked consent records', ['Consent'], OPS_AUTH,
    { '200': _success('Paginated revoked consent records', sg.makeObject({ records: sg.makeArray(sg.ref('ConsentRecord')), total: sg.makeInteger({ minimum: 0 }), pagination: sg.ref('PaginationMeta') })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: _pageParamsNoSort },
  ));

  add('/consent/health', 'get', _op(
    'consentHealth', 'Consent registry health', ['Consent'], OPS_AUTH,
    { '200': _success('Registry health status'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/consent/{id}', 'get', _op(
    'getConsent', 'Get consent record', ['Consent'], OPS_AUTH,
    {
      '200': _success('Consent record', sg.ref('ConsentRecord')),
      ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS,
    },
    { parameters: [sg.paramRef('ConsentIdParam')] },
  ));

  add('/consent/{id}/revoke', 'post', _op(
    'revokeConsent', 'Revoke consent', ['Consent'], OPS_AUTH,
    {
      '200': _success('Consent record after revocation', sg.ref('ConsentRecord')),
      ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS,
    },
    {
      parameters: [sg.paramRef('ConsentIdParam')],
      requestBody: _body(sg.makeObject({ revokedBy: sg.makeString(), revocationReason: sg.makeString(), tenantId: sg.TENANT_ID_SCHEMA }, { additionalProperties: false }), 'Revocation details', false),
    },
  ));

  add('/consent/{id}/suspend', 'post', _op(
    'suspendConsent', 'Suspend consent', ['Consent'], OPS_AUTH,
    {
      '200': _success('Consent record after suspension', sg.ref('ConsentRecord')),
      ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS,
    },
    {
      parameters: [sg.paramRef('ConsentIdParam')],
      requestBody: _body(sg.makeObject({ suspendedBy: sg.makeString(), suspensionReason: sg.makeString(), suspendedUntil: sg.makeString({ format: 'date-time' }), tenantId: sg.TENANT_ID_SCHEMA }, { additionalProperties: false }), 'Suspension details', false),
    },
  ));

  add('/consent/{id}/resume', 'post', _op(
    'resumeConsent', 'Resume consent', ['Consent'], OPS_AUTH,
    {
      '200': _success('Consent record after resumption', sg.ref('ConsentRecord')),
      ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS,
    },
    {
      parameters: [sg.paramRef('ConsentIdParam')],
      requestBody: _body(sg.makeObject({ resumedBy: sg.makeString(), tenantId: sg.TENANT_ID_SCHEMA }, { additionalProperties: false }), 'Resumption details (API-08)', false),
    },
  ));

  add('/consent/actor/{actorId}/revoke', 'post', _op(
    'revokeActorConsent', 'Revoke all consent for actor', ['Consent'], OPS_AUTH,
    { '200': _success('Revocation summary'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      description: 'Revokes (state transition to REVOKED) every non-terminal consent record for an actor. ' +
        'This is a bulk revocation, not a deletion or GDPR Article 17 erasure — no row is removed and ' +
        'consent_audit_log is untouched. For erasure, use POST /v1/admin/dsr/{id}/erase.',
      parameters: [sg.paramRef('ActorIdParam')],
      requestBody: _body(sg.makeObject({ revokedBy: sg.makeString(), revocationReason: sg.makeString() }), 'Revocation details', false),
    },
  ));

  add('/consent/actor/{actorId}', 'delete', _op(
    'revokeActorConsentLegacy', 'Revoke all consent for actor (deprecated alias)', ['Consent'], OPS_AUTH,
    { '200': _success('Revocation summary'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      description: 'DEPRECATED — use POST /consent/actor/{actorId}/revoke instead. Despite the DELETE verb, ' +
        'this endpoint has never deleted any record; it only revokes consent (state transition to REVOKED). ' +
        'It is kept only for backward compatibility, returns Deprecation/Sunset/Link response headers, and ' +
        'logs a CONSENT_DELETE_ACTOR_DEPRECATED_USED warning on every call. It does not fulfill GDPR Article ' +
        '17 erasure requests — use POST /v1/admin/dsr/{id}/erase for that (see docs/guides/dsr.md).',
      parameters: [sg.paramRef('ActorIdParam')],
      deprecated: true,
    },
  ));

  add('/consent/{id}/audit', 'get', _op(
    'consentAudit', 'Consent record audit log', ['Consent'], OPS_AUTH,
    { '200': _success('Audit log entries', sg.makeArray(sg.makeObject({}, { additionalProperties: true }))), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ConsentIdParam')] },
  ));

  add('/consent/{id}/status', 'get', _op(
    'getConsentStatus', 'Get consent status summary', ['Consent'], OPS_AUTH,
    { '200': _success('Consent status summary'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ConsentIdParam')] },
  ));

  add('/consent/{id}/history', 'get', _op(
    'getConsentHistory', 'Get consent state transition history', ['Consent'], OPS_AUTH,
    { '200': _success('State transition history', sg.makeArray(sg.makeObject({}, { additionalProperties: true }))), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ConsentIdParam')] },
  ));

  add('/consent/verify', 'post', _op(
    'verifyConsent', 'Ad-hoc consent verification', ['Consent'], OPS_AUTH,
    { '200': _success('Consent verification result'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ actorId: sg.ACTOR_ID_SCHEMA, action: sg.ACTION_SCHEMA, tenantId: sg.TENANT_ID_SCHEMA, requiredScope: sg.SCOPE_SCHEMA }, { required: ['actorId', 'action'] })) },
  ));

  // ── Policy Management ─────────────────────────────────────────────────────

  add('/policy-ui/dashboard', 'get', _op(
    'policyDashboard', 'Policy dashboard', ['Policy Management'], OPS_AUTH,
    { '200': _success('Policy dashboard data'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/policy-ui/policies', 'get', _op(
    'listPolicies', 'List policies', ['Policy Management'], OPS_AUTH,
    {
      '200': _success('Policy list', sg.makeObject({ policies: sg.makeArray(sg.ref('PolicyDefinition')), pagination: sg.ref('PaginationMeta') })),
      ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    {
      // API-4 fix: this previously documented `limit` (a name the handler
      // never actually read — it always read `pageSize`); `limit` now really
      // does work here too, as a deprecated alias, via src/utils/pagination.js.
      parameters: [
        _pQuery('page', sg.makeInteger({ minimum: 1, default: 1 })),
        _pQuery('pageSize', sg.makeInteger({ minimum: 1, maximum: 200, default: 50 })),
        sg.paramRef('LimitParam'), sg.paramRef('OffsetParam'),
        _pQuery('status', sg.makeString({ enum: ['ACTIVE', 'DISABLED'] })),
        _pQuery('search', sg.makeString(), 'Substring match on policy id or name'),
        _pQuery('sortBy', sg.makeString(), 'Field to sort by (any PolicyDefinition field, default updatedAt)'),
        _pQuery('sortDir', sg.makeString({ enum: ['asc', 'desc'] })),
        sg.paramRef('SortOrderParam'),
      ],
    },
  ));

  add('/policy-ui/policies', 'post', _op(
    'createPolicy', 'Create policy', ['Policy Management'], OPS_AUTH,
    { '201': _success('Created policy', sg.ref('PolicyDefinition')), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.ref('PolicyDefinition'), 'Policy definition') },
  ));

  add('/policy-ui/policies/validate', 'get', _op(
    'validatePolicyQuery', 'Validate policy (query form)', ['Policy Management'], OPS_AUTH,
    { '200': _success('Validation result'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Query-parameter variant of policy validation, for lightweight client-side checks.' },
  ));

  add('/policy-ui/policies/validate', 'post', _op(
    'validatePolicy', 'Validate policy', ['Policy Management'], OPS_AUTH,
    { '200': _success('Validation result'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.ref('PolicyDefinition'), 'Policy candidate to validate') },
  ));

  add('/policy-ui/policies/{policyId}', 'get', _op(
    'getPolicy', 'Get policy', ['Policy Management'], OPS_AUTH,
    { '200': _success('Policy definition', sg.ref('PolicyDefinition')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam')] },
  ));

  add('/policy-ui/policies/{policyId}', 'put', _op(
    'updatePolicy', 'Update policy', ['Policy Management'], OPS_AUTH,
    { '200': _success('Updated policy', sg.ref('PolicyDefinition')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam')], requestBody: _body(sg.ref('PolicyDefinition'), 'Updated policy definition') },
  ));

  add('/policy-ui/policies/{policyId}/enable', 'post', _op(
    'enablePolicy', 'Enable policy', ['Policy Management'], OPS_AUTH,
    { '200': _success('Policy enabled'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam')] },
  ));

  add('/policy-ui/policies/{policyId}/disable', 'post', _op(
    'disablePolicy', 'Disable policy', ['Policy Management'], OPS_AUTH,
    { '200': _success('Policy disabled'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam')] },
  ));

  add('/policy-ui/policies/{policyId}/versions', 'get', _op(
    'listPolicyVersions', 'List policy versions', ['Policy Management'], OPS_AUTH,
    { '200': _success('Version history'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    {
      // Opt-in pagination (API-4): omitting page/pageSize/limit/offset returns
      // the full unbounded list (backward compatible); supplying any of them
      // slices the response and adds canonical pagination metadata.
      parameters: [sg.paramRef('PolicyIdParam'), ..._pageParamsNoSort],
    },
  ));

  add('/policy-ui/policies/{policyId}/versions/{v}', 'get', _op(
    'getPolicyVersion', 'Get specific policy version', ['Policy Management'], OPS_AUTH,
    { '200': _success('Policy at specified version', sg.ref('PolicyDefinition')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam'), _pPath('v', sg.makeInteger({ minimum: 1 }), 'Version number')] },
  ));

  add('/policy-ui/policies/{policyId}/diff', 'get', _op(
    'getPolicyDiff', 'Get policy diff', ['Policy Management'], OPS_AUTH,
    { '200': _success('Version diff'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam'), _pQuery('from', sg.makeInteger({ minimum: 1 }), 'Source version'), _pQuery('to', sg.makeInteger({ minimum: 1 }), 'Target version')] },
  ));

  add('/policy-ui/policies/{policyId}/rollback', 'post', _op(
    'rollbackPolicy', 'Rollback policy', ['Policy Management'], OPS_AUTH,
    { '200': _success('Rollback result'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam')], requestBody: _body(sg.makeObject({ targetVersion: sg.makeInteger({ minimum: 1 }) }, { required: ['targetVersion'] }), 'Target version for rollback') },
  ));

  add('/policy-ui/policies/{policyId}/history', 'get', _op(
    'getPolicyHistory', 'Get policy history', ['Policy Management'], OPS_AUTH,
    { '200': _success('Policy change history'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    {
      // Opt-in pagination (API-4): omitting page/pageSize/limit/offset returns
      // the full unbounded list (backward compatible); supplying any of them
      // slices the response and adds canonical pagination metadata.
      parameters: [sg.paramRef('PolicyIdParam'), ..._pageParamsNoSort],
    },
  ));

  // ── Policy Simulation ──────────────────────────────────────────────────────

  add('/v1/policy/simulate', 'post', _op(
    'simulatePolicy', 'Simulate policy decision', ['Policy Simulation'], OPS_AUTH,
    { '200': _success('Simulation result', sg.ref('SimulationResult')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      description: 'Evaluate a context against policies without any side-effects (no nonce, audit, or rate-limit state written).',
      requestBody: _body(sg.makeObject({
        context:  sg.ref('SimulationContext'),
        policies: sg.makeArray(sg.ref('PolicyDefinition'), { description: 'Policies to evaluate (defaults to live policy set if omitted)' }),
        scenario: sg.makeString({ description: 'Optional scenario label for documentation purposes' }),
      }, { required: [] }), 'Simulation request'),
    },
  ));

  add('/v1/policy/compare', 'post', _op(
    'comparePolicies', 'Compare policy sets', ['Policy Simulation'], OPS_AUTH,
    { '200': _success('Policy comparison result'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      description: 'Compare the decisions produced by the current policy set versus a proposed replacement.',
      requestBody: _body(sg.makeObject({
        context:          sg.ref('SimulationContext'),
        currentPolicies:  sg.makeArray(sg.ref('PolicyDefinition'), { description: 'Current policies (defaults to live set)' }),
        proposedPolicies: sg.makeArray(sg.ref('PolicyDefinition'), { description: 'Proposed replacement policies' }),
        scenario:         sg.makeString(),
      }, { required: ['proposedPolicies'] }), 'Comparison request'),
    },
  ));

  add('/v1/policy/simulate/batch', 'post', _op(
    'batchSimulate', 'Batch policy simulation', ['Policy Simulation'], OPS_AUTH,
    { '200': _success('Batch simulation results'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      description: 'Evaluate up to 100 contexts in a single request. No side-effects.',
      requestBody: _body(sg.makeObject({
        simulations: sg.makeArray(sg.makeObject({ context: sg.ref('SimulationContext'), scenario: sg.makeString() }), { minItems: 1, maxItems: 100 }),
        policies:    sg.makeArray(sg.ref('PolicyDefinition')),
      }, { required: ['simulations'] }), 'Batch simulation request'),
    },
  ));

  // ── Policy Visual Builder (Component #41) ──────────────────────────────────

  const _pvTag = ['Policy Visual Builder'];

  add('/v1/policy/visual/graph', 'post', _op(
    'buildPolicyGraph', 'Build policy graph', _pvTag, OPS_AUTH,
    { '200': _success('Policy graph model', sg.makeObject({ nodes: sg.makeArray(sg.ref('GraphNode')), edges: sg.makeArray(sg.ref('GraphEdge')), meta: sg.makeObject({}, { additionalProperties: true }) })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Convert a policy to a directed graph model (nodes + edges).', requestBody: _body(sg.makeObject({ policy: sg.ref('PolicyDefinition') }, { required: ['policy'] })) },
  ));

  add('/v1/policy/visual/tree', 'post', _op(
    'buildPolicyTree', 'Build policy tree', _pvTag, OPS_AUTH,
    { '200': _success('Policy tree model'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      requestBody: _body(sg.makeObject({ policy: sg.ref('PolicyDefinition'), format: sg.makeString({ enum: ['json', 'text'], default: 'json' }) }, { required: ['policy'] })),
    },
  ));

  add('/v1/policy/visual/deps', 'post', _op(
    'buildPolicyDependencies', 'Build dependency graph', _pvTag, OPS_AUTH,
    { '200': _success('Dependency graph'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ policies: sg.makeArray(sg.ref('PolicyDefinition')) }), 'Policies to analyse (defaults to live set if omitted)', false) },
  ));

  add('/v1/policy/visual/stats', 'post', _op(
    'policyStatistics', 'Generate policy statistics', _pvTag, OPS_AUTH,
    { '200': _success('Policy statistics'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ policy: sg.ref('PolicyDefinition') }, { required: ['policy'] })) },
  ));

  add('/v1/policy/visual/highlight', 'post', _op(
    'highlightRisks', 'Risk-highlight policy graph', _pvTag, OPS_AUTH,
    { '200': _success('Annotated graph with risk findings'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ policy: sg.ref('PolicyDefinition') }, { required: ['policy'] })) },
  ));

  add('/v1/policy/visual/flow', 'get', _op(
    'getDecisionFlow', 'Get decision flow stages', _pvTag, OPS_AUTH,
    { '200': _success('QODIQA decision flow stages'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/v1/policy/visual/export', 'post', _op(
    'exportPolicyVisual', 'Export policy diagram', _pvTag, OPS_AUTH,
    {
      '200': {
        description: 'Exported diagram (SVG, PNG, or JSON depending on `format`)',
        content: {
          'image/svg+xml': { schema: sg.makeString({ description: 'SVG markup' }) },
          'image/png':     { schema: sg.makeString({ format: 'binary', description: 'PNG image bytes' }) },
          'application/json': { schema: sg.makeObject({ nodes: sg.makeArray(sg.ref('GraphNode')), edges: sg.makeArray(sg.ref('GraphEdge')) }) },
        },
      },
      '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    {
      requestBody: _body(sg.makeObject({
        policy:        sg.ref('PolicyDefinition'),
        format:        sg.makeString({ enum: ['svg', 'png', 'json'], default: 'svg', description: 'Output format' }),
        title:         sg.makeString({ description: 'Optional diagram title' }),
        layoutOptions: sg.makeObject({ nodeWidth: sg.makeInteger(), nodeHeight: sg.makeInteger(), horizontalGap: sg.makeInteger(), verticalGap: sg.makeInteger() }),
      }, { required: ['policy'] }), 'Export request'),
    },
  ));

  // ── Audit ─────────────────────────────────────────────────────────────────

  add('/audit/chain/integrity', 'get', _op(
    'getAuditChainIntegrity', 'Get audit chain integrity status', ['Audit'], OPS_AUTH,
    { '200': _success('Chain integrity result'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Verifies the hash-chained audit log has not been tampered with.' },
  ));

  add('/audit/chain/verifier/status', 'get', _op(
    'getChainVerifierStatus', 'Get background chain verifier status', ['Audit'], OPS_AUTH,
    { '200': _success('Verifier status'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/audit/chain/verifier/verify', 'post', _op(
    'triggerChainVerification', 'Trigger manual chain verification', ['Audit'], OPS_AUTH,
    { '200': _success('Verification result'), ..._AUTH_ERRORS, '429': sg.responseRef('TooManyRequests'), ..._STD_ERRORS },
  ));

  add('/audit/{artifactId}', 'get', _op(
    'getAuditEntry', 'Get audit log entry', ['Audit'], OPS_AUTH,
    { '200': _success('Audit entry'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ArtifactIdParam'), _pQuery('format', sg.makeString({ enum: ['json', 'pdf'] }), 'Response format')] },
  ));

  // ── Audit Store (centralized cross-subsystem audit event store) ───────────

  add('/audit-store/events', 'get', _op(
    'searchAuditStoreEvents', 'Search audit store events', ['Audit Store'], OPS_AUTH,
    { '200': _success('Paginated event search results', sg.makeObject({ events: sg.makeArray(sg.ref('AuditStoreEvent')), total: sg.makeInteger({ minimum: 0 }), pagination: sg.ref('PaginationMeta') })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      description: 'Full-text/filtered search across the centralized cross-subsystem audit event store (distinct from the cryptographic enforcement chain at /audit).',
      parameters: [
        ..._pageParamsWithLegacy,
        _pQuery('artifactId', sg.UUID_SCHEMA), _pQuery('requestId', sg.UUID_SCHEMA), _pQuery('correlationId', sg.makeString()),
        _pQuery('actorId', sg.ACTOR_ID_SCHEMA), _pQuery('actorUsername', sg.makeString()), _pQuery('keyId', sg.makeString()),
        _pQuery('policyId', sg.makeString()), _pQuery('tenantId', sg.TENANT_ID_SCHEMA),
        _pQuery('eventType', sg.makeString()), _pQuery('eventCategory', sg.makeString()),
        _pQuery('severity', sg.makeString({ enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] })),
        _pQuery('outcome', sg.makeString()), _pQuery('component', sg.makeString()),
        _pQuery('startTime', sg.ISO8601_SCHEMA), _pQuery('endTime', sg.ISO8601_SCHEMA),
      ],
    },
  ));

  add('/audit-store/events/{eventId}', 'get', _op(
    'getAuditStoreEvent', 'Get audit store event by ID', ['Audit Store'], OPS_AUTH,
    { '200': _success('Event details', sg.ref('AuditStoreEvent')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('EventIdParam')] },
  ));

  add('/audit-store/correlate/{requestId}', 'get', _op(
    'correlateAuditStoreEvents', 'Correlate events by request ID', ['Audit Store'], OPS_AUTH,
    { '200': _success('All events sharing this request ID', sg.makeObject({ requestId: sg.UUID_SCHEMA, events: sg.makeArray(sg.ref('AuditStoreEvent')), count: sg.makeInteger({ minimum: 0 }) })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [_pPath('requestId', sg.UUID_SCHEMA, 'HTTP request correlation identifier')] },
  ));

  add('/audit-store/artifact/{artifactId}/timeline', 'get', _op(
    'getArtifactAuditTimeline', 'Get cross-subsystem artifact timeline', ['Audit Store'], OPS_AUTH,
    { '200': _success('Artifact event timeline', sg.makeObject({ artifactId: sg.UUID_SCHEMA, events: sg.makeArray(sg.ref('AuditStoreEvent')), count: sg.makeInteger({ minimum: 0 }) })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ArtifactIdParam')] },
  ));

  add('/audit-store/actor/{actorId}/activity', 'get', _op(
    'getActorAuditActivity', 'Get actor audit activity trail', ['Audit Store'], OPS_AUTH,
    { '200': _success('Actor activity trail', sg.makeObject({ actorId: sg.ACTOR_ID_SCHEMA, events: sg.makeArray(sg.ref('AuditStoreEvent')), count: sg.makeInteger({ minimum: 0 }) })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [
      sg.paramRef('ActorIdParam'),
      // Range read, not classic offset pagination (no stable total count) —
      // see API-4-REMEDIATION-REPORT.md "justified exceptions". `page`/
      // `pageSize` are accepted as aliases for `offset`/`limit` here too.
      sg.paramRef('PageParam'), sg.paramRef('PageSizeParam'),
      _pQuery('limit', sg.makeInteger({ minimum: 1, maximum: 1000, default: 200 })),
      _pQuery('offset', sg.makeInteger({ minimum: 0, default: 0 })),
      _pQuery('startTime', sg.ISO8601_SCHEMA), _pQuery('endTime', sg.ISO8601_SCHEMA),
    ] },
  ));

  add('/audit-store/stats', 'get', _op(
    'getAuditStoreStats', 'Get audit store aggregate statistics', ['Audit Store'], OPS_AUTH,
    { '200': _success('Aggregate statistics and top event types'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/audit-store/ingestion-rate', 'get', _op(
    'getAuditIngestionRate', 'Get event ingestion rate', ['Audit Store'], OPS_AUTH,
    { '200': _success('Per-minute ingestion rate'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [_pQuery('windowMinutes', sg.makeInteger({ minimum: 1, maximum: 1440, default: 60 }))] },
  ));

  add('/audit-store/top-events', 'get', _op(
    'getTopAuditEventTypes', 'Get top event types by volume', ['Audit Store'], OPS_AUTH,
    { '200': _success('Top event types'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // Top-N ranking, not classic offset pagination — see
      // API-4-REMEDIATION-REPORT.md "justified exceptions". `pageSize` is
      // accepted as an alias for `limit`.
      parameters: [
        _pQuery('hours', sg.makeInteger({ minimum: 1, maximum: 168, default: 24 })),
        _pQuery('limit', sg.makeInteger({ minimum: 1, maximum: 100, default: 20 })),
        sg.paramRef('PageSizeParam'),
      ],
    },
  ));

  add('/audit-store/retention/policies', 'get', _op(
    'listRetentionPolicies', 'List audit retention policies', ['Audit Store'], OPS_AUTH,
    { '200': _success('Retention policies'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // Opt-in pagination (API-4): omitting page/pageSize/limit/offset
      // returns the full unbounded list (backward compatible).
      parameters: _pageParamsNoSort,
    },
  ));

  add('/audit-store/retention/policies', 'post', _op(
    'upsertRetentionPolicy', 'Create or update retention policy', ['Audit Store'], OPS_AUTH,
    { '200': _success('Upserted policy'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      requestBody: _body(sg.makeObject({
        name:             sg.makeString({ minLength: 1 }),
        description:      sg.makeString(),
        eventCategory:    sg.makeString(),
        eventTypePattern: sg.makeString(),
        tenantId:         sg.TENANT_ID_SCHEMA,
        severity:         sg.makeString({ enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] }),
        retainDays:       sg.makeInteger({ minimum: 0 }),
        complianceProfile: sg.makeString(),
      }, { required: ['name', 'retainDays'] }), 'Retention policy to create or update'),
    },
  ));

  add('/audit-store/retention/apply', 'post', _op(
    'applyRetentionCycle', 'Trigger retention cycle', ['Audit Store'], OPS_AUTH,
    { '200': _success('Retention cycle result'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Applies every configured retention policy now, deleting or archiving events past their retention window (except events under an active legal hold).' },
  ));

  add('/audit-store/retention/runs', 'get', _op(
    'listRetentionRuns', 'List retention run history', ['Audit Store'], OPS_AUTH,
    { '200': _success('Retention run history'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // "Recent N runs" read, not classic offset pagination (no stable total
      // count, no offset support) — see API-4-REMEDIATION-REPORT.md
      // "justified exceptions". `pageSize` is accepted as an alias for `limit`.
      parameters: [_pQuery('limit', sg.makeInteger({ minimum: 1, maximum: 200, default: 50 })), sg.paramRef('PageSizeParam')],
    },
  ));

  add('/audit-store/retention/holds', 'get', _op(
    'listLegalHolds', 'List active legal holds', ['Audit Store'], OPS_AUTH,
    { '200': _success('Active legal holds'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // Opt-in pagination (API-4): omitting page/pageSize/limit/offset
      // returns the full unbounded list (backward compatible).
      parameters: _pageParamsNoSort,
    },
  ));

  add('/audit-store/retention/holds', 'post', _op(
    'placeLegalHold', 'Place legal hold', ['Audit Store'], OPS_AUTH,
    { '200': _success('Legal hold placed'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      description: 'Events matching a legal hold\'s scope are exempted from retention deletion until the hold is released.',
      requestBody: _body(sg.makeObject({
        holdName:      sg.makeString({ minLength: 1 }),
        reason:        sg.makeString({ minLength: 1 }),
        artifactId:    sg.UUID_SCHEMA,
        tenantId:      sg.TENANT_ID_SCHEMA,
        eventCategory: sg.makeString(),
      }, { required: ['holdName', 'reason'] }), 'Legal hold scope (at least one of artifactId/tenantId/eventCategory required)'),
    },
  ));

  add('/audit-store/retention/holds/{holdName}', 'delete', _op(
    'releaseLegalHold', 'Release legal hold', ['Audit Store'], OPS_AUTH,
    { '200': _success('Legal hold released'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('HoldNameParam')] },
  ));

  // ── Audit Viewer (forensic audit chain explorer) ───────────────────────────

  add('/audit-viewer/chain-summary', 'get', _op(
    'getAuditViewerChainSummary', 'Get audit chain summary', ['Audit Viewer'], OPS_AUTH,
    { '200': _success('Chain summary — length, validity, decision/reason/stage breakdowns'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/audit-viewer/search', 'get', _op(
    'searchAuditViewer', 'Search audit chain entries', ['Audit Viewer'], OPS_AUTH,
    {
      '200': _success('Paginated search results', sg.makeObject({
        total: sg.makeInteger({ minimum: 0 }), page: sg.makeInteger(), pageSize: sg.makeInteger(),
        sortDir: sg.makeString({ enum: ['asc', 'desc'] }), sortOrder: sg.makeString({ enum: ['asc', 'desc'] }),
        totalItems: sg.makeInteger({ minimum: 0 }), totalPages: sg.makeInteger({ minimum: 0 }),
        hasNextPage: sg.makeBoolean(), hasPreviousPage: sg.makeBoolean(),
        results: sg.makeArray(sg.makeObject({}, { additionalProperties: true })),
      })),
      '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    {
      // Cap raised from this endpoint's previous 200 to the fleet-standard
      // 500 (API-4) — additive, every request that worked before still works.
      // `sort` (legacy) and `sortOrder` (canonical) are both real — see
      // src/utils/pagination.js parseSortOrder.
      parameters: [
        ..._pageParams,
        _pQuery('artifactId', sg.makeString()), _pQuery('decision', sg.makeString({ enum: ['ALLOW', 'BLOCK'] })),
        _pQuery('stage', sg.makeString()), _pQuery('startDate', sg.ISO8601_SCHEMA), _pQuery('endDate', sg.ISO8601_SCHEMA),
        _pQuery('verificationStatus', sg.makeString({ enum: ['VERIFIED', 'UNVERIFIED'] })),
        _pQuery('signatureStatus', sg.makeString({ enum: ['VALID', 'INVALID', 'EXPIRED', 'REVOKED', 'MISSING', 'UNKNOWN'] })),
        _pQuery('replayOnly', sg.makeBoolean()), _pQuery('failedOnly', sg.makeBoolean()),
        _pQuery('sort', sg.makeString({ enum: ['asc', 'desc'], default: 'desc' }), 'Deprecated alias for sortOrder.'),
      ],
    },
  ));

  add('/audit-viewer/timeline', 'get', _op(
    'getAuditViewerTimeline', 'Get audit event timeline', ['Audit Viewer'], OPS_AUTH,
    { '200': _success('Paginated event timeline'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // Cap raised from this endpoint's previous 200 to the fleet-standard
      // 500 (API-4) — additive, every request that worked before still works.
      parameters: [
        ..._pageParams, _pQuery('startDate', sg.ISO8601_SCHEMA), _pQuery('endDate', sg.ISO8601_SCHEMA),
        _pQuery('eventType', sg.makeString({ enum: ['ARTIFACT_ALLOWED', 'POLICY_BLOCKED', 'VALIDATION_FAILED', 'REPLAY_DETECTED', 'ARTIFACT_BLOCKED', 'SIGNATURE_VERIFIED', 'SIGNATURE_FAILED', 'CONSENT_DENIED', 'ANOMALY_DETECTED'] })),
      ],
    },
  ));

  add('/audit-viewer/export', 'get', _op(
    'exportAuditViewer', 'Export audit chain records', ['Audit Viewer'], OPS_AUTH,
    {
      '200': { description: 'Export file (JSON, CSV, or PDF depending on `format`)', content: { 'application/json': {}, 'text/csv': {}, 'application/pdf': {} } },
      '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    {
      description: `Exports up to 10,000 matching records. Accepts the same filters as GET /audit-viewer/search.`,
      parameters: [
        _pQuery('format', sg.makeString({ enum: ['json', 'csv', 'pdf'], default: 'json' })),
        _pQuery('artifactId', sg.makeString()), _pQuery('decision', sg.makeString({ enum: ['ALLOW', 'BLOCK'] })),
        _pQuery('startDate', sg.ISO8601_SCHEMA), _pQuery('endDate', sg.ISO8601_SCHEMA),
      ],
    },
  ));

  add('/audit-viewer/artifact/{artifactId}', 'get', _op(
    'inspectAuditViewerArtifact', 'Inspect artifact audit record', ['Audit Viewer'], OPS_AUTH,
    { '200': _success('Full artifact inspection — execution, signature, hashes, policy, verification, consent, replay, chain, and audit references'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ArtifactIdParam')] },
  ));

  add('/audit-viewer/signature/{artifactId}', 'get', _op(
    'inspectAuditViewerSignature', 'Inspect artifact signature validation', ['Audit Viewer'], OPS_AUTH,
    { '200': _success('Signature validation detail and known signing keys'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ArtifactIdParam')] },
  ));

  add('/audit-viewer/replay/{artifactId}', 'get', _op(
    'inspectAuditViewerReplay', 'Inspect replay/forensic analysis', ['Audit Viewer'], OPS_AUTH,
    { '200': _success('Replay lineage, detection timeline, and forensic cluster analysis (burst/sustained/distributed pattern, risk level)'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ArtifactIdParam')] },
  ));

  add('/audit-viewer/lineage/{artifactId}', 'get', _op(
    'inspectAuditViewerLineage', 'Inspect artifact lineage graph', ['Audit Viewer'], OPS_AUTH,
    { '200': _success('Lineage graph — nodes (artifact/policy/key/audit/verification), edges, and lifecycle steps'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ArtifactIdParam')] },
  ));

  add('/audit-viewer/chain/{artifactId}', 'get', _op(
    'verifyAuditViewerChain', 'Verify artifact chain integrity links', ['Audit Viewer'], OPS_AUTH,
    { '200': _success('Per-link verification (artifact/policy/key/audit-log/verification) with an overall integrity score'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ArtifactIdParam')] },
  ));

  add('/audit-viewer/investigation', 'get', _op(
    'listAuditInvestigations', 'List audit investigations', ['Audit Viewer'], OPS_AUTH,
    { '200': _success('Paginated investigations', sg.makeObject({ investigations: sg.makeArray(sg.ref('Investigation')), pagination: sg.ref('PaginationMeta') })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // API-4 fix: this previously documented the fleet-wide 500/50/sortOrder
      // via `_pageParams`, none of which matched the real handler (max 100,
      // default 20, no sort customization — always newest-first).
      parameters: [
        _pQuery('page', sg.makeInteger({ minimum: 1, default: 1 })),
        _pQuery('pageSize', sg.makeInteger({ minimum: 1, maximum: 100, default: 20 })),
        sg.paramRef('LimitParam'), sg.paramRef('OffsetParam'),
      ],
    },
  ));

  add('/audit-viewer/investigation', 'post', _op(
    'createAuditInvestigation', 'Create audit investigation', ['Audit Viewer'], OPS_AUTH,
    { '201': _success('Created investigation', sg.ref('Investigation')), '400': sg.responseRef('BadRequest'), '429': sg.responseRef('TooManyRequests'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.ref('InvestigationCreateRequest'), 'Investigation to create') },
  ));

  add('/audit-viewer/investigation/{id}', 'get', _op(
    'getAuditInvestigation', 'Get audit investigation', ['Audit Viewer'], OPS_AUTH,
    { '200': _success('Investigation detail, enriched with per-artifact audit status', sg.ref('Investigation')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('InvestigationIdParam')] },
  ));

  // ── Compliance ────────────────────────────────────────────────────────────

  add('/compliance/report/generate', 'post', _op(
    'generateReport', 'Generate compliance report', ['Compliance'], OPS_AUTH,
    { '202': _success('Report generation queued'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      requestBody: _body(sg.makeObject({
        frameworkId: sg.makeString({ enum: ['GDPR', 'EU_AI_ACT', 'ISO_42001', 'NIST_AI_RMF'], example: 'GDPR' }),
        periodStart: sg.makeString({ format: 'date-time', example: '2025-01-01T00:00:00Z' }),
        periodEnd:   sg.makeString({ format: 'date-time', example: '2025-12-31T23:59:59Z' }),
        tenantId:    sg.TENANT_ID_SCHEMA,
        sign:        sg.makeBoolean({ description: 'Cryptographically sign the report', default: false }),
      }, { required: ['frameworkId'] }), 'Report generation parameters'),
    },
  ));

  add('/compliance/reports', 'get', _op(
    'listReports', 'List compliance reports', ['Compliance'], OPS_AUTH,
    {
      '200': _success('Paginated report list', sg.makeObject({
        reports: sg.makeArray(sg.ref('ComplianceReport')),
        total:   sg.makeInteger({ minimum: 0 }),
        pagination: sg.ref('PaginationMeta'),
      })),
      ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    {
      // No sort customization — always newest-first server-side.
      parameters: [
        ..._pageParamsNoSort,
        _pQuery('frameworkId', sg.makeString({ enum: ['GDPR', 'EU_AI_ACT', 'ISO_42001', 'NIST_AI_RMF'] })),
        _pQuery('tenantId', sg.TENANT_ID_SCHEMA),
        _pQuery('status', sg.makeString()),
      ],
    },
  ));

  add('/compliance/report/{id}', 'get', _op(
    'getReport', 'Get compliance report', ['Compliance'], OPS_AUTH,
    { '200': _success('Report details', sg.ref('ComplianceReport')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ReportIdParam')] },
  ));

  add('/compliance/report/{id}/assessments', 'get', _op(
    'getReportAssessments', 'Get control assessments', ['Compliance'], OPS_AUTH,
    { '200': _success('Control assessment details'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ReportIdParam')] },
  ));

  add('/compliance/report/verify', 'post', _op(
    'verifyReport', 'Verify report integrity', ['Compliance'], OPS_AUTH,
    { '200': _success('Verification result'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ reportId: sg.UUID_SCHEMA }, { required: ['reportId'] })) },
  ));

  add('/compliance/report/{id}/download', 'get', _op(
    'downloadReport', 'Download compliance report', ['Compliance'], OPS_AUTH,
    { '200': { description: 'Report file (JSON or PDF)', content: { 'application/json': {}, 'application/pdf': {} } }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ReportIdParam'), _pQuery('fmt', sg.makeString({ enum: ['json', 'pdf'], default: 'json' }), 'Download format')] },
  ));

  add('/compliance/frameworks', 'get', _op(
    'listFrameworks', 'List compliance frameworks', ['Compliance'], OPS_AUTH,
    { '200': _success('Framework list'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/compliance/controls/{frameworkId}', 'get', _op(
    'getFrameworkControls', 'Get framework controls', ['Compliance'], OPS_AUTH,
    { '200': _success('Framework controls'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('FrameworkIdParam')] },
  ));

  add('/compliance/health', 'get', _op(
    'getComplianceHealth', 'Compliance subsystem health', ['Compliance'], OPS_AUTH,
    { '200': _success('Compliance report generator/store health'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  // ── Evidence ──────────────────────────────────────────────────────────────

  const _evidenceOps = (prefix, suffix) => {
    add(`${prefix}/package/{artifactId}`, 'get', _op(
      `getEvidencePackage${suffix}`, 'Build/retrieve evidence package (JSON)', ['Evidence'], OPS_AUTH,
      { '200': _success('Evidence package'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
      { description: 'Alias of GET .../package/{artifactId}/json.', parameters: [sg.paramRef('ArtifactIdParam')] },
    ));

    add(`${prefix}/package/{artifactId}/json`, 'get', _op(
      `getEvidencePackageJson${suffix}`, 'Get evidence package (JSON)', ['Evidence'], OPS_AUTH,
      { '200': _success('Evidence package JSON'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
      { parameters: [sg.paramRef('ArtifactIdParam')] },
    ));

    add(`${prefix}/package/{artifactId}/pdf`, 'get', _op(
      `getEvidencePackagePdf${suffix}`, 'Get evidence package (PDF)', ['Evidence'], OPS_AUTH,
      { '200': { description: 'Evidence PDF report', content: { 'application/pdf': {} } }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
      { parameters: [sg.paramRef('ArtifactIdParam')] },
    ));

    add(`${prefix}/package/{artifactId}/audit`, 'get', _op(
      `getEvidenceAuditChain${suffix}`, 'Get evidence audit chain excerpt', ['Evidence'], OPS_AUTH,
      { '200': _success('Filtered audit chain excerpt for this artifact'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
      { parameters: [sg.paramRef('ArtifactIdParam'), _pQuery('filtered', sg.makeBoolean({ default: true }), 'Return only entries related to this artifact')] },
    ));

    add(`${prefix}/package/{artifactId}/verify`, 'get', _op(
      `verifyEvidencePackageIntegrity${suffix}`, 'Verify evidence integrity', ['Evidence'], OPS_AUTH,
      { '200': _success('Evidence verification output'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
      { parameters: [sg.paramRef('ArtifactIdParam')] },
    ));

    add(`${prefix}/package/{artifactId}/bundle`, 'get', _op(
      `getEvidenceBundle${suffix}`, 'Get self-contained offline evidence bundle', ['Evidence'], OPS_AUTH,
      { '200': _success('Evidence bundle: evidence package + Merkle transparency inclusion proof, sealed together'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
      { description: 'Verifiable entirely offline via tools/verify/verify.bundle.external.js — no network, database, or server access required.', parameters: [sg.paramRef('ArtifactIdParam')] },
    ));
  };

  _evidenceOps('/evidence', '');
  _evidenceOps('/v1/evidence', 'V1');

  // ── Evidence Chain (append-only PostgreSQL-backed evidence ledger) ─────────

  add('/evidence-chain/records/search', 'get', _op(
    'searchEvidenceChainRecords', 'Search evidence chain records', ['Evidence'], OPS_AUTH,
    { '200': _success('Paginated evidence records'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      parameters: [
        ..._pageParams,
        _pQuery('artifactId', sg.UUID_SCHEMA), _pQuery('decision', sg.makeString({ enum: ['ALLOW', 'BLOCK'] })),
        _pQuery('policyHash', sg.makeString()), _pQuery('keyId', sg.makeString()), _pQuery('auditRecordId', sg.makeString()),
        _pQuery('tenantId', sg.TENANT_ID_SCHEMA), _pQuery('startTime', sg.ISO8601_SCHEMA), _pQuery('endTime', sg.ISO8601_SCHEMA),
      ],
    },
  ));

  add('/evidence-chain/records/by-artifact/{artifactId}', 'get', _op(
    'getEvidenceChainRecordByArtifact', 'Get evidence record by artifact', ['Evidence'], OPS_AUTH,
    { '200': _success('Evidence chain record'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ArtifactIdParam')] },
  ));

  add('/evidence-chain/records/{evidenceId}', 'get', _op(
    'getEvidenceChainRecord', 'Get evidence chain record', ['Evidence'], OPS_AUTH,
    { '200': _success('Evidence chain record'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('EvidenceIdParam')] },
  ));

  add('/evidence-chain/chain', 'get', _op(
    'getEvidenceChainRange', 'Get evidence chain range', ['Evidence'], OPS_AUTH,
    { '200': _success('Sequential evidence chain records'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [_pQuery('startId', sg.makeInteger({ minimum: 1 })), _pQuery('endId', sg.makeInteger({ minimum: 1 })), _pQuery('limit', sg.makeInteger({ minimum: 1, maximum: 10000, default: 100 }))] },
  ));

  add('/evidence-chain/chain/verify-range', 'post', _op(
    'verifyEvidenceChainRange', 'Verify evidence chain range integrity', ['Evidence'], OPS_AUTH,
    { '200': _success('Range verification result'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ startId: sg.makeInteger({ minimum: 1 }), endId: sg.makeInteger({ minimum: 1 }), limit: sg.makeInteger({ minimum: 1, maximum: 10000, default: 1000 }) }), 'Range to verify', false) },
  ));

  add('/evidence-chain/records/{evidenceId}/verify', 'post', _op(
    'verifyEvidenceChainRecord', 'Verify single evidence record', ['Evidence'], OPS_AUTH,
    { '200': _success('Verification outcome (steps passed/failed)'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('EvidenceIdParam')] },
  ));

  add('/evidence-chain/records/{evidenceId}/verifications', 'get', _op(
    'listEvidenceChainVerifications', 'List verification history for record', ['Evidence'], OPS_AUTH,
    { '200': _success('Verification history'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('EvidenceIdParam'), _pQuery('limit', sg.makeInteger({ minimum: 1, maximum: 500, default: 50 }))] },
  ));

  add('/evidence-chain/records/{evidenceId}/report', 'get', _op(
    'getEvidenceChainReport', 'Get evidence record report', ['Evidence'], OPS_AUTH,
    {
      '200': { description: 'Evidence report (inline JSON, or downloadable JSON attachment when format=json)', content: { 'application/json': {} } },
      '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS,
    },
    { parameters: [sg.paramRef('EvidenceIdParam'), _pQuery('format', sg.makeString({ enum: ['json'] }), 'Set to download as a JSON attachment')] },
  ));

  add('/evidence-chain/export/csv', 'get', _op(
    'exportEvidenceChainCsv', 'Export evidence records as CSV', ['Evidence'], OPS_AUTH,
    { '200': { description: 'CSV export of matching evidence records', content: { 'text/csv': {} } }, ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      parameters: [
        _pQuery('artifactId', sg.UUID_SCHEMA), _pQuery('decision', sg.makeString({ enum: ['ALLOW', 'BLOCK'] })),
        _pQuery('policyHash', sg.makeString()), _pQuery('keyId', sg.makeString()), _pQuery('tenantId', sg.TENANT_ID_SCHEMA),
        _pQuery('startTime', sg.ISO8601_SCHEMA), _pQuery('endTime', sg.ISO8601_SCHEMA), ..._pageParams,
      ],
    },
  ));

  add('/evidence-chain/dashboard', 'get', _op(
    'getEvidenceChainDashboard', 'Get evidence chain dashboard', ['Evidence'], OPS_AUTH,
    { '200': _success('Aggregate evidence chain statistics (record/allow/block counts, distinct keys and policy hashes, verification totals)'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  // ── Attestation ───────────────────────────────────────────────────────────

  add('/v1/attestation/verify', 'post', _op(
    'generateAttestation', 'Generate attestation', ['Attestation'], NO_AUTH,
    { '200': _success('Attestation result', sg.ref('AttestationResult')), '400': sg.responseRef('BadRequest'), ..._RATE_LIMITED, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ artifacts: sg.makeArray(sg.ref('Artifact')), context: sg.makeObject({}, { additionalProperties: true }) })) },
  ));

  add('/v1/attestation/evidence/verify', 'post', _op(
    'verifyEvidencePackage', 'Verify evidence package', ['Attestation'], NO_AUTH,
    { '200': _success('Evidence verification result'), '400': sg.responseRef('BadRequest'), ..._RATE_LIMITED, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ evidencePackage: sg.makeObject({}, { additionalProperties: true }) }, { required: ['evidencePackage'] })) },
  ));

  add('/v1/attestation/chain/verify', 'post', _op(
    'verifyAttestationChain', 'Verify evidence chain', ['Attestation'], OPS_AUTH,   // admin router + MANAGE_ATTESTATIONS (src/api/routes/attestation.js)
    { '200': _success('Chain verification result'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._RATE_LIMITED, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ chainId: sg.makeString() }, { required: ['chainId'] })) },
  ));

  add('/v1/attestation/{attestationId}', 'get', _op(
    'getAttestation', 'Get attestation', ['Attestation'], NO_AUTH,
    { '200': _success('Attestation record', sg.ref('AttestationResult')), ..._NOT_FOUND, ..._RATE_LIMITED, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AttestationIdParam')] },
  ));

  add('/v1/attestation/{attestationId}/export', 'get', _op(
    'exportAttestation', 'Export attestation', ['Attestation'], OPS_AUTH,
    { '200': { description: 'Attestation export (JSON or PDF)', content: { 'application/json': {}, 'application/pdf': {} } }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AttestationIdParam'), _pQuery('format', sg.makeString({ enum: ['json', 'pdf'], default: 'json' }))] },
  ));

  add('/v1/attestation/{attestationId}/evidence', 'get', _op(
    'attestationEvidence', 'Get attestation evidence', ['Attestation'], OPS_AUTH,
    { '200': _success('Evidence package'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AttestationIdParam')] },
  ));

  add('/v1/attestation/{attestationId}/summary', 'get', _op(
    'attestationSummary', 'Get attestation summary', ['Attestation'], OPS_AUTH,
    { '200': _success('Regulator summary'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AttestationIdParam')] },
  ));

  add('/v1/attestation/admin/history', 'get', _op(
    'attestationHistory', 'Attestation history', ['Attestation'], OPS_AUTH,
    { '200': _success('Paginated attestation history'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: _pageParams },
  ));

  add('/v1/attestation/admin/stats', 'get', _op(
    'attestationStats', 'Attestation statistics', ['Attestation'], OPS_AUTH,
    { '200': _success('Attestation statistics'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  // ── Certification ──────────────────────────────────────────────────────────

  add('/v1/certification/evaluate', 'post', _op(
    'evaluateCertification', 'Evaluate certification', ['Certification'], OPS_AUTH,   // admin router + SUBMIT_BATCH_CERTIFICATION
    { '200': _success('Certification result'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._RATE_LIMITED, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ artifacts: sg.makeArray(sg.ref('Artifact'), { maxItems: 50 }), evidencePackages: sg.makeArray(sg.makeObject({}, { additionalProperties: true }), { maxItems: 50 }), chain: sg.makeObject({}, { additionalProperties: true }), options: sg.makeObject({}, { additionalProperties: true }) })) },
  ));

  add('/v1/certification/{certificationId}', 'get', _op(
    'getCertificationResult', 'Get certification result', ['Certification'], NO_AUTH,
    { '200': _success('Certification result'), ..._NOT_FOUND, ..._RATE_LIMITED, ..._STD_ERRORS },
    { parameters: [sg.paramRef('CertificationIdParam')] },
  ));

  add('/v1/certification/{certificationId}/summary', 'get', _op(
    'getCertificationSummary', 'Get certification summary', ['Certification'], NO_AUTH,
    { '200': _success('Regulator-facing certification summary'), ..._NOT_FOUND, ..._RATE_LIMITED, ..._STD_ERRORS },
    { parameters: [sg.paramRef('CertificationIdParam')] },
  ));

  add('/v1/certification/{certificationId}/certificate', 'get', _op(
    'getCertificationCertificate', 'Get certification certificate', ['Certification'], NO_AUTH,
    { '200': { description: 'Certificate (JSON or PDF)', content: { 'application/json': {}, 'application/pdf': {} } }, ..._NOT_FOUND, ..._RATE_LIMITED, ..._STD_ERRORS },
    { parameters: [sg.paramRef('CertificationIdParam'), _pQuery('format', sg.makeString({ enum: ['json', 'pdf'], default: 'json' }))] },
  ));

  add('/v1/certification/admin/history', 'get', _op(
    'certificationHistory', 'Certification history', ['Certification'], OPS_AUTH,
    { '200': _success('History'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: _pageParams },
  ));

  add('/v1/certification/admin/stats', 'get', _op(
    'certificationStats', 'Certification statistics', ['Certification'], OPS_AUTH,
    { '200': _success('Statistics'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/v1/certification/{certificationId}/report', 'get', _op(
    'getCertificationReport', 'Get certification report', ['Certification'], OPS_AUTH,
    { '200': _success('Detailed certification report'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('CertificationIdParam')] },
  ));

  add('/v1/certification/{certificationId}/evidence', 'get', _op(
    'getCertificationEvidence', 'Get certification evidence package', ['Certification'], OPS_AUTH,
    { '200': _success('Certification evidence package'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('CertificationIdParam')] },
  ));

  add('/v1/certification/{certificationId}/export', 'get', _op(
    'exportCertification', 'Export certification', ['Certification'], OPS_AUTH,
    { '200': { description: 'Exported certification (JSON or PDF)', content: { 'application/json': {}, 'application/pdf': {} } }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('CertificationIdParam'), _pQuery('format', sg.makeString({ enum: ['json', 'pdf'], default: 'json' }))] },
  ));

  add('/v1/certifications/batch', 'post', _op(
    'createCertificationBatch', 'Submit certification batch', ['Certification'], OPS_AUTH,
    { '202': _success('Batch accepted — processing is asynchronous, poll GET .../batch/{batchId} for status'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      description: 'Requires SUBMIT_BATCH_CERTIFICATION permission.',
      requestBody: _body(sg.makeObject({
        frameworkId: sg.makeString({ enum: ['GDPR', 'EU_AI_ACT', 'ISO_42001', 'NIST_AI_RMF'] }),
        items:       sg.makeArray(sg.makeObject({}, { additionalProperties: true }), { minItems: 1 }),
      }, { required: ['frameworkId', 'items'] })),
    },
  ));

  add('/v1/certifications/batch/{batchId}', 'get', _op(
    'getCertificationBatch', 'Get certification batch status', ['Certification'], OPS_AUTH,
    { '200': _success('Batch status and summary counts'), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Requires READ_CERTIFICATIONS permission. Access is restricted to the owning tenant.', parameters: [sg.paramRef('BatchIdParam')] },
  ));

  add('/v1/certifications/batch/{batchId}/results', 'get', _op(
    'getBatchResults', 'Get batch certification results', ['Certification'], OPS_AUTH,
    { '200': _success('Per-item results, only available once the batch is not pending'), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Requires READ_CERTIFICATIONS permission.', parameters: [sg.paramRef('BatchIdParam')] },
  ));

  add('/v1/certifications/batch/{batchId}/cancel', 'post', _op(
    'cancelCertificationBatch', 'Cancel certification batch', ['Certification'], OPS_AUTH,
    { '200': _success('Batch cancelled'), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), '409': { description: 'Batch is already in a terminal state (completed/failed/cancelled)' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Cancels a pending or running batch. Requires CANCEL_BATCH_CERTIFICATION permission.', parameters: [sg.paramRef('BatchIdParam')] },
  ));

  // ── Transparency Log ───────────────────────────────────────────────────────

  const _transparencyOps = (prefix, suffix) => {
    add(`${prefix}/entry/{transparencyId}`, 'get', _op(
      `getTransparencyEntry${suffix}`, 'Get transparency entry', ['Transparency Log'], NO_AUTH,
      { '200': _success('Transparency entry', sg.makeObject({ entry: sg.ref('TransparencyEntry') }, { required: ['entry'] })), ..._NOT_FOUND, ..._STD_ERRORS },
      { parameters: [sg.paramRef('TransparencyIdParam')] },
    ));

    add(`${prefix}/entries`, 'get', _op(
      `listTransparencyEntries${suffix}`, 'List transparency entries', ['Transparency Log'], NO_AUTH,
      { '200': _success('Entry list (pagination metadata flat beside the list — src/utils/pagination.js withPaginationMeta)', sg.makeObject({
        entries: sg.makeArray(sg.ref('TransparencyEntry')),
        total: sg.makeInteger({ minimum: 0 }), page: sg.makeInteger({ minimum: 1 }), pageSize: sg.makeInteger({ minimum: 1 }),
        totalItems: sg.makeInteger({ minimum: 0 }), totalPages: sg.makeInteger({ minimum: 0 }), hasNextPage: sg.makeBoolean(), hasPreviousPage: sg.makeBoolean(),
      }, { required: ['entries', 'total', 'page', 'pageSize'] })), ..._STD_ERRORS },
      { parameters: _pageParams },
    ));

    add(`${prefix}/root`, 'get', _op(
      `getTransparencyRoot${suffix}`, 'Get latest Merkle root', ['Transparency Log'], NO_AUTH,
      { '200': _success('Latest signed root, or the root named by ?rootId (root is null with a message before the first root)', sg.makeObject({ root: sg.makeNullable(sg.ref('TransparencyRootRow')), message: sg.makeString() }, { required: ['root'] })), ..._STD_ERRORS },
    ));

    add(`${prefix}/roots`, 'get', _op(
      `listTransparencyRoots${suffix}`, 'List Merkle roots', ['Transparency Log'], NO_AUTH,
      { '200': _success('Root history, newest first (pagination metadata flat beside the list)', sg.makeObject({
        roots: sg.makeArray(sg.ref('TransparencyRootRow')),
        total: sg.makeInteger({ minimum: 0 }), page: sg.makeInteger({ minimum: 1 }), pageSize: sg.makeInteger({ minimum: 1 }),
        totalItems: sg.makeInteger({ minimum: 0 }), totalPages: sg.makeInteger({ minimum: 0 }), hasNextPage: sg.makeBoolean(), hasPreviousPage: sg.makeBoolean(),
      }, { required: ['roots', 'total', 'page', 'pageSize'] })), ..._STD_ERRORS },
      {
        // API-4 fix: this previously documented the fleet-wide 500/50 via
        // `_pageParams`, but the real handler caps at 200/20 (roots are a
        // smaller, coarser-grained collection than /entries in this same
        // router). `limit`/`offset` now also work as deprecated aliases.
        parameters: [
          _pQuery('page', sg.makeInteger({ minimum: 1, default: 1 })),
          _pQuery('pageSize', sg.makeInteger({ minimum: 1, maximum: 200, default: 20 })),
          sg.paramRef('LimitParam'), sg.paramRef('OffsetParam'),
        ],
      },
    ));

    add(`${prefix}/verify/{transparencyId}`, 'get', _op(
      `verifyTransparencyEntry${suffix}`, 'Verify transparency entry', ['Transparency Log'], NO_AUTH,
      { '200': _success('Entry verification result', sg.ref('TransparencyEntryVerification')), ..._NOT_FOUND, ..._STD_ERRORS },
      { parameters: [sg.paramRef('TransparencyIdParam')] },
    ));

    add(`${prefix}/proof/{transparencyId}`, 'get', _op(
      `getInclusionProof${suffix}`, 'Get Merkle inclusion proof', ['Transparency Log'], NO_AUTH,
      { '200': _success('Merkle inclusion proof (proof is null with a message until a root covers the entry). proofVerification.valid is true only when the proof verifies structurally AND the entry and covering-root signatures authenticate under active/deprecated transparency keys (ENTRY_SIGNATURE, ROOT_SIGNATURE checks; an unusable key store is SKIP and not valid)', sg.makeObject({
        transparencyId:    sg.UUID_SCHEMA,
        proof:             sg.makeNullable(sg.ref('TransparencyInclusionProof')),
        proofVerification: sg.makeObject({ valid: sg.makeBoolean(), structurallyValid: sg.makeBoolean(), authenticated: sg.makeBoolean(), checks: sg.makeArray(sg.ref('TransparencyCheck')), failedCheck: sg.makeNullable(sg.makeString()), failureReason: sg.makeNullable(sg.makeString()) }, { required: ['valid', 'checks'] }),
        message:           sg.makeString(),
      }, { required: ['transparencyId', 'proof'] })), ..._NOT_FOUND, ..._STD_ERRORS },
      { parameters: [sg.paramRef('TransparencyIdParam')] },
    ));

    add(`${prefix}/receipt/{requestId}`, 'get', _op(
      `getTransparencyReceipt${suffix}`, 'Get the signed receipt of a decision', ['Transparency Log'], NO_AUTH,
      { '200': _success('The receipt stored for that request (the body is the receipt and nothing else: no tenant, no reason). Receipts are kept for a bounded retrieval window (QODIQA_RECEIPT_TTL_SECONDS, default 3600 s); after it the answer is 404 and the durable evidence is the transparency inclusion proof', sg.makeObject({ receipt: sg.ref('SignedReceipt') }, { required: ['receipt'] })), '400': sg.responseRef('BadRequest'), ..._NOT_FOUND, ..._STD_ERRORS },
      { parameters: [sg.paramRef('ReceiptRequestIdParam')] },
    ));

    add(`${prefix}/consistency/{fromRootId}/{toRootId}`, 'get', _op(
      `getTransparencyConsistencyProof${suffix}`, 'Get Merkle consistency proof', ['Transparency Log'], NO_AUTH,
      { '200': _success('RFC 6962 consistency proof that tree(fromRoot) is a cryptographic prefix of tree(toRoot). verification.valid is true only when the hash relation verifies AND both roots\' signatures authenticate under active/deprecated transparency keys (FROM_ROOT_SIGNATURE, TO_ROOT_SIGNATURE checks; an unusable key store is SKIP and not valid); structurallyValid and authenticated report the two halves separately', sg.makeObject({
        fromRootId:       sg.UUID_SCHEMA,
        toRootId:         sg.UUID_SCHEMA,
        consistencyProof: sg.makeObject({}, { additionalProperties: true }),
        verification:     sg.makeObject({ valid: sg.makeBoolean(), structurallyValid: sg.makeBoolean(), authenticated: sg.makeBoolean(), checks: sg.makeArray(sg.ref('TransparencyCheck')), failedCheck: sg.makeNullable(sg.makeString()), failureReason: sg.makeNullable(sg.makeString()) }, { required: ['valid', 'structurallyValid', 'authenticated', 'checks'] }),
      }, { required: ['fromRootId', 'toRootId', 'consistencyProof', 'verification'] })), '400': sg.responseRef('BadRequest'), ..._NOT_FOUND, ..._STD_ERRORS },
      { parameters: [sg.paramRef('FromRootIdParam'), sg.paramRef('ToRootIdParam')] },
    ));

    add(`${prefix}/register`, 'post', _op(
      `registerTransparencyEntry${suffix}`, 'Register transparency entry', ['Transparency Log'], OPS_AUTH,
      { '201': _success('Registered entry', sg.ref('TransparencyEntry')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
      {
        requestBody: _body(sg.makeObject({
          entryType:     sg.makeString({ enum: ['ARTIFACT', 'EVIDENCE', 'VERIFICATION', 'POLICY', 'AUDIT', 'SYSTEM'] }),
          artifactId:    sg.UUID_SCHEMA,
          evidenceChainId: sg.UUID_SCHEMA,
          verificationId:  sg.UUID_SCHEMA,
          payload:       sg.makeObject({}, { additionalProperties: true }),
          tenantId:      sg.TENANT_ID_SCHEMA,
        }, { required: ['entryType'] }), 'Entry to register'),
      },
    ));

    add(`${prefix}/admin/roots/generate`, 'post', _op(
      `generateTransparencyRoot${suffix}`, 'Generate new Merkle root', ['Transparency Log'], OPS_AUTH,
      { '201': _success('New root', sg.ref('TransparencyRootGenerated')), ..._AUTH_ERRORS, ..._STD_ERRORS },
    ));

    add(`${prefix}/admin/stats`, 'get', _op(
      `transparencyStats${suffix}`, 'Transparency log statistics', ['Transparency Log'], OPS_AUTH,
      { '200': _success('Statistics'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    ));

    add(`${prefix}/admin/chain/validate`, 'get', _op(
      `validateTransparencyChain${suffix}`, 'Validate chain integrity', ['Transparency Log'], OPS_AUTH,
      { '200': _success('Validation result'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    ));
  };

  _transparencyOps('/transparency', '');
  _transparencyOps('/v1/transparency', 'V1');

  // ── Verification Portal ────────────────────────────────────────────────────

  const _portalOps = (prefix, suffix) => {
    add(`${prefix}/verify`, 'post', _op(
      `submitPortalVerification${suffix}`, 'Submit for verification', ['Verification Portal'], NO_AUTH,
      { '200': _success('Verification submitted'), '400': sg.responseRef('BadRequest'), ..._RATE_LIMITED, ..._STD_ERRORS },
      { requestBody: _body(sg.makeObject({ artifact: sg.ref('Artifact'), context: sg.makeObject({}, { additionalProperties: true }) })) },
    ));

    add(`${prefix}/result/{verificationId}`, 'get', _op(
      `getPortalResult${suffix}`, 'Get verification result', ['Verification Portal'], NO_AUTH,
      { '200': _success('Verification result'), ..._NOT_FOUND, ..._RATE_LIMITED, ..._STD_ERRORS },
      { parameters: [sg.paramRef('PortalIdParam')] },
    ));

    add(`${prefix}/report/{verificationId}`, 'get', _op(
      `getPortalReport${suffix}`, 'Download verification report', ['Verification Portal'], NO_AUTH,
      { '200': { description: 'Report (JSON or PDF)', content: { 'application/json': {}, 'application/pdf': {} } }, ..._NOT_FOUND, ..._RATE_LIMITED, ..._STD_ERRORS },
      { parameters: [sg.paramRef('PortalIdParam'), _pQuery('format', sg.makeString({ enum: ['json', 'pdf'], default: 'json' }))] },
    ));

    // the V1 package embeds the submitter address (internal audit data),
    // so it is served by the admin router under READ_VERIFICATION_PORTAL.
    add(`${prefix}/evidence/{verificationId}`, 'get', _op(
      `getPortalEvidence${suffix}`, 'Get verification evidence', ['Verification Portal'], OPS_AUTH,
      { '200': _success('Evidence package'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
      { parameters: [sg.paramRef('PortalIdParam')] },
    ));

    add(`${prefix}/admin/history`, 'get', _op(
      `portalHistory${suffix}`, 'Verification portal history', ['Verification Portal'], OPS_AUTH,
      { '200': _success('Submission history'), ..._AUTH_ERRORS, ..._STD_ERRORS },
      { parameters: _pageParams },
    ));

    add(`${prefix}/admin/stats`, 'get', _op(
      `portalStats${suffix}`, 'Verification portal statistics', ['Verification Portal'], OPS_AUTH,
      { '200': _success('Portal statistics'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    ));
  };

  _portalOps('/portal', '');
  _portalOps('/v1/portal', 'V1');

  // ── Provenance ─────────────────────────────────────────────────────────────

  add('/provenance/policies/search/history', 'get', _op(
    'searchProvenanceHistory', 'Search policy change history', ['Provenance'], OPS_AUTH,
    { '200': _success('Paginated change history across all policies'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      parameters: [
        ..._pageParams,
        _pQuery('policyId', sg.makeString({ pattern: '^[A-Za-z0-9_-]{1,64}$' })), _pQuery('actorId', sg.ACTOR_ID_SCHEMA),
        _pQuery('actorUsername', sg.makeString()), _pQuery('eventType', sg.makeString()), _pQuery('sourceIp', sg.makeString()),
        _pQuery('changeReason', sg.makeString()), _pQuery('startTime', sg.ISO8601_SCHEMA), _pQuery('endTime', sg.ISO8601_SCHEMA),
      ],
    },
  ));

  add('/provenance/policies/{policyId}/history', 'get', _op(
    'getPolicyProvenanceHistory', 'Get policy change history', ['Provenance'], OPS_AUTH,
    { '200': _success('Paginated change history for this policy'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam'), ..._pageParams, _pQuery('startTime', sg.ISO8601_SCHEMA), _pQuery('endTime', sg.ISO8601_SCHEMA), _pQuery('actorId', sg.ACTOR_ID_SCHEMA), _pQuery('eventType', sg.makeString())] },
  ));

  add('/provenance/policies/{policyId}/version/{version}', 'get', _op(
    'getPolicyProvenanceVersion', 'Get a specific policy provenance version', ['Provenance'], OPS_AUTH,
    { '200': _success('Provenance record for this version (policy_content included for admin/auditor roles only)'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam'), _pPath('version', sg.makeInteger({ minimum: 1 }), 'Version number')] },
  ));

  add('/provenance/policies/{policyId}/reconstruct/{timestamp}', 'get', _op(
    'reconstructPolicyAtTimestamp', 'Reconstruct policy state at a point in time', ['Provenance'], OPS_AUTH,
    { '200': _success('Reconstructed policy content as of the requested timestamp'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Requires INVESTIGATE_POLICIES permission.', parameters: [sg.paramRef('PolicyIdParam'), _pPath('timestamp', sg.ISO8601_SCHEMA, 'ISO 8601 timestamp (URL-encoded)')] },
  ));

  add('/provenance/policies/{policyId}/timeline', 'get', _op(
    'getPolicyProvenanceTimeline', 'Get policy provenance timeline', ['Provenance'], OPS_AUTH,
    { '200': _success('Chronological event timeline for this policy'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    {
      // Opt-in pagination (API-4): omitting page/pageSize/limit/offset
      // returns the full unbounded list (backward compatible).
      parameters: [
        sg.paramRef('PolicyIdParam'), _pQuery('startTime', sg.ISO8601_SCHEMA), _pQuery('endTime', sg.ISO8601_SCHEMA),
        ..._pageParamsNoSort,
      ],
    },
  ));

  add('/provenance/policies/{policyId}/diff/{versionA}/{versionB}', 'get', _op(
    'diffPolicyProvenanceVersions', 'Compare two policy versions', ['Provenance'], OPS_AUTH,
    { '200': _success('Structural diff between the two versions'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam'), _pPath('versionA', sg.makeInteger({ minimum: 1 }), 'First version'), _pPath('versionB', sg.makeInteger({ minimum: 1 }), 'Second version')] },
  ));

  add('/provenance/policies/{policyId}/lineage', 'get', _op(
    'getPolicyProvenanceLineage', 'Get policy provenance lineage', ['Provenance'], OPS_AUTH,
    { '200': _success('Full lineage graph for this policy'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('PolicyIdParam')] },
  ));

  add('/provenance/policies/{policyId}/integrity', 'post', _op(
    'verifyPolicyProvenanceIntegrity', 'Verify policy provenance hash chain integrity', ['Provenance'], OPS_AUTH,
    { '200': _success('Hash-chain integrity check result'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Requires INVESTIGATE_POLICIES permission.', parameters: [sg.paramRef('PolicyIdParam')] },
  ));

  add('/provenance/policies/{policyId}/report', 'get', _op(
    'getPolicyProvenanceReport', 'Generate policy provenance report', ['Provenance'], OPS_AUTH,
    {
      '200': { description: 'Provenance report (JSON, CSV, or PDF-ready JSON depending on `format`)', content: { 'application/json': {}, 'text/csv': {} } },
      '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS,
    },
    { description: 'Requires INVESTIGATE_POLICIES permission.', parameters: [sg.paramRef('PolicyIdParam'), _pQuery('format', sg.makeString({ enum: ['json', 'csv', 'pdf'], default: 'json' })), _pQuery('startTime', sg.ISO8601_SCHEMA), _pQuery('endTime', sg.ISO8601_SCHEMA)] },
  ));

  add('/provenance/dashboard/stats', 'get', _op(
    'getProvenanceDashboardStats', 'Get provenance dashboard statistics', ['Provenance'], OPS_AUTH,
    { '200': _success('Aggregate provenance statistics'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/provenance/dashboard/timeline', 'get', _op(
    'getProvenanceDashboardTimeline', 'Get cross-policy activity timeline', ['Provenance'], OPS_AUTH,
    { '200': _success('Cross-policy recent activity timeline (policy_content stripped for non-investigator roles)'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [..._pageParams, _pQuery('startTime', sg.ISO8601_SCHEMA), _pQuery('endTime', sg.ISO8601_SCHEMA), _pQuery('eventType', sg.makeString()), _pQuery('actorId', sg.ACTOR_ID_SCHEMA)] },
  ));

  add('/provenance/dashboard/investigator', 'get', _op(
    'getProvenanceInvestigatorDashboard', 'Get investigator dashboard view', ['Provenance'], OPS_AUTH,
    { '200': _success('Investigator view — top modified policies, rollback events, and aggregate stats'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Requires INVESTIGATE_POLICIES permission.', parameters: [_pQuery('eventType', sg.makeString()), _pQuery('actorId', sg.ACTOR_ID_SCHEMA), _pQuery('startTime', sg.ISO8601_SCHEMA), _pQuery('endTime', sg.ISO8601_SCHEMA)] },
  ));

  add('/provenance/dashboard/comparison', 'get', _op(
    'getProvenanceDashboardComparison', 'Compare two policy versions (dashboard view)', ['Provenance'], OPS_AUTH,
    { '200': _success('Version comparison view'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [_p('policyId', 'query', sg.makeString({ pattern: '^[A-Za-z0-9_-]{1,64}$' }), 'Policy identifier', true), _p('versionA', 'query', sg.makeInteger({ minimum: 1 }), 'First version', true), _p('versionB', 'query', sg.makeInteger({ minimum: 1 }), 'Second version', true)] },
  ));

  // ── RBAC ──────────────────────────────────────────────────────────────────

  add('/rbac/roles', 'get', _op(
    'listRoles', 'List RBAC roles', ['RBAC'], OPS_AUTH,
    { '200': _success('Role definitions — the five built-in roles plus every operator-defined custom role', sg.makeObject({ roles: sg.makeArray(sg.ref('RbacRole')) })), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/rbac/roles', 'post', _op(
    'createRbacRole', 'Create custom role', ['RBAC'], OPS_AUTH,
    { '201': _success('Created role', sg.ref('RbacRole')), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Create a custom role — a named collection of permissions drawn from the fixed matrix (GET /rbac/permissions). Does not affect the five built-in roles.', requestBody: _body(sg.ref('RbacCreateRoleRequest'), 'Role to create') },
  ));

  add('/rbac/roles/validate', 'post', _op(
    'validateRbacPermissions', 'Validate a permission set', ['RBAC'], OPS_AUTH,
    { '200': _success('Validation result — does not create or modify anything', sg.makeObject({ valid: sg.makeBoolean(), permissions: sg.makeArray(sg.makeString()), code: sg.makeString(), message: sg.makeString() })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Dry-run check of a permission array against the fixed matrix — rejects unknown permissions, duplicates, and invalid structures without persisting a role.', requestBody: _body(sg.ref('RbacValidatePermissionsRequest'), 'Permissions to validate') },
  ));

  add('/rbac/roles/{id}', 'get', _op(
    'getRbacRole', 'Get RBAC role', ['RBAC'], OPS_AUTH,
    { '200': _success('Role details', sg.ref('RbacRole')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('RoleIdParam')] },
  ));

  add('/rbac/roles/{id}', 'patch', _op(
    'updateRbacRole', 'Update custom role', ['RBAC'], OPS_AUTH,
    { '200': _success('Updated role', sg.ref('RbacRole')), '400': sg.responseRef('BadRequest'), '422': { description: 'Attempted to modify a built-in role' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Update a custom role\'s name, description, permissions, or enabled flag. The role\'s ID never changes, even when its name does. Built-in roles cannot be modified (422 CANNOT_MODIFY_BUILTIN). Canonical as of API-9/WP-030 (this is always a partial update, hence PATCH); PUT is a deprecated alias below.', parameters: [sg.paramRef('RoleIdParam')], requestBody: _body(sg.ref('RbacUpdateRoleRequest'), 'Fields to update') },
  ));

  add('/rbac/roles/{id}', 'put', _op(
    'updateRbacRoleLegacy', 'Update custom role (deprecated alias of PATCH)', ['RBAC'], OPS_AUTH,
    { '200': _success('Updated role', sg.ref('RbacRole')), '400': sg.responseRef('BadRequest'), '422': { description: 'Attempted to modify a built-in role' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    {
      description: 'DEPRECATED — use PATCH /rbac/roles/{id} instead (API-9/WP-030). Identical behavior; ' +
        'returns Deprecation/Link response headers and logs a RBAC_ADMIN_PUT_ROLE_DEPRECATED_USED warning.',
      parameters: [sg.paramRef('RoleIdParam')],
      requestBody: _body(sg.ref('RbacUpdateRoleRequest'), 'Fields to update'),
      deprecated: true,
    },
  ));

  add('/rbac/roles/{id}', 'delete', _op(
    'deleteRbacRole', 'Delete custom role', ['RBAC'], OPS_AUTH,
    { '200': _success('Role deleted'), '409': { description: 'Role is currently assigned to one or more users — pass ?force=true to delete anyway' }, '422': { description: 'Attempted to delete a built-in role' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Delete a custom role. Built-in roles cannot be deleted (422 CANNOT_MODIFY_BUILTIN). Refuses to delete a role assigned to any user unless ?force=true is passed.', parameters: [sg.paramRef('RoleIdParam'), _p('force', 'query', sg.makeBoolean(), 'Delete even if the role is currently assigned to users', false)] },
  ));

  add('/rbac/permissions', 'get', _op(
    'listPermissions', 'Permission matrix', ['RBAC'], OPS_AUTH,
    { '200': _success('Permission matrix'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/rbac/users', 'get', _op(
    'listRbacUsers', 'List RBAC users', ['RBAC'], OPS_AUTH,
    { '200': _success('User list', sg.makeObject({ users: sg.makeArray(sg.ref('RbacUser')), total: sg.makeInteger({ minimum: 0 }), pagination: sg.ref('PaginationMeta') })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // API-4 fix: this previously documented full canonical pagination
      // (including sortOrder) via `_pageParams`, but the real handler had no
      // pagination support at all. Opt-in pagination (no sort customization —
      // insertion order): omitting page/pageSize/limit/offset returns the
      // full unbounded list (backward compatible).
      parameters: _pageParamsNoSort,
    },
  ));

  add('/rbac/users', 'post', _op(
    'createRbacUser', 'Create RBAC user', ['RBAC'], OPS_AUTH,
    { '201': _success('Created user', sg.ref('RbacUser')), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.ref('RbacCreateUserRequest'), 'User to create') },
  ));

  add('/rbac/users/{id}', 'get', _op(
    'getRbacUser', 'Get RBAC user', ['RBAC'], OPS_AUTH,
    { '200': _success('User details', sg.ref('RbacUser')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('UserIdParam')] },
  ));

  add('/rbac/users/{id}', 'patch', _op(
    'updateRbacUser', 'Update RBAC user', ['RBAC'], OPS_AUTH,
    { '200': _success('Updated user', sg.ref('RbacUser')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Canonical as of API-9/WP-030 (this is always a partial update, hence PATCH); PUT is a deprecated alias below.', parameters: [sg.paramRef('UserIdParam')], requestBody: _body(sg.ref('RbacUpdateUserRequest'), 'Fields to update') },
  ));

  add('/rbac/users/{id}', 'put', _op(
    'updateRbacUserLegacy', 'Update RBAC user (deprecated alias of PATCH)', ['RBAC'], OPS_AUTH,
    { '200': _success('Updated user', sg.ref('RbacUser')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    {
      description: 'DEPRECATED — use PATCH /rbac/users/{id} instead (API-9/WP-030). Identical behavior; ' +
        'returns Deprecation/Link response headers and logs a RBAC_ADMIN_PUT_USER_DEPRECATED_USED warning.',
      parameters: [sg.paramRef('UserIdParam')],
      requestBody: _body(sg.ref('RbacUpdateUserRequest'), 'Fields to update'),
      deprecated: true,
    },
  ));

  add('/rbac/users/{id}', 'delete', _op(
    'deleteRbacUser', 'Delete RBAC user', ['RBAC'], OPS_AUTH,
    { '204': { description: 'User deleted' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('UserIdParam')] },
  ));

  add('/rbac/users/{id}/api-key', 'post', _op(
    'issueApiKey', 'Issue / rotate API key', ['RBAC'], OPS_AUTH,
    { '201': _success('Generated API key (plaintext shown once)', sg.makeObject({ apiKey: sg.makeString({ description: 'Plaintext API key — store securely, shown once', example: 'ok_abc123...' }), expiresAt: sg.makeNullable(sg.ISO8601_SCHEMA) })), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('UserIdParam')], description: 'Issue a new per-operator API key (expires after QODIQA_API_KEY_TTL_DAYS, default 90). The previous key keeps working for the rotation grace (default 24 h, never past its own expiry). The plaintext key is returned **once** — it cannot be retrieved again.' },
  ));

  add('/rbac/users/{id}/api-key', 'delete', _op(
    'revokeApiKey', 'Revoke API key', ['RBAC'], OPS_AUTH,
    { '204': { description: 'API key revoked' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('UserIdParam')] },
  ));

  // operator MFA. enroll/confirm are the only /rbac mutations
  // exempt from the X-QODIQA-OTP step-up; the admin reset requires it.
  add('/rbac/me/mfa', 'get', _op(
    'getMyMfaStatus', 'Get own MFA status', ['RBAC'], OPS_AUTH,
    { '200': _success('MFA status (never the secret or codes)', sg.makeObject({ enrolled: sg.makeBoolean(), required: sg.makeBoolean(), remainingRecoveryCodes: sg.makeInteger() })), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/rbac/me/mfa/enroll', 'post', _op(
    'beginMfaEnrollment', 'Start own TOTP enrolment', ['RBAC'], OPS_AUTH,
    { '201': _success('TOTP secret and otpauth URI (shown once)', sg.makeObject({ secret: sg.makeString(), otpauthUri: sg.makeString() })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Allowed only while the caller has no MFA enrolled (409 MFA_ALREADY_ENROLLED otherwise). The pending enrolment expires after 10 minutes.' },
  ));

  add('/rbac/me/mfa/confirm', 'post', _op(
    'confirmMfaEnrollment', 'Confirm own TOTP enrolment', ['RBAC'], OPS_AUTH,
    { '200': _success('Enrolled; 10 single-use recovery codes (shown once)', sg.makeObject({ enrolled: sg.makeBoolean(), recoveryCodes: sg.makeArray(sg.makeString()) })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Body: { code } — a current 6-digit TOTP code from the enrolled authenticator.', requestBody: _body(sg.makeObject({ code: sg.makeString() }), 'A current TOTP code', true) },
  ));

  add('/rbac/users/{id}/mfa', 'delete', _op(
    'resetUserMfa', 'Reset an operator MFA enrolment', ['RBAC'], OPS_AUTH,
    { '200': _success('MFA removed; the user must enrol again'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('UserIdParam')], description: 'Requires MANAGE_USERS and a step-up MFA code from the caller (X-QODIQA-OTP).' },
  ));

  add('/rbac/users/{id}/permissions', 'get', _op(
    'getUserPermissions', 'Get effective permissions', ['RBAC'], OPS_AUTH,
    { '200': _success('Effective permissions', sg.makeObject({ permissions: sg.makeArray(sg.makeString()) })), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('UserIdParam')] },
  ));

  // ── Key Management ────────────────────────────────────────────────────────

  add('/key-admin/inventory', 'get', _op(
    'getKeyInventory', 'Get full classified key inventory', ['Key Management'], OPS_AUTH,
    { '200': _success('Key inventory across all tenants (active/deprecated/revoked counts)'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // Opt-in pagination (API-4) over the `entries` array: omitting
      // page/pageSize/limit/offset returns the full unbounded list (backward
      // compatible); the summary counts always describe the full inventory.
      parameters: _pageParamsNoSort,
    },
  ));

  add('/key-admin/purge-expired', 'post', _op(
    'purgeExpiredKeys', 'Purge expired deprecated keys', ['Key Management'], OPS_AUTH,
    { '200': _success('Purge result (purged and archived counts)'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ clientId: sg.makeString({ description: 'Omit to purge across all clients' }) }), 'Optional client scope', false) },
  ));

  add('/key-admin/rotation-scheduler/status', 'get', _op(
    'getRotationSchedulerStatus', 'Get automatic rotation scheduler status', ['Key Management'], OPS_AUTH,
    { '200': _success('Scheduler status'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/key-admin/health', 'get', _op(
    'getKeyHealthSummary', 'Get aggregate key health', ['Key Management'], OPS_AUTH,
    { '200': _success('Aggregate key health across all tenants'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/key-admin/{clientId}/status', 'get', _op(
    'getClientKeyStatus', 'Get per-tenant key status', ['Key Management'], OPS_AUTH,
    { '200': _success('Key status for this client'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ClientIdParam')] },
  ));

  add('/key-admin/kek/rotate', 'post', _op(
    'rotateKek', 'Rotate the active KMS provider\'s wrapping key (KEK)', ['Key Management'], OPS_AUTH,
    {
      '200': _success('Rotation result — new key material is encrypted under the new KEK going forward; existing keys.json ciphertext is unaffected until scripts/migrate-keys-json-kek.js is run'),
      '409': sg.responseRef('Conflict'), '503': { description: 'Could not acquire the rotation lock' }, ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    { description: 'Rotates the KMS provider\'s own wrapping key (KEK) — the key that encrypts artifact-signing private key material at rest. Distinct from POST /key-admin/{clientId}/rotate, which rotates an artifact signing key. Lock-protected — a concurrent KEK rotation is rejected with 409. Registered before /key-admin/{clientId}/rotate so a literal "kek" is never captured as {clientId}.' },
  ));

  add('/key-admin/mac-keys/rotate', 'post', _op(
    'rotateMacKeyring', 'Rotate the keystore MAC keyring (consent cache + pub/sub signing)', ['Key Management'], OPS_AUTH,
    {
      '200': _success('Rotation result — activeKid and previousKid (key ids only, never key material)'),
      '409': sg.responseRef('Conflict'), '503': { description: 'Could not acquire the rotation lock' }, ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    { description: 'rotates the HMAC keyring that signs consent-cache entries and consent-revocation / organisation-status pub/sub messages. The previous key stays verifiable for one more rotation. Lock-protected — a concurrent rotation is rejected with 409. Registered before /key-admin/{clientId}/rotate so a literal "mac-keys" is never captured as {clientId}.' },
  ));

  add('/key-admin/{clientId}/rotate', 'post', _op(
    'rotateKeyEmergency', 'Emergency rotate signing key', ['Key Management'], OPS_AUTH,
    {
      '200': _success('Rotation result — the outgoing key is REVOKED (loses signing and verification capability)'),
      '409': sg.responseRef('Conflict'), '502': { description: 'Native signing provider revocation failed' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS,
    },
    { description: 'The default, ordinary "rotate" action. Use for a suspected key compromise. Lock-protected — a concurrent rotation for the same client is rejected with 409.', parameters: [sg.paramRef('ClientIdParam')] },
  ));

  add('/key-admin/{clientId}/rotate-graceful', 'post', _op(
    'rotateKeyGraceful', 'Planned (graceful) rotate signing key', ['Key Management'], OPS_AUTH,
    { '200': _success('Rotation result — the outgoing key is DEPRECATED (keeps verification capability for in-flight artifacts)'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Use only for planned, non-incident maintenance rotation — never in response to a suspected compromise.', parameters: [sg.paramRef('ClientIdParam')] },
  ));

  add('/key-admin/{clientId}/revoke', 'post', _op(
    'revokeKey', 'Revoke a specific signing key', ['Key Management'], OPS_AUTH,
    { '200': _success('Revocation result'), '400': sg.responseRef('BadRequest'), '502': { description: 'Native signing provider revocation failed' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    {
      parameters: [sg.paramRef('ClientIdParam')],
      requestBody: _body(sg.makeObject({ keyId: sg.makeString({ example: 'default:key_v1' }), reason: sg.makeString() }, { required: ['keyId'] }), 'Key to revoke — keyId must belong to this client'),
    },
  ));

  add('/key-admin/{clientId}/recover', 'post', _op(
    'recoverClientKey', 'Provision new active key for a no-key client', ['Key Management'], OPS_AUTH,
    { '200': _success('Recovery result'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'For a client with existing key history but no current active key. For clients with no history at all, use POST /key-admin/{clientId}/rotate instead.', parameters: [sg.paramRef('ClientIdParam')] },
  ));

  // ── Public Keys ───────────────────────────────────────────────────────────

  add('/keys', 'get', _op(
    'listKeys', 'List all public keys', ['Public Keys'], NO_AUTH,
    { '200': _success('All public keys'), ..._STD_ERRORS },
  ));

  add('/public-key', 'get', _op(
    'getActivePublicKey', 'Get active public key', ['Public Keys'], NO_AUTH,
    { '200': _success('Active public key'), ..._STD_ERRORS },
  ));

  add('/public-keys', 'get', _op(
    'discoverPublicKeys', 'Public key discovery', ['Public Keys'], NO_AUTH,
    { '200': _success('Available public keys'), ..._STD_ERRORS },
  ));

  add('/.well-known/qodiqa/keys', 'get', _op(
    'wellKnownKeys', 'Well-known public keys', ['Well-Known'], NO_AUTH,
    { '200': _success('Public key set (JWK format)'), ..._STD_ERRORS },
    { description: 'IANA well-known endpoint for public key discovery (JWKS format).' },
  ));

  add('/.well-known/qodiqa/keys/{keyId}', 'get', _op(
    'wellKnownKey', 'Well-known key by ID', ['Well-Known'], NO_AUTH,
    { '200': _success('Specific public key (JWK format)'), ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [_pPath('keyId', sg.makeString(), 'Key identifier')] },
  ));

  add('/.well-known/qodiqa/keys/archived', 'get', _op(
    'wellKnownArchivedKeys', 'Well-known archived (purged) public keys', ['Well-Known'], NO_AUTH,
    { '200': _success('Archived public key set (JWK format)'), ..._STD_ERRORS },
    { description: 'archived-key discovery endpoint — artifact-signing keys that have been purged from the live keystore (see /.well-known/qodiqa/keys) but remain published here so historical artifacts stay verifiable indefinitely. Independently and more strictly rate limited than the live discovery endpoint.' },
  ));

  add('/.well-known/qodiqa/transparency-keys', 'get', _op(
    'wellKnownTransparencyKeys', 'Well-known transparency-log public keys', ['Well-Known'], NO_AUTH,
    { '200': _success('Transparency log public key set (JWK format)'), ..._STD_ERRORS },
    { description: 'IANA well-known endpoint for transparency-log Merkle root signing key discovery (JWKS format), distinct from the artifact-signing key set at /.well-known/qodiqa/keys.' },
  ));

  add('/.well-known/qodiqa/transparency-keys/{keyId}', 'get', _op(
    'wellKnownTransparencyKey', 'Well-known transparency key by ID', ['Well-Known'], NO_AUTH,
    { '200': _success('Specific transparency-log public key (JWK format)'), ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [_pPath('keyId', sg.makeString(), 'Key identifier')] },
  ));

  add('/.well-known/qodiqa/checkpoint-keys', 'get', _op(
    'wellKnownCheckpointKeys', 'Well-known audit-checkpoint public keys', ['Well-Known'], NO_AUTH,
    { '200': _success('Audit-checkpoint public key set') , ..._STD_ERRORS },
    { description: 'the public keys of the audit-checkpoint signing key store (a separate trust domain from the artifact and transparency keys), for independent verification of signed audit-chain checkpoints and of audit.log.base.json.' },
  ));

  add('/.well-known/qodiqa/checkpoint-keys/{keyId}', 'get', _op(
    'wellKnownCheckpointKey', 'Well-known audit-checkpoint key by ID', ['Well-Known'], NO_AUTH,
    { '200': _success('Specific audit-checkpoint public key'), ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [_pPath('keyId', sg.makeString(), 'Key identifier')] },
  ));

  // ── Webhooks ──────────────────────────────────────────────────────────────

  // (API-15): every per-id webhook route answers 400 without ?tenantId= (src/api/routes/webhooks.js), the same
  // as the list operation; the spec previously declared it on the list only.
  const _webhookTenant = _p('tenantId', 'query', sg.TENANT_ID_SCHEMA, 'Required — the tenant that owns the endpoint (400 without it).', true);

  add('/v1/webhooks', 'post', _op(
    'createWebhook', 'Create webhook endpoint', ['Webhooks'], OPS_AUTH,
    { '201': _success('Created webhook endpoint (signing secret included once)', sg.makeObject({ webhook: sg.ref('WebhookEndpoint'), signingSecret: sg.makeString({ description: 'Webhook signing secret — store securely, shown once' }) })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.ref('WebhookCreateRequest'), 'Webhook endpoint to create') },
  ));

  add('/v1/webhooks', 'get', _op(
    'listWebhooks', 'List webhook endpoints', ['Webhooks'], OPS_AUTH,
    {
      '200': _success('Paginated webhook list', sg.makeObject({
        endpoints: sg.makeArray(sg.ref('WebhookEndpoint')), total: sg.makeInteger({ minimum: 0 }),
        pagination: sg.ref('PaginationMeta'),
      })),
      ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    {
      parameters: [
        _p('tenantId', 'query', sg.TENANT_ID_SCHEMA, 'Required', true),
        _pQuery('enabledOnly', sg.makeBoolean()),
        ..._pageParamsWithLegacy,
      ],
    },
  ));

  add('/v1/webhooks/{id}', 'get', _op(
    'getWebhook', 'Get webhook endpoint', ['Webhooks'], OPS_AUTH,
    { '200': _success('Webhook details', sg.ref('WebhookEndpoint')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('WebhookIdParam'), _webhookTenant] },
  ));

  add('/v1/webhooks/{id}', 'patch', _op(
    'updateWebhook', 'Update webhook endpoint', ['Webhooks'], OPS_AUTH,
    { '200': _success('Updated webhook', sg.ref('WebhookEndpoint')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('WebhookIdParam'), _webhookTenant], requestBody: _body(sg.ref('WebhookUpdateRequest'), 'Fields to update') },
  ));

  add('/v1/webhooks/{id}', 'delete', _op(
    'deleteWebhook', 'Delete webhook endpoint', ['Webhooks'], OPS_AUTH,
    { '204': { description: 'Webhook disabled' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('WebhookIdParam'), _webhookTenant] },
  ));

  add('/v1/webhooks/{id}/test', 'post', _op(
    'testWebhook', 'Send test event', ['Webhooks'], OPS_AUTH,
    { '200': _success('Test delivery result'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('WebhookIdParam'), _webhookTenant] },
  ));

  add('/v1/webhooks/{id}/deliveries', 'get', _op(
    'webhookDeliveries', 'Webhook delivery log', ['Webhooks'], OPS_AUTH,
    { '200': _success('Delivery log'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('WebhookIdParam'), _webhookTenant, ..._pageParamsWithLegacy, _pQuery('failedOnly', sg.makeBoolean())] },
  ));

  add('/v1/webhooks/metrics', 'get', _op(
    'webhookMetrics', 'Webhook delivery metrics', ['Webhooks'], OPS_AUTH,
    { '200': _success('Delivery metrics'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  // ── Organizations ─────────────────────────────────────────────────────────

  add('/v1/admin/organizations', 'post', _op(
    'createOrganization', 'Create organization', ['Organizations'], OPS_AUTH,
    { '201': _success('Created organization', sg.ref('Organization')), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.ref('OrgCreateRequest'), 'Organization to create') },
  ));

  add('/v1/admin/organizations', 'get', _op(
    'listOrganizations', 'List organizations', ['Organizations'], OPS_AUTH,
    {
      '200': _success('Organization list', sg.makeObject({
        organizations: sg.makeArray(sg.ref('Organization')), total: sg.makeInteger({ minimum: 0 }),
      })),
      ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    {
      // API-4 fix: this previously documented full canonical pagination
      // (including sortOrder) via `_pageParams`, but the real handler had no
      // pagination support at all. Opt-in pagination (no sort customization):
      // omitting page/pageSize/limit/offset returns the full unbounded list
      // (backward compatible).
      parameters: _pageParamsNoSort,
    },
  ));

  add('/v1/admin/organizations/{orgId}', 'get', _op(
    'getOrganization', 'Get organization', ['Organizations'], OPS_AUTH,
    { '200': _success('Organization details', sg.ref('Organization')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('OrgIdParam')] },
  ));

  add('/v1/admin/organizations/{orgId}', 'patch', _op(
    'updateOrganization', 'Update organization', ['Organizations'], OPS_AUTH,
    { '200': _success('Updated organization', sg.ref('Organization')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('OrgIdParam')], requestBody: _body(sg.makeObject({ name: sg.makeString() })) },
  ));

  add('/v1/admin/organizations/{orgId}/tenants/{tenantId}', 'post', _op(
    'assignTenant', 'Assign tenant to organization', ['Organizations'], OPS_AUTH,
    { '200': _success('Assignment result'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('OrgIdParam'), sg.paramRef('TenantIdParam')] },
  ));

  add('/v1/admin/organizations/{orgId}/tenants/{tenantId}', 'delete', _op(
    'removeTenant', 'Remove tenant from organization', ['Organizations'], OPS_AUTH,
    { '204': { description: 'Tenant removed from organization' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('OrgIdParam'), sg.paramRef('TenantIdParam')] },
  ));

  // ── Tenants ───────────────────────────────────────────────────────────────

  add('/v1/admin/tenants', 'post', _op(
    'createTenant', 'Register tenant', ['Tenants'], OPS_AUTH,
    { '201': _success('Created tenant', sg.ref('Tenant')), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.ref('TenantCreateRequest'), 'Tenant to register') },
  ));

  add('/v1/admin/tenants', 'get', _op(
    'listTenants', 'List tenants', ['Tenants'], OPS_AUTH,
    {
      '200': _success('Tenant list', sg.makeObject({
        tenants: sg.makeArray(sg.ref('Tenant')), total: sg.makeInteger({ minimum: 0 }),
      })),
      ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    {
      // API-4 fix: this previously documented full canonical pagination
      // (including sortOrder) via `_pageParams`, but the real handler had no
      // pagination support at all. Opt-in pagination (no sort customization):
      // omitting page/pageSize/limit/offset returns the full unbounded list
      // (backward compatible).
      parameters: _pageParamsNoSort,
    },
  ));

  add('/v1/admin/tenants/{tenantId}', 'get', _op(
    'getTenant', 'Get tenant', ['Tenants'], OPS_AUTH,
    { '200': _success('Tenant details', sg.ref('Tenant')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('TenantIdParam')] },
  ));

  add('/v1/admin/tenants/{tenantId}', 'patch', _op(
    'updateTenant', 'Update tenant', ['Tenants'], OPS_AUTH,
    { '200': _success('Updated tenant', sg.ref('Tenant')), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('TenantIdParam')], requestBody: _body(sg.makeObject({ name: sg.makeString(), status: sg.makeString({ enum: ['active', 'suspended', 'deprovisioned'] }), minProtocolVersion: sg.makeInteger({ enum: [1, 2], description: 'The lowest protocol version this tenant accepts; 2 refuses V1 artifacts (PROTOCOL_VERSION_TOO_LOW)' }) })) },
  ));

  add('/v1/admin/tenants/{tenantId}/policy-config', 'get', _op(
    'getTenantPolicyConfig', 'Get the tenant\'s effective per-tenant policy set and semantic configuration — read-only; writes go through the governed change-request flow', ['Tenants'], OPS_AUTH,
    { '200': _success('Effective tenant configuration with fallback markers', sg.makeObject({ tenantId: sg.makeString(), registered: sg.makeBoolean(), policySet: sg.makeObject({}), semanticConfig: sg.makeObject({}) })), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('TenantIdParam')] },
  ));

  // ── Agent identities and sessions ───────────────────────────────────

  const _tenantQ = _p('tenantId', 'query', sg.TENANT_ID_SCHEMA, 'The tenant that owns the agent / session (operator credentials are not tenant-scoped; every statement runs under this tenant\'s row-level security)', true);
  const _agentErrs = { '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, '404': sg.responseRef('NotFound'), '409': sg.responseRef('BadRequest'), '500': sg.responseRef('InternalError') };
  const _agentBody = sg.makeObject({
    tenantId: sg.TENANT_ID_SCHEMA, displayName: sg.makeString(), ownerUserId: sg.makeString(), publicKey: sg.makeString(),
    allowedActionClasses: sg.makeArray(sg.makeString()), maxActionsPerSession: sg.makeInteger(), maxSessionSeconds: sg.makeInteger(), costBudgetMicros: sg.makeInteger(),
  }, { required: ['tenantId', 'displayName'] });

  add('/v1/agents', 'post', _op('createAgent', 'Create an agent identity', ['Agents'], OPS_AUTH, { '201': _success('The agent', sg.ref('Agent')), ..._agentErrs },
    { requestBody: _body(_agentBody, 'The agent and the limits of its autonomy'), description: 'Requires MANAGE_AGENTS and an operator MFA step-up. The agent starts active; its agentId is a UUID v4 issued by the gateway.' }));
  add('/v1/agents', 'get', _op('listAgents', 'List a tenant\'s agents', ['Agents'], OPS_AUTH, { '200': _success('The agents', sg.makeObject({ agents: sg.makeArray(sg.ref('Agent')) }, { required: ['agents'] })), ..._agentErrs },
    { parameters: [_tenantQ, _pQuery('status', sg.makeString({ enum: ['active', 'suspended', 'revoked'] }), 'Filter by status')], description: 'Requires READ_AGENTS.' }));
  add('/v1/agents/{agentId}', 'get', _op('getAgent', 'One agent', ['Agents'], OPS_AUTH, { '200': _success('The agent', sg.ref('Agent')), ..._agentErrs },
    { parameters: [_pPath('agentId', sg.UUID_SCHEMA, 'The agent id (UUID v4)'), _tenantQ], description: 'Requires READ_AGENTS. Another tenant\'s agent is a 404.' }));
  add('/v1/agents/{agentId}', 'patch', _op('updateAgent', 'Change an agent\'s limits, or suspend / revoke it', ['Agents'], OPS_AUTH, { '200': _success('The agent', sg.ref('Agent')), ..._agentErrs },
    { parameters: [_pPath('agentId', sg.UUID_SCHEMA, 'The agent id (UUID v4)')], requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, status: sg.makeString({ enum: ['active', 'suspended', 'revoked'] }) }, { required: ['tenantId'], additionalProperties: true }), 'The tenant and the fields to change'),
      description: 'Requires MANAGE_AGENTS and an operator MFA step-up. Revoked is absorbing; suspending or revoking ends the agent\'s active sessions at once.' }));

  add('/v1/sessions', 'post', _op('startAgentSession', 'Start an agent session', ['Agents'], OPS_AUTH, { '201': _success('The session', sg.ref('AgentSession')), ..._agentErrs },
    { requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, agentId: sg.UUID_SCHEMA, ttlSeconds: sg.makeInteger(), maxActions: sg.makeInteger(), costBudgetMicros: sg.makeInteger() }, { required: ['tenantId', 'agentId'] }), 'The agent and the requested limits'),
      description: 'Requires MANAGE_AGENT_SESSIONS and an operator MFA step-up. The effective limits are the lower of the requested ones, the agent\'s and the platform caps (24 h, 100 000 actions).' }));
  add('/v1/sessions', 'get', _op('listAgentSessions', 'List a tenant\'s agent sessions', ['Agents'], OPS_AUTH, { '200': _success('The sessions', sg.makeObject({ sessions: sg.makeArray(sg.ref('AgentSession')) }, { required: ['sessions'] })), ..._agentErrs },
    { parameters: [_tenantQ, _pQuery('agentId', sg.makeString(), 'Filter by agent'), _pQuery('status', sg.makeString({ enum: ['active', 'ended', 'expired', 'killed'] }), 'Filter by status')], description: 'Requires READ_AGENTS.' }));
  add('/v1/sessions/{sessionId}', 'get', _op('getAgentSession', 'One agent session', ['Agents'], OPS_AUTH, { '200': _success('The session (expiry applied)', sg.ref('AgentSession')), ..._agentErrs },
    { parameters: [_pPath('sessionId', sg.UUID_SCHEMA, 'The session id'), _tenantQ], description: 'Requires READ_AGENTS.' }));
  add('/v1/sessions/{sessionId}/end', 'post', _op('endAgentSession', 'End an agent session', ['Agents'], OPS_AUTH, { '200': _success('The session', sg.ref('AgentSession')), ..._agentErrs },
    { parameters: [_pPath('sessionId', sg.UUID_SCHEMA, 'The session id')], requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, reason: sg.makeString() }, { required: ['tenantId'] }), 'The tenant and an optional reason'), description: 'Requires MANAGE_AGENT_SESSIONS and an operator MFA step-up.' }));
  add('/v1/sessions/{sessionId}/kill', 'post', _op('killAgentSession', 'Force-stop an agent session', ['Agents'], OPS_AUTH, { '200': _success('The session (status killed)', sg.ref('AgentSession')), ..._agentErrs },
    { parameters: [_pPath('sessionId', sg.UUID_SCHEMA, 'The session id')], requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, reason: sg.makeString() }, { required: ['tenantId'] }), 'The tenant and an optional reason'),
      description: 'Requires MANAGE_AGENT_SESSIONS and an operator MFA step-up. Aborts the executions of the session running in this process at once; elsewhere the next action is refused. Emitted at CRITICAL.' }));

  // ── Tool registry and per-action authorisation ───────────────────────────────────

  const _toolErrs = { '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, '404': sg.responseRef('NotFound'), '409': sg.responseRef('BadRequest'), '500': sg.responseRef('InternalError') };
  const _toolRef = sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, server: sg.makeString(), name: sg.makeString() }, { required: ['tenantId', 'server', 'name'], additionalProperties: true });
  add('/v1/tool-registry', 'post', _op('registerTool', 'Register a tool version', ['Agents'], OPS_AUTH, { '201': _success('The change and the version', sg.makeObject({ change: sg.makeString({ enum: ['NEW', 'MODIFIED'] }), tool: sg.ref('ToolVersion') }, { required: ['change', 'tool'] })), ..._toolErrs },
    { requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, server: sg.makeString(), name: sg.makeString(), schema: sg.makeObject({}, { additionalProperties: true }), actionClass: sg.makeString(), reversible: sg.makeBoolean(), requiresApproval: sg.makeBoolean(), policy: sg.makeObject({}, { additionalProperties: true }), description: sg.makeString() }, { required: ['tenantId', 'server', 'name', 'schema', 'actionClass', 'reversible'] }), 'The tool definition'),
      description: 'Requires MANAGE_TOOLS and an operator MFA step-up. The first version of a tool is active; a definition that differs in schema, class or reversibility becomes a new version in pending_review and is not callable until approved (the registrant cannot approve it).' }));
  add('/v1/tool-registry', 'get', _op('listTools', 'List the tool versions of a tenant', ['Agents'], OPS_AUTH, { '200': _success('The versions', sg.makeObject({ tools: sg.makeArray(sg.ref('ToolVersion')) }, { required: ['tools'] })), ..._toolErrs },
    { parameters: [_tenantQ, _pQuery('status', sg.makeString({ enum: ['active', 'pending_review', 'superseded', 'disabled'] }), 'Filter by status')], description: 'Requires READ_TOOLS.' }));
  add('/v1/tool-registry/entry', 'get', _op('getTool', 'One tool with its versions', ['Agents'], OPS_AUTH, { '200': _success('The tool', sg.makeObject({ server: sg.makeString(), name: sg.makeString(), active: sg.makeNullable(sg.ref('ToolVersion')), versions: sg.makeArray(sg.ref('ToolVersion')) }, { required: ['server', 'name', 'versions'] })), ..._toolErrs },
    { parameters: [_tenantQ, _pQuery('server', sg.makeString(), 'The tool server id'), _pQuery('name', sg.makeString(), 'The tool name')], description: 'Requires READ_TOOLS.' }));
  add('/v1/tool-registry/approve', 'post', _op('approveToolVersion', 'Approve a pending tool version', ['Agents'], OPS_AUTH, { '200': _success('The active version', sg.ref('ToolVersion')), ..._toolErrs },
    { requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, server: sg.makeString(), name: sg.makeString(), version: sg.makeInteger() }, { required: ['tenantId', 'server', 'name', 'version'] }), 'The version to activate'),
      description: 'Requires MANAGE_TOOLS and an operator MFA step-up. The previous active version is superseded. The operator who registered a changed definition cannot approve it (TOOL_SELF_APPROVAL).' }));
  add('/v1/tool-registry/disable', 'post', _op('disableTool', 'Disable the active version of a tool', ['Agents'], OPS_AUTH, { '200': _success('The disabled version', sg.ref('ToolVersion')), ..._toolErrs },
    { requestBody: _body(_toolRef, 'The tool'), description: 'Requires MANAGE_TOOLS and an operator MFA step-up. Calls are refused with TOOL_DISABLED from the next authorisation.' }));
  add('/v1/tool-registry/policy', 'post', _op('updateToolPolicy', 'Change the policy of the active version of a tool', ['Agents'], OPS_AUTH, { '200': _success('The version', sg.ref('ToolVersion')), ..._toolErrs },
    { requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, server: sg.makeString(), name: sg.makeString(), policy: sg.makeObject({}, { additionalProperties: true }), requiresApproval: sg.makeBoolean() }, { required: ['tenantId', 'server', 'name'] }), 'The policy fields to change'),
      description: 'Requires MANAGE_TOOLS and an operator MFA step-up.' }));
  add('/v1/actions/authorize', 'post', _op('authorizeAction', 'Authorize one action of an agent session', ['Agents'], [{ SigningApiKey: [] }],
    { '200': { description: 'The action artifact', content: { 'application/json': { schema: sg.ref('ActionAuthorizeResponse') } } },
      '202': { description: 'The tool requires approval: an approval request was opened (or is still open); poll it, then call again with approvalId', content: { 'application/json': { schema: sg.ref('ApprovalPending') } } },
      '400': _decisionBlock('Invalid request, arguments refused by the registered schema (INVALID_REQUEST, ACTION_INVALID_TOOL, ACTION_INVALID_ARGS, ACTION_ARGS_INVALID)'),
      '401': _decisionBlock('Signing credential or agent proof missing or invalid (UNAUTHORIZED, AGENT_PROOF_REQUIRED, AGENT_PROOF_INVALID)'),
      '403': _decisionBlock('Refused (AGENT_SESSION_*, TOOL_NOT_REGISTERED, TOOL_PENDING_REVIEW, TOOL_DISABLED, ACTION_CLASS_NOT_ALLOWED, ACTION_PLAN_REQUIRED, ACTION_PLAN_UNKNOWN, ACTION_PLAN_EXPIRED, ACTION_NOT_IN_PLAN, APPROVAL_INVALID, APPROVAL_DENIED, APPROVAL_EXPIRED, APPROVAL_CANCELLED)'),
      '409': _decisionBlock('The tool schema changed, the session chain moved, the session awaits an approval, or the approval was already used (TOOL_SCHEMA_CHANGED, ACTION_CHAIN_MISMATCH, SESSION_AWAITING_APPROVAL, APPROVAL_ALREADY_USED)'),
      // ACTION_PLAN_REQUIRED, ACTION_PLAN_UNKNOWN, ACTION_PLAN_EXPIRED, ACTION_NOT_IN_PLAN are 403s listed above

      '429': _decisionBlock('The session action or cost budget, or the plan step, is exhausted (ACTION_BUDGET_EXHAUSTED, COST_BUDGET_EXHAUSTED, ACTION_PLAN_STEP_EXHAUSTED)'),
      // as /sign: a drain-gated 503 is the canonical ServiceShuttingDown body; when the agent / registry / plan store is unavailable the route answers a DecisionBlock with reason ACTION_AUTHORIZATION_UNAVAILABLE
      '503': sg.responseRef('ServiceShuttingDown') },
    { requestBody: _body(sg.ref('ActionAuthorizeRequest'), 'The agent session, the tool and the arguments of the one action'),
      description: 'Authenticated like /sign (a tenant signing identity). The gateway assigns seq and prevActionHash and binds actionHash = SHA-256("QODIQA::ACTION::V2" || JCS-P1({v, tenantId, agentId, sessionId, seq, tool{server,name,schemaHash}, args, parentRequestHash, prevActionHash})). The artifact lives at most 60 s and authorises exactly that action.' }));

  add('/v1/actions/plans', 'post', _op('authorizeActionPlan', 'Authorize the execution plan of an agent session', ['Agents'], [{ SigningApiKey: [] }],
    { '201': { description: 'The plan', content: { 'application/json': { schema: sg.makeObject({ planId: sg.UUID_SCHEMA, plan: sg.ref('ActionPlan'), requestId: sg.makeNullable(sg.makeString()) }, { required: ['planId', 'plan'] }) } } },
      '400': _decisionBlock('Invalid request or plan (INVALID_REQUEST, INVALID_PLAN)'),
      '401': _decisionBlock('Signing credential or agent proof missing or invalid (UNAUTHORIZED, AGENT_PROOF_REQUIRED, AGENT_PROOF_INVALID)'),
      '403': _decisionBlock('Refused (AGENT_SESSION_*, TOOL_NOT_REGISTERED, TOOL_PENDING_REVIEW, TOOL_DISABLED, ACTION_CLASS_NOT_ALLOWED, ACTION_APPROVAL_REQUIRED)'),
      '503': sg.responseRef('ServiceShuttingDown') },
    { requestBody: _body(sg.ref('ActionPlanRequest'), 'The session and the steps (tool and maximum calls) the agent intends to use'),
      description: 'Authenticated like /sign. The plan is authorised once; while the session has an active plan, /v1/actions/authorize refuses any action that is not a step of it (ACTION_NOT_IN_PLAN) or whose step is used up (ACTION_PLAN_STEP_EXHAUSTED). A new plan replaces the previous one.' }));

  // ── Delegation ───────────────────────────────────────────────────────────────────────────────────
  const _delegErrs = {
    '400': _decisionBlock('Invalid request (INVALID_REQUEST, INVALID_CLASSES, INVALID_TOOLS, INVALID_TTL, INVALID_MAX_DEPTH, INVALID_MAX_ACTIONS)'),
    '401': _decisionBlock('Signing credential or agent proof missing or invalid (UNAUTHORIZED, AGENT_PROOF_REQUIRED, AGENT_PROOF_INVALID)'),
    '403': _decisionBlock('Refused (DELEGATION_INVALID, DELEGATION_ATTENUATION_VIOLATION, DELEGATION_DEPTH_EXCEEDED, DELEGATION_CYCLE, DELEGATION_REVOKED, ACTION_CLASS_NOT_ALLOWED, AGENT_SESSION_*)'),
    '404': _decisionBlock('No such delegation in this tenant (NOT_FOUND)'),
    '409': _decisionBlock('The issuer session chain moved or is out of order (ACTION_CHAIN_MISMATCH, ACTION_ORDER_VIOLATION)'),
    '429': _decisionBlock('The issuer session budget is exhausted (ACTION_BUDGET_EXHAUSTED)'),
    // as /sign: a drain-gated 503 is the canonical ServiceShuttingDown body; an unavailable store answers a DecisionBlock with reason DELEGATION_UNAVAILABLE
    '503': sg.responseRef('ServiceShuttingDown'),
  };
  add('/v1/delegations', 'post', _op('issueDelegation', 'Issue a delegation', ['Agents'], [{ SigningApiKey: [] }],
    { '201': { description: 'The delegation and its signed token', content: { 'application/json': { schema: sg.makeObject({ delegationId: sg.UUID_SCHEMA, delegation: sg.ref('Delegation'), token: sg.ref('DelegationToken'), chainHash: sg.makeString(), action: sg.makeObject({}, { additionalProperties: true }), requestId: sg.makeNullable(sg.makeString()) }, { required: ['delegationId', 'delegation', 'token', 'chainHash'] }) } } }, ..._delegErrs },
    { requestBody: _body(sg.ref('DelegationIssueRequest'), 'The issuer agent and session, the delegate and the rights given'),
      description: 'Authenticated like /sign. Without parentId this is a root grant (rights are a subset of the issuer\'s OWN classes); with parentId the issuer must be the delegate of that delegation and the child may only narrow it (classes, tools, maxActions, lifetime; depth is parent+1, never above the root\'s maxDepth; no agent twice in a chain). The issuance is itself an authorised action of the issuer session: class `delegate`, one place in the session chain and ledger.' }));
  add('/v1/delegations/verify', 'post', _op('verifyDelegation', 'Verify a delegation chain', ['Agents'], [{ SigningApiKey: [] }],
    { '200': { description: 'The verdict (valid: false carries the reason; HTTP stays 200)', content: { 'application/json': { schema: sg.makeObject({ valid: sg.makeBoolean(), reason: sg.makeString(), detail: sg.makeString(), state: sg.makeString({ enum: ['ACTIVE', 'UNKNOWN'] }), depth: sg.makeInteger(), chainHash: sg.makeString(), rootAgentId: sg.makeString(), subjectAgentId: sg.makeString(), classes: sg.makeArray(sg.makeString()), requestId: sg.makeNullable(sg.makeString()) }, { required: ['valid'], additionalProperties: true }) } } }, ..._delegErrs },
    { requestBody: _body(sg.makeObject({ chain: sg.makeArray(sg.ref('DelegationToken')), delegationId: sg.UUID_SCHEMA }, { description: 'Exactly one of chain (envelopes, root first: checked offline, plus the live state of its leaf) or delegationId (a stored delegation)' }), 'The chain or the delegation to check'),
      description: 'Checks signatures, links, attenuation, depth and cycles, then revocation and the state of every agent of the chain.' }));
  add('/v1/delegations/{delegationId}', 'get', _op('getDelegation', 'One delegation with its chain', ['Agents'], [{ SigningApiKey: [] }],
    { '200': { description: 'The delegation, its chain of tokens (root first) and whether it is currently valid', content: { 'application/json': { schema: sg.makeObject({ delegation: sg.ref('Delegation'), chain: sg.makeArray(sg.ref('DelegationToken')), valid: sg.makeBoolean(), reason: sg.makeString(), requestId: sg.makeNullable(sg.makeString()) }, { required: ['delegation', 'valid'] }) } } }, ..._delegErrs },
    { parameters: [_pPath('delegationId', sg.UUID_SCHEMA, 'The delegation id')], description: 'Another tenant\'s delegation is a 404.' }));
  add('/v1/delegations/{delegationId}/revoke', 'post', _op('revokeDelegation', 'Revoke a delegation and everything below it', ['Agents'], [{ SigningApiKey: [] }],
    { '200': { description: 'What was revoked', content: { 'application/json': { schema: sg.makeObject({ revoked: sg.makeArray(sg.UUID_SCHEMA), abortedExecutions: sg.makeInteger(), agentsRevoked: sg.makeArray(sg.makeString()), requestId: sg.makeNullable(sg.makeString()) }, { required: ['revoked', 'abortedExecutions', 'agentsRevoked'] }) } } }, ..._delegErrs },
    { parameters: [_pPath('delegationId', sg.UUID_SCHEMA, 'The delegation id')], requestBody: _body(sg.makeObject({ reason: sg.makeString(), revokeAgents: sg.makeBoolean() }, { required: ['reason'] }), 'Why, and whether the delegates of the revoked subtree are revoked too'),
      description: 'Cascades to every descendant at once; the executions running under any of them are aborted (this process at once, other replicas at their next action: every authorisation and every execution re-checks the chain). Suspending or revoking an agent revokes the delegations it issued or holds.' }));

  // ── MCP servers and the tool gateway ────────────────────────────────────────────────────────────
  const _mcpErrs = { '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, '404': sg.responseRef('NotFound'), '409': sg.responseRef('BadRequest'), '500': sg.responseRef('InternalError'), '502': sg.responseRef('InternalError') };
  const _srvRef = _pPath('serverId', sg.makeString(), 'The server id (the `server` of the tool registry)');
  add('/v1/mcp/servers', 'post', _op('registerMcpServer', 'Register an MCP server', ['Agents'], OPS_AUTH, { '201': _success('The server', sg.ref('McpServer')), ..._mcpErrs },
    { requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, serverId: sg.makeString(), url: sg.makeString(), identity: sg.makeObject({}, { additionalProperties: true }), description: sg.makeString() }, { required: ['tenantId', 'serverId', 'url'] }), 'The server and its pinned identity'),
      description: 'Requires MANAGE_MCP_SERVERS and an operator MFA step-up. The URL passes the SSRF policy of the model providers (https, no credentials, not an IP literal, not private / loopback / link-local / metadata); an https server must be registered with identity { kind: "tls-spki-pin", sha256 } - the SHA-256 of the certificate\'s public key (DER SubjectPublicKeyInfo) - and a connection whose key differs is dropped. http and local destinations exist only where QODIQA_MCP_ALLOW_LOCAL=true, never in production. There is no stdio transport.' }));
  add('/v1/mcp/servers', 'get', _op('listMcpServers', 'List a tenant\'s MCP servers', ['Agents'], OPS_AUTH, { '200': _success('The servers', sg.makeObject({ servers: sg.makeArray(sg.ref('McpServer')) }, { required: ['servers'] })), ..._mcpErrs },
    { parameters: [_tenantQ, _pQuery('status', sg.makeString({ enum: ['active', 'disabled'] }), 'Filter by status')], description: 'Requires READ_MCP_SERVERS.' }));
  add('/v1/mcp/servers/{serverId}', 'get', _op('getMcpServer', 'One MCP server', ['Agents'], OPS_AUTH, { '200': _success('The server', sg.ref('McpServer')), ..._mcpErrs },
    { parameters: [_srvRef, _tenantQ], description: 'Requires READ_MCP_SERVERS.' }));
  add('/v1/mcp/servers/{serverId}/disable', 'post', _op('disableMcpServer', 'Disable an MCP server', ['Agents'], OPS_AUTH, { '200': _success('The server', sg.ref('McpServer')), ..._mcpErrs },
    { parameters: [_srvRef], requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, reason: sg.makeString() }, { required: ['tenantId', 'reason'] }), 'Why'),
      description: 'Requires MANAGE_MCP_SERVERS and an operator MFA step-up. The next call through the server is refused on every replica and calls running through it are aborted (other replicas within about a second).' }));
  add('/v1/mcp/servers/{serverId}/enable', 'post', _op('enableMcpServer', 'Enable an MCP server', ['Agents'], OPS_AUTH, { '200': _success('The server', sg.ref('McpServer')), ..._mcpErrs },
    { parameters: [_srvRef], requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA }, { required: ['tenantId'] }), 'The tenant'), description: 'Requires MANAGE_MCP_SERVERS and an operator MFA step-up.' }));
  add('/v1/mcp/servers/{serverId}/identity', 'post', _op('rotateMcpServerIdentity', 'Rotate the pinned identity of an MCP server', ['Agents'], OPS_AUTH, { '200': _success('The server', sg.ref('McpServer')), ..._mcpErrs },
    { parameters: [_srvRef], requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, identity: sg.makeObject({}, { additionalProperties: true }) }, { required: ['tenantId', 'identity'] }), 'The new pin'),
      description: 'Requires MANAGE_MCP_SERVERS and an operator MFA step-up. The URL never changes: a different URL is a different server.' }));
  add('/v1/mcp/servers/{serverId}/tools/refresh', 'post', _op('refreshMcpServerTools', 'Discover the tools of an MCP server', ['Agents'], OPS_AUTH,
    { '200': _success('What was discovered', sg.makeObject({ serverId: sg.makeString(), discovered: sg.makeInteger(), NEW: sg.makeArray(sg.makeObject({}, { additionalProperties: true })), MODIFIED: sg.makeArray(sg.makeObject({}, { additionalProperties: true })), UNCHANGED: sg.makeArray(sg.makeObject({}, { additionalProperties: true })), SKIPPED: sg.makeArray(sg.makeObject({}, { additionalProperties: true })) }, { required: ['serverId', 'discovered'] })), ..._mcpErrs },
    { parameters: [_srvRef], requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA }, { required: ['tenantId'] }), 'The tenant'),
      description: 'Requires MANAGE_MCP_SERVERS and an operator MFA step-up. Asks the server for tools/list and registers what it offers in the tool registry as PROPOSALS: new or changed tools are pending_review and are not callable until an operator approves them (the class and reversibility are a conservative guess from the server\'s own hints). A schema outside the supported subset, or an invalid name, is skipped with its reason.' }));
  add('/v1/tools/call', 'post', _op('callTool', 'Call a tool through the gateway', ['Agents'], [{ SigningApiKey: [] }],
    { '200': { description: 'EXECUTE with the screened result, or a BLOCK when the result itself was withheld', content: { 'application/json': { schema: sg.ref('ToolCallResponse') } } },
      '400': _decisionBlock('Invalid request or artifact (INVALID_REQUEST, ACTION_INVALID_TOOL, ACTION_ARGS_INVALID, WRONG_ARTIFACT_KIND, ACTION_ARTIFACT_INVALID)'),
      '401': _decisionBlock('Credential or artifact signature invalid (UNAUTHORIZED, ACTION_SIGNATURE_INVALID)'),
      '403': _decisionBlock('Refused (ACTION_TENANT_MISMATCH, AGENT_*, TOOL_*, MCP_SERVER_UNKNOWN / _DISABLED, MCP_URL_*, ACTION_POLICY_REQUIRED / _DENIED, DELEGATION_*, ACTION_APPROVAL_REQUIRED)'),
      '409': _decisionBlock('The authorisation does not match this call or was already used, or the call was revoked while running (ACTION_MISMATCH, ACTION_REPLAY, ACTION_ORDER_VIOLATION, TOOL_SCHEMA_CHANGED, TOOL_REVOKED, MCP_SERVER_DISABLED, DELEGATION_REVOKED, AGENT_SESSION_KILLED)'),
      '429': _decisionBlock('The per-tool limit of the session is used up (ACTION_TOOL_LIMIT)'),
      '502': _decisionBlock('The MCP server failed or answered badly (TOOL_CALL_FAILED with details.code)'),
      '504': _decisionBlock('The MCP server did not answer in time (TOOL_CALL_FAILED, MCP_TIMEOUT)'),
      // as /sign: a drain-gated 503 is the canonical ServiceShuttingDown body; an unavailable store answers a DecisionBlock with reason TOOL_GATEWAY_UNAVAILABLE
      '503': sg.responseRef('ServiceShuttingDown') },
    { requestBody: _body(sg.ref('ToolCallRequest'), 'The action artifact and the call it authorises'),
      description: 'Authenticated like /sign. Runs ONE authorised action against a REGISTERED MCP server over HTTP (no stdio, no local execution): the artifact is verified, the actionHash is recomputed from this very call, the tool policy and the delegation chain are re-checked, the artifact is consumed once, the call goes out through the SSRF-guarded, pinned connection (no redirects, bounded time and size, abortable), the result is screened as untrusted content (encodings revealed, instruction conflict, semantic policy) and returned with its provenance and a receipt.' }));

  // ── Human approval ────────────────────────────────────────────────────────────────────────────────────
  const _apprErrs = { '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, '404': sg.responseRef('NotFound'), '409': sg.responseRef('BadRequest'), '500': sg.responseRef('InternalError') };
  const _apprId = _pPath('approvalId', sg.UUID_SCHEMA, 'The approval id');
  add('/v1/approvals', 'get', _op('listApprovals', 'List a tenant\'s approval requests', ['Agents'], OPS_AUTH, { '200': _success('The requests (expiry applied)', sg.makeObject({ approvals: sg.makeArray(sg.ref('ApprovalRequest')) }, { required: ['approvals'] })), ..._apprErrs },
    { parameters: [_tenantQ, _pQuery('status', sg.makeString({ enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED'] }), 'Filter by status'), _pQuery('agentId', sg.makeString(), 'Filter by agent')], description: 'Requires READ_APPROVALS.' }));
  add('/v1/approvals/{approvalId}', 'get', _op('getApproval', 'One approval request with the action it is about', ['Agents'], OPS_AUTH, { '200': _success('The request', sg.ref('ApprovalRequest')), ..._apprErrs },
    { parameters: [_apprId, _tenantQ], description: 'Requires READ_APPROVALS. Shows the tool and the exact arguments the approver is asked to approve.' }));
  add('/v1/approvals/{approvalId}/decision', 'post', _op('decideApproval', 'Approve or deny an action', ['Agents'], OPS_AUTH, { '200': _success('The decided request (with the signed statement)', sg.ref('ApprovalRequest')), ..._apprErrs },
    { parameters: [_apprId], requestBody: _body(sg.makeObject({ tenantId: sg.TENANT_ID_SCHEMA, decision: sg.makeString({ enum: ['APPROVE', 'DENY'] }), reason: sg.makeString(), ttlSeconds: sg.makeInteger({ description: 'How long the approval can be spent, 1-3600 (default 600)' }), notBefore: sg.makeString({ description: 'ISO 8601, not before now, within the request window' }) }, { required: ['tenantId', 'decision'] }), 'The decision'),
      description: 'Requires DECIDE_APPROVALS and an operator MFA step-up. The approver is never the requester: not the signing identity that asked, not the user the agent acts for, not an operator that user provisioned (APPROVAL_NOT_INDEPENDENT). The gateway signs the statement (QODIQA::APPROVAL::V1) naming the approver, the actionHash, the window and the MFA step-up. A DENY needs a reason.' }));
  add('/v1/actions/approvals/{approvalId}', 'get', _op('getActionApproval', 'The requester\'s view of its approval request', ['Agents'], [{ SigningApiKey: [] }],
    { '200': { description: 'The status of the request (without the arguments)', content: { 'application/json': { schema: sg.makeObject({ status: sg.makeString(), timestamp: sg.ISO8601_SCHEMA, requestId: sg.makeNullable(sg.makeString()), data: sg.ref('ApprovalRequesterView') }, { required: ['status', 'data'] }) } } },
      '404': _decisionBlock('No such request for this identity (NOT_FOUND)'), '503': sg.responseRef('ServiceShuttingDown') },
    { parameters: [_apprId], description: 'Authenticated like /sign. Only the identity that asked sees its request; poll it, or call /v1/actions/authorize again with the approvalId.' }));
  add('/v1/actions/approvals/{approvalId}/cancel', 'post', _op('cancelActionApproval', 'Withdraw an approval request', ['Agents'], [{ SigningApiKey: [] }],
    { '200': { description: 'The cancelled request', content: { 'application/json': { schema: sg.makeObject({ status: sg.makeString(), timestamp: sg.ISO8601_SCHEMA, requestId: sg.makeNullable(sg.makeString()), data: sg.ref('ApprovalRequesterView') }, { required: ['status', 'data'] }) } } },
      '400': _decisionBlock('Invalid request (INVALID_REQUEST)'), '404': _decisionBlock('No such request for this identity (NOT_FOUND)'), '409': _decisionBlock('It can no longer be cancelled (APPROVAL_NOT_CANCELLABLE)'), '503': sg.responseRef('ServiceShuttingDown') },
    { parameters: [_apprId], requestBody: _body(sg.makeObject({ reason: sg.makeString() }), 'Why (optional)'),
      description: 'Authenticated like /sign. Possible while PENDING and while APPROVED (a cancelled approval refuses the artifact, or the execution if the artifact exists already). A request that ends without the action gives its position in the session back.' }));

  // ── Downloadable proof of one request ─────────────────────────────

  add('/v1/proofs/{requestId}', 'get', _op(
    'getRequestProof', 'Downloadable proof of one request', ['Proofs'], OPS_AUTH,
    { '200': _success('The proof qodiqa-proof/1 of the request', sg.ref('RequestProof')),
      '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, '503': sg.responseRef('ServiceShuttingDown'), '500': sg.responseRef('InternalError') },
    { parameters: [sg.paramRef('ReceiptRequestIdParam'), _p('tenantId', 'query', sg.TENANT_ID_SCHEMA, 'The tenant that owns the request; a request of another tenant is indistinguishable from an unknown one (404)', true), _pQuery('fullChain', sg.makeBoolean(), "true: also serve the contiguous platform chain path, which contains OTHER tenants' raw entries; needs READ_AUDIT_PROOFS_FULL_CHAIN (admin). Without it the path and checkpoint are withheld.")],
      description: 'Requires READ_AUDIT_PROOFS (auditor, compliance, admin); no MFA step-up (read only); every read is logged. Assembles the audit entries of the request, the contiguous chain path to the earliest signed checkpoint that covers them, the transparency leaf with its inclusion proof and signed root, the receipt, the external anchors and the public keys. The gateway does not store the signed artifact: add it when verifying (qodiqa-proof-verify --artifact). Every part that cannot be assembled is left out and the verifier lowers its verdict accordingly.' },
  ));

  // ── Per-artifact revocation ────────────────────────────────────────

  add('/v1/admin/artifact-revocations', 'post', _op(
    'revokeArtifact', 'Revoke one signed artifact before it is used', ['Artifact revocation'], OPS_AUTH,
    { '200': _success('Result; created is false when the artifact was already revoked (the first record is kept)', sg.makeObject({
        created: sg.makeBoolean(), record: sg.ref('ArtifactRevocation'), ttlSeconds: sg.makeInteger({ minimum: 1, description: 'How long the revocation is kept: it must outlive the 60 s maximum artifact age plus clock skew' }),
      }, { required: ['created', 'record', 'ttlSeconds'] })),
      '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ requestId: sg.UUID_SCHEMA, reason: sg.makeString({ maxLength: 500 }) }, { required: ['requestId', 'reason'] }), 'The artifact to revoke (its payload.requestId) and why'),
      description: 'Requires MANAGE_ARTIFACT_REVOCATIONS and an operator MFA step-up (X-QODIQA-OTP). A revoked artifact is refused (BLOCK ARTIFACT_REVOKED) after its signature and request binding are verified and before its nonce is consumed. The operator action is emitted at CRITICAL to the audit/SIEM stream; the BLOCK produced when the artifact is later presented is an ordinary audit-chain entry.' },
  ));

  add('/v1/admin/artifact-revocations/{requestId}', 'get', _op(
    'getArtifactRevocation', 'Is this artifact revoked?', ['Artifact revocation'], OPS_AUTH,
    { '200': _success('Whether a revocation is currently recorded for the artifact', sg.makeObject({ revoked: sg.makeBoolean(), record: sg.makeNullable(sg.ref('ArtifactRevocation')) }, { required: ['revoked'] })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ReceiptRequestIdParam')], description: 'Requires MANAGE_ARTIFACT_REVOCATIONS. Revocations expire on their own (see ttlSeconds above); after that this reports revoked: false — by then the artifact itself is past its maximum age.' },
  ));

  // ── Global kill switch ─────────────────────────────────────────────

  add('/v1/admin/kill-switch', 'get', _op(
    'getKillSwitch', 'Get the global kill-switch state', ['Kill switch'], OPS_AUTH,
    { '200': _success('Current state', sg.ref('KillSwitchState')), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Requires READ_KILL_SWITCH. While the switch is active every /sign and /ai/chat request is answered BLOCK KILL_SWITCH_ACTIVE (HTTP 503) before anything else runs.' },
  ));

  add('/v1/admin/kill-switch/activate', 'post', _op(
    'activateKillSwitch', 'Raise the global kill switch (stop all signing and execution)', ['Kill switch'], OPS_AUTH,
    { '200': _success('Result; changed is false when it was already active', sg.ref('KillSwitchChange')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ reason: sg.makeString({ maxLength: 500, description: 'Why — required, at most 500 characters, no control characters' }) }, { required: ['reason'] }), 'Activation reason'),
      description: 'Requires MANAGE_KILL_SWITCH and an operator MFA step-up (X-QODIQA-OTP). Propagates to every replica within 5 s (signed control-plane record, Redis notification with a polling fallback; a replica that cannot confirm the state refuses too). Writes an audit-chain KILL_SWITCH entry (audit schema v8).' },
  ));

  add('/v1/admin/kill-switch/release', 'post', _op(
    'releaseKillSwitch', 'Lower the global kill switch (resume signing and execution)', ['Kill switch'], OPS_AUTH,
    { '200': _success('Result; changed is false when it was already off', sg.ref('KillSwitchChange')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ reason: sg.makeString({ maxLength: 500 }) }), 'Optional release note'),
      description: 'Requires MANAGE_KILL_SWITCH and an operator MFA step-up (X-QODIQA-OTP). Writes an audit-chain KILL_SWITCH entry (audit schema v8).' },
  ));

  // ── SAML 2.0 single sign-on - public: the browser arrives before it has a credential. 404 unless that provider is configured. ──

  const _samlId = _p('provider', 'query', sg.makeString({ pattern: '^[a-z][a-z0-9-]{0,30}$' }), 'SAML provider id from QODIQA_SAML_CONFIG_PATH', true);
  add('/auth/saml/login', 'get', _op(
    'samlLogin', 'Start a SAML single-sign-on login (redirects the browser to the identity provider)', ['Single sign-on'], NO_AUTH,
    { '200': { description: 'Not returned: a configured provider answers 302 (redirect to the identity provider with a signed relay state)' }, '404': sg.responseRef('NotFound'), '429': sg.responseRef('TooManyRequests') },
    { parameters: [_samlId], description: 'Only when the provider is configured (QODIQA_SAML_CONFIG_PATH): the answer is a 302 to the identity provider (an unconfigured provider is 404). 503 LOGIN_UNAVAILABLE when the identity or replay store cannot be reached. Rate limited per client address.' },
  ));
  add('/auth/saml/acs', 'post', _op(
    'samlAcs', 'SAML assertion consumer service: the response of the identity provider (form post) becomes an operator session token', ['Single sign-on'], NO_AUTH,
    { '200': _success('Operator session', sg.makeObject({ token: sg.makeString(), tokenType: sg.makeString({ enum: ['Bearer'] }), expiresAt: sg.makeInteger(), assured: sg.makeBoolean(), user: sg.makeObject({ id: sg.makeString(), username: sg.makeString(), role: sg.makeString() }) }, { required: ['token', 'tokenType', 'expiresAt'] })),
      '400': sg.responseRef('BadRequest'), '401': sg.responseRef('Unauthorized'), '404': sg.responseRef('NotFound'), '429': sg.responseRef('TooManyRequests') },
    { parameters: [_samlId], description: 'application/x-www-form-urlencoded SAMLResponse + RelayState. The assertion must be signed by a pinned IdP certificate, answer THIS login (signed relay state), be unused (replay guard) and name a subject linked to an enabled operator account; every refusal is the same generic 401. 503 LOGIN_UNAVAILABLE when the identity or replay store cannot be reached. The token (Bearer qos1...) is accepted by the admin API.' },
  ));
  add('/auth/saml/metadata', 'get', _op(
    'samlMetadata', 'SAML service-provider metadata', ['Single sign-on'], NO_AUTH,
    { '200': { description: 'SAML metadata (application/samlmetadata+xml)' }, '404': sg.responseRef('NotFound'), '429': sg.responseRef('TooManyRequests') },
    { parameters: [_samlId] },
  ));

  add('/auth/ldap/login', 'post', _op(
    'ldapLogin', 'LDAP / Active Directory password sign-in: the directory proves the password, the linked operator account gets a session token', ['Single sign-on'], NO_AUTH,
    { '200': _success('Operator session', sg.makeObject({ token: sg.makeString(), tokenType: sg.makeString({ enum: ['Bearer'] }), expiresAt: sg.makeInteger(), assured: sg.makeBoolean(), user: sg.makeObject({ id: sg.makeString(), username: sg.makeString(), role: sg.makeString() }) }, { required: ['token', 'tokenType', 'expiresAt'] })),
      '400': sg.responseRef('BadRequest'), '401': sg.responseRef('Unauthorized'), '404': sg.responseRef('NotFound'), '429': sg.responseRef('TooManyRequests') },
    { requestBody: _body(sg.makeObject({ provider: sg.makeString({ pattern: '^[a-z][a-z0-9-]{0,30}$' }), username: sg.makeString({ maxLength: 256 }), password: sg.makeString({ maxLength: 1024 }) }, { required: ['provider', 'username', 'password'] }), 'The directory provider id and the directory credentials'),
      description: 'Only when the provider is configured (QODIQA_LDAP_CONFIG_PATH). The (provider, directory subject) must be linked to an enabled operator account (no automatic account creation); every refusal (wrong password, unknown user, not linked, disabled, locked after 5 failures in 15 minutes, not in a required group) is the same generic 401. 503 LOGIN_UNAVAILABLE when the directory or identity store cannot be reached. Strictly rate limited per client address. The token (Bearer qos1...) is accepted by the admin API.' },
  ));

  // ── Dynamic OpenAI-compatible provider registry ─────────────────────

  const _providerBody = (req) => ({ requestBody: _body(sg.ref('ProviderRegistryInput'), 'The provider'), description: req });
  const _providerOne = sg.makeObject({ provider: sg.ref('ProviderRegistryEntry') }, { required: ['provider'] });
  const _providerId = _pPath('id', sg.makeString({ pattern: '^[a-z][a-z0-9-]{1,30}$' }), 'Provider id (the name is compat-<id>)');

  add('/v1/admin/providers', 'get', _op(
    'listProviders', 'List the dynamic OpenAI-compatible providers', ['Provider registry'], OPS_AUTH,
    { '200': _success('The providers', sg.makeObject({ providers: sg.makeArray(sg.ref('ProviderRegistryEntry')) }, { required: ['providers'] })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Requires READ_PROVIDERS. Built-in providers (openai, anthropic, ...) are configured by environment and are not listed here.' },
  ));

  add('/v1/admin/providers', 'post', _op(
    'registerProvider', 'Register an OpenAI-compatible provider (compat-<id>)', ['Provider registry'], OPS_AUTH,
    { '201': _success('Registered', _providerOne), '400': sg.responseRef('BadRequest'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    _providerBody('Requires MANAGE_PROVIDERS and an operator MFA step-up (X-QODIQA-OTP). The key is never sent here: apiKeyEnv names an environment variable (COMPAT_KEY_*) provisioned on every replica. baseUrl must be https to a public DNS name; a record changed outside the API is not callable (MAC).'),
  ));

  add('/v1/admin/providers/compare', 'post', _op(
    'compareProviders', 'Compare the enabled providers for a request of a given size (cost, latency, failure rate, load, weighted score)', ['Provider registry'], OPS_AUTH,
    { '200': _success('The comparison', sg.makeObject({
        providers: sg.makeArray(sg.makeObject({ provider: sg.makeString(), estimatedCostMicros: sg.makeNullable(sg.makeInteger()), currency: sg.makeNullable(sg.makeString()), avgLatencyMs: sg.makeNullable(sg.makeInteger()),
          samples: sg.makeInteger(), failureRate: sg.makeNullable(sg.makeNumber()), degraded: sg.makeBoolean(), inFlight: sg.makeInteger(), score: sg.makeNumber() }, { required: ['provider', 'score'] })),
        ranked: sg.makeArray(sg.makeString()), weights: sg.makeObject({}), mixedCurrencies: sg.makeBoolean(),
      }, { required: ['providers', 'ranked'] })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { requestBody: _body(sg.makeObject({ inputTokens: sg.makeInteger({ minimum: 0 }), outputTokens: sg.makeInteger({ minimum: 0 }), providers: sg.makeArray(sg.makeString()),
        weights: sg.makeObject({ cost: sg.makeNumber({ minimum: 0 }), latency: sg.makeNumber({ minimum: 0 }), failure: sg.makeNumber({ minimum: 0 }) }) }, { required: ['inputTokens', 'outputTokens'] }), 'The request size and optional weights'),
      description: 'Requires READ_PROVIDERS. Cost uses the tariffs of the ROUTING rules in force (the platform ships no price list); a provider with no tariff or no latency sample scores the worst value for that metric.' },
  ));

  add('/v1/admin/providers/{id}', 'get', _op(
    'getProvider', 'Get one dynamic provider', ['Provider registry'], OPS_AUTH,
    { '200': _success('The provider', _providerOne), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [_providerId], description: 'Requires READ_PROVIDERS.' },
  ));

  add('/v1/admin/providers/{id}', 'put', _op(
    'updateProvider', 'Change a dynamic provider', ['Provider registry'], OPS_AUTH,
    { '200': _success('Updated', _providerOne), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [_providerId], requestBody: _body(sg.ref('ProviderRegistryInput'), 'The members to change (id cannot change)'), description: 'Requires MANAGE_PROVIDERS and an operator MFA step-up. Takes effect on the next call on every replica within the control-plane bound (5 s).' },
  ));

  add('/v1/admin/providers/{id}/disable', 'post', _op(
    'disableProvider', 'Stop routing to a dynamic provider (there is no delete)', ['Provider registry'], OPS_AUTH,
    { '200': _success('Disabled', _providerOne), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [_providerId], description: 'Requires MANAGE_PROVIDERS and an operator MFA step-up.' },
  ));

  add('/v1/admin/providers/{id}/enable', 'post', _op(
    'enableProvider', 'Resume routing to a dynamic provider', ['Provider registry'], OPS_AUTH,
    { '200': _success('Enabled', _providerOne), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [_providerId], description: 'Requires MANAGE_PROVIDERS and an operator MFA step-up.' },
  ));

  // operator "sign out everywhere" for one tenant-portal user (session-version bump).
  add('/v1/admin/tenants/{tenantId}/portal-users/{portalUserId}/revoke-sessions', 'post', _op(
    'revokeTenantPortalUserSessions', 'Revoke every tenant-portal session of one portal user — the user stays enabled and can sign in again', ['Tenants'], OPS_AUTH,
    {
      '200': _success('Sessions revoked', sg.makeObject({
        portalUserId: sg.makeString(), tenantId: sg.makeString(),
        sessionVersion: sg.makeInteger({ minimum: 1 }), sessionsRevokedAt: sg.ISO8601_SCHEMA,
      })),
      ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS,
    },
    { parameters: [sg.paramRef('TenantIdParam'), _pPath('portalUserId', sg.makeString({ pattern: '^[A-Za-z0-9_-]{1,128}$' }), 'Tenant-portal user id (pu_…); must belong to {tenantId}')] },
  ));

  // ── Alerts ────────────────────────────────────────────────────────────────

  add('/alerts', 'get', _op(
    'listAlerts', 'List alerts', ['Alerts'], OPS_AUTH,
    { '200': _success('Paginated alert list', sg.makeObject({ records: sg.makeArray(sg.ref('Alert')), pagination: sg.ref('PaginationMeta') })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // `sort` is a named-field enum (e.g. `risk_score_desc`), not a
      // direction toggle — a justified exception to the canonical
      // `sortOrder` model (see API-4-REMEDIATION-REPORT.md). page/pageSize
      // are capped at 200 here, not the fleet-standard 500.
      parameters: [
        _pQuery('severity', sg.makeString({ enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] }), 'Filter by severity'),
        _pQuery('status', sg.makeString({ enum: ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'SUPPRESSED', 'FALSE_POSITIVE'] }), 'Filter by status'),
        _pQuery('type', sg.makeString(), 'Filter by alert type'), _pQuery('tenantId', sg.TENANT_ID_SCHEMA),
        _pQuery('requestId', sg.UUID_SCHEMA), _pQuery('artifactId', sg.UUID_SCHEMA), _pQuery('incidentId', sg.makeString()),
        _pQuery('from', sg.ISO8601_SCHEMA), _pQuery('to', sg.ISO8601_SCHEMA),
        _pQuery('page', sg.makeInteger({ minimum: 1, default: 1 })),
        _pQuery('pageSize', sg.makeInteger({ minimum: 1, maximum: 200, default: 50 })),
        _pQuery('sort', sg.makeString({ enum: ['detected_at_desc', 'risk_score_desc', 'severity_desc'], default: 'detected_at_desc' }), 'Named sort key (field + direction combined).'),
      ],
    },
  ));

  add('/alerts', 'post', _op(
    'createAlert', 'Create alert', ['Alerts'], OPS_AUTH,
    { '201': _success('Created alert', sg.ref('Alert')), '200': _success('Alert suppressed by correlation/dedup rules'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Internal-use endpoint — alerts are normally created by the DetectionEngine. Exposed for admin injection and integration testing.', requestBody: _body(sg.ref('AlertCreateRequest'), 'Alert to create') },
  ));

  add('/alerts/stats', 'get', _op(
    'alertStats', 'Alert statistics', ['Alerts'], OPS_AUTH,
    { '200': _success('Aggregate alert statistics for the requested time window'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [_pQuery('from', sg.ISO8601_SCHEMA, 'Window start (default: 24h ago)'), _pQuery('to', sg.ISO8601_SCHEMA, 'Window end (default: now)')] },
  ));

  add('/alerts/health', 'get', _op(
    'getAlertChannelHealth', 'Get notification channel health', ['Alerts'], OPS_AUTH,
    { '200': _success('Per-channel health status (email/SMS/Slack/PagerDuty/webhook/Teams/SIEM)'), '207': _success('Partial channel outage'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/alerts/counters', 'get', _op(
    'getAlertCounters', 'Get real-time anomaly counters', ['Alerts'], OPS_AUTH,
    { '200': _success('Real-time anomaly detection counter snapshot (dashboard)'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/alerts/test/{channel}', 'post', _op(
    'testAlertChannel', 'Send test notification', ['Alerts'], OPS_AUTH,
    { '200': _success('Test notification sent'), '400': sg.responseRef('BadRequest'), '502': { description: 'Channel failed to deliver the test notification' }, ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [_pPath('channel', sg.makeString({ enum: ['EMAIL', 'SMS', 'SLACK', 'PAGERDUTY', 'WEBHOOK', 'TEAMS', 'SIEM'] }), 'Notification channel to test')] },
  ));

  add('/alerts/stream', 'get', _op(
    'streamAlerts', 'Stream real-time alerts (SSE)', ['Alerts'], OPS_AUTH,
    { '200': { description: 'Server-Sent Events stream of newly created alerts, with a 30s heartbeat comment', content: { 'text/event-stream': {} } }, ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/alerts/{id}', 'get', _op(
    'getAlert', 'Get alert details', ['Alerts'], OPS_AUTH,
    { '200': _success('Alert details', sg.ref('Alert')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AlertIdParam')] },
  ));

  add('/alerts/{id}/acknowledge', 'post', _op(
    'acknowledgeAlert', 'Acknowledge alert', ['Alerts'], OPS_AUTH,
    { '200': _success('Alert acknowledged', sg.ref('Alert')), '400': sg.responseRef('BadRequest'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AlertIdParam')], requestBody: _body(sg.makeObject({ actor: sg.makeString(), note: sg.makeString() }), 'Optional acknowledgement details', false) },
  ));

  add('/alerts/{id}/resolve', 'post', _op(
    'resolveAlert', 'Resolve alert', ['Alerts'], OPS_AUTH,
    { '200': _success('Alert resolved', sg.ref('Alert')), '400': sg.responseRef('BadRequest'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AlertIdParam')], requestBody: _body(sg.makeObject({ actor: sg.makeString(), note: sg.makeString() }), 'Optional resolution details', false) },
  ));

  add('/alerts/{id}/suppress', 'post', _op(
    'suppressAlert', 'Suppress alert', ['Alerts'], OPS_AUTH,
    { '200': _success('Alert suppressed', sg.ref('Alert')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AlertIdParam')], requestBody: _body(sg.makeObject({ actor: sg.makeString() }), 'Optional actor', false) },
  ));

  add('/alerts/{id}/false-positive', 'post', _op(
    'markAlertFalsePositive', 'Mark alert as false positive', ['Alerts'], OPS_AUTH,
    { '200': _success('Alert marked as false positive', sg.ref('Alert')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AlertIdParam')], requestBody: _body(sg.makeObject({ actor: sg.makeString(), note: sg.makeString() }), 'Optional details', false) },
  ));

  add('/alerts/{id}/history', 'get', _op(
    'getAlertHistory', 'Get alert audit history', ['Alerts'], OPS_AUTH,
    { '200': _success('Alert lifecycle audit history'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AlertIdParam')] },
  ));

  add('/alerts/{id}/exposure-notification', 'get', _op(
    'getAlertExposureNotification', 'Drafts of the notifications for a DATA_EXPOSURE alert', ['Alerts'], OPS_AUTH,
    { '200': _success('Facts, a reference clock and four drafts (internal, authority, data subjects, controller): drafts only, not legal advice'), '400': sg.responseRef('BadRequest'), '409': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('AlertIdParam')] },
  ));

  // ── Dashboard ─────────────────────────────────────────────────────────────

  add('/dashboard/overview', 'get', _op(
    'getDashboardOverview', 'Get dashboard overview', ['Dashboard'], OPS_AUTH,
    { '200': _success('Summary counts (allowed/blocked/replayed/anomalies), cached 30s, plus execution integrity and uptime'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/dashboard/executions', 'get', _op(
    'getDashboardExecutions', 'Get recent allowed executions', ['Dashboard'], OPS_AUTH,
    { '200': _success('Paginated recent allowed executions'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: _pageParams },
  ));

  add('/dashboard/blocked', 'get', _op(
    'getDashboardBlocked', 'Get recent blocked requests', ['Dashboard'], OPS_AUTH,
    { '200': _success('Paginated recent blocked requests, with a by-reason breakdown'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: _pageParams },
  ));

  add('/dashboard/replays', 'get', _op(
    'getDashboardReplays', 'Get recent replay attempts', ['Dashboard'], OPS_AUTH,
    { '200': _success('Paginated replay attempts'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: _pageParams },
  ));

  add('/dashboard/anomalies', 'get', _op(
    'getDashboardAnomalies', 'Get recent anomaly events', ['Dashboard'], OPS_AUTH,
    { '200': _success('Paginated anomaly events, with a by-type breakdown'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: _pageParams },
  ));

  add('/dashboard/status', 'get', _op(
    'getDashboardStatus', 'Get component health status', ['Dashboard'], OPS_AUTH,
    { '200': _success('Component health status'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/dashboard/activity', 'get', _op(
    'getDashboardActivity', 'Get time-series request activity', ['Dashboard'], OPS_AUTH,
    { '200': _success('Time-series request activity'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [_pQuery('windowMinutes', sg.makeInteger({ minimum: 1, maximum: 1440, default: 60 }))] },
  ));

  add('/dashboard/stream', 'get', _op(
    'streamDashboardEvents', 'Stream real-time dashboard events (SSE)', ['Dashboard'], OPS_AUTH,
    { '200': { description: 'Server-Sent Events stream of real-time execution/block/replay/anomaly events', content: { 'text/event-stream': {} } }, ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  // ── Persistence Recovery Queue ─────────────────────────────────────────────

  add('/v1/prq/stats', 'get', _op(
    'getPrqStats', 'Get recovery queue statistics', ['Persistence Recovery'], OPS_AUTH,
    { '200': _success('Combined view: main queue depth, DLQ depth, archived depth, metrics snapshot'), ..._AUTH_ERRORS, ..._STD_ERRORS },
  ));

  add('/v1/prq/dlq', 'get', _op(
    'listDlqItems', 'List DLQ items', ['Persistence Recovery'], OPS_AUTH,
    { '200': _success('Paginated DLQ items'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      parameters: [
        // Canonical (API-4) — accepted as aliases for offset/limit below;
        // `sortOrder` is likewise accepted as an alias for `sort`.
        sg.paramRef('PageParam'), sg.paramRef('PageSizeParam'), sg.paramRef('SortOrderParam'),
        _pQuery('offset', sg.makeInteger({ minimum: 0, default: 0 })), _pQuery('limit', sg.makeInteger({ minimum: 1, maximum: 200, default: 50 })),
        _pQuery('after', sg.ISO8601_SCHEMA), _pQuery('before', sg.ISO8601_SCHEMA), _pQuery('operationType', sg.makeString()),
        _pQuery('service', sg.makeString()), _pQuery('minRetryCount', sg.makeInteger({ minimum: 0 })),
        _pQuery('sort', sg.makeString({ enum: ['asc', 'desc'], default: 'asc' }), 'Sort direction (oldest-first by default — opposite of this fleet\'s usual sortOrder default).'),
      ],
    },
  ));

  add('/v1/prq/dlq/replay', 'get', _op(
    'getDlqReplayMethodGuard', 'DLQ replay method guard', ['Persistence Recovery'], OPS_AUTH,
    { '405': { description: 'GET is not supported on this path — use POST /v1/prq/dlq/replay to replay DLQ items' }, ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Registered ahead of GET /v1/prq/dlq/{operationId} so the literal segment "replay" is never captured as an operationId. Always returns 405.' },
  ));

  add('/v1/prq/dlq/{operationId}', 'get', _op(
    'getDlqItem', 'Get DLQ item', ['Persistence Recovery'], OPS_AUTH,
    { '200': _success('DLQ item with full payload'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('OperationIdParam')] },
  ));

  add('/v1/prq/dlq/replay', 'post', _op(
    'replayDlqItems', 'Replay DLQ item(s)', ['Persistence Recovery'], OPS_AUTH,
    {
      '200': _success('Replay result — single-item or batch shape depending on request body'),
      '503': { description: 'PostgreSQL is unavailable — cannot replay DLQ items' },
      ..._AUTH_ERRORS, ..._STD_ERRORS,
    },
    {
      description: 'Accepts either `{ "operationId": "<id>" }` for a single item or `{ "operationIds": ["<id>", ...] }` for a batch.',
      requestBody: _body(sg.makeObject({ operationId: sg.makeString(), operationIds: sg.makeArray(sg.makeString()) }), 'Item(s) to replay'),
    },
  ));

  add('/v1/prq/dlq/{operationId}', 'delete', _op(
    'archiveDlqItem', 'Archive (soft-delete) DLQ item', ['Persistence Recovery'], OPS_AUTH,
    { '200': _success('Item archived'), '503': { description: 'PostgreSQL is unavailable' }, ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'The item is moved to the archived set, never physically destroyed.', parameters: [sg.paramRef('OperationIdParam')], requestBody: _body(sg.makeObject({ reason: sg.makeString() }), 'Optional archive reason', false) },
  ));

  add('/v1/prq/archived', 'get', _op(
    'listArchivedDlqItems', 'List archived DLQ items', ['Persistence Recovery'], OPS_AUTH,
    { '200': _success('Paginated archived DLQ items (admin audit trail)'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: _pageParamsNoSort },
  ));

  // ── Data Subject Rights ──────────────────

  add('/v1/admin/dsr', 'get', _op(
    'listDsrRequests', 'List DSR requests', ['Data Subject Rights'], OPS_AUTH,
    { '200': _success('Paginated DSR requests', sg.makeObject({ requests: sg.makeArray(sg.ref('DsrRequest')), pagination: sg.ref('PaginationMeta') })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // No sort customization — always newest-first server-side.
      description: 'Requires READ_DSR permission.',
      parameters: [
        _pQuery('actorId', sg.ACTOR_ID_SCHEMA), _pQuery('tenantId', sg.TENANT_ID_SCHEMA), _pQuery('status', sg.makeString()),
        _pQuery('requestType', sg.makeString({ enum: ['RECTIFICATION', 'ERASURE', 'RESTRICTION', 'PORTABILITY'] })),
        ..._pageParamsNoSort,
      ],
    },
  ));

  add('/v1/admin/dsr', 'post', _op(
    'createDsrRequest', 'Create DSR request', ['Data Subject Rights'], OPS_AUTH,
    { '201': _success('Created DSR request', sg.ref('DsrRequest')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Creates an Article 16/17/18/20 data subject rights request. Requires MANAGE_DSR permission.', requestBody: _body(sg.ref('DsrCreateRequest'), 'DSR request to create') },
  ));

  add('/v1/admin/dsr/{id}', 'get', _op(
    'getDsrRequest', 'Get DSR request detail', ['Data Subject Rights'], OPS_AUTH,
    { '200': _success('Request detail plus lifecycle event trail', sg.makeObject({ request: sg.ref('DsrRequest'), events: sg.makeArray(sg.makeObject({}, { additionalProperties: true })) })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('DsrRequestIdParam')] },
  ));

  add('/v1/admin/dsr/{id}/verify-identity', 'post', _op(
    'verifyDsrIdentity', 'Record identity verification', ['Data Subject Rights'], OPS_AUTH,
    { '200': _success('Updated DSR request', sg.ref('DsrRequest')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Required before a request can be approved. Requires MANAGE_DSR permission.', parameters: [sg.paramRef('DsrRequestIdParam')], requestBody: _body(sg.makeObject({ method: sg.makeString({ enum: ['OPERATOR_ATTESTATION', 'PRIOR_ACCOUNT_VERIFICATION', 'LEGAL_REQUEST'] }), result: sg.makeString({ enum: ['VERIFIED', 'FAILED'] }), evidence: sg.makeNullable(sg.makeString()), verifiedBy: sg.makeString() }, { required: ['method', 'result'] })) },
  ));

  add('/v1/admin/dsr/{id}/approve', 'post', _op(
    'approveDsrRequest', 'Approve DSR request', ['Data Subject Rights'], OPS_AUTH,
    { '200': _success('Updated DSR request', sg.ref('DsrRequest')), '400': sg.responseRef('BadRequest'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Approves a verified request for execution. Requires MANAGE_DSR permission.', parameters: [sg.paramRef('DsrRequestIdParam')], requestBody: _body(sg.makeObject({ approvedBy: sg.makeString() }), 'Optional approver override', false) },
  ));

  add('/v1/admin/dsr/{id}/rectify', 'post', _op(
    'rectifyDsrRequest', 'Execute Article 16 rectification', ['Data Subject Rights'], OPS_AUTH,
    { '200': _success('Updated DSR request', sg.ref('DsrRequest')), '400': sg.responseRef('BadRequest'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('DsrRequestIdParam')], requestBody: _body(sg.makeObject({ consentId: sg.UUID_SCHEMA, fields: sg.makeObject({}, { additionalProperties: true }), rectifiedBy: sg.makeString() }, { required: ['consentId', 'fields'] })) },
  ));

  add('/v1/admin/dsr/{id}/erase', 'post', _op(
    'eraseDsrRequest', 'Execute Article 17 erasure', ['Data Subject Rights'], OPS_AUTH,
    { '200': _success('Updated DSR request', sg.ref('DsrRequest')), '400': sg.responseRef('BadRequest'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('DsrRequestIdParam')], requestBody: _body(sg.makeObject({ pseudonymizeActorId: sg.makeBoolean(), erasedBy: sg.makeString() }), 'Erasure options', false) },
  ));

  add('/v1/admin/dsr/{id}/restrict', 'post', _op(
    'restrictDsrRequest', 'Execute Article 18 restriction', ['Data Subject Rights'], OPS_AUTH,
    { '200': _success('Updated DSR request', sg.ref('DsrRequest')), '400': sg.responseRef('BadRequest'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('DsrRequestIdParam')], requestBody: _body(sg.makeObject({ reason: sg.makeString(), restrictedBy: sg.makeString() }), 'Restriction details', false) },
  ));

  add('/v1/admin/dsr/{id}/lift', 'post', _op(
    'liftDsrRestriction', 'Lift Article 18 restriction', ['Data Subject Rights'], OPS_AUTH,
    { '200': _success('Updated DSR request', sg.ref('DsrRequest')), '400': sg.responseRef('BadRequest'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('DsrRequestIdParam')], requestBody: _body(sg.makeObject({ liftedBy: sg.makeString() }), 'Optional actor override', false) },
  ));

  add('/v1/admin/dsr/{id}/export', 'post', _op(
    'exportDsrData', 'Execute Article 20 portability export', ['Data Subject Rights'], OPS_AUTH,
    { '200': _success('Portable data export'), '400': sg.responseRef('BadRequest'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('DsrRequestIdParam')], requestBody: _body(sg.makeObject({ format: sg.makeString({ enum: ['JSON', 'CSV'], default: 'JSON' }), generatedBy: sg.makeString() }), 'Export options', false) },
  ));

  // ── Policy Governance ─────────────────────────────

  add('/v1/policy/governance', 'get', _op(
    'listPolicyChangeRequests', 'List policy change requests', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Paginated change requests', sg.makeObject({ requests: sg.makeArray(sg.ref('PolicyChangeRequest')), pagination: sg.ref('PaginationMeta') })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // No sort customization — always newest-first server-side.
      description: 'Requires READ_POLICY_GOVERNANCE permission.',
      parameters: [
        _pQuery('policyId', sg.makeString()), _pQuery('tenantId', sg.TENANT_ID_SCHEMA), _pQuery('status', sg.makeString()),
        _pQuery('requestType', sg.makeString()), _pQuery('authorId', sg.makeString()),
        ..._pageParamsNoSort,
      ],
    },
  ));

  add('/v1/policy/governance/{id}', 'get', _op(
    'getPolicyChangeRequest', 'Get policy change request detail', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Change request detail plus event trail', sg.ref('PolicyChangeRequest')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ChangeRequestIdParam')] },
  ));

  add('/v1/policy/governance/{id}/evidence', 'get', _op(
    'getPolicyChangeRequestEvidence', 'Get the evidence package of a change request', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Evidence package for this change request'), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { parameters: [sg.paramRef('ChangeRequestIdParam')] },
  ));

  add('/v1/policy/governance/draft', 'post', _op(
    'draftPolicyChange', 'Create draft policy change', ['Policy Governance'], OPS_AUTH,
    { '201': _success('Created draft', sg.ref('PolicyChangeRequest')), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Requires PROPOSE_POLICY_CHANGE permission.', requestBody: _body(sg.makeObject({ policyId: sg.makeString(), tenantId: sg.TENANT_ID_SCHEMA, requestType: sg.makeString({ enum: ['CREATE', 'UPDATE', 'ENABLE', 'DISABLE', 'ROLLBACK', 'ARCHIVE'] }), payload: sg.makeObject({}, { additionalProperties: true }), changeReason: sg.makeString({ minLength: 1 }) }, { required: ['policyId', 'requestType', 'changeReason'] })) },
  ));

  add('/v1/policy/governance/{id}/submit', 'post', _op(
    'submitPolicyChange', 'Submit draft for review', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Updated change request', sg.ref('PolicyChangeRequest')), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'DRAFT → SUBMITTED. Requires PROPOSE_POLICY_CHANGE permission; author only.', parameters: [sg.paramRef('ChangeRequestIdParam')] },
  ));

  add('/v1/policy/governance/{id}/review', 'post', _op(
    'reviewPolicyChange', 'Review policy change (claim + decide)', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Updated change request', sg.ref('PolicyChangeRequest')), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Requires REVIEW_POLICY_CHANGE permission; reviewer must not be the author.', parameters: [sg.paramRef('ChangeRequestIdParam')], requestBody: _body(sg.makeObject({ decision: sg.makeString({ enum: ['APPROVED', 'CHANGES_REQUESTED'] }), notes: sg.makeString() }, { required: ['decision'] })) },
  ));

  add('/v1/policy/governance/{id}/approve', 'post', _op(
    'approvePolicyChange', 'Approve reviewed policy change', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Updated change request', sg.ref('PolicyChangeRequest')), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'REVIEWED → APPROVED. Requires APPROVE_POLICY_CHANGE permission; approver must not be the author or (in strict mode) the reviewer.', parameters: [sg.paramRef('ChangeRequestIdParam')], requestBody: _body(sg.makeObject({ notes: sg.makeString() }), 'Optional notes', false) },
  ));

  add('/v1/policy/governance/{id}/reject', 'post', _op(
    'rejectPolicyChange', 'Reject policy change', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Updated change request', sg.ref('PolicyChangeRequest')), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Requires APPROVE_POLICY_CHANGE or REVIEW_POLICY_CHANGE permission.', parameters: [sg.paramRef('ChangeRequestIdParam')], requestBody: _body(sg.makeObject({ reason: sg.makeString() }, { required: ['reason'] })) },
  ));

  add('/v1/policy/governance/{id}/schedule', 'post', _op(
    'schedulePolicyChange', 'Schedule approved policy change', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Updated change request', sg.ref('PolicyChangeRequest')), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'APPROVED → SCHEDULED. Requires APPROVE_POLICY_CHANGE permission.', parameters: [sg.paramRef('ChangeRequestIdParam')], requestBody: _body(sg.makeObject({ scheduledFor: sg.makeString({ format: 'date-time' }) }, { required: ['scheduledFor'] })) },
  ));

  add('/v1/policy/governance/{id}/publish', 'post', _op(
    'publishPolicyChange', 'Publish policy change', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Publish result — the live policy set is reloaded'), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), '409': sg.responseRef('Conflict'), '500': { description: 'Publish succeeded but reloading the live policy set failed' }, ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Takes live effect. Requires PUBLISH_POLICY_CHANGE permission; publisher must not be the author.', parameters: [sg.paramRef('ChangeRequestIdParam')] },
  ));

  add('/v1/policy/governance/{id}/withdraw', 'post', _op(
    'withdrawPolicyChange', 'Withdraw policy change', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Updated change request', sg.ref('PolicyChangeRequest')), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Requires PROPOSE_POLICY_CHANGE permission (author) or admin.', parameters: [sg.paramRef('ChangeRequestIdParam')] },
  ));

  add('/v1/policy/governance/rollback', 'post', _op(
    'requestPolicyRollback', 'Request policy rollback', ['Policy Governance'], OPS_AUTH,
    { '201': _success('Rollback request created'), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Requires REQUEST_POLICY_ROLLBACK permission.', requestBody: _body(sg.makeObject({ policyId: sg.makeString(), toVersion: sg.makeInteger({ minimum: 1 }), reason: sg.makeString() }, { required: ['policyId', 'toVersion', 'reason'] })) },
  ));

  add('/v1/policy/governance/{id}/rollback/approve', 'post', _op(
    'approvePolicyRollback', 'Approve and apply policy rollback', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Rollback applied — the live policy set is reloaded'), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), '409': sg.responseRef('Conflict'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: '`{id}` here is the rollback change request id. Requires APPROVE_POLICY_ROLLBACK permission; approver must not be the author or original publisher.', parameters: [sg.paramRef('ChangeRequestIdParam')], requestBody: _body(sg.makeObject({ notes: sg.makeString() }), 'Optional notes', false) },
  ));

  add('/v1/policy/governance/emergency/activate', 'post', _op(
    'activateEmergencyPolicyOverride', 'Activate emergency policy override', ['Policy Governance'], OPS_AUTH,
    { '201': _success('Emergency override activated — the live policy set is reloaded'), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      description: 'Bypasses the normal maker-checker workflow for incident response. Requires EMERGENCY_POLICY_OVERRIDE permission and is subject to mandatory retrospective approval.',
      requestBody: _body(sg.makeObject({
        policyId: sg.makeString(), tenantId: sg.TENANT_ID_SCHEMA, requestType: sg.makeString({ enum: ['CREATE', 'UPDATE', 'ENABLE', 'DISABLE'] }),
        payload: sg.makeObject({}, { additionalProperties: true }), incidentReference: sg.makeString(), justification: sg.makeString(), ttlHours: sg.makeNumber({ minimum: 0, maximum: 168 }),
      }, { required: ['policyId', 'requestType', 'incidentReference', 'justification'] })),
    },
  ));

  add('/v1/policy/governance/emergency/{id}/retro-approve', 'post', _op(
    'retroApproveEmergencyOverride', 'Retrospectively approve/reject emergency override', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Retrospective decision recorded — a REJECTED decision or lazy-expiry reverts the live policy'), '400': sg.responseRef('BadRequest'), '403': sg.responseRef('Forbidden'), '409': { description: 'Emergency override has already expired' }, ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Requires APPROVE_EMERGENCY_POLICY permission; approver must not be the original activator.', parameters: [sg.paramRef('EmergencyIdParam')], requestBody: _body(sg.makeObject({ decision: sg.makeString({ enum: ['APPROVED', 'REJECTED'] }), notes: sg.makeString() }, { required: ['decision'] })) },
  ));

  add('/v1/policy/governance/emergency/sweep-expired', 'post', _op(
    'sweepExpiredEmergencyOverrides', 'Sweep expired emergency overrides', ['Policy Governance'], OPS_AUTH,
    { '200': _success('Sweep result — count of overrides reverted'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'Admin-triggered expiry sweep. Requires EMERGENCY_POLICY_OVERRIDE permission.' },
  ));

  // ── Signing Identities (TRUST-1) ────────────────────────────────────────────

  add('/signing-identities', 'get', _op(
    'listSigningIdentities', 'List signing identities', ['Signing Identities'], OPS_AUTH,
    { '200': _success('Signing identity list', sg.makeObject({ identities: sg.makeArray(sg.ref('SigningIdentity')), total: sg.makeInteger({ minimum: 0 }) })), ..._AUTH_ERRORS, ..._STD_ERRORS },
    {
      // Opt-in pagination (API-4): omitting page/pageSize/limit/offset
      // returns the full unbounded list (backward compatible).
      description: 'Requires READ_SIGNING_IDENTITIES permission.',
      parameters: _pageParamsNoSort,
    },
  ));

  add('/signing-identities', 'post', _op(
    'createSigningIdentity', 'Create signing identity', ['Signing Identities'], OPS_AUTH,
    { '201': _success('Created identity', sg.makeObject({ identity: sg.ref('SigningIdentity') })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._STD_ERRORS },
    { description: 'This is the only HTTP-reachable way to provision a signing identity for POST /sign. Requires MANAGE_SIGNING_IDENTITIES permission.', requestBody: _body(sg.ref('SigningIdentityCreateRequest'), 'Signing identity to create') },
  ));

  add('/signing-identities/{id}', 'get', _op(
    'getSigningIdentity', 'Get signing identity', ['Signing Identities'], OPS_AUTH,
    { '200': _success('Identity details', sg.makeObject({ identity: sg.ref('SigningIdentity') })), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Requires READ_SIGNING_IDENTITIES permission.', parameters: [sg.paramRef('SigningIdentityIdParam')] },
  ));

  add('/signing-identities/{id}', 'patch', _op(
    'updateSigningIdentity', 'Update signing identity', ['Signing Identities'], OPS_AUTH,
    { '200': _success('Updated identity', sg.makeObject({ identity: sg.ref('SigningIdentity') })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Updates scope/enabled state. Requires MANAGE_SIGNING_IDENTITIES permission. Canonical as of API-9/WP-030 (this is always a partial update, hence PATCH); PUT is a deprecated alias below.', parameters: [sg.paramRef('SigningIdentityIdParam')], requestBody: _body(sg.ref('SigningIdentityUpdateRequest'), 'Fields to update') },
  ));

  add('/signing-identities/{id}', 'put', _op(
    'updateSigningIdentityLegacy', 'Update signing identity (deprecated alias of PATCH)', ['Signing Identities'], OPS_AUTH,
    { '200': _success('Updated identity', sg.makeObject({ identity: sg.ref('SigningIdentity') })), '400': sg.responseRef('BadRequest'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    {
      description: 'DEPRECATED — use PATCH /signing-identities/{id} instead (API-9/WP-030). Identical behavior; ' +
        'returns Deprecation/Link response headers and logs a SIGNING_IDENTITY_ADMIN_PUT_DEPRECATED_USED warning.',
      parameters: [sg.paramRef('SigningIdentityIdParam')],
      requestBody: _body(sg.ref('SigningIdentityUpdateRequest'), 'Fields to update'),
      deprecated: true,
    },
  ));

  add('/signing-identities/{id}', 'delete', _op(
    'deleteSigningIdentity', 'Delete signing identity', ['Signing Identities'], OPS_AUTH,
    { '200': _success('Identity permanently deleted'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Permanent deletion. Requires MANAGE_SIGNING_IDENTITIES permission.', parameters: [sg.paramRef('SigningIdentityIdParam')] },
  ));

  add('/signing-identities/{id}/api-key', 'post', _op(
    'issueSigningApiKey', 'Issue / rotate signing API key', ['Signing Identities'], OPS_AUTH,
    { '201': _success('Plaintext signing API key (shown once)', sg.makeObject({ apiKey: sg.makeString({ description: 'Plaintext key — store securely, shown once', example: 'sk_abc123...' }), issuedAt: sg.ISO8601_SCHEMA })), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Requires MANAGE_SIGNING_IDENTITIES permission. The plaintext key is returned once and cannot be retrieved again.', parameters: [sg.paramRef('SigningIdentityIdParam')] },
  ));

  add('/signing-identities/{id}/api-key', 'delete', _op(
    'revokeSigningApiKey', 'Revoke signing API key', ['Signing Identities'], OPS_AUTH,
    { '200': _success('Key revoked'), ..._AUTH_ERRORS, ..._NOT_FOUND, ..._STD_ERRORS },
    { description: 'Immediately invalidates the signing API key. Requires MANAGE_SIGNING_IDENTITIES permission.', parameters: [sg.paramRef('SigningIdentityIdParam')], requestBody: _body(sg.makeObject({ reason: sg.makeString() }), 'Optional revocation reason', false) },
  ));

  // ── OpenAPI Meta ──────────────────────────────────────────────────────────

  add('/openapi.json', 'get', _op(
    'getOpenApiJson', 'Get OpenAPI specification (JSON)', ['Meta'], NO_AUTH,
    { '200': { description: 'The full OpenAPI 3.1.0 specification as JSON', content: { 'application/json': {} } }, ..._STD_ERRORS_NO_SHUTDOWN },
    { description: 'Cached in-memory (`Cache-Control: public, max-age=300`). Pass `?fresh=1` to bypass the cache and regenerate.', parameters: [_pQuery('fresh', sg.makeString({ enum: ['1'] }), 'Bypass the in-memory cache and regenerate the spec')] },
  ));

  add('/openapi.yaml', 'get', _op(
    'getOpenApiYaml', 'Get OpenAPI specification (YAML)', ['Meta'], NO_AUTH,
    { '200': { description: 'The full OpenAPI 3.1.0 specification as YAML', content: { 'application/yaml': {} } }, ..._STD_ERRORS_NO_SHUTDOWN },
    { description: 'Cached in-memory (`Cache-Control: public, max-age=300`). Pass `?fresh=1` to bypass the cache and regenerate.', parameters: [_pQuery('fresh', sg.makeString({ enum: ['1'] }), 'Bypass the in-memory cache and regenerate the spec')] },
  ));

  add('/docs', 'get', _op(
    'getSwaggerUi', 'Interactive Swagger UI explorer', ['Meta'], NO_AUTH,
    { '200': { description: 'Swagger UI HTML page', content: { 'text/html': {} } }, ..._STD_ERRORS_NO_SHUTDOWN },
    { description: 'Renders an interactive Swagger UI explorer for this specification (`Cache-Control: public, max-age=60`). The Swagger UI assets (swagger-ui-dist 5.17.14, each with a pinned sha384 integrity) and its initializer are served by this process at `/docs/assets/*` with no CDN, so the page works under the gateway HTML CSP (`script-src self`).' },
  ));

  _declareMfaStepUp(paths);
  return paths;
}

// / API-04: every operation behind the operator MFA step-up (src/openapi/mfaStepUpScope.js, held equal to the
// live app by mfaStepUpScope.test.js) declares the X-QODIQA-OTP header and the step-up responses.
function _declareMfaStepUp(paths) {
  const { requiresStepUp } = require('./mfaStepUpScope');
  for (const [p, item] of Object.entries(paths)) {
    for (const [m, op] of Object.entries(item)) {
      if (!requiresStepUp(m, p)) continue;
      op.parameters = [
        ...(op.parameters || []),
        _p('X-QODIQA-OTP', 'header', sg.makeString({ description: '6-digit TOTP or an unused recovery code', example: '123456' }),
          'Operator MFA step-up code. Required when MFA is enforced (QODIQA_OPS_MFA_REQUIRED, mandatory in production). A TOTP code is accepted at most once per 30-second step.', true),
      ];
      op.responses['401'] = sg.responseRef('UnauthorizedOrMfaRequired');
      op.responses['403'] = sg.responseRef('ForbiddenOrMfaEnrollmentRequired');
      op.responses['429'] = sg.responseRef('TooManyRequestsOrMfaLocked');
      op['x-qodiqa-mfa-step-up'] = true;
    }
  }
}

module.exports = { buildPaths };
