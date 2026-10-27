'use strict';

/**
 * · D7 — the HTTP status of an /ai/chat enforcement BLOCK.
 *
 * QODIQA_BLOCK_HTTP_MODE
 * 'decision' (DEFAULT, also when unset) — the contract, unchanged: every enforcement BLOCK is
 * HTTP 200 {decision:'BLOCK', reason, details, requestId}. Byte-identical to earlier.
 *   'status'   — opt-in: the same body, but the HTTP status carries the block class (table below).
 * Any other value is refused at boot (src/infra/config/bootValidator.js, rule `api.block_http_mode`).
 *
 * Scope: only the reasons answers with 200. Statuses that were already non-200 (and's BUDGET_EXCEEDED_*, a throttle like CLASSIFICATION_BUDGET_EXHAUSTED) are owned by
 * their own call sites and do NOT pass through here: RATE_LIMITED 429, CONTROL_PLANE_STALE 503, the
 * idempotency 4xx/5xx, the input-guard 400s, ARTIFACT_TOO_LARGE 413, provider errors/timeouts, 405.
 * A BLOCK decided after SSE headers were flushed (mid-stream output semantics) cannot change its status in
 * either mode: it stays a terminal `stream_cancelled` event (with the block `reason`) on the already-200 stream.
 *
 * Mapping constraints: never 401 (the Python SDK maps any 401 to
 * AuthenticationError before reading the reason); never 429 for a reason that is not a throttle (generic HTTP
 * clients auto-retry 429 — retrying into the anomaly detector would amplify it); 503 only for "a dependency could
 * not answer". [ / API-03, 2026-10-04: the canonical SDKs no longer resend POST /ai/chat on 429/5xx — the
 * artifact nonce may already be consumed — only on 503 SERVER_OVERLOADED (admission, before nonce registration).]
 */

const { SEMANTIC_REASONS, SEMANTIC_ENGINE_UNAVAILABLE_REASON } = require('../core/semantic/reasons');

const MODES = Object.freeze(['decision', 'status']);

const CLASSES = Object.freeze({
  // no / unreadable artifact — the request is malformed
  artifact_malformed: { status: 400, reasons: ['UNSUPPORTED_PROTOCOL_VERSION', 'UNSUPPORTED_CRITICAL_CLAIM', 'MISSING_ARTIFACT', 'ARTIFACT_DECODE_FAILED', 'ARTIFACT_INVALID_TYPE', 'INVALID_JSON', 'NOT_OBJECT', 'MISSING_SIGNATURE', 'MALFORMED_REQUEST_ID', 'VERSION_MISMATCH'] },
  // bad signature / key / time — not authorized by the artifact it presents
  artifact_invalid:   { status: 403, reasons: ['ARTIFACT_REVOKED', 'PROTOCOL_VERSION_TOO_LOW', 'WRONG_ARTIFACT_KIND', 'INVALID_ARTIFACT', 'INVALID_SIGNATURE', 'SIGNATURE_UNVERIFIABLE', 'KEY_NOT_FOUND', 'KEY_REVOKED', 'KEY_ARCHIVED', 'KEY_DEPRECATED', 'KEY_NOT_YET_ACTIVE', 'KEY_NOT_ACTIVE_AT_SIGNING_TIME', 'KEY_STATUS_UNKNOWN', 'SIGNING_TIME_UNKNOWN', 'EXPIRED', 'FUTURE_TIMESTAMP', 'TIME_SKEW_EXCEEDED', 'INVALID_EXPIRY', 'MISSING_TIMESTAMP'] },
  request_mismatch:   { status: 403, reasons: ['REQUEST_MISMATCH'] },
  replay:             { status: 409, reasons: ['REPLAY_DETECTED'] },
  anomaly:            { status: 403, reasons: ['ANOMALY_DETECTED'] },
  consent:            { status: 403, reasons: ['CONSENT_MISSING', 'CONSENT_NOT_FOUND', 'CONSENT_REVOKED', 'CONSENT_EXPIRED', 'CONSENT_SUSPENDED', 'CONSENT_NOT_ACTIVE', 'CONSENT_SCOPE_MISMATCH', 'CONSENT_SCOPE_MISSING', 'CONSENT_CONTEXT_INCOMPLETE', 'CONSENT_VERIFICATION_FAILED'] },
  policy:             { status: 403, reasons: ['POLICY_BLOCKED', 'POLICY_DENIED', 'IP_BLOCKED', 'IP_MISSING', 'OUTSIDE_TIME_WINDOW', 'TIMESTAMP_MISSING', 'RATE_LIMIT_KEY_MISSING'] },
  policy_rate_rule:   { status: 429, reasons: ['RATE_LIMIT_EXCEEDED'] },
  tenant_identity:    { status: 403, reasons: ['TENANT_UNKNOWN', 'TENANT_INACTIVE', 'TENANT_SUSPENDED', 'TENANT_CONTEXT_MISSING', 'ORG_SUSPENDED', 'ORG_DISABLED', 'SIGNING_IDENTITY_REVOKED', 'SCOPE_PROVIDER_DENIED', 'IDENTITY_PERMISSION_DENIED', 'NO_CALLER_IDENTITY', 'ACTOR_DECOMMISSIONED'] },
  // request and (non-stream) output semantics share one vocabulary; both are content decisions
  semantics:          { status: 403, reasons: Object.values(SEMANTIC_REASONS) },
  // data-protection, residency and per-request budget refusals are content/policy decisions
  data_protection:    { status: 403, reasons: ['DLP_BLOCKED', 'DLP_OUTPUT_STREAMING_UNSUPPORTED', 'RESIDENCY_CROSS_REGION_BLOCKED', 'RESIDENCY_PROVIDER_REGION_UNKNOWN', 'RESIDENCY_PROVIDER_UNKNOWN', 'BUDGET_REQUEST_TOO_LARGE', 'BUDGET_REQUEST_TOO_COSTLY', 'CONTENT_RULE_BLOCKED', 'CONTENT_RULE_STREAMING_UNSUPPORTED'] },
  // provider output beyond the classification cap — withheld, never released unclassified
  output_limit:       { status: 403, reasons: ['OUTPUT_TOO_LARGE'] },
  dependency_unavailable: { status: 503, reasons: ['NONCE_STORE_ERROR', 'ARTIFACT_REVOCATION_STATE_UNAVAILABLE', 'KILL_SWITCH_ACTIVE', 'KILL_SWITCH_STATE_UNAVAILABLE', 'DLP_UNAVAILABLE', 'BUDGET_UNAVAILABLE', 'CONTENT_RULE_UNAVAILABLE', 'REPLAY_STATE_UNPROVABLE', 'REDIS_UNAVAILABLE', 'CONSENT_STORE_UNAVAILABLE', 'CONSENT_STORE_ERROR', 'POLICY_STATE_UNAVAILABLE', 'ORG_STATUS_SYNC_UNAVAILABLE', 'ORG_STATUS_STALE', SEMANTIC_ENGINE_UNAVAILABLE_REASON] },
  internal_error:     { status: 500, reasons: ['INTERNAL_ERROR', 'EVALUATOR_MISSING', 'EVALUATOR_ERROR', 'CONSENT_EVALUATION_ERROR', 'NO_POLICIES_LOADED', 'NO_ENABLED_POLICIES', 'INVALID_CONTEXT'] },
});

// Any enforcement denial not listed above (a reason added later without updating this table) still gets a
// denial status in 'status' mode; blockHttpStatus.test.js pins that every reason in the inventory is
// listed explicitly, so the fallback is a safety net, not the mapping.
const UNLISTED_DENIAL_STATUS = 403;

const STATUS_BY_REASON = new Map();
for (const [cls, { status, reasons }] of Object.entries(CLASSES)) {
  for (const r of reasons) {
    if (STATUS_BY_REASON.has(r)) throw new Error(`blockHttpStatus: reason ${r} listed twice (${cls})`);
    STATUS_BY_REASON.set(r, { status, cls });
  }
}

function blockHttpMode(env = process.env) {
  return env.QODIQA_BLOCK_HTTP_MODE === 'status' ? 'status' : 'decision';
}

/** HTTP status for an enforcement BLOCK with this reason under the current mode. */
function blockHttpStatus(reason, env = process.env) {
  if (blockHttpMode(env) !== 'status') return 200;
  const hit = STATUS_BY_REASON.get(reason);
  return hit ? hit.status : UNLISTED_DENIAL_STATUS;
}

function blockClass(reason) {
  const hit = STATUS_BY_REASON.get(reason);
  return hit ? hit.cls : null;
}

module.exports = { MODES, CLASSES, UNLISTED_DENIAL_STATUS, blockHttpMode, blockHttpStatus, blockClass };
