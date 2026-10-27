'use strict';

/**
 * Response envelope registry — (API-1 remediation) response-envelope
 * governance.
 *
 * A hand-maintained, machine-readable manifest of every distinct top-level
 * JSON response shape ("envelope") used across the REST API, and which route
 * file uses which. Same design philosophy as src/openapi/routeScanner.js:
 * reviewed alongside the code it describes, not dynamic introspection —
 * dynamic introspection of arbitrary `res.json({...})` call sites across
 * ~50 route files (spreads, conditional fields, helper indirection) cannot
 * be done reliably, so this file is the single declarative source of truth
 * instead, and src/api/__tests__/responseEnvelopeGovernance.test.js is the
 * automated force that keeps it honest — see that file's header for exactly
 * what it checks.
 *
 * src/api/response.js's header comment is the prose specification of these
 * same envelope types; responseEnvelopeGovernance.test.js asserts every name
 * below also appears in that comment, so the two cannot drift apart.
 *
 * To add a new envelope type:
 *   1. Add it to ENVELOPE_TYPES below (name, mode, and its key set).
 *   2. Reference it from ROUTE_ENVELOPES for the file(s) that produce it.
 *   3. Add the type's name to response.js's header comment.
 * Skipping any of these three fails responseEnvelopeGovernance.test.js.
 */

const { MOUNTS } = require('../openapi/routeMounts');

// ── Envelope type catalog ──────────────────────────────────────────────────
//
// mode: 'exact'  — the response body's top-level key set must equal `keys`.
// mode: 'subset' — the response body's top-level key set must include every
//                  key in `keys` (used where a family of endpoints shares a
//                  constant field but otherwise varies its payload).
// mode: 'opaque' — not JSON / not meaningfully key-set-checkable (e.g. a
//                  Prometheus text exposition body); documented for
//                  completeness only, never runtime-asserted.

const ENVELOPE_TYPES = Object.freeze({
  // Built by src/api/response.js's success()/failure() — the default
  // envelope for the audit/RBAC/compliance/policy/keys/webhooks/etc.
  // management surface (~40 of the ~50 route files below).
  MANAGEMENT_SUCCESS: { mode: 'exact', keys: ['status', 'timestamp', 'requestId', 'data'] },
  MANAGEMENT_ERROR:   { mode: 'exact', keys: ['status', 'timestamp', 'requestId', 'error'] },

  // Core protocol surface (/ai/chat, /verify, /sign) — a normative business
  // decision, not a transport error. Owned by QODIQA-PROTOCOL-SPEC.md
  // §14.6/§14.7, not by response.js. 'details' is present on every observed
  // response; EXECUTE responses additionally carry artifactId/keyId, which
  // is why this is a 'subset' check (constant core, variable extras) rather
  // than 'exact'.
  ENFORCEMENT_DECISION: { mode: 'subset', keys: ['decision', 'reason', 'requestId'] },

  // POST /sign's success (200) response is its own SignResponse shape — not
  // an enforcement decision (it never returns BLOCK; failure paths return
  // ENFORCEMENT_DECISION-shaped 400/403/500 bodies instead, see sign.js).
  // Item 27: `requestId` added — the real body (sign.js:316-326) always
  // includes it; this entry previously omitted it (D26-5 point 2).
  SIGN_SUCCESS: { mode: 'exact', keys: ['artifactId', 'artifact', 'meta', 'requestId'] },

  // POST /v1/actions/authorize (artifactId, artifact, action, meta), /v1/actions/plans (planId, plan) and /v1/delegations (delegation, token, ...): authenticated like /sign, their refusals are
  // ENFORCEMENT_DECISION-shaped; only requestId is constant across the two successes.
  ACTION_SUCCESS: { mode: 'subset', keys: ['requestId'] },

  // POST /v1/tools/call: the executed answer (decision EXECUTE + result + receipt) or a BLOCK / ERROR decision body.
  TOOL_CALL: { mode: 'subset', keys: ['decision', 'requestId'] },

  // /.well-known/qodiqa/* — JWKS-style discovery, its own bespoke shapes,
  // predates and is independent of response.js.
  WELL_KNOWN_LIST:   { mode: 'exact', keys: ['keys', 'requestId'] },
  WELL_KNOWN_SINGLE: { mode: 'exact', keys: ['keyId', 'algorithm', 'publicKey', 'status', 'requestId'] },
  // 404/405/500 paths in well-known.js intentionally reuse the
  // enforcement-decision shape for consistency at that trust boundary.
  WELL_KNOWN_ERROR:  { mode: 'exact', keys: ['decision', 'reason', 'details', 'requestId'] },

  // Infrastructure probes — deliberately minimal, deliberately NOT the
  // management envelope (see response.js header and API_REFERENCE.md
  // "Response Envelopes" — this formalizes API-1's "third case"). Each is
  // its own type because each probe's shape is independently load-bearing
  // (kubernetes-probes.md, healthContentSafety.test.js) and none may be
  // silently harmonized with another.
  INFRA_HEALTH:       { mode: 'exact', keys: ['status', 'uptime'] },
  INFRA_READY:        { mode: 'exact', keys: ['ready', 'components'] },
  INFRA_HEALTH_REDIS: { mode: 'exact', keys: ['status', 'stores'] },
  // /diagnostics — ops-only, intentionally rich/bespoke; documented for
  // completeness, not runtime-asserted (not one of the files named).
  INFRA_DIAGNOSTICS: {
    mode: 'subset',
    keys: ['service', 'version', 'status', 'executionIntegrity', 'uptime', 'pid', 'nodeVersion', 'components'],
  },
  // /metrics — Prometheus text exposition format 0.0.4, not JSON.
  INFRA_METRICS: { mode: 'opaque', keys: [] },

  // src/alerting/api/alertRoutes.js — a genuinely distinct shape family
  // (constant `ok: boolean`, variable payload per endpoint: alert/alerts/
  // history/counters/stats). Flagged here as a *documented* pre-existing
  // exception,
  // not migrated onto the management envelope in this pass — see
  // API-8-REMEDIATION-REPORT.md for scope notes.
  ALERTS_OK: { mode: 'subset', keys: ['ok'] },

  // Item 27 (ITEM-26-RESPONSE-ENVELOPE-DECISION-RECORD.md, D26-2): the two
  // shapes found live but previously undocumented during item 26's census.

  // src/alerting/api/alertRoutes.js's error helper (`_err()`) — a bare
  // `{error:{code,message}}`, distinct from both MANAGEMENT_ERROR (which
  // wraps the same `error:{code,message}` in a status/timestamp/requestId
  // envelope) and ALERTS_OK's success shape above. Like checkEnvelopeShape
  // generally, this is a top-level key-set check only — `error`'s own
  // `code`/`message` sub-fields are not independently validated by this
  // registry entry (see responseEnvelopeGovernance.test.js §F(b) for the
  // one place that does assert them, on SERVICE_SHUTTING_DOWN below).
  ALERTS_ERROR: { mode: 'exact', keys: ['error'] },

  // src/runtime/requestDrain.js's pre-pipeline shutdown-drain middleware —
  // NOT owned by any route file (mounted ahead of every route in app.js),
  // which is why it is declared in MIDDLEWARE_ENVELOPES below rather than
  // ROUTE_ENVELOPE_OVERRIDES. QODIQA-PROTOCOL-SPEC.md §30.13/§35.11 document
  // it normatively and explicitly exempt it from §21.4's enforcement-error
  // schema. Runtime ground truth: src/runtime/requestDrain.js:30-36.
  SERVICE_SHUTTING_DOWN: { mode: 'exact', keys: ['success', 'error'] },
});

// ── Route-file → envelope-type mapping ─────────────────────────────────────
//
// Every file in routeMounts.js's MOUNTS list defaults to the management
// envelope (MANAGEMENT_SUCCESS/MANAGEMENT_ERROR) unless listed here.
// responseEnvelopeGovernance.test.js verifies every defaulted file actually
// requires response.js and calls success()/failure() — a file that stops
// doing so without gaining an explicit override here fails CI.
//
// This map is keyed on ROUTE file path only. Envelopes owned by
// application-wide middleware (not any single route) do NOT belong here —
// see MIDDLEWARE_ENVELOPES below instead.

const ROUTE_ENVELOPE_OVERRIDES = Object.freeze({
  'src/api/routes/health.js':       ['INFRA_HEALTH'],
  'src/api/routes/ready.js':        ['INFRA_READY'],
  'src/api/routes/healthRedis.js':  ['INFRA_HEALTH_REDIS'],
  'src/api/routes/metrics.js':      ['INFRA_METRICS'],
  'src/api/routes/diagnostics.js':  ['INFRA_DIAGNOSTICS'],
  'src/api/routes/well-known.js':   ['WELL_KNOWN_LIST', 'WELL_KNOWN_SINGLE', 'WELL_KNOWN_ERROR'],
  'src/api/routes/aiChat.js':       ['ENFORCEMENT_DECISION'],
  'src/api/routes/verify.js':       ['ENFORCEMENT_DECISION'],
  'src/api/routes/sign.js':         ['SIGN_SUCCESS', 'ENFORCEMENT_DECISION'],
  'src/api/routes/actions.js':      ['ACTION_SUCCESS', 'ENFORCEMENT_DECISION'],
  'src/api/routes/delegations.js':  ['ACTION_SUCCESS', 'ENFORCEMENT_DECISION'],
  'src/api/routes/tools.js':        ['TOOL_CALL', 'ENFORCEMENT_DECISION'],
  'src/alerting/api/alertRoutes.js': ['ALERTS_OK', 'ALERTS_ERROR'],
});

const DEFAULT_ENVELOPES = ['MANAGEMENT_SUCCESS', 'MANAGEMENT_ERROR'];

function buildRouteEnvelopes() {
  const files = new Set(MOUNTS.map(m => m.file));
  const map = {};
  for (const file of files) {
    map[file] = ROUTE_ENVELOPE_OVERRIDES[file] || DEFAULT_ENVELOPES;
  }
  return map;
}

const ROUTE_ENVELOPES = Object.freeze(buildRouteEnvelopes());

// ── Middleware-owned envelopes ──────────────────────────────────────────────
//
// Envelopes emitted by application-wide middleware rather than any single
// route file — ROUTE_ENVELOPE_OVERRIDES (route file -> envelope types) has no
// slot for these, and folding one in there would misrepresent a middleware as
// a route. Governed by responseEnvelopeGovernance.test.js §F, which reads
// this SAME map for both its static (file/type existence) and runtime
// (actual response shape) checks — no hardcoded duplicate file list.
const MIDDLEWARE_ENVELOPES = Object.freeze({
  'src/runtime/requestDrain.js': ['SERVICE_SHUTTING_DOWN'],
});

// ── Shape-check helper ──────────────────────────────────────────────────────

// Pure function: does `body`'s top-level key set satisfy `envelopeTypeName`?
// Returns { ok: true } or { ok: false, reason }. Exported so both the
// runtime-shape tests and the synthetic-mutation test in
// responseEnvelopeGovernance.test.js exercise the exact same logic.
function checkEnvelopeShape(body, envelopeTypeName) {
  const type = ENVELOPE_TYPES[envelopeTypeName];
  if (!type) return { ok: false, reason: `unknown envelope type '${envelopeTypeName}'` };
  if (type.mode === 'opaque') return { ok: true };

  const actual = Object.keys(body).sort();
  const expected = [...type.keys].sort();

  if (type.mode === 'exact') {
    const same = actual.length === expected.length && actual.every((k, i) => k === expected[i]);
    return same
      ? { ok: true }
      : { ok: false, reason: `expected exactly [${expected.join(', ')}], got [${actual.join(', ')}]` };
  }

  // mode === 'subset'
  const missing = expected.filter(k => !actual.includes(k));
  return missing.length === 0
    ? { ok: true }
    : { ok: false, reason: `missing required key(s) [${missing.join(', ')}], got [${actual.join(', ')}]` };
}

module.exports = { ENVELOPE_TYPES, ROUTE_ENVELOPES, MIDDLEWARE_ENVELOPES, checkEnvelopeShape };
