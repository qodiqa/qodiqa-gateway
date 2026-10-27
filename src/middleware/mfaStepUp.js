'use strict';

/**
 * Operator MFA step-up —.
 *
 * Mounted AFTER the admin stack (so req.rbacUser is the authenticated
 * operator) on the privileged mutation surfaces listed in
 * (see src/app.js). Reads (GET/HEAD/OPTIONS) and
 * the enforcement path never need a code.
 *
 * A mutating request must carry `X-QODIQA-OTP: <6-digit TOTP | recovery code>`:
 *   - operator without enrolled MFA  → 403 MFA_ENROLLMENT_REQUIRED
 *   - no code                        → 401 MFA_REQUIRED
 *   - wrong code                     → 401 MFA_INVALID (counts toward the lock)
 *   - locked (5 failures / 15 min)   → 429 MFA_LOCKED + Retry-After
 * A caller with no operator identity (none reaches here past rbacResolve, but
 * the check is unconditional) is refused: step-up needs a user to verify.
 *
 * QODIQA_OPS_MFA_REQUIRED=false disables the requirement (production refuses
 * it at boot — src/infra/config/bootValidator.js, rule `credentials`). It is
 * read per request, like RL_ENABLED.
 */

const { emit } = require('../../services/logger');
const { failure } = require('../api/response');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * @param {object}   [opts]
 * @param {(req) => boolean} [opts.when]   extra predicate (true → step-up applies)
 * @param {object}   opts.mfa              the MFA module (src/core/rbac/mfa) — injected by src/app.js
 */
function createMfaStepUp({ when = () => true, mfa } = {}) {
  // The MFA module is injected (src/app.js) — middleware never imports Core (.dependency-cruiser.js no-middleware-to-core).
  if (!mfa || typeof mfa.isRequired !== 'function') throw new TypeError('createMfaStepUp: an mfa module is required (src/app.js injects src/core/rbac/mfa)');
  return async function mfaStepUp(req, res, next) {
    if (SAFE_METHODS.has(req.method)) return next();
    if (!when(req)) return next();
    if (!mfa.isRequired()) return next();

    const user = req.rbacUser;
    const base = { requestId: req.requestId ?? null, path: req.originalUrl || req.path, method: req.method };
    // an operator who signed in through single sign-on with a token the identity provider vouches for as a recent second-factor authentication (provider `assurance`)
    // has already done the step-up there: no TOTP is asked. Without that assurance the normal TOTP rules below apply, enrolment included.
    if (user && user.id && req.operatorSso && req.operatorSso.assured === true) {
      emit('INFO', 'RBAC_MFA_STEP_UP_OK', { ...base, userId: user.id, username: user.username, method: 'idp', providerId: req.operatorSso.providerId });
      try { require('../observability/metrics').mfaEventsTotal.inc({ outcome: 'step_up_idp' }); } catch { /* best-effort metric */ }
      return next();
    }
    if (!user || !user.id) {
      emit('WARN', 'RBAC_MFA_STEP_UP_DENIED', { ...base, reason: 'NO_OPERATOR_IDENTITY' });
      try { require('../observability/metrics').mfaEventsTotal.inc({ outcome: 'step_up_denied' }); } catch { /* best-effort metric */ }
      return failure(res, 'MFA_ENROLLMENT_REQUIRED', 'This action requires an operator identity with MFA enrolled', 403);
    }

    let st;
    try { st = mfa.status(user.id); } catch (e) {
      emit('ERROR', 'RBAC_MFA_STEP_UP_ERROR', { ...base, userId: user.id, error: e.message });
      try { require('../observability/metrics').mfaEventsTotal.inc({ outcome: 'step_up_error' }); } catch { /* best-effort metric */ }
      return failure(res, 'MFA_UNAVAILABLE', 'MFA verification is unavailable', 503);
    }
    if (!st.enrolled) {
      emit('WARN', 'RBAC_MFA_STEP_UP_DENIED', { ...base, userId: user.id, username: user.username, reason: 'MFA_ENROLLMENT_REQUIRED' });
      try { require('../observability/metrics').mfaEventsTotal.inc({ outcome: 'step_up_denied' }); } catch { /* best-effort metric */ }
      return failure(res, 'MFA_ENROLLMENT_REQUIRED', 'Enroll MFA first: POST /rbac/me/mfa/enroll, then POST /rbac/me/mfa/confirm', 403);
    }

    const code = req.get('X-QODIQA-OTP');
    if (!code) {
      emit('WARN', 'RBAC_MFA_STEP_UP_DENIED', { ...base, userId: user.id, username: user.username, reason: 'MFA_REQUIRED' });
      try { require('../observability/metrics').mfaEventsTotal.inc({ outcome: 'step_up_denied' }); } catch { /* best-effort metric */ }
      return failure(res, 'MFA_REQUIRED', 'This action requires an MFA code in the X-QODIQA-OTP header', 401);
    }

    let v;
    // the state change (last-used step, failure count) is committed before we answer.
    try { v = await mfa.verifyStepUp(user, code); } catch (e) {
      emit('ERROR', 'RBAC_MFA_STEP_UP_ERROR', { ...base, userId: user.id, error: e.message });
      try { require('../observability/metrics').mfaEventsTotal.inc({ outcome: 'step_up_error' }); } catch { /* best-effort metric */ }
      return failure(res, 'MFA_UNAVAILABLE', 'MFA verification is unavailable', 503);
    }
    if (v.ok) {
      emit('INFO', 'RBAC_MFA_STEP_UP_OK', { ...base, userId: user.id, username: user.username, method: v.method });
      return next();
    }
    emit('WARN', 'RBAC_MFA_STEP_UP_DENIED', { ...base, userId: user.id, username: user.username, reason: v.reason });
    try { require('../observability/metrics').mfaEventsTotal.inc({ outcome: 'step_up_denied' }); } catch { /* best-effort metric */ }
    if (v.reason === 'MFA_LOCKED') {
      if (v.retryAfterSeconds) res.set('Retry-After', String(v.retryAfterSeconds));
      return failure(res, 'MFA_LOCKED', 'Too many failed MFA codes — try again later', 429);
    }
    if (v.reason === 'MFA_NOT_ENROLLED') {
      return failure(res, 'MFA_ENROLLMENT_REQUIRED', 'Enroll MFA first', 403);
    }
    return failure(res, 'MFA_INVALID', 'The MFA code is invalid', 401);
  };
}

// Governance: the transitions that change live or scheduled policy — the S1 scope. the governance mount
// gates EVERY mutation (src/app.js); this pattern is kept because the route-guard invariant
// (scripts/security/__tests__/routeGuardRegistry.test.js) still selects the S1 transitions with it.
const GOVERNANCE_STEP_UP = /\/(approve|publish|schedule|activate|retro-approve)\/?$/i;
// /rbac: self-service enrolment is the one mutation allowed without a code.
const RBAC_SELF_ENROLL = /^\/me\/mfa\/(enroll|confirm)\/?$/i;

// ── State-changing operations are protected according to risk ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// The step-up now covers EVERY POST/PUT/PATCH/DELETE on the operator admin plane (every src/app.js mount behind
// ctx.adminStack()). These are the ONLY admin-plane non-read operations that stay usable without a code, each for the
// reason given. Full OpenAPI-form paths ({param} = exactly one segment), both /v1 and unversioned aliases where both
// are mounted. src/openapi/mfaStepUpScope.test.js (MS-04/MS-05) fails when an admin-plane mutation is neither gated
// nor listed here, when an entry here is gated anyway, or when an entry names no mounted route.
// Matching is exact and case-sensitive: anything that does not match an entry literally is gated (fail closed).
const _VERIFY_ONLY = 'verification/computation only: changes no protected state (at most an append-only record that the verification ran)';
const STEP_UP_EXEMPTIONS = Object.freeze([
  { op: 'post /rbac/me/mfa/enroll',  reason: 'self-service MFA enrolment: an operator cannot present a code before enrolling; refused once MFA exists' },
  { op: 'post /rbac/me/mfa/confirm', reason: 'self-service MFA enrolment confirmation: proves the new TOTP secret itself' },
  { op: 'post /audit/chain/verifier/verify', reason: `${_VERIFY_ONLY}; never repairs (repairSupported:false)` },
  { op: 'post /provenance/policies/{policyId}/integrity', reason: _VERIFY_ONLY },
  { op: 'post /evidence-chain/chain/verify-range', reason: _VERIFY_ONLY },
  { op: 'post /evidence-chain/records/{evidenceId}/verify', reason: _VERIFY_ONLY },
  { op: 'post /compliance/report/verify', reason: `${_VERIFY_ONLY}; signature check of a caller-supplied report` },
  { op: 'post /consent/verify', reason: `${_VERIFY_ONLY}; ad-hoc consent lookup` },
  { op: 'post /v1/policy/simulate', reason: 'dry-run policy evaluation: no write' },
  { op: 'post /v1/policy/simulate/batch', reason: 'dry-run policy evaluation: no write' },
  { op: 'post /v1/policy/compare', reason: 'dry-run policy comparison: no write' },
  { op: 'post /v1/policy/visual/graph', reason: 'policy visualisation: no write' },
  { op: 'post /v1/policy/visual/tree', reason: 'policy visualisation: no write' },
  { op: 'post /v1/policy/visual/deps', reason: 'policy visualisation: no write' },
  { op: 'post /v1/policy/visual/stats', reason: 'policy visualisation: no write' },
  { op: 'post /v1/policy/visual/highlight', reason: 'policy visualisation: no write' },
  { op: 'post /v1/policy/visual/export', reason: 'policy visualisation export: no write' },
  { op: 'post /v1/attestation/chain/verify', reason: `${_VERIFY_ONLY}; mount not step-up-gated (shares /v1/attestation with public verification routes)` },
]);
const _escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const _EXEMPT = STEP_UP_EXEMPTIONS.map(({ op }) => {
  const [method, path] = op.split(' ');
  const re = new RegExp(`^${path.split(/\{[^}]+\}/).map(_escape).join('[^/]+')}/?$`);
  return { method: method.toUpperCase(), re };
});

/** True when `method fullPath` (concrete path, e.g. '/consent/verify') is a approved step-up exemption. */
function isStepUpExempt(method, fullPath) {
  const m = String(method || '').toUpperCase();
  const p = String(fullPath || '');
  return _EXEMPT.some((e) => e.method === m && e.re.test(p));
}

/** The `when` predicate for an admin-plane mount: every mutation except the exemptions above. */
function adminPlaneStepUpWhen(req) {
  return !isStepUpExempt(req.method, `${req.baseUrl || ''}${req.path || ''}`);
}

module.exports = { createMfaStepUp, GOVERNANCE_STEP_UP, RBAC_SELF_ENROLL, STEP_UP_EXEMPTIONS, isStepUpExempt, adminPlaneStepUpWhen };
