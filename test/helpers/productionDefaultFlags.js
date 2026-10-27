'use strict';

/**
 * The PRODUCTION values of the flags test/support/jest.setup.js forces OFF for unit suites.
 *
 * A server spawned from a Jest worker (test/harness/server.js startBootstrapped) inherits the worker's
 * environment, so without these it silently runs the unit-test configuration: no request limiter, no /sign lockout,
 * no MFA step-up, no FT-3 gate, in-process audit verifier. Found when /sign answered 200 during an injected Redis
 * outage (the limiter was simply off) and the boot log reported `ft3Enabled effective: false`.
 * Each value is the code's own default when the variable is unset:
 *   RL_ENABLED                         src/core/rateLimit/middleware.js  (!== 'false')
 *   QODIQA_SIGN_AUTH_LOCKOUT_ENABLED   src/api/routes/sign.js            (!== 'false')
 *   QODIQA_OPS_MFA_REQUIRED            src/core/rbac/mfa.js              (!== 'false'; production refuses false)
 *   QODIQA_SEM_FT3_ENABLED             src/core/semantic/embeddingSimilarity/config.js (unset → 'true')
 *   QODIQA_SEM_FT2_ENABLED             same file (shipped false — set explicitly so FT-3 stays the only fine-tuned gate)
 *   QODIQA_AUDIT_VERIFIER_WORKER       src/core/audit/verifier/index.js  (!== 'false')
 * Not restored: QODIQA_CONTROL_PLANE_BACKEND stays the bootstrap's in-memory control plane (production uses pg; the
 * dev bootstrap does not import a control plane into PostgreSQL).
 */
const PRODUCTION_DEFAULT_FLAGS = Object.freeze({
  RL_ENABLED: 'true',
  QODIQA_SIGN_AUTH_LOCKOUT_ENABLED: 'true',
  QODIQA_OPS_MFA_REQUIRED: 'true',
  QODIQA_SEM_FT3_ENABLED: 'true',
  QODIQA_SEM_FT2_ENABLED: 'false',
  QODIQA_AUDIT_VERIFIER_WORKER: 'true',
});

module.exports = { PRODUCTION_DEFAULT_FLAGS };
