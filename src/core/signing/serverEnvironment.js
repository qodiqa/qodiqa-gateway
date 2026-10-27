'use strict';

/**
 * Resolves the current deployment environment for signing-scope checks
 * (TRUST-1 remediation). A signing identity is scoped to one of
 * signingIdentityStore's ENVIRONMENTS (development/test/ci/staging/
 * production); this is what its scope is checked against, so a
 * staging-scoped credential can never sign artifacts on a production
 * instance even if leaked or reused there.
 *
 * QODIQA_ENVIRONMENT is the explicit override (set it in every deployment
 * manifest). Falling back to NODE_ENV is a development convenience only —
 * production deployments should always set QODIQA_ENVIRONMENT explicitly.
 */

const { ENVIRONMENTS } = require('./signingIdentityStore');

function resolveServerEnvironment() {
  const explicit = process.env.QODIQA_ENVIRONMENT;
  if (typeof explicit === 'string' && ENVIRONMENTS.includes(explicit)) {
    return explicit;
  }

  const nodeEnv = process.env.NODE_ENV;
  if (nodeEnv === 'production')  return 'production';
  if (nodeEnv === 'test')        return 'test';
  return 'development';
}

module.exports = { resolveServerEnvironment };
