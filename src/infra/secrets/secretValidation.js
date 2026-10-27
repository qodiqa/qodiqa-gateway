'use strict';

/**
 * Secret validation — COMPATIBILITY FACADE.
 *
 * Every check that used to be implemented here now has exactly one
 * implementation: `checks` in src/infra/config/bootValidator.js, which
 * server/startup.js runs (runBootValidation) before any listener opens. This
 * module keeps its public names so existing importers and its regression suite
 * keep working, and delegates each of them to that single implementation.
 *
 * runSecretValidation() keeps its historical scope — the secret subset only
 * (ops token, KEK, execution-invariant secret strength, OpenAI placeholder,
 * client id, Redis password, production keystore path) with the historical
 * events (SECRET_VALIDATION_OK / _FAILED / _FATAL, KMS_PROVIDER_ADVISORY). The
 * server no longer calls it; the full rule set is bootValidator's.
 *
 * QODIQA_SIGN_TOKEN is not validated here: it no longer exists (TRUST-1).
 * bootValidator flags it as a dead variable if it is still set.
 *
 * Secret values are never included in any finding.
 */

const { emit } = require('../../../services/logger');
const { checks, PROJECT_ROOT } = require('../config/bootValidator');

const _checkOpsToken                 = () => checks.opsToken(process.env);
const _checkKek                      = () => checks.kek(process.env);
const _checkExecutionInvariantSecret = () => checks.invariantStrength(process.env);
const _checkOpenAiKey                = () => checks.openAiKeyPlaceholder(process.env);
const _checkClientId                 = () => checks.clientId(process.env);
const _checkRedisPassword            = () => checks.redisPassword(process.env);
const _checkProductionKeystorePath   = () => checks.productionKeystorePath(process.env, PROJECT_ROOT);
const _checkProductionKmsProvider    = () => checks.productionKmsProvider(process.env);

/**
 * Historical secret-subset runner (see header). In production — or with
 * exitOnError — any finding emits SECRET_VALIDATION_FATAL and exits 1;
 * otherwise findings are emitted as WARN.
 */
function runSecretValidation({ exitOnError } = {}) {
  const shouldExit = exitOnError === true || process.env.NODE_ENV === 'production';

  for (const finding of _checkProductionKmsProvider()) {
    emit('WARN', 'KMS_PROVIDER_ADVISORY', {
      finding,
      message: 'Advisory only — startup continues. See finding for migration guidance.',
    });
  }

  const allFindings = [
    ..._checkOpsToken(),
    ..._checkKek(),
    ..._checkExecutionInvariantSecret(),
    ..._checkOpenAiKey(),
    ..._checkClientId(),
    ..._checkRedisPassword(),
    ..._checkProductionKeystorePath(),
  ];

  if (allFindings.length === 0) {
    emit('INFO', 'SECRET_VALIDATION_OK', { message: 'All secret values passed startup validation.' });
    return;
  }

  emit(shouldExit ? 'FATAL' : 'WARN', shouldExit ? 'SECRET_VALIDATION_FATAL' : 'SECRET_VALIDATION_FAILED', {
    findingCount: allFindings.length,
    findings:     allFindings,
    message:      shouldExit
      ? 'One or more secrets are missing, empty, or appear to be placeholder values. ' +
        'The server cannot start in production with insecure secret configuration. ' +
        'See findings above for remediation instructions.'
      : 'One or more secrets appear to be placeholder values. ' +
        'These findings would prevent startup in production (NODE_ENV=production).',
  });

  if (shouldExit) process.exit(1);
}

module.exports = {
  runSecretValidation,
  // Exported for targeted unit testing — underscore prefix signals internal use.
  _checkProductionKeystorePath,
  _checkProductionKmsProvider,
  _checkOpsToken,
  _checkKek,
  _checkExecutionInvariantSecret,
  _checkOpenAiKey,
  _checkClientId,
  _checkRedisPassword,
};
