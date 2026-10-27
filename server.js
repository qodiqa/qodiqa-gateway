'use strict';

// QODIQA gateway entrypoint.
//
// Coordinates composition and startup — nothing else. Middleware wiring and
// route mounting live in src/app.js; dependency initialization and the
// startup sequence live in server/startup.js.
//
// Finding D (items 21/22 — see audit/remediation/ITEM-21-22-REMEDIATION-
// REPORT.md): previously this file required ./server/startup unconditionally
// and synchronously, which meant `npm start`/`node server.js` — the
// documented, actual way this app is started — never initialized the
// KMS/Vault provider selected via QODIQA_KMS_PROVIDER at all; only
// `node start.js` did. Setting QODIQA_KMS_PROVIDER=aws-kms and running
// `npm start` silently booted against the local env-var KEK instead.
//
// Fixed by branching BEFORE requiring anything:
//   - QODIQA_KMS_PROVIDER unset/"local", OR keyProviderFactory.isInitialized()
//     already true (start.js already ran its own bootstrap before requiring
//     this file) — take the exact same synchronous path as before this fix.
//     keyProviderFactory.initialize() is async even for "local" (no real I/O,
//     but still Promise-returning), and CommonJS cannot top-level-await it
//     ahead of a synchronous require('./server/startup') — so the only way to
//     guarantee true byte-identical behavior on this, the default and by far
//     most heavily exercised path, is to not run that code at all. See the
//     lock-in test: src/infra/keys/__tests__/serverEntrypointGate.lockin.test.js.
//   - Otherwise (a non-local provider, and nothing has wired it yet — i.e.
//     `node server.js` run directly) — call the SAME
//     keyProviderFactory.bootstrapOrExit() helper start.js uses (zero
//     duplicated logic) before requiring server/startup, so the KEK is wired
//     exactly as start.js already guarantees for its own callers.
//
// Export shape for existing consumers (start.js,
// test/harness/shutdownIpcWrapper.js) is preserved ONLY on the
// default/already-initialized path: module.exports is the Express app
// itself, with .app and .startServer attached. On the new non-local,
// not-yet-initialized branch, module.exports is a Promise resolving to that
// same shape — reachable only via `node server.js` run directly with a
// cloud/Vault provider selected, a combination neither of those two existing
// consumers exercises today (start.js always initializes first; the test
// harness always runs with the default local provider).

const { emit } = require('./services/logger');
const kpf = require('./src/infra/keys/keyProviderFactory');
const csf = require('./src/infra/configSecrets/configSecretsFactory');

function _buildApp() {
  const { ctx, startServer: _startServer } = require('./server/startup');
  const { createApp } = require('./src/app');
  const app = createApp(ctx);
  function startServer() {
    return _startServer(app);
  }
  app.app = app;
  app.startServer = startServer;
  return app;
}

function _handleFatalStartup(err) {
  emit('FATAL', 'SERVER_STARTUP_FAILED', { message: err.message });
  process.exit(1);
}

const _kmsProvider           = process.env.QODIQA_KMS_PROVIDER || 'local';
const _configSecretsProvider = process.env.QODIQA_CONFIG_SECRETS_PROVIDER || 'env';

// the same Finding-D reasoning now applies to the config-secrets
// provider — `node server.js`/`npm start` run directly must not silently
// skip QODIQA_CONFIG_SECRETS_PROVIDER any more than it may skip
// QODIQA_KMS_PROVIDER. Each bootstrap is independently gated (a deployment
// may use a non-local KMS provider with the default "env" config-secrets
// provider, or vice versa) so neither is invoked unless it is actually
// needed — this keeps the default-path lock-in test's exact call-count
// assertions on keyProviderFactory unaffected.
const _needsKmsProviderBootstrap    = _kmsProvider !== 'local' && !kpf.isInitialized();
const _needsConfigSecretsBootstrap  = _configSecretsProvider !== 'env' && !csf.isInitialized();

if (!_needsKmsProviderBootstrap && !_needsConfigSecretsBootstrap) {
  // ── Default path — unchanged ────────────────────────────────────────────
  module.exports = _buildApp();

  if (require.main === module) {
    module.exports.startServer().catch(_handleFatalStartup);
  }
} else {
  // ── Finding D fix (KMS) + (config secrets) ─────────────────────────
  // Config secrets bootstrap runs BEFORE _buildApp() for the same reason it
  // must run before requiring server.js at all in start.js: _buildApp()
  // requires server/startup.js, which transitively requires
  // services/providers/config.js and src/alerting — both capture several
  // managed secret names at module-load time.
  async function _bootstrapAndBuildApp() {
    if (_needsKmsProviderBootstrap)   await kpf.bootstrapOrExit();
    if (_needsConfigSecretsBootstrap) await csf.bootstrapOrExit();
    return _buildApp();
  }

  module.exports = _bootstrapAndBuildApp();

  if (require.main === module) {
    module.exports.then(app => app.startServer()).catch(_handleFatalStartup);
  }
}
