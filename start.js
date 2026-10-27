'use strict';

/**
 * QODIQA production entry point.
 *
 * Initialises the configured KMS provider and injects the Key Encryption Key
 * (KEK) into secretsProvider's in-memory cache BEFORE server.js's startup
 * validation runs. keyStore.js's own bootstrap (reading the KEK from
 * secretsProvider) is lazy — it runs on the first real key-store operation,
 * inside keyManager.validateStartup() — but wiring the KEK here, before
 * server.js is even required, keeps this entry point simple to reason about
 * and guarantees the injected KEK is in place well before that first use.
 *
 * For the local provider (QODIQA_KMS_PROVIDER unset or "local") the KEK is
 * read from QODIQA_KEY_ENCRYPTION_KEY, which may itself be injected by
 * Kubernetes Secrets, AWS Secrets Manager, or any other runtime mechanism.
 *
 * For external providers the factory performs an async network call to fetch
 * the KEK before any key-store code runs:
 *
 *   QODIQA_KMS_PROVIDER=vault-kv      → HashiCorp Vault KV v2
 *   QODIQA_KMS_PROVIDER=vault-transit → Vault Transit (native signing)
 *   QODIQA_KMS_PROVIDER=aws-kms       → AWS KMS data-key wrapping
 *   QODIQA_KMS_PROVIDER=azure-kv      → Azure Key Vault key wrapping
 *   QODIQA_KMS_PROVIDER=gcp-kms       → Google Cloud KMS wrapping
 *   QODIQA_KMS_PROVIDER=hsm           → PKCS#11 HSM native signing
 *   QODIQA_KMS_PROVIDER=local         → env var KEK (default)
 *
 * Usage:
 *   node start.js                          # local provider (development)
 *   QODIQA_KMS_PROVIDER=vault-kv node start.js
 *   QODIQA_KMS_PROVIDER=aws-kms  node start.js
 *
 * also bootstraps the application-config secrets provider
 * (QODIQA_CONFIG_SECRETS_PROVIDER — default "env", no-op) and applies its
 * output to process.env BEFORE server.js is required. This must happen here
 * and not inside server/startup.js: several managed secret names
 * (OPENAI_API_KEY et al. via services/providers/config.js;
 * ALERT_WEBHOOK_SECRET et al. via src/alerting/notification/channels/*.js)
 * are captured at MODULE-LOAD TIME the moment those modules are first
 * required — which happens partway through server/startup.js, itself
 * required synchronously by server.js. See
 * src/infra/configSecrets/configSecretsFactory.js's header comment.
 */

(async () => {
  // ── 1-2. Initialise KMS provider + inject KEK into secretsProvider cache ────
  // Extracted into keyProviderFactory.bootstrapOrExit() (items 21/22) so this
  // exact sequence — same stderr messages, same exit(1) — is shared with
  // server.js's own Finding-D entrypoint gate instead of living in two
  // places that could drift. Must happen before keyStore's first real
  // operation (inside keyManager.validateStartup(), during server.js
  // startup), so it happens here, before server.js is even required.
  const kpf = require('./src/infra/keys/keyProviderFactory');
  await kpf.bootstrapOrExit();

  // ── 2b. bootstrap application-config secrets, apply to process.env ────
  // Must run before server.js is required (see header comment above).
  const csf = require('./src/infra/configSecrets/configSecretsFactory');
  await csf.bootstrapOrExit();

  // ── 3. Load server.js — keyStore's lazy bootstrap runs during its startup
  //    validation (keyManager.validateStartup()), using the injected KEK ─────
  let startServer;
  try {
    startServer = require('./server.js').startServer;
  } catch (err) {
    process.stderr.write(
      `[FATAL] Failed to load server.js: ${err.message}\n`,
    );
    process.exit(1);
  }

  if (typeof startServer !== 'function') {
    process.stderr.write(
      '[FATAL] server.js did not export startServer — cannot start the server.\n',
    );
    process.exit(1);
  }

  // ── 4. Start accepting traffic ───────────────────────────────────────────────
  await startServer();
})().catch(err => {
  process.stderr.write(`[FATAL] Unhandled startup error: ${err.message}\n`);
  process.exit(1);
});
