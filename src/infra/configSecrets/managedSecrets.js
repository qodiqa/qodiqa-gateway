'use strict';

/**
 * Managed application-config secrets.
 *
 * This is the fixed whitelist of environment variable names the config-secrets
 * provider (configSecretsFactory.js) is responsible for. It intentionally does
 * NOT include:
 *
 *   - QODIQA_KEY_ENCRYPTION_KEY / QODIQA_EXECUTION_INVARIANT_SECRET — these are
 *     cryptographic key material owned by src/infra/keys/keyProviderFactory.js
 *     and services/secrets/secretsProvider.js. Duplicating their retrieval here
 *     would blur the KMS/key-provider boundary this module is deliberately kept
 *     separate from.
 *   - QODIQA_CLIENT_ID — not a secret (documented in docs/security/secrets-management.md:
 *     "appears in artifact headers and audit logs in plaintext").
 *   - VAULT_ADDR / VAULT_TOKEN / VAULT_ROLE_ID / VAULT_SECRET_ID / VAULT_NAMESPACE /
 *     VAULT_TLS_CA_CERT — these are the credentials USED TO REACH the secrets
 *     manager itself; a secrets manager cannot supply its own connection
 *     bootstrap credentials (the same chicken-and-egg reason cloud KMS
 *     providers rely on ambient IAM credentials rather than fetching their own).
 *   - HF_TOKEN — present in local .env for developer tooling (Hugging Face
 *     model downloads during eval/fine-tune work) but never read by the QODIQA
 *     application process (`process.env.HF_TOKEN` does not appear anywhere
 *     under src/, services/, server/, server.js, start.js) — out of scope for
 *     an *application config* secrets provider.
 *
 * Each entry's `required` field describes whether the underlying subsystem
 * already fails closed on this being absent — it is documentation, not logic
 * this module enforces itself. configSecretsFactory.js deliberately does NOT
 * re-implement per-variable requiredness (that would duplicate validation
 * src/infra/config/bootValidator.js, src/infra/secrets/secretValidation.js,
 * services/providers/config.js, and src/infra/postgres/pool.js already own).
 * Its only job is: when the production provider is active, a name in this
 * list resolves EXCLUSIVELY from the secrets manager — present or absent,
 * never silently patched from a stray .env/process.env value. Downstream,
 * the EXISTING fail-closed checks in those modules take it from there.
 */

const MANAGED_CONFIG_SECRETS = Object.freeze([
  // ── Redis ──────────────────────────────────────────────────────────────────
  { name: 'REDIS_PASSWORD',              required: false, purpose: 'Redis ACL authentication' },
  { name: 'REDIS_USERNAME',              required: false, purpose: 'Redis ACL username' },

  // ── PostgreSQL ─────────────────────────────────────────────────────────────
  { name: 'QODIQA_PG_PASSWORD',          required: false, purpose: 'qodiqa_app role password (required when QODIQA_PG_ENABLED=true)' },
  // QODIQA_PG_MIG_PASSWORD is deliberately NOT managed here — this provider feeds the GATEWAY, which
  // never uses the migration credential (only the separate migration job does) and refuses it in production.
  { name: 'QODIQA_PG_RETENTION_PASSWORD', required: false, purpose: 'qodiqa_retention role password' },

  // ── AI provider credentials ────────────────────────────────────────────────
  { name: 'OPENAI_API_KEY',              required: false, purpose: 'OpenAI provider authentication' },
  { name: 'ANTHROPIC_API_KEY',           required: false, purpose: 'Anthropic provider authentication' },
  { name: 'GEMINI_API_KEY',              required: false, purpose: 'Gemini provider authentication' },
  { name: 'MISTRAL_API_KEY',             required: false, purpose: 'Mistral provider authentication' },
  { name: 'LLAMA_API_KEY',               required: false, purpose: 'Llama-compatible provider authentication (optional alongside LLAMA_BASE_URL)' },
  { name: 'LOCAL_API_KEY',               required: false, purpose: 'Local/Ollama-compatible provider authentication (optional alongside LOCAL_BASE_URL)' },

  // ── Operational / admin ────────────────────────────────────────────────────
  { name: 'QODIQA_OPS_TOKEN',            required: false, purpose: 'Legacy shared ops bearer token (deprecated in favor of per-operator RBAC API keys)' },

  // ── Alerting / notification channels (MON-3) ──────────────────────────────
  // NOTE: five of these (WEBHOOK_SECRET, SIEM_TOKEN, PAGERDUTY_ROUTING_KEY,
  // SLACK_WEBHOOK_URL, TEAMS_WEBHOOK_URL) are captured at MODULE-LOAD TIME by
  // src/alerting/notification/channels/*.js and src/alerting/notification/
  // NotificationService.js the moment server/startup.js's `require('../src/
  // alerting')` runs — configSecretsFactory.apply() MUST complete before that
  // require executes (see start.js / server.js wiring), or these five would
  // freeze at their pre-injection value for the process lifetime.
  { name: 'ALERT_WEBHOOK_SECRET',        required: false, purpose: 'HMAC signing secret for the generic outbound alert webhook' },
  { name: 'ALERT_SIEM_TOKEN',            required: false, purpose: 'Splunk HEC bearer token for SIEM alert forwarding' },
  { name: 'ALERT_PAGERDUTY_ROUTING_KEY', required: false, purpose: 'PagerDuty Events API v2 routing key' },
  { name: 'ALERT_SLACK_WEBHOOK_URL',     required: false, purpose: 'Slack incoming webhook URL (embeds a bearer-token-like path segment)' },
  { name: 'ALERT_TEAMS_WEBHOOK_URL',     required: false, purpose: 'Microsoft Teams incoming webhook URL (embeds a bearer-token-like path segment)' },
  { name: 'ALERT_SMS_TWILIO_AUTH_TOKEN', required: false, purpose: 'Twilio auth token for SMS alert delivery' },
  { name: 'ALERT_EMAIL_SMTP_PASS',       required: false, purpose: 'SMTP relay password for email alert delivery' },
  { name: 'ALERT_EMAIL_SENDGRID_API_KEY', required: false, purpose: 'SendGrid API key for email alert delivery' },
  { name: 'ALERT_EMAIL_MAILGUN_API_KEY', required: false, purpose: 'Mailgun API key for email alert delivery' },

  // ── Log shipping / SIEM export ───────────────────────────────────
  { name: 'QODIQA_LOGSHIP_DATADOG_API_KEY', required: false, purpose: 'Datadog Logs API key for bulk audit-log export' },
  { name: 'QODIQA_LOGSHIP_SPLUNK_TOKEN', required: false, purpose: 'Splunk HEC token for bulk audit-log export' },
  { name: 'QODIQA_LOGSHIP_SIEM_TOKEN',   required: false, purpose: 'Generic SIEM HEC token for bulk audit-log export (falls back to ALERT_SIEM_TOKEN when unset)' },

  // ── DSR / GDPR erasure ─────────────────────────────────────────────────────
  { name: 'QODIQA_DSR_PSEUDONYM_PEPPER', required: false, purpose: 'HMAC pepper used to pseudonymize erased actor IDs (src/core/dsr/ErasureService.js)' },

  // ── Tenant self-service portal / OIDC SSO ──────────────────────────
  // Same class as QODIQA_DSR_PSEUDONYM_PEPPER above (an HMAC signing/
  // application-authentication secret) rather than KEK-class cryptographic
  // material owned by services/secrets/secretsProvider.js — see
  // services/portal/portalSessionToken.js's header comment.
  { name: 'QODIQA_OIDC_CLIENT_SECRET',   required: false, purpose: 'OIDC confidential-client secret for the tenant portal SSO flow (src/core/portal/oidcClient.js)' },
  { name: 'QODIQA_PORTAL_SESSION_SECRET', required: false, purpose: 'HMAC signing key for tenant-portal session tokens (services/portal/portalSessionToken.js)' },
]);

// Read only by standalone bash scripts OUTSIDE the Node process (scripts/pg-
// backup.sh, scripts/pg-wal-archive.sh, scripts/backup-audit-log.sh via shell
// parameter expansion) — never by `process.env` inside server.js/start.js.
// Injecting it into this Node process's process.env would have no effect on
// those scripts, so it is deliberately NOT a managed name here. Documented in
// docs/security/secrets-management.md as an follow-up: inject via the orchestrator's
// own secret mechanism (Kubernetes Secret env, `vault kv get` wrapper, etc.)
// at the point those scripts are invoked.
const UNREACHABLE_FROM_NODE_PROCESS = Object.freeze(['QODIQA_BACKUP_HMAC_KEY']);

const MANAGED_CONFIG_SECRET_NAMES = Object.freeze(MANAGED_CONFIG_SECRETS.map(s => s.name));

const _NAME_SET = new Set(MANAGED_CONFIG_SECRET_NAMES);

/** @returns {boolean} whether `name` is a managed application-config secret. */
function isManagedConfigSecret(name) {
  return _NAME_SET.has(name);
}

module.exports = {
  MANAGED_CONFIG_SECRETS,
  MANAGED_CONFIG_SECRET_NAMES,
  isManagedConfigSecret,
  UNREACHABLE_FROM_NODE_PROCESS,
};
