'use strict';

// step 5 — exhaustive boot matrix for src/infra/config/bootValidator.js
//.
//
// Every case is run in all three profiles against a VALID base environment for
// that profile, and asserts the exact outcome per profile: fatal (refuses to
// boot), warn (boots, reported), or none — with the exact operator-facing
// message. A fatal case also asserts it is the ONLY fatal, so each test proves
// one rule, not an accident of the fixture.

const os = require('os');
const path = require('path');
const crypto = require('crypto');

const {
  validateBoot, runBootValidation, configFingerprint, SEM_FORBIDDEN_IN_PROD, SEM_GATE_DEFAULTS, SEM_ALLOWED, PROJECT_ROOT,
} = require('./bootValidator');
const { PROVIDER_FIXTURE_KEYS } = require('../../../test/helpers/providerFixtureKeys');

const hex = () => crypto.randomBytes(32).toString('hex');
const OUTSIDE_KEYS = path.join(os.tmpdir(), 'qodiqa-w2-matrix', 'keys.json');
// production requires a provisioned MAC keyring; the validator checks
// only that the file exists, so an empty placeholder file stands in for it.
const MAC_RING = path.join(os.tmpdir(), 'qodiqa-w2-matrix', 'mac-keys.json');
require('fs').mkdirSync(path.dirname(MAC_RING), { recursive: true });
if (!require('fs').existsSync(MAC_RING)) require('fs').writeFileSync(MAC_RING, '{}');
// production requires audit anchoring — a witness key + public-key file held outside the key store, and an
// anchor export path.
const WITNESS_DIR = path.join(os.tmpdir(), 'qodiqa-w2-witness'); // NOT inside the key store's directory
require('fs').mkdirSync(WITNESS_DIR, { recursive: true });
for (const f of ['witness-key.pem', 'witness-public-keys.json']) { const fp = path.join(WITNESS_DIR, f); if (!require('fs').existsSync(fp)) require('fs').writeFileSync(fp, f.endsWith('.json') ? '[]' : ''); }
const ANCHORING = {
  QODIQA_ANCHOR_EXPORT_PATH: path.join(WITNESS_DIR, 'anchors.jsonl'),
  QODIQA_WITNESS_MODE: 'local',
  QODIQA_WITNESS_KEY_PATH: path.join(WITNESS_DIR, 'witness-key.pem'),
  QODIQA_WITNESS_LOG_PATH: path.join(WITNESS_DIR, 'witness-log.jsonl'),
  QODIQA_WITNESS_PUBLIC_KEYS: path.join(WITNESS_DIR, 'witness-public-keys.json'),
};
const GEN = 'Generate a cryptographically random value: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"';

const PROFILE_NODE_ENV = { prod: 'production', dev: 'development', test: 'test' };

function base(profile) {
  const env = {
    NODE_ENV: PROFILE_NODE_ENV[profile],
    QODIQA_KEY_ENCRYPTION_KEY: hex(),
    QODIQA_EXECUTION_INVARIANT_SECRET: hex(),
    QODIQA_CLIENT_ID: 'w2-matrix-client',
    LOCAL_BASE_URL: 'http://127.0.0.1:11434/v1',
  };
  if (profile === 'prod') {
    Object.assign(env, {
      QODIQA_KEYS_PATH: OUTSIDE_KEYS,
      POLICY_FILE: path.join(PROJECT_ROOT, 'deploy/env/production.policies.example'),
      QODIQA_DSR_PSEUDONYM_PEPPER: hex(),
      QODIQA_MAC_KEYS_PATH: MAC_RING, // replaces REVOCATION_/ORG_STATUS_SIGNING_KEY
      RL_ENABLED: 'true',
      REDIS_URL: 'rediss://redis.internal:6380',
      QODIQA_KMS_PROVIDER: 'aws-kms',
      // production also requires every other key file outside the application directory
      QODIQA_TRANSPARENCY_KEYS_PATH: path.join(path.dirname(OUTSIDE_KEYS), 'transparency-keys.json'),
      AWS_KMS_EDK_PATH: path.join(path.dirname(OUTSIDE_KEYS), 'kek.edk'),
      // the transparency/persistence file journal on a persistent volume outside the application directory
      QODIQA_PRQ_JOURNAL_DIR: path.join(path.dirname(OUTSIDE_KEYS), 'prq-journal'),
      ...ANCHORING,
    });
  }
  return env;
}

// Base environments must be clean, or every "only this fatal" assertion below is meaningless.
describe('valid base environment per profile', () => {
  test('production base: no fatal, no warning', () => {
    const r = validateBoot(base('prod'));
    expect(r.fatal).toEqual([]);
    expect(r.warnings).toEqual([]);
    expect(r.profile).toBe('prod');
    expect(r.resolved).toMatchObject({ providers: ['local'], pgEnabled: false, redisTls: true,
      rateLimit: { enabled: true, hasRedisUrl: true }, planes: { adminEnabled: false, diagnosticsEnabled: false } });
  });

  test.each(['dev', 'test'])('%s base: no fatal; the documented non-production warnings only', (p) => {
    const r = validateBoot(base(p));
    expect(r.fatal).toEqual([]);
    expect(r.warnings.map((w) => w.variable).sort()).toEqual(
      ['QODIQA_DSR_PSEUDONYM_PEPPER', 'REDIS_URL']); // the pub/sub env keys are no longer required anywhere
    expect(r.resolved.planes).toEqual({ adminEnabled: true, diagnosticsEnabled: true });
  });
});

// ── Profile resolution (D-A) ───────────────────────────────────────────────────
describe('profile resolution — D-A: NODE_ENV must be exactly one of three values', () => {
  const cases = [
    ['unset', undefined, "NODE_ENV: is not set; set it to exactly 'production', 'development' or 'test'"],
    ['empty', '', "NODE_ENV: is not set; set it to exactly 'production', 'development' or 'test'"],
    ['prod', 'prod', "NODE_ENV: is 'prod'; only exactly 'production', 'development' or 'test' is accepted"],
    ['Production', 'Production', "NODE_ENV: is 'Production'; only exactly 'production', 'development' or 'test' is accepted"],
    ['staging', 'staging', "NODE_ENV: is 'staging'; only exactly 'production', 'development' or 'test' is accepted"],
    ['padded', ' production', "NODE_ENV: is ' production'; only exactly 'production', 'development' or 'test' is accepted"],
  ];
  test.each(cases)('NODE_ENV %s → refuses, exact message, no other rule evaluated', (_n, value, message) => {
    const env = base('prod');
    if (value === undefined) delete env.NODE_ENV; else env.NODE_ENV = value;
    const r = validateBoot(env);
    expect(r.profile).toBeNull();
    expect(r.resolved).toBeNull();
    expect(r.fatal).toEqual([{ variable: 'NODE_ENV', rule: 'profile', message }]);
  });

  test.each(Object.entries(PROFILE_NODE_ENV))('%s ← NODE_ENV=%s', (profile, nodeEnv) => {
    expect(validateBoot({ ...base(profile), NODE_ENV: nodeEnv }).profile).toBe(profile);
  });
});

// ── The matrix ────────────────────────────────────────────────────────────────
// [name, mutate(env, profile), { prod, dev, test }] where each outcome is
// null (no finding for `variable`) or [severity, variable, exact message].
const F = (variable, message) => ['fatal', variable, message];
const W = (variable, message) => ['warn', variable, message];
const all = (o) => ({ prod: o, dev: o, test: o });
const prodOnly = (o) => ({ prod: o, dev: null, test: null });
const prodFatalElseWarn = (variable, message) => ({ prod: F(variable, message), dev: W(variable, message), test: W(variable, message) });

const MATRIX = [
  // 2. Secrets — KEK
  ['KEK missing', (e) => { delete e.QODIQA_KEY_ENCRYPTION_KEY; },
    all(F('QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_KEY_ENCRYPTION_KEY: is required (64 hex characters)'))],
  ['KEK not 64 hex', (e) => { e.QODIQA_KEY_ENCRYPTION_KEY = 'g'.repeat(64); },
    all(F('QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_KEY_ENCRYPTION_KEY: must be exactly 64 hex characters'))],
  ['KEK all zeros', (e) => { e.QODIQA_KEY_ENCRYPTION_KEY = '0'.repeat(64); },
    prodFatalElseWarn('QODIQA_KEY_ENCRYPTION_KEY', `QODIQA_KEY_ENCRYPTION_KEY is all zeros — this is the null key and provides no encryption protection. ${GEN}`)],
  ['KEK all F', (e) => { e.QODIQA_KEY_ENCRYPTION_KEY = 'f'.repeat(64); },
    prodFatalElseWarn('QODIQA_KEY_ENCRYPTION_KEY', `QODIQA_KEY_ENCRYPTION_KEY is a repeating single-character pattern (e.g. all-zeros or all-F's). This is a test/placeholder value and must not be used in production. ${GEN}`)],
  ['KEK 2-char pattern', (e) => { e.QODIQA_KEY_ENCRYPTION_KEY = 'ab'.repeat(32); },
    prodFatalElseWarn('QODIQA_KEY_ENCRYPTION_KEY', `QODIQA_KEY_ENCRYPTION_KEY appears to repeat a 2-character byte pattern. This suggests a test or placeholder value. ${GEN}`)],
  // Invariant secret — fatal presence/shape in EVERY profile
  ['invariant secret missing', (e) => { delete e.QODIQA_EXECUTION_INVARIANT_SECRET; },
    all(F('QODIQA_EXECUTION_INVARIANT_SECRET', 'QODIQA_EXECUTION_INVARIANT_SECRET: is required (64 hex characters); it is verified at boot so no request can consume its nonce and then fail'))],
  ['invariant secret empty', (e) => { e.QODIQA_EXECUTION_INVARIANT_SECRET = ''; },
    all(F('QODIQA_EXECUTION_INVARIANT_SECRET', 'QODIQA_EXECUTION_INVARIANT_SECRET: is required (64 hex characters); it is verified at boot so no request can consume its nonce and then fail'))],
  ['invariant secret short', (e) => { e.QODIQA_EXECUTION_INVARIANT_SECRET = 'abc123'; },
    all(F('QODIQA_EXECUTION_INVARIANT_SECRET', 'QODIQA_EXECUTION_INVARIANT_SECRET: must be exactly 64 hex characters'))],
  ['invariant secret repeated', (e) => { e.QODIQA_EXECUTION_INVARIANT_SECRET = 'e'.repeat(64); },
    prodFatalElseWarn('QODIQA_EXECUTION_INVARIANT_SECRET', `QODIQA_EXECUTION_INVARIANT_SECRET is a repeating single-character pattern (e.g. all-zeros or all-F's). This is a test/placeholder value and must not be used in production. ${GEN}`)],
  ['invariant secret equals KEK', (e) => { e.QODIQA_EXECUTION_INVARIANT_SECRET = e.QODIQA_KEY_ENCRYPTION_KEY.toUpperCase(); },
    prodFatalElseWarn('QODIQA_EXECUTION_INVARIANT_SECRET', `QODIQA_EXECUTION_INVARIANT_SECRET must not be identical to QODIQA_KEY_ENCRYPTION_KEY. These are independent secrets protecting different security boundaries — ${GEN}`)],
  // Client id
  ['client id missing', (e) => { delete e.QODIQA_CLIENT_ID; },
    all(F('QODIQA_CLIENT_ID', 'QODIQA_CLIENT_ID: is required (default client identifier for transparency, compliance and certification signing)'))],
  ['client id placeholder', (e) => { e.QODIQA_CLIENT_ID = 'Demo'; },
    prodFatalElseWarn('QODIQA_CLIENT_ID', 'QODIQA_CLIENT_ID is a known placeholder identifier and must not be used in production. Set this to a meaningful, unique identifier for this deployment.')],
  ['client id left as an example-file placeholder', (e) => { e.QODIQA_CLIENT_ID = '<REPLACE_WITH_MEANINGFUL_DEPLOYMENT_IDENTIFIER>'; },
    prodFatalElseWarn('QODIQA_CLIENT_ID', 'QODIQA_CLIENT_ID is a known placeholder identifier and must not be used in production. Set this to a meaningful, unique identifier for this deployment.')],
  // Ops token
  ['admin plane on without ops token', (e) => { e.QODIQA_ADMIN_ENABLED = 'true'; },
    prodOnly(F('QODIQA_OPS_TOKEN', 'QODIQA_OPS_TOKEN: is required while QODIQA_ADMIN_ENABLED or QODIQA_DIAGNOSTICS_ENABLED is true'))],
  ['diagnostics plane on without ops token', (e) => { e.QODIQA_DIAGNOSTICS_ENABLED = 'true'; },
    prodOnly(F('QODIQA_OPS_TOKEN', 'QODIQA_OPS_TOKEN: is required while QODIQA_ADMIN_ENABLED or QODIQA_DIAGNOSTICS_ENABLED is true'))],
  ['ops token too short', (e) => { e['QODIQA_OPS_TOKEN'] = 'k3Q9x'; },
    prodFatalElseWarn('QODIQA_OPS_TOKEN', `QODIQA_OPS_TOKEN is only 5 character(s). A minimum of 32 characters is required for production use. ${GEN}`)],
  ['ops token placeholder', (e) => { e['QODIQA_OPS_TOKEN'] = 'changeme-changeme-changeme-changeme'; },
    prodFatalElseWarn('QODIQA_OPS_TOKEN', `QODIQA_OPS_TOKEN is a known placeholder or example value and must not be used in production. ${GEN}`)],
  // Redis password
  ['redis password placeholder', (e) => { e['REDIS_PASSWORD'] = 'changeme'; },
    prodFatalElseWarn('REDIS_PASSWORD', 'REDIS_PASSWORD is a known placeholder value and must not be used in production. Set a strong, randomly generated Redis password.')],
  ['redis password short', (e) => { e['REDIS_PASSWORD'] = 'Zq81mPx'; },
    prodFatalElseWarn('REDIS_PASSWORD', 'REDIS_PASSWORD is only 7 character(s). A minimum of 16 characters is required for production Redis authentication.')],
  // PostgreSQL role passwords
  ['PG enabled, app password missing', (e) => { e.QODIQA_PG_ENABLED = 'true'; e.QODIQA_PG_RETENTION_PASSWORD = hex(); e.QODIQA_PG_SYSTEM_PASSWORD = hex(); e.QODIQA_PG_REPORTING_PASSWORD = hex(); e.QODIQA_PG_CONTROL_PASSWORD = hex(); },
    all(F('QODIQA_PG_PASSWORD', 'QODIQA_PG_PASSWORD: is required while QODIQA_PG_ENABLED=true'))],
  ['PG enabled, app password short', (e) => { e.QODIQA_PG_ENABLED = 'true'; e['QODIQA_PG_PASSWORD'] = 'Kq7-zP2m'; e.QODIQA_PG_RETENTION_PASSWORD = hex(); e.QODIQA_PG_SYSTEM_PASSWORD = hex(); e.QODIQA_PG_REPORTING_PASSWORD = hex(); e.QODIQA_PG_CONTROL_PASSWORD = hex(); },
    prodOnly(F('QODIQA_PG_PASSWORD', 'QODIQA_PG_PASSWORD: is shorter than the required minimum length'))],
  ['PG enabled, app password placeholder', (e) => { e.QODIQA_PG_ENABLED = 'true'; e['QODIQA_PG_PASSWORD'] = 'REPLACE_WITH_VAULT_SECRET_APP'; e.QODIQA_PG_RETENTION_PASSWORD = hex(); e.QODIQA_PG_SYSTEM_PASSWORD = hex(); e.QODIQA_PG_REPORTING_PASSWORD = hex(); e.QODIQA_PG_CONTROL_PASSWORD = hex(); },
    prodFatalElseWarn('QODIQA_PG_PASSWORD', 'QODIQA_PG_PASSWORD: is a placeholder or example value')],
  // Portal / OIDC
  ['portal enabled without session secret', (e) => { e.QODIQA_PORTAL_ENABLED = 'true'; },
    prodFatalElseWarn('QODIQA_PORTAL_SESSION_SECRET', 'QODIQA_PORTAL_SESSION_SECRET: is required while the portal/OIDC feature is enabled')],
  ['OIDC issuer without client secret', (e) => { e.QODIQA_OIDC_ISSUER = 'https://idp.example.org'; },
    prodFatalElseWarn('QODIQA_OIDC_CLIENT_SECRET', 'QODIQA_OIDC_CLIENT_SECRET: is required while the portal/OIDC feature is enabled')],
  // DSR pepper / pub-sub signing (D-C)
  ['DSR pepper weak', (e) => { e.QODIQA_DSR_PSEUDONYM_PEPPER = 'x'.repeat(40); },
    prodOnly(F('QODIQA_DSR_PSEUDONYM_PEPPER', 'QODIQA_DSR_PSEUDONYM_PEPPER: is a single repeated character (a test/placeholder value)'))],
  // pub/sub + consent-cache signing uses the keystore MAC keyring
  ['deprecated revocation signing key still set', (e) => { e.REVOCATION_SIGNING_KEY = hex(); },
    all(W('REVOCATION_SIGNING_KEY', 'REVOCATION_SIGNING_KEY: is deprecated and ignored: pub/sub messages are signed with the keystore MAC keyring'))],
  ['MAC keyring not provisioned', (e) => { e.QODIQA_MAC_KEYS_PATH = path.join(os.tmpdir(), 'qodiqa-w2-matrix', 'absent-mac-keys.json'); },
    prodOnly(F('QODIQA_MAC_KEYS_PATH', `QODIQA_MAC_KEYS_PATH: MAC keyring not found at ${path.join(os.tmpdir(), 'qodiqa-w2-matrix', 'absent-mac-keys.json')}: provision it once (node scripts/security/macKeyring.js init) and share it with every node like the signing keystore — production never generates one per node`))],
  // KMS / Vault
  ['vault KMS without token', (e) => { e.QODIQA_KMS_PROVIDER = 'vault-kv'; delete e.VAULT_TOKEN; },
    all(F('VAULT_TOKEN', 'VAULT_TOKEN: is required for QODIQA_KMS_PROVIDER=vault-kv'))],
  // AppRole is an accepted alternative to a static token; a placeholder secret id is refused.
  ['vault KMS with AppRole and no token', (e) => { e.QODIQA_KMS_PROVIDER = 'vault-kv'; delete e.VAULT_TOKEN; e.VAULT_ROLE_ID = 'qodiqa-kms-role'; e.VAULT_SECRET_ID = hex(); },
    all(null)],
  ['vault KMS with AppRole, placeholder secret id', (e) => { e.QODIQA_KMS_PROVIDER = 'vault-kv'; delete e.VAULT_TOKEN; e.VAULT_ROLE_ID = 'qodiqa-kms-role'; e.VAULT_SECRET_ID = 'REPLACE_WITH_VAULT_SECRET_ID'; },
    all(F('VAULT_SECRET_ID', 'VAULT_SECRET_ID: is a placeholder or example value'))],
  ['vault KMS with only a role id (no secret id, no token)', (e) => { e.QODIQA_KMS_PROVIDER = 'vault-kv'; delete e.VAULT_TOKEN; e.VAULT_ROLE_ID = 'qodiqa-kms-role'; },
    all(F('VAULT_TOKEN', 'VAULT_TOKEN: is required for QODIQA_KMS_PROVIDER=vault-kv'))],
  // Alert channel tokens
  ['alert channel token placeholder', (e) => { e['ALERT_SLACK_TOKEN'] = 'your-slack-token'; },
    prodFatalElseWarn('ALERT_SLACK_TOKEN', 'ALERT_SLACK_TOKEN: is a placeholder or example value')],
  // Dead variable
  ['dead QODIQA_SIGN_TOKEN', (e) => { e.QODIQA_SIGN_TOKEN = hex(); },
    all(W('QODIQA_SIGN_TOKEN', 'QODIQA_SIGN_TOKEN: is a dead variable (nothing reads it) — remove it from the environment'))],

  // 3. Providers (D-E)
  ['no provider at all', (e) => { delete e.LOCAL_BASE_URL; },
    all(F('(providers)', '(providers): no valid AI provider is configured (set a valid OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, MISTRAL_API_KEY, LLAMA_BASE_URL or LOCAL_BASE_URL)'))],
  ['OpenAI key placeholder beside a valid provider', (e) => { e.OPENAI_API_KEY = 'sk-test'; },
    prodFatalElseWarn('OPENAI_API_KEY', 'OPENAI_API_KEY: is a placeholder value; the openai provider is not enabled')],
  ['Local URL not http(s)', (e) => { e.OPENAI_API_KEY = PROVIDER_FIXTURE_KEYS.openai; e.LOCAL_BASE_URL = 'ftp://127.0.0.1/v1'; },
    prodFatalElseWarn('LOCAL_BASE_URL', 'LOCAL_BASE_URL: is not a valid http(s) URL; the local provider is not enabled')],
  ['Local URL plain http to a non-loopback host', (e) => { e.LOCAL_BASE_URL = 'http://llm.internal:11434/v1'; },
    prodOnly(W('LOCAL_BASE_URL', 'LOCAL_BASE_URL: uses plain http:// to a non-loopback host'))],

  // 4. Semantic guards — a sample of every class; the full lists are pinned below
  ['semantic threshold override', (e) => { e.QODIQA_SEM_C_SIMILARITY_THRESHOLD = '0.9'; },
    prodFatalElseWarn('QODIQA_SEM_C_SIMILARITY_THRESHOLD', 'QODIQA_SEM_C_SIMILARITY_THRESHOLD: overrides semantic enforcement (kill switch, classifier list, threshold or band) and is not permitted in production')],
  ['semantic kill switch', (e) => { e.QODIQA_SEMANTIC_POLICY_ENABLED = 'false'; },
    prodFatalElseWarn('QODIQA_SEMANTIC_POLICY_ENABLED', 'QODIQA_SEMANTIC_POLICY_ENABLED: overrides semantic enforcement (kill switch, classifier list, threshold or band) and is not permitted in production')],
  ['FT-3 gate switched off', (e) => { e.QODIQA_SEM_FT3_ENABLED = 'false'; },
    prodFatalElseWarn('QODIQA_SEM_FT3_ENABLED', 'QODIQA_SEM_FT3_ENABLED: changes the shipped semantic gate set (shipped default: true) and is not permitted in production; to run without the fine-tuned screening model set QODIQA_SEM_FT3_OFF_ACK=true as well')],
  ['embedding layer off', (e) => { e.QODIQA_SEM_EMBEDDING_ENABLED = 'false'; },
    prodFatalElseWarn('QODIQA_SEM_EMBEDDING_ENABLED', 'QODIQA_SEM_EMBEDDING_ENABLED: changes the shipped semantic gate set (shipped default: true) and is not permitted in production; to run without the embedding screening layer set QODIQA_SEM_EMBEDDING_OFF_ACK=true as well')],
  ['embedding layer off, acknowledged', (e) => { e.QODIQA_SEM_EMBEDDING_ENABLED = 'false'; e.QODIQA_SEM_EMBEDDING_OFF_ACK = 'true'; },
    all(W('QODIQA_SEM_EMBEDDING_ENABLED', 'QODIQA_SEM_EMBEDDING_ENABLED: the embedding screening layer is OFF by explicit acknowledgement (QODIQA_SEM_EMBEDDING_OFF_ACK=true): content screening is limited to the rule engine'))],
  ['FT-3 gate off, acknowledged', (e) => { e.QODIQA_SEM_FT3_ENABLED = 'false'; e.QODIQA_SEM_FT3_OFF_ACK = 'true'; },
    all(W('QODIQA_SEM_FT3_ENABLED', 'QODIQA_SEM_FT3_ENABLED: the fine-tuned screening gate is OFF by explicit acknowledgement (QODIQA_SEM_FT3_OFF_ACK=true): content screening is reduced to the base gates'))],
  ['acknowledgement alone changes nothing', (e) => { e.QODIQA_SEM_FT3_OFF_ACK = 'true'; }, all(null)],
  ['FT-2 gate switched on', (e) => { e.QODIQA_SEM_FT2_ENABLED = 'true'; },
    prodFatalElseWarn('QODIQA_SEM_FT2_ENABLED', 'QODIQA_SEM_FT2_ENABLED: changes the shipped semantic gate set (shipped default: false) and is not permitted in production')],
  ['FT-3 gate explicitly at its default', (e) => { e.QODIQA_SEM_FT3_ENABLED = 'true'; }, all(null)],
  ['tighten-only semantic knob', (e) => { e.QODIQA_SEM_TAIL_WINDOW_ENABLED = 'true'; }, all(null)],

  // 5. Rate limiting
  // the limiter is ON by default; RL_ENABLED=false is the only off
  // switch (same severity as before), and a missing REDIS_URL is reported on
  // REDIS_URL itself.
  ['rate limiter off', (e) => { e.RL_ENABLED = 'false'; },
    prodFatalElseWarn('RL_ENABLED', 'RL_ENABLED=false turns the HTTP rate limiter off (every route unthrottled)')],
  ['rate limiter on without Redis', (e) => { e.RL_ENABLED = 'true'; delete e.REDIS_URL; },
    prodFatalElseWarn('REDIS_URL', 'REDIS_URL is unset: the rate limiter (and nonce/lockout stores) would use the default redis://localhost:6379')],
  ['rate limiter default (RL_ENABLED unset) without Redis', (e) => { delete e.RL_ENABLED; delete e.REDIS_URL; },
    prodFatalElseWarn('REDIS_URL', 'REDIS_URL is unset: the rate limiter (and nonce/lockout stores) would use the default redis://localhost:6379')],

  // 6. Transport security
  ['PG TLS explicitly off with PG on', (e) => {
    Object.assign(e, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_SSL: 'false', QODIQA_PG_PASSWORD: hex(), QODIQA_PG_RETENTION_PASSWORD: hex(), QODIQA_PG_SYSTEM_PASSWORD: hex(), QODIQA_PG_REPORTING_PASSWORD: hex(), QODIQA_PG_CONTROL_PASSWORD: hex() });
  }, prodOnly(F('QODIQA_PG_SSL', 'QODIQA_PG_SSL: disables PostgreSQL TLS, which is not permitted in production'))],
  ['Redis plaintext', (e) => { e.RL_ENABLED = 'true'; e.REDIS_URL = 'redis://redis.internal:6379'; },
    prodOnly(F('REDIS_URL', 'REDIS_URL: is a plaintext Redis connection; production requires rediss:// or REDIS_TLS=true'))],
  ['Redis certificate verification off', (e) => { e.REDIS_TLS_REJECT_UNAUTHORIZED = 'false'; },
    prodFatalElseWarn('REDIS_TLS_REJECT_UNAUTHORIZED', 'REDIS_TLS_REJECT_UNAUTHORIZED: disables TLS certificate verification (man-in-the-middle)')],
  ['Redis client cert without key', (e) => { e.REDIS_TLS_CERT = __filename; },
    all(F('REDIS_TLS_CERT', 'REDIS_TLS_CERT and REDIS_TLS_KEY must both be set or both be unset'))],
  ['Redis URL wrong scheme', (e) => { e.RL_ENABLED = 'true'; e.REDIS_URL = 'http://redis.internal:6379'; },
    all(F('REDIS_URL', 'REDIS_URL: has an unsupported scheme (use redis:// or rediss://)'))],

  // 7. Planes
  ['portal dev auth', (e) => { e.QODIQA_PORTAL_DEV_AUTH_ENABLED = 'true'; },
    prodOnly(F('QODIQA_PORTAL_DEV_AUTH_ENABLED', 'QODIQA_PORTAL_DEV_AUTH_ENABLED: enables the tenant-portal development authentication stub, which is not permitted in production'))],

  // 8. Retained production rules
  ['POLICY_FILE missing', (e) => { delete e.POLICY_FILE; },
    prodOnly(F('POLICY_FILE', 'POLICY_FILE: is required in production (the repository policies.json is a development fixture; start from deploy/env/production.policies.example)'))],
  ['keystore path unset', (e) => { delete e.QODIQA_KEYS_PATH; },
    prodOnly(F('QODIQA_KEYS_PATH', 'QODIQA_KEYS_PATH is not set in production. The default path (data/keys.json) resolves inside the application directory, which is not acceptable for production key storage. Set QODIQA_KEYS_PATH to a path on a dedicated secret volume outside the application directory, e.g. /opt/qodiqa/data/keys.json. See deploy/env/production.env.example for the recommended configuration.'))],
  ['keystore inside the repository', (e) => { e.QODIQA_KEYS_PATH = path.join(PROJECT_ROOT, 'data', 'keys.json'); },
    prodOnly(F('QODIQA_KEYS_PATH', `QODIQA_KEYS_PATH resolves inside the application directory "${path.resolve(PROJECT_ROOT)}". Repository-resident keystores are not permitted in production. Set QODIQA_KEYS_PATH to a path on a dedicated secret volume outside the application directory, e.g. /opt/qodiqa/data/keys.json.`))],
  // every other key file, resolved the way its module resolves it
  ...(() => {
    const R = path.resolve(PROJECT_ROOT);
    const SV = 'Set it to a path on a dedicated secret volume outside the application directory (the same volume as QODIQA_KEYS_PATH, e.g. /opt/qodiqa/data/).';
    const inside = (v, what, p) => `${v} resolves inside the application directory "${R}" (${what}: ${path.resolve(p)}). Repository-resident key files are not permitted in production. ${SV}`;
    const unset = (v, what, dflt) => `${v} is not set in production (${what}). The default (${dflt} under the working directory) resolves inside the application directory, which is not acceptable for production key storage. ${SV}`;
    const inRepo = (f) => path.join(PROJECT_ROOT, 'data', f);
    const OUT_DIR = path.dirname(OUTSIDE_KEYS);
    return [
      ['transparency key path unset', (e) => { delete e.QODIQA_TRANSPARENCY_KEYS_PATH; },
        prodOnly(F('QODIQA_TRANSPARENCY_KEYS_PATH', `QODIQA_TRANSPARENCY_KEYS_PATH is not set in production (transparency key file; the audit-checkpoint key file defaults beside it). The default (data/transparency-keys.json in the application directory) resolves inside the application directory, which is not acceptable for production key storage. ${SV}`))],
      ['transparency key path inside the repository', (e) => { e.QODIQA_TRANSPARENCY_KEYS_PATH = inRepo('transparency-keys.json'); },
        prodOnly(F('QODIQA_TRANSPARENCY_KEYS_PATH', inside('QODIQA_TRANSPARENCY_KEYS_PATH', 'transparency key file', inRepo('transparency-keys.json'))))],
      ['checkpoint key path inside the repository', (e) => { e.QODIQA_CHECKPOINT_KEYS_PATH = inRepo('checkpoint-keys.json'); },
        prodOnly(F('QODIQA_CHECKPOINT_KEYS_PATH', inside('QODIQA_CHECKPOINT_KEYS_PATH', 'checkpoint key file', inRepo('checkpoint-keys.json'))))],
      ['key archive inside the repository', (e) => { e.QODIQA_KEYS_ARCHIVE_PATH = inRepo('key-archive.json'); },
        prodOnly(F('QODIQA_KEYS_ARCHIVE_PATH', inside('QODIQA_KEYS_ARCHIVE_PATH', 'retired-key archive', inRepo('key-archive.json'))))],
      ['MAC keyring inside the repository', (e) => { e.QODIQA_MAC_KEYS_PATH = inRepo('mac-keys.json'); },
        prodOnly(F('QODIQA_MAC_KEYS_PATH', inside('QODIQA_MAC_KEYS_PATH', 'MAC keyring', inRepo('mac-keys.json'))))],
      ['witness key inside the repository', (e) => { e.QODIQA_WITNESS_KEY_PATH = inRepo('witness-key.pem'); },
        prodOnly(F('QODIQA_WITNESS_KEY_PATH', inside('QODIQA_WITNESS_KEY_PATH', 'witness private key', inRepo('witness-key.pem'))))],
      ['aws-kms wrapped KEK path unset', (e) => { delete e.AWS_KMS_EDK_PATH; },
        prodOnly(F('AWS_KMS_EDK_PATH', unset('AWS_KMS_EDK_PATH', 'wrapped KEK for QODIQA_KMS_PROVIDER=aws-kms', 'data/kek.edk')))],
      ['aws-kms wrapped KEK inside the repository', (e) => { e.AWS_KMS_EDK_PATH = inRepo('kek.edk'); },
        prodOnly(F('AWS_KMS_EDK_PATH', inside('AWS_KMS_EDK_PATH', 'wrapped KEK for QODIQA_KMS_PROVIDER=aws-kms', inRepo('kek.edk'))))],
      ['gcp-kms wrapped KEK path unset', (e) => { e.QODIQA_KMS_PROVIDER = 'gcp-kms'; },
        prodOnly(F('GCP_WRAPPED_KEY_PATH', unset('GCP_WRAPPED_KEY_PATH', 'wrapped KEK for QODIQA_KMS_PROVIDER=gcp-kms', 'data/kek.gcp')))],
      ['azure-kv wrapped KEK inside the repository', (e) => { e.QODIQA_KMS_PROVIDER = 'azure-kv'; e.AZURE_WRAPPED_KEY_PATH = inRepo('kek.wk'); },
        prodOnly(F('AZURE_WRAPPED_KEY_PATH', inside('AZURE_WRAPPED_KEY_PATH', 'wrapped KEK for QODIQA_KMS_PROVIDER=azure-kv', inRepo('kek.wk'))))],
      ['vault-transit with a gcp-kms KEK and no wrapped-key path', (e) => { e.QODIQA_KMS_PROVIDER = 'vault-transit'; e.QODIQA_KMS_KEK_PROVIDER = 'gcp-kms'; e.VAULT_TOKEN = hex(); },
        prodOnly(F('GCP_WRAPPED_KEY_PATH', unset('GCP_WRAPPED_KEY_PATH', 'wrapped KEK for QODIQA_KMS_PROVIDER=vault-transit', 'data/kek.gcp')))],
      ['hsm without an HSM key index path', (e) => { e.QODIQA_KMS_PROVIDER = 'hsm'; },
        prodOnly(F('HSM_KEY_INDEX_PATH', unset('HSM_KEY_INDEX_PATH', 'HSM key-handle index', 'data/hsm-keys.json')))],
      ['hsm key index inside the repository', (e) => { e.QODIQA_KMS_PROVIDER = 'hsm'; e.HSM_KEY_INDEX_PATH = inRepo('hsm-keys.json'); },
        prodOnly(F('HSM_KEY_INDEX_PATH', inside('HSM_KEY_INDEX_PATH', 'HSM key-handle index', inRepo('hsm-keys.json'))))],
      ['every key file on the secret volume', (e) => {
        Object.assign(e, { QODIQA_CHECKPOINT_KEYS_PATH: path.join(OUT_DIR, 'checkpoint-keys.json'), QODIQA_KEYS_ARCHIVE_PATH: path.join(OUT_DIR, 'key-archive.json') });
      }, all(null)],
      ['hsm with its index on the secret volume', (e) => { e.QODIQA_KMS_PROVIDER = 'hsm'; e.HSM_KEY_INDEX_PATH = path.join(OUT_DIR, 'hsm-keys.json'); }, all(null)],
    ];
  })(),
  ['local KMS advisory', (e) => { delete e.QODIQA_KMS_PROVIDER; },
    prodOnly(W('QODIQA_KMS_PROVIDER', 'QODIQA_KMS_PROVIDER is "local" (or unset) in production. The local provider reads the Key Encryption Key directly from QODIQA_KEY_ENCRYPTION_KEY. For maximum security, migrate to a dedicated KMS: vault-kv, vault-transit, aws-kms, azure-kv, gcp-kms, or hsm. This advisory does not block startup.'))],
  ['strict replay "false" is ignored in production', (e) => { e.STRICT_REPLAY_PROTECTION = 'false'; },
    prodOnly(W('STRICT_REPLAY_PROTECTION', 'STRICT_REPLAY_PROTECTION: is ignored in production (strict replay protection is always on)'))],

  // Shapes (moved from envValidation.js): fatal in production, warning elsewhere
  ['PORT not a number', (e) => { e.PORT = 'eighty'; },
    prodFatalElseWarn('PORT', 'PORT: must be a whole number between 1 and 65535')],
  ['PORT out of range', (e) => { e.PORT = '70000'; },
    prodFatalElseWarn('PORT', 'PORT: is out of range [1, 65535]')],
  ['boolean not true/false', (e) => { e.QODIQA_PG_ENABLED = 'yes'; },
    prodFatalElseWarn('QODIQA_PG_ENABLED', "QODIQA_PG_ENABLED: must be 'true' or 'false'")],
  ['certificate path missing', (e) => { e.QODIQA_PG_SSL_CA = path.join(os.tmpdir(), 'qodiqa-w2-does-not-exist', 'ca.pem'); },
    all(F('QODIQA_PG_SSL_CA', 'QODIQA_PG_SSL_CA: points to a file that does not exist'))],
  // migration-role placeholder-credential gate
  ['role credential gate off', (e) => { e.QODIQA_PG_ROLE_CREDENTIAL_GATE = 'off'; },
    prodOnly(F('QODIQA_PG_ROLE_CREDENTIAL_GATE', "QODIQA_PG_ROLE_CREDENTIAL_GATE: 'off' is refused in production: the migration-role placeholder-credential gate must enforce"))],
  ['role credential gate warn-only', (e) => { e.QODIQA_PG_ROLE_CREDENTIAL_GATE = 'warn'; },
    prodOnly(F('QODIQA_PG_ROLE_CREDENTIAL_GATE', "QODIQA_PG_ROLE_CREDENTIAL_GATE: 'warn' is refused in production: the migration-role placeholder-credential gate must enforce"))],
  ['role credential gate enforce', (e) => { e.QODIQA_PG_ROLE_CREDENTIAL_GATE = 'enforce'; }, all(null)],
  ['role credential gate invalid', (e) => { e.QODIQA_PG_ROLE_CREDENTIAL_GATE = 'yes'; },
    all(F('QODIQA_PG_ROLE_CREDENTIAL_GATE', "QODIQA_PG_ROLE_CREDENTIAL_GATE: must be 'off', 'warn' or 'enforce'"))],
  ['backup password is the migration placeholder', (e) => { e.QODIQA_PG_BACKUP_PASSWORD = 'REPLACE_WITH_VAULT_SECRET_BACKUP'; },
    prodFatalElseWarn('QODIQA_PG_BACKUP_PASSWORD', 'QODIQA_PG_BACKUP_PASSWORD: is a placeholder or example value')],
  ['backup password strong', (e) => { e.QODIQA_PG_BACKUP_PASSWORD = hex(); }, all(null)],
  // Redis stall detection
  ['redis command deadline disabled', (e) => { e.REDIS_COMMAND_DEADLINE_MS = '0'; },
    prodOnly(F('REDIS_COMMAND_DEADLINE_MS', 'REDIS_COMMAND_DEADLINE_MS: 0 disables Redis stall detection, which is refused in production'))],
  ['redis watchdog disabled', (e) => { e.REDIS_WATCHDOG_INTERVAL_MS = '0'; },
    prodOnly(F('REDIS_WATCHDOG_INTERVAL_MS', 'REDIS_WATCHDOG_INTERVAL_MS: 0 disables Redis stall detection, which is refused in production'))],
  ['redis deadline not an integer', (e) => { e.REDIS_COMMAND_DEADLINE_MS = 'fast'; },
    all(F('REDIS_COMMAND_DEADLINE_MS', 'REDIS_COMMAND_DEADLINE_MS: must be an integer between 0 and 60000'))],
  // witness / anchor configuration
  ['witness mode invalid', (e) => { e.QODIQA_WITNESS_MODE = 'http'; },
    all(F('QODIQA_WITNESS_MODE', "QODIQA_WITNESS_MODE: must be 'none', 'local' or 'exec'"))],
  ['witness exec without command', (e) => { e.QODIQA_WITNESS_MODE = 'exec'; e.QODIQA_WITNESS_PUBLIC_KEYS = ANCHORING.QODIQA_WITNESS_PUBLIC_KEYS; },
    all(F('QODIQA_WITNESS_EXEC', 'QODIQA_WITNESS_EXEC: is required when QODIQA_WITNESS_MODE=exec'))],
  ['redis stall settings valid', (e) => { e.REDIS_COMMAND_DEADLINE_MS = '1500'; e.REDIS_WATCHDOG_INTERVAL_MS = '2000'; e.REDIS_STALL_THRESHOLD = '3'; }, all(null)],
  // Launch plan R-06 / R-07: optional local-provider output cap and restrictive allowlist
  ['local max tokens zero', (e) => { e.LOCAL_MAX_TOKENS = '0'; },
    prodFatalElseWarn('LOCAL_MAX_TOKENS', 'LOCAL_MAX_TOKENS: must be an integer between 1 and 8192 (output-token cap for the local provider)')],
  ['local max tokens above ceiling', (e) => { e.LOCAL_MAX_TOKENS = '8193'; },
    prodFatalElseWarn('LOCAL_MAX_TOKENS', 'LOCAL_MAX_TOKENS: must be an integer between 1 and 8192 (output-token cap for the local provider)')],
  ['local max tokens not a number', (e) => { e.LOCAL_MAX_TOKENS = '256k'; },
    prodFatalElseWarn('LOCAL_MAX_TOKENS', 'LOCAL_MAX_TOKENS: must be an integer between 1 and 8192 (output-token cap for the local provider)')],
  ['local max tokens valid', (e) => { e.LOCAL_MAX_TOKENS = '256'; }, all(null)],
  ['local allowlist only separators', (e) => { e.PROVIDER_ALLOWED_MODELS_LOCAL = ' , ,'; },
    prodFatalElseWarn('PROVIDER_ALLOWED_MODELS_LOCAL', 'PROVIDER_ALLOWED_MODELS_LOCAL: must be a comma-separated list of valid model ids')],
  ['local allowlist valid', (e) => { e.PROVIDER_ALLOWED_MODELS_LOCAL = 'llama3.2:1b, qwen2.5:1.5b-instruct'; }, all(null)],
];

describe.each(['prod', 'dev', 'test'])('boot matrix — profile %s', (profile) => {
  test.each(MATRIX.map(([name, mutate, expected]) => [name, mutate, expected[profile]]))('%s', (_name, mutate, outcome) => {
    const env = base(profile);
    mutate(env, profile);
    const r = validateBoot(env);
    const baseline = validateBoot(base(profile));
    if (outcome === null) {
      // No finding: nothing fatal, and no warning the valid base did not
      // already have (supplying a variable may legitimately REMOVE one, e.g.
      // setting REDIS_URL in development clears the rate-limit warning).
      const baseVars = new Set(baseline.warnings.map((w) => w.variable));
      expect(r.fatal).toEqual([]);
      expect(r.warnings.filter((w) => !baseVars.has(w.variable))).toEqual([]);
      return;
    }
    const [severity, variable, message] = outcome;
    const bucket = severity === 'fatal' ? r.fatal : r.warnings;
    const hit = bucket.filter((v) => v.variable === variable);
    expect(hit.map((v) => v.message)).toContain(message);
    if (severity === 'fatal') {
      // one rule under test → exactly one fatal variable
      expect([...new Set(r.fatal.map((v) => v.variable))]).toEqual([variable]);
    } else {
      expect(r.fatal).toEqual([]);
      // and it is not ALSO reported as fatal
      expect(r.fatal.some((v) => v.variable === variable)).toBe(false);
    }
    // messages never carry a secret value
    for (const v of [...r.fatal, ...r.warnings]) {
      for (const k of ['QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_EXECUTION_INVARIANT_SECRET', 'QODIQA_DSR_PSEUDONYM_PEPPER', 'REVOCATION_SIGNING_KEY', 'QODIQA_OPS_TOKEN', 'REDIS_PASSWORD', 'QODIQA_PG_PASSWORD']) {
        if (env[k] && env[k].length >= 5) expect(v.message.includes(env[k])).toBe(false);
      }
    }
  });
});

describe('all violations are reported together, in one boot attempt', () => {
  test('three independent production violations → three fatals', () => {
    const env = base('prod');
    delete env.POLICY_FILE;
    env.RL_ENABLED = 'false';
    env.QODIQA_SEM_FT3_ENABLED = 'false';
    expect(validateBoot(env).fatal.map((f) => f.variable).sort()).toEqual(['POLICY_FILE', 'QODIQA_SEM_FT3_ENABLED', 'RL_ENABLED']);
  });
});

describe('semantic guard lists are complete for the shipped configuration surface', () => {
  test('every per-family FT-2/FT-3 threshold variable is forbidden in production', () => {
    for (const g of ['FT2', 'FT3']) {
      for (const f of ['LITERAL', 'PARAPHRASE', 'ROLEPLAY', 'FICTIONAL_FRAMING', 'CONFIDENTIAL_ORG', 'THIRD_PARTY_PII']) {
        expect(SEM_FORBIDDEN_IN_PROD).toContain(`QODIQA_SEM_${g}_T_${f}`);
      }
    }
  });
  test.each(SEM_FORBIDDEN_IN_PROD)('%s → fatal in production, warning in development', (n) => {
    expect(validateBoot({ ...base('prod'), [n]: '1' }).fatal.map((f) => f.variable)).toEqual([n]);
    expect(validateBoot({ ...base('dev'), [n]: '1' }).fatal).toEqual([]);
  });
  test.each(Object.entries(SEM_GATE_DEFAULTS))('%s: shipped default %s accepted, the other value refused in production', (n, dflt) => {
    expect(validateBoot({ ...base('prod'), [n]: dflt }).fatal).toEqual([]);
    expect(validateBoot({ ...base('prod'), [n]: dflt === 'true' ? 'false' : 'true' }).fatal.map((f) => f.variable)).toEqual([n]);
  });
  test.each(SEM_ALLOWED)('%s is allowed in production', (n) => {
    expect(validateBoot({ ...base('prod'), [n]: 'true' }).fatal).toEqual([]);
  });
});

describe('runBootValidation — what server/startup.js runs before any listener', () => {
  test('fatal: emits BOOT_VALIDATION_FATAL with every violation and exits 1', () => {
    const events = []; const exits = [];
    const env = base('prod'); delete env.POLICY_FILE; delete env.QODIQA_EXECUTION_INVARIANT_SECRET;
    runBootValidation({ env, emit: (s, t, f) => events.push({ s, t, f }), exit: (c) => exits.push(c) });
    expect(exits).toEqual([1]);
    const fatal = events.find((e) => e.t === 'BOOT_VALIDATION_FATAL');
    expect(fatal.s).toBe('FATAL');
    expect(fatal.f.profile).toBe('prod');
    expect(fatal.f.violationCount).toBe(2);
    expect(fatal.f.violations.map((v) => v.variable).sort()).toEqual(['POLICY_FILE', 'QODIQA_EXECUTION_INVARIANT_SECRET']);
    expect(events.some((e) => e.t === 'BOOT_VALIDATION_OK')).toBe(false);
  });

  test('valid: emits one BOOT_CONFIG_WARNING per warning, then BOOT_VALIDATION_OK, never exits', () => {
    const events = []; const exits = [];
    runBootValidation({ env: base('dev'), emit: (s, t, f) => events.push({ s, t, f }), exit: (c) => exits.push(c) });
    expect(exits).toEqual([]);
    expect(events.filter((e) => e.t === 'BOOT_CONFIG_WARNING')).toHaveLength(2);
    expect(events.at(-1)).toMatchObject({ s: 'INFO', t: 'BOOT_VALIDATION_OK', f: { profile: 'dev', warningCount: 2 } });
  });
});

describe('configFingerprint — secret values never contribute, only set/unset', () => {
  test('changing a secret value does not change the fingerprint; unsetting it does', () => {
    const env = base('prod');
    const a = configFingerprint(env);
    const b = configFingerprint({ ...env, QODIQA_KEY_ENCRYPTION_KEY: hex(), QODIQA_DSR_PSEUDONYM_PEPPER: hex() });
    expect(b.sha256).toBe(a.sha256);
    const c = configFingerprint({ ...env, QODIQA_DSR_PSEUDONYM_PEPPER: '' });
    expect(c.sha256).not.toBe(a.sha256);
  });
  test('changing a non-secret value changes the fingerprint', () => {
    const env = base('prod');
    expect(configFingerprint({ ...env, RL_ENABLED: 'false' }).sha256).not.toBe(configFingerprint(env).sha256);
  });
  test('non-QODIQA variables are ignored', () => {
    const env = base('prod');
    expect(configFingerprint({ ...env, PATH: '/elsewhere', HOME: '/x' }).sha256).toBe(configFingerprint(env).sha256);
  });
});

// broad private proxy ranges are fatal in production unless acknowledged.
describe('trusted_proxy — broad private ranges', () => {
  const fatalTp = (r) => r.fatal.filter((v) => v.variable === 'TRUSTED_PROXY');
  const warnTp = (r) => r.warnings.filter((v) => v.variable === 'TRUSTED_PROXY');
  test('production: uniquelocal/10.0.0.0/8 without acknowledgement → fatal', () => {
    for (const tp of ['loopback,linklocal,uniquelocal', '10.0.0.0/8']) {
      expect(fatalTp(validateBoot({ ...base('prod'), TRUSTED_PROXY: tp }))).toHaveLength(1);
    }
  });
  test('production: acknowledged (NetworkPolicy-guarded) → warning only', () => {
    const r = validateBoot({ ...base('prod'), TRUSTED_PROXY: 'loopback,uniquelocal', QODIQA_TRUSTED_PROXY_BROAD_ACK: 'true' });
    expect(fatalTp(r)).toEqual([]); expect(warnTp(r)).toHaveLength(1);
  });
  test('production: a specific proxy CIDR is accepted; development stays a warning', () => {
    expect(fatalTp(validateBoot({ ...base('prod'), TRUSTED_PROXY: 'loopback,10.42.0.0/16' }))).toEqual([]);
    expect(fatalTp(validateBoot({ ...base('dev'), TRUSTED_PROXY: 'uniquelocal' }))).toEqual([]);
  });
});

// weakening switches are refused in production.
describe('security_switches', () => {
  test.each([
    ['QODIQA_OPS_AUTH_LOCKOUT_ENABLED', 'false'],
    ['POLICY_GOVERNANCE_STRICT_MODE', 'false'],
    ['ENFORCE_HTTPS_PROTO', 'false'],
    ['ALERT_EMAIL_TRUSTED_RELAY_ONLY', 'true'],
    ['LOG_SANITIZER_SCAN_TOKENS', 'false'],
    ['LOG_SANITIZER_SCAN_PII', '0'],
  ])('%s=%s → fatal in production, not in development', (variable, value) => {
    expect(validateBoot({ ...base('prod'), [variable]: value }).fatal.some((v) => v.variable === variable)).toBe(true);
    expect(validateBoot({ ...base('dev'), [variable]: value }).fatal.some((v) => v.variable === variable)).toBe(false);
  });
  test('the safe values pass in production', () => {
    const r = validateBoot({ ...base('prod'), QODIQA_OPS_AUTH_LOCKOUT_ENABLED: 'true', POLICY_GOVERNANCE_STRICT_MODE: 'true', ENFORCE_HTTPS_PROTO: 'true', ALERT_EMAIL_TRUSTED_RELAY_ONLY: 'false', LOG_SANITIZER_SCAN_PII: 'true' });
    expect(r.fatal.filter((v) => /OPS_AUTH_LOCKOUT|GOVERNANCE_STRICT|ENFORCE_HTTPS|TRUSTED_RELAY|SANITIZER/.test(v.variable))).toEqual([]);
  });
  // the sanitizer enables scanning only for the exact string 'true'; any other spelling used to turn
  // redaction OFF while the validator (which only matched false-looking values) passed.
  test.each(['TRUE', '1', 'yes', 'on', 'enabled', 'disabled'])('LOG_SANITIZER_SCAN_TOKENS=%s → fatal in production', (value) => {
    expect(validateBoot({ ...base('prod'), LOG_SANITIZER_SCAN_TOKENS: value }).fatal.some((v) => v.variable === 'LOG_SANITIZER_SCAN_TOKENS')).toBe(true);
  });
});

// audit anchoring is the production posture, not an option.
describe('audit.anchoring in production', () => {
  const fatalVars = (env) => validateBoot(env).fatal.map((v) => v.variable);
  test('no export path / no witness / no witness public keys → refused', () => {
    expect(fatalVars({ ...base('prod'), QODIQA_ANCHOR_EXPORT_PATH: undefined })).toContain('QODIQA_ANCHOR_EXPORT_PATH');
    const noWitness = { ...base('prod'), QODIQA_WITNESS_MODE: 'none' };
    delete noWitness.QODIQA_WITNESS_KEY_PATH; delete noWitness.QODIQA_WITNESS_LOG_PATH;
    expect(fatalVars(noWitness)).toEqual(expect.arrayContaining(['QODIQA_WITNESS_MODE', 'QODIQA_ANCHOR_EXPORT_PATH']));
    const noPub = { ...base('prod') }; delete noPub.QODIQA_WITNESS_PUBLIC_KEYS;
    expect(fatalVars(noPub)).toContain('QODIQA_WITNESS_PUBLIC_KEYS');
  });
  test('a witness file that does not exist is refused', () => {
    expect(fatalVars({ ...base('prod'), QODIQA_WITNESS_PUBLIC_KEYS: path.join(os.tmpdir(), 'no-such-dir-recheck01', 'k.json') })).toContain('QODIQA_WITNESS_PUBLIC_KEYS');
  });
  // Correction pass 2026-10-05 (C13): a bare checkpoint/anchor bootstrap switch is refused in production.
  test('C13 production refuses QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true without a well-formed chain-head acknowledgement', () => {
    expect(fatalVars({ ...base('prod'), QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP: 'true' })).toContain('QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP');
    for (const ack of ['yes', '123', '123:abc', '12:0123456789ABCDEF', ' 12:0123456789abcdef']) {
      expect(fatalVars({ ...base('prod'), QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP: 'true', QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK: ack })).toContain('QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP');
    }
    expect(fatalVars({ ...base('prod'), QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP: 'true', QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK: '1200:0123456789abcdef' })).not.toContain('QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP');
    expect(fatalVars({ ...base('prod'), QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP: 'false' })).not.toContain('QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP');
    expect(fatalVars({ ...base('dev'), QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP: 'true' })).not.toContain('QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP');
  });

  // Final sprint: distributed production is refused OUTRIGHT (no checkpoints/anchors until) — no waiver changes that.
  test('distributed mode is refused in production — even fully anchored, even with a "waiver"', () => {
    expect(fatalVars({ ...base('prod'), QODIQA_DEPLOYMENT_MODE: 'distributed' })).toContain('QODIQA_DEPLOYMENT_MODE');
    expect(fatalVars({ ...base('prod'), QODIQA_AUDIT_ORDERING_MODE: 'distributed' })).toContain('QODIQA_DEPLOYMENT_MODE');
    const waived = { ...base('prod'), QODIQA_DEPLOYMENT_MODE: 'distributed', QODIQA_AUDIT_ANCHORING_WAIVER: 'distributed chain has no checkpoints yet' };
    expect(fatalVars(waived)).toEqual(expect.arrayContaining(['QODIQA_DEPLOYMENT_MODE', 'QODIQA_AUDIT_ANCHORING_WAIVER']));
    expect(fatalVars({ ...base('dev'), QODIQA_DEPLOYMENT_MODE: 'distributed' })).not.toContain('QODIQA_DEPLOYMENT_MODE');
  });
  test('there is no anchoring waiver: any waiver value is refused in production; placeholders are refused', () => {
    for (const w of ['n/a', 'a perfectly well-reasoned explanation of why']) {
      expect(fatalVars({ ...base('prod'), QODIQA_AUDIT_ANCHORING_WAIVER: w })).toContain('QODIQA_AUDIT_ANCHORING_WAIVER');
    }
    const noAnchoring = { ...base('prod'), QODIQA_AUDIT_ANCHORING_WAIVER: 'a perfectly well-reasoned explanation of why' };
    for (const k of Object.keys(ANCHORING)) delete noAnchoring[k];
    expect(fatalVars(noAnchoring)).toEqual(expect.arrayContaining(['QODIQA_ANCHOR_EXPORT_PATH', 'QODIQA_WITNESS_MODE']));
    expect(fatalVars({ ...base('prod'), QODIQA_ANCHOR_EXPORT_PATH: '<REPLACE_ANCHOR_EXPORT_PATH>' })).toContain('QODIQA_ANCHOR_EXPORT_PATH');
  });
  test('development keeps anchoring optional', () => {
    const dev = base('dev');
    expect(fatalVars(dev).filter((v) => /ANCHOR|WITNESS/.test(v))).toEqual([]);
  });
});

// validator and consumer agree — no spelling of a security switch can silently weaken it.
describe('security switches: exact true/false only, every profile', () => {
  const SWITCHES = ['LOG_SANITIZER_SCAN_PII', 'LOG_SANITIZER_SCAN_TOKENS', 'LOG_SANITIZER_SCAN_CRYPTO', 'LOG_SANITIZER_REDACT_IP',
    'QODIQA_OPS_AUTH_LOCKOUT_ENABLED', 'POLICY_GOVERNANCE_STRICT_MODE', 'ENFORCE_HTTPS_PROTO', 'ALERT_EMAIL_TRUSTED_RELAY_ONLY',
    'QODIQA_HEALTH_PROBE_AUTH_REQUIRED', 'QODIQA_HEALTH_REQUIRE_LOOPBACK', 'QODIQA_REQUIRE_NOTIFICATION_CHANNEL',
    'QODIQA_REQUIRE_TRANSPARENCY_SCANNER', 'QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP'];
  const SPELLINGS = ['TRUE', 'True', '1', 'yes', 'on', 'enabled', 'disabled', 'random', 'FALSE', '0'];
  test.each(SWITCHES)('%s: every non-canonical spelling is refused in production (and warned elsewhere)', (n) => {
    for (const v of SPELLINGS) {
      expect({ n, v, refused: validateBoot({ ...base('prod'), [n]: v }).fatal.some((f) => f.variable === n) }).toEqual({ n, v, refused: true });
      for (const p of ['dev', 'test']) {
        expect({ n, p, v, warned: validateBoot({ ...base(p), [n]: v }).warnings.some((f) => f.variable === n) }).toEqual({ n, p, v, warned: true });
      }
    }
    for (const v of ['true', 'false']) {
      expect(validateBoot({ ...base('dev'), [n]: v }).warnings.some((f) => f.variable === n && f.rule === 'shape.bool')).toBe(false);
    }
  });
  test('the sanitizer consumer keeps redaction ON for every value except exactly "false"', () => {
    const saved = { ...process.env };
    try {
      for (const v of [undefined, 'true', 'TRUE', '1', 'yes', 'on', 'enabled', 'disabled', 'random', 'FALSE', ' false ']) {
        for (const n of ['LOG_SANITIZER_SCAN_PII', 'LOG_SANITIZER_SCAN_TOKENS', 'LOG_SANITIZER_SCAN_CRYPTO']) { if (v === undefined) delete process.env[n]; else process.env[n] = v; }
        let cfg; jest.isolateModules(() => { cfg = require('../../../services/logSanitizerConfig').buildConfig(); });
        const expected = v !== undefined && v.trim() === 'false' ? false : true;
        expect({ v, pii: cfg.scanPii, tok: cfg.scanTokens, cry: cfg.scanCrypto }).toEqual({ v, pii: expected, tok: expected, cry: expected });
      }
    } finally {
      for (const n of ['LOG_SANITIZER_SCAN_PII', 'LOG_SANITIZER_SCAN_TOKENS', 'LOG_SANITIZER_SCAN_CRYPTO']) { if (saved[n] === undefined) delete process.env[n]; else process.env[n] = saved[n]; }
    }
  });
});
