'use strict';

/**
 * QODIQA boot validator — the single place the process decides whether the
 * configuration it was given is allowed to start. Rules:
 *.
 *
 * One declarative schema: VARIABLES (value shapes) + RULES (policy), compiled
 * into ONE Zod object schema whose superRefine emits every violation as an issue
 * carrying { severity: 'fatal' | 'warn', rule } — so all violations are reported
 * together, in one boot attempt. Absorbs the checks that previously lived in
 *, src/infra/secrets/secretValidation.js and
 * inline in server/startup.js (those modules now delegate here).
 *
 * Messages always name the variable and the rule, never the value — the only
 * exception is NODE_ENV's value, which is not secret and is what the operator
 * needs to see. validateBoot() is pure (no logging, no exit) and injectable for
 * tests; runBootValidation() is what server/startup.js calls before any
 * listener opens.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { z } = require('../../validation/zod');
const {
  isPlaceholder, secretProblems, providerKeyStatus, providerUrlStatus, azureConfigStatus, bedrockConfigStatus, isLoopbackHost,
  PROVIDER_KEY_FORMATS, HEX64,
} = require('./credentialRules');

const PROJECT_ROOT = path.resolve(__dirname, '..', '..', '..');
const PROFILES = Object.freeze({ production: 'prod', development: 'dev', test: 'test' });

// ── Declarative variable shapes (moved from envValidation.js, ranges unchanged) ──
const INT_VARS = Object.freeze({
  PORT: [1, 65535], MAX_BODY_BYTES: [1, 104_857_600],
  AI_CHAT_TIMEOUT_MS: [1, 600_000], AUDIT_TIMEOUT_MS: [1, 600_000], VERIFY_TIMEOUT_MS: [1, 600_000],
  OPENAI_TIMEOUT_MS: [1, 600_000], SHUTDOWN_TIMEOUT_MS: [1, 600_000], REDIS_CONNECT_TIMEOUT_MS: [1, 60_000],
  VERIFY_MAX_ARTIFACT_BYTES: [1, 1_048_576], VERIFY_MAX_REQUEST_BYTES: [1, 1_048_576],
  VERIFY_MAX_OBJECT_DEPTH: [1, 64], VERIFY_V2_RATE_LIMIT_MAX: [1, 100_000],
  VERIFY_V2_RATE_LIMIT_WINDOW_MS: [1, 3_600_000],
  QODIQA_API_KEY_TTL_DAYS: [1, 3650], QODIQA_API_KEY_ROTATION_GRACE_HOURS: [0, 720],
  QODIQA_API_KEY_EXPIRY_WARNING_DAYS: [0, 365],
});
const BOOL_VARS = Object.freeze([
  'REDIS_TLS', 'STRICT_REPLAY_PROTECTION', 'QODIQA_PG_ENABLED', 'QODIQA_PG_SSL', 'RL_ENABLED',
  'QODIQA_ADMIN_ENABLED', 'QODIQA_DIAGNOSTICS_ENABLED', 'QODIQA_PROFILING_DIAGNOSTICS_ENABLED',
  'QODIQA_PORTAL_ENABLED', 'QODIQA_PORTAL_DEV_AUTH_ENABLED',
  'QODIQA_SIGN_AUTH_LOCKOUT_ENABLED', 'QODIQA_OPS_MFA_REQUIRED',
  // every security / redaction switch accepts exactly 'true' or 'false' in EVERY profile —
  // consumers parse them differently (some enable only on exact 'true', some disable only on exact 'false'), so a
  // spelling such as TRUE / 1 / yes / on could silently leave a protection off. Any other value is refused at boot.
  'LOG_SANITIZER_SCAN_PII', 'LOG_SANITIZER_SCAN_TOKENS', 'LOG_SANITIZER_SCAN_CRYPTO', 'LOG_SANITIZER_REDACT_IP',
  'QODIQA_OPS_AUTH_LOCKOUT_ENABLED', 'POLICY_GOVERNANCE_STRICT_MODE', 'ENFORCE_HTTPS_PROTO', 'ALERT_EMAIL_TRUSTED_RELAY_ONLY',
  'QODIQA_HEALTH_PROBE_AUTH_REQUIRED', 'QODIQA_HEALTH_REQUIRE_LOOPBACK', 'QODIQA_REQUIRE_NOTIFICATION_CHANNEL',
  'QODIQA_REQUIRE_TRANSPARENCY_SCANNER', 'QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP',
  'QODIQA_KEYSTORE_REQUIRE_SEALED',   // OA-RC-2
]);
const PATH_VARS = Object.freeze([
  'REDIS_TLS_CA', 'REDIS_TLS_CERT', 'REDIS_TLS_KEY', 'QODIQA_PG_SSL_CA', 'QODIQA_PG_SSL_CERT', 'QODIQA_PG_SSL_KEY',
]);

// ── Semantic guard lists (BOOT-RULES.md section 4) — names only, no value is changed ──
const SEM_FORBIDDEN_IN_PROD = Object.freeze([
  'QODIQA_SEMANTIC_POLICY_ENABLED', 'QODIQA_SEMANTIC_DISABLED_CLASSIFIERS', 'QODIQA_SEMANTIC_REVIEW_BLOCKS',
  'QODIQA_SEMANTIC_THRESHOLD_WARN', 'QODIQA_SEMANTIC_THRESHOLD_REVIEW', 'QODIQA_SEMANTIC_THRESHOLD_DENY',
  'QODIQA_SEMANTIC_CLASSIFIER_TIMEOUT_MS',
  'QODIQA_SEM_C_SIMILARITY_THRESHOLD', 'QODIQA_SEM_C_THRESHOLD_LITERAL', 'QODIQA_SEM_C_THRESHOLD_PARAPHRASE',
  'QODIQA_SEM_C_THRESHOLD_ROLEPLAY', 'QODIQA_SEM_C_THRESHOLD_FICTIONAL_FRAMING',
  'QODIQA_SEM_C_HEAD_THRESHOLD', 'QODIQA_SEM_C_V9_THRESHOLD', 'QODIQA_SEM_C_V5_THRESHOLD',
  'QODIQA_SEM_FT2_BAND_B_LO', 'QODIQA_SEM_FT3_BAND_B_LO',
  ...['FT2', 'FT3'].flatMap((g) => ['LITERAL', 'PARAPHRASE', 'ROLEPLAY', 'FICTIONAL_FRAMING', 'CONFIDENTIAL_ORG', 'THIRD_PARTY_PII']
    .map((f) => `QODIQA_SEM_${g}_T_${f}`)),
]);
// Gate switches: allowed only at their shipped default in production.
const SEM_GATE_DEFAULTS = Object.freeze({
  QODIQA_SEM_EMBEDDING_ENABLED: 'true', QODIQA_SEM_FT3_ENABLED: 'true', QODIQA_SEM_NORMALIZE_ENABLED: 'true', QODIQA_SEM_INTENT_GATE_ENABLED: 'true',
  QODIQA_SEM_FT2_ENABLED: 'false', QODIQA_SEM_CLAUSE_GATE_ENABLED: 'false',
});
// Tighten-only or performance-only: allowed in every profile.
const SEM_ALLOWED = Object.freeze([
  'QODIQA_SEMANTIC_WARN_BLOCKS', 'QODIQA_SEM_WARN_ESCALATE', 'QODIQA_SEM_NORMALIZE_V2_ENABLED',
  'QODIQA_SEM_TAIL_WINDOW_ENABLED', 'QODIQA_SEM_FT2_INTRA_OP_THREADS', 'QODIQA_SEM_FT3_INTRA_OP_THREADS',
]);

const KEYED_PROVIDERS = Object.keys(PROVIDER_KEY_FORMATS);
const URL_PROVIDERS = Object.freeze({ llama: 'LLAMA_BASE_URL', local: 'LOCAL_BASE_URL' });

// ── Helpers ──────────────────────────────────────────────────────────────────
const set = (env, k) => env[k] !== undefined && env[k] !== '';
const PROBLEM_TEXT = Object.freeze({
  too_short: 'is shorter than the required minimum length',
  repeated: 'is a single repeated character (a test/placeholder value)',
  pattern: 'repeats a 2-character pattern (a test/placeholder value)',
  placeholder: 'is a placeholder or example value',
});
function resolveRl(env) {
  // the limiter is ON unless RL_ENABLED=false — the same predicate
  // as src/core/rateLimit/middleware.js _isRlEnabled(). REDIS_URL no longer
  // switches it on or off; it only says where Redis is.
  const enabled = env.RL_ENABLED !== 'false';
  return { enabled, hasRedisUrl: set(env, 'REDIS_URL') };
}
function resolvePgSsl(env, profile) {
  // Same resolution as src/infra/postgres/pool.js and (since D-D) migrate.js.
  return set(env, 'QODIQA_PG_SSL') ? env.QODIQA_PG_SSL === 'true' : profile === 'prod';
}
function resolveRedisTls(env) {
  return (env.REDIS_URL || '').startsWith('rediss://') || env.REDIS_TLS === 'true';
}
// ── Secret checks — the ONE implementation of each check ───────────────────────
// Operator-facing texts kept from secretValidation.js where they existed (its
// regression suite pins them). secretValidation.js now re-exports these; the
// RULES below call them. Each returns finding strings that never contain the value.
const GEN = 'Generate a cryptographically random value: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"';
const checks = {
  opsToken(env) {
    const raw = env.QODIQA_OPS_TOKEN;
    if (raw === undefined || raw === null) return [];
    const val = raw.trim();
    if (val.length === 0) return [`QODIQA_OPS_TOKEN is empty or contains only whitespace. ${GEN}`];
    const f = [];
    if (val.length < 32) f.push(`QODIQA_OPS_TOKEN is only ${val.length} character(s). A minimum of 32 characters is required for production use. ${GEN}`);
    if (isPlaceholder(val)) f.push(`QODIQA_OPS_TOKEN is a known placeholder or example value and must not be used in production. ${GEN}`);
    else if (/^(.)\1+$/.test(val) || /^(.{2})\1{7,}$/.test(val)) f.push(`QODIQA_OPS_TOKEN repeats a trivial character pattern (a test/placeholder value). ${GEN}`);
    return f;
  },
  kek(env) {
    const val = env.QODIQA_KEY_ENCRYPTION_KEY;
    if (!val || val.length !== 64) return [];
    if (/^0+$/.test(val)) return [`QODIQA_KEY_ENCRYPTION_KEY is all zeros — this is the null key and provides no encryption protection. ${GEN}`];
    if (/^(.)\1+$/.test(val)) return [`QODIQA_KEY_ENCRYPTION_KEY is a repeating single-character pattern (e.g. all-zeros or all-F's). This is a test/placeholder value and must not be used in production. ${GEN}`];
    if (/^(.{2})\1{15,}$/.test(val)) return [`QODIQA_KEY_ENCRYPTION_KEY appears to repeat a 2-character byte pattern. This suggests a test or placeholder value. ${GEN}`];
    return [];
  },
  invariantStrength(env) {
    const val = env.QODIQA_EXECUTION_INVARIANT_SECRET;
    if (!val || val.length !== 64) return [];
    const f = [];
    if (/^0+$/.test(val) || /^(.)\1+$/.test(val)) f.push(`QODIQA_EXECUTION_INVARIANT_SECRET is a repeating single-character pattern (e.g. all-zeros or all-F's). This is a test/placeholder value and must not be used in production. ${GEN}`);
    else if (/^(.{2})\1{15,}$/.test(val)) f.push(`QODIQA_EXECUTION_INVARIANT_SECRET appears to repeat a 2-character byte pattern. This suggests a test or placeholder value. ${GEN}`);
    const kek = env.QODIQA_KEY_ENCRYPTION_KEY;
    if (kek && kek.toLowerCase() === val.toLowerCase()) f.push(`QODIQA_EXECUTION_INVARIANT_SECRET must not be identical to QODIQA_KEY_ENCRYPTION_KEY. These are independent secrets protecting different security boundaries — ${GEN}`);
    return f;
  },
  openAiKeyPlaceholder(env) {
    return providerKeyStatus('openai', env.OPENAI_API_KEY) === 'placeholder'
      ? ['OPENAI_API_KEY appears to be a placeholder or example value and must not be used in production. Set this variable to a real OpenAI API key from your OpenAI account dashboard.']
      : [];
  },
  clientId(env) {
    const val = env.QODIQA_CLIENT_ID;
    if (!val) return [];
    // The legacy word list plus the shared placeholder definition (D-E: one
    // definition of "placeholder" — e.g. '<REPLACE_WITH_…>' from an example file).
    const weak = ['test', 'example', 'placeholder', 'default', 'client', 'my-client', 'myclient', 'demo', 'dev',
      'development', 'todo', 'fixme', 'changeme', 'change-me'].includes(val.toLowerCase()) || isPlaceholder(val);
    return weak ? ['QODIQA_CLIENT_ID is a known placeholder identifier and must not be used in production. Set this to a meaningful, unique identifier for this deployment.'] : [];
  },
  redisPassword(env) {
    const val = env.REDIS_PASSWORD;
    if (!val) return [];
    if (isPlaceholder(val)) return ['REDIS_PASSWORD is a known placeholder value and must not be used in production. Set a strong, randomly generated Redis password.'];
    if (val.length < 16) return [`REDIS_PASSWORD is only ${val.length} character(s). A minimum of 16 characters is required for production Redis authentication.`];
    return [];
  },
  productionKeystorePath(env, projectRoot = PROJECT_ROOT) {
    if (env.NODE_ENV !== 'production') return [];
    if (!env.QODIQA_KEYS_PATH) return ['QODIQA_KEYS_PATH is not set in production. The default path (data/keys.json) resolves inside the application directory, which is not acceptable for production key storage. Set QODIQA_KEYS_PATH to a path on a dedicated secret volume outside the application directory, e.g. /opt/qodiqa/data/keys.json. See deploy/env/production.env.example for the recommended configuration.'];
    const resolved = path.resolve(env.QODIQA_KEYS_PATH); const root = path.resolve(projectRoot);
    if (resolved === root || resolved.startsWith(root + path.sep)) return [`QODIQA_KEYS_PATH resolves inside the application directory "${root}". Repository-resident keystores are not permitted in production. Set QODIQA_KEYS_PATH to a path on a dedicated secret volume outside the application directory, e.g. /opt/qodiqa/data/keys.json.`];
    return [];
  },
  // the QODIQA_KEYS_PATH rule above, extended to EVERY other key file the process reads or
  // writes. Each path is resolved exactly the way its owning module resolves it (explicit variable, else the
  // module's default); a path that resolves inside the application directory is refused in production — key
  // material must live on a dedicated secret volume, never in the image / repository tree. Variables whose module
  // default sits under the working directory (wrapped KEK files, HSM index) are refused when unset, like
  // QODIQA_KEYS_PATH. Returns [{ variable, message }]; never contains a value other than the resolved path.
  productionKeyFilePaths(env, projectRoot = PROJECT_ROOT) {
    if (env.NODE_ENV !== 'production') return [];
    const root = path.resolve(projectRoot);
    const inside = (p) => { const r = path.resolve(p); return r === root || r.startsWith(root + path.sep); };
    const out = [];
    const SECRET_VOL = 'Set it to a path on a dedicated secret volume outside the application directory (the same volume as QODIQA_KEYS_PATH, e.g. /opt/qodiqa/data/).';
    const refuseInside = (variable, resolved, what) => {
      if (inside(resolved)) out.push({ variable, message: `${variable} resolves inside the application directory "${root}" (${what}: ${path.resolve(resolved)}). Repository-resident key files are not permitted in production. ${SECRET_VOL}` });
    };
    // Transparency signing keys — transparencyKeyStore.js default: <app>/data/transparency-keys.json (always inside the
    // application directory, so unset is refused like QODIQA_KEYS_PATH; the message names no machine-specific path).
    if (!set(env, 'QODIQA_TRANSPARENCY_KEYS_PATH')) {
      out.push({ variable: 'QODIQA_TRANSPARENCY_KEYS_PATH', message: `QODIQA_TRANSPARENCY_KEYS_PATH is not set in production (transparency key file; the audit-checkpoint key file defaults beside it). The default (data/transparency-keys.json in the application directory) resolves inside the application directory, which is not acceptable for production key storage. ${SECRET_VOL}` });
    } else {
      refuseInside('QODIQA_TRANSPARENCY_KEYS_PATH', env.QODIQA_TRANSPARENCY_KEYS_PATH, 'transparency key file');
    }
    // Audit-checkpoint signing keys — checkpointKeyStore.js: explicit, else beside the transparency file (same
    // directory, so covered by the rule above), else <app>/data (only when the transparency path is unset — reported above).
    if (set(env, 'QODIQA_CHECKPOINT_KEYS_PATH')) refuseInside('QODIQA_CHECKPOINT_KEYS_PATH', env.QODIQA_CHECKPOINT_KEYS_PATH, 'checkpoint key file');
    // Files that default beside QODIQA_KEYS_PATH (already covered by the keystore rule) — checked only when overridden.
    if (set(env, 'QODIQA_MAC_KEYS_PATH')) refuseInside('QODIQA_MAC_KEYS_PATH', env.QODIQA_MAC_KEYS_PATH, 'MAC keyring');
    if (set(env, 'QODIQA_KEYS_ARCHIVE_PATH')) refuseInside('QODIQA_KEYS_ARCHIVE_PATH', env.QODIQA_KEYS_ARCHIVE_PATH, 'retired-key archive');
    if (set(env, 'QODIQA_WITNESS_KEY_PATH')) refuseInside('QODIQA_WITNESS_KEY_PATH', env.QODIQA_WITNESS_KEY_PATH, 'witness private key');
    // Wrapped KEK — resolved the way keyProviderFactory.getKekProviderType() resolves the KEK provider.
    const provider = env.QODIQA_KMS_PROVIDER || 'local';
    const kekType = (provider === 'vault-transit' || provider === 'hsm') ? (env.QODIQA_KMS_KEK_PROVIDER || 'local') : provider;
    const WRAPPED = { 'aws-kms': ['AWS_KMS_EDK_PATH', 'data/kek.edk'], 'gcp-kms': ['GCP_WRAPPED_KEY_PATH', 'data/kek.gcp'], 'azure-kv': ['AZURE_WRAPPED_KEY_PATH', 'data/kek.wk'] };
    const wrappedFiles = [];
    if (WRAPPED[kekType]) wrappedFiles.push([...WRAPPED[kekType], `wrapped KEK for QODIQA_KMS_PROVIDER=${provider}`]);
    if (provider === 'hsm') wrappedFiles.push(['HSM_KEY_INDEX_PATH', 'data/hsm-keys.json', 'HSM key-handle index']);
    for (const [variable, dflt, what] of wrappedFiles) {
      if (!set(env, variable)) out.push({ variable, message: `${variable} is not set in production (${what}). The default (${dflt} under the working directory) resolves inside the application directory, which is not acceptable for production key storage. ${SECRET_VOL}` });
      else refuseInside(variable, env[variable], what);
    }
    return out;
  },
  // (D-F5-1): the transparency/persistence file journal holds the only durable copy of a leaf while PostgreSQL is down, so in production it
  // must live on a persistent volume the operator chose — never the container's ephemeral filesystem, never inside the application directory.
  productionJournalDir(env, projectRoot = PROJECT_ROOT, fsImpl = require('fs')) {
    if (env.NODE_ENV !== 'production') return [];
    if (!set(env, 'QODIQA_PRQ_JOURNAL_DIR')) {
      return ['QODIQA_PRQ_JOURNAL_DIR is not set in production. The file journal is the only durable record of a transparency leaf while PostgreSQL is down; its default (data/prq-journal under the application directory) is not a persistent volume. Set it to a directory on a dedicated persistent volume (the same volume as QODIQA_KEYS_PATH, e.g. /opt/qodiqa/data/prq-journal).'];
    }
    const root = path.resolve(projectRoot);
    const dir = path.resolve(env.QODIQA_PRQ_JOURNAL_DIR);
    if (dir === root || dir.startsWith(root + path.sep)) {
      return ['QODIQA_PRQ_JOURNAL_DIR resolves inside the application directory "' + root + '" (' + dir + '). A journal there is lost with the container; point it at a persistent volume outside the application directory.'];
    }
    // In a container, a journal on the same filesystem as / is on the container's ephemeral layer: it would not survive a restart of the container.
    try {
      const inContainer = fsImpl.existsSync('/.dockerenv') || set(env, 'KUBERNETES_SERVICE_HOST');
      // a directory that does not exist yet is created by the journal on whatever filesystem its nearest existing ancestor is on
      let probe = dir; while (!fsImpl.existsSync(probe) && path.dirname(probe) !== probe) probe = path.dirname(probe);
      if (inContainer && fsImpl.existsSync(probe) && fsImpl.statSync(probe).dev === fsImpl.statSync('/').dev) {
        return ['QODIQA_PRQ_JOURNAL_DIR (' + dir + ') is on the container root filesystem, which does not survive a container restart. Mount a persistent volume there.'];
      }
    } catch { /* an unreadable path is reported by the journal itself */ }
    return [];
  },
  productionKmsProvider(env) {
    if (env.NODE_ENV !== 'production') return [];
    return (env.QODIQA_KMS_PROVIDER || 'local').toLowerCase() === 'local'
      ? ['QODIQA_KMS_PROVIDER is "local" (or unset) in production. The local provider reads the Key Encryption Key directly from QODIQA_KEY_ENCRYPTION_KEY. For maximum security, migrate to a dedicated KMS: vault-kv, vault-transit, aws-kms, azure-kv, gcp-kms, or hsm. This advisory does not block startup.']
      : [];
  },
};

function resolveOpsPlanes(env, profile) {
  // Same resolution as opsConfig.loadOpsConfig(): a DEFINED variable (even '')
  // decides; only an absent one takes the profile default.
  const dflt = profile !== 'prod';
  return {
    adminEnabled: env.QODIQA_ADMIN_ENABLED !== undefined ? env.QODIQA_ADMIN_ENABLED === 'true' : dflt,
    diagnosticsEnabled: env.QODIQA_DIAGNOSTICS_ENABLED !== undefined ? env.QODIQA_DIAGNOSTICS_ENABLED === 'true' : dflt,
  };
}

// ── Declarative rules (BOOT-RULES.md sections 1–8) ─────────────────────────────
// Each rule: { id, section, check(env, profile, report, ctx) }; report(variable, severity, text).
const RULES = [
  // 2. Secrets
  { id: 'secret.kek', check(env, p, r) {
    const v = env.QODIQA_KEY_ENCRYPTION_KEY;
    if (!set(env, 'QODIQA_KEY_ENCRYPTION_KEY')) return r('QODIQA_KEY_ENCRYPTION_KEY', 'fatal', 'is required (64 hex characters)');
    if (!HEX64.test(v)) return r('QODIQA_KEY_ENCRYPTION_KEY', 'fatal', 'must be exactly 64 hex characters');
    for (const m of checks.kek(env)) r('QODIQA_KEY_ENCRYPTION_KEY', p === 'prod' ? 'fatal' : 'warn', m);
  } },
  // dedicated key-encryption keys for the transparency and checkpoint key stores (services/secrets/secretsProvider.js SCOPED_KEK_ENV).
  // Unset = the store keeps the shared KEK (compatible). Set = must be well-formed. In production QODIQA_AUDIT_KEK_SEPARATION decides what
  // sharing means: 'warn' reports it, 'enforce' refuses to boot unless the artifact, transparency and checkpoint KEKs are three
  // different values, 'off' (default) is silent.
  { id: 'secret.audit_keks', check(env, p, r) {
    const SCOPED = ['QODIQA_TRANSPARENCY_KEY_ENCRYPTION_KEY', 'QODIQA_CHECKPOINT_KEY_ENCRYPTION_KEY'];
    for (const n of SCOPED) {
      if (!set(env, n)) continue;
      if (!HEX64.test(env[n])) { r(n, 'fatal', 'must be exactly 64 hex characters'); continue; }
      for (const m of checks.kek({ ...env, QODIQA_KEY_ENCRYPTION_KEY: env[n] })) r(n, p === 'prod' ? 'fatal' : 'warn', m.split('QODIQA_KEY_ENCRYPTION_KEY').join(n));
    }
    const mode = String(env.QODIQA_AUDIT_KEK_SEPARATION || 'off').toLowerCase();
    if (!['off', 'warn', 'enforce'].includes(mode)) return r('QODIQA_AUDIT_KEK_SEPARATION', 'fatal', 'must be off, warn or enforce');
    if (p !== 'prod' || mode === 'off') return;
    const sev = mode === 'enforce' ? 'fatal' : 'warn';
    const shared = set(env, 'QODIQA_KEY_ENCRYPTION_KEY') ? env.QODIQA_KEY_ENCRYPTION_KEY.toLowerCase() : null;
    const seen = new Map(); if (shared) seen.set(shared, 'QODIQA_KEY_ENCRYPTION_KEY');
    for (const n of SCOPED) {
      if (!set(env, n)) { r(n, sev, 'is not set: this key store shares the artifact KEK, so one leaked KEK opens the signing keys of more than one trust domain (set a dedicated 64-hex KEK, or QODIQA_AUDIT_KEK_SEPARATION=off to accept the sharing)'); continue; }
      const v = env[n].toLowerCase();
      if (seen.has(v)) r(n, sev, 'equals ' + seen.get(v) + ': the key stores must not share one KEK');
      else seen.set(v, n);
    }
  } },
  { id: 'secret.invariant', check(env, p, r) {
    const n = 'QODIQA_EXECUTION_INVARIANT_SECRET'; const v = env[n];
    if (!set(env, n)) return r(n, 'fatal', 'is required (64 hex characters); it is verified at boot so no request can consume its nonce and then fail');
    if (!HEX64.test(v)) return r(n, 'fatal', 'must be exactly 64 hex characters');
    for (const m of checks.invariantStrength(env)) r(n, p === 'prod' ? 'fatal' : 'warn', m);
  } },
  { id: 'secret.client_id', check(env, p, r) {
    if (!set(env, 'QODIQA_CLIENT_ID')) return r('QODIQA_CLIENT_ID', 'fatal', 'is required (default client identifier for transparency, compliance and certification signing)');
    for (const m of checks.clientId(env)) r('QODIQA_CLIENT_ID', p === 'prod' ? 'fatal' : 'warn', m);
  } },
  { id: 'secret.ops_token', check(env, p, r) {
    const n = 'QODIQA_OPS_TOKEN'; const planes = resolveOpsPlanes(env, p);
    if (!set(env, n)) {
      if (p === 'prod' && (planes.adminEnabled || planes.diagnosticsEnabled)) r(n, 'fatal', 'is required while QODIQA_ADMIN_ENABLED or QODIQA_DIAGNOSTICS_ENABLED is true');
      return;
    }
    for (const m of checks.opsToken(env)) r(n, p === 'prod' ? 'fatal' : 'warn', m);
  } },
  { id: 'secret.redis_password', check(env, p, r) {
    for (const m of checks.redisPassword(env)) r('REDIS_PASSWORD', p === 'prod' ? 'fatal' : 'warn', m);
  } },
  { id: 'secret.pg_passwords', check(env, p, r) {
    if (env.QODIQA_PG_ENABLED !== 'true') return;
    // + the two dedicated cross-tenant role pools (rolePools.js, migration 060).
    // QODIQA_PG_MIG_PASSWORD is no longer required — the gateway never uses the migration credential
    // (only src/infra/postgres/migrate.js, run as a separate one-shot job, does); see secret.pg_migration_credential_absent.
    for (const n of ['QODIQA_PG_PASSWORD', 'QODIQA_PG_RETENTION_PASSWORD', 'QODIQA_PG_SYSTEM_PASSWORD', 'QODIQA_PG_REPORTING_PASSWORD']) {
      if (!set(env, n)) { r(n, 'fatal', 'is required while QODIQA_PG_ENABLED=true'); continue; }
      const probs = secretProblems(env[n], { minLength: 16 });
      if (p === 'prod') probs.forEach((pr) => r(n, 'fatal', PROBLEM_TEXT[pr]));
      else if (probs.includes('placeholder')) r(n, 'warn', PROBLEM_TEXT.placeholder);
    }
  } },
  { id: 'secret.pg_migration_credential_absent', check(env, p, r) {
    // the migration credential (CREATE on schema public, BYPASSRLS, owner of 12 tables) has no runtime
    // consumer in the gateway. Carried in the gateway's environment it only widens what a compromised gateway yields.
    if (set(env, 'QODIQA_PG_MIG_PASSWORD')) {
      r('QODIQA_PG_MIG_PASSWORD', p === 'prod' ? 'fatal' : 'warn', 'is set in the gateway environment: the running service never uses the migration credential — give it only to the separate one-shot migration job (node src/infra/postgres/migrate.js) and remove it here');
    }
  } },
  { id: 'audit.anchoring', check(env, p, r, ctx) { //
    // Witness-cosigned checkpoint anchors (src/core/audit/anchoring/*). A witness key held in the gateway's own key
    // store directory gives no independence: an insider holding the host holds both keys.
    // QODIQA_WITNESSES_CONFIG (a JSON list of witnesses) replaces the single-witness variables.
    if (set(env, 'QODIQA_WITNESSES_CONFIG')) {
      let list = null;
      try { list = JSON.parse(require('fs').readFileSync(env.QODIQA_WITNESSES_CONFIG, 'utf8')); } catch (e) { r('QODIQA_WITNESSES_CONFIG', 'fatal', `unreadable or not JSON: ${e.message}`); return; }
      if (!Array.isArray(list) || !list.length) { r('QODIQA_WITNESSES_CONFIG', 'fatal', 'must be a non-empty JSON array of witnesses'); return; }
      const ids = list.map((c) => c && c.witnessId);
      if (ids.some((x) => typeof x !== 'string' || !x) || new Set(ids).size !== ids.length) { r('QODIQA_WITNESSES_CONFIG', 'fatal', 'every witness needs a distinct witnessId'); return; }
      if (list.some((c) => !c || !['exec', 'local'].includes(c.mode))) { r('QODIQA_WITNESSES_CONFIG', 'fatal', "every witness needs mode 'exec' or 'local'"); return; }
      const min = Number(env.QODIQA_ANCHOR_MIN_WITNESSES);
      if (Number.isInteger(min) && min > list.length) r('QODIQA_ANCHOR_MIN_WITNESSES', 'fatal', `is ${min} but only ${list.length} witness(es) are configured: no anchor could ever be exported`);
      if (p === 'prod' && list.length < 2) r('QODIQA_WITNESSES_CONFIG', 'warn', 'lists a single witness: the protocol asks for two independent cosignatures');
      return;
    }
    const mode = env.QODIQA_WITNESS_MODE || 'none';
    if (!['none', 'local', 'exec'].includes(mode)) { r('QODIQA_WITNESS_MODE', 'fatal', "must be 'none', 'local' or 'exec'"); return; }
    { const min1 = Number(env.QODIQA_ANCHOR_MIN_WITNESSES); if (mode !== 'none' && Number.isInteger(min1) && min1 > 1) r('QODIQA_ANCHOR_MIN_WITNESSES', 'fatal', `is ${min1} but one witness is configured (QODIQA_WITNESS_MODE): no anchor could ever be exported (list witnesses in QODIQA_WITNESSES_CONFIG)`); }   // D-9
    if (mode === 'local') {
      for (const n of ['QODIQA_WITNESS_KEY_PATH', 'QODIQA_WITNESS_LOG_PATH']) if (!set(env, n)) r(n, 'fatal', 'is required when QODIQA_WITNESS_MODE=local');
      const keyDir = set(env, 'QODIQA_KEYS_PATH') ? path.resolve(path.dirname(env.QODIQA_KEYS_PATH)) : null;
      if (keyDir && set(env, 'QODIQA_WITNESS_KEY_PATH') && path.resolve(env.QODIQA_WITNESS_KEY_PATH).startsWith(keyDir + path.sep)) {
        r('QODIQA_WITNESS_KEY_PATH', p === 'prod' ? 'fatal' : 'warn', 'lies inside the gateway key store directory — a witness key must be held by another party');
      }
    }
    if (mode === 'exec' && !set(env, 'QODIQA_WITNESS_EXEC')) r('QODIQA_WITNESS_EXEC', 'fatal', 'is required when QODIQA_WITNESS_MODE=exec');
    // in production anchoring is the POSTURE, not an option. Without an export and a witness whose public key
    // the boot check can verify, an insider with host/DB access can rewrite recent history undetectably. FAIL-CLOSED:
    // there is no waiver (the earlier QODIQA_AUDIT_ANCHORING_WAIVER escape is gone — setting it in
    // production is itself refused, so no deployment can believe it is waived).
    const prodMissing = p === 'prod';
    if (p === 'prod' && set(env, 'QODIQA_AUDIT_ANCHORING_WAIVER')) r('QODIQA_AUDIT_ANCHORING_WAIVER', 'fatal', 'is not accepted: production requires audit anchoring (export + witness), with no waiver');
    // Correction pass 2026-10-05 (C13): the checkpoint/anchor BOOTSTRAP switch skips the deleted-anchor, deleted-
    // checkpoint, broken-chain and staleness checks. In production a bare `true` is not accepted: it must be paired with
    // QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK=<chainLength>:<first 16 hex of the head hash>, which the checkpoint boot check
    // compares with the live chain — so the bypass is bound to one inspected chain state and cannot be pre-set or left on.
    if (p === 'prod' && env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP === 'true' && !/^\d+:[0-9a-f]{16}$/.test(env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK || '')) {
      r('QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP', 'fatal', 'is true without QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK=<chainLength>:<head-hash-16-hex>: production accepts a checkpoint/anchor bootstrap only bound to the inspected chain head (C13)');
    }
    // the two recovery switches downgrade the FATAL boot integrity gates (file↔PG mirror
    // divergence, verifier watermark continuity) to WARN. Like the bootstrap switch above, production accepts them
    // only with an explicit, short-lived acknowledgement — QODIQA_AUDIT_RECOVERY_MODE_UNTIL=<ISO-8601 time at most
    // 24 h ahead> — so an incident override cannot be pre-set or silently left on. Other profiles: a warning.
    for (const n of ['QODIQA_AUDIT_MIRROR_RECOVERY_MODE', 'QODIQA_AUDIT_VERIFIER_RECOVERY_MODE']) {
      if (env[n] !== 'true') continue;
      if (p !== 'prod') { r(n, 'warn', 'downgrades a fatal audit-integrity boot check to a warning (incident recovery only)'); continue; }
      const until = Date.parse(env.QODIQA_AUDIT_RECOVERY_MODE_UNTIL || '');
      const now = Date.now();
      if (!(Number.isFinite(until) && until > now && until - now <= 24 * 3600 * 1000)) {
        r(n, 'fatal', 'is true without QODIQA_AUDIT_RECOVERY_MODE_UNTIL=<ISO-8601 time within the next 24 h>: production accepts an audit-integrity recovery override only as a short-lived, explicit incident acknowledgement');
      } else {
        r(n, 'warn', `downgrades a fatal audit-integrity boot check to a warning until ${new Date(until).toISOString()} (incident recovery override)`);
      }
    }
    if (mode !== 'none' && !set(env, 'QODIQA_WITNESS_PUBLIC_KEYS')) r('QODIQA_WITNESS_PUBLIC_KEYS', prodMissing ? 'fatal' : 'warn', 'is not set: anchors are written but the boot check cannot verify cosignatures');
    if (set(env, 'QODIQA_ANCHOR_EXPORT_PATH') && mode === 'none') r('QODIQA_ANCHOR_EXPORT_PATH', prodMissing ? 'fatal' : 'warn', 'is set without a witness: exported anchors are only as trustworthy as the export file\'s custody — production requires QODIQA_WITNESS_MODE=local|exec');
    if (p === 'prod') {
      for (const n of ['QODIQA_ANCHOR_EXPORT_PATH', 'QODIQA_WITNESS_EXEC', 'QODIQA_WITNESS_KEY_PATH', 'QODIQA_WITNESS_LOG_PATH', 'QODIQA_WITNESS_PUBLIC_KEYS']) {
        if (set(env, n) && /<REPLACE[A-Z0-9_+]*>/.test(env[n])) r(n, 'fatal', 'is still the deploy/env/production.env.example placeholder');
      }
      // the distributed audit chain has NO signed checkpoints and NO anchors yet (every
      // replica would sign). Production must not run it while claiming audit integrity, and no waiver can change that:
      // distributed production is refused outright until lands.
      if (String(env.QODIQA_DEPLOYMENT_MODE || '').toLowerCase() === 'distributed' || String(env.QODIQA_AUDIT_ORDERING_MODE || '').toLowerCase() === 'distributed') {
        r('QODIQA_DEPLOYMENT_MODE', 'fatal', 'is distributed: the distributed audit chain has no signed checkpoints or anchors yet, so production refuses it — run the single-node topology (anchored) in production; QODIQA_AUDIT_ANCHORING_WAIVER does not apply');
      }
    }
    if (prodMissing) {
      if (!set(env, 'QODIQA_ANCHOR_EXPORT_PATH')) r('QODIQA_ANCHOR_EXPORT_PATH', 'fatal', 'is required in production ');
      if (mode === 'none') r('QODIQA_WITNESS_MODE', 'fatal', "is 'none': production requires a witness");
      if (ctx && typeof ctx.fileExists === 'function') {
        for (const n of ['QODIQA_WITNESS_KEY_PATH', 'QODIQA_WITNESS_PUBLIC_KEYS']) {
          if (set(env, n) && (n !== 'QODIQA_WITNESS_KEY_PATH' || mode === 'local') && !ctx.fileExists(env[n])) r(n, 'fatal', `points at ${env[n]}, which does not exist`);
        }
      }
    }
  } },
  { id: 'redis.stall_detection', check(env, p, r) { //
    // Command deadline + PING watchdog are what turn a silent Redis partition into a fast
    // fail-closed refusal and a visible readiness drop (src/infra/redis/commandDeadline.js).
    // 0 disables a mechanism: refused in production.
    const spec = { REDIS_COMMAND_DEADLINE_MS: [0, 60000], REDIS_WATCHDOG_INTERVAL_MS: [0, 60000], REDIS_STALL_THRESHOLD: [1, 100] };
    for (const [n, [min, max]] of Object.entries(spec)) {
      if (!set(env, n)) continue;
      const v = Number(env[n]);
      if (!Number.isInteger(v) || v < min || v > max) { r(n, 'fatal', `must be an integer between ${min} and ${max}`); continue; }
      if (p === 'prod' && v === 0 && n !== 'REDIS_STALL_THRESHOLD') r(n, 'fatal', '0 disables Redis stall detection, which is refused in production');
    }
  } },
  { id: 'secret.pg_role_credentials', check(env, p, r) { //
    // The live placeholder-login gate (server/startup.js -2.45, src/infra/postgres/roleCredentials.js)
    // is what PROVES no migration-created role still accepts its published password; production may
    // not switch it off or down to warn-only.
    const n = 'QODIQA_PG_ROLE_CREDENTIAL_GATE'; const v = env[n];
    if (set(env, n) && !['off', 'warn', 'enforce'].includes(v)) r(n, 'fatal', "must be 'off', 'warn' or 'enforce'");
    if (p === 'prod' && set(env, n) && v !== 'enforce') r(n, 'fatal', `'${v}' is refused in production: the migration-role placeholder-credential gate must enforce`);
    // The backup identity (qodiqa_backup, BYPASSRLS, migration 067) is used only by the backup jobs, but
    // when its password is present in the gateway environment it must not be a placeholder or weak value.
    if (set(env, 'QODIQA_PG_BACKUP_PASSWORD')) {
      const probs = secretProblems(env.QODIQA_PG_BACKUP_PASSWORD, { minLength: 16 });
      if (p === 'prod') probs.forEach((pr) => r('QODIQA_PG_BACKUP_PASSWORD', 'fatal', PROBLEM_TEXT[pr]));
      else if (probs.includes('placeholder')) r('QODIQA_PG_BACKUP_PASSWORD', 'warn', PROBLEM_TEXT.placeholder);
    }
  } },
  { id: 'control_plane', check(env, p, r) { //
    // Identities, RBAC users/roles, tenants, orgs, portal users, policy state and
    // signing-key status live in the PostgreSQL control plane (migrations 065/066).
    // Memory mode (seeded from the legacy JSON files, never persisted) is dev/test only.
    // Production always resolves to the PostgreSQL backend; production without
    // PostgreSQL is already refused at startup by the durable-evidence gate
    // and by the control plane's own first pull (CONTROL_PLANE_UNAVAILABLE).
    // Outside production, memory mode is announced at runtime (CONTROL_PLANE_MEMORY_MODE).
    const n = 'QODIQA_CONTROL_PLANE_BACKEND'; const b = env[n];
    if (set(env, n) && b !== 'pg' && b !== 'memory') r(n, 'fatal', "must be 'pg' or 'memory'");
    if (p === 'prod') {
      if (b === 'memory') r(n, 'fatal', 'memory mode is development/test only; production requires the PostgreSQL control plane');
      if (env.QODIQA_PG_ENABLED === 'true') {
        if (!set(env, 'QODIQA_PG_CONTROL_PASSWORD')) r('QODIQA_PG_CONTROL_PASSWORD', 'fatal', 'is required in production (role qodiqa_control, migration 065)');
        else secretProblems(env.QODIQA_PG_CONTROL_PASSWORD, { minLength: 16 }).forEach((pr) => r('QODIQA_PG_CONTROL_PASSWORD', 'fatal', PROBLEM_TEXT[pr]));
      }
    }
    const st = parseInt(env.QODIQA_CONTROL_PLANE_MAX_STALENESS_MS, 10);
    if (Number.isFinite(st) && st > 5000) r('QODIQA_CONTROL_PLANE_MAX_STALENESS_MS', 'warn', 'is above the 5 s propagation bound; it is clamped to 5000');
  } },
  { id: 'bench.stage_timing', check(env, p, r) { // per-request stage timer (src/observability/stageTimer.js)
    // A benchmark instrument: it keeps a per-request record and mounts a loopback-only
    // /__bench/stages readout. Never in production (approval would be required to change this).
    const n = 'QODIQA_BENCH_STAGE_TIMING'; const v = env[n];
    if (set(env, n) && v !== 'true' && v !== 'false') r(n, 'fatal', "must be 'true' or 'false'");
    if (p === 'prod' && v === 'true') r(n, 'fatal', 'the bench stage timer is refused in production');
  } },
  { id: 'perf.admission', check(env, p, r) { // src/api/admission.js
    const ints = { QODIQA_ADMISSION_AI_CHAT_MAX_INFLIGHT: [1, 100000], QODIQA_ADMISSION_AI_CHAT_QUEUE: [0, 1000000], QODIQA_ADMISSION_AI_CHAT_QUEUE_TIMEOUT_MS: [1, 60000],
      QODIQA_ADMISSION_SIGN_MAX_INFLIGHT: [1, 100000], QODIQA_ADMISSION_SIGN_QUEUE: [0, 1000000], QODIQA_ADMISSION_SIGN_QUEUE_TIMEOUT_MS: [1, 60000], QODIQA_ADMISSION_RETRY_AFTER_SEC: [1, 3600],
      QODIQA_ADMISSION_VERIFY_MAX_INFLIGHT: [1, 100000], QODIQA_ADMISSION_VERIFY_QUEUE: [0, 1000000], QODIQA_ADMISSION_VERIFY_QUEUE_TIMEOUT_MS: [1, 60000], //
      QODIQA_ADMISSION_ACTIONS_MAX_INFLIGHT: [1, 100000], QODIQA_ADMISSION_ACTIONS_QUEUE: [0, 1000000], QODIQA_ADMISSION_ACTIONS_QUEUE_TIMEOUT_MS: [1, 60000],
      QODIQA_ADMISSION_TOOLS_MAX_INFLIGHT: [1, 100000], QODIQA_ADMISSION_TOOLS_QUEUE: [0, 1000000], QODIQA_ADMISSION_TOOLS_QUEUE_TIMEOUT_MS: [1, 60000],
      QODIQA_PG_POOL_MAX: [1, 500], QODIQA_PG_ACQUIRE_TIMEOUT_MS: [100, 60000], // D3
      QODIQA_OUTPUT_CLASSIFY_MAX_CHARS: [1000, 10000000], QODIQA_CLASSIFY_BUDGET_REFILL_PER_SEC: [1, 10000000], QODIQA_CLASSIFY_BUDGET_BURST: [1, 100000000], // D2
      QODIQA_ORG_STATUS_GRACE_MS: [0, 600000], // step 8
      QODIQA_INFERENCE_SPLIT_MIN: [0, 100000] }; // step 10
    for (const [n, [lo, hi]] of Object.entries(ints)) {
      if (!set(env, n)) continue;
      const v = env[n];
      if (!(/^\d+$/.test(v) && Number(v) >= lo && Number(v) <= hi)) r(n, 'fatal', `must be an integer from ${lo} to ${hi}`);
    }
  } },
  { id: 'perf.inference_workers', check(env, p, r) { // (D4): src/core/semantic/embeddingSimilarity/inferencePool.js
    const n = 'QODIQA_INFERENCE_WORKERS'; const v = env[n];
    if (set(env, n) && !(/^\d+$/.test(v) && Number(v) <= 64)) r(n, 'fatal', 'must be an integer from 0 (in-process) to 64');
  } },
  { id: 'api.block_http_mode', check(env, p, r) { // · D7: /ai/chat BLOCK HTTP status (src/api/blockHttpStatus.js)
    // 'decision' (default) ='s HTTP 200 for every enforcement BLOCK; 'status' = per-class 4xx/5xx. Both
    // are valid in every profile; anything else is a typo that would silently fall back to 'decision'.
    const n = 'QODIQA_BLOCK_HTTP_MODE'; const v = env[n];
    if (set(env, n) && v !== 'decision' && v !== 'status') r(n, 'fatal', "must be 'decision' or 'status'");
  } },
  { id: 'secret.portal_oidc', check(env, p, r) {
    const needs = [];
    if (env.QODIQA_PORTAL_ENABLED === 'true') needs.push('QODIQA_PORTAL_SESSION_SECRET');
    if (set(env, 'QODIQA_OIDC_ISSUER')) needs.push('QODIQA_OIDC_CLIENT_SECRET');
    for (const n of needs) {
      if (!set(env, n)) { r(n, p === 'prod' ? 'fatal' : 'warn', 'is required while the portal/OIDC feature is enabled'); continue; }
      if (p === 'prod') secretProblems(env[n], { minLength: 32 }).forEach((pr) => r(n, 'fatal', PROBLEM_TEXT[pr]));
    }
  } },
  { id: 'secret.dsr_pepper', check(env, p, r) {
    const n = set(env, 'QODIQA_DSR_PSEUDONYM_PEPPER') ? 'QODIQA_DSR_PSEUDONYM_PEPPER' : 'QODIQA_SIGNING_SECRET';
    if (!set(env, n)) return r('QODIQA_DSR_PSEUDONYM_PEPPER', p === 'prod' ? 'fatal' : 'warn', 'is required (or QODIQA_SIGNING_SECRET) for DSR erasure pseudonymisation');
    if (p === 'prod') secretProblems(env[n], { minLength: 32 }).forEach((pr) => r(n, 'fatal', PROBLEM_TEXT[pr]));
  } },
  { id: 'secret.pubsub_signing', check(env, p, r, ctx) { // supersedes D-C
    // Consent-revocation / org-status messages, the org-status hash and the
    // consent cache are signed with the keystore MAC keyring, mandatorily, in
    // every profile. The W2-era env keys are no longer read.
    for (const n of ['REVOCATION_SIGNING_KEY', 'ORG_STATUS_SIGNING_KEY']) {
      if (set(env, n)) r(n, 'warn', 'is deprecated and ignored: pub/sub messages are signed with the keystore MAC keyring');
    }
    if (p !== 'prod' || (!set(env, 'QODIQA_MAC_KEYS_PATH') && !set(env, 'QODIQA_KEYS_PATH'))) return; // keystore rule reports a missing path
    const ringPath = env.QODIQA_MAC_KEYS_PATH || path.join(path.dirname(env.QODIQA_KEYS_PATH), 'mac-keys.json');
    const exists = (ctx && ctx.fileExists) || ((f) => fs.existsSync(f));
    if (!exists(ringPath)) {
      r('QODIQA_MAC_KEYS_PATH', 'fatal', `MAC keyring not found at ${ringPath}: provision it once (node scripts/security/macKeyring.js init) and share it with every node like the signing keystore — production never generates one per node`);
    }
  } },
  { id: 'secret.vault_token', check(env, p, r) {
    if ((env.QODIQA_KMS_PROVIDER || 'local') === 'local') return;
    // AppRole (VAULT_ROLE_ID + VAULT_SECRET_ID) is an
    // accepted alternative to a static token — kmsConfig.js / vault.js prefer it.
    const appRole = set(env, 'VAULT_ROLE_ID') && set(env, 'VAULT_SECRET_ID');
    if (/^vault/.test(env.QODIQA_KMS_PROVIDER) && !set(env, 'VAULT_TOKEN') && !appRole) return r('VAULT_TOKEN', 'fatal', `is required for QODIQA_KMS_PROVIDER=${env.QODIQA_KMS_PROVIDER}`);
    if (set(env, 'VAULT_TOKEN') && isPlaceholder(env.VAULT_TOKEN)) r('VAULT_TOKEN', 'fatal', PROBLEM_TEXT.placeholder);
    if (set(env, 'VAULT_SECRET_ID') && isPlaceholder(env.VAULT_SECRET_ID)) r('VAULT_SECRET_ID', 'fatal', PROBLEM_TEXT.placeholder);
  } },
  { id: 'secret.channel_tokens', check(env, p, r) {
    for (const n of Object.keys(env).filter((k) => /^(ALERT_.*(TOKEN|SECRET|API_KEY|ROUTING_KEY|AUTH_TOKEN)|QODIQA_LOGSHIP_.*(API_KEY|TOKEN)|HF_TOKEN)$/.test(k))) {
      if (set(env, n) && isPlaceholder(env[n])) r(n, p === 'prod' ? 'fatal' : 'warn', PROBLEM_TEXT.placeholder);
    }
  } },
  { id: 'dead.sign_token', check(env, p, r) {
    if (set(env, 'QODIQA_SIGN_TOKEN')) r('QODIQA_SIGN_TOKEN', 'warn', 'is a dead variable (nothing reads it) — remove it from the environment');
  } },

  // 3. Providers
  { id: 'providers', check(env, p, r, ctx) {
    const enabled = [];
    for (const name of KEYED_PROVIDERS) {
      const { variable, describe } = PROVIDER_KEY_FORMATS[name];
      const st = providerKeyStatus(name, env[variable]);
      if (st === 'valid') enabled.push(name);
      else if (st !== 'absent') {
        const why = st === 'placeholder' ? 'is a placeholder value' : `does not match the expected format (${describe})`;
        r(variable, p === 'prod' ? 'fatal' : 'warn', `${why}; the ${name} provider is not enabled`);
      }
    }
    for (const [name, variable] of Object.entries(URL_PROVIDERS)) {
      const st = providerUrlStatus(env[variable]);
      if (st === 'valid') {
        enabled.push(name);
        const u = new URL(env[variable]);
        if (p === 'prod' && u.protocol === 'http:' && !isLoopbackHost(u.hostname)) r(variable, 'warn', 'uses plain http:// to a non-loopback host');
      } else if (st !== 'absent') r(variable, p === 'prod' ? 'fatal' : 'warn', `is not a valid http(s) URL; the ${name} provider is not enabled`);
    }
    // the two cloud providers need several values together (services/providers/azure.js, bedrock.js)
    for (const [name, st] of [['azure', azureConfigStatus(env)], ['bedrock', bedrockConfigStatus(env)]]) {
      if (st.status === 'valid') enabled.push(name);
      else if (st.status !== 'absent') r(name === 'azure' ? 'AZURE_OPENAI_*' : 'BEDROCK_*', p === 'prod' ? 'fatal' : 'warn', `${st.problems.join('; ')}; the ${name} provider is not enabled`);
    }
    ctx.providers = enabled;
    if (enabled.length === 0) r('(providers)', 'fatal', 'no valid AI provider is configured (set a valid OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, MISTRAL_API_KEY, LLAMA_BASE_URL or LOCAL_BASE_URL)');
  } },

  // Launch plan R-06 / R-07: optional local-provider output cap and restrictive model allowlist. Both are opt-in;
  // a malformed value is ignored by services/providers/config.js (WARN) — refused here in production so an operator
  // who meant to cap output never runs uncapped by typo. Parsing mirrors config.js parseLocalMaxTokens /
  // parseLocalAllowedModels (parity pinned in bootValidator.test.js).
  { id: 'provider_limits', check(env, p, r) {
    // R-06 (local) and R-23 (hosted, post-launch prep): the same 1..8192 opt-in output cap.
    for (const [name, label] of [['LOCAL', 'local'], ['OPENAI', 'openai'], ['MISTRAL', 'mistral'], ['LLAMA', 'llama'], ['GEMINI', 'gemini'], ['AZURE_OPENAI', 'azure'], ['BEDROCK', 'bedrock']]) {
      const v = `${name}_MAX_TOKENS`; const mt = env[v];
      if (mt === undefined || String(mt).trim() === '') continue;
      const t = String(mt).trim();
      const n = /^[0-9]+$/.test(t) ? Number(t) : NaN;
      if (!(Number.isSafeInteger(n) && n >= 1 && n <= 8192)) r(v, p === 'prod' ? 'fatal' : 'warn', `must be an integer between 1 and 8192 (output-token cap for the ${label} provider)`);
    }
    const am = env.PROVIDER_ALLOWED_MODELS_LOCAL;
    if (typeof am === 'string' && am.trim() !== '') {
      const ids = am.split(',').map((x) => x.trim()).filter(Boolean);
      // eslint-disable-next-line no-control-regex
      if (ids.length === 0 || ids.some((m) => m.length > 128 || /[\x00-\x1F\x7F]/.test(m))) r('PROVIDER_ALLOWED_MODELS_LOCAL', p === 'prod' ? 'fatal' : 'warn', 'must be a comma-separated list of valid model ids');
    }
  } },

  // OIDC federation. The file itself is validated when the sign router is built (a bad file is a failed start); here only what must never reach production.
  { id: 'oidc', check(env, p, r) {
    if (env.QODIQA_OIDC_ALLOW_INSECURE === 'true') r('QODIQA_OIDC_ALLOW_INSECURE', p === 'prod' ? 'fatal' : 'warn', 'permits a plain-http / loopback identity provider (development only) and is not permitted in production');
  } },

  // 4. Semantic guards (no semantic value is changed here)
  { id: 'semantic', check(env, p, r) {
    for (const n of SEM_FORBIDDEN_IN_PROD) {
      if (set(env, n)) r(n, p === 'prod' ? 'fatal' : 'warn', 'overrides semantic enforcement (kill switch, classifier list, threshold or band) and is not permitted in production');
    }
    for (const [n, dflt] of Object.entries(SEM_GATE_DEFAULTS)) {
      if (!set(env, n) || env[n] === dflt) continue;
      // Production without the fine-tuned screening model is allowed, but only on purpose: the operator must acknowledge it
      // with QODIQA_SEM_FT3_OFF_ACK=true, and the boot then records a warning that content screening is reduced.
      if (n === 'QODIQA_SEM_FT3_ENABLED' && env[n] === 'false' && env.QODIQA_SEM_FT3_OFF_ACK === 'true') {
        r(n, 'warn', 'the fine-tuned screening gate is OFF by explicit acknowledgement (QODIQA_SEM_FT3_OFF_ACK=true): content screening is reduced to the base gates');
        continue;
      }
      if (n === 'QODIQA_SEM_EMBEDDING_ENABLED' && env[n] === 'false' && env.QODIQA_SEM_EMBEDDING_OFF_ACK === 'true') {
        r(n, 'warn', 'the embedding screening layer is OFF by explicit acknowledgement (QODIQA_SEM_EMBEDDING_OFF_ACK=true): content screening is limited to the rule engine');
        continue;
      }
      if (n === 'QODIQA_SEM_EMBEDDING_ENABLED' && env[n] === 'false') {
        r(n, p === 'prod' ? 'fatal' : 'warn', `changes the shipped semantic gate set (shipped default: ${dflt}) and is not permitted in production; to run without the embedding screening layer set QODIQA_SEM_EMBEDDING_OFF_ACK=true as well`);
        continue;
      }
      const hint = n === 'QODIQA_SEM_FT3_ENABLED' && env[n] === 'false' ? '; to run without the fine-tuned screening model set QODIQA_SEM_FT3_OFF_ACK=true as well' : '';
      r(n, p === 'prod' ? 'fatal' : 'warn', `changes the shipped semantic gate set (shipped default: ${dflt}) and is not permitted in production${hint}`);
    }
  } },

  // 5. Rate limiting
  { id: 'rate_limit', check(env, p, r, ctx) {
    const rl = resolveRl(env); ctx.rateLimit = rl;
    if (rl.enabled && rl.hasRedisUrl) return;
    if (!rl.enabled) return r('RL_ENABLED', p === 'prod' ? 'fatal' : 'warn', 'RL_ENABLED=false turns the HTTP rate limiter off (every route unthrottled)');
    r('REDIS_URL', p === 'prod' ? 'fatal' : 'warn', 'REDIS_URL is unset: the rate limiter (and nonce/lockout stores) would use the default redis://localhost:6379');
  } },

  // 6. Transport security
  { id: 'tls.pg', check(env, p, r, ctx) {
    ctx.pgEnabled = env.QODIQA_PG_ENABLED === 'true';
    ctx.pgSsl = resolvePgSsl(env, p);
    if (p === 'prod' && ctx.pgEnabled && !ctx.pgSsl) r('QODIQA_PG_SSL', 'fatal', 'disables PostgreSQL TLS, which is not permitted in production');
  } },
  { id: 'tls.redis', check(env, p, r, ctx) {
    ctx.redisTls = resolveRedisTls(env);
    if (p === 'prod' && set(env, 'REDIS_URL') && !ctx.redisTls) r('REDIS_URL', 'fatal', "is a plaintext Redis connection; production requires rediss:// or REDIS_TLS=true");
    if (env.REDIS_TLS_REJECT_UNAUTHORIZED === 'false') r('REDIS_TLS_REJECT_UNAUTHORIZED', p === 'prod' ? 'fatal' : 'warn', 'disables TLS certificate verification (man-in-the-middle)');
    if (set(env, 'REDIS_TLS_CERT') !== set(env, 'REDIS_TLS_KEY')) r('REDIS_TLS_CERT', 'fatal', 'REDIS_TLS_CERT and REDIS_TLS_KEY must both be set or both be unset');
    if (set(env, 'REDIS_URL') && !/^rediss?:\/\//.test(env.REDIS_URL)) r('REDIS_URL', 'fatal', "has an unsupported scheme (use redis:// or rediss://)");
    else if (set(env, 'REDIS_URL')) { try { new URL(env.REDIS_URL); } catch { r('REDIS_URL', 'fatal', 'is not a valid URL'); } }
  } },

  // 6c.: switches that silently weaken a production deployment
  { id: 'security_switches', check(env, p, r) {
    if (p !== 'prod') return;
    // a must-be-on switch is accepted only unset or exactly 'true'. The consumers do not agree on what a
    // truthy spelling is (logSanitizerConfig enables scanning only for the exact string 'true', so 'TRUE' / '1' / 'yes'
    // silently turned redaction OFF while the old false-pattern check passed) — refuse anything else.
    const off = (v) => v !== undefined && v !== null && String(v).trim() !== '' && String(v).trim() !== 'true';
    if (off(env.QODIQA_OPS_AUTH_LOCKOUT_ENABLED)) r('QODIQA_OPS_AUTH_LOCKOUT_ENABLED', 'fatal', 'disables the operator-API brute-force lockout, which production requires');
    if (off(env.POLICY_GOVERNANCE_STRICT_MODE)) r('POLICY_GOVERNANCE_STRICT_MODE', 'fatal', 'relaxes policy-governance maker-checker (reviewer and approver may be one person), which production refuses');
    if (off(env.ENFORCE_HTTPS_PROTO)) r('ENFORCE_HTTPS_PROTO', 'fatal', 'disables the HTTPS-only check behind a trusted proxy, which production requires');
    if (String(env.ALERT_EMAIL_TRUSTED_RELAY_ONLY || '').toLowerCase() === 'true') r('ALERT_EMAIL_TRUSTED_RELAY_ONLY', 'fatal', 'allows SMTP AUTH to a relay without TLS (credentials in clear), which production refuses');
    for (const n of ['LOG_SANITIZER_SCAN_PII', 'LOG_SANITIZER_SCAN_TOKENS', 'LOG_SANITIZER_SCAN_CRYPTO']) {
      if (off(env[n])) r(n, 'fatal', 'turns off log redaction of credentials / PII / key material, which production requires');
    }
  } },

  // 6b. Proxy trust
  { id: 'trusted_proxy', check(env, p, r) {
    const raw = env.TRUSTED_PROXY === undefined ? 'loopback' : String(env.TRUSTED_PROXY);
    const entries = raw.split(',').map((x) => x.trim()).filter(Boolean);
    const trustAll = entries.filter((x) => /^(true|\*|all)$/i.test(x) || /\/0$/.test(x));
    if (trustAll.length) r('TRUSTED_PROXY', p === 'prod' ? 'fatal' : 'warn', `trusts every peer (${trustAll.join(', ')}): any client could spoof X-Forwarded-For`);
    const broad = entries.filter((x) => /^(uniquelocal|linklocal)$/i.test(x) || /^(10\.0\.0\.0\/8|172\.16\.0\.0\/12|192\.168\.0\.0\/16|fc00::\/7|169\.254\.0\.0\/16|fe80::\/10)$/i.test(x));
    // in production a broad private range is fatal unless the operator
    // acknowledges that a NetworkPolicy/firewall lets ONLY the proxy reach the gateway (QODIQA_TRUSTED_PROXY_BROAD_ACK).
    if (broad.length && !trustAll.length) {
      const ack = env.QODIQA_TRUSTED_PROXY_BROAD_ACK === 'true';
      const sev = p === 'prod' && !ack ? 'fatal' : 'warn';
      r('TRUSTED_PROXY', sev, `trusts whole private ranges (${broad.join(', ')}): any host in them can spoof X-Forwarded-For — list your proxy/ingress addresses instead${p === 'prod' && !ack ? ', or set QODIQA_TRUSTED_PROXY_BROAD_ACK=true only where a NetworkPolicy/firewall guarantees that nothing but the proxy can reach the gateway' : ''}`);
    }
    if (set(env, 'QODIQA_OPS_TRUST_PROXY')) r('QODIQA_OPS_TRUST_PROXY', 'warn', 'is deprecated and ignored: the admin IP allowlist uses TRUSTED_PROXY like every other consumer');
  } },

  // 6c. Credentials
  { id: 'credentials', check(env, p, r) {
    if (env.QODIQA_SIGN_AUTH_LOCKOUT_ENABLED === 'false') r('QODIQA_SIGN_AUTH_LOCKOUT_ENABLED', p === 'prod' ? 'fatal' : 'warn', 'turns off the /sign auth-failure lockout (unlimited signing-key guessing)');
    if (env.QODIQA_OPS_MFA_REQUIRED === 'false') r('QODIQA_OPS_MFA_REQUIRED', p === 'prod' ? 'fatal' : 'warn', 'turns off operator MFA step-up for privileged operations');
    const ttl = parseInt(env.QODIQA_API_KEY_TTL_DAYS, 10);
    if (Number.isFinite(ttl) && ttl > 365) r('QODIQA_API_KEY_TTL_DAYS', p === 'prod' ? 'fatal' : 'warn', `sets API keys to live ${ttl} days; the maximum permitted in production is 365`);
  } },

  // 7. Admin / diagnostics planes
  { id: 'planes', check(env, p, r, ctx) {
    ctx.planes = resolveOpsPlanes(env, p);
    if (p === 'prod' && env.QODIQA_PORTAL_DEV_AUTH_ENABLED === 'true') r('QODIQA_PORTAL_DEV_AUTH_ENABLED', 'fatal', 'enables the tenant-portal development authentication stub, which is not permitted in production');
  } },

  // 8. Retained production rules
  { id: 'retained.policy_file', check(env, p, r) {
    if (p === 'prod' && !set(env, 'POLICY_FILE')) r('POLICY_FILE', 'fatal', 'is required in production (the repository policies.json is a development fixture; start from deploy/env/production.policies.example)');
  } },
  { id: 'retained.keys_path', check(env, p, r, ctx) {
    for (const m of checks.productionKeystorePath(env, ctx.projectRoot)) r('QODIQA_KEYS_PATH', 'fatal', m);
  } },
  { id: 'retained.key_file_paths', check(env, p, r, ctx) { //
    for (const f of checks.productionKeyFilePaths(env, ctx.projectRoot)) r(f.variable, 'fatal', f.message);
  } },
  { id: 'retained.journal_dir', check(env, p, r, ctx) { //
    // unset = warn (the shipped compose / Kubernetes templates set it); a path inside the application directory or on a container's ephemeral layer = refuse
    for (const m of checks.productionJournalDir(env, ctx.projectRoot)) r('QODIQA_PRQ_JOURNAL_DIR', /is not set in production/.test(m) ? 'warn' : 'fatal', m);
  } },
  { id: 'anchoring.external', check(env, p, r, ctx) { //
    const fsx = require('fs');
    if (set(env, 'QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS') && !(Number.isInteger(Number(env.QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS)) && Number(env.QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS) >= 1000 && Number(env.QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS) <= 7 * 24 * 3600 * 1000)) {
      r('QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS', p === 'prod' ? 'fatal' : 'warn', 'must be an integer from 1000 to 604800000 (milliseconds between externally anchored checkpoints; the default is 24 h)');
    }
    if (set(env, 'QODIQA_ANCHOR_GIT_REPO')) {
      const repo = path.resolve(env.QODIQA_ANCHOR_GIT_REPO); const root = path.resolve(ctx.projectRoot);
      if (p === 'prod' && (repo === root || repo.startsWith(root + path.sep))) r('QODIQA_ANCHOR_GIT_REPO', 'fatal', 'resolves inside the application directory: an anchors repository there is under the gateway operator control and anchors nothing; use a working tree outside it (mirrored elsewhere)');
      else if (!fsx.existsSync(path.join(repo, '.git'))) r('QODIQA_ANCHOR_GIT_REPO', p === 'prod' ? 'fatal' : 'warn', 'is not a git working tree (no .git directory): create it with git init and give it a committer identity / signing key');
    }
    for (const n of ['QODIQA_ANCHOR_OTS_EXEC', 'QODIQA_ANCHOR_TSA_EXEC']) {
      if (set(env, n) && !fsx.existsSync(env[n])) r(n, p === 'prod' ? 'fatal' : 'warn', 'names an executable that does not exist');
    }
  } },
  { id: 'retained.kms_advisory', check(env, p, r) {
    for (const m of checks.productionKmsProvider(env)) r('QODIQA_KMS_PROVIDER', 'warn', m);
  } },
  { id: 'retained.keystore_sealed', check(env, p, r) { // OA-RC-2
    if (p === 'prod' && env.QODIQA_KEYSTORE_REQUIRE_SEALED === 'false') r('QODIQA_KEYSTORE_REQUIRE_SEALED', 'warn', "is 'false': unsealed (unauthenticated) key files are accepted and sealed on first use in production — seal them offline (scripts/keys/seal-keystore.js) and remove this override");
  } },
  { id: 'retained.strict_replay', check(env, p, r) {
    if (p === 'prod' && env.STRICT_REPLAY_PROTECTION === 'false') r('STRICT_REPLAY_PROTECTION', 'warn', 'is ignored in production (strict replay protection is always on)');
  } },
];

// ── The one schema ────────────────────────────────────────────────────────────
function buildSchema({ projectRoot = PROJECT_ROOT, fileExists = (p) => fs.existsSync(p), ctx }) {
  const shape = { NODE_ENV: z.string().optional() };
  const issue = (c, variable, severity, rule, text) => c.addIssue({
    code: z.ZodIssueCode.custom, path: [variable], message: text.startsWith(variable) ? text : `${variable}: ${text}`, params: { severity, rule },
  });
  for (const [n, [min, max]] of Object.entries(INT_VARS)) {
    shape[n] = z.string().optional().superRefine((v, c) => {
      if (v === undefined || v === '') return;
      const i = Number(v.trim());
      if (!Number.isInteger(i) || String(i) !== v.trim()) issue(c, n, 'shape', 'shape.int', `must be a whole number between ${min} and ${max}`);
      else if (i < min || i > max) issue(c, n, 'shape', 'shape.int', `is out of range [${min}, ${max}]`);
    });
  }
  for (const n of BOOL_VARS) {
    shape[n] = z.string().optional().superRefine((v, c) => {
      if (v !== undefined && v !== '' && v !== 'true' && v !== 'false') issue(c, n, 'shape', 'shape.bool', "must be 'true' or 'false'");
    });
  }
  for (const n of PATH_VARS) {
    shape[n] = z.string().optional().superRefine((v, c) => {
      if (v && !fileExists(path.resolve(v))) issue(c, n, 'fatal', 'shape.path', 'points to a file that does not exist');
    });
  }
  return z.object(shape).passthrough().superRefine((env, c) => {
    const raw = env.NODE_ENV;
    if (raw === undefined || raw === '') {
      issue(c, 'NODE_ENV', 'fatal', 'profile', "is not set; set it to exactly 'production', 'development' or 'test'");
      ctx.profile = null; return;
    }
    if (!Object.prototype.hasOwnProperty.call(PROFILES, raw)) {
      issue(c, 'NODE_ENV', 'fatal', 'profile', `is '${raw}'; only exactly 'production', 'development' or 'test' is accepted`);
      ctx.profile = null; return;
    }
    ctx.profile = PROFILES[raw];
    ctx.projectRoot = projectRoot;
    ctx.fileExists = fileExists; // rules use the same injectable existence check as the path shapes
    for (const rule of RULES) {
      rule.check(env, ctx.profile, (variable, severity, text) => issue(c, variable, severity, rule.id, text), ctx);
    }
  });
}

/**
 * Validate an environment. Pure: returns { profile, nodeEnv, fatal[], warnings[], resolved }.
 * Shape errors (malformed integers/booleans) are fatal in production and warnings elsewhere,
 * exactly as envValidation.js treated them.
 */
function validateBoot(env = process.env, opts = {}) {
  const ctx = {};
  const res = buildSchema({ ...opts, ctx }).safeParse({ ...env });
  const issues = res.success ? [] : res.error.issues;
  const toV = (i) => ({ variable: i.path[0] ?? '(config)', rule: i.params?.rule ?? 'zod', message: i.message });
  const fatal = []; const warnings = [];
  for (const i of issues) {
    let sev = i.params?.severity || 'fatal';
    if (sev === 'shape') sev = ctx.profile === 'prod' ? 'fatal' : 'warn';
    (sev === 'fatal' ? fatal : warnings).push(toV(i));
  }
  const resolved = ctx.profile ? {
    profile: ctx.profile, nodeEnv: env.NODE_ENV, providers: ctx.providers || [], rateLimit: ctx.rateLimit,
    pgEnabled: ctx.pgEnabled, pgSsl: ctx.pgSsl, redisTls: ctx.redisTls, planes: ctx.planes,
  } : null;
  return { profile: ctx.profile || null, nodeEnv: env.NODE_ENV ?? null, fatal, warnings, resolved };
}

/**
 * Config fingerprint: sha256 over every QODIQA-relevant variable, where secret-like
 * variables contribute only "set"/"unset" (never their value).
 */
const SECRETISH = /(SECRET|PASSWORD|PASS$|_KEY$|API_KEY|TOKEN|KEK|PEPPER|CREDENTIAL|PRIVATE)/;
function configFingerprint(env = process.env) {
  const keys = Object.keys(env).filter((k) => /^(QODIQA_|REDIS_|RL_|NODE_ENV$|PORT$|POLICY_FILE$|OPENAI_|ANTHROPIC_|GEMINI_|MISTRAL_|LLAMA_|LOCAL_|ALERT_|VAULT_|STRICT_REPLAY_PROTECTION$|MAX_BODY_BYTES$|AI_CHAT_TIMEOUT_MS$|REVOCATION_SIGNING_KEY$|ORG_STATUS_SIGNING_KEY$|HF_TOKEN$|PROVIDER_)/.test(k)).sort();
  const canon = keys.map((k) => [k, SECRETISH.test(k) && !/_(PATH|FILE|ID|MS|TTL|DAYS)$/.test(k) ? (set(env, k) ? '<set>' : '<unset>') : env[k]]);
  return { sha256: crypto.createHash('sha256').update(JSON.stringify(canon)).digest('hex'), variableCount: keys.length };
}

let _last = null;

/** Called by server/startup.js before any listener opens. Exits non-zero on any fatal violation. */
function runBootValidation({ env = process.env, emit = require('../../../services/logger').emit, exit = (c) => process.exit(c) } = {}) {
  const result = validateBoot(env);
  for (const w of result.warnings) emit('WARN', 'BOOT_CONFIG_WARNING', { variable: w.variable, rule: w.rule, message: w.message });
  if (result.fatal.length > 0) {
    emit('FATAL', 'BOOT_VALIDATION_FATAL', {
      profile: result.profile, nodeEnv: result.nodeEnv, violationCount: result.fatal.length,
      violations: result.fatal.map((f) => ({ variable: f.variable, rule: f.rule, message: f.message })),
      message: 'Refusing to start: the configuration violates the boot rules (docs/configuration/boot-rules.md). Fix every violation listed.',
    });
    exit(1);
    return result;
  }
  emit('INFO', 'BOOT_VALIDATION_OK', { profile: result.profile, warningCount: result.warnings.length });
  _last = { ...result, fingerprint: configFingerprint(env) };
  return result;
}

module.exports = {
  validateBoot,
  runBootValidation,
  configFingerprint,
  getLastBootValidation: () => _last,
  checks,
  // exported for tests and for the semantic drift guard
  SEM_FORBIDDEN_IN_PROD, SEM_GATE_DEFAULTS, SEM_ALLOWED, INT_VARS, BOOL_VARS, PATH_VARS, PROJECT_ROOT,
  resolveRl, resolvePgSsl, resolveRedisTls, resolveOpsPlanes,
};
