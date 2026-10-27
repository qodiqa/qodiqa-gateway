#!/usr/bin/env node
'use strict';

/**
 * Generates docs/configuration/boot-rules.md FROM THE BOOT VALIDATOR ITSELF
 *. Nothing in the rule tables is hand-written: every row is a
 * probe environment run through validateBoot() in all three profiles, and the
 * table records the severity and message the validator ACTUALLY produced. The
 * variable-shape and semantic tables come from the validator's exported lists.
 * So the document cannot drift from the code — and
 * src/infra/config/bootRulesDoc.test.js fails if the committed file is not
 * byte-identical to a fresh generation.
 *
 *   node scripts/config/generate-boot-rules-doc.js           write the doc
 *   node scripts/config/generate-boot-rules-doc.js --check   exit 1 if stale
 *
 * Probe values are fixed, obviously-fake constants (never secrets), so the
 * output is deterministic.
 */

const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');
const OUT = path.join(REPO, 'docs', 'configuration', 'boot-rules.md');
const V = require(path.join(REPO, 'src', 'infra', 'config', 'bootValidator'));

// Deterministic fixed fake values (hex, not secrets; never used outside this doc).
const HEX_A = '0123456789abcdef'.repeat(4).split('').reverse().join('').replace(/^(.{64}).*/, '$1');
const HEX_B = '89abcdef01234567'.repeat(4);
const HEX_C = 'fedcba9876543210'.repeat(4).split('').map((c, i) => (i % 3 ? c : '7')).join('');
const HEX_D = '13579bdf02468ace'.repeat(4);
const HEX_E = '2468ace013579bdf'.repeat(4);
const OUTSIDE = process.platform === 'win32' ? 'C:\\qodiqa-secrets\\keys.json' : '/opt/qodiqa/data/keys.json';

const PROFILES = { prod: 'production', dev: 'development', test: 'test' };
// the validator checks that the provisioned MAC keyring file exists,
// so the production base points at an empty placeholder file in the temp dir
// (never rendered); the "not provisioned" probe uses the fixed path below.
const MAC_RING = path.join(require('os').tmpdir(), 'qodiqa-boot-rules-doc', 'mac-keys.json');
fs.mkdirSync(path.dirname(MAC_RING), { recursive: true });
if (!fs.existsSync(MAC_RING)) fs.writeFileSync(MAC_RING, '{}');
// production requires audit anchoring; the base carries a witness key and public-key file (placeholders in
// the temp dir, outside the key store's directory — never rendered) and an anchor export path.
const WITNESS_DIR = path.join(require('os').tmpdir(), 'qodiqa-boot-rules-doc-witness');
fs.mkdirSync(WITNESS_DIR, { recursive: true });
for (const f of ['witness-key.pem', 'witness-public-keys.json']) { const fp = path.join(WITNESS_DIR, f); if (!fs.existsSync(fp)) fs.writeFileSync(fp, f.endsWith('.json') ? '[]' : ''); }
const ANCHORING = {
  QODIQA_ANCHOR_EXPORT_PATH: path.join(WITNESS_DIR, 'anchors.jsonl'),
  QODIQA_WITNESS_MODE: 'local',
  QODIQA_WITNESS_KEY_PATH: path.join(WITNESS_DIR, 'witness-key.pem'),
  QODIQA_WITNESS_LOG_PATH: path.join(WITNESS_DIR, 'witness-log.jsonl'),
  QODIQA_WITNESS_PUBLIC_KEYS: path.join(WITNESS_DIR, 'witness-public-keys.json'),
};
const MAC_RING_ABSENT = process.platform === 'win32' ? 'C:\\qodiqa-secrets\\mac-keys.json' : '/opt/qodiqa/data/mac-keys.json';

function base(profile) {
  const env = {
    NODE_ENV: PROFILES[profile],
    QODIQA_KEY_ENCRYPTION_KEY: HEX_A,
    QODIQA_EXECUTION_INVARIANT_SECRET: HEX_B,
    QODIQA_CLIENT_ID: 'docs-client',
    LOCAL_BASE_URL: 'http://127.0.0.1:11434/v1',
  };
  // Every profile's base carries the optional-but-recommended variables too, so
  // a probe that REMOVES one shows that profile's real outcome (the table
  // subtracts the base's own findings; a base missing the variable would hide
  // its warning).
  Object.assign(env, {
    QODIQA_DSR_PSEUDONYM_PEPPER: HEX_C,
    RL_ENABLED: 'true',
    REDIS_URL: 'rediss://redis.internal:6380',
  });
  if (profile === 'prod') {
    Object.assign(env, {
      QODIQA_KEYS_PATH: OUTSIDE,
      QODIQA_MAC_KEYS_PATH: MAC_RING,
      POLICY_FILE: path.join(REPO, 'deploy/env/production.policies.example'),
      QODIQA_KMS_PROVIDER: 'aws-kms',
      // every other key file outside the application directory too (fixed paths, never rendered).
      QODIQA_TRANSPARENCY_KEYS_PATH: path.join(path.dirname(OUTSIDE), 'transparency-keys.json'),
      AWS_KMS_EDK_PATH: path.join(path.dirname(OUTSIDE), 'kek.edk'),
      QODIQA_PRQ_JOURNAL_DIR: path.join(path.dirname(OUTSIDE), 'prq-journal'),   //
      ...ANCHORING,
    });
  }
  return env;
}

// [section, condition shown in the doc, mutate(env)]
const PROBES = [
  ['Profile', '`NODE_ENV` unset', (e) => { delete e.NODE_ENV; }],
  ['Profile', "`NODE_ENV` any value other than exactly `production`/`development`/`test`", (e) => { e.NODE_ENV = 'staging'; }],
  ['Secrets', '`QODIQA_KEY_ENCRYPTION_KEY` unset', (e) => { delete e.QODIQA_KEY_ENCRYPTION_KEY; }],
  ['Secrets', '`QODIQA_KEY_ENCRYPTION_KEY` not 64 hex', (e) => { e.QODIQA_KEY_ENCRYPTION_KEY = 'xyz'; }],
  ['Secrets', '`QODIQA_KEY_ENCRYPTION_KEY` all zeros', (e) => { e.QODIQA_KEY_ENCRYPTION_KEY = '0'.repeat(64); }],
  ['Secrets', '`QODIQA_EXECUTION_INVARIANT_SECRET` unset', (e) => { delete e.QODIQA_EXECUTION_INVARIANT_SECRET; }],
  ['Secrets', '`QODIQA_EXECUTION_INVARIANT_SECRET` not 64 hex', (e) => { e.QODIQA_EXECUTION_INVARIANT_SECRET = 'xyz'; }],
  ['Secrets', '`QODIQA_TRANSPARENCY_KEY_ENCRYPTION_KEY` not 64 hex', (e) => { e.QODIQA_TRANSPARENCY_KEY_ENCRYPTION_KEY = 'xyz'; }],
  ['Secrets', '`QODIQA_CHECKPOINT_KEY_ENCRYPTION_KEY` all zeros', (e) => { e.QODIQA_CHECKPOINT_KEY_ENCRYPTION_KEY = '0'.repeat(64); }],
  ['Secrets', '`QODIQA_AUDIT_KEK_SEPARATION=enforce` with the audit KEKs unset', (e) => { e.QODIQA_AUDIT_KEK_SEPARATION = 'enforce'; }],
  ['Secrets', '`QODIQA_AUDIT_KEK_SEPARATION` not off, warn or enforce', (e) => { e.QODIQA_AUDIT_KEK_SEPARATION = 'maybe'; }],
  ['Secrets', '`QODIQA_EXECUTION_INVARIANT_SECRET` equal to the KEK', (e) => { e.QODIQA_EXECUTION_INVARIANT_SECRET = e.QODIQA_KEY_ENCRYPTION_KEY; }],
  ['Secrets', '`QODIQA_CLIENT_ID` unset', (e) => { delete e.QODIQA_CLIENT_ID; }],
  ['Secrets', '`QODIQA_CLIENT_ID` a placeholder (`test`, `demo`, `default`, …)', (e) => { e.QODIQA_CLIENT_ID = 'demo'; }],
  ['Secrets', '`QODIQA_ADMIN_ENABLED=true` without `QODIQA_OPS_TOKEN`', (e) => { e.QODIQA_ADMIN_ENABLED = 'true'; }],
  ['Secrets', '`QODIQA_OPS_TOKEN` shorter than 32 characters', (e) => { e['QODIQA_OPS_TOKEN'] = 'k3Q9x'; }],
  ['Secrets', '`REDIS_PASSWORD` shorter than 16 characters', (e) => { e['REDIS_PASSWORD'] = 'Zq81mPx'; }],
  ['Secrets', 'PostgreSQL enabled, app-role password (`QODIQA_PG_PASSWORD`) unset', (e) => { e.QODIQA_PG_ENABLED = 'true'; e['QODIQA_PG_RETENTION_PASSWORD'] = HEX_E; e['QODIQA_PG_SYSTEM_PASSWORD'] = HEX_E; e['QODIQA_PG_REPORTING_PASSWORD'] = HEX_E; }],
  ['Secrets', '`QODIQA_PG_PASSWORD` shorter than 16 characters', (e) => { e.QODIQA_PG_ENABLED = 'true'; e['QODIQA_PG_PASSWORD'] = 'Kq7-zP2m'; e['QODIQA_PG_RETENTION_PASSWORD'] = HEX_E; e['QODIQA_PG_SYSTEM_PASSWORD'] = HEX_E; e['QODIQA_PG_REPORTING_PASSWORD'] = HEX_E; }],
  ['Secrets', 'migration credential (`QODIQA_PG_MIG_PASSWORD`) present in the gateway environment', (e) => { e['QODIQA_PG_MIG_PASSWORD'] = HEX_D; }],
  ['Secrets', '`QODIQA_PORTAL_ENABLED=true` without `QODIQA_PORTAL_SESSION_SECRET`', (e) => { e.QODIQA_PORTAL_ENABLED = 'true'; }],
  ['Secrets', '`QODIQA_DSR_PSEUDONYM_PEPPER` (and `QODIQA_SIGNING_SECRET`) unset', (e) => { delete e.QODIQA_DSR_PSEUDONYM_PEPPER; }],
  ['Secrets', 'MAC keyring file (`QODIQA_MAC_KEYS_PATH`, default beside `QODIQA_KEYS_PATH`) not provisioned', (e) => { e.QODIQA_MAC_KEYS_PATH = MAC_RING_ABSENT; }],
  ['Secrets', 'deprecated `REVOCATION_SIGNING_KEY` / `ORG_STATUS_SIGNING_KEY` still set', (e) => { e.REVOCATION_SIGNING_KEY = HEX_D; }],
  ['Secrets', '`QODIQA_KMS_PROVIDER=vault-kv` without `VAULT_TOKEN`', (e) => { e.QODIQA_KMS_PROVIDER = 'vault-kv'; }],
  ['Secrets', 'an `ALERT_*_TOKEN` channel credential is a placeholder', (e) => { e['ALERT_SLACK_TOKEN'] = 'your-slack-token'; }],
  ['Secrets', '`QODIQA_SIGN_TOKEN` set (dead)', (e) => { e.QODIQA_SIGN_TOKEN = HEX_D; }],
  ['Control plane', '`QODIQA_CONTROL_PLANE_BACKEND=memory`', (e) => { e.QODIQA_CONTROL_PLANE_BACKEND = 'memory'; }],
  ['Control plane', '`QODIQA_CONTROL_PLANE_BACKEND` not `pg`/`memory`', (e) => { e.QODIQA_CONTROL_PLANE_BACKEND = 'files'; }],
  ['Bench', '`QODIQA_BENCH_STAGE_TIMING=true`', (e) => { e.QODIQA_BENCH_STAGE_TIMING = 'true'; }],
  ['Bench', '`QODIQA_BENCH_STAGE_TIMING` not `true`/`false`', (e) => { e.QODIQA_BENCH_STAGE_TIMING = 'yes'; }],
  ['Performance', '`QODIQA_ADMISSION_AI_CHAT_MAX_INFLIGHT` out of range', (e) => { e.QODIQA_ADMISSION_AI_CHAT_MAX_INFLIGHT = '0'; }],
  ['Performance', '`QODIQA_INFERENCE_WORKERS` not an integer 0-64', (e) => { e.QODIQA_INFERENCE_WORKERS = 'many'; }],
  ['API', '`QODIQA_BLOCK_HTTP_MODE` not `decision`/`status`', (e) => { e.QODIQA_BLOCK_HTTP_MODE = 'on'; }],
  ['Control plane', 'PostgreSQL enabled, control-role password (`QODIQA_PG_CONTROL_PASSWORD`) unset', (e) => { Object.assign(e, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_PASSWORD: HEX_C, QODIQA_PG_RETENTION_PASSWORD: HEX_E, QODIQA_PG_SYSTEM_PASSWORD: HEX_E, QODIQA_PG_REPORTING_PASSWORD: HEX_E }); }],
  ['Control plane', '`QODIQA_PG_CONTROL_PASSWORD` shorter than 16 characters', (e) => { Object.assign(e, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_PASSWORD: HEX_C, QODIQA_PG_RETENTION_PASSWORD: HEX_E, QODIQA_PG_SYSTEM_PASSWORD: HEX_E, QODIQA_PG_REPORTING_PASSWORD: HEX_E, QODIQA_PG_CONTROL_PASSWORD: 'Kq7-zP2m' }); }],
  ['Control plane', '`QODIQA_CONTROL_PLANE_MAX_STALENESS_MS` above 5000', (e) => { e.QODIQA_CONTROL_PLANE_MAX_STALENESS_MS = '60000'; }],
  ['Providers', 'no valid provider configured', (e) => { delete e.LOCAL_BASE_URL; }],
  ['Providers', 'a provider key is a placeholder (e.g. `OPENAI_API_KEY=sk-test`)', (e) => { e.OPENAI_API_KEY = 'sk-test'; }],
  ['Providers', 'a provider key has the wrong format (e.g. `ANTHROPIC_API_KEY` without `sk-ant-`)', (e) => { e.ANTHROPIC_API_KEY = 'sk-' + 'a'.repeat(40); }],
  ['Providers', '`LOCAL_BASE_URL`/`LLAMA_BASE_URL` not an http(s) URL', (e) => { e.LOCAL_BASE_URL = 'ftp://127.0.0.1/v1'; e.GEMINI_API_KEY = 'docsfixturegeminikey' + 'a'.repeat(12); }],
  ['Providers', '`LOCAL_BASE_URL` plain `http://` to a non-loopback host', (e) => { e.LOCAL_BASE_URL = 'http://llm.internal:11434/v1'; }],
  //
  ['Audit integrity', '`QODIQA_AUDIT_MIRROR_RECOVERY_MODE=true` without a `QODIQA_AUDIT_RECOVERY_MODE_UNTIL` within 24 h', (e) => { e.QODIQA_AUDIT_MIRROR_RECOVERY_MODE = 'true'; }],
  ['Audit integrity', '`QODIQA_AUDIT_VERIFIER_RECOVERY_MODE=true` without a `QODIQA_AUDIT_RECOVERY_MODE_UNTIL` within 24 h', (e) => { e.QODIQA_AUDIT_VERIFIER_RECOVERY_MODE = 'true'; }],
  ['Semantic', 'any threshold / band / classifier / kill-switch override (list below)', (e) => { e.QODIQA_SEM_C_SIMILARITY_THRESHOLD = '0.9'; }],
  ['Semantic', 'a gate switch away from its shipped default (e.g. `QODIQA_SEM_FT3_ENABLED=false`)', (e) => { e.QODIQA_SEM_FT3_ENABLED = 'false'; }],
  ['Semantic', '`QODIQA_SEM_EMBEDDING_ENABLED=false` together with `QODIQA_SEM_EMBEDDING_OFF_ACK=true` (production without the embedding screening layer, on purpose)', (e) => { e.QODIQA_SEM_EMBEDDING_ENABLED = 'false'; e.QODIQA_SEM_EMBEDDING_OFF_ACK = 'true'; }],
  ['Semantic', '`QODIQA_SEM_FT3_ENABLED=false` together with `QODIQA_SEM_FT3_OFF_ACK=true` (production without the fine-tuned screening model, on purpose)', (e) => { e.QODIQA_SEM_FT3_ENABLED = 'false'; e.QODIQA_SEM_FT3_OFF_ACK = 'true'; }],
  ['Rate limiting', '`RL_ENABLED=false` (HTTP rate limiter off)', (e) => { e.RL_ENABLED = 'false'; }],
  ['Rate limiting', '`RL_ENABLED=true` without `REDIS_URL`', (e) => { e.RL_ENABLED = 'true'; delete e.REDIS_URL; }],
  ['Proxy trust', '`TRUSTED_PROXY` trusts every peer (`0.0.0.0/0`)', (e) => { e.TRUSTED_PROXY = '0.0.0.0/0'; }],
  ['Proxy trust', '`TRUSTED_PROXY` trusts whole private ranges (`uniquelocal`)', (e) => { e.TRUSTED_PROXY = 'loopback,uniquelocal'; }],
  ['Proxy trust', 'deprecated `QODIQA_OPS_TRUST_PROXY` set', (e) => { e.QODIQA_OPS_TRUST_PROXY = 'true'; }],
  //
  ['Security switches', '`QODIQA_OPS_AUTH_LOCKOUT_ENABLED=false` (operator-API lockout off)', (e) => { e.QODIQA_OPS_AUTH_LOCKOUT_ENABLED = 'false'; }],
  ['Security switches', '`POLICY_GOVERNANCE_STRICT_MODE=false` (relaxed maker-checker)', (e) => { e.POLICY_GOVERNANCE_STRICT_MODE = 'false'; }],
  ['Security switches', '`ENFORCE_HTTPS_PROTO=false` (HTTPS-only check off)', (e) => { e.ENFORCE_HTTPS_PROTO = 'false'; }],
  ['Security switches', '`ALERT_EMAIL_TRUSTED_RELAY_ONLY=true` (SMTP AUTH without TLS)', (e) => { e.ALERT_EMAIL_TRUSTED_RELAY_ONLY = 'true'; }],
  ['Security switches', 'a `LOG_SANITIZER_SCAN_*` redaction switch off (e.g. `LOG_SANITIZER_SCAN_TOKENS=false`)', (e) => { e.LOG_SANITIZER_SCAN_TOKENS = 'false'; }],
  ['Credentials', '`QODIQA_SIGN_AUTH_LOCKOUT_ENABLED=false` (/sign auth-failure lockout off)', (e) => { e.QODIQA_SIGN_AUTH_LOCKOUT_ENABLED = 'false'; }],
  ['Credentials', '`QODIQA_OPS_MFA_REQUIRED=false` (operator MFA step-up off)', (e) => { e.QODIQA_OPS_MFA_REQUIRED = 'false'; }],
  ['Credentials', '`QODIQA_API_KEY_TTL_DAYS` above 365', (e) => { e.QODIQA_API_KEY_TTL_DAYS = '400'; }],
  ['Transport', '`QODIQA_PG_SSL=false` with PostgreSQL enabled', (e) => { Object.assign(e, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_SSL: 'false', QODIQA_PG_PASSWORD: HEX_C, QODIQA_PG_RETENTION_PASSWORD: HEX_E, QODIQA_PG_SYSTEM_PASSWORD: HEX_E, QODIQA_PG_REPORTING_PASSWORD: HEX_E, QODIQA_PG_CONTROL_PASSWORD: HEX_E }); }],
  ['Transport', 'plaintext `redis://` `REDIS_URL`', (e) => { e.RL_ENABLED = 'true'; e.REDIS_URL = 'redis://redis.internal:6379'; }],
  ['Transport', '`REDIS_TLS_REJECT_UNAUTHORIZED=false`', (e) => { e.REDIS_TLS_REJECT_UNAUTHORIZED = 'false'; }],
  ['Transport', 'only one of `REDIS_TLS_CERT` / `REDIS_TLS_KEY` set', (e) => { e.REDIS_TLS_CERT = __filename; }],
  ['Transport', '`REDIS_URL` with a non-redis scheme', (e) => { e.RL_ENABLED = 'true'; e.REDIS_URL = 'http://redis.internal:6379'; }],
  ['Planes', '`QODIQA_PORTAL_DEV_AUTH_ENABLED=true`', (e) => { e.QODIQA_PORTAL_DEV_AUTH_ENABLED = 'true'; }],
  ['Retained', '`POLICY_FILE` unset', (e) => { delete e.POLICY_FILE; }],
  ['Retained', '`QODIQA_KEYS_PATH` unset or inside the repository', (e) => { delete e.QODIQA_KEYS_PATH; }],
  // the same rule for every other key file (unset probes only: an in-repository path renders the
  // machine-specific application directory into the message).
  ['Retained', '`QODIQA_TRANSPARENCY_KEYS_PATH` unset or inside the repository (the checkpoint key file defaults beside it; `QODIQA_CHECKPOINT_KEYS_PATH`, `QODIQA_MAC_KEYS_PATH`, `QODIQA_KEYS_ARCHIVE_PATH`, `QODIQA_WITNESS_KEY_PATH` are refused inside the repository when set)', (e) => { delete e.QODIQA_TRANSPARENCY_KEYS_PATH; }],
  ['Retained', 'cloud-KMS wrapped-KEK file (`AWS_KMS_EDK_PATH` / `GCP_WRAPPED_KEY_PATH` / `AZURE_WRAPPED_KEY_PATH`, per KEK provider) unset or inside the repository', (e) => { delete e.AWS_KMS_EDK_PATH; }],
  // the file journal must be on a persistent volume (unset only warns; the in-repository path renders the machine-specific directory, so only the unset probe)
  ['Retained', '`QODIQA_PRQ_JOURNAL_DIR` unset', (e) => { delete e.QODIQA_PRQ_JOURNAL_DIR; }],
  ['Anchoring', '`QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS` not an integer 1000..604800000', (e) => { e.QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS = 'soon'; }],
  ['Anchoring', '`QODIQA_ANCHOR_GIT_REPO` not a git working tree', (e) => { e.QODIQA_ANCHOR_GIT_REPO = path.join(path.dirname(OUTSIDE), 'no-such-anchor-repo'); }],
  ['Anchoring', '`QODIQA_ANCHOR_OTS_EXEC` names a missing executable', (e) => { e.QODIQA_ANCHOR_OTS_EXEC = path.join(path.dirname(OUTSIDE), 'no-such-ots-adapter'); }],
  ['Retained', '`QODIQA_KMS_PROVIDER=hsm` with `HSM_KEY_INDEX_PATH` unset or inside the repository', (e) => { e.QODIQA_KMS_PROVIDER = 'hsm'; }],
  ['Retained', '`QODIQA_KMS_PROVIDER` `local` or unset', (e) => { delete e.QODIQA_KMS_PROVIDER; }],
  ['Retained', '`STRICT_REPLAY_PROTECTION=false`', (e) => { e.STRICT_REPLAY_PROTECTION = 'false'; }],
  ['Retained', 'audit anchoring not configured (no `QODIQA_ANCHOR_EXPORT_PATH`)', (e) => { delete e.QODIQA_ANCHOR_EXPORT_PATH; }],
  ['Retained', 'no audit witness (`QODIQA_WITNESS_MODE=none`)', (e) => { e.QODIQA_WITNESS_MODE = 'none'; }],
  ['Retained', 'witness public keys unset', (e) => { delete e.QODIQA_WITNESS_PUBLIC_KEYS; }],
  ['Retained', '`QODIQA_DEPLOYMENT_MODE=distributed` (refused in production; no waiver)', (e) => { e.QODIQA_DEPLOYMENT_MODE = 'distributed'; }],
  ['Retained', '`QODIQA_AUDIT_ANCHORING_WAIVER` set (no waiver exists in production)', (e) => { e.QODIQA_AUDIT_ANCHORING_WAIVER = 'any reason at all'; }],
  ['Retained', '`LOG_SANITIZER_SCAN_TOKENS` set to anything but `true` (e.g. `TRUE`)', (e) => { e.LOG_SANITIZER_SCAN_TOKENS = 'TRUE'; }],
  ['Shapes', 'an integer variable not a whole number (e.g. `PORT=eighty`)', (e) => { e.PORT = 'eighty'; }],
  ['Shapes', 'a boolean variable not `true`/`false`', (e) => { e.QODIQA_PG_ENABLED = 'yes'; }],
  ['Shapes', 'a certificate path that does not exist', (e) => { e.QODIQA_PG_SSL_CA = path.join(REPO, 'no-such-dir', 'ca.pem'); }],
];

function outcome(profile, mutate) {
  const baseline = V.validateBoot(base(profile));
  const bf = new Set(baseline.fatal.map((v) => v.variable + v.message));
  const bw = new Set(baseline.warnings.map((v) => v.variable + v.message));
  const env = base(profile);
  mutate(env);
  const r = V.validateBoot(env);
  const fatal = r.fatal.filter((v) => !bf.has(v.variable + v.message));
  const warn = r.warnings.filter((v) => !bw.has(v.variable + v.message));
  if (fatal.length) return { sev: 'fatal', v: fatal[0] };
  if (warn.length) return { sev: 'warn', v: warn[0] };
  return { sev: 'none', v: null };
}

const SEV = { fatal: '**refuse**', warn: 'warn', none: '—' };
const cell = (s) => s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

function generate() {
  for (const p of Object.keys(PROFILES)) {
    const b = V.validateBoot(base(p));
    if (b.fatal.length || b.warnings.length) {
      throw new Error(`generator base for ${p} is not clean: ${[...b.fatal, ...b.warnings].map((f) => f.variable).join(', ')}`);
    }
  }
  const L = [];
  L.push('# Boot rules (generated)');
  L.push('');
  L.push('<!-- GENERATED by scripts/config/generate-boot-rules-doc.js from src/infra/config/bootValidator.js — do not edit by hand. -->');
  L.push('<!-- src/infra/config/bootRulesDoc.test.js fails if this file differs from a fresh generation. -->');
  L.push('');
  L.push('Every QODIQA process validates its configuration **before any listener opens**');
  L.push('(`server/startup.js` → `runBootValidation()`). All violations are reported');
  L.push('together; any **refuse** outcome emits one `FATAL BOOT_VALIDATION_FATAL`');
  L.push('event and exits non-zero. A **warn** outcome emits `WARN BOOT_CONFIG_WARNING`');
  L.push('and the process starts. Messages name the variable and the rule, never the value.');
  L.push('');
  L.push('Each rule states its own rationale in the table above.');
  L.push('What a running process actually established is reported by `BOOT_REPORT` (`src/infra/config/bootReport.js`).');
  L.push('');
  L.push('## Profiles');
  L.push('');
  L.push('| `NODE_ENV` | profile |');
  L.push('|---|---|');
  for (const [p, n] of Object.entries(PROFILES)) L.push(`| \`${n}\` | ${p} |`);
  L.push('| unset, empty, or anything else (`prod`, `Production`, `staging`, …) | **refuse** — no other rule is evaluated |');
  L.push('');
  L.push('## Rules');
  L.push('');
  L.push('Outcome of each condition per profile, as produced by the validator (the condition applied to an otherwise valid configuration).');
  L.push('');
  let section = null;
  for (const [sec, cond, mutate] of PROBES) {
    if (sec !== section) {
      section = sec;
      L.push(`### ${sec}`);
      L.push('');
      L.push('| condition | production | development | test | variable | message |');
      L.push('|---|---|---|---|---|---|');
    }
    const o = Object.fromEntries(Object.keys(PROFILES).map((p) => [p, outcome(p, mutate)]));
    const any = o.prod.v || o.dev.v || o.test.v;
    L.push(`| ${cond} | ${SEV[o.prod.sev]} | ${SEV[o.dev.sev]} | ${SEV[o.test.sev]} | ${any ? `\`${any.variable}\`` : ''} | ${any ? cell(any.message) : ''} |`);
    const next = PROBES[PROBES.findIndex((x) => x[2] === mutate) + 1];
    if (!next || next[0] !== sec) L.push('');
  }
  L.push('## Variable shapes');
  L.push('');
  L.push('Malformed values: **refuse** in production, warn elsewhere (certificate paths: refuse everywhere).');
  L.push('');
  L.push('| integer variable | accepted range |');
  L.push('|---|---|');
  for (const [n, [min, max]] of Object.entries(V.INT_VARS)) L.push(`| \`${n}\` | ${min} – ${max} |`);
  L.push('');
  L.push(`Booleans (exactly \`true\` or \`false\`): ${V.BOOL_VARS.map((n) => `\`${n}\``).join(', ')}.`);
  L.push('');
  L.push(`Certificate paths (must exist): ${V.PATH_VARS.map((n) => `\`${n}\``).join(', ')}.`);
  L.push('');
  L.push('## Semantic variables');
  L.push('');
  L.push('Boot validation guards these by name only; it never changes a semantic value.');
  L.push('`src/infra/config/semanticGuardDrift.test.js` fails if the runtime reads a semantic variable not classified here.');
  L.push('');
  L.push('**Refused in production** (warn elsewhere):');
  L.push('');
  for (const n of V.SEM_FORBIDDEN_IN_PROD) L.push(`- \`${n}\``);
  L.push('');
  L.push('**Gate switches — production accepts only the shipped default:**');
  L.push('');
  L.push('| variable | shipped default |');
  L.push('|---|---|');
  for (const [n, d] of Object.entries(V.SEM_GATE_DEFAULTS)) L.push(`| \`${n}\` | \`${d}\` |`);
  L.push('');
  L.push('**Allowed in every profile** (tighten-only or performance-only):');
  L.push('');
  for (const n of V.SEM_ALLOWED) L.push(`- \`${n}\``);
  L.push('');
  // the same text on every platform: paths that the probes pick per operating system are written in their POSIX form
  return L.join('\n').replace(/C:\\qodiqa-secrets\\/g, '/opt/qodiqa/data/');
}

if (require.main === module) {
  const text = generate();
  if (process.argv.includes('--check')) {
    const cur = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n') : '';
    if (cur !== text) { console.error(`${path.relative(REPO, OUT)} is stale — run node scripts/config/generate-boot-rules-doc.js`); process.exit(1); }
    console.log('boot-rules doc is current');
  } else {
    fs.mkdirSync(path.dirname(OUT), { recursive: true });
    fs.writeFileSync(OUT, text);
    console.log(`wrote ${path.relative(REPO, OUT)} (${PROBES.length} rule rows)`);
  }
}

module.exports = { generate, OUT, PROBES };
