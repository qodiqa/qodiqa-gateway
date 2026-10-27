'use strict';

/**
 * Credential rules shared by the boot validator (bootValidator.js) and the
 * provider registry (services/providers/config.js) — one definition of
 * "placeholder", "strong secret" and "valid provider key" (BOOT-RULES.md
 * sections 2–3). Pure functions only: no I/O, no logging, never returns or
 * formats the value it inspects.
 */

// Whole-value matches (case-insensitive, trimmed). Kept from the previous
// secretValidation.js deny-list so nothing that was rejected before is
// accepted now.
const PLACEHOLDER_WHOLE = new Set([
  'changeme', 'change-me', 'change_me', 'password', 'secret', 'test', 'test-token', 'testtoken',
  'example', 'example-secret', 'placeholder', 'your-secret-here', 'your_secret_here', 'my-secret',
  'mysecret', 'qodiqa', 'qodiqa-secret', 'qodiqasecret', 'default', 'default-secret', 'dev',
  'dev-token', 'devtoken', '1234567890', '12345678901234567890123456789012',
  'abcdefghijklmnopqrstuvwxyz', 'aabbccddeeffaabbccddeeffaabbccdd', 'supersecret', 'super-secret',
  'verysecret', 'very-secret', 'notsecure', 'not-secure', 'insecure', 'replace-me', 'replaceme',
  'todo', 'fixme', 'admin', 'root', 'abc', '123456', 'qwerty', 'token', 'your-token', 'your_token',
  'sample', 'xxx', 'none', 'null', 'undefined', 'empty', 'unset',
]);

// Substring matches (case-insensitive). the old list was exact-match only,
// so `changeme123` or `REPLACE_WITH_VAULT_SECRET_APP` passed.
const PLACEHOLDER_SUBSTRINGS = [
  'changeme', 'change-me', 'change_me', 'replace_with', 'replace-with', 'replacewith', 'replace-me',
  'replace_me', 'placeholder', 'your-', 'your_', 'example', 'dummy', 'fixme', 'todo', 'xxxx',
  '<', '>', 'insert-', 'insert_', 'redacted',
];

// Prefix patterns the previous OPENAI_API_KEY check rejected; kept for every provider key.
const PROVIDER_PLACEHOLDER_PREFIXES = [
  /^sk-x{5,}/i, /^sk-your[_-]/i, /^sk-placeholder/i, /^sk-test/i, /^sk-example/i, /^sk-changeme/i,
  /^sk-fake/i, /^sk-demo/i, /^your[_-]/i, /^[a-z]+[_-]api[_-]key/i,
];

function isPlaceholder(value) {
  if (typeof value !== 'string') return false;
  const v = value.trim().toLowerCase();
  if (v.length === 0) return true;
  if (PLACEHOLDER_WHOLE.has(v)) return true;
  return PLACEHOLDER_SUBSTRINGS.some((s) => v.includes(s));
}

/**
 * Strength problems for a secret value, as rule codes (never the value):
 *   'too_short'   shorter than minLength
 *   'repeated'    one character repeated (000…, fff…)
 *   'pattern'     a repeating 2-character pattern (abab…)
 *   'placeholder' matches isPlaceholder()
 */
function secretProblems(value, { minLength = 32 } = {}) {
  const problems = [];
  const v = typeof value === 'string' ? value.trim() : '';
  if (v.length < minLength) problems.push('too_short');
  if (v.length > 0 && /^(.)\1+$/.test(v)) problems.push('repeated');
  else if (v.length >= 16 && /^(.{2})\1{7,}$/.test(v)) problems.push('pattern');
  if (isPlaceholder(v)) problems.push('placeholder');
  return problems;
}

const HEX64 = /^[0-9a-fA-F]{64}$/;

// BOOT-RULES.md section 3 (decision D-E): provider-specific format and length.
const PROVIDER_KEY_FORMATS = Object.freeze({
  openai:    { variable: 'OPENAI_API_KEY',    re: /^sk-[A-Za-z0-9_-]{37,}$/,   describe: "'sk-' prefix, >= 40 characters, [A-Za-z0-9_-]" },
  anthropic: { variable: 'ANTHROPIC_API_KEY', re: /^sk-ant-[A-Za-z0-9_-]{33,}$/, describe: "'sk-ant-' prefix, >= 40 characters, [A-Za-z0-9_-]" },
  gemini:    { variable: 'GEMINI_API_KEY',    re: /^[A-Za-z0-9_-]{30,}$/,      describe: '>= 30 characters of [A-Za-z0-9_-]' },
  mistral:   { variable: 'MISTRAL_API_KEY',   re: /^[A-Za-z0-9]{30,}$/,        describe: '>= 30 characters of [A-Za-z0-9]' },
});

/** 'absent' | 'valid' | 'placeholder' | 'invalid_format' for a keyed provider. */
function providerKeyStatus(provider, value) {
  const fmt = PROVIDER_KEY_FORMATS[provider];
  if (!fmt) throw new Error(`credentialRules: unknown keyed provider ${provider}`);
  if (value === undefined || value === null || value === '') return 'absent';
  if (isPlaceholder(value) || PROVIDER_PLACEHOLDER_PREFIXES.some((re) => re.test(value.trim()))) return 'placeholder';
  return fmt.re.test(value) ? 'valid' : 'invalid_format';
}

/** 'absent' | 'valid' | 'invalid_url' for a base-URL provider (llama, local). */
function providerUrlStatus(value) {
  if (value === undefined || value === null || value === '') return 'absent';
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:' ? 'valid' : 'invalid_url';
  } catch { return 'invalid_url'; }
}

// the two cloud providers need several values together, so each has its own status function (the same 'absent' | 'valid' | 'placeholder' | 'invalid_format'
// vocabulary as providerKeyStatus; `problems` names the variables, never their values).
const AZURE_GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const AWS_REGION = /^[a-z]{2}(-[a-z]+)+-[0-9]$/;
function azureConfigStatus(env) {
  const endpoint = env.AZURE_OPENAI_ENDPOINT; const key = env.AZURE_OPENAI_API_KEY;
  const entra = [env.AZURE_TENANT_ID, env.AZURE_CLIENT_ID, env.AZURE_CLIENT_SECRET];
  const anything = [endpoint, key, ...entra].some((v) => v !== undefined && v !== '');
  if (!anything) return { status: 'absent', problems: [] };
  const problems = [];
  let epOk = false;
  try { const u = new URL(endpoint); epOk = u.protocol === 'https:'; } catch { /* below */ }
  if (!epOk) problems.push('AZURE_OPENAI_ENDPOINT must be an https URL');
  const keyOk = !!key && !isPlaceholder(key) && /^[A-Za-z0-9]{32,}$/.test(key.trim());
  const entraSet = entra.some((v) => v);
  const entraOk = entraSet && AZURE_GUID.test(entra[0] || '') && AZURE_GUID.test(entra[1] || '') && !!entra[2] && !isPlaceholder(entra[2]);
  if (!keyOk && !entraOk) problems.push(entraSet ? 'AZURE_TENANT_ID / AZURE_CLIENT_ID (GUIDs) and AZURE_CLIENT_SECRET are all required for Entra' : 'AZURE_OPENAI_API_KEY must be 32+ alphanumeric characters (or set the Entra credentials)');
  if (key && (isPlaceholder(key) || entra.some((v) => v && isPlaceholder(v)))) return { status: 'placeholder', problems: ['a credential is a placeholder value'] };
  return { status: problems.length ? 'invalid_format' : 'valid', problems, auth: entraOk ? 'entra' : keyOk ? 'api-key' : null };
}
function bedrockConfigStatus(env) {
  const region = env.BEDROCK_REGION; const id = env.BEDROCK_ACCESS_KEY_ID; const secret = env.BEDROCK_SECRET_ACCESS_KEY;
  if ([region, id, secret, env.BEDROCK_SESSION_TOKEN].every((v) => v === undefined || v === '')) return { status: 'absent', problems: [] };
  if ([id, secret].some((v) => v && isPlaceholder(v))) return { status: 'placeholder', problems: ['a credential is a placeholder value'] };
  const problems = [];
  if (!AWS_REGION.test(region || '')) problems.push('BEDROCK_REGION must be an AWS region such as us-east-1');
  if (!/^[A-Z0-9]{16,128}$/.test(id || '')) problems.push('BEDROCK_ACCESS_KEY_ID must be 16-128 uppercase alphanumeric characters');
  if (!/^[A-Za-z0-9/+=]{30,}$/.test(secret || '')) problems.push('BEDROCK_SECRET_ACCESS_KEY must be 30+ characters of [A-Za-z0-9/+=]');
  return { status: problems.length ? 'invalid_format' : 'valid', problems };
}

function isLoopbackHost(hostname) {
  return hostname === 'localhost' || hostname === '::1' || hostname === '[::1]' || /^127\./.test(hostname);
}

module.exports = {
  isPlaceholder,
  secretProblems,
  providerKeyStatus,
  providerUrlStatus,
  azureConfigStatus,
  bedrockConfigStatus,
  isLoopbackHost,
  PROVIDER_KEY_FORMATS,
  HEX64,
  PLACEHOLDER_WHOLE,
};
