'use strict';

/**
 * Provider configuration — centralized, isolated from application logic.
 *
 * Each provider entry describes:
 *   enabled       — whether the provider is configured and usable
 *   apiKey        — authentication credential (from env, null if not set)
 *   baseUrl       — API endpoint
 *   timeoutMs     — outbound call timeout in milliseconds
 *   allowedModels — Set of permitted model identifiers (empty = unrestricted)
 *   defaultModel  — model used when a request omits `model` (null = none;
 * caller must specify a model explicitly) — below
 *   local         — true for self-hosted endpoints (relaxed SSRF policy applies)
 *
 * A provider is enabled automatically when its required environment variable
 * is present.  No provider becomes enabled by default.
 *
 * allowedModels is the single authoritative model allowlist for the
 * whole platform — every enforcement path (services/providers/router.js,
 * router.stream.js, and each provider adapter) reads it exclusively through
 * services/providers/modelValidation.js. No other file may define its own
 * copy of a model allowlist; edit the Set below and every execution path
 * picks up the change automatically.
 *
 * Enforcement is conditional on the Set's contents, not unconditional
 *:
 *   - A NON-EMPTY allowedModels Set is enforced as a strict allowlist —
 *     modelValidation.js rejects any model name not present in the Set.
 *   - An EMPTY allowedModels Set means UNRESTRICTED model selection for
 *     that provider — modelValidation.js treats "no entries configured" as
 *     "no restriction to check against", not as "allow nothing". This is
 *     deliberate for llama and local (see their entries below): both are
 *     operator-configured, deployment-specific endpoints whose valid model
 *     names cannot be known in advance by this codebase, so the operator is
 *     trusted to run only models they intend to serve behind that endpoint.
 *   - openai, anthropic, gemini, and mistral all ship non-empty Sets and are
 *     therefore strictly enforced; only llama and local are unrestricted.
 *
 * Caution for future maintainers: `allowedModels` is a JS `Set`, and
 * `Object.freeze()` on the surrounding config object does NOT make the Set
 * itself immutable — `.add()`/`.delete()` would still work if anything ever
 * called them. Nothing in this codebase does (verified by repo-wide search);
 * every consumer treats the Set as read-only by convention. This was already
 * true and is not changed by the extension mechanism below —
 * `_buildAllowedModels()` always returns a freshly-constructed Set, never a
 * reference to the built-in literal, so there is no risk of two providers
 * (or a provider and a test double) accidentally sharing one Set instance.
 *
 * additive-only model-allowlist extension:
 *   PROVIDER_ALLOWED_MODELS_EXTRA_<PROVIDER_NAME>=model-a,model-b
 *   adds `model-a` and `model-b` to that provider's BUILT-IN allowlist above.
 *   It can only ever ADD entries — there is no syntax to remove or replace a
 *   built-in entry, so a legitimately-new model can be enabled without a
 *   code change, without the built-in baseline ever being weakened.
 *   Parsing rules (see `_parseExtraModels` below for the exact code):
 *     - Comma-separated; each entry is trimmed before use.
 *     - An empty entry (e.g. a trailing comma) is dropped silently.
 *     - An entry exceeding 128 characters or containing a C0 control
 *       character is dropped AND logged at WARN
 *       (`PROVIDER_ALLOWED_MODELS_EXTRA_INVALID_ENTRY`) — it can never
 *       validate against a real request either way (modelValidation.js
 *       rejects those same shapes before ever checking Set membership), so
 *       this is operator-visibility only, not a security boundary.
 *     - Missing, empty, or entirely-invalid configuration leaves the
 *       built-in allowlist completely unchanged — there is no failure mode
 *       that narrows or empties it.
 *     - A no-op, on purpose, for llama/local: their built-in allowlist is
 *       EMPTY (== unrestricted, any model accepted). Adding entries to an
 *       empty Set would flip it from "unrestricted" to "restricted to only
 *       the added entries" — the opposite of additive — so a configured
 *       extension for either provider is ignored, with a WARN
 *       (`PROVIDER_ALLOWED_MODELS_EXTRA_IGNORED`) since it is very likely a
 *       misconfiguration (the provider already accepts any model).
 *     - There is no removal/negation syntax. A string that merely looks like
 *       one (e.g. "-gpt-4") is just an ordinary additional entry, almost
 *       certainly never matched by a real request — it cannot remove
 *       "gpt-4" because nothing here ever deletes from the Set.
 *
 * configurable default model:
 *   PROVIDER_DEFAULT_MODEL_<PROVIDER_NAME>=model-name overrides `defaultModel`
 *   for that provider. The BUILT-IN default is the same literal,
 *   `gpt-3.5-turbo` (unchanged from before this remediation, not blindly
 *   swapped for a newer name), for exactly the providers where it actually
 *   validates: openai (it's a member of the strict allowlist above) and
 *   llama/local (their allowlist is EMPTY == unrestricted, so ANY non-empty
 *   model string was always accepted — this default was never actually
 *   incompatible for them, confirmed by the acceptance suite, e.g.
 *   AT-085/086/087, which omit `model` against provider:'local' and require
 *   the request to reach real dispatch). anthropic/gemini/mistral ship a
 *   `null` built-in default instead — their strict, disjoint allowlists do
 *   NOT contain `gpt-3.5-turbo`, so reusing it for them WOULD be the
 *   incompatible-default bug this remediation closes; the caller must supply
 *   `model` explicitly unless an operator configures one for them (see
 *   resolveDefaultModel() and its callers in src/api/routes/aiChat.js and
 *   src/streaming/streamEnforcer.js — both call this single function, so
 *   streaming and non-streaming always agree).
 *   A malformed override (too long / control characters) is dropped with a
 *   WARN (`PROVIDER_DEFAULT_MODEL_INVALID`), falling back to the built-in
 *   value — same fail-safe posture as the allowlist extension above.
 *   A load-time assertion (below CONFIGS) fails the whole module — the
 *   server cannot start — if any provider's configured default (built-in or
 *   overridden) is not a member of that provider's own EFFECTIVE allowlist
 *   (built-in + extension); skipped for an empty/unrestricted allowlist,
 *   where any non-empty default is valid by that provider's own policy. This
 *   is the "verified against the current provider implementation, not
 *   guessed" requirement made structural: an allowlist edit that silently
 *   invalidates a paired default is caught at boot, not discovered later as
 *   a confusing per-request failure.
 *
 * Environment variables:
 *   OPENAI_API_KEY          — required for openai
 *   OPENAI_TIMEOUT_MS       — optional timeout (default 30 000 ms)
 *   ANTHROPIC_API_KEY       — required for anthropic
 *   ANTHROPIC_TIMEOUT_MS    — optional timeout
 *   ANTHROPIC_MAX_TOKENS    — optional max output tokens (default 4096)
 *   GEMINI_API_KEY          — required for gemini
 *   GEMINI_TIMEOUT_MS       — optional timeout
 *   MISTRAL_API_KEY         — required for mistral
 *   MISTRAL_BASE_URL        — optional; defaults to https://api.mistral.ai/v1
 *   MISTRAL_TIMEOUT_MS      — optional timeout
 *   LLAMA_BASE_URL          — required for llama (enables the provider)
 *   LLAMA_API_KEY           — optional; some Llama deployments require a key
 *   LLAMA_TIMEOUT_MS        — optional timeout
 *   LOCAL_BASE_URL          — required for local (enables the provider)
 *   LOCAL_API_KEY           — optional; some local runtimes accept a key
 *   LOCAL_TIMEOUT_MS        — optional timeout
 *
 *   PROVIDER_FAILOVER_OPENAI     — failover provider if openai fails
 *   PROVIDER_FAILOVER_ANTHROPIC  — failover provider if anthropic fails
 *   PROVIDER_FAILOVER_GEMINI     — failover provider if gemini fails
 *   PROVIDER_FAILOVER_MISTRAL    — failover provider if mistral fails
 *   PROVIDER_FAILOVER_LLAMA      — failover provider if llama fails
 *   PROVIDER_FAILOVER_LOCAL      — failover provider if local fails
 *
 *   PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI     — comma-separated models ADDED to openai's allowlist
 *   PROVIDER_ALLOWED_MODELS_EXTRA_ANTHROPIC  — same, for anthropic
 *   PROVIDER_ALLOWED_MODELS_EXTRA_GEMINI     — same, for gemini
 *   PROVIDER_ALLOWED_MODELS_EXTRA_MISTRAL    — same, for mistral
 *   PROVIDER_ALLOWED_MODELS_EXTRA_LLAMA      — no-op (llama's allowlist is unrestricted; see above)
 *   PROVIDER_ALLOWED_MODELS_EXTRA_LOCAL      — no-op (local's allowlist is unrestricted; see above)
 *
 *   PROVIDER_DEFAULT_MODEL_OPENAI     — overrides openai's default model (built-in: gpt-3.5-turbo)
 *   PROVIDER_DEFAULT_MODEL_ANTHROPIC  — sets a default model for anthropic (built-in: none — model required)
 *   PROVIDER_DEFAULT_MODEL_GEMINI     — sets a default model for gemini (built-in: none — model required)
 *   PROVIDER_DEFAULT_MODEL_MISTRAL    — sets a default model for mistral (built-in: none — model required)
 *   PROVIDER_DEFAULT_MODEL_LLAMA      — overrides llama's default model (built-in: gpt-3.5-turbo — valid because llama's allowlist is unrestricted)
 * PROVIDER_DEFAULT_MODEL_LOCAL — sets local's default model (built-in: none since a request without `model` is refused until this is set)
 *   LOCAL_MAX_TOKENS                  — optional output-token cap for local (1..8192; unset = no cap) — launch plan R-06
 *   PROVIDER_ALLOWED_MODELS_LOCAL     — optional restrictive allowlist for local (unset = any model) — launch plan R-07
 */

const { emit } = require('../logger');
// (BOOT-RULES.md section 3, decision D-E): a provider is enabled only by a key/URL
// that passes the shared credential rules — never by a merely non-empty (e.g.
// placeholder) value. The boot validator applies the same rules and refuses
// production boot on an invalid or placeholder key; in dev/test the provider stays
// disabled and a BOOT_CONFIG_WARNING names the variable.
const { providerKeyStatus, providerUrlStatus, azureConfigStatus, bedrockConfigStatus } = require('../../src/infra/config/credentialRules');

const { resolveTimeoutMs } = require('./timeout'); // audit 2026-10-20 (3.7): one strict parser for all adapters
const DEFAULT_TIMEOUT_MS   = 30_000;
const DEFAULT_MAX_TOKENS   = 4_096;

// Shape limit shared by both config surfaces below (allowlist-extension
// entries and default-model overrides). Kept in sync with, but NOT imported
// from, modelValidation.js's own MAX_MODEL_LENGTH=128 — importing it here
// would create a require cycle, since modelValidation.js already requires
// this module for getProviderConfig().
const MAX_MODEL_ID_LENGTH = 128;
// eslint-disable-next-line no-control-regex
const MODEL_ID_CONTROL_CHAR_RE = /[\x00-\x1F\x7F]/;

function _parseInt(val, fallback) {
  const n = parseInt(val, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function _isShapeValidModelId(candidate) {
  return candidate.length > 0
    && candidate.length <= MAX_MODEL_ID_LENGTH
    && !MODEL_ID_CONTROL_CHAR_RE.test(candidate);
}

// ── additive-only model-allowlist extension ────────────────────────────
// See the module doc comment above for the full contract. Returns the list of
// extra model identifiers to add — never mutates or replaces `builtIn`.
function _parseExtraModels(providerName, envVarValue, builtInIsEmpty) {
  if (typeof envVarValue !== 'string' || envVarValue.trim().length === 0) return [];

  if (builtInIsEmpty) {
    emit('WARN', 'PROVIDER_ALLOWED_MODELS_EXTRA_IGNORED', {
      provider: providerName,
      message:  'Built-in allowlist is empty (unrestricted) — an additive extension would only ' +
                 'narrow it, so it is ignored. This is very likely a misconfiguration.',
    });
    return [];
  }

  const extras = [];
  for (const raw of envVarValue.split(',')) {
    const entry = raw.trim();
    if (entry.length === 0) continue; // e.g. a trailing comma — not worth a warning
    if (!_isShapeValidModelId(entry)) {
      emit('WARN', 'PROVIDER_ALLOWED_MODELS_EXTRA_INVALID_ENTRY', {
        provider: providerName,
        reason:   entry.length > MAX_MODEL_ID_LENGTH ? 'entry exceeds max length' : 'entry contains a control character',
        message:  'Dropped one entry from a PROVIDER_ALLOWED_MODELS_EXTRA_* override — it would never match a real request either way.',
      });
      continue;
    }
    extras.push(entry);
  }
  return extras;
}

// Builds the effective allowlist Set for one provider: built-in entries plus
// any valid additive extension. Always returns a NEW Set — never the same
// object as `builtIn` or shared with any other provider.
function _buildAllowedModels(providerName, builtIn) {
  const envVar = `PROVIDER_ALLOWED_MODELS_EXTRA_${providerName.toUpperCase()}`;
  const extras = _parseExtraModels(providerName, process.env[envVar], builtIn.size === 0);
  return extras.length === 0 ? new Set(builtIn) : new Set([...builtIn, ...extras]);
}

// ── Launch plan R-06 / R-07: optional local-provider output cap and restrictive model allowlist ────────────────────
// Both are opt-in. Unset → exactly the previous behaviour (no max_tokens sent; any model allowed).
//   LOCAL_MAX_TOKENS              integer 1..${LOCAL_MAX_TOKENS_CEILING}; sent as max_tokens on every local request
//                                 (normal and stream). Invalid → WARN and ignored here; production refuses it at boot
//                                 (src/infra/config/bootValidator.js, rule provider_limits).
//   PROVIDER_ALLOWED_MODELS_LOCAL comma-separated model ids; when set, the local allowlist is EXACTLY this set (unlike the
//                                 additive PROVIDER_ALLOWED_MODELS_EXTRA_*, which is ignored for an unrestricted
//                                 provider). The default-model consistency check below then applies to local too.
const LOCAL_MAX_TOKENS_CEILING = 8192;
function parseLocalMaxTokens(raw = process.env.LOCAL_MAX_TOKENS) {
  if (raw === undefined || raw === null || String(raw).trim() === '') return { value: null, valid: true };
  const t = String(raw).trim();
  if (!/^[0-9]+$/.test(t)) return { value: null, valid: false };
  const n = Number(t);
  if (!Number.isSafeInteger(n) || n < 1 || n > LOCAL_MAX_TOKENS_CEILING) return { value: null, valid: false };
  return { value: n, valid: true };
}
// R-23: the same opt-in cap for the hosted OpenAI-compatible providers and Gemini.
// <NAME>_MAX_TOKENS, 1..8192, unset → null (unchanged behaviour). Anthropic keeps ANTHROPIC_MAX_TOKENS (default 4096).
function _hostedMaxTokens(name) {
  const envVar = `${name.toUpperCase()}_MAX_TOKENS`;
  const r = parseLocalMaxTokens(process.env[envVar]);
  if (!r.valid) {
    emit('WARN', 'PROVIDER_MAX_TOKENS_INVALID', {
      provider: name, envVar,
      message: `${envVar} must be an integer between 1 and ${LOCAL_MAX_TOKENS_CEILING}; ignored (no output cap is applied).`,
    });
  }
  return r.value;
}
function _localMaxTokens() {
  const r = parseLocalMaxTokens();
  if (!r.valid) {
    emit('WARN', 'PROVIDER_MAX_TOKENS_INVALID', {
      provider: 'local', envVar: 'LOCAL_MAX_TOKENS',
      message: `LOCAL_MAX_TOKENS must be an integer between 1 and ${LOCAL_MAX_TOKENS_CEILING}; ignored (no output cap is applied).`,
    });
  }
  return r.value;
}
function parseLocalAllowedModels(raw = process.env.PROVIDER_ALLOWED_MODELS_LOCAL) {
  if (typeof raw !== 'string' || raw.trim().length === 0) return null;
  const out = [];
  for (const part of raw.split(',')) {
    const m = part.trim();
    if (m.length === 0) continue;
    if (!_isShapeValidModelId(m)) return { invalid: true, models: [] };
    out.push(m);
  }
  return { invalid: out.length === 0, models: out };
}
function _localAllowedModels() {
  const r = parseLocalAllowedModels();
  if (r === null) return _buildAllowedModels('local', new Set());
  if (r.invalid) {
    emit('WARN', 'PROVIDER_ALLOWED_MODELS_INVALID', { provider: 'local', envVar: 'PROVIDER_ALLOWED_MODELS_LOCAL',
      message: 'PROVIDER_ALLOWED_MODELS_LOCAL contains no valid model id; ignored (any model is allowed).' });
    return _buildAllowedModels('local', new Set());
  }
  return new Set(r.models);
}

// ── configurable default model ─────────────────────────────────────────
// Returns `builtInDefault` unless PROVIDER_DEFAULT_MODEL_<NAME> is set to a
// shape-valid override. A malformed override is dropped (WARN) rather than
// used or crashing the module — the built-in value continues to apply.
function _resolveConfiguredDefault(providerName, builtInDefault) {
  const envVar = `PROVIDER_DEFAULT_MODEL_${providerName.toUpperCase()}`;
  const raw    = process.env[envVar];
  if (typeof raw !== 'string' || raw.trim().length === 0) return builtInDefault;

  const candidate = raw.trim();
  if (!_isShapeValidModelId(candidate)) {
    emit('WARN', 'PROVIDER_DEFAULT_MODEL_INVALID', {
      provider: providerName,
      reason:   candidate.length > MAX_MODEL_ID_LENGTH ? 'value exceeds max length' : 'value contains a control character',
      message:  'Ignoring malformed PROVIDER_DEFAULT_MODEL_* override; falling back to the built-in default.',
    });
    return builtInDefault;
  }
  return candidate;
}

// an optional restrictive allowlist from a comma-separated env var (unset or no valid id = unrestricted, like the local provider's).
function _restrictiveList(envVar) {
  const r = parseLocalAllowedModels(process.env[envVar]);
  if (r === null || r.invalid) return new Set();
  return new Set(r.models);
}

// ── Provider configuration table ─────────────────────────────────────────────

const CONFIGS = Object.freeze({
  openai: Object.freeze({
    enabled:       providerKeyStatus('openai', process.env.OPENAI_API_KEY) === 'valid',
    apiKey:        process.env.OPENAI_API_KEY        || null,
    baseUrl:       'https://api.openai.com/v1',
    timeoutMs:     resolveTimeoutMs('OPENAI_TIMEOUT_MS', DEFAULT_TIMEOUT_MS),
    maxTokens:     _hostedMaxTokens('openai'),   // R-23: OPENAI_MAX_TOKENS, unset → null (no cap, as before)
    allowedModels: _buildAllowedModels('openai', new Set([
      'gpt-4',
      'gpt-4-turbo',
      'gpt-4-turbo-preview',
      'gpt-4o',
      'gpt-4o-mini',
      'gpt-3.5-turbo',
      'gpt-3.5-turbo-16k',
    ])),
    // The only provider with a documented, historically-relied-upon default
    // (docs/api/overview.md, the SDK examples) — value unchanged.
    defaultModel: _resolveConfiguredDefault('openai', 'gpt-3.5-turbo'),
    failoverProvider: process.env.PROVIDER_FAILOVER_OPENAI || null,
    local: false,
  }),

  anthropic: Object.freeze({
    enabled:       providerKeyStatus('anthropic', process.env.ANTHROPIC_API_KEY) === 'valid',
    apiKey:        process.env.ANTHROPIC_API_KEY     || null,
    baseUrl:       'https://api.anthropic.com',
    timeoutMs:     resolveTimeoutMs('ANTHROPIC_TIMEOUT_MS', DEFAULT_TIMEOUT_MS),
    maxTokens:     _parseInt(process.env.ANTHROPIC_MAX_TOKENS,  DEFAULT_MAX_TOKENS),
    allowedModels: _buildAllowedModels('anthropic', new Set([
      'claude-opus-4-7',
      'claude-sonnet-4-6',
      'claude-haiku-4-5-20251001',
      'claude-3-5-sonnet-20241022',
      'claude-3-5-haiku-20241022',
      'claude-3-opus-20240229',
      'claude-3-sonnet-20240229',
      'claude-3-haiku-20240307',
    ])),
    // No built-in default — never documented or relied upon for this
    // provider; operators may set PROVIDER_DEFAULT_MODEL_ANTHROPIC.
    defaultModel: _resolveConfiguredDefault('anthropic', null),
    failoverProvider: process.env.PROVIDER_FAILOVER_ANTHROPIC || null,
    local: false,
  }),

  gemini: Object.freeze({
    enabled:       providerKeyStatus('gemini', process.env.GEMINI_API_KEY) === 'valid',
    apiKey:        process.env.GEMINI_API_KEY        || null,
    baseUrl:       'https://generativelanguage.googleapis.com',
    timeoutMs:     resolveTimeoutMs('GEMINI_TIMEOUT_MS', DEFAULT_TIMEOUT_MS),
    maxTokens:     _hostedMaxTokens('gemini'),   // R-23: GEMINI_MAX_TOKENS, unset → null (no cap, as before)
    allowedModels: _buildAllowedModels('gemini', new Set([
      'gemini-2.5-pro',
      'gemini-2.5-flash',
      'gemini-2.0-flash',
      'gemini-2.0-flash-lite',
      'gemini-1.5-pro',
      'gemini-1.5-flash',
    ])),
    // No built-in default — never documented or relied upon for this
    // provider; operators may set PROVIDER_DEFAULT_MODEL_GEMINI.
    defaultModel: _resolveConfiguredDefault('gemini', null),
    failoverProvider: process.env.PROVIDER_FAILOVER_GEMINI || null,
    local: false,
  }),

  mistral: Object.freeze({
    enabled:       providerKeyStatus('mistral', process.env.MISTRAL_API_KEY) === 'valid',
    apiKey:        process.env.MISTRAL_API_KEY       || null,
    baseUrl:       process.env.MISTRAL_BASE_URL      || 'https://api.mistral.ai/v1',
    timeoutMs:     resolveTimeoutMs('MISTRAL_TIMEOUT_MS', DEFAULT_TIMEOUT_MS),
    maxTokens:     _hostedMaxTokens('mistral'),   // R-23: MISTRAL_MAX_TOKENS, unset → null (no cap, as before)
    allowedModels: _buildAllowedModels('mistral', new Set([
      'mistral-large-latest',
      'mistral-medium-latest',
      'mistral-small-latest',
      'open-mixtral-8x7b',
      'open-mixtral-8x22b',
      'open-mistral-7b',
      'codestral-latest',
      'mistral-embed',
    ])),
    // No built-in default — never documented or relied upon for this
    // provider; operators may set PROVIDER_DEFAULT_MODEL_MISTRAL.
    defaultModel: _resolveConfiguredDefault('mistral', null),
    failoverProvider: process.env.PROVIDER_FAILOVER_MISTRAL || null,
    local: false,
  }),

  llama: Object.freeze({
    enabled:       providerUrlStatus(process.env.LLAMA_BASE_URL) === 'valid',
    apiKey:        process.env.LLAMA_API_KEY         || null,
    baseUrl:       process.env.LLAMA_BASE_URL        || null,
    timeoutMs:     resolveTimeoutMs('LLAMA_TIMEOUT_MS', DEFAULT_TIMEOUT_MS),
    maxTokens:     _hostedMaxTokens('llama'),   // R-23: LLAMA_MAX_TOKENS, unset → null (no cap, as before)
    // Llama model names are deployment-specific.  Empty set = any model is allowed.
    // (_buildAllowedModels is still called for consistency — with an empty
    // built-in Set it always no-ops any configured extension; see the
    // module doc comment above.)
    allowedModels: _buildAllowedModels('llama', new Set()),
    // Built-in default is 'gpt-3.5-turbo', same literal as openai — NOT a
    // guess about what a real Llama deployment serves, but genuinely valid
    // here: an EMPTY (unrestricted) allowlist accepts any non-empty model
    // string, so this was never actually incompatible for this provider —
    // unlike anthropic/gemini/mistral's strict, disjoint allowlists, which
    // is why THEY get no built-in default instead. Confirmed load-bearing
    // by the acceptance suite (e.g. AT-085/086/087, which omit `model`
    // against provider:'local' and require the request to reach dispatch).
    defaultModel: _resolveConfiguredDefault('llama', 'gpt-3.5-turbo'),
    failoverProvider: process.env.PROVIDER_FAILOVER_LLAMA || null,
    local: false,   // Llama may live on cloud infra — determined at runtime by URL
  }),

  // Azure OpenAI. `model` in a request is the DEPLOYMENT name (operator-defined), so the allowlist is empty (any deployment) unless AZURE_OPENAI_DEPLOYMENTS
  // restricts it. Auth is an api-key or Microsoft Entra client credentials (services/providers/azureAuth.js).
  azure: Object.freeze({
    enabled:       azureConfigStatus(process.env).status === 'valid',
    apiKey:        null,
    baseUrl:       process.env.AZURE_OPENAI_ENDPOINT || null,
    apiVersion:    process.env.AZURE_OPENAI_API_VERSION || '2024-10-21',
    timeoutMs:     resolveTimeoutMs('AZURE_OPENAI_TIMEOUT_MS', DEFAULT_TIMEOUT_MS),
    maxTokens:     _hostedMaxTokens('azure_openai'),   // AZURE_OPENAI_MAX_TOKENS
    allowedModels: _restrictiveList('AZURE_OPENAI_DEPLOYMENTS'),
    defaultModel:  _resolveConfiguredDefault('azure', null),
    failoverProvider: process.env.PROVIDER_FAILOVER_AZURE || null,
    local: false,
  }),

  // AWS Bedrock (Converse API, SigV4). `model` is the Bedrock model id or inference-profile id. Credentials are BEDROCK_* (not the ambient AWS_* names, which the KMS
  // integration may legitimately hold): BEDROCK_REGION, BEDROCK_ACCESS_KEY_ID, BEDROCK_SECRET_ACCESS_KEY, optional BEDROCK_SESSION_TOKEN.
  bedrock: Object.freeze({
    enabled:       bedrockConfigStatus(process.env).status === 'valid',
    apiKey:        null,
    baseUrl:       process.env.BEDROCK_REGION ? `https://bedrock-runtime.${process.env.BEDROCK_REGION}.amazonaws.com` : null,
    region:        process.env.BEDROCK_REGION || null,
    timeoutMs:     resolveTimeoutMs('BEDROCK_TIMEOUT_MS', DEFAULT_TIMEOUT_MS),
    maxTokens:     _hostedMaxTokens('bedrock'),   // BEDROCK_MAX_TOKENS
    allowedModels: _restrictiveList('BEDROCK_ALLOWED_MODELS'),
    defaultModel:  _resolveConfiguredDefault('bedrock', null),
    failoverProvider: process.env.PROVIDER_FAILOVER_BEDROCK || null,
    local: false,
  }),

  local: Object.freeze({
    enabled:       providerUrlStatus(process.env.LOCAL_BASE_URL) === 'valid',
    apiKey:        process.env.LOCAL_API_KEY         || null,
    baseUrl:       process.env.LOCAL_BASE_URL        || null,
    timeoutMs:     resolveTimeoutMs('LOCAL_TIMEOUT_MS', DEFAULT_TIMEOUT_MS),
    maxTokens:     _localMaxTokens(),                 // R-06: LOCAL_MAX_TOKENS, unset → null (no cap, as before)
    // Local runtime model names are operator-defined.  Empty set = any model allowed, unless
    // PROVIDER_ALLOWED_MODELS_LOCAL restricts it (R-07).
    allowedModels: _localAllowedModels(),
    // NO built-in default. The previous
    // built-in 'gpt-3.5-turbo' was an OpenAI model name sent to a local
    // runtime (Ollama et al.) whenever a request omitted `model`; the runtime
    // answered 404 model-not-found, which surfaced as a misleading 503 and
    // counted against the local circuit breaker. The local default now comes
    // ONLY from PROVIDER_DEFAULT_MODEL_LOCAL (e.g. `qwen2.5:7b`, the model the
    // operator actually pulled). Unset → a request without `model` is refused
    // before dispatch (PROVIDER_MODEL_NOT_ALLOWED, the same mechanism
    // anthropic/gemini/mistral use) with a PROVIDER_MODEL_MISSING warning that
    // names this variable; nothing is ever sent to the runtime. Llama keeps
    // its built-in default unchanged.
    defaultModel: _resolveConfiguredDefault('local', null),
    failoverProvider: process.env.PROVIDER_FAILOVER_LOCAL || null,
    local: true,    // Self-hosted — relaxed SSRF policy (private network destinations allowed)
  }),
});

// ── load-time default-model consistency assertion ─────────────────────
// A configured default that is not a member of its own provider's effective
// allowlist is exactly the "stale/incompatible default" failure mode
// exists to close. Fail the whole module load — the server cannot start —
// rather than let a request silently receive a model that only turns out to
// be wrong when a real call is attempted. Skipped for a provider whose
// effective allowlist is empty (unrestricted) — there is nothing to check
// the default against, and any non-empty default is valid there by that
// provider's own policy (llama, local).
for (const [providerName, cfg] of Object.entries(CONFIGS)) {
  if (cfg.defaultModel === null) continue;
  if (cfg.allowedModels.size === 0) continue;
  if (!cfg.allowedModels.has(cfg.defaultModel)) {
    throw new Error(
      `PROVIDER_CONFIG_INVALID: ${providerName}'s configured default model "${cfg.defaultModel}" ` +
      `is not present in its own effective allowlist. Fix PROVIDER_DEFAULT_MODEL_${providerName.toUpperCase()} ` +
      `or the provider's allowlist (config.js's built-in Set, or PROVIDER_ALLOWED_MODELS_EXTRA_${providerName.toUpperCase()}).`
    );
  }
}

// an enabled local provider with no default model is a valid setup
// (every request may name its model), but the most common onboarding failure —
// so say so once, at load, naming the variable that fixes it.
if (CONFIGS.local.enabled && CONFIGS.local.defaultModel === null) {
  emit('WARN', 'PROVIDER_DEFAULT_MODEL_UNSET', {
    provider: 'local',
    envVar:   'PROVIDER_DEFAULT_MODEL_LOCAL',
    message:  'LOCAL_BASE_URL is set but PROVIDER_DEFAULT_MODEL_LOCAL is not — requests that omit `model` will be refused. Set it to a model the local runtime serves (e.g. the one pulled with `ollama pull`).',
  });
}

/**
 * Return the configuration object for a named provider.
 * @param {string} name
 * @returns {object | null}
 */
function getProviderConfig(name) {
  if (CONFIGS[name]) return CONFIGS[name];
  // dynamic OpenAI-compatible providers (`compat-<id>`) live in the control-plane registry; only that name shape ever reaches it
  if (typeof name === 'string' && name.startsWith('compat-')) return require('../../src/core/providers/compatRegistry').configFor(name);
  return null;
}

/**
 * Return the names of all currently enabled providers.
 * @returns {string[]}
 */
function getEnabledProviders() {
  return [...Object.entries(CONFIGS).filter(([, cfg]) => cfg.enabled).map(([name]) => name),
    ...require('../../src/core/providers/compatRegistry').enabledNames()];      //
}

/**
 * Return true if at least one provider is enabled.
 * @returns {boolean}
 */
function hasAnyProvider() {
  return getEnabledProviders().length > 0;
}

/**
 * resolve the default model for a named provider — the single function
 * both the non-streaming (src/api/routes/aiChat.js) and streaming
 * (src/streaming/streamEnforcer.js) request paths call when a request omits
 * `model`, so the two paths always agree. Returns `null` (never a wrong or
 * incompatible guess) when the provider is unknown or has no configured
 * default — the caller must then supply `model` explicitly; the existing
 * model-allowlist validation (modelValidation.js) rejects a null/missing
 * model as PROVIDER_MODEL_NOT_ALLOWED exactly as it already rejects any
 * other invalid model, so no new error code or early-exit branch is needed
 * in either caller.
 * @param {string} name
 * @returns {string | null}
 */
function resolveDefaultModel(name) {
  const cfg = getProviderConfig(name);
  return (cfg && typeof cfg.defaultModel === 'string' && cfg.defaultModel) ? cfg.defaultModel : null;
}

module.exports = { getProviderConfig, getEnabledProviders, hasAnyProvider, resolveDefaultModel, CONFIGS, parseLocalMaxTokens, parseLocalAllowedModels, LOCAL_MAX_TOKENS_CEILING };
