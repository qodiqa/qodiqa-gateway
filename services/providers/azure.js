'use strict';

/**
 * Azure OpenAI provider - production execution handler.
 *
 * Called ONLY through routeProviderCall() (services/providers/router.js) -> services/execution.js. Shares the execution pipeline (model check, outbound validation, retry,
 * timeout/cancellation, error classification, telemetry) with every other provider through services/providers/baseAdapter.js.
 *
 * The request's `model` is the DEPLOYMENT name (Azure routes by deployment, not by model id): the URL is
 *   {AZURE_OPENAI_ENDPOINT}/openai/deployments/{deployment}/chat/completions?api-version={AZURE_OPENAI_API_VERSION}
 * and the SDK's AzureOpenAI client builds it. Auth: the `api-key` header, or a Microsoft Entra bearer token (client credentials) - see azureAuth.js.
 *
 * SSRF: the endpoint is validated against the shared provider policy (https, not an IP literal, not private, a hostname of the shape <resource>.openai.azure.com or
 * <resource>.cognitiveservices.azure.com) on first use, and the connection goes through the guarded agent (resolved addresses re-checked, redirect hops held to the strict
 * policy). A bad endpoint refuses every call with PROVIDER_CONFIG_INVALID. Redirects from the service are never followed to an unchecked destination.
 *
 * Environment: AZURE_OPENAI_ENDPOINT (required), AZURE_OPENAI_API_KEY or AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET, AZURE_OPENAI_API_VERSION (default
 * 2024-10-21), AZURE_OPENAI_TIMEOUT_MS, AZURE_OPENAI_MAX_TOKENS, AZURE_OPENAI_DEPLOYMENTS (optional restrictive deployment allowlist), AZURE_OPENAI_AUTH (api-key|entra).
 *
 * Error normalization: the canonical PROVIDER_* codes of baseAdapter (Azure's 400 content-filter refusals are PROVIDER_INVALID_REQUEST).
 */

const { AzureOpenAI } = require('openai');
const { resolveTimeoutMs } = require('./timeout');
const { validateProviderUrl, createGuardedAgent } = require('./ssrf');
const { emit } = require('../logger');
const azureAuth = require('./azureAuth');
const {
  MAX_MESSAGES, MAX_CONTENT_BYTES, TRANSPORTS,
  runProviderCall, noRedirectFetch, guardedFetch,
} = require('./baseAdapter');

const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('AZURE_OPENAI_TIMEOUT_MS');

function configInvalid(reason) {
  emit('CRITICAL', 'PROVIDER_CONFIG_INVALID', { provider: 'azure', reason, message: 'AZURE_OPENAI_ENDPOINT failed URL validation - provider cannot execute.' });
  const err = new Error(`PROVIDER_CONFIG_INVALID: ${reason}`);
  err.code = 'PROVIDER_CONFIG_INVALID';
  return err;
}

let client = null;
let clientKey = null;
let fetchOverride = null;      // test seam: the SDK's fetch (proves the URL and headers the SDK builds without a network)

/** The SDK client for the current configuration (rebuilt if the endpoint, version or auth mode changed). */
function getClient(env = process.env) {
  const endpoint = env.AZURE_OPENAI_ENDPOINT;
  const check = validateProviderUrl(endpoint);
  if (!check.valid) throw configInvalid(check.reason);
  const authMode = azureAuth.mode(env);
  if (!authMode) { const e = new Error('PROVIDER_AUTH_FAILED'); e.code = 'PROVIDER_AUTH_FAILED'; throw e; }
  const apiVersion = env.AZURE_OPENAI_API_VERSION || '2024-10-21';
  const key = `${endpoint}|${apiVersion}|${authMode}`;
  if (client && clientKey === key) return client;
  const common = { endpoint: endpoint.replace(/\/+$/, ''), apiVersion, timeout: PROVIDER_TIMEOUT_MS, maxRetries: 0, fetch: guardedFetch(createGuardedAgent(endpoint, { ...env, LOCAL_PROVIDER_BLOCK_PRIVATE_NETWORKS: 'true', PROVIDER_GUARD_STRICT_PUBLIC: 'true' }), fetchOverride || noRedirectFetch) };   // strict address policy, no redirects
  client = authMode === 'entra'
    ? new AzureOpenAI({ ...common, azureADTokenProvider: () => azureAuth.entraToken({ env }) })
    : new AzureOpenAI({ ...common, apiKey: env.AZURE_OPENAI_API_KEY });
  clientKey = key;
  return client;
}

// A3-01: the deployment name goes into the URL path (/openai/deployments/{deployment}/chat/completions) and the SDK does not escape it, so a name
// such as `dep?api-version=x` or `dep/../../fine_tuning/jobs` would redirect the keyed request to another path of the same Azure host. Only a plain name is accepted.
const DEPLOYMENT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const spec = {
  name:      'azure',
  transport: TRANSPORTS.sdk,
  validate:  {},
  completeLogIncludesHash: true,

  getExecutionContext() { return { client: getClient() }; },

  transformRequest(body) {
    if (typeof body.model !== 'string' || !DEPLOYMENT_RE.test(body.model) || body.model.includes('..')) { const e = new Error('PROVIDER_MODEL_NOT_ALLOWED'); e.code = 'PROVIDER_MODEL_NOT_ALLOWED'; throw e; }
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('azure')?.maxTokens ?? null, body);
    return { model: body.model, messages: body.messages, ...(maxTokens ? { max_tokens: maxTokens } : {}) };
  },

  execute(payload, ctx) {
    return ctx.client.chat.completions.create(payload, ctx.signal ? { signal: ctx.signal } : undefined);
  },

  logFields(raw) { return { responseId: raw.id ?? null, usage: raw.usage ?? null }; },

  parseResponse(raw, ctx) {
    const output = raw?.choices?.[0]?.message?.content;
    return {
      output,
      model: raw.model || ctx.model,
      tokenUsage: {
        inputTokens:  raw.usage?.prompt_tokens     ?? null,
        outputTokens: raw.usage?.completion_tokens ?? null,
        totalTokens:  raw.usage?.total_tokens      ?? null,
      },
      executionMetadata: { responseId: raw.id ?? null },
    };
  },
};

/**
 * @param {{ model: string, messages: Array }} body   model = the Azure deployment name
 * @param {{ requestId: string, requestHash: string|null, policyHash: string|null }} meta
 * @param {AbortSignal} [signal]
 * @returns {Promise<object>} normalized ProviderResponse
 */
function callAzure(body, meta, signal) { return runProviderCall(spec, body, meta, signal); }

function _resetClient() { client = null; clientKey = null; azureAuth._reset(); }
function _setFetch(fn) { fetchOverride = fn; _resetClient(); }

module.exports = { callAzure, getClient, MAX_CONTENT_BYTES, MAX_MESSAGES, _resetClient, _setFetch, _spec: spec };
