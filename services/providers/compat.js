'use strict';

/**
 * Dynamic OpenAI-compatible provider adapter. One adapter serves every `compat-<id>` provider of src/core/providers/compatRegistry.js: the spec is built per call from the
 * registry record, so editing, disabling or re-keying a provider takes effect on the next call without a deploy.
 *
 * Transport: the OpenAI SDK against the record's baseUrl, through the guarded agent. A public (https) endpoint is held to the STRICT address policy even for its own host - it must
 * resolve to a public address (a name that later re-resolves to a private or metadata address is refused: DNS rebinding); only QODIQA_COMPAT_ALLOW_LOCAL=true (never in
 * production) relaxes that. The API key is read from the environment variable the record names (COMPAT_KEY_*), at call time; it is never stored or logged.
 *
 * Everything else - model allowlist, outbound validation, retry, timeout/cancellation, error classes, telemetry - is the shared pipeline in baseAdapter.js. Streaming mirrors
 * openai.stream.js (finish_reason is the terminal signal).
 */

const { OpenAI } = require('openai');
const { createGuardedAgent } = require('./ssrf');
const { TRANSPORTS, runProviderCall, runProviderStream, isOpenAICompatibleTerminalChunk, guardedFetch } = require('./baseAdapter');

const clients = new Map();       // provider name -> { sig, client }

function coded(code, detail) { const e = new Error(code); e.code = code; if (detail) e.detail = detail; return e; }

function record(name) {
  let r;
  try { r = require('../../src/core/providers/compatRegistry').resolve(name); }
  catch (e) { throw coded('PROVIDER_UNAVAILABLE', 'the provider registry could not be read'); }
  if (!r) throw coded('PROVIDER_NOT_CONFIGURED');
  return r;
}

function clientFor(name, env = process.env) {
  const r = record(name);
  const apiKey = r.apiKeyEnv ? env[r.apiKeyEnv] : 'none';       // the SDK requires a non-empty key; an endpoint that needs none ignores it
  const local = env.QODIQA_COMPAT_ALLOW_LOCAL === 'true' && env.NODE_ENV !== 'production';
  const sig = `${r.baseUrl}|${r.timeoutMs}|${r.revision}|${apiKey}`;
  const hit = clients.get(name);
  if (hit && hit.sig === sig) return hit.client;
  const client = new OpenAI({ apiKey, baseURL: r.baseUrl, timeout: r.timeoutMs, maxRetries: 0,     // the guarded agent rides on the fetch (openai >= 5 has no httpAgent)
    fetch: guardedFetch(createGuardedAgent(r.baseUrl, local ? env : { ...env, LOCAL_PROVIDER_BLOCK_PRIVATE_NETWORKS: 'true', PROVIDER_GUARD_STRICT_PUBLIC: 'true' })) });
  clients.set(name, { sig, client });
  return client;
}

function maxTokensFor(name, body) {
  const cfg = require('./config').getProviderConfig(name);
  return require('./limits').capMaxTokens(cfg && cfg.maxTokens ? cfg.maxTokens : null, body);
}

function specFor(name) {
  return {
    name,
    transport: TRANSPORTS.sdk,
    validate: {},
    completeLogIncludesHash: true,
    getExecutionContext() { return { client: clientFor(name) }; },
    transformRequest(body) { const mt = maxTokensFor(name, body); return { model: body.model, messages: body.messages, ...(mt ? { max_tokens: mt } : {}) }; },
    execute(payload, ctx) { return ctx.client.chat.completions.create(payload, ctx.signal ? { signal: ctx.signal } : undefined); },
    logFields(raw) { return { responseId: raw.id ?? null, usage: raw.usage ?? null }; },
    parseResponse(raw, ctx) {
      return {
        output: raw?.choices?.[0]?.message?.content,
        model: raw.model || ctx.model,
        tokenUsage: { inputTokens: raw.usage?.prompt_tokens ?? null, outputTokens: raw.usage?.completion_tokens ?? null, totalTokens: raw.usage?.total_tokens ?? null },
        executionMetadata: { responseId: raw.id ?? null },
      };
    },
  };
}

function streamSpecFor(name) {
  return {
    name,
    transport: TRANSPORTS.sdkStream,
    validate: {},
    transformRequest(body) { const mt = maxTokensFor(name, body); return { model: body.model, messages: body.messages, stream: true, ...(mt ? { max_tokens: mt } : {}) }; },
    async* execute(payload, ctx) {
      const s = await clientFor(name).chat.completions.create(payload, ctx.signal ? { signal: ctx.signal } : undefined);
      if (typeof ctx.markStreamAccepted === 'function') ctx.markStreamAccepted();
      yield* s;
    },
    isTerminalChunk: isOpenAICompatibleTerminalChunk,
    parseChunk(chunk) { return chunk && chunk.choices && chunk.choices[0] && chunk.choices[0].delta ? chunk.choices[0].delta.content : null; },
  };
}

/** A router handler (body, meta, signal) bound to one provider name. */
const handlerFor = (name) => (body, meta, signal) => runProviderCall(specFor(name), body, meta, signal);
const streamHandlerFor = (name) => (body, meta, signal) => runProviderStream(streamSpecFor(name), body, meta, signal);

function _reset() { clients.clear(); }

module.exports = { handlerFor, streamHandlerFor, specFor, streamSpecFor, clientFor, _reset };
