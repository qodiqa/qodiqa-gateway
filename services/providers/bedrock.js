'use strict';

/**
 * AWS Bedrock provider - Converse API, signed with SigV4 (services/providers/sigv4.js, no SDK dependency).
 *
 *   POST https://bedrock-runtime.<region>.amazonaws.com/model/<modelId>/converse
 *
 * The request's `model` is the Bedrock model id (for example `anthropic.claude-3-5-sonnet-20241022-v2:0`) or an inference-profile id. System messages become the Converse
 * `system` blocks; user/assistant messages become `messages` with text content blocks. The first message sent must be a user message (Converse requirement), consecutive
 * messages of one role are merged. The output is the concatenated text of the assistant's content blocks; usage comes from `usage.inputTokens/outputTokens/totalTokens`.
 *
 * SSRF: the host is built from BEDROCK_REGION (validated against ^[a-z]{2}(-[a-z]+)+-[0-9]$) and checked with the shared provider policy; redirects are refused. The model id
 * is URL-encoded as one path segment and must match [A-Za-z0-9._:/-]{1,128} (an inference-profile ARN contains slashes and colons, so those are allowed and encoded).
 * Credentials: BEDROCK_ACCESS_KEY_ID / BEDROCK_SECRET_ACCESS_KEY / optional BEDROCK_SESSION_TOKEN (deliberately not the ambient AWS_* names).
 *
 * Streaming: not provided (Converse streaming uses the binary event-stream framing, and no real Bedrock credential exists to verify a decoder against - the same position the
 * Gemini adapter is in). A stream request for this provider is refused by the streaming router with its standard "no native streaming" answer.
 * Status in the provider register: experimental until tested against the real service.
 */

const { resolveTimeoutMs } = require('./timeout');
const { validateProviderUrl } = require('./ssrf');
const sigv4 = require('./sigv4');
const { emit } = require('../logger');
const {
  MAX_MESSAGES, MAX_CONTENT_BYTES, TRANSPORTS,
  fetchJSON, runProviderCall,
} = require('./baseAdapter');

const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('BEDROCK_TIMEOUT_MS');
const MODEL_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const REGION_RE = /^[a-z]{2}(-[a-z]+)+-[0-9]$/;

function coded(code, detail) { const e = new Error(code); e.code = code; if (detail) e.detail = detail; return e; }

function credentials(env = process.env) {
  const region = env.BEDROCK_REGION; const accessKeyId = env.BEDROCK_ACCESS_KEY_ID; const secretAccessKey = env.BEDROCK_SECRET_ACCESS_KEY;
  if (!accessKeyId || !secretAccessKey) throw coded('PROVIDER_AUTH_FAILED');
  if (!REGION_RE.test(region || '')) throw coded('PROVIDER_CONFIG_INVALID', 'BEDROCK_REGION');
  return { region, accessKeyId, secretAccessKey, sessionToken: env.BEDROCK_SESSION_TOKEN || null };
}

function endpoint(region, model) {
  const base = `https://bedrock-runtime.${region}.amazonaws.com`;
  const check = validateProviderUrl(base);
  if (!check.valid) {
    emit('CRITICAL', 'PROVIDER_CONFIG_INVALID', { provider: 'bedrock', reason: check.reason, message: 'The Bedrock endpoint failed URL validation - provider cannot execute.' });
    throw coded('PROVIDER_CONFIG_INVALID', check.reason);
  }
  if (!MODEL_ID_RE.test(model) || model.includes('..')) throw coded('PROVIDER_MODEL_NOT_ALLOWED');
  return `${base}/model/${encodeURIComponent(model)}/converse`;
}

/** OpenAI-style messages -> Converse { system, messages }. */
function toConverse(messages) {
  const system = []; const out = [];
  for (const m of messages) {
    if (m.role === 'system') { system.push({ text: m.content }); continue; }
    const last = out[out.length - 1];
    if (last && last.role === m.role) last.content.push({ text: m.content });        // Converse requires strictly alternating roles
    else out.push({ role: m.role, content: [{ text: m.content }] });
  }
  return { system, messages: out };
}

const spec = {
  name:      'bedrock',
  transport: TRANSPORTS.fetch,
  // Converse needs a conversation that starts with a user turn.
  validate:  { extra: (messages) => { const first = messages.find((m) => m.role !== 'system'); return first && first.role === 'user' ? null : 'PROVIDER_INVALID_REQUEST'; } },
  completeLogIncludesHash: true,

  beforeValidatedEmit() { credentials(); },

  transformRequest(body) {
    const { system, messages } = toConverse(body.messages);
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('bedrock')?.maxTokens ?? null, body);
    return { messages, ...(system.length ? { system } : {}), ...(maxTokens ? { inferenceConfig: { maxTokens } } : {}) };
  },

  execute(payload, ctx) {
    const c = credentials();
    const url = endpoint(c.region, ctx.model);
    const bodyText = JSON.stringify(payload);
    const signed = sigv4.sign({ method: 'POST', url, headers: { 'content-type': 'application/json' }, body: bodyText, region: c.region, service: 'bedrock',
      accessKeyId: c.accessKeyId, secretAccessKey: c.secretAccessKey, sessionToken: c.sessionToken });
    return fetchJSON(url, { method: 'POST', redirect: 'error', headers: signed.headers, body: bodyText }, PROVIDER_TIMEOUT_MS, ctx.signal);
  },

  logFields(raw) { return { usage: raw.usage ?? null, stopReason: raw.stopReason ?? null }; },

  parseResponse(raw, ctx) {
    const blocks = raw && raw.output && raw.output.message && Array.isArray(raw.output.message.content) ? raw.output.message.content : null;
    const texts = blocks ? blocks.filter((b) => b && typeof b.text === 'string') : [];
    const output = texts.length > 0 ? texts.map((b) => b.text).join('') : undefined;          // an answer without a single text block is not an empty success
    const u = raw && raw.usage;
    return {
      output,
      model: ctx.model,
      tokenUsage: { inputTokens: u?.inputTokens ?? null, outputTokens: u?.outputTokens ?? null, totalTokens: u?.totalTokens ?? null },
      executionMetadata: { responseId: null },
    };
  },
};

function callBedrock(body, meta, signal) { return runProviderCall(spec, body, meta, signal); }

module.exports = { callBedrock, toConverse, endpoint, MAX_CONTENT_BYTES, MAX_MESSAGES, _spec: spec };
