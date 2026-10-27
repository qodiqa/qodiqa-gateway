'use strict';

/**
 * Azure OpenAI streaming: the OpenAI chat-completions SSE protocol through the same guarded AzureOpenAI client as services/providers/azure.js.
 * Streamed answers are complete only when a chunk carries a finish_reason; an accepted stream that fails later is never failed over.
 */

const { TRANSPORTS, runProviderStream, isOpenAICompatibleTerminalChunk } = require('./baseAdapter');
const { getClient } = require('./azure');

const spec = {
  name:      'azure',
  transport: TRANSPORTS.sdkStream,
  validate:  {},

  transformRequest(body) {
    const maxTokens = require('./limits').capMaxTokens(require('./config').getProviderConfig('azure')?.maxTokens ?? null, body);
    return { model: body.model, messages: body.messages, stream: true, ...(maxTokens ? { max_tokens: maxTokens } : {}) };
  },

  async* execute(payload, ctx) {
    const sdkStream = await getClient().chat.completions.create(payload, ctx.signal ? { signal: ctx.signal } : undefined);
    if (typeof ctx.markStreamAccepted === 'function') ctx.markStreamAccepted();
    yield* sdkStream;
  },

  isTerminalChunk: isOpenAICompatibleTerminalChunk,

  // Azure sends a first chunk with an empty `choices` array (prompt filter results) before the content: nothing to yield there.
  parseChunk(chunk) { return chunk && chunk.choices && chunk.choices[0] && chunk.choices[0].delta ? chunk.choices[0].delta.content : null; },
};

function callAzureStream(body, meta, signal) { return runProviderStream(spec, body, meta, signal); }

module.exports = { callAzureStream, _spec: spec };
