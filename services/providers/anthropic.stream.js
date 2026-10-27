'use strict';

/**
 * Anthropic streaming adapter — yields incremental text chunks via AsyncGenerator.
 *
 * Consumes the Anthropic Messages API SSE stream using native fetch (Node 18+ built-in).
 * Called ONLY through executeStreamingProviderCall() in services/execution.stream.js.
 * Shares its lifecycle (validation, cancellation, timeout composition, logging,
 * error normalization) with every other adapter via
 * services/providers/baseAdapter.js — only SSE line parsing is specific to
 * this file.
 *
 * Environment variables: same as services/providers/anthropic.js
 *   ANTHROPIC_API_KEY    — required
 *   ANTHROPIC_TIMEOUT_MS — optional (default 30 000 ms)
 *   ANTHROPIC_MAX_TOKENS — optional (default 4096)
 *
 * Yields: { delta: string }
 * Throws: canonical PROVIDER_* errors on any failure
 */

const { resolveTimeoutMs } = require('./timeout');
const { validateProviderUrl } = require('./ssrf');
const { composeSignals }      = require('./signalUtil');
const { emit }                = require('../logger');
const {
  TRANSPORTS, assertUrlSafeAtLoad, fetchWithTimeout, runProviderStream,
} = require('./baseAdapter');

const CANONICAL_BASE_URL  = 'https://api.anthropic.com';
const MESSAGES_PATH       = '/v1/messages';
const ANTHROPIC_VERSION   = '2023-06-01';
const PROVIDER_TIMEOUT_MS = resolveTimeoutMs('ANTHROPIC_TIMEOUT_MS');
const MAX_TOKENS          = parseInt(process.env.ANTHROPIC_MAX_TOKENS  || '4096',  10);

assertUrlSafeAtLoad({
  provider:     'anthropic',
  url:          CANONICAL_BASE_URL,
  check:        validateProviderUrl(CANONICAL_BASE_URL),
  eventCode:    'PROVIDER_SSRF_REJECTED',
  logMessage:   'Anthropic streaming adapter base URL failed SSRF validation — module cannot load.',
  errorMessage: 'PROVIDER_SSRF_REJECTED: ',
});

function _transformMessages(messages) {
  const systemParts  = [];
  const chatMessages = [];
  for (const msg of messages) {
    if (msg.role === 'system') {
      systemParts.push(msg.content);
    } else {
      chatMessages.push({ role: msg.role, content: msg.content });
    }
  }
  return {
    system:   systemParts.length > 0 ? systemParts.join('\n\n') : undefined,
    messages: chatMessages,
  };
}

function _extraValidation(messages) {
  const hasNonSystem = messages.some(m => m.role !== 'system');
  return hasNonSystem ? null : 'PROVIDER_INVALID_REQUEST';
}

// Anthropic's documented Messages SSE protocol is
//   message_start → (content_block_start → content_block_delta* → content_block_stop)* → message_delta* → message_stop
// interleaved with `ping`, and an in-band `error` event (e.g. `overloaded_error`) that may arrive AFTER the
// HTTP 200 and after deltas. the parser dropped `error` frames and treated "body ended" as
// success, so a mid-stream overload completed as a truncated SUCCESS. Now:
//   • an `error` event raises a coded provider error (mapping below), flagged providerMayHaveExecuted (the
//     request was accepted and generation started — it must never be re-sent or failed over);
//   • `message_stop` is the ONLY successful terminator; a body that ends without it is an incomplete stream
//     and raises PROVIDER_UNAVAILABLE (providerMayHaveExecuted), never a silent success;
//   • `[DONE]` is not part of Anthropic's protocol and is ignored (it neither terminates nor succeeds).
// Mapping of Anthropic's documented error types (docs.anthropic.com "Errors"):
const ANTHROPIC_STREAM_ERROR_CODES = Object.freeze({
  overloaded_error:      'PROVIDER_UNAVAILABLE',
  api_error:             'PROVIDER_UNAVAILABLE',
  rate_limit_error:      'PROVIDER_RATE_LIMITED',
  authentication_error:  'PROVIDER_AUTH_FAILED',
  permission_error:      'PROVIDER_AUTH_FAILED',
  invalid_request_error: 'PROVIDER_INVALID_REQUEST',
  not_found_error:       'PROVIDER_INVALID_REQUEST',
  request_too_large:     'PROVIDER_INVALID_REQUEST',
});

function _streamError(code) {
  const err = new Error(code);
  err.code  = code;
  err.providerMayHaveExecuted = true;
  return err;
}

// Parses one SSE line. Returns:
//   { event: name }          — an `event:` field line
//   { delta: string }        — a non-empty text delta
//   { stop: true }           — message_stop
//   { error: errorType }     — an in-band error event (errorType may be null when unparseable)
//   null                     — anything else (ping, structural events, comments, [DONE], malformed non-error data)
function _parseSseLine(line, currentEvent) {
  if (line.endsWith('\r')) line = line.slice(0, -1);
  if (line.startsWith('event:')) return { event: line.slice(6).trim() };
  if (!line.startsWith('data:')) return null;
  const data = line.slice(5).trim();
  if (data === '[DONE]') return null;

  let parsed;
  try { parsed = JSON.parse(data); } catch {
    // A malformed error frame is still an error — never let it pass as success.
    return currentEvent === 'error' ? { error: null } : null;
  }

  if (parsed?.type === 'error' || currentEvent === 'error') {
    return { error: typeof parsed?.error?.type === 'string' ? parsed.error.type : null };
  }
  if (parsed?.type === 'message_stop') return { stop: true };
  if (parsed?.type === 'content_block_delta' &&
      parsed?.delta?.type === 'text_delta' &&
      typeof parsed.delta.text === 'string' &&
      parsed.delta.text.length > 0) {
    return { delta: parsed.delta.text };
  }
  return null;
}

// Consumes the SSE response body, yielding parsed delta strings.
async function* _sseChunks(res, timeoutId, meta) {
  const reader  = res.body.getReader();
  const decoder = new TextDecoder();
  let   buffer  = '';
  let   currentEvent = null;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (!done) buffer += decoder.decode(value, { stream: true });
      else buffer += decoder.decode();

      const lines = buffer.split('\n');
      buffer = done ? '' : (lines.pop() ?? ''); // at end of body, the unterminated tail is a line too

      for (const line of lines) {
        if (line === '' || line === '\r') { currentEvent = null; continue; } // SSE event boundary
        const parsedLine = _parseSseLine(line, currentEvent);
        if (!parsedLine) continue;
        if (parsedLine.event !== undefined) { currentEvent = parsedLine.event; continue; }
        if (parsedLine.stop) return;
        if (parsedLine.error !== undefined) {
          const code = ANTHROPIC_STREAM_ERROR_CODES[parsedLine.error] || 'PROVIDER_UNAVAILABLE';
          emit('WARN', 'PROVIDER_STREAM_ERROR_EVENT', {
            provider:  'anthropic',
            requestId: meta?.requestId ?? null,
            errorType: parsedLine.error,
            code,
            message:   'Anthropic sent an in-stream error event — stream failed, not completed.',
          });
          throw _streamError(code);
        }
        yield parsedLine.delta;
      }
      if (done) break;
    }
    // Body ended without message_stop: an incomplete (truncated) stream, never a success.
    emit('WARN', 'PROVIDER_STREAM_INCOMPLETE', {
      provider:  'anthropic',
      requestId: meta?.requestId ?? null,
      message:   'Anthropic stream ended without message_stop — treated as a failed (truncated) stream.',
    });
    throw _streamError('PROVIDER_UNAVAILABLE');
  } finally {
    clearTimeout(timeoutId);
    try { reader.cancel(); } catch {}
  }
}

const spec = {
  name:      'anthropic',
  transport: TRANSPORTS.fetch,
  validate:  { extra: _extraValidation },

  beforeStart() {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      const err = new Error('PROVIDER_AUTH_FAILED');
      err.code  = 'PROVIDER_AUTH_FAILED';
      throw err;
    }
  },

  transformRequest(body) {
    const { system, messages: chatMessages } = _transformMessages(body.messages);
    return {
      model:      body.model,
      max_tokens: require('./limits').capMaxTokens(MAX_TOKENS, body),
      messages:   chatMessages,
      stream:     true,
      ...(system ? { system } : {}),
    };
  },

  async* execute(payload, ctx) {
    // Compose caller signal with our own timeout signal so the timeout is
    // still observed after the initial fetch resolves, while streaming the body.
    const timeoutAc = new AbortController();
    const timeoutId = setTimeout(() => {
      if (!timeoutAc.signal.aborted) timeoutAc.abort('provider_timeout');
    }, PROVIDER_TIMEOUT_MS);
    const abortSignal = composeSignals(ctx.signal, timeoutAc.signal);

    let res;
    try {
      res = await fetch(`${CANONICAL_BASE_URL}${MESSAGES_PATH}`, {
        method:  'POST',
        headers: {
          'content-type':      'application/json',
          'x-api-key':         process.env.ANTHROPIC_API_KEY,
          'anthropic-version': ANTHROPIC_VERSION,
          'accept':            'text/event-stream',
        },
        body:   JSON.stringify(payload),
        signal: abortSignal,
      });
    } catch (err) {
      clearTimeout(timeoutId);
      throw err;
    }

    if (!res.ok) {
      clearTimeout(timeoutId);
      const httpErr  = new Error(`HTTP ${res.status}`);
      httpErr.status = res.status;
      throw httpErr;
    }

    // HTTP 2xx — the provider accepted the call; any later failure must never be failed over.
    if (typeof ctx.markStreamAccepted === 'function') ctx.markStreamAccepted();
    yield* _sseChunks(res, timeoutId, ctx.meta);
  },

  parseChunk(delta) {
    return delta;
  },
};

/**
 * Stream an Anthropic Messages API response via SSE.
 *
 * @param {{ model: string, messages: Array }}     body
 * @param {{ requestId, requestHash, policyHash }} meta
 * @param {AbortSignal}                            [signal]
 * @yields {{ delta: string }}
 * @throws {Error} with .code set to a canonical PROVIDER_* string
 */
function callAnthropicStream(body, meta, signal) {
  return runProviderStream(spec, body, meta, signal);
}

module.exports = { callAnthropicStream };
