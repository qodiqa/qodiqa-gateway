'use strict';

/**
 * Multi-turn conversations for POST /ai/chat.
 *
 * A request carries EITHER the historical single `prompt` OR `messages` (and optionally `system`). Everything the model will see is part of the request
 * body, so it is already covered by the request binding (the signed requestHash is over the whole body): changing any message, its role or its order
 * invalidates the artifact. This module only defines what a valid conversation is and the one normal form every consumer (provider call, streaming call,
 * semantic screening, /verify dry-run, classification budget) uses, so they cannot disagree.
 *
 *   messages : [{ role: 'system' | 'user' | 'assistant', content: string }]   1..MAX_MESSAGES, each content 1..MAX_CONTENT_BYTES, total <= MAX_TOTAL_BYTES,
 *                                                                              the LAST message is the user's turn
 *   system   : string, becomes the first (system) message
 * tools, tool_choice, functions, function_call, response_format: still refused (tool traffic arrives with)
 *
 * QODIQA_MULTI_TURN_ENABLED=false restores the single-prompt-only behaviour (messages / system are refused again as UNSUPPORTED_FIELD).
 */

const MAX_MESSAGES = 50;
const MAX_CONTENT_BYTES = 32_768;
const MAX_TOTAL_BYTES = 131_072;
const ROLES = Object.freeze(['system', 'user', 'assistant']);
const CONVERSATION_FIELDS = Object.freeze(['messages', 'system']);

const _own = (v, k) => v !== null && typeof v === 'object' && Object.prototype.hasOwnProperty.call(v, k);
const bytes = (s) => Buffer.byteLength(s, 'utf8');

function enabled(env = process.env) { return env.QODIQA_MULTI_TURN_ENABLED !== 'false'; }
function hasConversationFields(body) { return CONVERSATION_FIELDS.some((k) => _own(body, k)); }

/** @returns {null | { reason: string, message: string }} null = the conversation fields are valid (or absent) */
function validateConversation(body) {
  if (!hasConversationFields(body)) return null;
  if (_own(body, 'prompt') && body.prompt !== undefined && body.prompt !== null) return { reason: 'PROMPT_AND_MESSAGES', message: 'send either `prompt` or `messages` / `system`, not both' };
  let total = 0;
  if (_own(body, 'system')) {
    if (typeof body.system !== 'string' || body.system.trim().length === 0) return { reason: 'INVALID_SYSTEM', message: '`system` must be a non-empty string' };
    if (bytes(body.system) > MAX_CONTENT_BYTES) return { reason: 'MESSAGE_TOO_LARGE', message: `\`system\` exceeds ${MAX_CONTENT_BYTES} bytes` };
    total += bytes(body.system);
  }
  if (!_own(body, 'messages')) return { reason: 'MISSING_PROMPT', message: '`messages` is required with `system`' };
  const m = body.messages;
  if (!Array.isArray(m) || m.length === 0) return { reason: 'INVALID_MESSAGES', message: '`messages` must be a non-empty array' };
  if (m.length > MAX_MESSAGES) return { reason: 'MESSAGES_TOO_MANY', message: `at most ${MAX_MESSAGES} messages` };
  for (const x of m) {
    if (x === null || typeof x !== 'object' || Array.isArray(x)) return { reason: 'INVALID_MESSAGES', message: 'every message must be an object { role, content }' };
    const keys = Object.keys(x);
    if (keys.some((k) => k !== 'role' && k !== 'content') || !ROLES.includes(x.role)) return { reason: 'INVALID_MESSAGES', message: `a message has exactly { role, content } with role one of ${ROLES.join(', ')}` };
    if (typeof x.content !== 'string' || x.content.trim().length === 0) return { reason: 'INVALID_MESSAGES', message: 'message content must be a non-empty string' };
    const b = bytes(x.content);
    if (b > MAX_CONTENT_BYTES) return { reason: 'MESSAGE_TOO_LARGE', message: `a message exceeds ${MAX_CONTENT_BYTES} bytes` };
    total += b;
  }
  if (total > MAX_TOTAL_BYTES) return { reason: 'MESSAGES_TOO_LARGE', message: `the conversation exceeds ${MAX_TOTAL_BYTES} bytes` };
  if (m[m.length - 1].role !== 'user') return { reason: 'LAST_MESSAGE_NOT_USER', message: 'the last message must be the user turn' };
  return null;
}

/** The conversation the provider receives: `system` first, then `messages` in order; or the single prompt as one user message. */
function normalizeConversation(body) {
  if (!body || typeof body !== 'object') return [];
  if (!hasConversationFields(body)) return typeof body.prompt === 'string' ? [{ role: 'user', content: body.prompt }] : [];
  const out = [];
  if (typeof body.system === 'string') out.push({ role: 'system', content: body.system });
  if (Array.isArray(body.messages)) for (const x of body.messages) out.push({ role: x.role, content: x.content });
  return out;
}

/** Every piece of text that must be screened, with its role and position. */
function screenTexts(body) {
  return normalizeConversation(body).map((m, index) => ({ role: m.role, index, text: m.content }));
}

/** Total length in characters of everything the model will read (the classification budget is charged on it). */
function totalLength(body) { return normalizeConversation(body).reduce((n, m) => n + m.content.length, 0); }

module.exports = { MAX_MESSAGES, MAX_CONTENT_BYTES, MAX_TOTAL_BYTES, ROLES, CONVERSATION_FIELDS, enabled, hasConversationFields, validateConversation, normalizeConversation, screenTexts, totalLength };
