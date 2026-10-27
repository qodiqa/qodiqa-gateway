'use strict';

const { z } = require('../zod');
const { MAX_MODEL_LENGTH } = require('../../../services/providers/modelValidation');

const MAX_PROMPT_BYTES = 32_768; // 32 KB

/**
 * Zod schema for POST /ai/chat request body.
 *
 * Only validates the JSON body (prompt field).
 * The x-qodiqa-artifact header is a binary/base64 value that requires
 * JSON parsing and cryptographic verification — those checks remain in the
 * route handler where they interact with the audit pipeline.
 */
// provider-shaping fields QODIQA does NOT
// support. the schema's .passthrough() accepted them and both routes
// forwarded only `prompt`, so they were silently dropped — never enforced,
// never sent (the auditor's `harmfulInMessagesWithPrompt` probe returned
// EXECUTE). They are now refused with 400 UNSUPPORTED_FIELD before any
// artifact, semantic or provider work. Multi-turn support is.
const UNSUPPORTED_FIELDS = Object.freeze([
  'messages', 'system', 'tools', 'tool_choice', 'functions', 'function_call', 'response_format',
]);
// Fields the routes actually read. Anything else is still accepted (D5-b → b1)
// but reported by findUnknownFields() so the route can WARN.
const KNOWN_FIELDS = Object.freeze(['prompt', 'model', 'stream', 'provider', 'messages', 'system', 'purpose', 'dataRegion']);   // purpose / dataRegion are DECLARATIONS that ABAC rules may require

const conversation = require('../conversation');
const _own = (v, k) => v !== null && typeof v === 'object' && Object.prototype.hasOwnProperty.call(v, k);
function findUnsupportedFields(body) {
  // `messages` and `system` are supported (multi-turn) unless QODIQA_MULTI_TURN_ENABLED=false
  return UNSUPPORTED_FIELDS.filter((k) => _own(body, k) && !(conversation.enabled() && conversation.CONVERSATION_FIELDS.includes(k)));
}
function findUnknownFields(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return [];
  return Object.keys(body).filter((k) => !KNOWN_FIELDS.includes(k) && !UNSUPPORTED_FIELDS.includes(k)).sort();
}

const aiChatBodySchema = z.object({
  prompt: z.string().optional(),
  model:  z.string().optional(),
  stream: z.boolean().optional(),
}).passthrough().superRefine((val, ctx) => {
  // Checked first: a request carrying `messages` instead of `prompt` must learn
  // the real reason (unsupported field), not MISSING_PROMPT.
  const unsupported = findUnsupportedFields(val);
  if (unsupported.length > 0) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      message: `unsupported field(s): ${unsupported.join(', ')} — only a single \`prompt\` is supported`,
      params:  { qodiqaReason: 'UNSUPPORTED_FIELD', fields: unsupported },
    });
    return;
  }
  // a conversation (messages / system) replaces the single prompt
  if (conversation.enabled() && conversation.hasConversationFields(val)) {
    const bad = conversation.validateConversation(val);
    if (bad) ctx.addIssue({ code: z.ZodIssueCode.custom, message: bad.message, params: { qodiqaReason: bad.reason } });
    else if (typeof val.model === 'string' && val.model.length > MAX_MODEL_LENGTH) ctx.addIssue({ code: z.ZodIssueCode.custom, message: `model exceeds ${MAX_MODEL_LENGTH} characters`, params: { qodiqaReason: 'MODEL_TOO_LARGE' } });
    return;
  }
  const p = val.prompt;
  if (p === undefined || p === null) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      message: 'prompt is required',
      params:  { qodiqaReason: 'MISSING_PROMPT' },
    });
    return;
  }
  if (typeof p !== 'string' || p.trim().length === 0) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      message: 'prompt must be a non-empty string',
      params:  { qodiqaReason: 'MISSING_PROMPT' },
    });
    return;
  }
  if (Buffer.byteLength(p, 'utf8') > MAX_PROMPT_BYTES) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      message: `prompt exceeds ${MAX_PROMPT_BYTES} bytes`,
      params:  { qodiqaReason: 'PROMPT_TOO_LARGE' },
    });
  }

  // defense-in-depth: bound `model` at the schema layer, ahead of the
  // authoritative allowlist check in services/providers/modelValidation.js.
  // Kept in sync with that module's MAX_MODEL_LENGTH rather than a separate
  // hardcoded number, so there is still only one length policy to change.
  if (typeof val.model === 'string' && val.model.length > MAX_MODEL_LENGTH) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      message: `model exceeds ${MAX_MODEL_LENGTH} characters`,
      params:  { qodiqaReason: 'MODEL_TOO_LARGE' },
    });
  }
});

module.exports = {
  aiChatBodySchema, MAX_PROMPT_BYTES, UNSUPPORTED_FIELDS, KNOWN_FIELDS, findUnsupportedFields, findUnknownFields,
};
