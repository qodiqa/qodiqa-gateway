'use strict';

const { z } = require('../zod');
const { exceedsDepth } = require('../helpers');

const VALID_HTTP_METHODS = Object.freeze(new Set([
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS',
]));

const MAX_TTL_MS    = 86_400_000;  // 24 h
const MIN_TTL_MS    = 1_000;       // 1 s
const MAX_PATH_BYTES = 2_048;
const MAX_BODY_DEPTH = 10;
const MAX_PAYLOAD_BYTES = 8_192;
// Claims that /sign sets itself (routes/sign.js innerPayload) — a caller may not supply them.
const RESERVED_PAYLOAD_KEYS = Object.freeze(['requestId', 'requestHash', 'policyHash', 'tenantId', 'callerContext']);

// Allowed top-level body keys — any other key is rejected.
const ALLOWED_BODY_KEYS = Object.freeze(['request', 'payload', 'ttl', 'v2']);

/**
 * Zod schema for POST /sign request body.
 *
 * Encodes every structural constraint previously checked inline in sign.js:
 *   • Only the allowed top-level keys (request, payload, ttl) are accepted.
 *   • request.method must be a recognised HTTP verb.
 *   • request.path must be a non-empty string within 2048 UTF-8 bytes.
 *   • request.body must be a plain object whose nesting depth ≤ MAX_BODY_DEPTH.
 *   • request itself accepts only {method, path, body} — no other keys
 *     (item 9 audit: this nested object had no known caller sending a 4th
 *     key; the outer object was already .strict(), the nested one wasn't).
 *   • payload is an optional plain object (no undefined values; enforced at
 *     JSON-parse time so only asserted, not re-validated here).
 *   • ttl is an optional positive finite number.
 *
 * Validation failures carry `params.qodiqaReason` so the route can return
 * the correct enforcement protocol reason code.
 */
const signBodySchema = z.object({
  request: z.object({
    method: z.string().min(1, 'method is required')
      .superRefine((val, ctx) => {
        if (!VALID_HTTP_METHODS.has(val)) {
          ctx.addIssue({
            code:    z.ZodIssueCode.custom,
            message: `method must be one of: ${[...VALID_HTTP_METHODS].join(', ')}`,
            params:  { qodiqaReason: 'INVALID_METHOD' },
          });
        }
      }),
    path: z.string().min(1, 'path is required')
      .superRefine((val, ctx) => {
        if (Buffer.byteLength(val, 'utf8') > MAX_PATH_BYTES) {
          ctx.addIssue({
            code:    z.ZodIssueCode.custom,
            message: `path exceeds ${MAX_PATH_BYTES} UTF-8 bytes`,
            params:  { qodiqaReason: 'PATH_TOO_LONG' },
          });
        }
      }),
    body: z.record(z.string(), z.unknown())
      .superRefine((val, ctx) => {
        if (exceedsDepth(val, MAX_BODY_DEPTH)) {
          ctx.addIssue({
            code:    z.ZodIssueCode.custom,
            message: `request.body nesting exceeds ${MAX_BODY_DEPTH} levels`,
            params:  { qodiqaReason: 'BODY_TOO_DEEP' },
          });
        }
      }),
    // (protocol V2, V2-FREEZE 3): the raw query string (without '?') and the values of the bound headers; only meaningful with a `v2` block.
    query:   z.string().max(2_048).optional(),
    headers: z.record(z.string(), z.string().max(1_024)).refine((h) => Object.keys(h).length <= 16, 'at most 16 headers').optional(),
  }).strict(),
  // `payload` stays the documented free-form application context (API_REFERENCE: e.g. userId), but it is
  // now bounded in nesting depth and serialized size so it cannot carry unbounded data into the SIGNED envelope. Server-owned claim
  // names (RESERVED_PAYLOAD_KEYS) are still silently overridden by /sign (SIGN-CALLER-03 anti-spoofing contract) — now with a WARN —
  // and QODIQA_SIGN_PAYLOAD_STRICT=true makes /sign reject every caller key except `provider` (see routes/sign.js).
  payload: z.record(z.string(), z.unknown())
    .superRefine((val, ctx) => {
      // (verification): the one documented claim, `provider`, must be a plain provider-name string on every path.
      if (Object.prototype.hasOwnProperty.call(val, 'provider') && !(typeof val.provider === 'string' && /^[A-Za-z0-9._-]{0,64}$/.test(val.provider))) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'payload.provider must be a provider name', params: { qodiqaReason: 'INVALID_REQUEST' } });
      }
      if (exceedsDepth(val, MAX_BODY_DEPTH)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `payload nesting exceeds ${MAX_BODY_DEPTH} levels`, params: { qodiqaReason: 'BODY_TOO_DEEP' } });
      }
      let bytes = 0;
      try { bytes = Buffer.byteLength(JSON.stringify(val), 'utf8'); } catch (_) { bytes = Infinity; }
      if (bytes > MAX_PAYLOAD_BYTES) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `payload exceeds ${MAX_PAYLOAD_BYTES} bytes`, params: { qodiqaReason: 'INVALID_REQUEST' } });
      }
    })
    .optional(),
  // the protocol V2 block { bind: { headers: [...] }, model?, limits?, crit? } (validated in src/validation/protocolV2.js).
  v2: z.record(z.string(), z.unknown()).optional(),
  ttl: z.number().finite().positive().optional()
    .superRefine((val, ctx) => {
      if (val !== undefined && val !== null && (!Number.isFinite(val) || val <= 0)) {
        ctx.addIssue({
          code:    z.ZodIssueCode.custom,
          message: 'ttl must be a positive finite number',
          params:  { qodiqaReason: 'INVALID_TTL' },
        });
      }
    }),
}).strict();

module.exports = { signBodySchema, VALID_HTTP_METHODS, MAX_TTL_MS, MIN_TTL_MS, RESERVED_PAYLOAD_KEYS, MAX_PAYLOAD_BYTES };
