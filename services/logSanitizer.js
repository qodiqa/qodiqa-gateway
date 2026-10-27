'use strict';

/**
 * Logging Sanitization Pipeline — Component 44.7
 *
 * Recursively sanitizes any value before it is written to a log sink.
 * Two complementary detection strategies:
 *
 *   Field-name redaction:
 *     Any object key whose normalized name matches a known sensitive stem
 *     (authorization, password, token, secret, privateKey, email, ssn, iban,
 *     creditCard, …) has its entire value replaced with [REDACTED].
 *     Normalized means: toLowerCase() + strip a leading "x-" HTTP header
 *     prefix (RFC 6648 custom-header convention, e.g. X-Api-Key, X-Auth-Token)
 *     + strip all non-alphanumeric characters.
 *
 *   Value-pattern scanning (strings only):
 *     String values that are NOT already field-name-redacted are scanned for:
 *       • Cryptographic material  → [CRYPTO]  (PEM blocks)
 *       • Tokens / credentials    → [TOKEN]   (JWT, Bearer, Basic auth)
 *       • PII                     → [EMAIL], [PHONE], [PII]
 *                                   (emails, phones, SSN, IBAN, credit cards)
 * • IPv4 and IPv6 addresses → [IP]
 *
 * Safety guarantees:
 *   • Never throws — every code path is wrapped in try/catch.
 *   • Bounded recursion — stops at maxDepth with [MAX_DEPTH] placeholder.
 *   • Circular-reference safe — tracks seen reference types in a WeakSet.
 *   • Handles all JavaScript types: primitives, objects, arrays, Error,
 *     Map, Set, Buffer, Date, RegExp, Symbol, BigInt, Function.
 *
 * Public API:
 *   sanitize(value, config?)   → sanitized copy of value (same shape)
 *   snapshot()                 → { redactedFields, piiDetections, tokenDetections,
 *                                  cryptoDetections, truncations }
 *   reset()                    → clears all metrics counters
 */

const net = require('net'); // S-02: IPv6 redaction candidate confirmation
const { defaultConfig } = require('./logSanitizerConfig');

// ── Sensitive field name stems ────────────────────────────────────────────────
//
// Unified set — merged and
// src/observability/logShipping/schema.js (SENSITIVE_STEMS), plus PII field names.
//
// All stems are normalized: lowercase, no non-alphanumeric characters.
// Matching: normalize(fieldName) → check against this set.

const SENSITIVE_FIELD_STEMS = new Set([
  // Authorization & bearer credentials
  'authorization', 'auth', 'bearer',
  // Passwords
  'password', 'passwd',
  // API keys and access keys
  'apikey', 'apikeyid', 'accesskey', 'secretkey',
  // Tokens of all kinds
  'token', 'accesstoken', 'refreshtoken', 'sessiontoken', 'authtoken',
  'csrftoken', 'idtoken', 'oauthtoken', 'oauthaccesstoken', 'oauthrefreshtoken',
  // Secrets
  'secret', 'clientsecret', 'signingsecret', 'webhooksecret', 'sharedsecret',
  // Generic credentials
  'credential', 'credentials',
  // Cryptographic key material
  'privatekey', 'privkey', 'signingkey', 'signaturekey', 'encryptionkey',
  'hsmkey', 'hsmref', 'keycontents', 'keydata', 'keymaterial',
  'tlskey', 'keyencryptionkey',
  // QODIQA-specific tokens
  'signtoken', 'qodiqasigntoken',
  // QODIQA's own credential field names that the generic stems above missed
  'adminkey', 'opstoken', 'qodiqaopstoken', 'pgpassword', 'portaltoken', 'sessiontokenvalue',
  'hmackey', 'mackey', 'backuphmackey', 'webhooksigningsecret',
  // PII field names
  'email', 'emailaddress', 'emailaddr',
  'phone', 'phonenumber', 'mobilenumber', 'cellphone', 'telephone',
  'ssn', 'socialsecuritynumber', 'socialsecurity',
  'creditcard', 'cardnumber', 'ccnumber', 'cvv', 'cvv2', 'cvc', 'csc', 'pan',
  'iban', 'bankaccount', 'accountnumber', 'routingnumber', 'sortcode',
  'dateofbirth', 'birthdate', 'dob',
  'streetaddress', 'homeaddress',
  'passportnumber', 'passportno',
  'driverslicense', 'driverlicense', 'driverslic', 'dlnumber',
  'taxid', 'taxidentifier', 'taxpayerid', 'ein', 'nin', 'nationalid',
  'sessionid',
]);

// ── Value-pattern regex definitions ──────────────────────────────────────────
//
// All patterns use the /g (global) flag.  String.prototype.replace() with a
// global regex always resets lastIndex before iterating, so module-level
// constants are safe to share across calls.

// PEM-encoded cryptographic material (private keys, certificates, etc.)
// Matches: -----BEGIN <TYPE>----- ... -----END <TYPE>-----
// The [\s\S]*? is non-greedy to avoid swallowing adjacent PEM blocks.
const RE_PEM = /-----BEGIN [A-Z][A-Z0-9 ]+-----[\s\S]*?-----END [A-Z][A-Z0-9 ]+-----/g;

// JWT tokens: three base64url segments; header and payload both start with eyJ
// (base64url of `{"`) with minimum length guards to avoid short false positives.
const RE_JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+/g;

// credentials QODIQA itself issues, recognised by VALUE wherever they appear (free text, error
// messages, URLs) — not only under a sensitive field name:
//   ok_<64 hex>   RBAC operator API keys          (src/core/rbac/store.js)
//   sk_<64 hex>   signing-identity API keys       (src/core/signing/signingIdentityStore.js)
//   whsec_<64 hex> webhook signing secrets        (src/core/webhooks/webhookSecrets.js)
//   pt_<b64url>.<hex>  portal session tokens      (services/portal/portalSessionToken.js)
const RE_QODIQA_KEY = /\b(?:ok|sk|whsec)_[0-9a-f]{64}\b/g;
const RE_PORTAL_TOKEN = /\bpt_[A-Za-z0-9_-]{16,}\.[0-9a-f]{32,}\b/g;
// AI-provider API keys the gateway itself holds, in the
// documented `sk-` family — OpenAI legacy `sk-<48 alnum>`, `sk-proj-…`, `sk-svcacct-…`, `sk-admin-…`, and Anthropic
// `sk-ant-api03-…`. A real key is >= 31 characters after `sk-` and mixes digits and upper case; requiring both keeps
// kebab-case words ("sk-learn-compatibility-layer") from matching. A truncated or abbreviated key (e.g. `sk-abc…xyz`,
// as provider dashboards display them) is below the length floor and is left alone: it is not a usable credential.
const RE_PROVIDER_KEY = /\bsk-(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Z])[A-Za-z0-9][A-Za-z0-9_-]{30,}/g;
// Ed25519 private keys exported as raw PKCS#8 DER (no PEM armour, so RE_PEM misses them): the fixed 16-byte
// PKCS#8 Ed25519 prefix, in base64 and in hex.
const RE_ED25519_PKCS8_B64 = /MC4CAQAwBQYDK2VwBCIEI[A-Za-z0-9+/]{40,}={0,2}/g;
const RE_ED25519_PKCS8_HEX = /302e020100300506032b657004220420[0-9a-fA-F]{64}/g;
// Userinfo in a URL (postgres://user:password@host, redis://:password@host): the password part is redacted.
const RE_URL_USERINFO = /\b([a-z][a-z0-9+.-]*:\/\/)([^\s:@/]*):([^\s@/]+)@/gi;

// HTTP Authorization header value patterns
const RE_BEARER = /\b(?:Bearer|Token)\s+[A-Za-z0-9\-._~+\/]{10,}=*/gi;
const RE_BASIC  = /\bBasic\s+[A-Za-z0-9+\/]{10,}={0,2}/gi;

// Email addresses (RFC 5321 simplified)
const RE_EMAIL = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;

// US-format phone: (NXX) NXX-XXXX or NXX-NXX-XXXX (area code 200-999)
// Lookbehind prevents matching within longer digit sequences.
// (NF-16): and within an alphanumeric token — a 10-digit decimal run inside a
// hex digest (sha256, entry/record hashes; ~1 in 5 random sha256 values) was
// rewritten to [PHONE], silently corrupting logged hashes and fingerprints.
const RE_PHONE_US = /(?<![.\dA-Za-z])\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?![\dA-Za-z])/g;

// International phone numbers in E.164 format (+CCNNNNNNNNN) and with 1-prefix
const RE_PHONE_INTL = /(?<![\dA-Za-z])\+?1[-.\s]?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?![\dA-Za-z])/g;
const RE_PHONE_E164 = /(?<!\d)\+[2-9]\d{6,14}(?!\d)/g;

// US Social Security Number (xxx-xx-xxxx, excludes invalid area codes)
const RE_SSN = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;

// IBAN — country code (2 alpha) + check digits (2 numeric) + BBAN
// Limited to well-known country codes to minimise false positives.
const RE_IBAN = /\b(?:AD|AE|AL|AT|AZ|BA|BE|BG|BH|BR|BY|CH|CR|CY|CZ|DE|DJ|DK|DO|EE|EG|ES|FI|FK|FO|FR|GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IQ|IS|IT|JO|KW|KZ|LB|LC|LI|LT|LU|LV|LY|MA|MC|MD|ME|MK|MR|MT|MU|NI|NL|NO|PK|PL|PS|PT|QA|RO|RS|SA|SC|SD|SE|SI|SK|SM|ST|SV|TN|TR|UA|VA|VG|XK)\d{2}[A-Z0-9]{10,30}\b/g;

// Credit card candidates — matched against known IIN ranges, then Luhn-verified.
const RE_CC_VISA       = /\b4\d{12}(?:\d{3})?\b/g;
const RE_CC_MC         = /\b5[1-5]\d{14}\b/g;
const RE_CC_AMEX       = /\b3[47]\d{13}\b/g;
const RE_CC_DISCOVER   = /\b6(?:011|5\d{2})\d{12}\b/g;
const RE_CC_MAESTRO    = /\b(?:6304|6759|676[123])\d{8,15}\b/g;

// IPv4 addresses (all valid octets)
const RE_IPV4 = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b/g;
// S-02: IPv6 candidates (2+ colons, hex groups, optional zone id). Each candidate is
// confirmed with net.isIPv6 before redaction, so times (07:55:10), MAC addresses and ratios are never touched.
const RE_IPV6_CANDIDATE = /(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[0-9A-Za-z]+)?(?![0-9A-Za-z:])/g;

// ── Luhn check ────────────────────────────────────────────────────────────────

function _luhn(str) {
  const digits = str.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// ── In-process metrics ────────────────────────────────────────────────────────
//
// Counts sanitization events for auditability.  Never reveals sensitive values.
// Cleared per test run via reset().

const _m = {
  redactedFields:   0,
  piiDetections:    0,
  tokenDetections:  0,
  cryptoDetections: 0,
  truncations:      0,
};

function snapshot() { return { ..._m }; }
function reset()     { Object.keys(_m).forEach(k => { _m[k] = 0; }); }

// ── Field name normalization ──────────────────────────────────────────────────

function _normalizeKey(key) {
  let k = String(key).toLowerCase();
  // Strip the conventional "X-" custom-HTTP-header prefix (RFC 6648 deprecated
  // it, but it remains ubiquitous in the wild: X-Api-Key, X-Auth-Token,
  // X-Access-Token, …) so these normalize identically to their un-prefixed
  // form before stem comparison. Deliberately requires the literal hyphen —
  // "xray" / "xerox" style words are untouched since they never contain "x-".
  if (k.startsWith('x-')) {
    k = k.slice(2);
  }
  return k.replace(/[^a-z0-9]/g, '');
}

function _isSensitiveField(key) {
  return SENSITIVE_FIELD_STEMS.has(_normalizeKey(key));
}

// ── String value scanning ─────────────────────────────────────────────────────

function _applyCC(str, placeholder) {
  function sub(re) {
    return str.replace(re, (match) => {
      if (_luhn(match)) { _m.piiDetections++; return placeholder; }
      return match;
    });
  }
  str = sub(RE_CC_VISA);
  str = sub(RE_CC_MC);
  str = sub(RE_CC_AMEX);
  str = sub(RE_CC_DISCOVER);
  str = sub(RE_CC_MAESTRO);
  return str;
}

function _sanitizeString(str, cfg) {
  if (typeof str !== 'string') return str;

  // Truncate oversized strings before scanning (bounds the regex work).
  let s = str;
  if (s.length > cfg.maxStringLength) {
    s = s.slice(0, cfg.maxStringLength) + cfg.placeholderTruncated;
    _m.truncations++;
  }

  // ── Fast-reject gates ────────────────────────────────────────────────────
  //
  // Every pattern below requires a specific literal substring or character
  // class to appear at all before it can match (an email needs '@', a JWT
  // needs 'eyJ', SSN/IBAN/phone/credit-card all need digits, …). Each gate is
  // a *necessary* condition for its regex — a strict superset of "could
  // match" — so skipping the regex when the gate is false can never skip an
  // actual detection; it only skips strings that were structurally
  // guaranteed not to match anyway. This is what makes the optimization safe:
  // it changes nothing about *what* gets redacted, only how much regex work
  // runs on strings that no pattern could ever match (the common case for
  // short enum-like fields such as decision codes and event names).
  const hasDigit = /\d/.test(s);

  // ── Cryptographic material (highest priority) ──────────────────────────────
  if (cfg.scanCrypto && s.includes('-----BEGIN')) {
    s = s.replace(RE_PEM, () => { _m.cryptoDetections++; return cfg.placeholderCrypto; });
  }
  if (cfg.scanCrypto && s.length >= 60) {
    if (s.includes('MC4CAQAwBQYDK2VwBCIEI')) s = s.replace(RE_ED25519_PKCS8_B64, () => { _m.cryptoDetections++; return cfg.placeholderCrypto; });
    if (s.includes('302e020100300506032b6570')) s = s.replace(RE_ED25519_PKCS8_HEX, () => { _m.cryptoDetections++; return cfg.placeholderCrypto; });
  }

  // ── Token patterns ─────────────────────────────────────────────────────────
  if (cfg.scanTokens) {
    if (s.includes('eyJ')) {
      s = s.replace(RE_JWT, () => { _m.tokenDetections++; return cfg.placeholderToken; });
    }
    // RE_BEARER/RE_BASIC require a literal prefix plus >=10 trailing chars —
    // any string shorter than that cannot match either pattern.
    if (s.length >= 10) {
      s = s.replace(RE_BEARER, () => { _m.tokenDetections++; return cfg.placeholderToken; });
      s = s.replace(RE_BASIC,  () => { _m.tokenDetections++; return cfg.placeholderToken; });
    }
    if (s.length >= 67 && s.includes('_')) {
      s = s.replace(RE_QODIQA_KEY,   () => { _m.tokenDetections++; return cfg.placeholderToken; });
      s = s.replace(RE_PORTAL_TOKEN, () => { _m.tokenDetections++; return cfg.placeholderToken; });
    }
    if (s.length >= 34 && s.includes('sk-')) {
      s = s.replace(RE_PROVIDER_KEY, () => { _m.tokenDetections++; return cfg.placeholderToken; });
    }
    if (s.includes('://') && s.includes('@')) {
      s = s.replace(RE_URL_USERINFO, (_all, scheme, user) => { _m.tokenDetections++; return `${scheme}${user}:${cfg.placeholderToken}@`; });
    }
  }

  // ── PII patterns ───────────────────────────────────────────────────────────
  if (cfg.scanPii) {
    if (s.includes('@')) {
      s = s.replace(RE_EMAIL, () => { _m.piiDetections++; return cfg.placeholderEmail; });
    }
    if (hasDigit) {
      s = s.replace(RE_SSN,        () => { _m.piiDetections++; return cfg.placeholderPii; });
      s = s.replace(RE_IBAN,       () => { _m.piiDetections++; return cfg.placeholderPii; });
      // Phone: US/NANP first, then international
      s = s.replace(RE_PHONE_INTL, () => { _m.piiDetections++; return cfg.placeholderPhone; });
      s = s.replace(RE_PHONE_US,   () => { _m.piiDetections++; return cfg.placeholderPhone; });
      s = s.replace(RE_PHONE_E164, () => { _m.piiDetections++; return cfg.placeholderPhone; });
      // Credit cards (Luhn-validated)
      s = _applyCC(s, cfg.placeholderPii);
    }
  }

  // ── IP addresses (optional) ────────────────────────────────────────────────
  if (cfg.redactIpAddresses && hasDigit) {
    s = s.replace(RE_IPV4, () => { _m.piiDetections++; return cfg.placeholderIp; });
    s = s.replace(RE_IPV6_CANDIDATE, (m) => {
      if (!net.isIPv6(m.split('%')[0])) return m;
      _m.piiDetections++; return cfg.placeholderIp;
    });
  }

  return s;
}

// ── Recursive sanitizer ───────────────────────────────────────────────────────

function _sanitize(value, ctx, depth) {
  if (depth > ctx.cfg.maxDepth) return ctx.cfg.placeholderDepthExceeded;

  // ── Primitives (safe to pass through) ─────────────────────────────────────
  if (value === null || value === undefined) return value;

  const t = typeof value;

  if (t === 'boolean' || t === 'number' || t === 'bigint') return value;

  if (t === 'symbol') return value.toString();

  if (t === 'function') return '[FUNCTION]';

  if (t === 'string') return _sanitizeString(value, ctx.cfg);

  // ── Reference types (circular-reference tracking) ─────────────────────────

  if (Buffer.isBuffer(value)) return ctx.cfg.placeholderBuffer;

  if (value instanceof Date) return value.toISOString();

  if (value instanceof RegExp) return value.toString();

  if (value instanceof Error) {
    // Errors are not in the WeakSet (they're objects but we always sanitize them).
    return _sanitizeError(value, ctx, depth);
  }

  if (value instanceof Map) {
    if (ctx.seen.has(value)) return ctx.cfg.placeholderCircular;
    ctx.seen.add(value);
    return _sanitizeMap(value, ctx, depth);
  }

  if (value instanceof Set) {
    if (ctx.seen.has(value)) return ctx.cfg.placeholderCircular;
    ctx.seen.add(value);
    return _sanitizeSet(value, ctx, depth);
  }

  if (Array.isArray(value)) {
    if (ctx.seen.has(value)) return ctx.cfg.placeholderCircular;
    ctx.seen.add(value);
    const out = [];
    for (const v of value) {
      out.push(_sanitize(v, ctx, depth + 1));
    }
    return out;
  }

  if (t === 'object') {
    if (ctx.seen.has(value)) return ctx.cfg.placeholderCircular;
    ctx.seen.add(value);
    return _sanitizeObject(value, ctx, depth);
  }

  // Unknown type — convert to string and scan
  return _sanitizeString(String(value), ctx.cfg);
}

function _sanitizeObject(obj, ctx, depth) {
  const out = {};
  let keys;
  try {
    keys = Object.keys(obj);
  } catch {
    return '[OBJECT_ERROR]';
  }
  for (const key of keys) {
    let val;
    try {
      val = obj[key];
    } catch {
      out[key] = '[ACCESS_ERROR]';
      continue;
    }
    if (_isSensitiveField(key)) {
      out[key] = ctx.cfg.placeholderRedacted;
      _m.redactedFields++;
    } else {
      out[key] = _sanitize(val, ctx, depth + 1);
    }
  }
  return out;
}

// Properties that are always handled explicitly by _sanitizeError and must be
// skipped in the enumerable-key loop to prevent double-processing when a
// subclass happens to make them enumerable.
const _ERROR_EXPLICIT_KEYS = new Set(['name', 'message', 'stack', 'cause', 'errors']);

function _sanitizeError(err, ctx, depth) {
  const out = {
    name:    err.name    || 'Error',
    message: typeof err.message === 'string'
      ? _sanitizeString(err.message, ctx.cfg)
      : '',
  };

  // error.stack — non-enumerable but always present on V8 errors
  if (typeof err.stack === 'string') {
    out.stack = _sanitizeString(err.stack, ctx.cfg);
  }

  // error.cause — non-enumerable own property added by Error(msg, { cause })
  // in Node.js 16.9+ / ES2022.  Object.keys() never yields it; must be read
  // directly.  The cause may itself be an Error (chained), a string, or any
  // value — _sanitize handles all of these recursively.
  if (Object.prototype.hasOwnProperty.call(err, 'cause')) {
    out.cause = _sanitize(err.cause, ctx, depth + 1);
  }

  // AggregateError.errors — non-enumerable array of sub-errors added by the
  // AggregateError constructor.  Each element is sanitized recursively so that
  // PII / tokens in any sub-error message or stack are redacted.
  if (err instanceof AggregateError && Array.isArray(err.errors)) {
    out.errors = _sanitize(err.errors, ctx, depth + 1);
  }

  // Sanitize enumerable custom properties (e.g. err.code, err.statusCode,
  // err.details).  Skip keys already handled above.
  for (const key of Object.keys(err)) {
    if (_ERROR_EXPLICIT_KEYS.has(key)) continue;
    if (_isSensitiveField(key)) {
      out[key] = ctx.cfg.placeholderRedacted;
      _m.redactedFields++;
    } else {
      out[key] = _sanitize(err[key], ctx, depth + 1);
    }
  }

  return out;
}

function _sanitizeMap(map, ctx, depth) {
  const out = {};
  for (const [k, v] of map) {
    const key = String(k);
    if (_isSensitiveField(key)) {
      out[key] = ctx.cfg.placeholderRedacted;
      _m.redactedFields++;
    } else {
      out[key] = _sanitize(v, ctx, depth + 1);
    }
  }
  return out;
}

function _sanitizeSet(set, ctx, depth) {
  const out = [];
  for (const v of set) {
    out.push(_sanitize(v, ctx, depth + 1));
  }
  return out;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Sanitize any value before it is written to a log sink.
 *
 * Returns a new value of the same shape as the input with all sensitive
 * content replaced by opaque placeholders.  Never throws.
 *
 * @param {*}      value   The value to sanitize (typically the `extra` object
 *                         passed to emit(), but works on any type)
 * @param {object} [config] Optional config override (default: defaultConfig).
 *                          Inject in tests via buildConfig() with overrides.
 * @returns {*} Sanitized copy — primitives are returned as-is or scanned,
 *              objects are returned as new plain objects.
 */
function sanitize(value, config) {
  const cfg = (config !== null && config !== undefined) ? config : defaultConfig;
  const ctx = { seen: new WeakSet(), cfg };
  try {
    return _sanitize(value, ctx, 0);
  } catch {
    return '[SANITIZATION_ERROR]';
  }
}

module.exports = {
  sanitize,
  snapshot,
  reset,
  // Exported for testing
  _isSensitiveField,
  _sanitizeString,
  SENSITIVE_FIELD_STEMS,
};
