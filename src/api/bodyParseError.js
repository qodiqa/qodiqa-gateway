'use strict';

/**
 * Launch plan R-15 (finding A-1): recognise an oversize-body error from express.json().
 *
 * Before R-15 every parser error — including a body over MAX_BODY_BYTES — was answered 400 MALFORMED_JSON, so a
 * client could not tell "too big" from "not JSON", and the contract (HTTP 413 for an oversize payload) was violated.
 * body-parser marks an oversize body with type 'entity.too.large' (status 413). src/app.js answers that case 413
 * PAYLOAD_TOO_LARGE and keeps every other parser error exactly as before (400 MALFORMED_JSON). The reason literals
 * stay in src/app.js on purpose: src/errors/__tests__/catalogCompleteness.test.js scans that file for them.
 *
 * @param {unknown} err
 * @returns {boolean}
 */
function isBodyTooLarge(err) {
  return !!err && typeof err === 'object' && err.type === 'entity.too.large';
}

const _utf8Strict = new TextDecoder('utf-8', { fatal: true });

/**
 * express.json() `verify` hook: the request body is UTF-8 only. Without it the parser decodes invalid
 * byte sequences to U+FFFD, so the bytes that were read differ from the bytes that a client signed/bound.
 * Throws (body-parser turns it into a parse error) on invalid UTF-8.
 */
function assertUtf8Body(req, _res, buf) {
  // body-parser decodes with the request's declared charset (anything starting with "utf-", e.g. utf-16le), so the bytes would be
  // validated as UTF-8 here but read as something else. Only an absent or UTF-8 charset is accepted.
  const ct = req && req.headers ? String(req.headers['content-type'] || '') : '';
  const m = /;\s*charset\s*=\s*"?([^";\s]+)"?/i.exec(ct);
  if (m && !/^utf-?8$/i.test(m[1])) throw new TypeError(`unsupported charset ${m[1]}: the body must be UTF-8`);
  if (buf && buf.length) _utf8Strict.decode(buf);
}

module.exports = { isBodyTooLarge, assertUtf8Body };
