'use strict';

// RAND-3: this diagnostic/tracing request ID previously carried only 32 bits
// of randomness (4 bytes) plus a predictable timestamp prefix — far weaker
// than the 122-bit crypto.randomUUID() used for the protocol-critical
// requestId in src/validation/requestId.js. This ID is never used as a nonce
// or replay-protection token (see nonceStore.js for that, separate value),
// but a low-entropy trace ID is still needlessly guessable/correlatable in
// logs. randomUUID() is used here for consistency with the rest of the
// codebase's identifier generation.
const { randomUUID } = require('crypto');

module.exports = function requestId(req, res, next) {
  const id = randomUUID();
  req.requestId = id;
  res.locals.requestId = id;
  res.set('X-Request-ID', id);
  next();
};
