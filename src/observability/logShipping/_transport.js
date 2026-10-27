'use strict';

// Default HTTPS transport for log shipping destinations.
//
// Uses Node.js built-in https module so there are no external dependencies
// and TLS certificate verification is always on (Node.js default).
//
// Callers receive { status, body } on success.
// Throws on network error, timeout, or non-HTTPS URL.

const https = require('https');

const DEFAULT_TIMEOUT_MS = 15_000;

function httpsPost(urlStr, headers, body) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(urlStr);
    } catch {
      return reject(new Error(`LOGSHIP_TRANSPORT: invalid URL: ${urlStr}`));
    }

    if (parsed.protocol !== 'https:') {
      return reject(new Error('LOGSHIP_TRANSPORT: only HTTPS endpoints are supported'));
    }

    const bodyBuf = Buffer.isBuffer(body)
      ? body
      : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8');

    const req = https.request(
      {
        hostname: parsed.hostname,
        port:     parsed.port || 443,
        path:     parsed.pathname + parsed.search,
        method:   'POST',
        // TLS certificate verification: Node.js default (enabled, no override)
        headers:  {
          'Content-Length': bodyBuf.length,
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );

    req.setTimeout(DEFAULT_TIMEOUT_MS, () => {
      const err = new Error('LOGSHIP_TRANSPORT: request timed out');
      err.code = 'ETIMEDOUT';
      req.destroy(err);
    });

    req.on('error', reject);
    req.write(bodyBuf);
    req.end();
  });
}

module.exports = { httpsPost };
