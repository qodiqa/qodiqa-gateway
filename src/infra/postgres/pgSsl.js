'use strict';

/**
 * PostgreSQL TLS resolution — the ONE implementation.
 *
 * Used by pool.js (app role), retentionPool.js (retention role) and migrate.js
 * (migration role). migrate.js only enabled TLS for the literal
 * QODIQA_PG_SSL=true, so in production with QODIQA_PG_SSL unset the app pool
 * required TLS while the migration runner connected in plaintext.
 *
 *   QODIQA_PG_SSL set (non-empty) → TLS iff it is the literal 'true'
 *   QODIQA_PG_SSL unset/empty     → TLS iff NODE_ENV === 'production'
 *   TLS on → { rejectUnauthorized: true } plus QODIQA_PG_SSL_CA / _CERT / _KEY
 *            file contents when those paths are set.
 *
 * bootValidator.resolvePgSsl() applies the same on/off rule at boot.
 *
 * @param {NodeJS.ProcessEnv} [env=process.env]
 * @returns {false | { rejectUnauthorized: true, ca?: Buffer, cert?: Buffer, key?: Buffer }}
 */

const fs = require('fs');

function resolvePgSslOptions(env = process.env) {
  const sslEnabled = env.QODIQA_PG_SSL
    ? env.QODIQA_PG_SSL === 'true'
    : env.NODE_ENV === 'production';
  if (!sslEnabled) return false;
  const ssl = { rejectUnauthorized: true };
  if (env.QODIQA_PG_SSL_CA)   ssl.ca   = fs.readFileSync(env.QODIQA_PG_SSL_CA);
  if (env.QODIQA_PG_SSL_CERT) ssl.cert = fs.readFileSync(env.QODIQA_PG_SSL_CERT);
  if (env.QODIQA_PG_SSL_KEY)  ssl.key  = fs.readFileSync(env.QODIQA_PG_SSL_KEY);
  return ssl;
}

module.exports = { resolvePgSslOptions };
