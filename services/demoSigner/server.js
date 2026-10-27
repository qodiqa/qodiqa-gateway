'use strict';

/**
 * Demo signer entry point (launch plan R-02):  npm run demo-signer
 *
 * Refuses to start on any invalid configuration (config.js). When
 * DEMO_SIGNER_ENABLED is not 'true' it still starts, but every sign request
 * returns 503 DEMO_DISABLED — that is the kill switch. The emergency stop for
 * artifacts already handed out is `node scripts/revoke-signing-identity.js`
 * for each demo identity (the gateway re-checks revocation at /ai/chat).
 *
 * Logs are one JSON object per line: scenario, outcome, status, latency and a
 * truncated HMAC of the client IP. Never prompt text, never key material.
 */

const { createClient } = require('redis');
const { loadConfig, DemoSignerConfigError } = require('./config');
const { createQuota } = require('./quota');
const { createGatewayClient } = require('./gatewayClient');
const { createDemoSignerApp } = require('./app');

// Canonical log envelope: timestamp, severity, eventType, category.
const _SEVERITY = { DEMO_SIGNER_START_REFUSED: 'FATAL', DEMO_SIGNER_FATAL: 'FATAL', DEMO_SIGNER_ERROR: 'ERROR', DEMO_SIGNER_REDIS_ERROR: 'ERROR' };
function log({ event, ...fields }) {
  const eventType = event || 'DEMO_SIGNER_EVENT';
  const severity = _SEVERITY[eventType] || (fields.status >= 500 ? 'WARN' : 'INFO');
  process.stdout.write(`${JSON.stringify({ timestamp: new Date().toISOString(), severity, eventType, category: 'OPERATIONAL', service: 'demo-signer', ...fields })}\n`);
}

async function main() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof DemoSignerConfigError) {
      log({ event: 'DEMO_SIGNER_START_REFUSED', problems: err.problems });
      process.exit(1);
    }
    throw err;
  }

  let quota = null;
  let redis = null;
  if (config.enabled) {
    redis = createClient({ url: config.redisUrl, socket: { connectTimeout: 5000, reconnectStrategy: (n) => Math.min(n * 200, 5000) } });
    redis.on('error', (e) => log({ event: 'DEMO_SIGNER_REDIS_ERROR', message: String(e && e.message).slice(0, 200) }));
    await redis.connect();
    quota = createQuota(redis, config);
  }
  const gatewayClient = createGatewayClient({ gatewayUrl: config.gatewayUrl || 'http://127.0.0.1:3000', timeoutMs: config.gatewayTimeoutMs });
  const app = createDemoSignerApp({ config, quota, gatewayClient, log });

  const server = app.listen(config.port, config.host, () => {
    log({ event: 'DEMO_SIGNER_STARTED', enabled: config.enabled, host: config.host, port: config.port, scenarios: config.scenarios,
      limits: { perIpPerMin: config.perIpPerMin, perIpPerDay: config.perIpPerDay, globalPerMin: config.globalPerMin } });
  });

  const shutdown = () => {
    server.close(() => {
      if (redis) redis.quit().catch(() => {}).finally(() => process.exit(0));
      else process.exit(0);
    });
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

if (require.main === module) {
  main().catch((err) => { log({ event: 'DEMO_SIGNER_FATAL', message: String(err && err.message).slice(0, 200) }); process.exit(1); });
}

module.exports = { main };
