'use strict';

/**
 * Shared Redis reachability probe.
 *
 * A plain TCP connect check — deliberately NOT a full RESP handshake or
 * AOF-persistence inspection. Used by both scripts/bootstrap-dev.js (to
 * decide whether to fail fast before spawning the server) and
 * test/serverStartupSmoke.test.js (to decide whether to skip the smoke
 * test), so both stay in sync on what "Redis is reachable" means.
 */

const net = require('net');

/**
 * @param {string} redisUrl  e.g. "redis://localhost:6379"
 * @param {number} [timeoutMs]
 * @returns {Promise<boolean>}
 */
function probeRedisReachable(redisUrl, timeoutMs = 1200) {
  return new Promise((resolve) => {
    let host = '127.0.0.1';
    let port = 6379;
    try {
      const parsed = new URL(redisUrl);
      host = parsed.hostname || host;
      port = parsed.port ? parseInt(parsed.port, 10) : port;
    } catch {
      // Malformed URL — treat as unreachable; the real client will report
      // the same failure in detail when something actually tries to connect.
    }

    const socket = net.createConnection({ host, port, timeout: timeoutMs });
    const finish = (reachable) => {
      socket.destroy();
      resolve(reachable);
    };
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error',   () => finish(false));
  });
}

module.exports = { probeRedisReachable };
