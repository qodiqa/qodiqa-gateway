'use strict';

/**
 * Test-harness-only entry point for AT-099 (graceful shutdown). Requires the
 * real, unmodified server.js exactly the way start.js already does in
 * production (require('./server.js').startServer()) — server.js's own
 * require.main guard only auto-starts when server.js itself is the process
 * entry point, so this wrapper calls startServer() explicitly instead,
 * mirroring start.js's own precedent.
 *
 * Bridges a parent IPC message to a real process.emit('SIGTERM') in this
 * child. This exists solely because on Windows, child.kill('SIGTERM') maps
 * to TerminateProcess rather than a POSIX signal (see helpers/process.js's
 * killProcessTree comment) — server.js's own process.on('SIGTERM', ...)
 * handler is never invoked that way, so real OS signal delivery cannot be
 * observed on this platform. process.emit('SIGTERM') reproduces exactly
 * what Node's internal signal watcher does upon a genuine POSIX signal; it
 * does not alter, mock, or bypass any production code path — server.js's
 * real shutdown handler runs unmodified.
 */

process.on('message', (msg) => {
  if (msg === 'TRIGGER_SIGTERM') process.emit('SIGTERM');
});

require('../../server.js').startServer().catch((err) => {
  console.error(JSON.stringify({ event: 'FATAL', reason: 'SERVER_STARTUP_FAILED', message: err.message }));
  process.exit(1);
});
