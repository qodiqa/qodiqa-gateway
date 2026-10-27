'use strict';

/**
 * Low-level process/port management shared by helpers/server.js and
 * helpers/redis.js. This is the only module in the framework that calls
 * child_process.spawn directly.
 *
 * Retries here are the ONLY retries permitted anywhere in the framework
 * (requirement #19 — infrastructure operations may retry; acceptance
 * assertions never do). "Retry" in this module always means "keep polling
 * a condition that is expected to become true shortly," never "re-attempt a
 * failed check."
 */

const net = require('net');
const os = require('os');
const { spawn, spawnSync } = require('child_process');

/**
 * Finds a free TCP port on 127.0.0.1. Retried internally by the OS (binding
 * to port 0) — no manual retry loop needed since the OS never hands out a
 * port already in use.
 */
function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

/**
 * Spawns a child process and captures every line written to stdout/stderr
 * (interleaved, in arrival order) into an in-memory buffer, while also
 * exposing the raw chunks separately and a subscribable per-line callback.
 *
 * @param {string} command
 * @param {string[]} args
 * @param {object} spawnOptions   passed through to child_process.spawn (cwd, env, ...)
 * @returns {{ child: import('child_process').ChildProcess, lines: string[], onLine(cb): void, getOutput(): string }}
 */
function spawnCapturing(command, args, spawnOptions = {}) {
  const child = spawn(command, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    ...spawnOptions,
  });

  const lines = [];
  const chunks = [];
  const lineCallbacks = [];

  // stdout and stderr each need their own carry buffer — sharing one would
  // let a stderr chunk arrive mid-stdout-line (or vice versa) and splice
  // unrelated partial lines together.
  function makeHandler() {
    let carry = '';
    return (buf) => {
      const text = buf.toString();
      chunks.push(text);
      carry += text;
      const parts = carry.split('\n');
      carry = parts.pop(); // last part may be an incomplete line
      for (const part of parts) {
        lines.push(part);
        for (const cb of lineCallbacks) cb(part);
      }
    };
  }

  child.stdout.on('data', makeHandler());
  child.stderr.on('data', makeHandler());

  return {
    child,
    lines,
    onLine(cb) {
      lineCallbacks.push(cb);
    },
    getOutput() {
      return chunks.join('');
    },
  };
}

/**
 * Polls `predicate` (sync or async) at `intervalMs` until it returns
 * truthy or `timeoutMs` elapses. This is the framework's one bounded-retry
 * primitive for infrastructure readiness (server startup, Redis reachable,
 * port released, etc.) — never used to retry an assertion.
 *
 * @returns {Promise<any>} the truthy value predicate() resolved to, or undefined on timeout
 */
async function waitForCondition(predicate, { timeoutMs = 15000, intervalMs = 150 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = await predicate();
    if (result) return result;
    if (Date.now() >= deadline) return undefined;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/**
 * Terminates a child process AND every process it spawned, then resolves
 * once it has exited. Safe to call on an already-exited child.
 *
 * On Windows, child.kill() (default SIGTERM) maps to TerminateProcess, not
 * a real POSIX signal — a process tree like
 * runner -> bootstrap-dev.js -> server.js never gets a chance to run its
 * own SIGTERM-forwarding handler, which would leak an orphaned server.js
 * still holding its port. `taskkill /T /F` kills the whole tree
 * unconditionally, which is what every acceptance test actually needs
 * (guaranteed cleanup, not graceful shutdown verification — that is
 * server.js's own concern, covered elsewhere).
 */
function killProcessTree(child, { graceMs = 3000 } = {}) {
  return new Promise((resolve) => {
    if (!child || child.killed || child.exitCode !== null) {
      resolve();
      return;
    }

    if (os.platform() === 'win32' && child.pid) {
      try {
        spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F']);
      } catch { /* process may have already exited */ }
      // taskkill is synchronous; the child's 'exit' event still fires
      // asynchronously shortly after, so wait for it (bounded) rather than
      // resolving immediately.
      if (child.exitCode !== null) { resolve(); return; }
      const fallback = setTimeout(resolve, graceMs);
      child.once('exit', () => { clearTimeout(fallback); resolve(); });
      return;
    }

    const forceKill = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
    }, graceMs);
    child.once('exit', () => {
      clearTimeout(forceKill);
      resolve();
    });
    try {
      child.kill('SIGTERM');
    } catch {
      clearTimeout(forceKill);
      resolve();
    }
  });
}

module.exports = {
  getFreePort,
  spawnCapturing,
  waitForCondition,
  killProcessTree,
};
