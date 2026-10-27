'use strict';

/**
 * phase 8 — parent-side driver for step-by-step IPC worker processes (test/distributed/*).
 *
 * startIpcWorker(modulePath, { env }) forks the worker with an EXPLICIT environment (never the parent's ambient
 * env, never .env — CLAUDE.md / boundary: a child must not inherit a LIVE connection string by accident)
 * and returns { pid, call(cmd, args, timeoutMs), waitFor(id, timeoutMs), kill(), exit(), exited, stderr() }.
 * Replies are matched by id; unsolicited messages (e.g. `<id>:thawed`) are buffered until waited for.
 */

const { fork } = require('child_process');

// The minimum a Node child needs on Windows/Linux to start, plus what the caller passes.
function baseEnv(extra) {
  const keep = ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'COMSPEC', 'windir'];
  const env = {};
  for (const k of keep) if (process.env[k] !== undefined) env[k] = process.env[k];
  // phase 17: the worker also preloads the LIVE-endpoint socket guard (CI exempt) — a product default
  // (localhost:5432 / redis://localhost:6379) reached by a mis-built `extra` is refused in the child too.
  const guard = require('./liveEndpointGuard');
  if (!guard.isExempt(process.env)) env.NODE_OPTIONS = guard.withPreload(process.env.NODE_OPTIONS);
  return { ...env, NODE_ENV: 'test', ...extra };
}

let _seq = 0;

function startIpcWorker(modulePath, { env = {}, args = [] } = {}) {
  const proc = fork(modulePath, args, { env: baseEnv(env), stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  const inbox = new Map();
  const waiters = new Map();
  let errBuf = '';
  let outBuf = '';
  proc.stderr.on('data', (c) => { errBuf += c.toString('utf8'); });
  proc.stdout.on('data', (c) => { outBuf += c.toString('utf8'); });
  proc.on('message', (m) => {
    if (!m || m.id === undefined) return;
    const w = waiters.get(m.id);
    if (w) { waiters.delete(m.id); clearTimeout(w.t); w.resolve(m); } else inbox.set(m.id, m);
  });
  const exited = new Promise((resolve) => proc.on('exit', (code, signal) => {
    for (const [id, w] of waiters) { clearTimeout(w.t); w.reject(new Error(`worker ${proc.pid} exited (${code}/${signal}) before reply ${id}; stderr: ${errBuf.slice(-800)}`)); }
    waiters.clear();
    resolve({ code, signal });
  }));

  function waitFor(id, timeoutMs = 20_000) {
    if (inbox.has(id)) { const m = inbox.get(id); inbox.delete(id); return Promise.resolve(m); }
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { waiters.delete(id); reject(new Error(`timeout waiting for ${id} from worker ${proc.pid}; stderr: ${errBuf.slice(-800)}`)); }, timeoutMs);
      waiters.set(id, { resolve, reject, t });
    });
  }

  function call(cmd, args = {}, timeoutMs = 20_000) {
    const id = `${cmd}#${++_seq}`;
    const p = waitFor(id, timeoutMs);
    proc.send({ id, cmd, args });
    return p;
  }

  return {
    proc,
    pid: proc.pid,
    call,
    waitFor,
    send: (cmd, args = {}) => { const id = `${cmd}#${++_seq}`; proc.send({ id, cmd, args }); return id; },
    kill: (sig = 'SIGKILL') => { try { proc.kill(sig); } catch (_) { /* gone */ } return exited; },
    exit: async () => {
      if (proc.exitCode === null && proc.signalCode === null && proc.connected) proc.send({ id: 'exit', cmd: 'exit' });
      let t;
      const r = await Promise.race([exited, new Promise((res) => { t = setTimeout(() => res(null), 5000); })]);
      clearTimeout(t);
      if (!r) { proc.kill('SIGKILL'); return exited; }
      return r;
    },
    exited,
    stderr: () => errBuf,
    stdout: () => outBuf,
  };
}

module.exports = { startIpcWorker, baseEnv };
